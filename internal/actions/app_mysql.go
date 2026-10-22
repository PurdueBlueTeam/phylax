package actions

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

// Database account audit and lock, and the admin SQL action, over the local
// unix socket with the built-in client (no mysql CLI).

var mysqlSockets = []string{"/var/run/mysqld/mysqld.sock", "/run/mysqld/mysqld.sock", "/var/lib/mysql/mysql.sock",
	"/run/mariadb/mariadb.sock", "/var/run/mariadb/mariadb.sock", "/tmp/mysql.sock"}

var socketParam = ParamSpec{Name: "socket", Type: Path}

func (e *Env) mysqlDial(ctx context.Context, p Params) (MySQLConn, error) {
	sock := p.Str("socket")
	if sock == "" {
		for _, c := range mysqlSockets {
			if _, err := os.Stat(e.Resolve(c)); err == nil {
				sock = c
				break
			}
		}
		if sock == "" {
			return nil, errors.New("no database socket found; give socket")
		}
	}
	return e.mysqlDialPath(ctx, e.Resolve(sock))
}

func (e *Env) mysqlDialPath(ctx context.Context, real string) (MySQLConn, error) {
	l := e.lx()
	t := MySQLTarget{Socket: real, User: l.MySQLAuth.User, Password: l.MySQLAuth.Password}
	if t.User == "" {
		t.User = "root"
	}
	var d MySQLDialer = unixMySQLDialer{}
	if l.MySQL != nil {
		d = l.MySQL
	}
	return d.Dial(ctx, t)
}

// Queries shared with the fake server in tests.
const (
	mysqlVersionSQL = "SELECT VERSION()"
	mysqlUsersSQL   = "SELECT User, Host, plugin, IF(authentication_string='','1','0') AS empty_pw, account_locked, Super_priv FROM mysql.user"
	mariaUsersSQL   = "SELECT u.User, u.Host, u.plugin, IF(u.authentication_string='','1','0') AS empty_pw, IFNULL(JSON_VALUE(g.Priv,'$.account_locked'),'false') AS account_locked, u.Super_priv FROM mysql.user u JOIN mysql.global_priv g ON g.User=u.User AND g.Host=u.Host"
)

// DBAccount is one database account as the audit sees it.
type DBAccount struct {
	User, Host, Plugin string
	EmptyPassword      bool
	Locked             bool
	Super              bool
}

func (a DBAccount) String() string { return fmt.Sprintf("'%s'@'%s'", a.User, a.Host) }

func listAccounts(ctx context.Context, c MySQLConn) (accts []DBAccount, version string, err error) {
	v, err := c.Query(ctx, mysqlVersionSQL)
	if err != nil || len(v.Rows) != 1 {
		return nil, "", fmt.Errorf("version query: %v", err)
	}
	version = v.Rows[0][0]
	q := mysqlUsersSQL
	if strings.Contains(strings.ToLower(version), "mariadb") {
		q = mariaUsersSQL
	}
	r, err := c.Query(ctx, q)
	if err != nil {
		return nil, version, err
	}
	for _, row := range r.Rows {
		if len(row) < 6 {
			return nil, version, errors.New("unexpected account row shape")
		}
		lock := strings.ToLower(row[4])
		accts = append(accts, DBAccount{User: row[0], Host: row[1], Plugin: row[2], EmptyPassword: row[3] == "1",
			Locked: lock == "y" || lock == "true", Super: row[5] == "Y"})
	}
	return accts, version, nil
}

type dbFinding struct{ Severity, Account, Issue string }

func auditAccounts(accts []DBAccount, adminUser string) []dbFinding {
	var out []dbFinding
	for _, a := range accts {
		if a.Locked {
			continue
		}
		socketAuth := a.Plugin == "unix_socket" || a.Plugin == "auth_socket"
		switch {
		case a.User == "":
			out = append(out, dbFinding{"critical", a.String(), "anonymous account"})
		case a.EmptyPassword && !socketAuth:
			out = append(out, dbFinding{"critical", a.String(), "empty password"})
		}
		if a.Host == "%" || a.Host == "" {
			sev := "warning"
			if a.Super {
				sev = "critical"
			}
			out = append(out, dbFinding{sev, a.String(), "reachable from any host"})
		}
		if a.Super && a.User != adminUser && a.User != "mysql.sys" && a.User != "mariadb.sys" && a.User != "root" && a.User != "debian-sys-maint" {
			out = append(out, dbFinding{"warning", a.String(), "has SUPER privilege"})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity < out[j].Severity // critical < warning
		}
		return out[i].Account < out[j].Account
	})
	return out
}

// ---- mysql.audit ----

type mysqlAudit struct{}

func (mysqlAudit) Spec() Spec {
	return Spec{Name: "mysql.audit", Risk: RiskNone, ReadOnly: true,
		Doc:    "List database accounts through the unix socket and flag anonymous, empty-password, any-host and extra SUPER accounts. fail_on_critical makes critical findings fail the node.",
		Params: []ParamSpec{socketParam, {Name: "fail_on_critical", Type: Bool}}}
}
func (mysqlAudit) Locks(Params) []string  { return nil }
func (mysqlAudit) Touches(Params) []Touch { return nil }
func (mysqlAudit) Plan(context.Context, *Env, Params) (Plan, error) {
	return Plan{Diff: "read-only"}, nil
}
func (mysqlAudit) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }
func (mysqlAudit) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	c, err := env.mysqlDial(ctx, p)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	accts, ver, err := listAccounts(ctx, c)
	if err != nil {
		return nil, err
	}
	fs := auditAccounts(accts, env.lx().MySQLAuth.User)
	crit := 0
	var lines []string
	for _, f := range fs {
		if f.Severity == "critical" {
			crit++
		}
		lines = append(lines, f.Severity+" "+f.Account+": "+f.Issue)
	}
	b, _ := json.Marshal(fs)
	out := Output{"server_version": ver, "accounts": fmt.Sprint(len(accts)), "critical": fmt.Sprint(crit),
		"findings": strings.Join(lines, "\n"), "findings_json": string(b)}
	if crit > 0 && p.Bool("fail_on_critical") {
		return out, fmt.Errorf("%d critical finding(s)", crit)
	}
	return out, nil
}
func (mysqlAudit) Verify(ctx context.Context, env *Env, p Params) error { return nil }

// ---- mysql.lock ----

const kindMySQLUnlock = "mysql.unlock"

type mysqlLockUndo struct {
	Socket string `json:"socket"`
	User   string `json:"user"`
	Host   string `json:"host"`
}

var dbNameRe = regexp.MustCompile(`^[A-Za-z0-9_.$\-]{1,80}$`)

type mysqlLock struct{}

func (mysqlLock) Spec() Spec {
	chk := func(v any) error {
		if !dbNameRe.MatchString(v.(string)) {
			return errors.New("invalid account name part")
		}
		return nil
	}
	return Spec{Name: "mysql.lock", Risk: RiskLockout,
		Doc: "ACCOUNT LOCK a database account (never the agent's own connection account, never a scored account). Rollback unlocks it.",
		Params: []ParamSpec{
			{Name: "user", Type: String, Required: true, Check: chk},
			{Name: "host", Type: String, Default: "localhost", Check: func(v any) error {
				if v.(string) == "%" {
					return nil
				}
				return chk(v)
			}},
			socketParam}}
}
func (mysqlLock) Locks(Params) []string { return nil }
func (mysqlLock) Touches(p Params) []Touch {
	return []Touch{{Kind: TouchAccount, Name: p.Str("user"), Op: OpLock}}
}

func (mysqlLock) self(env *Env, p Params) bool {
	me := env.lx().MySQLAuth.User
	if me == "" {
		me = "root"
	}
	return p.Str("user") == me && (p.Str("host") == "localhost" || p.Str("host") == "127.0.0.1")
}

func (m mysqlLock) find(ctx context.Context, env *Env, p Params) (acct DBAccount, ok bool, err error) {
	c, err := env.mysqlDial(ctx, p)
	if err != nil {
		return acct, false, err
	}
	defer c.Close()
	accts, _, err := listAccounts(ctx, c)
	if err != nil {
		return acct, false, err
	}
	for _, a := range accts {
		if a.User == p.Str("user") && a.Host == p.Str("host") {
			return a, true, nil
		}
	}
	return acct, false, nil
}

func (m mysqlLock) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	if m.self(env, p) {
		return Plan{}, errors.New("refusing to lock the account the agent connects as")
	}
	a, ok, err := m.find(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	if !ok {
		return Plan{}, fmt.Errorf("account %s@%s not found", p.Str("user"), p.Str("host"))
	}
	if a.Locked {
		return Plan{Done: true}, nil
	}
	return Plan{Diff: fmt.Sprintf("lock database account %s (locked false -> true)", a)}, nil
}

func (mysqlLock) Capture(_ context.Context, env *Env, p Params) (Rollback, error) {
	sock := p.Str("socket")
	if sock == "" {
		for _, c := range mysqlSockets {
			if _, err := os.Stat(env.Resolve(c)); err == nil {
				sock = c
				break
			}
		}
	}
	return Rollback{Kind: kindMySQLUnlock, Data: mysqlLockUndo{Socket: env.Resolve(sock), User: p.Str("user"), Host: p.Str("host")}}, nil
}

func alterLock(ctx context.Context, c MySQLConn, user, host, verb string) error {
	u, err := quoteMySQL(user)
	if err != nil {
		return err
	}
	h, err := quoteMySQL(host)
	if err != nil {
		return err
	}
	_, err = c.Query(ctx, fmt.Sprintf("ALTER USER %s@%s ACCOUNT %s", u, h, verb))
	return err
}

func undoMySQLLock(ctx context.Context, env *Env, e deadman.Entry) error {
	var u mysqlLockUndo
	if err := json.Unmarshal(e.Data, &u); err != nil {
		return err
	}
	c, err := env.mysqlDialPath(ctx, u.Socket)
	if err != nil {
		return err
	}
	defer c.Close()
	return alterLock(ctx, c, u.User, u.Host, "UNLOCK")
}

func (m mysqlLock) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	c, err := env.mysqlDial(ctx, p)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return nil, alterLock(ctx, c, p.Str("user"), p.Str("host"), "LOCK")
}

func (m mysqlLock) Verify(ctx context.Context, env *Env, p Params) error {
	a, ok, err := m.find(ctx, env, p)
	if err != nil {
		return err
	}
	if !ok || !a.Locked {
		return errors.New("account is not locked after ALTER USER")
	}
	return nil
}

// ---- sql.query ----

type sqlQuery struct{}

var (
	sqlReadRe     = regexp.MustCompile(`(?is)^\s*(select|show|describe|desc|explain)\b`)
	sqlForbidden  = regexp.MustCompile(`(?is)\b(into\s+(outfile|dumpfile)|load_file\s*\(|load\s+data|drop\s+(database|schema|table)|truncate|shutdown|sleep\s*\(|benchmark\s*\()`)
	sqlUpdDelRe   = regexp.MustCompile(`(?is)^\s*(update|delete)\b`)
	sqlWhereRe    = regexp.MustCompile(`(?is)\bwhere\b`)
	sqlAccountRe  = regexp.MustCompile("(?is)^\\s*(alter\\s+user|drop\\s+user|rename\\s+user|set\\s+password\\s+for|create\\s+user)\\s+(?:if\\s+(?:not\\s+)?exists\\s+)?['`\"]?([^'`\"@\\s]+)")
	namedStmtRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{2,40}$`)
	identOnlyRe   = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	namedStmtList = []string{"version", "audit_accounts", "rotate_opencart_admin"}
)

func (sqlQuery) Spec() Spec {
	return Spec{Name: "sql.query", Risk: RiskService,
		Doc: "Admin query against the local MySQL/MariaDB over the unix socket. statement is a named statement (version, audit_accounts, rotate_opencart_admin) or a single SQL statement with ? placeholders bound from args; write statements need write=true. engine mssql (local SQL Server) takes the named statements of mssql_audit.go (version, sysadmins, weak_logins, config, linked_servers, agent_jobs, startup_procs, trustworthy_dbs, server_triggers, audit, ...) or one T-SQL statement with ? placeholders.",
		Params: []ParamSpec{
			{Name: "engine", Type: Enum, Required: true, Enum: []string{"mysql", "mariadb", "mssql"}},
			{Name: "statement", Type: String, Required: true, Max: 16384},
			{Name: "args", Type: StringList, Max: 64},
			{Name: "write", Type: Bool},
			socketParam, mssqlServerParam, mssqlPortParam}}
}
func (sqlQuery) Locks(Params) []string  { return nil }
func (sqlQuery) Touches(Params) []Touch { return nil }

// stmt resolves the statement to run (named statements expand in Apply).
func (sqlQuery) checkRaw(ctx context.Context, env *Env, p Params) (string, error) {
	st := strings.TrimSpace(p.Str("statement"))
	st = strings.TrimSuffix(st, ";")
	if strings.Contains(stripSQLQuoted(st), ";") {
		return "", errors.New("exactly one statement is allowed")
	}
	if sqlForbidden.MatchString(stripSQLQuoted(st)) {
		return "", errors.New("statement uses a forbidden construct (file access, DROP, TRUNCATE, SLEEP)")
	}
	bound, err := bindMySQL(st, p.List("args"))
	if err != nil {
		return "", err
	}
	read := sqlReadRe.MatchString(st)
	if !read && !p.Bool("write") {
		return "", errors.New("write statements need write=true")
	}
	if sqlUpdDelRe.MatchString(st) && !sqlWhereRe.MatchString(stripSQLQuoted(st)) {
		return "", errors.New("UPDATE/DELETE without WHERE is refused")
	}
	if m := sqlAccountRe.FindStringSubmatch(st); m != nil {
		op := OpLock
		switch w := strings.ToLower(m[1]); {
		case strings.HasPrefix(w, "drop"):
			op = OpDelete
		case strings.HasPrefix(w, "rename"):
			op = OpRename
		case strings.HasPrefix(w, "set"), strings.HasPrefix(w, "alter") && strings.Contains(strings.ToLower(st), "identified"):
			op = OpSetPassword
		case strings.HasPrefix(w, "create"):
			op = OpModify
		}
		if err := env.guard().Allow(ctx, Touch{Kind: TouchAccount, Name: m[2], Op: op}); err != nil {
			return "", err
		}
	}
	return bound, nil
}

// stripSQLQuoted blanks quoted strings so keyword scans ignore literals.
func stripSQLQuoted(s string) string {
	var b strings.Builder
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == '\\' && i+1 < len(s) {
				i++
			} else if c == q {
				q = 0
			}
			b.WriteByte(' ')
		case c == '\'' || c == '"' || c == '`':
			q = c
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func (s sqlQuery) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	if p.Str("engine") == "mssql" {
		return mssqlQueryPlan(ctx, env, p)
	}
	st := p.Str("statement")
	if namedStmtRe.MatchString(st) {
		switch st {
		case "version", "audit_accounts":
			return Plan{Diff: "read-only named statement " + st}, nil
		case "rotate_opencart_admin":
			a, err := opencartArgs(p)
			if err != nil {
				return Plan{}, err
			}
			return Plan{Diff: fmt.Sprintf("rotate the password of OpenCart admin %q in %s.%suser (new password returned in output)", a.user, a.db, a.prefix)}, nil
		}
		return Plan{}, fmt.Errorf("unknown named statement %q (known: %s)", st, strings.Join(namedStmtList, ", "))
	}
	bound, err := s.checkRaw(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	if sqlReadRe.MatchString(bound) {
		return Plan{Diff: "read-only: " + bound}, nil
	}
	return Plan{Diff: "execute: " + bound, Notes: []string{"SQL changes are not rolled back automatically"}}, nil
}
func (sqlQuery) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }

type ocArgs struct{ db, prefix, user string }

func opencartArgs(p Params) (ocArgs, error) {
	a := ocArgs{db: "opencart", prefix: "oc_", user: "admin"}
	l := p.List("args")
	if len(l) > 3 {
		return a, errors.New("rotate_opencart_admin takes [db, prefix, username]")
	}
	for _, v := range l {
		if !identOnlyRe.MatchString(v) {
			return a, fmt.Errorf("invalid argument %q", v)
		}
	}
	if len(l) > 0 {
		a.db = l[0]
	}
	if len(l) > 1 {
		a.prefix = l[1]
	}
	if len(l) > 2 {
		a.user = l[2]
	}
	return a, nil
}

func randomPassword(n int) (string, error) {
	const alpha = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	for i := range b {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(alpha))))
		if err != nil {
			return "", err
		}
		b[i] = alpha[k.Int64()]
	}
	return string(b), nil
}

func (s sqlQuery) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	if p.Str("engine") == "mssql" {
		return mssqlQueryApply(ctx, env, p)
	}
	c, err := env.mysqlDial(ctx, p)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	switch st := p.Str("statement"); {
	case st == "version":
		r, err := c.Query(ctx, mysqlVersionSQL)
		if err != nil {
			return nil, err
		}
		return Output{"version": r.Rows[0][0]}, nil
	case st == "audit_accounts":
		accts, ver, err := listAccounts(ctx, c)
		if err != nil {
			return nil, err
		}
		var lines []string
		for _, f := range auditAccounts(accts, env.lx().MySQLAuth.User) {
			lines = append(lines, f.Severity+" "+f.Account+": "+f.Issue)
		}
		return Output{"server_version": ver, "accounts": fmt.Sprint(len(accts)), "findings": strings.Join(lines, "\n")}, nil
	case st == "rotate_opencart_admin":
		return rotateOpenCart(ctx, c, p)
	}
	bound, err := s.checkRaw(ctx, env, p)
	if err != nil {
		return nil, err
	}
	r, err := c.Query(ctx, bound)
	if err != nil {
		return nil, err
	}
	out := Output{"affected": fmt.Sprint(r.Affected), "rows": fmt.Sprint(len(r.Rows))}
	if len(r.Rows) > 0 {
		var b strings.Builder
		b.WriteString(strings.Join(r.Columns, "\t") + "\n")
		for i, row := range r.Rows {
			if i >= 200 {
				b.WriteString("...\n")
				break
			}
			b.WriteString(strings.ReplaceAll(strings.Join(row, "\t"), MySQLNull, "NULL") + "\n")
		}
		out["result"] = b.String()
	}
	return out, nil
}

func rotateOpenCart(ctx context.Context, c MySQLConn, p Params) (Output, error) {
	a, err := opencartArgs(p)
	if err != nil {
		return nil, err
	}
	table := "`" + a.db + "`.`" + a.prefix + "user`"
	chk, err := c.Query(ctx, fmt.Sprintf("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='%s' AND TABLE_NAME='%suser' AND COLUMN_NAME='salt'", a.db, a.prefix))
	if err != nil {
		return nil, err
	}
	pw, err := randomPassword(24)
	if err != nil {
		return nil, err
	}
	user, _ := quoteMySQL(a.user)
	var stmt string
	if len(chk.Rows) == 1 && chk.Rows[0][0] != "0" { // OpenCart 2/3: salted triple SHA1
		salt, err := randomPassword(9)
		if err != nil {
			return nil, err
		}
		h := func(s string) string { x := sha1.Sum([]byte(s)); return hex.EncodeToString(x[:]) }
		hash := h(salt + h(salt+h(pw)))
		qh, _ := quoteMySQL(hash)
		qs, _ := quoteMySQL(salt)
		stmt = fmt.Sprintf("UPDATE %s SET password=%s, salt=%s WHERE username=%s", table, qh, qs, user)
	} else { // OpenCart 4: password_hash (bcrypt)
		hb, err := bcrypt.GenerateFromPassword([]byte(pw), 10)
		if err != nil {
			return nil, err
		}
		qh, _ := quoteMySQL(strings.Replace(string(hb), "$2a$", "$2y$", 1))
		stmt = fmt.Sprintf("UPDATE %s SET password=%s WHERE username=%s", table, qh, user)
	}
	r, err := c.Query(ctx, stmt)
	if err != nil {
		return nil, err
	}
	if r.Affected != 1 {
		return nil, fmt.Errorf("expected to update exactly one admin row, updated %d", r.Affected)
	}
	return Output{"username": a.user, "password": pw, "secret": "password"}, nil
}

func (sqlQuery) Verify(context.Context, *Env, Params) error { return nil }
