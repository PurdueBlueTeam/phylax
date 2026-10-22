package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// fakeMSSQL is an in-memory model of the server state the actions read and
// change. It answers the exact statement texts the actions send and parses
// the few write statements they issue, so the tests check the real code
// paths (planning, guard, rollback data, undo) against a stateful server.
type fakeMSSQL struct {
	mu        sync.Mutex
	self      string
	selfAdmin bool
	pv        string
	cfg       map[string]int
	logins    []mssqlPrincipal
	sysadmins []string
	linked    [][]string
	jobs      [][]string
	startup   []string
	trust     [][]string
	triggers  [][]string
	noMsdb    bool
	execs     []string
	dials     []MSSQLTarget
}

func newFakeMSSQL() *fakeMSSQL {
	return &fakeMSSQL{self: "SVC\\phylax", selfAdmin: true, pv: "15.0.4430.1",
		cfg: map[string]int{"xp_cmdshell": 1, "Ole Automation Procedures": 1, "clr enabled": 1, "clr strict security": 1,
			"external scripts enabled": 0, "Ad Hoc Distributed Queries": 0, "show advanced options": 0,
			"scan for startup procs": 0, "cross db ownership chaining": 0, "remote access": 1, "Database Mail XPs": 0, "Agent XPs": 1},
		logins: []mssqlPrincipal{
			{Name: "SVC\\phylax", Type: "U"}, {Name: "NT SERVICE\\MSSQLSERVER", Type: "U"},
			{Name: "quotient", Type: "S", PolicyChk: 1}, {Name: "sa", Type: "S", PolicyChk: 1, NamePW: false},
			{Name: "backup", Type: "S", PolicyChk: 0, BlankPW: true}, {Name: "bob", Type: "S", PolicyChk: 1, NamePW: true},
			{Name: "carol", Type: "S", PolicyChk: 1}},
		sysadmins: []string{"sa", "SVC\\phylax", "NT SERVICE\\MSSQLSERVER", "quotient", "bob"},
		linked:    [][]string{{"REMOTE1", "SQL Server", "SQLNCLI", "10.0.0.9", "1", "1", "*->sa"}},
		jobs:      [][]string{{"nightly", "bob", "1", "1", "CmdExec", "master", "powershell -enc AAAA"}, {"backup", "sa", "1", "1", "TSQL", "master", "BACKUP DATABASE x"}},
		startup:   []string{"sp_evil"},
		trust:     [][]string{{"appdb", "bob", "1"}},
		triggers:  [][]string{{"trg_logon", "0", "CREATE TRIGGER trg_logon ON ALL SERVER FOR LOGON AS ..."}},
	}
}

func (f *fakeMSSQL) Dial(_ context.Context, t MSSQLTarget) (MSSQLConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dials = append(f.dials, t)
	return f, nil
}
func (f *fakeMSSQL) Close() error { return nil }

func b01(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func (f *fakeMSSQL) isAdmin(n string) bool {
	for _, s := range f.sysadmins {
		if strings.EqualFold(s, n) {
			return true
		}
	}
	return false
}

func (f *fakeMSSQL) Query(_ context.Context, q string, _ ...any) (*MSSQLResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch q {
	case mssqlSelfSQL:
		return &MSSQLResult{Columns: []string{"a", "b"}, Rows: [][]string{{f.self, b01(f.selfAdmin && f.isAdmin(f.self))}}}, nil
	case mssqlVersionSQL:
		return &MSSQLResult{Columns: []string{"version", "pv", "pl", "ul", "ed", "wa"},
			Rows: [][]string{{"Microsoft SQL Server 2019 (RTM-CU)", f.pv, "RTM", "CU18", "Standard", "0"}}}, nil
	case mssqlLoginsSQL:
		r := &MSSQLResult{Columns: []string{"name", "type", "dis", "pc", "ec", "blank", "samename"}}
		for _, l := range f.logins {
			bp, np := "0", "0"
			if l.Type != "S" {
				bp, np = "-1", "-1"
			} else {
				bp, np = b01(l.BlankPW), b01(l.NamePW)
			}
			r.Rows = append(r.Rows, []string{l.Name, l.Type, b01(l.Disabled), fmt.Sprint(l.PolicyChk), "0", bp, np})
		}
		return r, nil
	case mssqlSysadminsSQL:
		r := &MSSQLResult{Columns: []string{"name", "type", "dis"}}
		for _, s := range f.sysadmins {
			t, d := "S", "0"
			for _, l := range f.logins {
				if l.Name == s {
					t, d = l.Type, b01(l.Disabled)
				}
			}
			r.Rows = append(r.Rows, []string{s, t, d})
		}
		return r, nil
	case mssqlConfigSQL:
		r := &MSSQLResult{Columns: []string{"name", "use", "val"}}
		for k, v := range f.cfg {
			r.Rows = append(r.Rows, []string{k, fmt.Sprint(v), fmt.Sprint(v)})
		}
		return r, nil
	case mssqlLinkedSQL:
		return &MSSQLResult{Columns: []string{"1", "2", "3", "4", "5", "6", "7"}, Rows: f.linked}, nil
	case mssqlJobsSQL:
		if f.noMsdb {
			return nil, errors.New("Invalid object name 'msdb.dbo.sysjobs'")
		}
		return &MSSQLResult{Columns: []string{"1", "2", "3", "4", "5", "6", "7"}, Rows: f.jobs}, nil
	case mssqlStartupSQL:
		r := &MSSQLResult{Columns: []string{"name"}}
		for _, s := range f.startup {
			r.Rows = append(r.Rows, []string{s})
		}
		return r, nil
	case mssqlTrustSQL:
		return &MSSQLResult{Columns: []string{"1", "2", "3"}, Rows: f.trust}, nil
	case mssqlTriggersSQL:
		return &MSSQLResult{Columns: []string{"1", "2", "3"}, Rows: f.triggers}, nil
	}
	if strings.HasPrefix(q, "SELECT 1 AS") || strings.HasPrefix(q, "SELECT '") || strings.Contains(q, "@p1") {
		return &MSSQLResult{Columns: []string{"x"}, Rows: [][]string{{"1"}}}, nil
	}
	return nil, fmt.Errorf("fake: unexpected query %q", q)
}

var (
	reCfg   = regexp.MustCompile(`^EXEC sp_configure N'([^']+)', (\d); RECONFIGURE WITH OVERRIDE$`)
	reLogin = regexp.MustCompile(`^ALTER LOGIN \[([^\]]+)\] (ENABLE|DISABLE)$`)
	reRole  = regexp.MustCompile(`^IF IS_SRVROLEMEMBER\('sysadmin', N'([^']+)'\) = ([01]) ALTER SERVER ROLE \[sysadmin\] (ADD|DROP) MEMBER \[([^\]]+)\]$`)
)

func (f *fakeMSSQL) Exec(_ context.Context, q string, _ ...any) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, q)
	if m := reCfg.FindStringSubmatch(q); m != nil {
		if _, ok := f.cfg[m[1]]; !ok {
			return 0, errors.New("unknown option")
		}
		if m[1] != "show advanced options" && f.cfg["show advanced options"] == 0 && m[1] != "clr enabled" && m[1] != "external scripts enabled" {
			return 0, errors.New("advanced option needs 'show advanced options'")
		}
		f.cfg[m[1]] = int(m[2][0] - '0')
		return 0, nil
	}
	if m := reLogin.FindStringSubmatch(q); m != nil {
		for i := range f.logins {
			if f.logins[i].Name == m[1] {
				f.logins[i].Disabled = m[2] == "DISABLE"
				return 0, nil
			}
		}
		return 0, errors.New("no such login")
	}
	if m := reRole.FindStringSubmatch(q); m != nil {
		in := f.isAdmin(m[1])
		switch {
		case m[3] == "DROP" && in:
			var n []string
			for _, s := range f.sysadmins {
				if !strings.EqualFold(s, m[1]) {
					n = append(n, s)
				}
			}
			f.sysadmins = n
		case m[3] == "ADD" && !in:
			f.sysadmins = append(f.sysadmins, m[1])
		}
		return 0, nil
	}
	if strings.HasPrefix(q, "UPDATE") || strings.HasPrefix(q, "ALTER LOGIN") {
		return 1, nil
	}
	return 0, fmt.Errorf("fake: unexpected exec %q", q)
}

func (f *fakeMSSQL) install(t *testing.T) {
	t.Helper()
	SetMSSQLConfig(MSSQLConfig{Dialer: f, Auth: func(context.Context) (string, string, error) { return "", "", nil }})
	t.Cleanup(func() { SetMSSQLConfig(MSSQLConfig{}) })
}

func hasFinding(o Output, sub string) bool { return strings.Contains(o["findings"], sub) }

func TestMSSQLAudit(t *testing.T) {
	fk := newFakeMSSQL()
	fk.install(t)
	f := newFixture(t)
	o := f.ok(t, "mssql.audit", nil).Output
	for _, want := range []string{
		"critical config: xp_cmdshell is enabled", "critical config: Ole Automation", "warning config: CLR is enabled",
		"critical backup: blank password", "critical bob: password equals the login name",
		"warning bob: member of sysadmin", "warning quotient: member of sysadmin",
		"warning REMOTE1: linked server with RPC out", "job nightly: step 1 runs CmdExec as bob",
		"warning master.sp_evil: startup procedure", "critical appdb: TRUSTWORTHY is on (owner bob)",
		"warning trg_logon: server-level trigger", "below the fixed builds",
	} {
		if !hasFinding(o, want) {
			t.Errorf("missing finding %q in:\n%s", want, o["findings"])
		}
	}
	if hasFinding(o, "NT SERVICE") || hasFinding(o, "SVC\\phylax: member") {
		t.Errorf("system/own principals must not be flagged:\n%s", o["findings"])
	}
	if o["critical"] != "5" || o["connected_as"] != "SVC\\phylax" || o["server_version"] != "15.0.4430.1" {
		t.Errorf("summary %v", o)
	}
	if _, err := f.run(t, "mssql.audit", map[string]any{"fail_on_critical": true}); err == nil {
		t.Error("fail_on_critical must fail")
	}
	// no msdb (Express): audit still works and says so
	fk.noMsdb = true
	o = f.ok(t, "mssql.audit", nil).Output
	if o["agent_jobs_error"] == "" {
		t.Error("msdb error not reported")
	}
	// fixed build is not flagged
	fk.pv = "15.0.4490.9"
	if o = f.ok(t, "mssql.audit", nil).Output; hasFinding(o, "below the fixed builds") {
		t.Error("fixed build flagged")
	}
	fk.pv = "15.0.2190.7"
	if o = f.ok(t, "mssql.audit", nil).Output; hasFinding(o, "below the fixed builds") {
		t.Error("fixed GDR build flagged")
	}
	fk.pv = "15.0.2000.5"
	if o = f.ok(t, "mssql.audit", nil).Output; !hasFinding(o, "below the fixed builds") {
		t.Error("RTM GDR build not flagged")
	}
	// the server param is loopback only
	if _, err := f.run(t, "mssql.audit", map[string]any{"server": "10.1.1.1"}); err == nil {
		t.Error("remote server accepted")
	}
}

func TestMSSQLTargetAuth(t *testing.T) {
	fk := newFakeMSSQL()
	SetMSSQLConfig(MSSQLConfig{Dialer: fk, Auth: func(context.Context) (string, string, error) { return "phylax", "vault-pw", nil }})
	defer SetMSSQLConfig(MSSQLConfig{})
	f := newFixture(t)
	f.ok(t, "mssql.audit", map[string]any{"port": 14330})
	got := fk.dials[0]
	if got.User != "phylax" || got.Password != "vault-pw" || got.Integrated || got.Port != 14330 || got.Server != "localhost" {
		t.Fatalf("%+v", got)
	}
	SetMSSQLConfig(MSSQLConfig{Auth: func(context.Context) (string, string, error) { return "", "", errors.New("vault sealed") }, Dialer: fk})
	if _, err := f.run(t, "mssql.audit", nil); err == nil || !strings.Contains(err.Error(), "vault sealed") {
		t.Fatalf("%v", err)
	}
}

func TestMSSQLSQLQueryNamedAndRaw(t *testing.T) {
	fk := newFakeMSSQL()
	fk.install(t)
	f := newFixture(t)
	q := func(st string, extra ...map[string]any) (*Outcome, error) {
		p := map[string]any{"engine": "mssql", "statement": st}
		for _, e := range extra {
			for k, v := range e {
				p[k] = v
			}
		}
		return f.run(t, "sql.query", p)
	}
	o, err := q("version")
	if err != nil || o.Output["product_version"] != "15.0.4430.1" {
		t.Fatalf("%v %v", o, err)
	}
	o, err = q("review_sysadmins")
	if err != nil || !strings.Contains(o.Output["result"], "quotient") || o.Output["rows"] != "5" {
		t.Fatalf("%v %v", o, err)
	}
	o, err = q("weak_logins")
	if err != nil || o.Output["rows"] != "2" || strings.Contains(o.Output["result"], "carol") {
		t.Fatalf("weak logins: %v %v", o.Output, err)
	}
	o, err = q("review_linked_servers_and_agent_jobs")
	if err != nil || !strings.Contains(o.Output["result"], "REMOTE1") || !strings.Contains(o.Output["result"], "nightly") {
		t.Fatalf("%v %v", o, err)
	}
	if _, err = q("audit"); err != nil {
		t.Fatal(err)
	}
	if _, err = q("nope_nope"); err == nil || !strings.Contains(err.Error(), "unknown mssql named") {
		t.Fatalf("%v", err)
	}
	// raw: read ok, with ? binding; writes need write=true; dangerous constructs refused
	if o, err = q("SELECT 1 AS x WHERE 1 = ?", map[string]any{"args": []string{"1"}}); err != nil || o.Output["rows"] != "1" {
		t.Fatalf("%v %v", o, err)
	}
	for _, bad := range []string{
		"SELECT 1; SELECT 2", "EXEC sp_configure 'xp_cmdshell',1", "EXEC xp_cmdshell 'dir'", "SELECT 1 -- x", "SELECT * INTO t FROM sys.objects",
		"UPDATE t SET a=1", "SELECT * FROM OPENROWSET('a','b','c')", "SHUTDOWN", "UPDATE t SET a=1 WHERE id=1",
	} {
		if _, err := q(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := q("UPDATE t SET a=1 WHERE id=1", map[string]any{"write": true}); err != nil {
		t.Errorf("write: %v", err)
	}
	if _, err := q("SELECT '--' AS a, ';' AS b, '?' AS c"); err != nil {
		t.Errorf("quoted literals: %v", err)
	}
	if _, err := q("SELECT 1 AS x WHERE 1 = ?"); err == nil {
		t.Error("missing arg accepted")
	}
	// scoring guard on login statements
	f.env.Guard = StaticGuard{Accounts: []string{"quotient"}, Groups: []string{"sysadmin"}}
	for _, st := range []string{"ALTER LOGIN [quotient] DISABLE", "DROP LOGIN quotient", "ALTER LOGIN quotient WITH PASSWORD='x'",
		"ALTER LOGIN [quotient] WITH NAME=[q2]", "ALTER SERVER ROLE sysadmin DROP MEMBER [quotient]"} {
		if _, err := q(st, map[string]any{"write": true}); !errors.Is(err, ErrScoringUnsafe) {
			t.Errorf("%s: %v", st, err)
		}
	}
	if _, err := q("ALTER LOGIN [carol] WITH PASSWORD='x'", map[string]any{"write": true}); err != nil {
		t.Errorf("unscored login: %v", err)
	}
}

func lockParams(extra map[string]any) map[string]any {
	p := map[string]any{}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func TestMSSQLLockFeaturesAndRollback(t *testing.T) {
	fk := newFakeMSSQL()
	fk.install(t)
	f := newFixture(t)
	o := f.ok(t, "mssql.lock", nil)
	if fk.cfg["xp_cmdshell"] != 0 || fk.cfg["Ole Automation Procedures"] != 0 || fk.cfg["clr enabled"] != 0 {
		t.Fatalf("features not off: %v", fk.cfg)
	}
	if fk.cfg["show advanced options"] != 0 {
		t.Fatal("show advanced options must be restored")
	}
	if fk.cfg["remote access"] != 1 || fk.cfg["external scripts enabled"] != 0 {
		t.Fatal("unrelated options changed")
	}
	if o.DeadmanID == "" {
		t.Fatal("lock must arm a dead-man rollback")
	}
	// idempotent: second run has nothing to do
	if o2 := f.ok(t, "mssql.lock", nil); o2.Changed {
		t.Fatal("second run changed something")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if fk.cfg["xp_cmdshell"] != 1 || fk.cfg["Ole Automation Procedures"] != 1 || fk.cfg["clr enabled"] != 1 || fk.cfg["show advanced options"] != 0 {
		t.Fatalf("rollback did not restore: %v", fk.cfg)
	}
	if _, err := f.run(t, "mssql.lock", map[string]any{"features": []string{"bogus"}}); err == nil {
		t.Fatal("unknown feature accepted")
	}
	// a feature the audit already found off is left alone and not "restored"
	fk.cfg["clr enabled"] = 0
	o = f.ok(t, "mssql.lock", map[string]any{"features": []string{"clr"}})
	if o.Changed {
		t.Fatal("clr already off")
	}
}

func TestMSSQLLockLoginsAndSysadmins(t *testing.T) {
	fk := newFakeMSSQL()
	fk.install(t)
	f := newFixture(t)
	f.env.Guard = StaticGuard{Accounts: []string{"quotient"}, Groups: []string{"sysadmin"}}

	// explicit targets: scored, self and system principals are refusals
	for name, p := range map[string]map[string]any{
		"scored login":  {"disable_logins": []string{"quotient"}},
		"self login":    {"disable_logins": []string{"SVC\\phylax"}},
		"system login":  {"disable_logins": []string{"NT SERVICE\\MSSQLSERVER"}},
		"scored admin":  {"remove_sysadmins": []string{"quotient"}},
		"self admin":    {"remove_sysadmins": []string{"svc\\phylax"}},
		"service admin": {"remove_sysadmins": []string{"NT SERVICE\\MSSQLSERVER"}},
		"sa":            {"remove_sysadmins": []string{"sa"}},
		"unknown login": {"disable_logins": []string{"ghost"}},
	} {
		p["features"] = []string{"external_scripts"}
		if _, err := f.run(t, "mssql.lock", p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(fk.execs) != 0 {
		t.Fatalf("refused runs must not execute anything: %v", fk.execs)
	}

	o := f.ok(t, "mssql.lock", map[string]any{"features": []string{"external_scripts"}, "disable_logins": []string{"bob", "backup"}, "remove_sysadmins": []string{"bob"}})
	if !fk.logins[5].Disabled || !fk.logins[4].Disabled || fk.isAdmin("bob") {
		t.Fatalf("not applied: %+v %v", fk.logins, fk.sysadmins)
	}
	if fk.logins[2].Disabled || !fk.isAdmin("quotient") {
		t.Fatal("scored login touched")
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if fk.logins[5].Disabled || fk.logins[4].Disabled || !fk.isAdmin("bob") {
		t.Fatalf("rollback: %+v %v", fk.logins, fk.sysadmins)
	}

	// sweeps need a real guard
	f.env.Guard = AllowAll{}
	if _, err := f.run(t, "mssql.lock", map[string]any{"disable_unscored": true}); err == nil || !strings.Contains(err.Error(), "scoring guard") {
		t.Fatalf("sweep without guard: %v", err)
	}
	f.env.Guard = StaticGuard{Accounts: []string{"quotient"}, Groups: []string{"sysadmin"}}
	o = f.ok(t, "mssql.lock", map[string]any{"features": []string{"external_scripts"}, "disable_unscored": true, "sysadmin_sweep": true, "keep": []string{"carol"}})
	for _, l := range fk.logins {
		want := l.Name == "sa" || l.Name == "backup" || l.Name == "bob"
		if l.Disabled != want {
			t.Errorf("login %s disabled=%v want %v", l.Name, l.Disabled, want)
		}
	}
	if got := strings.Join(fk.sysadmins, ","); got != "sa,SVC\\phylax,NT SERVICE\\MSSQLSERVER,quotient" {
		t.Fatalf("sysadmins after sweep: %s", got)
	}
	if !strings.Contains(o.Output["skipped"], "quotient") && !strings.Contains(o.Output["skipped"], "scor") {
		t.Fatalf("skipped note: %q", o.Output["skipped"])
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	for _, l := range fk.logins {
		if l.Disabled {
			t.Errorf("%s still disabled after rollback", l.Name)
		}
	}
	if !fk.isAdmin("bob") || !fk.isAdmin("sa") || len(fk.sysadmins) != 5 {
		t.Fatalf("sysadmins after rollback: %v", fk.sysadmins)
	}
}

func TestMSSQLLockRefusesWithoutSysadmin(t *testing.T) {
	fk := newFakeMSSQL()
	fk.selfAdmin = false
	fk.install(t)
	f := newFixture(t)
	if _, err := f.run(t, "mssql.lock", map[string]any{"features": []string{"external_scripts"}, "remove_sysadmins": []string{"bob"}}); err == nil {
		t.Fatal("role change without sysadmin accepted")
	}
}

// Real-server test, gated: PHYLAX_MSSQL_DSN is "user:password@host:port"
// (a throwaway test server; the audit is read-only).
func TestMSSQLRealServer(t *testing.T) {
	dsn := os.Getenv("PHYLAX_MSSQL_DSN")
	if dsn == "" {
		t.Skip("PHYLAX_MSSQL_DSN not set (user:password@host:port of a disposable SQL Server)")
	}
	at := strings.LastIndex(dsn, "@")
	if at < 0 || !strings.Contains(dsn[:at], ":") || !strings.Contains(dsn[at+1:], ":") {
		t.Fatal("PHYLAX_MSSQL_DSN must look like user:password@host:port")
	}
	cred, hp := dsn[:at], dsn[at+1:]
	user, pw, _ := strings.Cut(cred, ":")
	host, port, _ := strings.Cut(hp, ":")
	if !mssqlLoopback(host) {
		t.Skipf("host %q is not loopback; the actions only connect locally", host)
	}
	SetMSSQLConfig(MSSQLConfig{Auth: func(context.Context) (string, string, error) { return user, pw, nil }})
	defer SetMSSQLConfig(MSSQLConfig{})
	f := newFixture(t)
	var n int
	fmt.Sscan(port, &n)
	o := f.ok(t, "mssql.audit", map[string]any{"server": host, "port": n}).Output
	if o["server_version"] == "" || o["connected_as"] == "" {
		t.Fatalf("%v", o)
	}
	if _, err := f.run(t, "sql.query", map[string]any{"engine": "mssql", "statement": "version", "server": host, "port": n}); err != nil {
		t.Fatal(err)
	}
}
