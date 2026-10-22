package actions

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// sql.query with engine mssql (called from sqlQuery.Plan/Apply).

var (
	mssqlReadRe      = regexp.MustCompile(`(?is)^\s*(select|with)\b`)
	mssqlForbidden   = regexp.MustCompile(`(?is)\b(xp_cmdshell|xp_regwrite|xp_regdeletekey|xp_dirtree|xp_fileexist|sp_oacreate|sp_oamethod|sp_addlinkedserver|sp_addlinkedsrvlogin|sp_addsrvrolemember|openrowset|opendatasource|bulk\s+insert|shutdown|drop\s+database|truncate|waitfor|backup|restore|dbcc|kill)\b`)
	mssqlConfigRe    = regexp.MustCompile(`(?is)\bsp_configure\b`)
	mssqlIntoRe      = regexp.MustCompile(`(?is)\binto\b`)
	mssqlUpdDelRe    = regexp.MustCompile(`(?is)^\s*(update|delete)\b`)
	mssqlAccountDDL  = regexp.MustCompile(`(?is)^\s*(alter|drop|create)\s+login\s+(\[(?:[^\]]|\]\])+\]|'(?:[^']|'')+'|[^\s;]+)(.*)$`)
	mssqlRoleMemberR = regexp.MustCompile(`(?is)^\s*alter\s+server\s+role\s+\S+\s+(?:add|drop)\s+member\s+(\[(?:[^\]]|\]\])+\]|[^\s;]+)`)
)

// stripMSSQLQuoted blanks '...', "..." and [...] so keyword scans ignore them.
func stripMSSQLQuoted(s string) string {
	b := []byte(s)
	var q byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case q != 0:
			end := q
			if q == '[' {
				end = ']'
			}
			if c == end {
				if i+1 < len(b) && b[i+1] == end { // doubled delimiter
					b[i], b[i+1] = ' ', ' '
					i++
					continue
				}
				q = 0
			}
			b[i] = ' '
		case c == '\'' || c == '"' || c == '[':
			q = c
			b[i] = ' '
		}
	}
	return string(b)
}

func unquoteMSSQLName(s string) string {
	switch {
	case strings.HasPrefix(s, "["):
		return strings.ReplaceAll(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"), "]]", "]")
	case strings.HasPrefix(s, "'"):
		return strings.ReplaceAll(strings.Trim(s, "'"), "''", "'")
	}
	return s
}

// bindMSSQL turns ? placeholders (outside quotes) into @p1.. and returns the
// driver args.
func bindMSSQL(st string, args []string) (string, []any, error) {
	masked := stripMSSQLQuoted(st)
	var b strings.Builder
	n := 0
	for i := 0; i < len(st); i++ {
		if masked[i] == '?' && st[i] == '?' {
			n++
			b.WriteString("@p" + strconv.Itoa(n))
			continue
		}
		b.WriteByte(st[i])
	}
	if n != len(args) {
		return "", nil, fmt.Errorf("statement has %d placeholders but %d args", n, len(args))
	}
	out := make([]any, len(args))
	for i, a := range args {
		out[i] = a
	}
	return b.String(), out, nil
}

// mssqlCheckRaw validates a raw statement and runs the scoring guard on the
// logins it names.
func mssqlCheckRaw(ctx context.Context, env *Env, p Params) (string, []any, error) {
	st := strings.TrimSpace(p.Str("statement"))
	st = strings.TrimSpace(strings.TrimSuffix(st, ";"))
	m := stripMSSQLQuoted(st)
	if strings.Contains(m, ";") {
		return "", nil, errors.New("exactly one statement is allowed")
	}
	if strings.Contains(m, "--") || strings.Contains(m, "/*") {
		return "", nil, errors.New("comments are not allowed in a statement")
	}
	if mssqlConfigRe.MatchString(m) {
		return "", nil, errors.New("sp_configure is not accepted here; use mssql.lock (reversible, scoring-guard aware)")
	}
	if mssqlForbidden.MatchString(m) {
		return "", nil, errors.New("statement uses a forbidden construct (OS access, linked-server or role changes by procedure, DROP DATABASE, SHUTDOWN, ...)")
	}
	read := mssqlReadRe.MatchString(st)
	if read && mssqlIntoRe.MatchString(m) {
		return "", nil, errors.New("SELECT ... INTO is a write; use write=true with INSERT")
	}
	if !read && !p.Bool("write") {
		return "", nil, errors.New("write statements need write=true")
	}
	if mssqlUpdDelRe.MatchString(st) && !regexp.MustCompile(`(?is)\bwhere\b`).MatchString(m) {
		return "", nil, errors.New("UPDATE/DELETE without WHERE is refused")
	}
	g := env.guard()
	if am := mssqlAccountDDL.FindStringSubmatch(st); am != nil {
		name := unquoteMSSQLName(am[2])
		rest := strings.ToLower(stripMSSQLQuoted(am[3]))
		op := OpModify
		switch strings.ToLower(am[1]) {
		case "drop":
			op = OpDelete
		case "alter":
			switch {
			case strings.Contains(rest, "disable"):
				op = OpLock
			case strings.Contains(rest, "password"):
				op = OpSetPassword
			case regexp.MustCompile(`\bname\s*=`).MatchString(rest):
				op = OpRename
			}
		}
		if err := g.Allow(ctx, Touch{Kind: TouchAccount, Name: name, Op: op}); err != nil {
			return "", nil, err
		}
	}
	if rm := mssqlRoleMemberR.FindStringSubmatch(st); rm != nil {
		name := unquoteMSSQLName(rm[1])
		op := OpModify
		if regexp.MustCompile(`(?is)\bdrop\s+member\b`).MatchString(m) {
			op = OpRemoveFromGroup
		}
		if err := g.Allow(ctx, Touch{Kind: TouchAccount, Name: name, Op: op, Group: "sysadmin"}); err != nil {
			return "", nil, err
		}
	}
	bound, args, err := bindMSSQL(st, p.List("args"))
	return bound, args, err
}

func mssqlQueryPlan(ctx context.Context, env *Env, p Params) (Plan, error) {
	st := p.Str("statement")
	if namedStmtRe.MatchString(st) {
		if _, ok := mssqlNamed[st]; !ok {
			return Plan{}, fmt.Errorf("unknown mssql named statement %q (known: %s)", st, strings.Join(mssqlNamedList(), ", "))
		}
		return Plan{Diff: "read-only named statement " + st}, nil
	}
	bound, _, err := mssqlCheckRaw(ctx, env, p)
	if err != nil {
		return Plan{}, err
	}
	if mssqlReadRe.MatchString(bound) {
		return Plan{Diff: "read-only: " + bound}, nil
	}
	return Plan{Diff: "execute: " + bound, Notes: []string{"SQL changes are not rolled back automatically"}}, nil
}

func mssqlQueryApply(ctx context.Context, env *Env, p Params) (Output, error) {
	st := p.Str("statement")
	named := namedStmtRe.MatchString(st)
	var bound string
	var args []any
	if !named {
		var err error
		if bound, args, err = mssqlCheckRaw(ctx, env, p); err != nil {
			return nil, err
		}
	} else if _, ok := mssqlNamed[st]; !ok {
		return nil, fmt.Errorf("unknown mssql named statement %q", st)
	}
	c, _, err := mssqlConnect(ctx, p)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if named {
		return mssqlRunNamed(ctx, c, env, st)
	}
	if !mssqlReadRe.MatchString(bound) {
		n, err := c.Exec(ctx, bound, args...)
		if err != nil {
			return nil, err
		}
		return Output{"affected": fmt.Sprint(n), "rows": "0"}, nil
	}
	r, err := c.Query(ctx, bound, args...)
	if err != nil {
		return nil, err
	}
	out := Output{"affected": "0", "rows": fmt.Sprint(len(r.Rows))}
	if len(r.Rows) > 0 {
		out["result"] = renderMSSQL(r)
	}
	return out, nil
}
