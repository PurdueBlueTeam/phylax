package actions

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// fakeMySQL is a MySQL protocol server on a unix socket: handshake with
// native / caching_sha2 / auth_socket, COM_QUERY with text result sets.
type fakeMySQL struct {
	t        *testing.T
	sock     string
	ln       net.Listener
	plugin   string // mysql_native_password | caching_sha2_password | caching_sha2_full | auth_socket
	password string
	mu       sync.Mutex
	queries  []string
	users    []fakeDBUser
	version  string
	handler  func(sql string) (cols []string, rows [][]string, affected uint64, err error, handled bool)
	infile   bool
}

type fakeDBUser struct {
	user, host, plugin string
	emptyPW            bool
	locked, super      bool
}

func newFakeMySQL(t *testing.T, plugin, password string) *fakeMySQL {
	t.Helper()
	dir, err := os.MkdirTemp("", "my")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	m := &fakeMySQL{t: t, sock: filepath.Join(dir, "m.sock"), plugin: plugin, password: password, version: "8.0.36"}
	m.ln, err = net.Listen("unix", m.sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.ln.Close() })
	go func() {
		for {
			c, err := m.ln.Accept()
			if err != nil {
				return
			}
			go m.serve(c)
		}
	}()
	return m
}

func (m *fakeMySQL) getVersion() string { m.mu.Lock(); defer m.mu.Unlock(); return m.version }
func (m *fakeMySQL) setVersion(v string) { m.mu.Lock(); m.version = v; m.mu.Unlock() }
func (m *fakeMySQL) setInfile()          { m.mu.Lock(); m.infile = true; m.mu.Unlock() }
func (m *fakeMySQL) isLocked(i int) bool { m.mu.Lock(); defer m.mu.Unlock(); return m.users[i].locked }

func (m *fakeMySQL) queryLog() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.queries...)
}

type srvConn struct {
	c   net.Conn
	seq byte
}

func (s *srvConn) read() ([]byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(s.c, h[:]); err != nil {
		return nil, err
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	s.seq = h[3] + 1
	b := make([]byte, n)
	_, err := io.ReadFull(s.c, b)
	return b, err
}
func (s *srvConn) write(p []byte) {
	h := []byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), s.seq}
	s.seq++
	_, _ = s.c.Write(append(h, p...))
}
func lenencS(s string) []byte {
	if s == MySQLNull {
		return []byte{0xfb}
	}
	return append([]byte{byte(len(s))}, s...) // test strings are < 251 bytes
}
func okPacket(affected uint64) []byte { return []byte{0, byte(affected), 0, 2, 0, 0, 0} }
func errPacket(code uint16, msg string) []byte {
	b := []byte{0xff, byte(code), byte(code >> 8), '#'}
	return append(append(b, "HY000"...), msg...)
}

func (m *fakeMySQL) serve(c net.Conn) {
	defer c.Close()
	s := &srvConn{c: c}
	salt := []byte("abcdefgh" + "ijklmnopqrst")
	var g bytes.Buffer
	g.WriteByte(10)
	g.WriteString(m.getVersion() + "\x00")
	g.Write([]byte{1, 0, 0, 0})
	g.Write(salt[:8])
	g.WriteByte(0)
	_ = binary.Write(&g, binary.LittleEndian, uint16(0x8000|0x0200|0x0001))
	g.WriteByte(45)
	g.Write([]byte{2, 0})
	_ = binary.Write(&g, binary.LittleEndian, uint16(0x0008))
	g.WriteByte(21)
	g.Write(make([]byte, 10))
	g.Write(salt[8:])
	g.WriteByte(0)
	greetPlugin := m.plugin
	if strings.HasPrefix(greetPlugin, "caching_sha2") {
		greetPlugin = "caching_sha2_password"
	}
	g.WriteString(greetPlugin + "\x00")
	s.write(g.Bytes())
	resp, err := s.read()
	if err != nil {
		return
	}
	rest := resp[4+4+1+23:]
	i := bytes.IndexByte(rest, 0)
	rest = rest[i+1:]
	alen := int(rest[0])
	auth := rest[1 : 1+alen]
	switch m.plugin {
	case "mysql_native_password", "caching_sha2_password":
		want, _ := scramble(m.plugin, m.password, salt)
		if !bytes.Equal(auth, want) {
			s.write(errPacket(1045, "Access denied"))
			return
		}
		if m.plugin == "caching_sha2_password" && m.password != "" {
			s.write([]byte{1, 3}) // fast auth success
		}
		s.write(okPacket(0))
	case "caching_sha2_full":
		s.write([]byte{1, 4})
		pw, err := s.read()
		if err != nil || string(bytes.TrimRight(pw, "\x00")) != m.password {
			s.write(errPacket(1045, "Access denied"))
			return
		}
		s.write(okPacket(0))
	case "auth_socket":
		s.write(okPacket(0))
	}
	for {
		s.seq = 0
		p, err := s.read()
		if err != nil {
			return
		}
		switch p[0] {
		case 0x01:
			return
		case 0x03:
			m.mu.Lock()
			sql := string(p[1:])
			m.queries = append(m.queries, sql)
			m.mu.Unlock()
			m.answer(s, sql)
		}
	}
}

func (m *fakeMySQL) answer(s *srvConn, sql string) {
	m.mu.Lock()
	infile := m.infile
	m.mu.Unlock()
	if infile {
		s.write([]byte{0xfb, 'f'})
		return
	}
	cols, rows, aff, err, handled := []string(nil), [][]string(nil), uint64(0), error(nil), false
	if m.handler != nil {
		cols, rows, aff, err, handled = m.handler(sql)
	}
	if !handled {
		cols, rows, aff, err = m.builtin(sql)
	}
	if err != nil {
		s.write(errPacket(1064, err.Error()))
		return
	}
	if cols == nil {
		s.write(okPacket(aff))
		return
	}
	s.write([]byte{byte(len(cols))})
	for _, c := range cols {
		var d bytes.Buffer
		for _, f := range []string{"def", "", "", "", c, c} {
			d.Write(lenencS(f))
		}
		d.Write([]byte{0x0c, 45, 0, 0, 0, 0, 0xfd, 0, 0, 0, 0, 0})
		s.write(d.Bytes())
	}
	s.write([]byte{0xfe, 0, 0, 2, 0})
	for _, r := range rows {
		var b bytes.Buffer
		for _, v := range r {
			b.Write(lenencS(v))
		}
		s.write(b.Bytes())
	}
	s.write([]byte{0xfe, 0, 0, 2, 0})
}

var alterRe = regexp.MustCompile(`^ALTER USER '([^']*)'@'([^']*)' ACCOUNT (LOCK|UNLOCK)$`)

func (m *fakeMySQL) builtin(sql string) ([]string, [][]string, uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case strings.HasPrefix(sql, "SET SESSION sql_mode"):
		return nil, nil, 0, nil
	case sql == mysqlVersionSQL:
		return []string{"VERSION()"}, [][]string{{m.version}}, 0, nil
	case sql == mysqlUsersSQL || sql == mariaUsersSQL:
		var rows [][]string
		for _, u := range m.users {
			yn := func(b bool) string {
				if b {
					return "Y"
				}
				return "N"
			}
			lock := yn(u.locked)
			if sql == mariaUsersSQL {
				lock = map[bool]string{true: "true", false: "false"}[u.locked]
			}
			rows = append(rows, []string{u.user, u.host, u.plugin, map[bool]string{true: "1", false: "0"}[u.emptyPW], lock, yn(u.super)})
		}
		return []string{"User", "Host", "plugin", "empty_pw", "account_locked", "Super_priv"}, rows, 0, nil
	}
	if a := alterRe.FindStringSubmatch(sql); a != nil {
		for i := range m.users {
			if m.users[i].user == a[1] && m.users[i].host == a[2] {
				m.users[i].locked = a[3] == "LOCK"
				return nil, nil, 0, nil
			}
		}
		return nil, nil, 0, fmt.Errorf("Operation ALTER USER failed for '%s'@'%s'", a[1], a[2])
	}
	return nil, nil, 0, fmt.Errorf("fake: unsupported statement %q", sql)
}

func (m *fakeMySQL) setUsers(u []fakeDBUser) { m.mu.Lock(); m.users = u; m.mu.Unlock() }

func (f *fixture) withMySQL(t *testing.T, m *fakeMySQL) {
	t.Helper()
	f.linux(t) // real dialer against the fake server
	f.write(t, "run/mysqld/mysqld.sock", "", 0o600)
	_ = os.Remove(f.path("run/mysqld/mysqld.sock"))
	if err := os.Symlink(m.sock, f.path("run/mysqld/mysqld.sock")); err != nil {
		t.Fatal(err)
	}
}

func testUsers() []fakeDBUser {
	return []fakeDBUser{
		{user: "root", host: "localhost", plugin: "auth_socket", emptyPW: false, super: true},
		{user: "", host: "localhost", plugin: "mysql_native_password", emptyPW: true},
		{user: "oc", host: "localhost", plugin: "mysql_native_password"},
		{user: "backup", host: "%", plugin: "mysql_native_password", super: true},
		{user: "legacy", host: "10.0.0.5", plugin: "mysql_native_password", emptyPW: true},
		{user: "old", host: "localhost", plugin: "mysql_native_password", emptyPW: true, locked: true},
	}
}

func TestMySQLClientAuthVariants(t *testing.T) {
	for _, c := range []struct {
		name, plugin, srvPW, cliPW string
		wantErr                    bool
	}{
		{"native ok", "mysql_native_password", "s3cret", "s3cret", false},
		{"native empty", "mysql_native_password", "", "", false},
		{"native wrong", "mysql_native_password", "s3cret", "nope", true},
		{"sha2 fast", "caching_sha2_password", "s3cret", "s3cret", false},
		{"sha2 full over the socket", "caching_sha2_full", "s3cret", "s3cret", false},
		{"sha2 full wrong", "caching_sha2_full", "s3cret", "bad", true},
		{"auth_socket", "auth_socket", "", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := newFakeMySQL(t, c.plugin, c.srvPW)
			conn, err := unixMySQLDialer{}.Dial(t.Context(), MySQLTarget{Socket: m.sock, User: "root", Password: c.cliPW})
			if c.wantErr {
				if err == nil || !strings.Contains(err.Error(), "1045") {
					t.Fatalf("want access denied, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			r, err := conn.Query(t.Context(), mysqlVersionSQL)
			if err != nil || len(r.Rows) != 1 || r.Rows[0][0] != "8.0.36" {
				t.Fatalf("%+v %v", r, err)
			}
			if q := m.queryLog(); !strings.HasPrefix(q[0], "SET SESSION sql_mode") {
				t.Fatalf("connection setup: %v", q)
			}
		})
	}
}

func TestMySQLClientRefusesLocalInfile(t *testing.T) {
	m := newFakeMySQL(t, "auth_socket", "")
	conn, err := unixMySQLDialer{}.Dial(t.Context(), MySQLTarget{Socket: m.sock, User: "root"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	m.setInfile()
	if _, err := conn.Query(t.Context(), "SELECT 1"); err == nil || !strings.Contains(err.Error(), "LOCAL INFILE") {
		t.Fatalf("got %v", err)
	}
}

func TestMySQLQuoteAndBind(t *testing.T) {
	q, _ := quoteMySQL("o'brien\\\n")
	if q != `'o\'brien\\\n'` {
		t.Fatal(q)
	}
	if _, err := quoteMySQL("a\x00b"); err == nil {
		t.Fatal("NUL accepted")
	}
	s, err := bindMySQL("SELECT * FROM t WHERE a=? AND b='?' AND c=?", []string{"x'; DROP TABLE t; --", "7"})
	if err != nil || s != `SELECT * FROM t WHERE a='x\'; DROP TABLE t; --' AND b='?' AND c='7'` {
		t.Fatalf("%q %v", s, err)
	}
	if _, err := bindMySQL("SELECT ?", nil); err == nil {
		t.Fatal("missing arg accepted")
	}
	if _, err := bindMySQL("SELECT 1", []string{"x"}); err == nil {
		t.Fatal("extra arg accepted")
	}
}

func TestMySQLAudit(t *testing.T) {
	f := newFixture(t)
	m := newFakeMySQL(t, "auth_socket", "")
	m.setUsers(testUsers())
	f.withMySQL(t, m)
	o := f.ok(t, "mysql.audit", map[string]any{})
	for _, want := range []string{
		"critical ''@'localhost': anonymous account",
		"critical 'legacy'@'10.0.0.5': empty password",
		"critical 'backup'@'%': reachable from any host",
		"warning 'backup'@'%': has SUPER privilege",
	} {
		if !strings.Contains(o.Output["findings"], want) {
			t.Errorf("missing finding %q in:\n%s", want, o.Output["findings"])
		}
	}
	if strings.Contains(o.Output["findings"], "'old'") || strings.Contains(o.Output["findings"], "'root'") || strings.Contains(o.Output["findings"], "'oc'") {
		t.Errorf("locked, socket-auth and normal accounts must not be flagged:\n%s", o.Output["findings"])
	}
	if o.Output["server_version"] != "8.0.36" || o.Output["accounts"] != "6" {
		t.Fatalf("%v", o.Output)
	}
	// MariaDB uses the global_priv query
	m.setVersion("10.11.6-MariaDB")
	f.ok(t, "mysql.audit", map[string]any{})
	if q := m.queryLog(); !strings.Contains(q[len(q)-1], "global_priv") {
		t.Fatalf("mariadb query: %v", q[len(q)-1])
	}
	out, err := f.run(t, "mysql.audit", map[string]any{"fail_on_critical": true})
	if err == nil || out.Output["critical"] == "0" {
		t.Fatalf("fail_on_critical: %v %v", err, out)
	}
}

func TestMySQLLockAndRollback(t *testing.T) {
	f := newFixture(t)
	m := newFakeMySQL(t, "auth_socket", "")
	m.setUsers(testUsers())
	f.withMySQL(t, m)
	p := map[string]any{"user": "legacy", "host": "10.0.0.5"}
	o, err := f.run(t, "mysql.lock", p, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "locked false -> true") {
		t.Fatalf("dry run: %+v %v", o.Plan, err)
	}
	if m.isLocked(4) {
		t.Fatal("dry run locked")
	}
	o = f.ok(t, "mysql.lock", p)
	if !m.isLocked(4) || o.DeadmanID == "" {
		t.Fatalf("locked=%v deadman=%q (lockout class arms by default)", m.isLocked(4), o.DeadmanID)
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if m.isLocked(4) {
		t.Fatal("rollback did not unlock")
	}
	f.ok(t, "mysql.lock", p, func(r *Request) { r.Deadman = NoDeadman })
	if o := f.ok(t, "mysql.lock", p); !o.Plan.Done {
		t.Fatal("already locked should be Done")
	}
	// never the agent's own account, never a scored account, never an unknown one
	if err := f.refused(t, "mysql.lock", map[string]any{"user": "root"}); !strings.Contains(err.Error(), "agent connects as") {
		t.Fatalf("self lock: %v", err)
	}
	f.env.Guard = StaticGuard{Accounts: []string{"oc"}}
	if err := f.refused(t, "mysql.lock", map[string]any{"user": "oc"}); !errors.Is(err, ErrScoringUnsafe) {
		t.Fatalf("scored: %v", err)
	}
	if _, err := f.run(t, "mysql.lock", map[string]any{"user": "nobody"}); err == nil {
		t.Fatal("unknown account")
	}
	if _, err := f.run(t, "mysql.lock", map[string]any{"user": "x'; DROP USER 'root"}); err == nil {
		t.Fatal("injection accepted")
	}
}

func TestSQLQueryRules(t *testing.T) {
	f := newFixture(t)
	m := newFakeMySQL(t, "auth_socket", "")
	m.setUsers(testUsers())
	m.handler = func(sql string) ([]string, [][]string, uint64, error, bool) {
		switch {
		case strings.HasPrefix(sql, "SELECT name FROM t"):
			return []string{"name"}, [][]string{{"a"}, {MySQLNull}}, 0, nil, true
		case strings.HasPrefix(sql, "UPDATE"):
			return nil, nil, 3, nil, true
		}
		return nil, nil, 0, nil, false
	}
	f.withMySQL(t, m)
	o := f.ok(t, "sql.query", map[string]any{"engine": "mysql", "statement": "SELECT name FROM t WHERE id=?", "args": []any{"1' OR '1'='1"}})
	if !strings.Contains(o.Output["result"], "name\na\nNULL") || o.Output["rows"] != "2" {
		t.Fatalf("%v", o.Output)
	}
	if q := m.queryLog(); q[len(q)-1] != `SELECT name FROM t WHERE id='1\' OR \'1\'=\'1'` {
		t.Fatalf("arguments must be bound as one escaped literal: %s", q[len(q)-1])
	}
	for _, c := range []struct{ stmt, why string }{
		{"UPDATE t SET a=1 WHERE id=1", "write statements need write=true"},
		{"SELECT 1; DROP TABLE t", "exactly one statement"},
		{"SELECT 1 INTO OUTFILE '/tmp/x'", "forbidden"},
		{"SELECT LOAD_FILE('/etc/passwd')", "forbidden"},
	} {
		if _, err := f.run(t, "sql.query", map[string]any{"engine": "mysql", "statement": c.stmt}); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: want %q, got %v", c.stmt, c.why, err)
		}
	}
	if _, err := f.run(t, "sql.query", map[string]any{"engine": "mysql", "statement": "UPDATE t SET a=1", "write": true}); err == nil || !strings.Contains(err.Error(), "WHERE") {
		t.Fatalf("update without where: %v", err)
	}
	o = f.ok(t, "sql.query", map[string]any{"engine": "mysql", "statement": "UPDATE t SET a=1 WHERE id=2", "write": true})
	if o.Output["affected"] != "3" {
		t.Fatal(o.Output)
	}
	// account statements go through the scoring guard
	f.env.Guard = StaticGuard{Accounts: []string{"oc"}}
	for _, st := range []string{"ALTER USER 'oc'@'localhost' ACCOUNT LOCK", "DROP USER 'oc'@'localhost'", "ALTER USER oc@localhost IDENTIFIED BY 'x'"} {
		if _, err := f.run(t, "sql.query", map[string]any{"engine": "mysql", "statement": st, "write": true}); !errors.Is(err, ErrScoringUnsafe) {
			t.Errorf("%s: %v", st, err)
		}
	}
	// mssql is not handled by this action
	if _, err := f.run(t, "sql.query", map[string]any{"engine": "mssql", "statement": "SELECT @@VERSION"}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("mssql: %v", err)
	}
	if _, err := f.run(t, "sql.query", map[string]any{"engine": "mysql", "statement": "no_such_named"}); err == nil {
		t.Fatal("unknown named statement")
	}
	o = f.ok(t, "sql.query", map[string]any{"engine": "mysql", "statement": "version"})
	if o.Output["version"] != "8.0.36" {
		t.Fatal(o.Output)
	}
}

func TestRotateOpenCartAdmin(t *testing.T) {
	for _, salted := range []bool{true, false} {
		f := newFixture(t)
		m := newFakeMySQL(t, "auth_socket", "")
		var update string
		m.handler = func(sql string) ([]string, [][]string, uint64, error, bool) {
			switch {
			case strings.Contains(sql, "information_schema.COLUMNS"):
				n := "0"
				if salted {
					n = "1"
				}
				return []string{"COUNT(*)"}, [][]string{{n}}, 0, nil, true
			case strings.HasPrefix(sql, "UPDATE `opencart`.`oc_user`"):
				update = sql
				return nil, nil, 1, nil, true
			}
			return nil, nil, 0, nil, false
		}
		f.withMySQL(t, m)
		p := map[string]any{"engine": "mysql", "statement": "rotate_opencart_admin"}
		o, err := f.run(t, "sql.query", p, func(r *Request) { r.DryRun = true })
		if err != nil || !strings.Contains(o.Plan.Diff, "opencart.oc_user") || strings.Contains(o.Plan.Diff, "password=") {
			t.Fatalf("dry run: %+v %v", o.Plan, err)
		}
		o = f.ok(t, "sql.query", p)
		pw := o.Output["password"]
		if len(pw) != 24 || o.Output["username"] != "admin" || update == "" {
			t.Fatalf("%v / %s", o.Output, update)
		}
		if strings.Contains(update, pw) {
			t.Fatal("clear-text password sent to the database")
		}
		if salted != strings.Contains(update, "salt=") {
			t.Fatalf("scheme mismatch (salted=%v): %s", salted, update)
		}
		if !salted && !strings.Contains(update, "$2y$10$") {
			t.Fatalf("OpenCart 4 needs bcrypt: %s", update)
		}
		if salted { // recompute the OpenCart 3 hash from the salt in the statement
			re := regexp.MustCompile(`password='([0-9a-f]{40})', salt='([A-Za-z0-9]+)'`)
			g := re.FindStringSubmatch(update)
			if g == nil || g[1] != ocSaltedHash(g[2], pw) {
				t.Fatalf("hash does not verify: %s", update)
			}
		}
		if _, err := f.run(t, "sql.query", map[string]any{"engine": "mysql", "statement": "rotate_opencart_admin", "args": []any{"db; drop"}}); err == nil {
			t.Fatal("injection via args accepted")
		}
	}
}

func ocSaltedHash(salt, pw string) string {
	h := func(s string) string { return sha1hex(s) }
	return h(salt + h(salt+h(pw)))
}

var _ = context.Background
