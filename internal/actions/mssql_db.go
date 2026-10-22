package actions

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
)

// SQL Server access for sql.query (engine mssql), mssql.audit and mssql.lock.
//
// The database sits behind MSSQLConn so the actions are unit tested against an
// in-memory model; the real implementation is the pure-Go go-mssqldb driver.
// Connections are local only (loopback). Windows uses integrated
// authentication (the agent's own identity) unless a SQL login is provided by
// the vault hook; encryption is never required of the client or forced on the
// server, because that can break the scored 1433 check.

// MSSQLResult is one result set (first only) or the affected-row count.
type MSSQLResult struct {
	Columns  []string
	Rows     [][]string
	Affected int64
}

// MSSQLConn is one connection to the local SQL Server.
type MSSQLConn interface {
	// Query runs a statement that returns rows.
	Query(ctx context.Context, q string, args ...any) (*MSSQLResult, error)
	// Exec runs a statement that returns no rows (DDL, sp_configure, ...).
	Exec(ctx context.Context, q string, args ...any) (int64, error)
	Close() error
}

// MSSQLTarget says how to connect.
type MSSQLTarget struct {
	Server     string // loopback host name or address
	Port       int
	User       string // empty with Integrated
	Password   string
	Integrated bool
}

// MSSQLDialer opens connections (tests use a fake).
type MSSQLDialer interface {
	Dial(ctx context.Context, t MSSQLTarget) (MSSQLConn, error)
}

// MSSQLConfig is the process-wide SQL Server access configuration, set once at
// agent start (the vault is not part of any param or rollback entry).
type MSSQLConfig struct {
	// Dialer replaces the real driver (tests).
	Dialer MSSQLDialer
	// Auth returns the SQL login from the vault. An empty user selects Windows
	// integrated authentication (Windows only).
	Auth func(ctx context.Context) (user, password string, err error)
}

var (
	mssqlCfgMu sync.RWMutex
	mssqlCfg   MSSQLConfig
)

// SetMSSQLConfig installs the SQL Server access configuration.
func SetMSSQLConfig(c MSSQLConfig) {
	mssqlCfgMu.Lock()
	defer mssqlCfgMu.Unlock()
	mssqlCfg = c
}

func getMSSQLConfig() MSSQLConfig {
	mssqlCfgMu.RLock()
	defer mssqlCfgMu.RUnlock()
	return mssqlCfg
}

var (
	mssqlServerParam = ParamSpec{Name: "server", Type: String, Max: 128, Check: func(v any) error {
		if !mssqlLoopback(v.(string)) {
			return errors.New("server must be a loopback name or address (the agent connects locally)")
		}
		return nil
	}}
	mssqlPortParam = ParamSpec{Name: "port", Type: Int, Check: func(v any) error {
		if n, ok := v.(int); ok && (n < 1 || n > 65535) {
			return errors.New("port out of range")
		}
		return nil
	}}
)

func mssqlLoopback(s string) bool {
	switch strings.ToLower(s) {
	case "", ".", "(local)", "localhost":
		return true
	}
	ip := net.ParseIP(strings.Trim(s, "[]"))
	return ip != nil && ip.IsLoopback()
}

// mssqlTarget builds the connect target from params and the configured auth.
func mssqlTarget(ctx context.Context, p Params) (MSSQLTarget, error) {
	t := MSSQLTarget{Server: p.Str("server"), Port: 1433}
	if t.Server == "" || t.Server == "." || t.Server == "(local)" {
		t.Server = "localhost"
	}
	if n, ok := p.Int("port"); ok && n != 0 {
		t.Port = n
	}
	if a := getMSSQLConfig().Auth; a != nil {
		u, pw, err := a(ctx)
		if err != nil {
			return t, fmt.Errorf("sql login from vault: %w", err)
		}
		t.User, t.Password = u, pw
	}
	if t.User == "" {
		if runtime.GOOS != "windows" && getMSSQLConfig().Dialer == nil {
			return t, errors.New("no SQL login configured (integrated authentication is Windows-only); set MSSQLConfig.Auth")
		}
		t.Integrated = true
	}
	return t, nil
}

func mssqlConnect(ctx context.Context, p Params) (MSSQLConn, MSSQLTarget, error) {
	t, err := mssqlTarget(ctx, p)
	if err != nil {
		return nil, t, err
	}
	var d MSSQLDialer = driverMSSQLDialer{}
	if cd := getMSSQLConfig().Dialer; cd != nil {
		d = cd
	}
	c, err := d.Dial(ctx, t)
	return c, t, err
}

// ---- real driver ----

type driverMSSQLDialer struct{}

func (driverMSSQLDialer) Dial(ctx context.Context, t MSSQLTarget) (MSSQLConn, error) {
	q := url.Values{}
	q.Set("app name", "phylax")
	q.Set("connection timeout", "10")
	// Login-only encryption, server certificate not validated: works with and
	// without a server certificate and with ForceEncryption either way.
	q.Set("encrypt", "false")
	q.Set("TrustServerCertificate", "true")
	u := url.URL{Scheme: "sqlserver", Host: net.JoinHostPort(t.Server, strconv.Itoa(t.Port))}
	if t.Integrated {
		if runtime.GOOS != "windows" {
			return nil, errors.New("integrated authentication is only available on Windows")
		}
		q.Set("authenticator", "winsspi")
	} else {
		u.User = url.UserPassword(t.User, t.Password)
	}
	u.RawQuery = q.Encode()
	conn, err := mssql.NewConnector(u.String())
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(2 * time.Minute)
	pc, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := db.PingContext(pc); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect %s: %w", u.Host, err)
	}
	return &driverMSSQLConn{db: db}, nil
}

type driverMSSQLConn struct{ db *sql.DB }

const mssqlMaxRows = 5000

func (c *driverMSSQLConn) Query(ctx context.Context, q string, args ...any) (*MSSQLResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	rows, err := c.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	res := &MSSQLResult{Columns: cols}
	for rows.Next() {
		if len(res.Rows) >= mssqlMaxRows {
			break
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]string, len(cols))
		for i, v := range vals {
			row[i] = mssqlString(v)
		}
		res.Rows = append(res.Rows, row)
	}
	return res, rows.Err()
}

func (c *driverMSSQLConn) Exec(ctx context.Context, q string, args ...any) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	r, err := c.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	return n, nil
}

func (c *driverMSSQLConn) Close() error { return c.db.Close() }

func mssqlString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(x)
	case string:
		return x
	case bool:
		if x {
			return "1"
		}
		return "0"
	case time.Time:
		return x.UTC().Format(time.RFC3339)
	}
	return fmt.Sprint(v)
}

// ---- quoting ----

func mssqlCheckName(s string) error {
	if s == "" || len(s) > 128 {
		return errors.New("invalid login name length")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return errors.New("login name contains control characters")
		}
	}
	return nil
}

// mssqlQuoteIdent renders s as a bracketed identifier.
func mssqlQuoteIdent(s string) (string, error) {
	if err := mssqlCheckName(s); err != nil {
		return "", err
	}
	return "[" + strings.ReplaceAll(s, "]", "]]") + "]", nil
}

// mssqlQuoteString renders s as an N'...' literal.
func mssqlQuoteString(s string) (string, error) {
	if err := mssqlCheckName(s); err != nil {
		return "", err
	}
	return "N'" + strings.ReplaceAll(s, "'", "''") + "'", nil
}
