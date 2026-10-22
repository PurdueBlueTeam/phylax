package actions

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// A minimal MySQL/MariaDB client over a unix socket (COM_QUERY, text
// protocol), enough for account audits and admin statements without the mysql
// CLI. Supports mysql_native_password, caching_sha2_password (full auth is
// sent in clear, which is acceptable only on a local unix socket) and
// auth_socket/unix_socket. LOCAL INFILE requests are refused.

// MySQLTarget names the server and the account the agent connects as.
type MySQLTarget struct {
	Socket   string // real path of the unix socket
	User     string
	Password string
}

// MySQLResult is a result set or an OK summary.
type MySQLResult struct {
	Columns  []string
	Rows     [][]string // NULL is rendered as "\x00NULL"
	Affected uint64
}

// MySQLNull is how a SQL NULL appears in MySQLResult.Rows.
const MySQLNull = "\x00NULL"

// MySQLConn is one open connection.
type MySQLConn interface {
	Query(ctx context.Context, sql string) (*MySQLResult, error)
	Close() error
}

// MySQLDialer opens connections; tests substitute their own.
type MySQLDialer interface {
	Dial(ctx context.Context, t MySQLTarget) (MySQLConn, error)
}

const (
	maxMySQLPacket = 16 << 20
	maxMySQLRows   = 20000
)

const (
	capLongPassword   = 0x1
	capLongFlag       = 0x4
	capConnectWithDB  = 0x8
	capProtocol41     = 0x200
	capTransactions   = 0x2000
	capSecureConn     = 0x8000
	capPluginAuth     = 0x80000
	mysqlCharsetUTF8M = 45
)

type unixMySQLDialer struct{}

func (unixMySQLDialer) Dial(ctx context.Context, t MySQLTarget) (MySQLConn, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "unix", t.Socket)
	if err != nil {
		return nil, err
	}
	c := &mysqlConn{nc: nc}
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	} else {
		_ = nc.SetDeadline(time.Now().Add(30 * time.Second))
	}
	if err := c.handshake(t); err != nil {
		nc.Close()
		return nil, err
	}
	// Quoting below assumes backslash escapes are on.
	if _, err := c.Query(ctx, "SET SESSION sql_mode = REPLACE(@@sql_mode,'NO_BACKSLASH_ESCAPES','')"); err != nil {
		nc.Close()
		return nil, err
	}
	return c, nil
}

type mysqlConn struct {
	nc  net.Conn
	seq byte
}

func (c *mysqlConn) Close() error {
	_ = c.write([]byte{0x01}) // COM_QUIT
	return c.nc.Close()
}

func (c *mysqlConn) read() ([]byte, error) {
	var out []byte
	for {
		var h [4]byte
		if _, err := io.ReadFull(c.nc, h[:]); err != nil {
			return nil, err
		}
		n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
		c.seq = h[3] + 1
		if len(out)+n > maxMySQLPacket {
			return nil, errors.New("mysql: packet too large")
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c.nc, buf); err != nil {
			return nil, err
		}
		out = append(out, buf...)
		if n < 0xffffff {
			return out, nil
		}
	}
}

func (c *mysqlConn) write(p []byte) error {
	for {
		n := len(p)
		if n > 0xffffff {
			n = 0xffffff
		}
		h := []byte{byte(n), byte(n >> 8), byte(n >> 16), c.seq}
		c.seq++
		if _, err := c.nc.Write(append(h, p[:n]...)); err != nil {
			return err
		}
		p = p[n:]
		if n < 0xffffff {
			return nil
		}
	}
}

func lenencInt(b []byte) (v uint64, n int, null bool, err error) {
	if len(b) == 0 {
		return 0, 0, false, io.ErrUnexpectedEOF
	}
	switch f := b[0]; {
	case f < 0xfb:
		return uint64(f), 1, false, nil
	case f == 0xfb:
		return 0, 1, true, nil
	case f == 0xfc && len(b) >= 3:
		return uint64(binary.LittleEndian.Uint16(b[1:])), 3, false, nil
	case f == 0xfd && len(b) >= 4:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4, false, nil
	case f == 0xfe && len(b) >= 9:
		return binary.LittleEndian.Uint64(b[1:]), 9, false, nil
	}
	return 0, 0, false, io.ErrUnexpectedEOF
}

func lenencStr(b []byte) (s string, n int, null bool, err error) {
	l, k, null, err := lenencInt(b)
	if err != nil || null {
		return "", k, null, err
	}
	if uint64(len(b)-k) < l {
		return "", 0, false, io.ErrUnexpectedEOF
	}
	return string(b[k : k+int(l)]), k + int(l), false, nil
}

func parseMySQLErr(p []byte) error {
	if len(p) < 3 {
		return errors.New("mysql: malformed error packet")
	}
	code := binary.LittleEndian.Uint16(p[1:])
	msg := p[3:]
	if len(msg) > 6 && msg[0] == '#' {
		msg = msg[6:]
	}
	return fmt.Errorf("mysql error %d: %s", code, msg)
}

func scramble(plugin, pw string, salt []byte) ([]byte, error) {
	if pw == "" {
		return nil, nil
	}
	switch plugin {
	case "mysql_native_password":
		s1 := sha1.Sum([]byte(pw))
		s2 := sha1.Sum(s1[:])
		h := sha1.New()
		h.Write(salt)
		h.Write(s2[:])
		out := h.Sum(nil)
		for i := range out {
			out[i] ^= s1[i]
		}
		return out, nil
	case "caching_sha2_password":
		s1 := sha256.Sum256([]byte(pw))
		s2 := sha256.Sum256(s1[:])
		h := sha256.New()
		h.Write(s2[:])
		h.Write(salt)
		out := h.Sum(nil)
		for i := range out {
			out[i] ^= s1[i]
		}
		return out, nil
	}
	return nil, fmt.Errorf("mysql: unsupported auth plugin %q", plugin)
}

func cstr(b []byte) (string, []byte) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return string(b), nil
	}
	return string(b[:i]), b[i+1:]
}

func (c *mysqlConn) handshake(t MySQLTarget) error {
	p, err := c.read()
	if err != nil {
		return err
	}
	if len(p) == 0 {
		return errors.New("mysql: empty greeting")
	}
	if p[0] == 0xff {
		return parseMySQLErr(p)
	}
	if p[0] != 10 {
		return fmt.Errorf("mysql: unsupported protocol version %d", p[0])
	}
	_, rest := cstr(p[1:]) // server version
	if len(rest) < 4+8+1+2+1+2+2+1+10 {
		return errors.New("mysql: short greeting")
	}
	rest = rest[4:] // connection id
	salt := append([]byte(nil), rest[:8]...)
	rest = rest[8+1:]
	capLo := uint32(binary.LittleEndian.Uint16(rest))
	rest = rest[2+1+2:]
	capHi := uint32(binary.LittleEndian.Uint16(rest))
	rest = rest[2:]
	alen := int(rest[0])
	rest = rest[1+10:]
	serverCaps := capLo | capHi<<16
	if serverCaps&capProtocol41 == 0 {
		return errors.New("mysql: server too old")
	}
	n := alen - 8
	if n < 13 {
		n = 13
	}
	if n > len(rest) {
		n = len(rest)
	}
	salt = append(salt, bytes.TrimRight(rest[:n], "\x00")...)
	rest = rest[n:]
	plugin := "mysql_native_password"
	if serverCaps&capPluginAuth != 0 {
		plugin, _ = cstr(rest)
	}
	return c.authenticate(t, plugin, salt)
}

func (c *mysqlConn) authenticate(t MySQLTarget, plugin string, salt []byte) error {
	resp, err := scramble(plugin, t.Password, salt)
	if err != nil && !isNoPasswordPlugin(plugin) {
		return err
	}
	flags := uint32(capLongPassword | capLongFlag | capProtocol41 | capTransactions | capSecureConn | capPluginAuth)
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, flags)
	_ = binary.Write(&b, binary.LittleEndian, uint32(maxMySQLPacket))
	b.WriteByte(mysqlCharsetUTF8M)
	b.Write(make([]byte, 23))
	b.WriteString(t.User)
	b.WriteByte(0)
	b.WriteByte(byte(len(resp)))
	b.Write(resp)
	b.WriteString(plugin)
	b.WriteByte(0)
	if err := c.write(b.Bytes()); err != nil {
		return err
	}
	for {
		p, err := c.read()
		if err != nil {
			return err
		}
		if len(p) == 0 {
			return errors.New("mysql: empty auth reply")
		}
		switch p[0] {
		case 0x00:
			return nil
		case 0xff:
			return parseMySQLErr(p)
		case 0xfe: // auth switch
			name, data := cstr(p[1:])
			salt = bytes.TrimRight(data, "\x00")
			plugin = name
			resp, err := scramble(plugin, t.Password, salt)
			if err != nil && !isNoPasswordPlugin(plugin) {
				return err
			}
			if isNoPasswordPlugin(plugin) {
				resp = nil
			}
			if err := c.write(resp); err != nil {
				return err
			}
		case 0x01: // more data (caching_sha2)
			if len(p) >= 2 && p[1] == 3 {
				continue // fast auth ok; an OK packet follows
			}
			if len(p) >= 2 && p[1] == 4 {
				if err := c.write(append([]byte(t.Password), 0)); err != nil { // unix socket only
					return err
				}
				continue
			}
			return errors.New("mysql: unexpected auth data")
		default:
			return fmt.Errorf("mysql: unexpected auth packet 0x%02x", p[0])
		}
	}
}

func isNoPasswordPlugin(p string) bool {
	return p == "auth_socket" || p == "unix_socket" || p == ""
}

func (c *mysqlConn) Query(ctx context.Context, sql string) (*MySQLResult, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.nc.SetDeadline(dl)
	} else {
		_ = c.nc.SetDeadline(time.Now().Add(60 * time.Second))
	}
	if len(sql) >= maxMySQLPacket-1 {
		return nil, errors.New("mysql: statement too large")
	}
	c.seq = 0
	if err := c.write(append([]byte{0x03}, sql...)); err != nil {
		return nil, err
	}
	p, err := c.read()
	if err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, errors.New("mysql: empty response")
	}
	switch p[0] {
	case 0xff:
		return nil, parseMySQLErr(p)
	case 0x00:
		aff, _, _, _ := lenencInt(p[1:])
		return &MySQLResult{Affected: aff}, nil
	case 0xfb:
		return nil, errors.New("mysql: server requested LOCAL INFILE; refused")
	}
	ncols, _, _, err := lenencInt(p)
	if err != nil || ncols == 0 || ncols > 4096 {
		return nil, errors.New("mysql: bad column count")
	}
	res := &MySQLResult{}
	for i := uint64(0); i < ncols; i++ {
		d, err := c.read()
		if err != nil {
			return nil, err
		}
		var name string
		off := 0
		for f := 0; f < 5; f++ { // catalog, schema, table, org_table, name
			s, k, _, err := lenencStr(d[off:])
			if err != nil {
				return nil, err
			}
			name, off = s, off+k
		}
		res.Columns = append(res.Columns, name)
	}
	if e, err := c.read(); err != nil { // EOF after the column definitions
		return nil, err
	} else if len(e) > 0 && e[0] == 0xff {
		return nil, parseMySQLErr(e)
	}
	for {
		r, err := c.read()
		if err != nil {
			return nil, err
		}
		if len(r) > 0 && r[0] == 0xff {
			return nil, parseMySQLErr(r)
		}
		if len(r) > 0 && r[0] == 0xfe && len(r) < 9 {
			return res, nil
		}
		if len(res.Rows) >= maxMySQLRows {
			return nil, errors.New("mysql: result too large")
		}
		row := make([]string, 0, ncols)
		off := 0
		for i := uint64(0); i < ncols; i++ {
			s, k, null, err := lenencStr(r[off:])
			if err != nil {
				return nil, err
			}
			if null {
				s = MySQLNull
			}
			row = append(row, s)
			off += k
		}
		res.Rows = append(res.Rows, row)
	}
}

// quoteMySQL renders s as a SQL string literal (backslash escapes on).
func quoteMySQL(s string) (string, error) {
	if strings.ContainsRune(s, 0) {
		return "", errors.New("NUL in SQL value")
	}
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case 0x1a:
			b.WriteString(`\Z`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String(), nil
}

// bindMySQL replaces each ? outside quotes with the quoted args, in order.
func bindMySQL(stmt string, args []string) (string, error) {
	var b strings.Builder
	ai := 0
	var q byte
	for i := 0; i < len(stmt); i++ {
		ch := stmt[i]
		switch {
		case q != 0:
			b.WriteByte(ch)
			if ch == '\\' && i+1 < len(stmt) {
				i++
				b.WriteByte(stmt[i])
			} else if ch == q {
				q = 0
			}
		case ch == '\'' || ch == '"' || ch == '`':
			q = ch
			b.WriteByte(ch)
		case ch == '?':
			if ai >= len(args) {
				return "", errors.New("more placeholders than args")
			}
			lit, err := quoteMySQL(args[ai])
			if err != nil {
				return "", err
			}
			b.WriteString(lit)
			ai++
		default:
			b.WriteByte(ch)
		}
	}
	if ai != len(args) {
		return "", errors.New("more args than placeholders")
	}
	return b.String(), nil
}
