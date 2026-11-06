package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// A minimal TDS 7.4 client: PRELOGIN, (TLS inside TDS when the server wants
// encryption), LOGIN7 with SQL authentication, and one SQL batch whose first
// column is compared with the expected output.

const (
	tdsBatch    = 1
	tdsReply    = 4
	tdsLogin7   = 0x10
	tdsPrelogin = 0x12
	tdsEOM      = 1
)

func tdsWrite(w io.Writer, typ byte, payload []byte) error {
	const max = 4096 - 8
	id := byte(1)
	for first := true; first || len(payload) > 0; first = false {
		n := min(len(payload), max)
		st := byte(0)
		if n == len(payload) {
			st = tdsEOM
		}
		h := []byte{typ, st, 0, 0, 0, 0, id, 0}
		binary.BigEndian.PutUint16(h[2:], uint16(8+n))
		if _, err := w.Write(append(h, payload[:n]...)); err != nil {
			return err
		}
		payload = payload[n:]
		id++
	}
	return nil
}

func tdsReadMsg(r io.Reader) (byte, []byte, error) {
	var out []byte
	var typ byte
	for {
		var h [8]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return 0, nil, err
		}
		l := int(binary.BigEndian.Uint16(h[2:]))
		if l < 8 {
			return 0, nil, errors.New("tds: bad packet length")
		}
		buf := make([]byte, l-8)
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, nil, err
		}
		typ = h[0]
		out = append(out, buf...)
		if h[1]&tdsEOM != 0 || len(out) > 16<<20 {
			return typ, out, nil
		}
	}
}

// tdsTLS carries the TLS handshake inside PRELOGIN packets, then passes through.
type tdsTLS struct {
	net.Conn
	pass bool
	buf  []byte
}

func (t *tdsTLS) Read(b []byte) (int, error) {
	if t.pass {
		return t.Conn.Read(b)
	}
	if len(t.buf) == 0 {
		_, p, err := tdsReadMsg(t.Conn)
		if err != nil {
			return 0, err
		}
		t.buf = p
	}
	n := copy(b, t.buf)
	t.buf = t.buf[n:]
	return n, nil
}

func (t *tdsTLS) Write(b []byte) (int, error) {
	if t.pass {
		return t.Conn.Write(b)
	}
	if err := tdsWrite(t.Conn, tdsPrelogin, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func preloginBody(encrypt byte) []byte {
	// options: VERSION(0) ENCRYPTION(1) INSTOPT(2) THREADID(3) MARS(4), 0xFF
	data := [][]byte{{0, 0, 0, 0, 0, 0}, {encrypt}, {0}, {0, 0, 0, 0}, {0}}
	tok := []byte{0, 1, 2, 3, 4}
	hdr := len(tok)*5 + 1
	var table, body []byte
	off := hdr
	for i, d := range data {
		table = append(table, tok[i], byte(off>>8), byte(off), byte(len(d)>>8), byte(len(d)))
		body = append(body, d...)
		off += len(d)
	}
	return append(append(table, 0xFF), body...)
}

func preloginEncryption(b []byte) (byte, bool) {
	for i := 0; i+5 <= len(b) && b[i] != 0xFF; i += 5 {
		if b[i] == 1 {
			off := int(binary.BigEndian.Uint16(b[i+1:]))
			if off < len(b) {
				return b[off], true
			}
		}
	}
	return 0, false
}

func tdsScramble(pw string) []byte {
	b := utf16le(pw)
	for i, c := range b {
		b[i] = ((c<<4)&0xF0 | c>>4) ^ 0xA5
	}
	return b
}

func login7(host, user, pass string) []byte {
	type field struct{ data []byte }
	hostname, app, server, lib := utf16le("WORKSTATION"), utf16le("go-mssqldb"), utf16le(host), utf16le("go-mssqldb")
	u, pw := utf16le(user), tdsScramble(pass)
	lang, db := utf16le(""), utf16le("")
	fields := [][]byte{hostname, u, pw, app, server, nil, lib, lang, db}
	// fixed part is 94 bytes; offsets are into the packet body
	buf := make([]byte, 94)
	off := 94
	var payload []byte
	put := func(pos int, d []byte, chars bool) {
		binary.LittleEndian.PutUint16(buf[pos:], uint16(off))
		n := len(d)
		if chars {
			n /= 2
		}
		binary.LittleEndian.PutUint16(buf[pos+2:], uint16(n))
		payload = append(payload, d...)
		off += len(d)
	}
	put(36, fields[0], true) // hostname
	put(40, fields[1], true) // username
	put(44, fields[2], true) // password
	put(48, fields[3], true) // appname
	put(52, fields[4], true) // servername
	put(56, nil, false)      // extension
	put(60, fields[6], true) // client interface name
	put(64, fields[7], true) // language
	put(68, fields[8], true) // database
	put(78, nil, false)      // SSPI
	put(82, nil, false)      // attach db
	put(86, nil, false)      // change password
	binary.LittleEndian.PutUint32(buf[4:], 0x74000004)
	binary.LittleEndian.PutUint32(buf[8:], 4096)
	binary.LittleEndian.PutUint32(buf[12:], 7)
	buf[24], buf[25] = 0xE0, 0x03
	copy(buf[72:], []byte{1, 2, 3, 4, 5, 6})
	out := append(buf, payload...)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	return out
}

type tdsErr struct {
	number uint32
	msg    string
}

type tdsResult struct {
	loginAck bool
	errs     []tdsErr
	rows     [][]string
	cols     int
	unsup    bool
}

func ucs2(b []byte) string { return fromUTF16LE(b) }

// parseTokens decodes the subset of the token stream a login/query returns.
func parseTokens(b []byte) tdsResult {
	var r tdsResult
	type col struct {
		typ    byte
		maxlen int
	}
	var cols []col
	for len(b) > 0 {
		t := b[0]
		b = b[1:]
		switch t {
		case 0xAA, 0xAB, 0xAD, 0xE3, 0xA9, 0xED, 0xA5, 0xA4:
			if len(b) < 2 {
				return r
			}
			l := int(binary.LittleEndian.Uint16(b))
			if 2+l > len(b) {
				return r
			}
			body := b[2 : 2+l]
			b = b[2+l:]
			switch t {
			case 0xAD:
				r.loginAck = true
			case 0xAA:
				if len(body) >= 8 {
					n := int(binary.LittleEndian.Uint16(body[6:]))
					if 8+2*n <= len(body) {
						r.errs = append(r.errs, tdsErr{binary.LittleEndian.Uint32(body), ucs2(body[8 : 8+2*n])})
					}
				}
			}
		case 0xFD, 0xFE, 0xFF:
			if len(b) < 12 {
				return r
			}
			b = b[12:]
		case 0x79:
			if len(b) < 4 {
				return r
			}
			b = b[4:]
		case 0x81:
			if len(b) < 2 {
				return r
			}
			n := int(binary.LittleEndian.Uint16(b))
			b = b[2:]
			cols = nil
			for range n {
				if len(b) < 7 {
					r.unsup = true
					return r
				}
				typ := b[6]
				b = b[7:]
				c := col{typ: typ}
				switch typ {
				case 0xE7, 0xA7:
					if len(b) < 7 {
						r.unsup = true
						return r
					}
					c.maxlen = int(binary.LittleEndian.Uint16(b))
					b = b[7:]
				case 0x26, 0x68:
					if len(b) < 1 {
						r.unsup = true
						return r
					}
					c.maxlen = int(b[0])
					b = b[1:]
				case 0x38, 0x34, 0x30, 0x7F, 0x32:
				default:
					r.unsup = true
					return r
				}
				if len(b) < 1 || len(b) < 1+2*int(b[0]) {
					r.unsup = true
					return r
				}
				b = b[1+2*int(b[0]):]
				cols = append(cols, c)
			}
			r.cols = n
		case 0xD1:
			row := make([]string, 0, len(cols))
			for _, c := range cols {
				var v string
				var ok bool
				switch c.typ {
				case 0xE7, 0xA7:
					if c.maxlen == 0xFFFF { // PLP
						if len(b) < 8 {
							r.unsup = true
							return r
						}
						null := binary.LittleEndian.Uint64(b) == ^uint64(0)
						b = b[8:]
						var acc []byte
						for {
							if len(b) < 4 {
								r.unsup = true
								return r
							}
							cl := int(binary.LittleEndian.Uint32(b))
							b = b[4:]
							if cl == 0 {
								break
							}
							if cl > len(b) {
								r.unsup = true
								return r
							}
							acc = append(acc, b[:cl]...)
							b = b[cl:]
						}
						if !null {
							v, ok = pstr(c.typ, acc), true
						}
					} else {
						if len(b) < 2 {
							r.unsup = true
							return r
						}
						l := int(binary.LittleEndian.Uint16(b))
						b = b[2:]
						if l != 0xFFFF {
							if l > len(b) {
								r.unsup = true
								return r
							}
							v, ok = pstr(c.typ, b[:l]), true
							b = b[l:]
						}
					}
				case 0x26, 0x68:
					if len(b) < 1 || int(b[0]) > len(b)-1 {
						r.unsup = true
						return r
					}
					l := int(b[0])
					v, ok = intStr(c.typ, b[1:1+l]), l > 0
					b = b[1+l:]
				case 0x38, 0x34, 0x30, 0x7F, 0x32:
					n := map[byte]int{0x38: 4, 0x34: 2, 0x30: 1, 0x7F: 8, 0x32: 1}[c.typ]
					if len(b) < n {
						r.unsup = true
						return r
					}
					v, ok = intStr(0x26, b[:n]), true
					b = b[n:]
				}
				if !ok {
					v = ""
				}
				row = append(row, v)
			}
			r.rows = append(r.rows, row)
		default:
			r.unsup = true
			return r
		}
	}
	return r
}

func pstr(typ byte, b []byte) string {
	if typ == 0xE7 {
		return ucs2(b)
	}
	return string(b)
}

func intStr(typ byte, b []byte) string {
	var v int64
	switch len(b) {
	case 1:
		v = int64(b[0])
	case 2:
		v = int64(int16(binary.LittleEndian.Uint16(b)))
	case 4:
		v = int64(int32(binary.LittleEndian.Uint32(b)))
	case 8:
		v = int64(binary.LittleEndian.Uint64(b))
	default:
		return ""
	}
	return strconv.FormatInt(v, 10)
}

func probeMSSQL(ctx context.Context, p *probe) error {
	if err := p.needCred(); err != nil {
		return err
	}
	raw, err := p.dialSpec(ctx)
	if err != nil {
		return err
	}
	defer raw.Close()
	p.step("connect")
	if err := tdsWrite(raw, tdsPrelogin, preloginBody(0)); err != nil {
		return protoErr(err, "db connection or login failed")
	}
	typ, pre, err := tdsReadMsg(raw)
	if err != nil || typ != tdsReply {
		return protoErr(errors.Join(err, fmt.Errorf("packet type %d", typ)), "db connection or login failed")
	}
	enc, _ := preloginEncryption(pre)
	p.step("prelogin")
	var conn io.ReadWriter = raw
	var tlsConn *tls.Conn
	var wrap *tdsTLS
	if enc == 0 || enc == 1 || enc == 3 { // OFF (login only), ON, REQ
		wrap = &tdsTLS{Conn: raw}
		tlsConn = tls.Client(wrap, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, ServerName: p.spec.Host})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return failDebug(ClassProtocol, err.Error(), "db connection or login failed: tls handshake")
		}
		wrap.pass = true
		conn = tlsConn
		p.step("tls")
	}
	if err := tdsWrite(conn, tdsLogin7, login7(p.spec.Host, p.cred.User, p.cred.Pass.Reveal())); err != nil {
		return protoErr(err, "db connection or login failed")
	}
	if enc == 0 { // login-only encryption: the rest is plaintext
		conn = raw
		if wrap != nil {
			_ = wrap // the TLS layer is done
		}
		typ, body, err := tdsReadMsg(raw)
		return mssqlAfterLogin(ctx, p, raw, typ, body, err, conn)
	}
	typ, body, err := tdsReadMsg(conn)
	return mssqlAfterLogin(ctx, p, conn, typ, body, err, conn)
}

func mssqlAfterLogin(ctx context.Context, p *probe, rw io.ReadWriter, typ byte, body []byte, err error, conn io.ReadWriter) error {
	if err != nil || typ != tdsReply {
		return protoErr(errors.Join(err, fmt.Errorf("packet type %d", typ)), "db connection or login failed")
	}
	r := parseTokens(body)
	if !r.loginAck {
		msg := ""
		if len(r.errs) > 0 {
			msg = fmt.Sprintf("%d: %s", r.errs[0].number, r.errs[0].msg)
		}
		return failDebug(ClassAuth, msg, "db connection or login failed")
	}
	p.step("login")
	if p.item.Query == "" {
		return nil
	}
	hdr := make([]byte, 22)
	binary.LittleEndian.PutUint32(hdr, 22)
	binary.LittleEndian.PutUint32(hdr[4:], 18)
	binary.LittleEndian.PutUint16(hdr[8:], 2)
	binary.LittleEndian.PutUint32(hdr[18:], 1)
	if err := tdsWrite(rw, tdsBatch, append(hdr, utf16le(p.item.Query)...)); err != nil {
		return protoErr(err, "could not query db")
	}
	typ, body, err = tdsReadMsg(rw)
	if err != nil || typ != tdsReply {
		return protoErr(errors.Join(err, fmt.Errorf("packet type %d", typ)), "could not query db with command")
	}
	qr := parseTokens(body)
	if len(qr.errs) > 0 {
		return failDebug(ClassProtocol, qr.errs[0].msg, "could not query db with command")
	}
	p.step("query")
	if p.item.Output == "" {
		if p.strict() && len(qr.rows) == 0 && !qr.unsup {
			p.strictIssue("query returned no rows")
		}
		return nil
	}
	if qr.unsup && len(qr.rows) == 0 {
		return fail(ClassProtocol, "result uses an unsupported TDS column type")
	}
	var re *regexp.Regexp
	if p.item.UseRegex {
		var e error
		if re, e = regexp.Compile(p.item.Output); e != nil {
			return fail(ClassConfig, "bad regex: %v", e)
		}
	}
	for _, row := range qr.rows {
		if len(row) == 0 {
			continue
		}
		if re != nil && re.MatchString(row[0]) || re == nil && strings.TrimSpace(row[0]) == strings.TrimSpace(p.item.Output) {
			return nil
		}
	}
	// Quotient returns failure with an empty Error here; we say why.
	return fail(ClassContent, "no matching output found for query")
}

var _ = bytes.MinRead
