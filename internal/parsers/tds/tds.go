// Package tds parses MSSQL's Tabular Data Stream: pre-login (version,
// encryption, instance), Login7 (user, host, app, server, library, database;
// the obfuscated password is decoded only to hash it), the LOGINACK / ERROR
// outcome and SQL batch text (clipped, with a hash). When the login is wrapped
// in TLS (encryption OFF/ON/REQ negotiated) Login7 is invisible: the session
// is reported with tds.tls=true and only the pre-login fields.
package tds

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/ntlm"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// Packet types.
const (
	typBatch    = 0x01
	typRPC      = 0x03
	typReply    = 0x04
	typLogin7   = 0x10
	typSSPI     = 0x11
	typPrelogin = 0x12
)

const (
	maxPayload = 32 << 10
	maxQueries = 32
)

type side struct {
	hdr    [8]byte
	hn     int
	left   int // payload bytes still to come in the current packet
	typ    byte
	eom    bool
	msg    []byte
	msgTyp byte
	dead   bool
}

// Parser is the per-connection TDS parser.
type Parser struct {
	meta txn.Meta
	emit txn.Emit
	s    [2]side

	start, last time.Time
	stage       int // 0 start, 1 prelogin sent, 2 prelogin answered, 3 login sent, 4 login answered
	cliVer      string
	srvVer      string
	cliEnc      int
	srvEnc      int
	instance    string
	tlsWrapped  bool
	login       *login
	loginOK     *bool
	errNum      uint32
	queries     []string
	nQueries    int
	nRPC        int
	emitted     bool
	seen        bool
}

type login struct {
	host, user, app, server, lib, db string
	passHash                         string
	integrated                       bool
	ntlmUser, ntlmDomain             string
	tdsVersion                       uint32
	pktSize                          uint32
}

// New returns a stream parser.
func New(m txn.Meta, emit txn.Emit) txn.Stream {
	return &Parser{meta: m, emit: emit, cliEnc: -1, srvEnc: -1}
}

// Sniff reports whether b starts like a TDS pre-login or login packet.
func Sniff(b []byte) bool {
	return len(b) >= 8 && (b[0] == typPrelogin || b[0] == typLogin7) && b[1] <= 0x0f &&
		int(binary.BigEndian.Uint16(b[2:])) >= 8
}

// Data implements txn.Stream.
func (p *Parser) Data(d txn.Dir, b []byte, ts time.Time) {
	if p.start.IsZero() {
		p.start = ts
	}
	p.last = ts
	s := &p.s[d]
	for len(b) > 0 && !s.dead {
		if s.left == 0 {
			for s.hn < 8 && len(b) > 0 {
				s.hdr[s.hn] = b[0]
				s.hn++
				b = b[1:]
			}
			if s.hn < 8 {
				return
			}
			s.hn = 0
			n := int(binary.BigEndian.Uint16(s.hdr[2:]))
			if n < 8 || s.hdr[0] == 0 || s.hdr[0] > 0x20 {
				s.dead = true
				return
			}
			s.typ, s.eom, s.left = s.hdr[0], s.hdr[1]&1 != 0, n-8
			if len(s.msg) == 0 {
				s.msgTyp = s.typ
			}
			if s.left == 0 {
				p.packetDone(d, s)
			}
			continue
		}
		take := len(b)
		if take > s.left {
			take = s.left
		}
		if room := maxPayload - len(s.msg); room > 0 {
			k := take
			if k > room {
				k = room
			}
			s.msg = append(s.msg, b[:k]...)
		}
		b = b[take:]
		s.left -= take
		if s.left == 0 {
			p.packetDone(d, s)
		}
	}
}

func (p *Parser) packetDone(d txn.Dir, s *side) {
	if !s.eom {
		return
	}
	msg, typ := s.msg, s.msgTyp
	s.msg = s.msg[:0]
	p.seen = true
	if d == txn.C2S {
		p.client(typ, msg)
	} else {
		p.server(typ, msg)
	}
}

func (p *Parser) client(typ byte, m []byte) {
	switch typ {
	case typPrelogin:
		if p.stage >= 2 {
			// a second pre-login message after the answer is the TLS handshake
			// carried inside TDS packets
			p.tlsWrapped = true
			p.s[0].dead, p.s[1].dead = true, true
			return
		}
		p.stage = 1
		v, enc, inst := parsePrelogin(m)
		p.cliVer, p.cliEnc, p.instance = v, enc, inst
	case typLogin7:
		p.stage = 3
		p.login = parseLogin7(m)
	case typSSPI:
		if p.login != nil {
			if raw := ntlm.Find(m); raw != nil {
				if nm, ok := ntlm.Parse(raw); ok && nm.Type == 3 {
					p.login.ntlmUser, p.login.ntlmDomain = nm.User, nm.Domain
				}
			}
		}
	case typBatch:
		p.nQueries++
		if txt := batchText(m); txt != "" && len(p.queries) < maxQueries {
			p.queries = append(p.queries, txn.Clip(txt))
		}
	case typRPC:
		p.nRPC++
	}
}

func (p *Parser) server(typ byte, m []byte) {
	if typ != typReply {
		return
	}
	switch p.stage {
	case 1:
		p.stage = 2
		p.srvVer, p.srvEnc, _ = parsePrelogin(m)
	case 3:
		p.stage = 4
		ok, num := loginResult(m)
		if ok != nil {
			p.loginOK, p.errNum = ok, num
		}
	}
}

// parsePrelogin returns the version string, encryption option (-1 if absent)
// and instance name.
func parsePrelogin(m []byte) (ver string, enc int, inst string) {
	enc = -1
	for i := 0; i+5 <= len(m); i += 5 {
		tok := m[i]
		if tok == 0xFF {
			break
		}
		off := int(binary.BigEndian.Uint16(m[i+1:]))
		n := int(binary.BigEndian.Uint16(m[i+3:]))
		if off < 0 || n < 0 || off > len(m) || n > len(m)-off {
			break
		}
		v := m[off : off+n]
		switch tok {
		case 0:
			if n >= 6 {
				ver = fmt.Sprintf("%d.%d.%d", v[0], v[1], binary.BigEndian.Uint16(v[2:]))
			}
		case 1:
			if n >= 1 {
				enc = int(v[0])
			}
		case 2:
			j := 0
			for j < len(v) && v[j] != 0 {
				j++
			}
			inst = txn.Clip(string(v[:j]))
		}
	}
	return
}

func ucs2(m []byte, off, chars int) string {
	n := chars * 2
	if off < 0 || chars <= 0 || chars > 1024 || off > len(m) || n > len(m)-off {
		return ""
	}
	u := make([]uint16, chars)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(m[off+2*i:])
	}
	return string(utf16.Decode(u))
}

func parseLogin7(m []byte) *login {
	if len(m) < 94 {
		return nil
	}
	l := &login{tdsVersion: binary.LittleEndian.Uint32(m[4:]), pktSize: binary.LittleEndian.Uint32(m[8:])}
	f := func(at int) (int, int) {
		return int(binary.LittleEndian.Uint16(m[at:])), int(binary.LittleEndian.Uint16(m[at+2:]))
	}
	o, c := f(36)
	l.host = txn.Clip(ucs2(m, o, c))
	o, c = f(40)
	l.user = txn.Clip(ucs2(m, o, c))
	o, c = f(44)
	if c > 0 && c <= 1024 && o >= 0 && o <= len(m) && 2*c <= len(m)-o {
		pw := make([]byte, 2*c)
		for i := range pw {
			b := m[o+i] ^ 0xA5
			pw[i] = b<<4 | b>>4
		}
		u := make([]uint16, c)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(pw[2*i:])
		}
		l.passHash = txn.HashSecret(string(utf16.Decode(u)))
	}
	o, c = f(48)
	l.app = txn.Clip(ucs2(m, o, c))
	o, c = f(52)
	l.server = txn.Clip(ucs2(m, o, c))
	o, c = f(60)
	l.lib = txn.Clip(ucs2(m, o, c))
	o, c = f(68)
	l.db = txn.Clip(ucs2(m, o, c))
	l.integrated = m[25]&0x80 != 0
	so := int(binary.LittleEndian.Uint16(m[78:]))
	sn := int(binary.LittleEndian.Uint16(m[80:]))
	if sn > 0 && so >= 0 && so <= len(m) && sn <= len(m)-so {
		if raw := ntlm.Find(m[so : so+sn]); raw != nil {
			if nm, ok := ntlm.Parse(raw); ok && nm.Type == 3 {
				l.ntlmUser, l.ntlmDomain = nm.User, nm.Domain
			}
		}
	}
	return l
}

func batchText(m []byte) string {
	if len(m) < 4 {
		return ""
	}
	hl := int(binary.LittleEndian.Uint32(m))
	body := m
	if hl >= 4 && hl <= len(m) && hl < 1024 {
		body = m[hl:]
	}
	chars := len(body) / 2
	if chars > 512 {
		chars = 512
	}
	return ucs2(body, 0, chars)
}

// loginResult walks the token stream of a login reply.
func loginResult(m []byte) (ok *bool, errNum uint32) {
	for len(m) > 0 {
		tok := m[0]
		switch tok {
		case 0xAD, 0xAA, 0xAB, 0xE3, 0xED, 0xE5:
			if len(m) < 3 {
				return
			}
			n := int(binary.LittleEndian.Uint16(m[1:]))
			if 3+n > len(m) {
				n = len(m) - 3
			}
			body := m[3 : 3+n]
			if tok == 0xAD {
				t := true
				return &t, 0
			}
			if tok == 0xAA && len(body) >= 4 {
				f := false
				return &f, binary.LittleEndian.Uint32(body)
			}
			m = m[3+n:]
		case 0xFD, 0xFE, 0xFF:
			return
		default:
			return
		}
	}
	return
}

// End implements txn.Stream.
func (p *Parser) End(ts time.Time) {
	if p.emitted || !p.seen {
		return
	}
	p.emitted = true
	t := txn.New(p.meta, "mssql", "session", p.start)
	t.End = p.last
	if p.cliVer != "" {
		t.Set("tds.client_version", p.cliVer)
	}
	if p.srvVer != "" {
		t.Set("tds.server_version", p.srvVer)
	}
	if p.cliEnc >= 0 {
		t.SetInt("tds.client_encryption", int64(p.cliEnc))
	}
	if p.srvEnc >= 0 {
		t.SetInt("tds.server_encryption", int64(p.srvEnc))
	}
	if p.instance != "" {
		t.Set("tds.instance", p.instance)
	}
	t.SetBool("tds.tls", p.tlsWrapped)
	if l := p.login; l != nil {
		t.Set("tds.user", l.user)
		t.Set("tds.host", l.host)
		t.Set("tds.app", l.app)
		t.Set("tds.server", l.server)
		t.Set("tds.library", l.lib)
		t.Set("tds.database", l.db)
		t.SetBool("tds.integrated", l.integrated)
		t.Set("tds.tds_version", fmt.Sprintf("0x%08x", l.tdsVersion))
		t.SetInt("tds.packet_size", int64(l.pktSize))
		c := &txn.Cred{User: l.user, Mech: "sql"}
		if l.integrated {
			c.Mech = "ntlm"
			if l.ntlmUser != "" {
				c.User, c.Domain = txn.Clip(l.ntlmUser), txn.Clip(l.ntlmDomain)
			}
		} else if l.passHash != "" {
			c.PassHash = l.passHash
			t.Secret = append(t.Secret, "cred.pass_hash")
		}
		t.Cred = c
	}
	if p.loginOK != nil {
		t.SetBool("tds.login_ok", *p.loginOK)
		t.Succeeded(*p.loginOK)
		if !*p.loginOK {
			t.SetInt("tds.error", int64(p.errNum))
		}
	}
	t.SetInt("tds.batches", int64(p.nQueries))
	t.SetInt("tds.rpcs", int64(p.nRPC))
	if len(p.queries) > 0 {
		t.Add("tds.queries", p.queries...)
	}
	p.emit(t)
}
