// Package smb2 parses SMB2/3 over TCP 445 (NetBIOS-framed): negotiate
// dialects, NTLM session setup (flags, user, domain, workstation), tree connect
// paths, create (file names) and read volumes. NTLM responses and session keys
// are never read. Each connection yields one "session" transaction at its end.
//
// SMB 3.x encrypted traffic (transform header 0xFD) is detected and parsing
// stops; signing does not hide anything we read. An SMB1 multi-protocol
// negotiate is reported as dialect strings.
package smb2

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/ntlm"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// Commands.
const (
	cmdNegotiate    = 0
	cmdSessionSetup = 1
	cmdLogoff       = 2
	cmdTreeConnect  = 3
	cmdTreeDisc     = 4
	cmdCreate       = 5
	cmdClose        = 6
	cmdRead         = 8
	cmdWrite        = 9
)

const (
	keepPerMsg   = 8 << 10
	maxMsg       = 1 << 24
	hdrLen       = 64
	statusMore   = 0xC0000016
	maxListItems = 128
)

type side struct {
	nb   [4]byte
	nbN  int
	left int    // bytes of the current message still to come
	buf  []byte // kept prefix of the current message
	dead bool
}

// Parser is the per-connection SMB2 parser.
type Parser struct {
	meta txn.Meta
	emit txn.Emit
	s    [2]side

	start, last time.Time
	dialects    []string
	dialect     string
	smb1        bool
	t1Flags     uint32
	t3          *ntlm.Message
	t2          *ntlm.Message
	authStatus  *uint32
	trees       []string
	files       []string
	readBytes   int64
	writeBytes  int64
	reads       int
	encrypted   bool
	emitted     bool
	seenAny     bool
	loggedOff   bool
}

// New returns a stream parser.
func New(m txn.Meta, emit txn.Emit) txn.Stream { return &Parser{meta: m, emit: emit} }

// Sniff reports whether b starts a NetBIOS-framed SMB message.
func Sniff(b []byte) bool {
	return len(b) >= 8 && b[0] == 0 && (b[4] == 0xFE || b[4] == 0xFF) && string(b[5:8]) == "SMB"
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
			// NetBIOS session header: type byte (0), 24-bit length
			for s.nbN < 4 && len(b) > 0 {
				s.nb[s.nbN] = b[0]
				s.nbN++
				b = b[1:]
			}
			if s.nbN < 4 {
				return
			}
			s.nbN = 0
			if s.nb[0] != 0 {
				s.dead = true
				return
			}
			n := int(s.nb[1])<<16 | int(s.nb[2])<<8 | int(s.nb[3])
			if n == 0 {
				continue
			}
			if n > maxMsg {
				s.dead = true
				return
			}
			s.left, s.buf = n, s.buf[:0]
		}
		take := len(b)
		if take > s.left {
			take = s.left
		}
		if room := keepPerMsg - len(s.buf); room > 0 {
			k := take
			if k > room {
				k = room
			}
			s.buf = append(s.buf, b[:k]...)
		}
		b = b[take:]
		s.left -= take
		if s.left == 0 {
			p.message(d, s.buf)
			s.buf = s.buf[:0]
		}
	}
}

func (p *Parser) message(d txn.Dir, m []byte) {
	if len(m) < 4 {
		return
	}
	switch {
	case m[0] == 0xFD:
		p.encrypted = true
		p.s[0].dead, p.s[1].dead = true, true
		return
	case m[0] == 0xFF && string(m[1:4]) == "SMB":
		p.smb1Msg(d, m)
		return
	case m[0] != 0xFE || string(m[1:4]) != "SMB":
		return
	}
	p.seenAny = true
	for off, n := 0, 0; off < len(m) && n < 16; n++ {
		h := m[off:]
		if len(h) < hdrLen {
			return
		}
		next := int(binary.LittleEndian.Uint32(h[20:]))
		end := len(h)
		if next > 0 && next <= len(h) {
			end = next
		}
		p.command(d, h[:end])
		if next == 0 {
			return
		}
		off += next
	}
}

func (p *Parser) smb1Msg(d txn.Dir, m []byte) {
	// SMB1 header is 32 bytes; command 0x72 = negotiate; request body:
	// WordCount(1)=0, ByteCount(2), then {0x02, ASCIIZ dialect}...
	p.smb1 = true
	if d != txn.C2S || len(m) < 36 || m[4] != 0x72 {
		return
	}
	bc := int(binary.LittleEndian.Uint16(m[33:]))
	body := m[35:]
	if bc < len(body) {
		body = body[:bc]
	}
	for len(body) > 1 && len(p.dialects) < maxListItems {
		if body[0] != 2 {
			break
		}
		i := 1
		for i < len(body) && body[i] != 0 {
			i++
		}
		p.dialects = append(p.dialects, string(body[1:i]))
		if i >= len(body) {
			break
		}
		body = body[i+1:]
	}
}

func u16(b []byte, o int) int {
	if o+2 > len(b) {
		return 0
	}
	return int(binary.LittleEndian.Uint16(b[o:]))
}
func u32(b []byte, o int) uint32 {
	if o+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[o:])
}

func utf16At(h []byte, off, n int) string {
	if off < hdrLen || n <= 0 || n > 2048 || off > len(h) || n > len(h)-off {
		return ""
	}
	raw := h[off : off+n]
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	return string(utf16.Decode(u))
}

func (p *Parser) command(d txn.Dir, h []byte) {
	cmd := u16(h, 12)
	flags := u32(h, 16)
	status := u32(h, 8)
	resp := flags&1 != 0
	body := h[hdrLen:]
	switch cmd {
	case cmdNegotiate:
		if !resp {
			n := u16(body, 2)
			for i := 0; i < n && i < maxListItems && 36+2*i+2 <= len(body); i++ {
				p.dialects = append(p.dialects, fmt.Sprintf("0x%04x", u16(body, 36+2*i)))
			}
		} else if len(body) >= 6 {
			p.dialect = fmt.Sprintf("0x%04x", u16(body, 4))
		}
	case cmdSessionSetup:
		var off, n int
		if !resp {
			off, n = u16(body, 12), u16(body, 14)
		} else {
			off, n = u16(body, 4), u16(body, 6)
			st := status
			p.authStatus = &st
		}
		if off >= hdrLen && n > 0 && off <= len(h) {
			end := off + n
			if end > len(h) {
				end = len(h)
			}
			if raw := ntlm.Find(h[off:end]); raw != nil {
				if m, ok := ntlm.Parse(raw); ok {
					switch m.Type {
					case 1:
						p.t1Flags = m.Flags
					case 2:
						p.t2 = &m
					case 3:
						p.t3 = &m
					}
				}
			}
		}
	case cmdTreeConnect:
		if !resp {
			if path := utf16At(h, u16(body, 4), u16(body, 6)); path != "" && len(p.trees) < maxListItems {
				p.trees = append(p.trees, txn.Clip(path))
			}
		}
	case cmdCreate:
		if !resp {
			name := utf16At(h, u16(body, 44), u16(body, 46))
			if name != "" && len(p.files) < maxListItems {
				p.files = append(p.files, txn.Clip(name))
			}
		}
	case cmdRead:
		if resp && status == 0 {
			p.readBytes += int64(u32(body, 4))
			p.reads++
		}
	case cmdWrite:
		if resp && status == 0 {
			p.writeBytes += int64(u32(body, 4))
		}
	case cmdLogoff:
		if resp {
			p.loggedOff = true
		}
	}
}

// End implements txn.Stream.
func (p *Parser) End(ts time.Time) {
	if p.emitted || (!p.seenAny && !p.smb1) {
		return
	}
	p.emitted = true
	t := txn.New(p.meta, "smb", "session", p.start)
	t.End = p.last
	t.EnsureList("smb.dialects")
	t.Add("smb.dialects", p.dialects...)
	if p.dialect != "" {
		t.Set("smb.dialect", p.dialect)
	}
	if p.smb1 {
		t.SetBool("smb.smb1", true)
	}
	if p.encrypted {
		t.SetBool("smb.encrypted", true)
	}
	if p.t1Flags != 0 {
		t.Set("smb.ntlm_neg_flags", fmt.Sprintf("0x%08x", p.t1Flags))
	}
	if p.t3 != nil {
		m := p.t3
		t.Set("smb.ntlm_flags", fmt.Sprintf("0x%08x", m.Flags))
		t.Set("smb.user", txn.Clip(m.User))
		t.Set("smb.domain", txn.Clip(m.Domain))
		t.Set("smb.workstation", txn.Clip(m.Workstation))
		if m.HasVersion {
			t.Set("smb.ntlm_version", fmt.Sprintf("%d.%d.%d", m.Version[0], m.Version[1], uint16(m.Version[2])|uint16(m.Version[3])<<8))
		}
		t.Cred = &txn.Cred{User: txn.Clip(m.User), Domain: txn.Clip(m.Domain), Mech: "ntlm"}
		if p.t2 != nil {
			dom := strings.ToLower(m.Domain)
			isServer := false
			for _, n := range p.t2.ServerNames() {
				if n == dom && dom != "" {
					isServer = true
				}
			}
			t.SetBool("smb.domain_is_server", isServer)
			t.Set("smb.server_name", txn.Clip(p.t2.NbComputer))
		}
	}
	if p.authStatus != nil && *p.authStatus != statusMore {
		ok := *p.authStatus == 0
		t.SetBool("smb.auth_ok", ok)
		t.Set("smb.auth_status", fmt.Sprintf("0x%08x", *p.authStatus))
		t.Succeeded(ok)
	}
	if len(p.trees) > 0 {
		t.Set("smb.tree", p.trees[0])
		t.Add("smb.trees", p.trees...)
	}
	if len(p.files) > 0 {
		t.Add("smb.files", p.files...)
	}
	t.SetInt("smb.reads", int64(p.reads))
	t.SetInt("smb.read_bytes", p.readBytes)
	t.SetInt("smb.write_bytes", p.writeBytes)
	t.SetBool("smb.logoff", p.loggedOff)
	p.emit(t)
}
