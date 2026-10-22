// Package dns parses DNS messages over UDP datagrams and TCP streams (2-byte
// length framing). Each message becomes a "query" or "response" transaction;
// correlate the pair by dns.id and Community ID. The parser is hand written
// with hard bounds on names, compression jumps and record counts.
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// Bounds.
const (
	maxRecords = 64
	maxName    = 255
	maxJumps   = 16
)

// Question is one entry of the question section.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// RR is a resource record with a rendered value.
type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string
}

// Message is a decoded DNS message.
type Message struct {
	ID               uint16
	Response         bool
	Opcode           int
	AA, TC, RD, RA   bool
	Rcode            int
	Questions        []Question
	Answers          []RR
	NS, Additional   int // record counts as parsed
	EDNS             bool
	UDPSize          uint16
	QDCount, ANCount int
}

// ErrShort is returned for truncated messages.
var ErrShort = errors.New("dns: short message")

var typeNames = map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 255: "ANY", 252: "AXFR", 251: "IXFR"}

// TypeName renders a record type.
func TypeName(t uint16) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE%d", t)
}

func readName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	end, jumps := -1, 0
	for {
		if off >= len(msg) {
			return "", 0, ErrShort
		}
		c := int(msg[off])
		switch c & 0xC0 {
		case 0x00:
			if c == 0 {
				if end < 0 {
					end = off + 1
				}
				if sb.Len() == 0 {
					return ".", end, nil
				}
				return sb.String(), end, nil
			}
			if off+1+c > len(msg) {
				return "", 0, ErrShort
			}
			if sb.Len()+c+1 > maxName {
				return "", 0, errors.New("dns: name too long")
			}
			sb.Write(msg[off+1 : off+1+c])
			sb.WriteByte('.')
			off += 1 + c
		case 0xC0:
			if off+1 >= len(msg) {
				return "", 0, ErrShort
			}
			if end < 0 {
				end = off + 2
			}
			jumps++
			if jumps > maxJumps {
				return "", 0, errors.New("dns: compression loop")
			}
			off = (c&0x3F)<<8 | int(msg[off+1])
		default:
			return "", 0, errors.New("dns: bad label")
		}
	}
}

// Parse decodes a DNS message.
func Parse(b []byte) (*Message, error) {
	if len(b) < 12 {
		return nil, ErrShort
	}
	m := &Message{ID: binary.BigEndian.Uint16(b)}
	fl := binary.BigEndian.Uint16(b[2:])
	m.Response = fl&0x8000 != 0
	m.Opcode = int(fl >> 11 & 0xF)
	m.AA, m.TC, m.RD, m.RA = fl&0x400 != 0, fl&0x200 != 0, fl&0x100 != 0, fl&0x80 != 0
	m.Rcode = int(fl & 0xF)
	qd := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	ns := int(binary.BigEndian.Uint16(b[8:]))
	ar := int(binary.BigEndian.Uint16(b[10:]))
	m.QDCount, m.ANCount, m.NS, m.Additional = qd, an, ns, ar
	off := 12
	for i := 0; i < qd && i < maxRecords; i++ {
		name, n, err := readName(b, off)
		if err != nil || n+4 > len(b) {
			return m, ErrShort
		}
		m.Questions = append(m.Questions, Question{name, binary.BigEndian.Uint16(b[n:]), binary.BigEndian.Uint16(b[n+2:])})
		off = n + 4
	}
	// answers, authority, additional: walk all so EDNS (OPT in additional) is seen
	total := an + ns + ar
	for i := 0; i < total && i < 3*maxRecords; i++ {
		name, n, err := readName(b, off)
		if err != nil || n+10 > len(b) {
			return m, nil // keep what we have: headers and questions are good
		}
		rr := RR{Name: name, Type: binary.BigEndian.Uint16(b[n:]), Class: binary.BigEndian.Uint16(b[n+2:]), TTL: binary.BigEndian.Uint32(b[n+4:])}
		rdl := int(binary.BigEndian.Uint16(b[n+8:]))
		rd := n + 10
		if rd+rdl > len(b) {
			return m, nil
		}
		if rr.Type == 41 && i >= an+ns {
			m.EDNS = true
			m.UDPSize = rr.Class
		}
		if i < an {
			rr.Data = rdata(b, rd, rdl, rr.Type)
			m.Answers = append(m.Answers, rr)
		}
		off = rd + rdl
	}
	return m, nil
}

func rdata(msg []byte, off, n int, typ uint16) string {
	d := msg[off : off+n]
	switch typ {
	case 1:
		if n == 4 {
			return netip.AddrFrom4([4]byte(d)).String()
		}
	case 28:
		if n == 16 {
			return netip.AddrFrom16([16]byte(d)).String()
		}
	case 2, 5, 12:
		if s, _, err := readName(msg, off); err == nil {
			return s
		}
	case 15:
		if n >= 3 {
			if s, _, err := readName(msg, off+2); err == nil {
				return fmt.Sprintf("%d %s", binary.BigEndian.Uint16(d), s)
			}
		}
	case 16:
		var sb strings.Builder
		for i := 0; i < len(d); {
			l := int(d[i])
			if i+1+l > len(d) {
				break
			}
			sb.Write(d[i+1 : i+1+l])
			i += 1 + l
		}
		return txn.Clip(sb.String())
	}
	return fmt.Sprintf("%d bytes", n)
}

// Transaction renders a message as a transaction between a client and server.
func Transaction(cid string, client, server netip.AddrPort, m *Message, ts time.Time, tcp bool) txn.Txn {
	typ := "query"
	if m.Response {
		typ = "response"
	}
	t := txn.New(txn.Meta{Client: client, Server: server, CommunityID: cid}, "dns", typ, ts)
	t.SetInt("dns.id", int64(m.ID))
	t.SetBool("dns.rd", m.RD)
	t.SetBool("dns.edns", m.EDNS)
	if m.EDNS {
		t.SetInt("dns.udp_size", int64(m.UDPSize))
	}
	t.SetInt("dns.opcode", int64(m.Opcode))
	t.SetBool("dns.tcp", tcp)
	if len(m.Questions) > 0 {
		q := m.Questions[0]
		t.Set("dns.qname", txn.Clip(q.Name))
		t.Set("dns.qtype", TypeName(q.Type))
	}
	if m.Response {
		t.SetInt("dns.rcode", int64(m.Rcode))
		t.SetBool("dns.aa", m.AA)
		t.SetBool("dns.tc", m.TC)
		t.SetInt("dns.answer_count", int64(m.ANCount))
		t.EnsureList("dns.answers")
		for _, a := range m.Answers {
			t.Add("dns.answers", TypeName(a.Type)+" "+txn.Clip(a.Data))
		}
		t.Succeeded(m.Rcode == 0)
	}
	return t
}

// Datagram parses one UDP payload from src to dst. A query's source is the
// client; a response's destination is.
func Datagram(cid string, src, dst netip.AddrPort, payload []byte, ts time.Time) (txn.Txn, bool) {
	m, err := Parse(payload)
	if err != nil && (m == nil || len(m.Questions) == 0) {
		return txn.Txn{}, false
	}
	if m.Response {
		return Transaction(cid, dst, src, m, ts, false), true
	}
	return Transaction(cid, src, dst, m, ts, false), true
}

// Parser handles DNS over TCP.
type Parser struct {
	meta txn.Meta
	emit txn.Emit
	buf  [2][]byte
	dead [2]bool
}

// New returns a TCP stream parser.
func New(m txn.Meta, emit txn.Emit) txn.Stream { return &Parser{meta: m, emit: emit} }

// Data implements txn.Stream.
func (p *Parser) Data(d txn.Dir, b []byte, ts time.Time) {
	if p.dead[d] {
		return
	}
	p.buf[d] = append(p.buf[d], b...)
	for len(p.buf[d]) >= 2 {
		n := int(binary.BigEndian.Uint16(p.buf[d]))
		if n < 12 {
			p.dead[d], p.buf[d] = true, nil
			return
		}
		if len(p.buf[d]) < 2+n {
			return
		}
		if m, err := Parse(p.buf[d][2 : 2+n]); err == nil || (m != nil && len(m.Questions) > 0) {
			p.emit(Transaction(p.meta.CommunityID, p.meta.Client, p.meta.Server, m, ts, true))
		}
		p.buf[d] = p.buf[d][2+n:]
	}
}

// End implements txn.Stream.
func (p *Parser) End(time.Time) {}
