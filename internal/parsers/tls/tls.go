// Package tls extracts TLS handshake metadata from a reassembled stream:
// ClientHello (SNI, ALPN, versions, JA3, JA4, length), ServerHello (version,
// cipher, ALPN) and, for TLS 1.2 and earlier, the leaf certificate hash and
// subject. Nothing after the hello flights is read.
package tls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

const maxHandshake = 32 << 10

// Parser is the per-connection TLS metadata parser.
type Parser struct {
	meta    txn.Meta
	emit    txn.Emit
	dir     [2]side
	hello   *ClientHello
	t       txn.Txn
	started bool
	emitted bool
	alerts  int
}

type side struct {
	rec  []byte // partial record bytes
	hs   []byte // handshake bytes
	done bool   // stop parsing this direction
}

// New returns a stream parser.
func New(m txn.Meta, emit txn.Emit) txn.Stream { return &Parser{meta: m, emit: emit} }

// Sniff reports whether b starts like a TLS handshake record.
func Sniff(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04
}

// Data implements txn.Stream.
func (p *Parser) Data(d txn.Dir, b []byte, ts time.Time) {
	s := &p.dir[d]
	if s.done || p.emitted {
		return
	}
	s.rec = append(s.rec, b...)
	for !s.done {
		if len(s.rec) < 5 {
			return
		}
		typ, ver, n := s.rec[0], binary.BigEndian.Uint16(s.rec[1:]), int(binary.BigEndian.Uint16(s.rec[3:]))
		if ver>>8 != 3 || n > 1<<14+2048 || (typ != 22 && typ != 21 && typ != 20 && typ != 23) {
			s.done = true // not TLS
			return
		}
		if len(s.rec) < 5+n {
			return
		}
		body := s.rec[5 : 5+n]
		s.rec = s.rec[5+n:]
		switch typ {
		case 22:
			if len(s.hs)+len(body) > maxHandshake {
				s.done = true
				return
			}
			s.hs = append(s.hs, body...)
			p.handshake(d, s, ts)
		case 21:
			p.alerts++
		default: // CCS or application data: the flight we care about is over
			s.done = true
		}
	}
}

func (p *Parser) handshake(d txn.Dir, s *side, ts time.Time) {
	for len(s.hs) >= 4 {
		ht := s.hs[0]
		n := int(s.hs[1])<<16 | int(s.hs[2])<<8 | int(s.hs[3])
		if n > maxHandshake {
			s.done = true
			return
		}
		if len(s.hs) < 4+n {
			return
		}
		body := s.hs[4 : 4+n]
		switch {
		case d == txn.C2S && ht == 1 && p.hello == nil:
			if h, err := ParseClientHello(body, 4+n); err == nil {
				p.hello = h
				p.start(h, ts)
			} else {
				s.done = true
			}
		case d == txn.S2C && ht == 2 && p.started:
			p.serverHello(body)
			if p.t.Attr["tls.sh_version"] == "0x0304" { // 1.3: everything after is encrypted
				p.finish(ts)
				return
			}
		case d == txn.S2C && ht == 11 && p.started:
			p.certificate(body)
		case d == txn.S2C && ht == 14: // ServerHelloDone ends the TLS 1.2 flight
			p.finish(ts)
			return
		}
		s.hs = s.hs[4+n:]
	}
}

func (p *Parser) start(h *ClientHello, ts time.Time) {
	t := txn.New(p.meta, "tls", "handshake", ts)
	t.Set("tls.ja3", h.JA3())
	t.Set("tls.ja3_string", h.JA3String())
	t.Set("tls.ja4", h.JA4())
	t.Set("tls.sni", txn.Clip(h.SNI))
	t.SetInt("tls.hello_len", int64(h.Len))
	t.Set("tls.version", fmt.Sprintf("0x%04x", h.MaxVersion()))
	t.SetInt("tls.cipher_count", int64(len(h.Ciphers)))
	t.SetInt("tls.ext_count", int64(len(h.Extensions)))
	t.EnsureList("tls.alpn")
	for _, a := range h.ALPN {
		t.Add("tls.alpn", txn.Clip(a))
	}
	p.t, p.started = t, true
}

func (p *Parser) serverHello(b []byte) {
	r := &rd{b: b}
	ver := r.u16()
	r.take(32)
	r.take(r.u8())
	cipher := r.u16()
	r.u8() // compression
	if r.err != nil {
		return
	}
	p.t.Set("tls.sh_cipher", fmt.Sprintf("0x%04x", cipher))
	selected := ver
	if len(r.b) >= 2 {
		er := &rd{b: r.take(r.u16())}
		for len(er.b) >= 4 {
			t, l := er.u16(), er.u16()
			d := er.take(l)
			if er.err != nil {
				break
			}
			switch t {
			case extSuppVers:
				if len(d) >= 2 {
					selected = int(binary.BigEndian.Uint16(d))
				}
			case extALPN:
				lr := &rd{b: d}
				lr.u16()
				p.t.Set("tls.sh_alpn", txn.Clip(string(lr.take(lr.u8()))))
			}
		}
	}
	p.t.Set("tls.sh_version", fmt.Sprintf("0x%04x", selected))
}

func (p *Parser) certificate(b []byte) {
	if len(b) < 6 {
		return
	}
	chain := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	if chain > len(b)-3 {
		return
	}
	n := int(b[3])<<16 | int(b[4])<<8 | int(b[5])
	if n > len(b)-6 || n == 0 {
		return
	}
	der := b[6 : 6+n]
	h := sha256.Sum256(der)
	p.t.Set("tls.cert_sha256", hex.EncodeToString(h[:]))
	if c, err := x509.ParseCertificate(der); err == nil {
		p.t.Set("tls.cert_subject", txn.Clip(c.Subject.String()))
		p.t.Set("tls.cert_issuer", txn.Clip(c.Issuer.String()))
		p.t.Set("tls.cert_not_after", c.NotAfter.UTC().Format(time.RFC3339))
	}
}

func (p *Parser) finish(ts time.Time) {
	if p.emitted || !p.started {
		return
	}
	p.emitted = true
	p.t.End = ts
	if p.alerts > 0 {
		p.t.SetInt("tls.alerts", int64(p.alerts))
	}
	p.emit(p.t)
}

// End implements txn.Stream.
func (p *Parser) End(ts time.Time) { p.finish(ts) }
