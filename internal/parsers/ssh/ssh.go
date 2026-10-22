// Package ssh extracts what is visible before SSH encryption starts: both
// identification banners, both KEXINIT algorithm lists, HASSH (client) and
// HASSHServer, and the session dwell time. Authentication methods, PTY and
// shell requests are encrypted and cannot be read from packets; those features
// (ssh.auth, ssh.pty, ssh.fail_then_accept) must come from sshd logs.
package ssh

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

const (
	maxBanner  = 512
	maxPacket  = 35000
	msgKexInit = 20
	msgNewKeys = 21
)

// KexInit is a decoded SSH_MSG_KEXINIT.
type KexInit struct {
	Kex, HostKey, EncC2S, EncS2C, MacC2S, MacS2C, CompC2S, CompS2C []string
}

// HASSHString is the client fingerprint input: kex;enc_c2s;mac_c2s;comp_c2s.
func (k KexInit) HASSHString() string {
	return strings.Join(k.Kex, ",") + ";" + strings.Join(k.EncC2S, ",") + ";" +
		strings.Join(k.MacC2S, ",") + ";" + strings.Join(k.CompC2S, ",")
}

// HASSHServerString is the server fingerprint input: kex;enc_s2c;mac_s2c;comp_s2c.
func (k KexInit) HASSHServerString() string {
	return strings.Join(k.Kex, ",") + ";" + strings.Join(k.EncS2C, ",") + ";" +
		strings.Join(k.MacS2C, ",") + ";" + strings.Join(k.CompS2C, ",")
}

// MD5Hex hashes a fingerprint string.
func MD5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// ParseKexInit decodes a KEXINIT payload (starting at the message type byte).
func ParseKexInit(p []byte) (KexInit, bool) {
	var k KexInit
	if len(p) < 17 || p[0] != msgKexInit {
		return k, false
	}
	p = p[17:]
	lists := make([][]string, 10)
	for i := range lists {
		if len(p) < 4 {
			return k, false
		}
		n := int(binary.BigEndian.Uint32(p))
		if n < 0 || n > len(p)-4 {
			return k, false
		}
		s := string(p[4 : 4+n])
		p = p[4+n:]
		if s != "" {
			lists[i] = strings.Split(s, ",")
		}
	}
	k = KexInit{Kex: lists[0], HostKey: lists[1], EncC2S: lists[2], EncS2C: lists[3],
		MacC2S: lists[4], MacS2C: lists[5], CompC2S: lists[6], CompS2C: lists[7]}
	return k, true
}

type side struct {
	buf    []byte
	banner string
	gotB   bool
	kex    *KexInit
	done   bool
	newkey time.Time
}

// Parser is the per-connection SSH parser.
type Parser struct {
	meta        txn.Meta
	emit        txn.Emit
	s           [2]side
	first, last time.Time
	emitted     bool
}

// New returns a stream parser.
func New(m txn.Meta, emit txn.Emit) txn.Stream { return &Parser{meta: m, emit: emit} }

// Sniff reports whether b starts with an SSH identification string.
func Sniff(b []byte) bool { return bytes.HasPrefix(b, []byte("SSH-")) }

// Data implements txn.Stream.
func (p *Parser) Data(d txn.Dir, b []byte, ts time.Time) {
	if p.first.IsZero() {
		p.first = ts
	}
	p.last = ts
	s := &p.s[d]
	if s.done {
		return
	}
	s.buf = append(s.buf, b...)
	for !s.done {
		if !s.gotB {
			i := bytes.IndexByte(s.buf, '\n')
			if i < 0 {
				if len(s.buf) > maxBanner {
					s.done = true
				}
				return
			}
			line := strings.TrimRight(string(s.buf[:i]), "\r")
			s.buf = s.buf[i+1:]
			if strings.HasPrefix(line, "SSH-") {
				s.banner, s.gotB = line, true
			} else if d == txn.C2S || len(line) > maxBanner {
				s.done = true // a client must open with its banner
			}
			continue
		}
		if len(s.buf) < 5 {
			return
		}
		n := int(binary.BigEndian.Uint32(s.buf))
		if n < 2 || n > maxPacket {
			s.done = true
			return
		}
		if len(s.buf) < 4+n {
			if cap(s.buf) > 2*maxPacket {
				s.done = true
			}
			return
		}
		pad := int(s.buf[4])
		if pad >= n-1 {
			s.done = true
			return
		}
		payload := s.buf[5 : 4+n-pad : 4+n-pad]
		if len(payload) > 0 {
			switch payload[0] {
			case msgKexInit:
				if k, ok := ParseKexInit(payload); ok && s.kex == nil {
					s.kex = &k
				}
			case msgNewKeys:
				s.newkey = ts
				s.done = true
			}
		}
		s.buf = s.buf[4+n:]
	}
	if s.done {
		s.buf = nil
	}
}

// End implements txn.Stream.
func (p *Parser) End(ts time.Time) {
	if p.emitted {
		return
	}
	p.emitted = true
	c, sv := &p.s[txn.C2S], &p.s[txn.S2C]
	if c.banner == "" && sv.banner == "" {
		return
	}
	t := txn.New(p.meta, "ssh", "session", p.first)
	t.End = p.last
	t.Set("ssh.banner", txn.Clip(c.banner))
	t.Set("ssh.server_banner", txn.Clip(sv.banner))
	if c.kex != nil {
		hs := c.kex.HASSHString()
		t.Set("ssh.hassh", MD5Hex(hs))
		t.Set("ssh.hassh_string", hs[:min(len(hs), 2048)])
		t.Set("ssh.hostkey_algs", txn.Clip(strings.Join(c.kex.HostKey, ",")))
	}
	if sv.kex != nil {
		t.Set("ssh.hassh_server", MD5Hex(sv.kex.HASSHServerString()))
	}
	t.SetBool("ssh.kex_seen", c.kex != nil)
	t.SetBool("ssh.encrypted", !c.newkey.IsZero())
	t.SetInt("ssh.dwell_ms", p.last.Sub(p.first).Milliseconds())
	p.emit(t)
}
