// Package ftp parses the FTP control channel: command verbs, login (password
// hashed, never stored), replies, transferred file names, and the data
// channels announced by PASV/EPSV/PORT/EPRT so the capture engine can link the
// data connection to this session.
package ftp

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/internal/lines"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// Parser is the per-connection FTP control parser.
type Parser struct {
	meta  txn.Meta
	emit  txn.Emit
	split [2]lines.Splitter

	start, last time.Time
	banner      string
	gotBanner   bool
	pending     []string // unanswered command verbs
	cmds        []string
	files       []string
	user        string
	passHash    string
	authOK      *bool
	dataPorts   []string
	multi       string // code of an open multi-line reply
	lastCode    int
	stopped     bool
	emitted     bool
	tls         bool
	xferOK      int
	xferBad     int
}

// New returns a stream parser.
func New(m txn.Meta, emit txn.Emit) txn.Stream {
	return &Parser{meta: m, emit: emit}
}

// Data implements txn.Stream.
func (p *Parser) Data(d txn.Dir, b []byte, ts time.Time) {
	if p.stopped {
		return
	}
	if p.start.IsZero() {
		p.start = ts
	}
	p.last = ts
	p.split[d].Write(b, func(line []byte, long bool) bool {
		if d == txn.C2S {
			p.client(string(line))
		} else {
			p.server(string(line))
		}
		return !p.stopped
	})
}

func (p *Parser) client(line string) {
	verb, arg := lines.Verb(line)
	if verb == "" {
		return
	}
	p.cmds = lines.Push(p.cmds, verb)
	if len(p.pending) < 64 {
		p.pending = append(p.pending, verb)
	}
	switch verb {
	case "USER":
		p.user = txn.Clip(arg)
	case "PASS":
		p.passHash = txn.HashSecret(arg)
	case "RETR", "STOR", "APPE", "STOU", "DELE", "RNFR", "RNTO", "LIST", "NLST", "MLSD", "MLST", "SIZE", "CWD":
		if arg != "" && verb != "CWD" && verb != "SIZE" {
			p.files = lines.Push(p.files, verb+" "+txn.Clip(arg))
		}
	case "PORT":
		if ap, ok := parsePort(arg); ok {
			p.expect(ap, "ftp-data(active)")
		}
	case "EPRT":
		if ap, ok := parseEPRT(arg); ok {
			p.expect(ap, "ftp-data(active)")
		}
	}
}

func (p *Parser) expect(ap netip.AddrPort, note string) {
	p.dataPorts = lines.Push(p.dataPorts, ap.String())
	if p.meta.Expect != nil {
		p.meta.Expect(ap, note)
	}
}

func (p *Parser) server(line string) {
	if len(line) < 3 {
		return
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return
	}
	if len(line) > 3 && line[3] == '-' {
		if p.multi == "" {
			p.multi = line[:3]
		}
		if !p.gotBanner && code == 220 && p.banner == "" {
			p.banner = txn.Clip(line[4:])
		}
		return
	}
	if p.multi != "" && p.multi != line[:3] {
		return // inside a multi-line reply
	}
	p.multi = ""
	text := ""
	if len(line) > 4 {
		text = line[4:]
	}
	if !p.gotBanner {
		p.gotBanner = true
		if p.banner == "" {
			p.banner = txn.Clip(text)
		}
		if len(p.pending) == 0 {
			return
		}
	}
	if code/100 == 1 { // preliminary; the final reply follows
		return
	}
	verb := ""
	if len(p.pending) > 0 {
		verb, p.pending = p.pending[0], p.pending[1:]
	}
	p.lastCode = code
	switch verb {
	case "PASS":
		ok := code == 230
		p.authOK = &ok
	case "PASV":
		if code == 227 {
			if ap, ok := parsePASV(text, p.meta.Server.Addr()); ok {
				p.expect(ap, "ftp-data(passive)")
			}
		}
	case "EPSV":
		if code == 229 {
			if port, ok := parseEPSV(text); ok {
				p.expect(netip.AddrPortFrom(p.meta.Server.Addr(), port), "ftp-data(passive)")
			}
		}
	case "RETR", "STOR", "APPE", "STOU":
		if code/100 == 2 {
			p.xferOK++
		} else {
			p.xferBad++
		}
	case "AUTH":
		if code/100 == 2 || code == 234 {
			p.tls = true
			p.stopped = true
		}
	}
}

func parsePASV(text string, fallback netip.Addr) (netip.AddrPort, bool) {
	i := strings.IndexByte(text, '(')
	j := strings.IndexByte(text, ')')
	var inner string
	if i >= 0 && j > i {
		inner = text[i+1 : j]
	} else {
		// some servers omit the parentheses
		k := strings.IndexAny(text, "0123456789")
		if k < 0 {
			return netip.AddrPort{}, false
		}
		inner = text[k:]
	}
	ap, ok := parsePort(inner)
	if !ok {
		return ap, false
	}
	// A server behind NAT announces a private address: the data connection
	// still goes to the address the control connection used.
	if fallback.IsValid() {
		ap = netip.AddrPortFrom(fallback, ap.Port())
	}
	return ap, true
}

func parsePort(s string) (netip.AddrPort, bool) {
	f := strings.Split(strings.TrimSpace(s), ",")
	if len(f) != 6 {
		return netip.AddrPort{}, false
	}
	var v [6]int
	for i := range f {
		n, err := strconv.Atoi(strings.TrimSpace(f[i]))
		if err != nil || n < 0 || n > 255 {
			return netip.AddrPort{}, false
		}
		v[i] = n
	}
	a := netip.AddrFrom4([4]byte{byte(v[0]), byte(v[1]), byte(v[2]), byte(v[3])})
	return netip.AddrPortFrom(a, uint16(v[4]<<8|v[5])), true
}

func parseEPSV(text string) (uint16, bool) {
	i := strings.IndexByte(text, '(')
	j := strings.IndexByte(text, ')')
	if i < 0 || j < i+2 {
		return 0, false
	}
	in := text[i+1 : j]
	d := in[0]
	f := strings.Split(in, string(d))
	if len(f) < 5 {
		return 0, false
	}
	n, err := strconv.Atoi(f[3])
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}

func parseEPRT(arg string) (netip.AddrPort, bool) {
	if len(arg) < 5 {
		return netip.AddrPort{}, false
	}
	f := strings.Split(arg, string(arg[0]))
	if len(f) < 5 {
		return netip.AddrPort{}, false
	}
	a, err := netip.ParseAddr(f[2])
	if err != nil {
		return netip.AddrPort{}, false
	}
	n, err := strconv.Atoi(f[3])
	if err != nil || n < 1 || n > 65535 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a, uint16(n)), true
}

// End implements txn.Stream.
func (p *Parser) End(ts time.Time) {
	if p.emitted || (len(p.cmds) == 0 && !p.gotBanner) {
		return
	}
	p.emitted = true
	t := txn.New(p.meta, "ftp", "session", p.start)
	t.End = p.last
	t.Set("ftp.banner", p.banner)
	t.EnsureList("ftp.cmds")
	t.Add("ftp.cmds", p.cmds...)
	if len(p.files) > 0 {
		t.Add("ftp.files", p.files...)
	}
	if len(p.dataPorts) > 0 {
		t.Add("ftp.data_channels", p.dataPorts...)
	}
	if p.user != "" || p.passHash != "" {
		t.Cred = &txn.Cred{User: p.user, Mech: "plain", PassHash: p.passHash}
		if p.passHash != "" {
			t.Secret = append(t.Secret, "cred.pass_hash")
		}
	}
	if p.authOK != nil {
		t.SetBool("ftp.auth_ok", *p.authOK)
		t.Succeeded(*p.authOK)
	}
	t.SetInt("ftp.transfers_ok", int64(p.xferOK))
	t.SetInt("ftp.transfers_failed", int64(p.xferBad))
	if p.tls {
		t.SetBool("ftp.tls", true)
	}
	p.emit(t)
}
