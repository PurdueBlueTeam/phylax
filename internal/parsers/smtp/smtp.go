// Package smtp parses an SMTP session: EHLO argument, AUTH mechanism and user
// (password hashed, never stored), MAIL FROM parameters, RCPT TO, and the
// DATA section's Subject and body. A body is stored only when it is at most
// 128 bytes (the scorer's is 64 hex digits); otherwise only its length and
// hash are kept.
package smtp

import (
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/internal/lines"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

const (
	maxData     = 16 << 10
	maxBodyKeep = 128
)

type authStep int

const (
	authNone authStep = iota
	authPlain
	authLoginUser
	authLoginPass
)

// Parser is the per-connection SMTP parser.
type Parser struct {
	meta  txn.Meta
	emit  txn.Emit
	split [2]lines.Splitter

	start, last time.Time
	greeted     bool
	pending     []string
	cmds        []string
	ehlo        string
	mech        string
	user        string
	passHash    string
	authOK      *bool
	step        authStep
	mailParams  string
	from        string
	rcpts       []string
	inData      bool
	data        []byte
	dataLines   int
	dataBytes   int
	subject     string
	body        string
	bodyLen     int
	bodySum     string
	msgs        int
	delivered   int
	stopped     bool
	emitted     bool
	multi       string
	tls         bool
}

// New returns a stream parser.
func New(m txn.Meta, emit txn.Emit) txn.Stream { return &Parser{meta: m, emit: emit} }

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
	if p.inData {
		p.dataLine(line)
		return
	}
	switch p.step {
	case authPlain:
		p.step = authNone
		p.plain(line)
		return
	case authLoginUser:
		if u, ok := lines.DecodeB64(line); ok {
			p.user = txn.Clip(u)
		}
		p.step = authLoginPass
		return
	case authLoginPass:
		if pw, ok := lines.DecodeB64(line); ok {
			p.passHash = txn.HashSecret(pw)
		}
		p.step = authNone
		return
	}
	verb, arg := lines.Verb(line)
	if verb == "" {
		return
	}
	p.cmds = lines.Push(p.cmds, verb)
	if len(p.pending) < 64 {
		p.pending = append(p.pending, verb)
	}
	switch verb {
	case "EHLO", "HELO":
		p.ehlo = txn.Clip(arg)
	case "AUTH":
		mech, rest, _ := strings.Cut(arg, " ")
		p.mech = strings.ToLower(mech)
		switch p.mech {
		case "plain":
			if rest != "" {
				p.plain(rest)
			} else {
				p.step = authPlain
			}
		case "login":
			if rest != "" {
				if u, ok := lines.DecodeB64(rest); ok {
					p.user = txn.Clip(u)
				}
				p.step = authLoginPass
			} else {
				p.step = authLoginUser
			}
		}
	case "MAIL":
		p.mailParams, p.from = parseMail(arg)
		p.rcpts = nil
	case "RCPT":
		if a := angle(arg); a != "" {
			p.rcpts = lines.Push(p.rcpts, txn.Clip(a))
		}
	}
}

func (p *Parser) plain(b64 string) {
	if u, pw, ok := lines.DecodePlain(b64); ok {
		p.user, p.passHash = txn.Clip(u), txn.HashSecret(pw)
	}
}

func angle(arg string) string {
	i := strings.IndexByte(arg, '<')
	j := strings.IndexByte(arg, '>')
	if i < 0 || j < i {
		return ""
	}
	return arg[i+1 : j]
}

func parseMail(arg string) (params, from string) {
	from = txn.Clip(angle(arg))
	if j := strings.IndexByte(arg, '>'); j >= 0 {
		params = strings.TrimSpace(arg[j+1:])
	}
	return strings.ToUpper(params), from
}

func (p *Parser) dataLine(line string) {
	if line == "." {
		p.inData = false
		p.finishData()
		return
	}
	if strings.HasPrefix(line, "..") {
		line = line[1:]
	}
	p.dataBytes += len(line) + 2
	if len(p.data) < maxData {
		p.data = append(p.data, line...)
		p.data = append(p.data, '\n')
	}
}

func (p *Parser) finishData() {
	raw := string(p.data)
	hdr, body, found := strings.Cut(raw, "\n\n")
	if !found {
		hdr, body = "", raw
	}
	if hdr != "" {
		for _, l := range strings.Split(hdr, "\n") {
			if len(l) > 8 && strings.EqualFold(l[:8], "subject:") {
				p.subject = txn.Clip(strings.TrimSpace(l[8:]))
			}
		}
	}
	body = strings.TrimSpace(body)
	p.bodyLen = len(body)
	p.bodySum = txn.SHA256Hex([]byte(body))
	if len(body) <= maxBodyKeep {
		p.body = body
	} else {
		p.body = ""
	}
	p.msgs++
	p.data = p.data[:0]
	if len(p.pending) < 64 {
		p.pending = append(p.pending, ".")
	}
}

func (p *Parser) server(line string) {
	if len(line) < 3 {
		return
	}
	if len(line) > 3 && line[3] == '-' {
		if p.multi == "" {
			p.multi = line[:3]
		}
		return
	}
	code := line[:3]
	if code[0] < '1' || code[0] > '5' {
		return
	}
	if p.multi != "" && p.multi != code {
		return
	}
	p.multi = ""
	if !p.greeted {
		p.greeted = true
		if len(p.pending) == 0 {
			return
		}
	}
	if code == "334" || code[0] == '1' {
		return
	}
	verb := ""
	if len(p.pending) > 0 {
		verb, p.pending = p.pending[0], p.pending[1:]
	}
	switch verb {
	case "AUTH":
		ok := code[0] == '2'
		p.authOK = &ok
	case "STARTTLS":
		if code[0] == '2' {
			p.tls = true
			p.stopped = true
		}
	case "DATA":
		if code == "354" {
			p.inData = true
			p.data = p.data[:0]
		}
	case ".":
		if code[0] == '2' {
			p.delivered++
		}
	}
}

// End implements txn.Stream.
func (p *Parser) End(ts time.Time) {
	if p.emitted || (len(p.cmds) == 0 && !p.greeted) {
		return
	}
	p.emitted = true
	t := txn.New(p.meta, "smtp", "session", p.start)
	t.End = p.last
	t.EnsureList("smtp.cmds")
	t.Add("smtp.cmds", p.cmds...)
	t.Set("smtp.ehlo_arg", p.ehlo)
	if p.mailParams != "" {
		t.Set("smtp.mail_ext", txn.Clip(p.mailParams))
	}
	if p.from != "" {
		t.Set("smtp.from", p.from)
	}
	if len(p.rcpts) > 0 {
		t.Add("smtp.rcpts", p.rcpts...)
	}
	if p.mech != "" {
		t.Set("smtp.auth_mech", p.mech)
	}
	if p.user != "" || p.passHash != "" {
		t.Cred = &txn.Cred{User: p.user, Mech: p.mech, PassHash: p.passHash}
		if p.passHash != "" {
			t.Secret = append(t.Secret, "cred.pass_hash")
		}
	}
	if p.authOK != nil {
		t.SetBool("smtp.auth_ok", *p.authOK)
		t.Succeeded(*p.authOK)
	}
	if p.msgs > 0 {
		t.SetInt("smtp.messages", int64(p.msgs))
		t.SetInt("smtp.delivered", int64(p.delivered))
		t.Set("smtp.subject", p.subject)
		t.SetInt("smtp.body_len", int64(p.bodyLen))
		t.Set("smtp.body_sha256", p.bodySum)
		if p.body != "" {
			t.Set("smtp.body", p.body)
		}
	}
	if p.tls {
		t.SetBool("smtp.tls", true)
	}
	p.emit(t)
}
