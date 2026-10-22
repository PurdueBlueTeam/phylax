// Package pop3 parses a POP3 session: command verbs, USER/PASS and AUTH PLAIN
// credentials (passwords hashed, never stored) and the server's +OK/-ERR
// replies. STLS ends parsing.
package pop3

import (
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/internal/lines"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// Parser is the per-connection POP3 parser.
type Parser struct {
	meta  txn.Meta
	emit  txn.Emit
	split [2]lines.Splitter

	start, last time.Time
	greeted     bool
	inMulti     bool // inside a multi-line reply body (RETR, LIST, ...)
	pending     []string
	cmds        []string
	user        string
	passHash    string
	mech        string
	authOK      *bool
	saslNext    bool
	stopped     bool
	emitted     bool
	tls         bool
	retrieved   int
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
	if p.saslNext {
		p.saslNext = false
		if u, pw, ok := lines.DecodePlain(line); ok {
			p.user, p.passHash = txn.Clip(u), txn.HashSecret(pw)
		}
		return
	}
	verb, arg := lines.Verb(line)
	if verb == "" {
		return
	}
	p.cmds = lines.Push(p.cmds, verb)
	if len(p.pending) < 64 {
		pv := verb
		if (verb == "LIST" || verb == "UIDL") && arg != "" {
			pv += "1" // single-line form
		}
		p.pending = append(p.pending, pv)
	}
	switch verb {
	case "USER":
		p.user, p.mech = txn.Clip(arg), "plain"
	case "PASS":
		p.passHash = txn.HashSecret(arg)
	case "AUTH":
		m, rest, _ := strings.Cut(arg, " ")
		p.mech = strings.ToLower(m)
		if p.mech == "plain" {
			if rest != "" {
				if u, pw, ok := lines.DecodePlain(rest); ok {
					p.user, p.passHash = txn.Clip(u), txn.HashSecret(pw)
				}
			} else {
				p.saslNext = true
			}
		}
	}
}

func (p *Parser) server(line string) {
	if p.inMulti {
		if line == "." {
			p.inMulti = false
		}
		return
	}
	ok := strings.HasPrefix(line, "+OK")
	if !ok && !strings.HasPrefix(line, "-ERR") {
		return
	}
	if !p.greeted {
		p.greeted = true
		return
	}
	verb := ""
	if len(p.pending) > 0 {
		verb, p.pending = p.pending[0], p.pending[1:]
	}
	switch verb {
	case "PASS":
		p.authOK = &ok
	case "AUTH":
		if p.mech == "plain" {
			p.authOK = &ok
		}
	case "STLS":
		if ok {
			p.tls = true
			p.stopped = true
		}
	case "RETR", "TOP", "LIST", "UIDL", "CAPA":
		if ok {
			p.inMulti = true
			if verb == "RETR" {
				p.retrieved++
			}
		}
	}
}

// End implements txn.Stream.
func (p *Parser) End(ts time.Time) {
	if p.emitted || (len(p.cmds) == 0 && !p.greeted) {
		return
	}
	p.emitted = true
	t := txn.New(p.meta, "pop3", "session", p.start)
	t.End = p.last
	t.EnsureList("pop3.cmds")
	t.Add("pop3.cmds", p.cmds...)
	if p.user != "" || p.passHash != "" {
		t.Cred = &txn.Cred{User: p.user, Mech: p.mech, PassHash: p.passHash}
		if p.passHash != "" {
			t.Secret = append(t.Secret, "cred.pass_hash")
		}
	}
	if p.authOK != nil {
		t.SetBool("pop3.auth_ok", *p.authOK)
		t.Succeeded(*p.authOK)
	}
	t.SetInt("pop3.retrieved", int64(p.retrieved))
	if p.tls {
		t.SetBool("pop3.tls", true)
	}
	p.emit(t)
}
