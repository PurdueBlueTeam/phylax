// Package imap parses an IMAP4 session: tags, command verbs, LOGIN and
// AUTHENTICATE users (passwords hashed, never stored) and the tagged result of
// authentication. STARTTLS ends parsing.
package imap

import (
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/internal/lines"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// Parser is the per-connection IMAP parser.
type Parser struct {
	meta  txn.Meta
	emit  txn.Emit
	split [2]lines.Splitter

	start, last time.Time
	greeted     bool
	cmds        []string
	firstTag    string
	loginTag    string
	user        string
	passHash    string
	mech        string
	authOK      *bool
	tags        map[string]string // outstanding tag -> verb
	saslTag     string            // waiting for the client's SASL response line
	mailboxes   []string
	stopped     bool
	emitted     bool
	tls         bool
}

// New returns a stream parser.
func New(m txn.Meta, emit txn.Emit) txn.Stream {
	return &Parser{meta: m, emit: emit, tags: map[string]string{}}
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

// args splits an IMAP argument string into atoms and quoted strings.
func args(s string) []string {
	var out []string
	i := 0
	for i < len(s) && len(out) < 16 {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '"' {
			var sb strings.Builder
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				sb.WriteByte(s[i])
				i++
			}
			i++
			out = append(out, sb.String())
			continue
		}
		j := i
		for j < len(s) && s[j] != ' ' {
			j++
		}
		out = append(out, s[i:j])
		i = j
	}
	return out
}

func (p *Parser) client(line string) {
	if p.saslTag != "" {
		p.saslTag = ""
		if line != "*" {
			if u, pw, ok := lines.DecodePlain(line); ok {
				p.user, p.passHash = txn.Clip(u), txn.HashSecret(pw)
			}
		}
		return
	}
	tag, rest, ok := strings.Cut(line, " ")
	if !ok || tag == "" || strings.ContainsAny(tag, "*+") {
		return
	}
	verb, arg := lines.Verb(rest)
	if verb == "" {
		return
	}
	if p.firstTag == "" {
		p.firstTag = txn.Clip(tag)
	}
	p.cmds = lines.Push(p.cmds, verb)
	if len(p.tags) < 64 {
		p.tags[tag] = verb
	}
	switch verb {
	case "LOGIN":
		a := args(arg)
		p.loginTag, p.mech = tag, "login"
		if len(a) >= 1 {
			p.user = txn.Clip(a[0])
		}
		if len(a) >= 2 {
			p.passHash = txn.HashSecret(a[1])
		}
	case "AUTHENTICATE":
		a := args(arg)
		p.loginTag = tag
		if len(a) >= 1 {
			p.mech = strings.ToLower(a[0])
		}
		if p.mech == "plain" {
			if len(a) >= 2 {
				if u, pw, ok := lines.DecodePlain(a[1]); ok {
					p.user, p.passHash = txn.Clip(u), txn.HashSecret(pw)
				}
			} else {
				p.saslTag = tag
			}
		}
	case "SELECT", "EXAMINE", "LIST", "LSUB", "STATUS", "CREATE", "DELETE":
		if a := args(arg); len(a) > 0 && verb != "LIST" && verb != "LSUB" {
			p.mailboxes = lines.Push(p.mailboxes, verb+" "+txn.Clip(a[0]))
		}
	}
}

func (p *Parser) server(line string) {
	if !p.greeted && strings.HasPrefix(line, "* ") {
		p.greeted = true
		return
	}
	tag, rest, ok := strings.Cut(line, " ")
	if !ok || tag == "*" || tag == "+" {
		return
	}
	verb, outstanding := p.tags[tag]
	if !outstanding {
		return
	}
	delete(p.tags, tag)
	status, _ := lines.Verb(rest)
	switch verb {
	case "LOGIN", "AUTHENTICATE":
		if tag == p.loginTag {
			ok := status == "OK"
			p.authOK = &ok
		}
	case "STARTTLS":
		if status == "OK" {
			p.tls = true
			p.stopped = true
		}
	}
}

// End implements txn.Stream.
func (p *Parser) End(ts time.Time) {
	if p.emitted || (len(p.cmds) == 0 && !p.greeted) {
		return
	}
	p.emitted = true
	t := txn.New(p.meta, "imap", "session", p.start)
	t.End = p.last
	t.EnsureList("imap.cmds")
	t.Add("imap.cmds", p.cmds...)
	if p.firstTag != "" {
		t.Set("imap.tag", p.firstTag)
	}
	if len(p.mailboxes) > 0 {
		t.Add("imap.mailboxes", p.mailboxes...)
	}
	if p.mech != "" {
		t.Set("imap.auth_mech", p.mech)
	}
	if p.user != "" || p.passHash != "" {
		t.Cred = &txn.Cred{User: p.user, Mech: p.mech, PassHash: p.passHash}
		if p.passHash != "" {
			t.Secret = append(t.Secret, "cred.pass_hash")
		}
	}
	if p.authOK != nil {
		t.SetBool("imap.auth_ok", *p.authOK)
		t.Succeeded(*p.authOK)
	}
	if p.tls {
		t.SetBool("imap.tls", true)
	}
	p.emit(t)
}
