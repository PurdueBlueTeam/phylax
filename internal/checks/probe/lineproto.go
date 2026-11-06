package probe

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// lineConn is a CRLF line protocol connection.
type lineConn struct {
	net.Conn
	r *bufio.Reader
}

func newLineConn(c net.Conn) *lineConn { return &lineConn{Conn: c, r: bufio.NewReaderSize(c, 8192)} }

func (c *lineConn) readLine() (string, error) {
	l, err := c.r.ReadString('\n')
	if err != nil && l == "" {
		return "", err
	}
	if len(l) > 64<<10 {
		return "", fmt.Errorf("line too long")
	}
	return strings.TrimRight(l, "\r\n"), nil
}

func (c *lineConn) send(format string, a ...any) error {
	_, err := io.WriteString(c.Conn, fmt.Sprintf(format, a...)+"\r\n")
	return err
}

// tlsClient wraps c in TLS. verify mirrors the scorer: IMAP/POP3 verify the
// certificate (so self-signed certs fail there too); SMTP/LDAP/HTTPS do not.
func (p *probe) tlsClient(ctx context.Context, c net.Conn, verify bool) (net.Conn, error) {
	h := p.spec.Host
	tc := tls.Client(c, &tls.Config{InsecureSkipVerify: !verify, ServerName: h})
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		return nil, failDebug(ClassProtocol, err.Error(), "tls handshake failed")
	}
	return tc, nil
}

func (p *probe) openLine(ctx context.Context, verify bool) (*lineConn, error) {
	c, err := p.dialSpec(ctx)
	if err != nil {
		return nil, err
	}
	if p.spec.Encrypted {
		if c, err = p.tlsClient(ctx, c, verify); err != nil {
			return nil, err
		}
	}
	return newLineConn(c), nil
}

func protoErr(err error, what string) error {
	if err == nil {
		return nil
	}
	return classify(err, what)
}

// ---- FTP ----

func ftpReply(c *lineConn) (int, string, error) {
	l, err := c.readLine()
	if err != nil {
		return 0, "", err
	}
	if len(l) < 3 {
		return 0, l, fmt.Errorf("short reply %q", l)
	}
	code, err := strconv.Atoi(l[:3])
	if err != nil {
		return 0, l, fmt.Errorf("bad reply %q", l)
	}
	if len(l) > 3 && l[3] == '-' {
		for {
			m, err := c.readLine()
			if err != nil {
				return code, l, err
			}
			if strings.HasPrefix(m, l[:3]+" ") {
				return code, m, nil
			}
		}
	}
	return code, l, nil
}

func ftpCmd(c *lineConn, format string, a ...any) (int, string, error) {
	if err := c.send(format, a...); err != nil {
		return 0, "", err
	}
	return ftpReply(c)
}

var epsvRE = regexp.MustCompile(`\(\|\|\|(\d+)\|\)`)

func probeFTP(ctx context.Context, p *probe) error {
	user, pass := "anonymous", "anonymous"
	if p.hasCr {
		user, pass = p.cred.User, p.cred.Pass.Reveal()
	}
	c, err := p.dialSpec(ctx)
	if err != nil {
		return failDebug(ClassUnreachable, "", "ftp connection failed")
	}
	lc := newLineConn(c)
	defer lc.Close()
	if code, msg, err := ftpReply(lc); err != nil || code != 220 {
		return failDebug(ClassProtocol, errStr(err, msg), "ftp connection failed")
	}
	p.step("banner")
	code, msg, err := ftpCmd(lc, "USER %s", user)
	if err == nil && code == 331 {
		code, msg, err = ftpCmd(lc, "PASS %s", pass)
	}
	if err != nil {
		return protoErr(err, "ftp login failed")
	}
	if code != 230 {
		return failDebug(ClassAuth, msg, "ftp login failed")
	}
	p.step("login")
	// Quotient's client issues these on every session.
	_, _, _ = ftpCmd(lc, "FEAT")
	_, _, _ = ftpCmd(lc, "TYPE I")
	_, _, _ = ftpCmd(lc, "OPTS UTF8 ON")
	if p.item.File == "" {
		_, _, _ = ftpCmd(lc, "QUIT")
		return nil
	}
	code, msg, err = ftpCmd(lc, "EPSV")
	m := epsvRE.FindStringSubmatch(msg)
	if err != nil || code != 229 || m == nil {
		return failDebug(ClassProtocol, msg, "failed to retrieve file %s", p.item.File)
	}
	dc, err := p.dial(ctx, "tcp", net.JoinHostPort(p.spec.Host, m[1]))
	if err != nil {
		return failDebug(ClassProtocol, "", "failed to retrieve file %s", p.item.File)
	}
	defer dc.Close()
	code, msg, err = ftpCmd(lc, "RETR %s", p.item.File)
	if err != nil || (code != 150 && code != 125) {
		return failDebug(ClassContent, errStr(err, msg), "failed to retrieve file %s", p.item.File)
	}
	data, err := io.ReadAll(io.LimitReader(dc, maxBody))
	if err != nil {
		return protoErr(err, "failed to retrieve file "+p.item.File)
	}
	p.step("retr")
	_ = dc.Close()
	if code, msg, err = ftpReply(lc); p.strict() && (err != nil || code != 226) {
		p.strictIssue("transfer not confirmed (%s)", errStr(err, msg))
	}
	_, _, _ = ftpCmd(lc, "QUIT")
	return checkFile(p, data, p.item.File)
}

func errStr(err error, msg string) string {
	if err != nil {
		return err.Error()
	}
	return msg
}

// checkFile applies the file expectations. Quotient: Regex xor SHA-256 (the
// regex wins when both are set). Strict: every configured expectation holds,
// and a file with no expectation must at least be non-empty.
func checkFile(p *probe, data []byte, name string) error {
	it := p.item
	switch {
	case it.Regex != "":
		re, err := regexp.Compile(it.Regex)
		if err != nil {
			return fail(ClassConfig, "bad regex: %v", err)
		}
		if !re.Match(data) {
			return fail(ClassContent, "couldn't find regex in file %s", name)
		}
		if p.strict() && it.SHA256 != "" && !hashEq(data, it.SHA256) {
			p.strictIssue("file hash differs from the expected hash")
		}
	case it.SHA256 != "":
		if !hashEq(data, it.SHA256) {
			return fail(ClassContent, "file hash did not match")
		}
	default:
		if p.strict() && len(data) == 0 {
			p.strictIssue("file is empty")
		}
	}
	return nil
}

func hashEq(data []byte, want string) bool {
	sum := sha256.Sum256(data)
	return strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(want))
}

// ---- SMTP ----

func smtpReply(c *lineConn) (int, []string, error) {
	var lines []string
	for {
		l, err := c.readLine()
		if err != nil {
			return 0, lines, err
		}
		lines = append(lines, l)
		if len(l) < 3 {
			return 0, lines, fmt.Errorf("bad reply %q", l)
		}
		code, err := strconv.Atoi(l[:3])
		if err != nil {
			return 0, lines, fmt.Errorf("bad reply %q", l)
		}
		if len(l) == 3 || l[3] == ' ' {
			return code, lines, nil
		}
	}
}

func smtpCmd(c *lineConn, format string, a ...any) (int, []string, error) {
	if err := c.send(format, a...); err != nil {
		return 0, nil, err
	}
	return smtpReply(c)
}

func probeSMTP(ctx context.Context, p *probe) error {
	lc, err := p.openLine(ctx, false)
	if err != nil {
		return err
	}
	defer lc.Close()
	if code, ls, err := smtpReply(lc); err != nil || code != 220 {
		return failDebug(ClassProtocol, strings.Join(ls, "|"), "smtp greeting failed")
	}
	p.step("banner")
	code, ls, err := smtpCmd(lc, "EHLO localhost")
	if err != nil || code != 250 {
		return failDebug(ClassProtocol, strings.Join(ls, "|"), "smtp EHLO failed")
	}
	authAdvertised := false
	for _, l := range ls {
		if len(l) > 4 && strings.HasPrefix(strings.ToUpper(l[4:]), "AUTH") {
			authAdvertised = true
		}
	}
	if !p.hasCr || !(p.spec.RequireAuth || authAdvertised) {
		_, _, _ = smtpCmd(lc, "QUIT")
		return nil
	}
	user := p.userAt()
	tok := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + p.cred.Pass.Reveal()))
	// AUTH PLAIN over plaintext (the scorer wraps the client to allow it); never STARTTLS.
	if code, ls, err = smtpCmd(lc, "AUTH PLAIN %s", tok); err != nil {
		return protoErr(err, "login failed")
	} else if code != 235 {
		return failDebug(ClassAuth, strings.Join(ls, "|"), "login failed for %s", p.cred.User)
	}
	p.step("auth")
	if code, ls, err = smtpCmd(lc, "MAIL FROM:<%s> BODY=8BITMIME", user); err != nil || code/100 != 2 {
		return failDebug(ClassProtocol, errStr(err, strings.Join(ls, "|")), "setting sender failed")
	}
	rcpt := user
	var others []Cred
	for _, c := range p.spec.Creds {
		if c.User != p.cred.User {
			others = append(others, c)
		}
	}
	if len(others) > 0 {
		o := others[p.rng.IntN(len(others))]
		rcpt = o.User
		if p.spec.Domain != "" && !strings.Contains(rcpt, "@") {
			rcpt += "@" + p.spec.Domain
		}
	}
	if code, ls, err = smtpCmd(lc, "RCPT TO:<%s>", rcpt); err != nil || code/100 != 2 {
		return failDebug(ClassProtocol, errStr(err, strings.Join(ls, "|")), "setting receiver failed")
	}
	if code, ls, err = smtpCmd(lc, "DATA"); err != nil || code != 354 {
		return failDebug(ClassProtocol, errStr(err, strings.Join(ls, "|")), "creating email writer failed")
	}
	body := "Subject: " + randHex(p.rng, 8) + "\r\n\r\n" + randHex(p.rng, 32) + "\r\n"
	// The scorer's verdict is computed before the final "." is acknowledged.
	if _, err = io.WriteString(lc, body+".\r\n"); err != nil {
		return protoErr(err, "creating email writer failed")
	}
	p.step("data")
	if p.strict() {
		if code, ls, err = smtpReply(lc); err != nil || code/100 != 2 {
			p.strictIssue("message not accepted after DATA (%s)", errStr(err, strings.Join(ls, "|")))
		}
	}
	_ = lc.send("QUIT")
	return nil
}

// ---- IMAP ----

func imapQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// imapRun sends one tagged command and returns the untagged lines and the
// tagged status line.
func imapRun(c *lineConn, tag, cmd string) ([]string, string, error) {
	if err := c.send("%s %s", tag, cmd); err != nil {
		return nil, "", err
	}
	var un []string
	for {
		l, err := c.readLine()
		if err != nil {
			return un, "", err
		}
		if strings.HasPrefix(l, tag+" ") {
			return un, l[len(tag)+1:], nil
		}
		un = append(un, l)
	}
}

func randTag(p *probe, n int) string {
	const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = a[p.rng.IntN(len(a))]
	}
	return string(b)
}

func probeIMAP(ctx context.Context, p *probe) error {
	lc, err := p.openLine(ctx, true) // encrypted: verification on, like the scorer
	if err != nil {
		return err
	}
	defer lc.Close()
	g, err := lc.readLine()
	if err != nil || !strings.HasPrefix(g, "* OK") && !strings.HasPrefix(g, "* PREAUTH") {
		return failDebug(ClassProtocol, errStr(err, g), "connection to server failed")
	}
	p.step("banner")
	if !p.hasCr { // no credlist: passes on connect
		return nil
	}
	_, st, err := imapRun(lc, randTag(p, 6), "LOGIN "+imapQuote(p.userAt())+" "+imapQuote(p.cred.Pass.Reveal()))
	if err != nil {
		return protoErr(err, "login failed")
	}
	if !strings.HasPrefix(st, "OK") {
		return failDebug(ClassAuth, st, "login failed: creds %s", p.cred.User)
	}
	p.step("login")
	_, st, err = imapRun(lc, randTag(p, 6), `LIST "" "*"`)
	if err != nil || !strings.HasPrefix(st, "OK") {
		return failDebug(ClassProtocol, errStr(err, st), "listing mailboxes failed")
	}
	p.step("list")
	if p.strict() {
		if _, st, err = imapRun(lc, randTag(p, 6), "SELECT INBOX"); err != nil || !strings.HasPrefix(st, "OK") {
			p.strictIssue("SELECT INBOX failed (%s)", errStr(err, st))
		}
	}
	_, _, _ = imapRun(lc, randTag(p, 6), "LOGOUT")
	return nil
}

// ---- POP3 ----

func pop3Cmd(c *lineConn, format string, a ...any) (string, error) {
	if err := c.send(format, a...); err != nil {
		return "", err
	}
	l, err := c.readLine()
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(l, "+OK") {
		return l, fmt.Errorf("%s", l)
	}
	return l, nil
}

func probePOP3(ctx context.Context, p *probe) error {
	// The scorer dials with a fixed 3 s timeout.
	c, err := p.dialWithin(ctx, 3*time.Second, "tcp", p.spec.addr())
	if err != nil {
		return err
	}
	if p.spec.Encrypted {
		if c, err = p.tlsClient(ctx, c, true); err != nil {
			return err
		}
	}
	lc := newLineConn(c)
	defer lc.Close()
	g, err := lc.readLine()
	if err != nil || !strings.HasPrefix(g, "+OK") {
		return failDebug(ClassProtocol, errStr(err, g), "connection to server failed")
	}
	p.step("banner")
	if !p.hasCr {
		return nil
	}
	if r, err := pop3Cmd(lc, "USER %s", p.userAt()); err != nil {
		return failDebug(ClassAuth, r+" "+err.Error(), "login failed")
	}
	if r, err := pop3Cmd(lc, "PASS %s", p.cred.Pass.Reveal()); err != nil {
		return failDebug(ClassAuth, r, "login failed")
	}
	p.step("login")
	if _, err := pop3Cmd(lc, "NOOP"); err != nil {
		return failDebug(ClassProtocol, err.Error(), "listing mailboxes failed")
	}
	r, err := pop3Cmd(lc, "STAT")
	if err != nil {
		return failDebug(ClassProtocol, err.Error(), "listing mailboxes failed")
	}
	if p.strict() {
		f := strings.Fields(r)
		if len(f) != 3 {
			p.strictIssue("malformed STAT reply %q", r)
		} else if _, e1 := strconv.Atoi(f[1]); e1 != nil {
			p.strictIssue("malformed STAT reply %q", r)
		}
	}
	_, _ = pop3Cmd(lc, "QUIT")
	return nil
}

var _ = rand.Reader
