package checks

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// runSMTP sends the message via SMTP (STARTTLS when the server offers it,
// unless tls: false) and then retrieves the newest message from the mailbox
// over POP3, reporting the retrieved Subject header. The check passes when
// it matches expected.subject.
func runSMTP(ctx context.Context, ck Check) (map[string]any, error) {
	smtpHost, err := pstr(ck.Params, "smtp_host")
	if err != nil {
		return nil, err
	}
	from, err := pstr(ck.Params, "from")
	if err != nil {
		return nil, err
	}
	to, err := pstr(ck.Params, "to")
	if err != nil {
		return nil, err
	}
	subject, err := pstr(ck.Params, "subject")
	if err != nil {
		return nil, err
	}
	body := pstrOpt(ck.Params, "body")
	mailboxHost, err := pstr(ck.Params, "mailbox_host")
	if err != nil {
		return nil, err
	}
	mailUser, err := pstr(ck.Params, "mail_user")
	if err != nil {
		return nil, err
	}
	mailPass, err := pstr(ck.Params, "mail_pass")
	if err != nil {
		return nil, err
	}

	msg := mailMessage(from, to, subject, body)
	if err := smtpSend(ctx, ck, smtpHost, from, to, msg); err != nil {
		return nil, err
	}
	subj, err := pop3RetrieveSubject(ctx, ck, mailboxHost, mailUser, mailPass)
	if err != nil {
		return nil, err
	}
	return map[string]any{"subject": subj}, nil
}

func mailMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%d.%s@phylax>\r\n", time.Now().UnixNano(), from)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString(`Content-Type: text/plain; charset="utf-8"` + "\r\n\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// smtpSend delivers msg to to, using STARTTLS when advertised.
func smtpSend(ctx context.Context, ck Check, host, from, to string, msg []byte) error {
	addr, err := addrWithDefaultPort(host, ck)
	if err != nil {
		return fmt.Errorf("smtp: %v", err)
	}
	conn, err := net.DialTimeout("tcp", addr, dialTimeout(ctx))
	if err != nil {
		return fmt.Errorf("smtp: %v", err)
	}
	defer conn.Close()
	if err := setConnDeadline(conn, ctx); err != nil {
		return fmt.Errorf("smtp: %v", err)
	}
	rw := textproto.NewConn(conn)

	if _, _, err := rw.ReadResponse(2); err != nil {
		return fmt.Errorf("smtp: greeting: %v", err)
	}
	caps, err := smtpEhlo(rw, conn)
	if err != nil {
		return fmt.Errorf("smtp: EHLO: %v", err)
	}
	if pstrOpt(ck.Params, "tls") != "false" && strings.Contains(strings.ToUpper(caps), "STARTTLS") {
		if err := smtpCmd(conn, rw, 2, "STARTTLS"); err != nil {
			return fmt.Errorf("smtp: STARTTLS: %v", err)
		}
		cfg := &tls.Config{ServerName: hostnameOnly(addr)}
		if pstrOpt(ck.Params, "insecure_tls") == "true" {
			cfg.InsecureSkipVerify = true
		} else if pool, err := x509.SystemCertPool(); err == nil {
			cfg.RootCAs = pool
		}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("smtp: TLS handshake: %v", err)
		}
		conn = tc
		rw = textproto.NewConn(tc)
		if _, err := smtpEhlo(rw, tc); err != nil {
			return fmt.Errorf("smtp: EHLO after STARTTLS: %v", err)
		}
	}
	mailCmd := fmt.Sprintf("MAIL FROM:<%s>", from)
	if err := smtpCmd(conn, rw, 2, mailCmd); err != nil {
		return fmt.Errorf("smtp: MAIL: %v", err)
	}
	rcptCmd := fmt.Sprintf("RCPT TO:<%s>", to)
	if err := smtpCmd(conn, rw, 2, rcptCmd); err != nil {
		return fmt.Errorf("smtp: RCPT: %v", err)
	}
	if err := smtpCmd(conn, rw, 3, "DATA"); err != nil {
		return fmt.Errorf("smtp: DATA: %v", err)
	}
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("smtp: data: %v", err)
	}
	if !strings.HasSuffix(string(msg), "\r\n") {
		if _, err := conn.Write([]byte("\r\n")); err != nil {
			return fmt.Errorf("smtp: data: %v", err)
		}
	}
	if _, err := conn.Write([]byte("\r\n.\r\n")); err != nil {
		return fmt.Errorf("smtp: data end: %v", err)
	}
	if _, _, err := rw.ReadResponse(2); err != nil {
		return fmt.Errorf("smtp: data accepted: %v", err)
	}
	_ = smtpCmd(conn, rw, 2, "QUIT")
	return nil
}

// smtpCmd writes one command and waits for a response with the given
// leading code.
func smtpCmd(w net.Conn, rw *textproto.Conn, ok int, cmd string) error {
	if _, err := fmt.Fprintf(w, "%s\r\n", cmd); err != nil {
		return err
	}
	_, _, err := rw.ReadResponse(ok)
	return err
}
// smtpEhlo sends EHLO and returns the full capability text.
func smtpEhlo(rw *textproto.Conn, w net.Conn) (string, error) {
	if _, err := w.Write([]byte("EHLO phylax.local\r\n")); err != nil {
		return "", err
	}
	line, err := rw.ReadLine()
	if err != nil {
		return "", err
	}
	if len(line) < 4 || (line[3] != '-' && line[3] != ' ') {
		return "", fmt.Errorf("bad EHLO reply %q", line)
	}
	caps := line
	if line[3] != '-' {
		return caps, nil
	}
	for {
		next, err := rw.ReadLine()
		if err != nil {
			return "", err
		}
		caps += "\n" + next
		if len(next) >= 4 && next[:3] == line[:3] && next[3] == ' ' {
			return caps, nil
		}
	}
}

func hostnameOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

// pop3RetrieveSubject logs in and RETRs the newest message, returning its
// Subject header.
func pop3RetrieveSubject(ctx context.Context, ck Check, host, user, pass string) (string, error) {
	addr, err := addrWithDefaultPort(host, ck)
	if err != nil {
		return "", fmt.Errorf("pop3: %v", err)
	}
	conn, err := net.DialTimeout("tcp", addr, dialTimeout(ctx))
	if err != nil {
		return "", fmt.Errorf("pop3: %v", err)
	}
	defer conn.Close()
	if err := setConnDeadline(conn, ctx); err != nil {
		return "", fmt.Errorf("pop3: %v", err)
	}
	r := bufio.NewReader(conn)

	if _, err := pop3Expect(r, "+"); err != nil {
		return "", fmt.Errorf("pop3: greeting: %v", err)
	}
	if _, err := pop3Cmd(r, conn, user, "USER"); err != nil {
		return "", fmt.Errorf("pop3: USER: %v", err)
	}
	if _, err := pop3Cmd(r, conn, pass, "PASS"); err != nil {
		return "", fmt.Errorf("pop3: PASS: %v", err)
	}
	line, err := pop3Cmd(r, conn, "", "STAT")
	if err != nil {
		return "", fmt.Errorf("pop3: STAT: %v", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", fmt.Errorf("pop3: bad STAT reply %q", line)
	}
	n, err := strconv.Atoi(fields[1])
	if err != nil || n < 1 {
		return "", fmt.Errorf("pop3: bad STAT reply %q", line)
	}
	// The newest message is the last one.
	msg, err := pop3Retr(r, conn, strconv.Itoa(n))
	if err != nil {
		return "", fmt.Errorf("pop3: RETR: %v", err)
	}
	pop3Cmd(r, conn, "", "QUIT")

	subj, ok := mailSubject(msg)
	if !ok {
		return "", fmt.Errorf("pop3: retrieved message has no Subject header")
	}
	return subj, nil
}

// pop3Cmd sends the command (empty for just-read) and expects +OK.
func pop3Cmd(r *bufio.Reader, w net.Conn, arg, cmd string) (string, error) {
	if cmd != "" {
		line := cmd
		if arg != "" {
			line += " " + arg
		}
		if _, err := fmt.Fprintf(w, "%s\r\n", line); err != nil {
			return "", err
		}
	}
	return pop3Expect(r, "+")
}

func pop3Expect(r *bufio.Reader, prefix string) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("server said %q", line)
	}
	return line, nil
}

// pop3Retr fetches message n and reads its body to the end-of-data marker.
func pop3Retr(r *bufio.Reader, w net.Conn, n string) ([]byte, error) {
	if _, err := fmt.Fprintf(w, "RETR %s\r\n", n); err != nil {
		return nil, err
	}
	if _, err := pop3Expect(r, "+"); err != nil {
		return nil, err
	}
	var msg []byte
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if strings.TrimRight(l, "\r\n") == "." {
			break
		}
		msg = append(msg, l...)
	}
	return msg, nil
}

// mailSubject extracts the Subject header value from a raw message.
func mailSubject(msg []byte) (string, bool) {
	for _, line := range strings.Split(string(msg), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(line), "subject:") {
			return strings.TrimSpace(line[len("Subject:"):]), true
		}
	}
	return "", false
}
