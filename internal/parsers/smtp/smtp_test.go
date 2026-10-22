package smtp

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/parsertest"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

func c(s string) parsertest.Step { return parsertest.C2S([]byte(s)) }
func s(x string) parsertest.Step { return parsertest.S2C([]byte(x)) }

var (
	subject = "0123456789abcdef"
	body    = strings.Repeat("a1b2c3d4", 8) // 64 hex digits
)

func plain(u, p string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + u + "\x00" + p))
}

func quotientSession() []parsertest.Step {
	return []parsertest.Step{
		s("220 mail.team21.local ESMTP Postfix\r\n"),
		c("EHLO localhost\r\n"), s("250-mail.team21.local\r\n250-PIPELINING\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"),
		c("AUTH PLAIN " + plain("alice@team21.local", "pw-Alice-1") + "\r\n"), s("235 2.7.0 Authentication successful\r\n"),
		c("MAIL FROM:<alice@team21.local> BODY=8BITMIME\r\n"), s("250 2.1.0 Ok\r\n"),
		c("RCPT TO:<bob@team21.local>\r\n"), s("250 2.1.5 Ok\r\n"),
		c("DATA\r\n"), s("354 End data with <CR><LF>.<CR><LF>\r\n"),
		c("From: alice@team21.local\r\nTo: bob@team21.local\r\nSubject: " + subject + "\r\n\r\n" + body + "\r\n.\r\n"),
		s("250 2.0.0 Ok: queued as 4F1\r\n"),
		c("QUIT\r\n"), s("221 2.0.0 Bye\r\n"),
	}
}

func TestQuotientSMTP(t *testing.T) {
	for _, n := range []int{1 << 20, 5, 1} {
		out := parsertest.Run(New, parsertest.Resegment(quotientSession(), n)...)
		if len(out) != 1 {
			t.Fatalf("n=%d got %d", n, len(out))
		}
		x := out[0]
		if got := strings.Join(x.List["smtp.cmds"], " "); got != "EHLO AUTH MAIL RCPT DATA QUIT" {
			t.Fatalf("cmds %s", got)
		}
		if x.Attr["smtp.ehlo_arg"] != "localhost" || x.Attr["smtp.mail_ext"] != "BODY=8BITMIME" || x.Attr["smtp.subject"] != subject ||
			x.Attr["smtp.body"] != body || x.Attr["smtp.auth_ok"] != "true" || x.Attr["smtp.delivered"] != "1" {
			t.Fatalf("attrs %v", x.Attr)
		}
		if x.Cred == nil || x.Cred.User != "alice@team21.local" || x.Cred.PassHash != txn.HashSecret("pw-Alice-1") {
			t.Fatalf("cred %+v", x.Cred)
		}
		for k, v := range x.Attr {
			if strings.Contains(v, "pw-Alice") {
				t.Fatalf("leak %s", k)
			}
		}
	}
	cl, _ := scorer.NewClassifier(scorer.DefaultTable())
	r := cl.Classify(parsertest.Run(New, quotientSession()...)[0].Features())
	for _, id := range []string{"smtp.cmds", "smtp.ehlo_localhost", "smtp.8bitmime", "smtp.subject16", "smtp.body64"} {
		if !r.HasEvidence(id) {
			t.Fatalf("missing %s: %+v", id, r)
		}
	}
	if r.Verdict != scorer.VerdictScorer {
		t.Fatalf("verdict %s", r.Verdict)
	}
}

func TestLongBodyIsHashedNotStoredAndLoginAuth(t *testing.T) {
	long := strings.Repeat("secret mail text ", 50)
	b := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	out := parsertest.Run(New,
		s("220 x ESMTP\r\n"),
		c("EHLO h\r\n"), s("250 ok\r\n"),
		c("AUTH LOGIN\r\n"), s("334 VXNlcm5hbWU6\r\n"),
		c(b("bob")+"\r\n"), s("334 UGFzc3dvcmQ6\r\n"),
		c(b("hunter3")+"\r\n"), s("535 5.7.8 Authentication failed\r\n"),
		c("MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\n"), s("250 ok\r\n250 ok\r\n354 go\r\n"),
		c("Subject: s\r\n\r\n"+long+"\r\n.\r\n"), s("250 ok\r\n"),
	)
	x := out[0]
	if _, has := x.Attr["smtp.body"]; has || x.Attr["smtp.body_sha256"] == "" || x.Cred.User != "bob" || x.Attr["smtp.auth_ok"] != "false" {
		t.Fatalf("%v %+v", x.Attr, x.Cred)
	}
	if x.Cred.PassHash != txn.HashSecret("hunter3") {
		t.Fatal("login password not hashed")
	}
}

func TestStartTLSStops(t *testing.T) {
	out := parsertest.Run(New, s("220 x ESMTP\r\n"), c("EHLO a\r\n"), s("250 ok\r\n"), c("STARTTLS\r\n"), s("220 ready\r\n"), c("EHLO secret\r\n"))
	if out[0].Attr["smtp.tls"] != "true" || out[0].Attr["smtp.ehlo_arg"] != "a" {
		t.Fatalf("%v", out[0].Attr)
	}
}

func FuzzSMTP(f *testing.F) { parsertest.Fuzz(f, New, quotientSession()) }
