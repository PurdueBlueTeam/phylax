package imap

import (
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/parsertest"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

func c(s string) parsertest.Step { return parsertest.C2S([]byte(s)) }
func s(x string) parsertest.Step { return parsertest.S2C([]byte(x)) }

func quotientSession() []parsertest.Step {
	return []parsertest.Step{
		s("* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n"),
		c("aB3xYz LOGIN \"alice@team21.local\" \"pw \\\"quoted\\\" 1\"\r\n"), s("aB3xYz OK [CAPABILITY IMAP4rev1] Logged in\r\n"),
		c("aB3xYz LIST \"\" \"*\"\r\n"), s("* LIST (\\HasNoChildren) \".\" \"INBOX\"\r\naB3xYz OK List completed\r\n"),
		c("aB3xYz LOGOUT\r\n"), s("* BYE Logging out\r\naB3xYz OK Logout completed\r\n"),
	}
}

func TestQuotientIMAP(t *testing.T) {
	for _, n := range []int{1 << 20, 4, 1} {
		out := parsertest.Run(New, parsertest.Resegment(quotientSession(), n)...)
		if len(out) != 1 {
			t.Fatalf("n=%d %d", n, len(out))
		}
		x := out[0]
		if strings.Join(x.List["imap.cmds"], " ") != "LOGIN LIST LOGOUT" || x.Attr["imap.tag"] != "aB3xYz" || x.Attr["imap.auth_ok"] != "true" {
			t.Fatalf("%v %v", x.Attr, x.List)
		}
		if x.Cred.User != "alice@team21.local" || x.Cred.PassHash != txn.HashSecret(`pw "quoted" 1`) {
			t.Fatalf("%+v", x.Cred)
		}
	}
	cl, _ := scorer.NewClassifier(scorer.DefaultTable())
	r := cl.Classify(parsertest.Run(New, quotientSession()...)[0].Features())
	if !r.HasEvidence("imap.cmds") || !r.HasEvidence("imap.tag6") {
		t.Fatalf("%+v", r)
	}
}

func TestFailedLoginAndAuthenticatePlain(t *testing.T) {
	out := parsertest.Run(New, s("* OK hi\r\n"), c("a1 LOGIN u p\r\n"), s("a1 NO [AUTHENTICATIONFAILED] bad\r\n"))
	if out[0].Attr["imap.auth_ok"] != "false" {
		t.Fatalf("%v", out[0].Attr)
	}
	// AUTHENTICATE PLAIN with continuation: base64("\0carol\0pw")
	out = parsertest.Run(New, s("* OK hi\r\n"), c("a2 AUTHENTICATE PLAIN\r\n"), s("+ \r\n"), c("AGNhcm9sAHB3\r\n"), s("a2 OK done\r\n"))
	if out[0].Cred == nil || out[0].Cred.User != "carol" || out[0].Attr["imap.auth_ok"] != "true" {
		t.Fatalf("%+v", out[0])
	}
}

func FuzzIMAP(f *testing.F) { parsertest.Fuzz(f, New, quotientSession()) }
