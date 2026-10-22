package pop3

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
		s("+OK Dovecot ready.\r\n"),
		c("USER alice@team21.local\r\n"), s("+OK\r\n"),
		c("PASS pw-Alice-1\r\n"), s("+OK Logged in.\r\n"),
		c("NOOP\r\n"), s("+OK\r\n"),
		c("STAT\r\n"), s("+OK 2 1500\r\n"),
		c("QUIT\r\n"), s("+OK Logging out.\r\n"),
	}
}

func TestQuotientPOP3(t *testing.T) {
	for _, n := range []int{1 << 20, 3, 1} {
		out := parsertest.Run(New, parsertest.Resegment(quotientSession(), n)...)
		if len(out) != 1 {
			t.Fatalf("n=%d %d", n, len(out))
		}
		x := out[0]
		if strings.Join(x.List["pop3.cmds"], " ") != "USER PASS NOOP STAT QUIT" || x.Attr["pop3.auth_ok"] != "true" ||
			x.Cred.User != "alice@team21.local" || x.Cred.PassHash != txn.HashSecret("pw-Alice-1") {
			t.Fatalf("%v %v %+v", x.Attr, x.List, x.Cred)
		}
	}
	cl, _ := scorer.NewClassifier(scorer.DefaultTable())
	if r := cl.Classify(parsertest.Run(New, quotientSession()...)[0].Features()); !r.HasEvidence("pop3.cmds") {
		t.Fatalf("%+v", r)
	}
}

func TestMultilineRetrDoesNotConfuseReplies(t *testing.T) {
	out := parsertest.Run(New,
		s("+OK hi\r\n"),
		c("USER u\r\nPASS p\r\n"), s("+OK\r\n-ERR bad password\r\n"),
		c("RETR 1\r\n"), s("+OK 40 octets\r\nSubject: x\r\n\r\n+OK looks like a status\r\n.\r\n"),
		c("QUIT\r\n"), s("+OK bye\r\n"),
	)
	x := out[0]
	if x.Attr["pop3.auth_ok"] != "false" || x.Attr["pop3.retrieved"] != "1" {
		t.Fatalf("%v", x.Attr)
	}
}

func FuzzPOP3(f *testing.F) { parsertest.Fuzz(f, New, quotientSession()) }
