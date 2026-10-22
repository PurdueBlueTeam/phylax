package ftp

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/parsertest"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

func c(s string) parsertest.Step { return parsertest.C2S([]byte(s)) }
func s(x string) parsertest.Step { return parsertest.S2C([]byte(x)) }

// Quotient's FTP check: USER, PASS, FEAT, TYPE I, OPTS UTF8 ON, EPSV, RETR, QUIT.
func quotientSession() []parsertest.Step {
	return []parsertest.Step{
		s("220 (vsFTPd 3.0.5)\r\n"),
		c("USER scoring\r\n"), s("331 Please specify the password.\r\n"),
		c("PASS Sup3rSecret!\r\n"), s("230 Login successful.\r\n"),
		c("FEAT\r\n"), s("211-Features:\r\n EPRT\r\n EPSV\r\n UTF8\r\n211 End\r\n"),
		c("TYPE I\r\n"), s("200 Switching to Binary mode.\r\n"),
		c("OPTS UTF8 ON\r\n"), s("200 Always in UTF8 mode.\r\n"),
		c("EPSV\r\n"), s("229 Entering Extended Passive Mode (|||40123|).\r\n"),
		c("RETR /srv/ftp/sop.txt\r\n"), s("150 Opening BINARY mode data connection.\r\n226 Transfer complete.\r\n"),
		c("QUIT\r\n"), s("221 Goodbye.\r\n"),
	}
}

func TestQuotientSessionAndDataChannel(t *testing.T) {
	var expected []string
	m := parsertest.Meta()
	m.Server = netip.MustParseAddrPort("172.20.240.10:21")
	m.Expect = func(ap netip.AddrPort, note string) { expected = append(expected, ap.String()+" "+note) }
	for _, n := range []int{1 << 20, 3, 1} {
		expected = nil
		out := parsertest.RunMeta(New, m, parsertest.Resegment(quotientSession(), n)...)
		if len(out) != 1 {
			t.Fatalf("n=%d: %d txns", n, len(out))
		}
		x := out[0]
		if got := strings.Join(x.List["ftp.cmds"], " "); got != "USER PASS FEAT TYPE OPTS EPSV RETR QUIT" {
			t.Fatalf("cmds: %s", got)
		}
		if x.Attr["ftp.auth_ok"] != "true" || x.Cred == nil || x.Cred.User != "scoring" || x.Cred.PassHash != txn.HashSecret("Sup3rSecret!") {
			t.Fatalf("auth: %v %+v", x.Attr, x.Cred)
		}
		if len(expected) != 1 || expected[0] != "172.20.240.10:40123 ftp-data(passive)" {
			t.Fatalf("n=%d data channel: %v", n, expected)
		}
		if x.Attr["ftp.transfers_ok"] != "1" || len(x.List["ftp.files"]) != 1 || x.List["ftp.files"][0] != "RETR /srv/ftp/sop.txt" {
			t.Fatalf("transfer: %v %v", x.Attr, x.List)
		}
		for k, v := range x.Attr {
			if strings.Contains(v, "Sup3rSecret") {
				t.Fatalf("password leaked in %s", k)
			}
		}
	}
	cl, _ := scorer.NewClassifier(scorer.DefaultTable())
	out := parsertest.RunMeta(New, m, quotientSession()...)
	if r := cl.Classify(out[0].Features()); !r.HasEvidence("ftp.cmds") {
		t.Fatalf("classifier: %+v", r)
	}
}

func TestPASVActivePortAndFailedLogin(t *testing.T) {
	var got []string
	m := parsertest.Meta()
	m.Expect = func(ap netip.AddrPort, note string) { got = append(got, ap.String()+" "+note) }
	out := parsertest.RunMeta(New, m,
		s("220 hi\r\n"),
		c("USER a\r\nPASS b\r\n"), s("331 pw\r\n530 Login incorrect.\r\n"),
		c("PASV\r\n"), s("227 Entering Passive Mode (192,168,1,5,19,136).\r\n"),
		c("PORT 10,0,0,5,200,10\r\n"), s("200 PORT ok\r\n"),
		c("EPRT |1|10.0.0.5|51234|\r\n"), s("200 ok\r\n"),
	)
	if out[0].Attr["ftp.auth_ok"] != "false" {
		t.Fatalf("%v", out[0].Attr)
	}
	// PASV address is rewritten to the control connection's server (NAT), port kept
	want := []string{"10.0.0.9:5000 ftp-data(passive)", "10.0.0.5:51210 ftp-data(active)", "10.0.0.5:51234 ftp-data(active)"}
	if strings.Join(got, ";") != strings.Join(want, ";") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestAuthTLSStopsParsingAndLongLines(t *testing.T) {
	out := parsertest.Run(New, s("220 x\r\n"), c("AUTH TLS\r\n"), s("234 go ahead\r\n"), c("USER secret\r\n"))
	if len(out) != 1 || out[0].Attr["ftp.tls"] != "true" || strings.Contains(strings.Join(out[0].List["ftp.cmds"], ","), "USER") {
		t.Fatalf("%+v", out)
	}
	_ = parsertest.Run(New, c("USER "+strings.Repeat("A", 100000)+"\r\nPASS x\r\n"))
}

func FuzzFTP(f *testing.F) { parsertest.Fuzz(f, New, quotientSession()) }
