package tds

import (
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/capture/fixture"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/parsertest"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

func session(ok bool) []parsertest.Step {
	login := fixture.TDSLoginAck()
	if !ok {
		login = fixture.TDSLoginError()
	}
	return []parsertest.Step{
		parsertest.C2S(fixture.TDSPrelogin(false, [6]byte{15, 0, 0, 0, 0, 0}, 2, "")),
		parsertest.S2C(fixture.TDSPrelogin(true, [6]byte{15, 0, 2000 >> 8, 2000 & 0xff, 0, 0}, 2, "")),
		parsertest.C2S(fixture.TDSLogin7("kali", "sa", "P@ssw0rd!", "impacket", "172.20.240.120", "Core Microsoft SqlClient Data Provider", "master")),
		parsertest.S2C(login),
		parsertest.C2S(fixture.TDSBatch("SELECT 1")),
		parsertest.S2C(fixture.TDSLoginAck()),
	}
}

func TestPreloginLoginAndBatch(t *testing.T) {
	for _, n := range []int{1 << 20, 11, 1} {
		out := parsertest.Run(New, parsertest.Resegment(session(true), n)...)
		if len(out) != 1 {
			t.Fatalf("n=%d got %d", n, len(out))
		}
		x := out[0]
		if x.Proto != "mssql" || x.Attr["tds.client_version"] != "15.0.0" || x.Attr["tds.server_encryption"] != "2" || x.Attr["tds.tls"] != "false" {
			t.Fatalf("prelogin: %v", x.Attr)
		}
		if x.Attr["tds.user"] != "sa" || x.Attr["tds.host"] != "kali" || x.Attr["tds.app"] != "impacket" || x.Attr["tds.database"] != "master" ||
			x.Attr["tds.server"] != "172.20.240.120" || !strings.HasPrefix(x.Attr["tds.library"], "Core Microsoft") || x.Attr["tds.login_ok"] != "true" {
			t.Fatalf("login7: %v", x.Attr)
		}
		if x.Cred.User != "sa" || x.Cred.PassHash != txn.HashSecret("P@ssw0rd!") {
			t.Fatalf("cred %+v", x.Cred)
		}
		if len(x.List["tds.queries"]) != 1 || x.List["tds.queries"][0] != "SELECT 1" || x.Attr["tds.batches"] != "1" {
			t.Fatalf("batch: %v", x.List)
		}
		for k, v := range x.Attr {
			if strings.Contains(v, "P@ssw0rd") {
				t.Fatalf("leak %s", k)
			}
		}
	}
	// mssql has no native Quotient check: the classifier caps it as custom
	cl, _ := scorer.NewClassifier(scorer.DefaultTable())
	if r := cl.Classify(parsertest.Run(New, session(true)...)[0].Features()); !r.Custom {
		t.Fatalf("%+v", r)
	}
}

func TestFailedLoginAndTLSWrappedLogin(t *testing.T) {
	x := parsertest.Run(New, session(false)...)[0]
	if x.Attr["tds.login_ok"] != "false" || x.Attr["tds.error"] != "18456" {
		t.Fatalf("%v", x.Attr)
	}
	// Encryption negotiated: the next client message after the pre-login answer
	// is a TLS handshake carried in pre-login packets, so Login7 is not visible.
	tls := parsertest.Run(New,
		parsertest.C2S(fixture.TDSPrelogin(false, [6]byte{15}, 0, "")),
		parsertest.S2C(fixture.TDSPrelogin(true, [6]byte{15}, 1, "")),
		parsertest.C2S(fixture.TDSPrelogin(false, [6]byte{15}, 0, "")),
	)[0]
	if tls.Attr["tds.tls"] != "true" || tls.Attr["tds.user"] != "" {
		t.Fatalf("%v", tls.Attr)
	}
}

func TestMalformed(t *testing.T) {
	l := fixture.TDSLogin7("h", "u", "p", "a", "s", "l", "d")
	for i := 0; i < len(l); i += 3 {
		_ = parsertest.Run(New, parsertest.C2S(l[:i]))
	}
	bad := append([]byte(nil), l...)
	for i := 8 + 36; i < 8+60; i++ {
		bad[i] = 0xff
	}
	_ = parsertest.Run(New, parsertest.C2S(bad))
}

func FuzzTDS(f *testing.F) { parsertest.Fuzz(f, New, session(true), session(false)) }
