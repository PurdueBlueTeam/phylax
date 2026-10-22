package winrm

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/capture/fixture"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/parsertest"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func post(auth, body string) string {
	h := "POST /wsman HTTP/1.1\r\nHost: 172.20.240.100:5985\r\nUser-Agent: Go-http-client/1.1\r\nContent-Type: application/soap+xml;charset=UTF-8\r\n"
	if auth != "" {
		h += "Authorization: " + auth + "\r\n"
	}
	return h + fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
}

func resp(status, hdr, body string) string {
	return fmt.Sprintf("HTTP/1.1 %s\r\n%sContent-Length: %d\r\n\r\n%s", status, hdr, len(body), body)
}

func session() []parsertest.Step {
	t1 := fixture.NTLMNegotiate(0xe2088297)
	t2 := fixture.NTLMChallenge("WIN-AD", "WIN-AD", "win-ad.team21.local", 0xe2898215)
	t3 := fixture.NTLMAuthenticate("WIN-AD", "scoring", "", 0xe2888215)
	return []parsertest.Step{
		parsertest.C2S([]byte(post("", "<s:Envelope>create</s:Envelope>"))),
		parsertest.S2C([]byte(resp("401 Unauthorized", "WWW-Authenticate: Negotiate\r\nWWW-Authenticate: Basic realm=\"WSMAN\"\r\n", ""))),
		parsertest.C2S([]byte(post("Negotiate "+b64(t1), ""))),
		parsertest.S2C([]byte(resp("401 Unauthorized", "WWW-Authenticate: Negotiate "+b64(t2)+"\r\n", ""))),
		parsertest.C2S([]byte(post("Negotiate "+b64(t3), "<s:Envelope>sealed</s:Envelope>"))),
		parsertest.S2C([]byte(resp("200 OK", "", "<s:Envelope>ok</s:Envelope>"))),
	}
}

func TestWinRMNTLMExchange(t *testing.T) {
	out := parsertest.Run(New, session()...)
	if len(out) != 3 {
		t.Fatalf("got %d txns", len(out))
	}
	if out[0].Attr["winrm.first_no_auth"] != "true" || out[0].Attr["winrm.method"] != "POST" || out[0].Attr["winrm.path"] != "/wsman" ||
		out[0].Attr["winrm.ua"] != "Go-http-client/1.1" || out[0].Attr["winrm.status"] != "401" {
		t.Fatalf("first: %v", out[0].Attr)
	}
	if _, ok := out[1].Attr["winrm.first_no_auth"]; ok {
		t.Fatal("first_no_auth set on a later exchange")
	}
	if out[1].Attr["winrm.ntlm_type"] != "1" {
		t.Fatalf("second: %v", out[1].Attr)
	}
	last := out[2]
	if last.Attr["winrm.ntlm_type"] != "3" || last.Cred == nil || last.Cred.User != "scoring" || last.Cred.Domain != "WIN-AD" ||
		last.Attr["winrm.ntlm_flags"] != "0xe2888215" || last.Attr["winrm.status"] != "200" {
		t.Fatalf("third: %v %+v", last.Attr, last.Cred)
	}
	if last.Cred.PassHash != "" {
		t.Fatal("NTLM must not carry a password hash")
	}
	c, _ := scorer.NewClassifier(scorer.DefaultTable())
	r := c.Classify(out[0].Features())
	for _, id := range []string{"winrm.post", "winrm.ua", "winrm.first_no_auth"} {
		if !r.HasEvidence(id) {
			t.Fatalf("missing %s: %+v", id, r)
		}
	}
	if r.Verdict != scorer.VerdictScorer && r.Verdict != scorer.VerdictLikelyScorer {
		t.Fatalf("verdict %s score %.2f", r.Verdict, r.Score)
	}
}

func TestWinRMResegmented(t *testing.T) {
	for _, n := range []int{1, 3, 64} {
		if out := parsertest.Run(New, parsertest.Resegment(session(), n)...); len(out) != 3 {
			t.Fatalf("n=%d got %d", n, len(out))
		}
	}
}

func TestNonWSManRequestIgnored(t *testing.T) {
	out := parsertest.Run(New, parsertest.C2S([]byte("GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n")), parsertest.S2C([]byte(resp("200 OK", "", "x"))))
	if len(out) != 0 {
		t.Fatalf("%+v", out)
	}
}

func FuzzWinRM(f *testing.F) { parsertest.Fuzz(f, New, session()) }
