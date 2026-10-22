package ntlm

import (
	"encoding/base64"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/capture/fixture"
)

func TestParseTypes(t *testing.T) {
	m, ok := Parse(fixture.NTLMAuthenticate("DOM", "user", "WS", 0xe2888215))
	if !ok || m.Type != 3 || m.Domain != "DOM" || m.User != "user" || m.Workstation != "WS" || m.Flags != 0xe2888215 || !m.HasVersion || m.Version[0] != 10 {
		t.Fatalf("%+v", m)
	}
	c, ok := Parse(fixture.NTLMChallenge("TGT", "NB", "dns.example", 0xe2898215))
	if !ok || c.Type != 2 || c.Target != "TGT" || c.NbComputer != "NB" || c.DNSComputer != "dns.example" {
		t.Fatalf("%+v", c)
	}
	if n := c.ServerNames(); len(n) != 3 || n[0] != "nb" {
		t.Fatalf("%v", n)
	}
	n, ok := Parse(fixture.NTLMNegotiate(0xe2088297))
	if !ok || n.Type != 1 || n.Flags != 0xe2088297 {
		t.Fatalf("%+v", n)
	}
}

func TestFromHeaderAndFind(t *testing.T) {
	raw := fixture.NTLMNegotiate(1)
	h := "Negotiate " + base64.StdEncoding.EncodeToString(raw)
	if got := FromHeader(h); string(got[:7]) != "NTLMSSP" {
		t.Fatalf("%q", got)
	}
	if FromHeader("Basic abcd") != nil || FromHeader("NTLM !!!") != nil || FromHeader("NTLM") != nil {
		t.Fatal("non-ntlm accepted")
	}
	if Find(fixture.SPNEGOWrap(raw)) == nil || Find([]byte("nothing")) != nil {
		t.Fatal("Find")
	}
}

func TestMalformedNeverPanics(t *testing.T) {
	good := fixture.NTLMAuthenticate("DOM", "user", "WS", 0xe2888215)
	for i := 0; i <= len(good); i++ {
		Parse(good[:i])
	}
	bad := append([]byte(nil), good...)
	for i := 12; i < 60; i++ {
		bad[i] = 0xff // offsets and lengths far out of range
	}
	Parse(bad)
	ch := fixture.NTLMChallenge("T", "N", "D", 0)
	for i := 0; i <= len(ch); i++ {
		Parse(ch[:i])
	}
}

func FuzzNTLM(f *testing.F) {
	f.Add(fixture.NTLMAuthenticate("DOM", "user", "WS", 0xe2888215))
	f.Add(fixture.NTLMChallenge("T", "N", "D", 1))
	f.Add(fixture.NTLMNegotiate(1))
	f.Fuzz(func(t *testing.T, b []byte) { Parse(b) })
}
