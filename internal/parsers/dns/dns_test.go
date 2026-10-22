package dns

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/capture/fixture"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/parsertest"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

var (
	cli = netip.MustParseAddrPort("10.0.0.5:40000")
	srv = netip.MustParseAddrPort("172.20.240.100:53")
	t0  = parsertest.T0
)

func TestQuotientQueryAndResponse(t *testing.T) {
	q, ok := Datagram("1:x", cli, srv, fixture.DNSQuery(0x1234, "www.team21.local", 1, false), t0)
	if !ok {
		t.Fatal("query not parsed")
	}
	if q.Type != "query" || q.Attr["dns.qname"] != "www.team21.local." || q.Attr["dns.qtype"] != "A" || q.Attr["dns.rd"] != "true" ||
		q.Attr["dns.edns"] != "false" || q.Attr["dns.id"] != "4660" || q.Client != cli {
		t.Fatalf("%+v", q)
	}
	cl, _ := scorer.NewClassifier(scorer.DefaultTable())
	if r := cl.Classify(q.Features()); !r.HasEvidence("dns.no_edns") || !r.HasEvidence("dns.rd") {
		t.Fatalf("%+v", r)
	}
	r, ok := Datagram("1:x", srv, cli, fixture.DNSResponseA(0x1234, "www.team21.local", [4]byte{172, 20, 240, 10}), t0)
	if !ok || r.Type != "response" || r.Client != cli || r.Server != srv {
		t.Fatalf("%+v", r)
	}
	if got := r.List["dns.answers"]; len(got) != 1 || got[0] != "A 172.20.240.10" || r.Attr["dns.rcode"] != "0" {
		t.Fatalf("%v %v", r.List, r.Attr)
	}
	// a browser-like resolver sends EDNS
	e, _ := Datagram("1:x", cli, srv, fixture.DNSQuery(1, "x.example", 15, true), t0)
	if e.Attr["dns.edns"] != "true" || e.Attr["dns.qtype"] != "MX" || e.Attr["dns.udp_size"] != "4096" {
		t.Fatalf("%v", e.Attr)
	}
}

func TestTCPFramingAcrossSegments(t *testing.T) {
	frame := func(m []byte) []byte { return append([]byte{byte(len(m) >> 8), byte(len(m))}, m...) }
	q := frame(fixture.DNSQuery(7, "a.b", 1, false))
	r := frame(fixture.DNSResponseA(7, "a.b", [4]byte{1, 2, 3, 4}))
	steps := []parsertest.Step{parsertest.C2S(append(q, q...)), parsertest.S2C(r)}
	for _, n := range []int{1 << 20, 3, 1} {
		out := parsertest.Run(New, parsertest.Resegment(steps, n)...)
		if len(out) != 3 || out[0].Type != "query" || out[2].Type != "response" || out[2].Attr["dns.tcp"] != "true" {
			t.Fatalf("n=%d: %d txns", n, len(out))
		}
	}
}

func TestCompressionLoopAndTruncation(t *testing.T) {
	// a name pointer that points at itself
	loop := append(make([]byte, 12), 0xC0, 12, 0, 1, 0, 1)
	binary.BigEndian.PutUint16(loop[4:], 1)
	if _, err := Parse(loop); err == nil {
		t.Fatal("loop accepted")
	}
	good := fixture.DNSResponseA(1, "www.team21.local", [4]byte{1, 1, 1, 1})
	for i := 0; i < len(good); i++ {
		_, _ = Parse(good[:i])
		_, _ = Datagram("c", cli, srv, good[:i], t0)
	}
	// absurd counts do not allocate unbounded work
	big := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(big[6:], 65535)
	binary.BigEndian.PutUint16(big[10:], 65535)
	if m, _ := Parse(big); m == nil || len(m.Answers) > maxRecords*3 {
		t.Fatal("unbounded answers")
	}
}

func FuzzDNS(f *testing.F) {
	frame := func(m []byte) []byte { return append([]byte{byte(len(m) >> 8), byte(len(m))}, m...) }
	parsertest.Fuzz(f, New, []parsertest.Step{
		parsertest.C2S(frame(fixture.DNSQuery(7, "a.b", 1, true))), parsertest.S2C(frame(fixture.DNSResponseA(7, "a.b", [4]byte{1, 2, 3, 4}))),
	})
}

func FuzzDNSDatagram(f *testing.F) {
	f.Add(fixture.DNSQuery(1, "x.y", 1, true))
	f.Add(fixture.DNSResponseA(1, "x.y", [4]byte{9, 9, 9, 9}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if x, ok := Datagram("c", cli, srv, b, t0); ok && (x.Proto != "dns" || x.Type == "") {
			t.Fatalf("%+v", x)
		}
	})
}
