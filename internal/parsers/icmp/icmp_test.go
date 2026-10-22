package icmp

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

func msg(typ byte, id, seq uint16, payload []byte) []byte {
	b := []byte{typ, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], seq)
	return append(b, payload...)
}

var (
	a  = netip.MustParseAddr("10.0.0.5")
	b  = netip.MustParseAddr("10.0.0.9")
	t0 = time.Unix(1700000000, 0)
)

func TestGoPingShape(t *testing.T) {
	payload := make([]byte, 24) // UnixNano + tracker
	x, ok := Echo("c", a, b, false, msg(8, 0xBEEF, 0, payload), t0)
	if !ok || x.Type != "echo_request" || x.Attr["icmp.payload_len"] != "24" || x.Attr["icmp.seq"] != "0" || x.Attr["icmp.id"] != "48879" {
		t.Fatalf("%+v", x)
	}
	cl, _ := scorer.NewClassifier(scorer.DefaultTable())
	if r := cl.Classify(x.Features()); !r.HasEvidence("icmp.payload24") || !r.HasEvidence("icmp.seq0") {
		t.Fatalf("%+v", r)
	}
	if x.Attr["icmp.iputils_pattern"] != "false" {
		t.Fatal("go-ping payload is not the iputils pattern")
	}
}

func TestIputilsPatternAndReplyDirection(t *testing.T) {
	p := make([]byte, 8)
	for i := 0; i < 48; i++ {
		p = append(p, byte(0x10+i))
	}
	req, _ := Echo("c", a, b, false, msg(8, 1, 1, p), t0)
	if req.Attr["icmp.iputils_pattern"] != "true" || req.Attr["icmp.payload_len"] != "56" {
		t.Fatalf("%v", req.Attr)
	}
	rep, ok := Echo("c", b, a, false, msg(0, 1, 1, p), t0)
	if !ok || rep.Type != "echo_reply" || rep.Client.Addr() != a || rep.Server.Addr() != b {
		t.Fatalf("%+v", rep)
	}
	v6, ok := Echo("c", netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2"), true, msg(128, 3, 4, nil), t0)
	if !ok || v6.Attr["icmp.v6"] != "true" || v6.Attr["icmp.payload_len"] != "0" {
		t.Fatalf("%+v", v6)
	}
}

func TestNonEchoAndShortAreIgnored(t *testing.T) {
	if _, ok := Echo("c", a, b, false, msg(3, 0, 0, nil), t0); ok {
		t.Fatal("dest unreachable parsed as echo")
	}
	for i := 0; i < 8; i++ {
		if _, ok := Echo("c", a, b, false, msg(8, 0, 0, nil)[:i], t0); ok {
			t.Fatal("short message parsed")
		}
	}
}

func FuzzICMP(f *testing.F) {
	f.Add(msg(8, 1, 2, make([]byte, 24)), false)
	f.Add(msg(129, 1, 2, nil), true)
	f.Fuzz(func(t *testing.T, m []byte, v6 bool) {
		if x, ok := Echo("c", a, b, v6, m, t0); ok && x.Proto != "icmp" {
			t.Fatal("bad proto")
		}
	})
}
