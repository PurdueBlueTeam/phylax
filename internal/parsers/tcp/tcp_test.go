package tcp

import (
	"net/netip"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

func sum(port uint16, res string, c2s, s2c int64, hold time.Duration) Summary {
	t0 := time.Unix(1700000000, 0)
	return Summary{Client: netip.MustParseAddrPort("10.0.0.5:50000"), Server: netip.AddrPortFrom(netip.MustParseAddr("10.0.0.9"), port),
		CommunityID: "1:x", Start: t0, End: t0.Add(hold), Result: res, BytesC2S: c2s, BytesS2C: s2c}
}

func TestBareConnectHoldIsRDPOrTCP(t *testing.T) {
	cl, _ := scorer.NewClassifier(scorer.DefaultTable())
	x, ok := Transaction(sum(3389, Established, 0, 0, 20*time.Second))
	if !ok || x.Proto != "rdp" || x.Attr["tcp.zero_payload"] != "true" || x.Attr["tcp.hold_ms"] != "20000" {
		t.Fatalf("%+v", x)
	}
	if r := cl.Classify(x.Features()); !r.HasEvidence("rdp.zero_payload") || !r.HasEvidence("rdp.hold") {
		t.Fatalf("%+v", r)
	}
	for _, c := range []struct {
		hold time.Duration
		want bool
	}{{50 * time.Millisecond, true}, {3 * time.Millisecond, false}, {200 * time.Second, false}} {
		y, _ := Transaction(sum(8000, Established, 0, 0, c.hold))
		if y.Proto != "tcp" || cl.Classify(y.Features()).HasEvidence("tcp.hold") != c.want {
			t.Fatalf("hold %v: %+v", c.hold, y.Attr)
		}
	}
}

func TestConnectionsWithPayloadAreLeftToParsers(t *testing.T) {
	if _, ok := Transaction(sum(80, Established, 10, 0, time.Second)); ok {
		t.Fatal("payload flow emitted a bare tcp txn")
	}
	if x, ok := Transaction(sum(81, Refused, 0, 0, time.Millisecond)); !ok || x.Attr["tcp.result"] != "refused" || x.OK == nil || *x.OK {
		t.Fatalf("%+v", x)
	}
	if x, ok := Transaction(sum(81, Timeout, 0, 0, 0)); !ok || x.Attr["tcp.zero_payload"] != "false" {
		t.Fatalf("%+v", x)
	}
}
