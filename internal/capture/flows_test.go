package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func h(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:8])
}

func v4(ip string) [16]byte {
	var a [16]byte
	switch ip {
	case "10.0.0.1":
		copy(a[12:], []byte{10, 0, 0, 1})
	case "10.0.0.2":
		copy(a[12:], []byte{10, 0, 0, 2})
	}
	return a
}

// TestFlow: two hosts converse; the flow record carries both
// directions' bytes, packets, first-bytes hashes and the result.
func TestFlow(t *testing.T) {
	tk := NewTracker(h)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	tk.ForTest(func() time.Time { return now })
	a, b := v4("10.0.0.1"), v4("10.0.0.2")
	req := []byte("GET / HTTP/1.1\r\n") // 16 bytes
	tk.Observe(now, a, b, 50000, 80, 6, req, false, false)
	now = now.Add(time.Second)
	tk.Observe(now, b, a, 80, 50000, 6, []byte("HTTP/1.1 200 OK\r\nx"), false, false) // 20
	now = now.Add(time.Second)
	tk.Observe(now, a, b, 50000, 80, 6, req, true, false)
	out := tk.Finish(now)
	if len(out) != 1 {
		t.Fatalf("want 1 flow, got %d", len(out))
	}
	f := out[0]
	if f.BytesAB != 32 || f.PktsAB != 2 {
		t.Fatalf("AB bytes/pkts = %d/%d", f.BytesAB, f.PktsAB)
	}
	if f.BytesBA != 18 || f.PktsBA != 1 {
		t.Fatalf("BA bytes/pkts = %d/%d", f.BytesBA, f.PktsBA)
	}
	if f.HashAB == "" || f.HashBA == "" {
		t.Fatal("first-bytes hashes missing")
	}
	if f.Result != "established" {
		t.Fatalf("result = %q", f.Result)
	}
}

// TestScanAggregation: one source touching many ports produces one
// scan record, not thousands of flows (docs: Capture mechanics).
func TestScanAggregation(t *testing.T) {
	tk := NewTracker(nil)
	now := time.Now()
	tk.ForTest(func() time.Time { return now })
	scan := v4("10.0.0.1")
	dst := v4("10.0.0.2")
	for i := 0; i < 50; i++ {
		tk.Observe(now, scan, dst, 40000+uint16(i), uint16(i+1), 6, nil, false, false)
	}
	out := tk.Finish(now.Add(time.Second))
	scans := 0
	for _, f := range out {
		if f.Scan {
			scans++
		}
	}
	if scans != 1 {
		t.Fatalf("want 1 scan record, got %d (total flows %d)", scans, len(out))
	}
	if len(out) != 1 {
		t.Fatalf("scan source's individual flows must be folded, got %d flows", len(out))
	}
}

// TestRing: the cap evicts oldest; a frozen ring does not rotate; the
// slice filters by source and window.
func TestRing(t *testing.T) {
	r := NewRing(1024)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	a, b := v4("10.0.0.1"), v4("10.0.0.2")
	for i := 0; i < 100; i++ {
		r.Add(now.Add(time.Duration(i)*time.Second), "eth0", a, b, 1, 2, 6, make([]byte, 200), false)
	}
	if r.Drops() == 0 {
		t.Fatal("ring over cap must drop")
	}
	r.Freeze()
	before := len(r.Slice(now, now.Add(time.Hour), [16]byte{}))
	r.Add(now.Add(2*time.Hour), "eth0", a, b, 1, 2, 6, make([]byte, 200), false)
	after := len(r.Slice(now, now.Add(3*time.Hour), [16]byte{}))
	if after != before {
		t.Fatal("frozen ring must not rotate")
	}
	// source filter
	all := len(r.Slice(now, now.Add(time.Hour), [16]byte{}))
	onlyA := len(r.Slice(now, now.Add(time.Hour), a))
	if onlyA != all {
		// every entry is from a, so the filter keeps all
		t.Fatalf("filter kept %d of %d", onlyA, all)
	}
	var z [16]byte
	copy(z[12:], []byte{10, 0, 0, 9})
	none := len(r.Slice(now, now.Add(time.Hour), z))
	if none != 0 {
		t.Fatalf("filter should keep none, got %d", none)
	}
}
