package capture

import (
	"bytes"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
)

var base = time.Unix(1700000000, 0)

func at(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func fill(r *Ring, from, n int, src, dst string, size int) {
	for i := 0; i < n; i++ {
		d := bytes.Repeat([]byte{byte(from + i)}, size)
		r.Add(at(from+i), size+14, d, ip(src), ip(dst))
	}
}

func TestRingBoundsPackets(t *testing.T) {
	r := NewRing(RingConfig{MaxBytes: 1 << 30, MaxPackets: 100})
	fill(r, 0, 1000, "10.0.0.1", "10.0.0.2", 60)
	st := r.Stats()
	if st.Packets != 100 || st.Evicted != 900 {
		t.Fatalf("%+v", st)
	}
	if !st.Oldest.Equal(at(900)) || !st.Newest.Equal(at(999)) {
		t.Fatalf("kept the wrong packets: %v..%v", st.Oldest, st.Newest)
	}
}

func TestRingBoundsBytes(t *testing.T) {
	r := NewRing(RingConfig{MaxBytes: 50_000, MaxPackets: 1 << 20})
	fill(r, 0, 2000, "10.0.0.1", "10.0.0.2", 500)
	st := r.Stats()
	if st.Bytes > 50_000 || st.Packets < 80 || st.Packets > 100 {
		t.Fatalf("%+v", st)
	}
	// a packet larger than the whole ring is refused, not stored
	if r.Add(at(5000), 1<<20, make([]byte, 100_000), ip("10.0.0.1"), ip("10.0.0.2")) {
		t.Fatal("oversize packet stored")
	}
}

func TestAddCopiesData(t *testing.T) {
	r := NewRing(RingConfig{})
	buf := []byte{1, 2, 3, 4}
	r.Add(at(0), 4, buf, ip("10.0.0.1"), ip("10.0.0.2"))
	buf[0] = 99
	var out bytes.Buffer
	if n, err := r.WriteSlice(&out, at(0), at(1), nil); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	rd, _ := pcapgo.NewReader(&out)
	d, _, _ := rd.ReadPacketData()
	if d[0] != 1 {
		t.Fatalf("ring aliases the caller's buffer: %v", d)
	}
}

func readPCAP(t *testing.T, b []byte) (n int, first, last time.Time, datas [][]byte) {
	t.Helper()
	rd, err := pcapgo.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	for {
		d, ci, err := rd.ReadPacketData()
		if err != nil {
			break
		}
		if n == 0 {
			first = ci.Timestamp
		}
		last = ci.Timestamp
		n++
		datas = append(datas, d)
	}
	return
}

func TestWriteSliceIsRealPCAPFilteredByWindowAndIP(t *testing.T) {
	r := NewRing(RingConfig{})
	fill(r, 0, 10, "10.0.0.1", "10.0.0.2", 60)
	fill(r, 10, 10, "10.0.0.3", "10.0.0.4", 80)
	var out bytes.Buffer
	n, err := r.WriteSlice(&out, at(5), at(14), []netip.Addr{ip("10.0.0.3")})
	if err != nil || n != 5 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	got, first, last, datas := readPCAP(t, out.Bytes())
	if got != 5 || !first.Equal(at(10)) || !last.Equal(at(14)) || len(datas[0]) != 80 {
		t.Fatalf("pcap content: n=%d %v %v len=%d", got, first, last, len(datas[0]))
	}
	// link type is recorded
	rd, _ := pcapgo.NewReader(bytes.NewReader(out.Bytes()))
	if rd.LinkType() != 1 {
		t.Fatalf("linktype %v", rd.LinkType())
	}
}

func TestFreezePinsWindowAndKeepsRecordingAfterEviction(t *testing.T) {
	r := NewRing(RingConfig{MaxPackets: 50, HoldBytes: 1 << 20})
	fill(r, 0, 40, "10.0.0.1", "10.0.0.2", 60) // t=0..39 in the ring
	// alert at t=40: freeze 5 "minutes" before to 10 after (compressed to seconds here)
	r.Freeze("alert-1", at(35), at(60), []netip.Addr{ip("10.0.0.1")})
	// traffic keeps flowing: far more than the ring holds, so the ring evicts
	// the frozen packets, and some of it is unrelated to the frozen IPs
	for i := 40; i < 140; i++ {
		src := "10.0.0.1"
		if i%2 == 1 {
			src = "10.0.0.9"
		}
		r.Add(at(i), 74, bytes.Repeat([]byte{byte(i)}, 60), ip(src), ip("10.0.0.2"))
	}
	info, err := r.Frozen("alert-1")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Closed {
		t.Fatal("window should have closed once packets passed its end")
	}
	var out bytes.Buffer
	n, err := r.WriteFrozen(&out, "alert-1")
	if err != nil {
		t.Fatal(err)
	}
	got, first, last, datas := readPCAP(t, out.Bytes())
	// 35..39 (pre-alert, evicted from the ring since) plus even seconds 40..60 (post-alert)
	want := 5 + 11
	if n != want || got != want || !first.Equal(at(35)) || !last.Equal(at(60)) {
		t.Fatalf("frozen: n=%d got=%d (want %d) %v..%v", n, got, want, first, last)
	}
	if datas[0][0] != 35 || datas[len(datas)-1][0] != 60 {
		t.Fatalf("payload order wrong: %d %d", datas[0][0], datas[len(datas)-1][0])
	}
	if st := r.Stats(); st.Packets != 50 {
		t.Fatalf("live ring should still be bounded: %+v", st)
	}
	r.Release("alert-1")
	if _, err := r.Frozen("alert-1"); err == nil {
		t.Fatal("released freeze still present")
	}
	if _, err := r.WriteFrozen(&out, "nope"); err != ErrNoHold {
		t.Fatalf("%v", err)
	}
}

func TestFreezeExtendAndBudget(t *testing.T) {
	r := NewRing(RingConfig{HoldBytes: 3000})
	fill(r, 0, 10, "10.0.0.1", "10.0.0.2", 100) // cost 164 each
	r.Freeze("a", at(0), at(100), nil)
	r.Freeze("a", at(0), at(200), []netip.Addr{ip("10.0.0.1")}) // idempotent merge, extends
	info, _ := r.Frozen("a")
	if info.Packets != 10 || !info.To.Equal(at(200)) {
		t.Fatalf("%+v", info)
	}
	for i := 10; i < 100; i++ {
		r.Add(at(i), 114, make([]byte, 100), ip("10.0.0.1"), ip("10.0.0.2"))
	}
	info, _ = r.Frozen("a")
	if info.Bytes > 3000 || !info.Full || r.Stats().HoldDrops == 0 {
		t.Fatalf("hold budget not enforced: %+v drops=%d", info, r.Stats().HoldDrops)
	}
}

func TestRingConcurrentAddFreezeWrite(t *testing.T) {
	r := NewRing(RingConfig{MaxPackets: 500, HoldBytes: 1 << 20})
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 5000; i++ {
			r.Add(at(i), 74, make([]byte, 60), ip("10.0.0.1"), ip("10.0.0.2"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			r.Freeze(fmt.Sprint("f", i%5), at(0), at(10000), nil)
			_, _ = r.Frozen("f0")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			var b bytes.Buffer
			_, _ = r.WriteSlice(&b, at(0), at(10000), nil)
			r.Stats()
			r.Release(fmt.Sprint("f", i%5))
		}
	}()
	wg.Wait()
}
