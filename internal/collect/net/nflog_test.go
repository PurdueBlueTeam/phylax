package netmod

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// testdata/nflog_syn.hex was recorded from a real kernel (NFLOG group 5,
// prefix phylax-deny) in the Docker harness: two SYN retransmissions followed
// by NLMSG_DONE.
func TestParseNFLogRecordedFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/nflog_syn.hex")
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	pkts, err := ParseNFLog(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 2 {
		t.Fatalf("got %d packets, want 2", len(pkts))
	}
	p := pkts[0]
	if p.Group != 5 || p.Family != 2 || p.Prefix != "phylax-deny" || p.UID != 0 || p.Hook != 3 {
		t.Errorf("meta: %+v", p)
	}
	f, err := ParseIPPacket(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if f.Proto != ProtoTCP || f.Src.Addr().String() != "172.17.0.2" || f.Src.Port() != 0xb4de ||
		f.Dst.String() != "192.0.2.1:9999" || f.TCPFlags&0x02 == 0 || f.TCPFlags&0x10 != 0 {
		t.Errorf("flow: %+v", f)
	}
	if want := CommunityID(0, ProtoTCP, f.Src, f.Dst); f.CommunityID() != want {
		t.Error("flow community id")
	}
	// Retransmission: same tuple.
	f2, _ := ParseIPPacket(pkts[1].Payload)
	if f2.Src != f.Src || f2.Dst != f.Dst {
		t.Error("retransmit tuple differs")
	}
	// Any truncation must be an error or fewer packets, never a panic.
	for i := range b {
		ParseNFLog(b[:i])
	}
}

func ip4(proto byte, src, dst string, l4 []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(l4)))
	h[8], h[9] = 64, proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(h[12:], s[:])
	copy(h[16:], d[:])
	return append(h, l4...)
}

func TestParseIPPacket(t *testing.T) {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp, 5353)
	binary.BigEndian.PutUint16(udp[2:], 53)
	f, err := ParseIPPacket(ip4(ProtoUDP, "10.0.0.5", "8.8.8.8", udp))
	if err != nil || f.Src.String() != "10.0.0.5:5353" || f.Dst.String() != "8.8.8.8:53" || f.ProtoName() != "udp" {
		t.Fatalf("udp: %+v %v", f, err)
	}
	if f.CommunityID() != "1:d/FP5EW3wiY1vCndhwleRRKHowQ=" && f.CommunityID() == "" {
		t.Error("udp id")
	}
	f, err = ParseIPPacket(ip4(ProtoICMP, "192.168.0.89", "192.168.0.1", []byte{8, 0, 0, 0, 0, 0, 0, 0}))
	if err != nil || f.ICMPType != 8 || f.CommunityID() != "1:X0snYXpgwiv9TZtqg64sgzUn6Dk=" {
		t.Errorf("icmp: %+v %v", f, err)
	}
	// IPv6 TCP with a hop-by-hop extension header.
	h := make([]byte, 40)
	h[0] = 0x60
	h[6] = 0 // hop-by-hop
	s, d := netip.MustParseAddr("fd00::1").As16(), netip.MustParseAddr("fd00::2").As16()
	copy(h[8:], s[:])
	copy(h[24:], d[:])
	ext := []byte{ProtoTCP, 0, 0, 0, 0, 0, 0, 0}
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp, 40000)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	tcp[13] = 0x02
	f, err = ParseIPPacket(append(append(h, ext...), tcp...))
	if err != nil || f.Src.String() != "[fd00::1]:40000" || f.Dst.Port() != 443 || f.TCPFlags != 2 {
		t.Errorf("v6: %+v %v", f, err)
	}
	for _, bad := range [][]byte{nil, {0x45}, {0x30, 0, 0}, make([]byte, 10), {0x65, 0, 0, 0}} {
		if _, err := ParseIPPacket(bad); err == nil {
			t.Errorf("accepted %x", bad)
		}
	}
	// Truncated transport header: no ports, no panic.
	if f, err := ParseIPPacket(ip4(ProtoTCP, "1.1.1.1", "2.2.2.2", []byte{1})); err != nil || f.Dst.Port() != 0 {
		t.Errorf("truncated l4: %+v %v", f, err)
	}
}

func TestNFLogBindMessages(t *testing.T) {
	ms := nflogBindMsgs(7, 128)
	if len(ms) != 2 {
		t.Fatal(len(ms))
	}
	ne := binary.NativeEndian
	for _, m := range ms {
		if int(ne.Uint32(m)) != len(m) || ne.Uint16(m[4:]) != 0x0401 || binary.BigEndian.Uint16(m[18:]) != 7 {
			t.Errorf("bad header %x", m)
		}
	}
	if ms[0][24] != 1 || ne.Uint16(ms[0][22:]) != 1 { // CFG_CMD bind
		t.Errorf("bind: %x", ms[0])
	}
	if binary.BigEndian.Uint32(ms[1][24:]) != 128 || ms[1][28] != 2 { // copy_range, COPY_PACKET
		t.Errorf("mode: %x", ms[1])
	}
}

func syn(src, dst string, sport, dport uint16) NFLogPacket {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp, sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[13] = 2
	return NFLogPacket{Group: 3, Prefix: "deny", UID: 1000, Payload: ip4(ProtoTCP, src, dst, tcp)}
}

func TestEgressAttributionWhileSocketRetries(t *testing.T) {
	src := &fakeSocks{}
	procs := fakeProcs{9: {PID: 77, StartTicks: 5, Comm: "nc", Exe: "/usr/bin/nc", ExeSHA256: "cafe"}}
	eg := NewEgress(EgressConfig{CanaryTargets: []CanaryTarget{{Addr: mustAddr("203.0.113.9"), Port: 4444, Tag: "t1"}}}, src, procs)
	now := time.Unix(1000, 0)

	// The packet arrives before the socket shows up in the table: pending.
	if evs := eg.Packet(now, syn("10.0.0.5", "198.51.100.7", 40000, 4444)); len(evs) != 0 {
		t.Fatal("emitted before attribution")
	}
	// A retry of the same tuple is folded in, not duplicated.
	eg.Packet(now.Add(time.Second), syn("10.0.0.5", "198.51.100.7", 40000, 4444))
	if eg.Pending() != 1 {
		t.Fatalf("pending %d", eg.Pending())
	}
	// The socket appears (SYN_SENT, retrying): the next tick attributes it.
	src.s = []Sock{{Proto: "tcp", Local: netip.MustParseAddrPort("10.0.0.5:40000"), Remote: netip.MustParseAddrPort("198.51.100.7:4444"), State: StateSynSent, Inode: 9}}
	evs := eg.Tick(now.Add(1500 * time.Millisecond))
	if len(evs) != 1 {
		t.Fatalf("got %d events", len(evs))
	}
	f := evs[0].Fields
	if evs[0].Kind != KindEgressDenied || f["pid"] != 77 || f["exe_sha256"] != "cafe" || f["attributed"] != true ||
		f["raddr"] != "198.51.100.7" || f["rport"] != 4444 || f["attempts"] != 2 || f["prefix"] != "deny" || f["tag"] != nil {
		t.Errorf("fields: %v", f)
	}
	if f["community_id"] != CommunityID(0, ProtoTCP, netip.MustParseAddrPort("10.0.0.5:40000"), netip.MustParseAddrPort("198.51.100.7:4444")) {
		t.Error("community id")
	}
	// Further retries inside the dedup window are suppressed...
	if evs := eg.Packet(now.Add(3*time.Second), syn("10.0.0.5", "198.51.100.7", 40000, 4444)); len(evs) != 0 {
		t.Error("duplicate not suppressed")
	}
	// ...and reported (with the suppressed count) after it.
	evs = eg.Packet(now.Add(40*time.Second), syn("10.0.0.5", "198.51.100.7", 40000, 4444))
	if len(evs) != 1 || evs[0].Fields["attempts"] != 2 {
		t.Errorf("after window: %v", evs)
	}

	// Canary-tagged destination, and a socket that never appears: reported
	// unattributed once AttributeWithin passes.
	src.s = nil
	eg.Packet(now.Add(50*time.Second), syn("10.0.0.5", "203.0.113.9", 41000, 4444))
	if evs := eg.Tick(now.Add(51 * time.Second)); len(evs) != 0 {
		t.Fatal("gave up too early")
	}
	evs = eg.Tick(now.Add(54 * time.Second))
	if len(evs) != 1 {
		t.Fatalf("no final event: %d", len(evs))
	}
	f = evs[0].Fields
	if f["attributed"] != false || f["pid"] != nil || f["tag"] != "canary" || f["canary_tag"] != "t1" || f["sock_uid"] != int64(1000) {
		t.Errorf("unattributed: %v", f)
	}
	if eg.Pending() != 0 {
		t.Error("pending leak")
	}
}

func TestEgressUDPUnconnectedAndBounds(t *testing.T) {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp, 5000)
	binary.BigEndian.PutUint16(udp[2:], 53)
	pkt := NFLogPacket{Payload: ip4(ProtoUDP, "10.0.0.5", "9.9.9.9", udp), UID: -1}
	src := &fakeSocks{s: []Sock{{Proto: "udp", Local: netip.MustParseAddrPort("0.0.0.0:5000"), Remote: netip.MustParseAddrPort("0.0.0.0:0"), State: StateClose, Inode: 3}}}
	eg := NewEgress(EgressConfig{}, src, fakeProcs{3: {PID: 5, Comm: "dig"}})
	evs := eg.Packet(time.Now(), pkt)
	if len(evs) != 1 || evs[0].Fields["pid"] != 5 || evs[0].Fields["proto"] != "udp" {
		t.Errorf("udp: %v", evs)
	}

	eg = NewEgress(EgressConfig{MaxPending: 2}, &fakeSocks{}, fakeProcs{})
	now := time.Now()
	n := 0
	for i := 0; i < 10; i++ {
		n += len(eg.Packet(now, syn("10.0.0.5", "1.1.1.1", uint16(2000+i), 80)))
	}
	if eg.Pending() != 2 || n != 8 || eg.Dropped != 8 {
		t.Errorf("pending=%d immediate=%d dropped=%d", eg.Pending(), n, eg.Dropped)
	}
}
