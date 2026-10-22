package netmod

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

type fakeSocks struct {
	mu sync.Mutex
	s  []Sock
}

func (f *fakeSocks) Sockets() ([]Sock, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Sock(nil), f.s...), nil
}
func (f *fakeSocks) add(s Sock) { f.mu.Lock(); f.s = append(f.s, s); f.mu.Unlock() }

type fakeProcs map[uint64]Proc

func (f fakeProcs) Resolve([]uint64) map[uint64]Proc { return f }

func lsn(proto, ap string, inode uint64) Sock {
	st := uint8(StateListen)
	if proto == "udp" {
		st = StateClose
	}
	return Sock{Proto: proto, Local: netip.MustParseAddrPort(ap), Remote: netip.AddrPortFrom(netip.IPv4Unspecified(), 0), State: st, Inode: inode}
}
func est(proto, l, r string, inode uint64) Sock {
	return Sock{Proto: proto, Local: netip.MustParseAddrPort(l), Remote: netip.MustParseAddrPort(r), State: StateEstablished, Inode: inode}
}

func kinds(evs []event.Event) map[string]int {
	m := map[string]int{}
	for _, e := range evs {
		m[e.Kind]++
	}
	return m
}

func TestTrackerDiffAndDirection(t *testing.T) {
	src := &fakeSocks{}
	procs := fakeProcs{
		1: {PID: 10, Comm: "sshd", Exe: "/usr/sbin/sshd", ExeSHA256: "aa"},
		2: {PID: 11, Comm: "sshd", Exe: "/usr/sbin/sshd", ExeSHA256: "aa"},
		3: {PID: 12, Comm: "curl", Exe: "/usr/bin/curl", ExeSHA256: "bb"},
	}
	tr := NewTracker(TrackerConfig{Services: map[string]string{"22": "ssh", "udp/53": "dns", "443": "https"}}, src, procs)
	now := time.Unix(100, 0)

	src.s = []Sock{lsn("tcp", "0.0.0.0:22", 1), est("tcp", "10.0.0.5:22", "10.0.0.9:50000", 2), est("tcp", "10.0.0.5:41000", "93.184.216.34:443", 3)}
	evs, err := tr.Poll(now)
	if err != nil {
		t.Fatal(err)
	}
	if k := kinds(evs); k[KindListenerAdded] != 1 || k[KindConnectionOpened] != 2 {
		t.Fatalf("first poll: %v", k)
	}
	byDir := map[string]event.Event{}
	for _, e := range evs {
		if e.Kind == KindListenerAdded {
			f := e.Fields
			if f["baseline"] != true || f["service"] != "ssh" || f["pid"] != 10 || f["exe_sha256"] != "aa" {
				t.Errorf("listener fields: %v", f)
			}
		}
		if e.Kind == KindConnectionOpened {
			byDir[e.Fields["dir"].(string)] = e
		}
	}
	in, out := byDir["inbound"], byDir["outbound"]
	if in.Fields["rport"] != 50000 || in.Fields["service"] != "ssh" || in.Fields["pid"] != 11 {
		t.Errorf("inbound: %v", in.Fields)
	}
	if out.Fields["raddr"] != "93.184.216.34" || out.Fields["service"] != "https" || out.Fields["comm"] != "curl" {
		t.Errorf("outbound: %v", out.Fields)
	}
	if in.Fields["community_id"] == "" || in.Fields["community_id"] == out.Fields["community_id"] {
		t.Error("community ids")
	}

	// Steady state: no events.
	evs, _ = tr.Poll(now.Add(2 * time.Second))
	if len(evs) != 0 {
		t.Fatalf("steady state emitted %v", kinds(evs))
	}

	// Outbound closes, inbound closes, listener goes, new UDP listener appears.
	src.s = []Sock{lsn("udp", "0.0.0.0:53", 4)}
	procs[4] = Proc{PID: 13, Comm: "named"}
	evs, _ = tr.Poll(now.Add(5 * time.Second))
	k := kinds(evs)
	if k[KindListenerRemoved] != 1 || k[KindListenerAdded] != 1 || k[KindConnectionClosed] != 2 {
		t.Fatalf("diff: %v", k)
	}
	for _, e := range evs {
		if e.Kind == KindConnectionClosed {
			if e.Fields["duration_ms"] != int64(5000) {
				t.Errorf("duration %v", e.Fields["duration_ms"])
			}
			if e.Fields["pid"] == nil {
				t.Error("close lost process")
			}
		}
		if e.Kind == KindListenerAdded {
			if e.Fields["baseline"] != nil || e.Fields["service"] != "dns" {
				t.Errorf("udp listener: %v", e.Fields)
			}
		}
	}
	if tr.Conns() != 0 || tr.Listeners() != 1 {
		t.Errorf("state: %d conns %d listeners", tr.Conns(), tr.Listeners())
	}
}

func TestDirectionInference(t *testing.T) {
	src := &fakeSocks{s: []Sock{
		lsn("tcp", "127.0.0.1:8080", 1),                    // loopback-only listener
		lsn("tcp", "[::]:9000", 1),                         // wildcard
		lsn("udp", "0.0.0.0:5353", 1),                      // udp listener
		est("tcp", "127.0.0.1:8080", "127.0.0.1:50001", 2), // inbound
		est("tcp", "10.0.0.5:8080", "10.0.0.9:50002", 3),   // port matches but listener addr differs: outbound
		est("tcp", "10.0.0.5:9000", "10.0.0.9:50003", 4),   // wildcard listener: inbound
		est("udp", "10.0.0.5:5353", "10.0.0.7:5353", 5),    // connected udp from listener port: inbound
		est("tcp", "127.0.0.1:50001", "127.0.0.1:8080", 6), // client side of loopback: outbound
	}}
	tr := NewTracker(TrackerConfig{}, src, fakeProcs{})
	evs, _ := tr.Poll(time.Now())
	want := map[uint64]string{2: "inbound", 3: "outbound", 4: "inbound", 5: "inbound", 6: "outbound"}
	for _, e := range evs {
		if e.Kind != KindConnectionOpened {
			continue
		}
		in := e.Fields["inode"].(uint64)
		if e.Fields["dir"] != want[in] {
			t.Errorf("inode %d: dir %v want %s", in, e.Fields["dir"], want[in])
		}
	}
}

func TestDirectionStickyAfterListenerGone(t *testing.T) {
	src := &fakeSocks{s: []Sock{lsn("tcp", "0.0.0.0:22", 1), est("tcp", "10.0.0.5:22", "10.0.0.9:5", 2)}}
	tr := NewTracker(TrackerConfig{}, src, fakeProcs{})
	tr.Poll(time.Now())
	src.s = src.s[1:]
	evs, _ := tr.Poll(time.Now())
	for _, e := range evs {
		if e.Kind == KindConnectionClosed && e.Fields["dir"] != "inbound" {
			t.Error("direction changed")
		}
	}
}

func TestTrackerBounded(t *testing.T) {
	src := &fakeSocks{}
	for i := 0; i < 50; i++ {
		src.s = append(src.s, est("tcp", "10.0.0.5:40000", netip.AddrPortFrom(netip.MustParseAddr("10.0.0.9"), uint16(1000+i)).String(), uint64(i+1)))
	}
	tr := NewTracker(TrackerConfig{MaxConns: 10}, src, fakeProcs{})
	evs, _ := tr.Poll(time.Now())
	if len(evs) != 10 || tr.Conns() != 10 || tr.Dropped != 40 {
		t.Errorf("events %d conns %d dropped %d", len(evs), tr.Conns(), tr.Dropped)
	}
}

func TestLateAttribution(t *testing.T) {
	src := &fakeSocks{s: []Sock{est("tcp", "10.0.0.5:4000", "1.1.1.1:443", 7)}}
	procs := fakeProcs{}
	tr := NewTracker(TrackerConfig{}, src, procs)
	tr.Poll(time.Now())
	procs[7] = Proc{PID: 5, Comm: "late"}
	tr.Poll(time.Now())
	src.s = nil
	evs, _ := tr.Poll(time.Now())
	if len(evs) != 1 || evs[0].Fields["comm"] != "late" {
		t.Errorf("late attribution not carried to close: %v", evs)
	}
}

func mustAP(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
