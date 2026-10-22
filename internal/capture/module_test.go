package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"

	"github.com/PurdueBlueTeam/phylax/internal/capture/fixture"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
	"github.com/PurdueBlueTeam/phylax/internal/spool"
)

type sink struct {
	mu  sync.Mutex
	evs []event.Event
}

func (s *sink) emit(e event.Event) error {
	s.mu.Lock()
	s.evs = append(s.evs, e)
	s.mu.Unlock()
	return nil
}

func (s *sink) all() []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Event(nil), s.evs...)
}

func (s *sink) kind(k string) []event.Event {
	var out []event.Event
	for _, e := range s.all() {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

func (s *sink) waitKind(t *testing.T, k string, n int, d time.Duration) []event.Event {
	t.Helper()
	dl := time.Now().Add(d)
	for time.Now().Before(dl) {
		if got := s.kind(k); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d %s events, have %d", n, k, len(s.kind(k)))
	return nil
}

const (
	hostIP   = "10.0.0.100"
	passwd   = "hunter2-correct-horse"
	ftpUser  = "bob"
	scanPeer = "198.51.100.7"
)

// labCapture: an HTTP exchange, an FTP login with a password, and a SYN scan
// of 25 ports on this host from one source.
func labCapture() *fixture.Capture {
	c := newCap()
	cn := c.TCP(ap("203.0.113.9:40000"), ap(hostIP+":80")).Handshake()
	cn.Send(true, []byte(quotientReq))
	cn.Send(false, []byte(okResp))
	cn.Close()
	ft := c.TCP(ap("203.0.113.10:40001"), ap(hostIP+":21")).Handshake()
	ft.Send(false, []byte("220 ready\r\n"))
	ft.Send(true, []byte("USER "+ftpUser+"\r\n"))
	ft.Send(false, []byte("331 need password\r\n"))
	ft.Send(true, []byte("PASS "+passwd+"\r\n"))
	ft.Send(false, []byte("230 logged in\r\n"))
	ft.Send(true, []byte("QUIT\r\n"))
	ft.Send(false, []byte("221 bye\r\n"))
	ft.Close()
	for i := 0; i < 25; i++ {
		c.TCP(ap(fmt.Sprintf("%s:%d", scanPeer, 50000+i)), ap(fmt.Sprintf("%s:%d", hostIP, 1000+i))).SYNOnly()
	}
	return c
}

func newTestModule(t *testing.T, c *fixture.Capture, mut func(*ModuleConfig)) (*Module, *sink, chan event.Event, func()) {
	t.Helper()
	cfg := ModuleConfig{
		Host: "web1", StateDir: t.TempDir(), LocalAddrs: []netip.Addr{netip.MustParseAddr(hostIP)},
		ScoredPorts: []uint16{21, 80}, OrgNets: DefaultOrgNets(), StatsEvery: time.Hour,
		Open: func(InterfaceOptions) (Source, error) { return NewPCAPSource(bytes.NewReader(c.PCAP())) },
	}
	alerts := make(chan event.Event, 8)
	cfg.Subscribe = func(int) (<-chan event.Event, func()) { return alerts, func() {} }
	if mut != nil {
		mut(&cfg)
	}
	m, err := NewModule(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- m.Start(ctx, s.emit) }()
	stop := func() {
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("Start returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("module did not stop")
		}
	}
	t.Cleanup(cancel)
	select {
	case <-m.SourceDone():
	case <-time.After(10 * time.Second):
		t.Fatal("pcap source never finished")
	}
	return m, s, alerts, stop
}

func TestModuleLifecycleEvents(t *testing.T) {
	_, s, _, stop := newTestModule(t, labCapture(), nil)
	defer stop()

	h := s.waitKind(t, KindHTTPRequest, 1, 2*time.Second)
	if h[0].Fields["method"] != "GET" || h[0].Fields["dst_port"] != 80 || h[0].Fields["src_ip"] != "203.0.113.9" {
		t.Fatalf("http_request: %+v", h[0].Fields)
	}
	tx := s.waitKind(t, KindTxn, 1, 2*time.Second)
	var ftp event.Event
	for _, e := range tx {
		if e.Fields["proto"] == "ftp" {
			ftp = e
		}
	}
	if ftp.Kind == "" {
		t.Fatalf("no ftp net.txn in %+v", tx)
	}
	if ftp.Fields["cred"].(map[string]any)["user"] != ftpUser {
		t.Fatalf("cred: %+v", ftp.Fields["cred"])
	}
	if _, ok := ftp.Fields["list"].(map[string]any)["ftp.cmds"]; !ok {
		t.Fatalf("scorer feature list missing: %+v", ftp.Fields["list"])
	}
	// SYN-only flows reach the bus as inbound net.flow with the rule field names.
	flows := s.waitKind(t, KindFlow, 25, 2*time.Second)
	syn := 0
	for _, e := range flows {
		f := e.Fields
		if f["raddr"] == scanPeer && f["dir"] == "inbound" && f["handshake"] == "timeout" && f["laddr"] == hostIP {
			syn++
		}
	}
	if syn != 25 {
		t.Fatalf("%d SYN-only inbound flows, want 25", syn)
	}
	if sc := s.kind(KindScan); len(sc) == 0 || sc[0].Fields["src_ip"] != scanPeer {
		t.Fatalf("net.scan: %+v", sc)
	}
}

func TestModuleSecretsDroppedOrSealedNeverPlain(t *testing.T) {
	hash := txn.HashSecret(passwd)
	check := func(t *testing.T, evs []event.Event) {
		t.Helper()
		b, _ := json.Marshal(evs)
		for _, bad := range []string{passwd, hash} {
			if strings.Contains(string(b), bad) {
				t.Fatalf("%q is in the emitted events", bad)
			}
		}
	}
	t.Run("dropped without a key", func(t *testing.T) {
		_, s, _, stop := newTestModule(t, labCapture(), nil)
		defer stop()
		s.waitKind(t, KindFlow, 25, 2*time.Second)
		check(t, s.all())
		for _, e := range s.kind(KindTxn) {
			if e.Fields["proto"] == "ftp" {
				d, _ := e.Fields["secrets_dropped"].([]any)
				if len(d) != 1 || d[0] != "cred.pass_hash" {
					t.Fatalf("dropped marker: %+v", e.Fields)
				}
			}
		}
	})
	t.Run("sealed with a key", func(t *testing.T) {
		key := bytes.Repeat([]byte{7}, 32)
		sl, _ := NewAESGCMSealer(key)
		_, s, _, stop := newTestModule(t, labCapture(), func(c *ModuleConfig) { c.Seal = sl })
		defer stop()
		s.waitKind(t, KindFlow, 25, 2*time.Second)
		check(t, s.all())
		var got string
		for _, e := range s.kind(KindTxn) {
			if sealed, ok := e.Fields["sealed"].(map[string]any); ok {
				got, _ = sealed["cred.pass_hash"].(string)
			}
		}
		if got == "" {
			t.Fatal("no sealed credential field")
		}
		if p, err := sl.Open(got); err != nil || p != hash {
			t.Fatalf("sealed value opens to %q, %v", p, err)
		}
	})
	t.Run("not in the spool files", func(t *testing.T) {
		dir := t.TempDir()
		sp, err := spool.Open(dir, spool.Options{Agent: "web1"})
		if err != nil {
			t.Fatal(err)
		}
		_, s, _, stop := newTestModule(t, labCapture(), nil)
		s.waitKind(t, KindFlow, 25, 2*time.Second)
		stop()
		for _, e := range s.all() {
			if _, err := sp.Append(e); err != nil {
				t.Fatal(err)
			}
		}
		sp.Close()
		_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() {
				b, _ := os.ReadFile(p)
				if bytes.Contains(b, []byte(passwd)) || bytes.Contains(b, []byte(hash)) {
					t.Errorf("%s holds a credential", p)
				}
			}
			return nil
		})
	})
}

func alertFor(at time.Time, rule string) event.Event {
	return event.Event{Agent: "web1", Time: at, Kind: KindAlert, Priority: event.PriorityCritical, Fields: map[string]any{
		"rule": rule, "collect": []any{"freeze_ring"},
		"entities": map[string]any{"raddr": scanPeer, "laddr": hostIP},
		"evidence": []any{map[string]any{"kind": KindFlow, "fields": map[string]any{"raddr": "203.0.113.9", "dst_port": 80}}},
	}}
}

func countPCAP(t *testing.T, path string) (n int) {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	r, err := pcapgo.NewReader(fh)
	if err != nil {
		t.Fatalf("not a valid pcap: %v", err)
	}
	for {
		_, _, err := r.ReadPacketData()
		if err != nil {
			return n
		}
		n++
	}
}

func TestFreezeOnAlertWritesValidPcapWithinBudget(t *testing.T) {
	c := labCapture()
	m, s, alerts, stop := newTestModule(t, c, func(cfg *ModuleConfig) {
		cfg.FreezeAfter = 150 * time.Millisecond
		cfg.DiskBudget = 1 << 20
	})
	defer stop()
	// The alert time is the packet clock of the lab capture.
	alerts <- alertFor(time.Unix(1700000000, 0).Add(50*time.Millisecond), "D13e.test")
	evs := s.waitKind(t, KindEvidence, 2, 5*time.Second) // at the alert, and when the window closes
	var last event.Event
	for _, e := range evs {
		if e.Fields["final"] == true {
			last = e
		}
	}
	if last.Kind == "" {
		t.Fatalf("no final evidence: %+v", evs)
	}
	f := last.Fields
	if f["error"] != nil {
		t.Fatalf("evidence error: %v", f["error"])
	}
	path := f["path"].(string)
	if !strings.HasPrefix(path, filepath.Join(m.cfg.StateDir, "capture")) {
		t.Fatalf("pcap outside the state dir: %s", path)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > 1<<20 || int(fi.Size()) != f["bytes"].(int) {
		t.Fatalf("pcap file %v %v", fi, err)
	}
	// Only the involved peers' packets, and some of them.
	n := countPCAP(t, path)
	if n == 0 || n != f["packets"].(int) {
		t.Fatalf("pcap holds %d packets, evidence says %v", n, f["packets"])
	}
	ips := f["ips"].([]any)
	if len(ips) != 2 { // the scanner and the HTTP client; never the host's own address
		t.Fatalf("freeze ips %v", ips)
	}
	if f["sha256"] == "" || f["rule"] != "D13e.test" {
		t.Fatalf("evidence: %+v", f)
	}
	// The hold is released after the final write.
	time.Sleep(50 * time.Millisecond)
	if _, err := m.Engine().Ring().Frozen(freezeID("D13e.test", m.fz.AlertIPs(alertFor(time.Now(), "D13e.test")))); err == nil {
		t.Fatal("hold not released")
	}
}

func TestFreezeIgnoresAlertsWithoutFreezeRing(t *testing.T) {
	_, s, alerts, stop := newTestModule(t, labCapture(), func(cfg *ModuleConfig) { cfg.FreezeAfter = 20 * time.Millisecond })
	defer stop()
	a := alertFor(time.Unix(1700000000, 0), "x")
	a.Fields["collect"] = []any{"process_tree"}
	alerts <- a
	other := alertFor(time.Unix(1700000000, 0), "x")
	other.Agent = "db1" // an alert about another host is not ours to freeze for
	alerts <- other
	time.Sleep(200 * time.Millisecond)
	if n := len(s.kind(KindEvidence)); n != 0 {
		t.Fatalf("%d evidence events", n)
	}
}

func TestFreezeDiskBudget(t *testing.T) {
	t.Run("larger than the budget is refused", func(t *testing.T) {
		m, s, alerts, stop := newTestModule(t, labCapture(), func(cfg *ModuleConfig) {
			cfg.FreezeAfter = 20 * time.Millisecond
			cfg.DiskBudget = 100 // smaller than any pcap
		})
		defer stop()
		alerts <- alertFor(time.Unix(1700000000, 0).Add(50*time.Millisecond), "r1")
		evs := s.waitKind(t, KindEvidence, 1, 5*time.Second)
		if e, _ := evs[0].Fields["error"].(string); !strings.Contains(e, "budget") {
			t.Fatalf("evidence: %+v", evs[0].Fields)
		}
		if ents, _ := os.ReadDir(m.cfg.PcapDir); len(ents) != 0 {
			t.Fatalf("files written over budget: %v", ents)
		}
	})
	t.Run("oldest pcaps are evicted to make room", func(t *testing.T) {
		dir := t.TempDir()
		old := filepath.Join(dir, "fz-old.pcap")
		if err := os.WriteFile(old, bytes.Repeat([]byte{1}, 6000), 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(old, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour))
		fz := &Freezer{Ring: NewRing(RingConfig{}), Dir: dir, Budget: 7000}
		// 6000 + a 24 byte empty pcap fits; add another 6000 file and it must go.
		if n, err := fz.makeRoom(filepath.Join(dir, "fz-new.pcap"), 5000); err != nil || n != 1 {
			t.Fatalf("evicted %d, %v", n, err)
		}
		if _, err := os.Stat(old); !os.IsNotExist(err) {
			t.Fatal("old pcap kept")
		}
	})
}

func TestModuleFiniteSourceKeepsRunningAndStops(t *testing.T) {
	m, s, _, stop := newTestModule(t, labCapture(), nil)
	_ = m
	s.waitKind(t, KindFlow, 25, 2*time.Second)
	stop() // returns nil within the timeout, checked by stop
}

func TestModuleRateLimitsAreBounded(t *testing.T) {
	c := newCap()
	for i := 0; i < 200; i++ {
		c.TCP(ap(fmt.Sprintf("198.51.100.%d:5%04d", i%250+1, i)), ap(fmt.Sprintf("%s:%d", hostIP, 2000+i))).SYNOnly()
	}
	m, s, _, stop := newTestModule(t, c, func(cfg *ModuleConfig) { cfg.FlowRate = 10 })
	defer stop()
	time.Sleep(100 * time.Millisecond)
	if n := len(s.kind(KindFlow)); n > 40 || n == 0 {
		t.Fatalf("%d flows passed a 10/s limit", n)
	}
	if m.dropped[1].Load() == 0 {
		t.Fatal("drops not counted")
	}
}
