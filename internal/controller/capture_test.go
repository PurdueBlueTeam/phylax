package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/capture"
	"github.com/PurdueBlueTeam/phylax/internal/capture/fixture"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

const (
	capHost = "rocky-ecom"
	capIP   = "172.20.240.10"
)

// synScan is nTargets SYN-only connection attempts from sources that rotate
// inside one /16 (or a fixed source), each to a different port on this host.
func synScan(src func(i int) string, nTargets int) *fixture.Capture {
	c := fixture.New(time.Unix(1700000000, 0))
	for i := 0; i < nTargets; i++ {
		c.TCP(netip.MustParseAddrPort(fmt.Sprintf("%s:%d", src(i), 40000+i)),
			netip.MustParseAddrPort(fmt.Sprintf("%s:%d", capIP, 1000+i))).SYNOnly()
	}
	return c
}

// captureEvents runs the real capture module over c and returns what it
// emitted, as the controller would receive them (a JSON round trip).
func captureEvents(t *testing.T, c *fixture.Capture) []event.Event {
	t.Helper()
	m, err := capture.NewModule(capture.ModuleConfig{
		Host: capHost, StateDir: t.TempDir(), ScoredPorts: []uint16{80},
		LocalAddrs: []netip.Addr{netip.MustParseAddr(capIP)}, FlowRate: 5000, StatsEvery: time.Hour,
		Open: func(capture.InterfaceOptions) (capture.Source, error) {
			return capture.NewPCAPSource(bytes.NewReader(c.PCAP()))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var out []event.Event
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- m.Start(ctx, func(e event.Event) error {
			e.Agent = capHost
			b, _ := json.Marshal(e)
			var back event.Event
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.UseNumber()
			if err := dec.Decode(&back); err != nil {
				return err
			}
			mu.Lock()
			out = append(out, back)
			mu.Unlock()
			return nil
		})
	}()
	select {
	case <-m.SourceDone():
	case <-time.After(10 * time.Second):
		t.Fatal("capture never finished")
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	return append([]event.Event(nil), out...)
}

func controllerWithRules(t *testing.T) *Controller {
	t.Helper()
	c := newBareController(t, t.TempDir())
	if err := c.SetConfigInputs(context.Background(), ConfigInputs{Manifest: realManifest(t), Rules: realRules(t)}); err != nil {
		t.Fatal(err)
	}
	return c
}

func alertRules(t *testing.T, c *Controller) []string {
	t.Helper()
	rows, err := c.st.Alerts(context.Background(), "", 50)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.Rule)
	}
	return out
}

func feed(c *Controller, evs []event.Event) {
	for i := range evs {
		evs[i].Seq = uint64(i + 1)
	}
	c.captureObserve(context.Background(), evs, uint64(len(evs)))
}

const p88 = "D13e.scan-source-rotation"

// The scanner rotates sources inside one /16 so no per-source scan rule fires;
// only the controller-scope rule over the capture module's SYN-only flows does.
func TestCaptureSYNScanFiresP88(t *testing.T) {
	c := controllerWithRules(t)
	evs := captureEvents(t, synScan(func(i int) string { return fmt.Sprintf("198.51.%d.10", i) }, 35))
	flows := 0
	for _, e := range evs {
		if e.Kind == "net.flow" && e.Fields["handshake"] == "timeout" && e.Fields["dir"] == "inbound" {
			flows++
		}
		if e.Kind == "net.scan" {
			t.Fatal("a single source should not have crossed the per-source scan threshold")
		}
	}
	if flows != 35 {
		t.Fatalf("%d SYN-only inbound flows from the capture module, want 35", flows)
	}
	feed(c, evs)
	if got := alertRules(t, c); len(got) != 1 || got[0] != p88 {
		t.Fatalf("alerts %v, want [%s]", got, p88)
	}
	rows, _ := c.st.Alerts(context.Background(), "", 5)
	k := parseKeys(rows[0].Keys)
	if k.Entities["raddr_net16"] != "198.51.0.0/16" && !strings.HasPrefix(k.Entities["raddr_net16"], "198.51.") {
		t.Fatalf("entities %v", k.Entities)
	}
	if len(k.Evidence) == 0 || k.Evidence[0].Agent != capHost || k.Evidence[0].Seq == 0 {
		t.Fatalf("evidence refs %+v", k.Evidence)
	}
	// Replaying the same stored batch inside the cooldown does not alert again.
	feed(c, evs)
	if got := alertRules(t, c); len(got) != 1 {
		t.Fatalf("duplicate alert: %v", got)
	}
}

func TestCaptureScorerSourcesAreExcluded(t *testing.T) {
	m := realManifest(t)
	srcs := ManifestScorerSources(m)
	want := map[string]bool{}
	for name, h := range m.Hosts {
		if h.HasRole(manifest.RoleScanner) {
			a, ok := m.HostAddr(name)
			if !ok {
				t.Fatalf("scanner %s has no address", name)
			}
			want[a.String()] = false
		}
	}
	if len(want) == 0 {
		t.Fatal("manifest has no scanner host")
	}
	for _, s := range srcs {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for a, ok := range want {
		if !ok {
			t.Fatalf("vantage %s missing from %v", a, srcs)
		}
	}
	scanner := ""
	for a := range want {
		scanner = a
	}
	t.Run("manifest vantage", func(t *testing.T) {
		c := controllerWithRules(t)
		// One /16 key, 35 targets, but every source is the Kali's own address.
		feed(c, captureEvents(t, synScan(func(int) string { return scanner }, 35)))
		if got := alertRules(t, c); len(got) != 0 {
			t.Fatalf("our own scanner raised %v", got)
		}
	})
	t.Run("learned from scorer discovery", func(t *testing.T) {
		c := controllerWithRules(t)
		const learned = "203.0.113.77"
		if c.NoteScorerSource("not an address") {
			t.Fatal("accepted junk")
		}
		evs := captureEvents(t, synScan(func(int) string { return learned }, 35))
		feed(c, evs) // not yet known: alerts
		if got := alertRules(t, c); len(got) != 1 {
			t.Fatalf("unlearned source: %v", got)
		}
		c2 := controllerWithRules(t)
		if !c2.NoteScorerSource(learned) {
			t.Fatal("not accepted")
		}
		feed(c2, evs)
		if got := alertRules(t, c2); len(got) != 0 {
			t.Fatalf("learned scorer source raised %v", got)
		}
		// and it survives a rule reload
		c2.cfgs.mu.Lock()
		c2.cfgs.gen++
		c2.cfgs.mu.Unlock()
		feed(c2, evs)
		if got := alertRules(t, c2); len(got) != 0 {
			t.Fatalf("after reload: %v", got)
		}
	})
}

func TestCaptureObserveIgnoresWhatItShouldNot(t *testing.T) {
	c := controllerWithRules(t)
	evs := captureEvents(t, synScan(func(i int) string { return fmt.Sprintf("198.51.%d.10", i) }, 35))
	// not stored yet (Seq above the ack): never counted
	for i := range evs {
		evs[i].Seq = uint64(i + 1)
	}
	c.captureObserve(context.Background(), evs, 0)
	if got := alertRules(t, c); len(got) != 0 {
		t.Fatalf("unstored events were counted: %v", got)
	}
	// outbound or direction-less flows are not inbound probes
	for i := range evs {
		if evs[i].Kind == "net.flow" {
			delete(evs[i].Fields, "dir")
		}
	}
	c.captureObserve(context.Background(), evs, uint64(len(evs)))
	if got := alertRules(t, c); len(got) != 0 {
		t.Fatalf("flows without direction counted: %v", got)
	}
}

// The whole path: capture module -> agent spool -> link -> controller ingest
// -> controller-scope rule -> operator alert queue.
func TestCaptureSYNScanEndToEndThroughSpoolAndLink(t *testing.T) {
	x := newCtl(t)
	if err := x.c.SetConfigInputs(context.Background(), ConfigInputs{Manifest: realManifest(t), Rules: realRules(t)}); err != nil {
		t.Fatal(err)
	}
	tok, err := x.c.Enroller().MintToken(capHost, 0)
	if err != nil {
		t.Fatal(err)
	}
	a := newAgent(t, x, capHost, tok)
	for _, e := range captureEvents(t, synScan(func(i int) string { return fmt.Sprintf("198.51.%d.10", i) }, 35)) {
		if _, err := a.sp.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); a.run(ctx) }()
	defer func() { cancel(); <-done }()
	waitFor(t, time.Second, "P88 alert from spooled capture flows", func() bool {
		rows, _ := x.c.st.Alerts(context.Background(), "", 10)
		for _, r := range rows {
			if r.Rule == p88 && r.Host == capHost {
				return true
			}
		}
		return false
	})
}
