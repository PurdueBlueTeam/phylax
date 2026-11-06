package load_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/bench"
	"github.com/PurdueBlueTeam/phylax/internal/bench/load"
	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/enroll"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

func TestGenEmitsRates(t *testing.T) {
	g := &load.Gen{Rates: [bench.NumClasses]float64{1, 5, 20, 0}, Size: 50}
	var mu sync.Mutex
	got := map[event.Priority]int{}
	emit := func(e event.Event) error {
		mu.Lock()
		defer mu.Unlock()
		got[e.Priority]++
		if e.Kind != "bench.load" || len(e.Fields["pad"].(string)) != 50 {
			t.Error(e)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	g.Start(ctx, emit)
	mu.Lock()
	defer mu.Unlock()
	if got[event.PriorityCritical] < 1 || got[event.PriorityCritical] > 3 ||
		got[event.PriorityHigh] < 8 || got[event.PriorityHigh] > 12 ||
		got[event.PriorityNormal] < 35 || got[event.PriorityNormal] > 45 || got[event.PriorityBulk] != 0 {
		t.Fatal(got)
	}
	if g.Emitted() != uint64(got[0]+got[1]+got[2]) {
		t.Fatal(g.Emitted())
	}
}

func TestGenStop(t *testing.T) {
	g := &load.Gen{Rates: [bench.NumClasses]float64{1, 1, 1, 1}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- g.Start(ctx, func(event.Event) error { return nil })
	}()
	time.Sleep(50 * time.Millisecond)
	g.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Start did not return after Stop")
	}
}

func TestStartAgentsRealEnrollment(t *testing.T) {
	c, addr, stop := startController(t)
	dir := t.TempDir()
	if err := c.Enroller().WriteBundles(dir, []string{"bench-001", "bench-002"}, enroll.BundleOptions{
		Controllers: []string{addr}, TTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	proxy, err := load.NewProxy("127.0.0.1:0", addr, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	work := t.TempDir()
	a, err := load.StartAgents(ctx, dir, "bench-", 2, proxy.Addr(), work,
		[bench.NumClasses]float64{0, 5, 5, 0}, 100,
		link.Backoff{Min: 50 * time.Millisecond, Max: 500 * time.Millisecond}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Stop()

	waitFor(t, 20*time.Second, "both agents to connect", func() bool { return a.Connected() == 2 })
	waitFor(t, 20*time.Second, "bench-001 to ack 20 events and connect once", func() bool {
		st, ok := c.AgentStatus("bench-001")
		return ok && st.Acked >= 20 && st.Connects == 1
	})

	a.StopGen()
	waitFor(t, 20*time.Second, "the spool to drain", func() bool { return a.Depth() == 0 })
	a.Stop()

	// The bundle token was consumed by the first run; a second run with fresh
	// state but the same bundles cannot enroll.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	b, err := load.StartAgents(ctx2, dir, "bench-", 2, proxy.Addr(), filepath.Join(t.TempDir(), "work2"),
		[bench.NumClasses]float64{}, 0, link.Backoff{Min: 50 * time.Millisecond, Max: 500 * time.Millisecond}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	time.Sleep(3 * time.Second)
	if n := b.Connected(); n != 0 {
		t.Fatalf("%d agents connected with a consumed token", n)
	}
	_ = stop
}

func TestStartAgentsNotEnoughBundles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bench-001.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := load.StartAgents(context.Background(), dir, "bench-", 2, "127.0.0.1:1", t.TempDir(),
		[bench.NumClasses]float64{}, 0, link.Backoff{}, 0)
	if err == nil || !strings.Contains(err.Error(), "need 2, found 1") {
		t.Fatalf("error = %v, want need 2, found 1", err)
	}
}

// startController runs a real controller on a loopback listener and returns
// its address; stop shuts it down.
func startController(t *testing.T) (*controller.Controller, string, func()) {
	t.Helper()
	c, err := controller.New(context.Background(), controller.Config{
		AgentListen:   "127.0.0.1:0",
		DataDir:       filepath.Join(t.TempDir(), "data"),
		BenchInterval: controller.Duration(500 * time.Millisecond),
	}, controller.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Serve(ctx, ln) }()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("controller did not shut down")
		}
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(stop)
	return c, ln.Addr().String(), stop
}

func waitFor(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
