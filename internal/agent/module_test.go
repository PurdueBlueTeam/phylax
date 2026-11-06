package agent

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
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
func (s *sink) count(kind string) (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.evs {
		if e.Kind == kind {
			n++
		}
	}
	return
}

func runSup(t *testing.T, o SupervisorOptions, specs ...ModuleSpec) (*Supervisor, *sink, context.CancelFunc) {
	t.Helper()
	sk := &sink{}
	o.Emit, o.Logger = sk.emit, quietLog()
	if o.Backoff.Min == 0 {
		o.Backoff = link.Backoff{Min: time.Millisecond, Max: 5 * time.Millisecond}
	}
	s := NewSupervisor(o)
	for _, sp := range specs {
		if err := s.Add(sp); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("supervisor did not stop")
		}
	})
	return s, sk, cancel
}

func TestSupervisorRestartsCrashesAndPanics(t *testing.T) {
	var runs atomic.Int32
	s, sk, _ := runSup(t, SupervisorOptions{}, ModuleSpec{Module: funcModule{"flaky", func(ctx context.Context, emit Emit) error {
		switch runs.Add(1) {
		case 1:
			return errors.New("boom")
		case 2:
			var m map[string]int
			m["x"] = 1 // panic: nil map write
		}
		emit(event.Event{Kind: "alive"})
		<-ctx.Done()
		return nil
	}}})
	eventually(t, 5*time.Second, "third run", func() bool { return sk.count("alive") == 1 })
	st := s.Snapshot()["flaky"]
	if st.State != StateRunning || st.Restarts != 2 || st.LastError == "" {
		t.Fatalf("status %+v", st)
	}
	if sk.count("agent.module_crash") != 2 {
		t.Fatalf("crash events: %d", sk.count("agent.module_crash"))
	}
}

func TestSupervisorBackoffGrowsAndNilReturnStops(t *testing.T) {
	var starts []time.Time
	var mu sync.Mutex
	s, _, _ := runSup(t, SupervisorOptions{Backoff: link.Backoff{Min: 20 * time.Millisecond, Max: 200 * time.Millisecond}},
		ModuleSpec{Module: funcModule{"bad", func(ctx context.Context, _ Emit) error {
			mu.Lock()
			starts = append(starts, time.Now())
			mu.Unlock()
			return errors.New("x")
		}}},
		ModuleSpec{Module: funcModule{"done", func(context.Context, Emit) error { return nil }}})
	eventually(t, 5*time.Second, "4 starts", func() bool { mu.Lock(); defer mu.Unlock(); return len(starts) >= 4 })
	mu.Lock()
	gap1, gap3 := starts[1].Sub(starts[0]), starts[3].Sub(starts[2])
	mu.Unlock()
	if gap1 < 10*time.Millisecond || gap3 < gap1/2 || gap3 < 40*time.Millisecond {
		t.Fatalf("backoff not growing: %v then %v", gap1, gap3)
	}
	if st := s.Snapshot()["done"]; st.State != StateStopped || st.Restarts != 0 {
		t.Fatalf("finished module: %+v", st)
	}
}

func TestSupervisorRateLimitDropsWithoutBlocking(t *testing.T) {
	s, sk, _ := runSup(t, SupervisorOptions{}, ModuleSpec{Rate: 1, Burst: 5, Module: funcModule{"loud", func(ctx context.Context, emit Emit) error {
		for i := 0; i < 100; i++ {
			emit(event.Event{Kind: "loud"})
		}
		<-ctx.Done()
		return nil
	}}})
	eventually(t, 5*time.Second, "limited", func() bool { return s.Snapshot()["loud"].Emitted+s.Snapshot()["loud"].RateDropped == 100 })
	st := s.Snapshot()["loud"]
	if st.Emitted < 5 || st.Emitted > 7 || sk.count("loud") != int(st.Emitted) {
		t.Fatalf("emitted %d dropped %d sink %d", st.Emitted, st.RateDropped, sk.count("loud"))
	}
}

func TestHealthModuleReportsGapsAndState(t *testing.T) {
	src := &fakeHealth{mods: map[string]ModuleStatus{"a": {State: StateRunning}}}
	h := NewHealthModule(src, 10*time.Millisecond).(*healthModule)
	sk := &sink{}
	h.report(sk.emit, time.Now())
	src.mods = map[string]ModuleStatus{"a": {State: StateRestarting, Restarts: 1, RateDropped: 4, DownSince: time.Now()}}
	h.report(sk.emit, time.Now())
	if sk.count("agent.health") != 2 || sk.count("telemetry_gap") != 2 {
		t.Fatalf("health=%d gaps=%d", sk.count("agent.health"), sk.count("telemetry_gap"))
	}
	reasons := map[string]bool{}
	for _, e := range sk.evs {
		if e.Kind == "telemetry_gap" {
			reasons[e.Fields["reason"].(string)] = true
		}
	}
	if !reasons["rate_limit"] || !reasons["module_down"] {
		t.Fatal(reasons)
	}
}

type fakeHealth struct{ mods map[string]ModuleStatus }

func (f *fakeHealth) Modules() map[string]ModuleStatus { return f.mods }
func (f *fakeHealth) SpoolStats() spool.Stats          { return spool.Stats{HeadSeq: 5, AckSeq: 2} }
func (f *fakeHealth) Link() LinkStatus                 { return LinkStatus{} }
