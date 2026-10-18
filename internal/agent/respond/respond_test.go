package respond

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/detect"
)

type pub struct {
	mu    sync.Mutex
	evs   []string
	data  map[string]any
	ready chan struct{}
}

func (p *pub) Publish(evType string, data any) error {
	p.mu.Lock()
	p.evs = append(p.evs, evType)
	if d, ok := data.(map[string]any); ok {
		p.data = d
	}
	p.mu.Unlock()
	select {
	case <-p.ready:
	default:
		close(p.ready)
	}
	return nil
}

func (p *pub) has(typ string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.evs {
		if e == typ {
			return true
		}
	}
	return false
}

func newModule(p *pub, restoreCalls *int, healthOK *bool) *Module {
	recipe := Recipe{
		For:  "D10b.firewall-tamper",
		Name: "restore.firewall",
		Run: func(ctx context.Context, a detect.Alert, env *Env) (string, string, string, error) {
				*restoreCalls++
			return "firewall:disabled", "firewall:declared", "re-apply", nil
		},
	}
	return New(&Env{
		Health:   func(name string) bool { return *healthOK },
		SafeMode: func() bool { return false },
		Publish:  p,
	}, []Recipe{recipe})
}

func alert() detect.Alert {
	return detect.Alert{Rule: "D10b.firewall-tamper", Tier: 0, TS: time.Now()}
}

func runOne(t *testing.T, m *Module) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = m.Run(ctx)
		close(done)
	}()
	m.Submit(alert())
	select {
	case <-done:
		t.Fatal("run exited early")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestT02Local (lab T02): a firewall disable is restored within 10 s
// (here: milliseconds), and the trigger is identified — 3 restores in
// 10 minutes opens an incident and stops the restore loop.
func TestT02Local(t *testing.T) {
	p := &pub{ready: make(chan struct{})}
	calls, health := 0, true
	m := newModule(p, &calls, &health)

	start := time.Now()
	runOne(t, m)
	elapsed := time.Since(start)
	if calls != 1 {
		t.Fatalf("want 1 restore, got %d", calls)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("restore took %s (> 10 s)", elapsed)
	}
	// 2nd restore runs (only 2 in the window so far)
	runOne(t, m)
	if calls != 2 {
		t.Fatalf("want 2 restores, got %d", calls)
	}
	// 3rd in 10 minutes: the loop guard opens an incident instead of
	// restoring forever.
	runOne(t, m)
	if calls != 2 {
		t.Fatalf("3rd restore in 10 min must be suppressed, got %d", calls)
	}
	if !p.has("incident") {
		t.Fatal("3 restores in 10 min must open an incident")
	}
	p.mu.Lock()
	kind, _ := p.data["kind"].(string)
	p.mu.Unlock()
	if kind != "restore-loop" {
		t.Fatalf("incident kind = %q, want restore-loop", kind)
	}
	// further restores keep being suppressed (loop already broken)
	runOne(t, m)
	if calls != 2 {
		t.Fatalf("post-incident restore must be suppressed, got %d calls", calls)
	}
}

// TestBreaker: a red health check within 2 minutes of a tier-0 action
// disables that action type and escalates.
func TestBreaker(t *testing.T) {
	p := &pub{ready: make(chan struct{})}
	calls := 0
	health := true
	m := newModule(p, &calls, &health)
	health = false
	runOne(t, m)
	if !p.has("response") {
		t.Fatal("response event missing")
	}
	runOne(t, m)
	if calls != 1 {
		t.Fatalf("breaker must block the 2nd run, got %d", calls)
	}
}

// TestRateLimit: at most 3 executed tier-0 actions per host per minute
// (host-wide, across action types); beyond that they escalate.
func TestRateLimit(t *testing.T) {
	p := &pub{ready: make(chan struct{})}
	calls := 0
	recipes := []Recipe{}
	for _, rule := range []string{"R1", "R2", "R3", "R4"} {
		recipes = append(recipes, Recipe{
			For:  rule,
			Name: "act." + rule,
			Run: func(ctx context.Context, a detect.Alert, env *Env) (string, string, string, error) {
				calls++
				return "a", "b", "c", nil
			},
		})
	}
	m := New(&Env{
		Health:   func(name string) bool { return true },
		SafeMode: func() bool { return false },
		Publish:  p,
	}, recipes)
	fire := func(rule string) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { _ = m.Run(ctx); close(done) }()
		m.Submit(detect.Alert{Rule: rule, Tier: 0, TS: time.Now()})
		select {
		case <-done:
			t.Fatal("run exited early")
		case <-time.After(200 * time.Millisecond):
		}
		cancel()
	}
	fire("R1")
	fire("R2")
	fire("R3")
	if calls != 3 {
		t.Fatalf("want 3 runs under the limit, got %d", calls)
	}
	fire("R4")
	if calls != 3 {
		t.Fatalf("4th action in a minute must escalate, got %d", calls)
	}
}

// TestSafeMode: tier-0 is suspended in safe mode (detection continues).
func TestSafeMode(t *testing.T) {
	p := &pub{ready: make(chan struct{})}
	calls, health := 0, true
	m := newModule(p, &calls, &health)
	m.env.SafeMode = func() bool { return true }
	runOne(t, m)
	if calls != 0 {
		t.Fatal("safe mode must suspend tier-0")
	}
}

// TestLockHeld: a restore waits on a shared plan lock; while held it
// does not run unguarded.
func TestLockHeld(t *testing.T) {
	p := &pub{ready: make(chan struct{})}
	calls, health := 0, true
	m := newModule(p, &calls, &health)
	m.env.LockTry = func(name, owner string) bool { return false }
	m.env.LockOwner = func(name string) string { return "plan-1" }
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = m.Run(ctx) }()
	m.Submit(alert())
	time.Sleep(1200 * time.Millisecond) // a few wait ticks; still held
	cancel()
	if calls != 0 {
		t.Fatalf("restore must not run while a plan holds the lock, got %d", calls)
	}
}
