package controller

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*fakeTimer
	tickers []*fakeTicker
	ops     chan struct{}
}

type fakeTimer struct {
	clk      *fakeClock
	deadline time.Time
	active   bool
	ch       chan time.Time
}

type fakeTicker struct {
	clk      *fakeClock
	next     time.Time
	interval time.Duration
	active   bool
	ch       chan time.Time
}

func newFakeClock(now time.Time) *fakeClock {
	return &fakeClock{now: now, ops: make(chan struct{}, 1024)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) timer {
	c.mu.Lock()
	t := &fakeTimer{clk: c, deadline: c.now.Add(d), active: true, ch: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	c.signal()
	return t
}

func (c *fakeClock) NewTicker(d time.Duration) ticker {
	c.mu.Lock()
	t := &fakeTicker{clk: c, next: c.now.Add(d), interval: d, active: true, ch: make(chan time.Time, 1)}
	c.tickers = append(c.tickers, t)
	c.mu.Unlock()
	c.signal()
	return t
}

func (c *fakeClock) signal() {
	select {
	case c.ops <- struct{}{}:
	default:
	}
}

func (c *fakeClock) waitOps(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-c.ops:
		case <-time.After(2 * time.Second):
			t.Fatalf("timer operation %d/%d did not happen", i+1, n)
		}
	}
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, t := range c.timers {
		if t.active && !t.deadline.After(c.now) {
			t.active = false
			select {
			case t.ch <- c.now:
			default:
			}
		}
	}
	for _, t := range c.tickers {
		for t.active && !t.next.After(c.now) {
			select {
			case t.ch <- c.now:
			default:
			}
			t.next = t.next.Add(t.interval)
		}
	}
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() {
	t.clk.mu.Lock()
	t.active = false
	t.clk.mu.Unlock()
}

func (t *fakeTimer) Reset(d time.Duration) {
	t.clk.mu.Lock()
	t.deadline = t.clk.now.Add(d)
	t.active = true
	select {
	case <-t.ch:
	default:
	}
	t.clk.mu.Unlock()
	t.clk.signal()
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }

func (t *fakeTicker) Stop() {
	t.clk.mu.Lock()
	t.active = false
	t.clk.mu.Unlock()
}

func TestAnalyzerDebounceMaxWait(t *testing.T) {
	fc := newFakeClock(time.Unix(0, 0))
	c := newTestControllerWithManifest(t, nil)
	c.clk = fc
	c.now = fc.Now
	runs := make(chan time.Time, 16)
	m := anaMod{testMod(), []module.Analyzer{{Name: "debounce", Inputs: []string{"agent.resumed"},
		Run: func(_ context.Context, _ store.Reader, now time.Time) ([]event.Event, error) {
			runs <- now
			return nil, nil
		}}}}
	h := c.hostFor(m)
	st := &moduleRunState{mod: m}
	trig := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.runAnalyzer(ctx, h, st, m.as[0], trig)
	}()
	defer func() {
		cancel()
		<-done
	}()
	for i := 0; i < 60; i++ {
		select {
		case trig <- struct{}{}:
		case <-time.After(2 * time.Second):
			t.Fatalf("trigger %d was not consumed", i)
		}
		ops := 1
		if i == 0 || i == 20 || i == 40 {
			ops = 2 // a run just cleared the pending state: both timers are set
		}
		fc.waitOps(t, ops)
		fc.Advance(500 * time.Millisecond)
		if (i+1)%20 == 0 {
			select {
			case <-runs:
			case <-time.After(2 * time.Second):
				t.Fatalf("no analyser run at %s", fc.Now())
			}
		}
	}
	if got := fc.Now().Sub(time.Unix(0, 0)); got != 30*time.Second {
		t.Fatalf("fake clock at %s, want 30s", got)
	}
}
