package vantage

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// sink collects emitted events.
type sink struct {
	mu sync.Mutex
	ev []event.Event
}

func (s *sink) emit(e event.Event) error {
	s.mu.Lock()
	s.ev = append(s.ev, e)
	s.mu.Unlock()
	return nil
}

func (s *sink) all() []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Event(nil), s.ev...)
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

func eventually(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// fakeClock advances only when slept on.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	sleeps []time.Duration
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (f *fakeClock) Now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.t }
func (f *fakeClock) Sleep(ctx context.Context, d time.Duration) bool {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.sleeps = append(f.sleeps, d)
	f.mu.Unlock()
	return ctx.Err() == nil
}
func (f *fakeClock) total() (s time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range f.sleeps {
		s += d
	}
	return
}
func (f *fakeClock) clock() clock { return clock{Now: f.Now, Sleep: f.Sleep} }
