package vantage

import (
	"context"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

func TestAllowlist(t *testing.T) {
	a, err := ParseAllowlist("172.25.21.0/24", "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"172.25.21.10": true, "172.25.21.255": true, "172.25.22.10": false, "10.0.0.5": true, "10.0.0.6": false,
		"example.com": false, "": false, "::ffff:172.25.21.9": true, "172.25.2.1": false,
	} {
		if got := a.Allows(host); got != want {
			t.Errorf("Allows(%q) = %v, want %v", host, got, want)
		}
	}
	if _, err := ParseAllowlist("nonsense"); err == nil {
		t.Error("bad entry accepted")
	}
}

func TestLimiterPacesAtRate(t *testing.T) {
	fc := newFakeClock()
	l := newLimiter(10, 3, fc.clock())
	start := fc.Now()
	for range 53 {
		if !l.Wait(context.Background()) {
			t.Fatal("wait failed")
		}
	}
	// 53 tokens at 10/s with a burst of 3: the last starts at (53-3)/10 = 5s.
	if el := fc.Now().Sub(start); el < 4900*time.Millisecond || el > 5100*time.Millisecond {
		t.Fatalf("elapsed %v", el)
	}
	// idle time does not bank more than the burst
	fc.Sleep(context.Background(), time.Hour)
	before := fc.total()
	for range 3 {
		l.Wait(context.Background())
	}
	if fc.total() != before {
		t.Errorf("the burst should be immediate")
	}
	l.Wait(context.Background())
	if fc.total()-before < 90*time.Millisecond {
		t.Errorf("the 4th token must wait ~100ms, waited %v", fc.total()-before)
	}
	if !newLimiter(0, 1, fc.clock()).tryNow() {
		t.Error("a zero-rate limiter is unlimited")
	}
}

type fakeGate struct {
	clk     *fakeClock
	opensAt time.Time
	calls   int
	needs   []time.Duration
}

func (g *fakeGate) SafeFor(now time.Time, need time.Duration) scorer.Window {
	g.calls++
	g.needs = append(g.needs, need)
	if now.Before(g.opensAt) {
		return scorer.Window{Safe: false, NextOpens: g.opensAt}
	}
	return scorer.Window{Safe: true, Start: g.opensAt, Remaining: time.Minute}
}

func TestWaitSafeAlignsToWindow(t *testing.T) {
	fc := newFakeClock()
	g := &fakeGate{clk: fc, opensAt: fc.Now().Add(3 * time.Second)}
	if !waitSafe(context.Background(), g, fc.clock(), 5*time.Second, time.Minute) {
		t.Fatal("never became safe")
	}
	if fc.Now().Before(g.opensAt) {
		t.Fatal("proceeded before the window opened")
	}
	for _, n := range g.needs {
		if n != 5*time.Second {
			t.Fatalf("asked for %v", n)
		}
	}
	// gives up after maxWait
	g2 := &fakeGate{clk: fc, opensAt: fc.Now().Add(time.Hour)}
	if waitSafe(context.Background(), g2, fc.clock(), time.Second, 2*time.Second) {
		t.Fatal("should give up")
	}
	// nil gate: always safe
	if !waitSafe(context.Background(), nil, fc.clock(), time.Second, time.Second) {
		t.Fatal("nil gate")
	}
}
