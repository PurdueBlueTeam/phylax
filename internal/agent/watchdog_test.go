package agent

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestPulseStalled(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	now := t0
	p := NewPulse(func() time.Time { return now }, "heartbeat", "supervisor")
	p.Beat("heartbeat")
	p.Beat("supervisor")
	now = t0.Add(40 * time.Second)
	if got, want := p.Stalled(30*time.Second), []string{"heartbeat", "supervisor"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Stalled = %v, want %v", got, want)
	}
	p.Beat("heartbeat")
	if got, want := p.Stalled(30*time.Second), []string{"supervisor"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after a heartbeat beat: %v, want %v", got, want)
	}
	p.Beat("bogus")
	if got, want := p.Stalled(30*time.Second), []string{"supervisor"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("an unknown source changed the result: %v, want %v", got, want)
	}
	if got := p.Stalled(time.Minute); len(got) != 0 {
		t.Fatalf("within the limit: %v", got)
	}
}

func TestWatchdogStopsNotifyingWhenStalled(t *testing.T) {
	var clockNs atomic.Int64
	clock := func() time.Time { return time.Unix(0, clockNs.Load()) }
	a := &Agent{cfg: Config{HeartbeatInterval: 5 * time.Millisecond}, log: quietLog()}
	a.pulse = NewPulse(clock, "heartbeat", "supervisor", "config")

	notify := make(chan string, 256)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.watchdog(ctx, func(s string) {
		select {
		case notify <- s:
		default:
		}
	})

	// Beating sources: the watchdog notifies on every tick.
	var beating atomic.Bool
	beating.Store(true)
	go func() {
		t := time.NewTicker(time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if beating.Load() {
					a.pulse.Beat("heartbeat")
					a.pulse.Beat("supervisor")
					a.pulse.Beat("config")
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	waitNotify(t, notify)

	// No beats and the clock past the limit: the agent is wedged, so the
	// watchdog says nothing.
	beating.Store(false)
	time.Sleep(20 * time.Millisecond) // let a beat in flight land
	clockNs.Add(int64(time.Second))
	drain(notify)
	select {
	case s := <-notify:
		t.Fatalf("notified while stalled: %q", s)
	case <-time.After(100 * time.Millisecond):
	}

	// Beats resume: so do the notifications.
	beating.Store(true)
	waitNotify(t, notify)
}

func waitNotify(t *testing.T, ch <-chan string) {
	t.Helper()
	select {
	case s := <-ch:
		if s != "WATCHDOG=1" {
			t.Fatalf("notification %q, want WATCHDOG=1", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the watchdog did not notify")
	}
}

func drain(ch <-chan string) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// TestWaitBeatsWhileOffline pins that a controller outage is not a stalled
// agent: the reconnect wait keeps the heartbeat source beating, so systemd does
// not restart a healthy agent that is merely offline.
func TestWaitBeatsWhileOffline(t *testing.T) {
	const hb = 50 * time.Millisecond
	a := &Agent{cfg: Config{HeartbeatInterval: hb}, log: quietLog()}
	a.pulse = NewPulse(time.Now, "heartbeat")
	done := make(chan bool, 1)
	go func() { done <- a.wait(context.Background(), 8*hb) }()
	for i := 0; i < 8; i++ {
		time.Sleep(hb)
		if s := a.pulse.Stalled(3 * hb); len(s) != 0 {
			t.Fatalf("the reconnect wait stalls %v", s)
		}
	}
	if ok := <-done; !ok {
		t.Fatal("wait ended early")
	}
}
