package agent

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/spool"
)

func TestEnrollmentHeartbeatsAndPlaceholders(t *testing.T) {
	ctl := newFakeController(t, "ubuntu-ecom", "tok-1", 0)
	ctl.sendOnWelcome = []link.Message{
		&link.Step{Plan: "p1", Node: "n1", Host: "ubuntu-ecom", Epoch: 1, Seq: 7, Action: "user.lock", Sig: "x"},
		&link.Config{Version: 3, Epoch: 1, Body: json.RawMessage(`{}`), Sig: "x"},
		&link.Control{Kind: "safe_mode", On: true},
	}
	l := Layout{Root: t.TempDir()}
	writeBundle(t, l, ctl, "tok-1")
	r := startAgent(t, Config{Layout: l, Version: "9.9", HeartbeatInterval: 50 * time.Millisecond,
		Modules: []ModuleSpec{{Module: funcModule{"gen", func(ctx context.Context, emit Emit) error {
			emit(event.Event{Kind: "test.hello", Priority: event.PriorityHigh, Fields: map[string]any{"a": 1.0}})
			<-ctx.Done()
			return nil
		}}}}})

	eventually(t, 5*time.Second, "events+heartbeats+step result", func() bool {
		evs, _, hbs := ctl.snapshot()
		ctl.mu.Lock()
		defer ctl.mu.Unlock()
		kinds := map[string]bool{}
		for _, e := range evs {
			kinds[e.Kind] = true
		}
		sm := false
		for _, h := range hbs {
			sm = sm || h.SafeMode
		}
		return kinds["test.hello"] && kinds["agent.health"] && kinds["agent.config_rejected"] &&
			len(hbs) >= 3 && sm && len(ctl.results) == 1
	})
	evs, hellos, hbs := ctl.snapshot()
	if hellos[0].Token != "tok-1" || hellos[0].Host != "ubuntu-ecom" || hellos[0].Version != "9.9" || hellos[0].Roles[0] != "capture" {
		t.Fatalf("hello: %+v", hellos[0])
	}
	if hbs[0].HostClock.IsZero() || hbs[0].Modules["health"] != StateRunning {
		t.Fatalf("heartbeat: %+v", hbs[0])
	}
	ctl.mu.Lock()
	res := ctl.results[0]
	ctl.mu.Unlock()
	if res.Status != "rejected" || res.Plan != "p1" || res.Seq != 7 || res.Phase != "check" {
		t.Fatalf("step result: %+v", res)
	}
	// hash chain intact end to end
	for i, e := range evs {
		if e.Seq != uint64(i+1) {
			t.Fatalf("event %d has seq %d", i, e.Seq)
		}
	}
	// enrollment persisted after welcome, token scrubbed
	eventually(t, 2*time.Second, "enrolled state", func() bool {
		st, _ := l.LoadState()
		b, err := l.LoadBundle()
		return st.Enrolled && err == nil && b.Token == ""
	})
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(l.Identity())
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("identity mode: %v %v", fi, err)
		}
	}
	r.stop()
	// A later start must not present the token again and keeps its identity.
	pin := r.a.Pin()
	r2 := startAgent(t, Config{Layout: l, Version: "9.9"})
	if r2.a.Pin() != pin {
		t.Fatal("identity changed across restarts")
	}
	eventually(t, 5*time.Second, "second hello", func() bool { _, h, _ := ctl.snapshot(); return len(h) >= 2 })
	_, hellos, _ = ctl.snapshot()
	if hellos[1].Token != "" || hellos[1].LastSeq == 0 {
		t.Fatalf("second hello: %+v", hellos[1])
	}
}

func TestWrongPinNeverEnrolls(t *testing.T) {
	ctl := newFakeController(t, "h", "tok", 0)
	l := Layout{Root: t.TempDir()}
	other, _ := link.GenerateIdentity("x")
	l.SaveBundle(&Bundle{Controllers: []string{ctl.addr}, ControllerPin: other.Pin.String(), Host: "h", Token: "tok"})
	startAgent(t, Config{Layout: l})
	time.Sleep(300 * time.Millisecond)
	if _, h, _ := ctl.snapshot(); len(h) != 0 {
		t.Fatal("hello (and token) sent to a controller with the wrong pin")
	}
}

func seed(t *testing.T, l Layout, host string, n int) {
	t.Helper()
	sp, err := spool.Open(l.SpoolDir(), spool.Options{Agent: host})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := sp.Append(event.Event{Kind: "seed", Priority: event.PriorityNormal, Fields: map[string]any{"i": float64(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	sp.Close()
}

func TestResumeFromControllerAck(t *testing.T) {
	ctl := newFakeController(t, "h", "", 6) // controller already holds 1..6
	l := Layout{Root: t.TempDir()}
	writeBundle(t, l, ctl, "")
	l.SaveState(State{Enrolled: true})
	seed(t, l, "h", 10)
	startAgent(t, Config{Layout: l})
	eventually(t, 5*time.Second, "events 7..10", func() bool {
		evs, _, _ := ctl.snapshot()
		n := 0
		for _, e := range evs {
			if e.Kind == "seed" {
				n++
			}
		}
		return n == 4
	})
	evs, hellos, _ := ctl.snapshot()
	if evs[0].Seq != 7 || hellos[0].LastSeq < 10 {
		t.Fatalf("first resent seq %d, hello %+v", evs[0].Seq, hellos[0])
	}
}

func TestReconnectAfterServerRestartLosesNothing(t *testing.T) {
	ctl := newFakeController(t, "h", "", 0)
	l := Layout{Root: t.TempDir()}
	writeBundle(t, l, ctl, "")
	l.SaveState(State{Enrolled: true})
	const total = 600
	startAgent(t, Config{Layout: l, HeartbeatInterval: 50 * time.Millisecond,
		Modules: []ModuleSpec{{Module: funcModule{"gen", func(ctx context.Context, emit Emit) error {
			for i := 0; i < total; i++ {
				if err := emit(event.Event{Kind: "gen", Priority: event.PriorityNormal, Fields: map[string]any{"i": float64(i)}}); err != nil {
					return err
				}
				time.Sleep(2 * time.Millisecond)
			}
			<-ctx.Done()
			return nil
		}}}}})
	eventually(t, 5*time.Second, "some events", func() bool { e, _, _ := ctl.snapshot(); return len(e) > 50 })
	ctl.restart()
	eventually(t, 15*time.Second, "all events", func() bool {
		evs, _, _ := ctl.snapshot()
		n := 0
		for _, e := range evs {
			if e.Kind == "gen" {
				n++
			}
		}
		return n == total
	})
	evs, hellos, _ := ctl.snapshot()
	if len(hellos) < 2 {
		t.Fatalf("expected a reconnect, hellos=%d", len(hellos))
	}
	seen := map[uint64]bool{}
	gen := 0
	for _, e := range evs {
		if seen[e.Seq] {
			t.Fatalf("duplicate seq %d", e.Seq)
		}
		seen[e.Seq] = true
		if e.Kind == "gen" {
			if int(e.Fields["i"].(float64)) != gen {
				t.Fatalf("gen events out of order or missing at %d", gen)
			}
			gen++
		}
	}
}

func TestSensorsNeverBlockWhenLinkDown(t *testing.T) {
	l := Layout{Root: t.TempDir()}
	l.SaveBundle(&Bundle{Controllers: []string{"127.0.0.1:1"}, ControllerPin: link.Pin{}.String(), Host: "h"})
	took := make(chan time.Duration, 1)
	r := startAgent(t, Config{Layout: l, Modules: []ModuleSpec{{Module: funcModule{"gen", func(ctx context.Context, emit Emit) error {
		st := time.Now()
		for i := 0; i < 2000; i++ {
			emit(event.Event{Kind: "x", Priority: event.PriorityNormal})
		}
		took <- time.Since(st)
		<-ctx.Done()
		return nil
	}}}}})
	select {
	case d := <-took:
		if d > 5*time.Second {
			t.Fatalf("emit blocked: %v", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("module blocked")
	}
	if h, _ := r.a.sp.Head(); h < 2000 {
		t.Fatalf("head %d", h)
	}
	if r.a.Link().Connected {
		t.Fatal("claims connected")
	}
}

func TestDeadmanRecoverAtStart(t *testing.T) {
	l := Layout{Root: t.TempDir()}
	ctl := newFakeController(t, "h", "", 0)
	writeBundle(t, l, ctl, "")
	l.SaveState(State{Enrolled: true})
	called := make(chan string, 4)
	h := func(_ context.Context, e deadman.Entry) error { called <- e.ID; return nil }
	m, err := deadman.Open(l.DeadmanDir(), deadman.Options{Handlers: map[string]deadman.Handler{"t": h}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Arm(context.Background(), deadman.ArmRequest{ID: "n1", Kind: "t", Timeout: 20 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	m.Close() // agent "crashes" with the entry armed
	time.Sleep(40 * time.Millisecond)
	startAgent(t, Config{Layout: l, DeadmanHandlers: map[string]deadman.Handler{"t": h}})
	select {
	case id := <-called:
		if id != "n1" {
			t.Fatal(id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expired entry not rolled back at start")
	}
	eventually(t, 5*time.Second, "recovered event", func() bool {
		evs, _, _ := ctl.snapshot()
		for _, e := range evs {
			if e.Kind == "agent.deadman_recovered" {
				return true
			}
		}
		return false
	})
}
