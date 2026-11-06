package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// scriptedFactory emits the exact events the test hands it, so a test can
// check the envelope tag the emit path stamps on each kind.
var (
	scriptMu sync.Mutex
	scripts  = map[string]chan event.Event{}
)

type scriptedModule struct {
	name string
	in   chan event.Event
}

func (m scriptedModule) Name() string { return m.name }
func (m scriptedModule) Start(ctx context.Context, emit Emit) error {
	for {
		select {
		case e := <-m.in:
			if err := emit(e); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func scriptedFactory(name string) Factory {
	ch := make(chan event.Event, 16)
	scriptMu.Lock()
	scripts[name] = ch
	scriptMu.Unlock()
	return Factory{Name: name, Section: func(*plan.AgentConfig) (string, bool) { return "v1", true },
		Build: func(Env, *plan.AgentConfig) (ModuleSpec, error) {
			return ModuleSpec{Module: scriptedModule{name: name, in: ch}}, nil
		}}
}

// startScripted runs a harness with one scripted emitter and waits until the
// module is running, so a trigger cannot land before its Start loop.
func startScripted(t *testing.T, dir string) (*Harness, context.CancelFunc) {
	t.Helper()
	h, err := NewHarness(HarnessOptions{Host: "h1", StateDir: dir, Factories: []Factory{scriptedFactory("wx")}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go h.Run(ctx)
	h.Apply(&plan.AgentConfig{Host: "h1"})
	eventually(t, 5*time.Second, "module started", func() bool {
		for _, st := range h.a.sup.Snapshot() {
			if st.State == StateRunning {
				return true
			}
		}
		return false
	})
	return h, cancel
}

func mustEvent(t *testing.T, kind string, v any) event.Event {
	t.Helper()
	e, err := event.New(kind, v)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// emitAndLast makes the scripted module emit e and returns the event the
// harness recorded for it, i.e. after the emit path stamped its tag.
func emitAndLast(t *testing.T, h *Harness, name string, e event.Event) event.Event {
	t.Helper()
	before := len(h.Emitted())
	scriptMu.Lock()
	ch := scripts[name]
	scriptMu.Unlock()
	ch <- e
	eventually(t, 5*time.Second, "event emitted", func() bool { return len(h.Emitted()) > before })
	evs := h.Emitted()
	return evs[len(evs)-1]
}

func fileChange(t *testing.T, user string) event.Event {
	t.Helper()
	return mustEvent(t, event.KindFileChange, event.FileChange{Op: "modify", Path: "/etc/httpd/conf/httpd.conf", User: user, Source: "audit"})
}

func workWindowFact(id, tag, user string, from time.Time, d time.Duration) event.ControllerFact {
	return event.ControllerFact{ID: id, Fact: "work_window", TS: from, TTL: time.Hour,
		Data: map[string]any{"window": id, "tag": tag, "user": user, "for": d.String(),
			"until": from.Add(d).UTC().Format(time.RFC3339)}}
}

func TestWorkWindowStampsTag(t *testing.T) {
	h, cancel := startScripted(t, t.TempDir())
	defer cancel()
	now := time.Now()
	mono := time.Duration(0)
	h.setNow(func() time.Time { return now })
	h.setMono(func() time.Duration { return mono })
	h.Fact(workWindowFact("w1", "window:w1", "alice", now, 10*time.Minute))

	if got := emitAndLast(t, h, "wx", fileChange(t, "alice")).Tag; got != "window:w1" {
		t.Fatalf("the claimed user's change: tag %q", got)
	}
	if got := emitAndLast(t, h, "wx", fileChange(t, "mallory")).Tag; got != "" {
		t.Fatalf("another user's change: tag %q", got)
	}
	// Process, authentication, network and honeytoken events are never stamped,
	// even for the claimed user (R6: all red activity is seen).
	proc := mustEvent(t, event.KindProcessStart, event.ProcessStart{PID: 42, Exe: "/bin/sh", User: "alice", Source: "audit"})
	auth := mustEvent(t, event.KindAuthEvent, event.AuthEvent{Result: "success", Account: "alice", Service: "sshd"})
	conn := mustEvent(t, event.KindConn, event.Conn{Op: "opened", Dir: "outbound", Proto: "tcp", User: "alice", Source: "net"})
	honey := event.Event{Kind: "honeytokens.read", Fields: map[string]any{"user": "alice"}}
	for _, e := range []event.Event{proc, auth, conn, honey} {
		if got := emitAndLast(t, h, "wx", e).Tag; got != "" {
			t.Errorf("%s tagged %q", e.Kind, got)
		}
	}
	planTagged := fileChange(t, "alice")
	planTagged.Tag = "plan:p1"
	if got := emitAndLast(t, h, "wx", planTagged).Tag; got != "plan:p1" {
		t.Fatalf("a plan tag must be kept: %q", got)
	}
	mono = 11 * time.Minute
	if got := emitAndLast(t, h, "wx", fileChange(t, "alice")).Tag; got != "" {
		t.Fatalf("after the window ended: tag %q", got)
	}
}

func TestWorkWindowIgnoresWallClock(t *testing.T) {
	h, cancel := startScripted(t, t.TempDir())
	defer cancel()
	now := time.Now()
	mono := time.Duration(0)
	h.setNow(func() time.Time { return now })
	h.setMono(func() time.Duration { return mono })
	h.Fact(workWindowFact("w1", "window:w1", "alice", now, 10*time.Minute))

	for _, skew := range []time.Duration{time.Hour, -time.Hour, 30 * time.Hour} {
		now = time.Now().Add(skew)
		if got := emitAndLast(t, h, "wx", fileChange(t, "alice")).Tag; got != "window:w1" {
			t.Fatalf("wall clock %v ended or extended the window: tag %q", skew, got)
		}
	}
	mono = 10*time.Minute - time.Second
	if got := emitAndLast(t, h, "wx", fileChange(t, "alice")).Tag; got != "window:w1" {
		t.Fatalf("a second before the deadline: tag %q", got)
	}
	mono = 10 * time.Minute
	if got := emitAndLast(t, h, "wx", fileChange(t, "alice")).Tag; got != "" {
		t.Fatalf("the monotonic deadline must end the window: tag %q", got)
	}
}

func TestWorkWindowSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	h1, cancel1 := startScripted(t, dir)
	h1.setMono(func() time.Duration { return 0 })
	h1.Fact(workWindowFact("w1", "window:w1", "alice", time.Now(), 10*time.Minute))
	cancel1()

	h2, cancel2 := startScripted(t, dir)
	defer cancel2()
	h2.setMono(func() time.Duration { return 0 })
	if got := emitAndLast(t, h2, "wx", fileChange(t, "alice")).Tag; got != "window:w1" {
		t.Fatalf("the persisted window must reopen: tag %q", got)
	}
}

func TestWorkWindowEnd(t *testing.T) {
	h, cancel := startScripted(t, t.TempDir())
	defer cancel()
	now := time.Now()
	h.setMono(func() time.Duration { return 0 })
	h.Fact(workWindowFact("w1", "window:w1", "alice", now, 10*time.Minute))
	if got := emitAndLast(t, h, "wx", fileChange(t, "alice")).Tag; got != "window:w1" {
		t.Fatalf("open: tag %q", got)
	}
	h.Fact(event.ControllerFact{ID: "end", Fact: "work_window", TS: now, TTL: time.Hour,
		Data: map[string]any{"window": "w1", "end": true}})
	if got := emitAndLast(t, h, "wx", fileChange(t, "alice")).Tag; got != "" {
		t.Fatalf("end: tag %q", got)
	}
}
