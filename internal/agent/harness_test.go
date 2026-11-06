package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func harnessFactory(build func(Env, *plan.AgentConfig) (ModuleSpec, error)) Factory {
	return Factory{Name: "hx", Section: func(*plan.AgentConfig) (string, bool) { return "v1", true }, Build: build}
}

type oneShot struct{}

func (oneShot) Name() string { return "hx" }
func (oneShot) Start(ctx context.Context, emit Emit) error {
	_ = emit(event.Event{Kind: "hx.x"})
	<-ctx.Done()
	return nil
}

type emitOnce struct{ got chan error }

func (emitOnce) Name() string { return "hx" }
func (e emitOnce) Start(ctx context.Context, emit Emit) error {
	e.got <- emit(event.Event{Kind: "hx.x"})
	<-ctx.Done()
	return nil
}

var (
	testSubsMu sync.Mutex
	testSubs   = map[string]chan event.Event{}
)

func subscriberFactory(name string, kinds []string) Factory {
	ch := make(chan event.Event, 16)
	testSubsMu.Lock()
	testSubs[name] = ch
	testSubsMu.Unlock()
	return Factory{Name: name, Section: func(*plan.AgentConfig) (string, bool) { return "v1", true },
		Build: func(env Env, _ *plan.AgentConfig) (ModuleSpec, error) {
			return ModuleSpec{Module: subMod{name: name, kinds: kinds, out: ch}, Subscriber: true}, nil
		}}
}

func testSubscriber(name string) <-chan event.Event {
	testSubsMu.Lock()
	defer testSubsMu.Unlock()
	return testSubs[name]
}

type subMod struct {
	name  string
	kinds []string
	out   chan event.Event
}

func (m subMod) Name() string { return m.name }
func (m subMod) Start(ctx context.Context, _ Emit) error {
	// The real Env is not reachable here; the harness wires the bus in Task 15/31.
	<-ctx.Done()
	return nil
}

var (
	emitTrigMu sync.Mutex
	emitTrig   = map[string]chan struct{}{}
)

func emitterFactory(name string) Factory {
	ch := make(chan struct{}, 16)
	emitTrigMu.Lock()
	emitTrig[name] = ch
	emitTrigMu.Unlock()
	return Factory{Name: name, Section: func(*plan.AgentConfig) (string, bool) { return "v1", true },
		Build: func(Env, *plan.AgentConfig) (ModuleSpec, error) {
			return ModuleSpec{Module: emitMod{name: name, trig: ch}}, nil
		}}
}

func triggerEmit(name string) {
	emitTrigMu.Lock()
	ch := emitTrig[name]
	emitTrigMu.Unlock()
	ch <- struct{}{}
}

type emitMod struct {
	name string
	trig chan struct{}
}

func (m emitMod) Name() string { return m.name }
func (m emitMod) Start(ctx context.Context, emit Emit) error {
	for {
		select {
		case <-m.trig:
			_ = emit(event.Event{Kind: m.name + ".e"})
		case <-ctx.Done():
			return nil
		}
	}
}

func TestHarnessRunsFactory(t *testing.T) {
	t.Skip("unimplemented: W1 Task 15")
	h, err := NewHarness(HarnessOptions{Host: "h1", StateDir: t.TempDir(), Factories: []Factory{harnessFactory(func(Env, *plan.AgentConfig) (ModuleSpec, error) {
		return ModuleSpec{Module: oneShot{}}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	h.Apply(&plan.AgentConfig{Host: "h1"})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.Emitted()) == 1 && h.Emitted()[0].Kind == "hx.x" {
			if hl, ok := h.Health("hx"); ok && hl.State == module.StateOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("emitted %v", h.Emitted())
}

func TestHarnessUnavailable(t *testing.T) {
	t.Skip("unimplemented: W1 Task 15")
	h, _ := NewHarness(HarnessOptions{Host: "h1", StateDir: t.TempDir(), Factories: []Factory{harnessFactory(func(Env, *plan.AgentConfig) (ModuleSpec, error) {
		return ModuleSpec{}, fmt.Errorf("%w: needs linux", ErrUnavailable)
	})}})
	h.Apply(&plan.AgentConfig{Host: "h1"})
	hl, ok := h.Health("hx")
	if !ok || hl.State != module.StateUnavailable || len(hl.Gaps) != 1 {
		t.Fatalf("%+v %v", hl, ok)
	}
}

func TestHarnessEmitErr(t *testing.T) {
	t.Skip("unimplemented: W1 Task 15")
	got := make(chan error, 1)
	h, _ := NewHarness(HarnessOptions{Host: "h1", StateDir: t.TempDir(), EmitErr: func() error { return errors.New("link down") },
		Factories: []Factory{harnessFactory(func(Env, *plan.AgentConfig) (ModuleSpec, error) {
			return ModuleSpec{Module: emitOnce{got}}, nil
		})}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	h.Apply(&plan.AgentConfig{Host: "h1"})
	select {
	case err := <-got:
		if err == nil {
			t.Fatal("emit error not returned")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no emit")
	}
}
