package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

type hugeHealthMod struct{}

func (hugeHealthMod) Name() string                               { return "huge" }
func (hugeHealthMod) Start(ctx context.Context, emit Emit) error { <-ctx.Done(); return nil }
func (hugeHealthMod) Health() module.Health {
	gaps := make([]module.Gap, 100)
	for i := range gaps {
		gaps[i] = module.Gap{What: "gap", Why: "why"}
	}
	return module.Health{
		State:  module.StateDegraded,
		Detail: strings.Repeat("d", 2*link.MaxHealthDetail),
		Gaps:   gaps,
		Info:   map[string]string{strings.Repeat("k", 300): strings.Repeat("v", 300)},
	}
}

type hrMod struct{}

func (hrMod) Name() string                               { return "hr" }
func (hrMod) Start(ctx context.Context, emit Emit) error { <-ctx.Done(); return nil }
func (hrMod) Health() module.Health {
	return module.Health{State: module.StateDegraded, Gaps: []module.Gap{{What: "x", Why: "y"}}, Info: map[string]string{"rules_hash": "abc"}}
}

func TestSupervisorHealthMergesReporter(t *testing.T) {
	s := NewSupervisor(SupervisorOptions{Emit: func(event.Event) error { return nil }})
	_ = s.Add(ModuleSpec{Module: hrMod{}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h, ok := s.Health("hr"); ok && h.State == module.StateDegraded {
			if h.Info["rules_hash"] != "abc" || len(h.Gaps) != 1 {
				t.Fatalf("%+v", h)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("health never reported")
}

func TestHeartbeatHealthClampedToWireLimits(t *testing.T) {
	s := NewSupervisor(SupervisorOptions{Emit: func(event.Event) error { return nil }})
	if err := s.Add(ModuleSpec{Module: hugeHealthMod{}}); err != nil {
		t.Fatal(err)
	}
	a := &Agent{sup: s}
	hb := &link.Heartbeat{HostClock: time.Now(), Health: a.heartbeatHealth()}
	if err := hb.Validate(); err != nil {
		t.Fatalf("clamped health does not validate: %v", err)
	}
	h := hb.Health["huge"]
	if len(h.Gaps) != link.MaxHealthGaps || h.Gaps[len(h.Gaps)-1].What != "truncated" {
		t.Fatalf("truncation not marked: %+v", h.Gaps)
	}
	if len(h.Detail) > link.MaxHealthDetail || len(h.Info) != 1 {
		t.Fatalf("health not clamped: %d detail, %d info", len(h.Detail), len(h.Info))
	}
	for k, v := range h.Info {
		if len(k) > link.MaxHealthInfoKey || len(v) > link.MaxHealthInfoValue {
			t.Fatalf("info not clamped: %d/%d", len(k), len(v))
		}
	}
}

func TestRegisterFactoryValidatesManifest(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("name mismatch accepted")
		}
	}()
	RegisterFactory(Factory{Name: "zz1", Manifest: module.Manifest{Name: "zz2", Sides: []module.Side{module.SideAgent}, Privilege: "root"},
		Section: func(*plan.AgentConfig) (string, bool) { return "", false }, Build: func(Env, *plan.AgentConfig) (ModuleSpec, error) { return ModuleSpec{}, nil }})
}

func TestSubscribeKindFilter(t *testing.T) {
	ctl := newFakeController(t, "h", "tok", 0)
	l := Layout{Root: t.TempDir()}
	writeBundle(t, l, ctl, "tok")
	envc := make(chan Env, 1)
	f := Factory{Name: "sub", Manifest: module.Manifest{Name: "sub", Sides: []module.Side{module.SideAgent},
		Privilege: "user", Consumes: []string{"k1"}},
		Section: func(*plan.AgentConfig) (string, bool) { return "v1", true },
		Build: func(env Env, _ *plan.AgentConfig) (ModuleSpec, error) {
			envc <- env
			return ModuleSpec{Module: funcModule{"sub", func(ctx context.Context, _ Emit) error { <-ctx.Done(); return nil }}}, nil
		}}
	r := startAgent(t, Config{Layout: l, HeartbeatInterval: 20 * time.Millisecond, Factories: []Factory{f}})
	eventually(t, 5*time.Second, "connected", func() bool { return ctl.send(&link.Ack{}) == nil })
	r.a.reconcile(context.Background(), &plan.AgentConfig{Host: "h"})
	var env Env
	select {
	case env = <-envc:
	case <-time.After(2 * time.Second):
		t.Fatal("factory was not built")
	}
	ch, stop := env.Subscribe(8, "k1", "k2")
	defer stop()
	r.a.publish(event.Event{Kind: "k1"})
	r.a.publish(event.Event{Kind: "k2"})
	r.a.publish(event.Event{Kind: "k3"})
	select {
	case e := <-ch:
		if e.Kind != "k1" {
			t.Fatalf("got %s, want k1", e.Kind)
		}
	case <-time.After(time.Second):
		t.Fatal("no k1 event")
	}
	select {
	case e := <-ch:
		t.Fatalf("unexpected %s", e.Kind)
	case <-time.After(100 * time.Millisecond):
	}
}
