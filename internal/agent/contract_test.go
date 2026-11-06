package agent

import (
	"context"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

type hrMod struct{}

func (hrMod) Name() string                               { return "hr" }
func (hrMod) Start(ctx context.Context, emit Emit) error { <-ctx.Done(); return nil }
func (hrMod) Health() module.Health {
	return module.Health{State: module.StateDegraded, Gaps: []module.Gap{{What: "x", Why: "y"}}, Info: map[string]string{"rules_hash": "abc"}}
}

func TestSupervisorHealthMergesReporter(t *testing.T) {
	t.Skip("unimplemented: W1 Task 13")
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

func TestRegisterFactoryValidatesManifest(t *testing.T) {
	t.Skip("unimplemented: W1 Task 13")
	defer func() {
		if recover() == nil {
			t.Fatal("name mismatch accepted")
		}
	}()
	RegisterFactory(Factory{Name: "zz1", Manifest: module.Manifest{Name: "zz2", Sides: []module.Side{module.SideAgent}, Privilege: "root"},
		Section: func(*plan.AgentConfig) (string, bool) { return "", false }, Build: func(Env, *plan.AgentConfig) (ModuleSpec, error) { return ModuleSpec{}, nil }})
}

func TestSubscribeKindFilter(t *testing.T) {
	t.Skip("unimplemented: W1 Task 13")
	// build a test agent (testutil_test.go); env := agent env for a factory whose Manifest.Consumes = ["k1"]
	// ch, stop := env.Subscribe(8, "k1", "k2")
	// publish events of kind k1, k2, k3
	// want: ch yields exactly one event, kind k1
}
