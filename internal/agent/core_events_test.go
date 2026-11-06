package agent

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// crashFactory fails its first run and then idles, so the supervisor reports
// exactly one agent.module_crash.
type crashFactory struct {
	runs atomic.Int32
}

func (c *crashFactory) factory() Factory {
	return Factory{
		Name: "crash",
		Section: func(cfg *plan.AgentConfig) (string, bool) {
			if cfg.Modules.Net == nil {
				return "", false
			}
			return "on", true
		},
		Build: func(env Env, cfg *plan.AgentConfig) (ModuleSpec, error) {
			return ModuleSpec{Module: funcModule{"crash", func(ctx context.Context, emit Emit) error {
				if c.runs.Add(1) == 1 {
					return errors.New("test crash")
				}
				<-ctx.Done()
				return nil
			}}}, nil
		},
	}
}

// TestAgentCoreEventsValidate drives the agent through each core event it
// emits and checks that every event of a declared kind validates against the
// declared schema, whether it was read off the bus or out of the spool.
func TestAgentCoreEventsValidate(t *testing.T) {
	env := newCfgEnv(t)
	crash := &crashFactory{}
	r := startAgent(t, Config{Layout: env.l, HeartbeatInterval: 20 * time.Millisecond,
		HealthInterval: 20 * time.Millisecond, Factories: []Factory{crash.factory()}})

	bus, unsub := r.a.subscribe(4096)
	var mu sync.Mutex
	var published []event.Event
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case e := <-bus:
				mu.Lock()
				published = append(published, e)
				mu.Unlock()
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() { close(stop); unsub() })

	// A signed config starts the crashing module; an unsigned control is
	// refused; the health module reports on its interval.
	eventually(t, 5*time.Second, "connected", func() bool { return env.ctl.send(&link.Ack{}) == nil })
	if err := env.ctl.send(env.sign(t, cfgBody("h", 1, 1, "web"))); err != nil {
		t.Fatal(err)
	}
	env.waitConfig(t, "ok/1.1")
	if err := env.ctl.send(&link.Control{V: 1, Host: "h", Kind: "safe_mode", On: true, Epoch: 1, Seq: 1,
		NotBefore: 1, NotAfter: 2, Sig: []byte("unsigned-garbage")}); err != nil {
		t.Fatal(err)
	}

	want := []string{"agent.start", "agent.config_applied", "agent.control_refused", "agent.module_crash", "agent.health"}
	eventually(t, 5*time.Second, "core events", func() bool {
		evs, _, _ := env.ctl.snapshot()
		seen := map[string]bool{}
		for _, e := range evs {
			seen[e.Kind] = true
		}
		for _, k := range want {
			if !seen[k] {
				return false
			}
		}
		return true
	})

	mu.Lock()
	busEvents := append([]event.Event(nil), published...)
	mu.Unlock()
	evs, _, _ := env.ctl.snapshot()
	seen := map[string]bool{}
	for _, e := range append(busEvents, evs...) {
		seen[e.Kind] = true
		if _, ok := event.Lookup(e.Kind); !ok {
			continue // a test module's own undeclared kind
		}
		if err := event.Validate(e); err != nil {
			t.Errorf("%s (seq %d) does not validate: %v", e.Kind, e.Seq, err)
		}
	}
	for _, k := range want {
		if !seen[k] {
			t.Errorf("no %s event seen", k)
		}
	}
}
