package conformance

import (
	"context"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// AgentCase is one agent module under test.
type AgentCase struct {
	Factory  agent.Factory
	Default  *plan.AgentConfig // the module's default block on a fixture host
	Reconfig *plan.AgentConfig // a changed block (check 8)
	KeepKey  string            // key the module stores with Env.Keep; "" when it keeps nothing
	Load     []event.Event     // consumed events fed on the bus (checks 6 and 7)
	Block    any               // pointer to a zero settings struct (check 9); nil: plan.BlockFor(Default, Factory.Name)
}

// Agent runs the agent-side conformance checks.
func Agent(t *testing.T, c AgentCase) {
	t.Helper()
	errs := runAgentChecks(c)
	names := make([]string, 0, len(errs))
	for name := range errs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		err := errs[name]
		t.Run(name, func(t *testing.T) {
			if err != nil {
				t.Error(err)
			}
		})
	}
}

// runAgentChecks returns one error per named check. A check panicking is a
// failure of that check, not of the suite.
func runAgentChecks(c AgentCase) map[string]error {
	checks := []struct {
		name string
		fn   func(AgentCase) error
	}{
		{"no_config", checkNoConfig},
		{"default_config", checkDefaultConfig},
		{"stops_cleanly", checkStopsCleanly},
	}
	errs := make(map[string]error, len(checks))
	for _, ch := range checks {
		errs[ch.name] = safeCheck(ch.name, c, ch.fn)
	}
	return errs
}

// safeCheck turns a panic out of a check into that check's error.
func safeCheck(name string, c AgentCase, fn func(AgentCase) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s: panic: %v", c.Factory.Name, r)
		}
	}()
	return fn(c)
}

// newHarness builds a real harness for one check, with a fresh state dir. The
// returned cleanup removes the state dir.
func newHarness(c AgentCase, emitErr func() error) (*agent.Harness, func(), error) {
	host := "h1"
	if c.Default != nil && c.Default.Host != "" {
		host = c.Default.Host
	}
	dir, err := os.MkdirTemp("", "phylax-conformance-*")
	if err != nil {
		return nil, nil, err
	}
	h, err := agent.NewHarness(agent.HarnessOptions{
		Host:      host,
		StateDir:  dir,
		Factories: []agent.Factory{c.Factory},
		EmitErr:   emitErr,
	})
	if err != nil {
		os.RemoveAll(dir)
		return nil, nil, err
	}
	return h, func() { os.RemoveAll(dir) }, nil
}

// waitFor polls a module's health until ok reports true or d elapses.
func waitFor(h *agent.Harness, name string, d time.Duration, ok func(module.Health, bool) bool) (module.Health, bool) {
	deadline := time.Now().Add(d)
	for {
		hl, present := h.Health(name)
		if ok(hl, present) {
			return hl, true
		}
		if time.Now().After(deadline) {
			return hl, false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func running(hl module.Health, present bool) bool { return present && hl.State == module.StateOK }

// checkNoConfig is check 1: a module without its config block is disabled or
// refuses to build; it never panics and never runs.
func checkNoConfig(c AgentCase) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s: panic with an empty config: %v", c.Factory.Name, r)
		}
	}()
	if _, on := c.Factory.Section(&plan.AgentConfig{}); !on {
		return nil
	}
	h, cleanup, herr := newHarness(c, nil)
	if herr != nil {
		return herr
	}
	defer cleanup()
	h.Apply(&plan.AgentConfig{})
	hl, present := h.Health(c.Factory.Name)
	if present && hl.State == module.StateUnavailable {
		return nil
	}
	return fmt.Errorf("%s: runs with no config block (health %+v, present %v); Section must report disabled or Build must return agent.ErrUnavailable",
		c.Factory.Name, hl, present)
}

// checkDefaultConfig is check 2: with the module's default block, health
// reaches ok (or unavailable when the host cannot run it) within 10 s.
func checkDefaultConfig(c AgentCase) error {
	h, cleanup, err := newHarness(c, nil)
	if err != nil {
		return err
	}
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	h.Apply(c.Default)
	hl, ok := waitFor(h, c.Factory.Name, 10*time.Second, func(hl module.Health, present bool) bool {
		return present && (hl.State == module.StateOK || hl.State == module.StateUnavailable)
	})
	if !ok {
		return fmt.Errorf("%s: health did not reach ok or unavailable within 10s: %+v", c.Factory.Name, hl)
	}
	return nil
}

// agentSettle lets a just-started module reach its first statement before a
// check cancels its context; a module reporting ok while still starting would
// otherwise race the stop check.
const agentSettle = 100 * time.Millisecond

// checkStopsCleanly is check 3: after cancel, Run returns within 5 s and the
// goroutine set returns to the pre-start set within 1 s.
func checkStopsCleanly(c AgentCase) error {
	h, cleanup, err := newHarness(c, nil)
	if err != nil {
		return err
	}
	defer cleanup()
	before := goroutineKeys()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.Run(ctx)
		close(done)
	}()
	h.Apply(c.Default)
	waitFor(h, c.Factory.Name, 5*time.Second, running)
	time.Sleep(agentSettle)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("%s: Run did not return within 5s of cancel", c.Factory.Name)
	}
	deadline := time.Now().Add(time.Second)
	for {
		extra := extraGoroutines(before, goroutineKeys())
		if len(extra) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s: goroutines still running after stop: %v", c.Factory.Name, extra)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
