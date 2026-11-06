package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// moduleRunState is one controller module's runner state.
type moduleRunState struct {
	mod     module.ControllerModule
	mu      sync.Mutex
	state   module.State
	detail  string
	gaps    []module.Gap
	aGaps   map[string]module.Gap
	running bool
	done    chan struct{}
}

// moduleStableAfter is how long a module must run before its restart backoff
// resets (the agent supervisor's number).
const moduleStableAfter = 30 * time.Second

func (st *moduleRunState) markRunning() {
	st.mu.Lock()
	st.state, st.detail, st.gaps, st.running = "", "", nil, true
	st.mu.Unlock()
}

func (st *moduleRunState) markState(state module.State, detail string, gaps ...module.Gap) {
	st.mu.Lock()
	st.state, st.detail, st.gaps, st.running = state, detail, append([]module.Gap(nil), gaps...), false
	st.mu.Unlock()
}

func (c *Controller) setModuleRunning(name string, running bool) {
	c.runMu.Lock()
	if c.running == nil {
		c.running = map[string]bool{}
	}
	c.running[name] = running
	c.runMu.Unlock()
}

func (c *Controller) markRunning(st *moduleRunState) {
	st.markRunning()
	c.setModuleRunning(st.mod.Manifest().Name, true)
}

func (c *Controller) markState(st *moduleRunState, state module.State, detail string, gaps ...module.Gap) {
	st.markState(state, detail, gaps...)
	c.setModuleRunning(st.mod.Manifest().Name, false)
}

// RunModules runs every enabled controller module until ctx ends.
func (c *Controller) RunModules(ctx context.Context, mods []module.ControllerModule) error {
	man, err := c.currentManifest()
	if err != nil {
		c.log.Warn("module runner has no manifest; using each module's default", "err", err)
	}
	host := ""
	if man != nil {
		host = man.ControllerHost()
	}
	states := make([]*moduleRunState, 0, len(mods))
	for _, m := range mods {
		name := m.Manifest().Name
		st := &moduleRunState{mod: m, done: make(chan struct{})}
		c.modMu.Lock()
		if c.mods == nil {
			c.mods = map[string]*moduleRunState{}
		}
		c.mods[name] = st
		c.modMu.Unlock()
		states = append(states, st)

		enabled := m.Manifest().Default
		if man != nil {
			enabled = man.ModuleEnabled(host, name, enabled)
		}
		if !enabled {
			st.markState(module.StateDisabled, "")
			close(st.done)
			continue
		}
		go c.runModule(ctx, m, st)
	}
	<-ctx.Done()
	for _, st := range states {
		select {
		case <-st.done:
		case <-time.After(5 * time.Second):
			c.log.Error("module did not exit within 5s; abandoning it", "module", st.mod.Manifest().Name)
		}
	}
	return nil
}

// runModule supervises one module (and its analysers) until ctx ends.
func (c *Controller) runModule(ctx context.Context, m module.ControllerModule, st *moduleRunState) {
	defer close(st.done)
	mctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var awg sync.WaitGroup
	if ap, ok := m.(module.AnalyzerProvider); ok {
		if as := ap.Analyzers(); len(as) > 0 {
			awg.Add(1)
			go func() {
				defer awg.Done()
				c.runAnalyzers(mctx, m, st, as)
			}()
		}
	}
	c.superviseModule(mctx, m, st)
	cancel()
	awg.Wait()
}

func (c *Controller) superviseModule(ctx context.Context, m module.ControllerModule, st *moduleRunState) {
	name := m.Manifest().Name
	bo := link.Backoff{Min: c.modBackoffMin, Max: time.Minute}
	if bo.Min <= 0 {
		bo.Min = time.Second
	}
	h := c.hostFor(m)
	for {
		if ctx.Err() != nil {
			c.markState(st, module.StateUnavailable, "stopped")
			return
		}
		c.markRunning(st)
		start := time.Now()
		err := startModule(ctx, m, h)
		h.stopSubscriptions()
		if ctx.Err() != nil {
			c.markState(st, module.StateUnavailable, "stopped")
			return
		}
		if errors.Is(err, module.ErrNoConfig) {
			c.markState(st, module.StateUnavailable, "no config block",
				module.Gap{What: "config", Why: "modules/" + name + ".yml missing"})
			return
		}
		if time.Since(start) >= moduleStableAfter {
			bo.Reset()
		}
		detail := "stopped"
		if err != nil {
			detail = err.Error()
		}
		c.markState(st, module.StateRestarting, detail)
		select {
		case <-ctx.Done():
			c.markState(st, module.StateUnavailable, "stopped")
			return
		case <-time.After(bo.Next()):
		}
	}
}

// startModule runs one Start call, turning a panic into an error so the runner
// can restart the module.
func startModule(ctx context.Context, m module.ControllerModule, h module.Host) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return m.Start(ctx, h)
}

// ModuleHealth returns controller-module health by name.
func (c *Controller) ModuleHealth() map[string]module.Health {
	c.modMu.Lock()
	states := make(map[string]*moduleRunState, len(c.mods))
	for n, st := range c.mods {
		states[n] = st
	}
	c.modMu.Unlock()
	out := make(map[string]module.Health, len(states))
	for name, st := range states {
		st.mu.Lock()
		state, detail := st.state, st.detail
		gaps := append([]module.Gap(nil), st.gaps...)
		names := make([]string, 0, len(st.aGaps))
		for n := range st.aGaps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			gaps = append(gaps, st.aGaps[n])
		}
		st.mu.Unlock()
		var h module.Health
		if state != "" {
			h = module.Health{State: state, Detail: detail, Gaps: gaps}
		} else {
			h = safeModuleHealth(st.mod)
			h.Gaps = append(h.Gaps, gaps...)
		}
		h.Usage.Dropped = c.bus.dropped(name)
		out[name] = h
	}
	return out
}

func (c *Controller) RunReadOnly(ctx context.Context, mod, template string, params map[string]string) (string, error) {
	panic("unimplemented: W1 Task 23")
}

func (c *Controller) CreateStanding(ctx context.Context, sa plan.StandingApproval) error {
	panic("unimplemented: W1 Task 24")
}

func (c *Controller) RevokeStanding(ctx context.Context, id, by string) error {
	panic("unimplemented: W1 Task 24")
}

func (c *Controller) RunStanding(ctx context.Context, mod, approvalID, template string, params map[string]string) (string, error) {
	panic("unimplemented: W1 Task 24")
}

func (c *Controller) Propose(ctx context.Context, p module.Proposal) (int64, error) {
	panic("unimplemented: W1 Task 25")
}

func (c *Controller) AcceptProposal(ctx context.Context, id int64, by string) (string, error) {
	panic("unimplemented: W1 Task 25")
}

func (c *Controller) DismissProposal(ctx context.Context, id int64, by string) error {
	panic("unimplemented: W1 Task 25")
}

func (c *Controller) RunAuto(ctx context.Context, mod, template string, params map[string]string) (string, error) {
	panic("unimplemented: W1 Task 26")
}

func (c *Controller) ReenableAuto(ctx context.Context, mod, template, host, by string) error {
	panic("unimplemented: W1 Task 28")
}

func (c *Controller) SendFact(ctx context.Context, mod string, m module.ControlMsg) error {
	panic("unimplemented: W1 Task 30")
}

// noteAutoRollback feeds the auto circuit breaker.
func (c *Controller) noteAutoRollback(mod, template, host string, at time.Time) {
	panic("unimplemented: W1 Task 28")
}

// safeModuleHealth calls a module's Health, turning a panic into an error
// report so a broken module cannot take the controller's health page down.
func safeModuleHealth(mod module.ControllerModule) (h module.Health) {
	defer func() {
		if r := recover(); r != nil {
			why := fmt.Sprintf("panic: %v", r)
			h = module.Health{State: module.StateError, Detail: why,
				Gaps: []module.Gap{{What: "health", Why: why}}}
		}
	}()
	return mod.Health()
}
