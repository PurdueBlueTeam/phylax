package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sort"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// Config states reported in heartbeats under the reserved module name "config"
// as "<state>/<epoch>.<version>".
const (
	ConfigNone     = "none"     // no config ever applied
	ConfigPending  = "pending"  // accepted, modules not yet reconciled
	ConfigOK       = "ok"       // applied, every enabled module is running
	ConfigDegraded = "degraded" // applied, but a module is unavailable or failed to build
)

// ConfigStatusModule is the reserved Heartbeat.Modules key carrying the config status.
const ConfigStatusModule = "config"

// ConfigStatus is the agent's view of its signed configuration.
type ConfigStatus struct {
	State   string
	Epoch   uint64
	Version uint64
	// Modules is each registered module's outcome: running, disabled,
	// "unavailable: reason" or "error: reason".
	Modules map[string]string
}

// ConfigStatus returns the current config status.
func (a *Agent) ConfigStatus() ConfigStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.cfgStat
	st.Modules = make(map[string]string, len(a.cfgStat.Modules))
	for k, v := range a.cfgStat.Modules {
		st.Modules[k] = v
	}
	if st.State == "" {
		st.State = ConfigNone
	}
	return st
}

func (a *Agent) configHeartbeat() string {
	st := a.ConfigStatus()
	return fmt.Sprintf("%s/%d.%d", st.State, st.Epoch, st.Version)
}

// Applied returns the config last accepted (nil before the first).
func (a *Agent) AppliedConfig() *plan.AgentConfig {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.desired
}

func (a *Agent) refuseConfig(w *link.Config, why string) error {
	a.log.Warn("config refused", "version", w.Version, "epoch", w.Epoch, "why", why)
	a.emit(event.Event{Kind: "agent.config_rejected", Priority: event.PriorityHigh,
		Fields: map[string]any{"version": w.Version, "epoch": w.Epoch, "reason": why}})
	return nil
}

// handleConfig verifies a config (mandatory: signed by the plan key, for this
// host, above the durable (epoch, version) mark), persists it and queues the
// module reconciliation. Refusals are reported as agent.config_rejected events
// and never end the session.
func (a *Agent) handleConfig(_ context.Context, w *link.Config) error {
	if a.cfgVer == nil {
		return a.refuseConfig(w, "no plan-signing key configured: config is never accepted unsigned")
	}
	cfg, err := a.cfgVer.Verify(w)
	if errors.Is(err, plan.ErrConfigCurrent) {
		return nil
	}
	if err != nil {
		return a.refuseConfig(w, err.Error())
	}
	raw, err := json.Marshal(w)
	if err == nil {
		err = atomicfile.WriteFile(a.cfg.Layout.Config(), raw, 0o600)
	}
	if err != nil {
		// The mark was advanced; the same config may be presented again.
		a.log.Error("persist config", "err", err)
		return a.refuseConfig(w, "could not persist: "+err.Error())
	}
	a.adopt(cfg)
	return nil
}

// adopt makes cfg the desired config and wakes the reconciler.
func (a *Agent) adopt(cfg *plan.AgentConfig) {
	if dg, err := cfg.Digest(); err == nil {
		a.cfgVer.MarkApplied(cfg.Epoch, cfg.Version, dg)
	}
	a.mu.Lock()
	a.desired = cfg
	a.cfgStat.State, a.cfgStat.Epoch, a.cfgStat.Version = ConfigPending, cfg.Epoch, cfg.Version
	a.mu.Unlock()
	select {
	case a.cfgKick <- struct{}{}:
	default:
	}
}

// loadPersistedConfig applies the last good config from disk, so a restart
// without the controller still runs the modules. The signature is verified
// again (the file lives on a host an attacker may have written to); the replay
// mark is not consulted, the file being what the mark was taken from.
func (a *Agent) loadPersistedConfig() {
	if a.cfgVer == nil {
		return
	}
	raw, err := os.ReadFile(a.cfg.Layout.Config())
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var w link.Config
	if err == nil {
		err = json.Unmarshal(raw, &w)
	}
	var cfg *plan.AgentConfig
	if err == nil {
		cfg, err = a.cfgVer.Parse(&w)
	}
	if err != nil {
		a.log.Error("persisted config rejected", "err", err)
		a.emit(event.Event{Kind: "agent.config_rejected", Priority: event.PriorityCritical,
			Fields: map[string]any{"reason": "persisted config: " + err.Error()}})
		return
	}
	a.adopt(cfg)
}

// configLoop reconciles modules with the latest accepted config.
func (a *Agent) configLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.cfgKick:
		}
		a.mu.Lock()
		cfg := a.desired
		a.mu.Unlock()
		if cfg == nil || ctx.Err() != nil {
			continue
		}
		a.reconcile(ctx, cfg)
	}
}

func (a *Agent) moduleEnv() Env {
	return Env{Host: a.bundle.Host, StateDir: a.cfg.Layout.Root, Logger: a.log, PlanKey: a.planKey, Health: a, a: a}
}

// reconcile starts, stops and reconfigures modules so that they match cfg.
func (a *Agent) reconcile(ctx context.Context, cfg *plan.AgentConfig) {
	env := a.moduleEnv()
	res := map[string]string{}
	degraded := false
	for _, f := range registered(a.cfg.Factories) {
		if ctx.Err() != nil {
			return
		}
		fp, enabled := f.Section(cfg)
		cur, has := a.managed[f.Name]
		if !enabled {
			if has {
				a.sup.Remove(f.Name)
				delete(a.managed, f.Name)
			}
			res[f.Name] = "disabled"
			continue
		}
		if has && cur == fp {
			res[f.Name] = "running"
			continue
		}
		if !has && a.sup.Has(f.Name) && f.Name != "health" {
			// A module of that name was supplied statically (Config.Modules).
			res[f.Name] = "running (static)"
			continue
		}
		spec, err := f.Build(env, cfg)
		switch {
		case errors.Is(err, ErrUnavailable):
			a.sup.Remove(f.Name)
			delete(a.managed, f.Name)
			res[f.Name] = "unavailable: " + err.Error()
			degraded = true
			continue
		case err != nil || spec.Module == nil:
			if err == nil {
				err = errors.New("factory returned no module")
			}
			a.log.Error("module build failed", "module", f.Name, "err", err)
			res[f.Name] = "error: " + err.Error()
			degraded = true
			continue // an already running module keeps its previous settings
		}
		a.sup.Remove(f.Name)
		if err := a.sup.Add(spec); err != nil {
			res[f.Name] = "error: " + err.Error()
			degraded = true
			delete(a.managed, f.Name)
			continue
		}
		a.managed[f.Name] = fp
		res[f.Name] = "running"
	}
	if mb := cfg.Budgets.MemoryLimitMB; mb > 0 {
		lim := int64(mb) << 20
		if a.cfg.MemoryLimit <= 0 || lim < a.cfg.MemoryLimit {
			debug.SetMemoryLimit(lim)
		}
	}
	state := ConfigOK
	if degraded {
		state = ConfigDegraded
	}
	a.mu.Lock()
	superseded := a.desired != cfg
	if !superseded {
		a.cfgStat = ConfigStatus{State: state, Epoch: cfg.Epoch, Version: cfg.Version, Modules: res}
	}
	a.mu.Unlock()
	names := make([]string, 0, len(res))
	for n := range res {
		names = append(names, n)
	}
	sort.Strings(names)
	mf := map[string]any{}
	for _, n := range names {
		mf[n] = res[n]
	}
	a.log.Info("config applied", "epoch", cfg.Epoch, "version", cfg.Version, "state", state)
	a.emit(event.Event{Kind: "agent.config_applied", Priority: event.PriorityHigh, Time: time.Now(),
		Fields: map[string]any{"epoch": cfg.Epoch, "version": cfg.Version, "state": state, "modules": mf}})
}
