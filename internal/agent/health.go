package agent

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/spool"
)

// LinkStatus is the link's state as the health module reports it.
type LinkStatus struct {
	Connected   bool
	Enrolled    bool
	Connects    uint64
	LastConnect time.Time
	LastError   string
}

// HealthSource is what the health module reads.
type HealthSource interface {
	SpoolStats() spool.Stats
	Modules() map[string]ModuleStatus
	Link() LinkStatus
}

type healthModule struct {
	src      HealthSource
	interval time.Duration
	prev     map[string]ModuleStatus
	last     time.Time
}

// NewHealthModule returns the built-in health module. Every interval (and once
// at start) it emits an agent.health event with spool stats, module states and
// link state, plus telemetry_gap events for module rate-limit/spool drops and
// for modules that were down during the interval.
func NewHealthModule(src HealthSource, interval time.Duration) Module {
	if interval <= 0 {
		interval = time.Minute
	}
	return &healthModule{src: src, interval: interval}
}

func (h *healthModule) Name() string { return "health" }

// Health reports the module's own state. The module needs root because it
// reads the supervisor of a root agent, so a non-root run reports the
// privilege gap instead of claiming full coverage (conformance check 4).
func (h *healthModule) Health() module.Health {
	info := map[string]string{"modules": strconv.Itoa(len(h.src.Modules()))}
	if runningAsRoot() {
		return module.Health{State: module.StateOK, Info: info}
	}
	return module.Health{State: module.StateDegraded, Info: info,
		Gaps: []module.Gap{{What: "privilege", Why: "the health module reads the supervisor of a root agent"}}}
}

// runningAsRoot reports whether this process holds the privilege the module's
// manifest claims. Windows agents run as SYSTEM, which os.Geteuid cannot see.
func runningAsRoot() bool {
	return runtime.GOOS == "windows" || os.Geteuid() == 0
}

func (h *healthModule) Start(ctx context.Context, emit Emit) error {
	h.last = time.Now()
	h.report(emit, h.last)
	t := time.NewTicker(h.interval)
	defer t.Stop()
	for {
		select {
		case now := <-t.C:
			h.report(emit, now)
		case <-ctx.Done():
			return nil
		}
	}
}

func (h *healthModule) report(emit Emit, now time.Time) {
	sp := h.src.SpoolStats()
	mods := h.src.Modules()
	lk := h.src.Link()
	names := make([]string, 0, len(mods))
	for n := range mods {
		names = append(names, n)
	}
	sort.Strings(names)
	mf := map[string]any{}
	for _, n := range names {
		m := mods[n]
		mf[n] = map[string]any{"state": m.State, "restarts": m.Restarts, "emitted": m.Emitted,
			"rate_dropped": m.RateDropped, "spool_drops": m.SpoolDrops, "last_error": m.LastError}
	}
	emit(core("agent.health", event.AgentHealth{
		Spool: map[string]any{"head": sp.HeadSeq, "ack": sp.AckSeq, "depth": sp.HeadSeq - sp.AckSeq,
			"used_bytes": sp.UsedBytes, "max_bytes": sp.MaxBytes, "unacked_bytes": sp.UnackedBytes,
			"shed": sp.Shed, "gap_records": sp.GapRecords, "state": sp.State},
		Modules: mf,
		Link: map[string]any{"connected": lk.Connected, "enrolled": lk.Enrolled, "connects": lk.Connects,
			"last_error": lk.LastError},
	}))
	from := h.last.UTC().Format(time.RFC3339Nano)
	to := now.UTC().Format(time.RFC3339Nano)
	for _, n := range names {
		if n == h.Name() {
			continue
		}
		m, p := mods[n], h.prev[n]
		if d := m.RateDropped - p.RateDropped; d > 0 {
			emit(gap(n, "rate_limit", d, from, to))
		}
		if d := m.SpoolDrops - p.SpoolDrops; d > 0 {
			emit(gap(n, "spool_refused", d, from, to))
		}
		if !m.DownSince.IsZero() || m.Restarts > p.Restarts {
			emit(gap(n, "module_down", uint64(max(1, m.Restarts-p.Restarts)), from, to))
		}
	}
	h.prev, h.last = mods, now
}

func gap(source, reason string, count uint64, from, to string) event.Event {
	return core(event.KindTelemetryGap, event.TelemetryGap{Source: source, Reason: reason, Count: count, From: from, To: to})
}

const healthDefaultFP = "default"

// mustType returns the declared event type of a kind the module emits; an
// undeclared kind is a programming error, not a missing event.
func mustType(kind string) event.Type {
	ty, ok := event.Lookup(kind)
	if !ok {
		panic("agent: health emits undeclared kind " + kind)
	}
	return ty
}

func init() {
	RegisterFactory(Factory{
		Name: "health",
		Manifest: module.Manifest{
			Name: "health", Sides: []module.Side{module.SideAgent}, Privilege: "root", Default: true,
			Emits: []event.Type{mustType("agent.health"), mustType(event.KindTelemetryGap)},
		},
		Section: func(c *plan.AgentConfig) (string, bool) {
			h := c.Modules.Health
			if h != nil && !h.Enabled {
				return "", false
			}
			if h != nil && h.IntervalSec > 0 {
				return fmt.Sprintf("%d/%v/%d", h.IntervalSec, h.RatePerSec, h.Burst), true
			}
			return healthDefaultFP, true // a core module: no block still runs it
		},
		Build: func(env Env, c *plan.AgentConfig) (ModuleSpec, error) {
			iv := env.a.cfg.HealthInterval
			spec := ModuleSpec{}
			if h := c.Modules.Health; h != nil {
				if h.IntervalSec > 0 {
					iv = time.Duration(h.IntervalSec) * time.Second
				}
				spec.Rate, spec.Burst = h.RatePerSec, h.Burst
			}
			spec.Module = NewHealthModule(env.Health, iv)
			return spec, nil
		},
	})
}
