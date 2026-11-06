package vantage

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/checks/probe"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// CheckSource supplies the checks to run: the learned item and credential
// unions per service, delivered by the controller. Credentials live in memory
// only, inside the returned Specs.
type CheckSource interface {
	Specs(ctx context.Context) []probe.Spec
}

// CheckSourceFunc adapts a function to CheckSource.
type CheckSourceFunc func(ctx context.Context) []probe.Spec

// Specs implements CheckSource.
func (f CheckSourceFunc) Specs(ctx context.Context) []probe.Spec { return f(ctx) }

// CheckRunnerConfig tunes the external check runner.
type CheckRunnerConfig struct {
	Allow  Allowlist // required: only these addresses are probed
	Source CheckSource
	// Interval between passes over all checks (default 45s; the design says
	// every 30-60 s per check). A pass is jittered by +-10%.
	Interval time.Duration
	// SweepEvery: every Nth pass of a check also sweeps its whole learned
	// item union (default 10; 0 disables the union sweep).
	SweepEvery int
	Gate       Gate          // round clock; nil = no alignment
	MaxDefer   time.Duration // longest wait for a quiet window before skipping a pass (default Interval)
	// MinGap between probe starts, and the cap on the number in flight; probes
	// stay below knife-edge volume (default 250ms, 2 in flight).
	MinGap        time.Duration
	MaxConcurrent int
	Probe         probe.Options // Timeout, Strict, BadAttempts, ...
	Rand          *rand.Rand
	clock
}

// CheckRunner is the agent module for the `check_runner` role on the Kali.
type CheckRunner struct {
	cfg  CheckRunnerConfig
	rng  *rand.Rand
	rmu  sync.Mutex
	gap  *limiter
	runs map[string]int // per check pass counters

	passes, probes, deferred, refused atomic.Uint64
	refusedSeen                       sync.Map
}

// NewCheckRunner validates the configuration.
func NewCheckRunner(cfg CheckRunnerConfig) (*CheckRunner, error) {
	if cfg.Source == nil {
		return nil, fmt.Errorf("vantage: check runner needs a Source")
	}
	if len(cfg.Allow.prefixes) == 0 {
		return nil, fmt.Errorf("vantage: check runner needs a non-empty allowlist")
	}
	cfg.clock.defaults()
	if cfg.Interval <= 0 {
		cfg.Interval = 45 * time.Second
	}
	if cfg.SweepEvery < 0 {
		cfg.SweepEvery = 0
	} else if cfg.SweepEvery == 0 {
		cfg.SweepEvery = 10
	}
	if cfg.MaxDefer <= 0 {
		cfg.MaxDefer = cfg.Interval
	}
	if cfg.MinGap <= 0 {
		cfg.MinGap = 250 * time.Millisecond
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 2
	}
	rng := cfg.Rand
	if rng == nil {
		rng = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	}
	return &CheckRunner{cfg: cfg, rng: rng, runs: map[string]int{},
		gap: newLimiter(float64(time.Second)/float64(cfg.MinGap), 1, cfg.clock)}, nil
}

// Name implements agent.Module.
func (r *CheckRunner) Name() string { return "vantage.check_runner" }

// Stats returns counters: passes started, probes run, passes deferred (no quiet
// window), probes refused (target not allowlisted).
func (r *CheckRunner) Stats() (passes, probes, deferred, refused uint64) {
	return r.passes.Load(), r.probes.Load(), r.deferred.Load(), r.refused.Load()
}

// Start implements agent.Module: it runs passes until ctx ends.
func (r *CheckRunner) Start(ctx context.Context, emit agent.Emit) error {
	for {
		r.RunOnce(ctx, emit)
		r.rmu.Lock()
		j := 0.9 + 0.2*r.rng.Float64()
		r.rmu.Unlock()
		if !r.cfg.Sleep(ctx, time.Duration(float64(r.cfg.Interval)*j)) {
			return nil
		}
	}
}

func (r *CheckRunner) shuffle(n int) []int {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	return r.rng.Perm(n)
}

// RunOnce runs one pass over every check: a faithful sample each, plus the
// union sweep on every SweepEvery-th pass of that check.
func (r *CheckRunner) RunOnce(ctx context.Context, emit agent.Emit) {
	specs := r.cfg.Source.Specs(ctx)
	r.passes.Add(1)
	sem := make(chan struct{}, r.cfg.MaxConcurrent)
	var wg sync.WaitGroup
	need := r.cfg.Probe.Timeout
	if need <= 0 {
		need = 10 * time.Second
	}
	for _, i := range r.shuffle(len(specs)) {
		spec := specs[i]
		if ctx.Err() != nil {
			break
		}
		if !r.cfg.Allow.Allows(spec.Host) {
			r.refuse(emit, spec)
			continue
		}
		// Never let a probe sit inside a scorer burst: wait for a window big
		// enough for the whole probe, or skip this check for the pass.
		if !waitSafe(ctx, r.cfg.Gate, r.cfg.clock, need, r.cfg.MaxDefer) {
			if ctx.Err() == nil {
				r.deferred.Add(1)
				_ = emit(newEvent(KindCheckDeferred, event.PriorityNormal, r.cfg.Now(), map[string]any{
					"id": spec.ID, "type": string(spec.Type), "host": spec.Host, "reason": "no quiet window"}))
			}
			continue
		}
		if !r.gap.Wait(ctx) {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		r.rmu.Lock()
		r.runs[spec.ID]++
		n := r.runs[spec.ID]
		r.rmu.Unlock()
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			opts := r.cfg.Probe
			opts.Rand = nil
			r.probes.Add(1)
			res := probe.Faithful(ctx, spec, opts)
			_ = emit(CheckEvent(res, r.cfg.Now()))
			if r.cfg.SweepEvery > 0 && n%r.cfg.SweepEvery == 0 && len(spec.Items) > 1 {
				for _, sr := range probe.Sweep(ctx, spec, opts, r.cfg.MinGap) {
					r.probes.Add(1)
					_ = emit(CheckEvent(sr, r.cfg.Now()))
				}
			}
		}()
	}
	wg.Wait()
}

func (r *CheckRunner) refuse(emit agent.Emit, spec probe.Spec) {
	r.refused.Add(1)
	if _, dup := r.refusedSeen.LoadOrStore(spec.ID+"|"+spec.Host, true); dup {
		return
	}
	_ = emit(newEvent(KindRefused, event.PriorityHigh, r.cfg.Now(), map[string]any{
		"id": spec.ID, "type": string(spec.Type), "host": spec.Host, "reason": "target is not in the public-address allowlist"}))
}

// CheckEvent renders a result as a vantage.check event. It carries no
// credential; Debug is capped.
func CheckEvent(res probe.Result, now time.Time) event.Event {
	steps := make(map[string]any, len(res.Steps))
	for _, s := range res.Steps {
		steps[s.Name] = s.Elapsed.Milliseconds()
	}
	dbg := res.Debug
	if len(dbg) > 256 {
		dbg = dbg[:256]
	}
	f := map[string]any{
		"id": res.ID, "type": string(res.Type), "host": res.Host, "port": res.Port,
		"item": res.Item, "user": res.User, "mode": res.Mode, "strict": res.Strict,
		"ok": res.OK, "scorer_ok": res.ScorerOK, "strict_ok": res.StrictOK,
		"class": string(res.Class), "err": res.Err, "elapsed_ms": res.Elapsed.Milliseconds(),
		"steps": steps,
	}
	if dbg != "" {
		f["debug"] = dbg
	}
	if len(res.StrictIssues) > 0 {
		f["strict_issues"] = res.StrictIssues
	}
	prio := event.PriorityNormal
	if !res.OK {
		prio = event.PriorityHigh
	}
	return newEvent(KindCheck, prio, now, f)
}
