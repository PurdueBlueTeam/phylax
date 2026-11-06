package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/module"
)

// Emit hands one event to the agent. It never blocks on the network: events go
// to the local spool, so a down link cannot stall a sensor. A non-nil error
// (rate limited, shed, spool full) means the event was dropped; the spool
// announces shedding with gap records and the supervisor counts the rest.
type Emit func(event.Event) error

// HealthReporter is implemented by a module with its own health detail.
type HealthReporter interface{ Health() module.Health }

// clampHealth fits a module health report inside the heartbeat limits, marking
// a truncation with a trailing gap. The reporter owns the original slices and
// maps, so everything is copied before it is changed.
func clampHealth(h module.Health) module.Health {
	truncated := false
	if len(h.State) > link.MaxHealthState {
		h.State = module.State(clipUTF8(string(h.State), link.MaxHealthState))
		truncated = true
	}
	if len(h.Detail) > link.MaxHealthDetail {
		h.Detail = clipUTF8(h.Detail, link.MaxHealthDetail)
		truncated = true
	}
	h.Gaps = append([]module.Gap(nil), h.Gaps...)
	if len(h.Gaps) > link.MaxHealthGaps {
		truncated = true
	}
	for i := range h.Gaps {
		if len(h.Gaps[i].What) > link.MaxHealthGapField {
			h.Gaps[i].What = clipUTF8(h.Gaps[i].What, link.MaxHealthGapField)
			truncated = true
		}
		if len(h.Gaps[i].Why) > link.MaxHealthGapField {
			h.Gaps[i].Why = clipUTF8(h.Gaps[i].Why, link.MaxHealthGapField)
			truncated = true
		}
	}
	if h.Info != nil {
		keys := make([]string, 0, len(h.Info))
		for k := range h.Info {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > link.MaxHealthInfo {
			truncated = true
		}
		info := make(map[string]string, min(len(keys), link.MaxHealthInfo))
		for _, k := range keys {
			if len(info) >= link.MaxHealthInfo {
				break
			}
			nk := k
			if len(nk) > link.MaxHealthInfoKey {
				nk = clipUTF8(nk, link.MaxHealthInfoKey)
				truncated = true
			}
			if _, dup := info[nk]; dup {
				var ok bool
				if nk, ok = uniqueInfoKey(info, nk); !ok {
					truncated = true
					continue
				}
				truncated = true
			}
			v := h.Info[k]
			if len(v) > link.MaxHealthInfoValue {
				v = clipUTF8(v, link.MaxHealthInfoValue)
				truncated = true
			}
			info[nk] = v
		}
		h.Info = info
	}
	limit := link.MaxHealthGaps
	if truncated && limit > 0 {
		limit--
	}
	if len(h.Gaps) > limit {
		h.Gaps = h.Gaps[:limit]
	}
	if truncated {
		h.Gaps = append(h.Gaps, module.Gap{What: "truncated", Why: "health report clamped to heartbeat limits"})
	}
	return h
}

func clipUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func uniqueInfoKey(info map[string]string, k string) (string, bool) {
	for i := 2; i < 1000; i++ {
		suffix := fmt.Sprintf("~%d", i)
		base := k
		if len(base)+len(suffix) > link.MaxHealthInfoKey {
			base = clipUTF8(base, link.MaxHealthInfoKey-len(suffix))
		}
		if _, ok := info[base+suffix]; !ok {
			return base + suffix, true
		}
	}
	return "", false
}

// Module is one supervised unit of agent functionality.
type Module interface {
	Name() string
	// Start runs the module until ctx is cancelled (return nil or ctx.Err()) or
	// it fails. A returned error or a panic is a crash and is restarted with
	// backoff. A nil return while ctx is live means the module finished and
	// will not be restarted.
	Start(ctx context.Context, emit Emit) error
}

// Module states reported in heartbeats and health events.
const (
	StateStarting   = "starting"
	StateRunning    = "ok"
	StateRestarting = "restarting"
	StateStopped    = "stopped"
	StateOverBudget = "over_budget"
)

// ModuleStatus is a snapshot of one module.
type ModuleStatus struct {
	State       string
	Restarts    int
	LastError   string
	Emitted     uint64
	RateDropped uint64 // dropped by the module's rate limit
	SpoolDrops  uint64 // refused by the spool (shed/full)
	DownSince   time.Time
}

// ModuleSpec registers a module with limits.
type ModuleSpec struct {
	Module Module
	// Rate is the sustained events/second allowed (0 = unlimited); Burst is the
	// bucket size (default max(1, Rate)). Over the limit events are dropped and
	// counted, never blocking the module.
	Rate  float64
	Burst int
	// Subscriber marks a module that calls Env.Subscribe from Start. The agent
	// buffers locally published events until it has, so none are lost in the
	// start-up window.
	Subscriber bool
}

// Budget is the memory/CPU budget hook. It is polled every SupervisorOptions.
// BudgetInterval for each running module; a non-nil error stops the module,
// which is then restarted after backoff (state over_budget meanwhile).
type Budget func(module string) error

// SupervisorOptions tune restart behaviour.
type SupervisorOptions struct {
	Emit           Emit // required: the unlimited underlying emitter
	Logger         *slog.Logger
	Backoff        link.Backoff  // default 1s..60s
	StableAfter    time.Duration // a run this long resets the backoff (default 30s)
	Budget         Budget
	BudgetInterval time.Duration // default 5s
	sleep          func(time.Duration) <-chan time.Time
}

// Supervisor runs modules as goroutines with panic recovery and exponential
// restart backoff.
type Supervisor struct {
	o  SupervisorOptions
	mu sync.Mutex
	ms map[string]*modState
	wg sync.WaitGroup
	// ctx is set once Run has started; modules added afterwards start at once.
	ctx    context.Context
	closed bool
}

type modState struct {
	name   string
	spec   ModuleSpec
	status ModuleStatus
	bucket bucket
	// started/cancel/done are set when the module's goroutine runs.
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewSupervisor creates a supervisor; add modules with Add before Run.
func NewSupervisor(o SupervisorOptions) *Supervisor {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Backoff.Min == 0 {
		o.Backoff.Min = time.Second
	}
	if o.Backoff.Max == 0 {
		o.Backoff.Max = time.Minute
	}
	if o.StableAfter == 0 {
		o.StableAfter = 30 * time.Second
	}
	if o.BudgetInterval == 0 {
		o.BudgetInterval = 5 * time.Second
	}
	if o.sleep == nil {
		o.sleep = time.After
	}
	return &Supervisor{o: o, ms: map[string]*modState{}}
}

// Add registers a module. Names must be unique. Before Run the module starts
// with Run; after it, at once.
func (s *Supervisor) Add(spec ModuleSpec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := spec.Module.Name()
	if _, dup := s.ms[n]; dup {
		return fmt.Errorf("agent: duplicate module %q", n)
	}
	burst := spec.Burst
	if burst <= 0 {
		burst = max(1, int(spec.Rate))
	}
	m := &modState{name: n, spec: spec, status: ModuleStatus{State: StateStarting}, bucket: newBucket(spec.Rate, burst)}
	s.ms[n] = m
	if s.ctx != nil {
		if s.closed {
			return errors.New("agent: supervisor is stopping")
		}
		s.launchLocked(m)
	}
	return nil
}

// launchLocked starts m's goroutine. Caller holds s.mu and s.ctx is set.
func (s *Supervisor) launchLocked(m *modState) {
	mctx, cancel := context.WithCancel(s.ctx)
	m.started, m.cancel, m.done = true, cancel, make(chan struct{})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(m.done)
		defer cancel()
		s.supervise(mctx, m)
	}()
}

// Remove stops the named module, waits for it to exit and forgets it. It
// reports whether the module existed.
func (s *Supervisor) Remove(name string) bool {
	s.mu.Lock()
	m, ok := s.ms[name]
	if !ok {
		s.mu.Unlock()
		return false
	}
	cancel, done := m.cancel, m.done
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	s.mu.Lock()
	if s.ms[name] == m {
		delete(s.ms, name)
	}
	s.mu.Unlock()
	return true
}

// Has reports whether a module with this name is registered.
func (s *Supervisor) Has(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.ms[name]
	return ok
}

// Run starts every module and blocks until ctx is cancelled and all have exited.
// Modules may be added and removed while it runs.
func (s *Supervisor) Run(ctx context.Context) {
	s.mu.Lock()
	s.ctx = ctx
	for _, m := range s.ms {
		if !m.started {
			s.launchLocked(m)
		}
	}
	s.mu.Unlock()
	<-ctx.Done()
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.wg.Wait()
}

// Health returns a module's merged supervisor and reporter health.
func (s *Supervisor) Health(name string) (module.Health, bool) {
	s.mu.Lock()
	m, ok := s.ms[name]
	if !ok {
		s.mu.Unlock()
		return module.Health{}, false
	}
	st, mod := m.status, m.spec.Module
	s.mu.Unlock()

	h := module.Health{Usage: module.Usage{Events: st.Emitted, Dropped: st.RateDropped + st.SpoolDrops}}
	switch st.State {
	case StateRunning:
		h.State = module.StateOK
	case StateStarting:
		h.State, h.Detail = module.StateDegraded, "starting"
	case StateRestarting:
		h.State = module.StateRestarting
	case StateOverBudget:
		h.State = module.StateOverBudget
	case StateStopped:
		h.State = module.StateDisabled
	default:
		h.State = module.StateError
	}
	if r, ok := mod.(HealthReporter); ok {
		rep := clampHealth(r.Health())
		if st.State != StateRestarting && st.State != StateOverBudget && rep.State != "" {
			h.State = rep.State
		}
		h.Detail, h.Gaps, h.Info = rep.Detail, rep.Gaps, rep.Info
		h.Usage.CPUMillis, h.Usage.HeldBytes, h.Usage.BytesOut = rep.Usage.CPUMillis, rep.Usage.HeldBytes, rep.Usage.BytesOut
	}
	return h, true
}

// Snapshot returns every module's status.

func (s *Supervisor) Snapshot() map[string]ModuleStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]ModuleStatus, len(s.ms))
	for n, m := range s.ms {
		out[n] = m.status
	}
	return out
}

// States returns module name to state, for heartbeats.
func (s *Supervisor) States() map[string]string {
	out := map[string]string{}
	for n, st := range s.Snapshot() {
		out[n] = st.State
	}
	return out
}

func (s *Supervisor) update(m *modState, f func(*modState)) {
	s.mu.Lock()
	f(m)
	s.mu.Unlock()
}

// limited wraps emit with the module's token bucket and counters.
func (s *Supervisor) limited(m *modState) Emit {
	return func(e event.Event) error {
		s.mu.Lock()
		if !m.bucket.take() {
			m.status.RateDropped++
			s.mu.Unlock()
			return ErrRateLimited
		}
		s.mu.Unlock()
		err := s.o.Emit(e)
		s.mu.Lock()
		if err != nil {
			m.status.SpoolDrops++
		} else {
			m.status.Emitted++
		}
		s.mu.Unlock()
		return err
	}
}

func (s *Supervisor) supervise(ctx context.Context, m *modState) {
	name, mod := m.name, m.spec.Module
	bo := s.o.Backoff
	for ctx.Err() == nil {
		started := time.Now()
		s.update(m, func(m *modState) { m.status.State, m.status.DownSince = StateRunning, time.Time{} })
		err, overBudget := s.runOnce(ctx, m, mod)
		if ctx.Err() != nil {
			break
		}
		if err == nil && !overBudget {
			s.update(m, func(m *modState) { m.status.State = StateStopped })
			return
		}
		if time.Since(started) >= s.o.StableAfter {
			bo.Reset()
		}
		state := StateRestarting
		if overBudget {
			state = StateOverBudget
		}
		d := bo.Next()
		s.update(m, func(m *modState) {
			m.status.State, m.status.LastError = state, err.Error()
			m.status.Restarts++
			m.status.DownSince = time.Now()
		})
		s.o.Logger.Warn("module crashed", "module", name, "err", err, "restart_in", d)
		s.crashEvent(name, err, d)
		select {
		case <-s.o.sleep(d):
		case <-ctx.Done():
		}
	}
	s.update(m, func(m *modState) { m.status.State = StateStopped })
}

func (s *Supervisor) crashEvent(name string, err error, d time.Duration) {
	_ = s.o.Emit(core("agent.module_crash", event.AgentModuleCrash{Module: name, Error: err.Error(), RestartInMS: d.Milliseconds()}))
}

// runOnce runs the module with panic recovery and the budget watcher.
func (s *Supervisor) runOnce(ctx context.Context, m *modState, mod Module) (err error, overBudget bool) {
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var budgetErr error
	var bmu sync.Mutex
	if s.o.Budget != nil {
		go func() {
			t := time.NewTicker(s.o.BudgetInterval)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					if e := s.o.Budget(m.name); e != nil {
						bmu.Lock()
						budgetErr = e
						bmu.Unlock()
						cancel()
						return
					}
				case <-rctx.Done():
					return
				}
			}
		}()
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v\n%s", r, debug.Stack())
			}
		}()
		err = mod.Start(rctx, s.limited(m))
	}()
	bmu.Lock()
	defer bmu.Unlock()
	if budgetErr != nil && ctx.Err() == nil {
		return fmt.Errorf("over budget: %w", budgetErr), true
	}
	if err == context.Canceled && ctx.Err() != nil {
		err = nil
	}
	return err, false
}

// ErrRateLimited is returned by Emit when a module exceeds its rate limit.
var ErrRateLimited = fmt.Errorf("agent: module rate limit exceeded")

type bucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func newBucket(rate float64, burst int) bucket {
	return bucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: time.Now()}
}

func (b *bucket) take() bool {
	if b.rate <= 0 {
		return true
	}
	now := time.Now()
	b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
