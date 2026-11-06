package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// HarnessOptions configure a test harness: a real agent without link, spool or
// identity.
type HarnessOptions struct {
	Host      string
	StateDir  string
	Factories []Factory
	PlanKey   ed25519.PublicKey
	EmitErr   func() error // nil: every emit succeeds
}

// harnessMaxEmitted bounds the in-memory event list (oldest dropped).
const harnessMaxEmitted = 100_000

// Harness runs real modules over the real reconciler and supervisor.
type Harness struct {
	a *Agent
	o HarnessOptions

	mu      sync.Mutex
	emitted []event.Event
}

func NewHarness(o HarnessOptions) (*Harness, error) {
	h := &Harness{o: o}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := &Agent{
		cfg:           Config{Layout: Layout{Root: o.StateDir}, Factories: o.Factories, Logger: log},
		log:           log,
		bundle:        &Bundle{Host: o.Host},
		planKey:       o.PlanKey,
		managed:       map[string]string{},
		notify:        make(chan struct{}, 1),
		cfgKick:       make(chan struct{}, 1),
		factoriesOnly: true,
	}
	so := a.cfg.Supervisor
	// The supervisor's emit is the harness's event sink: a module's event is
	// recorded (after EmitErr) whether or not the "link" accepted it.
	so.Emit = func(e event.Event) error {
		a.publish(e)
		var err error
		if o.EmitErr != nil {
			err = o.EmitErr()
		}
		h.record(e)
		return err
	}
	so.Logger = log
	a.sup = NewSupervisor(so)
	h.a = a
	return h, nil
}

func (h *Harness) record(e event.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.emitted) >= harnessMaxEmitted {
		copy(h.emitted, h.emitted[1:])
		h.emitted[len(h.emitted)-1] = e
		return
	}
	h.emitted = append(h.emitted, e)
}

// Apply runs the real reconciler over the harness's factories only.
func (h *Harness) Apply(cfg *plan.AgentConfig) {
	h.a.mu.Lock()
	h.a.desired = cfg
	h.a.cfgStat = ConfigStatus{State: ConfigPending, Epoch: cfg.Epoch, Version: cfg.Version}
	ctx := h.a.runCtx
	h.a.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	// The reconciler's own agent.config_applied is not a module event; keep it
	// out of Emitted (a module calling a.emit would still reach the sink).
	h.a.sink = nil
	h.a.reconcile(ctx, cfg)
	h.a.sink = func(e event.Event) error { h.record(e); return nil }
}

// Run starts the supervisor and blocks until ctx ends.
func (h *Harness) Run(ctx context.Context) {
	h.a.mu.Lock()
	if h.a.runCtx == nil {
		h.a.runCtx = ctx
	}
	sup := h.a.sup
	h.a.mu.Unlock()
	sup.Run(ctx)
}

// Publish feeds an event to the on-host bus without storing it.
func (h *Harness) Publish(e event.Event) { h.a.publish(e) }

// Emitted returns a copy of the events the supervisor's emit accepted.
func (h *Harness) Emitted() []event.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]event.Event(nil), h.emitted...)
}

// Health is the supervisor's merged health, including a module the config
// status marks unavailable.
func (h *Harness) Health(name string) (module.Health, bool) {
	if hl, ok := h.a.sup.Health(name); ok {
		return hl, true
	}
	if why, ok := strings.CutPrefix(h.a.ConfigStatus().Modules[name], "unavailable: "); ok {
		return module.Health{State: module.StateUnavailable, Gaps: []module.Gap{{What: name, Why: why}}}, true
	}
	return module.Health{}, false
}

func (h *Harness) Kept(key string) any {
	v, _ := h.a.kept.Load(key)
	return v
}

// Fact delivers a controller fact through the same store-and-publish path as a
// verified control: it is stored for Env.Fact and published on the bus only.
func (h *Harness) Fact(f event.ControllerFact) {
	raw, err := json.Marshal(f)
	if err != nil {
		panic("agent: fact: " + err.Error())
	}
	_ = h.a.receiveFact(raw)
}

// setNow replaces the agent's wall clock (facts and windows).
func (h *Harness) setNow(f func() time.Time) { h.a.setNow(f) }

// env is the Env a module built by this harness receives.
func (h *Harness) env() Env {
	return Env{Host: h.o.Host, StateDir: h.o.StateDir, Logger: h.a.log, a: h.a}
}
