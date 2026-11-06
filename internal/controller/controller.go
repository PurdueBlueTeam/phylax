package controller

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/bench"
	"github.com/PurdueBlueTeam/phylax/internal/enroll"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
)

// Alert is something an operator should see. Until the controller has its own
// event chain, alerts are logged, kept in a bounded in-memory ring and passed
// to Options.OnAlert.
type Alert struct {
	Time   time.Time
	Host   string
	Kind   string // agent.silent, agent.resumed, store.chain_error, plan.failed, enroll.alert, ...
	Reason string // plan.failed and enroll.alert: which failure or enrollment refusal
	Detail string
}

// Options are the non-file knobs of a Controller.
type Options struct {
	Logger *slog.Logger
	// HostKnown reports whether a host name is in the manifest; nil allows any.
	HostKnown func(host string) bool
	// OnAlert is called (synchronously, keep it quick) for every alert.
	OnAlert func(Alert)
	Version string
	// Advertise is the controller host:port hosts see (serve -advertise).
	// Empty means the bootstrap handler uses the request Host.
	Advertise string

	// Registry is the action catalog plans are validated against (default
	// actions.Core()).
	Registry *actions.Registry
	// Guard supplies the scoring guard for a host (the manifest-backed one in
	// production); the dry run lints every node with it. Nil = no lint here
	// (agents still enforce their own guard).
	Guard func(host string) actions.ScoringGuard
	// StepTimeout bounds the wait for a step result (default 2m).
	StepTimeout time.Duration
	// StepValidity is how long a signed step stays valid (default 5m).
	StepValidity time.Duration
	// OnStepResult observes every verified step result before it is acted on.
	// Returning true drops the result and the agent's link (fault injection
	// for tests; production leaves it nil).
	OnStepResult func(StepEvent) bool
	// OnStepSent observes every signed step handed to an agent session.
	OnStepSent func(host string, s *link.Step)
	// OnControlSent observes every signed control handed to an agent session.
	OnControlSent func(host string, c *link.Control)
	// ControlValidity is how long a signed control stays valid (default 60s).
	ControlValidity time.Duration
	// ResumeGrace is how long, after a restart, a resumed plan waits for the
	// agents of its nodes to reconnect before it fails applies for absent
	// hosts (default StepTimeout).
	ResumeGrace time.Duration
	// Vault holds the honeytoken secret material (deception_registry.go).
	// Nil disables honeytoken generation; plans never carry secrets either way.
	Vault SecretVault
	// Probe checks a scored service for auto plans and gate: auto.
	Probe func(ctx context.Context, service string) error
	// GatePoll is how often an auto gate is re-evaluated (default 1s).
	GatePoll time.Duration
	// MaxHostInflight bounds the steps in flight per host (default 6, below
	// the agent's 8-step cap so a valid plan never sees a busy answer).
	MaxHostInflight int
	// BusyRetry is how long to wait before re-sending a step the agent
	// answered busy (default 2s).
	BusyRetry time.Duration
	// EnrollTimer arms the enrollment window timer (WatchEnrollment); default
	// time.AfterFunc. Tests drive it so no test waits a real window.
	EnrollTimer func(d time.Duration, f func()) (stop func())
	// QuotaUsed reports the data disk's used percentage; nil reads the
	// filesystem holding DataDir. Tests install a fixed value to drive the
	// shed levels.
	QuotaUsed func() (usedPct float64, err error)
}

const alertRing = 256

// Controller owns the store, identity, tokens and agent sessions.
type Controller struct {
	cfg   Config
	opt   Options
	log   *slog.Logger
	id    *link.Identity
	st    *store.Store
	enr   *enroll.Enroller
	now   func() time.Time
	clk   clock
	enrMu sync.Mutex // serialises enrollment decisions

	mu     sync.Mutex
	agents map[string]*agentState
	alerts []Alert

	// restoreWait is the hosts a restored controller still waits for before
	// it signs (restorewait.go); persisted under restoreWaitKey.
	rwmu        sync.Mutex
	restoreWait map[string]bool

	reg     *actions.Registry
	planKey ed25519.PrivateKey
	pmu     sync.Mutex // guards plans and pend
	plans   map[string]*planRT
	pend    map[stepKey]*pending
	ctlMu   sync.Mutex // serialises control signing and queueing
	chainMu sync.Mutex // serialises the controller-origin event chain (chain.go)
	closed  atomic.Bool
	cfgs    cfgState // agent config generation (agentconfig.go)
	dx      *devExec // controller-side device/Splunk execution (devexec_run.go)
	checks  *ChecksHub

	enrWatchMu sync.Mutex
	enrWatch   *enrollWatch // the active enrollment watch (enrollwatch.go), nil when none

	autoMu sync.Mutex // serialises attempt-ledger read-modify-write (auto.go)

	honey    honeyState // honeytoken registry (deception_registry.go)
	honeyGen sync.Mutex // serialises GenerateHoneytokens

	// module seams (W1); later tasks fill these in.
	modBackoffMin    time.Duration
	analysisDeadline time.Duration
	bus              *eventBus

	// probeRetry is the wait before one scorer-mimic probe retry (5s).
	probeRetry time.Duration

	// quota is the controller data disk's shed level (quota.go).
	quota *store.Quota

	// bs counts what the bench records: stored events per class, latency,
	// gaps, connects and down time (benchstats.go).
	bs benchStats
	// benchLog is the recorder's file while Serve runs (bench.go).
	benchLog *bench.Log

	modMu   sync.Mutex
	mods    map[string]*moduleRunState
	runMu   sync.Mutex
	running map[string]bool
	uiMu    sync.Mutex
	ui      *ui.Server
	manMu   sync.Mutex // serialises overrides.yml writes and manifest reloads
}

// New creates the data dir, identity (first run), store and token file.
func New(ctx context.Context, cfg Config, opt Options) (*Controller, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Advertise == "" {
		cfg.Advertise = opt.Advertise
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	id, err := link.LoadOrCreateIdentity(cfg.IdentityPath, "phylax-controller")
	if err != nil {
		return nil, fmt.Errorf("controller identity: %w", err)
	}
	st, err := store.Open(ctx, cfg.DataDir+string(os.PathSeparator)+"phylax.db")
	if err != nil {
		return nil, err
	}
	// The controller's own events live on a chain like an agent's, keyed by the
	// controller identity (chain.go). Enrolling is idempotent.
	if err := st.EnrollAgent(ctx, ControllerAgent, id.Pin[:]); err != nil {
		st.Close()
		return nil, err
	}
	pk, err := loadPlanKey(filepath.Join(cfg.DataDir, "plan.key"))
	if err != nil {
		st.Close()
		return nil, err
	}
	if opt.Registry == nil {
		opt.Registry = actions.Core()
	}
	if opt.StepTimeout <= 0 {
		opt.StepTimeout = 2 * time.Minute
	}
	if opt.StepValidity <= 0 {
		opt.StepValidity = 5 * time.Minute
	}
	if opt.ResumeGrace <= 0 {
		opt.ResumeGrace = opt.StepTimeout
	}
	if opt.GatePoll <= 0 {
		opt.GatePoll = time.Second
	}
	if opt.MaxHostInflight <= 0 {
		opt.MaxHostInflight = defaultMaxHostInflight
	}
	if opt.BusyRetry <= 0 {
		opt.BusyRetry = defaultBusyRetry
	}
	c := &Controller{cfg: cfg, opt: opt, log: opt.Logger, id: id, st: st, now: time.Now, clk: realClock{},
		agents: map[string]*agentState{}, reg: opt.Registry, planKey: pk,
		plans: map[string]*planRT{}, pend: map[stepKey]*pending{},
		bus: newEventBus(), mods: map[string]*moduleRunState{}, running: map[string]bool{},
		probeRetry: 5 * time.Second, restoreWait: map[string]bool{}}
	enr, err := enroll.New(enroll.Options{
		DataDir: cfg.DataDir, MaxLiveTokens: cfg.MaxLiveTokens, Store: st, Identity: id,
		PlanKey:    pk.Public().(ed25519.PublicKey),
		ReleaseDir: cfg.ReleaseDir,
		Advertise:  opt.Advertise,
		HostKnown:  opt.HostKnown, Emit: c.EmitController, Alert: c.enrollAlert,
		Connected:  func(h string) bool { s, ok := c.AgentStatus(h); return ok && s.Connected },
		Disconnect: c.disconnectAgent,
	})
	if err != nil {
		st.Close()
		return nil, err
	}
	c.enr = enr
	// The controller-side executor exists from the start, so a module action
	// runs without EnableDeviceExec; that call only adds the device directory.
	c.dx = newDevExec(c, opt)
	used := opt.QuotaUsed
	if used == nil {
		used = func() (float64, error) { return diskUsedPct(cfg.DataDir) }
	}
	c.quota = store.NewQuota(used)
	st.SetQuota(c.quota)
	c.checks = newChecksHub(c)
	if err := c.loadConfigRecs(); err != nil {
		st.Close()
		return nil, err
	}
	if err := c.loadHoneytokens(ctx); err != nil {
		st.Close()
		return nil, err
	}
	// Alert-queue rows (attributed against the honeytoken registry loaded
	// above) and check results are written in the ingest transaction;
	// anything stored before that (or lost) is replayed now.
	st.SetIngestHook(c.ingestHook)
	c.replayAgentAlerts(ctx)
	c.checks.rebuild(ctx)
	// Unfinished plans come back from the store; running ones resume when
	// their agents reconnect (restore.go).
	if err := c.loadPlans(ctx); err != nil {
		st.Close()
		return nil, err
	}
	ags, err := st.Agents(ctx)
	if err != nil {
		st.Close()
		return nil, err
	}
	for _, a := range ags {
		// The controller's own chain is not an agent: no liveness state, so
		// the silence watcher and the agents page never see it.
		if a.ID == ControllerAgent {
			continue
		}
		// Known agents start "last seen now" so a controller restart does not
		// instantly report every agent silent.
		s := c.stateLocked(a.ID)
		s.lastSeen = c.now()
	}
	if err := c.loadRestoreWait(ctx); err != nil {
		st.Close()
		return nil, err
	}
	return c, nil
}

// Pin is the controller's transport key pin (what agents pin).
func (c *Controller) Pin() link.Pin { return c.id.Pin }

// Store exposes the event store.
func (c *Controller) Store() *store.Store { return c.st }

// Enroller exposes the core enrollment path.
func (c *Controller) Enroller() *enroll.Enroller { return c.enr }

// Alerts returns the most recent alerts, oldest first.
func (c *Controller) Alerts() []Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Alert(nil), c.alerts...)
}

func (c *Controller) alert(host, kind, detail string) {
	c.alertRow(host, kind, "", detail)
	c.alertEvent(host, kind, detail)
}

// alertRow records the operator alert in the ring, logs it and notifies
// OnAlert.
func (c *Controller) alertRow(host, kind, reason, detail string) {
	a := Alert{Time: c.now(), Host: host, Kind: kind, Reason: reason, Detail: detail}
	c.log.Warn("alert", "host", host, "kind", kind, "reason", reason, "detail", detail)
	c.mu.Lock()
	c.alerts = append(c.alerts, a)
	if len(c.alerts) > alertRing {
		c.alerts = c.alerts[len(c.alerts)-alertRing:]
	}
	c.mu.Unlock()
	if c.opt.OnAlert != nil {
		c.opt.OnAlert(a)
	}
}

// alertTyped records the operator alert row and emits the declared alert event
// that explains it. The event is built with event.New from its declared
// payload, so it validates and the store's ingest hook gives it an alert-queue
// row. Use it instead of alert when the kind's payload is not {host, detail},
// and pass the priority the design's table gives this event (plan.failed and
// enroll.alert decide their alert row per reason).
func (c *Controller) alertTyped(host, reason, detail string, priority event.Priority, kind string, payload any) {
	c.alertRow(host, kind, reason, detail)
	e, err := event.New(kind, payload)
	if err != nil {
		c.log.Error("cannot build alert event", "host", host, "kind", kind, "err", err)
		return
	}
	e.Priority = priority
	if _, err := c.EmitController(context.Background(), e); err != nil {
		c.log.Error("cannot emit alert event", "host", host, "kind", kind, "err", err)
	}
}

// planFailed emits the one plan-failure kind and its alert row. A dead-man or
// rollback failure is critical; a missing or unverifiable step result high.
func (c *Controller) planFailed(host string, f event.PlanFailed, detail string) {
	prio := event.PriorityCritical
	if f.Reason == event.ReasonStepTimeout || f.Reason == event.ReasonBadResult {
		prio = event.PriorityHigh
	}
	f.Host, f.Detail = host, detail
	c.alertTyped(host, f.Reason, detail, prio, event.KindPlanFailed, f)
}

// enrollAlert emits the one enrollment-alert kind for a refused, mismatched or
// reused key. A binary-hash mismatch is critical; the others high.
func (c *Controller) enrollAlert(host, reason, detail string) {
	prio := event.PriorityHigh
	if reason == event.ReasonHashMismatch {
		prio = event.PriorityCritical
	}
	c.alertTyped(host, reason, detail, prio, event.KindEnrollAlert,
		event.EnrollAlert{Reason: reason, Host: host, Detail: detail})
}

// alertEvent puts an operator alert on the controller's event chain when the
// kind is a declared event kind: the alert then survives in the store, with
// its alert-queue row, instead of only in the ring. Kinds that are not
// declared (store.chain_error, config.generate_failed, sla.*) stay ring-only,
// and a declared kind whose payload is not {host, detail} is not forced into
// one.
func (c *Controller) alertEvent(host, kind, detail string) {
	ty, ok := event.Lookup(kind)
	if !ok {
		return
	}
	e := event.Event{Kind: kind, Schema: ty.Schema, Priority: ty.Priority,
		Fields: map[string]any{"host": host, "detail": detail}}
	if err := event.Validate(e); err != nil {
		c.log.Error("alert event does not validate; not stored", "host", host, "kind", kind, "err", err)
		return
	}
	if _, err := c.EmitController(context.Background(), e); err != nil {
		c.log.Error("cannot emit alert event", "host", host, "kind", kind, "err", err)
	}
}

// Run listens on the configured address and serves until ctx is cancelled.
func (c *Controller) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", c.cfg.AgentListen)
	if err != nil {
		return err
	}
	return c.Serve(ctx, ln)
}

// Serve serves agents on ln until ctx is cancelled, then waits for all
// sessions to finish. It does not close the store; call Close afterwards.
func (c *Controller) Serve(ctx context.Context, ln net.Listener) error {
	srv, err := link.NewServer(link.ServerOptions{
		Identity: c.id,
		// Unknown keys are admitted to the handshake so they can enroll; the
		// hello handler decides. An unenrolled key is never treated as authenticated.
		Check:         func(link.Pin) error { return nil },
		Handlers:      map[string]link.Handler{link.ALPNAgent: c.handleAgent},
		Bootstrap:     c.enr.Bootstrap(),
		MaxHandshakes: c.cfg.MaxHandshakes,
		MaxConns:      c.cfg.MaxConns,
		Logger:        c.log,
	})
	if err != nil {
		return err
	}
	c.log.Info("controller listening", "addr", ln.Addr().String(), "pin", c.id.Pin.String())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); c.watchSilence(ctx) }()
	wg.Add(1)
	go func() { defer wg.Done(); c.startQuota(ctx, quotaSampleEvery) }()
	if err := c.startBench(ctx, &wg); err != nil {
		c.log.Warn("bench recorder off", "err", err)
	}
	err = srv.Serve(ctx, ln)
	wg.Wait()
	return err
}

// Close stops plan timers and closes the store. Plans stay as persisted; a new
// controller on the same data dir resumes them.
func (c *Controller) Close() error {
	c.closed.Store(true)
	c.enrWatchMu.Lock()
	if c.enrWatch != nil && c.enrWatch.stop != nil {
		c.enrWatch.stop()
	}
	c.enrWatch = nil
	c.enrWatchMu.Unlock()
	c.pmu.Lock()
	for k, pd := range c.pend {
		if pd.timer != nil {
			pd.timer.Stop()
		}
		delete(c.pend, k)
	}
	c.pmu.Unlock()
	// Wait out any plan code still holding a plan lock.
	c.pmu.Lock()
	rts := make([]*planRT, 0, len(c.plans))
	for _, rt := range c.plans {
		rts = append(rts, rt)
	}
	c.pmu.Unlock()
	for _, rt := range rts {
		rt.mu.Lock()
		for _, gs := range rt.gates {
			if gs.timer != nil {
				gs.timer.Stop()
			}
		}
		rt.mu.Unlock()
	}
	err := c.st.Close()
	if berr := c.closeBench(); berr != nil && err == nil {
		err = berr
	}
	return err
}
