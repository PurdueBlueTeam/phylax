package agent

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/spool"
)

// Config configures an Agent.
type Config struct {
	Layout  Layout
	Version string
	Logger  *slog.Logger
	// Modules run under the supervisor besides the built-in health module.
	Modules  []ModuleSpec
	Handlers Handlers
	// Backstop is the OS dead-man timer (nil = journal and in-process timer
	// only; production passes deadman.DefaultBackstop).
	Backstop deadman.Backstop
	// DeadmanHandlers are merged over the rollback registry.
	DeadmanHandlers map[string]deadman.Handler
	// HeartbeatInterval defaults to 5 s; HealthInterval to 60 s.
	HeartbeatInterval time.Duration
	HealthInterval    time.Duration
	// Backoff for reconnects (default 1 s to 30 s).
	Backoff link.Backoff
	// Supervisor tuning (module restart backoff, budget hook).
	Supervisor SupervisorOptions
	// Spool overrides spool options (Agent is set from the bootstrap host).
	Spool spool.Options
	// MemoryLimit, if > 0, is passed to debug.SetMemoryLimit.
	MemoryLimit int64
	// DialTimeout bounds connect plus handshake (default 10 s).
	DialTimeout time.Duration
	// Exec enables execution of signed plan steps (nil = steps are rejected).
	Exec *ExecConfig
	// Factories are module factories used in addition to (and overriding by
	// name) the process-wide registry (RegisterFactory).
	Factories []Factory
}

// Agent is the running agent.
type Agent struct {
	cfg     Config
	log     *slog.Logger
	bundle  *Bundle
	pin     link.Pin
	id      *link.Identity
	sp      *spool.Spool
	dm      *deadman.Manager
	sup     *Supervisor
	exec    *execState
	ctlVer  *plan.ControlVerifier // nil when the bootstrap has no plan_key: every control is refused
	cfgVer  *plan.ConfigVerifier  // likewise: a config is never accepted unsigned
	planKey ed25519.PublicKey

	// config handling (see config.go)
	cfgKick chan struct{}
	desired *plan.AgentConfig // guarded by mu
	cfgStat ConfigStatus      // guarded by mu
	managed map[string]string // module -> settings fingerprint; configLoop only
	kept    sync.Map
	sink    Emit // harness event sink when there is no spool
	// factoriesOnly makes reconcile use cfg.Factories alone (test harness).
	factoriesOnly bool
	tapMu         sync.Mutex
	taps          []*tap
	held          []event.Event // published while a subscriber was starting; guarded by tapMu
	subWait       int
	holds         int
	holdUntil     time.Time
	execWG        sync.WaitGroup
	// runCtx is the agent's run context; steps execute under it, not under
	// the (per-connection) handler context.
	runCtx context.Context

	notify   chan struct{}
	safeMode atomic.Bool

	mu       sync.Mutex
	state    State
	linkStat LinkStatus
	attempt  int
}

// New loads the bootstrap, identity and state (generating the identity on
// first start). Call Run to start.
func New(cfg Config) (*Agent, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 5 * time.Second
	}
	if cfg.HealthInterval <= 0 {
		cfg.HealthInterval = time.Minute
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	b, err := cfg.Layout.LoadBundle()
	if err != nil {
		return nil, fmt.Errorf("agent: bootstrap: %w", err)
	}
	pin, err := b.Validate()
	if err != nil {
		return nil, err
	}
	id, err := cfg.Layout.LoadIdentity(b.Host)
	if err != nil {
		return nil, fmt.Errorf("agent: identity: %w", err)
	}
	st, err := cfg.Layout.LoadState()
	if err != nil {
		return nil, fmt.Errorf("agent: state: %w", err)
	}
	a := &Agent{cfg: cfg, log: cfg.Logger, bundle: b, pin: pin, id: id, state: st,
		notify: make(chan struct{}, 1), runCtx: context.Background(),
		cfgKick: make(chan struct{}, 1), managed: map[string]string{"health": healthDefaultFP}}
	if err := a.initExec(); err != nil {
		return nil, err
	}
	key := cfg.PlanKeyOverride()
	if len(key) == 0 {
		if key, err = b.PlanPublicKey(); err != nil {
			return nil, err
		}
	}
	if len(key) > 0 {
		a.ctlVer = &plan.ControlVerifier{Key: key, HostID: b.Host, Store: plan.FileSeqStore{Path: cfg.Layout.ControlSeq()}}
		a.cfgVer = &plan.ConfigVerifier{Key: key, HostID: b.Host, Store: plan.FileSeqStore{Path: cfg.Layout.ConfigSeq()}}
		a.planKey = key
	}
	return a, nil
}

// Pin is this agent's own key pin (what the controller records at enrollment).
func (a *Agent) Pin() link.Pin { return a.id.Pin }

// emit appends to the spool without touching the network.
func (a *Agent) emit(e event.Event) error {
	a.publish(e)
	if a.sp == nil {
		if a.sink != nil {
			return a.sink(e)
		}
		return nil
	}
	_, err := a.sp.Append(e)
	if err == nil {
		select {
		case a.notify <- struct{}{}:
		default:
		}
	}
	return err
}

// core builds an event of a declared kind. The kind and its payload struct are
// declared together, so a mismatch is a programming error: emitting a core
// event under the wrong shape must never silently drop security telemetry.
func core[T any](kind string, v T) event.Event {
	e, err := event.New(kind, v)
	if err != nil {
		panic("agent: " + err.Error())
	}
	return e
}

// HealthSource implementation.
func (a *Agent) SpoolStats() spool.Stats { return a.sp.Stats() }
func (a *Agent) Modules() map[string]ModuleStatus {
	a.mu.Lock()
	sup := a.sup
	a.mu.Unlock()
	if sup == nil {
		return map[string]ModuleStatus{}
	}
	return sup.Snapshot()
}
func (a *Agent) Link() LinkStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	l := a.linkStat
	l.Enrolled = a.state.Enrolled
	return l
}

// Run runs the agent until ctx is cancelled. Order: open spool, dead-man
// Recover (before anything else acts), start modules, then the link loop.
func (a *Agent) Run(ctx context.Context) error {
	if a.cfg.MemoryLimit > 0 {
		debug.SetMemoryLimit(a.cfg.MemoryLimit)
	}
	so := a.cfg.Spool
	so.Agent = a.bundle.Host
	var err error
	if a.sp, err = spool.Open(a.cfg.Layout.SpoolDir(), so); err != nil {
		return fmt.Errorf("agent: spool: %w", err)
	}
	defer a.sp.Close()

	hs := RollbackHandlers()
	if a.exec != nil {
		for k, v := range actions.DeadmanHandlers(a.exec.env) {
			hs[k] = v
		}
	}
	for k, v := range a.cfg.DeadmanHandlers {
		hs[k] = v
	}
	if a.dm, err = deadman.Open(a.cfg.Layout.DeadmanDir(), deadman.Options{Handlers: hs, Backstop: a.cfg.Backstop,
		OnResult: a.onDeadmanResult}); err != nil {
		return fmt.Errorf("agent: dead-man journal: %w", err)
	}
	defer a.dm.Close()
	if a.exec != nil {
		a.exec.env.Deadman = a.dm
	}
	acted, rerr := a.dm.Recover(ctx)
	for _, e := range acted {
		ev := core("agent.deadman_recovered", event.AgentDeadmanRecovered{ID: e.ID, Node: e.NodeID, State: string(e.State), Error: e.Error})
		ev.Priority = event.PriorityCritical // today's emitter: a rollback a human must see
		a.emit(ev)
	}
	if rerr != nil {
		a.log.Error("dead-man recovery", "err", rerr)
		ev := core("agent.deadman_recovery_error", event.AgentDeadmanRecoveryError{Error: rerr.Error()})
		ev.Priority = event.PriorityCritical
		a.emit(ev)
	}

	so2 := a.cfg.Supervisor
	so2.Emit, so2.Logger = a.emit, a.log
	sup := NewSupervisor(so2)
	a.mu.Lock()
	a.sup = sup
	a.mu.Unlock()
	if err := a.sup.Add(ModuleSpec{Module: NewHealthModule(a, a.cfg.HealthInterval)}); err != nil {
		return err
	}
	for _, m := range a.cfg.Modules {
		a.expectSubscriber(m)
		if err := a.sup.Add(m); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.runCtx = ctx
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.sup.Run(ctx) }()
	go func() { defer wg.Done(); a.configLoop(ctx) }()
	// Last good config first: with the controller away the modules still run.
	a.loadPersistedConfig()
	a.emit(core("agent.start", event.AgentStart{Version: a.cfg.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, Roles: a.bundle.Roles}))
	sdNotify("READY=1")
	go a.watchdog(ctx)

	a.connectLoop(ctx)
	cancel()
	wg.Wait()
	a.execWG.Wait()
	sdNotify("STOPPING=1")
	return nil
}

func (a *Agent) watchdog(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			sdNotify("WATCHDOG=1")
		case <-ctx.Done():
			return
		}
	}
}

func (a *Agent) connectLoop(ctx context.Context) {
	bo := a.cfg.Backoff
	for ctx.Err() == nil {
		established, err := a.session(ctx)
		a.mu.Lock()
		a.linkStat.Connected = false
		if err != nil {
			a.linkStat.LastError = err.Error()
		}
		a.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		if established {
			bo.Reset()
		}
		d := bo.Next()
		a.log.Warn("link down", "err", err, "retry_in", d)
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return
		}
	}
}

type spoolSource struct{ sp *spool.Spool }

func (s spoolSource) Events(after uint64, max int) ([]event.Event, error) {
	return s.sp.ResendFrom(after+1, max)
}

// session runs one connection. established reports whether it got as far as
// welcome and the controller's first ack.
func (a *Agent) session(ctx context.Context) (established bool, err error) {
	a.mu.Lock()
	addr := a.bundle.Controllers[a.attempt%len(a.bundle.Controllers)]
	a.attempt++
	enrolled := a.state.Enrolled
	a.mu.Unlock()

	conn, err := link.Dial(ctx, addr, link.DialOptions{Identity: a.id, ServerPin: a.pin, ALPN: link.ALPNAgent, Timeout: a.cfg.DialTimeout})
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	welcome := make(chan struct{})
	var once sync.Once
	var sess *link.Session
	reply := func(c context.Context, p link.Priority, m link.Message) error { return sess.Send(c, p, m) }
	h := a.cfg.Handlers
	sess = link.NewSession(conn, link.Options{Role: link.RoleAgent, Handler: func(hc context.Context, m link.Message) error {
		switch v := m.(type) {
		case *link.Welcome:
			if err := a.onWelcome(hc, v, enrolled); err != nil {
				return err
			}
			once.Do(func() { close(welcome) })
		case *link.Config:
			return pick(h.Config, a.handleConfig)(hc, v)
		case *link.Step:
			return a.stepHandler()(hc, v, reply)
		case *link.Fetch:
			return pick3(h.Fetch, a.placeholderFetch)(hc, v, reply)
		case *link.Control:
			return a.handleControl(hc, v, reply)
		default:
			a.log.Debug("ignoring message", "type", m.MsgType())
		}
		return nil
	}})

	hello := &link.Hello{Proto: link.ProtoVersion, Minor: link.ProtoMinor, Deadman: a.deadmanReport(), Host: a.bundle.Host, Version: a.cfg.Version,
		Roles: a.bundle.Roles, Caps: map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "modules": a.moduleManifests()}}
	hello.LastSeq, _ = a.sp.Head()
	if !enrolled {
		hello.Token = a.bundle.Token
	}
	if err := sess.Send(ctx, link.PrioCritical, hello); err != nil {
		return false, err
	}
	runErr := make(chan error, 1)
	go func() { runErr <- sess.Run(ctx) }()
	defer func() { cancel(); sess.Close(); <-runErr }()

	wctx, wcancel := context.WithTimeout(ctx, a.cfg.DialTimeout)
	defer wcancel()
	select {
	case <-welcome:
	case <-sess.Done():
		return false, sess.Err()
	case <-wctx.Done():
		return false, errors.New("timed out waiting for welcome")
	}
	if _, err := sess.WaitFirstAck(wctx); err != nil {
		return false, fmt.Errorf("waiting for first ack: %w", err)
	}
	a.mu.Lock()
	a.linkStat.Connected, a.linkStat.LastError = true, ""
	a.linkStat.Connects++
	a.linkStat.LastConnect = time.Now()
	a.mu.Unlock()
	a.sp.Rewind()
	a.flushResults(ctx, sess)

	go a.ackPump(ctx, sess)
	up := &link.Uplink{Session: sess, Source: spoolSource{a.sp}, Notify: a.notify}
	upErr := make(chan error, 1)
	go func() { upErr <- up.Run(ctx) }()

	hb := time.NewTicker(a.cfg.HeartbeatInterval)
	defer hb.Stop()
	a.heartbeat(sess)
	for {
		select {
		case <-hb.C:
			a.heartbeat(sess)
		case err := <-upErr:
			return true, err
		case <-sess.Done():
			return true, sess.Err()
		case <-ctx.Done():
			return true, ctx.Err()
		}
	}
}

func pick[T any](f, def func(context.Context, T) error) func(context.Context, T) error {
	if f != nil {
		return f
	}
	return def
}

func pick3[T any](f, def func(context.Context, T, Reply) error) func(context.Context, T, Reply) error {
	if f != nil {
		return f
	}
	return def
}

func (a *Agent) onWelcome(ctx context.Context, w *link.Welcome, wasEnrolled bool) error {
	if !wasEnrolled {
		if !w.Enrolled {
			return errors.New("controller did not confirm enrollment")
		}
		// Persist only after welcome (design: Enrollment step 3), then drop the token.
		if err := a.cfg.Layout.SaveState(State{Enrolled: true}); err != nil {
			return fmt.Errorf("persist enrollment: %w", err)
		}
		a.mu.Lock()
		a.state.Enrolled = true
		b := *a.bundle
		a.mu.Unlock()
		b.Token = ""
		if err := a.cfg.Layout.SaveBundle(&b); err != nil {
			a.log.Warn("could not scrub token from bootstrap", "err", err)
		}
		a.log.Info("enrolled")
	}
	if w.Config != nil {
		return pick(a.cfg.Handlers.Config, a.handleConfig)(ctx, w.Config)
	}
	return nil
}

func (a *Agent) ackPump(ctx context.Context, s *link.Session) {
	for {
		ch := s.AckChanged()
		if seq, ok := s.Acked(); ok {
			if err := a.sp.Ack(seq); err != nil && !errors.Is(err, spool.ErrClosed) {
				a.log.Warn("spool ack", "err", err)
			}
		}
		select {
		case <-ch:
		case <-s.Done():
			return
		case <-ctx.Done():
			return
		}
	}
}

func (a *Agent) heartbeat(s *link.Session) {
	st := a.sp.Stats()
	cong := st.State
	if cong == "" {
		cong = spool.StateOK
	}
	hb := &link.Heartbeat{Seq: st.HeadSeq, HostClock: time.Now().UTC(), SpoolDepth: st.HeadSeq - st.AckSeq,
		Congestion: cong, Modules: a.heartbeatModules(), Health: a.heartbeatHealth(), SafeMode: a.safeMode.Load(), Drops: st.Shed}
	// TrySend: never block on a congested link; a newer heartbeat replaces a queued one.
	if err := s.TrySend(link.PrioCritical, hb); err != nil {
		a.log.Debug("heartbeat not queued", "err", err)
	}
}

// PlanKeyOverride is Exec.PlanKey when set.
func (c Config) PlanKeyOverride() ed25519.PublicKey {
	if c.Exec != nil {
		return c.Exec.PlanKey
	}
	return nil
}

// deadmanReport lists the dead-man entries that belong to plan nodes, newest
// first and bounded, for hello: a restarted controller reconciles with it.
func (a *Agent) deadmanReport() []link.DeadmanEntry {
	if a.dm == nil {
		return nil
	}
	entries, err := a.dm.List()
	if err != nil {
		a.log.Warn("dead-man list for hello", "err", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ArmedAt.After(entries[j].ArmedAt) })
	var out []link.DeadmanEntry
	for _, e := range entries {
		if e.NodeID == "" || len(out) >= link.MaxDeadmanEntries || len(e.NodeID) > 2*1024+1 {
			continue
		}
		out = append(out, link.DeadmanEntry{ID: e.ID, Node: e.NodeID, State: string(e.State), Deadline: e.Deadline.Unix()})
	}
	return out
}

// heartbeatModules is the supervisor's module states plus the config status
// under the reserved name ConfigStatusModule.
func (a *Agent) heartbeatModules() map[string]string {
	m := a.sup.States()
	m[ConfigStatusModule] = a.configHeartbeat()
	return m
}

// heartbeatHealth is the supervisor's merged health for every module, plus a
// config-status module that could not be built (unavailable: why) as a gap.
func (a *Agent) heartbeatHealth() map[string]module.Health {
	a.mu.Lock()
	sup := a.sup
	a.mu.Unlock()
	out := map[string]module.Health{}
	if sup != nil {
		for name := range sup.Snapshot() {
			if h, ok := sup.Health(name); ok {
				out[name] = h
			}
		}
	}
	for name, v := range a.ConfigStatus().Modules {
		if name == ConfigStatusModule {
			continue
		}
		if why, ok := strings.CutPrefix(v, "unavailable: "); ok {
			out[name] = module.Health{State: module.StateUnavailable, Gaps: []module.Gap{{What: name, Why: why}}}
		}
	}
	return out
}
