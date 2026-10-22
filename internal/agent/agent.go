package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
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
}

// Agent is the running agent.
type Agent struct {
	cfg    Config
	log    *slog.Logger
	bundle *Bundle
	pin    link.Pin
	id     *link.Identity
	sp     *spool.Spool
	dm     *deadman.Manager
	sup    *Supervisor

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
	return &Agent{cfg: cfg, log: cfg.Logger, bundle: b, pin: pin, id: id, state: st,
		notify: make(chan struct{}, 1)}, nil
}

// Pin is this agent's own key pin (what the controller records at enrollment).
func (a *Agent) Pin() link.Pin { return a.id.Pin }

// emit appends to the spool without touching the network.
func (a *Agent) emit(e event.Event) error {
	_, err := a.sp.Append(e)
	if err == nil {
		select {
		case a.notify <- struct{}{}:
		default:
		}
	}
	return err
}

// HealthSource implementation.
func (a *Agent) SpoolStats() spool.Stats          { return a.sp.Stats() }
func (a *Agent) Modules() map[string]ModuleStatus { return a.sup.Snapshot() }
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
	for k, v := range a.cfg.DeadmanHandlers {
		hs[k] = v
	}
	if a.dm, err = deadman.Open(a.cfg.Layout.DeadmanDir(), deadman.Options{Handlers: hs, Backstop: a.cfg.Backstop}); err != nil {
		return fmt.Errorf("agent: dead-man journal: %w", err)
	}
	defer a.dm.Close()
	acted, rerr := a.dm.Recover(ctx)
	for _, e := range acted {
		a.emit(event.Event{Kind: "agent.deadman_recovered", Priority: event.PriorityCritical,
			Fields: map[string]any{"id": e.ID, "node": e.NodeID, "state": string(e.State), "error": e.Error}})
	}
	if rerr != nil {
		a.log.Error("dead-man recovery", "err", rerr)
		a.emit(event.Event{Kind: "agent.deadman_recovery_error", Priority: event.PriorityCritical,
			Fields: map[string]any{"error": rerr.Error()}})
	}

	so2 := a.cfg.Supervisor
	so2.Emit, so2.Logger = a.emit, a.log
	a.sup = NewSupervisor(so2)
	if err := a.sup.Add(ModuleSpec{Module: NewHealthModule(a, a.cfg.HealthInterval)}); err != nil {
		return err
	}
	for _, m := range a.cfg.Modules {
		if err := a.sup.Add(m); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); a.sup.Run(ctx) }()
	a.emit(event.Event{Kind: "agent.start", Priority: event.PriorityHigh, Fields: map[string]any{
		"version": a.cfg.Version, "os": runtime.GOOS, "arch": runtime.GOARCH, "roles": a.bundle.Roles}})
	sdNotify("READY=1")
	go a.watchdog(ctx)

	a.connectLoop(ctx)
	cancel()
	wg.Wait()
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
			return pick(h.Config, a.placeholderConfig)(hc, v)
		case *link.Step:
			return pick3(h.Step, a.placeholderStep)(hc, v, reply)
		case *link.Fetch:
			return pick3(h.Fetch, a.placeholderFetch)(hc, v, reply)
		case *link.Control:
			return pick(h.Control, a.defaultControl)(hc, v)
		default:
			a.log.Debug("ignoring message", "type", m.MsgType())
		}
		return nil
	}})

	hello := &link.Hello{Proto: link.ProtoVersion, Host: a.bundle.Host, Version: a.cfg.Version,
		Roles: a.bundle.Roles, Caps: map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH}}
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
		return pick(a.cfg.Handlers.Config, a.placeholderConfig)(ctx, w.Config)
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
		Congestion: cong, Modules: a.sup.States(), SafeMode: a.safeMode.Load(), Drops: st.Shed}
	// TrySend: never block on a congested link; a newer heartbeat replaces a queued one.
	if err := s.TrySend(link.PrioCritical, hb); err != nil {
		a.log.Debug("heartbeat not queued", "err", err)
	}
}
