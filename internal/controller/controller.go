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
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// Alert is something an operator should see. Until the controller has its own
// event chain, alerts are logged, kept in a bounded in-memory ring and passed
// to Options.OnAlert.
type Alert struct {
	Time   time.Time
	Host   string
	Kind   string // agent.silent, agent.resumed, store.chain_error, enroll.refused, ...
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
}

const alertRing = 256

// Controller owns the store, identity, tokens and agent sessions.
type Controller struct {
	cfg   Config
	opt   Options
	log   *slog.Logger
	id    *link.Identity
	st    *store.Store
	tok   *Tokens
	now   func() time.Time
	enrMu sync.Mutex // serialises enrollment decisions

	mu     sync.Mutex
	agents map[string]*agentState
	alerts []Alert

	reg     *actions.Registry
	planKey ed25519.PrivateKey
	pmu     sync.Mutex // guards plans and pend
	plans   map[string]*planRT
	pend    map[stepKey]*pending
	ctlMu   sync.Mutex // serialises control signing and queueing
	closed  atomic.Bool
}

// New creates the data dir, identity (first run), store and token file.
func New(ctx context.Context, cfg Config, opt Options) (*Controller, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
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
	tok, err := OpenTokens(cfg.DataDir+string(os.PathSeparator)+"tokens.json", cfg.MaxLiveTokens)
	if err != nil {
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
	c := &Controller{cfg: cfg, opt: opt, log: opt.Logger, id: id, st: st, tok: tok, now: time.Now,
		agents: map[string]*agentState{}, reg: opt.Registry, planKey: pk,
		plans: map[string]*planRT{}, pend: map[stepKey]*pending{}}
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
		// Known agents start "last seen now" so a controller restart does not
		// instantly report every agent silent.
		s := c.stateLocked(a.ID)
		s.lastSeen = c.now()
	}
	return c, nil
}

// Pin is the controller's transport key pin (what agents pin).
func (c *Controller) Pin() link.Pin { return c.id.Pin }

// Store exposes the event store.
func (c *Controller) Store() *store.Store { return c.st }

// MintToken creates a one-time enrollment token for a manifest host.
func (c *Controller) MintToken(host string, ttl time.Duration) (string, error) {
	if c.opt.HostKnown != nil && !c.opt.HostKnown(host) {
		return "", ErrUnknownHost
	}
	return c.tok.Mint(host, ttl)
}

// Alerts returns the most recent alerts, oldest first.
func (c *Controller) Alerts() []Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Alert(nil), c.alerts...)
}

func (c *Controller) alert(host, kind, detail string) {
	a := Alert{Time: c.now(), Host: host, Kind: kind, Detail: detail}
	c.log.Warn("alert", "host", host, "kind", kind, "detail", detail)
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
	err = srv.Serve(ctx, ln)
	wg.Wait()
	return err
}

// Close stops plan timers and closes the store. Plans stay as persisted; a new
// controller on the same data dir resumes them.
func (c *Controller) Close() error {
	c.closed.Store(true)
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
		rt.mu.Unlock()
	}
	return c.st.Close()
}
