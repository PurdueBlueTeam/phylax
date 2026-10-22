package netmod

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/deps"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Config configures the module.
type Config struct {
	// Interval between sock_diag polls (default 2s).
	Interval time.Duration
	// Services maps "proto/port" or "port" to a service name, e.g. "tcp/22":"ssh".
	Services map[string]string
	// MaxConns bounds tracked connections (default 65536).
	MaxConns int
	// HashExe hashes owning binaries (sha256, cached by dev+inode+ctime+size).
	HashExe bool
	// ByteCounters asks the kernel for tcp_info byte counters.
	ByteCounters bool
	// ProcRoot overrides /proc (tests).
	ProcRoot string

	// NFLogGroups are the renderer's NFLOG groups for denied egress; none
	// disables the egress reader.
	NFLogGroups []uint16
	Egress      EgressConfig

	// Canary probes run every CanaryInterval (default 5m) with CanaryTimeout.
	CanaryTargets  []CanaryTarget
	CanaryInterval time.Duration
	CanaryTimeout  time.Duration

	// NoDeps disables service dependency discovery (deps.edge / deps.peer).
	NoDeps bool
	// DNS, when set, names edge destinations from recent DNS answers.
	DNS *deps.DNSCache

	Logger *slog.Logger

	// Test hooks: replace the sock_diag source, the process resolver and the
	// NFLOG packet feed.
	Source SockSource
	Procs  ProcResolver
	Feed   <-chan NFLogPacket
}

// Module is the agent module. Create with New.
type Module struct{ cfg Config }

var _ agent.Module = (*Module)(nil)

// New returns the net module.
func New(cfg Config) *Module {
	if cfg.Interval <= 0 {
		cfg.Interval = 2 * time.Second
	}
	if cfg.CanaryInterval <= 0 {
		cfg.CanaryInterval = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Module{cfg: cfg}
}

// Name implements agent.Module.
func (m *Module) Name() string { return "net" }

// Start implements agent.Module.
func (m *Module) Start(ctx context.Context, emit agent.Emit) error {
	cfg := m.cfg
	src, procs, err := defaultSources(cfg)
	if err != nil {
		return err
	}
	if cfg.Source != nil {
		src = cfg.Source
	}
	if cfg.Procs != nil {
		procs = cfg.Procs
	}
	// The resolver is not concurrency-safe; the poller and the egress
	// worker share it through this serialised wrapper.
	sp := &lockedProcs{inner: procs}

	tc := TrackerConfig{Services: cfg.Services, MaxConns: cfg.MaxConns}
	if !cfg.NoDeps {
		tc.Deps = deps.NewCollector(deps.Config{DNS: cfg.DNS})
	}
	tr := NewTracker(tc, src, sp)
	eg := NewEgress(withCanaries(cfg.Egress, cfg.CanaryTargets), src, sp)

	send := func(evs []event.Event) {
		for _, e := range evs {
			_ = emit(e) // drops are counted by the supervisor
		}
	}

	feed := cfg.Feed
	if feed == nil && len(cfg.NFLogGroups) > 0 {
		f, err := startNFLog(ctx, cfg.NFLogGroups, cfg.Logger)
		if err != nil {
			// Missing CAP_NET_ADMIN or nfnetlink_log is not fatal: keep the
			// socket telemetry and say so.
			cfg.Logger.Warn("net: egress reader unavailable", "err", err)
			_ = emit(event.Event{Time: time.Now(), Kind: KindSensorDegraded, Priority: event.PriorityHigh,
				Fields: map[string]any{"module": "net", "sensor": "nflog", "error": err.Error()}})
		} else {
			feed = f
		}
	}

	if len(cfg.CanaryTargets) > 0 {
		go m.canaryLoop(ctx, emit)
	}

	poll := time.NewTicker(cfg.Interval)
	defer poll.Stop()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	doPoll := func() {
		evs, err := tr.Poll(time.Now())
		if err != nil {
			cfg.Logger.Warn("net: poll failed", "err", err)
			return
		}
		send(evs)
	}
	doPoll()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-poll.C:
			doPoll()
		case p := <-feed: // nil channel blocks forever when disabled
			send(eg.Packet(time.Now(), p))
		case <-tick.C:
			send(eg.Tick(time.Now()))
		}
	}
}

func withCanaries(e EgressConfig, c []CanaryTarget) EgressConfig {
	e.CanaryTargets = c
	return e
}

func (m *Module) canaryLoop(ctx context.Context, emit agent.Emit) {
	t := time.NewTimer(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, tg := range m.cfg.CanaryTargets {
			if ctx.Err() != nil {
				return
			}
			_ = emit(ProbeCanary(ctx, tg, m.cfg.CanaryTimeout))
		}
		t.Reset(m.cfg.CanaryInterval)
	}
}

// ParseCanaryTarget builds a target from an address string and port.
func ParseCanaryTarget(addr string, port uint16, tag string) (CanaryTarget, error) {
	a, err := netip.ParseAddr(addr)
	return CanaryTarget{Addr: a, Port: port, Tag: tag}, err
}
