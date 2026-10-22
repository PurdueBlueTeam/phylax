package capture

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// Emit is the agent's event sink (agent.Emit): non-blocking, an error means
// the event was dropped.
type Emit = func(event.Event) error

// Subscribe returns a bounded stream of every event the agent publishes
// (agent.Env.Subscribe).
type Subscribe = func(buf int) (<-chan event.Event, func())

// ModuleConfig configures the capture module.
type ModuleConfig struct {
	Host     string
	StateDir string

	Interface   string // "" = all interfaces
	ScoredPorts []uint16
	Services    map[uint16]string // nil = DefaultServices
	Exclude     []netip.AddrPort  // controller link: never captured
	// LocalAddrs are this host's addresses (flow direction, freeze filter).
	// Empty reads them from the interface.
	LocalAddrs []netip.Addr
	OrgNets    []OrgNet

	Ring         RingConfig
	ScanWindow   time.Duration
	ScanTargets  int
	PcapDir      string // default <StateDir>/capture
	DiskBudget   int64
	FreezeBefore time.Duration
	FreezeAfter  time.Duration

	// Seal encrypts credential-derived fields; nil drops them.
	Seal Sealer

	// TxnRate, FlowRate and ScanRate bound events per second per class
	// (defaults 300, 300, 20); excess is dropped and counted in capture.stats.
	TxnRate, FlowRate, ScanRate float64
	StatsEvery                  time.Duration // default 60s

	// Open overrides how the packet source is opened (tests use a pcap).
	Open      func(InterfaceOptions) (Source, error)
	Subscribe Subscribe
	Logger    *slog.Logger
}

// Module is the agent's packet capture module: AF_PACKET (or a test source)
// into the engine, parsed transactions, flows and scans out as events, and
// the ring frozen to a pcap when an alert for this host asks for it.
type Module struct {
	cfg ModuleConfig

	local   atomic.Pointer[map[netip.Addr]bool]
	fz      *Freezer
	engine  atomic.Pointer[Engine]
	dropped [3]atomic.Uint64 // txn, flow, scan: rate limited
	shed    atomic.Uint64    // queue full or emit refused
	emitted atomic.Uint64
	done    chan struct{} // closed when the source has ended (finite sources)
	doneMu  sync.Once
}

// NewModule validates cfg.
func NewModule(cfg ModuleConfig) (*Module, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.TxnRate <= 0 {
		cfg.TxnRate = 300
	}
	if cfg.FlowRate <= 0 {
		cfg.FlowRate = 300
	}
	if cfg.ScanRate <= 0 {
		cfg.ScanRate = 20
	}
	if cfg.StatsEvery <= 0 {
		cfg.StatsEvery = time.Minute
	}
	if cfg.PcapDir == "" {
		if cfg.StateDir == "" {
			return nil, errors.New("capture: StateDir or PcapDir is required")
		}
		cfg.PcapDir = filepath.Join(cfg.StateDir, "capture")
	}
	if cfg.Open == nil {
		cfg.Open = OpenInterface
	}
	if _, err := NewHTTPEvents(cfg.OrgNets); err != nil {
		return nil, err
	}
	return &Module{cfg: cfg, done: make(chan struct{})}, nil
}

// Name implements the agent's Module.
func (*Module) Name() string { return "capture" }

// SourceDone is closed when a finite source (a pcap) has been fully read and
// every resulting event handed over. Live sources never close it.
func (m *Module) SourceDone() <-chan struct{} { return m.done }

// Freezer exposes the freeze-on-alert component (tests, status).
func (m *Module) Freezer() *Freezer { return m.fz }

// Engine exposes the running engine (tests, status); nil before Start.
func (m *Module) Engine() *Engine { return m.engine.Load() }

func (m *Module) isLocal(a netip.Addr) bool {
	p := m.local.Load()
	return p != nil && (*p)[a.Unmap()]
}

func (m *Module) refreshLocal() {
	set := map[netip.Addr]bool{}
	for _, a := range m.cfg.LocalAddrs {
		set[a.Unmap()] = true
	}
	if len(m.cfg.LocalAddrs) == 0 {
		var ifs []net.Interface
		if m.cfg.Interface != "" {
			if i, err := net.InterfaceByName(m.cfg.Interface); err == nil {
				ifs = append(ifs, *i)
			}
		} else {
			ifs, _ = net.Interfaces()
		}
		for _, i := range ifs {
			addrs, _ := i.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					if ad, ok := netip.AddrFromSlice(ipn.IP); ok {
						set[ad.Unmap()] = true
					}
				}
			}
		}
	}
	m.local.Store(&set)
}

type limiter struct {
	mu          sync.Mutex
	rate, burst float64
	tokens      float64
	last        time.Time
}

func newLimiter(rate float64) *limiter {
	return &limiter{rate: rate, burst: max(rate*2, 1), tokens: max(rate*2, 1), last: time.Now()}
}

func (l *limiter) take() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

const queueLen = 4096

// Start runs until ctx ends. A source error is a crash (the supervisor
// restarts the module); a finite source ending leaves the module idle but
// alive, so the ring can still be frozen.
func (m *Module) Start(ctx context.Context, emit Emit) error {
	cfg := m.cfg
	m.refreshLocal()
	conv := &Converter{Local: m.isLocal, Seal: cfg.Seal}
	if h, err := NewHTTPEvents(cfg.OrgNets); err == nil {
		conv.HTTP = h
	} else {
		return err
	}

	// Subscribe first: the agent holds locally published events for us only
	// until we have, and an alert must never find nobody listening.
	var alerts <-chan event.Event
	if cfg.Subscribe != nil {
		ch, unsub := cfg.Subscribe(1024)
		defer unsub()
		alerts = ch
	}

	q := make(chan event.Event, queueLen)
	lim := [3]*limiter{newLimiter(cfg.TxnRate), newLimiter(cfg.FlowRate), newLimiter(cfg.ScanRate)}
	push := func(class int, ev event.Event) {
		if !lim[class].take() {
			m.dropped[class].Add(1)
			return
		}
		select {
		case q <- ev: // callbacks run under the engine lock: never block here
		default:
			m.shed.Add(1)
		}
	}
	ecfg := Config{
		ScoredPorts: cfg.ScoredPorts, Services: cfg.Services, Exclude: cfg.Exclude, Ring: cfg.Ring,
		ScanWindow: cfg.ScanWindow, ScanThreshold: cfg.ScanTargets,
		OnTxn: func(t txn.Txn) {
			if ev, ok := conv.TxnEvent(t); ok {
				push(0, ev)
			}
		},
		OnFlow: func(f Flow) { push(1, conv.FlowEvent(f)) },
		OnScan: func(s Scan) { push(2, conv.ScanEvent(s)) },
	}
	eng := NewEngine(ecfg)
	m.engine.Store(eng)
	m.fz = &Freezer{Ring: eng.Ring(), Dir: cfg.PcapDir, Budget: cfg.DiskBudget, Before: cfg.FreezeBefore,
		After: cfg.FreezeAfter, Local: m.isLocal, Emit: emit, Log: cfg.Logger}

	src, err := cfg.Open(InterfaceOptions{Name: cfg.Interface,
		Filter: Filter{Ports: capPorts(cfg.ScoredPorts), Exclude: capAddrs(cfg.Exclude)}})
	if err != nil {
		return err
	}
	defer src.Close()
	ictx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // events out
		defer wg.Done()
		for {
			select {
			case ev := <-q:
				if emit(ev) != nil {
					m.shed.Add(1)
				} else {
					m.emitted.Add(1)
				}
			case <-ictx.Done():
				return
			}
		}
	}()

	runErr := make(chan error, 1)
	go func() { runErr <- Run(ictx, src, eng) }()

	stats := time.NewTicker(cfg.StatsEvery)
	defer stats.Stop()
	finished := false
	for {
		select {
		case <-ctx.Done():
			cancel()
			if runErr != nil {
				<-runErr
			}
			wg.Wait()
			m.fz.Wait()
			return nil
		case err := <-runErr:
			if err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
				cancel()
				wg.Wait()
				m.fz.Wait()
				return err
			}
			// Finite source: let the queue drain, then stay up for freezes.
			for len(q) > 0 {
				time.Sleep(time.Millisecond)
			}
			finished = true
			m.doneMu.Do(func() { close(m.done) })
			runErr = nil
		case ev := <-alerts:
			if ev.Kind == KindAlert && (ev.Agent == "" || ev.Agent == cfg.Host) {
				m.fz.OnAlert(ctx, ev)
			}
		case <-stats.C:
			m.refreshLocal()
			_ = emit(m.statsEvent(src, finished))
		}
	}
}

func (m *Module) statsEvent(src Source, finished bool) event.Event {
	es := m.engine.Load().Stats()
	ss := src.Stats()
	return event.Event{Time: time.Now(), Kind: KindStats, Priority: event.PriorityNormal, Fields: map[string]any{
		"packets": es.Packets, "kernel_drops": ss.Drops, "decode_errors": es.DecodeErrors,
		"flows_active": es.FlowsActive, "flows_ended": es.FlowsEnded, "txns": es.Txns,
		"parser_panics": es.ParserPanics, "reasm_gaps": es.ReasmGaps,
		"ring_packets": es.Ring.Packets, "ring_bytes": es.Ring.Bytes, "ring_evicted": es.Ring.Evicted, "hold_drops": es.Ring.HoldDrops,
		"events_emitted": m.emitted.Load(), "events_shed": m.shed.Load(),
		"txn_rate_dropped": m.dropped[0].Load(), "flow_rate_dropped": m.dropped[1].Load(), "scan_rate_dropped": m.dropped[2].Load(),
		"freezes_skipped": m.fz.Skipped(), "source_finished": finished,
	}}
}

func capPorts(p []uint16) []uint16 {
	if len(p) > maxFilterPorts {
		return p[:maxFilterPorts]
	}
	return p
}

func capAddrs(a []netip.AddrPort) []netip.AddrPort {
	if len(a) > 8 {
		return a[:8]
	}
	return a
}
