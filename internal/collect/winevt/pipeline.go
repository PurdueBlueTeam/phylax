package winevt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Errors a Source/Opener returns so the pipeline can react.
var (
	// ErrChannelNotFound: the channel does not exist (e.g. Sysmon not installed
	// yet). The worker retries every RetryInterval.
	ErrChannelNotFound = errors.New("winevt: channel not found")
	// ErrBookmarkStale: the bookmarked record no longer exists (log cleared or
	// wrapped) or the bookmark is invalid. The pipeline records a gap, drops
	// the bookmark and resubscribes from the oldest available record.
	ErrBookmarkStale = errors.New("winevt: bookmark stale")
)

// Batch is what a Source returns from Next.
type Batch struct {
	// Events are rendered event XML documents, oldest first.
	Events [][]byte
	// Bookmark is the opaque bookmark positioned after the last event of this
	// batch ("" when Events is empty).
	Bookmark string
}

// Source is one open subscription. Next blocks until events are available, ctx
// is cancelled (return ctx.Err()) or the subscription fails.
type Source interface {
	Next(ctx context.Context) (Batch, error)
	Close() error
}

// Opener opens a subscription. bookmark=="" means no saved position: start at
// the oldest record when fromOldest, otherwise at future events only.
type Opener func(ctx context.Context, ch Channel, bookmark string, fromOldest bool) (Source, error)

// ChannelStats is a snapshot of one channel for heartbeats.
type ChannelStats struct {
	State        string // starting, ok, unavailable, error
	Received     uint64
	Emitted      uint64
	Filtered     uint64
	ParseErrors  uint64
	QueueDropped uint64
	EmitDropped  uint64
	LastRecordID uint64
	Resets       uint64 // stale-bookmark resubscriptions
	LastError    string
}

type item struct {
	xml      []byte
	bookmark string // set on bookmark-only items
}

type worker struct {
	m     *Module
	ch    Channel
	st    ChannelStats
	mu    sync.Mutex
	gaps  gapAcc
	emit  agent.Emit
	log   *slog.Logger
	lastM uint64 // last record id seen by the consumer, for log-clear detection
}

func (w *worker) stat(f func(*ChannelStats)) {
	w.mu.Lock()
	f(&w.st)
	w.mu.Unlock()
}

// run keeps one channel subscribed until ctx ends.
func (w *worker) run(ctx context.Context) {
	fromOldest := false
	var outage bool
	delay := w.m.cfg.RetryInterval
	for ctx.Err() == nil {
		err := w.session(ctx, fromOldest)
		if ctx.Err() != nil {
			return
		}
		fromOldest = false
		// A stale/invalid verdict only makes sense when a bookmark was in use;
		// otherwise (e.g. a rejected query) retrying from oldest would spin.
		hadBM := w.m.bm.Get(w.ch.Name) != ""
		switch {
		case errors.Is(err, ErrBookmarkStale) && hadBM:
			w.m.bm.Clear(w.ch.Name)
			w.stat(func(s *ChannelStats) { s.Resets++; s.LastError = err.Error() })
			w.emitGap("bookmark_stale", 1, 0, 0)
			fromOldest = true
			continue
		case errors.Is(err, ErrChannelNotFound):
			w.stat(func(s *ChannelStats) { s.State, s.LastError = "unavailable", err.Error() })
			if !outage {
				w.emitGap("channel_unavailable", 1, 0, 0)
				outage = true
			}
		case err != nil:
			w.log.Warn("winevt: subscription failed", "channel", w.ch.Name, "err", err)
			w.stat(func(s *ChannelStats) { s.State, s.LastError = "error", err.Error() })
			if !outage {
				w.emitGap("subscription_error", 1, 0, 0)
				outage = true
			}
		default:
			outage = false
		}
		select {
		case <-ctx.Done():
		case <-w.m.after(delay):
		}
	}
}

// session opens the subscription and pumps events until error or ctx end.
func (w *worker) session(ctx context.Context, fromOldest bool) error {
	bm := w.m.bm.Get(w.ch.Name)
	if bm == "" && w.m.cfg.FromOldest {
		fromOldest = true
	}
	src, err := w.m.open(ctx, w.ch, bm, fromOldest)
	if err != nil {
		return err
	}
	defer src.Close()
	w.stat(func(s *ChannelStats) { s.State, s.LastError = "ok", "" })

	q := make(chan item, w.m.cfg.QueueSize)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); w.consume(q) }()
	defer func() { close(q); wg.Wait() }()

	for {
		b, err := src.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				w.push(q, b)
				return nil
			}
			w.push(q, b)
			return err
		}
		w.push(q, b)
	}
}

// push queues a batch. Events wait up to QueueWait for room, then are dropped
// and counted as a telemetry gap; the bookmark item is always delivered (the
// consumer never blocks on the network, so this terminates).
func (w *worker) push(q chan item, b Batch) {
	for _, x := range b.Events {
		w.stat(func(s *ChannelStats) { s.Received++ })
		select {
		case q <- item{xml: x}:
			continue
		default:
		}
		t := time.NewTimer(w.m.cfg.QueueWait)
		select {
		case q <- item{xml: x}:
			t.Stop()
		case <-t.C:
			w.stat(func(s *ChannelStats) { s.QueueDropped++ })
			w.gaps.add("queue_full", quickRecordID(x))
		}
	}
	if b.Bookmark != "" {
		q <- item{bookmark: b.Bookmark}
	}
}

func (w *worker) consume(q chan item) {
	tick := time.NewTicker(w.m.cfg.GapFlushInterval)
	defer tick.Stop()
	pending := false
	flush := func() {
		w.flushGaps()
		if err := w.m.bm.SaveIfDue(); err != nil {
			w.log.Warn("winevt: bookmark save failed", "err", err)
		}
	}
	for {
		select {
		case it, ok := <-q:
			if !ok {
				w.flushGaps()
				if err := w.m.bm.Flush(); err != nil {
					w.log.Warn("winevt: bookmark flush failed", "err", err)
				}
				return
			}
			if it.xml != nil {
				w.handle(it.xml)
				pending = true
				continue
			}
			w.m.bm.Set(w.ch.Name, it.bookmark)
			pending = false
			flush()
		case <-tick.C:
			if !pending {
				flush()
			} else {
				w.flushGaps()
			}
		}
	}
}

func (w *worker) handle(x []byte) {
	r, err := ParseXML(x)
	if err != nil {
		w.stat(func(s *ChannelStats) { s.ParseErrors++ })
		w.gaps.add("parse_error", quickRecordID(x))
		return
	}
	if r.RecordID != 0 {
		if r.RecordID < w.lastM {
			// Record ids restart after a log clear: informational gap marker.
			w.gaps.add("record_id_reset", r.RecordID)
		}
		w.lastM = r.RecordID
		w.stat(func(s *ChannelStats) { s.LastRecordID = r.RecordID })
	}
	if r.Channel == "" {
		r.Channel = w.ch.Name
	}
	if !w.ch.Match(r) {
		w.stat(func(s *ChannelStats) { s.Filtered++ })
		return
	}
	for _, e := range w.m.mapper.Map(r) {
		if err := w.emit(e); err != nil {
			w.stat(func(s *ChannelStats) { s.EmitDropped++ })
			w.gaps.add("emit_refused", r.RecordID)
			continue
		}
		w.stat(func(s *ChannelStats) { s.Emitted++ })
	}
}

// ---- gap accounting ----

type gapAcc struct {
	mu sync.Mutex
	m  map[string]*gapRec
}

type gapRec struct {
	count      uint64
	from, to   time.Time
	rmin, rmax uint64
}

func (g *gapAcc) add(reason string, rid uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.m == nil {
		g.m = map[string]*gapRec{}
	}
	r := g.m[reason]
	now := time.Now().UTC()
	if r == nil {
		r = &gapRec{from: now}
		g.m[reason] = r
	}
	r.count++
	r.to = now
	if rid != 0 {
		if r.rmin == 0 || rid < r.rmin {
			r.rmin = rid
		}
		if rid > r.rmax {
			r.rmax = rid
		}
	}
}

func (w *worker) flushGaps() {
	w.gaps.mu.Lock()
	m := w.gaps.m
	w.gaps.m = nil
	w.gaps.mu.Unlock()
	for reason, r := range m {
		w.sendGap(reason, r.count, r.from, r.to, r.rmin, r.rmax)
	}
}

func (w *worker) emitGap(reason string, count uint64, rmin, rmax uint64) {
	now := time.Now().UTC()
	w.sendGap(reason, count, now, now, rmin, rmax)
}

func (w *worker) sendGap(reason string, count uint64, from, to time.Time, rmin, rmax uint64) {
	f := map[string]any{
		"source": "winevt:" + w.ch.Name, "reason": reason, "count": count,
		"from": from.Format(time.RFC3339Nano), "to": to.Format(time.RFC3339Nano),
		"channel": w.ch.Name,
	}
	if rmin != 0 {
		f["from_record"], f["to_record"] = strconv.FormatUint(rmin, 10), strconv.FormatUint(rmax, 10)
	}
	_ = w.emit(event.Event{Kind: "telemetry_gap", Priority: event.PriorityHigh, Time: to, Fields: f})
}

// ---- module ----

// Config configures the module.
type Config struct {
	// Channels to subscribe to; default DefaultChannels().
	Channels []Channel
	// BookmarkPath is the bookmark file (required).
	BookmarkPath string
	// QueueSize bounds the per-channel queue (default 4096 events).
	QueueSize int
	// QueueWait is how long the reader waits for queue room before dropping an
	// event and recording a gap (default 2s).
	QueueWait time.Duration
	// RetryInterval between reopen attempts (default 30s).
	RetryInterval time.Duration
	// GapFlushInterval is how often accumulated gaps are emitted (default 5s).
	GapFlushInterval time.Duration
	// BookmarkSaveInterval coalesces bookmark writes (default 1s).
	BookmarkSaveInterval time.Duration
	// FromOldest starts channels with no bookmark at the oldest record instead
	// of future events only (default false: avoid flooding on first start).
	FromOldest bool
	// Host overrides the host name in events.
	Host string
	// DropExe excludes the agent's own executable (see Mapper.DropExe).
	DropExe []string
	// SysmonHints are service/driver names Sysmon was installed under.
	SysmonHints []string
	// SysmonInterval is how often Sysmon is probed (default 60s).
	SysmonInterval time.Duration
	// Open overrides the platform subscription opener (tests).
	Open Opener
	// Probe overrides the platform Sysmon probe (tests).
	Probe  func(hints []string) (SysmonInfo, error)
	Logger *slog.Logger
	// After overrides time.After (tests).
	After func(time.Duration) <-chan time.Time
}

// Module implements agent.Module.
type Module struct {
	cfg    Config
	bm     *BookmarkStore
	mapper *Mapper
	open   Opener
	chans  []Channel

	sysmon atomic.Pointer[SysmonInfo]

	mu      sync.Mutex
	workers []*worker
}

// Name implements agent.Module.
func (m *Module) Name() string { return "winevt" }

func (m *Module) after(d time.Duration) <-chan time.Time {
	if m.cfg.After != nil {
		return m.cfg.After(d)
	}
	return time.After(d)
}

// New validates the config and builds the module. On non-Windows platforms the
// module is a stub that does nothing unless Config.Open is set (tests).
func New(cfg Config) (*Module, error) {
	if cfg.BookmarkPath == "" {
		return nil, fmt.Errorf("winevt: BookmarkPath is required")
	}
	if len(cfg.Channels) == 0 {
		cfg.Channels = DefaultChannels()
	}
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&cfg.QueueWait, 2*time.Second)
	def(&cfg.RetryInterval, 30*time.Second)
	def(&cfg.GapFlushInterval, 5*time.Second)
	def(&cfg.BookmarkSaveInterval, time.Second)
	def(&cfg.SysmonInterval, 60*time.Second)
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 4096
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	m := &Module{cfg: cfg}
	seen := map[string]bool{}
	for _, c := range cfg.Channels {
		n, err := c.Normalize()
		if err != nil {
			return nil, err
		}
		if seen[n.Name] {
			return nil, fmt.Errorf("winevt: duplicate channel %q", n.Name)
		}
		seen[n.Name] = true
		m.chans = append(m.chans, n)
	}
	m.open = cfg.Open
	if m.open == nil {
		m.open = platformOpen
	}
	m.mapper = &Mapper{Host: cfg.Host, DropExe: cfg.DropExe, Use4688: m.use4688}
	return m, nil
}

// use4688 enables the 4688 fallback unless a healthy Sysmon is feeding process
// events. Before the first probe the fallback is on (duplicates are better
// than a blind start); the probe runs immediately at Start.
func (m *Module) use4688() bool {
	i := m.sysmon.Load()
	return i == nil || !(i.Present && i.Running)
}

// Sysmon returns the last probe result (zero value before the first probe).
func (m *Module) Sysmon() SysmonInfo {
	if i := m.sysmon.Load(); i != nil {
		return *i
	}
	return SysmonInfo{}
}

// Stats returns a per-channel snapshot.
func (m *Module) Stats() map[string]ChannelStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]ChannelStats{}
	for _, w := range m.workers {
		w.mu.Lock()
		out[w.ch.Name] = w.st
		w.mu.Unlock()
	}
	return out
}

// Start implements agent.Module.
func (m *Module) Start(ctx context.Context, emit agent.Emit) error {
	if m.cfg.Open == nil && !platformSupported {
		m.cfg.Logger.Info("winevt: not supported on this platform; module idle")
		return nil
	}
	bm, err := OpenBookmarks(m.cfg.BookmarkPath, m.cfg.BookmarkSaveInterval)
	m.bm = bm
	if err != nil {
		m.cfg.Logger.Warn("winevt: bookmarks reset", "err", err)
		_ = emit(event.Event{Kind: "telemetry_gap", Priority: event.PriorityHigh, Time: time.Now().UTC(),
			Fields: map[string]any{"source": "winevt", "reason": "bookmark_file_corrupt", "count": uint64(1)}})
	}
	m.mu.Lock()
	m.workers = nil
	for _, c := range m.chans {
		m.workers = append(m.workers, &worker{m: m, ch: c, emit: emit, log: m.cfg.Logger,
			st: ChannelStats{State: "starting"}})
	}
	ws := m.workers
	m.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); m.sysmonLoop(ctx, emit) }()
	for _, w := range ws {
		wg.Add(1)
		go func() { defer wg.Done(); w.run(ctx) }()
	}
	wg.Wait()
	return nil
}

// sysmonLoop probes Sysmon, emits a sensor_state event on change and drives
// the 4688 fallback switch.
func (m *Module) sysmonLoop(ctx context.Context, emit agent.Emit) {
	probe := m.cfg.Probe
	if probe == nil {
		probe = platformProbe
	}
	var last *SysmonInfo
	for ctx.Err() == nil {
		info, err := probe(m.cfg.SysmonHints)
		if err != nil {
			m.cfg.Logger.Warn("winevt: sysmon probe failed", "err", err)
		} else {
			cp := info
			m.sysmon.Store(&cp)
			if last == nil || *last != info {
				fallback := ""
				if !(info.Present && info.Running) {
					fallback = "4688"
				}
				_ = emit(event.Event{Kind: "sensor_state", Priority: event.PriorityCritical, Time: time.Now().UTC(),
					Fields: map[string]any{"sensor": "sysmon", "present": info.Present, "running": info.Running,
						"driver_running": info.DriverRunning, "service_name": info.ServiceName,
						"driver_name": info.DriverName, "renamed": info.Renamed, "config_hash": info.ConfigHash,
						"fallback": fallback, "expected_config_hash": SysmonConfigSHA256()}})
				last = &cp
			}
		}
		select {
		case <-ctx.Done():
		case <-m.after(m.cfg.SysmonInterval):
		}
	}
}

var _ agent.Module = (*Module)(nil)
