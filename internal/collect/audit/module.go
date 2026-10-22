//go:build linux

package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	libaudit "github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Status is the audit health block for heartbeats.
type Status struct {
	Mode         string    `json:"mode"` // multicast | unicast
	Enabled      uint32    `json:"enabled"`
	AuditPID     uint32    `json:"audit_pid"`
	Backlog      uint32    `json:"backlog"`
	BacklogLimit uint32    `json:"backlog_limit"`
	KernelLost   uint32    `json:"kernel_lost"`
	RulesHash    string    `json:"rules_hash"`
	RulesOK      bool      `json:"rules_ok"`
	RulesInstall int       `json:"rules_installed"`
	RulesFailed  int       `json:"rules_failed"`
	NeverRules   int       `json:"never_rules"`
	RcvBuf       int       `json:"rcvbuf"`
	EventsIn     uint64    `json:"events_in"`
	QueueDropped uint64    `json:"queue_dropped"`
	RateDropped  uint64    `json:"rate_dropped"`
	SeqLost      uint64    `json:"seq_lost"`
	OwnDropped   uint64    `json:"own_dropped"`
	EmitErrors   uint64    `json:"emit_errors"`
	LastVerify   time.Time `json:"last_verify"`
	SweepLast    time.Time `json:"sweep_last"`
}

// Module is the audit telemetry module. It implements agent.Module.
type Module struct {
	cfg Config
	rs  *RuleSet

	procs  *procTable
	bootID string

	emit agent.Emit
	bkt  tokenBucket

	gaps gapAcc

	recent sync.Map // path -> time.Time of the last audit-reported change

	mu sync.Mutex
	st Status

	eventsIn, queueDropped, rateDropped, seqLost, ownDropped, emitErrors atomic.Uint64

	// testing hook: when non-nil, called instead of opening the kernel
	// control client.
	openControl func() (kernelControl, error)
}

var _ agent.Module = (*Module)(nil)

// New validates cfg and builds the rule set.
func New(cfg Config) (*Module, error) {
	cfg.defaults()
	switch cfg.Mode {
	case "auto", "multicast", "unicast":
	default:
		return nil, fmt.Errorf("audit: unknown mode %q", cfg.Mode)
	}
	lines := BuildRuleLines(&cfg, osExists)
	var rs *RuleSet
	if !cfg.NoRules {
		var err error
		if rs, err = NewRuleSet(lines); err != nil {
			return nil, err
		}
	} else {
		rs = &RuleSet{}
	}
	m := &Module{cfg: cfg, rs: rs,
		procs: newProcTable(cfg.ProcRoot, 2*time.Minute, 16384),
		bkt:   newBucket(cfg.RatePerSec, cfg.Burst),
	}
	m.procs.now = time.Now
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		m.bootID = strings.TrimSpace(string(b))
	}
	return m, nil
}

// Name implements agent.Module.
func (m *Module) Name() string { return "audit" }

// Rules returns the rule lines this module will install.
func (m *Module) Rules() []string { return append([]string(nil), m.rs.Lines...) }

// Status returns a snapshot of audit health.
func (m *Module) Status() Status {
	m.mu.Lock()
	s := m.st
	m.mu.Unlock()
	s.EventsIn, s.QueueDropped, s.RateDropped = m.eventsIn.Load(), m.queueDropped.Load(), m.rateDropped.Load()
	s.SeqLost, s.OwnDropped, s.EmitErrors = m.seqLost.Load(), m.ownDropped.Load(), m.emitErrors.Load()
	return s
}

func (m *Module) setStatus(f func(*Status)) { m.mu.Lock(); f(&m.st); m.mu.Unlock() }

// send applies the event rate limit and counts errors. Gap and rules events
// bypass the limit (force).
func (m *Module) send(e event.Event, force bool) {
	if !force && !m.bkt.allow(time.Now()) {
		m.rateDropped.Add(1)
		m.gaps.add("rate_limited", 1, e.Time, false)
		return
	}
	if err := m.emit(e); err != nil {
		m.emitErrors.Add(1)
	}
}

type queued struct {
	typ  auparse.AuditMessageType
	data []byte
}

// Start implements agent.Module: it runs until ctx is cancelled.
func (m *Module) Start(ctx context.Context, emit agent.Emit) error {
	m.emit = emit
	var ctl kernelControl
	var err error
	if m.openControl != nil {
		ctl, err = m.openControl()
	} else {
		ctl, err = libaudit.NewAuditClient(nil)
	}
	if err != nil {
		return fmt.Errorf("audit: open control socket: %w", err)
	}
	defer ctl.Close()

	st, err := ctl.GetStatus()
	if err != nil {
		return fmt.Errorf("audit: status (needs CAP_AUDIT_CONTROL in the initial namespaces): %w", err)
	}
	multicast, err := m.chooseMode(st)
	if err != nil {
		return err
	}
	mode := "unicast"
	if multicast {
		mode = "multicast"
	}
	rd, nl, err := newReader(multicast, 16<<20)
	if err != nil {
		return err
	}
	readerClosed := false
	closeReader := func() {
		if !readerClosed {
			readerClosed = true
			nl.Interrupt()
		}
	}
	defer func() { closeReader(); nl.Resume(); rd.Close() }()

	// Settings. Unicast: we become the sole reader (SetPID). Multicast leaves
	// the audit pid to auditd.
	if !m.cfg.NoManageSettings {
		if err := m.applySettings(rd, ctl, st, multicast); err != nil {
			return err
		}
	}

	var g *guard
	if !m.cfg.NoRules {
		g, err = newGuard(ctl, m.rs, m.cfg.Logger)
		if err != nil {
			return err
		}
		rep, err := g.Reconcile()
		if err != nil {
			return err
		}
		m.cfg.Logger.Info("audit: rules installed", "mode", mode, "rules", rep.Installed, "failed", len(rep.Failed), "hash", rep.Hash[:12])
		if len(rep.Failed) > 0 {
			m.sendRulesChanged("install_failed", rep, nil)
		}
		m.setStatus(func(s *Status) {
			s.RulesHash, s.RulesOK, s.RulesInstall, s.RulesFailed, s.NeverRules = rep.Hash, len(rep.Failed) == 0, rep.Installed, len(rep.Failed), len(rep.Never)
		})
		if m.cfg.RemoveRulesOnExit {
			defer g.Remove()
		}
	}
	if st2, err := ctl.GetStatus(); err == nil {
		m.setStatus(func(s *Status) { m.fillKernel(s, st2) })
		m.gaps.lastLost = st2.Lost
	}
	m.setStatus(func(s *Status) { s.Mode, s.RcvBuf = mode, nl.rcvbuf })

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	q := make(chan queued, m.cfg.QueueLen)
	errc := make(chan error, 4)
	var wg sync.WaitGroup
	run := func(f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil {
				errc <- err
			}
			cancel()
		}()
	}

	run(func() error { return m.readLoop(ctx, rd, q) })
	run(func() error { return m.parseLoop(ctx, q) })
	run(func() error { return m.verifyLoop(ctx, ctl, g, rd, multicast) })
	if m.cfg.SweepInterval > 0 {
		run(func() error { return m.sweepLoop(ctx) })
	}

	<-ctx.Done()
	closeReader() // wake the reader out of poll
	wg.Wait()
	m.flushGaps(true)
	select {
	case err := <-errc:
		return err
	default:
	}
	return nil
}

func (m *Module) chooseMode(st *libaudit.AuditStatus) (multicast bool, err error) {
	auditdRunning := st.PID != 0 && st.PID != uint32(m.cfg.selfPID) && pidAlive(m.cfg.ProcRoot, int(st.PID))
	switch m.cfg.Mode {
	case "multicast":
		return true, nil
	case "unicast":
		if auditdRunning {
			return false, fmt.Errorf("audit: unicast requested but audit pid %d is already registered", st.PID)
		}
		return false, nil
	}
	return auditdRunning, nil
}

func pidAlive(procRoot string, pid int) bool {
	_, err := os.Stat(procRoot + "/" + strconv.Itoa(pid))
	return err == nil
}

func (m *Module) applySettings(rd *libaudit.AuditClient, ctl kernelControl, st *libaudit.AuditStatus, multicast bool) error {
	c, ok := ctl.(*libaudit.AuditClient)
	if !ok {
		return nil
	}
	if st.Enabled == 0 {
		if err := c.SetEnabled(true, libaudit.WaitForReply); err != nil {
			return fmt.Errorf("audit: enable: %w", err)
		}
	}
	if st.BacklogLimit < m.cfg.BacklogLimit {
		if err := c.SetBacklogLimit(m.cfg.BacklogLimit, libaudit.WaitForReply); err != nil {
			m.cfg.Logger.Warn("audit: raise backlog limit", "err", err) // locked config: not fatal
		}
	}
	if st.Failure == 0 || st.Failure == 2 {
		_ = c.SetFailure(libaudit.LogOnFailure, libaudit.WaitForReply) // log, never panic
	}
	if !multicast {
		if err := rd.SetPID(libaudit.WaitForReply); err != nil {
			return fmt.Errorf("audit: become the audit reader (is auditd running?): %w", err)
		}
	}
	return nil
}

func (m *Module) fillKernel(s *Status, k *libaudit.AuditStatus) {
	s.Enabled, s.AuditPID, s.Backlog, s.BacklogLimit, s.KernelLost = k.Enabled, k.PID, k.Backlog, k.BacklogLimit, k.Lost
}

// ---- reader / parser ----

func (m *Module) readLoop(ctx context.Context, rd *libaudit.AuditClient, q chan<- queued) error {
	for {
		msg, err := rd.Receive(false)
		if err != nil {
			switch {
			case errors.Is(err, errInterrupted) || ctx.Err() != nil:
				return nil
			case errors.Is(err, syscall.ENOBUFS):
				// Socket buffer overrun: an unknown number of records is gone.
				m.gaps.add("enobufs", 1, time.Now(), false)
				continue
			case errors.Is(err, syscall.EINTR), errors.Is(err, syscall.EAGAIN):
				continue
			}
			return fmt.Errorf("audit: receive: %w", err)
		}
		if msg.Type < 1300 || msg.Type > 1399 {
			continue // control replies, user-space and SELinux/AVC records
		}
		data := make([]byte, len(msg.Data))
		copy(data, msg.Data)
		select {
		case q <- queued{msg.Type, data}:
		default:
			m.queueDropped.Add(1)
			m.gaps.add("queue_overflow", 1, time.Now(), true)
		}
	}
}

type reasm struct{ m *Module }

func (r reasm) ReassemblyComplete(msgs []*auparse.AuditMessage) { r.m.handle(msgs) }
func (r reasm) EventsLost(count int) {
	r.m.seqLost.Add(uint64(count))
	r.m.gaps.add("sequence_gap", uint64(count), time.Now(), true)
}

func (m *Module) parseLoop(ctx context.Context, q <-chan queued) error {
	ra, err := libaudit.NewReassembler(2048, 2*time.Second, reasm{m})
	if err != nil {
		return err
	}
	defer ra.Close()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// Drain what is already queued so shutdown loses nothing.
			for {
				select {
				case it := <-q:
					m.push(ra, it)
				default:
					return nil
				}
			}
		case it := <-q:
			m.push(ra, it)
		case <-tick.C:
			_ = ra.Maintain()
			m.flushGaps(false)
		}
	}
}

func (m *Module) push(ra *libaudit.Reassembler, it queued) {
	m.eventsIn.Add(1)
	if err := ra.Push(it.typ, it.data); err != nil {
		m.cfg.Logger.Debug("audit: unparsable record", "type", it.typ, "err", err)
	}
}

// ---- verification ----

func (m *Module) verifyLoop(ctx context.Context, ctl kernelControl, g *guard, rd *libaudit.AuditClient, multicast bool) error {
	t := time.NewTicker(m.cfg.VerifyInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			m.verifyOnce(ctl, g, rd, multicast)
		}
	}
}

func (m *Module) verifyOnce(ctl kernelControl, g *guard, rd *libaudit.AuditClient, multicast bool) {
	var reasons []string
	st, err := ctl.GetStatus()
	if err != nil {
		m.cfg.Logger.Warn("audit: status", "err", err)
		return
	}
	if d := st.Lost - m.gaps.lastLost; st.Lost >= m.gaps.lastLost && d > 0 {
		m.gaps.add("kernel_lost", uint64(d), time.Now(), true)
	}
	m.gaps.lastLost = st.Lost
	if st.Enabled == 0 {
		reasons = append(reasons, "audit_disabled")
		if !m.cfg.NoManageSettings {
			_ = ctl.SetEnabled(true, libaudit.WaitForReply)
		}
	}
	if !multicast && st.PID != uint32(m.cfg.selfPID) {
		reasons = append(reasons, "reader_displaced")
		if !m.cfg.NoManageSettings {
			_ = rd.SetPID(libaudit.WaitForReply)
		}
	}
	var rep RulesReport
	rulesOK := true
	if g != nil {
		var changed bool
		rep, changed, err = g.Verify()
		if err != nil {
			m.cfg.Logger.Warn("audit: verify rules", "err", err)
		} else if changed {
			if len(rep.Missing) > 0 || len(rep.Stale) > 0 {
				reasons = append(reasons, "rules_changed")
				rulesOK = false
			}
			if len(rep.Never) > 0 {
				reasons = append(reasons, "never_rule")
			}
		}
	}
	if len(reasons) > 0 {
		m.sendRulesChanged(strings.Join(reasons, ","), rep, st)
	}
	m.setStatus(func(s *Status) {
		m.fillKernel(s, st)
		s.LastVerify = time.Now()
		if g != nil && err == nil {
			s.RulesHash, s.RulesOK, s.RulesInstall, s.RulesFailed, s.NeverRules = rep.Hash, rulesOK && len(rep.Failed) == 0, rep.Installed, len(rep.Failed), len(rep.Never)
		}
	})
}

func capList(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// sendRulesChanged emits the D10-style event.
func (m *Module) sendRulesChanged(reason string, rep RulesReport, st *libaudit.AuditStatus) {
	f := map[string]any{
		"source": "audit", "reason": reason,
		"expected_hash": rep.Baseline, "actual_hash": rep.Hash,
		"missing": capList(rep.Missing, 20), "missing_count": len(rep.Missing),
		"stale_count": len(rep.Stale), "repaired": rep.Repaired,
		"never_rules": capList(rep.Never, 5), "failed_count": len(rep.Failed),
	}
	if len(rep.Failed) > 0 {
		var fl []string
		for l, e := range rep.Failed {
			fl = append(fl, l+": "+e)
		}
		f["failed"] = capList(fl, 10)
	}
	if st != nil {
		f["enabled"], f["audit_pid"], f["lost"], f["backlog"] = st.Enabled, st.PID, st.Lost, st.Backlog
	}
	m.send(event.Event{Time: time.Now().UTC(), Kind: KindRulesChanged, Priority: event.PriorityCritical, Fields: f}, true)
}

// ---- gaps ----

type gapKey struct {
	reason string
	exact  bool
}
type gapVal struct {
	count    uint64
	from, to time.Time
}

type gapAcc struct {
	mu       sync.Mutex
	m        map[gapKey]*gapVal
	lastLost uint32
}

func (a *gapAcc) add(reason string, n uint64, at time.Time, exact bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil {
		a.m = map[gapKey]*gapVal{}
	}
	k := gapKey{reason, exact}
	v := a.m[k]
	if v == nil {
		v = &gapVal{from: at}
		a.m[k] = v
	}
	v.count += n
	v.to = at
}

func (a *gapAcc) take() map[gapKey]*gapVal {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.m
	a.m = nil
	return out
}

func (m *Module) flushGaps(final bool) {
	for k, v := range m.gaps.take() {
		m.send(event.Event{Time: time.Now().UTC(), Kind: KindGap, Priority: event.PriorityHigh, Fields: map[string]any{
			"source": "audit", "reason": k.reason, "count": v.count, "count_exact": k.exact,
			"from": v.from.UTC().Format(time.RFC3339Nano), "to": v.to.UTC().Format(time.RFC3339Nano),
		}}, true)
	}
}

// ---- rate limit ----

type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(rate float64, burst int) tokenBucket {
	return tokenBucket{rate: rate, burst: float64(burst), tokens: float64(burst)}
}

func (b *tokenBucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.last.IsZero() {
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
