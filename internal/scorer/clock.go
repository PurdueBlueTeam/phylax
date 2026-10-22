// Package scorer holds the controller-side model of the competition scorer
// (Quotient): the round-clock estimator, the behavioural fingerprint
// classifier, check discovery, SLA streak tracking and the PCR (password
// change request) transaction engine.
//
// Everything here is pure logic fed by flow/transaction events and driven by
// explicit timestamps (no hidden clocks, no I/O), so it is deterministic and
// testable. Evidence: research/topics/quotient.md; design: phylax_design.md
// "Active checks and check discovery" and "PCR as a transaction".
package scorer

import (
	"math"
	"slices"
	"sort"
	"sync"
	"time"
)

// ClockConfig tunes the round-clock estimator. Zero values take defaults.
type ClockConfig struct {
	DefaultDelay  time.Duration // upstream default 60s
	DefaultJitter time.Duration // upstream default 5s
	MinConns      int           // connections that make a burst (15)
	CoreWindow    time.Duration // MinConns must fall within this (100ms; observed 25-55ms)
	JoinGap       time.Duration // a connection this close to the previous joins the burst (1s; retries seen ~1s)
	MinBursts     int           // bursts before the estimate is no longer provisional (10)
	SafetyAfter   time.Duration // quiet time after the last connection of a burst (2s)
	SafetyBefore  time.Duration // margin before the earliest predicted next burst (3s)
	EnqueuePad    time.Duration // hazard before a burst's first connection: the enqueue pass (2s)
	PlausibleDev  float64       // max |interval - m*Delay| / Delay for a plausible round (0.35)
	MaxBursts     int           // retained bursts (128)
}

func (c *ClockConfig) defaults() {
	if c.DefaultDelay <= 0 {
		c.DefaultDelay = 60 * time.Second
	}
	if c.DefaultJitter <= 0 {
		c.DefaultJitter = 5 * time.Second
	}
	if c.MinConns <= 0 {
		c.MinConns = 15
	}
	if c.CoreWindow <= 0 {
		c.CoreWindow = 100 * time.Millisecond
	}
	if c.JoinGap <= 0 {
		c.JoinGap = time.Second
	}
	if c.MinBursts <= 0 {
		c.MinBursts = 10
	}
	if c.SafetyAfter <= 0 {
		c.SafetyAfter = 2 * time.Second
	}
	if c.SafetyBefore <= 0 {
		c.SafetyBefore = 3 * time.Second
	}
	if c.EnqueuePad <= 0 {
		c.EnqueuePad = 2 * time.Second
	}
	if c.PlausibleDev <= 0 {
		c.PlausibleDev = 0.35
	}
	if c.MaxBursts <= 0 {
		c.MaxBursts = 128
	}
}

// Burst is one detected scorer round burst against our team.
type Burst struct {
	Seq   int       // ordinal of the burst (counts every qualifying burst)
	Start time.Time // first connection of the densest MinConns-connection core
	End   time.Time // last connection of the burst
	Conns int
}

// Estimate is the published round clock.
type Estimate struct {
	Delay, Jitter time.Duration
	Bursts        int // qualifying bursts retained
	Accepted      int // bursts on the fitted round lattice
	Samples       int // single-round intervals used for Delay/Jitter
	Outliers      int // bursts or intervals rejected
	DroppedRounds int // inferred missing rounds (interval = m*Delay, m>1)
	Provisional   bool
	Confidence    float64 // 0..1
	MinInterval   time.Duration
	LastStart     time.Time
	LastEnd       time.Time
	LastSeq       int
}

// Window answers "may I do something time-critical now?".
type Window struct {
	Safe          bool
	Start, End    time.Time // this quiet window (zero if unknown)
	Remaining     time.Duration
	NextBurstFrom time.Time // earliest predicted next burst start
	NextBurstTo   time.Time // latest predicted next burst start
	NextOpens     time.Time // when the window after the next burst opens (worst case)
	Confidence    float64
	LastBurstSeq  int
	Overdue       bool // the expected burst has not arrived: a round gap
	Reason        string
}

// WindowSource is what the PCR engine needs from the clock.
type WindowSource interface {
	// SafeFor reports whether a quiet window of at least need is open at now.
	SafeFor(now time.Time, need time.Duration) Window
	// Hazard reports whether t falls in a burst or its enqueue pass (a PCR
	// landing then can produce a mixed credential snapshot).
	Hazard(t time.Time) bool
	// BurstSeqAt returns the sequence number of the last burst starting at or
	// before t (0 if none).
	BurstSeqAt(t time.Time) int
}

// Estimator clusters scorer-attributed new-connection timestamps into bursts
// and estimates the round clock. Safe for concurrent use.
type Estimator struct {
	mu     sync.Mutex
	cfg    ClockConfig
	times  []time.Time // connections of the open burst
	bursts []Burst
	seq    int
	last   time.Time // newest connection seen
	late   int       // dropped as out-of-order
}

// NewEstimator returns an estimator.
func NewEstimator(cfg ClockConfig) *Estimator {
	cfg.defaults()
	return &Estimator{cfg: cfg}
}

// Observe records one new inbound connection (scorer-attributed) at t.
// Timestamps must be roughly non-decreasing; one older than the open burst by
// more than JoinGap is dropped.
func (e *Estimator) Observe(t time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.observeLocked(t)
}

func (e *Estimator) observeLocked(t time.Time) {
	if n := len(e.times); n > 0 {
		lastIn := e.times[n-1]
		if t.Before(lastIn) {
			if lastIn.Sub(t) > e.cfg.JoinGap {
				e.late++
				return
			}
		} else if t.Sub(lastIn) > e.cfg.JoinGap {
			e.finalizeLocked()
		}
	} else if !e.last.IsZero() && e.last.Sub(t) > e.cfg.JoinGap {
		e.late++
		return
	}
	if len(e.times) < 4096 {
		e.times = append(e.times, t)
	}
	if t.After(e.last) {
		e.last = t
	}
}

// ObserveBurst records an already-clustered burst.
func (e *Estimator) ObserveBurst(start, end time.Time, conns int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.finalizeLocked()
	e.addBurstLocked(start, end, conns)
}

// Tick closes the open burst if it has gone quiet. Queries call it implicitly.
func (e *Estimator) Tick(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tickLocked(now)
}

func (e *Estimator) tickLocked(now time.Time) {
	if n := len(e.times); n > 0 && now.Sub(e.times[n-1]) > e.cfg.JoinGap {
		e.finalizeLocked()
	}
}

func (e *Estimator) finalizeLocked() {
	ts := e.times
	e.times = nil
	if len(ts) < e.cfg.MinConns {
		return
	}
	slices.SortFunc(ts, func(a, b time.Time) int { return a.Compare(b) })
	// Densest window of MinConns connections.
	best, bestSpan := -1, time.Duration(math.MaxInt64)
	for i := 0; i+e.cfg.MinConns <= len(ts); i++ {
		if span := ts[i+e.cfg.MinConns-1].Sub(ts[i]); span < bestSpan {
			best, bestSpan = i, span
		}
	}
	if best < 0 || bestSpan > e.cfg.CoreWindow {
		return
	}
	e.addBurstLocked(ts[best], ts[len(ts)-1], len(ts))
}

func (e *Estimator) addBurstLocked(start, end time.Time, conns int) {
	e.seq++
	e.bursts = append(e.bursts, Burst{Seq: e.seq, Start: start, End: end, Conns: conns})
	if len(e.bursts) > e.cfg.MaxBursts {
		e.bursts = slices.Clone(e.bursts[len(e.bursts)-e.cfg.MaxBursts:])
	}
}

// Bursts returns the retained bursts.
func (e *Estimator) Bursts() []Burst {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.bursts)
}

// Dropped returns the number of out-of-order connections discarded.
func (e *Estimator) Dropped() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.late
}

// InBurst reports whether t lies inside a retained burst (plus grace).
func (e *Estimator) InBurst(t time.Time, grace time.Duration) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.bursts) - 1; i >= 0 && i >= len(e.bursts)-8; i-- {
		b := e.bursts[i]
		if !t.Before(b.Start.Add(-grace)) && !t.After(b.End.Add(grace)) {
			return true
		}
	}
	return false
}

// Estimate returns the current clock estimate as of now.
func (e *Estimator) Estimate(now time.Time) Estimate {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tickLocked(now)
	return e.estimateLocked(now)
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	sort.Float64s(s)
	if n := len(s); n%2 == 1 {
		return s[n/2]
	} else {
		return (s[n/2-1] + s[n/2]) / 2
	}
}

func dur(sec float64) time.Duration { return time.Duration(sec * float64(time.Second)) }

func (e *Estimator) estimateLocked(now time.Time) Estimate {
	est := Estimate{Bursts: len(e.bursts), Delay: e.cfg.DefaultDelay, Jitter: e.cfg.DefaultJitter, Provisional: true}
	if len(e.bursts) == 0 {
		return est
	}
	// Raw consecutive intervals give a robust first guess of Delay.
	var raw []float64
	for i := 1; i < len(e.bursts); i++ {
		raw = append(raw, e.bursts[i].Start.Sub(e.bursts[i-1].Start).Seconds())
	}
	d0 := e.cfg.DefaultDelay.Seconds()
	if len(raw) > 0 {
		d0 = median(raw)
	}
	if d0 <= 0 {
		d0 = e.cfg.DefaultDelay.Seconds()
	}
	// Walk the bursts keeping those on the round lattice anchored at the
	// previous accepted burst. Short intervals are spurious bursts, long ones
	// are m*Delay (dropped rounds); only m==1 intervals feed Delay/Jitter.
	anchor := e.bursts[0]
	est.Accepted = 1
	var singles []float64
	for _, b := range e.bursts[1:] {
		d := b.Start.Sub(anchor.Start).Seconds()
		m := math.Round(d / d0)
		if m < 1 || math.Abs(d-m*d0) > e.cfg.PlausibleDev*d0 || m > 12 {
			est.Outliers++
			continue
		}
		if m == 1 {
			singles = append(singles, d)
		} else {
			est.DroppedRounds += int(m) - 1
		}
		anchor = b
		est.Accepted++
	}
	// Reject residual outliers among single intervals by MAD.
	if len(singles) >= 3 {
		med := median(singles)
		dev := make([]float64, len(singles))
		for i, s := range singles {
			dev[i] = math.Abs(s - med)
		}
		thr := math.Max(4*1.4826*median(dev), 1.0)
		kept := singles[:0:0]
		for _, s := range singles {
			if math.Abs(s-med) <= thr {
				kept = append(kept, s)
			} else {
				est.Outliers++
			}
		}
		singles = kept
	}
	est.Samples = len(singles)
	est.LastStart, est.LastEnd, est.LastSeq = anchor.Start, anchor.End, anchor.Seq
	// Anchor must also reflect the newest qualifying burst end for safety;
	// callers treat any newer rejected burst as hazard via Hazard().
	if len(singles) > 0 {
		sum := 0.0
		minI, maxI := singles[0], singles[0]
		for _, s := range singles {
			sum += s
			minI, maxI = math.Min(minI, s), math.Max(maxI, s)
		}
		mean := sum / float64(len(singles))
		est.MinInterval = dur(minI)
		est.Provisional = anchorsBelow(est.Accepted, e.cfg.MinBursts)
		if est.Provisional {
			// Fewer than MinBursts: defaults can be badly wrong (lab ran 20+-5),
			// so use what was observed, widened to at least the upstream jitter.
			est.Delay = dur(median(singles))
			est.Jitter = dur(math.Max(e.cfg.DefaultJitter.Seconds(), (maxI-minI)/2))
		} else {
			varsum := 0.0
			for _, s := range singles {
				varsum += (s - mean) * (s - mean)
			}
			std := 0.0
			if len(singles) > 1 {
				std = math.Sqrt(varsum / float64(len(singles)-1))
			}
			// Uniform on [D-J, D+J]: std = J/sqrt(3).
			j := math.Max(math.Sqrt(3)*std, (maxI-minI)/2)
			est.Delay, est.Jitter = dur(mean), dur(j)
		}
	}
	est.Confidence = e.confidence(est, now)
	return est
}

func anchorsBelow(accepted, min int) bool { return accepted < min }

func (e *Estimator) confidence(est Estimate, now time.Time) float64 {
	if est.Samples == 0 {
		return 0.05
	}
	var c float64
	if est.Provisional {
		c = math.Min(0.35, 0.1+0.03*float64(est.Samples))
	} else {
		c = 0.6 + 0.4*(1-math.Exp(-float64(est.Accepted-e.cfg.MinBursts+1)/20))
	}
	if est.Bursts > 0 && float64(est.Outliers)/float64(est.Bursts) > 0.3 {
		c *= 0.7
	}
	if !now.IsZero() && !est.LastStart.IsZero() &&
		now.Sub(est.LastStart) > 3*(est.Delay+est.Jitter) {
		c *= 0.5
	}
	return math.Min(c, 1)
}

// Hazard implements WindowSource.
func (e *Estimator) Hazard(t time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tickLocked(t)
	if n := len(e.times); n >= 5 && !t.Before(e.times[0].Add(-e.cfg.EnqueuePad)) {
		return true
	}
	for _, b := range e.bursts {
		if !t.Before(b.Start.Add(-e.cfg.EnqueuePad)) && !t.After(b.End.Add(e.cfg.SafetyAfter)) {
			return true
		}
	}
	return false
}

// BurstSeqAt implements WindowSource.
func (e *Estimator) BurstSeqAt(t time.Time) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	seq := 0
	for _, b := range e.bursts {
		if !b.Start.After(t) {
			seq = b.Seq
		}
	}
	return seq
}

// SafeNow reports the quiet window at now with no minimum length.
func (e *Estimator) SafeNow(now time.Time) Window { return e.SafeFor(now, 0) }

// SafeFor implements WindowSource. The window is
// [last burst end + SafetyAfter, earliest predicted next start - SafetyBefore].
func (e *Estimator) SafeFor(now time.Time, need time.Duration) Window {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tickLocked(now)
	est := e.estimateLocked(now)
	w := Window{Confidence: est.Confidence, LastBurstSeq: est.LastSeq}
	if len(e.bursts) == 0 {
		w.Reason = "no bursts observed: round clock unknown"
		return w
	}
	if n := len(e.times); n >= 5 && now.Sub(e.times[n-1]) <= e.cfg.JoinGap {
		w.Reason = "burst in progress"
		return w
	}
	newest := e.bursts[len(e.bursts)-1]
	if now.Before(newest.End.Add(e.cfg.SafetyAfter)) {
		w.Reason = "burst just ended: waiting out the safety margin"
		w.Start = newest.End.Add(e.cfg.SafetyAfter)
		return w
	}
	lo := est.Delay - est.Jitter
	if est.MinInterval > 0 && est.MinInterval < lo {
		lo = est.MinInterval
	}
	hi := est.Delay + est.Jitter
	w.NextBurstFrom = est.LastStart.Add(lo)
	w.NextBurstTo = est.LastStart.Add(hi)
	burstLen := est.LastEnd.Sub(est.LastStart)
	w.NextOpens = w.NextBurstTo.Add(burstLen + e.cfg.SafetyAfter)
	w.Start = newest.End.Add(e.cfg.SafetyAfter)
	if est.LastEnd.After(w.Start.Add(-e.cfg.SafetyAfter)) {
		w.Start = est.LastEnd.Add(e.cfg.SafetyAfter)
	}
	w.End = w.NextBurstFrom.Add(-e.cfg.SafetyBefore)
	if now.After(w.NextBurstTo.Add(e.cfg.JoinGap)) {
		w.Overdue = true
		w.Reason = "expected burst has not arrived: round gap, clock phase uncertain"
		return w
	}
	if !w.End.After(w.Start) {
		w.Reason = "no quiet window between bursts"
		return w
	}
	if now.Before(w.Start) {
		w.Reason = "before window opens"
		return w
	}
	w.Remaining = w.End.Sub(now)
	if w.Remaining < need || w.Remaining <= 0 {
		w.Reason = "window closing: not enough time left"
		return w
	}
	w.Safe = true
	w.Reason = "quiet window open"
	return w
}
