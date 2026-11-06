package bench

import (
	"context"
	"log/slog"
	"time"
)

// Counters are the controller's cumulative figures since it started. The
// recorder turns them into per-interval deltas, so a failed or slow sample
// loses nothing.
type Counters struct {
	Events, Bytes [NumClasses]uint64
	Latency       [NumClasses]Hist
	Commit        Hist
	GapRecords    uint64
	GapEvents     uint64
	Connects      uint64
	Down          Hist
}

// Source is what the recorder samples: the controller implements it from what
// it already counts.
type Source interface {
	Counters() Counters
	Agents() []AgentSample
	StoreBytes() int64
	QueryTimes(ctx context.Context) map[string]float64
}

// QuotaSource is optional: a Source that also implements it gets QuotaLevel and
// SkippedEvents in the ctl record (the controller's benchSource implements it
// once W1 Task 8b is merged; the recorder type-asserts).
type QuotaSource interface {
	QuotaLevel() string    // highest level since the last call, then reset
	SkippedEvents() uint64 // cumulative; the recorder records the difference
}

// Recorder samples a Source every interval and writes one ctl record and one
// agent record per agent to a Log.
type Recorder struct {
	src      Source
	log      *Log
	interval time.Duration
	proc     func() (cpuMs, rssBytes uint64)
	prev     *Counters
	prevAt   time.Time // when prev was taken: the base of the next IntervalMS
	prevSkip uint64    // SkippedEvents at the previous sample (cumulative counter)
	cpuBase  uint64    // process CPU at the previous sample
	quota    QuotaSource
}

// NewRecorder returns a recorder that samples src into log every interval.
func NewRecorder(src Source, log *Log, interval time.Duration) *Recorder {
	r := &Recorder{src: src, log: log, interval: interval, proc: ProcStats, prevAt: time.Now()}
	if q, ok := src.(QuotaSource); ok {
		r.quota = q
	}
	return r
}

// Sample writes one ctl record (counters as deltas since the previous sample)
// and one agent record per agent, all with the same time.
func (r *Recorder) Sample(ctx context.Context, now time.Time) error {
	cur := r.src.Counters()
	var delta Counters
	if r.prev != nil {
		delta = subCounters(cur, *r.prev)
	} else {
		delta = cur // the first sample differs from zero
	}
	interval := now.Sub(r.prevAt)
	if interval <= 0 || interval > 24*time.Hour {
		interval = r.interval // a zero or absurd window would divide by zero
	}
	cpu, rss := r.proc()
	prevCPU := r.cpuBase
	if r.prev == nil {
		prevCPU = 0
	}
	ags := r.src.Agents()
	c := &Ctl{
		IntervalMS: interval.Milliseconds(),
		Events:     delta.Events,
		Bytes:      delta.Bytes,
		Latency:    delta.Latency,
		Commit:     delta.Commit,
		GapRecords: delta.GapRecords,
		GapEvents:  delta.GapEvents,
		Connects:   delta.Connects,
		Down:       delta.Down,
		CPUMs:      subU(cpu, prevCPU),
		RSSBytes:   rss,
		StoreBytes: r.src.StoreBytes(),
		Agents:     len(ags),
		QueryMS:    r.src.QueryTimes(ctx),
	}
	for _, a := range ags {
		if a.Connected {
			c.Connected++
		}
	}
	if r.quota != nil {
		c.QuotaLevel = r.quota.QuotaLevel()
		skip := r.quota.SkippedEvents()
		c.SkippedEvents = subU(skip, r.prevSkip)
		r.prevSkip = skip
	}
	if err := r.log.Write(Record{T: now, Kind: KindCtl, Ctl: c}); err != nil {
		return err
	}
	for _, a := range ags {
		if err := r.log.Write(Record{T: now, Kind: KindAgent, Agent: &a}); err != nil {
			return err
		}
	}
	r.prev, r.prevAt, r.cpuBase = &cur, now, cpu
	return nil
}

// Run samples every interval until ctx is done, then samples once more. A write
// error is logged once through slog.Warn and does not stop the sampling.
func (r *Recorder) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	warned := false
	sample := func() {
		if err := r.Sample(ctx, time.Now()); err != nil && !warned {
			warned = true
			slog.Warn("bench: sample write failed, continuing", "err", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			sample() // flush the last interval
			return
		case <-t.C:
			sample()
		}
	}
}

// subU is a - b saturating at 0, so a counter reset cannot produce a huge
// delta.
func subU(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return 0
}

// subCounters is cur - prev per field, saturating: the recorder turns the
// controller's cumulative counters into per-interval deltas.
func subCounters(cur, prev Counters) Counters {
	var d Counters
	for i := range cur.Events {
		d.Events[i] = subU(cur.Events[i], prev.Events[i])
		d.Bytes[i] = subU(cur.Bytes[i], prev.Bytes[i])
		d.Latency[i] = cur.Latency[i].Sub(prev.Latency[i])
	}
	d.Commit = cur.Commit.Sub(prev.Commit)
	d.GapRecords = subU(cur.GapRecords, prev.GapRecords)
	d.GapEvents = subU(cur.GapEvents, prev.GapEvents)
	d.Connects = subU(cur.Connects, prev.Connects)
	d.Down = cur.Down.Sub(prev.Down)
	return d
}
