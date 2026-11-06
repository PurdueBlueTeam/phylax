package bench

import (
	"context"
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
}

// NewRecorder returns a recorder that samples src into log every interval.
func NewRecorder(src Source, log *Log, interval time.Duration) *Recorder {
	panic("unimplemented: W14 Task 4")
}

// Sample writes one ctl record (counters as deltas since the previous sample)
// and one agent record per agent, all with the same time.
func (r *Recorder) Sample(ctx context.Context, now time.Time) error {
	panic("unimplemented: W14 Task 4")
}

// Run samples every interval until ctx is done, then samples once more. A write
// error is logged once through slog.Warn and does not stop the sampling.
func (r *Recorder) Run(ctx context.Context) {
	panic("unimplemented: W14 Task 4")
}
