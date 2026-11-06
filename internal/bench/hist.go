package bench

import (
	"sync/atomic"
	"time"
)

// NumClasses is the number of priority classes: the order of event.Priority
// and of the spool's class names (critical, high, normal, bulk).
const NumClasses = 4

// HistBuckets is the fixed bucket count of a Hist: HistBoundsMs bounds plus one
// overflow bucket.
const HistBuckets = 16

// ClassNames are the priority class names in event.Priority order.
var ClassNames = [NumClasses]string{"critical", "high", "normal", "bulk"}

// HistBoundsMs are the upper bounds (inclusive) of buckets 0..14; bucket 15
// holds everything larger. Bucket edge 10000 ms is the transport envelope, so
// "p99 at most 10 s" is an exact bucket comparison.
var HistBoundsMs = [HistBuckets - 1]float64{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 60000}

// Hist is a fixed 1-2-5 millisecond histogram: 14 duration buckets, one
// overflow. JSON: an array of 16 integers.
//
// shortcut: fixed 16 buckets, upgrade when a figure needs finer than 1-2-5.
type Hist [HistBuckets]uint64

// Observe records d in the bucket of its millisecond value.
func (h *Hist) Observe(d time.Duration) {
	panic("unimplemented: W14 Task 2")
}

// Count is the number of observations in the histogram.
func (h Hist) Count() uint64 {
	panic("unimplemented: W14 Task 2")
}

// Add adds o to h bucket by bucket.
func (h *Hist) Add(o Hist) {
	panic("unimplemented: W14 Task 2")
}

// Sub returns h - o, saturating at 0 per bucket, so a counter reset cannot
// produce a huge delta.
func (h Hist) Sub(o Hist) Hist {
	panic("unimplemented: W14 Task 2")
}

// QuantileMs is the upper bound of the bucket holding the q-quantile (0 < q <=
// 1): the nearest-rank observation. It is math.Inf(1) for the overflow bucket
// and 0 for an empty histogram.
func (h Hist) QuantileMs(q float64) float64 {
	panic("unimplemented: W14 Task 2")
}

// AtomicHist is a Hist that any goroutine may observe without a lock; Snapshot
// is its consistent-enough copy (each bucket is a separate atomic, so a
// snapshot can see a newer observation in one bucket and an older one in
// another, which no percentile cares about).
type AtomicHist struct{ b [HistBuckets]atomic.Uint64 }

// Observe records d in the bucket of its millisecond value.
func (h *AtomicHist) Observe(d time.Duration) {
	panic("unimplemented: W14 Task 2")
}

// Snapshot returns the current bucket counts.
func (h *AtomicHist) Snapshot() Hist {
	panic("unimplemented: W14 Task 2")
}
