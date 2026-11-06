package bench

import (
	"math"
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
	h[bucketIndex(d)]++
}

// bucketIndex is the first bucket whose bound is at least d's millisecond
// value, else the overflow bucket. A negative duration lands in bucket 0.
func bucketIndex(d time.Duration) int {
	ms := float64(d) / float64(time.Millisecond)
	for i, ub := range HistBoundsMs {
		if ms <= ub {
			return i
		}
	}
	return HistBuckets - 1
}

// Count is the number of observations in the histogram.
func (h Hist) Count() uint64 {
	var n uint64
	for _, c := range h {
		n += c
	}
	return n
}

// Add adds o to h bucket by bucket.
func (h *Hist) Add(o Hist) {
	for i := range h {
		h[i] += o[i]
	}
}

// Sub returns h - o, saturating at 0 per bucket, so a counter reset cannot
// produce a huge delta.
func (h Hist) Sub(o Hist) Hist {
	var d Hist
	for i := range h {
		if h[i] > o[i] {
			d[i] = h[i] - o[i]
		}
	}
	return d
}

// QuantileMs is the upper bound of the bucket holding the q-quantile (0 < q <=
// 1): the nearest-rank observation. It is math.Inf(1) for the overflow bucket
// and 0 for an empty histogram.
func (h Hist) QuantileMs(q float64) float64 {
	n := h.Count()
	if n == 0 || q <= 0 {
		return 0
	}
	if q > 1 {
		q = 1
	}
	rank := uint64(math.Ceil(q * float64(n)))
	var cum uint64
	for i, c := range h {
		cum += c
		if cum < rank {
			continue
		}
		if i == HistBuckets-1 {
			return math.Inf(1)
		}
		return HistBoundsMs[i]
	}
	return math.Inf(1) // rank above Count: unreachable while Count matches
}

// AtomicHist is a Hist that any goroutine may observe without a lock; Snapshot
// is its consistent-enough copy (each bucket is a separate atomic, so a
// snapshot can see a newer observation in one bucket and an older one in
// another, which no percentile cares about).
type AtomicHist struct{ b [HistBuckets]atomic.Uint64 }

// Observe records d in the bucket of its millisecond value.
func (h *AtomicHist) Observe(d time.Duration) {
	h.b[bucketIndex(d)].Add(1)
}

// Snapshot returns the current bucket counts.
func (h *AtomicHist) Snapshot() Hist {
	var out Hist
	for i := range h.b {
		out[i] = h.b[i].Load()
	}
	return out
}
