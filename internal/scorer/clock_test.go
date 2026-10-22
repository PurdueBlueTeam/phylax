package scorer

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

var t0 = time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)

// feed generates a synthetic round stream and returns the start of each real burst.
func feed(e *Estimator, rng *rand.Rand, n, delay, jitter int, dropP float64, spurious int) (starts []time.Time) {
	at := t0
	var all []time.Time // real + spurious burst starts, to emit in order
	for i := 0; i < n; i++ {
		if i > 0 {
			at = at.Add(time.Duration(delay+rng.Intn(2*jitter)-jitter) * time.Second)
		}
		if rng.Float64() >= dropP || i == 0 {
			all = append(all, at)
			starts = append(starts, at)
		}
	}
	for i := 0; i < spurious; i++ { // stray 15-conn bursts mid-interval
		all = append(all, starts[1+rng.Intn(len(starts)-2)].Add(time.Duration(delay)*time.Second*time.Duration(30+rng.Intn(15))/100))
	}
	sortTimes(all)
	for _, s := range all {
		k := 15 + rng.Intn(6)
		for j := 0; j < k; j++ {
			e.Observe(s.Add(time.Duration(25+rng.Intn(30)) * time.Millisecond * time.Duration(j) / time.Duration(k)))
		}
	}
	return
}

func sortTimes(ts []time.Time) {
	for i := 1; i < len(ts); i++ {
		for j := i; j > 0 && ts[j].Before(ts[j-1]); j-- {
			ts[j], ts[j-1] = ts[j-1], ts[j]
		}
	}
}

func near(t *testing.T, name string, got time.Duration, want float64, tol float64) {
	t.Helper()
	if math.Abs(got.Seconds()-want) > tol {
		t.Fatalf("%s = %v, want %.1fs +- %.1f", name, got, want, tol)
	}
}

func TestEstimatorDelays(t *testing.T) {
	for _, tc := range []struct{ delay, jitter int }{{20, 5}, {60, 5}} {
		for _, drop := range []float64{0, 0.15} {
			e := NewEstimator(ClockConfig{})
			rng := rand.New(rand.NewSource(int64(tc.delay)*7 + int64(drop*100)))
			starts := feed(e, rng, 60, tc.delay, tc.jitter, drop, 0)
			last := starts[len(starts)-1]
			est := e.Estimate(last.Add(5 * time.Second))
			if est.Provisional {
				t.Fatalf("still provisional after %d bursts", est.Bursts)
			}
			near(t, "delay", est.Delay, float64(tc.delay)-0.5, 1.2) // uniform [D-J, D+J-1]
			near(t, "jitter", est.Jitter, float64(tc.jitter), 1.6)
			if drop > 0 && est.DroppedRounds == 0 {
				t.Fatalf("dropped rounds not noticed")
			}
			if est.Confidence < 0.7 {
				t.Fatalf("confidence %.2f too low", est.Confidence)
			}
		}
	}
}

func TestEstimatorOutliers(t *testing.T) {
	e := NewEstimator(ClockConfig{})
	rng := rand.New(rand.NewSource(3))
	starts := feed(e, rng, 80, 60, 5, 0.05, 6)
	est := e.Estimate(starts[len(starts)-1].Add(5 * time.Second))
	near(t, "delay", est.Delay, 59.5, 1.5)
	near(t, "jitter", est.Jitter, 5, 2)
	if est.Outliers == 0 {
		t.Fatal("spurious bursts not counted as outliers")
	}
}

func TestProvisionalUsesObservedNotDefaults(t *testing.T) {
	e := NewEstimator(ClockConfig{})
	feed(e, rand.New(rand.NewSource(1)), 5, 20, 5, 0, 0)
	est := e.Estimate(t0.Add(100 * time.Second))
	if !est.Provisional || est.Confidence > 0.4 {
		t.Fatalf("want provisional low confidence, got %+v", est)
	}
	if est.Delay > 30*time.Second {
		t.Fatalf("provisional estimate ignored observed 20s rounds: %v", est.Delay)
	}
	if got := NewEstimator(ClockConfig{}).Estimate(t0); got.Delay != 60*time.Second || got.Confidence > 0.1 {
		t.Fatalf("no bursts must give upstream defaults at low confidence: %+v", got)
	}
}

func TestSafeWindow(t *testing.T) {
	e := NewEstimator(ClockConfig{})
	rng := rand.New(rand.NewSource(9))
	starts := feed(e, rng, 30, 60, 5, 0, 0)
	last := starts[len(starts)-1]
	est := e.Estimate(last.Add(time.Second))
	// During/just after the burst: unsafe.
	for _, d := range []time.Duration{100 * time.Millisecond, time.Second} {
		if w := e.SafeNow(last.Add(d)); w.Safe {
			t.Fatalf("safe %v after burst start: %+v", d, w)
		}
	}
	if !e.Hazard(last.Add(time.Second)) || e.Hazard(last.Add(20*time.Second)) {
		t.Fatal("hazard region wrong")
	}
	w := e.SafeFor(last.Add(10*time.Second), 30*time.Second)
	if !w.Safe || w.Remaining < 30*time.Second {
		t.Fatalf("mid-interval should be safe: %+v", w)
	}
	// Never reaches into the earliest possible next burst.
	earliest := last.Add(est.Delay - est.Jitter)
	if !w.End.Before(earliest) {
		t.Fatalf("window end %v not before earliest next burst %v", w.End, earliest)
	}
	if w := e.SafeFor(last.Add(50*time.Second), 30*time.Second); w.Safe {
		t.Fatal("late in the interval, 30s does not fit")
	}
	// Overdue: no burst for 2 intervals => unsafe, flagged as gap.
	if w := e.SafeNow(last.Add(130 * time.Second)); w.Safe || !w.Overdue {
		t.Fatalf("overdue round must be unsafe: %+v", w)
	}
	if e.BurstSeqAt(last.Add(time.Second)) != e.Bursts()[len(e.Bursts())-1].Seq {
		t.Fatal("BurstSeqAt wrong")
	}
	if w := NewEstimator(ClockConfig{}).SafeNow(t0); w.Safe {
		t.Fatal("no data must be unsafe")
	}
}

func TestBurstDetectionNeedsDensity(t *testing.T) {
	e := NewEstimator(ClockConfig{})
	for i := 0; i < 40; i++ { // slow trickle: 40 conns over 4s
		e.Observe(t0.Add(time.Duration(i) * 100 * time.Millisecond))
	}
	for i := 0; i < 10; i++ { // too few
		e.Observe(t0.Add(time.Minute + time.Duration(i)*time.Millisecond))
	}
	e.Tick(t0.Add(time.Hour))
	if n := len(e.Bursts()); n != 0 {
		t.Fatalf("got %d bursts from non-bursty traffic", n)
	}
}
