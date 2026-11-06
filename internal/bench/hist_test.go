package bench

import (
	"math"
	"sync"
	"testing"
	"time"
)

func TestHistBuckets(t *testing.T) {
	var h Hist
	h.Observe(500 * time.Microsecond)          // 0.5 ms -> bucket 0 (<= 1)
	h.Observe(10 * time.Millisecond)           // bucket 3 (<= 10)
	h.Observe(10001 * time.Microsecond * 1000) // 10.001 s -> bucket 13 (<= 20000)
	h.Observe(2 * time.Minute)                 // bucket 15
	if h[0] != 1 || h[3] != 1 || h[13] != 1 || h[15] != 1 || h.Count() != 4 {
		t.Fatalf("%v", h)
	}
}

func TestHistQuantile(t *testing.T) {
	var h Hist
	for i := 0; i < 99; i++ {
		h.Observe(8 * time.Millisecond) // bucket <= 10
	}
	h.Observe(3 * time.Second) // bucket <= 5000
	if got := h.QuantileMs(0.5); got != 10 {
		t.Fatal(got)
	}
	if got := h.QuantileMs(0.99); got != 10 {
		t.Fatal(got) // 99th of 100 is still in the 10 ms bucket
	}
	if got := h.QuantileMs(1); got != 5000 {
		t.Fatal(got)
	}
	var empty Hist
	if empty.QuantileMs(0.5) != 0 {
		t.Fatal("empty")
	}
	h.Observe(5 * time.Minute)
	if !math.IsInf(h.QuantileMs(1), 1) {
		t.Fatal("overflow bucket")
	}
}

func TestHistSubAdd(t *testing.T) {
	a, b := Hist{3, 2}, Hist{1, 5}
	d := a.Sub(b)
	if d[0] != 2 || d[1] != 0 {
		t.Fatalf("%v", d) // saturating
	}
	a.Add(b)
	if a[0] != 4 || a[1] != 7 {
		t.Fatalf("%v", a)
	}
}

func TestAtomicHistConcurrent(t *testing.T) {
	var h AtomicHist
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				h.Observe(time.Millisecond)
			}
		}()
	}
	wg.Wait()
	if h.Snapshot().Count() != 8000 {
		t.Fatal(h.Snapshot())
	}
}
