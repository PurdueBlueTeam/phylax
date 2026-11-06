package bench

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// fakeSrc is the only fake in the bench tests: the recorder's edge. The
// recorder, the log and the reader are real.
type fakeSrc struct {
	c   Counters
	ags []AgentSample
}

func (f *fakeSrc) Counters() Counters    { return f.c }
func (f *fakeSrc) Agents() []AgentSample { return f.ags }
func (f *fakeSrc) StoreBytes() int64     { return 4096 }
func (f *fakeSrc) QueryTimes(context.Context) map[string]float64 {
	return map[string]float64{"overview": 3.5}
}

func TestRecorderDeltas(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.jsonl")
	l, _ := OpenLog(p, 1<<20)
	src := &fakeSrc{ags: []AgentSample{{Host: "h1", Connected: true}, {Host: "h2"}}}
	r := NewRecorder(src, l, 10*time.Second)
	cpu := uint64(0)
	r.proc = func() (uint64, uint64) { cpu += 250; return cpu, 1 << 20 }
	t0 := time.Unix(1700000000, 0).UTC()
	src.c.Events[1], src.c.Bytes[1], src.c.Connects = 100, 20000, 2
	src.c.Latency[1].Observe(40 * time.Millisecond)
	if err := r.Sample(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	src.c.Events[1], src.c.Bytes[1], src.c.GapEvents = 160, 32000, 7
	src.c.Latency[1].Observe(9 * time.Second)
	if err := r.Sample(context.Background(), t0.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	l.Close()
	recs, _ := ReadFiles(p)
	var ctl []*Ctl
	agents := 0
	for _, x := range recs {
		switch x.Kind {
		case KindCtl:
			ctl = append(ctl, x.Ctl)
		case KindAgent:
			agents++
		}
	}
	if len(ctl) != 2 || agents != 4 {
		t.Fatalf("%d ctl %d agent", len(ctl), agents)
	}
	c := ctl[1]
	if c.Events[1] != 60 || c.Bytes[1] != 12000 || c.GapEvents != 7 || c.Connects != 0 {
		t.Fatalf("%+v", c)
	}
	if c.Latency[1].Count() != 1 || c.Latency[1].QuantileMs(1) != 10000 {
		t.Fatalf("%v", c.Latency[1])
	}
	if c.IntervalMS != 10000 || c.CPUMs != 250 || c.Agents != 2 || c.Connected != 1 || c.QueryMS["overview"] != 3.5 {
		t.Fatalf("%+v", c)
	}
}

func TestRecorderRunStopsAndFlushes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.jsonl")
	l, err := OpenLog(p, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	src := &fakeSrc{ags: []AgentSample{{Host: "h1", Connected: true}}}
	r := NewRecorder(src, l, 20*time.Millisecond)
	r.proc = func() (uint64, uint64) { return 1, 1 << 20 }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return within 1 s of cancel")
	}
	l.Close()
	recs, err := ReadFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, x := range recs {
		if x.Kind == KindCtl {
			n++
		}
	}
	if n < 3 {
		t.Fatalf("%d ctl records after ~100 ms at 20 ms", n)
	}
}
