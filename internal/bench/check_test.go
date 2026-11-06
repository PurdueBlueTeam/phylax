package bench

import (
	"testing"
	"time"
)

// loadRun builds a synthetic load run: one ctl record before the partition and
// one after the recovery, the phase marks, and two agent samples for host
// bench-1.
func loadRun(p99Before, p99After time.Duration, gapEvents uint64, reconnects uint64, reconnectAfter time.Duration, caught bool) []Record {
	t0 := time.Unix(1700000000, 0).UTC()
	var before, after Ctl
	before.Events[1], after.Events[1] = 100, 100
	before.Latency[1].Observe(p99Before)
	after.Latency[1].Observe(p99After)
	after.GapEvents = gapEvents
	recs := []Record{
		{T: t0, Kind: KindMark, Mark: "load_start"},
		ctlRecAt(t0.Add(10*time.Second), before),
		{T: t0.Add(20 * time.Second), Kind: KindMark, Mark: "partition_start"},
		{T: t0.Add(80 * time.Second), Kind: KindMark, Mark: "partition_end"},
		agRecAt(t0.Add(90*time.Second), AgentSample{Host: "bench-1", Connects: 1 + reconnects, ConnectedAt: t0.Add(80*time.Second + reconnectAfter)}),
		agRecAt(t0.Add(15*time.Second), AgentSample{Host: "bench-1", Connects: 1, ConnectedAt: t0}),
	}
	if caught {
		recs = append(recs, Record{T: t0.Add(100 * time.Second), Kind: KindMark, Mark: "caught_up"})
	} else {
		recs = append(recs, Record{T: t0.Add(200 * time.Second), Kind: KindMark, Mark: "not_caught_up"})
	}
	return append(recs, ctlRecAt(t0.Add(130*time.Second), after))
}

func failed(rs []Result) []string {
	var f []string
	for _, r := range rs {
		if !r.Pass {
			f = append(f, r.Name)
		}
	}
	return f
}

func TestCheckPasses(t *testing.T) {
	rs := Check(loadRun(3*time.Second, 2*time.Second, 0, 1, 5*time.Second, true), "bench-", Criteria{LatencyP99Ms: 10000, MaxReconnectS: 35})
	if f := failed(rs); len(f) != 0 {
		t.Fatal(f, rs)
	}
}

func TestCheckEachFailure(t *testing.T) {
	c := Criteria{LatencyP99Ms: 10000, MaxReconnectS: 35}
	cases := map[string][]Record{
		"latency_p99_before": loadRun(15*time.Second, time.Second, 0, 1, 5*time.Second, true),
		"latency_p99_after":  loadRun(time.Second, 15*time.Second, 0, 1, 5*time.Second, true),
		"no_loss":            loadRun(time.Second, time.Second, 4, 1, 5*time.Second, true),
		"reconnect_time":     loadRun(time.Second, time.Second, 0, 1, 40*time.Second, true),
		"reconnect_count":    loadRun(time.Second, time.Second, 0, 3, 5*time.Second, true),
		"caught_up":          loadRun(time.Second, time.Second, 0, 1, 5*time.Second, false),
	}
	for name, recs := range cases {
		found := false
		for _, r := range Check(recs, "bench-", c) {
			if r.Name == name && !r.Pass {
				found = true
			}
		}
		if !found {
			t.Errorf("%s did not fail", name)
		}
	}
}

func TestCheckNoPartitionMarks(t *testing.T) {
	rs := Check([]Record{{T: time.Unix(1700000000, 0), Kind: KindMark, Mark: "load_start"}}, "bench-", Criteria{})
	if len(rs) != 1 || rs[0].Name != "partition_marks" || rs[0].Pass {
		t.Fatal(rs)
	}
}
