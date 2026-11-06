package bench

import (
	"fmt"
	"time"
)

// Criteria are the transport envelope's pass figures for a load run.
type Criteria struct {
	LatencyP99Ms  float64 // 10000
	MaxReconnectS float64 // 35
}

// Result is one named pass or fail.
type Result struct {
	Name, Got, Want string
	Pass            bool
}

// Check evaluates the envelope criteria on a load run: recs from the
// controller file and the load file, hostPrefix the synthetic agents.
func Check(recs []Record, hostPrefix string, c Criteria) []Result {
	var (
		first, last               time.Time
		partition                 time.Time
		caughtAt                  time.Time
		havePartition, haveCaught bool
		haveNotCaught             bool
	)
	for _, r := range recs {
		if first.IsZero() || r.T.Before(first) {
			first = r.T
		}
		if r.T.After(last) {
			last = r.T
		}
		if r.Kind != KindMark {
			continue
		}
		switch r.Mark {
		case "partition_start":
			if !havePartition {
				partition, havePartition = r.T, true
			}
		case "caught_up":
			if !haveCaught {
				caughtAt, haveCaught = r.T, true
			}
		case "not_caught_up":
			haveNotCaught = true
		}
	}
	if !havePartition {
		return []Result{{Name: "partition_marks", Got: "none", Want: "a partition_start mark", Pass: false}}
	}

	out := []Result{latencyResult("latency_p99_before", recs, Filter{From: first, To: partition}, c)}
	if !haveCaught {
		out = append(out, Result{Name: "latency_p99_after", Got: "no caught_up mark",
			Want: latencyWant(c), Pass: false})
	} else {
		// Skip the interval that contains the caught_up mark: its events were
		// queued during the partition.
		from, interval := caughtAt, time.Duration(0)
		var best time.Time
		for _, r := range recs {
			if r.Kind != KindCtl || r.Ctl == nil || r.T.Before(caughtAt) {
				continue
			}
			if best.IsZero() || r.T.Before(best) {
				best = r.T
				interval = time.Duration(r.Ctl.IntervalMS) * time.Millisecond
			}
		}
		from = caughtAt.Add(interval)
		out = append(out, latencyResult("latency_p99_after", recs, Filter{From: from, To: last}, c))
	}

	// The rest are whole-run figures (agent samples restricted to the
	// synthetic hosts of the load run).
	s := Summarize(recs, Filter{HostPrefix: hostPrefix})
	out = append(out, Result{
		Name: "no_loss",
		Got:  fmt.Sprintf("gap events %d, shed %d", s.GapEvents, s.ShedMax),
		Want: "0 gap events and 0 shed",
		Pass: s.GapEvents == 0 && s.ShedMax == 0,
	})
	out = append(out, Result{
		Name: "reconnect_time",
		Got:  fmt.Sprintf("n %d, never %d, max %.1f s", s.ReconnectN, s.NoReconnect, s.Reconnect.Max),
		Want: fmt.Sprintf("every agent reconnects once within %.1f s", c.MaxReconnectS),
		Pass: s.NoReconnect == 0 && s.ReconnectN > 0 && s.Reconnect.Max <= c.MaxReconnectS,
	})
	worstHost, worstReconnects := "", uint64(0)
	for host, n := range s.ReconnectsPerAgent {
		if n != 1 && (worstHost == "" || n > worstReconnects) {
			worstHost, worstReconnects = host, n
		}
	}
	reconnects := Result{Name: "reconnect_count", Want: "exactly 1 reconnect per agent", Pass: worstHost == ""}
	if worstHost != "" {
		reconnects.Got = fmt.Sprintf("%s reconnected %d times", worstHost, worstReconnects)
	}
	out = append(out, reconnects)
	out = append(out, Result{
		Name: "caught_up",
		Got:  fmt.Sprintf("caught_up %t, not_caught_up %t", haveCaught, haveNotCaught),
		Want: "a caught_up mark and no not_caught_up mark",
		Pass: haveCaught && !haveNotCaught,
	})
	return out
}

// latencyWant is the envelope figure for one latency criterion.
func latencyWant(c Criteria) string {
	return fmt.Sprintf("p99 at most %.1f ms", c.LatencyP99Ms)
}

// latencyResult summarises the records in f and passes when every class that
// carried events has a p99 within the envelope.
func latencyResult(name string, recs []Record, f Filter, c Criteria) Result {
	s := Summarize(recs, f)
	var worstClass string
	worst := 0.0
	for i, cl := range s.Class {
		if cl.EventsPerS == 0 && cl.LatencyMs.Max == 0 {
			continue
		}
		if cl.LatencyMs.P99 > worst {
			worst, worstClass = cl.LatencyMs.P99, ClassNames[i]
		}
	}
	if worstClass == "" {
		return Result{Name: name, Got: "no events", Want: latencyWant(c), Pass: true}
	}
	return Result{Name: name, Got: fmt.Sprintf("%s %.1f ms", worstClass, worst), Want: latencyWant(c), Pass: worst <= c.LatencyP99Ms}
}
