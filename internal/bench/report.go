package bench

import (
	"fmt"
	"io"
	"math"
	"sort"
	"time"
)

// Filter selects the records a summary covers.
type Filter struct {
	From, To   time.Time // zero = unbounded; a record is in when From <= T <= To
	HostPrefix string    // agent samples only; "" = all
}

// Quantiles are exact nearest-rank percentiles plus the maximum.
type Quantiles struct{ P50, P95, P99, Max float64 }

// ClassSummary is one priority class's throughput and event-to-commit latency.
type ClassSummary struct {
	EventsPerS, BytesPerS float64
	LatencyMs             Quantiles // bucket upper bounds; Max is the highest non-empty bucket bound
}

// ModuleSummary is one module's usage across the agents in the window.
type ModuleSummary struct {
	CPUMsPerS    float64 // worst agent
	HeldBytesMax uint64
	EventsPerS   float64 // summed over agents
	BytesOutPerS float64 // summed over agents
	Dropped      uint64  // summed over agents
	WorstState   string
}

// Summary is what Summarize derives from the records in a window.
type Summary struct {
	From, To                        time.Time
	Samples, Agents                 int
	Class                           [NumClasses]ClassSummary
	CommitMs, DownMs                Quantiles
	GapRecords, GapEvents, Connects uint64
	CPUPct                          Quantiles // P50, P95, P99, Max of cpu_ms / interval
	RSSMaxBytes                     uint64
	StoreStart, StoreEnd            int64
	QueryMs                         map[string]Quantiles
	RTTMs                           Quantiles
	SpoolDepthMax, LagMax, ShedMax  uint64
	NonOKSamples                    int // agent samples whose congestion is not "ok" or ""
	SkewAbsMaxMS                    float64
	Reconnect                       Quantiles // seconds from the partition_end mark to the agent's next hello
	ReconnectN, NoReconnect         int
	ReconnectsPerAgent              map[string]uint64 // Connects(last) - Connects(first) in the window
	CatchUpS                        float64           // caught_up mark minus partition_end mark; -1 when either is absent
	Module                          map[string]ModuleSummary
	Marks                           []Record
}

// stateSeverity orders module states from worst to best: a module's WorstState
// is the highest-ranked state any agent reported.
var stateSeverity = map[string]int{
	"error": 5, "restarting": 4, "unavailable": 3, "degraded": 2, "disabled": 1, "ok": 0,
}

// timedAgent is one agent sample with its record time, so Summarize can take
// the first and last sample per host regardless of record order.
type timedAgent struct {
	t time.Time
	a AgentSample
}

// Summarize reduces the records the filter accepts to one Summary.
func Summarize(recs []Record, f Filter) Summary {
	s := Summary{CatchUpS: -1, QueryMs: map[string]Quantiles{}, ReconnectsPerAgent: map[string]uint64{}, Module: map[string]ModuleSummary{}}

	var (
		agents     []timedAgent
		marks      []Record
		intervalMs int64
		events     [NumClasses]uint64
		bytesOut   [NumClasses]uint64
		latency    [NumClasses]Hist
		commit     Hist
		down       Hist
		queryVals  = map[string][]float64{}
		cpuPct     []float64
		rtts       []float64
		mods       = map[string]map[string][]timedMod{} // host -> module -> samples
	)
	for _, r := range recs {
		if !inWindow(r.T, f) {
			continue
		}
		if s.From.IsZero() || r.T.Before(s.From) {
			s.From = r.T
		}
		if r.T.After(s.To) {
			s.To = r.T
		}
		switch r.Kind {
		case KindCtl:
			if r.Ctl == nil {
				continue
			}
			c := *r.Ctl
			s.Samples++
			intervalMs += c.IntervalMS
			for i := 0; i < NumClasses; i++ {
				events[i] += c.Events[i]
				bytesOut[i] += c.Bytes[i]
				latency[i].Add(c.Latency[i])
			}
			commit.Add(c.Commit)
			down.Add(c.Down)
			s.GapRecords += c.GapRecords
			s.GapEvents += c.GapEvents
			s.Connects += c.Connects
			if c.IntervalMS > 0 {
				cpuPct = append(cpuPct, float64(c.CPUMs)/float64(c.IntervalMS)*100)
			}
			if c.RSSBytes > s.RSSMaxBytes {
				s.RSSMaxBytes = c.RSSBytes
			}
			if s.Samples == 1 {
				s.StoreStart = c.StoreBytes
			}
			s.StoreEnd = c.StoreBytes
			for name, v := range c.QueryMS {
				queryVals[name] = append(queryVals[name], v)
			}
		case KindAgent:
			if r.Agent == nil || !hostMatches(r.Agent.Host, f.HostPrefix) {
				continue
			}
			a := *r.Agent
			agents = append(agents, timedAgent{t: r.T, a: a})
			if a.RTTMs > 0 {
				rtts = append(rtts, a.RTTMs)
			}
			if a.SpoolDepth > s.SpoolDepthMax {
				s.SpoolDepthMax = a.SpoolDepth
			}
			if a.LagEvents > s.LagMax {
				s.LagMax = a.LagEvents
			}
			if a.Shed > s.ShedMax {
				s.ShedMax = a.Shed
			}
			if a.Congestion != "" && a.Congestion != "ok" {
				s.NonOKSamples++
			}
			if abs := math.Abs(a.SkewMS); abs > s.SkewAbsMaxMS {
				s.SkewAbsMaxMS = abs
			}
			for name, u := range a.Modules {
				if mods[a.Host] == nil {
					mods[a.Host] = map[string][]timedMod{}
				}
				mods[a.Host][name] = append(mods[a.Host][name], timedMod{t: r.T, u: u})
			}
		case KindMark:
			marks = append(marks, r)
			s.Marks = append(s.Marks, r)
		}
	}
	sort.SliceStable(s.Marks, func(i, j int) bool { return s.Marks[i].T.Before(s.Marks[j].T) })

	if intervalMs > 0 {
		secs := float64(intervalMs) / 1000
		for i := 0; i < NumClasses; i++ {
			s.Class[i] = ClassSummary{
				EventsPerS: float64(events[i]) / secs,
				BytesPerS:  float64(bytesOut[i]) / secs,
				LatencyMs:  histQuantiles(latency[i]),
			}
		}
	}
	s.CommitMs, s.DownMs = histQuantiles(commit), histQuantiles(down)
	s.CPUPct = quantiles(cpuPct)
	s.RTTMs = quantiles(rtts)
	for name, v := range queryVals {
		s.QueryMs[name] = quantiles(v)
	}

	hosts := map[string]bool{}
	for _, ta := range agents {
		hosts[ta.a.Host] = true
	}
	s.Agents = len(hosts)
	s.ReconnectsPerAgent, s.Reconnect, s.ReconnectN, s.NoReconnect = reconnect(agents, marks)
	s.CatchUpS = catchUpS(marks)
	s.Module = moduleSummary(mods)
	return s
}

// inWindow reports whether t is inside f's time bounds (zero is unbounded).
func inWindow(t time.Time, f Filter) bool {
	if !f.From.IsZero() && t.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && t.After(f.To) {
		return false
	}
	return true
}

// hostMatches is the HostPrefix rule: "" accepts every host.
func hostMatches(host, prefix string) bool {
	return prefix == "" || len(host) >= len(prefix) && host[:len(prefix)] == prefix
}

// reconnect measures, for every partition_end mark, the first sample of each
// host whose ConnectedAt is after the mark, and counts the hosts with none.
func reconnect(agents []timedAgent, marks []Record) (perAgent map[string]uint64, q Quantiles, n, missing int) {
	perAgent = map[string]uint64{}
	byHost := map[string][]timedAgent{}
	for _, ta := range agents {
		byHost[ta.a.Host] = append(byHost[ta.a.Host], ta)
	}
	for _, samples := range byHost {
		sort.SliceStable(samples, func(i, j int) bool { return samples[i].t.Before(samples[j].t) })
	}
	var secs []float64
	for _, m := range marks {
		if m.Mark != "partition_end" {
			continue
		}
		for _, samples := range byHost {
			found := false
			for _, ta := range samples {
				if ta.a.ConnectedAt.After(m.T) {
					secs = append(secs, ta.a.ConnectedAt.Sub(m.T).Seconds())
					found = true
					break
				}
			}
			if !found {
				missing++
			}
		}
	}
	for host, samples := range byHost {
		first, last := samples[0].a.Connects, samples[len(samples)-1].a.Connects
		if last >= first {
			perAgent[host] = last - first
		} else {
			perAgent[host] = last // the controller restarted: its count began again
		}
	}
	return perAgent, quantiles(secs), len(secs), missing
}

// catchUpS is the first caught_up mark minus the first partition_end mark, -1
// when either is absent.
func catchUpS(marks []Record) float64 {
	var end, up time.Time
	for _, m := range marks {
		switch m.Mark {
		case "partition_end":
			if end.IsZero() {
				end = m.T
			}
		case "caught_up":
			if up.IsZero() {
				up = m.T
			}
		}
	}
	if end.IsZero() || up.IsZero() {
		return -1
	}
	return up.Sub(end).Seconds()
}

// timedMod is one module usage sample with its record time.
type timedMod struct {
	t time.Time
	u ModuleUse
}

// moduleSummary aggregates the per-host module samples: rates from the first
// and last sample, worst agent for CPU, sums over agents for events, bytes and
// drops.
func moduleSummary(mods map[string]map[string][]timedMod) map[string]ModuleSummary {
	out := map[string]ModuleSummary{}
	for _, byName := range mods {
		for name, samples := range byName {
			sort.SliceStable(samples, func(i, j int) bool { return samples[i].t.Before(samples[j].t) })
			first, last := samples[0], samples[len(samples)-1]
			secs := last.t.Sub(first.t).Seconds()
			m := out[name]
			m.CPUMsPerS = math.Max(m.CPUMsPerS, rate(first.u.CPUMs, last.u.CPUMs, secs)) // worst agent
			m.EventsPerS += rate(first.u.Events, last.u.Events, secs)                    // summed over agents
			m.BytesOutPerS += rate(first.u.BytesOut, last.u.BytesOut, secs)
			m.Dropped += counterDelta(first.u.Dropped, last.u.Dropped)
			for _, s := range samples {
				m.HeldBytesMax = max(m.HeldBytesMax, s.u.HeldBytes)
				m.WorstState = worseState(m.WorstState, s.u.State)
			}
			out[name] = m
		}
	}
	return out
}

// rate is (last - first) / secs, using last when the counter went backwards
// (the agent or module restarted). A zero window has no rate.
//
// shortcut: a single sample reports rate 0, upgrade when the bench samples
// longer than one interval.
func rate(first, last uint64, secs float64) float64 {
	if secs <= 0 {
		return 0
	}
	if last < first {
		return float64(last) / secs
	}
	return float64(last-first) / secs
}

// counterDelta is last - first, using last when the counter went backwards.
func counterDelta(first, last uint64) uint64 {
	if last < first {
		return last
	}
	return last - first
}

// worseState returns the more severe of two module states.
func worseState(a, b string) string {
	if stateSeverity[b] > stateSeverity[a] {
		return b
	}
	return a
}

// quantiles are exact nearest-rank percentiles over sorted copies of v.
func quantiles(v []float64) Quantiles {
	if len(v) == 0 {
		return Quantiles{}
	}
	sort.Float64s(v)
	at := func(p float64) float64 {
		r := int(math.Ceil(p * float64(len(v))))
		if r < 1 {
			r = 1
		}
		if r > len(v) {
			r = len(v)
		}
		return v[r-1]
	}
	return Quantiles{P50: at(0.5), P95: at(0.95), P99: at(0.99), Max: v[len(v)-1]}
}

// histQuantiles are the bucket bounds of a histogram's nearest-rank quantiles;
// Max is the highest non-empty bucket's bound.
func histQuantiles(h Hist) Quantiles {
	return Quantiles{P50: h.QuantileMs(0.5), P95: h.QuantileMs(0.95), P99: h.QuantileMs(0.99), Max: h.QuantileMs(1)}
}

// Write prints the text report: one block per figure group, in a fixed order,
// omitting a block whose data is empty.
func (s Summary) Write(w io.Writer) {
	fmt.Fprintf(w, "window  %s .. %s  %.1f s  %d samples  %d agents\n",
		s.From.UTC().Format(time.RFC3339), s.To.UTC().Format(time.RFC3339), s.To.Sub(s.From).Seconds(), s.Samples, s.Agents)
	if s.Samples > 0 {
		fmt.Fprintf(w, "class     events/s  bytes/s  latency ms p50 p95 p99 max\n")
		for i, name := range ClassNames {
			q := s.Class[i].LatencyMs
			fmt.Fprintf(w, "%-9s %.1f  %.1f  %.1f %.1f %.1f %.1f\n", name, s.Class[i].EventsPerS, s.Class[i].BytesPerS,
				q.P50, q.P95, q.P99, q.Max)
		}
		fmt.Fprintf(w, "commit ms  p50 %.1f  p95 %.1f  p99 %.1f  max %.1f\n", s.CommitMs.P50, s.CommitMs.P95, s.CommitMs.P99, s.CommitMs.Max)
		fmt.Fprintf(w, "down ms    p50 %.1f  p95 %.1f  p99 %.1f  max %.1f\n", s.DownMs.P50, s.DownMs.P95, s.DownMs.P99, s.DownMs.Max)
		fmt.Fprintf(w, "gaps  records %d  events %d   connects %d\n", s.GapRecords, s.GapEvents, s.Connects)
		fmt.Fprintf(w, "controller  cpu %%  p50 %.1f  p95 %.1f  p99 %.1f  max %.1f   rss max MB %.1f   store MB %.1f -> %.1f\n",
			s.CPUPct.P50, s.CPUPct.P95, s.CPUPct.P99, s.CPUPct.Max, float64(s.RSSMaxBytes)/(1<<20),
			float64(s.StoreStart)/(1<<20), float64(s.StoreEnd)/(1<<20))
		names := make([]string, 0, len(s.QueryMs))
		for name := range s.QueryMs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			q := s.QueryMs[name]
			fmt.Fprintf(w, "query ms  %s  p50 %.1f  p95 %.1f  p99 %.1f  max %.1f\n", name, q.P50, q.P95, q.P99, q.Max)
		}
	}
	if s.Agents > 0 {
		fmt.Fprintf(w, "agents  rtt ms p50 %.1f  p95 %.1f  p99 %.1f  max %.1f   spool depth max %d   lag events max %d   shed max %d   non-ok samples %d   skew abs max ms %.1f\n",
			s.RTTMs.P50, s.RTTMs.P95, s.RTTMs.P99, s.RTTMs.Max, s.SpoolDepthMax, s.LagMax, s.ShedMax, s.NonOKSamples, s.SkewAbsMaxMS)
	}
	if s.ReconnectN > 0 || s.NoReconnect > 0 {
		fmt.Fprintf(w, "reconnect after partition s  p50 %.1f  p95 %.1f  p99 %.1f  max %.1f   n %d   never %d   catch up s %.1f\n",
			s.Reconnect.P50, s.Reconnect.P95, s.Reconnect.P99, s.Reconnect.Max, s.ReconnectN, s.NoReconnect, s.CatchUpS)
	}
	names := make([]string, 0, len(s.Module))
	for name := range s.Module {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		m := s.Module[name]
		fmt.Fprintf(w, "module  %s  cpu ms/s %.1f  held MB %.1f  events/s %.1f  bytes out/s %.1f  dropped %d  state %s\n",
			name, m.CPUMsPerS, float64(m.HeldBytesMax)/(1<<20), m.EventsPerS, m.BytesOutPerS, m.Dropped, m.WorstState)
	}
	for _, m := range s.Marks {
		fmt.Fprintf(w, "mark  %s  %s\n", m.T.UTC().Format(time.RFC3339), m.Mark)
	}
}
