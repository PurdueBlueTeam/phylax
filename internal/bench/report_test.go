package bench

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestSummarizeRates(t *testing.T) {
	t.Skip("unimplemented: W14 Task 5")
	var a, b Ctl
	a.Events[0], a.Bytes[0] = 20, 4000
	a.Latency[0].Observe(30 * time.Millisecond)
	b.Events[0], b.Bytes[0] = 40, 8000
	b.Latency[0].Observe(9 * time.Second)
	b.CPUMs = 2000
	s := Summarize([]Record{ctlRec(10, a), ctlRec(20, b)}, Filter{})
	if s.Class[0].EventsPerS != 3 || s.Class[0].BytesPerS != 600 {
		t.Fatalf("%+v", s.Class[0])
	}
	if s.Class[0].LatencyMs.Max != 10000 || s.Class[0].LatencyMs.P50 != 50 {
		t.Fatalf("%+v", s.Class[0].LatencyMs)
	}
	if s.CPUPct.Max != 20 {
		t.Fatalf("%+v", s.CPUPct)
	}
}

func TestSummarizeFilterAndPrefix(t *testing.T) {
	t.Skip("unimplemented: W14 Task 5")
	recs := []Record{agRec(10, AgentSample{Host: "bench-1", RTTMs: 2}), agRec(10, AgentSample{Host: "ad", RTTMs: 90}),
		agRec(50, AgentSample{Host: "bench-1", RTTMs: 4})}
	s := Summarize(recs, Filter{HostPrefix: "bench-", To: time.Unix(1700000040, 0)})
	if s.Agents != 1 || s.RTTMs.Max != 2 {
		t.Fatalf("%+v", s)
	}
}

func TestSummarizeReconnect(t *testing.T) {
	t.Skip("unimplemented: W14 Task 5")
	end := time.Unix(1700000100, 0).UTC()
	recs := []Record{{T: end, Kind: KindMark, Mark: "partition_end"},
		agRec(110, AgentSample{Host: "h1", ConnectedAt: end.Add(-100 * time.Second), Connects: 1}),
		agRec(120, AgentSample{Host: "h1", ConnectedAt: end.Add(4 * time.Second), Connects: 2}),
		agRec(120, AgentSample{Host: "h2", ConnectedAt: end.Add(-100 * time.Second), Connects: 1}),
		{T: end.Add(30 * time.Second), Kind: KindMark, Mark: "caught_up"}}
	s := Summarize(recs, Filter{})
	if s.ReconnectN != 1 || s.NoReconnect != 1 || s.Reconnect.Max != 4 || s.CatchUpS != 30 {
		t.Fatalf("%+v", s)
	}
	if s.ReconnectsPerAgent["h1"] != 1 || s.ReconnectsPerAgent["h2"] != 0 {
		t.Fatal(s.ReconnectsPerAgent)
	}
}

func TestSummarizeModuleRatesAndReset(t *testing.T) {
	t.Skip("unimplemented: W14 Task 5")
	mk := func(sec int, cpu, ev uint64) Record {
		return agRec(sec, AgentSample{Host: "h1", Modules: map[string]ModuleUse{"net": {State: "ok", CPUMs: cpu, Events: ev, HeldBytes: 5 << 20}}})
	}
	s := Summarize([]Record{mk(0, 1000, 100), mk(100, 3000, 700)}, Filter{})
	m := s.Module["net"]
	if m.CPUMsPerS != 20 || m.EventsPerS != 6 || m.HeldBytesMax != 5<<20 {
		t.Fatalf("%+v", m)
	}
	s = Summarize([]Record{mk(0, 5000, 900), mk(100, 400, 50)}, Filter{}) // restart: counters went down
	if s.Module["net"].CPUMsPerS != 4 || s.Module["net"].EventsPerS != 0.5 {
		t.Fatalf("%+v", s.Module["net"])
	}
}

func TestSummarizeSkewLine(t *testing.T) {
	t.Skip("unimplemented: W14 Task 5")
	s := Summarize([]Record{agRec(0, AgentSample{Host: "h", SkewMS: -7000})}, Filter{})
	var buf bytes.Buffer
	s.Write(&buf)
	if !strings.Contains(buf.String(), "skew abs max ms 7000.0") {
		t.Fatal(buf.String())
	}
}

func TestWriteGoldenOrder(t *testing.T) {
	t.Skip("unimplemented: W14 Task 5")
	// A small mixed fixture: assert the output lines start with, in order:
	// "window ", "class ", "critical ", "high ", "normal ", "bulk ", "commit ms", "down ms", "gaps ",
	// "controller ", "query ms", "agents ", "reconnect after partition", "module ", "mark ".
}
