package bench

import (
	"io"
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

// Summarize reduces the records the filter accepts to one Summary.
func Summarize(recs []Record, f Filter) Summary {
	panic("unimplemented: W14 Task 5")
}

// Write prints the text report: one block per figure group, in a fixed order,
// omitting a block whose data is empty.
func (s Summary) Write(w io.Writer) {
	panic("unimplemented: W14 Task 5")
}
