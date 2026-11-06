package bench

import "time"

// Record kinds: one controller record and one record per agent per sampling
// interval, plus the marks that delimit a load run's phases.
const (
	KindCtl   = "ctl"
	KindAgent = "agent"
	KindMark  = "mark"
)

// Record is one line of the bench file. Exactly one of Ctl, Agent and Mark is
// set, according to Kind.
type Record struct {
	T     time.Time    `json:"t"`
	Kind  string       `json:"kind"`
	Ctl   *Ctl         `json:"ctl,omitempty"`
	Agent *AgentSample `json:"agent,omitempty"`
	Mark  string       `json:"mark,omitempty"`
}

// Ctl is one interval of controller figures: counters are deltas over
// IntervalMS, gauges are instantaneous.
type Ctl struct {
	IntervalMS int64              `json:"interval_ms"`
	Events     [NumClasses]uint64 `json:"events"`     // events stored, by class
	Bytes      [NumClasses]uint64 `json:"bytes"`      // JSON bytes of those events
	Latency    [NumClasses]Hist   `json:"latency_ms"` // event time to store commit
	Commit     Hist               `json:"commit_ms"`  // SQLite commit of one ingest transaction
	GapRecords uint64             `json:"gap_records"`
	GapEvents  uint64             `json:"gap_events"` // events the gap records cover
	Connects   uint64             `json:"connects"`   // accepted hellos
	Down       Hist               `json:"down_ms"`    // time an agent was disconnected before its next hello
	CPUMs      uint64             `json:"cpu_ms"`     // controller process CPU time used in the interval
	RSSBytes   uint64             `json:"rss_bytes"`
	StoreBytes int64              `json:"store_bytes"` // database plus WAL
	// QuotaLevel is the highest store quota level reached in the interval
	// (W1 Task 8b); empty before that task merges.
	QuotaLevel    string             `json:"quota_level,omitempty"`
	SkippedEvents uint64             `json:"skipped_events,omitempty"` // events the quota refused in the interval
	Agents        int                `json:"agents"`
	Connected     int                `json:"connected"`
	QueryMS       map[string]float64 `json:"query_ms,omitempty"` // "overview", "health", "events"
}

// ModuleUse is one module's usage from the agent's heartbeat: cumulative
// counters except HeldBytes, which is a gauge.
type ModuleUse struct {
	State     string `json:"state"`
	CPUMs     uint64 `json:"cpu_ms"`     // cumulative
	HeldBytes uint64 `json:"held_bytes"` // gauge
	Events    uint64 `json:"events"`     // cumulative
	BytesOut  uint64 `json:"bytes_out"`  // cumulative
	Dropped   uint64 `json:"dropped"`    // cumulative
}

// AgentSample is one agent's figures at one sampling interval.
type AgentSample struct {
	Host        string               `json:"host"`
	Connected   bool                 `json:"connected"`
	ConnectedAt time.Time            `json:"connected_at"` // controller time of the last accepted hello
	Connects    uint64               `json:"connects"`
	RTTMs       float64              `json:"rtt_ms"` // 0 until the first echo
	Head        uint64               `json:"head"`   // agent head sequence from its last heartbeat
	Acked       uint64               `json:"acked"`
	LagEvents   uint64               `json:"lag_events"` // Head - Acked, 0 when Acked >= Head
	SpoolDepth  uint64               `json:"spool_depth"`
	Congestion  string               `json:"congestion"`
	Shed        uint64               `json:"shed"` // agent's cumulative shed count
	SkewMS      float64              `json:"skew_ms"`
	Modules     map[string]ModuleUse `json:"modules,omitempty"`
}
