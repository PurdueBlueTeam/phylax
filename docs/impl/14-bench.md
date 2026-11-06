# W14: Comms Bench Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure the agent-to-controller communication path two ways with the same numbers: a controller-side recorder that samples per-agent link, spool, ingest, module, process, store and query figures every 10 s into a bounded JSONL file (on by default, summarised by `phylax bench report`), and a lab load generator (`phylax bench load`) that drives N synthetic agents built on the real link, spool and agent code against a real controller, cuts the link for 60 s, and reports and checks the same figures against the design envelope.

**Architecture:** One new leaf package `internal/bench` (histograms, record types, bounded log, recorder, report, process stats; standard library only) and a sub-package `internal/bench/load` (cut-able TCP proxy, synthetic module, scenario runner). The controller counts what it already sees (the ingest drain, `hello`, `heartbeat`) into fixed-size atomic histograms and counters, and implements `bench.Source`; the recorder turns cumulative counters into per-interval deltas. The link measures heartbeat round trip itself and ships it in the next heartbeat. Synthetic agents are real `agent.Agent` values (real `spool`, `link`, supervisor, heartbeat, reconnect) whose only module emits events at configured rates; they enroll with real tokens from W2's `WriteBundles` and reach the controller through the proxy, which is how the partition is made.

**Tech Stack:** Go 1.27.2 (mise), standard library only (`encoding/json`, `sync/atomic`, `net`, `os`, `runtime`). No new modules in `go.mod`. `/proc` for process figures on Linux.

**Spec:** `phylax_design.md` (v4): "Wire protocol and spool" (heartbeat, priority, reliability, the spool, "Volume and envelope": outages up to 60 s, event-to-controller latency 10 s or less while the link is up), "Core components: Agent runtime (heartbeat)", "Event store and vault", "Testing and lab" (the lab, the new "Comms bench" paragraph, test matrix T80 and T81); `docs/impl/invitational-data.md` questions O3, O5, O6, S16; `docs/impl/01-module-contract.md` Task 14 (`link.Heartbeat.Health`, `(*Controller).AgentHealth`) and the `module.Health` and `module.Usage` types; `docs/impl/02-invitational.md` Tasks 2, 3 (`WriteBundles`, `serve -bundles`) and Task 15 (how the rehearsal runs on the replica). Master plan: `docs/impl/README.md` (this plan is W14; the README table gets a row when this plan merges).

## Decisions (David, 2026-11-06, and this plan)

| Decision | Why |
| --- | --- |
| Two parts, one set of numbers: a live recorder at the event and a lab load run on the replica | David asked to compare the event's numbers with the replica's; the load run is the only way to test the 60 s outage on demand |
| Recorder samples every 10 s (`bench_interval`), on by default in every mode including observe mode; `bench_off: true` disables it | Observe mode is configuration and nothing in it turns the recorder off; the interval is a field only because tests need 500 ms |
| One format: JSONL, one record per line, `<data_dir>/bench.jsonl` plus `bench.jsonl.1` | `jq` and the report both read it; an append of one line cannot leave a half record in the middle; no CSV, no second format |
| Bounded: the file rotates at `bench_max_mb` (default 64) and keeps one previous file, 128 MB at most | 12 agents at 10 s is about 5 MB an hour, so a whole competition fits; a long soak drops the oldest, never fills the disk |
| Latency, commit time, down time are fixed 1-2-5 millisecond histograms recorded as per-interval bucket deltas | Percentiles over a run need mergeable data; 16 integers per series is bounded; bucket edge 10 000 ms equals the envelope, so "p99 at most 10 s" is exact |
| RTT is heartbeat send to its echoed `ack`, measured by the agent's `link.Session` and shipped in the next heartbeat as `rtt_us` | No ping message exists; reuses the heartbeat and the ack the controller already sends. It includes the controller's heartbeat handler wait, which is what an agent experiences |
| Event-to-controller latency is controller clock at store commit minus the event time corrected by the agent's last heartbeat clock skew, clamped at 0, per priority class | Events carry the agent clock; the skew is already measured (`AgentStatus.ClockSkew`); the skew includes one-way delay, so the error is at most RTT/2 and the recorder exports `skew_ms` beside it |
| Bytes by class are the JSON size of stored events, not wire bytes | The wire carries mixed-class compressed batches, so per-class wire bytes do not exist; the lab reads wire bytes from interface counters |
| Per-module numbers are `module.Usage` (`cpu_ms`, `held_bytes`, `events`, `bytes_out`, `dropped`) from `Heartbeat.Health`, taken as cumulative counters except `held_bytes`; the report derives rates and handles a counter reset | W1 Task 14 names; `held_bytes` is the contract's only per-module memory figure, so per-module RSS is reported as held bytes and the agent process RSS comes from the C2 sampler |
| Time to reconnect = controller `ConnectedAt` (last accepted `hello`) minus the `partition_end` mark | Works for synthetic and real agents alike and needs no agent-side hook; marks come from `bench load` or `phylax bench mark` on the controller host, so one clock |
| Synthetic agents are real `agent.Agent` values with one synthetic module, enrolled with real tokens through W2's bundles, behind a cut-able TCP proxy | "Real internal/link + spool code" and a real enrollment; the proxy drops every connection for the partition without touching agent code |
| Pass criteria are the four the envelope gives; every other number is measured and reported | Design decision 9; the envelope is a sizing figure. The four: p99 event-to-commit at most 10 s outside the partition and its recovery; zero gap events and zero shed after a 60 s partition; each agent reconnects once within 35 s of restore (30 s backoff cap plus handshake); all agents catch up |
| `bench load` requires `-lab`, and bench hosts exist only in a lab manifest copy | It writes synthetic events into the target controller's store permanently; one flag prevents pointing it at a controller with real data |
| The controller disk quota level and the events it skipped are reported when W1 Task 8b is merged (R9, 2026-11-06): `Ctl.QuotaLevel` (the highest level reached in the interval: `ok`, `bulk`, `evidence`, `critical`) and `Ctl.SkippedEvents`; the report prints both with the store size, and any level above `ok` is shown at the top of the report | The Invitational collects far more data than a normal run and the bench is where store growth is read; a skipped event is a gap, so the zero-gap pass criterion already fails if the quota sheds during a run |
| Controller process CPU and RSS are Linux-only (`/proc/self`); other systems report 0 | The controller runs on Linux (`ubuntu-wkst`); `shortcut:` comment |

## Global Constraints

- Go 1.27.2 via mise; `CGO_ENABLED=0`; `make build build-windows vet test race` passes at every commit (linux/amd64 and windows/amd64 both build and vet). `-race` needs `CGO_ENABLED=1`.
- Every package ships tests; tests exercise the real code (no mock of the code under test; the only fake is `bench.Source` in the recorder's own unit test, and the real controller `Source` is tested against a real controller in Task 11). A test that needs Linux `/proc` or `sh` calls `t.Skip` with a reason.
- Commits are small, one logical change, message `area: summary` (for example `bench: histograms`). No attribution lines of any kind.
- No shelling out in the default path; bounded everything: the log file, record line length (1 MiB on read), histogram size, the per-host maps (bounded by enrolled agents), proxy connections (bounded by `MaxConns`).
- No compatibility shims or dual formats. New wire fields are optional and receivers ignore unknown fields (`link` package comment), so `ProtoMinor` does not change.
- Times stored in UTC. Passwords and tokens never appear in a record, a log line or a report.
- A module imports only core packages (W1). `internal/bench` imports only the standard library; `internal/controller`, `internal/store` and `cmd/phylax` import it; it imports none of them. `internal/bench/load` may import `internal/agent`, `internal/link`, `internal/spool`, `internal/event` and `internal/bench`, never `internal/agent/mods`.
- The design is authoritative; a forced design change edits `phylax_design.md` in the same commit with the reason.
- Code style ponytail: the smallest complete change; a known limit carries `// shortcut: <limit>, <when to upgrade>`.
- Branch `v4-bench`, cut from `v4` after W1 and W2's Tasks 2 and 3 merge. **Order:** Tasks 1 to 12 (the recorder and report) ship first and are what runs at the Invitational; Tasks 13 to 17 (load) follow.

## Review Focus

1. **The recorder perturbing what it measures.** Counters sit in `drain` under the per-agent lock and marshal each stored event once for its size. Expected: atomics and fixed arrays only, no allocation per histogram observation, no lock added beyond the existing `st.mu`; the lab run compares controller CPU with the recorder on and `bench_off` (Task 17 step 5).
2. **Unbounded growth.** The log file, the per-agent samples, the proxy's connection set. Expected: the file never exceeds `2 x bench_max_mb`; one sample is O(agents x modules); the proxy drops closed connections (Task 3 `TestLogRotationBounded`, Task 13 `TestProxyCutClosesAndRefuses`).
3. **Wrong latency from clock skew.** A skewed agent clock makes every latency wrong by the skew. Expected: the corrected figure is clamped at 0, the sample carries `skew_ms`, and the report prints the largest absolute skew beside the latency table so a bad figure is recognised (Task 5 `TestSummarizeSkewLine`).
4. **A torn or hand-edited file.** The controller can die mid-line. Expected: the reader skips an unparsable last line and refuses a line over 1 MiB without reading the rest into memory (Task 3 `TestReadSkipsTornLine`).
5. **The partition not being a real partition.** The proxy closes connections (a reset) while a real outage often drops packets silently, which the controller notices only after `read_idle` (20 s). Expected: the load run uses the proxy for repeatability and the lab task repeats the partition with `iptables -j DROP` for the real agents, recording both (Task 17).
6. **Synthetic data in a real store.** Expected: `-lab` is required, bench hosts exist only in the generated lab manifest, and the lab task restores the controller's snapshot afterwards (Tasks 15, 16, 17).

---

## What exists today (verified in the code on branch `v4`, 2026-11-06) and what is new

| Number | Already measured | New in this plan |
| --- | --- | --- |
| Spool depth and congestion state | `link.Heartbeat.SpoolDepth`, `.Congestion` (every 5 s), kept in `controller.AgentStatus`; `agent.health` event every 60 s carries `spool.{head,ack,depth,used_bytes,unacked_bytes,shed,gap_records,state}` | Sampled every 10 s per agent into the file (Task 11) |
| Gap records | `store.Store.Gaps(ctx, agent)` (shown on the Platform page); `spool.Stats.GapRecords`, `Shed` | Controller counts gap records and gap events as it stores them (Task 10) |
| Ack lag | `AgentStatus.Acked`, `.Buffered`; heartbeat `Seq` (the agent's head) is received and dropped | `HeadSeq` kept; `lag_events = HeadSeq - Acked` (Task 10) |
| Reconnects | `LinkStatus.Connects` on the agent, only in `agent.health`; the controller logs "agent connected" | Controller counts `hello`s per agent, remembers `ConnectedAt`, measures the disconnected time (Task 10) |
| Clock skew | `AgentStatus.ClockSkew`, `SkewAt` | Exported per sample; used to correct latency (Task 10) |
| Module state | `Heartbeat.Modules` (state strings); W1 Task 14 adds `Heartbeat.Health` with `module.Usage` | Consumed and recorded (Task 11); nothing new on the agent |
| RTT | nothing (no ping; `Ack` is not tied to a heartbeat) | `Heartbeat.ID`, `Heartbeat.RTTUs`, `Ack.HB`; stamped in `link.Session` (Task 8) |
| Events/s and bytes/s by priority class | nothing | Per-class counters in `drain` (Task 10) |
| Event-to-controller latency | nothing (`event.Event.Time` is set by the spool, the store keeps no commit time) | Per-class histogram in `drain` (Task 10) |
| SQLite commit latency, store size | nothing public (`store.fileSize` is private) | `Store.CommitHist()`, `Store.Size()` (Task 9) |
| Controller CPU and RSS | nothing | `bench.ProcStats` (Task 7) |
| UI and API query latency | nothing | The recorder times `WebOps.Overview`, `WebOps.Health` and `store.Events` each sample (Task 11) |
| Percentile reports, load generator, partition step, pass criteria | nothing | Tasks 5, 6, 12 to 15 |

---

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `internal/bench/{hist,record,log,recorder,report,check,proc}.go`, `proc_linux.go`, `proc_other.go` | histograms, record types, bounded log and reader, recorder, summary, criteria, process figures | 1 to 7 |
| `internal/link/{message,session}.go`, `docs/protocol.md` | `Heartbeat.ID`, `RTTUs`, `Ack.HB`, session stamping | 8 |
| `internal/store/{store,ingest}.go` | `CommitHist`, `Size` | 9 |
| `internal/controller/{benchstats,agent,config,bench}.go` | counters, per-agent fields, `Source`, recorder wiring, config | 10, 11 |
| `cmd/phylax/bench.go` | `phylax bench report|mark|load` | 12, 15 |
| `internal/bench/load/{proxy,gen,run}.go` | cut-able proxy, synthetic module and agents, scenario | 13 to 15 |
| `tools/bench/make-bench-manifest.sh` | lab manifest with N bench hosts | 16 |
| `docs/impl/lab/w14-bench.md` | lab record | 17 |

---

### Task 1: Seams (Sonnet or Opus)

**Files:**
- Create: `internal/bench/{hist,record,log,recorder,report,check,proc}.go`, `internal/bench/proc_linux.go`, `internal/bench/proc_other.go`, `internal/bench/load/{proxy,gen,run}.go`
- Create (every test file with `t.Skip("unimplemented: W14 Task N")` bodies, one per later task): `internal/bench/{hist,log,recorder,report,check,proc}_test.go`, `internal/bench/load/{proxy,gen,run}_test.go`
- Modify: none

**Interfaces:** the seams task writes these types in full and every function body as `panic("unimplemented: W14 Task N")`. Later tasks use these names and no others.

```go
// ---- internal/bench/hist.go ----
package bench

const (
	NumClasses = 4 // critical, high, normal, bulk: the order of event.Priority and spool class names
	HistBuckets = 16
)

var ClassNames = [NumClasses]string{"critical", "high", "normal", "bulk"}

// HistBoundsMs are the upper bounds (inclusive) of buckets 0..14; bucket 15 holds everything larger.
var HistBoundsMs = [HistBuckets - 1]float64{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 60000}

type Hist [HistBuckets]uint64 // JSON: an array of 16 integers

func (h *Hist) Observe(d time.Duration)
func (h Hist) Count() uint64
func (h *Hist) Add(o Hist)
func (h Hist) Sub(o Hist) Hist            // saturating at 0 per bucket
func (h Hist) QuantileMs(q float64) float64 // upper bound of the bucket holding the q-quantile (0 < q <= 1); math.Inf(1) for bucket 15; 0 when empty

type AtomicHist struct{ b [HistBuckets]atomic.Uint64 }

func (h *AtomicHist) Observe(d time.Duration)
func (h *AtomicHist) Snapshot() Hist

// ---- internal/bench/record.go ----
const (
	KindCtl   = "ctl"
	KindAgent = "agent"
	KindMark  = "mark"
)

type Record struct {
	T     time.Time    `json:"t"`
	Kind  string       `json:"kind"`
	Ctl   *Ctl         `json:"ctl,omitempty"`
	Agent *AgentSample `json:"agent,omitempty"`
	Mark  string       `json:"mark,omitempty"`
}

// Ctl is one interval of controller figures: counters are deltas over IntervalMS, gauges are instantaneous.
type Ctl struct {
	IntervalMS int64              `json:"interval_ms"`
	Events     [NumClasses]uint64 `json:"events"`      // events stored, by class
	Bytes      [NumClasses]uint64 `json:"bytes"`       // JSON bytes of those events
	Latency    [NumClasses]Hist   `json:"latency_ms"`  // event time to store commit
	Commit     Hist               `json:"commit_ms"`   // SQLite commit of one ingest transaction
	GapRecords uint64             `json:"gap_records"`
	GapEvents  uint64             `json:"gap_events"`  // events the gap records cover
	Connects   uint64             `json:"connects"`    // accepted hellos
	Down       Hist               `json:"down_ms"`     // time an agent was disconnected before its next hello
	CPUMs      uint64             `json:"cpu_ms"`      // controller process CPU time used in the interval
	RSSBytes   uint64             `json:"rss_bytes"`
	StoreBytes int64              `json:"store_bytes"` // database plus WAL
	QuotaLevel    string          `json:"quota_level,omitempty"`   // highest store quota level in the interval (W1 Task 8b); empty before it merges
	SkippedEvents uint64          `json:"skipped_events,omitempty"` // events the quota refused in the interval
	Agents     int                `json:"agents"`
	Connected  int                `json:"connected"`
	QueryMS    map[string]float64 `json:"query_ms,omitempty"` // "overview", "health", "events"
}

type ModuleUse struct {
	State     string `json:"state"`
	CPUMs     uint64 `json:"cpu_ms"`     // cumulative
	HeldBytes uint64 `json:"held_bytes"` // gauge
	Events    uint64 `json:"events"`     // cumulative
	BytesOut  uint64 `json:"bytes_out"`  // cumulative
	Dropped   uint64 `json:"dropped"`    // cumulative
}

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

// ---- internal/bench/log.go ----
type Log struct{ /* path, max, file, size, mu */ }

func OpenLog(path string, maxBytes int64) (*Log, error)        // O_APPEND|O_CREATE, mode 0600; size from the existing file
func (l *Log) Write(r Record) error                             // rotates to path+".1" before a write that would pass maxBytes
func (l *Log) Close() error
func AppendMark(path, name string, now time.Time) error         // one mark record, 1 MiB cap file
func ReadFiles(paths ...string) ([]Record, error)               // each file then its ".1" first if present; sorted by T; skips an unparsable last line; error on a line over 1 MiB

// ---- internal/bench/recorder.go ----
type Counters struct { // cumulative since the controller started
	Events, Bytes        [NumClasses]uint64
	Latency              [NumClasses]Hist
	Commit               Hist
	GapRecords, GapEvents, Connects uint64
	Down                 Hist
}

type Source interface {
	Counters() Counters
	Agents() []AgentSample
	StoreBytes() int64
	QueryTimes(ctx context.Context) map[string]float64
}

// QuotaSource is optional: a Source that also implements it gets QuotaLevel and SkippedEvents in the ctl record
// (the controller's benchSource implements it once W1 Task 8b is merged; the recorder type-asserts).
type QuotaSource interface {
	QuotaLevel() string      // highest level since the last call, then reset
	SkippedEvents() uint64   // cumulative; the recorder records the difference
}

type Recorder struct{ /* src, log, interval, proc, prev */ }

func NewRecorder(src Source, log *Log, interval time.Duration) *Recorder
func (r *Recorder) Sample(ctx context.Context, now time.Time) error // writes one ctl record and one agent record per agent
func (r *Recorder) Run(ctx context.Context)                          // Sample every interval until ctx is done; write errors are logged once and sampling continues

// ---- internal/bench/report.go ----
type Filter struct {
	From, To   time.Time // zero = unbounded; a record is in when From <= T <= To
	HostPrefix string    // agent samples only; "" = all
}

type Quantiles struct{ P50, P95, P99, Max float64 }

type ClassSummary struct {
	EventsPerS, BytesPerS float64
	LatencyMs             Quantiles // bucket upper bounds; Max is the highest non-empty bucket bound
}

type ModuleSummary struct {
	CPUMsPerS    float64 // worst agent
	HeldBytesMax uint64
	EventsPerS   float64 // summed over agents
	BytesOutPerS float64 // summed over agents
	Dropped      uint64  // summed over agents
	WorstState   string
}

type Summary struct {
	From, To        time.Time
	Samples, Agents int
	Class           [NumClasses]ClassSummary
	CommitMs, DownMs Quantiles
	GapRecords, GapEvents, Connects uint64
	CPUPct          Quantiles // P50, P95, P99, Max of cpu_ms / interval
	RSSMaxBytes     uint64
	StoreStart, StoreEnd int64
	QueryMs         map[string]Quantiles
	RTTMs           Quantiles
	SpoolDepthMax, LagMax, ShedMax uint64
	NonOKSamples    int     // agent samples whose congestion is not "ok" or ""
	SkewAbsMaxMS    float64
	Reconnect       Quantiles // seconds from the partition_end mark to the agent's next hello
	ReconnectN, NoReconnect int
	ReconnectsPerAgent map[string]uint64 // Connects(last) - Connects(first) in the window
	CatchUpS        float64   // caught_up mark minus partition_end mark; -1 when either is absent
	Module          map[string]ModuleSummary
	Marks           []Record
}

func Summarize(recs []Record, f Filter) Summary
func (s Summary) Write(w io.Writer)

// ---- internal/bench/check.go ----
type Criteria struct {
	LatencyP99Ms  float64 // 10000
	MaxReconnectS float64 // 35
}

type Result struct {
	Name, Got, Want string
	Pass            bool
}

// Check evaluates the envelope criteria on a load run: recs from the controller file and the load file, hostPrefix the synthetic agents.
func Check(recs []Record, hostPrefix string, c Criteria) []Result

// ---- internal/bench/proc.go ----
func ProcStats() (cpuMs, rssBytes uint64) // Linux: /proc/self; elsewhere 0, 0
```

`internal/bench/load` signatures are in Tasks 13 to 15.

- [ ] **Step 1:** Write the files above (types complete, bodies `panic`), the skipped tests, and `docs/impl/14-bench.md` references nothing else. In `internal/bench/hist.go` add `// shortcut: fixed 16 buckets, upgrade when a figure needs finer than 1-2-5`.
- [ ] **Step 2: Check events are not declared.** Run `grep -rn "event.Declared()" --include=*_test.go .` and confirm no test that enumerates declared kinds imports `internal/bench`. The synthetic kind `bench.load` is deliberately undeclared (it is emitted only by `phylax bench load`, `event.Validate` runs only in tests).
- [ ] **Step 3: Run:** `make build build-windows vet test`. Expected: PASS (all new tests skipped).
- [ ] **Step 4: Commit.** `git add internal/bench && git commit -m "bench: seams"`

---

### Task 2: Histograms

**Files:**
- Modify: `internal/bench/hist.go`
- Test: `internal/bench/hist_test.go`

**Interfaces:**
- Consumes: Task 1 types.
- Produces: working `Hist`, `AtomicHist` methods. Bucket of a duration: the first `i` with `ms <= HistBoundsMs[i]`, else 15.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestHistBuckets(t *testing.T) {
	var h Hist
	h.Observe(500 * time.Microsecond) // 0.5 ms -> bucket 0 (<= 1)
	h.Observe(10 * time.Millisecond)  // bucket 3 (<= 10)
	h.Observe(10001 * time.Microsecond * 1000) // 10.001 s -> bucket 13 (<= 20000)
	h.Observe(2 * time.Minute)        // bucket 15
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
	if got := h.QuantileMs(0.5); got != 10 { t.Fatal(got) }
	if got := h.QuantileMs(0.99); got != 10 { t.Fatal(got) } // 99th of 100 is still in the 10 ms bucket
	if got := h.QuantileMs(1); got != 5000 { t.Fatal(got) }
	var empty Hist
	if empty.QuantileMs(0.5) != 0 { t.Fatal("empty") }
	h.Observe(5 * time.Minute)
	if !math.IsInf(h.QuantileMs(1), 1) { t.Fatal("overflow bucket") }
}
func TestHistSubAdd(t *testing.T) {
	a, b := Hist{3, 2}, Hist{1, 5}
	d := a.Sub(b)
	if d[0] != 2 || d[1] != 0 { t.Fatalf("%v", d) } // saturating
	a.Add(b)
	if a[0] != 4 || a[1] != 7 { t.Fatalf("%v", a) }
}
func TestAtomicHistConcurrent(t *testing.T) {
	var h AtomicHist
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); for j := 0; j < 1000; j++ { h.Observe(time.Millisecond) } }()
	}
	wg.Wait()
	if h.Snapshot().Count() != 8000 { t.Fatal(h.Snapshot()) }
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/bench/ -run 'Hist' -count=1`. Expected: FAIL (`panic: unimplemented`).
- [ ] **Step 3: Implement.** `QuantileMs`: rank = `ceil(q * count)`, walk buckets accumulating, return the bound of the bucket that reaches rank.
- [ ] **Step 4: Run, expect PASS.** Run: `CGO_ENABLED=1 go test -race ./internal/bench/ -run Hist -count=1`.
- [ ] **Step 5: Commit.** `git commit -am "bench: histograms"`

---

### Task 3: Bounded log and reader

**Files:**
- Modify: `internal/bench/log.go`
- Test: `internal/bench/log_test.go`

**Interfaces:**
- Consumes: `Record`.
- Produces: `OpenLog`, `(*Log).Write`, `(*Log).Close`, `AppendMark`, `ReadFiles` as in Task 1. Rotation: when `size + len(line) > max` and `size > 0`, close the file, `os.Rename(path, path+".1")` (replacing any older one), open a new file. A single line larger than `max` is still written alone. `ReadFiles` reads `p+".1"` then `p` for each path, a missing file is skipped, a line over 1 MiB is an error naming the file, an unparsable **last** line of a file is skipped and an unparsable earlier line is an error.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func rec(sec int, mark string) Record {
	return Record{T: time.Unix(1700000000+int64(sec), 0).UTC(), Kind: KindMark, Mark: mark}
}
func TestLogRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bench.jsonl")
	l, err := OpenLog(p, 1<<20)
	if err != nil { t.Fatal(err) }
	for i := 0; i < 3; i++ { if err := l.Write(rec(i, "m")); err != nil { t.Fatal(err) } }
	l.Close()
	got, err := ReadFiles(p)
	if err != nil || len(got) != 3 || got[2].T != rec(2, "m").T { t.Fatalf("%v %v", got, err) }
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 { t.Fatal(st.Mode()) }
}
func TestLogRotationBounded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bench.jsonl")
	l, _ := OpenLog(p, 1000)
	for i := 0; i < 200; i++ { l.Write(rec(i, "xxxxxxxxxxxxxxxxxxxx")) }
	l.Close()
	a, _ := os.Stat(p)
	b, err := os.Stat(p + ".1")
	if err != nil || a.Size() > 1000 || b.Size() > 1000 { t.Fatalf("%v %v", a, b) }
	got, _ := ReadFiles(p)
	if len(got) == 0 || got[len(got)-1].T != rec(199, "").T { t.Fatal("newest record missing") }
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].T.Before(got[j].T) }) { t.Fatal("unsorted") }
}
func TestLogReopenAppends(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bench.jsonl")
	l, _ := OpenLog(p, 1<<20); l.Write(rec(0, "a")); l.Close()
	l, _ = OpenLog(p, 1<<20); l.Write(rec(1, "b")); l.Close()
	if got, _ := ReadFiles(p); len(got) != 2 { t.Fatal(got) }
}
func TestReadSkipsTornLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.jsonl")
	os.WriteFile(p, []byte(`{"t":"2023-11-14T22:13:20Z","kind":"mark","mark":"a"}`+"\n"+`{"t":"2023-11-14T22:1`), 0o600)
	got, err := ReadFiles(p)
	if err != nil || len(got) != 1 { t.Fatalf("%v %v", got, err) }
	os.WriteFile(p, []byte("garbage\n"+`{"t":"2023-11-14T22:13:20Z","kind":"mark","mark":"a"}`+"\n"), 0o600)
	if _, err := ReadFiles(p); err == nil { t.Fatal("garbage in the middle accepted") }
}
func TestReadRefusesHugeLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.jsonl")
	os.WriteFile(p, []byte(strings.Repeat("x", 2<<20)+"\n"), 0o600)
	if _, err := ReadFiles(p); err == nil { t.Fatal("2 MiB line accepted") }
}
func TestAppendMark(t *testing.T) {
	p := filepath.Join(t.TempDir(), "marks.jsonl")
	AppendMark(p, "partition_start", time.Unix(1700000000, 0)); AppendMark(p, "partition_end", time.Unix(1700000060, 0))
	got, _ := ReadFiles(p)
	if len(got) != 2 || got[1].Mark != "partition_end" || got[1].Kind != KindMark { t.Fatal(got) }
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/bench/ -run 'Log|Read|AppendMark' -count=1`.
- [ ] **Step 3: Implement.** Use `bufio.Reader.ReadSlice('\n')` with a 1 MiB buffer limit (`bufio.ErrBufferFull` is the "too long" error). `Write` holds a mutex.
- [ ] **Step 4: Run, expect PASS.** `CGO_ENABLED=1 go test -race ./internal/bench/ -count=1`.
- [ ] **Step 5: Commit.** `git commit -am "bench: bounded JSONL log and reader"`

---

### Task 4: Recorder

**Files:**
- Modify: `internal/bench/recorder.go`
- Test: `internal/bench/recorder_test.go`

**Interfaces:**
- Consumes: `Source`, `Log`, `Counters`, `ProcStats` (Task 7; until then `Recorder.proc` is a field defaulting to `ProcStats`, and the test sets it).
- Produces: `NewRecorder`, `Sample`, `Run`. `Sample` writes one `KindCtl` record whose counters are the difference from the previous sample's `Counters()` (the first sample differs from zero), `IntervalMS` since the previous sample (since `NewRecorder` for the first), `CPUMs` the difference of `proc()`, `RSSBytes`, `StoreBytes`, `Agents = len(Agents())`, `Connected` the count with `Connected`, `QueryMS` from `QueryTimes`; then one `KindAgent` record per agent, same `T`. `Run` calls `Sample` at each tick and once more when the context ends; a write error is logged once through `slog.Warn` and does not stop it.

- [ ] **Step 1: Remove the skips and write the test** (the fake `Source` is the edge; the recorder, log and reader are real):

```go
type fakeSrc struct{ c Counters; ags []AgentSample }
func (f *fakeSrc) Counters() Counters { return f.c }
func (f *fakeSrc) Agents() []AgentSample { return f.ags }
func (f *fakeSrc) StoreBytes() int64 { return 4096 }
func (f *fakeSrc) QueryTimes(context.Context) map[string]float64 { return map[string]float64{"overview": 3.5} }

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
	if err := r.Sample(context.Background(), t0); err != nil { t.Fatal(err) }
	src.c.Events[1], src.c.Bytes[1], src.c.GapEvents = 160, 32000, 7
	src.c.Latency[1].Observe(9 * time.Second)
	if err := r.Sample(context.Background(), t0.Add(10*time.Second)); err != nil { t.Fatal(err) }
	l.Close()
	recs, _ := ReadFiles(p)
	var ctl []*Ctl
	agents := 0
	for _, x := range recs {
		switch x.Kind { case KindCtl: ctl = append(ctl, x.Ctl); case KindAgent: agents++ }
	}
	if len(ctl) != 2 || agents != 4 { t.Fatalf("%d ctl %d agent", len(ctl), agents) }
	c := ctl[1]
	if c.Events[1] != 60 || c.Bytes[1] != 12000 || c.GapEvents != 7 || c.Connects != 0 { t.Fatalf("%+v", c) }
	if c.Latency[1].Count() != 1 || c.Latency[1].QuantileMs(1) != 10000 { t.Fatalf("%v", c.Latency[1]) }
	if c.IntervalMS != 10000 || c.CPUMs != 250 || c.Agents != 2 || c.Connected != 1 || c.QueryMS["overview"] != 3.5 { t.Fatalf("%+v", c) }
}
func TestRecorderRunStopsAndFlushes(t *testing.T) {
	// Run with interval 20 ms for ~100 ms, cancel: at least 3 ctl records, Run returns within 1 s.
}
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/bench/ -run Recorder -count=1`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** `CGO_ENABLED=1 go test -race ./internal/bench/ -run Recorder -count=1`.
- [ ] **Step 5: Commit.** `git commit -am "bench: recorder turns cumulative counters into interval deltas"`

---

### Task 5: Summarize and the text report

**Files:**
- Modify: `internal/bench/report.go`
- Test: `internal/bench/report_test.go`

**Interfaces:**
- Consumes: `Record`, `Hist`, `Filter`.
- Produces: `Summarize`, `(Summary).Write`.

Rules (each has a test below):
- A record is in the window when `Filter` accepts its `T`; agent records also need `HostPrefix`.
- `Class[i].EventsPerS` = sum of `Ctl.Events[i]` over included ctl records divided by the sum of their `IntervalMS` in seconds; `BytesPerS` likewise; `LatencyMs` from the sum of the interval `Latency[i]` histograms (`Max` = bound of the highest non-empty bucket).
- `CPUPct` quantiles (nearest rank, exact values) of `CPUMs / IntervalMS * 100` per ctl record; `QueryMs[name]` quantiles of the per-record values; `RTTMs` over agent samples with `RTTMs > 0`; `SkewAbsMaxMS` max of `abs(SkewMS)`; `NonOKSamples` counts congestion not `""` or `ok`.
- `Reconnect`: for each mark named `partition_end` (time `T0`) and each host with agent samples, the first sample with `ConnectedAt` after `T0` gives `ConnectedAt - T0` seconds; a host with none counts in `NoReconnect`.
- `CatchUpS` = first `caught_up` mark minus first `partition_end` mark, -1 when either is absent. `Marks` lists every mark in the window.
- `ReconnectsPerAgent[host]` = last `Connects` minus first `Connects` in the window.
- Module: for each (host, module) take the first and last sample in the window, `rate = (last - first) / seconds` (last < first means a restart: use `last`); `ModuleSummary` aggregates by module name as described in Task 1's field comments; `WorstState` order: `error`, `over_budget`, `restarting`, `unavailable`, `degraded`, `disabled`, `ok`.
- `Write` prints exactly these lines (numbers `%.1f`, bytes in MB with one decimal), in this order, omitting a block whose data is empty:

```
window  <From RFC3339> .. <To RFC3339>  <seconds> s  <Samples> samples  <Agents> agents
class     events/s  bytes/s  latency ms p50 p95 p99 max
critical  ...
...
commit ms  p50 p95 p99 max
down ms    p50 p95 p99 max
gaps  records <n>  events <n>   connects <n>
controller  cpu %  p50 p95 p99 max   rss max MB <x>   store MB <start> -> <end>
query ms  <name>  p50 p95 p99 max      (one line per name, sorted)
agents  rtt ms p50 p95 p99 max   spool depth max <n>   lag events max <n>   shed max <n>   non-ok samples <n>   skew abs max ms <x>
reconnect after partition s  p50 p95 p99 max   n <n>   never <n>   catch up s <x>
module  <name>  cpu ms/s <x>  held MB <x>  events/s <x>  bytes out/s <x>  dropped <n>  state <s>     (one line per module, sorted)
mark  <RFC3339>  <name>     (one per mark)
```

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func ctlRec(sec int, c Ctl) Record {
	c.IntervalMS = 10000
	return Record{T: time.Unix(1700000000+int64(sec), 0).UTC(), Kind: KindCtl, Ctl: &c}
}
func agRec(sec int, a AgentSample) Record {
	return Record{T: time.Unix(1700000000+int64(sec), 0).UTC(), Kind: KindAgent, Agent: &a}
}
func TestSummarizeRates(t *testing.T) {
	var a, b Ctl
	a.Events[0], a.Bytes[0] = 20, 4000
	a.Latency[0].Observe(30 * time.Millisecond)
	b.Events[0], b.Bytes[0] = 40, 8000
	b.Latency[0].Observe(9 * time.Second)
	b.CPUMs = 2000
	s := Summarize([]Record{ctlRec(10, a), ctlRec(20, b)}, Filter{})
	if s.Class[0].EventsPerS != 3 || s.Class[0].BytesPerS != 600 { t.Fatalf("%+v", s.Class[0]) }
	if s.Class[0].LatencyMs.Max != 10000 || s.Class[0].LatencyMs.P50 != 50 { t.Fatalf("%+v", s.Class[0].LatencyMs) }
	if s.CPUPct.Max != 20 { t.Fatalf("%+v", s.CPUPct) }
}
func TestSummarizeFilterAndPrefix(t *testing.T) {
	recs := []Record{agRec(10, AgentSample{Host: "bench-1", RTTMs: 2}), agRec(10, AgentSample{Host: "ad", RTTMs: 90}),
		agRec(50, AgentSample{Host: "bench-1", RTTMs: 4})}
	s := Summarize(recs, Filter{HostPrefix: "bench-", To: time.Unix(1700000040, 0)})
	if s.Agents != 1 || s.RTTMs.Max != 2 { t.Fatalf("%+v", s) }
}
func TestSummarizeReconnect(t *testing.T) {
	end := time.Unix(1700000100, 0).UTC()
	recs := []Record{{T: end, Kind: KindMark, Mark: "partition_end"},
		agRec(110, AgentSample{Host: "h1", ConnectedAt: end.Add(-100 * time.Second), Connects: 1}),
		agRec(120, AgentSample{Host: "h1", ConnectedAt: end.Add(4 * time.Second), Connects: 2}),
		agRec(120, AgentSample{Host: "h2", ConnectedAt: end.Add(-100 * time.Second), Connects: 1}),
		{T: end.Add(30 * time.Second), Kind: KindMark, Mark: "caught_up"}}
	s := Summarize(recs, Filter{})
	if s.ReconnectN != 1 || s.NoReconnect != 1 || s.Reconnect.Max != 4 || s.CatchUpS != 30 { t.Fatalf("%+v", s) }
	if s.ReconnectsPerAgent["h1"] != 1 || s.ReconnectsPerAgent["h2"] != 0 { t.Fatal(s.ReconnectsPerAgent) }
}
func TestSummarizeModuleRatesAndReset(t *testing.T) {
	mk := func(sec int, cpu, ev uint64) Record {
		return agRec(sec, AgentSample{Host: "h1", Modules: map[string]ModuleUse{"net": {State: "ok", CPUMs: cpu, Events: ev, HeldBytes: 5 << 20}}})
	}
	s := Summarize([]Record{mk(0, 1000, 100), mk(100, 3000, 700)}, Filter{})
	m := s.Module["net"]
	if m.CPUMsPerS != 20 || m.EventsPerS != 6 || m.HeldBytesMax != 5<<20 { t.Fatalf("%+v", m) }
	s = Summarize([]Record{mk(0, 5000, 900), mk(100, 400, 50)}, Filter{}) // restart: counters went down
	if s.Module["net"].CPUMsPerS != 4 || s.Module["net"].EventsPerS != 0.5 { t.Fatalf("%+v", s.Module["net"]) }
}
func TestSummarizeSkewLine(t *testing.T) {
	s := Summarize([]Record{agRec(0, AgentSample{Host: "h", SkewMS: -7000})}, Filter{})
	var buf bytes.Buffer
	s.Write(&buf)
	if !strings.Contains(buf.String(), "skew abs max ms 7000.0") { t.Fatal(buf.String()) }
}
func TestWriteGoldenOrder(t *testing.T) {
	// A small mixed fixture: assert the output lines start with, in order:
	// "window ", "class ", "critical ", "high ", "normal ", "bulk ", "commit ms", "down ms", "gaps ", "controller ", "query ms", "agents ", "reconnect after partition", "module ", "mark ".
}
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/bench/ -run 'Summarize|Write' -count=1`.
- [ ] **Step 3: Implement** with one pass over the records and exact-value quantiles by sorting (`nearest rank = ceil(q * n)`). `Write` uses `fmt.Fprintf` with fixed column widths.
- [ ] **Step 4: Run, expect PASS.** `CGO_ENABLED=1 go test -race ./internal/bench/ -run 'Summarize|Write' -count=1`.
- [ ] **Step 5: Commit.** `git commit -am "bench: summary and text report"`

---

### Task 6: Envelope criteria

**Files:**
- Modify: `internal/bench/check.go`
- Test: `internal/bench/check_test.go`

**Interfaces:**
- Consumes: `Summarize`, `Record`, marks named `load_start`, `partition_start`, `partition_end`, `caught_up`, `not_caught_up`, `load_end`.
- Produces: `Check(recs, hostPrefix, c) []Result`, results in this order and with these names:
  1. `latency_p99_before`: window `[first record, partition_start]`; for each class with events, p99 at most `c.LatencyP99Ms`. `Got` lists the worst class and value.
  2. `latency_p99_after`: window `[caught_up + 1 interval, last record]` (interval from the first ctl record in the window); same rule. Fails with `Got: "no caught_up mark"` when absent.
  3. `no_loss`: whole run: `GapEvents == 0` and `ShedMax == 0` (with `hostPrefix`).
  4. `reconnect_time`: `NoReconnect == 0`, `ReconnectN > 0` and `Reconnect.Max <= c.MaxReconnectS`.
  5. `reconnect_count`: every host in `ReconnectsPerAgent` equals exactly 1.
  6. `caught_up`: a `caught_up` mark exists and no `not_caught_up` mark.
  A run with no `partition_start` mark returns one failing result `partition_marks` with `Got: "none"`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
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
func failed(rs []Result) []string { var f []string; for _, r := range rs { if !r.Pass { f = append(f, r.Name) } }; return f }

func TestCheckPasses(t *testing.T) {
	rs := Check(loadRun(3*time.Second, 2*time.Second, 0, 1, 5*time.Second, true), "bench-", Criteria{LatencyP99Ms: 10000, MaxReconnectS: 35})
	if f := failed(rs); len(f) != 0 { t.Fatal(f, rs) }
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
		for _, r := range Check(recs, "bench-", c) { if r.Name == name && !r.Pass { found = true } }
		if !found { t.Errorf("%s did not fail", name) }
	}
}
func TestCheckNoPartitionMarks(t *testing.T) {
	rs := Check([]Record{{T: time.Unix(1700000000, 0), Kind: KindMark, Mark: "load_start"}}, "bench-", Criteria{})
	if len(rs) != 1 || rs[0].Name != "partition_marks" || rs[0].Pass { t.Fatal(rs) }
}
```
(`ctlRecAt` and `agRecAt` are the Task 5 helpers taking a time; the Task 5 test file's helpers move to `helpers_test.go` in this task.)

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/bench/ -run Check -count=1`.
- [ ] **Step 3: Implement** on top of `Summarize` with `Filter` windows.
- [ ] **Step 4: Run, expect PASS.** `CGO_ENABLED=1 go test -race ./internal/bench/ -count=1`.
- [ ] **Step 5: Commit.** `git commit -am "bench: envelope pass criteria"`

---

### Task 7: Process figures

**Files:**
- Modify: `internal/bench/proc_linux.go`, `internal/bench/proc_other.go`, `internal/bench/proc.go`
- Test: `internal/bench/proc_test.go`

**Interfaces:**
- Produces: `ProcStats() (cpuMs, rssBytes uint64)`. Linux: fields 14 and 15 (`utime`, `stime`, clock ticks) of `/proc/self/stat` times 10 ms (`// shortcut: USER_HZ assumed 100, upgrade if a kernel reports otherwise`), RSS = field 2 of `/proc/self/statm` times `os.Getpagesize()`. The parse of `/proc/self/stat` must skip past the last `)` because the command name may contain spaces. Other systems: `0, 0` with `// shortcut: controller runs on Linux, upgrade when it does not`. Build tags: `proc_linux.go` (`//go:build linux`), `proc_other.go` (`//go:build !linux`); `proc.go` holds nothing but the doc comment.

- [ ] **Step 1: Remove the skip and write the test:**

```go
func TestProcStats(t *testing.T) {
	if runtime.GOOS != "linux" { t.Skip("needs /proc") }
	c0, r0 := ProcStats()
	end := time.Now().Add(300 * time.Millisecond)
	for x := 0; time.Now().Before(end); x++ { _ = x * x }
	c1, _ := ProcStats()
	if c1-c0 < 100 || r0 < 1<<20 { t.Fatalf("cpu %d -> %d rss %d", c0, c1, r0) }
}
func TestParseStatCommWithSpaces(t *testing.T) {
	line := "123 (my (weird) name) S 1 2 3 4 5 6 7 8 9 10 250 150 0 0"
	if got := parseStatCPUTicks(line); got != 400 { t.Fatal(got) }
}
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/bench/ -run 'Proc|ParseStat' -count=1`.
- [ ] **Step 3: Implement** `parseStatCPUTicks(line string) uint64` in `proc_linux.go` (the second test is Linux-only too: put it in `proc_linux_test.go`).
- [ ] **Step 4: Run, expect PASS** and `GOOS=windows go vet ./internal/bench/`.
- [ ] **Step 5: Commit.** `git commit -am "bench: controller process CPU and RSS"`

---

### Task 8: Heartbeat round-trip time on the link

**Files:**
- Modify: `internal/link/message.go` (`Heartbeat.ID`, `Heartbeat.RTTUs`, `Ack.HB`), `internal/link/session.go` (stamp in `prepare`, echo in `readLoop`, `(*Session).RTT`), `internal/controller/agent.go` (`heartbeat` replies `Ack{Seq: acked, HB: hb.ID}`), `docs/protocol.md` (heartbeat row and the ack text)
- Test: `internal/link/rtt_test.go`

**Interfaces:**
- Consumes: `Session`, `Heartbeat`, `Ack`.
- Produces:
  ```go
  // Heartbeat gains:
  ID    uint64 `json:"id,omitempty"`     // per-session counter, set by Session when the heartbeat is queued
  RTTUs uint32 `json:"rtt_us,omitempty"` // round trip of the last echoed heartbeat, microseconds, set by Session; 0 until one is echoed
  // Ack gains:
  HB uint64 `json:"hb,omitempty"` // the Heartbeat.ID this ack answers
  func (s *Session) RTT() time.Duration // last measured heartbeat round trip, 0 if none
  ```
  Rules: `prepare` (before `Marshal`) sets `hb.ID = ++s.hbID` and `hb.RTTUs = uint32(min(rtt, 1<<32-1))` and records `hbSent = time.Now()` for that ID under a separate mutex `hbMu`. The `Ack` branch of `readLoop` calls `s.onHBEcho(v.HB)`: when `v.HB != 0 && v.HB == s.hbID` it sets `rtt = time.Since(hbSent)`, otherwise it ignores the echo (a superseded or late heartbeat). The session's own `AckFunc` reply on a received heartbeat also sets `HB: v.ID`.

- [ ] **Step 1: Write the failing test** using the package's real server helper (`startServer`, `memSource` in `helpers_test.go`):

```go
func TestHeartbeatRTT(t *testing.T) {
	// startServer with Handlers["phylax/agent"] running NewSession(Role controller) whose Handler answers
	// every *Heartbeat with s.TrySend(PrioCritical, &Ack{Seq: 0, HB: hb.ID}) after time.Sleep(20 * time.Millisecond).
	// The client side: NewSession(Role agent), Run; send a Heartbeat via TrySend; eventually (2 s) client.RTT() >= 20ms and < 1s.
	// Send a second heartbeat: its marshalled RTTUs (read through the server handler's received *Heartbeat) is >= 20000 and its ID is 2.
}
func TestStaleEchoIgnored(t *testing.T) {
	// Send heartbeat ID 1 then ID 2 quickly; the server echoes HB: 1 only. client.RTT() stays 0.
}
func TestHeartbeatNewFieldsAreOptional(t *testing.T) {
	// Unmarshal `{"seq":1,"host_clock":"2026-11-06T00:00:00Z"}` into *Heartbeat and `{"seq":2}` into *Ack: no error, ID/RTTUs/HB zero.
	// Unmarshal a heartbeat carrying an unknown field: no error (receivers ignore unknown fields).
}
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/link/ -run 'RTT|StaleEcho|NewFieldsAreOptional' -count=1`. Expected: FAIL (compile error `unknown field ID`).
- [ ] **Step 3: Implement** the fields, the stamp, the echo, the controller reply, and the two doc edits (`docs/protocol.md` line 130 row adds `id`, `rtt_us`; the ack text states `hb` echoes a heartbeat id).
- [ ] **Step 4: Run, expect PASS.** `CGO_ENABLED=1 go test -race ./internal/link/ ./internal/controller/ -count=1` (the existing session and controller tests still pass).
- [ ] **Step 5: Commit.** `git commit -am "link: heartbeat round-trip time (id, rtt_us, ack hb)"`

---

### Task 9: Store commit time and size

**Files:**
- Modify: `internal/store/store.go` (`commit bench.AtomicHist` field, `CommitHist`, `Size`), `internal/store/ingest.go` (time `tx.Commit()` at line 225)
- Test: `internal/store/bench_test.go`

**Interfaces:**
- Consumes: `bench.AtomicHist`, `bench.Hist`.
- Produces:
  ```go
  func (s *Store) CommitHist() bench.Hist // one observation per successful Ingest commit
  func (s *Store) Size() int64            // database file plus its -wal file, bytes
  ```

- [ ] **Step 1: Write the failing test** with the existing helpers in `store_test.go` (a real store, a helper that builds a valid chained batch; reuse the one the existing ingest tests use):

```go
func TestCommitHistAndSize(t *testing.T) {
	// s := open a temp store; enroll agent "a"; Size0 := s.Size()
	// ingest 3 batches of 50 chained events each (existing helper)
	// want: s.CommitHist().Count() == 3; s.Size() > Size0
	// an Ingest that fails before commit (unknown agent) does not add an observation: still 3 after it
}
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/store/ -run CommitHist -count=1` (compile error).
- [ ] **Step 3: Implement.** `Size` stats `s.path` and `s.path+"-wal"`; ignore errors (0).
- [ ] **Step 4: Run, expect PASS.** `CGO_ENABLED=1 go test -race ./internal/store/ -count=1`.
- [ ] **Step 5: Commit.** `git commit -am "store: commit latency histogram and size"`

---

### Task 10: Controller counters and per-agent fields

**Files:**
- Create: `internal/controller/benchstats.go`
- Modify: `internal/controller/agent.go` (`agentState` fields, `AgentStatus` fields, `hello`, `handleAgent` end, `heartbeat`, `drain`), `internal/controller/controller.go` (`bs benchStats` field)
- Test: `internal/controller/benchstats_test.go`

**Interfaces:**
- Consumes: `bench.AtomicHist`, `bench.NumClasses`, Task 8 `Heartbeat.RTTUs`.
- Produces:
  ```go
  // AgentStatus gains:
  Connects    uint64        // accepted hellos
  ConnectedAt time.Time     // controller time of the last accepted hello
  HeadSeq     uint64        // the agent's head sequence from its last heartbeat
  RTT         time.Duration // from the last heartbeat's RTTUs
  // internal/controller/benchstats.go
  type benchStats struct {
  	events, bytes                    [bench.NumClasses]atomic.Uint64
  	lat                              [bench.NumClasses]bench.AtomicHist
  	gapRecords, gapEvents, connects atomic.Uint64
  	down                             bench.AtomicHist
  }
  func (b *benchStats) stored(e event.Event, now time.Time, skew time.Duration) // one stored (non-gap) event
  func (b *benchStats) gap(e event.Event)                                      // one stored gap record
  func (b *benchStats) counters() bench.Counters                               // cumulative snapshot (Commit left zero; Task 11 fills it from the store)
  ```
  Rules: class = `int(e.Priority)` clamped to 0..3. Bytes = `len(json.Marshal(e))` (`// shortcut: one extra marshal per stored event, upgrade to the wire length if the controller CPU shows it`). Latency = `now - (e.Time - skew)` where `skew` is `st.hb.ClockSkew` (agent minus controller), clamped at 0. A gap record adds 1 to `gapRecords` and `e.Seq - from` to `gapEvents` (`gapFrom(e)`), and is not counted as an event. In `drain`, after `Ingest` returns, count every event of `run` with `Seq <= ack.Seq` (call `stored` or `gap`) before the existing `captureObserve`. In `hello`: `st.connects++`, `st.connectedAt = now`, `bs.connects++`, and when `st.downAt` is non-zero `bs.down.Observe(now - st.downAt)` and clear it. In `handleAgent` after the session ends, when `st.sess == a`: `st.downAt = c.now()`. `heartbeat` stores `HeadSeq = hb.Seq` and `RTT`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestBenchStatsClassesAndLatency(t *testing.T) {
	var b benchStats
	now := time.Unix(1700000100, 0)
	b.stored(event.Event{Priority: event.PriorityHigh, Time: now.Add(-3 * time.Second), Kind: "k", Fields: map[string]any{"a": 1}}, now, 0)
	b.stored(event.Event{Priority: event.PriorityHigh, Time: now.Add(-3 * time.Second), Kind: "k"}, now, 2*time.Second) // agent clock 2 s ahead: true age 1 s
	b.stored(event.Event{Priority: event.PriorityBulk, Time: now.Add(time.Hour)}, now, 0)                                   // future: clamped to 0
	c := b.counters()
	if c.Events[1] != 2 || c.Events[3] != 1 || c.Bytes[1] == 0 { t.Fatalf("%+v", c) }
	if c.Latency[1][11] != 1 /* 3 s <= 5000 */ || c.Latency[1][9] != 1 /* 1 s <= 1000 */ || c.Latency[3][0] != 1 { t.Fatalf("%v", c.Latency) }
}
func TestBenchStatsGap(t *testing.T) {
	var b benchStats
	b.gap(event.Event{Kind: store.KindGap, Seq: 20, Fields: map[string]any{"from": float64(11), "to": float64(19), "count": float64(9)}})
	if c := b.counters(); c.GapRecords != 1 || c.GapEvents != 9 || c.Events[0] != 0 { t.Fatalf("%+v", c) }
}
func TestControllerCountsIngestAndConnects(t *testing.T) {
	// x := newCtl(t); a := the e2e helper agent enrolled as "h1"; send 20 events: 10 PriorityNormal, 10 PriorityHigh; wait until acked 20.
	// c := x.c.bs.counters(): Events[1] == 10, Events[2] == 10, Latency[1].Count() == 10, Connects == 1.
	// a.kill() and wait for the reconnect: Connects == 2, c.Down.Count() == 1.
	// st, _ := x.c.AgentStatus("h1"): Connects == 2, !ConnectedAt.IsZero().
}
func TestHeartbeatCarriesHeadAndRTT(t *testing.T) {
	// real agent from e2e helpers sends a heartbeat with Seq 7 and RTTUs 1500 (link.Heartbeat sent through the session directly):
	// AgentStatus.HeadSeq == 7 and RTT == 1500*time.Microsecond.
}
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/controller/ -run 'BenchStats|CountsIngest|HeadAndRTT' -count=1`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** `CGO_ENABLED=1 go test -race ./internal/controller/ -count=1` (all existing controller tests too).
- [ ] **Step 5: Commit.** `git commit -am "controller: ingest, gap, connect and latency counters for the bench"`

---

### Task 11: Controller `Source`, config and the recorder in `Serve`

**Files:**
- Create: `internal/controller/bench.go`
- Modify: `internal/controller/config.go` (`BenchOff bool json:"bench_off"`, `BenchInterval Duration json:"bench_interval"` default 10 s, `BenchMaxMB int json:"bench_max_mb"` default 64), `internal/controller/controller.go` (`Serve` starts the recorder next to `watchSilence`; `Close` closes the log)
- Test: `internal/controller/bench_test.go`

**Interfaces:**
- Consumes: `bench.Source`, `bench.NewRecorder`, `bench.OpenLog`, `Store.CommitHist`, `Store.Size`, `Controller.AgentStatus`, `Controller.AgentHealth(host) map[string]module.Health` (W1 Task 14), `NewWebOps`, `WebOps.Overview`, `WebOps.Health`, `store.Query`.
- Produces:
  ```go
  type benchSource struct{ c *Controller; ops *WebOps }
  func newBenchSource(c *Controller) *benchSource            // ops = NewWebOps(c, c.cfg.PlansPath, chains.Config{})
  func (s *benchSource) Counters() bench.Counters            // c.bs.counters() with Commit = c.st.CommitHist()
  func (s *benchSource) Agents() []bench.AgentSample         // one per AgentHosts(), sorted by host
  func (s *benchSource) StoreBytes() int64                   // c.st.Size()
  func (s *benchSource) QueryTimes(ctx context.Context) map[string]float64 // "overview", "health", "events" (store.Events, Limit 100, Desc), each bounded by a 5 s context; a failed query is omitted
  func (c *Controller) BenchPath() string                    // filepath.Join(cfg.DataDir, "bench.jsonl")
  ```
  Mapping: `Modules[name]` from `AgentHealth`: `State = string(h.State)`, `CPUMs = h.Usage.CPUMillis`, `HeldBytes = h.Usage.HeldBytes`, `Events = h.Usage.Events`, `BytesOut = h.Usage.BytesOut`, `Dropped = h.Usage.Dropped`. `LagEvents = HeadSeq - Acked` when positive. `RTTMs = RTT / time.Millisecond` as float. `SkewMS = ClockSkew` as float ms. `Shed = Drops`. `Congestion`, `SpoolDepth`, `Connected`, `Connects`, `ConnectedAt`, `Head`, `Acked` copied.

- [ ] **Step 1: Write the failing tests:**

```go
func TestBenchSourceSamplesRealAgent(t *testing.T) {
	// x := newCtl(t) with Config.BenchInterval = 200ms (set before start); a real e2e agent "h1" sends 30 normal events and heartbeats
	// whose RTTUs = 800 and whose Health (W1 Task 14) carries module "net" {Usage: {CPUMillis: 90, HeldBytes: 1<<20, Events: 30, BytesOut: 5000}}.
	// Wait 1 s. recs, _ := bench.ReadFiles(x.c.BenchPath()).
	// Want: at least 3 ctl records; the sum of Ctl.Events[2] over them == 30; Latency[2].Count() == 30; Commit.Count() >= 1;
	// Ctl.StoreBytes > 0; Ctl.RSSBytes > 0 (Linux); QueryMS has "overview", "health", "events";
	// an agent record for "h1" with RTTMs == 0.8, Connected, Connects == 1, Modules["net"].CPUMs == 90 && HeldBytes == 1<<20.
}
func TestBenchOffWritesNothing(t *testing.T) {
	// Config.BenchOff = true: after 500 ms of Serve there is no bench.jsonl in the data dir.
}
func TestBenchDefaultsOn(t *testing.T) {
	cfg := Config{DataDir: t.TempDir()}
	if err := cfg.Validate(); err != nil || cfg.BenchOff || time.Duration(cfg.BenchInterval) != 10*time.Second || cfg.BenchMaxMB != 64 { t.Fatalf("%+v %v", cfg, err) }
}
func TestBenchConfigRejectsUnknownKey(t *testing.T) { /* LoadConfig of {"data_dir":"x","bench_of":true} errors (existing strict loader) */ }
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/controller/ -run 'BenchSource|BenchOff|BenchDefaults|BenchConfig' -count=1`.
- [ ] **Step 3: Implement.** `Serve` opens the log (`BenchMaxMB << 20`), runs `bench.NewRecorder(newBenchSource(c), log, interval).Run(ctx)` in a goroutine tracked by the same `WaitGroup` as `watchSilence`, and closes the log when it returns. A failure to open the log logs a warning and continues without the recorder (the controller must start even when the disk is odd).
- [ ] **Step 4: Run, expect PASS.** `CGO_ENABLED=1 go test -race ./internal/controller/ -count=1`.
- [ ] **Step 5: Run it for real.** Start `phylax serve -data-dir $(mktemp -d)` with a throwaway enrolled test agent (the e2e helpers' `cmd/phylax/agent_test.go` flow, or `phylax agent` with a bundle from `phylax serve -bundles`), wait 25 s, and `tail -3 <data-dir>/bench.jsonl | jq -c '.kind'`. Expected: `"ctl"`, `"agent"` lines every 10 s. Say in the report if no agent could be enrolled.
- [ ] **Step 6: Commit.** `git commit -am "controller: bench recorder on by default, writing bench.jsonl"`

---

### Task 12: `phylax bench report` and `phylax bench mark`

**Files:**
- Create: `cmd/phylax/bench.go`
- Test: `cmd/phylax/bench_test.go`

**Interfaces:**
- Consumes: `bench.ReadFiles`, `bench.Summarize`, `bench.AppendMark`, `bench.Check`.
- Produces: the `bench` command (`register(command{name: "bench", summary: "communications bench: report, mark, load", run: runBench})`) with subcommands:
  - `phylax bench report [-from RFC3339] [-to RFC3339] [-host-prefix P] [-check] FILE...` prints `Summarize(...).Write` for the window; when the records hold `partition_start` and `caught_up` marks it prints the whole run first and then the three phases (`before partition`, `partition and recovery`, `after`) each under a `== name` line; with `-check` it also prints `bench.Check` results as `PASS name got want` or `FAIL name got want` and returns an error (exit 1) if any fail. `-check` with no partition marks prints the one failing `partition_marks` result.
  - `phylax bench mark FILE NAME` appends one mark with the current time.
  `load` is added in Task 15 (`runBench` dispatches on the first argument; an unknown one prints usage and returns an error).

- [ ] **Step 1: Write the failing tests:**

```go
func TestBenchReportPrintsSummary(t *testing.T) {
	// Write a bench file with bench.OpenLog: two ctl records (events[1] = 50 each, interval 10 s) and one agent record.
	// out := capture stdout of commands["bench"].run(ctx, []string{"report", file})  (the command writes to os.Stdout; swap it with a pipe as the other cmd tests do)
	// want out contains "window ", "high ", "5.0" (events/s), and "agents ".
}
func TestBenchMarkAppends(t *testing.T) {
	// run "bench mark FILE partition_start" twice; bench.ReadFiles(FILE) has 2 marks with names in order, T within 2 s of now.
}
func TestBenchReportCheckFailsWithoutMarks(t *testing.T) {
	// "report -check FILE" on a file with no partition marks returns an error and prints "FAIL partition_marks".
}
func TestBenchUnknownSubcommand(t *testing.T) { /* run(ctx, []string{"nope"}) errors, "usage" in stderr */ }
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./cmd/phylax/ -run 'BenchReport|BenchMark|BenchUnknown' -count=1`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** `CGO_ENABLED=1 go test -race ./cmd/phylax/ -count=1`, then `make build build-windows vet`.
- [ ] **Step 5: Run it for real** on the file from Task 11 step 5: `./phylax bench report <data-dir>/bench.jsonl`. Expected: the table above with that agent's row filled; say so in the report.
- [ ] **Step 6: Commit.** `git commit -am "phylax bench report and mark"`

---

### Task 13: Cut-able TCP proxy

**Files:**
- Modify: `internal/bench/load/proxy.go`
- Test: `internal/bench/load/proxy_test.go`

**Interfaces:**
- Produces:
  ```go
  type Proxy struct{ /* ln, target, mu, conns map[net.Conn]struct{}, cut bool, max int */ }
  func NewProxy(listen, target string, maxConns int) (*Proxy, error) // listens now; Addr() is usable at once
  func (p *Proxy) Addr() string
  func (p *Proxy) Cut()     // closes every open pair; until Restore an accepted connection is closed immediately
  func (p *Proxy) Restore()
  func (p *Proxy) Close() error // stops accepting, closes everything, waits for the goroutines
  ```
  Each accepted connection dials `target` (5 s timeout), copies both ways with `io.Copy`, and removes itself from the set when either side ends. Over `maxConns` the new connection is closed. `// shortcut: no per-connection byte counters, upgrade if wire bytes per agent are needed`.

- [ ] **Step 1: Remove the skips and write the tests** (a real TCP echo server as the target):

```go
func TestProxyForwards(t *testing.T) { /* echo server; dial proxy; write "ping"; read "ping" */ }
func TestProxyCutClosesAndRefuses(t *testing.T) {
	// two open conns through the proxy; p.Cut(); both reads return an error/EOF within 1 s;
	// a new dial succeeds at TCP level but its read returns EOF within 1 s (refused after accept);
	// p.Restore(); a new dial echoes again.
}
func TestProxyMaxConns(t *testing.T) { /* maxConns 2: the third connection reads EOF; after closing one, a new one works */ }
func TestProxyCloseWaits(t *testing.T) { /* Close returns, no goroutine left: connection count 0, a dial now fails */ }
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/bench/load/ -run Proxy -count=1`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** `CGO_ENABLED=1 go test -race ./internal/bench/load/ -run Proxy -count=1`.
- [ ] **Step 5: Commit.** `git commit -am "bench: cut-able TCP proxy"`

---

### Task 14: Synthetic module and agents

**Files:**
- Modify: `internal/bench/load/gen.go`
- Test: `internal/bench/load/gen_test.go`

**Interfaces:**
- Consumes: `agent.Agent`, `agent.Config`, `agent.Layout`, `agent.Bundle`, `agent.ModuleSpec`, `agent.Module`, `agent.Emit`, `event.Event`, `spool.Options`, `link.Backoff`, `bench.NumClasses`.
- Produces:
  ```go
  // Gen is the synthetic module: it emits Rates[class] events per second of kind "bench.load" at that priority.
  type Gen struct {
  	Rates [bench.NumClasses]float64 // events/s per class (critical, high, normal, bulk)
  	Size  int                       // payload bytes of the "pad" field
  	emitted atomic.Uint64
  	stop    atomic.Bool
  }
  func (g *Gen) Name() string                                  // "benchload"
  func (g *Gen) Start(ctx context.Context, emit agent.Emit) error // ticks every 100 ms, emits floor(rate*elapsed) catch-up per class; returns nil at ctx.Done or after Stop
  func (g *Gen) Stop()
  func (g *Gen) Emitted() uint64

  type Agents struct{ /* list of running agents */ }
  // StartAgents loads every bundle <dir>/<prefix>*.json (sorted; at most n), rewrites Controllers to []string{proxyAddr},
  // lays each out under work/<host>, and runs agent.New(...).Run in a goroutine with one shared Gen configuration (one Gen per agent).
  func StartAgents(ctx context.Context, bundleDir, prefix string, n int, proxyAddr, work string, rates [bench.NumClasses]float64, size int, bo link.Backoff, spoolMax int64) (*Agents, error)
  func (a *Agents) Hosts() []string
  func (a *Agents) Connected() int                 // agents whose Link().Connected is true
  func (a *Agents) StopGen()                       // every Gen.Stop
  func (a *Agents) Depth() (max uint64)            // max over agents of SpoolStats().HeadSeq - AckSeq
  func (a *Agents) Emitted() uint64                // sum of Gen.Emitted
  func (a *Agents) Stop()                          // cancel and wait for every Run to return
  ```
  Event shape: `event.Event{Kind: "bench.load", Priority: event.Priority(class), Fields: map[string]any{"n": <per-agent counter>, "pad": strings.Repeat("x", Size)}}`. The agent config sets `HeartbeatInterval: 5s` (the default), `HealthInterval: time.Hour` (no `agent.health` churn), `Logger` to a discard logger, `Spool: spool.Options{MaxBytes: spoolMax}` (0 = default 200 MB), `ModuleSpec{Module: gen, Rate: 0}` (unlimited, so the supervisor never drops the load). `StartAgents` returns an error naming the bundle when fewer than `n` bundles match or one fails `agent.ParseBundle`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestGenEmitsRates(t *testing.T) {
	g := &Gen{Rates: [bench.NumClasses]float64{1, 5, 20, 0}, Size: 50}
	var mu sync.Mutex
	got := map[event.Priority]int{}
	emit := func(e event.Event) error {
		mu.Lock(); defer mu.Unlock()
		got[e.Priority]++
		if e.Kind != "bench.load" || len(e.Fields["pad"].(string)) != 50 { t.Error(e) }
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	g.Start(ctx, emit)
	mu.Lock(); defer mu.Unlock()
	if got[event.PriorityCritical] < 1 || got[event.PriorityCritical] > 3 ||
		got[event.PriorityHigh] < 8 || got[event.PriorityHigh] > 12 ||
		got[event.PriorityNormal] < 35 || got[event.PriorityNormal] > 45 || got[event.PriorityBulk] != 0 { t.Fatal(got) }
	if g.Emitted() != uint64(got[0]+got[1]+got[2]) { t.Fatal(g.Emitted()) }
}
func TestGenStop(t *testing.T) { /* Start in a goroutine, Stop(), Start returns nil within 500 ms while ctx is live */ }
func TestStartAgentsRealEnrollment(t *testing.T) {
	// In package load_test (to import internal/controller without a cycle): controller.New on a temp dir (Config{AgentListen: "127.0.0.1:0"}),
	// Serve on a listener; c.WriteBundles(dir, []string{"bench-001", "bench-002"}, controller.BundleOptions{Controllers: []string{ln.Addr().String()}, TTL: time.Hour}) (W2 Task 2);
	// proxy := NewProxy("127.0.0.1:0", ln.Addr().String(), 16);
	// a, err := StartAgents(ctx, dir, "bench-", 2, proxy.Addr(), work, rates{0, 5, 5, 0}, 100, link.Backoff{Min: 50 * time.Millisecond, Max: 500 * time.Millisecond}, 0)
	// eventually (20 s): a.Connected() == 2, and c.AgentStatus("bench-001").Acked >= 20 and Connects == 1 (enrolled with the real token, once).
	// a.StopGen(); eventually a.Depth() == 0; a.Stop() returns; the token cannot be reused: c.Tokens consume of the same bundle token fails (existing tokens test API) -- assert via a second StartAgents on the same dir with fresh work dir: the agents never connect within 3 s (token consumed).
}
func TestStartAgentsNotEnoughBundles(t *testing.T) { /* dir with 1 bundle, n = 2 -> error mentions "need 2, found 1" */ }
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/bench/load/ -run 'Gen|StartAgents' -count=1`.
- [ ] **Step 3: Implement.** `Gen.Start` keeps `start := time.Now()` and per class `sent`; every 100 ms emits `int(rate*elapsed.Seconds()) - sent` events so a slow tick catches up, never more than 5000 per tick per class (`// shortcut: bounded burst, upgrade if a generator must model a stall`).
- [ ] **Step 4: Run, expect PASS.** `CGO_ENABLED=1 go test -race ./internal/bench/load/ -count=1`.
- [ ] **Step 5: Commit.** `git commit -am "bench: synthetic module and real-agent runner"`

---

### Task 15: Scenario runner and `phylax bench load`

**Files:**
- Modify: `internal/bench/load/run.go`, `cmd/phylax/bench.go`
- Test: `internal/bench/load/run_test.go` (package `load_test`), `cmd/phylax/bench_test.go`

**Interfaces:**
- Consumes: Tasks 6, 12, 13, 14; `controller.Controller.BenchPath()`.
- Produces:
  ```go
  type Config struct {
  	BundleDir, Prefix string
  	N                 int
  	Rates             [bench.NumClasses]float64
  	Size              int
  	Duration          time.Duration // total run, including the partition
  	PartitionAt       time.Duration // from load start
  	PartitionFor      time.Duration
  	CtlBench          string        // the controller's bench.jsonl (read at the end)
  	CtlInterval       time.Duration // the controller's bench_interval; the runner waits two of them before reading
  	Out               string        // directory: agents/<host> state, load.jsonl marks
  	Backoff           link.Backoff
  	SpoolMax          int64
  	Criteria          bench.Criteria
  	CatchUpTimeout    time.Duration // default 120 s
  }
  type Result struct {
  	Checks  []bench.Result
  	Summary bench.Summary // whole run, synthetic hosts only
  	Pass    bool
  }
  func Run(ctx context.Context, c Config, w io.Writer) (Result, error)
  ```
  Sequence: validate (`N >= 1`, `PartitionAt + PartitionFor < Duration`, bundles present) -> `NewProxy("127.0.0.1:0", <controller address from the first bundle>, 2*N+8)` -> `StartAgents` -> wait until `Connected() == N` (60 s, else error) -> mark `load_start` in `Out/load.jsonl` -> sleep `PartitionAt` -> mark `partition_start`, `proxy.Cut()` -> sleep `PartitionFor` -> `proxy.Restore()`, mark `partition_end` -> poll every 250 ms until `Depth() <= max(10, 2*sum(Rates))` (generators still running), then mark `caught_up`; if that is not reached by `Duration`, mark `not_caught_up` -> at `Duration` mark `load_end`, `StopGen`, wait for `Depth() == 0` (up to `CatchUpTimeout`; failing that mark `not_caught_up` if not already marked) -> `Stop()` -> sleep `2*CtlInterval` so the controller's last samples are written -> `ReadFiles(CtlBench, Out/load.jsonl)` -> `Check(recs, Prefix, Criteria)` -> print the `Summarize` text (host prefix applied) and one `PASS|FAIL name got want` line per check to `w`. `Result.Pass` is all checks passing. Agents and proxy are stopped on every error path.

  Command: `phylax bench load -lab -bundles DIR [-prefix bench-] -n 20 [-rates 1,5,20,20] [-size 200] [-duration 5m] [-partition-at 60s] [-partition-for 60s] -ctl-bench FILE [-ctl-interval 10s] [-out DIR] [-spool-mb 200]`. Without `-lab` it returns the error `bench load writes synthetic events into the target controller's store; pass -lab to confirm this is a lab controller`. Exit status 1 when `Result.Pass` is false. `-rates` is four comma-separated numbers.

- [ ] **Step 1: Write the failing tests:**

```go
func TestRunEndToEndPartition(t *testing.T) {
	// load_test package. Real controller in-process: Config{AgentListen: "127.0.0.1:0", DataDir: tmp, BenchInterval: Duration(500ms)}; Serve on a listener.
	// WriteBundles for bench-001..bench-003 (W2 Task 2) with Controllers = the listener address.
	// res, err := Run(ctx, Config{BundleDir: dir, Prefix: "bench-", N: 3, Rates: {1, 5, 10, 0}, Size: 80,
	//     Duration: 12 * time.Second, PartitionAt: 3 * time.Second, PartitionFor: 3 * time.Second,
	//     CtlBench: c.BenchPath(), CtlInterval: 500 * time.Millisecond, Out: t.TempDir(),
	//     Backoff: link.Backoff{Min: 50 * time.Millisecond, Max: 500 * time.Millisecond},
	//     Criteria: bench.Criteria{LatencyP99Ms: 10000, MaxReconnectS: 5}}, &out)
	// want: err == nil; res.Pass (print res.Checks on failure);
	//   res.Summary.ReconnectN == 3 && NoReconnect == 0 && Reconnect.Max < 5;
	//   every ReconnectsPerAgent value == 1; GapEvents == 0;
	//   Class[2].EventsPerS > 20 (3 agents x 10/s, averaged over the whole run including the stall, so > 20 not == 30);
	//   the store holds, per agent, a contiguous sequence with no gap: c.Store().Count(ctx, host) == the agent's emitted + its start event;
	//   out contains "reconnect after partition" and "PASS no_loss".
}
func TestRunFailsWhenSpoolTooSmall(t *testing.T) {
	// same, but SpoolMax = 200 KB and Rates {0, 0, 200, 200} Size 500 for a 4 s partition: events are shed while the link is down.
	// want: res.Pass == false and the "no_loss" check failed (GapEvents > 0 or ShedMax > 0), err == nil.
}
func TestRunValidatesConfig(t *testing.T) { /* PartitionAt+PartitionFor >= Duration -> error; N 0 -> error; missing bundles -> error naming the dir */ }
// cmd/phylax/bench_test.go
func TestBenchLoadNeedsLab(t *testing.T) { /* run("load", -bundles x -ctl-bench y) without -lab: error contains "-lab"; nothing is dialled */ }
func TestBenchLoadParsesRates(t *testing.T) { /* parseRates("1,5,20,20") == {1,5,20,20}; "1,2" and "a,b,c,d" error */ }
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/bench/load/ ./cmd/phylax/ -run 'RunEndToEnd|SpoolTooSmall|RunValidates|BenchLoad' -count=1`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** `CGO_ENABLED=1 go test -race ./internal/bench/... ./cmd/phylax/ -count=1`, then `make build build-windows vet test race`.
- [ ] **Step 5: Run it for real, once, on this machine.** Build `phylax`, make a 5-host bench manifest with Task 16's script, start `phylax serve` with `bench_interval` `2s` and `-bundles`, and run `phylax bench load -lab -n 5 -duration 40s -partition-at 10s -partition-for 10s -ctl-interval 2s` against it. Expected: `PASS` lines and the report. If Task 16 is not merged yet, say so and rely on the in-process test; the replica run is Task 17.
- [ ] **Step 6: Commit.** `git commit -am "bench: load scenario with a 60 s partition, and phylax bench load"`

---

### Task 16: Lab manifest with N bench hosts

**Files:**
- Create: `tools/bench/make-bench-manifest.sh`
- Test: `internal/controller/benchmanifest_test.go`

**Interfaces:**
- Consumes: `manifest.LoadDir`, `LoadConfigInputs`, `BuildAgentConfig`, W2's `WriteBundles`.
- Produces: `sh make-bench-manifest.sh SRC DST N` copies the manifest directory `SRC` to `DST` and appends to `DST/hosts.yml` the hosts `bench-001` to `bench-<N>` (N at most 500) as `{ segment: lan, ip: 172.20.241.<10 + i mod 240>, os: { family: debian, distro: ubuntu, version: "22.04" }, roles: [] }`, with the `ip` third octet `241 + (i-1)/240` so addresses stay unique. Refuses a non-empty `DST` or N outside 1..500; prints `bench manifest: DST (N hosts)`. Edits only the copy (`# bench:ro: edits the copy`).

- [ ] **Step 1: Write the failing test** (skips on windows or without `sh`):

```go
func TestBenchManifest(t *testing.T) {
	// run the script with SRC ../../manifest/2027, DST tmp/m, N 30
	// m := manifest.LoadDir(DST): 30 more hosts than the source; names bench-001 and bench-030 exist; no two hosts share an ip
	// BuildAgentConfig(inputs, "bench-001") succeeds and enables no module (every module block nil) -- a synthetic agent receives an empty config
	// controller.New(... HostKnown from m) then c.WriteBundles(dir, []string{"bench-001", "bench-030"}, opts) succeeds (hosts are known)
}
func TestBenchManifestRefusals(t *testing.T) { /* non-empty DST, N=0, N=501: non-zero exit, DST untouched */ }
```

- [ ] **Step 2: Run, expect FAIL.** `go test ./internal/controller/ -run BenchManifest -count=1`.
- [ ] **Step 3: Implement the script.**
- [ ] **Step 4: Run, expect PASS.** Also `phylax manifest lint --dir DST` reports 0 errors (record the output).
- [ ] **Step 5: Commit.** `git commit -am "bench: lab manifest generator"`

---

### Task 17: Lab task (stronger agent or David): comms bench on the replica

**Files:**
- Create: `docs/impl/lab/w14-bench.md` (results)
- Modify: any script or Go file for a real failure, same rules as the other tasks

**Interfaces:**
- Consumes: the BTaP replica from `btap-infra` stack `stacks/ccdc` (2026 replica: Palo side 26010 to 26013, Cisco side 26014 to 26017; the controller runs on `ubuntu-wkst`), the Phylax binaries and the W2 rehearsal setup (`docs/impl/02-invitational.md` Task 15: enroll the real agents from the kit, observe mode, safe mode on), Tasks 11, 12, 15 and 16.
- Produces: `w14-bench.md` with date, commit, VMIDs, one block per run (command line, the full `phylax bench report` output, the check lines), the comparison table against the live recording, and what was not run.

- [ ] **Step 1: Baseline with real agents only (30 min).** Start the replica from its snapshots, run the W2 rehearsal setup so the real agents are enrolled and the controller has `bench.jsonl` on by default. Do not touch `bench_off`. After 30 minutes: `phylax bench report <data-dir>/bench.jsonl > baseline.txt`. Record per-class events/s, p99 latency, RTT per agent, module CPU/held bytes, store growth per hour, query times. This is the replica row for the comparison with the Invitational's live recording (O3, O6).
- [ ] **Step 2: Bench manifest and bundles.** On the controller VM: `sh tools/bench/make-bench-manifest.sh manifest/2027 /var/lib/phylax/bench-manifest 50`; restart `phylax serve` with `manifest_path` pointing at it and `-bundles /var/lib/phylax/bundles -advertise <controller-ip>:7443`; snapshot the controller VM first (`pct`/`qm snapshot`, name `pre-bench`) because the bench writes synthetic events into its store for good. Check that real agents keep their config version (no re-push storm) and that a `bench-001` agent accepts the empty config without an error status (record the Platform page state).
- [ ] **Step 3: Load run, 20 agents, 5 minutes, one 60 s partition (on the controller VM).**

  ```sh
  phylax bench load -lab -bundles /var/lib/phylax/bundles -n 20 -rates 1,5,20,20 -size 200 \
    -duration 5m -partition-at 90s -partition-for 60s \
    -ctl-bench /var/lib/phylax/bench.jsonl -ctl-interval 10s -out /var/lib/phylax/bench-run1
  ```

  Expected: the four checks pass (`latency_p99_before`, `latency_p99_after`, `no_loss`, `reconnect_time`, `reconnect_count`, `caught_up`). Compute the partition's spool need first: rate x size x 60 s per agent must stay under the bulk admission limit of the agent spool (50% of 200 MB), which 61 events/s x 200 B x 60 s = 0.7 MB satisfies by a wide margin; then raise the rate until it does not (see step 4).
- [ ] **Step 4: Find the edge.** Repeat step 3 with `-n 20` and `-rates 5,25,100,200`, then `-n 50` and the same rates, then `-n 100`. For each run record the first run in which a check fails or `shed`/gap events appear, the controller CPU and RSS, commit p99, and the largest `lag_events`. This answers "how many agents at what rate before the envelope is missed"; it is measured and reported, not a target.
- [ ] **Step 5: Recorder cost.** Run step 3's command twice more, once with `bench_off: true` and once with it on, with the same load; compare controller CPU from `top -b -n 1 -p <pid>` samples every 10 s (the recorder cannot report its own absence). Record the difference; Review Focus 1 expects it to be small. If it is not, find which counter costs it (`bench.AtomicHist.Observe`, the per-event marshal) and fix with a `shortcut:` comment.
- [ ] **Step 6: Real partition on the real agents.** Mark and cut: `phylax bench mark <data-dir>/bench-marks.jsonl partition_start; iptables -I INPUT -p tcp --dport 7443 -j DROP`; wait 60 s; `iptables -D INPUT -p tcp --dport 7443 -j DROP; phylax bench mark <data-dir>/bench-marks.jsonl partition_end`; wait 2 minutes; `phylax bench report <data-dir>/bench.jsonl <data-dir>/bench-marks.jsonl`. Record time to reconnect per real agent (Linux, Windows 2019/2022, Windows 11, Kali), whether the controller noticed after `read_idle` (20 s), whether any real agent shed or gapped, and the event latency of the replay. Compare with the proxy cut of step 3 (a reset) and write down the difference.
- [ ] **Step 7: Wire bytes.** During step 3, read `ip -s link show <iface>` on the controller before and after (or `/proc/net/dev`); record bytes per second in and out and compare with the recorder's JSON bytes per second: the ratio is the compression the wire gets (one number per class mix).
- [ ] **Step 8: UI latency through HTTP.** With a logged-in session cookie on the loopback UI (`curl -b cookies.txt -w '%{time_total}'` on `/`, `/agents`, the Platform page) at idle, during step 3, and during the partition; record next to the recorder's in-process `query_ms` so the template and HTTP share is visible.
- [ ] **Step 9: Compare and restore.** Fill the comparison table: replica baseline (step 1) against the live Invitational recording, once available (`bench.jsonl` copied from `ubuntu-wkst` after the event). Roll the controller VM back to `pre-bench`. Record what was not run (the Windows `pktmon`-side drops, a 1000-agent run, a controller restart under load).
- [ ] **Step 10: Commit.**

```bash
git add docs/impl/lab/w14-bench.md
git commit -m "docs: comms bench lab results"
```

---

## Self-review

1. **Spec coverage.** Per agent RTT: Task 8 and the `rtt_ms` column. Event-to-controller latency: Task 10 `lat`, Task 5 table, Task 6 criterion. Events/s and bytes/s by class: Task 10, Task 5. Spool depth and congestion: Task 11 (`AgentSample`) with the report's `non-ok samples`. Gap records: Task 10, Task 6 `no_loss`. Reconnect count and time to reconnect: Task 10 (`Connects`, `ConnectedAt`, `Down`), Task 5 `Reconnect`, Task 6. Ack lag: Task 10 `HeadSeq`, Task 11 `LagEvents`. Per-module CPU, held bytes (the contract's only memory figure), bytes: Task 11 consuming `module.Usage`, Task 5 `Module`. Controller CPU and RSS: Tasks 7 and 11. Store size and commit latency: Task 9. UI and API query latency: Task 11 (in-process) and Task 17 step 8 (HTTP). Live recorder on by default with a bounded file and `bench report`: Tasks 3, 4, 11, 12. Load generator with real link and spool code and real tokens: Tasks 13 to 15 on W2's bundles. Partition step: Task 13 and 15. Same numbers: the load run reads the controller's own file (Task 15). Lab task and record file: Task 17. Pass criteria: Task 6. Design edits (Test matrix T80 and T81, the "Comms bench" paragraph, the heartbeat row): made when this plan was written.
2. **Placeholder scan.** Every task names its files, signatures and test assertions. Three tests are described by their setup and assertions in comments because they use the controller's e2e helpers (`newCtl`, the in-process agent) whose exact method names the implementer reads in `internal/controller/e2e_test.go`: Task 10 `TestControllerCountsIngestAndConnects`, `TestHeartbeatCarriesHeadAndRTT`, Task 11 `TestBenchSourceSamplesRealAgent`. Each states the numbers it must find.
3. **Type consistency.** `Hist`/`AtomicHist` (Task 2) are used by Tasks 4, 5, 9, 10; `Record`, `Ctl`, `AgentSample`, `ModuleUse` (Task 1) by Tasks 3 to 6, 11, 12; `Counters`/`Source` (Task 1) by Tasks 4 and 11; `Filter`, `Summary` by Tasks 5, 6, 12, 15; marks `load_start`, `partition_start`, `partition_end`, `caught_up`, `not_caught_up`, `load_end` are written in Task 15 and read in Tasks 5, 6, 12; `BenchPath` (Task 11) by Task 15; `WriteBundles`/`BundleOptions` are W2 Task 2's names; `AgentHealth`, `module.Health.Usage.{CPUMillis,HeldBytes,Events,BytesOut,Dropped}` are W1 Tasks 1 and 14's names.
4. **Open points flagged, not decided.** (a) Event latency uses the last heartbeat's skew, which includes one-way delay; the report prints the largest skew so a bad figure shows. (b) A bench host receiving an empty signed config is assumed fine; Task 17 step 2 checks it. (c) The controller VM's default `read_idle` (20 s) makes a silent drop look like a 20 s later disconnect; Task 17 step 6 measures it. (d) Per-module RSS does not exist in the contract; `held_bytes` stands in, and agent process RSS comes from the C2 sampler (`tools/invitational/c2-sampler.sh`).
5. **Proportion.** 17 tasks: 1 seams, 14 code tasks (about 100 to 200 lines each, plus tests; 3 touch the controller), 1 shell task, 1 lab task. About 1,700 lines of Go with tests; no new dependency.
