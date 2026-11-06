# W3: Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move `audit`, `winevt` and `net` onto the module contract, build `logs` and `inventory`, make every producer emit the canonical common kinds through `event.New`, and apply the rename map to producers, rules and consumers so no old kind name is left.

**Architecture:** Each module is one package (`internal/audit`, `internal/winevt`, `internal/net` with Go package `netmod`, `internal/logs`, `internal/inventory`) with its agent registration in `internal/agent/mods/`. A producer builds a typed common-kind struct, calls `event.New`, and attaches anything the struct does not carry with `Event.WithExtra` (an `x_` field no rule may read). `internal/sockets` takes the socket-table, process-join and Community ID code that `net`, `capture`, `traceback` and `depot/gotools` share. `inventory` has an agent side (collectors, differential engine, probes) and a controller side (fold into two tables, a page); the pure fold lives in `internal/inventory/fold`.

**Tech Stack:** Go 1.27.2 (mise), `modernc.org/sqlite` (rpm database), `gopkg.in/yaml.v3`, `golang.org/x/sys`, `go-libaudit` (already used). No new modules in `go.mod`.

**Spec:** `phylax_design.md` (v4): "The module contract" and "Event kinds" (canonical fields, rename map); module sections "Telemetry" (`audit` 1877, `winevt` 2107, `net` 2314, `logs` 2505, `inventory` 2672); Known bugs 15 (net part), 16, 17 (audit part); Test matrix T11, T12, T21, T29, T43, T69, T71, T75; Appendix D. Master plan: `docs/impl/README.md`. Contract names: `docs/impl/01-module-contract.md` (W1) Interfaces blocks.

## Design gaps and decisions (Task 1 writes each into `phylax_design.md` in the same commit)

1. **The W1 common structs cannot carry what the rules and consumers read.** `rules/linux_exec.yml` reads `argc`, `cgroup`, `env.LD_PRELOAD`; `rules/mw-redteam.yml` reads `gpo`, `sysvol_policy`; `internal/traceback/obs.go` reads `start_ticks`, `writer_start_ticks`, `exe_sha256`, `pid_start`. W1's `Decode` is strict, so `event.New` would drop or reject them. Decision: W1 owns the fields (W1 Task 4a lists exactly those optional members of its structs) and every other producer field is attached with `WithExtra` (`x_` prefix; `Decode` ignores it, rules may not read it). Rule of thumb for later changes: a field a rule, analyser or consumer reads belongs in the struct; a field only a human reads is `x_`.
2. **`winevt.sec_event` and `inventory` row payloads are open.** The payload keys depend on `category` (about 60 categories) or on the table. Declared as `map[string]any` types; `shortcut: payload untyped per category, type a category when a consumer needs more than rules do`.
3. **`Event.WithExtra`** is W1's (Task 3a): producers use it, this plan does not build it.
4. **`actions.Register`** (W1 Task 2a; the exported form of the built `registerExtra`, the one name every workstream uses) lets a module package register the actions the design says it owns (`audit.rules`, `audit.immutable`, `collect.inventory`, `probe.run`). Actions reach the running module through a package-level `Active()` handle: `shortcut: one agent per process, a handle per module instance if that changes`.
5. **`CommunityID` and the protocol constants move to `internal/sockets`.** `capture`, `traceback` and `chains` import them from `internal/net` today; after the move that would be a sibling import (Known bug 15). The design describes `internal/sockets` as `sock_diag` plus the inode join; Task 1 adds "Community ID v1" to that line.
6. **Content for `logs` and `inventory` lives inside the package** (`internal/logs/parsers/*.yml`, `internal/inventory/probes/*.yml`, `internal/inventory/software/*.yml`, embedded with `go:embed`). Appendix D has no top-level `logs/` or `inventory/` and the agent needs the content offline and signed with the release. The consistency pass already corrected the module sections and Appendix D; Task 1 Step 5 verifies it.
7. **`net` stops feeding `deps` and `deps` is not yet a subscriber.** Task 17 removes `net`'s `deps` import (Known bug 15); `deps.edge` and `deps.peer` stop being produced until W8 makes `deps` subscribe to `conn` and `listener`. W8's plan must start from that fact. Until then `internal/deps` keeps its code and tests.
8. **Hand-offs, not built here.** (a) `net.shadow_drop` and `net.ingress_denied` are declared here; emitting them (the separate NFLOG group, Known bug 14, the Windows shadow evaluator) is W6, in `internal/net`. `plan.NetSettings` keeps `NFLogGroups` until W6 swaps it for `deny_log_group` and `shadow_log_group`. (b) `sysmon.install`, `sysmon.config`, `eventlog.size` and an action that enables an analytic channel have no owner in the master plan; none is built here. Recommend W5 (hardening) takes them. (c) The controller-side comparison of the heartbeat `rules_hash` (tier-1 alert on a change or a drop to no rules) has no declared kind to emit; this plan only fills `Health.Info`. Recommend W10 (Platform page) or W4 (a rule on `agent.health`) owns it. (d) The `respond` tier-0 Sysmon reinstall recipe is W4.
9. **`json.Number` on the bus.** `event.New` stores numbers as `json.Number`; `internal/detect/field.go` (`toStr`, `toNum`) does not handle it, so `uid: {gt: 0}` would silently stop matching live events. Task 2 fixes it first; W4 inherits the fix.

## Global Constraints

- Go 1.27.2 via mise; `CGO_ENABLED=0`; `make build build-windows vet test race` passes at every commit (linux/amd64 and windows/amd64 both build and vet). `-race` needs `CGO_ENABLED=1`.
- Every package ships tests; tests exercise the real code (no mock of the code under test; fakes only at the edge the package does not own: a fake netlink socket, a recorded event XML, a fixture `/proc` or `/etc` tree). A test that needs privileges, Windows or containers calls `t.Skip` with a reason string.
- Commits are small, one logical change, message `area: summary` (for example `audit: canonical process_start`). No attribution lines of any kind.
- No shelling out in the default path. Bounded queues, buffers, decoded sizes, timeouts. Atomic writes through `internal/atomicfile` for state files (bookmarks, offsets, inventory snapshots).
- No compatibility shims, aliases or dual formats: a renamed kind or field is renamed everywhere (producer, tests, `rules/*.yml`, consumers, `docs/*.md`) in the same commit.
- A module imports only the core packages and the shared libraries listed in W1's Global Constraints (`internal/atomicfile`, `internal/parsers/...`, `internal/sockets`, `internal/inventory/fold`, ...). `net` imports no `deps`; `traceback`, `capture` and `chains` import `internal/sockets`, not `internal/net`.
- Times are UTC. Secrets, password hashes and key blobs never appear in an event, a log or a snapshot.
- **Producer recipe (every task that converts a producer).** (1) Build the declared struct and call `event.New(kind, v)`; set `e.Time` afterwards. (2) Attach producer-only fields with `e = e.WithExtra("name", v)`. (3) Never emit a field name the rename map retired: `image`, `pexe`, `pcomm`, `pcmdline`, `actor_exe`, `actor_pid`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `addr`, `port` (on `conn` and `listener`), `direction`, `in`, `out`. (4) The producer's test feeds a recorded input through the real code and asserts `event.Validate(e) == nil` for every event and that no retired name appears. (5) In the same commit, edit every rule, test, consumer and doc that read the old kind or field (the task names them).
- **Rule edit recipe.** `event: X` becomes `event: Y`; a retired kind that split into one canonical kind plus a discriminator gains the condition (`result: success`, `op: added`, ...). Rule inline tests change the same way. Verify with `go test ./internal/detect/ -run 'TestCorpusInlineTests|TestPendingRulesParse'`.
- The design is authoritative; a forced design change edits `phylax_design.md` in the same commit with the reason.
- Code style ponytail: the smallest complete change; a known limit carries `// shortcut: <limit>, <when to upgrade>`.

## Review Focus

1. **Numbers on the bus.** Events built by `event.New` carry `json.Number`; the on-host rule engine compared only `int`, `uint64` and `float64`, so numeric conditions (`uid: {gt: 0}`, `argc: 0`) silently stop matching after the conversion. Expected: a numeric rule fires on a freshly converted event. Task 2 `TestEngineMatchesJSONNumber`; Task 4 repeats it end to end for `D3e.pwnkit-exec`.
2. **A renamed kind that no rule matches.** A rule's inline test builds its own event, so it passes after a rename even when the producer still emits the old name or field. Expected: each producer's recorded fixture, run through the real producer and the real rule corpus, fires the rule it is meant to (Task 39 `TestProducerFixturesFireRules`: `D1.service-spawns-shell` from an audit exec, a failed-login burst from `logs` and `winevt`, `D12` listener rule from `net`).
3. **Log tails under rotation and hostile content.** Copytruncate, rename-then-create, a partial last line, a 100 MiB line of binary bytes, a file that vanishes. Expected: no duplicate and no lost complete line, lines over 8 KiB cut and flagged, a gap event for every loss (Task 25).
4. **Inventory state loss.** A restart with a deleted or corrupt snapshot file must read as a new epoch with a baseline snapshot, never as thousands of `added` rows (and never as an alert). Expected: Task 28 `TestLostStateIsNewEpochNotMassAdd`; Task 34 `TestRestartKeepsEpoch`.
5. **`net` baseline and own-link feedback.** After a reconfiguration the first snapshot must not read as new activity, and the agent's own TLS link must not produce `conn` events (events about the link make link traffic). Expected: Task 19 `TestReconfigureKeepsBaseline`; Task 18 `TestOwnLinkExcluded`.

---

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `internal/event/kinds.go`, `types.go` | extension fields on common structs; `WithExtra` | W1 Tasks 3a, 4a (not built here) |
| `internal/e2e/telemetry_test.go` | producer fixtures through the real rules | 39 |
| `internal/sockets/` | `Sock`, `SockDiag`, `ProcFS`, `Proc`, `CommunityID`, protocol constants; Windows extended-table readers | 1, 15 |
| `internal/audit/` | `audit` module (moved from `internal/collect/audit`) | 1, 4-10 |
| `internal/audit/kinds.go` | `audit.module_load`, `audit.rules_changed`, `audit.af_alg` | 1 |
| `internal/winevt/` | `winevt` module (moved from `internal/collect/winevt`) | 1, 11-15 |
| `internal/winevt/kinds.go` | `winevt.sec_event`, `winevt.sensor_state` | 1 |
| `internal/net/` (package `netmod`) | `net` module (moved from `internal/collect/net`) | 1, 3, 17-21 |
| `internal/net/kinds.go` | `net.egress_denied`, `net.shadow_drop`, `net.ingress_denied`, `net.canary_result`, `net.sensor_degraded` | 1 |
| `internal/logs/` | `logs` module: `tail.go`, `parser.go`, `parsers/*.yml`, `module.go`, `kinds.go` | 1, 22-27 |
| `internal/inventory/` | `inventory`: `tables.go`, `diff.go`, `collect_linux_*.go`, `collect_windows*.go`, `software.go`, `probe.go`, `probes/`, `software/`, `module.go`, `actions.go`, `controller.go`, `ui.go` | 1, 28-37 |
| `internal/inventory/fold/` | pure fold of snapshot plus row events | 1, 2 |
| `internal/agent/mods/logs.go`, `inventory.go` | factories | 1, 26, 34 |
| `internal/actions/registry.go` | `Register` | W1 Task 2a (not built here) |
| `internal/plan/agentconfig.go` | `LogsSettings`, `InventorySettings`, `WinevtSettings.BackscanHours` | 1 |
| `internal/detect/field.go` | `json.Number` | 2 |
| `rules/*.yml`, `rules/pending/needs_producer.yml` | renamed kinds and fields; unparked inventory and logs rules | 3-5, 11, 12, 27, 38 |
| `internal/traceback/obs.go`, `trace.go`, `internal/chains/remediate.go`, `internal/deps/graph.go`, `internal/controller/capture_ingest.go` | readers of the renamed kinds | 3, 4, 10, 11 |
| `manifest/2027/modules/{audit,winevt,net,logs,inventory}.yml`, `internal/controller/genconfig.go`, `internal/event/legacy_test.go` | reference blocks, rendering, retired-name guard | 38 |
| `docs/rules.md`, `docs/agent.md`, `docs/deps.md`, `docs/capture.md` | field and kind reference | with each rename |
| `docs/impl/lab/w3-telemetry.md` | lab record | 40 |

---

### Task 1: Seams (Sonnet or Opus)

Done by a stronger model. Moves the three packages, writes the declared kinds, the shared-library skeletons, the stubs of the two new modules, the new settings structs, and every skipped test the later tasks implement. Merges on its own (its own pull request into `v3-redesign`); W6 waits for it (it needs the `net.*` kinds).

**Files:**
- Move (`git mv`, then fix the package clause and every importer in the same commit): `internal/collect/audit` to `internal/audit` (package `audit`); `internal/collect/winevt` to `internal/winevt` (package `winevt`); `internal/collect/net` to `internal/net` (package stays `netmod`). Importers to fix: `internal/agent/mods/{audit_linux,winevt,net}.go`, `internal/traceback/obs.go`, `internal/capture/{decode,engine,events,engine_test}.go`, `internal/chains/chains_test.go`, `internal/depot/gotools/proc_linux.go`.
- Move into `internal/sockets/` (package `sockets`): `communityid.go` and `communityid_test.go` (`CommunityID`, `CommunityIDICMP`, `CommunityIDNoPorts`, `ProtoICMP`, `ProtoTCP`, `ProtoUDP`, `ProtoICMPv6`, `ProtoSCTP`), `sockdiag.go`, `sockdiag_linux.go` (`Sock`, `SockDiag`, `State*`), `proc_linux.go` as `procfs_linux.go` and its test (`ProcFS`), and the `Proc` struct from `tracker.go` into `proc.go`. `internal/net` then imports `internal/sockets`; `capture`, `traceback`, `chains` tests and `gotools` import it instead of `internal/net`. `Flow.CommunityID()` in `nflog.go` calls `sockets.CommunityID`.
- Create: `internal/audit/kinds.go`, `internal/winevt/kinds.go`, `internal/net/kinds.go`, `internal/logs/{doc.go,kinds.go,module.go}`, `internal/inventory/{doc.go,kinds.go,tables.go,module.go,controller.go}`, `internal/inventory/fold/fold.go`, `internal/agent/mods/{logs,inventory}.go`
- Modify: `internal/plan/agentconfig.go`, `internal/module/all/all.go`, `internal/module/conformance/allowed.go` (`ModulePackages` entries for the five modules; `PreContract` keeps the three retrofits until their conformance task), `phylax_design.md`
- Create: every test file named in Tasks 2 to 40, each test body as given in that task's Step 1, first statement `t.Skip("unimplemented: W3 Task N")`; fixture helpers they share.

**Interfaces:**
- Consumes: W1 names (`event.Declare`, `event.New`, `Event.WithExtra`, the extension fields, `actions.Register`, `module.Manifest`, `module.Common`, `module.Health`, `agent.Factory`, `plan.ModuleLimits`).
- Produces (exact):

```go
// ---- internal/event (W1, not built here) ----
// Event.WithExtra (W1 Task 3a) and the extension fields of the common structs (W1 Task 4a: ProcessParent.PID/StartTicks/Live/Unresolved,
// ProcessStart.Argc/CGroup/EUID/AUID/Env/StartTicks, FileChange writer and GPO fields, Conn/Listener.ExeDeleted/ExeSHA256/PIDStart,
// AuthEvent logon fields, Replay on four kinds) are consumed here as given.

// ---- internal/audit/kinds.go (Declare in init; Priority per the design's Events table; Alert false) ----
type ModuleLoad struct {
	Syscall string `json:"syscall"` // init_module | finit_module
	Module  string `json:"module,omitempty"`
	Exe     string `json:"exe,omitempty"`
	Comm    string `json:"comm,omitempty"`
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid,omitempty"`
	UID     int    `json:"uid"`
	AUID    int64  `json:"auid"`
	Key     string `json:"key"` // phylax_kmod
}
type AFAlg struct {
	Syscall string `json:"syscall"` // socket
	Family  int    `json:"family"`  // 38
	Type    int    `json:"type"`
	Exe     string `json:"exe,omitempty"`
	Comm    string `json:"comm,omitempty"`
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid,omitempty"`
	UID     int    `json:"uid"`
	AUID    int64  `json:"auid"`
	Key     string `json:"key"` // phylax_afalg
}
type RulesChanged struct {
	Source       string   `json:"source"`
	Reason       string   `json:"reason"` // comma list: audit_disabled, reader_displaced, rules_changed, never_rule, install_failed
	ExpectedHash string   `json:"expected_hash"`
	ActualHash   string   `json:"actual_hash"`
	Missing      []string `json:"missing,omitempty"`
	MissingCount int      `json:"missing_count"`
	StaleCount   int      `json:"stale_count"`
	Repaired     bool     `json:"repaired"`
	NeverRules   []string `json:"never_rules,omitempty"`
	FailedCount  int      `json:"failed_count"`
	Failed       []string `json:"failed,omitempty"`
	Enabled      *bool    `json:"enabled,omitempty"`
	AuditPID     *int     `json:"audit_pid,omitempty"`
	Lost         *uint32  `json:"lost,omitempty"`
	Backlog      *uint32  `json:"backlog,omitempty"`
}
const (KindModuleLoad = "audit.module_load"; KindRulesChanged = "audit.rules_changed"; KindAFAlg = "audit.af_alg") // High, Critical, High

// ---- internal/winevt/kinds.go ----
type SecEvent map[string]any // open payload; shortcut: untyped per category, type a category when a consumer needs it
type SensorState struct {
	Sensor            string `json:"sensor"` // sysmon
	Present           bool   `json:"present"`
	Running           bool   `json:"running"`
	DriverRunning     bool   `json:"driver_running"`
	ServiceName       string `json:"service_name,omitempty"`
	DriverName        string `json:"driver_name,omitempty"`
	Renamed           bool   `json:"renamed"`
	ConfigHash        string `json:"config_hash,omitempty"`
	ExpectedConfigHash string `json:"expected_config_hash,omitempty"`
	Fallback          string `json:"fallback,omitempty"` // "4688" while Sysmon is not running
}
const (KindSecEvent = "winevt.sec_event"; KindSensorState = "winevt.sensor_state") // High, Critical

// ---- internal/net/kinds.go ----
type ProcFields struct { // embedded in the three process-bearing kinds
	PID        int    `json:"pid,omitempty"`
	PIDStart   uint64 `json:"pid_start,omitempty"`
	Comm       string `json:"comm,omitempty"`
	Exe        string `json:"exe,omitempty"`
	ExeSHA256  string `json:"exe_sha256,omitempty"`
	ExeDeleted bool   `json:"exe_deleted,omitempty"`
	UID        *int   `json:"uid,omitempty"`
}
type EgressDenied struct {
	ProcFields
	Dir         string `json:"dir"` // outbound
	Proto       string `json:"proto"`
	LAddr       string `json:"laddr,omitempty"`
	LPort       uint16 `json:"lport,omitempty"`
	RAddr       string `json:"raddr"`
	RPort       uint16 `json:"rport"`
	CommunityID string `json:"community_id,omitempty"`
	Attributed  bool   `json:"attributed"`
	Attempts    int    `json:"attempts"`
	NFLogGroup  int    `json:"nflog_group"`
	Prefix      string `json:"prefix,omitempty"`
	SockUID     *int   `json:"sock_uid,omitempty"`
	Inode       uint64 `json:"inode,omitempty"`
	Sensor      string `json:"sensor,omitempty"` // "5157" on Windows
	Canary      bool   `json:"canary,omitempty"`
	CanaryTag   string `json:"canary_tag,omitempty"`
}
type ShadowDrop struct { // emitted by W6
	ProcFields
	Dir, Proto, Src, Dst string
	SPort, DPort         uint16
	CommunityID          string `json:"community_id,omitempty"`
	Prefix               string `json:"prefix"`
	NFLogGroup           int    `json:"nflog_group"`
}
type IngressDenied struct { // emitted by W6
	Dir, Proto, RAddr, LAddr string
	LPort                    uint16
	NFLogGroup               int    `json:"nflog_group"`
	Prefix                   string `json:"prefix"`
	ScoredPort, ScorerLike   bool
}
type CanaryResult struct {
	RAddr     string `json:"raddr"`
	RPort     uint16 `json:"rport"`
	Proto     string `json:"proto"`
	Canary    bool   `json:"canary"` // always true
	CanaryTag string `json:"canary_tag,omitempty"`
	Result    string `json:"result"` // leak | blocked | error
	Expected  bool   `json:"expected"`
	Detail    string `json:"detail,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
}
type SensorDegraded struct{ Module, Sensor, Error string }
const (KindEgressDenied = "net.egress_denied"; KindShadowDrop = "net.shadow_drop"; KindIngressDenied = "net.ingress_denied";
	KindCanaryResult = "net.canary_result"; KindSensorDegraded = "net.sensor_degraded") // High, Normal, High, Normal (Critical on a leak), High

// ---- internal/logs/kinds.go ----
type Line struct {
	File   string `json:"file"`
	Line   string `json:"line"`
	Source string `json:"source,omitempty"`
	Method string `json:"method,omitempty"`
	URI    string `json:"uri,omitempty"`
	Status int    `json:"status,omitempty"`
	UA     string `json:"ua,omitempty"`
	Host   string `json:"host,omitempty"`
	Bytes  int64  `json:"bytes,omitempty"`
}
const KindLine = "logs.line" // Bulk

// ---- internal/inventory/kinds.go ----
type Row = fold.Row // map[string]any
type Snapshot struct {
	Table       string `json:"table"`
	SchemaVer   int    `json:"schema"`
	Epoch       int    `json:"epoch"`
	Reason      string `json:"reason"` // baseline | epoch_change | periodic | requested
	Rows        []Row  `json:"rows"`
	Count       int    `json:"count"`
	Part, Parts int    `json:"part","parts"`
	CollectedAt string `json:"collected_at"`
}
type RowEvent struct {
	Table       string   `json:"table"`
	Epoch       int      `json:"epoch"`
	Op          string   `json:"op"` // added | removed | changed | overflow
	Key         string   `json:"key,omitempty"`
	Row         Row      `json:"row,omitempty"`
	Old         Row      `json:"old,omitempty"`
	ChangedCols []string `json:"changed_cols,omitempty"`
	Count       int      `json:"count,omitempty"` // overflow only
}
type ProbeResult struct {
	Probe       string            `json:"probe"`
	Params      map[string]string `json:"params,omitempty"`
	Host        string            `json:"host"`
	Columns     []string          `json:"columns"`
	Rows        [][]any           `json:"rows"`
	Truncated   bool              `json:"truncated"`
	CollectedAt string            `json:"collected_at"`
	Live        bool              `json:"live"`
}
const (KindSnapshot = "inventory.snapshot"; KindRow = "inventory.row"; KindProbeResult = "inventory.probe_result") // Bulk, Normal (High for persistence tables), Normal

// ---- internal/inventory/tables.go (data, written in full by Task 1) ----
type TableDef struct {
	Name     string
	SchemaVer int
	Columns  []string
	Key      []string
	OS       string        // "linux", "windows", "" both (a table with different columns per OS is two TableDefs with the same Name)
	Interval time.Duration // 0: the module default
	Persist  bool          // row events are High priority
}
func Defs() []TableDef                // every table of the design's table (accounts ... domain_join), per OS
func DefFor(name, goos string) (TableDef, bool)

// ---- internal/inventory/fold/fold.go ----
type Row = map[string]any
type Event struct{ Op, Key string; Row Row }
func Fold(snapshot []Row, key []string, evs []Event) []Row // sorted by key; pure

// ---- internal/plan/agentconfig.go ----
type LogFile struct {
	Path    string `json:"path"`
	Parser  string `json:"parser"`
	Service string `json:"service,omitempty"`
	Lines   bool   `json:"lines,omitempty"`
}
type LogsSettings struct {
	ModuleLimits
	Files []LogFile `json:"files"`
}
type InventorySettings struct {
	ModuleLimits
	Tables              []string `json:"tables,omitempty"`
	IntervalSec         int      `json:"interval_sec,omitempty"`
	SoftwareIntervalSec int      `json:"software_interval_sec,omitempty"`
	ResnapshotHours     int      `json:"resnapshot_hours,omitempty"`
	MaxRows             int      `json:"max_rows,omitempty"`
}
// WinevtSettings gains: BackscanHours int `json:"backscan_hours,omitempty"` // 0 means 24; negative disables
// ModuleSettings gains: Logs *LogsSettings `json:"logs,omitempty"`; Inventory *InventorySettings `json:"inventory,omitempty"`
```

- [ ] **Step 1: Do the moves.** `git mv`, fix package clauses (`package audit`, `package winevt`, `package netmod` stays), fix every importer listed, delete `internal/collect/`. Run `make build build-windows vet test` between moves; the tree must be green after each.
- [ ] **Step 2: Write the shared-library skeletons and stubs.** `sockets` is the moved code and compiles; `inventory/tables.go` and `fold.Fold` signature are written (`Fold` body `panic("unimplemented: W3 Task 2")`); `internal/logs/module.go` and `internal/inventory/module.go` define `type Module struct{}` with `Name()` and a `Start` returning `agent.ErrUnavailable`; the two new factories in `internal/agent/mods` register with `Section` returning `"", false`. Stubs panic `unimplemented: W3 Task N` except where the signature above says otherwise.
- [ ] **Step 3: Write the declarations.** The three `kinds.go` files declare every kind in `init` (`event.Declare`) with the priorities above; the settings structs and `ModuleSettings` fields. The `Manifest` values of the five modules are written in Tasks 5, 12, 19, 25 and 33; here each module package has an unexported `manifest()` returning the design's literal with `Emits` listing the declared kinds (so `TestKindTable` already sees them).
- [ ] **Step 4: Skipped tests.** For each of Tasks 2 to 40 create the test file the task names, bodies as in its Step 1, `t.Skip("unimplemented: W3 Task N")` first.
- [ ] **Step 5: Edit `phylax_design.md`.** Add the nine decisions above (one bullet each, with the reason) under the telemetry module sections; fix the `internal/sockets` line (Community ID) in "Shared libraries"; correct the content paths in `logs` and `inventory` §3 and Appendix D; (the extension fields in "Canonical fields of the common kinds" are W1 Task 4a's design edit).
- [ ] **Step 6: Verify.** Run `make build build-windows vet test race`. Expected: all pass. Then `go test -v ./internal/... 2>&1 | grep -c 'unimplemented: W3 Task'`; expected: the number of skipped tests written in Step 4.
- [ ] **Step 7: Commit** `telemetry: W3 seams (moves, kinds, sockets, extension fields, stubs)`.

---

### Task 2: The rule engine reads `json.Number`; `fold.Fold`

**Files:**
- Modify: `internal/detect/field.go` (`toStr`, `toNum`)
- Modify: `internal/inventory/fold/fold.go`
- Test: `internal/detect/field_number_test.go`, `internal/inventory/fold/fold_test.go`

**Interfaces:**
- Consumes: `event.New` (W1 Task 3), `event.ProcessStart` with `Argc`, `UID`.
- Produces: `toNum(json.Number)` and `toStr(json.Number)` work; `fold.Fold(snapshot []Row, key []string, evs []Event) []Row`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestEngineMatchesJSONNumber(t *testing.T) {
	uid, argc := 1000, 0
	e, err := event.New(event.KindProcessStart, event.ProcessStart{PID: 7, Exe: "/usr/bin/pkexec", Comm: "pkexec", UID: &uid, Argc: &argc, Source: "audit"})
	if err != nil { t.Fatal(err) }
	if n, ok := toNum(e.Fields["uid"]); !ok || n != 1000 { t.Fatalf("uid %v %v", n, ok) }
	if s, ok := toStr(e.Fields["argc"]); !ok || s != "0" { t.Fatalf("argc %q %v", s, ok) }
}
// fold_test.go
func TestFoldAppliesRowEventsToSnapshot(t *testing.T) {
	snap := []Row{{"name": "root", "uid": 0}, {"name": "bob", "uid": 1000}}
	got := Fold(snap, []string{"name"}, []Event{
		{Op: "added", Key: "eve", Row: Row{"name": "eve", "uid": 1001}},
		{Op: "removed", Key: "bob"},
		{Op: "changed", Key: "root", Row: Row{"name": "root", "uid": 0, "shell": "/bin/sh"}},
	})
	// want names [eve root] sorted by key; root has shell; bob absent; input slice not modified
}
func TestFoldIgnoresOverflowAndUnknownOps(t *testing.T) { /* Op "overflow" and "weird" leave the rows unchanged */ }
func TestFoldDeterministic(t *testing.T) { /* same input twice -> reflect.DeepEqual */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ ./internal/inventory/fold/ -run 'JSONNumber|Fold' -v`. Expected: FAIL (`toNum` returns false; `unimplemented: W3 Task 2`).
- [ ] **Step 3: Implement.** Add `case json.Number` to both switches (`Float64()`, `String()`). `Fold` copies the snapshot into a map by joined key (`\x00`-joined key columns), applies events in order, returns rows sorted by joined key; `overflow` and unknown ops are ignored.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/ ./internal/inventory/fold/`. Expected: PASS.
- [ ] **Step 5: Commit** `detect: numeric conditions read json.Number; inventory/fold: pure snapshot fold`.

---

### Task 3: `net`: `listener` and `conn` (canonical) and their readers

The first rename task. It also writes the single `conn` branch of the readers that `audit` and `winevt` use later; the old `net_connect` branch stays until Task 10 deletes it.

**Files:**
- Modify: `internal/net/tracker.go` (`listenerEvent`, `connEvent`, constants), `internal/net/real_linux_test.go`, `tracker_test.go`
- Modify: `internal/traceback/obs.go` (`KindConn`, `KindListener`; `Normalize`), `internal/traceback/trace.go:537`, `internal/traceback/trace_test.go`
- Modify: `internal/deps/graph.go` (`Ingest` reads `listener`), `internal/controller/capture_ingest.go` (`kindConnOpened` becomes `event.KindConn`, filter `op: opened`), `rules/network.yml`, `rules/profiles.yml`, `rules/mw-redteam.yml` (only if it names these kinds), `docs/rules.md`, `docs/deps.md`, `docs/capture.md`
- Test: `internal/net/canonical_test.go`

**Interfaces:**
- Consumes: `event.New`, `event.Conn`, `event.Listener`, `Event.WithExtra`, `sockets.Sock`, `sockets.Proc`.
- Produces: the tracker emits kind `conn` (`op: opened|closed`, `source: net`) and `listener` (`op: added|removed`, `source: net`); `traceback.KindConn`, `traceback.KindListener`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestTrackerEmitsCanonicalConnAndListener(t *testing.T) {
	// fakeSocks with one listener tcp 10.0.0.5:22 (inode 1, owner sshd) and one established inbound tcp 10.0.0.5:22 <- 203.0.113.9:40000; Poll twice (second poll removes the connection)
	for _, e := range evs {
		if err := event.Validate(e); err != nil { t.Fatalf("%s: %v", e.Kind, err) }
	}
	// want kinds {listener:1 (op added, baseline true), conn:2 (op opened then closed)}
	// listener fields: lport "22", laddr "10.0.0.5", service "ssh", source "net"; keys "addr" and "port" absent
	// conn opened: dir "inbound", laddr/lport = 10.0.0.5/22, raddr/rport = 203.0.113.9/40000, community_id non-empty, state "established", exe "/usr/sbin/sshd"
	// conn closed: duration_ms present; no "state"
	// x_ extras present: x_inode, x_sock_uid, x_src, x_dst
}
func TestNoRetiredNamesInNetEvents(t *testing.T) { /* walk every Fields key of every event from all tracker tests; none in {"addr","port","net.listener_added", ...} */ }
// traceback
func TestObsNormalizesCanonicalConn(t *testing.T) {
	// conn opened inbound (laddr 10.0.1.1 lport 443, raddr 203.0.113.5 rport 40000) -> ClassConnOpen, Dir "in", RAddr 203.0.113.5
	// conn closed -> ClassConnClose; conn opened from source audit with only raddr/rport -> ClassConnOpen, LAddr ""
}
func TestDepsIngestsListenerKind(t *testing.T) { /* listener op added lport 8081 -> graph has the listener; op removed deletes an observed one, keeps a declared one */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/net/ ./internal/traceback/ ./internal/deps/ -run 'Canonical|Retired|Obs|Listener' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Replace the four `Kind*` constants with `event.KindConn`/`event.KindListener`; `listenerEvent` and `connEvent` build `event.Listener`/`event.Conn` (`PID`, `Exe`, `Comm`, `User` from the owner, `PIDStart`, `ExeSHA256`, `ExeDeleted` in the struct) and attach `inode`, `sock_uid`, `src`, `dst` with `WithExtra`; `uid` is dropped from `conn` (not canonical; `x_uid`). Traceback `Normalize`: one `case KindConn` (class by `op`, `Dir` from `dir`, addresses from `laddr/lport/raddr/rport`, `CID` from `community_id` or computed with `sockets.CommunityID` when proto is tcp/udp and absent), one `case KindListener` is not needed in `Normalize` (traceback does not model listeners) so only the trace.go loop changes. `capture_ingest.go`: feed agent `conn` events with `op: opened` and `capture.flow` translated events as before. Rules: `net.listener_added` becomes `listener` with `op: added`, fields `port` to `lport`, `addr` to `laddr`; `net.connection_opened` becomes `conn` with `op: opened`; rewrite the inline tests the same way. Docs: replace the field tables for these kinds.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/net/ ./internal/traceback/ ./internal/deps/ ./internal/controller/ ./internal/detect/ -run 'Canonical|Retired|Obs|Listener|Corpus|Pending|Capture'`. Expected: PASS.
- [ ] **Step 5: Commit** `net: canonical listener and conn; readers and rules renamed`.

---

### Task 4: `audit`: canonical `process_start`

**Files:**
- Modify: `internal/audit/handle.go` (`onExec`, `idFields`), `internal/audit/config.go`, `internal/traceback/obs.go` (`KindProcessStart` branch), `rules/linux_exec.yml`, `rules/mw-redteam.yml`, `rules/profiles.yml`, `docs/rules.md`
- Test: `internal/audit/canonical_test.go`; existing `module_test.go` and `assemble_test.go` assertions on `image`, `pexe`, `pcomm`

**Interfaces:**
- Consumes: `event.ProcessStart` (with the W1 Task 4a extension fields), `event.ProcessParent`, `Event.WithExtra`.
- Produces: audit `process_start` is `event.ProcessStart{Source:"audit", Exe, Comm, Cmdline, CWD, PID, PPID, UID, EUID, AUID, Argc, CGroup, Env, StartTicks, Parent:{PID,Exe,Comm,Cmdline,StartTicks,Live,Unresolved}}`; everything else the design lists (`gid`, `egid`, `ses`, `tty`, `argv`, `exec_path`, `proctitle`, `argv_truncated`, `argv_incomplete`, `syscall`, `success`, `exit`, `key`, `audit_serial`, `boot_id`) is `x_<name>`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestProcessStartCanonical(t *testing.T) {
	m, c := testModule(t, nil)
	feedFixture(t, m, "exec_many.log") // loadFixture + m.handle
	e := c.kind(event.KindProcessStart)[0]
	if err := event.Validate(e); err != nil { t.Fatal(err) }
	for _, k := range []string{"image", "pexe", "pcomm"} {
		if _, ok := e.Fields[k]; ok { t.Errorf("retired field %q", k) }
	}
	if e.Fields["exe"] == "" || e.Fields["source"] != "audit" { t.Fatalf("%v", e.Fields) }
	if _, ok := e.Fields["parent"].(map[string]any); !ok { t.Fatal("parent must be an object") }
	if _, ok := e.Fields["x_audit_serial"]; !ok { t.Fatal("serial must be x_audit_serial") }
}
func TestParentFromCacheAfterExitStillObject(t *testing.T) { /* existing scenario: parent {exe, comm} resolved from the table after exit; live false */ }
func TestPwnkitRuleFiresOnConvertedEvent(t *testing.T) {
	// exec_failed-style fixture with comm pkexec uid 1000 argc 0 -> run rules/linux_exec.yml engine on the bus form of the event -> D3e.pwnkit-exec fires
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/audit/ -run 'Canonical|PwnkitRule|StillObject' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `onExec` builds the struct; the `idFields` helper becomes a function that returns the struct members it can fill and a list of `(name, value)` extras. `Priority` stays High, Normal when the exec failed. Rules: `image` to `exe`, `pexe`/`pcomm`/`pcmdline` to `parent.exe`/`parent.comm`/`parent.cmdline`, `entities:` and `message:` templates likewise, and the inline tests. Traceback `process_start` branch: drop the `image` and `pexe` fallbacks, read `parent.exe`, `parent.pid`, `exe_sha256` becomes `sha256`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/audit/ ./internal/traceback/ ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit** `audit: canonical process_start; rules and traceback renamed`.

---

### Task 5: `audit`: canonical `file_change`, `conn`, `telemetry_gap`, `audit.rules_changed`

**Files:**
- Modify: `internal/audit/handle.go` (`onFile`, `onNet`, `emitSweepDiff`), `internal/audit/module.go` (`flushGaps`, `sendRulesChanged`), `internal/audit/config.go` (constants removed), `internal/traceback/obs.go` (file branch drops nothing audit-specific; reads `exe`, `pid`, `writer_start_ticks`), `rules/network.yml` (`audit.rules_changed` D10 rule: `hash` field)
- Test: `internal/audit/canonical_test.go`

**Interfaces:**
- Consumes: `event.FileChange`, `event.Conn`, `event.TelemetryGap`, `audit.RulesChanged`, `WithExtra`.
- Produces: all audit events validate; `net_connect` is gone from the audit package.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestFileChangeCanonical(t *testing.T) {
	// file_create.log and file_rename.log fixtures: Validate ok; op "create" / "rename" with old_path; exe, pid, user (the writer) set; keys actor_exe/actor_pid absent;
	// self_tamper true on a phylax_self path; x_paths, x_dirs present; Priority critical
}
func TestSweepFileChangeCanonical(t *testing.T) { /* source "sweep", writer_known false, content_changed true, sha256/old_sha256, Priority high, Validate ok */ }
func TestAuditConnCanonical(t *testing.T) {
	// net_connect.log fixture (connect to 198.51.100.7:443, accept from 203.0.113.9:51000)
	// connect -> conn{op opened, dir outbound, raddr, rport, source audit}; accept -> dir inbound; keys addr/port/direction absent; x_family present
	// a connect to a unix socket address -> no conn event (counted in x? no: dropped, Health Usage.Dropped unchanged)
}
func TestGapAndRulesChangedValidate(t *testing.T) {
	// SequenceGap scenario: telemetry_gap{source audit, reason "sequence_gap", count, from, to RFC3339 UTC}, x_count_exact bool; Validate ok
	// flushed-rules scenario: audit.rules_changed Validate ok; reason "rules_changed"; repaired true; expected_hash != actual_hash
}
func TestNoNetConnectKindRemains(t *testing.T) { /* walk every event of every audit test in this package: kind != "net_connect" */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/audit/ -run 'Canonical|GapAndRules|NoNetConnect' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** with the producer recipe. `onNet` parses the address; a non-IP address (unix socket, empty) emits nothing. `flushGaps` and `sendRulesChanged` use `event.New`; the gap `count_exact` is `WithExtra("count_exact", ...)`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/audit/ ./internal/traceback/ ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit** `audit: canonical file_change, conn, gap and rules_changed`.

---

### Task 6: `audit`: settings, manifest, `HealthReporter` and the heartbeat rules hash (Known bugs 16, 17)

**Files:**
- Modify: `internal/agent/mods/audit_linux.go` (`Manifest`, `Section` honours `Enabled`, `Build` passes settings), `internal/audit/module.go` (`Health()`), `internal/audit/manifest.go` (new: the `Manifest` literal)
- Test: `internal/audit/health_test.go`

**Interfaces:**
- Consumes: `module.Manifest`, `module.Health`, `module.Gap`, `module.State*`, `agent.Factory.Manifest`, `agent.HealthReporter`; the `Status` struct already in `module.go`.
- Produces: `func (m *Module) Health() module.Health`; `func Manifest() module.Manifest` (the literal in design section 3: `Name "audit"`, `OS ["linux"]`, `Privilege "root"`, `Emits` the seven kinds, `Budget{150, 96, 2000, 4000, 24<<20, 1}`, `Default true`, `Actions ["audit.rules","audit.immutable"]`).

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestHealthCarriesRulesHash(t *testing.T) {
	m, _, _, g := guardedModule(t)
	_, _ = g.Reconcile() // installs rules, baseline taken
	h := m.Health()
	if h.State != module.StateOK { t.Fatalf("%v", h) }
	if len(h.Info["rules_hash"]) != 64 || h.Info["mode"] == "" { t.Fatalf("%v", h.Info) }
	if h.Info["rules_installed"] == "" || h.Info["rules_failed"] != "0" { t.Fatalf("%v", h.Info) }
	if len(h.Detail) != 12 { t.Fatal("Detail is the first 12 hex of the hash and nothing reads it") }
}
func TestHealthDegradedOnNeverRuleAndFailedRules(t *testing.T) { /* foreign never rule -> StateDegraded, Gaps contains What "never rules present"; install failure -> Gaps "rules" naming the refused rule */ }
func TestHealthUnavailableWithoutRoot(t *testing.T) { /* factory Build as non-root returns ErrUnavailable wrapping the reason (skip with message when running as root) */ }
func TestManifestValidAndKindsDeclared(t *testing.T) { /* Manifest().Validate()==nil; every Emits kind event.Lookup ok; Emits has process_start, file_change, conn, telemetry_gap and the three audit.* */ }
func TestSectionHonoursEnabled(t *testing.T) { /* block with Enabled false -> Section enabled false */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/audit/ ./internal/agent/mods/ -run 'Health|Manifest|SectionHonours' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Health()` reads `Status()`: `ok` when installed, enabled, reader attached, no never rules; `degraded` per the design's list; `Info` keys `rules_hash` (full), `mode`, `rules_installed`, `rules_failed`, `audit_pid`, `backlog`, `lost`; `Usage` from the module's counters (events, dropped = rate-limited + queue overflow, held bytes = process table + queue + sweep snapshot estimate). Factory sets `Manifest: audit.Manifest()`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/audit/ ./internal/agent/mods/`. Expected: PASS.
- [ ] **Step 5: Commit** `audit: manifest, HealthReporter and heartbeat rules hash`.

---

### Task 7: `audit`: `audit.module_load` and `audit.af_alg`

**Files:**
- Modify: `internal/audit/rules.go` (two fixed rule lines), `internal/audit/assemble.go` (`kmod_load` branch), `internal/audit/handle.go` (`onKmod`, `onAFAlg`)
- Create: `internal/audit/testdata/kmod_load.log`, `internal/audit/testdata/afalg_socket.log` (recorded `auditctl`-style SYSCALL records: syscall 175 `init_module` with key `phylax_kmod`; syscall 41 `socket` a0=0x26 with key `phylax_afalg`)
- Test: `internal/audit/kmod_test.go`

**Interfaces:**
- Consumes: `audit.ModuleLoad`, `audit.AFAlg` (Task 1).
- Produces: `BuildRuleLines` adds `-a always,exit -F arch=b64 -S init_module,finit_module -k phylax_kmod` (and the `b32` form where `archFlags` yields it) and `-a always,exit -F arch=b64 -S socket -F a0=38 -F auid>=1000 -F auid!=unset -k phylax_afalg`, both unconditional.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestRuleLinesIncludeKmodAndAFAlg(t *testing.T) {
	lines := BuildRuleLines(&Config{}, allExist)
	need := []string{"-S init_module,finit_module -k phylax_kmod", "-S socket -F a0=38 -F auid>=1000 -F auid!=unset -k phylax_afalg"}
	for _, n := range need { if !anyContains(lines, n) { t.Errorf("missing %q", n) } }
}
func TestModuleLoadEvent(t *testing.T) {
	// kmod_load.log -> one audit.module_load: syscall "init_module", key "phylax_kmod", exe/comm/pid/uid/auid set; Validate ok; Priority high; no process_start emitted
}
func TestAFAlgEvent(t *testing.T) {
	// afalg_socket.log -> audit.af_alg: family 38, key "phylax_afalg", auid 1000; Validate ok
}
func TestRulesHashChangesWithNewRules(t *testing.T) { /* HashLines of the lines differs from a set without the two rules (old baseline invalid by design) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/audit/ -run 'Kmod|AFAlg|ModuleLoad' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Assemble` routes a SYSCALL whose key list contains `phylax_kmod` or `phylax_afalg` and that has no EXECVE to `onKmod`/`onAFAlg`; the module name is read from the PATH record when present. Add the two lines in `BuildRuleLines` after the exec rule.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/audit/`. Expected: PASS.
- [ ] **Step 5: Commit** `audit: module-load and AF_ALG events and fixed rules`.

---

### Task 8: `audit`: unsupported filesystem gap (review D98)

**Files:**
- Modify: `internal/audit/module.go` (`verifyOnce`, `Health`), create `internal/audit/fstype_linux.go`, `fstype_other.go`
- Test: `internal/audit/fstype_test.go`

**Interfaces:**
- Produces: `func unsupportedFS(paths []string, statfs func(string) (int64, error)) []string` returns the watch paths on NFS, overlayfs, FUSE, CIFS, btrfs-subvolume-less magic numbers (`0x6969`, `0x794c7630`, `0x65735546`, `0xFF534D42`, `0xFE534D42`); `Health` adds `Gap{What:"unsupported filesystem under <path>"}`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestUnsupportedFSDetected(t *testing.T) {
	fake := func(p string) (int64, error) { if p == "/mnt/nfs/www" { return 0x6969, nil }; return 0xEF53, nil } // ext4
	got := unsupportedFS([]string{"/etc", "/mnt/nfs/www"}, fake)
	if len(got) != 1 || got[0] != "/mnt/nfs/www" { t.Fatalf("%v", got) }
}
func TestHealthReportsUnsupportedFS(t *testing.T) { /* module with a statfs hook returning overlayfs 0x794c7630 for /var/www -> Health.State degraded and Gaps contains "unsupported filesystem under /var/www" */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/audit/ -run 'UnsupportedFS' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `statfs` through `golang.org/x/sys/unix.Statfs`; `fstype_other.go` returns nil. Checked at start and on every verify tick.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/audit/ && GOOS=windows go vet ./internal/audit/`. Expected: PASS and a clean vet.
- [ ] **Step 5: Commit** `audit: report unsupported filesystems as a coverage gap`.

---

### Task 9: `audit`: the actions `audit.rules` and `audit.immutable`

**Files:**
- Create: `internal/audit/actions.go` (init registers through `actions.Register`; `Active()`), modify `internal/audit/module.go` (`Active` handle set in `Start`; `UpdateWatches`)
- Test: `internal/audit/actions_test.go`

**Interfaces:**
- Consumes: `actions.Action`, `actions.Spec`, `actions.Params`, `actions.Register` (W1 Task 2a).
- Produces: `func Active() *Module` (nil when the module is not running); `func (m *Module) UpdateWatches(add, remove []string) (RulesReport, error)` (edits the declared `extra_watches`, reconciles through the guard and re-baselines, under the guard's mutex so the verify loop never repairs it away); actions `audit.rules` (`Risk: actions.RiskService`; params `add` and `remove` as comma-separated paths, `Locks` `["audit"]`) and `audit.immutable` (`Risk: actions.RiskDestructive`; param `enable` bool; Apply sets `-e 2`; `Capture` returns no rollback and `Plan` notes "reboot is the rollback"; refuses when the module is not the unicast owner of the audit pid).

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestUpdateWatchesRebaselinesWithoutTamperEvent(t *testing.T) {
	m, c, _, g := guardedModule(t)
	_, _ = g.Reconcile()
	rep, err := m.UpdateWatches([]string{"/opt/app"}, nil)
	if err != nil || !rep.Repaired { t.Fatalf("%v %+v", err, rep) }
	// a following Verify reports no change and the module emitted no audit.rules_changed for this edit
	if n := len(c.kind(audit.KindRulesChanged)); n != 0 { t.Fatalf("self-inflicted tamper events: %d", n) }
	if !anyContains(m.Rules(), "/opt/app") { t.Fatal("rule not installed") }
}
func TestAuditRulesActionRoutesThroughActiveModule(t *testing.T) { /* registry from actions.Core() contains audit.rules; with no Active module Apply returns ErrUnsupported-wrapped error; with one it installs */ }
func TestImmutableNeverAutomatic(t *testing.T) { /* Spec().Risk == RiskDestructive and Plan.Notes contains "reboot" */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/audit/ -run 'UpdateWatches|AuditRulesAction|Immutable' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Model both actions on `fileHash`/`serviceState` in `internal/actions/files.go` (zero-value struct implementing `actions.Action`). `Active` is an `atomic.Pointer[Module]` set at `Start` and cleared at exit (`shortcut: one agent per process, upgrade to a registry by agent id if that changes`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/audit/ ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit** `audit: audit.rules and audit.immutable actions`.

---

### Task 10: `audit`: conformance, producer fixtures, exec-storm test

**Files:**
- Create: `internal/audit/conformance_test.go` (package `audit_test`), `internal/audit/fixtures_test.go`, `internal/audit/storm_test.go`
- Modify: `internal/module/conformance/allowed.go` (remove `audit` from `PreContract`)

**Interfaces:**
- Consumes: `conformance.Agent`, `conformance.AgentCase`, `agent.Registered()`.
- Produces: `audit` is a contract module.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestAuditConformance(t *testing.T) {
	f := factoryNamed(t, "audit")
	conformance.Agent(t, conformance.AgentCase{
		Factory:  f,
		Default:  &plan.AgentConfig{Host: "h1", Modules: plan.ModuleSettings{Audit: &plan.AuditSettings{ModuleLimits: limitsEnabled()}}},
		Reconfig: &plan.AgentConfig{Host: "h1", Modules: plan.ModuleSettings{Audit: &plan.AuditSettings{ModuleLimits: limitsEnabled(), WebRoots: []string{"/srv/www"}}}},
		Load:     auditFixtureEvents(t), // none consumed: nil is fine; the module Consumes nothing
	})
}
func TestAuditFixturesDecodeStrictly(t *testing.T) { /* T75: every testdata/*.log through the real assembler+handler; every emitted event of a common kind passes event.Validate; process_start fixtures have no key outside the struct fields and x_ names */ }
func TestExecStormReportsEveryMiss(t *testing.T) {
	// T43 CI form: push 1000 synthetic exec records per second for 3 s through m.push at the default rate limit (2000/s, burst 4000);
	// kept + sum(telemetry_gap.count for reason rate_limited, queue_overflow) == pushed; no silent loss
}
```

On a non-root test run the factory reports `unavailable`, which check 2 accepts; the conformance run needs no privilege.

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/audit/ -run 'Conformance|Fixtures|Storm' -v`. Expected: FAIL until `PreContract` no longer lists `audit` (`TestPreContractShrinks` in the conformance package fails the other way: it demands the removal).
- [ ] **Step 3: Fix what the suite finds** (typical: a goroutine left running after stop, an undeclared field). Remove `audit` from `PreContract`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/audit/ ./internal/module/...`. Expected: PASS, including `TestNoSiblingImports` and `TestKindTable` for `audit`.
- [ ] **Step 5: Commit** `audit: on the module contract (conformance, fixtures, exec storm)`.

---

### Task 11: `winevt`: canonical `process_start`, `process_exit`, `conn`, `file_change`, `dns_query`, and `winevt.*` names; remove `net_connect`

**Files:**
- Modify: `internal/winevt/mapper.go` (`mapSysmon`, 4688 branch, constants), `internal/winevt/pipeline.go` (`sensor_state`), `internal/winevt/mapper_test.go`, `module_test.go`, `internal/traceback/obs.go` (delete the `KindNetConnect` branch, `KindSecEvent` becomes `winevt.sec_event`, file branch drops `actor_*`), `internal/traceback/trace.go`, `internal/chains/remediate.go` (`traceback.KindSecEvent` use), `rules/windows.yml`, `rules/mw-redteam.yml`, `rules/deception.yml`, `rules/pending/needs_producer.yml`, `docs/rules.md`
- Test: `internal/winevt/canonical_test.go`

**Interfaces:**
- Consumes: `event.ProcessStart`, `ProcessExit`, `Conn`, `FileChange`, `DNSQuery`, `winevt.SecEvent`, `winevt.SensorState`, `WithExtra`.
- Produces: Sysmon 1 and 4688 emit `process_start` (`source: winevt`; `parent{exe, comm, cmdline}`); Sysmon 5 emits `process_exit`; Sysmon 3 emits `conn` (`op: opened`, `dir` outbound when `Initiated`, else inbound; `laddr/lport` the local end; `raddr/rport` the other end; `x_rhost` from `destination_hostname`); Sysmon 11, 23, 26 emit `file_change` (`exe`, `pid`, `user` the writer; `gpo` fields in the struct); Sysmon 22 emits `dns_query` (`query`, `query_results`, `pid`, `exe`, `user`, `source: winevt`, Priority Bulk) and no longer a `sec_event`; everything else stays `winevt.sec_event` / `winevt.sensor_state`. Sysmon `ProcessGuid`, hashes, `channel`, `provider`, `event_id`, `record_id`, `host`, `sensor`, `logon_id` are `x_` on the common kinds.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestSysmonCommonKindsCanonical(t *testing.T) {
	m := &Mapper{Host: "dc1"}
	cases := map[string]string{"sysmon1.xml": "process_start", "sysmon3.xml": "conn", "sysmon11.xml": "file_change", "sysmon22.xml": "dns_query"}
	for name, kind := range cases {
		e := mapOne(t, m, name)
		if e.Kind != kind { t.Fatalf("%s: kind %s", name, e.Kind) }
		if err := event.Validate(e); err != nil { t.Fatalf("%s: %v", name, err) }
		for _, k := range []string{"image", "pexe", "pcomm", "actor_exe", "actor_pid", "src_ip", "dst_ip", "src_port", "dst_port", "initiated"} {
			if _, ok := e.Fields[k]; ok { t.Errorf("%s: retired field %q", name, k) }
		}
	}
}
func TestSysmon3DirectionOutboundAndInbound(t *testing.T) {
	// fixture with Initiated true: dir "outbound", laddr = SourceIp, raddr = DestinationIp, lport = SourcePort, rport = DestinationPort
	// the same record with Initiated false: dir "inbound", laddr = DestinationIp, raddr = SourceIp (local end is the destination)
}
func TestSysmon5IsProcessExit(t *testing.T) { /* a Sysmon 5 record (extend mkXML or add testdata/sysmon5.xml) -> kind process_exit, pid, exe set; Validate ok */ }
func TestSecEventAndSensorStateRenamed(t *testing.T) { /* sec4697.xml -> winevt.sec_event with category service_install; pipeline sensor probe -> winevt.sensor_state; Priority critical; both Validate ok (open payload / SensorState struct) */ }
func TestWindowsRulesStillFire(t *testing.T) { /* run rules/windows.yml + mw-redteam.yml engine over the mapped fixtures: sethc created (file_change, exe) matches; service install matches on winevt.sec_event */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/winevt/ -run 'Canonical|Sysmon3|Sysmon5|Renamed|WindowsRules' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The mapper starts each record with a `map[string]any` of raw EventData as today (kept for `winevt.sec_event`); for a record mapped to a common kind it builds the struct and attaches the raw hashes/GUID/channel/provider/event_id/record_id/host/sensor as `WithExtra`. Rule files: kind renames per the recipe (`sec_event` to `winevt.sec_event`, `actor_exe` to `exe`, `pexe`/`pcomm` to `parent.*`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/winevt/ ./internal/traceback/ ./internal/chains/ ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit** `winevt: canonical common kinds and winevt.* names; rules and readers renamed`.

---

### Task 12: `winevt`: `auth_event` from 4624 and 4625

**Files:**
- Modify: `internal/winevt/mapper.go` (4624/4625), `internal/traceback/obs.go` (delete `KindAuthSuccess`, `KindAuthFail`; one `case KindAuthEvent`), `rules/auth.yml`, `rules/deception.yml`, `rules/pending/needs_producer.yml`, `docs/rules.md`
- Test: `internal/winevt/auth_test.go`, `internal/traceback/obs_auth_test.go`

**Interfaces:**
- Consumes: `event.AuthEvent` (extension fields from W1 Task 4a).
- Produces: 4624 gives `auth_event{result:"success"}`, 4625 `result:"fail"` with `account`, `domain`, `source` (cleaned IP, empty for `-`), `source_port`, `service:"windows"`, `method`, `logon_type`, `logon_type_name`, `machine_account`, `status`, `sub_status`, `failure_reason`, `process`, `workstation`, `subject_account`; `x_anonymous_logon`, `x_target_logon_id`, `x_channel`, `x_event_id`, `x_record_id`. Priority High.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestAuthEventFromSecurity(t *testing.T) {
	m := &Mapper{Host: "dc1"}
	ok := mapOne(t, m, "sec4624.xml")
	fail := mapOne(t, m, "sec4625.xml")
	for _, e := range []event.Event{ok, fail} {
		if e.Kind != "auth_event" { t.Fatal(e.Kind) }
		if err := event.Validate(e); err != nil { t.Fatal(err) }
	}
	if ok.Fields["result"] != "success" || fail.Fields["result"] != "fail" { t.Fatal("result") }
	if fail.Fields["status"] == nil || fail.Fields["service"] != "windows" { t.Fatalf("%v", fail.Fields) }
}
func TestAuthDashIPBecomesEmptyStillHolds(t *testing.T) { /* existing TestAuthDashIPBecomesEmpty on the new kind: source absent */ }
func TestAuthRulesMatchResultNotKind(t *testing.T) {
	// rules/auth.yml D18 (default-cred logon) matches {kind: auth_event, result: success, account: azul, source: 203.0.113.5, service: sshd}
	// and not result: fail; the failed-login burst rule counts only result: fail
}
func TestObsAuthEvent(t *testing.T) { /* auth_event success -> ClassAuthOK, fail -> ClassAuthFail; Account normalised; Source, Service, Method, LogonType read; Exe from process */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/winevt/ ./internal/traceback/ ./internal/detect/ -run 'AuthEvent|AuthRules|AuthDash' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Rule edits: `event: auth_success` to `event: auth_event` plus `- result: success`; `auth_fail` likewise with `fail`; lists `[auth_success, auth_fail]` to `auth_event`; inline tests change `kind:` and add `result:`. `rules/deception.yml` rules that list `sec_event` among them become `winevt.sec_event` (already done in Task 11) and `auth_event`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/winevt/ ./internal/traceback/ ./internal/chains/ ./internal/scorer/ ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit** `winevt: auth_event from 4624 and 4625; auth rules and readers renamed`.

---

### Task 13: `winevt`: gaps through `event.New`, manifest, settings, `HealthReporter`

**Files:**
- Modify: `internal/winevt/pipeline.go` (gap emitters, `Health`), create `internal/winevt/manifest.go`, modify `internal/agent/mods/winevt.go`
- Test: `internal/winevt/health_test.go`

**Interfaces:**
- Produces: `func Manifest() module.Manifest` (design section 3: `OS ["windows"]`, `Privilege "root"`, `Emits` nine kinds, `Budget{100, 64, 500, 1000, 12<<20, 1}`, `Default true`, `Content ["sysmon"]`, `Actions` nil here because the four logging actions are not built in W3); `func (m *Module) Health() module.Health`; `telemetry_gap{source:"winevt:<channel>" or "winevt", reason, count, from, to}` with `x_channel`, `x_from_record`, `x_to_record`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestGapsValidateAndCarryChannel(t *testing.T) {
	// the existing TestBackpressureRecordsTelemetryGap scenario: gap event Validate ok; source "winevt:Security"; reason "queue_full"; count > 0; x_from_record < x_to_record
}
func TestHealthStates(t *testing.T) {
	// all channels ok and Sysmon running -> ok
	// Sysmon not running (fallback) -> degraded, Gaps contains "Sysmon not running; process events come from 4688 (no hashes, no network or file events)"
	// a channel missing -> degraded with "channel <name> missing"; stale bookmark -> Gaps "Security log cleared / bookmark reset: events between ..."
	// Detail empty unless the Sysmon service name is not stock
}
func TestManifestValid(t *testing.T) { /* Validate nil; Emits contain process_start, process_exit, auth_event, conn, file_change, dns_query, telemetry_gap, winevt.sec_event, winevt.sensor_state */ }
func TestSectionHonoursEnabled(t *testing.T) { /* enabled false -> Section false */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/winevt/ ./internal/agent/mods/ -run 'Gaps|HealthStates|ManifestValid|SectionHonours' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the gap emitters with `event.New` (priority High) and `Health()` from the per-channel counters the pipeline already keeps. Factory sets `Manifest: winevt.Manifest()`; non-Windows `Build` still returns `ErrUnavailable`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/winevt/ ./internal/agent/mods/ && GOOS=windows go vet ./internal/winevt/`. Expected: PASS.
- [ ] **Step 5: Commit** `winevt: manifest, HealthReporter, typed telemetry_gap`.

---

### Task 14: `winevt`: enrollment backscan (review D94)

**Files:**
- Modify: `internal/winevt/pipeline.go` (first start with no bookmark runs the backscan), `internal/winevt/filter.go` (`TimeCreated[timediff(@SystemTime) <= N]` clause), `internal/winevt/config.go` or the `Config` struct (`BackscanHours`), `internal/agent/mods/winevt.go` (pass `s.BackscanHours`), `internal/winevt/mapper.go` (replay flag)
- Test: `internal/winevt/backscan_test.go`

**Interfaces:**
- Consumes: `plan.WinevtSettings.BackscanHours` (Task 1).
- Produces: `Config.Backscan time.Duration` (0 disables); `(Channel) XPath(backscan time.Duration) string`; events from the backscan carry the original `Time` and the payload `replay: true` (`SecEvent["replay"]` on `winevt.sec_event`; the `Replay` member Task 1 added on the four common structs), Priority Bulk, never forwarded as live telemetry unless a rule fires (the module marks them `Bulk`; the rule engine's replay exclusion is W4).

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestBackscanXPathWindow(t *testing.T) {
	got := Channel{Name: "Security", Include: []int{4624, 4625}}.XPath(24 * time.Hour)
	if !strings.Contains(got, "timediff(@SystemTime) <= 86400000") { t.Fatal(got) }
}
func TestBackscanMarksReplayAndKeepsOriginalTime(t *testing.T) {
	// fake log with 3 records timestamped 2h ago and no bookmark file; Backscan 24h: 3 events, each fields.replay true, Time == record time (not now), Priority bulk;
	// then 1 live record: replay absent, Priority high
}
func TestBackscanOnlyOnFirstStart(t *testing.T) { /* second Start with a bookmark file present: no backscan, resumes from the bookmark */ }
func TestBackscanDisabledNegative(t *testing.T) { /* BackscanHours -1 => Backscan 0 => first run starts at future events (existing test still passes) */ }
func TestBackscanXPathUnderClauseCap(t *testing.T) { /* default Security include list + backscan clause: still <= 18 id clauses; over the cap it falls back to '*' plus client-side filtering */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/winevt/ -run Backscan -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The fake `Source` in `module_test.go` already takes `fromOldest`; the backscan opens each default channel (Security, System, PowerShell, Task Scheduler, Sysmon if present) with the time clause, drains it, then starts the live subscription from the saved bookmark position. `BackscanHours` 0 means 24, negative disables.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/winevt/ ./internal/event/ && GOOS=windows go vet ./internal/winevt/`. Expected: PASS.
- [ ] **Step 5: Commit** `winevt: one-time enrollment backscan marked replay`.

---

### Task 15: `winevt`: conformance and producer fixtures

**Files:**
- Create: `internal/winevt/conformance_test.go`, `internal/winevt/fixtures_test.go`
- Modify: `internal/module/conformance/allowed.go` (remove `winevt` from `PreContract`)

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestWinevtConformance(t *testing.T) {
	f := factoryNamedWindows(t) // winevt's Build needs a fixture Source: the test registers a factory copy whose Build injects the fakeLog Source and sets OS to runtime.GOOS
	conformance.Agent(t, conformance.AgentCase{Factory: f, Default: winevtCfg(), Reconfig: winevtCfg2(), KeepKey: ""})
}
func TestWinevtFixturesDecodeStrictly(t *testing.T) {
	// T75: every testdata/*.xml through Mapper.Map; every event whose kind is a common kind passes event.Validate;
	// winevt.sec_event events carry category; no event has a key from the retired set
}
func TestEveryFixtureStillCovered(t *testing.T) { /* existing TestEveryFixtureIsCovered */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/winevt/ -run 'Conformance|FixturesDecode' -v`. Expected: FAIL.
- [ ] **Step 3: Fix what the suite finds; remove `winevt` from `PreContract`.** The reconfiguration check relies on the bookmark living in `StateDir` (already so).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/winevt/ ./internal/module/...`. Expected: PASS.
- [ ] **Step 5: Commit** `winevt: on the module contract`.

---

### Task 16: `sockets`: Windows extended TCP and UDP tables

**Files:**
- Create: `internal/sockets/table_windows.go` (calls `GetExtendedTcpTable`/`GetExtendedUdpTable` through `golang.org/x/sys/windows`), `internal/sockets/table.go` (pure parsers, all OS), `internal/sockets/table_test.go`

**Interfaces:**
- Consumes: `sockets.Sock`.
- Produces:

```go
// SockPID is a socket with the owning process id from the extended table.
type SockPID struct {
	Sock
	PID uint32
}
func ParseTCPTable4(b []byte) ([]SockPID, error)  // MIB_TCPTABLE_OWNER_PID
func ParseTCPTable6(b []byte) ([]SockPID, error)  // MIB_TCP6TABLE_OWNER_PID
func ParseUDPTable4(b []byte) ([]SockPID, error)  // MIB_UDPTABLE_OWNER_PID
func ParseUDPTable6(b []byte) ([]SockPID, error)  // MIB_UDP6TABLE_OWNER_PID
func (SockDiag) ... // not touched; on Windows: func ExtendedTables() ([]SockPID, error) in table_windows.go
```

`Sock.State` uses the same numeric states as `sock_diag` (map MIB states: 2 LISTEN to 10, 5 ESTABLISHED to 1, ...); `Sock.Inode` is 0 on Windows.

- [ ] **Step 1: Write the tests** (byte fixtures built in the test with `encoding/binary`, little endian):

```go
func TestParseTCPTable4(t *testing.T) {
	// header count=2; row1: state 2 (LISTEN) local 0.0.0.0:445 (port network-order in dwLocalPort) remote 0.0.0.0:0 pid 4
	//                row2: state 5 (ESTAB) local 10.0.0.5:49500 remote 10.0.0.9:1433 pid 3120
	// want 2 rows: row1 IsListener, Local 0.0.0.0:445, PID 4, State StateListen; row2 IsConnection, Remote 10.0.0.9:1433, PID 3120, State StateEstablished
}
func TestParseTableRejectsShortAndOversize(t *testing.T) { /* count larger than the buffer -> error; count > 65536 -> error; nil -> error */ }
func TestParseUDPTable6(t *testing.T) { /* one row ::1 port 5353 pid 900 -> Proto "udp", Local [::1]:5353 */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/sockets/ -run 'ParseTCP|ParseTable|ParseUDP' -v`. Expected: FAIL (`undefined`).
- [ ] **Step 3: Implement** the four parsers (bounded: reject a count above 65536 or beyond the buffer) and `ExtendedTables` (two-call buffer sizing loop, at most 4 retries, 8 MiB cap).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/sockets/ && GOOS=windows go vet ./internal/sockets/`. Expected: PASS and a clean vet. The API calls themselves run in the lab task.
- [ ] **Step 5: Commit** `sockets: Windows extended table readers`.

---

### Task 17: `net`: no `deps` coupling (Known bug 15)

**Files:**
- Modify: `internal/net/tracker.go` (delete `TrackerConfig.Deps`, `depsConn`, the `Observe` call), `internal/net/module.go` (delete `NoDeps`, `DNS`, `deps.NewCollector`), delete `internal/net/deps_test.go`, `internal/agent/mods/net.go`
- Test: `internal/net/imports_test.go`

**Interfaces:**
- Produces: `internal/net` and its tests import no `internal/deps`; `Config` loses `NoDeps` and `DNS`; `TrackerConfig` loses `Deps`.

- [ ] **Step 1: Remove the skip and write the test:**

```go
func TestNetImportsNoDeps(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-test", "-f", "{{.ImportPath}}", ".").Output()
	if err != nil { t.Fatal(err) }
	if strings.Contains(string(out), "internal/deps") { t.Fatal("net imports deps (sibling import, Known bug 15)") }
}
func TestNetEmitsNoDepsKinds(t *testing.T) { /* run the tracker over a connection fixture: no event kind with prefix "deps." */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/net/ -run 'NoDeps|NetEmitsNo' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the deletions; keep `internal/deps` unchanged (W8 makes it a subscriber). Record in the commit message that dependency discovery pauses until W8.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet && go test -race ./internal/net/ ./internal/deps/ ./internal/agent/...`. Expected: PASS.
- [ ] **Step 5: Commit** `net: stop calling deps (bug 15); deps becomes a subscriber in W8`.

---

### Task 18: `net`: typed `net.*` events, `canary: true`, own-link exclusion, NFLOG overflow gap

**Files:**
- Modify: `internal/net/egress.go` (`try` builds `EgressDenied`), `internal/net/canary.go` (`CanaryResult`, `canary: true`), `internal/net/module.go` (`SensorDegraded`, `telemetry_gap` through `event.New`, own-link exclusion), `internal/net/tracker.go` (skip the agent's own sockets), `internal/net/nflog_linux.go` (expose `Lost`), `rules/network.yml` (canary exemptions read `canary: true`; D12 canary rule), `internal/traceback/obs.go` (egress fallback reads `raddr/rport` only)
- Test: `internal/net/typed_test.go`

**Interfaces:**
- Consumes: `netmod.EgressDenied`, `CanaryResult`, `SensorDegraded`, `event.TelemetryGap`.
- Produces: `TrackerConfig.OwnPID int` and `EgressConfig.OwnPID int` (sockets owned by that pid are neither reported as `conn` nor attributed); gap reasons `nflog_enobufs`, `connection_table_full` as `telemetry_gap{source:"net"}`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestEgressDeniedTyped(t *testing.T) { /* attributed denial: Validate ok; attributed true; raddr/rport; community_id; canary absent; envelope Tag empty */ }
func TestCanaryUsesPayloadFlagNotTag(t *testing.T) {
	e := ProbeCanary(ctx, blockedTarget, time.Second) // target on a closed local port
	if err := event.Validate(e); err != nil { t.Fatal(err) }
	if e.Fields["canary"] != true || e.Tag != "" { t.Fatalf("%v tag %q", e.Fields, e.Tag) }
	if _, ok := e.Fields["tag"]; ok { t.Fatal("fields.tag retired") }
	// a denial whose destination is a canary target: egress_denied canary true, canary_tag set
}
func TestOwnLinkExcluded(t *testing.T) {
	// fakeSocks: one established socket owned by OwnPID (the agent's TLS link to the controller), one owned by pid 900.
	// Poll -> exactly one conn opened (pid 900); a denied packet matching the agent's socket is emitted unattributed? no: not emitted at all (platform problem reported by the link)
}
func TestNFLogOverflowBecomesGap(t *testing.T) { /* feed Lost=5 -> telemetry_gap{source net, reason nflog_enobufs, count 5}; Health later shows the gap */ }
func TestSensorDegradedTyped(t *testing.T) { /* Start with a source that fails NFLOG -> net.sensor_degraded Validate ok; the module continues with socket telemetry */ }
func TestCanaryRulesExemptByPayloadFlag(t *testing.T) { /* rules/network.yml egress rules: {canary: true} is exempt, V3.egress-canary-leak fires on net.canary_result result leak */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/net/ ./internal/detect/ -run 'Typed|Canary|OwnLink|NFLogOverflow|SensorDegraded' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The factory sets `OwnPID: os.Getpid()`. The controller-rendered canary `Tag: "canary"` becomes `canary_tag` only (`genconfig.go` unchanged; the value is a label).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/net/ ./internal/traceback/ ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit** `net: typed net.* kinds, canary payload flag, own-link exclusion, NFLOG overflow gap`.

---

### Task 19: `net`: settings, manifest, `HealthReporter`, baseline across reconfiguration, conformance

**Files:**
- Create: `internal/net/manifest.go`, `internal/net/health.go`, `internal/net/conformance_test.go`, `internal/net/health_test.go`
- Modify: `internal/net/module.go` (`Env.Keep` of the tracker snapshot), `internal/agent/mods/net.go` (`Manifest`, `Keep` plumbing), `internal/module/conformance/allowed.go` (remove `net`)

**Interfaces:**
- Produces: `Manifest()` (design section 3: `OS ["linux","windows"]`, `Consumes ["winevt.sec_event"]`, `Emits` eight kinds, `Budget{80, 64, 200, 400, 8<<20, 0}`, `Default true`); `Config.Keep func(key string, v any)` and `Config.Kept func(key string) any` wired from `agent.Env`; `func (m *Module) Health() module.Health`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestReconfigureKeepsBaseline(t *testing.T) {
	// harness: Apply cfg with Services {"tcp/22":"ssh"}; wait for the baseline snapshot (listener baseline true);
	// Apply cfg with Services {"tcp/22":"ssh","tcp/80":"http"} (module replaced); the first snapshot of the new module emits NO event with baseline true for sockets that existed before; a new listener on 80 is op added without baseline
	// Kept("net.tracker") non-nil after replacement
}
func TestHealthDegradedWhenNFLogFailsOrTableFull(t *testing.T) { /* NFLOG start error -> degraded + Gap "NFLOG not available: <err>"; 65537 connections -> Gap "connection table full (1 dropped)" */ }
func TestHealthUnavailableOffLinux(t *testing.T) { /* the factory on a non-Linux/non-Windows GOOS returns ErrUnavailable; skip on Linux with the message */ }
func TestNetConformance(t *testing.T) {
	conformance.Agent(t, conformance.AgentCase{Factory: netFactoryWithFixtureSource(t), Default: netCfg(), Reconfig: netCfg2(), KeepKey: "net.tracker", Load: nil})
}
func TestNetFixturesDecodeStrictly(t *testing.T) { /* T75: tracker tests' events, egress and canary events: Validate ok; conn/listener source "net" */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/net/ -run 'Reconfigure|HealthDegraded|Conformance|FixturesDecode' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The tracker exports `Snapshot() []byte`-free state: store the `*Tracker` itself with `Keep("net.tracker", tr)` and, on the next `Start`, adopt it (re-point its `SockSource` and `ProcResolver`). `Health` follows the design's states; `Info` has `listeners`, `conns`, `dropped`, `nflog_lost`. Remove `net` from `PreContract`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/net/ ./internal/agent/... ./internal/module/...`. Expected: PASS.
- [ ] **Step 5: Commit** `net: on the module contract (manifest, health, baseline kept across reconfiguration)`.

---

### Task 20: `net` on Windows: listeners and connections from the extended tables

**Files:**
- Create: `internal/net/source_windows.go` (a `SockSource` over `sockets.ExtendedTables`, and a `ProcResolver` that resolves pid to image path), `internal/net/source_windows_other.go`; modify `internal/net/module_other.go`/`module_linux.go` (`defaultSources` for Windows), `internal/agent/mods/net.go` (drop the Linux-only refusal)
- Test: `internal/net/source_windows_test.go`

**Interfaces:**
- Consumes: `sockets.SockPID`, `sockets.ParseTCPTable4` etc. (Task 16).
- Produces: `func socksFromTables(rows []sockets.SockPID) (socks []sockets.Sock, owners map[uint64]sockets.Proc)` (pure; gives each row a synthetic inode `uint64(pid)<<32 | localPort` so the existing inode-keyed tracker works); `Proc.Exe` from `QueryFullProcessImageName` on Windows only.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestSocksFromTablesFeedsTracker(t *testing.T) {
	rows := []sockets.SockPID{ /* LISTEN 0.0.0.0:445 pid 4; ESTAB 10.0.0.5:49500 -> 10.0.0.9:1433 pid 3120 */ }
	socks, owners := socksFromTables(rows)
	tr := NewTracker(TrackerConfig{Services: map[string]string{"tcp/445": "smb"}}, fakeSource(socks), fakeOwners(owners))
	evs, _ := tr.Poll(time.Now())
	// listener lport 445 service smb pid 4; conn opened dir outbound raddr 10.0.0.9 rport 1433 pid 3120; all Validate ok
}
func TestManifestOSIncludesWindows(t *testing.T) { /* Manifest().OS == [linux windows]; factory on windows builds (skip with message off Windows) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/net/ -run 'SocksFromTables|ManifestOSIncludes' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** NFLOG and canaries stay Linux (`Config.NFLogGroups` ignored on Windows with a `net.sensor_degraded`-free skip); canaries work on both (plain dial).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/net/ && GOOS=windows go vet ./internal/net/ ./internal/agent/...`. Expected: PASS.
- [ ] **Step 5: Commit** `net: Windows listeners and connections from the extended tables`.

---

### Task 21: `net` on Windows: 5157 becomes `net.egress_denied`

**Files:**
- Create: `internal/net/wfp.go`; modify `internal/net/module.go` (`Env.Subscribe` on the bus for `winevt.sec_event`), `internal/agent/mods/net.go` (the factory becomes `subSpec`)
- Test: `internal/net/wfp_test.go`

**Interfaces:**
- Consumes: `winevt.SecEvent` payload keys (`category: wfp_connection`, `event_id: 5157`, `direction`, `application`, `source_address`, `source_port`, `destination_address`, `destination_port`, `protocol`, `process_id`), `Env.Subscribe(buf, "winevt.sec_event")`.
- Produces: `func EgressFromWFP(e event.Event, ownExe string) (event.Event, bool)`; the module manifest `Consumes` already lists `winevt.sec_event`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestWFP5157OutboundBecomesEgressDenied(t *testing.T) {
	in := wfpEvent(5157, "outbound", `C:\Users\bob\AppData\Local\Temp\x.exe`, "10.0.0.5", 49800, "203.0.113.9", 4444, "tcp", 3120)
	out, ok := EgressFromWFP(in, `C:\Program Files\Phylax\phylax.exe`)
	if !ok { t.Fatal("not converted") }
	if err := event.Validate(out); err != nil { t.Fatal(err) }
	f := out.Fields
	if f["raddr"] != "203.0.113.9" || f["rport"] != json.Number("4444") || f["attributed"] != true || f["sensor"] != "5157" { t.Fatalf("%v", f) }
	if f["exe"] != `C:\Users\bob\AppData\Local\Temp\x.exe` { t.Fatal("exe") }
}
func TestWFPIgnoresInboundOtherIDsAndOwnLink(t *testing.T) {
	// inbound 5157 -> false (net.ingress_denied is W6); event_id 5156 -> false; application == ownExe (case-insensitive) -> false
}
func TestWFPEndToEndThroughBus(t *testing.T) { /* harness: Publish a winevt.sec_event 5157; Emitted contains one net.egress_denied; Publish an unrelated winevt.sec_event: nothing */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/net/ -run 'WFP' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `winevt` already maps 5156/5157 as `wfp_connection` (`mapper.go`); this task only reads them. `shortcut: inbound 5157 is ignored until W6 emits net.ingress_denied`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/net/ ./internal/agent/mods/`. Expected: PASS.
- [ ] **Step 5: Commit** `net: Windows 5157 blocks re-emitted as net.egress_denied`.

---

### Task 22: `logs`: parser format, loader and inline test runner

**Files:**
- Create: `internal/logs/parser.go`, `internal/logs/timeparse.go`, `internal/logs/embed.go` (`//go:embed parsers/*.yml`), `internal/logs/parser_test.go`

**Interfaces:**
- Consumes: `event.AuthEvent`, `logs.Line`.
- Produces:

```go
type Pattern struct {
	Re      string            `yaml:"re"`      // RE2 with named groups
	Event   string            `yaml:"event"`   // auth_event | line | ignore
	Result  string            `yaml:"result"`  // success | fail (auth_event)
	Fields  map[string]string `yaml:"fields"`  // event field -> named group
	Static  map[string]string `yaml:"static"`  // event field -> constant (method: password)
	Time    string            `yaml:"time"`    // named group holding the syslog or ISO stamp; "" = the host clock
}
type Test struct{ Line string `yaml:"line"`; Want map[string]string `yaml:"want"`; Ignored bool `yaml:"ignored"` }
type Parser struct {
	Name     string    `yaml:"name"`
	Patterns []Pattern `yaml:"patterns"`
	Tests    []Test    `yaml:"tests"`
}
func LoadParsers(fsys fs.FS) (map[string]*Parser, error)       // compiles every RE2; error on a bad pattern, duplicate name, or a parser with no tests
func (p *Parser) Parse(line string, now time.Time) (ev *event.Event, matched bool) // first matching pattern wins; nil event + matched true = deliberately ignored
func (p *Parser) RunTests(now time.Time) []error
func ResolveSyslogTime(stamp string, now time.Time) time.Time  // "Dec 31 23:59:58" with now = Jan 1 00:00:02 yields Dec 31 of the previous year; a stamp more than 24 h in the future is read as last year
```

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestLoadParsersRejectsBadPatternAndMissingTests(t *testing.T) {
	// fstest.MapFS with a parser whose re is "(" -> error mentioning the file; a parser with no tests -> error
}
func TestParseFirstMatchWinsAndIgnore(t *testing.T) { /* two patterns; the first matching produces the event; an "ignore" pattern returns nil,true */ }
func TestHostileLineLinearTime(t *testing.T) {
	line := strings.Repeat("a", 8192) + " from " + strings.Repeat("9", 8192)
	start := time.Now(); _, _ = p.Parse(line, now)
	if time.Since(start) > 50*time.Millisecond { t.Fatal("RE2 must stay linear") }
}
func TestResolveSyslogTimeYearBoundary(t *testing.T) {
	now := time.Date(2027, 1, 1, 0, 0, 2, 0, time.UTC)
	got := ResolveSyslogTime("Dec 31 23:59:58", now)
	if got != time.Date(2026, 12, 31, 23, 59, 58, 0, time.UTC) { t.Fatal(got) }
	if g := ResolveSyslogTime("Jun  5 08:00:00", time.Date(2027, 6, 5, 8, 0, 1, 0, time.UTC)); g.Year() != 2027 { t.Fatal(g) }
	if g := ResolveSyslogTime("garbage", now); !g.Equal(now) { t.Fatal("unparsable time falls back to the host clock") }
}
func TestEmbeddedParsersAllPassTheirOwnTests(t *testing.T) { /* LoadParsers(embedded); for each parser RunTests() == nil */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/logs/ -run 'LoadParsers|FirstMatch|Hostile|SyslogTime|Embedded' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Parse` caps its input at 8 KiB (`Line.Line` carries the cut line; the cut is the tailer's concern), uses `regexp` only (RE2). `internal/logs/parsers/` gets one placeholder `raw.yml` (the real parsers are Tasks 23 and 24).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/logs/`. Expected: PASS.
- [ ] **Step 5: Commit** `logs: YAML parser format with inline tests, RE2 only`.

---

### Task 23: `logs`: authentication parsers (sshd, dovecot, vsftpd, proftpd)

**Files:**
- Create: `internal/logs/parsers/{sshd,dovecot,vsftpd,proftpd}.yml` (each with inline `tests:`), `internal/logs/parsers_auth_test.go`

**Interfaces:**
- Produces: parsers named `sshd`, `dovecot`, `vsftpd`, `proftpd`, each yielding `auth_event{service, result, account, source, source_port?, method?, invalid_user?}`; `AuthEvent.Service` values are `sshd`, `dovecot`, `vsftpd`, `proftpd`.

- [ ] **Step 1: Write the tests** (recorded lines; the YAML `tests:` carry the same lines):

```go
func TestSSHDParser(t *testing.T) {
	now := time.Date(2027, 3, 14, 12, 0, 0, 0, time.UTC)
	cases := []struct{ line, result, account, source, method string; invalid bool }{
		{"Mar 14 11:59:01 web sshd[811]: Accepted publickey for azul from 203.0.113.5 port 52114 ssh2: RSA SHA256:abc", "success", "azul", "203.0.113.5", "publickey", false},
		{"Mar 14 11:59:05 web sshd[812]: Failed password for root from 203.0.113.7 port 40022 ssh2", "fail", "root", "203.0.113.7", "password", false},
		{"Mar 14 11:59:09 web sshd[813]: Failed password for invalid user admin from 203.0.113.7 port 40023 ssh2", "fail", "admin", "203.0.113.7", "password", true},
		{"Mar 14 11:59:11 web sshd[814]: Invalid user test from 203.0.113.8 port 40024", "fail", "test", "203.0.113.8", "", true},
	}
	// each: Parse matched, event kind auth_event, Validate ok, fields as listed, service "sshd", Time == the stamp's time resolved against now
	// "Connection closed by authenticating user root 203.0.113.7 port 40022 [preauth]" -> matched, ignored (nil event)
}
func TestDovecotVsftpdProftpdParsers(t *testing.T) { /* a success and a failure line each, recorded shapes from the design: dovecot "imap-login: Login: user=<bob>, method=PLAIN, rip=203.0.113.9" and "auth failed"; vsftpd "OK LOGIN: Client \"203.0.113.9\""/"FAIL LOGIN"; proftpd "USER bob: Login successful" */ }
func TestNoPasswordEverCaptured(t *testing.T) { /* a line containing "pass=secret123" yields no field containing secret123 */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/logs/ -run 'SSHD|Dovecot|NoPassword' -v`. Expected: FAIL.
- [ ] **Step 3: Write the four YAML files** from the design's section 6 shapes; patterns are written from the recorded lines above; for dovecot, vsftpd and proftpd the lab images supply the final samples (design open item): ship the tests with the lines available and mark `# sample: design shape, replace with lab line (R-lab)` on any unverified one.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/logs/`. Expected: PASS (`TestEmbeddedParsersAllPassTheirOwnTests` included).
- [ ] **Step 5: Commit** `logs: sshd, dovecot, vsftpd, proftpd parsers`.

---

### Task 24: `logs`: cockpit, postfix, access (web admin login), raw parsers

**Files:**
- Create: `internal/logs/parsers/{cockpit,postfix,access,raw}.yml`, `internal/logs/parsers_misc_test.go`

**Interfaces:**
- Produces: `cockpit` and `postfix` yield `auth_event` (`service` `cockpit`, `postfix-sasl`); `access` yields `logs.line` fields (`source`, `method`, `uri`, `status`, `ua`, `host`, `bytes`) for Apache combined and the hardening pack's custom format, and `auth_event` for a web admin login POST (`service` the configured service name, success on status 302/303, fail on 200, URL regex part of the parser: `login_url: "(?i)/admin/index\\.php\\?route=common/login"` as a pattern); `raw` yields `logs.line` with only `file` and `line` (the tailer fills those).

- [ ] **Step 1: Write the tests:**

```go
func TestAccessParserCombinedAndCustom(t *testing.T) {
	line := `203.0.113.9 - - [14/Mar/2027:11:59:01 +0000] "GET /index.php?id=1 HTTP/1.1" 200 5123 "-" "curl/8.5.0"`
	// logs.line: source 203.0.113.9, method GET, uri "/index.php?id=1", status 200, bytes 5123, ua "curl/8.5.0"
}
func TestWebAdminLoginInferredFromPostStatus(t *testing.T) {
	post302 := `203.0.113.9 - - [14/Mar/2027:11:59:01 +0000] "POST /admin/index.php?route=common/login HTTP/1.1" 302 0 "-" "Mozilla/5.0"`
	post200 := strings.Replace(post302, " 302 ", " 200 ", 1)
	// 302 -> auth_event result success; 200 -> result fail; both also logs.line when lines: true; a GET to the same URL -> no auth_event
}
func TestRawParserEmitsLineOnly(t *testing.T) { /* "device eth0 entered promiscuous mode" -> logs.line with file/line, no other key */ }
func TestPostfixAndCockpitAuth(t *testing.T) { /* "sasl_username=bob" accepted line and "authentication failed" line; cockpit PAM line shapes from the design */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/logs/ -run 'Access|WebAdmin|Raw|PostfixAndCockpit' -v`. Expected: FAIL.
- [ ] **Step 3: Write the four YAML files.** `# shortcut: web admin result inferred from the HTTP status of the login POST, validate per application in the lab` in `access.yml`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/logs/`. Expected: PASS.
- [ ] **Step 5: Commit** `logs: cockpit, postfix, access and raw parsers`.

---

### Task 25: `logs`: the file tailer

**Files:**
- Create: `internal/logs/tail.go`, `internal/logs/tail_test.go`

**Interfaces:**
- Produces:

```go
type Tailer struct{ /* unexported */ }
type TailConfig struct {
	Path       string
	StateDir   string        // offsets.json lives here
	Poll       time.Duration // default 1 s
	MaxLine    int           // default 8192
	StartAtEnd bool          // first sight of a file with no saved offset
}
type Chunk struct {
	Line      string
	Truncated bool // longer than MaxLine; the rest was discarded
	Offset    int64
}
type Loss struct{ Reason string; File string; Count uint64 } // file_unreadable | file_missing | rotated_tail_lost | line_too_long | offsets_corrupt
func NewTailer(cfg TailConfig) (*Tailer, error)
func (t *Tailer) Poll() ([]Chunk, []Loss)   // one pass: stat, read to the last complete line, handle rotation and truncation
func (t *Tailer) Commit() error              // writes offsets.json atomically (path, inode, offset); callers call it at most once a second and after each batch
```

- [ ] **Step 1: Remove the skips and write the tests** (a temp dir; no timers, `Poll` is driven by the test):

```go
func TestTailAppendAndPartialLine(t *testing.T) { /* write "a\nb"; Poll -> [a]; append "c\n"; Poll -> [bc] */ }
func TestTailRotationByRename(t *testing.T) { /* write x, Poll; rename to x.1 and create new x with y; append to the old inode "z\n" before the next Poll; Poll yields z then y (old descriptor finished to EOF first) */ }
func TestTailCopytruncate(t *testing.T) { /* write 100 bytes, Poll, truncate to 0 and write "n\n"; Poll -> [n] and a Loss{rotated_tail_lost} only if unread bytes could have been lost (here none read since commit => reported) */ }
func TestTailMissingThenAppears(t *testing.T) { /* Poll on a missing file -> Loss file_missing once (not on every poll); create it; the next Poll reads from offset 0 of the NEW file? no: StartAtEnd false for a file that appeared after start -> reads from 0 */ }
func TestTailUnreadable(t *testing.T) { /* chmod 000 (skip with message when root) -> Loss file_unreadable */ }
func TestTailOffsetsResumeAfterRestart(t *testing.T) { /* Poll 3 lines, Commit; new Tailer same StateDir; append 1 line; Poll -> only the new line */ }
func TestTailCorruptOffsetsFile(t *testing.T) {
	// garbage in offsets.json: file moved aside to offsets.json.corrupt, Loss{offsets_corrupt}, tail restarts at the END of the file (history not replayed)
}
func TestTailLongBinaryLineCut(t *testing.T) {
	// a 10 MiB line with no newline then "\n" then "ok\n": Chunk 1 Truncated true with len <= 8192, Loss line_too_long count 1, Chunk 2 "ok"; memory bounded (the reader never holds more than MaxLine + a read buffer of 64 KiB)
}
func TestTailFirstStartAtEnd(t *testing.T) { /* existing file with history, no offsets: StartAtEnd true yields nothing; a later append yields the new line */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/logs/ -run Tail -v`. Expected: FAIL.
- [ ] **Step 3: Implement** with `os.Stat`, inode via `syscall.Stat_t` (Linux build tag; a `tail_other.go` compiles on Windows with `inode` 0 and rotation detected by size shrink only: `shortcut: Windows tail has no inode, rotation by rename is detected by a smaller size only`). Offsets written with `internal/atomicfile`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/logs/ && GOOS=windows go vet ./internal/logs/`. Expected: PASS.
- [ ] **Step 5: Commit** `logs: bounded file tailer with rotation, truncation and atomic offsets`.

---

### Task 26: `logs`: the module, manifest, health, factory, conformance

**Files:**
- Create: `internal/logs/module.go` (replaces the stub), `internal/logs/manifest.go`, `internal/logs/health.go`, `internal/logs/conformance_test.go`, `internal/logs/module_test.go`
- Modify: `internal/agent/mods/logs.go`

**Interfaces:**
- Consumes: `Tailer` (Task 25), `Parser` (Tasks 22 to 24), `plan.LogsSettings`.
- Produces: `func New(cfg Config) (*Module, error)` with `Config{Files []plan.LogFile; StateDir string; Parsers fs.FS (nil: embedded); Now func() time.Time; Logger *slog.Logger}`; `Name() "logs"`; `Start(ctx, emit)`; `Health()`; `Manifest()` (design section 3: `OS ["linux"]`, `Privilege "root"`, `Emits` three kinds, `Budget{30, 8, 300, 600, 4<<20, 1}`, `Default true`, `Content ["logs/parsers"]` corrected to the embedded path per decision 6).

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestModuleEmitsAuthEventsAndLines(t *testing.T) {
	// temp dir with auth.log (sshd) and access.log (access, lines true); module with both; append a failed login and a GET
	// want auth_event{result fail, service sshd, account root, source, Time == the line's own stamp} and logs.line for the access line; every event Validate ok; Priority high / bulk
}
func TestRateLimitReportsGap(t *testing.T) { /* RatePerSec 5: 500 access lines in one poll -> telemetry_gap{source logs, reason rate_limited, count > 0, file} and kept+count == 500 */ }
func TestUnparsedCountedInHealth(t *testing.T) { /* auth file with lines but no parse for 10 simulated minutes -> Health degraded; Info["unparsed"] counted */ }
func TestHealthMissingFileGap(t *testing.T) { /* missing /var/log/auth.log -> Gap "no auth log: sshd logs only to journald on this host (install rsyslog from the depot or add a journal reader)" for the sshd parser file; "<file> missing" otherwise */ }
func TestOffsetsAdvanceWhenLinkIsDown(t *testing.T) { /* emit always fails: offsets still advance; no crash (conformance check 7 in miniature) */ }
func TestLogsConformance(t *testing.T) { conformance.Agent(t, conformance.AgentCase{Factory: factoryNamed(t, "logs"), Default: logsCfg(t), Reconfig: logsCfg2(t), Load: nil}) }
func TestLogsFixturesDecodeStrictly(t *testing.T) { /* T75: every parser's inline test lines through Module: events Validate ok */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/logs/ ./internal/agent/mods/ -run 'Module|RateLimit|Unparsed|HealthMissing|Offsets|Conformance|FixturesDecode' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** One goroutine, one `Tailer` per file, poll every second; `Commit()` after each batch at most once a second. Rate limit by token bucket per module; drops become one gap per file per flush. Remove nothing from `PreContract` (logs was never listed); `ModulePackages` already has the entry.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/logs/ ./internal/agent/mods/ ./internal/module/...`. Expected: PASS.
- [ ] **Step 5: Commit** `logs: module on the contract`.

---

### Task 27: `logs`: rules wiring (`logs.line`, `auth_event`) and unparked rule D17e

**Files:**
- Modify: `rules/logs.yml` (`log_line` to `logs.line`), `rules/pending/needs_producer.yml` (D17e, and the other `log_line` rules whose producer now exists), `docs/rules.md`
- Test: `internal/logs/rules_integration_test.go`

**Interfaces:**
- Consumes: `detect.LoadDir`, `detect.Engine` (as `internal/detect/engine_test.go` builds it).

- [ ] **Step 1: Remove the skip and write the tests:**

```go
func TestRulesRunOverRealParserOutput(t *testing.T) {
	// parse the access and kern.log lines through the real Parser; load rules/ with detect.LoadDir; feed the produced events to a detect engine:
	// "GET /?id=1 union select" -> D2e fires; "device eth0 entered promiscuous mode" -> D19 fires; "usb 1-1: New USB device found" -> D23 fires
	// sshd failures x12 from one source -> D9e.ssh-bruteforce fires (auth_event result fail); the scorer-shaped burst (3 fails within 200 ms then a success, 30 s apart) does not
}
func TestD17eUnparked(t *testing.T) { /* web admin POST x N from one source via the access parser -> D17e fires; rule no longer carries needs: */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/logs/ -run 'RulesRun|D17e' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the renames (recipe) and move D17e out of `rules/pending/` into `rules/logs.yml` with its tests (its `needs:` line removed). Keep D14d and D14b pending (device syslog; no producer).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/logs/ ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit** `logs: rules read logs.line and auth_event; D17e unparked`.

---

### Task 28: `inventory`: differential engine, epochs, state files

**Files:**
- Create: `internal/inventory/diff.go`, `internal/inventory/state.go`, `internal/inventory/diff_test.go`

**Interfaces:**
- Consumes: `TableDef` (Task 1), `fold.Row`.
- Produces:

```go
type Change struct{ Key string; Row, Old fold.Row; Cols []string }
type DiffResult struct{ Added, Removed []fold.Row; Changed []Change }
func Diff(def TableDef, old, cur []fold.Row) DiffResult   // by key columns; a changed row compares a hash of the non-key columns; Cols are the changed columns
func KeyOf(def TableDef, r fold.Row) string                // key columns joined with "\x00" rendered with "|" for display
type State struct {
	Epoch  int        `json:"epoch"`
	Schema int        `json:"schema"`
	Rows   []fold.Row `json:"rows"`
}
type Store struct{ Dir string }                            // Dir = StateDir/inventory
func (s Store) Load(def TableDef) (State, bool)            // bool false when the file is missing, corrupt or the schema differs (a corrupt file is moved to <table>.json.corrupt)
func (s Store) Save(def TableDef, st State) error          // atomicfile
```

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestDiffAddedRemovedChangedNoop(t *testing.T) {
	def := TableDef{Name: "accounts", Columns: []string{"name", "uid", "shell"}, Key: []string{"name"}}
	old := []fold.Row{{"name": "root", "uid": 0, "shell": "/bin/bash"}, {"name": "bob", "uid": 1000, "shell": "/bin/bash"}}
	cur := []fold.Row{{"name": "root", "uid": 0, "shell": "/bin/sh"}, {"name": "eve", "uid": 1001, "shell": "/bin/bash"}}
	d := Diff(def, old, cur)
	// Added [eve], Removed [bob], Changed [{Key root, Cols [shell], Old.shell /bin/bash}]; Diff(def, cur, cur) is empty
}
func TestDiffKeyCollisionLastRowWins(t *testing.T) { /* two rows with one key in cur: one row kept, deterministic (the later), no panic */ }
func TestStoreSaveLoadRoundTrip(t *testing.T) { /* Save then Load -> equal rows and epoch */ }
func TestLostStateIsNewEpochNotMassAdd(t *testing.T) {
	// 5000-row old state file deleted; Load reports (State{}, false); the caller path (Plan func in the same file) returns Epoch+1 with a snapshot and ZERO row events
	// a corrupt file: moved aside, same outcome
}
func TestSchemaBumpIsNewEpoch(t *testing.T) { /* saved state Schema 1, def SchemaVer 2 -> not loaded -> new epoch, snapshot reason epoch_change */ }
```

Add the planner the module uses so the epoch rule has one home:

```go
type Plan struct {
	Epoch    int
	Snapshot bool       // send an inventory.snapshot
	Reason   string     // baseline | epoch_change | periodic | requested
	Diff     DiffResult // empty when Snapshot is true for a new epoch
}
func Next(def TableDef, loaded State, ok bool, cur []fold.Row, forceSnapshot bool) Plan
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/inventory/ -run 'Diff|Store|LostState|SchemaBump' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Next`: not loaded and no prior state: epoch 1, reason `baseline`, no diff. Not loaded but a state file had existed (corrupt, lost, schema change): previous epoch unknown to the module, so epoch = 1 + the epoch kept in memory by `Keep` (Task 34) or 1 + a second tiny file `<table>.epoch`; use the epoch file (written alongside, `shortcut: epoch counter in its own file so a corrupt snapshot cannot reset it`). Loaded: same epoch, diff only; `forceSnapshot` adds a snapshot with reason `requested`/`periodic`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/inventory/`. Expected: PASS.
- [ ] **Step 5: Commit** `inventory: differential engine, epochs and state files`.

---

### Task 29: `inventory`: Linux collectors A (accounts, groups, sudoers, authorized_keys)

**Files:**
- Create: `internal/inventory/collect.go` (the `Collector` type and `Env`), `internal/inventory/collect_linux_ident.go`, `internal/inventory/collect_linux_ident_test.go`, `internal/inventory/testdata/linux/etc/{passwd,shadow,group,sudoers,sudoers.d/webadmin}`, `testdata/linux/home/bob/.ssh/authorized_keys`, `testdata/linux/root/.ssh/authorized_keys`

**Interfaces:**
- Produces:

```go
type CollectEnv struct {
	Root string        // filesystem root ("" or "/" = real); fixtures use a temp tree
	Now  func() time.Time
	MaxRows int
}
type Collector func(ctx context.Context, env CollectEnv) ([]fold.Row, error)
func Collectors(goos string) map[string]Collector  // table name -> collector for the OS
```

Columns exactly as in the design's table: `accounts` (`name`, `uid`, `gid`, `shell`, `home`, `locked`, `empty_password`, `hash_algo`, `last_change`, `expires`, `in_sudo`), `groups` (`name`, `gid`, `members`), `sudoers` (`file`, `line`, `who`, `hosts`, `runas`, `nopasswd`, `command`; key `file` + `line`), `authorized_keys` (`user`, `file`, `type`, `fingerprint`, `comment`, `options`; key `user` + `fingerprint`).

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestAccountsNeverReadHashes(t *testing.T) {
	rows := run(t, "accounts") // fixture shadow has root:$6$salt$HASHVALUE..., bob:!:..., svc:: (empty), eve:*:
	for _, r := range rows { for _, v := range r { if strings.Contains(fmt.Sprint(v), "HASHVALUE") { t.Fatal("hash leaked into a row") } } }
	root := byName(rows, "root")
	if root["hash_algo"] != "sha512" || root["locked"] != false || root["empty_password"] != false { t.Fatalf("%v", root) }
	if byName(rows, "svc")["empty_password"] != true || byName(rows, "bob")["locked"] != true { t.Fatal("flags") }
}
func TestAccountsUID0AndInSudo(t *testing.T) { /* passwd has toor uid 0 -> row uid 0; in_sudo true for a user in group sudo/wheel or named in sudoers */ }
func TestGroupsMembersSorted(t *testing.T) { /* members "bob,alice" -> "alice,bob" */ }
func TestSudoersParsesIncludeDirAndNopasswd(t *testing.T) { /* "webadmin ALL=(ALL) NOPASSWD: /usr/bin/systemctl" in sudoers.d -> nopasswd true, command; @includedir honoured; comments and Defaults skipped */ }
func TestAuthorizedKeysFingerprintNotBlob(t *testing.T) {
	// ssh-ed25519 key line with options and a comment -> fingerprint "SHA256:<43 base64 chars>" computed from the blob; no row value contains the base64 blob
}
func TestMaxRowsTruncates(t *testing.T) { /* MaxRows 3 on a 10-account passwd -> 3 rows and ErrTruncated (a sentinel error the module turns into a table_truncated gap) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/inventory/ -run 'Accounts|Groups|Sudoers|AuthorizedKeys|MaxRows' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** (parsed in Go, nothing shelled, `Root`-prefixed reads, `last_change`/`expires` from shadow days since epoch as RFC 3339 dates). `ErrTruncated` is declared in `collect.go`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/inventory/`. Expected: PASS.
- [ ] **Step 5: Commit** `inventory: Linux identity tables (accounts, groups, sudoers, authorized_keys)`.

---

### Task 30: `inventory`: Linux collectors B (units, tasks, mounts, drivers)

**Files:**
- Create: `internal/inventory/collect_linux_sys.go`, `collect_linux_sys_test.go`, `testdata/linux/{etc/systemd/system/ecom.service,etc/systemd/system/ecom.service.d/override.conf,etc/crontab,etc/cron.d/backup,var/spool/cron/crontabs/bob,proc/modules,proc/self/mountinfo}`

**Interfaces:**
- Produces collectors for `units` (`name`, `fragment_path`, `enabled`, `active`, `exec_start`, `user`, `environment`, `ambient_caps`, `drop_ins`; key `name`), `tasks` (Linux: `kind`, `owner`, `schedule`, `command`; key `kind`+`owner`+`id` where `id` is the 1-based line index in its file; the column list adds `id`), `mounts` (`source`, `target`, `fstype`, `options`; key `target`+`source`), `drivers` (Linux, from `/proc/modules`: `name`, `size`, `used_by`, `taint`; key `name`).

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestUnitsParseEnvironmentAndDropIns(t *testing.T) {
	// ecom.service has Environment=LD_PRELOAD=/tmp/.x.so, ExecStart=/opt/ecom/bin/ecom, AmbientCapabilities=CAP_NET_BIND_SERVICE, User=www-data; a drop-in override.conf adds Environment=FOO=1
	// row: environment contains LD_PRELOAD=/tmp/.x.so and FOO=1; ambient_caps "CAP_NET_BIND_SERVICE"; drop_ins lists override.conf; enabled from the wants symlink in the fixture tree
}
func TestTasksCronAndSpools(t *testing.T) { /* /etc/crontab, /etc/cron.d/backup and a user spool: kind "cron", owner from the user column or spool name, schedule and command split correctly; comments and env lines skipped */ }
func TestMountsMountOverContentRoot(t *testing.T) { /* mountinfo with a tmpfs mounted on /var/www/html -> a row target /var/www/html fstype tmpfs options contains rw; escapes like \040 in paths decoded */ }
func TestDriversFromProcModules(t *testing.T) { /* "nf_tables 217088 1 - Live 0x0 (OE)" -> name nf_tables, size 217088, used_by "-", taint "OE" */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/inventory/ -run 'Units|Tasks|Mounts|Drivers' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** (INI-style unit parser by hand: sections, repeated keys, `Environment=` with quoted pairs; `shortcut: units are parsed from the unit files on disk, not from systemd's loaded state`). `active` is read from `/run/systemd/units` presence of the unit's invocation file when available, else empty.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/inventory/`. Expected: PASS.
- [ ] **Step 5: Commit** `inventory: Linux system tables (units, tasks, mounts, drivers)`.

---

### Task 31: `inventory`: Linux collectors C (bpf_programs, interfaces, domain_join)

**Files:**
- Create: `internal/inventory/collect_linux_net.go`, `collect_linux_net_test.go`, `collect_linux_bpf.go` (BPF syscall via `golang.org/x/sys/unix`, build tag linux), `testdata/linux/etc/{sssd/sssd.conf,krb5.conf,samba/smb.conf,resolv.conf}`

**Interfaces:**
- Produces collectors `bpf_programs` (`id`, `type`, `name`, `tag`; key `id`), `interfaces` (columns `name`, `flags`, `promisc`, `kind`, `mac`, `mtu`, `addresses`, `routes`, `neighbours`), `domain_join` (`source`, `realm_or_domain`, `servers`, `method`; key `source`). Pure parsers: `func parseNetlinkLinks(b []byte) ([]fold.Row, error)` fed recorded netlink bytes (`testdata/linux/netlink_links.bin`), `func domainJoinRows(root string) []fold.Row`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestDomainJoinReadsOnlyNamedKeys(t *testing.T) {
	rows := domainJoinRows(fixtureRoot) // sssd.conf has ad_domain=corp.example, ad_server=dc1.corp.example, ldap_default_authtok=SECRET
	if got := byName(rows, "sssd"); got["realm_or_domain"] != "corp.example" || got["servers"] != "dc1.corp.example" { t.Fatalf("%v", got) }
	for _, r := range rows { for _, v := range r { if strings.Contains(fmt.Sprint(v), "SECRET") { t.Fatal("secret key value read") } } }
	// krb5.conf default_realm + [realms] kdc; smb.conf security=ads realm; resolv.conf search domain: one row per source
}
func TestInterfacesPromiscFlag(t *testing.T) { /* recorded netlink dump: eth0 IFF_PROMISC set -> promisc true; lo -> false */ }
func TestBPFNoPermissionIsGapNotFailure(t *testing.T) { /* collector returns ErrNoPermission (sentinel) when the syscall returns EPERM; skip the real-syscall path with a message when not root */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/inventory/ -run 'DomainJoin|InterfacesPromisc|BPF' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Netlink via `syscall.NetlinkRIB` (stdlib) for links, addresses, routes and neighbours; `domain_join` reads only the keys the design names.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/inventory/ && GOOS=windows go vet ./internal/inventory/`. Expected: PASS.
- [ ] **Step 5: Commit** `inventory: Linux network, BPF and domain-join tables`.

---

### Task 32: `inventory`: `software` (dpkg, rpm, product versions)

**Files:**
- Create: `internal/inventory/software.go`, `software_test.go`, `internal/inventory/software/{splunk,opencart,roundcube}.yml`, `testdata/linux/var/lib/dpkg/status`, `testdata/linux/rpmdb.sqlite` (built by `testdata/mkrpm.go` under `//go:build ignore`; committed binary < 64 KiB), `testdata/linux/opt/splunk/etc/splunk.version`, `testdata/linux/var/www/html/index.php`

**Interfaces:**
- Produces: collector `software` (`name`, `version`, `arch`, `source`; key `name`+`source`; `source` is `dpkg`, `rpm` or `product`); `type ProductDef struct{ Product string; Glob string; Re string; Tests []Test }`; `func LoadProducts(fsys fs.FS) ([]ProductDef, error)`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestDpkgStatus(t *testing.T) { /* installed packages only ("Status: install ok installed"); a "deinstall ok config-files" entry skipped; version and arch read */ }
func TestRpmSQLite(t *testing.T) { /* modernc sqlite opens the fixture rpmdb.sqlite read-only; row name "openssl", version "3.0.7-27.el9" (version-release) */ }
func TestBerkeleyDBIsGapNotFailure(t *testing.T) { /* a file starting with the BDB magic -> ErrUnsupportedFormat, which the module turns into Gap "rpm database format not readable (Berkeley DB)" */ }
func TestProductVersionFiles(t *testing.T) {
	// splunk.yml: glob "opt/splunk/etc/splunk.version", re "VERSION=([0-9.]+)" -> product splunk 9.2.1; opencart from index.php "define('VERSION', '4.0.2.3')"; inline tests of every ProductDef pass
}
func TestSoftwareRereadOnlyWhenDBMtimeChanges(t *testing.T) { /* two Collect calls with an unchanged dpkg status mtime: the second does not re-parse (counter on the reader) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/inventory/ -run 'Dpkg|Rpm|Berkeley|ProductVersion|Reread' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The rpm database is opened with `file:...?mode=ro&immutable=1`, query `SELECT ...` over the `Packages` blob is not possible without the rpm header parser: read the `Name`/`Version`/`Release`/`Arch` from the header blob with the small parser in the same file (`shortcut: only the four tags are decoded, rpm header format v4`). Docker image listing is Task 33's follow-up and not in this task.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/inventory/`. Expected: PASS.
- [ ] **Step 5: Commit** `inventory: software table (dpkg, rpm sqlite, product version files)`.

---

### Task 33: `inventory`: Windows collectors

**Files:**
- Create: `internal/inventory/collect_windows.go` (build tag windows: SCM, registry, `NetUserEnum`, `GetAdaptersAddresses`), `collect_windows_parse.go` (pure, all OS: scheduled task XML, uninstall-key row mapping, hotfix and build mapping), `collect_windows_parse_test.go`, `testdata/windows/tasks/{Microsoft/Windows/Backup/Task1,Updater}` (XML), `testdata/windows/uninstall.json`

**Interfaces:**
- Produces Windows definitions in `Defs()` (already written by Task 1): `accounts` (`name`, `sid`, `enabled`, `locked`, `password_never_expires`, `last_logon`, `privileges`), `groups`, `tasks` (`name`, `path`, `author`, `principal`, `run_level`, `command`, `arguments`, `xml_sha256`, `enabled`), `services` (`name`, `display_name`, `image_path`, `start_type`, `account`, `state`), `drivers` (`name`, `image_path`, `state`), `interfaces` (`name`, `addresses`, `gateway`, `dns`), `software` (OS build, UBR, hotfixes, installed programs, SQL Server build); `func parseTaskXML(b []byte) (fold.Row, error)`; `func softwareRowsFromUninstall(entries []UninstallEntry) []fold.Row`.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestParseTaskXML(t *testing.T) {
	r, err := parseTaskXML(readFixture("windows/tasks/Updater"))
	// name "Updater", author, principal "SYSTEM", run_level "HighestAvailable", command, arguments, enabled true, xml_sha256 = sha256 of the file bytes
}
func TestTaskXMLHostileInput(t *testing.T) { /* 8 MiB XML with deep nesting -> error, no panic; DOCTYPE/entity expansion rejected */ }
func TestSoftwareRowsFromUninstall(t *testing.T) { /* entries with DisplayName/DisplayVersion -> rows source "product"; entries without a DisplayName skipped; duplicates by name+version collapse */ }
func TestWindowsCollectorsRegistered(t *testing.T) { /* Collectors("windows") has every Windows table in Defs("windows"); compile-checked on Linux via the pure parts; the API parts run in the lab (skip message) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/inventory/ -run 'TaskXML|SoftwareRowsFromUninstall|WindowsCollectors' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `collect_windows.go` uses `golang.org/x/sys/windows` and `windows/svc/mgr`, `windows/registry`; `NetUserEnum`/`NetLocalGroupEnum` through `netapi32` lazy procs. Password hashes are never read. `shortcut: Windows tasks come from the XML files under System32\Tasks only, not cross-checked against TaskCache`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/inventory/ && GOOS=windows go vet ./internal/inventory/`. Expected: PASS and a clean vet.
- [ ] **Step 5: Commit** `inventory: Windows collectors`.

---

### Task 34: `inventory`: the agent module

**Files:**
- Create: `internal/inventory/module.go` (replaces the stub), `manifest.go`, `health.go`, `module_test.go`, `conformance_test.go`
- Modify: `internal/agent/mods/inventory.go`

**Interfaces:**
- Consumes: Tasks 28 to 33, `plan.InventorySettings`.
- Produces: `func New(cfg Config) (*Module, error)`, `Config{Tables []string; Interval, SoftwareInterval time.Duration; ResnapshotEvery time.Duration; MaxRows int; StateDir string; Root string; GOOS string; Now func() time.Time; Collectors map[string]Collector; Logger *slog.Logger; Keep func(string, any); Kept func(string) any}`; `Manifest()` (design section 3: `Sides [agent, controller]`, `OS nil`, `Consumes ["inventory.row","inventory.snapshot"]`, `Tables ["inventory_rows","inventory_epochs"]`, `Default false`, `Budget{60, 48, 50, 400, 6<<20, 8}`, `Actions ["collect.inventory","probe.run"]`, `Pages ["/inventory"]`); `func (m *Module) CollectNow(ctx context.Context, tables []string, snapshot bool) (map[string]int, error)` (rows per table); `Health()`.

Rules: one goroutine, one table at a time, jittered start (`Now`-seeded hash of host name so tests are deterministic), `software` every 15 min, `domain_join` at start and hourly, others every `Interval` (60 s); baseline snapshots chunked at 500 rows (`part`/`parts`), bulk priority; row events normal, High for `Persist` tables; at most 200 row events per table per collection then one `op: overflow` with the count; `ResnapshotEvery` (6 h) full snapshot reason `periodic`; a truncated table or failed collector becomes a `telemetry_gap{source:"inventory", reason, table, count}` and a Health gap.

- [ ] **Step 1: Remove the skips and write the tests** (fixture `Root`, injected `Now`, collector returning scripted rows):

```go
func TestBaselineSendsSnapshotAndNoRowEvents(t *testing.T) { /* first collection of accounts (3 rows): one inventory.snapshot reason baseline epoch 1, count 3; zero inventory.row; Validate ok */ }
func TestChangeBecomesRowEvent(t *testing.T) { /* add an account row: one inventory.row op added, key, row, epoch 1, Priority high (accounts is a persistence table); a software change is normal */ }
func TestRowOverflowCap(t *testing.T) { /* 500 added rows in one collection -> exactly 200 row events + one op overflow count 300 */ }
func TestSnapshotChunking(t *testing.T) { /* 1200-row table -> 3 snapshot events, part 1..3 of 3, 500/500/200 rows */ }
func TestRestartKeepsEpoch(t *testing.T) { /* run, stop, new Module same StateDir: no new baseline; a change made while down arrives as a row event at the first collection */ }
func TestDeletedStateStartsNewEpoch(t *testing.T) { /* delete accounts.json: new Module emits snapshot reason epoch_change epoch 2 and zero row events; Health Gap "inventory state lost on this host, new epoch" */ }
func TestMaxRowsTruncationGap(t *testing.T) { /* MaxRows 100 on a 150-row table -> telemetry_gap reason table_truncated count 50 and Health degraded */ }
func TestCollectNowHonoursSnapshotFlag(t *testing.T) { /* CollectNow(["groups"], true) -> snapshot reason requested */ }
func TestBudgetUnder20000RowFixture(t *testing.T) { /* 20000-row table: Health.Usage.HeldBytes <= Manifest().Budget.HeldMB<<20; one collector at a time */ }
func TestInventoryAgentConformance(t *testing.T) { conformance.Agent(t, conformance.AgentCase{Factory: factoryNamed(t, "inventory"), Default: invCfg(), Reconfig: invCfg2(), KeepKey: "inventory.epochs"}) }
func TestInventoryFixturesDecodeStrictly(t *testing.T) { /* T75: all events of the tests above Validate ok */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/inventory/ ./internal/agent/mods/ -run 'Baseline|ChangeBecomes|RowOverflow|Chunking|RestartKeeps|DeletedState|MaxRowsTruncation|CollectNow|Budget|Conformance|FixturesDecode' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Reconfiguration keeps the per-table epochs through `Keep("inventory.epochs", map[string]int)`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/inventory/ ./internal/agent/... ./internal/module/...`. Expected: PASS.
- [ ] **Step 5: Commit** `inventory: agent module (collection loop, epochs, events, health)`.

---

### Task 35: `inventory`: probes, `probe.run` and `collect.inventory`

**Files:**
- Create: `internal/inventory/probe.go`, `probe_test.go`, `internal/inventory/probes/{accounts_uid0,authorized_keys_for,units_enabled,mounts_without_noexec,software_version,interfaces_promisc}.yml`, `internal/inventory/actions.go`, `actions_test.go`
- Modify: `internal/inventory/module.go` (`Active()`; `RunProbe`)

**Interfaces:**
- Consumes: `actions.Action`, `actions.Register`, `TableDef`, `Module.CollectNow`.
- Produces:

```go
type Pred struct{ Col, Op string; Value any } // Op: eq ne in re prefix gt lt
type ParamDef struct{ Name, Type string; Min, Max int; Pattern string }
type ProbeDef struct {
	Module string `yaml:"module"`; Name, Doc, Table string
	Where  []Pred; Select []string; Limit int; Live bool
	Params []ParamDef
	Tests  []ProbeTest
}
func LoadProbes(fsys fs.FS, defs []TableDef) ([]ProbeDef, error) // rejects: unknown table, unknown column in where/select, > 16 predicates, limit > 1000, undeclared ${param}, a probe with no tests, module != "inventory"
func RunProbe(p ProbeDef, rows []fold.Row, params map[string]string) (cols []string, out [][]any, truncated bool, err error)
func (m *Module) RunProbe(ctx context.Context, name string, params map[string]string) (event.Event, error) // returns the inventory.probe_result event
// actions: "collect.inventory" {tables string, snapshot bool}; "probe.run" {name string, params string(json, max 4 KiB)}; both Spec.ReadOnly true, Risk none
```

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestProbeOperatorsAndLimits(t *testing.T) { /* each of eq ne in re prefix gt lt on a small accounts table; Limit 2 on 5 matches -> 2 rows truncated true */ }
func TestLoadProbesRejects(t *testing.T) { /* table-driven fstest.MapFS: unknown column, unknown table, 17 predicates, limit 1001, ${x} without a ParamDef, no tests, a "join" key => each errors */ }
func TestParamValidationBeforeRun(t *testing.T) { /* authorized_keys_for{user} with user "../../etc" fails the declared pattern ^[a-z_][a-z0-9_-]{0,31}$; no collector runs */ }
func TestProbeCannotReadArbitraryFile(t *testing.T) { /* a ProbeDef with table "accounts" and select ["name"] only reads the snapshot; there is no path column type (compile-time: ParamDef.Type "path" is rejected by LoadProbes) */ }
func TestEmbeddedProbesPassTheirTests(t *testing.T) { /* every probes/*.yml: LoadProbes against Defs(runtime.GOOS and the other OS); each ProbeTest over fixture rows */ }
func TestNoProbeNamesAColumnTheTableLacks(t *testing.T) { /* iterate Defs for both OSes */ }
func TestOversizeProbeResultIsStoredAsFile(t *testing.T) { /* result > 256 KiB: event carries truncated true and the full result goes through the action's Output as a file path under StateDir (chunk fetch is the core's) */ }
func TestActionsReadOnlyAndRegistered(t *testing.T) { /* actions.Core() has collect.inventory and probe.run; Spec().ReadOnly and Risk none; with no Active module Apply returns an error wrapping actions.ErrUnsupported */ }
func TestProbeRunProducesResultEvent(t *testing.T) { /* module with the accounts fixture; RunProbe("accounts_uid0") -> inventory.probe_result Validate ok; rows [[toor ...]] ; live false; Live probe re-collects first */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/inventory/ -run 'Probe|Actions|Param' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `${param}` substitutes a typed value into a predicate only (never into a column name). Model the actions on `fileHash` in `internal/actions/files.go`. `shortcut: probe parameters of type path are not supported, add a per-probe allowed root when a probe needs one`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/inventory/ ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit** `inventory: typed probes, probe.run and collect.inventory`.

---

### Task 36: `inventory`: controller side (fold writer, tables, determinism)

**Files:**
- Create: `internal/inventory/controller.go` (replaces the stub), `internal/inventory/controller_test.go`, `internal/inventory/controller_conformance_test.go`
- Modify: `internal/module/all/all.go` (nothing new: the package already imports)

**Interfaces:**
- Consumes: `module.ControllerModule`, `module.Host` (`Subscribe`, `Tables`, `Query`, `Config`), `store.ModuleDB`, `fold.Fold`, `module.Analyzer`.
- Produces: a controller module `inventory` registered with `module.Register` in `init`; tables created by `ModuleDB.Migrate`:

```sql
CREATE TABLE inventory_rows(host TEXT NOT NULL, tbl TEXT NOT NULL, key TEXT NOT NULL, row TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, PRIMARY KEY(host,tbl,key));
CREATE TABLE inventory_epochs(host TEXT NOT NULL, tbl TEXT NOT NULL, epoch INTEGER NOT NULL, baseline_time INTEGER NOT NULL, PRIMARY KEY(host,tbl));
```

and `func Current(ctx context.Context, q store.Reader, host, table string) ([]fold.Row, int, error)` (the latest snapshot plus the row events after it, via `fold.Fold`; what other modules' analysers use) plus `func (c *Controller) Analyzers() []module.Analyzer` with one analyser `inventory_untagged_changes` (rows changed in the last hour by table, deterministic) feeding the Overview tile.

Writer: one goroutine reads `Host.Subscribe([]string{"inventory.snapshot","inventory.row"}, 1024)`; snapshot parts accumulate in memory (bounded: 64 parts per host and table) and replace the table's rows when `part == parts`; row events upsert or delete; an epoch higher than the stored one with no snapshot yet is recorded as a `state_lost` gap event by the controller (`Host.Emit` of `telemetry_gap{source:"inventory", reason:"state_lost", table}`).

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestSnapshotThenRowsEqualsTable(t *testing.T) {
	// publish snapshot parts 1/2, 2/2 (epoch 1) then row events added/removed/changed; query inventory_rows: equals fold.Fold of the same input; inventory_epochs row epoch 1
}
func TestNewEpochSnapshotReplacesRows(t *testing.T) { /* snapshot epoch 2 reason epoch_change replaces the table; no alert-class event emitted */ }
func TestMissingEpochIsStateLostGap(t *testing.T) { /* row events at epoch 3 for a host whose stored epoch is 1 and no snapshot arrived: a telemetry_gap reason state_lost under agent "controller" */ }
func TestIncompleteSnapshotBounded(t *testing.T) { /* parts 1/50 only, then 65 different tables' partial snapshots: memory bounded, oldest partial dropped */ }
func TestCurrentMatchesTable(t *testing.T) { /* Current() over the store equals the module's table rows */ }
func TestAnalyserDeterministic(t *testing.T) { /* run twice over the seeded store: identical JSON */ }
func TestInventoryControllerConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: inventoryController(), Config: "enabled: true\n", Seed: seedInventoryEvents(), Now: time.Unix(1e9, 0)})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/inventory/ -run 'SnapshotThenRows|NewEpoch|MissingEpoch|IncompleteSnapshot|Current|Analyser|ControllerConformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Manifest()` is the same value as the agent factory's.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/inventory/ ./internal/module/...`. Expected: PASS.
- [ ] **Step 5: Commit** `inventory: controller fold into two tables, Current(), untagged-change analyser`.

---

### Task 37: `inventory`: UI page, tile, host-grid column

**Files:**
- Create: `internal/inventory/ui.go`, `internal/inventory/ui_test.go`, `internal/inventory/ui/{inventory.html}` (embedded template), `plans/inventory/probe.yaml`
- Modify: `internal/inventory/controller.go` (`Start` registers through `h.UI()`)

**Interfaces:**
- Consumes: `ui.Registrar` (`Page`, `Tile`, `GridColumn`, `Action`), `ui.Cell`, `module.Host.RunReadOnly`.
- Produces: page `/inventory` (per host the tables with last-change times and the row-event timeline; an "Ask" form: probe, parameters, one or more hosts), `POST /m/inventory/action/ask` (creates one `Host.RunReadOnly("probe", {probe, params, host})` per selected host; results group identical outputs "14 same, 2 differ", outliers first), tile `untagged changes in the last hour` by table, grid column `inventory baselined` (`verified` when every enabled table has an epoch and a snapshot, `pending`, `failed` on a collection gap). `plans/inventory/probe.yaml` is a one-node plan template running `probe.run` with `${probe}` and `${params}` against `${host}`. `shortcut: the Ask form targets named hosts, label-expression targets arrive with plan-template label expansion (W5)`.

- [ ] **Step 1: Remove the skips and write the tests** (the registrar and test server the way `internal/ui/registrar_test.go` builds them):

```go
func TestInventoryPageRenders(t *testing.T) { /* GET /m/inventory/ with seeded tables: 200; contains the host name, a table name and the probe names; hostile cell values (<script>) are escaped */ }
func TestAskCreatesReadOnlyRunPerHost(t *testing.T) { /* POST ask with hosts h1,h2 and probe accounts_uid0: Host.RunReadOnly called twice with template "probe" and params including host; an unknown probe name or a parameter failing its pattern -> 400 and no run */ }
func TestGroupedResultsCollapseIdentical(t *testing.T) { /* 14 identical results + 2 outliers -> "14 same, 2 differ", outliers first */ }
func TestGridColumnStates(t *testing.T) { /* verified / pending / failed from the inventory_epochs rows and gap events */ }
func TestProbePlanTemplateLints(t *testing.T) { /* plans/inventory/probe.yaml loads, expands with params, lint.Run with ClassAutoReadOnly returns no finding (read-only, no scored touch) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/inventory/ -run 'InventoryPage|Ask|GroupedResults|GridColumn|ProbePlan' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** with `html/template` (auto-escape).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/inventory/ ./internal/ui/`. Expected: PASS.
- [ ] **Step 5: Commit** `inventory: page, tile, grid column and the Ask form`.

---

### Task 38: Unpark the inventory rules; reference blocks; controller rendering; no-old-name guard

**Files:**
- Modify: `rules/pending/needs_producer.yml` (move `D11c`, `D2b`, `D19b`, `D21`, `D6d2` out), `rules/network.yml` or a new `rules/inventory.yml` (the five rules, retargeted to `event: inventory.row`, conditions on `table`, `op` and `row.*`, their old event names `bpf_prog_new`, `mount_new`, `net_iface`, `net_addr_change`, `unit_parsed` gone), `internal/controller/genconfig.go` (render `Logs` and `Inventory` blocks), create `manifest/2027/modules/{audit,winevt,net,logs,inventory}.yml`, `internal/event/legacy_test.go`, `internal/inventory/rules_test.go`, `internal/controller/genconfig_telemetry_test.go`

**Interfaces:**
- Consumes: `(*manifest.Manifest).ModuleEnabled`, `ModuleBlock.Decode` (W1 Task 11), `plan.LogsSettings`, `plan.InventorySettings`.
- Produces: the controller renders `modules.logs` (files per host from the OS family and the service kinds: `debian`: `/var/log/auth.log`, `rhel`: `/var/log/secure`, `ssh` kind adds the sshd parser, `http` kind the access log with `lines: true`, `mail` kind dovecot and postfix, `ftp` kind vsftpd, `/var/log/kern.log` raw `lines: true`) and `modules.inventory` (enabled on every host in the reference manifest); reference blocks with the design's defaults.

- [ ] **Step 1: Remove the skips and write the tests:**

```go
func TestParkedInventoryRulesFire(t *testing.T) {
	// D11c: inventory.row table bpf_programs op added -> fires; D2b: mounts added with target under a content root -> fires; D19b: interfaces changed promisc false->true; D21: interfaces addresses changed (manifest_match computed by detect, seeded false);
	// D6d2: units row with environment containing LD_PRELOAD; each has a negative test; a baseline snapshot event alone fires nothing
}
func TestGenconfigRendersLogsAndInventory(t *testing.T) {
	// reference manifest host rocky-ecom (rhel, http+ssh): logs.files contains /var/log/secure sshd, the apache access log with lines true; debian host: /var/log/auth.log; Windows host: no logs block; inventory enabled everywhere
	// the block decodes strictly into plan.LogsSettings / InventorySettings; Enabled true
}
func TestReferenceModuleBlocksDecodeStrictly(t *testing.T) { /* each manifest/2027/modules/<module>.yml decodes with DisallowUnknownFields into its settings struct; module.Schema(&struct) validates the YAML */ }
// internal/event/legacy_test.go
func TestNoRetiredKindNamesInTree(t *testing.T) {
	// walks the repo (../..) *.go, *.yml, *.yaml, *.md; skips phylax_design.md, docs/impl/, docs/phylax_design.v2-*.md, testdata, this file
	// patterns (regexp, case sensitive): `\bproc\.exec\b`, `\bprocess_end\b`, `\bauth_success\b`, `\bauth_fail\b`, `\bnet_connect\b`, `\bnet\.connection_(opened|closed)\b`, `\bnet\.listener_(added|removed)\b`, `\blog_line\b`, `(^|[^.\w])sec_event\b`, `(^|[^.\w])sensor_state\b`, `"fim"`
	// any hit fails with file:line
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/inventory/ ./internal/controller/ ./internal/event/ -run 'ParkedInventory|GenconfigRenders|ReferenceModuleBlocks|NoRetiredKindNames' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Remove any stale mention the guard finds (comments in `docs/*.md`, `rules/*.yml` headers, `docs/capture.md`). The `fim` pattern only matches the quoted kind string.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit** `telemetry: inventory rules unparked, reference blocks, retired-name guard`.

---

### Task 39: Cross-module producer fixtures through the real rules (T75 CI half)

**Files:**
- Create: `internal/e2e/telemetry_test.go` (package `e2e`, as the other tests there)

**Interfaces:**
- Consumes: the five modules' fixture helpers via exported test-only constructors in each package's `export_test.go`-free way: each module package exposes `func FixtureEvents(t testing.TB) []event.Event` in a `fixtures.go` (non-test file with `//go:build fixtures`? no: ponytail, put the helper in `internal/<module>/fixtures_test.go` and have this test re-run each module's recorded input itself through the module's exported mapping function: `audit.Assemble`+`handle`, `winevt.Mapper.Map`, `netmod.Tracker.Poll`, `logs.Parser.Parse`, `inventory.Next`).

- [ ] **Step 1: Write the test:**

```go
func TestProducerFixturesFireRules(t *testing.T) {
	rules := loadRealCorpus(t) // detect.LoadDir("../../rules")
	cases := []struct{ name string; events func(t *testing.T) []event.Event; wantRule string }{
		{"audit exec under a scored service", auditExecShellUnderApache, "D1.service-spawns-shell"},
		{"audit pwnkit shape", auditPkexecNoArgs, "D3e.pwnkit-exec"},
		{"winevt service install", winevtService7045, "W3.suspicious-service-install"}, // the rule id in rules/mw-redteam.yml for 7045 SysWOW64
		{"logs ssh brute force", logsSSHFailures12, "D9e.ssh-bruteforce"},
		{"winevt 4625 burst", winevtFailedLogons, "D9e.ssh-bruteforce"},
		{"net telnet listener", netTelnetListener, "D3.unexpected-listener"},
		{"net outbound to unknown", netOutboundConn, "D12.unexpected-outbound"},
		{"inventory bpf program added", invBPFAdded, "D11c.bpf-program-new"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evs := c.events(t)
			for _, e := range evs { if err := event.Validate(e); err != nil { t.Fatal(err) } }
			got := runEngine(t, rules, evs) // bus-form events through a real detect engine with the seeds the rule needs
			if !contains(got, c.wantRule) { t.Fatalf("rules fired %v, want %s", got, c.wantRule) }
		})
	}
}
```

The rule ids in `wantRule` are read from the corpus when the test is written (`grep '^id:' rules/*.yml`); the implementer replaces any id above that does not exist with the id of the rule the case is about, and a case with no matching rule is deleted with a comment saying which rule is missing.

- [ ] **Step 2: Run, expect FAIL** if any producer still emits a retired name. Run: `go test ./internal/e2e/ -run TestProducerFixturesFireRules -v`. Expected: PASS when Tasks 3 to 38 are merged; a failure names the producer and rule.
- [ ] **Step 3: Fix what it finds** in the producer or the rule, not in this test.
- [ ] **Step 4: Run all gates.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit** `e2e: producer fixtures fire the real rules`.

---

### Task 40: Lab (stronger agent or David)

Run on the BTaP Proxmox replica (`stacks/ccdc`, the "ccdc27" lab). Record in `docs/impl/lab/w3-telemetry.md`: date, commit, VMIDs, test id, pass or fail, measured values, what was not run. Open an issue per failure. Does not block the merge.

- [ ] **T43 exec storm** on a Rocky 9 and an Ubuntu 22.04 host: 50, 200 and 1000 execs per second for 60 s each; audit keeps 99% or more at 200 per second and every miss has a `telemetry_gap` (compare `process_start` count with a controlled loop's exec count). If it fails, record it against open question A2.Q2.
- [ ] **T12 `LD_PRELOAD` rootkit**: a unit with `LD_PRELOAD` appears as `inventory.row` (`units`), and `process_start.env` carries it; D11 and D6d2 fire; latency reported.
- [ ] **T11 log clear and Sysmon stop** (campaign 03) on a Windows host: `wevtutil cl Security` produces `winevt.sec_event{category: log_cleared}` at critical, a stopped Sysmon produces `winevt.sensor_state` with `fallback: "4688"`, the heartbeat stays intact, and the bookmark resets with a `bookmark_stale` gap. Reinstall is W4 and not run.
- [ ] **Windows `net`**: listeners and connections from the extended tables on the DC, the 5157 re-emit with a real blocked outbound connection (`New-NetFirewallRule -Action Block`), measured latency; the real `ExtendedTables` and `NetUserEnum` calls.
- [ ] **T21** first contact then the agent killed and disabled (Linux and Windows): the per-module telemetry stops and the controller marks the host silent; report first-heartbeat and silence latencies.
- [ ] **T29 module-state half**: `kill -9` the agent at random during winevt bookmark writes, `logs` offsets writes and `inventory` snapshot writes (200 iterations each); every restart succeeds, no inventory mass-add, no log line duplicated more than the in-flight batch, no skipped complete line.
- [ ] **T69**: inventory snapshots on a fleet of 6 hosts; `probe.run` returns typed output; a changed account arrives as one `inventory.row`; measure CPU and bytes per host.
- [ ] **T71**: per module, the ratio of self-reported CPU and held bytes to the cgroup (Linux) or Job Object (Windows) figure; report, no threshold. Replace the `shortcut: budget numbers are estimates` comments with measured values where the run supports it.
- [ ] **T75 on lab data**: capture a day of each producer's events from the replica and run `event.Validate` over them; report any field outside the structs.
- [ ] **Logs lines**: record the real Cockpit, ProFTPD, Postfix SASL, Dovecot and Roundcube/OpenCart login lines from the lab images and replace the design-shape samples in `internal/logs/parsers/*.yml` (commit separately).

---

## Self-review

**Spec coverage.** Module sections: `audit` Purpose to Limits (manifest, config, events, reader/rules/verify/heartbeat hash/loss/sweep/containers, actions, health, tests) are Tasks 4 to 10 (reader, rules, verify loop and sweep exist and are kept by the move in Task 1; the new parts are canonical events, manifest, health with the rules hash, module-load and AF_ALG, filesystem gap, actions, conformance, storm test). `winevt`: canonical kinds (11), `auth_event` (12), manifest and health (13), backscan (14), conformance (15); the Sysmon install, tier-0 reinstall, `eventlog.size` and analytic channel enable are named hand-offs (decision 8), not built. `net`: canonical kinds (3), no `deps` (17), typed kinds, canary flag, own-link, NFLOG gap (18), manifest, health, baseline Keep, conformance (19), Windows tables and 5157 (16, 20, 21); `net.shadow_drop`, `net.ingress_denied` and the Windows shadow evaluator are W6 (declared in Task 1). `logs`: parsers (22 to 24), tailer (25), module (26), rules (27). `inventory`: engine (28), Linux collectors (29 to 32), Windows (33), module (34), probes and actions (35), controller side (36), UI (37), parked rules (38). Shared libraries: `internal/sockets` (1, 16), `internal/inventory/fold` (1, 2). Rename map: producers (3, 4, 5, 11, 12, plus `log_line` new in 22 to 27), rules and consumers in the same tasks, guard in 38. Known bugs: 15 net (1, 17), 16 (6), 17 audit (5, 6). Tests: T11, T12, T21, T29, T43, T69, T71, T75 in 10, 15, 19, 26, 34, 39, 40.

**Placeholder scan.** No "TBD". Tasks 26, 34, 36, 37 name test helpers (`factoryNamed`, `invCfg`, `limitsEnabled`, `auditFixtureEvents`, `fixtureRoot`, `wfpEvent`, `byName`, `readFixture`, `seedInventoryEvents`) that the seams task writes as real helpers in the skipped test files; each is a few lines over an existing pattern (`factoryNamed` is W1 Task 38's).

**Type consistency.** `Collector`, `CollectEnv`, `TableDef`, `Plan`/`Next`, `State`/`Store`, `ProbeDef`, `Tailer` and `Parser` are each defined once and used with the same names later. The `inventory` struct field `SchemaVer` avoids a clash with `Event.Schema`.

**Review Focus coverage.** (1) Task 2 and Task 4; (2) Task 39; (3) Task 25 and Task 40; (4) Tasks 28 and 34; (5) Tasks 18 and 19.

**Proportion.** About 1,740 lines against about 1,000 lines of module sections plus the kind table and rename map (Task 1 alone is 250 lines of exact signatures); test bodies are shown where the spec fixes a value and described where the existing test file already has the scenario.
