# W1: Module Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the design's module contract into code: typed events, `internal/module`, the agent and controller module registries, the controller `Host`, approval classes and the controller executor, `control: fact`, the lint registry, the UI registrar, the conformance suite and the CI gates, with `health` and `suricata` as the first two modules on the contract.

**Architecture:** `internal/module` is a leaf package of data types and interfaces (it imports only `internal/event`, `internal/store`, `internal/vault`, `internal/ui`, `internal/manifest` and the standard library), so `internal/plan`, `internal/link`, `internal/agent` and `internal/controller` can all import it. (`internal/manifest` joins that list: it imports no repo package, and `Host.Manifest()` returns its type.) The agent side extends the built factory registry and supervisor; the controller side gets a module runner, a `Host` implementation, a controller-origin event chain and the plan-starting paths (`auto_readonly`, `standing`, `auto`, proposals). The conformance suite is a test-support package every module's own `conformance_test.go` calls; static checks (imports, kind table, presence) run once over the registry.

**Tech Stack:** Go 1.27.2 (mise), standard library, existing deps only (`modernc.org/sqlite`, `gopkg.in/yaml.v3`, `golang.org/x/sys`). No new modules in `go.mod`.

**Spec:** `phylax_design.md` (v4): "The module contract" (all subsections), "Event kinds", "Core components: Agent runtime (heartbeat)", "Wire protocol and spool (control types, fact subtypes)", "Execution engine (action contract, controller executor and approval classes, scoring-safety lint: lint registration)", "Manifest (files)", "Event store and vault (query API)", "UI shell (module registration, Platform)", "Testing and lab (T45, T46, T65 bug 11 and 17, T73, T74, T75, CI)". Master plan: `docs/impl/README.md`.

## Deviations from the design (applied by Task 1 to `phylax_design.md` in the same commit)

1. **`Host` plan methods take a template, not a `plan.Plan`.** `plan.ModuleLimits` embeds `module.Common`, so `internal/plan` imports `internal/module`; `internal/module` therefore cannot import `internal/plan`. `RunReadOnly(template, params)`, `RunStanding(approvalID, template, params)` and `RunAuto(template, params)` take a plan template under `plans/<module>/` plus string parameters, matching "content before code" and the standing approval's `Template` scope. `Proposal` carries a template too.
2. **`store.Reader`** is the read-only query interface the design calls `store.Query`; the name `store.Query` is the existing event filter struct (9 call sites). `Query` gains `Fields map[string]string`.
3. **`Host.Tables()`** is added: a module that declares `Tables` needs a write path for its one writer goroutine; the design's `Host` has none.
4. **`Analyzer.Run` takes a `context.Context`** so the analysis worker can stop a run over its deadline ("a run over budget is stopped").
5. **`module.Common` gains `Auto []string` (`auto:`)**, the module's `auto` template allowlist; the design names the allowlist but not its home.
6. **`event.Type` gains `Alert bool`**, the per-kind alert flag of the kind table; `event.Type.Fields` is not serialised.
7. **`Event.Schema` is `json:"schema,omitempty"`**, so an event sealed before this change (schema 0, no tag) keeps its hash. Declared kinds always carry a schema of 1 or more.
8. **`process_start` parent fields** are one object `parent: {exe, comm, cmdline, service}`; the flat `pexe`, `pcomm`, `pcmdline` names are dropped (rules read `parent.exe`). **`dns_query`** and **`telemetry_gap`** get canonical structs (the design lists none): `dns_query {query, query_results, pid, exe, user, source}` (today's winevt Sysmon 22 names), `telemetry_gap {source, reason, count, from, to, detail}` (today's emitters).
9. **`hosts.yml` `modules:`** is a map `{<module>: true|false}`; **`labels:`** is a list of strings. The design names both but not their shape.
10. **Controller modules register with `module.Register`** from their package `init`, and `internal/module/all` blank-imports every module package so the binary and the CI checks see one list.
11. **`Env.Subscribe(buf int, kinds ...string)`** keeps the buffer argument the built code has.
12. **`RunAuto`'s triggering event** is passed as the reserved parameter `trigger` (`<agent>:<seq>`), recorded in the plan's `Approver` and never substituted into the template.
13. **Core kind count is 29, not 28** at Task 5: the design's table had 29 core rows (listed in Task 5) while its summary sentence said 28. The 2026-11-06 review (R1, R8, R9) adds four core kinds (Task 5a), so the table now has 33 core kinds and 189 in all; CI generates the three counts from the table (Task 41).
14. **`act_enabled` in the module block is the fleet default; the per-host form is in `overrides.yml`.** `Overrides.Act` (`act: {<module>: [<label expression>]}`) and `Overrides.SafeModeHosts` with `Manifest.ActEnabled(host, module)` (Task 11b); `RunAuto` reads the effective value. W4 renders it into the signed agent configs; `detect` no longer gates on its own flag and `respond.act_enabled` is the single master for tier 0 (R2, decided 2026-11-06).
15. **The seam extras W3, W5, W6, W7 and W11 each assumed are W1's.** One name for exporting action registration: `actions.Register` (the design's name; W3's `RegisterExtra` and W6/W11's `RegisterFamily` are retired), with `actions.RegisterUndo`, `actions.Unsupported`, `Env.Now()` and `Env.Ext` (Task 2a). `Event.WithExtra` (`x_` prefix) and the extension fields of the common structs (Tasks 3a, 4a). `storetest.New` (Task 8a). `Host.Manifest()` and `Host.UpdateOverrides` (Task 17a). `LoadModuleTemplateFor`, `plans.Parse`/`ResolveLabels` and the root `plans` package in `CoreImports` (Task 22b).
16. **`Env.Now` is a method, so the old field `Env.Now` becomes `Env.Clock`.** A Go type cannot have a field and a method of one name; W6 and W11 call `env.Now()`. The three places that set the field (`actions/helpers_test.go`, `e2e_test.go`, the agent) change in Task 2a.
17. **`internal/module` may also import `internal/manifest`** (it imports no repo package), because `Host.Manifest()` returns the loaded manifest and `Host.UpdateOverrides` takes `*manifest.Overrides`. `manifest` must never import `module`.
18. **The two plan options no workstream owned are W1's:** `expires_after` (Task 22a, the dead-man machinery with the confirm turned off) and `gate: auto` (Task 27a, `until:` conditions: time, probe, absence of an event). Templates spell them `expires_after: 30m` and `gate: auto` with `until:`; `ParseTemplate` translates (`translateNodeKeys`). W7 builds `window: scorer_quiet`, `gate: manual` and `txn:` and adds its keys to the same translator; W5 hardening and W10 backup depend on W7 Tasks 2 to 7 for `window:`.
19. **Modules reach `overrides.yml` and per-device vault keys through `Host`.** `Host.UpdateOverrides` over `manifest.AppendOverrides` (Task 11a, with `Overrides.LearnedListeners`), and `Host.Secrets` accepts prefix grants (`cred/*`, Task 9a) so `devices` and `creds` need no fixed names in their block.

20. **YAML keys equal JSON tags; durations are `module.Duration`.** A small wrapper over `time.Duration` that unmarshals `"90s"` or `"2m"` in YAML and JSON is the one exception to the one-to-one mapping (R11, Task 33).
21. **Tables are projections of the module's own events, command events included.** Operator actions are typed command events the module emits through `Host.Emit`; conformance check 11 replays them (R10, Task 36).
22. **The agent answers `busy`, not `failed`, over the step cap; a plan that touches a scored service defaults to `rollback_plan`; the probe runs inside the node and `deadman_confirm` waits for the after-probe** (R12, Tasks 27, 27b, 27c).
23. **Tags cover only our own activity** (R6, Tasks 32 and 32a). **Controller disk quotas** (R9, Task 8b).

## Global Constraints

- Go 1.27.2 via mise; `CGO_ENABLED=0`; `make build build-windows vet test race` passes at every commit (linux/amd64 and windows/amd64 both build and vet).
- Every package ships tests; tests exercise the real code (no mocking of the code under test, no tautological asserts). A test that needs privileges or containers calls `t.Skip` with a reason string.
- Commits are small, one logical change, message `area: summary` (e.g. `event: typed kind registry`). No attribution lines.
- No shelling out in the default path (tests may run `go list`).
- Bounded everything: queues, buffers, decoded sizes, timeouts. Atomic writes through `internal/atomicfile` for state files.
- No compatibility shims, aliases or dual formats; renamed things are renamed everywhere in the same commit.
- `internal/module` imports only `internal/event`, `internal/store`, `internal/vault`, `internal/ui`, `internal/manifest` and the standard library.
- A module imports only the core packages (`internal/event`, `internal/module`, `internal/agent`, `internal/link`, `internal/plan`, `internal/actions`, `internal/store`, `internal/manifest`, `internal/manifest/render`, `internal/deadman`, `internal/ui`, `internal/vault`, and the root `plans` package) and the shared libraries (`internal/atomicfile`, `internal/parsers/...`, `internal/checks/probe`, `internal/sockets`, `internal/signing`, `internal/integrity/format`, `internal/inventory/fold`). `internal/enroll` is never importable by a module.
- Times stored in UTC. Secrets never appear in events, logs or config files.
- The design is authoritative; a forced design change edits `phylax_design.md` in the same commit with the reason.
- Code style ponytail: the smallest complete change; a known limit carries `// shortcut: <limit>, <when to upgrade>`.

## Review Focus

1. **Events sealed before the envelope change.** A spool or store written by the old code holds events without `schema` and `tag`. Expected: they still verify after the upgrade (Task 2 `TestPreSchemaEventStillVerifies`).
2. **In-process consumers of converted emitters.** `event.New` stores numbers as `json.Number`, as the store already does on read; a bus consumer that type-asserts `uint64` or `float64` on a converted kind's field would silently stop matching. Expected: `New`'s fields equal a store round trip (Task 3 `TestNewMatchesStoreRoundTrip`), and Task 6 fixes every such assertion it finds.
3. **Controller restart mid-chain.** The controller-origin chain must continue from the stored head, never restart at seq 1 (which the store refuses as a replay). Task 16 `TestEmitControllerAfterRestart`.
4. **`RunAuto` with an unknown state.** No heartbeat yet for a target, the agent offline, no probe callback, or safe mode unknown: expected a click proposal, never an apply. Task 26 `TestRunAutoUnknownSafeModeProposes`.
5. **Fact TTL against agent clock skew.** The controller's `ts` and the agent's clock disagree; expected: a fact's TTL counts from the agent's receipt time. Task 31 `TestFactTTLFromReceipt`.

---

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `internal/event/event.go` | envelope (`Schema`, `Tag`) | 2 |
| `internal/actions/{registry,win_env,env}.go` | `Register`, `RegisterUndo`, `Unsupported`, `Env.Now`/`Clock`, `Env.Ext` | 2a |
| `internal/event/types.go` | `Type`, `Declare`, `Lookup`, `Declared`, `New`, `Decode`, `Validate`, `WithExtra` | 1, 3, 3a |
| `internal/event/kinds.go` | common kinds and canonical structs, extension fields | 1, 4, 4a |
| `internal/event/core.go` | core kinds and payload structs | 1, 5 |
| `internal/module/module.go` | `Side`, `Budget`, `Manifest`, `Common`, `State`, `Gap`, `Usage`, `Health`, `Effective` | 1, 7 |
| `internal/module/host.go` | `Host`, `ControlMsg`, `Proposal`, `EventRef`, `ControllerModule`, `Analyzer`, `AnalyzerProvider`, `Configurable`, errors | 1 |
| `internal/module/registry.go` | `Register`, `Registered`, `Lookup` | 1, 7 |
| `internal/module/schema.go` | JSON Schema of a config block | 1, 33 |
| `internal/module/all/all.go` | blank imports of every module package | 1, 38, 39 |
| `internal/module/conformance/` | the suite (`agent.go`, `controller.go`, `leak.go`, `static_test.go`, `allowed.go`) | 1, 34-37 |
| `internal/store/reader.go` | `Reader`, `ModuleDB`, `(*Store).ModuleDB` | 1, 8 |
| `internal/store/storetest/storetest.go` | `New`, seeded store for module tests | 1, 8a |
| `internal/store/standing.go`, `proposals.go` | core tables for standing approvals and proposals | 24, 25 |
| `internal/vault/reader.go` | `Reader`, `Source`, `Scoped`, `Covers`, `ErrNotAllowed` | 1, 9, 9a |
| `internal/ui/registrar.go` | `Registrar`, `Cell`, `Discard`, `(*Server).Registrar`, views | 1, 10 |
| `internal/manifest/modules.go`, `labels.go` | module blocks, host `modules:`/`labels:`, label expressions | 1, 11 |
| `internal/manifest/overrides_write.go` | `AppendOverrides`, `LearnedListener` | 1, 11a |
| `internal/plan/agentconfig.go` | `ModuleLimits` embeds `module.Common`; strict parse; `BlockFor` | 12 |
| `internal/plan/approval.go` | `ApprovalClass`, `StandingApproval` | 1, 22 |
| `internal/plan/template.go` | `ExpandTemplate` | 1, 22 |
| `internal/plan/plan.go`, `step.go` | `ExpiresAfterSec`, `GateUntil` | 22a, 27a |
| `plans/plans.go` | `Template.Module`, `Parse`, `ResolveLabels` | 1, 22b |
| `internal/plan/fact.go` | `ControlFact`, `FactSender`, limits | 1, 30 |
| `internal/plan/lint/lint.go`, `ss000.go`, `ss010.go`, `ss011.go` | lint registry, `SS000` (read-only), `SS010` (auto plans), `SS011` (rollback_plan for scored touches) | 1, 21, 27b |
| `internal/agent/registry.go`, `module.go` | `Factory.Manifest`, `HealthReporter`, `Supervisor.Health`, `Subscribe` kinds | 13 |
| `internal/agent/harness.go` | `Harness` for the conformance suite | 1, 15 |
| `internal/agent/facts.go`, `window.go` | facts and the `work_window` effect | 31, 32 |
| `internal/link/message.go` | heartbeat `Health` | 14 |
| `internal/controller/chain.go` | controller-origin event chain | 16 |
| `internal/controller/host.go`, `modules.go`, `analysis.go` | `Host` implementation (`Manifest`, `UpdateOverrides`, prefix secrets), module runner, analysis worker | 1, 17, 17a, 18-20 |
| `internal/controller/plantemplates.go` | `LoadModuleTemplateFor`, `translateNodeKeys` (`expires_after`, `gate:`) | 22, 22a, 22b, 27a |
| `internal/controller/approvals.go`, `auto.go`, `proposals.go`, `exec.go`, `facts.go` | approval classes, auto conditions, breaker, proposals, executor, facts | 23-30 |
| `internal/suricata/` | `suricata` moved from `internal/integrations/suricata` | 39 |
| `cmd/phylax/modules.go` | `phylax modules` | 40 |
| `.github/workflows/ci.yml`, `Makefile` | CI gates | 41 |
| `docs/impl/lab/w1-module-contract.md` | lab record | 42 |

---

### Task 1: Seams (Sonnet or Opus)

Done by a stronger model. Writes every exported type, interface and function signature below with stub bodies, the new fields on existing structs, the skipped test files for later tasks with their helpers, and the design-text deviations. Later tasks implement against exactly these names.

**Files:**
- Create: `internal/event/types.go`, `internal/event/kinds.go`, `internal/event/core.go`
- Create: `internal/module/module.go`, `internal/module/host.go`, `internal/module/registry.go`, `internal/module/schema.go`, `internal/module/all/all.go`
- Create: `internal/module/conformance/doc.go`, `agent.go`, `controller.go`, `allowed.go`
- Create: `internal/store/reader.go`, `internal/vault/reader.go`, `internal/ui/registrar.go`
- Create: `internal/manifest/modules.go`, `internal/manifest/labels.go`
- Create: `internal/plan/approval.go`, `internal/plan/template.go`, `internal/plan/fact.go`, `internal/plan/lint/lint.go`
- Create: `internal/agent/harness.go`
- Create: `internal/controller/host.go`, `internal/controller/modules.go`
- Create: `internal/store/storetest/storetest.go`, `internal/manifest/overrides_write.go` (stubs; Tasks 8a and 11a)
- Create: every test file named in Tasks 2 to 42 (lettered tasks included: 3a, 4a, 8a, 9a, 11a, 17a, 22a, 22b, 27a) except Task 12's, each test body as given in that task's Step 1, with `t.Skip("unimplemented: W1 Task N")` as its first line (Task 2's `internal/event/envelope_test.go` and Task 2a's `internal/actions/register_test.go` unskipped: those two are real from the start), and the test helpers listed in Step 2
- Modify (zero-value-safe field additions only): `internal/manifest/types.go` (`Overrides.LearnedListeners`, `LearnedListener`), `plans/plans.go` (`Template.Module`), `internal/event/event.go`, `internal/store/query.go`, `internal/manifest/types.go`, `internal/agent/registry.go`, `internal/link/message.go`, `internal/plan/plan.go`, `internal/plan/step.go`, `internal/actions/env.go`, `internal/controller/controller.go`
- Modify: `phylax_design.md` (the sketches in "The module contract" and "Lint registration" to the signatures below; the 19 deviations above; "28 core kinds" to 29)

**Interfaces:**
- Consumes: the built `internal/event.Event`, `internal/store.Store`/`Query`, `internal/vault.Vault`/`Secret`, `internal/ui.Server`, `internal/manifest.Manifest`/`Host`, `internal/plan.Plan`/`Node`/`AgentConfig`, `internal/agent.Factory`/`Env`/`ModuleSpec`/`Supervisor`, `internal/actions.Registry`/`Spec`/`Env`.
- Produces (exact; every later task and every other workstream plan uses these):

```go
// ---- internal/event/types.go ----
package event

type Type struct {
	Kind     string   `json:"kind"`
	Schema   int      `json:"schema"`
	Priority Priority `json:"prio"`
	Alert    bool     `json:"alert,omitempty"`
	Fields   any      `json:"-"` // zero value of the payload struct
}

var (
	ErrUndeclared   = errors.New("event: kind not declared")
	ErrKindMismatch = errors.New("event: kind or payload type mismatch")
	ErrSchema       = errors.New("event: schema version not understood")
)

func Declare(t Type)                                // from init; panics on duplicate kind, Schema < 1, nil Fields or empty Kind
func Lookup(kind string) (Type, bool)
func Declared() []Type                              // sorted by Kind
func New[T any](kind string, v T) (Event, error)    // Kind, Schema, Priority, Fields set; Fields hold json.Number for numbers
func Decode[T any](e Event, kind string) (T, error) // strict; keys with prefix "x_" are ignored
func Validate(e Event) error                        // strict decode of e against its declared kind

// ---- internal/event/kinds.go ---- (types are data: written in full by Task 1; Declare calls added by Task 4)
const (
	KindProcessStart = "process_start"
	KindProcessExit  = "process_exit"
	KindFileChange   = "file_change"
	KindConn         = "conn"
	KindListener     = "listener"
	KindAuthEvent    = "auth_event"
	KindDNSQuery     = "dns_query"
	KindTelemetryGap = "telemetry_gap"
)

type ProcessParent struct {
	Exe     string `json:"exe,omitempty"`
	Comm    string `json:"comm,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
	Service string `json:"service,omitempty"`
}
type ProcessStart struct {
	PID     int            `json:"pid"`
	PPID    int            `json:"ppid,omitempty"`
	Exe     string         `json:"exe"`
	Comm    string         `json:"comm,omitempty"`
	Cmdline string         `json:"cmdline,omitempty"`
	CWD     string         `json:"cwd,omitempty"`
	User    string         `json:"user,omitempty"`
	UID     *int           `json:"uid,omitempty"`
	SHA256  string         `json:"sha256,omitempty"`
	Parent  *ProcessParent `json:"parent,omitempty"`
	Source  string         `json:"source"` // audit | winevt
}
type ProcessExit struct {
	ProcessStart
	ExitCode int `json:"exit_code"`
}
type FileChange struct {
	Op             string `json:"op"` // create | delete | modify | attr | rename
	Path           string `json:"path"`
	OldPath        string `json:"old_path,omitempty"`
	Exe            string `json:"exe,omitempty"`
	PID            int    `json:"pid,omitempty"`
	User           string `json:"user,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	OldSHA256      string `json:"old_sha256,omitempty"`
	ContentChanged *bool  `json:"content_changed,omitempty"`
	IsDir          bool   `json:"is_dir,omitempty"`
	Source         string `json:"source"` // audit | sweep | winevt
}
type Conn struct {
	Op          string `json:"op"`  // opened | closed
	Dir         string `json:"dir"` // inbound | outbound
	Proto       string `json:"proto"`
	LAddr       string `json:"laddr,omitempty"`
	LPort       uint16 `json:"lport,omitempty"`
	RAddr       string `json:"raddr,omitempty"`
	RPort       uint16 `json:"rport,omitempty"`
	PID         int    `json:"pid,omitempty"`
	Exe         string `json:"exe,omitempty"`
	Comm        string `json:"comm,omitempty"`
	User        string `json:"user,omitempty"`
	State       string `json:"state,omitempty"`
	Service     string `json:"service,omitempty"`
	CommunityID string `json:"community_id,omitempty"`
	DurationMS  int64  `json:"duration_ms,omitempty"`
	BytesOut    uint64 `json:"bytes_out,omitempty"`
	BytesIn     uint64 `json:"bytes_in,omitempty"`
	Source      string `json:"source"` // net | audit | winevt | capture
	Baseline    bool   `json:"baseline,omitempty"`
}
type Listener struct {
	Op       string `json:"op"` // added | removed
	Proto    string `json:"proto"`
	LAddr    string `json:"laddr,omitempty"`
	LPort    uint16 `json:"lport"`
	PID      int    `json:"pid,omitempty"`
	Exe      string `json:"exe,omitempty"`
	Comm     string `json:"comm,omitempty"`
	User     string `json:"user,omitempty"`
	Service  string `json:"service,omitempty"`
	Baseline bool   `json:"baseline,omitempty"`
	Source   string `json:"source"`
}
type AuthEvent struct {
	Result      string `json:"result"` // success | fail
	Account     string `json:"account"`
	Domain      string `json:"domain,omitempty"`
	Source      string `json:"source,omitempty"` // client address
	SourcePort  uint16 `json:"source_port,omitempty"`
	Service     string `json:"service"`
	Method      string `json:"method,omitempty"`
	LogonType   int    `json:"logon_type,omitempty"`
	InvalidUser bool   `json:"invalid_user,omitempty"`
	Host        string `json:"host,omitempty"`
}
type DNSQuery struct {
	Query        string `json:"query"`
	QueryResults string `json:"query_results,omitempty"`
	PID          int    `json:"pid,omitempty"`
	Exe          string `json:"exe,omitempty"`
	User         string `json:"user,omitempty"`
	Source       string `json:"source"`
}
type TelemetryGap struct {
	Source string `json:"source"`
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
	From   string `json:"from,omitempty"` // RFC 3339, UTC
	To     string `json:"to,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// ---- internal/event/core.go ---- (types written by Task 1; Declare calls by Task 5)
type ControllerFact struct {
	ID   string         `json:"id"`
	Fact string         `json:"fact"` // subtype
	TS   time.Time      `json:"ts"`   // controller clock, display only
	TTL  time.Duration  `json:"ttl"`  // counted from the agent's receipt
	Data map[string]any `json:"data,omitempty"`
}
// plus one struct per core kind as listed in Task 5 (AgentStart ... PlanAutoHalted)

// ---- internal/module/module.go ----
package module

type Side string

const (
	SideAgent      Side = "agent"
	SideController Side = "controller"
)

type Budget struct {
	CPUMillisPerSec int     `json:"cpu_ms_per_sec"`
	HeldMB          int     `json:"held_mb"`
	EventsPerSec    float64 `json:"events_per_sec"`
	Burst           int     `json:"burst"`
	BytesOutPerMin  int     `json:"bytes_out_per_min"`
	DiskMB          int     `json:"disk_mb"`
}

type Manifest struct {
	Name      string       `json:"name"`
	Sides     []Side       `json:"sides"`
	OS        []string     `json:"os,omitempty"`
	Privilege string       `json:"privilege"` // root | user | none
	Roles     []string     `json:"roles,omitempty"`
	Consumes  []string     `json:"consumes,omitempty"`
	Emits     []event.Type `json:"emits,omitempty"`
	Budget    Budget       `json:"budget"`
	Default   bool         `json:"default"`
	Tables    []string     `json:"tables,omitempty"`
	Content   []string     `json:"content,omitempty"`
	Actions   []string     `json:"actions,omitempty"`
	Pages     []string     `json:"pages,omitempty"`
	Evidence  []string     `json:"evidence,omitempty"`
}

func (m Manifest) Validate() error

type Common struct {
	Enabled    bool     `json:"enabled" yaml:"enabled"`
	ActEnabled bool     `json:"act_enabled" yaml:"act_enabled"`
	Auto       []string `json:"auto,omitempty" yaml:"auto,omitempty"` // templates under plans/<module>/ that RunAuto may start
}

type State string

const (
	StateOK          State = "ok"
	StateDegraded    State = "degraded"
	StateUnavailable State = "unavailable"
	StateDisabled    State = "disabled"
	StateOverBudget  State = "over_budget"
	StateRestarting  State = "restarting"
	StateError       State = "error"
)

type Gap struct {
	What string `json:"what"`
	Why  string `json:"why"`
}
type Usage struct {
	CPUMillis uint64 `json:"cpu_ms"`
	HeldBytes uint64 `json:"held_bytes"`
	Events    uint64 `json:"events"`
	BytesOut  uint64 `json:"bytes_out"`
	Dropped   uint64 `json:"dropped"`
}
type Health struct {
	State  State             `json:"state"`
	Detail string            `json:"detail,omitempty"`
	Gaps   []Gap             `json:"gaps,omitempty"`
	Usage  Usage             `json:"usage"`
	Info   map[string]string `json:"info,omitempty"`
}

// Effective is the enablement rule: the host's modules: entry, else the block's enabled, else the default.
func Effective(host, block *bool, def bool) bool

// ---- internal/module/host.go ----
var (
	ErrNoConfig   = errors.New("module: no config block")
	ErrNotInScope = errors.New("module: not in the module's manifest")
	ErrProposed   = errors.New("module: plan not started; a click proposal was created")
)

type Host interface {
	Config(v any) error                                                    // strict decode of modules/<name>.yml; ErrNoConfig when absent
	Query() store.Reader                                                   // read-only event queries
	Tables() (store.ModuleDB, error)                                       // the module's own tables; error unless Manifest.Tables is non-empty
	Manifest() *manifest.Manifest                                          // the loaded manifest (hosts, labels, services, overrides); read-only by convention
	UpdateOverrides(fn func(*manifest.Overrides) error) error              // atomic read-modify-write of overrides.yml; the manifest reloads
	Emit(e event.Event) error                                              // stored under agent "controller"; kind must be in Manifest.Emits
	Subscribe(kinds []string, buf int) (<-chan event.Event, func())        // committed events; kinds must be in Manifest.Consumes
	Propose(p Proposal) error                                              // a one-click suggestion; never applies
	RunReadOnly(template string, params map[string]string) (planID string, err error)
	RunStanding(approvalID, template string, params map[string]string) (planID string, err error) // ErrProposed when out of scope
	RunAuto(template string, params map[string]string) (planID string, err error)                 // ErrProposed when an auto condition fails
	Control(m ControlMsg) error                                            // a signed control: fact to agents
	Secrets(names ...string) (vault.Reader, error)                         // names must be covered by a string in the module's config block; "cred/*" grants a prefix
	UI() ui.Registrar
	Logger() *slog.Logger
}

type ControlMsg struct {
	Type  string         // "fact"
	Hosts []string       // agent names, or label expressions (manifest.ParseLabels)
	Fact  string         // subtype: work_window | round_clock | gpo_finding | scorer_probe_result | creds_txn
	ID    string         // a later fact with the same ID replaces the earlier one
	Data  map[string]any // typed by the subtype; at most plan.MaxFactData bytes encoded
	TTL   time.Duration  // > 0 and <= plan.MaxFactTTL
}

type EventRef struct {
	Agent string `json:"agent"`
	Seq   uint64 `json:"seq"`
}

type Proposal struct {
	Module   string            // set by the Host
	Title    string            // one line, shown on the button
	Template string            // plan template under plans/<module>/
	Params   map[string]string
	Evidence []EventRef
	Reason   string            // why a click is needed (the failed auto condition, or "tier 1")
}

type ControllerModule interface {
	Manifest() Manifest
	Start(ctx context.Context, h Host) error // runs until ctx ends; ErrNoConfig means unavailable
	Health() Health
}

type Analyzer struct {
	Name   string
	Inputs []string      // kinds it reads; also the trigger set
	Every  time.Duration // 0: on trigger only
	Run    func(ctx context.Context, q store.Reader, now time.Time) ([]event.Event, error)
}

type AnalyzerProvider interface{ Analyzers() []Analyzer } // optional on a ControllerModule
type Configurable interface{ ConfigBlock() any }          // optional: zero value of the config struct (schema, conformance)

// ---- internal/module/registry.go ----
func Register(m ControllerModule) // from init; panics on duplicate name or invalid manifest
func Registered() []ControllerModule
func Lookup(name string) (ControllerModule, bool)

// ---- internal/module/schema.go ----
func Schema(v any) ([]byte, error) // JSON Schema (2020-12) of a config struct, additionalProperties false

// ---- internal/store/reader.go ----
package store

type Reader interface {
	Events(ctx context.Context, q Query) ([]event.Event, error)
	Event(ctx context.Context, agent string, seq uint64) (event.Event, error)
	Latest(ctx context.Context, agent, kind string) (event.Event, error)
}
type ModuleDB interface {
	Migrate(ctx context.Context, migrations []string) error // ordered; applied once; may only create or alter tables named <module>_*
	Exec(ctx context.Context, query string, args ...any) (sql.Result, error) // writes only to <module>_* tables
	Query(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}
func (s *Store) ModuleDB(module string) ModuleDB
// Query gains: Fields map[string]string // top-level field equality, compared as text

// ---- internal/vault/reader.go ----
package vault

type Reader interface{ Get(name string) (Secret, error) }
type Source interface{ Get(name string) (Secret, string, error) } // *Vault satisfies it
var ErrNotAllowed = errors.New("vault: secret not in scope")
func Scoped(src Source, names []string) Reader

// ---- internal/ui/registrar.go ----
package ui

type Registrar interface {
	Page(route, title string, h http.Handler)                                  // GET /m/<module>/<route>
	Tile(name string, render func(ctx context.Context) (template.HTML, error))
	GridColumn(step string, cell func(ctx context.Context, host string) Cell)
	Action(name string, h http.Handler)                                        // POST /m/<module>/action/<name>
}
type Cell struct {
	State  string // verified | pending | failed | drifted | n/a | manual
	Detail string
	Link   string
}
var Discard Registrar // registers nothing (UI off)
type TileView struct {
	Module, Name string
	HTML         template.HTML
	Err          string
}
type GridColumnView struct {
	Module, Step string
	Cell         func(ctx context.Context, host string) Cell
}
type PageLink struct{ Module, Route, Title string }
type ModuleRow struct { // one module's health on the Platform page (ui does not import module)
	Agent, Module, State, Detail string
	Gaps                         []string
	PreContract                  bool
}
func (s *Server) Registrar(module string, enabled func() bool) Registrar
func (s *Server) Tiles(ctx context.Context) []TileView
func (s *Server) GridColumns() []GridColumnView
func (s *Server) ModulePages() []PageLink

// ---- internal/manifest/modules.go, labels.go ----
package manifest

type ModuleBlock struct {
	Raw        []byte   // YAML of modules/<name>.yml after template expansion
	Enabled    *bool    // nil when the block omits enabled
	ActEnabled bool
	Auto       []string
}
func (b ModuleBlock) Decode(v any) error // strict
// Manifest gains: Modules map[string]ModuleBlock
// Host gains: Modules map[string]bool `yaml:"modules,omitempty" json:"modules,omitempty"`; Labels []string `yaml:"labels,omitempty" json:"labels,omitempty"`
func (m *Manifest) ModuleEnabled(host, module string, def bool) bool
type LabelExpr struct{ /* parsed tree; unexported fields */ }
func ParseLabels(expr string) (LabelExpr, error)
func (e LabelExpr) Match(labels []string) bool
func (m *Manifest) HostsMatching(e LabelExpr) []string // sorted host names

// ---- internal/plan ----
package plan

type ApprovalClass string

const (
	ClassClick        ApprovalClass = "click"
	ClassAutoReadOnly ApprovalClass = "auto_readonly"
	ClassStanding     ApprovalClass = "standing"
	ClassAuto         ApprovalClass = "auto"
)
type StandingApproval struct {
	ID       string    `json:"id"`
	Module   string    `json:"module"`
	Template string    `json:"template"`
	Targets  string    `json:"targets"` // label expression
	Actions  []string  `json:"actions"`
	Expires  time.Time `json:"expires"`
	Approver string    `json:"approver"`
	Created  string    `json:"created"` // operator login
	Revoked  bool      `json:"revoked,omitempty"`
}
// Plan gains: Class ApprovalClass `json:"class,omitempty"`; Module, Template, Approver string (json and yaml tags of the same names)
// StepBody gains: Class ApprovalClass `json:"class,omitempty"` (covered by the step signature)
// ModuleLimits becomes: struct { module.Common; RatePerSec float64 `json:"rate_per_sec,omitempty"`; Burst int `json:"burst,omitempty"` }
func ExpandTemplate(p Plan, params map[string]string) (Plan, error)
func BlockFor(cfg *AgentConfig, name string) (block any, ok bool)

const (
	ControlFact = "fact"
	MaxFactData = 16 << 10
	MaxFactTTL  = 24 * time.Hour
)
func FactSender(fact string) (module string, ok bool)

// ---- internal/plan/lint ----
package lint

type Finding struct{ Rule, Node, Message string }
type Ctx struct {
	Manifest *manifest.Manifest
	Query    store.Reader
	Class    plan.ApprovalClass
	Actions  *actions.Registry
}
type Rule struct {
	ID    string // ^[A-Z]{2,4}[0-9]{3}$
	Doc   string
	Check func(n plan.Node, c Ctx) []Finding
}
func Register(r Rule) // from init; panics on a bad or duplicate id
func Rules() []Rule  // sorted by ID
func Run(p plan.Plan, c Ctx) []Finding

// ---- internal/agent ----
package agent

// Factory gains: Manifest module.Manifest (zero for a pre-contract module)
type HealthReporter interface{ Health() module.Health }
func (s *Supervisor) Health(name string) (module.Health, bool)
func Registered() []Factory // the process-wide factory registry, sorted by name
// Env.Subscribe becomes: func (e Env) Subscribe(buf int, kinds ...string) (<-chan event.Event, func())
func (e Env) Fact(id string) (event.ControllerFact, bool) // false when never received or expired

type HarnessOptions struct {
	Host      string
	StateDir  string
	Factories []Factory
	PlanKey   ed25519.PublicKey
	EmitErr   func() error // nil: every emit succeeds
}
type Harness struct{ /* unexported */ }
func NewHarness(o HarnessOptions) (*Harness, error)
func (h *Harness) Apply(cfg *plan.AgentConfig)
func (h *Harness) Run(ctx context.Context)
func (h *Harness) Publish(e event.Event)
func (h *Harness) Emitted() []event.Event
func (h *Harness) Health(name string) (module.Health, bool)
func (h *Harness) Kept(key string) any
func (h *Harness) Fact(f event.ControllerFact)

// ---- internal/actions ----
// Env gains: Probe func(ctx context.Context, service string) error // nil: the probe cannot run

// ---- internal/controller ----
func (c *Controller) EmitController(ctx context.Context, e event.Event) (event.Event, error)
func (c *Controller) RunModules(ctx context.Context, mods []module.ControllerModule) error
func (c *Controller) ModuleHealth() map[string]module.Health
func (c *Controller) AgentHealth(host string) map[string]module.Health
func (c *Controller) RunReadOnly(ctx context.Context, mod, template string, params map[string]string) (string, error)
func (c *Controller) CreateStanding(ctx context.Context, sa plan.StandingApproval) error
func (c *Controller) RevokeStanding(ctx context.Context, id, by string) error
func (c *Controller) RunStanding(ctx context.Context, mod, approvalID, template string, params map[string]string) (string, error)
func (c *Controller) Propose(ctx context.Context, p module.Proposal) (int64, error)
func (c *Controller) AcceptProposal(ctx context.Context, id int64, by string) (string, error)
func (c *Controller) DismissProposal(ctx context.Context, id int64, by string) error
func (c *Controller) RunAuto(ctx context.Context, mod, template string, params map[string]string) (string, error)
func (c *Controller) ReenableAuto(ctx context.Context, mod, template, host, by string) error
func (c *Controller) SendFact(ctx context.Context, mod string, m module.ControlMsg) error
// Options gains: Probe func(ctx context.Context, service string) error

// ---- internal/module/conformance ----
package conformance

type AgentCase struct {
	Factory  agent.Factory
	Default  *plan.AgentConfig // the module's default block on a fixture host
	Reconfig *plan.AgentConfig // a changed block (check 8)
	KeepKey  string            // key the module stores with Env.Keep; "" when it keeps nothing
	Load     []event.Event     // consumed events fed on the bus (checks 6 and 7)
	Block    any               // pointer to a zero settings struct (check 9); nil: plan.BlockFor(Default, Factory.Name)
}
func Agent(t *testing.T, c AgentCase)

type ControllerCase struct {
	Module module.ControllerModule
	Config string        // YAML of modules/<name>.yml with the default settings
	Seed   []event.Event // fixture store contents for analysers (check 11)
	Now    time.Time
}
func Controller(t *testing.T, c ControllerCase)

// The exported functions are thin wrappers: each check is a named function
// returning an error, so the suite's own tests can assert that a check fails.
func runAgentChecks(c AgentCase) map[string]error           // unexported; key = subtest name
func runControllerChecks(c ControllerCase) map[string]error // unexported

var PreContract []string             // registered module names not yet on the contract; only ever shrinks
var AllowedLibraries []string        // the closed list of shared stateless libraries
var CoreImports []string             // the core packages a module may import
var ModulePackages map[string]string // module name -> package path (34 catalogue modules plus health)
var LinkLoss = 60 * time.Second      // check 7 duration; 2 s under testing.Short()

// ---- seam extras that W3, W5, W6, W7 and W11 assumed (each implemented by the task named) ----

// internal/actions (Task 2a; a rename, not a stub). ONE name for exporting action registration: Register.
func Register(f func() []Action) // was registerExtra; the retired variants RegisterExtra and RegisterFamily do not exist
func RegisterUndo(kind string, fn func(ctx context.Context, env *Env, e deadman.Entry) error) // was registerUndo; panics on a duplicate kind
func Unsupported(what string) error // was unsupported; wraps ErrUnsupported
func (e *Env) Now() time.Time       // the field Env.Now is renamed Env.Clock
// Env gains: Ext map[string]any // module-owned backends keyed by module name; nil reads as absent

// internal/event (Tasks 3a, 4a)
func (e Event) WithExtra(key string, v any) Event // Fields["x_"+key] = v on a copy; Decode and Validate ignore x_ keys
// Optional (omitempty) members added to the common structs, the exact list in Task 4a:
//   ProcessParent: PID, StartTicks, Live, Unresolved
//   ProcessStart:  Argc *int, CGroup, EUID *int, AUID *int64, Env map[string]string, StartTicks
//   FileChange:    Comm, WriterCmdline, WriterStartTicks, SelfTamper, WriterKnown *bool, GPO, GPOGUID, GPOSection, GPOItem, SysvolPolicy
//   Conn, Listener: ExeDeleted, ExeSHA256, PIDStart
//   AuthEvent:     LogonTypeName, MachineAccount, Status, SubStatus, FailureReason, Process, Workstation, SubjectAccount
//   Replay bool on ProcessStart, FileChange, Conn and AuthEvent (the enrollment backscan marker)

// internal/store/storetest (Task 8a)
func New(t *testing.T, evs ...event.Event) *store.Store // temp store; events grouped by Agent, Seq 1..n, sealed, ingested

// internal/vault (Task 9a)
func Covers(grants []string, name string) bool // an entry ending "/*" grants every name with that prefix; Scoped uses it

// internal/manifest (Task 11a)
func AppendOverrides(dir string, fn func(*Overrides) error) error // atomic, validated, mode 0600 kept
type LearnedListener struct {
	Host, Proto string // tcp | udp
	Port        uint16
	Reason      string
	Observed    string // RFC 3339, UTC
}
// Overrides gains: LearnedListeners []LearnedListener `yaml:"learned_listeners,omitempty" json:"learned_listeners,omitempty"`

// internal/plan (Tasks 22a, 27a): the two core plan options no workstream owned
// Node gains: ExpiresAfterSec int `json:"expires_after_sec,omitempty"`; Until *GateUntil `json:"until,omitempty"` (a gate with Until is gate: auto)
// StepBody gains: ExpiresAfterSec int `json:"expires_after_sec,omitempty"` (covered by the signature)
type GateUntil struct {
	AfterSec int      `json:"after_sec,omitempty"` // seconds after the gate's last dependency finished
	Probe    string   `json:"probe,omitempty"`     // scored service name, or "*" for every scored service on the plan's targets
	NoEvent  *NoEvent `json:"no_event,omitempty"`
}
type NoEvent struct {
	Kind   string            `json:"kind"`
	Fields map[string]string `json:"fields,omitempty"`
}
// controller.Options gains: GatePoll time.Duration (default 1s)

// plans (root package, Task 22b) and internal/controller
func Parse(raw []byte) (*Template, error) // plans.Parse; strict, 256 KiB cap
func ResolveLabels(t *Template, hosts func(expr string) ([]string, error)) (map[string]any, error) // plans.ResolveLabels: {labels: expr} vars
// plans.Template gains: Module string `yaml:"module"`
func LoadModuleTemplateFor(plansRoot, mod, name string, hosts func(expr string) ([]string, error)) (plan.Plan, error)
// LoadModuleTemplate(plansRoot, mod, name) is LoadModuleTemplateFor with a nil resolver. CoreImports gains the root plans package path.
```

- [ ] **Step 1: Write the stubs.** Types, constants and interfaces exactly as above. Function bodies: `panic("unimplemented: W1 Task N")` naming the implementing task (`Declare` → 3, common `Declare` calls → 4, ...), except `Effective`, which is one line and written now, and `agent.Registered()` (the sorted process-wide factory list, one line over the existing `registered(nil)`). Add the new fields to existing structs now, all zero-value safe (`omitempty` where JSON-encoded): `event.Event.Schema` and `Tag` (in the order of Task 2), `store.Query.Fields`, `manifest.Manifest.Modules`, `manifest.Host.Modules` and `Labels`, `agent.Factory.Manifest`, `link.Heartbeat.Health`, `plan.Plan.Class`, `Module`, `Template`, `Approver`, `plan.StepBody.Class`, `actions.Env.Probe`, `controller.Options.Probe`. Do not change `plan.ModuleLimits` (Task 12 does, with its callers). `Env.Subscribe` becomes variadic in kinds (the filter itself is Task 13). `var _ Reader = (*Store)(nil)` compiles against the built `Store` methods. `PreContract` lists every factory registered today: `audit`, `capture`, `deception`, `detect`, `health`, `integrity`, `net`, `winevt`. `AllowedLibraries` and `CoreImports` hold the module paths of the two lists in Global Constraints. `internal/module/all/all.go` blank-imports `internal/agent/mods`.
- [ ] **Step 2: Write the skipped tests and their helpers.** For each of Tasks 3 to 42, lettered tasks included, except Task 12 (which writes its own, because its tests need the `ModuleLimits` change), create the test file the task names with the test functions of its Step 1, the first statement of each being `t.Skip("unimplemented: W1 Task N")`. Prose comments inside a test body become the code they describe. Write, for real, the helpers those tests call: in `internal/controller` (`modtest_helpers_test.go`): `newTestController`, `newTestControllerAt`, `newTestControllerWithManifest(t, files map[string]string)` (manifest dir with a minimal topology naming controller host `ctl`, hosts `h1` (labels `linux`, `server`, scored service `web`) and `db1`, plus `files`), `newTestControllerWithPlans`, `newTestControllerWithRegistry`, `newStandingController`, `newAutoController`, `setHeartbeat`, `mustNew`, `testMod`, `ctlMod`, `ctx`; in `internal/module/conformance` (`helpers_test.go`): the fixture factories and modules each test names, `cfgWith`, `cfgWith2`, `someLoad`, `looseSettings`; in `internal/agent`: `harnessFactory`, `subscriberFactory`, `emitterFactory`, `emitOnce`. A helper that needs behaviour a later task builds may call the stub (the test is skipped until then).
- [ ] **Step 2b: Envelope tests, not skipped.** The four `internal/event/envelope_test.go` tests of Task 2 pass as soon as the fields exist; commit them unskipped here (Step 0 of Task 2 records the old hash before the fields are added: do that first).
- [ ] **Step 3: Apply the deviations to `phylax_design.md`.** Edit the Go sketches under "The capability manifest", "Agent modules", "Controller modules and analysers", "Health and budgets", "Configuration", "UI shell: Module registration" and "Lint registration" to the signatures above, and add the 19 deviations as one bullet each under "The module contract" with their reasons. Already in the design from the consistency pass (verify, do not re-add): the `Host` plan methods taking a template, `Tables`, `Manifest`, `UpdateOverrides` and prefix `Secrets` in the `Host` sketch, the root `plans` package in the core package list, `registry.set`/`registry.delete`/`registry.snapshot`, `ad.recycle_restored` in the `ad` Emits, the sshsig namespace `phylax-release`, and the embedded content paths of `logs` and `inventory`.
- [ ] **Step 4: Verify.** Run: `make build build-windows vet test race`. Expected: all pass. Then `go test -v ./internal/... 2>&1 | grep -c 'unimplemented: W1 Task'`. Expected: a count equal to the number of skipped tests written in Step 2 (no stub panics, only skips).
- [ ] **Step 5: Commit.**

```bash
git add internal docs phylax_design.md
git commit -m "module: W1 seams (contract types, stubs, skipped tests, design deviations)"
```

Open this as its own pull request into `v4` and merge after review; W3 and W5 start from it.

---

### Task 2: Envelope `Schema` and `Tag` in the store and on the wire

The fields themselves and the four event tests below land in Task 1 (Step 2b); Step 0 is done by Task 1's implementer before adding the fields. This task makes the store keep them.

**Files:**
- Modify: `internal/store/migrations.go` (append migration), `internal/store/query.go` (`eventCols`, `scanEvent`), `internal/store/ingest.go` (`insertEvent`)
- Modify: `internal/link/message.go` (`ProtoMinor` 1 → 2)
- Test: `internal/event/envelope_test.go` (Task 1), `internal/store/envelope_test.go`

**Interfaces:**
- Consumes: `Event` with fields in this order: `Agent, Seq, Time, Kind, Schema int "json:\"schema,omitempty\"", Priority, Tag string "json:\"tag,omitempty\"", Fields, PrevHash, Hash` (Task 1); `(*store.Store).Ingest`, `Events`.
- Produces: the store persists and returns `Schema` and `Tag`; protocol minor 2.

- [ ] **Step 0 (done in Task 1, before the fields are added): record the old hash.** Run in `internal/event` a scratch test that prints `ComputeHash()` of `Event{Agent: "a", Seq: 1, Time: time.Unix(0, 0).UTC(), Kind: "k", Priority: PriorityNormal, Fields: map[string]any{"x": "y"}}` (PrevHash ""). Paste the value as `oldHash` below. Delete the scratch test.
- [ ] **Step 1: Remove the skip** in `TestStoreRoundTripsSchemaAndTag` (the event tests are already live from Task 1):

```go
// internal/event/envelope_test.go
func TestCanonicalOmitsZeroSchemaAndTag(t *testing.T) {
	c, _ := Event{Agent: "a", Kind: "k"}.Canonical()
	if bytes.Contains(c, []byte(`"schema"`)) || bytes.Contains(c, []byte(`"tag"`)) {
		t.Fatalf("zero schema/tag must be omitted: %s", c)
	}
}
func TestCanonicalCarriesSchemaAndTag(t *testing.T) {
	c, _ := Event{Agent: "a", Kind: "k", Schema: 1, Tag: "plan:p1"}.Canonical()
	for _, want := range []string{`"schema":1`, `"tag":"plan:p1"`} {
		if !bytes.Contains(c, []byte(want)) {
			t.Fatalf("missing %s in %s", want, c)
		}
	}
}
func TestTagCoveredByHash(t *testing.T) {
	e := Event{Agent: "a", Kind: "k", Schema: 1, Tag: "w:1", Time: time.Unix(1, 0)}
	if err := e.Seal(0, GenesisHash); err != nil {
		t.Fatal(err)
	}
	e.Tag = "w:2"
	if err := e.Verify(0, GenesisHash); !errors.Is(err, ErrChain) {
		t.Fatalf("tag change not detected: %v", err)
	}
}
func TestPreSchemaEventStillVerifies(t *testing.T) {
	const oldHash = "<paste from Step 0>"
	e := Event{Agent: "a", Seq: 1, Time: time.Unix(0, 0).UTC(), Kind: "k", Priority: PriorityNormal, Fields: map[string]any{"x": "y"}, Hash: oldHash}
	if err := e.Verify(0, GenesisHash); err != nil {
		t.Fatalf("old event no longer verifies: %v", err)
	}
}

// internal/store/envelope_test.go
func TestStoreRoundTripsSchemaAndTag(t *testing.T) {
	// open a store in t.TempDir() and register agent "h1" the way store_test.go does
	e := event.Event{Agent: "h1", Time: time.Unix(5, 0).UTC(), Kind: "k", Schema: 1, Tag: "plan:p9", Priority: event.PriorityHigh}
	if err := e.Seal(0, event.GenesisHash); err != nil {
		t.Fatal(err)
	}
	// Ingest(ctx, "h1", []event.Event{e}); then Events(ctx, Query{Agent: "h1"})
	// want: one event, got.Schema == 1, got.Tag == "plan:p9", got.Verify(0, event.GenesisHash) == nil
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/store/ -run SchemaAndTag -v`. Expected: FAIL (`got.Schema == 0`: the store drops the field, and `Verify` fails on the read-back event).
- [ ] **Step 3: Implement.** Append migration `ALTER TABLE events ADD COLUMN schema INTEGER NOT NULL DEFAULT 0; ALTER TABLE events ADD COLUMN tag TEXT NOT NULL DEFAULT '';` and read/write both columns. Set `ProtoMinor = 2` with a comment that minor 2 added `schema` and `tag` to the envelope.
- [ ] **Step 4: Run, expect PASS.** Run: `make test race`. Expected: PASS (all packages; no fixture hash changed because both fields are omitted when zero).
- [ ] **Step 5: Commit.** `git commit -am "store: persist envelope schema and tag; protocol minor 2"`

---

### Task 2a: Exported action registration hooks (`actions.Register`, `RegisterUndo`, `Unsupported`, `Env.Now`, `Env.Ext`)

Haiku-sized. A rename plus two small additions; no module imports yet. W3, W5, W6, W7 and W11 register their actions through these names and no others (the design's name is `actions.Register`; the earlier `RegisterExtra` and `RegisterFamily` variants are gone).

**Files:**
- Modify: `internal/actions/registry.go` (`registerExtra` to `Register`), `internal/actions/win_env.go` (`registerUndo` to `RegisterUndo`, `unsupported` to `Unsupported`), `internal/actions/env.go` (field `Now` renamed `Clock`; method `Now()`; field `Ext`), every caller in `internal/actions` (`mssql_register.go`, `registry_win.go`, `win_defender.go`, `ad_accounts.go`, `splunk_actions.go`, `win_audit.go`, `win_service.go`, the `unsupported(` call sites), `internal/actions/helpers_test.go` and `internal/e2e/e2e_test.go` (`Now:` to `Clock:`)
- Test: `internal/actions/register_test.go`

**Interfaces:**
- Consumes: the built `Registry`, `Core()`, `Action`, `ErrUnsupported`, `deadman.Entry`.
- Produces (exact):

```go
func Register(f func() []Action) // was registerExtra; Core() appends every registered set
func RegisterUndo(kind string, fn func(ctx context.Context, env *Env, e deadman.Entry) error) // was registerUndo; panics on a duplicate kind
func Unsupported(what string) error // was unsupported: fmt.Errorf("%s: %w", what, ErrUnsupported)
func (e *Env) Now() time.Time       // e.Clock() when set, else time.Now(); replaces the unexported now()
// Env: the field `Now func() time.Time` is renamed `Clock` (a Go type cannot have a field and a method of one name);
// Env gains Ext map[string]any // backends owned by modules, keyed by module name ("firewall", "devices", "wazuh"); a nil map reads as absent
```

Rules: no alias for a retired name. `Env.Ext` has no accessor: a module reads `env.Ext[ExtKey]` and type-asserts.

- [ ] **Step 1: Write the failing tests:**

```go
// internal/actions/register_test.go
func TestRegisterAddsToCore(t *testing.T) {
	Register(func() []Action { return []Action{namedAction("regtest.hello")} }) // namedAction: the minimal fake of helpers_test.go (write one if absent)
	if _, err := Core().Get("regtest.hello"); err != nil {
		t.Fatal(err)
	}
}
func TestRegisterUndoDuplicatePanics(t *testing.T) {
	RegisterUndo("regtest.undo", func(context.Context, *Env, deadman.Entry) error { return nil })
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate undo kind accepted")
		}
	}()
	RegisterUndo("regtest.undo", func(context.Context, *Env, deadman.Entry) error { return nil })
}
func TestUnsupportedWrapsSentinel(t *testing.T) {
	err := Unsupported("network devices")
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "network devices") {
		t.Fatalf("%v", err)
	}
}
func TestEnvNowUsesClock(t *testing.T) {
	fixed := time.Date(2027, 2, 6, 9, 0, 0, 0, time.UTC)
	e := &Env{Clock: func() time.Time { return fixed }}
	if !e.Now().Equal(fixed) {
		t.Fatal(e.Now())
	}
	if d := time.Since((&Env{}).Now()); d < 0 || d > time.Second {
		t.Fatal(d)
	}
}
func TestEnvExtNilReadsAbsent(t *testing.T) {
	e := &Env{}
	if v, ok := e.Ext["firewall"]; ok || v != nil {
		t.Fatal("nil Ext must read as absent")
	}
	e.Ext = map[string]any{"firewall": 1}
	if e.Ext["firewall"] != 1 {
		t.Fatal("Ext lost a value")
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ -run 'Register|Unsupported|EnvNow|EnvExt' -v`. Expected: FAIL (compile error: the names do not exist).
- [ ] **Step 3: Implement** the renames and additions, fix every caller, run `make build build-windows vet` between the rename and the test run.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: export Register, RegisterUndo, Unsupported; Env.Now and Env.Ext"`

---

### Task 3: Typed kind registry

**Files:**
- Modify: `internal/event/types.go`
- Test: `internal/event/types_test.go`

**Interfaces:**
- Consumes: `Event` (Task 2).
- Produces: `Declare`, `Lookup`, `Declared`, `New[T]`, `Decode[T]`, `Validate`, `ErrUndeclared`, `ErrKindMismatch`, `ErrSchema` (Task 1 signatures).

- [ ] **Step 1: Remove the skips:**

```go
type tPayload struct {
	A string `json:"a"`
	N int    `json:"n,omitempty"`
}

func init() {
	Declare(Type{Kind: "ttest.one", Schema: 2, Priority: PriorityHigh, Fields: tPayload{}})
	Declare(Type{Kind: "ttest.two", Schema: 1, Priority: PriorityNormal, Alert: true, Fields: tPayload{}})
}

func TestNewSetsTypeDefaults(t *testing.T) {
	e, err := New("ttest.one", tPayload{A: "x", N: 3})
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != "ttest.one" || e.Schema != 2 || e.Priority != PriorityHigh {
		t.Fatalf("header %+v", e)
	}
	if e.Fields["a"] != "x" || e.Fields["n"] != json.Number("3") {
		t.Fatalf("fields %#v", e.Fields)
	}
}
func TestNewUndeclared(t *testing.T) {
	if _, err := New("ttest.none", tPayload{}); !errors.Is(err, ErrUndeclared) {
		t.Fatalf("want ErrUndeclared, got %v", err)
	}
}
func TestNewWrongPayloadType(t *testing.T) {
	if _, err := New("ttest.two", struct{ B int }{1}); !errors.Is(err, ErrKindMismatch) {
		t.Fatalf("want ErrKindMismatch, got %v", err)
	}
}
func TestDecodeStrict(t *testing.T) {
	e, _ := New("ttest.one", tPayload{A: "x", N: 3})
	got, err := Decode[tPayload](e, "ttest.one")
	if err != nil || got != (tPayload{A: "x", N: 3}) {
		t.Fatalf("decode %+v %v", got, err)
	}
	if _, err := Decode[tPayload](e, "ttest.two"); !errors.Is(err, ErrKindMismatch) {
		t.Fatalf("kind mismatch: %v", err)
	}
	bad := e
	bad.Fields = map[string]any{"a": "x", "zz": 1}
	if _, err := Decode[tPayload](bad, "ttest.one"); err == nil {
		t.Fatal("unknown field accepted")
	}
	old := e
	old.Schema = 1
	if _, err := Decode[tPayload](old, "ttest.one"); !errors.Is(err, ErrSchema) {
		t.Fatalf("schema: %v", err)
	}
}
func TestDecodeIgnoresXPrefix(t *testing.T) {
	e, _ := New("ttest.one", tPayload{A: "x"})
	e.Fields["x_serial"] = "7"
	if _, err := Decode[tPayload](e, "ttest.one"); err != nil {
		t.Fatalf("x_ field rejected: %v", err)
	}
}
func TestDeclareDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	Declare(Type{Kind: "ttest.one", Schema: 1, Fields: tPayload{}})
}
func TestDeclaredSortedAndLookup(t *testing.T) {
	ts := Declared()
	if !sort.SliceIsSorted(ts, func(i, j int) bool { return ts[i].Kind < ts[j].Kind }) {
		t.Fatal("not sorted")
	}
	if ty, ok := Lookup("ttest.two"); !ok || !ty.Alert {
		t.Fatalf("lookup %+v %v", ty, ok)
	}
}
func TestValidate(t *testing.T) {
	e, _ := New("ttest.one", tPayload{A: "x"})
	if err := Validate(e); err != nil {
		t.Fatal(err)
	}
	e.Fields["zz"] = true
	if Validate(e) == nil {
		t.Fatal("unknown field accepted")
	}
	if err := Validate(Event{Kind: "ttest.none"}); !errors.Is(err, ErrUndeclared) {
		t.Fatalf("undeclared: %v", err)
	}
}
func TestNewMatchesStoreRoundTrip(t *testing.T) {
	e, _ := New("ttest.one", tPayload{A: "x", N: 3})
	raw, _ := json.Marshal(e.Fields)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var back map[string]any
	_ = dec.Decode(&back)
	if !reflect.DeepEqual(back, e.Fields) {
		t.Fatalf("bus form %#v != store form %#v", e.Fields, back)
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/event/ -run 'New|Decode|Declare|Validate' -v`. Expected: FAIL with `panic: unimplemented: W1 Task 3`.
- [ ] **Step 3: Implement** in `internal/event/types.go`: a `sync.RWMutex`-guarded map `kind → Type` plus the `reflect.Type` of `Fields`. `New` checks `reflect.TypeOf(v)` against the declared type, marshals `v` and decodes into `map[string]any` with `UseNumber`. `Decode` and `Validate` drop `x_`-prefixed keys, marshal the rest and decode with `DisallowUnknownFields` into a new value of the declared type; `Validate` uses `reflect.New`. Schema must equal the declared schema.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/event/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "event: typed kind registry (Declare, New, Decode, Validate)"`

---

### Task 3a: `Event.WithExtra`

Haiku-sized.

**Files:**
- Modify: `internal/event/types.go`
- Test: `internal/event/extra_test.go`

**Interfaces:**
- Consumes: `New`, `Decode`, `Validate` (Task 3).
- Produces: `func (e Event) WithExtra(key string, v any) Event`.

Rules: returns a copy of `e` whose `Fields` map is a copy with `Fields["x_"+key] = v` added (the receiver's map is never modified, so a shared event is safe). A `key` that does not match `^[a-z][a-z0-9_]{0,31}$` panics (a programming error, as `Declare` does). `Decode` and `Validate` already ignore `x_` keys (Task 3); a rule may not read an `x_` field (a lint in the detect loader, W4). A field a rule, analyser or consumer reads belongs in the declared struct; `x_` carries what only a human reads.

- [ ] **Step 1: Write the failing tests:**

```go
func TestWithExtraCopiesAndPrefixes(t *testing.T) {
	e, _ := New("ttest.one", tPayload{A: "x"})
	f := e.WithExtra("raw_line", "su: failed")
	if f.Fields["x_raw_line"] != "su: failed" {
		t.Fatalf("%v", f.Fields)
	}
	if _, ok := e.Fields["x_raw_line"]; ok {
		t.Fatal("receiver modified")
	}
	if err := Validate(f); err != nil {
		t.Fatalf("x_ field must not fail strict validation: %v", err)
	}
	got, err := Decode[tPayload](f, "ttest.one")
	if err != nil || got.A != "x" {
		t.Fatalf("%+v %v", got, err)
	}
}
func TestWithExtraBadKeyPanics(t *testing.T) {
	e, _ := New("ttest.one", tPayload{A: "x"})
	defer func() {
		if recover() == nil {
			t.Fatal("bad key accepted")
		}
	}()
	e.WithExtra("Bad Key", 1)
}
func TestWithExtraSurvivesJSONRoundTrip(t *testing.T) {
	// e.WithExtra("n", 3) -> json.Marshal -> Unmarshal into Event -> Fields["x_n"] present; Validate still nil
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/event/ -run WithExtra -v`. Expected: FAIL (`unimplemented: W1 Task 3a`).
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/event/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "event: WithExtra for producer-only fields"`

---

### Task 4: Common kinds

**Files:**
- Modify: `internal/event/kinds.go` (add `init` with the eight `Declare` calls)
- Test: `internal/event/kinds_test.go`

**Interfaces:**
- Consumes: `Declare` (Task 3); the structs of Task 1.
- Produces: the eight common kinds declared at schema 1, `Alert: false`, default priorities `process_start` High, `process_exit` Normal, `file_change` High, `conn` Normal, `listener` High, `auth_event` High, `dns_query` Bulk, `telemetry_gap` High (today's emitters' priorities).

- [ ] **Step 1: Remove the skips:**

```go
func TestCommonKindsDeclared(t *testing.T) {
	want := map[string]any{KindProcessStart: ProcessStart{}, KindProcessExit: ProcessExit{}, KindFileChange: FileChange{},
		KindConn: Conn{}, KindListener: Listener{}, KindAuthEvent: AuthEvent{}, KindDNSQuery: DNSQuery{}, KindTelemetryGap: TelemetryGap{}}
	for k, f := range want {
		ty, ok := Lookup(k)
		if !ok || ty.Schema != 1 || ty.Alert || reflect.TypeOf(ty.Fields) != reflect.TypeOf(f) {
			t.Errorf("%s: %+v %v", k, ty, ok)
		}
	}
}
func TestConnCanonicalNames(t *testing.T) {
	e, err := New(KindConn, Conn{Op: "opened", Dir: "inbound", Proto: "tcp", LAddr: "10.0.0.1", LPort: 80, RAddr: "10.0.0.9", RPort: 5555, Source: "net"})
	if err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(maps.Keys(e.Fields))
	if !slices.Equal(keys, []string{"dir", "laddr", "lport", "op", "proto", "raddr", "rport", "source"}) {
		t.Fatalf("keys %v", keys)
	}
}
func TestLegacyFieldNamesRejected(t *testing.T) {
	for _, f := range []map[string]any{
		{"op": "opened", "dir": "out", "proto": "tcp", "source": "net", "src_ip": "1.2.3.4"},
		{"op": "opened", "dir": "inbound", "proto": "tcp", "source": "net", "dst_port": 22},
	} {
		if Validate(Event{Kind: KindConn, Schema: 1, Fields: f}) == nil {
			t.Errorf("accepted %v", f)
		}
	}
	if Validate(Event{Kind: KindProcessStart, Schema: 1, Fields: map[string]any{"pid": 1, "exe": "/x", "source": "audit", "image": "/x"}}) == nil {
		t.Error("image accepted")
	}
}
func TestProcessStartParentObject(t *testing.T) {
	e, _ := New(KindProcessStart, ProcessStart{PID: 2, Exe: "/bin/sh", Source: "audit", Parent: &ProcessParent{Exe: "/usr/sbin/httpd", Service: "ecom-http"}})
	p, ok := e.Fields["parent"].(map[string]any)
	if !ok || p["exe"] != "/usr/sbin/httpd" || p["service"] != "ecom-http" {
		t.Fatalf("parent %#v", e.Fields["parent"])
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/event/ -run 'Common|Canonical|Legacy|Parent' -v`. Expected: FAIL (`TestCommonKindsDeclared: process_start: {...} false`).
- [ ] **Step 3: Implement** the `init` in `kinds.go` with the priorities above.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/event/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "event: declare the eight common kinds with canonical fields"`

---

### Task 4a: Extension fields on the common structs

Haiku-sized. The structs of Task 1 already carry the fields (data written in Task 1); this task proves them and the strictness that must not loosen. W3 producers and the rules read these names: `rules/linux_exec.yml` (`argc`, `cgroup`, `env.LD_PRELOAD`), `rules/mw-redteam.yml` (`gpo`, `sysvol_policy`), `internal/traceback/obs.go` (`start_ticks`, `writer_start_ticks`, `exe_sha256`, `pid_start`). Rule of thumb for later changes: a field a rule, analyser or consumer reads belongs in the struct; a field only a human reads is `x_`.

**Files:**
- Modify: `internal/event/kinds.go` (confirm every field of the Interfaces block below, add the missing ones)
- Test: `internal/event/kinds_ext_test.go`

**Interfaces:**
- Consumes: `New`, `Decode`, `Validate` (Task 3), the common kinds (Task 4).
- Produces: optional members (all `omitempty`) of the Task 1 structs:
  - `ProcessParent`: `PID int "pid"`, `StartTicks uint64 "start_ticks"`, `Live bool "live"`, `Unresolved bool "unresolved"`
  - `ProcessStart`: `Argc *int "argc"`, `CGroup string "cgroup"`, `EUID *int "euid"`, `AUID *int64 "auid"`, `Env map[string]string "env"`, `StartTicks uint64 "start_ticks"`
  - `FileChange`: `Comm string "comm"`, `WriterCmdline string "writer_cmdline"`, `WriterStartTicks uint64 "writer_start_ticks"`, `SelfTamper bool "self_tamper"`, `WriterKnown *bool "writer_known"`, `GPO bool "gpo"`, `GPOGUID string "gpo_guid"`, `GPOSection string "gpo_section"`, `GPOItem string "gpo_item"`, `SysvolPolicy bool "sysvol_policy"`
  - `Conn` and `Listener`: `ExeDeleted bool "exe_deleted"`, `ExeSHA256 string "exe_sha256"`, `PIDStart uint64 "pid_start"`
  - `AuthEvent`: `LogonTypeName`, `Status`, `SubStatus`, `FailureReason`, `Process`, `Workstation`, `SubjectAccount string` (snake_case JSON names), `MachineAccount bool "machine_account"`
  - `Replay bool "replay"` on `ProcessStart`, `FileChange`, `Conn` and `AuthEvent` (the enrollment backscan marker; `detect` never fires on a replayed event)

- [ ] **Step 1: Write the failing tests:**

```go
func TestExtensionFieldsRoundTrip(t *testing.T) {
	argc := 0
	in := ProcessStart{PID: 7, Exe: "/usr/bin/su", Source: "audit", Argc: &argc, CGroup: "/system.slice/x", StartTicks: 99,
		Env: map[string]string{"LD_PRELOAD": "/tmp/x.so"}, Parent: &ProcessParent{Exe: "/bin/bash", PID: 3, Live: true}}
	e, err := New(KindProcessStart, in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode[ProcessStart](e, KindProcessStart)
	if err != nil || out.Argc == nil || *out.Argc != 0 || out.Env["LD_PRELOAD"] != "/tmp/x.so" || out.Parent.PID != 3 {
		t.Fatalf("%+v %v", out, err)
	}
}
func TestZeroArgcSurvives(t *testing.T) { // *int: argc 0 is present, absent is nil
	zero := 0
	e, _ := New(KindProcessStart, ProcessStart{PID: 1, Exe: "/x", Source: "audit", Argc: &zero})
	if _, ok := e.Fields["argc"]; !ok {
		t.Fatal("argc 0 dropped by omitempty")
	}
}
func TestUnknownFieldStillRejected(t *testing.T) {
	e, _ := New(KindConn, Conn{Op: "opened", Dir: "outbound", Proto: "tcp", Source: "net"})
	e.Fields["srcip"] = "10.0.0.1" // a retired name
	if Validate(e) == nil {
		t.Fatal("unknown field accepted")
	}
	e2, _ := New(KindConn, Conn{Op: "opened", Dir: "outbound", Proto: "tcp", Source: "net", ExeSHA256: "ab", PIDStart: 5, Replay: true})
	if err := Validate(e2); err != nil {
		t.Fatal(err)
	}
}
func TestReplayOnFourKinds(t *testing.T) {
	// for ProcessStart, FileChange, Conn, AuthEvent: New(kind, struct{...Replay: true}) -> Fields["replay"] == true
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/event/ -run 'ExtensionFields|ZeroArgc|UnknownFieldStill|ReplayOnFour' -v`. Expected: FAIL (`unimplemented: W1 Task 4a`, or a missing field).
- [ ] **Step 3: Implement:** add any member of the list above that Task 1 or Task 4 left out; the tests drive the rest.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/event/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "event: extension fields on the common structs"`

---

### Task 5: Core kinds

**Files:**
- Modify: `internal/event/core.go`
- Test: `internal/event/core_test.go`

**Interfaces:**
- Consumes: `Declare` (Task 3).
- Produces: 29 core kinds at schema 1 with these payload structs (all json tags snake_case of the field name; `omitempty` on every field except those marked `*`). For kinds with a built emitter, the fields are exactly the keys that emitter writes today (open the file and copy them); the "Fields" column is authoritative only where there is no emitter.

| Kind | Struct | Alert | Priority | Emitter today | Fields |
| --- | --- | --- | --- | --- | --- |
| `agent.start` | `AgentStart` | - | High | `internal/agent/agent.go` | copy |
| `agent.health` | `AgentHealth` | - | Normal | `internal/agent/health.go` | `spool`, `modules`, `link` as `map[string]any` (`shortcut: nested objects untyped at schema 1, type them when a consumer reads them`) |
| `agent.step` | `AgentStep` | - | High | `internal/agent/exec.go` | copy |
| `agent.step_result` | `AgentStepResult` | - | High | none | `plan*`, `node*`, `host*`, `phase*`, `outcome*`, `error`, `class` |
| `agent.step_refused` | `AgentStepRefused` | - | High | `internal/agent/exec.go` | copy |
| `evidence.blob` | `EvidenceBlob` | - | High | none | `alert*` (alert id), `sha256*`, `size*` (int64), `name`, `chunks` (int) |
| `agent.config_applied` | `AgentConfigApplied` | - | High | `internal/agent/config.go` | copy (`modules` is `map[string]string`) |
| `agent.config_rejected` | `AgentConfigRejected` | - | High | `internal/agent/config.go` | copy |
| `agent.control_refused` | `AgentControlRefused` | - | High | `internal/agent/handlers.go` | `kind*`, `reason*`, `epoch`, `seq` (uint64) |
| `agent.module_crash` | `AgentModuleCrash` | - | High | `internal/agent/module.go` | `module*`, `error*`, `restart_in_ms` (int64) |
| `controller.fact` | `ControllerFact` | - | High | none (Task 31) | as in Task 1 |
| `agent.deadman_fired` | `AgentDeadmanFired` | yes | Critical | `internal/agent/handlers.go` | copy |
| `agent.deadman_recovered` | `AgentDeadmanRecovered` | - | High | `internal/agent/agent.go` | copy |
| `agent.deadman_recovery_error` | `AgentDeadmanRecoveryError` | - | High | `internal/agent/agent.go` | copy |
| `agent.enrolled`, `agent.reenrolled` | `AgentEnrolled`, `AgentReenrolled` | - | High | none (W12) | `host*`, `key_hash*`, `manifest*` |
| `agent.silent`, `agent.resumed` | `AgentSilent`, `AgentResumed` | silent: yes | High | `internal/controller/agent.go` (`c.alert`) | `host*`, `detail` |
| `spool.gap` | `SpoolGap` | - | High | `internal/spool/spool.go` | `from*`, `to*`, `count*` (uint64), `class*` |
| `enroll.refused`, `enroll.key_mismatch`, `enroll.key_reuse` | `EnrollRefused`, `EnrollKeyMismatch`, `EnrollKeyReuse` | mismatch, reuse: yes | High | `internal/controller/agent.go` (`c.alert`) | `host*`, `detail` |
| `plan.step_timeout`, `plan.bad_result`, `plan.deadman_fired`, `plan.rollback_failed`, `plan.restore_failed`, `plan.confirm_failed` | `PlanStepTimeout`, `PlanBadResult`, `PlanDeadmanFired`, `PlanRollbackFailed`, `PlanRestoreFailed`, `PlanConfirmFailed` | all but the first two: yes | High (the alert ones Critical) | `internal/controller/plans.go`, `restore.go` (`c.alert`) | `host*`, `detail` |
| `plan.auto_halted` | `PlanAutoHalted` | yes | Critical | none (Task 28) | `module*`, `template*`, `host*`, `rollbacks*` (int) |

- [ ] **Step 1: Remove the skips:**

```go
var coreAlert = map[string]bool{"agent.deadman_fired": true, "agent.silent": true, "enroll.key_mismatch": true,
	"enroll.key_reuse": true, "plan.deadman_fired": true, "plan.rollback_failed": true, "plan.restore_failed": true,
	"plan.confirm_failed": true, "plan.auto_halted": true}

func TestCoreKindsDeclared(t *testing.T) {
	kinds := []string{"agent.start", "agent.health", "agent.step", "agent.step_result", "agent.step_refused", "evidence.blob",
		"agent.config_applied", "agent.config_rejected", "agent.control_refused", "agent.module_crash", "controller.fact",
		"agent.deadman_fired", "agent.deadman_recovered", "agent.deadman_recovery_error", "agent.enrolled", "agent.reenrolled",
		"agent.silent", "agent.resumed", "spool.gap", "enroll.refused", "enroll.key_mismatch", "enroll.key_reuse",
		"plan.step_timeout", "plan.bad_result", "plan.deadman_fired", "plan.rollback_failed", "plan.restore_failed",
		"plan.confirm_failed", "plan.auto_halted"}
	if len(kinds) != 29 {
		t.Fatal("table has 29 core kinds")
	}
	for _, k := range kinds {
		ty, ok := Lookup(k)
		if !ok || ty.Schema != 1 || ty.Alert != coreAlert[k] {
			t.Errorf("%s: %+v %v", k, ty, ok)
		}
	}
}
func TestSpoolGapShapeValidates(t *testing.T) {
	// the spool builds gap records as a map; it must decode against SpoolGap
	e := Event{Kind: "spool.gap", Schema: 1, Fields: map[string]any{"from": uint64(3), "to": uint64(9), "count": uint64(7), "class": "bulk"}}
	if err := Validate(e); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/event/ -run 'Core|SpoolGap' -v`. Expected: FAIL (`agent.start: {...} false`).
- [ ] **Step 3: Implement** the structs and the `init` with the 29 `Declare` calls.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/event/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "event: declare the 29 core kinds"`

---

### Task 5a: Core kinds for the console-script alerts, a locked controller and the store quota

Haiku-sized. The 2026-11-06 design review (R1, R8, R9) adds four core kinds to the Event kinds table and flags `enroll.refused` alert-class. The core count becomes 33 and the table total 189. Task 5's assertion of 29 core kinds is updated in this task's commit, not before.

**Files:**
- Modify: `internal/event/core.go`
- Test: `internal/event/core_test.go`

**Interfaces:**
- Consumes: `Declare` (Task 3), the Task 5 core kinds.
- Produces:

```go
const (
	KindEnrollHashMismatch = "enroll.hash_mismatch"
	KindEnrollNoShow       = "enroll.no_show"
	KindControllerLocked   = "controller.locked"
	KindStoreQuota         = "store.quota"
)

type EnrollHashMismatch struct { // the agent's hello binary_sha256 differs from the hash of the binary the controller served
	Host     string `json:"host"`
	Served   string `json:"served"`   // sha256 hex of the served binary
	Reported string `json:"reported"` // sha256 hex the agent reported
}
type EnrollNoShow struct { // a host with a served bundle did not connect inside the enrollment window
	Host      string `json:"host"`
	WindowSec int    `json:"window_sec"`
	Since     string `json:"since"` // RFC 3339, UTC: when the bundle was written
}
type ControllerLocked struct { // plan signing is locked after a restart
	Since   string   `json:"since"`             // RFC 3339, UTC
	Stopped []string `json:"stopped,omitempty"` // what is not running: "auto plans", "facts", "deadman_confirm", "safe_mode", "snapshots"
}
type StoreQuota struct { // the controller disk crossed a quota level
	Level   string   `json:"level"`   // "ok", "bulk", "evidence", "critical"
	UsedPct int      `json:"used_pct"`
	Shed    []string `json:"shed,omitempty"` // classes now refused: "bulk", "evidence", "normal"
}
```

| Kind | Struct | Alert | Priority |
| --- | --- | --- | --- |
| `enroll.hash_mismatch` | `EnrollHashMismatch` | yes | Critical |
| `enroll.no_show` | `EnrollNoShow` | yes | High |
| `controller.locked` | `ControllerLocked` | yes | Critical |
| `store.quota` | `StoreQuota` | yes | High (the emitter raises it to Critical at the `critical` level) |

`enroll.refused` becomes alert-class (`Alert: true`; its emitter already uses High). All four are schema 1 and emitted under agent `controller` through `EmitController`; this task only declares them (emitters: `enroll.hash_mismatch` and `enroll.no_show` in W2 Task 16 and W12, `controller.locked` in W12 Task 13a, `store.quota` in Task 8b).

- [ ] **Step 1: Update the tests:**

```go
// core_test.go: coreAlert gains "enroll.refused", "enroll.hash_mismatch", "enroll.no_show", "controller.locked", "store.quota";
// the kinds list gains the four new kinds; the length assertion becomes 33 ("table has 33 core kinds")
func TestNewCoreKindsValidate(t *testing.T) {
	for kind, v := range map[string]any{
		KindEnrollHashMismatch: EnrollHashMismatch{Host: "h1", Served: "aa", Reported: "bb"},
		KindEnrollNoShow:       EnrollNoShow{Host: "h1", WindowSec: 600, Since: "2026-11-07T14:00:00Z"},
		KindControllerLocked:   ControllerLocked{Since: "2026-11-07T14:00:00Z", Stopped: []string{"auto plans"}},
		KindStoreQuota:         StoreQuota{Level: "bulk", UsedPct: 91, Shed: []string{"bulk"}},
	} {
		e, err := New(kind, v)
		if err != nil || Validate(e) != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/event/ -run 'Core|NewCoreKinds' -v`. Expected: FAIL (`undeclared kind`).
- [ ] **Step 3: Implement** the four structs, the constants and the `Declare` calls; flip `enroll.refused`'s `Alert`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/event/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "event: declare enroll.hash_mismatch, enroll.no_show, controller.locked, store.quota"`

---

### Task 6: Agent core emitters through `event.New`

**Files:**
- Modify: `internal/agent/agent.go`, `exec.go`, `config.go`, `handlers.go`, `module.go`, `health.go`; `internal/spool/spool.go` (set `Schema: 1` on gap records)
- Test: `internal/agent/core_events_test.go`

**Interfaces:**
- Consumes: `event.New`, `event.Validate`, the core structs (Task 5), `event.TelemetryGap` (Task 4).
- Produces: every agent-side core event and `telemetry_gap` from `health` is built with `event.New` and validates.

- [ ] **Step 1: Remove the skip:**

```go
func TestAgentCoreEventsValidate(t *testing.T) {
	// Use the in-package test agent and controller of testutil_test.go: start the agent,
	// apply a config, send one control the agent refuses (unsigned), make a test module
	// crash once, wait for one health report.
	// Then read every event the agent spooled and every event its bus published.
	// want: for each event e of a declared kind, event.Validate(e) == nil;
	// and at least one each of agent.start, agent.config_applied, agent.control_refused,
	// agent.module_crash, agent.health was seen.
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/agent/ -run TestAgentCoreEventsValidate -v`. Expected: FAIL with `event: schema version not understood` (events carry schema 0).
- [ ] **Step 3: Implement.** Replace each `event.Event{Kind: "agent.…", Fields: map…}` literal with `event.New(kind, Struct{…})`, keeping the priority the code sets today when it differs from the default. Then `grep -rn 'Fields\["' internal/ | grep -E '\.\((u?int|float)64\)'` for consumers of these kinds and switch each to the numeric helper its package already uses (for example `store.fieldUint`); `json.Number` is what the store hands out already.
- [ ] **Step 4: Run, expect PASS.** Run: `make test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "agent: build core events with event.New"`

---

### Task 7: Module manifest validation and controller registry

**Files:**
- Modify: `internal/module/module.go` (`Validate`), `internal/module/registry.go`
- Test: `internal/module/module_test.go`

**Interfaces:**
- Consumes: Task 1 types.
- Produces: `(Manifest).Validate`, `Register`, `Registered`, `Lookup`, `Effective`.

Validation rules: `Name` matches `^[a-z][a-z0-9_]{1,31}$`; `Sides` non-empty, each `agent` or `controller`, no duplicate; `OS` ⊆ {`linux`, `windows`}; `Privilege` ∈ {`root`, `user`, `none`}, and `none` only when `Sides` is exactly `[controller]`; each `Emits[i].Kind` is a common kind (`event.Kind*` constants), or starts with `Name + "."`, or is `agent.*`/`telemetry_gap` when `Name` is `health` or `exec` (the core modules); no `Consumes` entry is empty or contains `*`; every `Budget` field ≥ 0. Declaredness of `Emits` is not checked here (init order); the conformance suite checks it.

- [ ] **Step 1: Remove the skips:**

```go
func good() Manifest {
	return Manifest{Name: "demo", Sides: []Side{SideController}, Privilege: "none",
		Emits: []event.Type{{Kind: "demo.found", Schema: 1}}, Consumes: []string{"conn"}}
}
func TestManifestValidate(t *testing.T) {
	if err := good().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []func(*Manifest){
		func(m *Manifest) { m.Name = "Demo" },
		func(m *Manifest) { m.Sides = nil },
		func(m *Manifest) { m.OS = []string{"darwin"} },
		func(m *Manifest) { m.Privilege = "admin" },
		func(m *Manifest) { m.Sides = []Side{SideAgent}; m.Privilege = "none" },
		func(m *Manifest) { m.Emits = []event.Type{{Kind: "other.found", Schema: 1}} },
		func(m *Manifest) { m.Emits = []event.Type{{Kind: "agent.health", Schema: 1}} },
		func(m *Manifest) { m.Consumes = []string{"capture.*"} },
		func(m *Manifest) { m.Budget.HeldMB = -1 },
	}
	for i, f := range bad {
		m := good()
		f(&m)
		if m.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	h := Manifest{Name: "health", Sides: []Side{SideAgent}, Privilege: "root", Emits: []event.Type{{Kind: "agent.health", Schema: 1}, {Kind: "telemetry_gap", Schema: 1}}}
	if err := h.Validate(); err != nil {
		t.Fatalf("core module: %v", err)
	}
}

type regMod struct{ m Manifest }

func (r regMod) Manifest() Manifest                     { return r.m }
func (regMod) Start(ctx context.Context, _ Host) error { <-ctx.Done(); return nil }
func (regMod) Health() Health                          { return Health{State: StateOK} }

func TestRegistry(t *testing.T) {
	m := good()
	m.Name = "regtest"
	m.Emits = []event.Type{{Kind: "regtest.x", Schema: 1}}
	Register(regMod{m})
	if got, ok := Lookup("regtest"); !ok || got.Manifest().Name != "regtest" {
		t.Fatal("lookup")
	}
	names := []string{}
	for _, r := range Registered() {
		names = append(names, r.Manifest().Name)
	}
	if !slices.IsSorted(names) || !slices.Contains(names, "regtest") {
		t.Fatalf("registered %v", names)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate accepted")
		}
	}()
	Register(regMod{m})
}
func TestEffective(t *testing.T) {
	tr, fa := true, false
	cases := []struct {
		host, block *bool
		def, want   bool
	}{{nil, nil, true, true}, {nil, nil, false, false}, {nil, &fa, true, false}, {nil, &tr, false, true}, {&fa, &tr, true, false}, {&tr, &fa, false, true}}
	for i, c := range cases {
		if Effective(c.host, c.block, c.def) != c.want {
			t.Errorf("case %d", i)
		}
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/module/ -v`. Expected: FAIL with `panic: unimplemented: W1 Task 7`.
- [ ] **Step 3: Implement** `Validate` (rules above, errors name the field), and the registry as a mutex-guarded map written only from `init`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/module/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "module: manifest validation and controller registry"`

---

### Task 8: Store reader, field equality and module tables

**Files:**
- Modify: `internal/store/query.go` (`Query.Fields`), `internal/store/reader.go`, `internal/store/migrations.go` (append `module_migrations`)
- Test: `internal/store/reader_test.go`

**Interfaces:**
- Consumes: built `Store`, `Ingest`, `Events`.
- Produces: `Reader`, `Query.Fields`, `ModuleDB` (`Migrate`, `Exec`, `Query`), `(*Store).ModuleDB(module string) ModuleDB`.

Rules: a `Fields` key must match `^[a-z0-9_]{1,64}$` (it goes into a JSON path); values compare as text: `CAST(json_extract(fields, '$.'||key) AS TEXT) = ?`. `Migrate` keeps `module_migrations(module TEXT PRIMARY KEY, applied INTEGER NOT NULL)`, applies entries past `applied` in one transaction, and refuses a statement that creates or alters a table whose name does not start with `<module>_`. `Exec` refuses a statement whose `INSERT INTO`, `REPLACE INTO`, `UPDATE` or `DELETE FROM` target does not start with `<module>_`. `shortcut: table ownership checked by name prefix with a regexp, upgrade to a SQLite authorizer if a module needs dynamic SQL`.

- [ ] **Step 1: Remove the skips:**

```go
func TestQueryFieldEquality(t *testing.T) {
	// store with agent "h1"; ingest two sealed events kind "k" with Fields {"host":"a","n":5} and {"host":"b","n":6}
	// Events(ctx, Query{Kind: "k", Fields: map[string]string{"host": "a"}}) -> 1 event, Fields["host"]=="a"
	// Events(ctx, Query{Kind: "k", Fields: map[string]string{"n": "6"}}) -> 1 event
}
func TestQueryFieldKeyValidated(t *testing.T) {
	// Events(ctx, Query{Fields: map[string]string{"a') OR 1=1 --": "x"}}) -> non-nil error
}
func TestModuleDBMigrateOwnPrefix(t *testing.T) {
	db := st.ModuleDB("deps")
	if err := db.Migrate(ctx, []string{"CREATE TABLE deps_edge(a TEXT)"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, []string{"CREATE TABLE deps_edge(a TEXT)"}); err != nil {
		t.Fatalf("second run must be a no-op: %v", err)
	}
	if err := st.ModuleDB("deps").Migrate(ctx, []string{"CREATE TABLE deps_edge(a TEXT)", "CREATE TABLE edge(a TEXT)"}); err == nil {
		t.Fatal("foreign table name accepted")
	}
}
func TestModuleDBExecOwnTables(t *testing.T) {
	db := st.ModuleDB("deps")
	_ = db.Migrate(ctx, []string{"CREATE TABLE deps_edge(a TEXT)"})
	if _, err := db.Exec(ctx, "INSERT INTO deps_edge(a) VALUES (?)", "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "DELETE FROM events"); err == nil {
		t.Fatal("write to a core table accepted")
	}
	rows, err := db.Query(ctx, "SELECT a FROM deps_edge")
	if err != nil {
		t.Fatal(err)
	}
	rows.Close()
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/store/ -run 'Field|ModuleDB' -v`. Expected: FAIL (`unimplemented: W1 Task 8`, or `Fields` ignored).
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/store/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "store: Reader, field equality, module tables"`

---

### Task 8a: `storetest.New`, a seeded store for module tests

Haiku-sized. Every analyser and controller module test (W6 `firewall`, `egress`, W8 `traceback`, `chains`, `deps`) needs a real store with a readable, correctly sealed chain; this is the one helper.

**Files:**
- Create: `internal/store/storetest/storetest.go`
- Test: `internal/store/storetest/storetest_test.go`

**Interfaces:**
- Consumes: `store.Open`, `(*Store).Ingest`, the event package's sealing helper (Task 2: the same one the agent uses), `store.Reader` (Task 8).
- Produces:

```go
// New opens a temporary store, groups evs by Agent, assigns Seq 1..n in the order given (per agent),
// seals each agent's chain with the event package's sealing helper, ingests them and returns the store
// (closed by t.Cleanup). *store.Store satisfies store.Reader.
func New(t *testing.T, evs ...event.Event) *store.Store
```

Rules: an event with a zero `Time` gets `time.Date(2027, 2, 6, 9, 0, 0, 0, time.UTC)` plus one second per position; an undeclared kind fails the test (`t.Fatal`); the helper never bypasses the store's own replay and hash checks.

- [ ] **Step 1: Write the failing tests:**

```go
func TestNewSeedsReadableChain(t *testing.T) {
	a, _ := event.New("ttest.seed", struct{ N int `json:"n"` }{1})
	a.Agent = "h1"
	b := a
	b.Agent = "h1"
	c := a
	c.Agent = "db1"
	st := New(t, a, b, c)
	got, err := st.Events(context.Background(), store.Query{Agent: "h1"})
	if err != nil || len(got) != 2 || got[0].Seq != 1 || got[1].Seq != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	if e, err := st.Latest(context.Background(), "db1", "ttest.seed"); err != nil || e.Seq != 1 {
		t.Fatalf("%+v %v", e, err)
	}
}
func TestNewKeepsGivenTimes(t *testing.T) {
	// an event with Time set keeps it; one without gets a strictly increasing default; Events returns them in that order
}
```

(`ttest.seed` is declared by an `init` in the test file, as `ttest.one` is in Task 3.)

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/store/storetest/ -v`. Expected: FAIL (`unimplemented: W1 Task 8a`).
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/store/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "store: storetest.New seeded store for module tests"`

---

### Task 8b: Controller disk quotas, the shed order and the audit exemption (R9)

The design (Event store and vault: Quotas) sets hard quotas on the controller's data disk with a fixed shed order: refuse bulk at 90% used, evidence at 95%, accept only high and critical events at 98%; alerts are never shed; safe mode and the kill switch are exempt from the audit-write refusal. The W14 bench reports store growth; if it reports a level above `ok` it says so in its Overview line.

**Files:**
- Create: `internal/store/quota.go`, `internal/controller/quota.go`
- Modify: `internal/store/ingest.go` (admission), `internal/store/store.go` (migration for `quota_skips`), `internal/ui/ui.go` (`Config.AuditExempt`), `internal/controller/controller.go` (start the sampler), `internal/controller/agent.go` (chunk answers)
- Test: `internal/store/quota_test.go`, `internal/controller/quota_test.go`, `internal/ui/audit_exempt_test.go`

**Interfaces:**
- Consumes: `Store.Ingest`, `Store.Gaps`, `Store.GapTotals`, `Store.DiskSize`, `event.Lookup` (alert flag), `EmitController` (Task 16), `event.StoreQuota` (Task 5a), `ui.Server.protected`.
- Produces:

```go
// package store
type QuotaLevel int

const (
	QuotaOK       QuotaLevel = iota
	QuotaBulk                // >= 90% used: refuse bulk events and bulk transfers
	QuotaEvidence            // >= 95%: also refuse alert evidence chunks and pcap slices
	QuotaCritical            // >= 98%: accept only high and critical events
)

func (l QuotaLevel) String() string // "ok", "bulk", "evidence", "critical"

// Admit reports whether an event is stored at this level. alert is true when the kind is alert-class
// (event.Lookup(kind).Alert) and the priority is high or critical, i.e. the event becomes an alert row: it is always admitted.
func (l QuotaLevel) Admit(prio event.Priority, alert bool) bool

// AdmitChunk reports whether a content-addressed transfer of the given class ("bulk" | "evidence") is accepted.
func (l QuotaLevel) AdmitChunk(class string) bool

type Quota struct{ /* used func() (float64, error); level atomic; hysteresis 2 points */ }

func NewQuota(used func() (usedPct float64, err error)) *Quota
func (q *Quota) Level() QuotaLevel
// Sample re-reads the usage and returns the new level and whether it changed. Rising crosses at 90/95/98;
// falling steps down only when usage is 2 points below the threshold (hysteresis).
func (q *Quota) Sample() (QuotaLevel, bool)
func (s *Store) SetQuota(q *Quota) // Ingest consults q.Level() once per batch

// Ingest, for an event the level does not admit: the event is chain-verified like any other (seq, prev, hash),
// the agent's head advances over it, its body is NOT stored, and the run is recorded in quota_skips
// (agent, from_seq, to_seq, reason "controller quota", at); Ack.Accepted does not count it, a new field Ack.Skipped does.
// Gaps() and GapTotals() include the skipped runs (reason "controller quota").
```

```go
// package controller
func (c *Controller) startQuota(ctx context.Context, every time.Duration) // samples; on a level change emits event.StoreQuota
//   (priority High; Critical at QuotaCritical; "ok" is emitted on recovery at Normal priority but is not alert-class traffic
//   because the ingest rule needs high or critical); a refused chunk (QuotaLevel.AdmitChunk false) is answered with the
//   chunk error code "quota" and the agent retries later.
// package ui
// Config gains: AuditExempt []string // route patterns ("POST /agents/{host}/safe-mode", "POST /safe-mode", "POST /settings/kill-switch");
// when the audit write fails for a request matching one, the request proceeds, the failure is logged, and the entry
// is kept in a bounded in-memory queue (64) that is written first on the next successful audit.
```

Usage is `statfs` of the filesystem holding the data directory (Used / Total); `NewQuota` takes the function so tests drive it. `shortcut: usage is the whole filesystem's, not the data directory's, upgrade when the data disk is shared`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestQuotaLevelAdmit(t *testing.T) {
	type c struct {
		l      QuotaLevel
		prio   event.Priority
		alert  bool
		want   bool
	}
	for i, k := range []c{
		{QuotaOK, event.PriorityBulk, false, true},
		{QuotaBulk, event.PriorityBulk, false, false},
		{QuotaBulk, event.PriorityNormal, false, true},
		{QuotaEvidence, event.PriorityNormal, false, true},
		{QuotaCritical, event.PriorityNormal, false, false},
		{QuotaCritical, event.PriorityHigh, false, true},
		{QuotaCritical, event.PriorityCritical, false, true},
		{QuotaCritical, event.PriorityBulk, true, true}, // an alert is never shed
	} {
		if got := k.l.Admit(k.prio, k.alert); got != k.want {
			t.Errorf("case %d: %v", i, got)
		}
	}
	if QuotaBulk.AdmitChunk("bulk") || !QuotaBulk.AdmitChunk("evidence") || QuotaEvidence.AdmitChunk("evidence") {
		t.Fatal("chunk classes")
	}
}
func TestQuotaSampleHysteresis(t *testing.T) {
	pct := 50.0
	q := NewQuota(func() (float64, error) { return pct, nil })
	for _, s := range []struct {
		pct  float64
		want QuotaLevel
	}{{89, QuotaOK}, {90, QuotaBulk}, {95, QuotaEvidence}, {98, QuotaCritical}, {97, QuotaCritical}, {95.9, QuotaCritical},
		{95.5, QuotaCritical}, {95, QuotaEvidence}, {92.5, QuotaEvidence}, {87.9, QuotaOK}} {
		pct = s.pct
		if got, _ := q.Sample(); got != s.want {
			t.Errorf("%.1f: got %v want %v", s.pct, got, s.want)
		}
	}
}
func TestIngestSkipsRefusedAndKeepsChain(t *testing.T) {
	// storetest store with agent "h1"; quota level forced to QuotaBulk; ingest a sealed batch seq 1..4 with priorities
	// normal, bulk, bulk, high
	// want: Ack.Seq == 4, Accepted == 2, Skipped == 2; Events(h1) returns seq 1 and 4 only; a following batch (seq 5, prev = hash of seq 4)
	// is accepted; Gaps(h1) contains one gap 2..3 with reason "controller quota"; GapTotals counts it
}
func TestIngestNeverSkipsAlerts(t *testing.T) {
	// level QuotaCritical; a bulk-priority event of an alert-class kind with priority bulk is not an alert (needs high or critical): skipped;
	// a critical detect.alert-like event of an alert-class kind is stored
}
func TestIngestSkippedEventStillChainChecked(t *testing.T) {
	// level QuotaBulk; a bulk event with a wrong hash is rejected with ErrChain, not silently skipped
}
// controller/quota_test.go
func TestQuotaEmitsOnCrossing(t *testing.T) {
	// controller with a fake usage function; set 91, Sample via the ticker hook -> one store.quota event, level "bulk", Alert-class priority High;
	// set 98.5 -> one more at Critical priority with shed containing "normal"; set 10 -> one with level "ok"
}
func TestChunkRefusedAtEvidenceLevel(t *testing.T) {
	// level QuotaEvidence: an evidence chunk from a test agent is answered with error code "quota"; a bulk chunk too; at QuotaOK both succeed
}
// ui/audit_exempt_test.go
func TestAuditExemptRouteSurvivesAuditFailure(t *testing.T) {
	// Config.Audit returns an error; Config.AuditExempt lists "POST /agents/{host}/safe-mode"
	// want: POST to that route is served (not 500); any other POST route returns 500 "audit unavailable";
	// after the audit recovers, the queued entry is written before the next one
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/store/ ./internal/controller/ ./internal/ui/ -run 'Quota|IngestSkips|IngestNever|AuditExempt|ChunkRefused' -v`. Expected: FAIL (`undefined: QuotaLevel`).
- [ ] **Step 3: Implement** as specified. `quota_skips` is a new migration; `Ingest` skips only after the chain checks pass; the ingest hook never sees a skipped event.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/store/ ./internal/controller/ ./internal/ui/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "store: disk quotas with a shed order, skipped runs and an audit exemption for safe mode"`

---

### Task 9: Scoped vault reader

**Files:**
- Modify: `internal/vault/reader.go`
- Test: `internal/vault/reader_test.go`

**Interfaces:**
- Consumes: built `(*Vault).Get(name) (Secret, string, error)`, `ErrLocked`, `ErrNotFound`.
- Produces: `Reader`, `Source`, `Scoped`, `ErrNotAllowed`.

- [ ] **Step 1: Remove the skip:**

```go
func TestScoped(t *testing.T) {
	// create and unlock a vault in t.TempDir() as vault_test.go does; put "a" and "b"
	r := Scoped(v, []string{"a"})
	if s, err := r.Get("a"); err != nil || s.String() == "" { // use the Secret accessor vault_test.go uses
		t.Fatalf("a: %v", err)
	}
	if _, err := r.Get("b"); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("b: %v", err)
	}
	// lock v; r.Get("a") -> errors.Is(err, ErrLocked)
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/vault/ -run TestScoped -v`. Expected: FAIL (`unimplemented: W1 Task 9`).
- [ ] **Step 3: Implement** `Scoped` as a small struct holding the source and a name set.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/vault/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "vault: scoped reader for modules"`

---

### Task 9a: Prefix grants in the scoped vault reader (per-device vault keys)

Haiku-sized. `devices` needs one vault key per device and account (`cred/<device>/<account>`, built by `creds.VaultKey`), `creds` needs `cred/*` and `pcr/*`; a module block cannot list names it does not know in advance. A granted name ending in `/*` is a prefix grant.

**Files:**
- Modify: `internal/vault/reader.go`
- Test: `internal/vault/reader_test.go` (extend)

**Interfaces:**
- Consumes: `Scoped`, `ErrNotAllowed` (Task 9).
- Produces: `Scoped(src, names)` treats an entry ending in `/*` as a grant of every secret whose name starts with the part before the `*` (so `cred/*` grants `cred/palo1/phylax`, not `credx/a` and not `cred` itself); every other entry stays an exact name. `func Covers(grants []string, name string) bool` (exported: `Host.Secrets` in Task 17a uses it to validate a request).

- [ ] **Step 1: Write the failing tests:**

```go
func TestScopedPrefixGrant(t *testing.T) {
	// vault with "cred/palo1/phylax", "cred/vyos/phylax", "credx/a", "pcr/h1"; r := Scoped(v, []string{"cred/*"})
	// r.Get("cred/palo1/phylax") ok; r.Get("cred/vyos/phylax") ok
	// r.Get("credx/a") and r.Get("pcr/h1") -> errors.Is(err, ErrNotAllowed)
}
func TestCovers(t *testing.T) {
	g := []string{"cred/*", "notify.webhook"}
	for name, want := range map[string]bool{"cred/h1/admin": true, "cred/": true, "cred": false, "credx/a": false, "notify.webhook": true, "notify.webhook2": false, "cred/*": true} {
		if Covers(g, name) != want {
			t.Errorf("%q: want %v", name, want)
		}
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/vault/ -run 'Prefix|Covers' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** in `reader.go`: `Covers` is the whole rule; `Scoped` calls it.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/vault/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "vault: prefix grants (name/*) in the scoped reader"`

---

### Task 10: UI registrar

**Files:**
- Modify: `internal/ui/registrar.go`
- Test: `internal/ui/registrar_test.go`

**Interfaces:**
- Consumes: built `(*Server).Handle` (authenticated, CSRF-checked, audited), the test login helpers of `ui_test.go`.
- Produces: `(*Server).Registrar`, `Tiles`, `GridColumns`, `ModulePages`, `Discard`.

Rules: `module` and `route` match `^[a-z0-9_]{1,32}$` and `^[a-z0-9_/-]{1,64}$` with no `..` (else panic, a programming error); `Page` registers `GET /m/<module>/<route>`, `Action` registers `POST /m/<module>/action/<name>`; both serve 404 while `enabled()` is false; `Tiles` and `GridColumns` skip disabled modules; a tile whose render fails shows its error text (escaped), never breaks the page. Register before serving.

- [ ] **Step 1: Remove the skips:**

```go
func TestRegistrarPage(t *testing.T) {
	on := true
	// e := the test server env from ui_test.go
	r := e.s.Registrar("demo", func() bool { return on })
	r.Page("x", "Demo", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hi") }))
	// unauthenticated GET /m/demo/x -> not 200
	// logged-in GET /m/demo/x -> 200, body "hi"
	on = false
	// logged-in GET /m/demo/x -> 404
}
func TestRegistrarActionNeedsCSRF(t *testing.T) {
	r := e.s.Registrar("demo", func() bool { return true })
	r.Action("go", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	// logged-in POST /m/demo/action/go without the CSRF token -> 403; with it -> 204
}
func TestRegistrarTiles(t *testing.T) {
	on := true
	r := e.s.Registrar("demo", func() bool { return on })
	r.Tile("t", func(context.Context) (template.HTML, error) { return "<b>ok</b>", nil })
	r.Tile("bad", func(context.Context) (template.HTML, error) { return "", errors.New("boom") })
	tv := e.s.Tiles(context.Background())
	// want 2 views; tv[i].HTML == "<b>ok</b>" for "t"; Err == "boom" for "bad"
	on = false
	if len(e.s.Tiles(context.Background())) != 0 {
		t.Fatal("disabled module tile shown")
	}
}
func TestRegistrarRejectsBadRoute(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("bad route accepted")
		}
	}()
	e.s.Registrar("demo", func() bool { return true }).Page("../x", "x", http.NotFoundHandler())
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/ui/ -run Registrar -v`. Expected: FAIL (`unimplemented: W1 Task 10`).
- [ ] **Step 3: Implement** a per-module registrar struct appending to server-held slices behind a mutex; handlers wrap with the `enabled` check and go through `s.Handle`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/ui/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "ui: module registrar (pages, actions, tiles, grid columns)"`

---

### Task 11: Manifest module blocks, host `modules:` and labels

**Files:**
- Modify: `internal/manifest/types.go` (`Manifest.Modules`, `Host.Modules`, `Host.Labels`), `internal/manifest/load.go` (read `modules/*.yml`), `internal/manifest/modules.go`, `internal/manifest/labels.go`, `manifest/schema/hosts.yml.schema.json`
- Test: `internal/manifest/modules_test.go`, `internal/manifest/labels_test.go`

**Interfaces:**
- Consumes: built `Load`, `expandNode`, the strict decode in `load.go`.
- Produces: `ModuleBlock`, `ModuleBlock.Decode`, `Manifest.Modules`, `Host.Modules`, `Host.Labels`, `(*Manifest).ModuleEnabled`, `ParseLabels`, `LabelExpr.Match`, `(*Manifest).HostsMatching`.

Rules: `modules/` entries must be files named `^[a-z][a-z0-9_]*\.yml$` (anything else is a load error); each is template-expanded like the other files; `Enabled` is nil when the key is absent; `enabled`, `act_enabled` and `auto` are read from the YAML and the full text kept in `Raw`. `ModuleEnabled(host, module, def)` applies the same precedence as `module.Effective` inline (host entry, else the block's `Enabled`, else `def`); `manifest` must not import `internal/module`, because `module` imports `manifest` (deviation 17), and a test pins that both agree on all nine nil/true/false combinations. Label grammar: identifiers `[a-z0-9_-]+`, `!`, `&&`, `||`, parentheses; precedence `!` > `&&` > `||`; at most 256 bytes.

- [ ] **Step 1: Remove the skips:**

```go
func TestLoadModuleBlocks(t *testing.T) {
	fsys := minimalManifestFS() // topology.yml + hosts.yml as load_test.go builds them, host "web1"
	fsys["modules/demo.yml"] = &fstest.MapFile{Data: []byte("enabled: false\nact_enabled: true\nauto: [harden]\nlevel: 3\n")}
	fsys["modules/other.yml"] = &fstest.MapFile{Data: []byte("level: 1\n")}
	m, err := Load(fsys, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b := m.Modules["demo"]
	if b.Enabled == nil || *b.Enabled || !b.ActEnabled || !slices.Equal(b.Auto, []string{"harden"}) {
		t.Fatalf("block %+v", b)
	}
	if m.Modules["other"].Enabled != nil {
		t.Fatal("absent enabled must be nil")
	}
	var cfg struct {
		module.Common `yaml:",inline"`
		Level         int `yaml:"level"`
	}
	if err := b.Decode(&cfg); err != nil || cfg.Level != 3 || !cfg.ActEnabled {
		t.Fatalf("decode %+v %v", cfg, err)
	}
	var strict struct {
		Level int `yaml:"level"`
	}
	if b.Decode(&strict) == nil {
		t.Fatal("unknown keys accepted")
	}
}
func TestModuleBlockBadFileName(t *testing.T) {
	fsys := minimalManifestFS()
	fsys["modules/Demo.yaml"] = &fstest.MapFile{Data: []byte("{}")}
	if _, err := Load(fsys, Options{}); err == nil {
		t.Fatal("bad file name accepted")
	}
}
func TestModuleEnabledPrecedence(t *testing.T) {
	fsys := minimalManifestFS() // hosts.yml gives web1 `modules: {demo: true}` and `labels: [linux, web]`
	fsys["modules/demo.yml"] = &fstest.MapFile{Data: []byte("enabled: false\n")}
	m, _ := Load(fsys, Options{})
	if !m.ModuleEnabled("web1", "demo", false) {
		t.Fatal("host entry must win")
	}
	if m.ModuleEnabled("db1", "demo", true) {
		t.Fatal("block false must beat default true")
	}
	if !m.ModuleEnabled("db1", "absent", true) {
		t.Fatal("default applies without a block")
	}
}

// labels_test.go
func TestParseLabels(t *testing.T) {
	cases := []struct {
		expr   string
		labels []string
		want   bool
	}{
		{"linux && !workstation", []string{"linux", "server"}, true},
		{"linux && !workstation", []string{"linux", "workstation"}, false},
		{"(a || b) && c", []string{"b", "c"}, true},
		{"a || b && c", []string{"a"}, true},
		{"!a", nil, true},
	}
	for _, c := range cases {
		e, err := ParseLabels(c.expr)
		if err != nil || e.Match(c.labels) != c.want {
			t.Errorf("%q %v: %v", c.expr, c.labels, err)
		}
	}
	for _, bad := range []string{"", "a &&", "a b", "!(", "a & b", strings.Repeat("a", 257)} {
		if _, err := ParseLabels(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/manifest/ -run 'Module|Labels' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified (a small recursive-descent parser for labels). Add `modules` (object of booleans) and `labels` (array of strings) to `hosts.yml.schema.json`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/manifest/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "manifest: module blocks, host modules and labels, label expressions"`

---

### Task 11a: `manifest.AppendOverrides` and `Overrides.LearnedListeners`

Haiku-sized. `Host` has no way to write `overrides.yml` (the design: "event-specific values are entered in the UI and written to `overrides.yml`"). This is the one writer; Task 17a hands it to modules as `Host.UpdateOverrides`. W4 (`rule_modes`, `exceptions`), W6 (`learned_listeners`, `egress.allow`) and the UI add their own `Overrides` fields and call it.

**Files:**
- Create: `internal/manifest/overrides_write.go`
- Modify: `internal/manifest/types.go` (`Overrides.LearnedListeners`, `LearnedListener`), `internal/manifest/validate.go` (validate the new entries)
- Test: `internal/manifest/overrides_write_test.go`

**Interfaces:**
- Consumes: the built `Overrides`, `LoadDir`, `internal/atomicfile`.
- Produces:

```go
// reads dir/overrides.yml (absent: empty), applies fn, validates (the same rules LoadDir applies), writes atomically,
// mode 0600 kept (0600 for a new file). On any error the file is unchanged.
func AppendOverrides(dir string, fn func(*Overrides) error) error

type LearnedListener struct { // a port on which scorer traffic was seen arriving: rendered into the `learned` group (any source)
	Host     string `yaml:"host" json:"host"`
	Proto    string `yaml:"proto" json:"proto"` // tcp | udp
	Port     uint16 `yaml:"port" json:"port"`
	Reason   string `yaml:"reason" json:"reason"`
	Observed string `yaml:"observed" json:"observed"` // RFC 3339, UTC
}
// Overrides gains: LearnedListeners []LearnedListener `yaml:"learned_listeners,omitempty" json:"learned_listeners,omitempty"`
```

Rules: a `LearnedListener` needs `host`, `proto` (`tcp` or `udp`), `port` 1 to 65535, `reason` and a parseable `observed`; a second entry with the same host, proto and port is a validation error (the caller checks first). `shortcut: AppendOverrides rewrites the file from the struct, so comments in overrides.yml are lost; upgrade to a yaml.Node round trip if operators hand-edit it`. A process-wide mutex serialises writers in one controller.

- [ ] **Step 1: Write the failing tests:**

```go
func TestAppendOverridesAtomicAndValidated(t *testing.T) {
	dir := t.TempDir()
	ll := LearnedListener{Host: "h1", Proto: "tcp", Port: 8081, Reason: "scorer traffic seen", Observed: "2027-02-06T15:04:05Z"}
	if err := AppendOverrides(dir, func(o *Overrides) error { o.LearnedListeners = append(o.LearnedListeners, ll); return nil }); err != nil {
		t.Fatal(err)
	}
	m, err := LoadDir(dir, Options{}) // or the overrides-only loader of load.go
	if err != nil || len(m.Overrides.LearnedListeners) != 1 || m.Overrides.LearnedListeners[0] != ll {
		t.Fatalf("%+v %v", m.Overrides, err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "overrides.yml"))
	bad := ll
	bad.Reason = ""
	if err := AppendOverrides(dir, func(o *Overrides) error { o.LearnedListeners = append(o.LearnedListeners, bad); return nil }); err == nil {
		t.Fatal("entry without a reason accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "overrides.yml"))
	if !bytes.Equal(before, after) {
		t.Fatal("a rejected write changed the file")
	}
}
func TestAppendOverridesFnErrorLeavesFile(t *testing.T) {
	// fn returns errors.New("no"): AppendOverrides returns it (errors.Is) and no file is created in an empty dir
}
func TestAppendOverridesKeepsMode(t *testing.T) {
	// existing overrides.yml mode 0600 stays 0600; a new file is 0600
}
func TestAppendOverridesConcurrent(t *testing.T) {
	// 20 goroutines each append one distinct LearnedListener port; afterwards the file holds 20 entries (race-clean)
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/manifest/ -run AppendOverrides -v`. Expected: FAIL (`unimplemented: W1 Task 11a`).
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/manifest/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "manifest: AppendOverrides and learned listeners"`

---

### Task 11b: Per-host switches in `overrides.yml`: `act` and `safe_mode_hosts` (R2)

Haiku-sized. The design (Configuration: per-host switches) puts the per-host form of `act_enabled` and of safe mode in `overrides.yml`, because the module block is frozen with the repository: `act: { <module>: [<label expression>] }` and `safe_mode_hosts: [<label expression>]`. W1 owns the schema, the validation and the two resolver methods; W4 renders the effective `act_enabled` into each host's `AgentConfig` and the Settings page edits the lists. Nothing here sends a control message: `RunAuto` (Task 26) reads `ActEnabled`, and the existing per-host `SetSafeMode` stays the way W2 turns safe mode off for a host.

**Files:**
- Modify: `internal/manifest/types.go` (`Overrides.Act`, `Overrides.SafeModeHosts`), `internal/manifest/validate.go`, `internal/manifest/modules.go`
- Test: `internal/manifest/act_test.go`

**Interfaces:**
- Consumes: `ParseLabels`, `LabelExpr.Match`, `ModuleBlock.ActEnabled` (Task 11), `AppendOverrides` (Task 11a).
- Produces:

```go
// Overrides gains:
Act           map[string][]string `yaml:"act,omitempty" json:"act,omitempty"`                         // module name -> label expressions
SafeModeHosts []string            `yaml:"safe_mode_hosts,omitempty" json:"safe_mode_hosts,omitempty"` // label expressions

// ActEnabled is the effective act switch of a module on a host: the module block's act_enabled, or a match of any
// expression listed under the module in Overrides.Act. An overrides entry only adds hosts; it never turns off a module
// whose block says true. A host matches on its labels plus its own name (an implicit label), so a single host is named by its name.
func (m *Manifest) ActEnabled(host, module string) bool

// SafeModeHostSet returns the sorted host names matching any Overrides.SafeModeHosts expression.
func (m *Manifest) SafeModeHostSet() []string
```

Rules: a key of `Act` must match `^[a-z][a-z0-9_]*$` and name a module block that exists in `m.Modules` or a module registered in `module.Registered()` is not checked here (the manifest package must not import `module`; `phylax manifest lint` reports an `act` key without a `modules/<name>.yml`); every expression must parse with `ParseLabels`; at most 64 expressions per module and 64 in `safe_mode_hosts`; an expression that matches no host is a lint warning (`RuleOverridesNoHost`, severity warn), not a load error, so a typo is visible but the file still loads. `shortcut: act can only add hosts, upgrade if an operator needs to switch a module off for one host while its block says on (use safe mode meanwhile)`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestActEnabledPerHost(t *testing.T) {
	m := actFixture(t) // hosts web1 (labels linux, web) and db1 (linux, db); modules/respond.yml has act_enabled: false, modules/firewall.yml has act_enabled: true
	m.Overrides.Act = map[string][]string{"respond": {"web1"}, "hardening": {"linux && !db"}}
	cases := []struct {
		host, module string
		want         bool
	}{{"web1", "respond", true}, {"db1", "respond", false}, {"web1", "hardening", true}, {"db1", "hardening", false},
		{"db1", "firewall", true}, {"web1", "absent", false}}
	for _, c := range cases {
		if got := m.ActEnabled(c.host, c.module); got != c.want {
			t.Errorf("%s/%s: got %v", c.host, c.module, got)
		}
	}
}
func TestSafeModeHostSet(t *testing.T) {
	m := actFixture(t)
	m.Overrides.SafeModeHosts = []string{"db", "web1"}
	if got := m.SafeModeHostSet(); !slices.Equal(got, []string{"db1", "web1"}) {
		t.Fatalf("%v", got)
	}
}
func TestOverridesActValidated(t *testing.T) {
	dir := t.TempDir()
	bad := []func(*Overrides){
		func(o *Overrides) { o.Act = map[string][]string{"Respond": {"web1"}} },
		func(o *Overrides) { o.Act = map[string][]string{"respond": {"a &&"}} },
		func(o *Overrides) { o.SafeModeHosts = []string{"a b"} },
		func(o *Overrides) { o.Act = map[string][]string{"respond": make([]string, 65)} },
	}
	for i, f := range bad {
		if err := AppendOverrides(dir, func(o *Overrides) error { f(o); return nil }); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	ok := func(o *Overrides) error { o.Act = map[string][]string{"respond": {"web1"}}; o.SafeModeHosts = []string{"web1"}; return nil }
	if err := AppendOverrides(dir, ok); err != nil {
		t.Fatal(err)
	}
}
func TestOverridesActNoHostIsLintWarning(t *testing.T) {
	// act: {respond: [nosuchlabel]} loads; Lint(m) contains a RuleOverridesNoHost finding with SevWarn naming "respond"
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/manifest/ -run 'ActEnabled|SafeModeHostSet|OverridesAct' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified (use `HostsMatching` plus the implicit host-name label).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/manifest/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "manifest: per-host act and safe_mode_hosts in overrides"`

---

### Task 12: `module.Common` in every agent settings block

**Files:**
- Modify: `internal/plan/agentconfig.go` (`ModuleLimits`, delete `DetectSettings.ActEnabled`, strict decode in `(*ConfigVerifier).Parse`, add `BlockFor`)
- Modify: `internal/agent/mods/doc.go` (`spec`, `subSpec` take `rate float64`), every factory's `Section` in `internal/agent/mods/*.go` (enabled = block non-nil and `Enabled`), `internal/agent/mods/detect.go` (read `s.ActEnabled` from `Common`)
- Modify: `internal/controller/genconfig.go` (every rendered block gets `Enabled: true`)
- Test: `internal/plan/common_test.go`, `internal/agent/mods/enabled_test.go`

**Interfaces:**
- Consumes: `module.Common` (Task 1).
- Produces: `plan.ModuleLimits{module.Common; RatePerSec float64; Burst int}`; `plan.BlockFor(cfg, name) (any, bool)` (stub from Task 1); agent config bodies with unknown fields are refused.

- [ ] **Step 1: Write the failing tests** (Task 1 did not, because they need the `ModuleLimits` change):

```go
// internal/plan/common_test.go
func TestModuleLimitsCarriesCommon(t *testing.T) {
	b, _ := json.Marshal(NetSettings{ModuleLimits: ModuleLimits{Common: module.Common{Enabled: true}}})
	if !bytes.Contains(b, []byte(`"enabled":true`)) || !bytes.Contains(b, []byte(`"act_enabled":false`)) {
		t.Fatalf("%s", b)
	}
}
func TestConfigParseRejectsUnknownField(t *testing.T) {
	// build the canonical body of a valid AgentConfig for host "h1", then add the key "x_typo": 1
	// inside modules.net; sign it with configSigningBytes and an ed25519 key; wrap as *link.Config
	// v := &ConfigVerifier{Key: pub, HostID: "h1", Store: <mem store as agentconfig_test.go uses>}
	// v.Parse(w) -> non-nil error mentioning "x_typo"
}
func TestBlockFor(t *testing.T) {
	cfg := &AgentConfig{Modules: ModuleSettings{Net: &NetSettings{}}}
	if b, ok := BlockFor(cfg, "net"); !ok || b.(*NetSettings) == nil {
		t.Fatal("net")
	}
	if b, ok := BlockFor(cfg, "audit"); !ok || b.(*AuditSettings) != nil {
		t.Fatal("absent block must be a typed nil")
	}
	if _, ok := BlockFor(cfg, "nope"); ok {
		t.Fatal("unknown module")
	}
}

// internal/agent/mods/enabled_test.go
func TestSectionHonoursEnabled(t *testing.T) {
	// for each registered factory except "health": a config whose block for it is present with
	// Enabled false -> Section reports enabled == false; with Enabled true -> enabled == true
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/plan/ ./internal/agent/mods/ -run 'Common|Unknown|BlockFor|Enabled' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `BlockFor` finds the `ModuleSettings` field whose json tag name equals `name` by reflection. `Parse` decodes the body with `DisallowUnknownFields`. `health` stays on when its block is nil (core module). Update existing tests that build settings literals.
- [ ] **Step 4: Run, expect PASS.** Run: `make test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "plan: module.Common in every agent settings block; strict config decode"`

---

### Task 13: Agent factory manifest, health reporter, kind-filtered subscribe

**Files:**
- Modify: `internal/agent/registry.go` (`Factory.Manifest`, `RegisterFactory` validation, `Env` carries the module name and `Consumes`, `Subscribe(buf, kinds...)`), `internal/agent/module.go` (`HealthReporter`, `(*Supervisor).Health`), `internal/agent/config.go` (`reconcile` sets the per-factory `Env` fields)
- Test: `internal/agent/contract_test.go`

**Interfaces:**
- Consumes: `module.Manifest`, `module.Health` (Task 1), `(Manifest).Validate` (Task 7).
- Produces: `Factory.Manifest`; `HealthReporter`; `(*Supervisor).Health(name) (module.Health, bool)`; `Env.Subscribe(buf int, kinds ...string)`.

Rules: `RegisterFactory` panics when `Manifest.Name` is set and differs from `Name` or fails `Validate`. Supervisor state mapping: `ok`→`ok`, `starting`→`degraded` (Detail `starting`), `restarting`→`restarting`, `over_budget`→`over_budget`, `stopped`→`disabled`. `Usage.Events` = `Emitted`, `Usage.Dropped` = `RateDropped + SpoolDrops`. With a `HealthReporter`, its `State` wins unless the supervisor says `restarting` or `over_budget`; its `Detail`, `Gaps`, `Info`, `CPUMillis`, `HeldBytes`, `BytesOut` are copied. `Subscribe` with no kinds delivers every kind (pre-contract modules); with kinds, only those; a kind outside the factory's `Manifest.Consumes` (when the manifest is set) is dropped from the filter and logged once.

- [ ] **Step 1: Remove the skips:**

```go
type hrMod struct{}

func (hrMod) Name() string                                   { return "hr" }
func (hrMod) Start(ctx context.Context, emit Emit) error     { <-ctx.Done(); return nil }
func (hrMod) Health() module.Health {
	return module.Health{State: module.StateDegraded, Gaps: []module.Gap{{What: "x", Why: "y"}}, Info: map[string]string{"rules_hash": "abc"}}
}

func TestSupervisorHealthMergesReporter(t *testing.T) {
	s := NewSupervisor(SupervisorOptions{Emit: func(event.Event) error { return nil }})
	_ = s.Add(ModuleSpec{Module: hrMod{}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	// poll up to 2 s: h, ok := s.Health("hr")
	// want ok, h.State == module.StateDegraded, h.Info["rules_hash"] == "abc", len(h.Gaps) == 1
}
func TestRegisterFactoryValidatesManifest(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("name mismatch accepted")
		}
	}()
	RegisterFactory(Factory{Name: "zz1", Manifest: module.Manifest{Name: "zz2", Sides: []module.Side{module.SideAgent}, Privilege: "root"},
		Section: func(*plan.AgentConfig) (string, bool) { return "", false }, Build: func(Env, *plan.AgentConfig) (ModuleSpec, error) { return ModuleSpec{}, nil }})
}
func TestSubscribeKindFilter(t *testing.T) {
	// build a test agent (testutil_test.go); env := agent env for a factory whose Manifest.Consumes = ["k1"]
	// ch, stop := env.Subscribe(8, "k1", "k2")
	// publish events of kind k1, k2, k3
	// want: ch yields exactly one event, kind k1
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/agent/ -run 'Health|RegisterFactory|Subscribe' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified. Existing callers `env.Subscribe(1024)` compile unchanged.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/agent/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "agent: factory manifests, HealthReporter, kind-filtered subscribe"`

---

### Task 14: Heartbeat health blocks and `hello` manifests

**Files:**
- Modify: `internal/link/message.go` (`Heartbeat.Health`, bounds in `Validate`), `internal/agent/agent.go` (`heartbeat` fills `Health`; `hello` `Caps["modules"]`), `internal/controller/agent.go` (keep the latest per agent), new `internal/controller/health.go` (`AgentHealth`)
- Test: `internal/link/heartbeat_test.go`, `internal/controller/health_test.go`

**Interfaces:**
- Consumes: `(*Supervisor).Health` (Task 13); config status (`ConfigStatus.Modules`).
- Produces: `link.Heartbeat.Health map[string]module.Health` (`json:"health,omitempty"`); `(*Controller).AgentHealth(host) map[string]module.Health`; `hello` `Caps["modules"]` = the `[]module.Manifest` of factories with a manifest.

Bounds in `Validate`: at most 256 entries; `Detail` ≤ 1024 bytes; ≤ 32 `Gaps`, each `What`/`Why` ≤ 256; ≤ 32 `Info` entries, keys ≤ 64 and values ≤ 256 bytes. A module whose config status is `unavailable: <why>` appears with `State: unavailable` and `Gaps: [{What: <name>, Why: <why>}]`.

- [ ] **Step 1: Remove the skips:**

```go
// internal/link/heartbeat_test.go
func TestHeartbeatHealthBounds(t *testing.T) {
	ok := &Heartbeat{HostClock: time.Now(), Health: map[string]module.Health{"a": {State: module.StateOK}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	gaps := make([]module.Gap, 33)
	bad := &Heartbeat{HostClock: time.Now(), Health: map[string]module.Health{"a": {State: module.StateOK, Gaps: gaps}}}
	if bad.Validate() == nil {
		t.Fatal("33 gaps accepted")
	}
}
// internal/controller/health_test.go
func TestAgentHealthFromHeartbeat(t *testing.T) {
	// with the e2e helpers (newCtl and a real agent): register a factory whose module implements
	// HealthReporter with Info {"rules_hash": "abc"}; enable it in the config; wait for two heartbeats
	// want: c.AgentHealth(host)[name].Info["rules_hash"] == "abc"
	// and an unavailable module (Build returns ErrUnavailable) shows State unavailable with one Gap
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/link/ ./internal/controller/ -run 'HeartbeatHealth|AgentHealth' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified; keep `Heartbeat.Modules` (the config status key `config` and the state strings) unchanged.
- [ ] **Step 4: Run, expect PASS.** Run: `make test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "link: per-module health in heartbeats; module manifests in hello"`

---

### Task 15: Agent harness

**Files:**
- Modify: `internal/agent/harness.go`; `internal/agent/agent.go` (`emit` writes to a harness sink when the agent has no spool)
- Test: `internal/agent/harness_test.go`

**Interfaces:**
- Consumes: `reconcile`, `Supervisor`, `publish`, `subscribe`, `kept` (built); `Supervisor.Health` (Task 13).
- Produces: `HarnessOptions`, `Harness`, `NewHarness`, `Apply`, `Run`, `Publish`, `Emitted`, `Health`, `Kept` (Task 1 signatures). `Fact` is a stub until Task 31.

The harness is a real `*Agent` built without link, spool or identity: its supervisor's emit appends to an in-memory list (bounded to 100 000 events, oldest dropped) after calling `EmitErr`; `Apply` runs the real `reconcile` over `Factories` only; `Health` returns the supervisor health, or for a module the config status marks `unavailable: why`, `State: unavailable` with that gap.

- [ ] **Step 1: Remove the skips:**

```go
func harnessFactory(build func(Env, *plan.AgentConfig) (ModuleSpec, error)) Factory {
	return Factory{Name: "hx", Section: func(*plan.AgentConfig) (string, bool) { return "v1", true }, Build: build}
}

type oneShot struct{}

func (oneShot) Name() string { return "hx" }
func (oneShot) Start(ctx context.Context, emit Emit) error {
	_ = emit(event.Event{Kind: "hx.x"})
	<-ctx.Done()
	return nil
}

func TestHarnessRunsFactory(t *testing.T) {
	h, err := NewHarness(HarnessOptions{Host: "h1", StateDir: t.TempDir(), Factories: []Factory{harnessFactory(func(Env, *plan.AgentConfig) (ModuleSpec, error) {
		return ModuleSpec{Module: oneShot{}}, nil
	})}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)
	h.Apply(&plan.AgentConfig{Host: "h1"})
	// poll up to 2 s: len(h.Emitted()) == 1 && h.Emitted()[0].Kind == "hx.x"; h.Health("hx").State == module.StateOK
}
func TestHarnessUnavailable(t *testing.T) {
	h, _ := NewHarness(HarnessOptions{Host: "h1", StateDir: t.TempDir(), Factories: []Factory{harnessFactory(func(Env, *plan.AgentConfig) (ModuleSpec, error) {
		return ModuleSpec{}, fmt.Errorf("%w: needs linux", ErrUnavailable)
	})}})
	h.Apply(&plan.AgentConfig{Host: "h1"})
	hl, ok := h.Health("hx")
	if !ok || hl.State != module.StateUnavailable || len(hl.Gaps) != 1 {
		t.Fatalf("%+v %v", hl, ok)
	}
}
func TestHarnessEmitErr(t *testing.T) {
	got := make(chan error, 1)
	h, _ := NewHarness(HarnessOptions{Host: "h1", StateDir: t.TempDir(), EmitErr: func() error { return errors.New("link down") },
		Factories: []Factory{harnessFactory(func(Env, *plan.AgentConfig) (ModuleSpec, error) {
			return ModuleSpec{Module: emitOnce{got}}, nil // emitOnce sends emit's error on got
		})}})
	// run, apply; want <-got != nil within 2 s
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/agent/ -run Harness -v`. Expected: FAIL (`unimplemented: W1 Task 15`).
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/agent/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "agent: test harness over the real reconciler and supervisor"`

---

### Task 16: Controller-origin event chain

**Files:**
- Create: `internal/controller/chain.go`
- Modify: `internal/controller/controller.go` (`New` ensures the `controller` agent row exists, keyed by the controller identity's public key), `internal/controller/alerts.go` (ingest hook: alert rows for declared alert-class kinds), the `c.alert` function in `internal/controller/agent.go` (also emits declared kinds)
- Test: `internal/controller/chain_test.go`

**Interfaces:**
- Consumes: `event.Lookup`, `event.Validate`; `(*store.Store).Ingest`, `Latest`, `InsertAlertOnce` via `IngestTx`.
- Produces: `(*Controller).EmitController(ctx, e) (event.Event, error)`.

Rules: `EmitController` sets `Agent = "controller"`, `Time = now` when zero, requires `event.Validate(e) == nil`, seals from the stored head of agent `controller` and ingests, under one mutex. The ingest hook adds an alert row (rule = kind, host = `fields.host` when present else the agent) for an event whose kind is declared with `Alert: true` and whose priority is `PriorityHigh` or `PriorityCritical`; `detect.alert` keeps its existing path (it is declared by W4). `c.alert(host, kind, detail)` also emits an event of `kind` with fields `{host, detail}` when `event.Lookup(kind)` succeeds; undeclared kinds (`store.chain_error`, `config.generate_failed`) stay ring-only.

- [ ] **Step 1: Remove the skips:**

```go
func TestEmitControllerChain(t *testing.T) {
	c := newTestController(t) // controller.New with DataDir t.TempDir(), AgentListen "127.0.0.1:0", UIListen "off"
	e1, err := c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	if err != nil {
		t.Fatal(err)
	}
	e2, _ := c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h2"}))
	if e1.Agent != "controller" || e1.Seq != 1 || e2.Seq != 2 || e2.PrevHash != e1.Hash {
		t.Fatalf("%+v %+v", e1, e2)
	}
}
func TestEmitControllerAfterRestart(t *testing.T) {
	dir := t.TempDir()
	c := newTestControllerAt(t, dir)
	_, _ = c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	c.Close()
	c = newTestControllerAt(t, dir)
	e, err := c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	if err != nil || e.Seq != 2 {
		t.Fatalf("seq %d err %v", e.Seq, err)
	}
}
func TestEmitControllerAlertRow(t *testing.T) {
	c := newTestController(t)
	_, _ = c.EmitController(ctx, mustNew(t, "agent.silent", event.AgentSilent{Host: "h1", Detail: "no message"}))
	_, _ = c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	// want: exactly one alert row (list rows with the store method alerts.go uses), rule "agent.silent", host "h1"
}
func TestEmitControllerRejectsUndeclared(t *testing.T) {
	c := newTestController(t)
	if _, err := c.EmitController(ctx, event.Event{Kind: "nope"}); !errors.Is(err, event.ErrUndeclared) {
		t.Fatalf("got %v", err)
	}
}
func TestDeclaredAlertBecomesEvent(t *testing.T) {
	c := newTestController(t)
	c.alert("h1", "agent.silent", "no message for 30s")
	// want: c.st.Latest(ctx, "controller", "agent.silent") returns an event with Fields["host"] == "h1"
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run 'EmitController|DeclaredAlert' -v`. Expected: FAIL (`undefined: EmitController` until Task 1's stub, then `unimplemented`).
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: controller-origin event chain; alert rows from the kind flag"`

---

### Task 17: Controller `Host` (config, query, tables, emit, secrets, UI, logger)

**Files:**
- Modify: `internal/controller/host.go`
- Test: `internal/controller/host_test.go`

**Interfaces:**
- Consumes: `manifest.ModuleBlock` (Task 11), `store.Reader`/`ModuleDB` (Task 8), `vault.Scoped` (Task 9), `(*ui.Server).Registrar`/`ui.Discard` (Task 10), `EmitController` (Task 16).
- Produces: `type moduleHost struct` implementing every `module.Host` method except `Subscribe`, `Propose`, `RunReadOnly`, `RunStanding`, `RunAuto`, `Control` (later tasks) and `Manifest`, `UpdateOverrides` and prefix `Secrets` (Task 17a); `func (c *Controller) hostFor(m module.ControllerModule) *moduleHost`; `var _ module.Host = (*moduleHost)(nil)`.

Rules: `Config` returns `module.ErrNoConfig` without a block, else `block.Decode(v)`. `Tables` errors unless `Manifest().Tables` is non-empty, else `c.st.ModuleDB(name)`. `Emit` refuses (`module.ErrNotInScope`) a kind not in `Manifest().Emits`, forces `Agent = "controller"`, then `EmitController`. `Secrets(names...)` refuses (`vault.ErrNotAllowed`) a name that is not a string value somewhere in the block's YAML, else `vault.Scoped(source, names)` over the controller's vault (`vault.ErrLocked` when none or locked). `UI` is the server's registrar for the module (enabled = the module is running) or `ui.Discard` when the UI is off. `Logger` is the controller logger with `module=<name>`.

- [ ] **Step 1: Remove the skips:**

```go
func init() {
	event.Declare(event.Type{Kind: "ctltest.found", Schema: 1, Priority: event.PriorityNormal, Fields: struct {
		X string `json:"x"`
	}{}})
}

type ctlMod struct{ m module.Manifest }

func (c ctlMod) Manifest() module.Manifest                    { return c.m }
func (ctlMod) Start(ctx context.Context, _ module.Host) error { <-ctx.Done(); return nil }
func (ctlMod) Health() module.Health                          { return module.Health{State: module.StateOK} }

func testMod() ctlMod {
	return ctlMod{module.Manifest{Name: "ctltest", Sides: []module.Side{module.SideController}, Privilege: "none",
		Emits: []event.Type{{Kind: "ctltest.found", Schema: 1}}, Consumes: []string{"agent.resumed"}}}
}

func TestHostConfigStrict(t *testing.T) {
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\nlevel: 2\ndb: ecom.db\n"})
	h := c.hostFor(testMod())
	var cfg struct {
		module.Common `yaml:",inline"`
		Level         int    `yaml:"level"`
		DB            string `yaml:"db"`
	}
	if err := h.Config(&cfg); err != nil || cfg.Level != 2 {
		t.Fatalf("%+v %v", cfg, err)
	}
	var strict struct {
		Level int `yaml:"level"`
	}
	if h.Config(&strict) == nil {
		t.Fatal("unknown keys accepted")
	}
	other := testMod()
	other.m.Name = "nocfg"
	if err := c.hostFor(other).Config(&strict); !errors.Is(err, module.ErrNoConfig) {
		t.Fatalf("got %v", err)
	}
}
func TestHostEmitOnlyManifestKinds(t *testing.T) {
	c := newTestControllerWithManifest(t, nil)
	h := c.hostFor(testMod())
	e, _ := event.New("ctltest.found", struct {
		X string `json:"x"`
	}{"y"})
	e.Agent = "spoofed"
	if err := h.Emit(e); err != nil {
		t.Fatal(err)
	}
	got, _ := c.st.Latest(ctx, "controller", "ctltest.found")
	if got.Agent != "controller" {
		t.Fatal("agent not forced")
	}
	r, _ := event.New("agent.resumed", event.AgentResumed{Host: "h"})
	if err := h.Emit(r); !errors.Is(err, module.ErrNotInScope) {
		t.Fatalf("got %v", err)
	}
}
func TestHostSecretsScoped(t *testing.T) {
	// controller with an unlocked test vault holding "ecom.db" and "other"; block as in TestHostConfigStrict
	// h.Secrets("ecom.db") -> reader; Get("ecom.db") ok
	// h.Secrets("other") -> errors.Is(err, vault.ErrNotAllowed)
}
func TestHostTablesNeedDeclaration(t *testing.T) {
	c := newTestControllerWithManifest(t, nil)
	if _, err := c.hostFor(testMod()).Tables(); err == nil {
		t.Fatal("tables without declaration")
	}
	m := testMod()
	m.m.Tables = []string{"ctltest_rows"}
	if _, err := c.hostFor(m).Tables(); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run TestHost -v`. Expected: FAIL (`unimplemented: W1 Task 17`).
- [ ] **Step 3: Implement** as specified; the unimplemented methods keep their Task 1 stubs.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: module Host (config, query, tables, emit, secrets, ui)"`

---

### Task 17a: `Host.Manifest`, `Host.UpdateOverrides` and prefix secrets

Haiku-sized. Three things modules need from `Host` that Task 17 left out: the loaded manifest (W6's shadow verdict, egress allow table, device inventory and W11's `Stage` all read it), a write path to `overrides.yml` (W6 `learned_listeners`), and per-device vault keys through `Host.Secrets` (Task 9a prefix grants).

**Files:**
- Modify: `internal/controller/host.go`, `internal/module/host.go` (the two methods are already on the interface from Task 1)
- Test: `internal/controller/host_ext_test.go`

**Interfaces:**
- Consumes: Task 11a `manifest.AppendOverrides`, Task 9a `vault.Covers`, Task 17 `moduleHost`, the controller's loaded `*manifest.Manifest` and manifest directory.
- Produces: `moduleHost.Manifest() *manifest.Manifest` (the controller's current manifest; never nil on a running controller; callers must not mutate it); `moduleHost.UpdateOverrides(fn func(*manifest.Overrides) error) error` (`manifest.AppendOverrides(manifestDir, fn)`, then the controller reloads its manifest so every `Manifest().Overrides` shows the change; a failed write or validation leaves manifest and file unchanged); `Secrets(names...)` accepts a requested name when `vault.Covers(grants, name)` holds, where `grants` are the string values anywhere in the module's block (a value ending `/*` is a prefix grant), and returns `vault.Scoped(source, names)`; a request equal to a prefix grant (`cred/*`) serves the whole prefix.

Rules: `UpdateOverrides` returns `module.ErrNoConfig` for a module without a config block; the write holds the manifest reload lock; the module emits its own event for the change. `shortcut: any module with a config block may write overrides, upgrade to a manifest field (overrides: [learned_listeners]) when a module that must not write appears`.

- [ ] **Step 1: Write the failing tests** (helpers of Task 17):

```go
func TestHostManifestNotNil(t *testing.T) {
	c := newTestControllerWithManifest(t, nil)
	m := c.hostFor(testMod()).Manifest()
	if m == nil || len(m.Hosts) == 0 {
		t.Fatalf("%+v", m)
	}
}
func TestHostUpdateOverridesReloads(t *testing.T) {
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n"})
	h := c.hostFor(testMod())
	err := h.UpdateOverrides(func(o *manifest.Overrides) error {
		o.LearnedListeners = append(o.LearnedListeners, manifest.LearnedListener{Host: "h1", Proto: "tcp", Port: 8081, Reason: "scorer seen", Observed: "2027-02-06T15:04:05Z"})
		return nil
	})
	if err != nil || len(h.Manifest().Overrides.LearnedListeners) != 1 {
		t.Fatalf("%v %+v", err, h.Manifest().Overrides)
	}
	if h2 := c.hostFor(testMod()); len(h2.Manifest().Overrides.LearnedListeners) != 1 {
		t.Fatal("a second host handle does not see the change")
	}
	bad := h.UpdateOverrides(func(o *manifest.Overrides) error { o.LearnedListeners = append(o.LearnedListeners, manifest.LearnedListener{Host: "h1"}); return nil })
	if bad == nil || len(h.Manifest().Overrides.LearnedListeners) != 1 {
		t.Fatal("invalid entry accepted or manifest changed")
	}
}
func TestHostSecretsPrefixGrant(t *testing.T) {
	// block "enabled: true\nsecrets: [cred/*]\n"; unlocked test vault holds "cred/palo1/phylax", "cred/vyos/phylax", "other"
	// h.Secrets("cred/*") -> reader; Get("cred/palo1/phylax") and Get("cred/vyos/phylax") ok; Get("other") -> vault.ErrNotAllowed
	// h.Secrets("cred/palo1/phylax") -> ok (covered by the grant); h.Secrets("other") -> vault.ErrNotAllowed
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run 'HostManifest|HostUpdateOverrides|HostSecretsPrefix' -v`. Expected: FAIL (`unimplemented: W1 Task 17a`).
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: Host.Manifest, Host.UpdateOverrides, prefix secrets"`

---

### Task 18: `Host.Subscribe` over committed events

**Files:**
- Create: `internal/controller/bus.go`
- Modify: `internal/controller/alerts.go` (the ingest hook registers `tx.OnCommit` to publish the batch), `internal/controller/host.go` (`Subscribe`)
- Test: `internal/controller/bus_test.go`

**Interfaces:**
- Consumes: `store.IngestTx.OnCommit` (built), `moduleHost` (Task 17).
- Produces: `(*moduleHost).Subscribe(kinds, buf)`; an unexported `c.bus` with `publish([]event.Event)` and a per-subscriber drop counter readable as `c.bus.dropped(module string) uint64`.

Rules: delivered only after the store commit; channel capacity `buf` (1..65536, default 1024); a full channel drops and counts, never blocks ingest; kinds outside `Manifest().Consumes` are removed from the filter and logged; the cancel function closes nothing the publisher may still send on (remove under the lock, then stop).

- [ ] **Step 1: Remove the skips:**

```go
func TestHostSubscribeCommitted(t *testing.T) {
	c := newTestControllerWithManifest(t, nil)
	h := c.hostFor(testMod()) // Consumes ["agent.resumed"]
	ch, stop := h.Subscribe([]string{"agent.resumed", "agent.silent"}, 8)
	defer stop()
	_, _ = c.EmitController(ctx, mustNew(t, "agent.silent", event.AgentSilent{Host: "h1"}))
	_, _ = c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	select {
	case e := <-ch:
		if e.Kind != "agent.resumed" {
			t.Fatalf("got %s (agent.silent is not in Consumes)", e.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
}
func TestHostSubscribeSlowConsumer(t *testing.T) {
	c := newTestControllerWithManifest(t, nil)
	_, stop := c.hostFor(testMod()).Subscribe([]string{"agent.resumed"}, 1)
	defer stop()
	start := time.Now()
	for i := 0; i < 50; i++ {
		_, _ = c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	}
	if time.Since(start) > 5*time.Second || c.bus.dropped("ctltest") == 0 {
		t.Fatalf("blocked or not counted: %v %d", time.Since(start), c.bus.dropped("ctltest"))
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run TestHostSubscribe -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: committed-event bus for controller modules"`

---

### Task 19: Controller module runner

**Files:**
- Modify: `internal/controller/modules.go`; `cmd/phylax/serve.go` (run `c.RunModules(ctx, module.Registered())` in a goroutine)
- Test: `internal/controller/modules_test.go`

**Interfaces:**
- Consumes: `module.Registered`, `(*manifest.Manifest).ModuleEnabled`, `hostFor` (Task 17), `link.Backoff`.
- Produces: `(*Controller).RunModules(ctx, mods) error`, `(*Controller).ModuleHealth() map[string]module.Health`.

Rules: enablement is `ModuleEnabled(<controller host from topology>, name, Manifest().Default)`; a disabled module never starts and reports `disabled`. An enabled module runs in a goroutine with panic recovery and restart backoff 1 s to 60 s, reset after 30 s of stable running (the agent supervisor's numbers); `ErrNoConfig` from `Start` means `unavailable` with gap `{config, modules/<name>.yml missing}` and no restart; while running, `ModuleHealth` returns the module's `Health()` with `Usage.Dropped` set from the bus drop counter; during backoff `restarting`. `RunModules` returns after `ctx` ends and every module goroutine has exited (each gets 5 s; one that does not exit is reported and abandoned).

- [ ] **Step 1: Remove the skips:**

```go
type flakyMod struct {
	ctlMod
	starts *atomic.Int32
}

func (f flakyMod) Start(ctx context.Context, h module.Host) error {
	if f.starts.Add(1) == 1 {
		panic("first start fails")
	}
	<-ctx.Done()
	return nil
}

func TestRunModulesEnablement(t *testing.T) {
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n", "modules/offmod.yml": "enabled: false\n"})
	off := testMod()
	off.m.Name = "offmod"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.RunModules(ctx, []module.ControllerModule{testMod(), off}) }()
	// poll up to 2 s: c.ModuleHealth()["ctltest"].State == module.StateOK and ["offmod"].State == module.StateDisabled
	cancel()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("RunModules did not return")
	}
}
func TestRunModulesRestartsAfterPanic(t *testing.T) {
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n"})
	c.modBackoffMin = 10 * time.Millisecond // unexported knob for tests
	f := flakyMod{testMod(), new(atomic.Int32)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.RunModules(ctx, []module.ControllerModule{f})
	// poll up to 3 s: f.starts.Load() == 2 && c.ModuleHealth()["ctltest"].State == module.StateOK
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run RunModules -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: module runner with restart backoff and health"`

---

### Task 20: Analysis worker

**Files:**
- Create: `internal/controller/analysis.go`
- Modify: `internal/controller/modules.go` (start the worker for modules implementing `module.AnalyzerProvider`)
- Test: `internal/controller/analysis_test.go`

**Interfaces:**
- Consumes: `moduleHost.Subscribe` (Task 18), `moduleHost.Emit` (Task 17), `module.Analyzer`.
- Produces: analysers run on trigger (committed `Inputs` events, debounced 1 s) and every `Every`; each run under `context.WithTimeout(ctx, c.analysisDeadline)` (default 10 s); outputs emitted through the module's `Host.Emit`; a run that errors or overruns emits nothing and adds the gap `{analyser <name>, <error or "run exceeded 10s">}` to the module's health until the next good run.

- [ ] **Step 1: Remove the skips:**

```go
type anaMod struct {
	ctlMod
	as []module.Analyzer
}

func (a anaMod) Analyzers() []module.Analyzer { return a.as }

func TestAnalyzerTriggeredByInput(t *testing.T) {
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n"})
	m := anaMod{testMod(), []module.Analyzer{{Name: "count", Inputs: []string{"agent.resumed"},
		Run: func(ctx context.Context, q store.Reader, now time.Time) ([]event.Event, error) {
			evs, err := q.Events(ctx, store.Query{Kind: "agent.resumed"})
			if err != nil {
				return nil, err
			}
			out, err := event.New("ctltest.found", struct {
				X string `json:"x"`
			}{fmt.Sprint(len(evs))})
			return []event.Event{out}, err
		}}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.RunModules(ctx, []module.ControllerModule{m})
	_, _ = c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	// poll up to 4 s: c.st.Latest(ctx, "controller", "ctltest.found") has Fields["x"] == "1"
}
func TestAnalyzerDeadline(t *testing.T) {
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n"})
	c.analysisDeadline = 100 * time.Millisecond
	m := anaMod{testMod(), []module.Analyzer{{Name: "slow", Every: 50 * time.Millisecond,
		Run: func(ctx context.Context, _ store.Reader, _ time.Time) ([]event.Event, error) { <-ctx.Done(); return nil, ctx.Err() }}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.RunModules(ctx, []module.ControllerModule{m})
	// poll up to 2 s: some gap in c.ModuleHealth()["ctltest"].Gaps has What == "analyser slow"
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run Analyzer -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified. `shortcut: per-module analyser CPU budget is the run deadline only, upgrade when a lab run shows an analyser hogging the worker`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: analysis worker with per-run deadline"`

---

### Task 21: Lint registry and `SS000`

**Files:**
- Modify: `internal/plan/lint/lint.go`
- Create: `internal/plan/lint/ss000.go`
- Test: `internal/plan/lint/lint_test.go`

**Interfaces:**
- Consumes: `plan.Node`, `plan.Plan`, `plan.ApprovalClass` (Task 1); `actions.Registry.Get`, `Spec().Validate(params)`, `Action.Touches`.
- Produces: `Register`, `Rules`, `Run`, `Finding`, `Ctx`, `Rule`; rule `SS000` registered from `init`.

`SS000` applies when `Ctx.Class` is `auto_readonly` (no finding for any other class). A node passes only if it is not a gate, its action exists, `Spec().ReadOnly`, `Risk == RiskNone`, `Touches(params)` is empty and the action is not `host.exec`. The auto-plan rule is its own id, `SS010` (file `ss010.go`, design M5): it applies when `Ctx.Class` is `auto`, and a node is refused if its action is unknown, `host.exec`, of risk `destructive`, or in the click-only set `proc.kill_tree`, `ad.account.krbtgt_reset`, `palo.revert`, `backup.restore` (the set is a package variable `ClickOnly`). Finding messages name the condition.

- [ ] **Step 1: Remove the skips:**

```go
func node(id, action string, params map[string]any) plan.Node {
	return plan.Node{ID: id, Action: action, Target: "h1", Params: params}
}
func TestRegisterRejectsBadAndDuplicate(t *testing.T) {
	for _, id := range []string{"X1", "ss001", "SS0001", "SS000"} { // SS000 is already registered
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s accepted", id)
				}
			}()
			Register(Rule{ID: id, Check: func(plan.Node, Ctx) []Finding { return nil }})
		}()
	}
}
func TestSS000ReadOnly(t *testing.T) {
	reg := actions.Core()
	ro := plan.Plan{Nodes: []plan.Node{node("p", "net.tcp_probe", /* params net.tcp_probe's Spec declares, e.g. */ map[string]any{"host": "127.0.0.1", "port": 22})}}
	if f := Run(ro, Ctx{Class: plan.ClassAutoReadOnly, Actions: reg}); len(f) != 0 {
		t.Fatalf("read-only plan refused: %v", f)
	}
	w := plan.Plan{Nodes: []plan.Node{node("w", "file.write", map[string]any{"path": "/tmp/x", "content": "y"})}}
	f := Run(w, Ctx{Class: plan.ClassAutoReadOnly, Actions: reg})
	if len(f) != 1 || f[0].Rule != "SS000" || f[0].Node != "w" {
		t.Fatalf("write not refused: %v", f)
	}
	if len(Run(w, Ctx{Class: plan.ClassClick, Actions: reg})) != 0 {
		t.Fatal("SS000 must not apply to click plans")
	}
}
func TestSS010AutoRefusesClickOnly(t *testing.T) {
	reg := actions.Core()
	p := plan.Plan{Nodes: []plan.Node{node("x", "host.exec", map[string]any{"argv": []any{"/bin/true"}})}}
	f := Run(p, Ctx{Class: plan.ClassAuto, Actions: reg})
	if len(f) == 0 || f[0].Rule != "SS010" {
		t.Fatal("host.exec allowed in an auto plan, or reported under the wrong id")
	}
}
func TestRulesSorted(t *testing.T) {
	ids := []string{}
	for _, r := range Rules() {
		ids = append(ids, r.ID)
	}
	if !slices.IsSorted(ids) || !slices.Contains(ids, "SS000") || !slices.Contains(ids, "SS010") {
		t.Fatal(ids)
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/plan/lint/ -v`. Expected: FAIL (`unimplemented: W1 Task 21`).
- [ ] **Step 3: Implement** as specified (params for the test actions: read their `Spec().Params` and use valid values).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/plan/lint/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "lint: rule registry and SS000"`

---

### Task 22: Approval class on plans and steps; template parameters

**Files:**
- Modify: `internal/plan/plan.go` (`Plan.Class`, `Module`, `Template`, `Approver`), `internal/plan/step.go` (`StepBody.Class`; `Signer.Issue` copies the plan's class), `internal/plan/template.go` (`ExpandTemplate`), `internal/controller/plantemplates.go` (accept `module:`; add `LoadModuleTemplate`)
- Test: `internal/plan/template_test.go`, `internal/plan/class_test.go`, `internal/controller/plantemplates_module_test.go`

**Interfaces:**
- Consumes: built `Plan`, `Node`, `StepBody`, `Signer`, `Verifier`, `ParseTemplate`, `LoadTemplate`.
- Produces: `Plan.Class/Module/Template/Approver`; `StepBody.Class`; `ExpandTemplate(p, params) (Plan, error)`; `func LoadModuleTemplate(plansRoot, mod, name string) (plan.Plan, error)` in `internal/controller`.

`ExpandTemplate` replaces `${name}` (name `^[a-z][a-z0-9_]{0,31}$`) in every node's `Target` and in every string inside `Params` (recursing into maps and slices); errors on a placeholder without a parameter, on a parameter that no placeholder uses (except the reserved `trigger`), and on a parameter value containing `${`. `LoadModuleTemplate` loads from `plansRoot/<mod>/` and errors unless the template's `module:` equals `mod`.

- [ ] **Step 1: Remove the skips:**

```go
// internal/plan/template_test.go
func TestExpandTemplate(t *testing.T) {
	p := Plan{ID: "t", Nodes: []Node{{ID: "a", Action: "file.hash", Target: "${host}", Params: map[string]any{"path": "/srv/${f}", "list": []any{"${f}", 3}}}}}
	got, err := ExpandTemplate(p, map[string]string{"host": "h1", "f": "x", "trigger": "h1:7"})
	if err != nil {
		t.Fatal(err)
	}
	n := got.Nodes[0]
	if n.Target != "h1" || n.Params["path"] != "/srv/x" || n.Params["list"].([]any)[0] != "x" {
		t.Fatalf("%+v", n)
	}
	if p.Nodes[0].Target != "${host}" {
		t.Fatal("input plan modified")
	}
	for i, params := range []map[string]string{{"host": "h1"}, {"host": "h1", "f": "x", "extra": "1"}, {"host": "h1", "f": "${x}"}} {
		if _, err := ExpandTemplate(p, params); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
// internal/plan/class_test.go
func TestStepSignatureCoversClass(t *testing.T) {
	// issue a step with the test signer of step_test.go for a plan with Class: ClassAuto
	// want: step.Class == ClassAuto; Verify ok
	// set step.Class = ClassClick; Verify -> error
}
// internal/controller/plantemplates_module_test.go
func TestLoadModuleTemplateChecksModule(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "demo"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "demo", "ok.yml"), []byte("id: ok\nmodule: demo\non_failure: stop_dependents\nnodes: []\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "demo", "bad.yml"), []byte("id: bad\nmodule: other\non_failure: stop_dependents\nnodes: []\n"), 0o644)
	if p, err := LoadModuleTemplate(root, "demo", "ok"); err != nil || p.Module != "demo" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := LoadModuleTemplate(root, "demo", "bad"); err == nil {
		t.Fatal("foreign module accepted")
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/plan/ ./internal/controller/ -run 'Expand|Class|ModuleTemplate' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified. Adding `Class` to `StepBody` changes the signed bytes of new steps only.
- [ ] **Step 4: Run, expect PASS.** Run: `make test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "plan: approval class on plans and steps; template parameters"`

---

### Task 22a: Plan option `expires_after`

Haiku-sized, but touches the agent exec path: read `internal/agent/exec.go` and `internal/deadman` first. The design (Execution engine: Expiry) resolves the primitive as the dead-man's machinery with the confirm turned off, so it fires with the controller gone. W6 `egress` (`patch_window`), W4 `respond` source blocks and W11 depot misses use it.

**Files:**
- Modify: `internal/plan/plan.go` (`Node.ExpiresAfterSec`, validation), `internal/plan/step.go` (`StepBody.ExpiresAfterSec`, copied by `Signer.Issue`), `internal/controller/plantemplates.go` (`ParseTemplate`: key `expires_after: 30m` becomes `expires_after_sec`), `internal/controller/plans.go` (no `deadman_confirm` for such a node; refuse on a controller-side action), `internal/agent/exec.go` (apply path)
- Test: `internal/plan/expiry_test.go`, `internal/controller/expiry_test.go`, `internal/agent/expiry_test.go`

**Interfaces:**
- Consumes: built `Node`, `StepBody`, `Signer.Issue`, `deadman.Manager.Arm`/`Fire`, `actions.Request.Deadman`, `x.fresh` in the agent's apply path, `ParseTemplate`.
- Produces: `Node.ExpiresAfterSec int "expires_after_sec,omitempty"` and `StepBody.ExpiresAfterSec` (covered by the signature); `func translateNodeKeys(generic any) error` in `plantemplates.go` (the one place YAML sugar becomes JSON keys; Task 27a and W7 add their keys to it).

Rules: `ExpiresAfterSec` is 0 (off) or 60 to 86400; not allowed on a gate node; not allowed on a node whose action is `Runs: RunsController` (device nodes use the device protocol's own timers; the controller refuses at plan creation with `expires_after: controller-side action`). In a template `expires_after` is a Go duration string (`30m`). On the agent, an apply step with `ExpiresAfterSec > 0` sets `req.Deadman = ExpiresAfter`, skips the fresh-connection check, and the controller sends no `deadman_confirm` for the node; when the action produced no rollback data (`out.DeadmanID == ""`) the step fails with `expires_after: action has no undo` and nothing remains applied. When the entry fires (timer or `phylax agent rollback <id>`), the agent reports an `agent.step_result` with phase `expire` and the node and plan ids from the entry. A new apply of the same node replaces the armed record (extend); a `step_status` cancellation removes it. Safe mode never prevents an expiry (same as rollback).

- [ ] **Step 1: Write the failing tests:**

```go
// internal/plan/expiry_test.go
func TestNodeExpiresAfterValidates(t *testing.T) {
	ok := Node{ID: "a", Action: "file.write", Target: "h1", ExpiresAfterSec: 1800}
	if err := validateNode(ok); err != nil {
		t.Fatal(err)
	}
	for i, n := range []Node{
		{ID: "a", Action: "file.write", Target: "h1", ExpiresAfterSec: 30},
		{ID: "a", Action: "file.write", Target: "h1", ExpiresAfterSec: 90000},
		{ID: "g", Gate: true, ExpiresAfterSec: 600},
		{ID: "a", Action: "file.write", Target: "h1", ExpiresAfterSec: -1},
	} {
		if validateNode(n) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
func TestStepSignatureCoversExpiry(t *testing.T) {
	// issue a step for a node with ExpiresAfterSec 1800: step.ExpiresAfterSec == 1800 and Verify ok; set it to 60: Verify -> error
}
// internal/controller/expiry_test.go
func TestTemplateExpiresAfterDuration(t *testing.T) {
	p, err := ParseTemplate([]byte("id: t\nnodes:\n- {id: a, action: file.write, target: h1, params: {path: /tmp/x, content: y}, expires_after: 30m}\n"))
	if err != nil || p.Nodes[0].ExpiresAfterSec != 1800 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := ParseTemplate([]byte("id: t\nnodes:\n- {id: a, action: file.write, target: h1, params: {}, expires_after: soon}\n")); err == nil {
		t.Fatal("bad duration accepted")
	}
}
func TestExpiresAfterRefusedOnControllerAction(t *testing.T) {
	// plan with node {action: ctltest.local (Runs: RunsController), ExpiresAfterSec: 600}: Create -> error containing "controller-side action"
}
// internal/agent/expiry_test.go
func TestExpiryRollsBackWithoutConfirm(t *testing.T) {
	// agent test env with a manifest-free file.write undo (the dead-man test helper of exec_test.go); expireUnit = 10 ms so 60 "seconds" is 600 ms
	// apply step with ExpiresAfterSec 60, no deadman_confirm sent: after 1 s the file has its old content
	// and the harness saw an agent.step_result with Phase "expire" for the node; the armed record is gone
}
func TestExpiryActionWithoutUndoFails(t *testing.T) {
	// a read-only action with ExpiresAfterSec 60: the step result is failed, error contains "has no undo"
}
func TestExpiryExtendReplacesRecord(t *testing.T) {
	// apply the node twice 300 ms apart: exactly one armed record exists, its deadline is the second's
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/plan/ ./internal/controller/ ./internal/agent/ -run 'Expir' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified. The agent keeps `expireUnit time.Duration` (default `time.Second`) as a package variable for tests. `shortcut: one armed record per node id, no per-target records for a multi-host node, upgrade if a node ever targets a label set`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/plan/ ./internal/controller/ ./internal/agent/ ./internal/deadman/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "plan: expires_after time-boxed nodes on the dead-man machinery"`

---

### Task 22b: `LoadModuleTemplateFor`, the `plans` seam and `plans` in `CoreImports`

Haiku-sized. Pack templates (`plans/<module>/*.yaml` in the `plans.Template` format: `vars`, `each`, `scoring_note`) and controller file templates are one directory per module. W5's hardening packs and any module that targets a role (`{labels: "dc"}`) need the label resolver; modules and the module-import check need the `plans` package on the allow list.

**Files:**
- Modify: `plans/plans.go` (`Template.Module string "yaml:\"module\""`; `Parse(raw []byte) (*Template, error)`; `ResolveLabels`), `internal/controller/plantemplates.go` (`LoadModuleTemplateFor`; `LoadModuleTemplate` becomes the nil-resolver call), `internal/module/conformance/allowed.go` (`CoreImports` gains `github.com/PurdueBlueTeam/phylax/plans`)
- Test: `plans/parse_test.go`, `internal/controller/plantemplates_labels_test.go`

**Interfaces:**
- Consumes: Task 22 `LoadModuleTemplate`, `ExpandTemplate`; Task 11 `manifest.ParseLabels`, `(*Manifest).HostsMatching`; the built `plans.Load`, `Template.Expand`, `plans.NewCatalog`.
- Produces:

```go
// plans
func Parse(raw []byte) (*Template, error) // strict (unknown field is an error), 256 KiB cap; Load(path) calls it. A missing module: is not an error here (W5 Task 37 makes it one)
func ResolveLabels(t *Template, hosts func(expr string) ([]string, error)) (map[string]any, error) // overrides for every var shaped {labels: expr}
// controller
func LoadModuleTemplateFor(plansRoot, mod, name string, hosts func(expr string) ([]string, error)) (plan.Plan, error)
// A file with a top-level `vars:` or a node with `each:` is a pack: plans.Parse, ResolveLabels(hosts), Template.Expand over plans.NewCatalog(), Module set from the template (must equal mod).
// Any other file is the controller file format (ParseTemplate). LoadModuleTemplate(plansRoot, mod, name) calls this with a nil resolver (a label var then errors).
```

The three W1 call sites that load a template (`RunReadOnly`, `RunStanding`/`CreateStanding` expansion, `RunAuto`, `AcceptProposal`; Tasks 23 to 26) pass `c.hostsMatching`, which resolves a label expression against the loaded manifest (`ParseLabels` then `HostsMatching`).

- [ ] **Step 1: Write the failing tests:**

```go
// plans/parse_test.go
func TestResolveLabelsExpandsEach(t *testing.T) {
	tpl, err := Parse([]byte("id: x\nmodule: hardening\nvars:\n  dcs: {labels: dc}\nnodes:\n- {id: a, each: dcs, action: ad.zerologon_check, target: ${host}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ov, err := ResolveLabels(tpl, func(e string) ([]string, error) { return []string{"ad", "ad2"}, nil })
	cat, _ := NewCatalog()
	pl, err2 := tpl.Expand(cat, ov)
	if err != nil || err2 != nil || len(pl.Nodes) != 2 || pl.Nodes[1].Target != "ad2" {
		t.Fatalf("%v %v %+v", err, err2, pl)
	}
	if tpl.Module != "hardening" {
		t.Fatal(tpl.Module)
	}
}
func TestUnresolvedLabelVarIsAnError(t *testing.T) { /* Expand without ResolveLabels -> error mentioning "is not a list" */ }
func TestParseRejectsUnknownField(t *testing.T) { /* "bogus: 1" at top level -> error */ }
// internal/controller/plantemplates_labels_test.go
func TestLoadModuleTemplateForResolvesLabels(t *testing.T) {
	// plansRoot/demo/pack.yaml: a pack with `vars: {servers: {labels: server}}` and an `each: servers` node, module: demo
	// manifest (newTestControllerWithManifest): h1 has label server, db1 does not
	// LoadModuleTemplateFor(root, "demo", "pack", c.hostsMatching) -> one node with Target "h1"
	// LoadModuleTemplate(root, "demo", "pack") (nil resolver) -> error
	// a pack whose module: is "other" -> error
}
func TestLoadModuleTemplateForPlainFile(t *testing.T) { /* the Task 22 ok.yml loads unchanged through LoadModuleTemplateFor with a nil resolver */ }
func TestCoreImportsHasPlans(t *testing.T) { /* conformance.CoreImports contains the plans path */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./plans/ ./internal/controller/ ./internal/module/conformance/ -run 'ResolveLabels|Unresolved|ParseRejects|LoadModuleTemplateFor|CoreImportsHasPlans' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified; `plans.Load` keeps its signature and calls `Parse`.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "plans: Parse and ResolveLabels; controller: LoadModuleTemplateFor; plans on the module allow list"`

---

### Task 23: `RunReadOnly`

**Files:**
- Create: `internal/controller/approvals.go`
- Modify: `internal/controller/host.go` (`RunReadOnly` delegates with the module name)
- Test: `internal/controller/approvals_test.go`

**Interfaces:**
- Consumes: `LoadModuleTemplate`, `ExpandTemplate` (Task 22), `lint.Run` (Task 21), built `CreatePlan`, `ApprovePlan`, `Apply`.
- Produces: `(*Controller).RunReadOnly(ctx, mod, template, params) (string, error)`; `(*moduleHost).RunReadOnly`.

Steps inside: load and expand; set `Class = ClassAutoReadOnly`, `Module`, `Template`, `Approver = "auto_readonly:" + mod`; id from `PlanIDFor`; `lint.Run` with `Ctx{Manifest, Query: c.st, Class, Actions: c.reg}`; any finding → error listing every finding, nothing stored; else `CreatePlan`, `ApprovePlan(id, Approver)`, `Apply`. Templates live under `Config.PlansPath`.

- [ ] **Step 1: Remove the skips:**

```go
func TestRunReadOnlyStartsPlan(t *testing.T) {
	c := newTestControllerWithPlans(t, map[string]string{"ctltest/probe.yml": "id: probe\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: p, action: net.tcp_probe, target: '${host}', params: {host: 127.0.0.1, port: 22}}\n"})
	id, err := c.RunReadOnly(ctx, "ctltest", "probe", map[string]string{"host": "h1"})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := c.PlanStatus(id)
	// want: the stored plan has Class auto_readonly, Approver "auto_readonly:ctltest", and is approved (st shows it)
	_ = st
}
func TestRunReadOnlyRefusesWrite(t *testing.T) {
	c := newTestControllerWithPlans(t, map[string]string{"ctltest/w.yml": "id: w\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: w, action: file.write, target: h1, params: {path: /tmp/x, content: y}}\n"})
	_, err := c.RunReadOnly(ctx, "ctltest", "w", nil)
	if err == nil || !strings.Contains(err.Error(), "SS000") {
		t.Fatalf("got %v", err)
	}
	// want: no plan stored (c.StoredPlans(ctx) is empty)
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run RunReadOnly -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: auto_readonly plans (RunReadOnly)"`

---

### Task 24: Standing approvals

**Files:**
- Create: `internal/store/standing.go` (table `standing_approvals` in a new core migration; `InsertStanding`, `Standing`, `ListStanding`, `SetStandingRevoked`)
- Modify: `internal/controller/approvals.go` (`CreateStanding`, `RevokeStanding`, `RunStanding`), `internal/controller/host.go`
- Test: `internal/store/standing_test.go`, `internal/controller/standing_test.go`

**Interfaces:**
- Consumes: `plan.StandingApproval` (Task 1), `manifest.ParseLabels`, `Host.Labels` (Task 11), `Propose` (Task 25; until then `RunStanding` returns `module.ErrProposed` without recording, and Task 25 wires the record).
- Produces: move the `StandingApproval` type to `internal/store` (`store.StandingApproval`; `store` cannot import `plan`, since `plan` imports `module`, which imports `store`) and keep `type StandingApproval = store.StandingApproval` in `internal/plan/approval.go` so every `plan.StandingApproval` caller is unchanged; `store` methods `InsertStanding(ctx, StandingApproval) error`, `Standing(ctx, id string) (StandingApproval, error)`, `ListStanding(ctx) ([]StandingApproval, error)`, `SetStandingRevoked(ctx, id string) error`; replace the skipped placeholder `internal/store/standing_test.go` with real tests; controller `CreateStanding`, `RevokeStanding`, `RunStanding`.

Rules: `CreateStanding` requires `ID`, `Module`, `Template`, `Approver`, `Created`, a parseable `Targets`, a non-empty `Actions` list with no `host.exec` and no action of risk `lockout` or `destructive`, and `now < Expires <= now + 72h` (`shortcut: 72 h cap stands in for "the event's end", upgrade when the manifest records the event window`). `RunStanding` falls back to a click proposal (`module.ErrProposed`, reason named) when the approval is missing, revoked or expired, its `Module` or `Template` differ, a node's action is not in `Actions`, a node's risk is `lockout` or above, a node is `host.exec`, or a node's target host's labels do not match `Targets`. Otherwise `Class = ClassStanding`, `Approver = sa.Approver + " (standing " + sa.ID + ")"`, lint, create, approve, apply.

- [ ] **Step 1: Remove the skips:**

```go
// internal/controller/standing_test.go (manifest: host h1 labels [linux, server]; plans ctltest/dump.yml with one file.hash node on ${host})
func sa() plan.StandingApproval {
	return plan.StandingApproval{ID: "s1", Module: "ctltest", Template: "dump", Targets: "linux", Actions: []string{"file.hash"},
		Expires: time.Now().Add(time.Hour), Approver: "Captain", Created: "admin"}
}
func TestCreateStandingValidates(t *testing.T) {
	c := newStandingController(t)
	for i, f := range []func(*plan.StandingApproval){
		func(s *plan.StandingApproval) { s.Expires = time.Time{} },
		func(s *plan.StandingApproval) { s.Expires = time.Now().Add(73 * time.Hour) },
		func(s *plan.StandingApproval) { s.Actions = []string{"host.exec"} },
		func(s *plan.StandingApproval) { s.Approver = "" },
		func(s *plan.StandingApproval) { s.Targets = "linux &&" },
	} {
		s := sa()
		f(&s)
		if c.CreateStanding(ctx, s) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if err := c.CreateStanding(ctx, sa()); err != nil {
		t.Fatal(err)
	}
}
func TestRunStandingInScope(t *testing.T) {
	c := newStandingController(t)
	_ = c.CreateStanding(ctx, sa())
	id, err := c.RunStanding(ctx, "ctltest", "s1", "dump", map[string]string{"host": "h1"})
	if err != nil || id == "" {
		t.Fatalf("%q %v", id, err)
	}
	// want: stored plan Class standing, Approver "Captain (standing s1)"
}
func TestRunStandingOutOfScopeProposes(t *testing.T) {
	c := newStandingController(t)
	s := sa()
	s.Targets = "windows"
	_ = c.CreateStanding(ctx, s)
	if _, err := c.RunStanding(ctx, "ctltest", "s1", "dump", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("got %v", err)
	}
	_ = c.RevokeStanding(ctx, "s1", "admin")
	if _, err := c.RunStanding(ctx, "ctltest", "s1", "dump", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("revoked: %v", err)
	}
}
func TestRunStandingExpired(t *testing.T) {
	// insert s with Expires one second ahead via CreateStanding, wait until past, RunStanding -> ErrProposed
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/store/ ./internal/controller/ -run Standing -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified; write a store round-trip test for the four store methods in `standing_test.go`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/store/ ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: standing approvals with scope and expiry"`

---

### Task 25: Proposals

**Files:**
- Create: `internal/store/proposals.go` (table `proposals`: `id INTEGER PRIMARY KEY, module, title, template, params JSON, evidence JSON, reason, created_ns, state ('open'|'accepted'|'dismissed'), plan_id, by`), `internal/controller/proposals.go`, `internal/ui/proposals.go` + `internal/ui/templates/proposals.html` (list open proposals; Accept and Dismiss buttons)
- Modify: `internal/controller/host.go` (`Propose`), `internal/controller/approvals.go` (`RunStanding` fallbacks record a proposal), `internal/ui/ui.go` (`Ops` gains the three proposal methods)
- Test: `internal/controller/proposals_test.go`, `internal/ui/proposals_test.go`

**Interfaces:**
- Consumes: `module.Proposal`, `module.EventRef`, `LoadModuleTemplate`, `ExpandTemplate`, `CreatePlan`, `ApprovePlan`, `Apply`.
- Produces: store `InsertProposal(ctx, ProposalRow) (int64, error)`, `Proposal(ctx, id) (ProposalRow, error)`, `OpenProposals(ctx) ([]ProposalRow, error)`, `CloseProposal(ctx, id int64, state, planID, by string) error`, with `type ProposalRow struct{ ID int64; Module, Title, Template string; Params map[string]string; Evidence []string /* "agent:seq" */; Reason string; Created time.Time; State, PlanID, By string }`; controller `Propose`, `AcceptProposal`, `DismissProposal`; `(*moduleHost).Propose`; UI routes `GET /proposals`, `POST /proposals/{id}/accept`, `POST /proposals/{id}/dismiss`.

Rules: `Propose` validates that the template loads for the module and expands with the params (a broken proposal is refused at creation, not at the click); Title ≤ 200 bytes; at most 1000 open proposals per module (`shortcut: oldest open proposal of the module is dismissed beyond 1000, upgrade if a module legitimately floods`). `AcceptProposal` creates the plan with `Class = ClassClick`, `Approver = by`, approves and applies it, and closes the proposal `accepted` with the plan id; accepting a closed proposal is an error.

- [ ] **Step 1: Remove the skips:**

```go
func TestProposeAndAccept(t *testing.T) {
	c := newTestControllerWithPlans(t, map[string]string{"ctltest/fix.yml": "id: fix\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: a, action: file.hash, target: '${host}', params: {path: /etc/hosts}}\n"})
	id, err := c.Propose(ctx, module.Proposal{Module: "ctltest", Title: "hash hosts", Template: "fix", Params: map[string]string{"host": "h1"}, Reason: "tier 1",
		Evidence: []module.EventRef{{Agent: "h1", Seq: 7}}})
	if err != nil {
		t.Fatal(err)
	}
	planID, err := c.AcceptProposal(ctx, id, "driver")
	if err != nil || planID == "" {
		t.Fatalf("%q %v", planID, err)
	}
	// want: the plan's Class is click and Approver "driver"; the row is accepted with plan_id; OpenProposals is empty
	if _, err := c.AcceptProposal(ctx, id, "driver"); err == nil {
		t.Fatal("accepted twice")
	}
}
func TestProposeRejectsBrokenTemplate(t *testing.T) {
	c := newTestControllerWithPlans(t, nil)
	if _, err := c.Propose(ctx, module.Proposal{Module: "ctltest", Title: "x", Template: "missing"}); err == nil {
		t.Fatal("missing template accepted")
	}
}
func TestRunStandingFallbackRecordsProposal(t *testing.T) {
	// as TestRunStandingOutOfScopeProposes; then OpenProposals has one row with Module "ctltest" and a Reason naming "targets"
}
// internal/ui/proposals_test.go
func TestProposalsPage(t *testing.T) {
	// Ops fake returning one open proposal titled "<script>x</script>": GET /proposals is 200 and the title is escaped
	// POST /proposals/1/accept with CSRF calls Ops.AcceptProposal(1, <operator>) and redirects
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ ./internal/ui/ -run 'Propos' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/store/ ./internal/controller/ ./internal/ui/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: click proposals and the proposals page"`

---

### Task 26: `RunAuto` and the auto conditions

**Files:**
- Create: `internal/controller/auto.go`
- Modify: `internal/controller/host.go` (`RunAuto`), `internal/controller/controller.go` (`Options.Probe`)
- Test: `internal/controller/auto_test.go`

**Interfaces:**
- Consumes: `manifest.ModuleBlock.ActEnabled`/`Auto` (Task 11), the last heartbeat per agent (`SafeMode`, receive time), `lint.Run` with `ClassAuto` (Task 21), `Propose` (Task 25), `Options.Probe`.
- Produces: `(*Controller).RunAuto(ctx, mod, template, params) (string, error)`; `Options.Probe func(ctx context.Context, service string) error`; `(*moduleHost).RunAuto`.

Conditions, checked in this order; the first failure creates a proposal with `Reason` naming it and returns `module.ErrProposed`:
1. the module's effective act switch on every target host is true: `Manifest.ActEnabled(host, mod)` (Task 11b: the block's `act_enabled` or an `overrides.yml` `act` entry matching the host);
2. `template` is in the block's `auto` list;
3. the template loads and expands (`trigger` is not substituted);
4. every target host has a heartbeat received in the last 15 s with `SafeMode == false` (no heartbeat = unknown = fail: Review Focus 4);
5. `lint.Run(..., Class: ClassAuto)` has no finding (rules `SS010` and `SS011`);
6. every node with `plan.ScoredTouch(...)` non-empty (its `Touches` hits a manifest-scored service on its target host; the manifest `health:` block decides until discovery has learned the live set, Task 27b) has a probe: `Options.Probe != nil` (else reason `probe cannot run`);
7. the breaker for (module, template, host) is closed (Task 28; until then always closed).
On success: `Class = ClassAuto`, `OnFailure = rollback_plan`, `Approver = "auto:" + mod + "/" + template` plus `" trigger " + params["trigger"]` when given; create, approve, apply.

- [ ] **Step 1: Remove the skips:**

```go
// helper: newAutoController(t, block string) with manifest host h1 (scored service "web" on h1) and plans
// ctltest/t1.yml (file.hash on ${host}: read-only, no touches), ctltest/t2.yml (file.write of a temp path on ${host}: a path touch)
// and ctltest/bad.yml (host.exec on ${host}); setHeartbeat(c, "h1", safeMode bool, at time.Time) writes the agent state directly
func TestRunAutoNeedsActEnabled(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: false\nauto: [t1]\n")
	setHeartbeat(c, "h1", false, time.Now())
	_, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"})
	if !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "act_enabled") {
		t.Fatalf("got %v", err)
	}
	// want: one open proposal for ctltest with Reason containing "act_enabled"
}
func TestRunAutoNotOnAllowlist(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [other]\n")
	setHeartbeat(c, "h1", false, time.Now())
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("got %v", err)
	}
}
func TestRunAutoUnknownSafeModeProposes(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n")
	c.opt.Probe = func(context.Context, string) error { return nil }
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("no heartbeat: %v", err)
	}
	setHeartbeat(c, "h1", true, time.Now())
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("safe mode on: %v", err)
	}
	setHeartbeat(c, "h1", false, time.Now().Add(-time.Minute))
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("stale heartbeat: %v", err)
	}
}
func TestRunAutoLintAndProbe(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t2, bad]\n")
	setHeartbeat(c, "h1", false, time.Now())
	if _, err := c.RunAuto(ctx, "ctltest", "bad", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("host.exec: %v", err)
	}
	_, err := c.RunAuto(ctx, "ctltest", "t2", map[string]string{"host": "h1"}) // Probe is nil
	if !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "probe cannot run") {
		t.Fatalf("no probe: %v", err)
	}
}
func TestRunAutoStarts(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n")
	c.opt.Probe = func(context.Context, string) error { return nil }
	setHeartbeat(c, "h1", false, time.Now())
	id, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1", "trigger": "h1:7"})
	if err != nil || id == "" {
		t.Fatalf("%q %v", id, err)
	}
	// want: stored plan Class auto, OnFailure rollback_plan, Approver "auto:ctltest/t1 trigger h1:7"
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run RunAuto -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: auto plans behind act_enabled, allowlist, safe mode, lint and probe"`

---

### Task 27: Probe inside each node that touches a scored service; `deadman_confirm` after the after-probe (R12)

**Files:**
- Modify: `internal/controller/plans.go` (dispatch and result handling for nodes of `ClassAuto` plans), `internal/controller/auto.go`
- Test: `internal/controller/auto_probe_test.go`

**Interfaces:**
- Consumes: `Options.Probe`; the plan engine's node dispatch and rollback paths (`dispatch`, `onStepResult`, `RollbackOrder`, `MarkRolledBack`, the `deadman_confirm` send); `plan.ProbeGroups` and `plan.ScoredTouch` (Task 27b).
- Produces: for a node of a plan of any class that touches a scored service (`ScoredTouch` non-empty), the probe runs inside the node, not as a separate node. Per probe group (Task 27b: one group per host and shared lock set; a node with its own `deadman` is its own group): before the first node of the group is dispatched, `Probe(ctx, service)` for each scored service of the group, and a red probe fails the node with reason `before-probe red: <service>` (nothing applied); after the last node of the group verifies (immediately after the node for a `deadman` node), the same probes, and a red probe rolls the group back through the plan's `rollback_plan` path with reason `after-probe red: <service>`. **`deadman_confirm` for a node with a dead-man window is sent only after its after-probe has passed**; on a red probe it is not sent, so the agent's own timer also rolls the node back. Probes are bounded: one retry after 5 s (`c.probeRetry`, overridable in tests), then red. One probe per group and phase: a ten-node pack on one host runs two probes, not twenty.

- [ ] **Step 1: Remove the skips:**

```go
func TestAutoAfterProbeRollsBack(t *testing.T) {
	// e2e helpers (newCtl + a real agent "h1" with a scored service "web" in the manifest); module block act_enabled with auto [t1];
	// t1: one file.write node to a temp path on h1
	// Options.Probe returns nil before and an error after (count calls)
	// RunAuto(... "t1" ...) then Wait(planID)
	// want: node state rolled_back, reason contains "after-probe red: web"; the temp file content is the original
}
func TestDeadmanConfirmWaitsForAfterProbe(t *testing.T) {
	// click plan, one deadman file.write node touching scored service "web"; Probe: nil before, error after
	// want: no deadman_confirm control was sent for the node (OnControlSent saw none); the agent's timer (shortened in the test) rolls the file back;
	// with a green after-probe the confirm is sent exactly once and only after the probe call
}
func TestOneProbePerGroupAndPhase(t *testing.T) {
	// plan with five file.write nodes on h1 sharing the lock content:web, all touching "web"; count Probe calls
	// want: 2 (one before, one after); with one of the five carrying deadman: 2+2 = 4
}
func TestAutoBeforeProbeStops(t *testing.T) {
	// same setup; Probe always errors
	// want: node failed with "before-probe red: web"; the agent received no apply step (OnStepSent saw none)
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run AutoAfter\|AutoBefore -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified, touching only the `ClassAuto` branch.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: scorer-mimic probe inside nodes that touch a scored service, confirm after the after-probe"`

---

### Task 27b: A plan that touches a scored service defaults to `rollback_plan`; probe groups (R12)

Haiku-sized. The design (Plans, Dead-man switch, scorer-mimic probe) says: a plan that touches a scored service defaults to `rollback_plan` and a template naming another policy for it is a lint error; "touches" means a node's `Touches` hits a service the manifest scores (the manifest `health:` block decides until discovery has learned the live set); nodes that share a host and a lock set share one probe per phase, except a node with its own dead-man window, which is probed on its own.

**Files:**
- Create: `internal/plan/lint/ss011.go`, `internal/plan/probegroups.go`
- Modify: `internal/controller/plantemplates.go` (default `on_failure`), `internal/plan/lint/lint.go` (register)
- Test: `internal/plan/lint/ss011_test.go`, `internal/plan/probegroups_test.go`

**Interfaces:**
- Consumes: `lint.Register`, `Ctx.Manifest`, `Action.Touches`, `Action.Locks`, `plan.Plan.OnFailure` (Task 22 constants).
- Produces:

```go
// package plan
// ScoredTouch returns the manifest-scored services on the node's target host that the node's Touches hits.
// A service is scored when services.yml says scored: true; until discovery has learned the live set the services named
// by the manifest health: block are the scored set (no learned-set argument exists on purpose).
func ScoredTouch(m *manifest.Manifest, n Node, touches []actions.Touch) []string

// ProbeGroup is a set of nodes of one plan on one host that share one before-probe and one after-probe.
type ProbeGroup struct {
	Host     string
	Services []string // scored services to probe, sorted
	Nodes    []string // node ids in plan order
}

// ProbeGroups returns the groups: nodes that touch a scored service, target the same host and have overlapping Locks
// (transitively) form one group; a node with Deadman set is always its own group (its confirm waits for its own after-probe).
func ProbeGroups(p Plan, scored map[string][]string /* node id -> scored services touched */, locks map[string][]string /* node id -> locks */) []ProbeGroup

// package lint: rule SS011 (Class click, standing, auto): a plan with any ScoredTouch whose OnFailure is explicitly set
// to stop_dependents or continue is a finding "plan touches a scored service: on_failure must be rollback_plan".
// An omitted on_failure is not a finding: ExpandTemplate sets rollback_plan for such a plan.
```

- [ ] **Step 1: Write the failing tests:**

```go
func TestDefaultRollbackPlanForScoredTouch(t *testing.T) {
	// template with one file.write node on h1 (scored service web, path under the web root) and no on_failure
	// -> expanded plan.OnFailure == rollback_plan; a template whose nodes touch nothing scored keeps stop_dependents
}
func TestSS011RejectsOtherPolicy(t *testing.T) {
	// same template with on_failure: continue -> lint finding SS011 naming the node; with rollback_plan -> none
}
func TestProbeGroupsShareLocks(t *testing.T) {
	// nodes a, b on h1 locks [content:web] and [content:web, path:x], node c on h1 locks [sshd], node d on h2 locks [content:web]
	// all touch scored services: groups {a,b}, {c}, {d}
}
func TestProbeGroupDeadmanIsAlone(t *testing.T) {
	// node b has Deadman 90s and shares a lock with a: groups {a}, {b}
}
func TestScoredTouchUsesManifestHealthBeforeDiscovery(t *testing.T) {
	// manifest service "ecom-http" scored with a health: block on h1; a node whose Touches names its config path -> ["ecom-http"];
	// a node on h1 touching an unscored path -> empty
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/plan/... -run 'Rollback|SS011|ProbeGroup|ScoredTouch' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/plan/... ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "plan: rollback_plan default for scored touches (SS011) and probe groups"`

---

### Task 27c: The agent answers `busy`, not `failed`, over the step cap (R12)

Haiku-sized. Today a valid step over the 8-step cap is answered `failed` (`internal/agent/exec.go`: "agent busy: too many steps executing"), which fires `on_failure` and, on an `auto` plan, a whole-plan rollback. The design: the agent answers `busy`, which the controller treats as retry, and the controller keeps per-host in-flight steps below the cap.

**Files:**
- Modify: `internal/plan/result.go` (`OutcomeBusy`), `internal/agent/exec.go`, `internal/controller/plans.go` (dispatch limit and retry), `docs/protocol.md`
- Test: `internal/agent/busy_test.go`, `internal/controller/busy_test.go`

**Interfaces:**
- Consumes: `x.sem` (cap `n`, 8 by default), `finishStep`, the plan engine's dispatch and `onStepResult`.
- Produces: `plan.OutcomeBusy = "busy"` (accepted by result validation); the agent answers `busy` with the step's digest and no state change when `sem` is full (the step is not recorded as running, so a re-send is processed normally); the controller limits in-flight steps per host to `MaxHostInflight = 6` (a field of `Options`, default 6, below the agent cap) and, on a `busy` result, re-queues the same step after `BusyRetry` (default 2 s, `Options.BusyRetry`, up to 30 retries, then the node fails with `agent busy for 60 s`). A `busy` result never counts toward `on_failure`, never records an audit failure and never opens the auto breaker.

- [ ] **Step 1: Write the failing tests:**

```go
func TestAgentAnswersBusyOverCap(t *testing.T) {
	// agent harness with exec cap 2 and a slow test action; send three signed apply steps for different nodes
	// want: two accepted, the third result Outcome == plan.OutcomeBusy; the third node is not in the running set
}
func TestBusyResultValidates(t *testing.T) { /* plan.Result{Outcome: "busy"} passes validation; "bogus" still fails */ }
func TestControllerKeepsInflightBelowCap(t *testing.T) {
	// one host, 12 independent ready nodes, a fake agent that holds results; want: never more than MaxHostInflight steps sent before a result returns
}
func TestControllerRetriesBusy(t *testing.T) {
	// fake agent answers busy to the first send of node n then verified; want: node n verified, on_failure never invoked, no plan.rollback event
	// after 31 busy answers: node failed with "agent busy"
}
func TestBusyOnAutoPlanDoesNotRollBack(t *testing.T) {
	// RunAuto plan, agent answers busy twice for node 2, then ok: plan ends verified; the breaker count is unchanged
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/agent/ ./internal/controller/ -run 'Busy|Inflight' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/plan/ ./internal/agent/ ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "exec: busy answer over the step cap, per-host in-flight limit, retry on busy"`

---

### Task 27a: `gate: auto`

Haiku-sized. The design's `gate: auto` (A-AUTO) passes by itself when its `until:` conditions hold and fails the plan otherwise, with the reason on the node. A plain `gate: approval` keeps waiting for a click; `gate: manual` is W7's.

**Files:**
- Modify: `internal/plan/plan.go` (`Node.Until`, `GateUntil`, validation, `RequiresOwnApproval`), `internal/controller/plantemplates.go` (`translateNodeKeys`: `gate:` strings), `internal/controller/plans.go` (evaluate a ready auto gate instead of waiting for approval), `internal/controller/auto.go`
- Test: `internal/plan/autogate_test.go`, `internal/controller/autogate_test.go`

**Interfaces:**
- Consumes: Task 22a `translateNodeKeys`; Task 27 `Options.Probe`, `c.probeRetry`; `store.Reader.Events`; the plan engine's ready-node dispatch.
- Produces:

```go
// Node gains: Until *GateUntil `json:"until,omitempty"` (a gate node with Until set is a gate: auto)
type GateUntil struct {
	AfterSec int      `json:"after_sec,omitempty"` // wait until this long after the gate's last dependency finished (the minimum shadow time)
	Probe    string   `json:"probe,omitempty"`     // a scored service name, or "*" for every scored service on the plan's targets; "" none
	NoEvent  *NoEvent `json:"no_event,omitempty"`
}
type NoEvent struct {
	Kind   string            `json:"kind"`             // a declared kind
	Fields map[string]string `json:"fields,omitempty"` // top-level field equality (store.Query.Fields)
}
// RequiresOwnApproval: a gate node with Until set returns false (it needs no approval record); every other gate still true.
// Options gains: GatePoll time.Duration (default 1s; tests set 10ms)
```

Rules: `Until` only on a gate node; it needs at least one condition; `AfterSec` 0 to 86400; `NoEvent.Kind` must be declared (`event.Lookup`). In a template, `gate: approval` (and the old `gate: true`) means a plain gate, `gate: auto` means a gate with `until:` (required), `gate: manual` means a gate (W7 Task 4 adds `ask:` and `reply:` and requires them); any other string is an error. `until:` keys in a template: `after` (a Go duration, becomes `after_sec`), `probe`, `no_event`. Evaluation, when the gate's dependencies are all verified: (1) `AfterSec` not yet elapsed: the gate stays pending, note `waiting: <n>s of shadow time left`, re-evaluated every `GatePoll`; (2) `Probe` through `Options.Probe` with the Task 27 retry rule: red fails the gate; (3) `NoEvent`: any event of the kind (and the fields) committed since the gate's last dependency finished fails the gate; (4) all hold: the gate passes with approval `By: "auto"`, `Note: "gate: auto"`. A failed gate fails the plan under the plan's `on_failure` policy and records the reason on the node (`gate: auto failed: <condition>`). A missing `Options.Probe` with a `Probe` condition fails the gate with `no probe configured` (never a silent pass). Works in every approval class; in a `click` plan the plan approval still comes first. `shortcut: conditions are time, probe and absence of an event; a nested summary condition (the firewall's would-drop table) is evaluated by the owning module before it calls RunAuto, upgrade when a second module needs one`.

- [ ] **Step 1: Write the failing tests:**

```go
// internal/plan/autogate_test.go
func TestAutoGateValidates(t *testing.T) {
	ok := Node{ID: "g", Gate: true, Needs: []string{"a"}, Until: &GateUntil{AfterSec: 600, Probe: "*"}}
	if err := validateNode(ok); err != nil {
		t.Fatal(err)
	}
	for i, n := range []Node{
		{ID: "a", Action: "file.hash", Target: "h1", Until: &GateUntil{AfterSec: 5}},    // Until on a non-gate
		{ID: "g", Gate: true, Until: &GateUntil{}},                                      // no condition
		{ID: "g", Gate: true, Until: &GateUntil{AfterSec: 90000}},
		{ID: "g", Gate: true, Until: &GateUntil{NoEvent: &NoEvent{Kind: "no.such.kind"}}},
	} {
		if validateNode(n) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if RequiresOwnApproval(ok, RiskNone) {
		t.Fatal("an auto gate needs no approval record")
	}
	if !RequiresOwnApproval(Node{ID: "g", Gate: true}, RiskNone) {
		t.Fatal("a plain gate lost its approval")
	}
}
// internal/controller/autogate_test.go
func TestTemplateGateStrings(t *testing.T) {
	p, err := ParseTemplate([]byte("id: t\nnodes:\n- {id: a, action: file.hash, target: h1, params: {path: /etc/hostname}}\n- {id: g, gate: auto, needs: [a], until: {after: 10m, probe: '*', no_event: {kind: agent.resumed}}}\n- {id: p, gate: approval, needs: [g]}\n"))
	if err != nil || p.Nodes[1].Until == nil || p.Nodes[1].Until.AfterSec != 600 || p.Nodes[2].Until != nil || !p.Nodes[2].Gate {
		t.Fatalf("%+v %v", p, err)
	}
	for _, bad := range []string{"gate: auto", "gate: sometimes"} { // auto without until; unknown string
		if _, err := ParseTemplate([]byte("id: t\nnodes:\n- {id: g, " + bad + "}\n")); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
func TestAutoGatePassesWhenConditionsHold(t *testing.T) {
	// e2e helpers; plan: a (file.hash on h1) -> g (gate auto, AfterSec 1, Probe "web") -> b (file.hash); GatePoll 10ms; Probe nil-error
	// approve the plan (no gate approval call); within 3 s b is verified and g's approval is By "auto"
}
func TestAutoGateWaitsForShadowTime(t *testing.T) {
	// AfterSec 2: after 500 ms the gate is pending with a note containing "left"; b not dispatched
}
func TestAutoGateFailsOnRedProbe(t *testing.T) {
	// Probe returns an error: the gate state is failed, reason contains "gate: auto failed", b is never dispatched
}
func TestAutoGateFailsOnEvent(t *testing.T) {
	// NoEvent{Kind: "agent.resumed"}: emit one agent.resumed through EmitController after a verifies; the gate fails with the kind in the reason;
	// an event committed before a finished does not fail it
}
func TestAutoGateNoProbeConfiguredFails(t *testing.T) { /* Options.Probe nil and Probe "web": failed, reason contains "no probe configured" */ }
func TestPlainGateStillWaitsForClick(t *testing.T) { /* gate: approval in an auto-class plan stays pending until ApproveNode */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/plan/ ./internal/controller/ -run 'AutoGate|TemplateGate|PlainGate' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/plan/ ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "plan: gate: auto with time, probe and event-absence conditions"`

---

### Task 28: Auto circuit breaker

**Files:**
- Modify: `internal/controller/auto.go`
- Test: `internal/controller/breaker_test.go`

**Interfaces:**
- Consumes: the rollback outcome of `ClassAuto` plans (Task 27), `store` kv (`internal/store/kv.go`), `EmitController` (Task 16), `event.PlanAutoHalted`.
- Produces: `(*Controller).noteAutoRollback(mod, template, host string, at time.Time)` (unexported, called on every automatic rollback); `(*Controller).ReenableAuto(ctx, mod, template, host, by)`; condition 7 of `RunAuto`.

Rules: two automatic rollbacks of the same (module, template, host) within 10 minutes halt it: kv key `auto_halted/<module>/<template>/<host>` set (survives restart), `plan.auto_halted` emitted at `PriorityCritical`; `RunAuto` then proposes with reason `template halted on <host>`; `ReenableAuto` deletes the key and records an audit entry with `by`.

- [ ] **Step 1: Remove the skips:**

```go
func TestBreakerHaltsAfterTwoRollbacks(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n")
	c.opt.Probe = func(context.Context, string) error { return nil }
	setHeartbeat(c, "h1", false, time.Now())
	now := time.Now()
	c.noteAutoRollback("ctltest", "t1", "h1", now)
	c.noteAutoRollback("ctltest", "t1", "h1", now.Add(9*time.Minute))
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "halted") {
		t.Fatalf("got %v", err)
	}
	e, err := c.st.Latest(ctx, "controller", "plan.auto_halted")
	if err != nil || e.Priority != event.PriorityCritical {
		t.Fatalf("%+v %v", e, err)
	}
	_ = c.ReenableAuto(ctx, "ctltest", "t1", "h1", "driver")
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); err != nil {
		t.Fatalf("after re-enable: %v", err)
	}
}
func TestBreakerWindow(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n")
	now := time.Now()
	c.noteAutoRollback("ctltest", "t1", "h1", now)
	c.noteAutoRollback("ctltest", "t1", "h1", now.Add(11*time.Minute))
	// want: not halted (kv key absent)
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run Breaker -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: auto circuit breaker per module, template and host"`

---

### Task 29: Controller executor for every controller-side action

**Files:**
- Create: `internal/controller/exec.go` (the executor moved out of `devexec_run.go` and made available without devices)
- Modify: `internal/controller/devexec_run.go` (device setup only), `internal/controller/controller.go` (`New` installs the executor), `internal/actions/env.go` (`Env.Probe`)
- Test: `internal/controller/exec_test.go`

**Interfaces:**
- Consumes: built `devExec` (`exec`, `env`, `localCheck`, `dispatchLocalLocked`, `localDone`), `isLocalAction`, `EmitController`, `Options.Probe`.
- Produces: `actions.Env.Probe`; every `Runs: RunsController` action runs in the controller executor whether or not `EnableDeviceExec` was called (device actions without a directory fail with `no device directory`); after each phase the executor emits `agent.step_result` (agent `controller`) with plan, node, host, phase, outcome, error and the plan's class; the executor's `Env.Probe` is `Options.Probe`.

- [ ] **Step 1: Remove the skips:**

```go
type ctlAction struct{ probed *atomic.Int32 }

func (ctlAction) Spec() actions.Spec {
	return actions.Spec{Name: "ctltest.local", Risk: actions.RiskNone, ReadOnly: true, Runs: actions.RunsController}
}
func (ctlAction) Locks(actions.Params) []string           { return nil }
func (ctlAction) Touches(actions.Params) []actions.Touch  { return nil }
// Plan, Capture and Verify return zero values; Apply calls env.Probe(ctx, "web") when env.Probe != nil and counts it

func TestLocalActionWithoutDevices(t *testing.T) {
	reg := actions.Core()
	a := ctlAction{new(atomic.Int32)}
	reg.Register(a)
	c := newTestControllerWithRegistry(t, reg, func(context.Context, string) error { return nil }) // Options.Registry, Options.Probe
	// create, approve, apply a click plan with one node {action: ctltest.local, target: <controller host>}; Wait
	// want: node verified; a.probed.Load() == 1;
	// c.st.Latest(ctx, "controller", "agent.step_result") decodes to event.AgentStepResult with Outcome set and Node == the node id
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run LocalAction -v`. Expected: FAIL (executor absent without `EnableDeviceExec`).
- [ ] **Step 3: Implement** the move and the three additions; existing device tests keep passing.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/ ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: executor for every controller-side action, with Env.Probe"`

---

### Task 30: Facts, controller side

**Files:**
- Modify: `internal/plan/fact.go`, `internal/controller/facts.go` (new), `internal/controller/host.go` (`Control`)
- Test: `internal/plan/fact_test.go`, `internal/controller/facts_test.go`

**Interfaces:**
- Consumes: `module.ControlMsg` (Task 1), `manifest.ParseLabels`/`HostsMatching` (Task 11), built `SendControl(ctx, host, kind, on, args)`.
- Produces: `plan.FactSender` with the table `work_window→teamfeed`, `round_clock→scorer`, `gpo_finding→ad`, `scorer_probe_result→checks`, `creds_txn→creds`; `(*Controller).SendFact(ctx, mod, m)`; `(*moduleHost).Control(m)` = `SendFact` with a 30 s timeout.

Rules: `Type == "fact"`; `FactSender(m.Fact) == mod`; `ID` 1..128 bytes; `0 < TTL <= MaxFactTTL`; encoded `Data` ≤ `MaxFactData`; each `Hosts` entry is a manifest host name, else a label expression; no resolved host is an error. Args are the JSON of `event.ControllerFact{ID, Fact, TS: now, TTL, Data}`, sent with `SendControl(ctx, host, plan.ControlFact, true, args)` to every resolved host; a host that is not connected is logged and skipped (it treats the fact as unknown).

- [ ] **Step 1: Remove the skips:**

```go
// internal/plan/fact_test.go
func TestFactSender(t *testing.T) {
	for fact, mod := range map[string]string{"work_window": "teamfeed", "round_clock": "scorer", "gpo_finding": "ad", "scorer_probe_result": "checks", "creds_txn": "creds"} {
		if got, ok := FactSender(fact); !ok || got != mod {
			t.Errorf("%s: %s %v", fact, got, ok)
		}
	}
	if _, ok := FactSender("made_up"); ok {
		t.Error("unknown subtype")
	}
}
// internal/controller/facts_test.go
func TestSendFactValidates(t *testing.T) {
	c := newTestControllerWithManifest(t, nil) // host h1
	good := module.ControlMsg{Type: "fact", Hosts: []string{"h1"}, Fact: "round_clock", ID: "rc", TTL: time.Minute, Data: map[string]any{"delay": 60}}
	for i, f := range []func(*module.ControlMsg){
		func(m *module.ControlMsg) { m.Type = "safe_mode" },
		func(m *module.ControlMsg) { m.TTL = 0 },
		func(m *module.ControlMsg) { m.TTL = 25 * time.Hour },
		func(m *module.ControlMsg) { m.ID = "" },
		func(m *module.ControlMsg) { m.Data = map[string]any{"x": strings.Repeat("a", 17<<10)} },
		func(m *module.ControlMsg) { m.Hosts = []string{"nohost && x"} },
	} {
		m := good
		f(&m)
		if c.SendFact(ctx, "scorer", m) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if c.SendFact(ctx, "checks", good) == nil {
		t.Error("wrong sender accepted")
	}
}
func TestSendFactSigned(t *testing.T) {
	// e2e helpers with a connected agent h1; capture Options.OnControlSent
	// SendFact(ctx, "scorer", good) -> nil; the captured control has Kind "fact" and args decode to
	// event.ControllerFact{ID: "rc", Fact: "round_clock", TTL: time.Minute, ...}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/plan/ ./internal/controller/ -run 'Fact' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/plan/ ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: control: fact with subtype senders and bounds"`

---

### Task 31: Facts, agent side

**Files:**
- Create: `internal/agent/facts.go`
- Modify: `internal/agent/handlers.go` (the kind switch of `handleControl`), `internal/agent/registry.go` (`Env.Fact`), `internal/agent/harness.go` (`Fact`)
- Test: `internal/agent/facts_test.go`

**Interfaces:**
- Consumes: `plan.ControlFact`, `plan.MaxFactData`, `event.ControllerFact`, `event.New`, `publish` (bus only).
- Produces: a verified `fact` control is decoded strictly (≤ `MaxFactData` bytes), stored in memory keyed by `ID` with the agent's receipt time (at most 1024 facts; the oldest is evicted), and published on the on-host bus as a `controller.fact` event (never spooled). `Env.Fact(id)` returns false when never received or when `now > receivedAt + TTL`. An unknown control kind is answered with `agent.control_refused` (verify this already holds; test it). `Harness.Fact(f)` delivers through the same store-and-publish path. Unexported test hooks used by Tasks 31 and 32: `(*Harness).setNow(func() time.Time)` (the agent's clock for facts and windows) and `(*Harness).env() Env`.

- [ ] **Step 1: Remove the skips:**

```go
func TestFactReachesBusNotSpool(t *testing.T) {
	h, _ := NewHarness(HarnessOptions{Host: "h1", StateDir: t.TempDir(), Factories: []Factory{subscriberFactory("fx", []string{"controller.fact"})}})
	// run, apply; ch := the subscriber module's received channel
	h.Fact(event.ControllerFact{ID: "rc", Fact: "round_clock", TS: time.Now(), TTL: time.Minute, Data: map[string]any{"delay": 60}})
	// want: the subscriber receives one event of kind controller.fact with Fields["id"] == "rc"
	// want: no controller.fact in h.Emitted() (nothing reached the spool path)
}
func TestFactTTLFromReceipt(t *testing.T) {
	h, _ := NewHarness(HarnessOptions{Host: "h1", StateDir: t.TempDir()})
	now := time.Now()
	h.setNow(func() time.Time { return now }) // unexported clock hook
	h.Fact(event.ControllerFact{ID: "x", Fact: "round_clock", TS: now.Add(-time.Hour), TTL: time.Minute}) // controller clock an hour behind
	if _, ok := h.env().Fact("x"); !ok {
		t.Fatal("fact must be known right after receipt")
	}
	now = now.Add(61 * time.Second)
	if _, ok := h.env().Fact("x"); ok {
		t.Fatal("fact must be unknown after its TTL")
	}
	if _, ok := h.env().Fact("never"); ok {
		t.Fatal("unreceived fact must be unknown")
	}
}
func TestFactReplacedByID(t *testing.T) {
	// two facts with ID "x", Data {"v":1} then {"v":2}: Env.Fact("x").Data["v"] == json.Number("2")
}
func TestUnknownControlRefused(t *testing.T) {
	// test agent of testutil_test.go: a correctly signed control of kind "made_up" -> an agent.control_refused event
	// with Fields["kind"] == "made_up" is spooled; the agent keeps running
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/agent/ -run 'Fact|UnknownControl' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/agent/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "agent: controller facts on the bus with receipt-time TTL"`

---

### Task 32: `work_window` supervisor effect

**Files:**
- Create: `internal/agent/window.go`
- Modify: `internal/agent/agent.go` (`emit` stamps the open window's tag; load the window at start), `internal/agent/facts.go` (a `work_window` fact updates the window)
- Test: `internal/agent/window_test.go`

**Interfaces:**
- Consumes: `event.ControllerFact` (Task 31), `internal/atomicfile`.
- Produces: `work_window` fact data `{window string, tag string, user string, until RFC 3339 string, for string (a Go duration), end bool}` opens, extends or (with `end: true`) ends the window; the window is persisted at `<StateDir>/work_window.json` atomically. **Tags cover only our own activity (R6):** while the window is open, an event gets the window's tag only if its `Tag` is empty, its kind is change-class (`file_change`, `inventory.row`, `audit.rules_changed`, `winevt.sec_event`; the set is `window.ChangeClass`) and it is attributed to the claimed user (its `user` field equals the window's `user`); process, network, authentication and honeytoken events are never stamped. The window ends by a monotonic duration: `for` counted from the agent's receipt on `Agent.mono` (a monotonic source, default `time.Since(start)`), so changing the system clock neither extends nor ends it; `until` is display only. It ends by itself at the deadline with or without a link. An event that already carries a plan tag keeps it. `shortcut: attribution by the user field, a change by another process of the same user is tagged; the window's remaining time is persisted every 10 s and downtime does not count, upgrade when the controller can end windows after a reconnect`.

- [ ] **Step 1: Remove the skips:**

```go
func TestWorkWindowStampsTag(t *testing.T) {
	dir := t.TempDir()
	h, _ := NewHarness(HarnessOptions{Host: "h1", StateDir: dir, Factories: []Factory{emitterFactory("wx")}}) // emits "wx.e" on demand
	now := time.Now()
	mono := time.Duration(0)
	h.setMono(func() time.Duration { return mono })
	h.Fact(event.ControllerFact{ID: "ww", Fact: "work_window", TS: now, TTL: time.Hour,
		Data: map[string]any{"window": "w1", "tag": "window:w1", "user": "alice", "for": "10m", "until": now.Add(10 * time.Minute).UTC().Format(time.RFC3339)}})
	// emit file_change with user alice -> Tag "window:w1"
	// emit file_change with user mallory -> Tag ""
	// emit process_start (user alice), auth_event, conn, honeytokens.read -> Tag "" (never stamped)
	// an emit with Tag "plan:p1" keeps "plan:p1"
	mono = 11 * time.Minute
	// emit file_change with user alice -> Tag ""
}
func TestWorkWindowIgnoresWallClock(t *testing.T) {
	// open a 10 minute window; set the wall clock (h.setNow) one hour ahead and one hour back: a file_change by the claimed user is still tagged
	// until mono passes 10 minutes, and untagged after, whatever the wall clock says
}
func TestWorkWindowSurvivesRestart(t *testing.T) {
	// open a window ending in 10 minutes in harness 1; build harness 2 on the same StateDir
	// trigger one emit in harness 2 -> Tag "window:w1"
}
func TestWorkWindowEnd(t *testing.T) {
	// open, then a fact with {"window":"w1","end":true} -> next emit has Tag ""
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/agent/ -run WorkWindow -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified (one window at a time; a fact for another window replaces it).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/agent/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "agent: work_window fact stamps the envelope tag"`

---

### Task 32a: Plan tags only on events from the step's own process tree (R6)

Haiku-sized. No task stamped plan tags on events: `actions.WithTag` records resource tags only. The design (Execution engine: Tagging and adoption, "What may be tagged") stamps a plan tag only on events whose process descends from the step's own child; an event from any other process on the host is untagged even while a step runs.

**Files:**
- Create: `internal/agent/tagscope.go`
- Modify: `internal/agent/agent.go` (`emit` consults the scope), `internal/actions/env.go` (register spawned children), `internal/actions/host_exec.go` (the `host.exec` runner registers its child)
- Test: `internal/agent/tagscope_test.go`

**Interfaces:**
- Consumes: the `pid`, `ppid` and `pid_start` payload fields of `process_start`, `file_change` and `conn` (Task 4/4a), `actions.Tag`.
- Produces:

```go
// package agent
type TagScope struct{ /* guarded map: pid+start -> plan tag */ }

func NewTagScope() *TagScope
// Register adds the step's own child process (pid and start time) under the plan tag.
func (s *TagScope) Register(planTag string, pid int, startTime uint64)
// Release removes every process registered under planTag (called when the step ends).
func (s *TagScope) Release(planTag string)
// Tag returns the plan tag for an event: for a process_start whose ppid (with the parent's start time when the event carries it)
// is registered, the child is registered too (descent) and the tag is returned; for any other kind whose pid is registered, the tag;
// otherwise "". Window tags are separate (Task 32).
func (s *TagScope) Tag(kind string, fields map[string]any) string
```

An event that already has a `Tag` keeps it. `shortcut: descent is followed through process_start events the agent sees (audit, winevt); a child started before the agent's sensor attaches is untagged, upgrade when the executor can read /proc/<pid>/task children`. A pid is matched together with its start time so a reused pid is not tagged.

- [ ] **Step 1: Write the failing tests:**

```go
func TestTagScopeChildAndDescendants(t *testing.T) {
	s := NewTagScope()
	s.Register("plan:p1", 100, 5000)
	if got := s.Tag("process_start", map[string]any{"pid": 101, "ppid": 100, "pid_start": uint64(5001)}); got != "plan:p1" {
		t.Fatalf("child: %q", got)
	}
	if got := s.Tag("process_start", map[string]any{"pid": 102, "ppid": 101}); got != "plan:p1" {
		t.Fatalf("grandchild: %q", got)
	}
	if got := s.Tag("file_change", map[string]any{"pid": 102}); got != "plan:p1" {
		t.Fatalf("file_change from a descendant: %q", got)
	}
}
func TestTagScopeIgnoresOtherProcesses(t *testing.T) {
	s := NewTagScope()
	s.Register("plan:p1", 100, 5000)
	for _, f := range []map[string]any{{"pid": 900, "ppid": 1}, {"pid": 901, "ppid": 4}, {"pid": 100, "pid_start": uint64(9999)}} {
		if got := s.Tag("process_start", f); got != "" {
			t.Errorf("%v tagged %q", f, got)
		}
	}
}
func TestTagScopeRelease(t *testing.T) {
	s := NewTagScope()
	s.Register("plan:p1", 100, 5000)
	s.Tag("process_start", map[string]any{"pid": 101, "ppid": 100})
	s.Release("plan:p1")
	if s.Tag("file_change", map[string]any{"pid": 101}) != "" {
		t.Fatal("descendant still tagged after the step ended")
	}
}
func TestEmitStampsOnlyTheStepTree(t *testing.T) {
	// harness: a host.exec step that runs a child; emit a process_start for its child (tagged) and one for an unrelated pid (untagged)
	// while the step runs; after it ends neither is tagged
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/agent/ -run 'TagScope|StampsOnlyTheStepTree' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/agent/ ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "agent: plan tags only on events from the step's own process tree"`

---

### Task 33: JSON Schema of module config blocks

**Files:**
- Modify: `internal/module/schema.go`
- Create: `internal/module/duration.go`, `internal/module/duration_test.go`, `internal/module/all/schema_test.go`, `manifest/schema/modules/` (generated files)
- Test: `internal/module/schema_test.go`

**Interfaces:**
- Consumes: `plan.BlockFor` (Task 12), `module.Registered`, `module.Configurable`, `agent.Registered()` (Task 1).
- Produces: `module.Duration` (R11, the one exception to the one-to-one YAML mapping), `module.Schema(v any) ([]byte, error)`; one `manifest/schema/modules/<name>.schema.json` per contract module; the check that committed files equal the generated ones (`go test ./internal/module/all/ -run Schema -update` rewrites them).

Mapping: struct → `object` with `properties` from json tags (embedded structs flattened), `additionalProperties: false`, `required` = fields without `omitempty`; `string`, `bool` → `boolean`, ints → `integer`, floats → `number`, `module.Duration` → `string` with `"pattern": "^[0-9]+(ns|us|ms|s|m|h)([0-9]+(ns|us|ms|s|m|h))*$"` (a bare `time.Duration` in a settings struct is an error from `Schema`: R11), slices → `array` with `items`, `map[string]T` → `object` with `additionalProperties` = schema of T, pointers → the pointee, `any` → `{}`. Output is indented JSON with sorted keys and `"$schema": "https://json-schema.org/draft/2020-12/schema"`, `"title": <name>`.

- [ ] **Step 1: Remove the skips:**

```go
func TestSchemaOfStruct(t *testing.T) {
	type inner struct {
		N int `json:"n"`
	}
	type cfg struct {
		Common
		Level  int               `json:"level"`
		Hosts  []string          `json:"hosts,omitempty"`
		Inner  inner             `json:"inner"`
		Map    map[string]string `json:"map,omitempty"`
		Window Duration          `json:"window,omitempty"`
	}
	b, err := Schema(cfg{})
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	_ = json.Unmarshal(b, &s)
	props := s["properties"].(map[string]any)
	for _, k := range []string{"enabled", "act_enabled", "auto", "level", "hosts", "inner", "map", "window"} {
		if _, ok := props[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	if s["additionalProperties"] != false || props["level"].(map[string]any)["type"] != "integer" {
		t.Fatalf("%s", b)
	}
}
// internal/module/duration.go: type Duration struct{ time.Duration }; UnmarshalJSON and UnmarshalYAML accept a string ("90s", "2m", "1h30m") and
// reject a number, a negative value and an empty string; MarshalJSON and MarshalYAML write d.String().
func TestDurationRoundTrip(t *testing.T) {
	var s struct {
		Dead Duration `json:"dead" yaml:"dead"`
	}
	if err := yaml.Unmarshal([]byte("dead: 90s\n"), &s); err != nil || s.Dead.Duration != 90*time.Second {
		t.Fatalf("%v %v", s, err)
	}
	if err := json.Unmarshal([]byte(`{"dead":"2m"}`), &s); err != nil || s.Dead.Duration != 2*time.Minute {
		t.Fatalf("%v %v", s, err)
	}
	b, _ := json.Marshal(s)
	if string(b) != `{"dead":"2m0s"}` {
		t.Fatalf("%s", b)
	}
	for _, bad := range []string{`{"dead":90}`, `{"dead":"-5s"}`, `{"dead":""}`, `{"dead":"soon"}`} {
		if json.Unmarshal([]byte(bad), &s) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
func TestSchemaRejectsBareTimeDuration(t *testing.T) {
	type bad struct {
		Common
		D time.Duration `json:"d"`
	}
	if _, err := Schema(bad{}); err == nil {
		t.Fatal("a bare time.Duration in a settings struct must be an error")
	}
}
func TestSchemaOfDuration(t *testing.T) {
	// Schema of a struct with a Duration field: the property is {"type":"string","pattern":...}; "90s", "2m" and "1h30m" match the pattern, "90" does not
}
// internal/module/all/schema_test.go
func TestModuleSchemasCommitted(t *testing.T) {
	// for every agent factory with a manifest: block type from plan.BlockFor(&plan.AgentConfig{}, name)
	// for every controller module implementing module.Configurable: ConfigBlock()
	// generate; with -update write manifest/schema/modules/<name>.schema.json; else compare with the file (diff in the error)
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/module/ ./internal/module/all/ -run Schema -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified; run with `-update` once (no contract module yet, so no file is written until Tasks 38 and 39).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/module/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "module: JSON Schema of config blocks, checked in CI"`

---

### Task 34: Conformance, agent checks 1 to 3

**Files:**
- Create: `internal/module/conformance/leak.go`
- Modify: `internal/module/conformance/agent.go`
- Test: `internal/module/conformance/agent_test.go` (runs the suite over two fixture factories defined in the test: one conforming, one that leaks a goroutine)

**Interfaces:**
- Consumes: `agent.NewHarness` and its methods (Task 15), `plan.BlockFor`.
- Produces: `runAgentChecks(c) map[string]error` with the checks `no_config` (check 1: `Section(&plan.AgentConfig{})` reports disabled or `Build` returns `agent.ErrUnavailable`; neither panics; a panic is recovered and returned as the error), `default_config` (check 2: with `c.Default`, health reaches `ok` or `unavailable` within 10 s), `stops_cleanly` (check 3: after cancel the harness `Run` returns within 5 s and the goroutine set returns to the pre-start set within 1 s, comparing `runtime.Stack(buf, true)` snapshots by top function and ignoring goroutines that existed before); and `conformance.Agent(t, c)`, which runs `runAgentChecks` and reports each entry as a subtest (`t.Run(name, ...)` failing with the error). Later tasks add entries to the same map.

- [ ] **Step 1: Remove the skips:**

```go
func TestAgentChecks1to3Pass(t *testing.T) {
	Agent(t, AgentCase{Factory: goodFactory(), Default: cfgWith("good")})
}
func TestAgentCheck3CatchesLeak(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: leakyFactory(), Default: cfgWith("leaky")}); errs["stops_cleanly"] == nil {
		t.Fatal("goroutine leak not detected")
	}
}
func TestAgentCheck2CatchesHang(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: neverOKFactory(), Default: cfgWith("neverok")}); errs["default_config"] == nil {
		t.Fatal("module stuck in starting not detected")
	}
}
func TestAgentCheck1CatchesPanic(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: panicsWithoutConfigFactory(), Default: cfgWith("p")}); errs["no_config"] == nil {
		t.Fatal("panic on empty config not detected")
	}
}
```

(`goodFactory`, `leakyFactory`, `neverOKFactory`, `panicsWithoutConfigFactory` and `cfgWith` are helpers in `helpers_test.go` of this package: real `agent.Factory` values with small modules, and a config with the named module's block enabled. Each factory uses a unique `Name`; the tests pass the factory to the harness directly and never register it globally.)

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/module/conformance/ -run 'Checks1to3|Check3|Check2' -v`. Expected: FAIL (`unimplemented: W1 Task 34`).
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -short -race ./internal/module/conformance/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "conformance: agent checks 1-3 (no config, default config, clean stop)"`

---

### Task 35: Conformance, agent checks 4 to 7 and 12

**Files:**
- Modify: `internal/module/conformance/agent.go`
- Test: `internal/module/conformance/agent_more_test.go`

**Interfaces:**
- Consumes: Task 34; `event.Validate`, `event.Lookup`; `Factory.Manifest`.
- Produces subtests: `health` (check 4: within 5 s a health block exists; for each OS in `Manifest.OS` other than `runtime.GOOS`, and for `Privilege == "root"` when not running as root, the state is `unavailable` or `degraded` with a non-empty `Gaps`), `declared_kinds` (checks 5 and 12: every emitted event's kind is in `Manifest.Emits` and `event.Validate` passes; every `Consumes` entry is declared with `event.Lookup`), `budget` (check 6: `c.Load` published at 10× `Budget.EventsPerSec` for 3 s; emitted rate ≤ `EventsPerSec × 1.1 + Burst`; reported `HeldBytes` ≤ `HeldMB << 20`; reported `CPUMillis` per second ≤ `CPUMillisPerSec` when non-zero), `link_loss` (check 7: with `EmitErr` failing for `LinkLoss` (60 s; 2 s under `testing.Short()`) and `c.Load` published, the module stays `ok` and the supervisor restarts it zero times).

- [ ] **Step 1: Remove the skips:**

```go
func TestAgentCheck5CatchesUndeclared(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: emitsUndeclaredFactory(), Default: cfgWith("undecl")}); errs["declared_kinds"] == nil {
		t.Fatal("undeclared kind not detected")
	}
}
func TestAgentCheck12CatchesLegacyField(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: emitsConnWithSrcIPFactory(), Default: cfgWith("legacy")}); errs["declared_kinds"] == nil {
		t.Fatal("non-canonical conn field not detected")
	}
}
func TestAgentCheck6CatchesOverBudget(t *testing.T) {
	// the module reports HeldBytes above its HeldMB
	if errs := runAgentChecks(AgentCase{Factory: heldBytesLiarFactory(), Default: cfgWith("fat")}); errs["budget"] == nil {
		t.Fatal("over budget not detected")
	}
}
func TestAgentCheck7CatchesCrashOnEmitError(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: crashOnEmitErrFactory(), Default: cfgWith("fragile"), Load: someLoad()}); errs["link_loss"] == nil {
		t.Fatal("crash under link loss not detected")
	}
}
func TestAgentCheck4CatchesMissingGap(t *testing.T) {
	// manifest OS ["plan9"] but Build succeeds and health is ok with no gaps
	if errs := runAgentChecks(AgentCase{Factory: wrongOSNoGapFactory(), Default: cfgWith("os")}); errs["health"] == nil {
		t.Fatal("missing OS gap not detected")
	}
}
func TestAgentChecks4to7Pass(t *testing.T) {
	Agent(t, AgentCase{Factory: goodFactory(), Default: cfgWith("good"), Load: someLoad()})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/module/conformance/ -run 'Check5|Check12|Check6|Check7|Checks4to7' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -short -race ./internal/module/conformance/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "conformance: agent checks 4-7 and 12 (health, kinds, budget, link loss)"`

---

### Task 36: Conformance, agent checks 8 and 9; controller checks

**Files:**
- Modify: `internal/module/conformance/agent.go`, `internal/module/conformance/controller.go`
- Test: `internal/module/conformance/controller_test.go`, `internal/module/conformance/agent_reconfig_test.go`

**Interfaces:**
- Consumes: Tasks 34 and 35; `plan.BlockFor`; `controller.New`, `RunModules`, `ModuleHealth` (Task 19), `hostFor` through `RunModules`; `module.Configurable`, `module.AnalyzerProvider`.
- Produces agent subtests `reconfig` (check 8: `Apply(c.Reconfig)` replaces the module and, when `KeepKey != ""`, `Kept(KeepKey)` is non-nil after replacement) and `config_decode` (check 9: the block type (`c.Block`, else `plan.BlockFor`; neither is an error) decodes `{"enabled":true,"act_enabled":true}` with `DisallowUnknownFields` with both set, and refuses `{"x_unknown":1}`). Fixture factories in this package's tests set `Block` to their own settings struct. Produces `conformance.Controller(t, c)` with subtests `no_config` (no block: the module ends `unavailable` or `disabled`, no panic), `default_config` (`c.Config` as `modules/<name>.yml` with `enabled: true`: `ok` or `unavailable` within 10 s), `stops_cleanly` (5 s, no leak), `declared_kinds` (every stored event of agent `controller` whose kind starts with the module prefix validates and is in `Emits`), `config_decode` (when `Configurable`: `ConfigBlock()`'s type decodes `enabled: true` and `act_enabled: true` strictly; and the module run with `c.Config` plus the line `x_unknown: 1` ends `unavailable` or `error` within 10 s, never `ok`: a module fails closed on a bad block), `analysers` (check 11: each analyser run twice over a store seeded with `c.Seed` at `c.Now` returns byte-identical JSON) and `tables_replay` (check 11, R10: for a module with `Manifest().Tables`, run it over `c.Seed` plus `c.Commands` (the module's own command events, committed through `Host.Emit` like the operator would), dump its `<module>_*` tables, drop and re-create them, replay the module's committed events and its content files through the writer, and compare: the rebuilt rows must equal the dump; a module whose table holds data no event carries fails with the table and column named). `ControllerCase` gains `Commands []event.Event`.

- [ ] **Step 1: Remove the skips:**

```go
func TestAgentCheck8CatchesLostKeep(t *testing.T) {
	c := AgentCase{Factory: forgetfulFactory(), Default: cfgWith("forget"), Reconfig: cfgWith2("forget"), KeepKey: "baseline"}
	if errs := runAgentChecks(c); errs["reconfig"] == nil {
		t.Fatal("lost Keep state not detected")
	}
}
func TestAgentCheck9CatchesLooseBlock(t *testing.T) {
	// Block is a test settings struct whose UnmarshalJSON ignores unknown keys
	if errs := runAgentChecks(AgentCase{Factory: goodFactory(), Default: cfgWith("good"), Block: &looseSettings{}}); errs["config_decode"] == nil {
		t.Fatal("unknown field accepted")
	}
}
func TestControllerCheck11CatchesNondeterminism(t *testing.T) {
	c := ControllerCase{Module: randomAnalyserModule(), Config: "enabled: true\n", Now: time.Unix(1e9, 0)}
	if errs := runControllerChecks(c); errs["analysers"] == nil {
		t.Fatal("nondeterministic analyser not detected")
	}
}
func TestControllerCheck9CatchesLooseConfig(t *testing.T) {
	// a Configurable module whose Start ignores Host.Config errors and reports ok
	c := ControllerCase{Module: ignoresConfigErrorModule(), Config: "enabled: true\n", Now: time.Unix(1e9, 0)}
	if errs := runControllerChecks(c); errs["config_decode"] == nil {
		t.Fatal("unknown key accepted")
	}
}
func TestControllerCheck11CatchesUnreplayableTable(t *testing.T) {
	// a module whose writer also inserts a row from a UI handler without emitting an event (table ctltest_notes)
	c := ControllerCase{Module: sideWriterModule(), Config: "enabled: true\n", Now: time.Unix(1e9, 0)}
	if errs := runControllerChecks(c); errs["tables_replay"] == nil || !strings.Contains(errs["tables_replay"].Error(), "ctltest_notes") {
		t.Fatal("table that cannot be rebuilt from events not detected")
	}
}
func TestControllerCheck11PassesCommandEvents(t *testing.T) {
	// the same table written only from a command event kind ctltest.note (in Emits, passed in ControllerCase.Commands) rebuilds identically
}
func TestControllerChecksPass(t *testing.T) {
	Controller(t, ControllerCase{Module: goodControllerModule(), Config: "enabled: true\n", Now: time.Unix(1e9, 0)})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/module/conformance/ -run 'Check8|Check9|Check11|ControllerChecks|Replay' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified. The controller harness is a real `controller.New` in `t.TempDir()` with `AgentListen: "127.0.0.1:0"`, `UIListen: "off"` and a manifest directory holding a minimal topology, one host and `modules/<name>.yml`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -short -race ./internal/module/conformance/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "conformance: reconfiguration, strict blocks, controller checks, analyser determinism"`

---

### Task 37: Conformance static checks

**Files:**
- Create: `internal/module/conformance/static_test.go`
- Modify: `internal/module/conformance/allowed.go` (`ModulePackages`: module name → package path, for the 34 catalogue modules plus `health`)
- Test: the file itself; injected-failure cases use fixture packages under `internal/module/conformance/testdata/` (ignored by `go build`, loaded with `go list` against a temp `GOPATH`-free module copy is not needed: parse their files with `go/parser`)

**Interfaces:**
- Consumes: `agent.Registered()`, `module.Registered()`, `event.Declared()`, `PreContract`, `AllowedLibraries`, `CoreImports`, `phylax_design.md`.
- Produces these tests:
  - `TestNoSiblingImports` (check 9, bug 15 guard): for every contract module (a registered agent factory or controller module with a manifest, not in `PreContract`), `go list -deps -f '{{.ImportPath}}' ./<pkg>/...` contains no other module's package (from `ModulePackages`) and nothing under `internal/` outside `CoreImports`, `AllowedLibraries` and its own tree; and its `internal/agent/mods/<name>*.go` files import only core packages, the allowed libraries and its own package (parsed with `go/parser`). `internal/enroll` is never allowed.
  - `TestKindTable` (T46): parse the "Event kinds" table of `phylax_design.md` (rows between the header `| Kind | Class |` and the next blank line); every declared kind outside the test prefixes (`ttest.`, `ctltest.`, `regtest.`) has a row with the same schema, alert flag and class (`common` for the eight common kinds, `core` for the 33 (Tasks 5 and 5a), `module` otherwise); every common and core row is declared; every row whose emitter is a contract module is declared; every contract module's `Emits` kinds have rows naming it as emitter; every `Consumes` entry has a row.
  - `TestPreContractShrinks`: every registered factory or controller module without a manifest is in `PreContract`; every `PreContract` name that now has a manifest fails the test ("remove X from PreContract").
  - `TestConformanceTestPresent`: every contract module's package directory has a `_test.go` file containing `conformance.Agent(` or `conformance.Controller(`.
  - `TestLibrariesStateless`: each `AllowedLibraries` package that exists has no `init` function calling `Register`, `Declare` or `RegisterFactory`, and no package-level `var` of map, slice or pointer type assigned outside `init` (parsed with `go/parser`; `shortcut: syntactic check, upgrade to go/analysis if a library hides state behind a constructor`).

- [ ] **Step 1: Remove the skips** (the five tests above, written in full by Task 1 against the stubs; plus the injected-failure test):

```go
func TestImportCheckCatchesSibling(t *testing.T) {
	// testdata/sibling/a.go is "package x" importing ".../internal/integrity"; checkFileImports("depot", "testdata/sibling/a.go")
	// must return an error naming internal/integrity; testdata/ok/a.go importing internal/signing and internal/sockets returns nil
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/module/conformance/ -run 'Sibling|KindTable|PreContract|ConformanceTestPresent|Stateless|ImportCheck' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the helpers the tests call (`checkFileImports`, `parseKindTable`, `contractModules`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/module/conformance/`. Expected: PASS (no contract module yet besides fixtures; `health` is in `PreContract`).
- [ ] **Step 5: Commit.** `git commit -am "conformance: import, kind-table, pre-contract and presence checks"`

---

### Task 38: Worked example A: `health` on the contract

**Files:**
- Modify: `internal/agent/health.go` (factory `Manifest`, `HealthReporter`, `TelemetryGap` through `event.New`), `internal/module/conformance/allowed.go` (remove `health` from `PreContract`)
- Create: `internal/agent/health_conformance_test.go` (package `agent_test`), `manifest/schema/modules/health.schema.json` (via `-update`)
- Test: `internal/agent/health_conformance_test.go`

**Interfaces:**
- Consumes: everything above.
- Produces: the first agent module on the contract, the pattern every agent retrofit copies:

```go
Manifest: module.Manifest{
	Name: "health", Sides: []module.Side{module.SideAgent}, Privilege: "root", Default: true,
	Emits: []event.Type{mustType("agent.health"), mustType(event.KindTelemetryGap)},
	Budget: module.Budget{CPUMillisPerSec: 1, HeldMB: 1, EventsPerSec: 1, Burst: 64, BytesOutPerMin: 64 << 10},
}
// mustType(kind) = the declared event.Type, panicking if undeclared (an unexported helper in health.go)
```

`Health()` reports `ok` with `Info{"modules": "<count>"}`; `Privilege` is root because it reads the supervisor of a root agent, and on a non-root test run the harness reports the privilege gap as `degraded` (check 4).

- [ ] **Step 1: Remove the skip:**

```go
func TestHealthConformance(t *testing.T) {
	f := factoryNamed(t, "health") // from agent.Registered()
	conformance.Agent(t, conformance.AgentCase{
		Factory:  f,
		Default:  &plan.AgentConfig{Host: "h1", Modules: plan.ModuleSettings{Health: &plan.HealthSettings{ModuleLimits: plan.ModuleLimits{Common: module.Common{Enabled: true}}, IntervalSec: 1}}},
		Reconfig: &plan.AgentConfig{Host: "h1", Modules: plan.ModuleSettings{Health: &plan.HealthSettings{ModuleLimits: plan.ModuleLimits{Common: module.Common{Enabled: true}}, IntervalSec: 2}}},
	})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/agent/ -run TestHealthConformance -v`. Expected: FAIL (`declared_kinds`: manifest empty, or `PreContract` check).
- [ ] **Step 3: Implement** the manifest, `Health()`, the `event.New` gap; remove `health` from `PreContract`; run `go test ./internal/module/all/ -run Schema -update`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/agent/ ./internal/module/...`. Expected: PASS, including `TestNoSiblingImports`, `TestKindTable` and `TestPreContractShrinks` with `health` as a contract module.
- [ ] **Step 5: Commit.** `git commit -am "health: first agent module on the contract"`

---

### Task 39: Worked example B: `suricata` on the contract (controller side)

**Files:**
- Move: `internal/integrations/suricata/*` → `internal/suricata/` (`git mv`; delete the old directory; no shim)
- Create: `internal/suricata/module.go` (controller module, config block, kind declarations), `internal/suricata/conformance_test.go`, `manifest/2027/modules/suricata.yml` (`enabled: false`), `manifest/schema/modules/suricata.schema.json`
- Modify: `internal/suricata/eve.go`, `zeek.go` (kinds `suricata.alert`, `suricata.dns`, `suricata.http`, `suricata.zeek_conn`, `suricata.zeek_dns`; events built with `event.New`; `Agent` left empty, the Host sets `controller`), `internal/module/all/all.go` (blank-import `internal/suricata`)
- Test: `internal/suricata/suricata_test.go` (existing, updated), `internal/suricata/conformance_test.go`

**Interfaces:**
- Consumes: everything above.
- Produces: the first controller module on the contract, the pattern every controller retrofit copies:

```go
type Config struct {
	module.Common `yaml:",inline"`
	Hosts         []string `yaml:"hosts,omitempty" json:"hosts,omitempty"` // where Suricata and Zeek run (controller by default)
}
type Module struct{ /* health behind a mutex */ }
func (*Module) Manifest() module.Manifest // Name "suricata", Sides [controller], Privilege "none", Default false,
	// Emits the six suricata.* kinds (incl. suricata.run), Actions ["suricata.analyze_pcap"], Budget per the module section
func (*Module) Start(ctx context.Context, h module.Host) error // decodes Config; reports unavailable with gap
	// {"suricata.analyze_pcap", "not built (W11)"} and waits for ctx
func (*Module) Health() module.Health
func (*Module) ConfigBlock() any // Config{}
func init() { module.Register(&Module{}) }
```

Payload structs: one per kind, fields exactly the keys `eve.go` and `zeek.go` write today (`suricata.run` has `pcap`, `alerts`, `records`, `error`). The rename map applies: `zeek.conn` → `suricata.zeek_conn`, `zeek.dns` → `suricata.zeek_dns`. This fixes the `suricata` half of Known bug 17 (`Agent: "suricata"`/`"zeek"` is gone).

- [ ] **Step 1: Remove the skips:**

```go
func TestSuricataConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Module{}, Config: "enabled: true\n", Now: time.Unix(1e9, 0)})
}
func TestReadEVEEmitsDeclaredKinds(t *testing.T) {
	evs, _, err := ReadEVE(mustOpen(t, "testdata/eve.json"), false)
	if err != nil || len(evs) == 0 {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Agent != "" {
			t.Fatalf("reader must not set the agent: %q", e.Agent)
		}
		if err := event.Validate(e); err != nil {
			t.Fatalf("%s: %v", e.Kind, err)
		}
	}
}
func TestReadZeekKinds(t *testing.T) {
	evs, _, _ := ReadZeek(mustOpen(t, "testdata/conn.log"), KindZeekConn)
	if len(evs) == 0 || evs[0].Kind != "suricata.zeek_conn" {
		t.Fatalf("%v", evs)
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/suricata/ -v`. Expected: FAIL (package not found until the move, then kind errors).
- [ ] **Step 3: Implement** the move and the module; check `grep -rn 'integrations/suricata\|"zeek\.' --include=*.go .` returns nothing.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS, including the static checks with `suricata` as a contract module.
- [ ] **Step 5: Commit.** `git commit -am "suricata: move to internal/suricata; first controller module on the contract"`

---

### Task 40: `phylax modules` and the Platform page module table

**Files:**
- Create: `cmd/phylax/modules.go`
- Modify: `cmd/phylax/main.go` (dispatch `modules`; import `internal/module/all` instead of `internal/agent/mods`), `internal/ui/reports.go` + `internal/ui/templates/health.html` (module table), `internal/ui/ui.go` (`Ops` gains `Modules(ctx) []ModuleRow`), `internal/controller/webops.go` (implements it from `AgentHealth`, `ModuleHealth` and `PreContract`)
- Test: `cmd/phylax/modules_test.go`, `internal/ui/modules_page_test.go`

**Interfaces:**
- Consumes: `agent.Registered()` (Task 1), `module.Registered()`, `conformance.PreContract` (import from `cmd/phylax` is fine; it is a plain list), `ui.ModuleRow`, `AgentHealth`, `ModuleHealth`.
- Produces: `phylax modules [-json]` printing one line per module (`name sides os default emits-count status`) or the manifests as JSON, `status` being `contract` or `pre-contract`; the `/health` page gains a table of every agent's and the controller's module health (state, detail, gaps), pre-contract modules marked.

- [ ] **Step 1: Remove the skips:**

```go
// cmd/phylax/modules_test.go
func TestModulesCommand(t *testing.T) {
	var out bytes.Buffer
	if err := runModules([]string{"-json"}, &out); err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name   string          `json:"name"`
		Status string          `json:"status"`
		Manifest module.Manifest `json:"manifest"`
	}
	_ = json.Unmarshal(out.Bytes(), &rows)
	// want: a row "health" status contract; a row "suricata" status contract; a row "audit" status pre-contract
}
// internal/ui/modules_page_test.go
func TestHealthPageModuleTable(t *testing.T) {
	// Ops fake returning rows {Agent: "h1", Module: "audit", State: "degraded", Gaps: ["<b>x</b>: y"], PreContract: true}
	// logged-in GET /health -> 200; body contains "audit", "pre-contract", and the gap text escaped (&lt;b&gt;)
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./cmd/phylax/ ./internal/ui/ -run 'ModulesCommand|ModuleTable' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race && ./bin/phylax modules`. Expected: PASS; the command lists `health` and `suricata` as contract and the other registered modules as pre-contract.
- [ ] **Step 5: Commit.** `git commit -am "cmd: phylax modules; Platform page module health"`

---

### Task 41: CI gates

**Files:**
- Modify: `.github/workflows/ci.yml`, `Makefile`
- Create: `internal/module/conformance/skip_guard_test.go` (Known bug 11 guard)
- Test: `internal/module/conformance/skip_guard_test.go`

**Interfaces:**
- Consumes: the conformance package (Tasks 34 to 37).
- Produces: `TestKindCounts` (M1): the three numbers in the Event kinds prose of `phylax_design.md` ("There are N kinds: 8 common kinds, C core kinds and M module kinds") equal the counts computed from the table, and the test names in the T46 row ("All twelve checks") equal the conformance suite's check list length; a drift fails CI. `make conformance` = `go test -race -count=1 ./internal/module/... ` plus every package containing a `conformance_test.go` (`go test -race -count=1 -run Conformance ./...`); CI triggers on pushes to `v4` and `v4-*` and on pull requests; separate jobs `build` (`make build build-windows size vet`), `test` (`go test ./...`), `race` (`go test -race ./...`), `conformance` (`make conformance`, full 60 s link loss, no `-short`); `TestSkipsCarryReason`: every `t.Skip(`/`t.Skipf(` call in a `_test.go` file under `internal/` and `cmd/` has a non-empty string argument (parsed with `go/parser`), and every `t.SkipNow()` has a `shortcut:` or reason comment on the line above.

- [ ] **Step 1: Remove the skip:**

```go
func TestSkipsCarryReason(t *testing.T) {
	bad := findBareSkips(t, "../../..") // walks internal/ and cmd/, parses *_test.go, returns "file:line" for t.Skip() with no or empty argument
	if len(bad) > 0 {
		t.Fatalf("t.Skip without a reason (Known bug 11):\n%s", strings.Join(bad, "\n"))
	}
}
```

- [ ] **Step 2: Run, expect FAIL or PASS.** Run: `go test ./internal/module/conformance/ -run TestSkipsCarryReason -v`. Expected: FAIL listing offenders if any exist; fix each by adding the reason the skip already implies (the precondition it checks). If none exist, the test passes on first run; keep it as the guard.
- [ ] **Step 3: Implement** the workflow and Makefile changes. Mark `race` and `conformance` as required checks in the repository settings (David does this in GitHub; note it in the pull request).
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows size vet test race conformance`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "ci: race and conformance jobs on v4 and v4-*; t.Skip reason guard"`

---

### Task 42: Lab (stronger agent or David)

**Files:**
- Create: `docs/impl/lab/w1-module-contract.md`

Run on the BTaP replica (`stacks/ccdc`: `ubuntu-wkst` as controller, `rocky-ecom`, `ubuntu-email`, `win11`, `ad`), from a build of the merged branch:

- [ ] **Step 1: Platform.** Every agent's heartbeat shows per-module health on `/health`; `health` and `suricata` show as contract modules, the rest pre-contract; a non-root test agent shows the privilege gap. Record screenshots or the page text.
- [ ] **Step 2: Facts (T74 core half).** Send a `round_clock` fact from a test controller module to `rocky-ecom` and `win11`; confirm `controller.fact` on each bus (agent debug log) and none in the store; cut the link for longer than the TTL and confirm the fact reads unknown; send a `work_window` fact, run `touch` on the host and confirm the `file_change` (once W3 exists; today any agent event) carries the window tag, then let it end with the link down.
- [ ] **Step 3: Approval classes (T73).** Run a read-only template with `RunReadOnly`, a refused write template, a standing approval in scope and out of scope (and after expiry), and an `auto` template with `act_enabled` false (proposal), true with no probe (proposal), and with a probe stub that goes red after the change (rollback, then breaker halt after the second).
- [ ] **Step 4: Controller restart and spool (T18, T29 partial).** Restart `phylax serve` mid-run; confirm the controller chain continues (no seq 1 after restart) and agents resume; `kill -9` an agent during a burst and confirm its spool repairs and events with `schema` and `tag` verify.
- [ ] **Step 5: Record and commit.** Write the date, commit, VMIDs, each step's result and measured values, and what was not run, to `docs/impl/lab/w1-module-contract.md`. `git commit -m "lab: W1 module contract results"`.

---

## Self-review

**Spec coverage** (design "The module contract" and the core pieces W1 owns):

| Design requirement | Task |
| --- | --- |
| One package, registration file, config block with `enabled`/`act_enabled`, unknown fields an error, schema from struct | 11, 12, 33, 36 (check 9) |
| Declared typed events, `Declare`/`Lookup`/`New`/`Decode`, schema versions | 3, 4, 5 |
| Envelope `Schema` and `Tag`, protocol minor | 2 |
| Kinds for the console-script alerts, a locked controller and the store quota (R1, R8, R9) | 5a |
| Disk quotas, shed order, audit exemption (R9) | 8b |
| Per-host `act` and `safe_mode_hosts` (R2) | 11b |
| Probe inside the node, confirm after the after-probe, `rollback_plan` default, `busy` (R12) | 27, 27b, 27c |
| Tags only on our own activity (R6) | 32, 32a |
| `module.Duration` (R11); table replay (R10) | 33, 36 |
| Canonical fields of common kinds, `x_` prefix, rules reject others (CI half) | 4, 35 (check 12) |
| Kind table single source, compared with the registry and `Consumes` (T46) | 37 |
| Capability manifest, published by `phylax modules` and in `hello` | 1, 7, 14, 40 |
| Agent `Factory.Manifest`, `HealthReporter`, `ModuleSpec` from budget, `Subscribe` kinds | 13 |
| Controller `Host`, `ControlMsg`, `ControllerModule`, `Analyzer` | 17, 18, 19, 20, 23-30 |
| Persistence rule: one writer, module tables, query API | 8, 17 |
| Health and budgets, heartbeat per-module block (bug 16 core) | 13, 14 |
| Configuration: host `modules:`, effective enablement, observe-mode switch | 7, 11, 12 |
| Isolation: no sibling imports, shared libraries closed list | 37 |
| Conformance checks 1-12 | 34 (1-3), 35 (4-7, 12), 36 (8, 9, 11), 41 (10: `-race` job) |
| Controller executor, approval classes, auto conditions, breaker (T73, T79 core half) | 22-29 |
| `actions.Register`, `RegisterUndo`, `Unsupported`, `Env.Now`, `Env.Ext` (one registration name) | 2a |
| `Event.WithExtra`, extension fields on the common structs | 3a, 4a |
| `storetest.New`; `Host.Manifest`, `Host.UpdateOverrides`, prefix secrets; `AppendOverrides` | 8a, 9a, 11a, 17a |
| Plan options `expires_after` and `gate: auto`; `LoadModuleTemplateFor`; `plans` in `CoreImports` | 22a, 22b, 27a |
| Lint registration and `SS000` | 21 |
| `control: fact`, `controller.fact`, subtypes, `work_window` effect (T74 core half) | 30, 31, 32 |
| UI registrar, Platform module health | 10, 40 |
| Controller-origin events under agent `controller` (bug 17 core) | 16, 39 |
| Known bug 11 guard | 41 |
| Retrofit order: contract, conformance, Host and registrar, then modules; "pre-contract" listing | task order; 37, 40 |

Not in W1, by design: per-module content (`rules/<module>/`, `plans/<module>/`) and every module retrofit other than `health` and `suricata` (README workstreams); the agent's last-line re-lint of `auto` plans beyond the existing guard (`shortcut` noted in Task 21's rule; W5 extends the guard data); label-expression targets inside templates beyond `LoadModuleTemplateFor`'s `{labels: expr}` variables (W5); the plan options `window: scorer_quiet`, `gate: manual` and `txn:` (W7 Tasks 3 and 4; W5 and W10 depend on W7 Tasks 2 to 7).

**Step scan:** every test step carries test names and assertions; prose-only test bodies (Tasks 6, 14, 27, 30, 31, 42 and the store/vault helpers) name the exact setup helper, the action and the assertion, because they drive existing e2e harnesses whose helper names the implementer reads from the package's own `_test.go` files. No step says "handle edge cases" or "add validation" without the rule.

**Type consistency:** `store.Reader` everywhere (never `store.Query` as an interface); `module.ErrProposed` for every fallback; `Host` plan methods take `(template, params)`; `ModuleDB.Migrate` (no `Store.MigrateModule`); `Env.Subscribe(buf, kinds...)`; `event.ControllerFact` is the fact args and the `controller.fact` payload; `plan.ClassAuto` etc. match the design's class names.

**Review Focus:** each of the five lines has its test in the owning task (2, 3/6, 16, 26, 31).

**Proportion:** the plan is about a sixth of the design's length; code blocks are signatures and tests, with no function bodies except where an algorithm is not fixed by the test (none needed one).
