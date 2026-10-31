# W4: Detection and Response Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move `detect` onto the module contract and finish its engine (`lists`, `exceptions`, `rate`, `replay`, `jitter`, mode promotion, controller-scope evaluation, evidence collectors), build `respond` (tier-0 runner with guards, breaker and loop stop; recipes; the A-AUTO tier-0 set; controller proposals and `Host.RunAuto`) and `content_guard` (golden store, six constraints, boot-critical list), and port the rule corpus into `rules/detect/` behind a rule-id registry.

**Architecture:** `internal/detect` keeps its evaluator and gains a module wrapper (agent side) and a controller module (scope `controller` rules over committed events). `internal/respond` has an agent side that consumes `detect.alert` and runs signed recipes through the agent's own `actions.Env` (dead-man armed for the breaker window, confirmed only when every probe stays green) and a controller side that turns alerts into one-click proposals and `RunAuto` plans. `internal/content_guard` is agent-only and restores a short list of files from a plan-tagged golden store. Recipes, rules, lists and plan templates are YAML content under `rules/` and `plans/respond/`; the three new actions families (`proc.*`, `dir.snapshot`, `guard.*`) plus `sysmon.install` are small Go.

**Tech Stack:** Go 1.27.2 (mise), `gopkg.in/yaml.v3`, `golang.org/x/sys`, `internal/atomicfile`. No new modules in `go.mod`.

**Spec:** `phylax_design.md` (v4): "Rule format" (1731), modules `detect` (2877), `respond` (3096), `content_guard` (3300); "Execution engine" (approval classes, auto conditions, session eviction, the scoring-safety lint exceptions, Processes and Files action families); Known bugs 2 and 22; Test matrix T02, T03, T16, T20, T36, T52, T74 (respond half), T75 (rule half), T79 (rule promotion pass); Appendix D (rules layout). Master plan: `docs/impl/README.md`. Contract names: `docs/impl/01-module-contract.md` (W1) Interfaces blocks; W3 (`docs/impl/03-telemetry.md`) Produces names for kinds and the `json.Number` fix; W5 and W6 plans for the action names recipes call.

## Design gaps and decisions (Task 1 writes each into `phylax_design.md` in the same commit)

1. **The agent `Env` cannot run an action.** `agent.Env` has `Subscribe`, `Keep`, `Fact`, `Health`; the actions environment lives in `agent.ExecConfig`. `respond` and `content_guard` need to execute actions locally, with the dead-man, locks and the scoring guard. Task 1 adds `func (e Env) Actions() *actions.Env` (nil when the agent runs without `ExecConfig`; a module that needs it then reports `unavailable`).
2. **`agent.health` does not carry module `Info`, and is not emitted when it changes.** The rule `D10.audit-rules-changed` (heartbeat rules hash, Known bug 16's consumer) cannot see `rules_hash` today; W1 puts `Health` in the heartbeat but leaves the `agent.health` event as it is, and its `HealthSource` has no module health. Task 11 adds `HealthSource.ModuleHealth()`, copies state and `Info` into `modules.<name>`, and emits at once when a module's state or `Info` changes (the design already says the supervisor does).
3. **Two rules want the id `D10.audit-rules-changed`.** The corpus rule on the `audit.rules_changed` event (tier 0, no recipe: the `audit` module repairs its own rules) is renamed `D10.audit-rules-event`; the id `D10.audit-rules-changed` goes to the controller-scope rule on `agent.health` the design names.
4. **An alert needs an id before it is sealed.** `evidence.blob` references the alert, the spool assigns `seq` later. `detect.alert` gains `id` (16 hex characters, `sha256(agent|rule|time_ns)`), set by the engine.
5. **`evidence.blob` (W1 Task 5) lacks `collector`, `truncated`, `error`.** Task 1 adds them. Chunk upload of the blob (Wire protocol: file-chunk transfer) is W11's `fetch`/chunk work (Known bug 4); until then the item stays under `StateDir/evidence/<alert id>/` and `evidence.blob` announces it with `chunks: 0` (`shortcut: blobs are announced but not uploaded, upgrade when W11's chunk transfer merges`). The two controller-side collectors (`transactions_window_10m`, `trace_back`) and the controller's `freeze_capture` (Known bug 7, W6) are not built here; the loader accepts the names.
6. **`overrides.yml` has no `rule_modes`, `exceptions` or reset record, and nothing writes it.** Task 9 adds `Overrides.RuleModes`, `Overrides.Exceptions`, `Overrides.RespondResetEpoch` and `manifest.AppendOverrides(dir, fn)` (atomic read-modify-write; comments in the file are not preserved, `shortcut`). The Alerts page's "silence" button (a UI-shell item) calls it; W4 builds no button.
7. **`respond.breaker` has no `rule`, and `respond` has no controller consumers for it.** The auto-demotion rule (a promoted rule that opens a breaker twice) needs the rule id. `respond.breaker` gains `rule`; the controller side of `respond` consumes `detect.alert`, `respond.action` and `respond.breaker` (the kind table's consumer column is updated). "Twice" counts breakers for the rule since its promotion record's `added` time (24 h when the mode came from the rule file).
8. **Re-enabling a breaker needs a signed path to the agent.** The five fact subtypes do not fit. `Overrides.RespondResetEpoch` is folded into `RespondSettings.ResetEpoch`; the agent clears all breaker and loop state when the epoch in the signed config exceeds the one it kept. The UI's "re-enable" button bumps the epoch with `AppendOverrides` and pushes the config.
9. **The design YAML for `respond` and `content_guard` does not map 1:1 onto the Go settings** (`breaker_window: 2m` against `BreakerWindowSec`; `services: {ecom-http: alert}` against `[]GuardService`). Each module gets a `Config` struct that is the block's YAML (the design YAML, unchanged) and the controller converts it into `plan.RespondSettings` / `plan.ContentGuardSettings`.
10. **Rollback of a tier-0 action reuses the dead-man journal.** The runner calls `actions.Env.Execute` with `Request.Deadman` = breaker window + 30 s, probes for the whole window, then `Confirm`s; a red probe calls `Rollback`. An action that returns no rollback data (`ErrNotReversible`) cannot run at tier 0 and is reported `skipped_guard` (a click proposal follows).
11. **"Scorer-labelled source" is not known on the agent.** `source_block` never blocks an address in `Tier0Settings.NeverBlock` (manifest-listed own addresses, controller, relays, Kali, learned scorer runner ranges, rendered by the controller). Divisor re-draws scorer addresses, so the list can lag (`shortcut`); the trigger (a decoy login or a honey credential, never on a scored port) and the post-block probe are what protect the scorer.
12. **Per-object rate.** The design gives the host cap (3 per minute) but no per-object cap. Decision: 1 per minute per `(host, object)`; loop detection (3 in 10 minutes) does the rest.
13. **Respond and detect cannot import each other** (no sibling imports). `respond` reads `detect.alert` through its own loose view struct (not `event.Decode`, which is strict and would reject a new alert key); the cross-check "every recipe trigger names a real rule id, every promoted rule has a recipe" runs in `internal/e2e` and in `cmd/phylax` (the binary may import both).
14. **Actions owned by other workstreams are not registered yet** (`fw.restore`, `fw.apply`, `unit.disable`, `task.disable`, `runkey.remove`, `ad.recycle_restore`, `ad.gpo_unlink`, `session.terminate_predating`, `binary.restore_from_depot`, `hunt.persistence`). `internal/respond/pending.go` lists each with its workstream; the recipe check accepts a listed name, and a test fails when a listed name is registered (delete the entry). The same pattern applies to rules: a rule whose event kind is not declared yet lives in `rules/pending/` with `needs: kind:<kind>`, and `TestPendingRulesStillNeedSomething` fails when that kind has been declared.
15. **Rules layout.** `rules/detect/*.yml` (every rule has `module: detect`), `rules/ported/*.yml` (hand-ported, `module: detect`), `rules/pending/*.yml`, and at the top `rules/lists.yml`, `rules/profiles.yml`. The D15 rules (owned by `decoys` and `honeytokens`) stay in `rules/detect/deception.yml` until W9 moves them. All packs go to all hosts unless the block's `packs:` names a subset (`shortcut: no per-OS pack filter, upgrade if the held-memory budget is exceeded`). `D14` is reserved for `devices` (Known bug 2).
16. **Controller-scope rules use receive time and ignore replayed events** (design builder check). The controller module stamps `Time` with its clock before `Process`. The pass-the-hash pack needs a `source_label` field only `traceback` (W8) can supply; the pack ships in `rules/pending/` with `needs:` (open item in the design: the controller enriches events from `traceback` label events by store query; W8 declares the kind).
17. **Fact payload shapes `respond` reads are assumptions the senders must match** (hand-offs, listed in the final task): `scorer_probe_result` from `checks` (W7): id `scorer_probe:<service>`, `Data{"service": string, "ok": bool}`, ttl at least 2 round delays; `gpo_finding` from `ad` (W5): id the GPO GUID, `Data` keys looked up case-insensitively: `affects`, `section`, `item`, `enforced`.
18. **`sysmon.install` has no owner** (W3 gap 8b; W5 did not take it). Built here (Task 23) because the `sysmon_reinstall` recipe needs it.
19. **`Touch.Op = "restore"` (`actions.OpRestore`)** is the marker both `ad.recycle_restore` (W5) and `guard.restore` use for the scored-content exception. Whichever merges first adds the constant; the second reuses it. `StaticGuard` gains `RestorePaths []string` (Task 36).
20. **`content.guard` is not in the manifest.** `manifest.Content` gains `Guard []string` (Task 34).
21. **`content_guard` is agent-only, so it has no controller side to register its page, tile and host-grid column.** Not built here (`shortcut: no Content guard page; the events show in the event views and the Platform page shows health, upgrade by giving the module a controller side when W10 builds the host x step grid`). Its manifest lists no `Pages`. The "clear a loop" and "re-take the golden copy" buttons are the same `AppendOverrides` epoch mechanism as gap 8 (`GuardClearEpoch`) and a `guard.snapshot` plan proposal.
22. **The recipe format needs six step flags the design example does not show:** `optional` (skip silently when an entity is absent), `gate` (a read-only step whose named output must be non-empty or the recipe stops: `yara.scan` before a quarantine), `block` (the `source_block` guards), `os` (`linux` or `windows`), `probe` and `rollback` (the step touches scored state, A-AUTO), plus recipe-level `unscored_hosts_only`. A recipe parameter may contain `${name}`, expanded by the controller per host (Task 38) or, for `${now}`, by the runner.

## Global Constraints

- Go 1.27.2 via mise; `CGO_ENABLED=0`; `make build build-windows vet test race` passes at every commit (linux/amd64 and windows/amd64 both build and vet). `-race` needs `CGO_ENABLED=1`.
- Every package ships tests; tests exercise the real code (no mock of the code under test; fakes only at the edge the package does not own: a fake `actions.Action` registered in a fresh `actions.NewRegistry()` for the runner, a fake `ProcBackend`, a fake ADBackend). A test that needs privileges, Windows or containers calls `t.Skip` with a reason string.
- Commits are small, one logical change, message `area: summary` (for example `detect: lists and the list operator`). No attribution lines of any kind.
- No shelling out in the default path (`sysmon.install` and the Windows `bcdedit` use the existing allowlisted `Executor`). Bounded queues, buffers, decoded sizes, timeouts. Atomic writes through `internal/atomicfile` for state files (golden index, breaker state, block records).
- No compatibility shims, aliases or dual formats: a renamed rule id, field or kind is renamed everywhere (rules, recipes, tests, `docs/rules.md`) in the same commit.
- A module imports only the core packages and the shared libraries listed in W1's Global Constraints. `detect`, `respond` and `content_guard` import each other never.
- Times are UTC. Secrets never appear in events, logs, alerts or config.
- The default is off and alert-only: `act_enabled` false, recipes allowed list empty, every content_guard service `alert`. An automatic action runs only with `act_enabled` true, safe mode off, the recipe in `Tier0.Allowed` and in the signed config, every probe known and green.
- Tier 0 never runs `proc.kill_tree`, `proc.suspend`, an action of risk `destructive`, a scored-password change outside a `resync`, krbtgt, a device revert or a whole-service restore. CI rejects a recipe that lists one under `tier0:` or `auto:`.
- A tier-0 step takes its parameters only from the alert's `entities` or from literals in the signed recipe; the value passes the action's typed parameter check and the scoring guard.
- Code style ponytail: the smallest complete change; a known limit carries `// shortcut: <limit>, <when to upgrade>`.
- The design is authoritative; a forced design change edits `phylax_design.md` in the same commit with the reason.

## Review Focus

1. **Unknown means do not act.** No `scorer_probe_result` fact yet, an expired one, a scored service with no `health:` block, a probe that errors: expected a `respond.action` with `skipped_guard` and a click proposal, never an apply (Task 26 `TestUnknownVerdictNeverActs`, Task 30 `TestSkippedTier0BecomesProposal`).
2. **Hostile event values used as action parameters.** A file path with `..` or a newline, a unit name with a space, an entity that the alert does not carry: expected `skipped_guard`, no action call (Task 27 `TestParamMustBeAnEntity`, `TestHostileEntityRefused`).
3. **Replayed history.** An enrollment backscan or a resent spool carries old events flagged `replay: true`: expected no alert, no `count` window entry, no response (Task 7 `TestReplayExcluded`).
4. **The restorer fights the red persistence or a GPO.** A timer disables the firewall every minute; an Enforced GPO reverts Defender: expected the third restore stops (`respond.loop`), a GPO fact turns it into `skipped_gpo` (Task 25 `TestLoopOpensOnThird`, Task 26 `TestGPOStopsLoop`).
5. **A guarded content file is replaced by a symlink, deleted, or changed while a plan holds the lock.** Expected: the guard never follows the link, restores a deleted listed file, ignores a tagged or lock-held change and marks the golden stale (Task 34 `TestSymlinkPathRefused`, Task 35 `TestTaggedChangeMarksStale`, `TestDeletedFileRestored`).

---

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `internal/detect/kinds.go` | `detect.alert`, `detect.suppressed` payloads and `Declare` | 1 |
| `internal/detect/module.go`, `manifest.go`, `config.go` | agent module, manifest, block `Config`, health | 2 |
| `internal/detect/fieldcheck.go` | canonical-field and declared-kind check | 3 |
| `internal/detect/lists.go`, `exceptions.go`, `rate.go`, `jitter.go`, `modes.go` | engine additions | 4 to 9 |
| `internal/detect/controller.go` | controller module (scope `controller`) | 10 |
| `internal/detect/collect*.go` | evidence collectors | 12 |
| `internal/detect/registry.go`, `tree.go`, `attack.go`, `attack_v19.txt`, `thirdparty.go` | id registry, rule tree loader, ATT&CK ids, third-party list | 13 to 15 |
| `internal/detect/ui.go` | Rules page, tile | 33 |
| `rules/detect/*.yml`, `rules/ported/*.yml`, `rules/pending/*.yml`, `rules/lists.yml`, `rules/profiles.yml` | rule corpus | 13, 16 to 19 |
| `cmd/phylax/rules.go` | `phylax rules test`, `registry`, `third-party`, `promote` | 15 |
| `internal/actions/proc.go`, `proc_linux.go`, `proc_windows.go`, `proc_other.go`, `dirsnap.go`, `sysmon.go` | `proc.*`, `dir.snapshot`, `sysmon.install` | 20 to 23 |
| `internal/respond/` | `kinds.go`, `recipe.go`, `validate.go`, `pending.go`, `guards.go`, `breaker.go`, `runner.go`, `controller.go`, `config.go`, `manifest.go`, `ui.go` | 24 to 33 |
| `rules/respond/*.yml`, `rules/respond/recipes.go`, `rules/respond/boot_critical.yml` | recipes (embedded), boot-critical list | 28, 29, 32, 37 |
| `plans/respond/*.yml` | one-node plan templates for proposals and auto plans | 28, 29, 32 |
| `internal/content_guard/` (package `contentguard`) | `kinds.go`, `golden.go`, `actions.go`, `watch.go`, `restore.go`, `modes.go`, `boot.go`, `module.go`, `config.go`, `ui.go` | 34 to 37 |
| `internal/controller/genconfig.go` | renders the three blocks into the signed config | 38 |
| `manifest/2027/modules/{detect,respond,content_guard}.yml` | reference blocks | 38 |
| `internal/e2e/detect_respond_test.go` | recorded-alert replay, id cross-checks | 39 |
| `docs/impl/lab/w4-detection-response.md` | lab record | 40 |

---

### Task 1: Seams (Sonnet or Opus)

Done by a stronger model. Declares the nine kinds, writes the settings structs, the package skeletons with stub bodies, the extension fields on W1 and W3 types, the design edits and every skipped test file the later tasks implement. Merges on its own (its own pull request into `v3-redesign`); W9 waits for it (it needs `detect.alert`).

**Files:**
- Create: `internal/detect/kinds.go`, `internal/respond/{doc.go,kinds.go,recipe.go,validate.go,pending.go,guards.go,breaker.go,runner.go,controller.go,config.go,manifest.go}`, `internal/content_guard/{doc.go,kinds.go,golden.go,watch.go,restore.go,modes.go,boot.go,module.go,config.go}` (package `contentguard`), `rules/respond/recipes.go`, `internal/agent/mods/{respond,content_guard}.go`
- Modify: `internal/agent/registry.go` (`Env.Actions`), `internal/event/core.go` (`EvidenceBlob`), `internal/plan/agentconfig.go` (settings structs, `ModuleSettings`), `internal/manifest/types.go` (`Overrides`, `Content.Guard`), `internal/module/all/all.go`, `internal/module/conformance/allowed.go` (`ModulePackages` entries for `respond`, `content_guard`), `phylax_design.md`
- Create: every test file named in Tasks 2 to 39 with the test bodies of that task's Step 1, first statement `t.Skip("unimplemented: W4 Task N")`; shared helpers (`internal/respond/testutil_test.go`: `newRunnerFixture`, `fakeAction`; `internal/detect/testutil_test.go`: `mustRuleSet`, `ev`).

**Interfaces:**
- Consumes: W1 Task 1 to 5 names (`event.Declare`, `event.New`, `event.Decode`, `module.Manifest`, `module.Common`, `module.Health`, `module.ControllerModule`, `module.Host`, `agent.Factory`, `agent.HealthReporter`, `plan.ModuleLimits`, `event.ControllerFact`); W3 Task 1 (`event.Event.WithExtra`, the replay field on common structs, `actions.RegisterExtra(f func() []Action)`).
- Produces (exact):

```go
// ---- internal/detect/kinds.go (Declare in init; alert flag true for detect.alert) ----
const (
	KindAlert      = "detect.alert"      // schema 1, critical, Alert true
	KindSuppressed = "detect.suppressed" // schema 1, normal
)
type AlertEvidence struct {
	Kind   string         `json:"kind"`
	Time   string         `json:"time"` // RFC 3339, UTC
	Fields map[string]any `json:"fields"`
}
type AlertFields struct {
	ID       string            `json:"id"` // 16 hex of sha256(agent|rule|time_ns)
	Rule     string            `json:"rule"`
	Title    string            `json:"title"`
	Severity string            `json:"severity"`
	Tier     int               `json:"tier"`
	Mode     string            `json:"mode"` // act | alert
	Message  string            `json:"message"`
	Attack   []string          `json:"attack"`
	Collect  []string          `json:"collect,omitempty"`
	Entities map[string]string `json:"entities,omitempty"`
	Evidence []AlertEvidence   `json:"evidence,omitempty"`
	Source   map[string]string `json:"source,omitempty"`
}
type SuppressedFields struct {
	Rule   string            `json:"rule"`
	Count  int               `json:"count"`
	Window string            `json:"window"`
	By     map[string]string `json:"by,omitempty"`
}

// ---- internal/respond/kinds.go (Declare in init) ----
const (
	KindAction  = "respond.action"  // schema 1, high
	KindBreaker = "respond.breaker" // schema 1, critical
	KindLoop    = "respond.loop"    // schema 1, critical
)
const ( // ActionFields.Outcome
	OutApplied = "applied"; OutFailed = "failed"; OutRolledBack = "rolled_back"
	OutSkippedSafeMode = "skipped_safe_mode"; OutSkippedGuard = "skipped_guard"; OutSkippedRate = "skipped_rate"
	OutSkippedBreaker = "skipped_breaker"; OutSkippedLock = "skipped_lock"; OutSkippedGPO = "skipped_gpo"
)
type ActionFields struct {
	Alert   string `json:"alert,omitempty"` // detect.alert id
	Rule    string `json:"rule"`
	Recipe  string `json:"recipe"`
	Action  string `json:"action"`
	Target  string `json:"target,omitempty"`
	Outcome string `json:"outcome"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
	Undo    string `json:"undo,omitempty"`   // dead-man entry id while armed, "confirmed" after
	Health  string `json:"health,omitempty"` // green | red:<service> | unknown:<why>
	Tag     string `json:"tag,omitempty"`
}
type BreakerFields struct {
	Action   string `json:"action"`
	Host     string `json:"host"`
	Rule     string `json:"rule"`
	Reason   string `json:"reason"`
	Reenable string `json:"reenable"`
}
type LoopFields struct {
	Object  string `json:"object"`
	Recipe  string `json:"recipe"`
	Count   int    `json:"count"`
	Window  string `json:"window"`
	Lineage string `json:"lineage,omitempty"`
}

// ---- internal/content_guard/kinds.go (package contentguard) ----
const (
	KindChange   = "content_guard.change"   // schema 1, high
	KindRestore  = "content_guard.restore"  // schema 1, high
	KindStop     = "content_guard.stop"     // schema 1, critical
	KindPromoted = "content_guard.promoted" // schema 1, normal
)
type Writer struct {
	PID  int    `json:"pid,omitempty"`
	Exe  string `json:"exe,omitempty"`
	AUID int64  `json:"auid,omitempty"`
}
type ChangeFields struct {
	Service       string `json:"service"`
	Path          string `json:"path"`
	Op            string `json:"op"`
	GoldenSHA256  string `json:"golden_sha256,omitempty"`
	CurrentSHA256 string `json:"current_sha256,omitempty"`
	Writer        Writer `json:"writer"`
	Mode          string `json:"mode"`     // alert | act
	Decision      string `json:"decision"` // alert | restore | ignored_tag | ignored_plan_lock
}
type RestoreFields struct {
	Service      string `json:"service"`
	Path         string `json:"path"`
	GoldenSHA256 string `json:"golden_sha256"`
	ProbeBefore  string `json:"probe_before"`
	ProbeAfter   string `json:"probe_after"`
	Result       string `json:"result"` // restored | rolled_back | probe_failed
}
type StopFields struct {
	Service string `json:"service"`
	Path    string `json:"path"`
	Reason  string `json:"reason"` // loop | probe_failed | golden_missing
	Count   int    `json:"count,omitempty"`
}
type PromotedFields struct {
	Service       string `json:"service"`
	From          string `json:"from"`
	To            string `json:"to"`
	ShadowMinutes int    `json:"shadow_minutes"`
	WouldRestores int    `json:"would_restores"`
	ProbeGreen    bool   `json:"probe_green"`
}

// ---- internal/agent/registry.go ----
func (e Env) Actions() *actions.Env // nil when the agent runs without ExecConfig

// ---- internal/event/core.go: EvidenceBlob gains (all omitempty) ----
// Collector string `json:"collector"`; Truncated bool `json:"truncated"`; Error string `json:"error"`

// ---- internal/plan/agentconfig.go ----
type ListFile struct {
	Name   string   `json:"name"`   // "unix_shells", "manifest.scored_users", "scorer.accounts"
	Values []string `json:"values"`
}
type Exception struct { // an exception from overrides.yml: equality on alert entities
	Rule    string            `json:"rule"`
	Name    string            `json:"name"`
	Fields  map[string]string `json:"fields"` // all must equal the event field (case-insensitive)
	Reason  string            `json:"reason"`
	Owner   string            `json:"owner"`
	Added   string            `json:"added"`
	Expires string            `json:"expires,omitempty"` // YYYY-MM-DD or RFC 3339
}
type RuleMode struct {
	Rule   string `json:"rule"`
	Mode   string `json:"mode"` // act | alert
	Reason string `json:"reason"`
	Owner  string `json:"owner"`
	Added  string `json:"added"`
}
// DetectSettings gains: Lists []ListFile `json:"lists,omitempty"`; Exceptions []Exception `json:"exceptions,omitempty"`;
//   RuleModes []RuleMode `json:"rule_modes,omitempty"`
type RecipeFile struct{ Name, YAML string }          // json tags "name", "yaml"
type HealthProbe struct {
	Action string         `json:"action"` // net.tcp_probe | net.http_probe
	Params map[string]any `json:"params"`
}
type HostService struct {
	Name   string       `json:"name"`
	Scored bool         `json:"scored"`
	Health *HealthProbe `json:"health,omitempty"` // nil on a scored service: tier 0 cannot run on this host
}
type Tier0Settings struct { // exactly the design's fields
	MaxPerHostPerMin int      `json:"max_per_host_per_min,omitempty"`
	BreakerWindowSec int      `json:"breaker_window_sec,omitempty"`
	LoopCount        int      `json:"loop_count,omitempty"`
	LoopWindowSec    int      `json:"loop_window_sec,omitempty"`
	BlockExpiresSec  int      `json:"block_expires_sec,omitempty"`
	BlockMaxActive   int      `json:"block_max_active,omitempty"`
	Allowed          []string `json:"allowed,omitempty"`
}
type RespondSettings struct {
	ModuleLimits
	Tier0      Tier0Settings `json:"tier0"`
	Protected  []string      `json:"protected_processes,omitempty"`
	Recipes    []RecipeFile  `json:"recipes,omitempty"`
	Services   []HostService `json:"services,omitempty"`
	NeverBlock []string      `json:"never_block,omitempty"` // CIDRs/addresses source_block refuses
	ResetEpoch int           `json:"reset_epoch,omitempty"`
}
// ContentGuardSettings, GuardService, GuardBoot exactly as the design (module content_guard, part 4), plus
//   ContentGuardSettings.ClearEpoch int `json:"clear_epoch,omitempty"`; GuardService.Health *HealthProbe `json:"health,omitempty"` (the service's probe, run locally);
//   GuardBoot.Candidates []BootCandidate and: type BootCandidate struct{ Path string `json:"path"`; Distro []string `json:"distro,omitempty"`; Resolve string `json:"resolve,omitempty"` /* "initramfs" */ ; Never bool `json:"never,omitempty"` /* never auto-restored */ }
// ModuleSettings gains: Respond *RespondSettings `json:"respond,omitempty"`; ContentGuard *ContentGuardSettings `json:"content_guard,omitempty"`

// ---- internal/manifest/types.go ----
// Overrides gains: RuleModes []RuleMode `yaml:"rule_modes,omitempty"`; Exceptions []RuleException `yaml:"exceptions,omitempty"`;
//   RespondResetEpoch int `yaml:"respond_reset_epoch,omitempty"`; GuardClearEpoch int `yaml:"guard_clear_epoch,omitempty"`
// type RuleException / RuleMode: same fields and json/yaml tags as plan.Exception / plan.RuleMode
// Content gains: Guard []string `yaml:"guard,omitempty" json:"guard,omitempty"`

// ---- module registration ----
// internal/agent/mods/respond.go and content_guard.go: agent.RegisterFactory(agent.Factory{Name, Manifest, Section, Build}) with
//   Build returning ErrUnavailable("seams") until Tasks 27 and 37; internal/respond registers its controller module with module.Register from init (Task 30).
// conformance.PreContract gains nothing: the new modules enter the suite at their conformance task.
```

- [ ] **Step 1: Write the stubs.** Types, constants and signatures exactly as above; function bodies `panic("unimplemented: W4 Task N")` naming the implementing task, except trivial constants. The nine `Declare` calls are real (priorities and alert flag as given). `Env.Actions()` returns `e.a.exec.env` or nil. Add `module.Registered` entries only where the module has a controller side (`detect`, `respond`), each a stub whose `Start` returns `module.ErrNoConfig`.
- [ ] **Step 2: Write the skipped tests and their helpers** for Tasks 2 to 39 (each task's Step 1 body, first statement `t.Skip("unimplemented: W4 Task N")`).
- [ ] **Step 3: Apply the design edits.** In `phylax_design.md`: gaps 3 to 9, 11, 12, 15 and 17 to 20 as text in the owning module sections (the `respond` catalogue row becomes "Agent + controller"; the kind table gains `respond.action` and `respond.breaker` consumers `respond`, the `rule` key of `respond.breaker` and the `id` key of `detect.alert`; `evidence.blob` keys; the recipe example's `params_from` is a map `{param: entities.field}`; `D10.audit-rules-event`; the rules layout line in Appendix D; the Overrides row in Manifest: Files). Bump "28 core kinds" is W1's; do not touch it.
- [ ] **Step 4: Verify.** Run: `make build build-windows vet test race`. Expected: all pass. Then `go test -v ./internal/... 2>&1 | grep -c 'unimplemented: W4 Task'`. Expected: the number of skipped tests written in Step 2, and no stub panic runs.
- [ ] **Step 5: Commit.**

```bash
git add internal rules cmd phylax_design.md
git commit -m "detect: W4 seams (kinds, settings, package skeletons, skipped tests, design edits)"
```

Open this as its own pull request into `v3-redesign` and merge after review.

---

### Task 2: `detect` agent module on the contract

**Files:**
- Create: `internal/detect/module.go`, `internal/detect/manifest.go`, `internal/detect/config.go`
- Modify: `internal/agent/mods/detect.go` (thin factory; `AlertEvent` and `KindAlert` move to `internal/detect`; fix importers), `internal/detect/engine.go` (alert `ID`), `internal/module/conformance/allowed.go` (remove `detect` from `PreContract`)
- Test: `internal/detect/module_test.go`, `internal/detect/conformance_test.go`

**Interfaces:**
- Consumes: `agent.Env` (`Subscribe(buf, kinds...)`, `Keep`, `Kept`, `Logger`), `agent.HealthReporter`, `module.Manifest`, `module.Health`, `event.New`, `plan.DetectSettings`.
- Produces:

```go
func Manifest() module.Manifest // Name "detect", Sides [agent, controller], OS ["linux","windows"], Privilege "root", Default true,
	// Consumes the design's list (common kinds plus the module kinds), Emits [detect.alert, detect.suppressed],
	// Budget{CPUMillisPerSec: 10, HeldMB: 16, EventsPerSec: 5, Burst: 50, BytesOutPerMin: 200 << 10, DiskMB: 1},
	// Pages ["alerts","rules"], Content ["rules/detect","rules/ported","rules/lists.yml","rules/profiles.yml"]
type Config struct { // modules/detect.yml; unknown fields are an error
	module.Common `yaml:",inline"`
	MaxKeys       int      `yaml:"max_keys,omitempty"`
	RatePerSec    float64  `yaml:"rate_per_sec,omitempty"`
	Burst         int      `yaml:"burst,omitempty"`
	Packs         []string `yaml:"packs,omitempty"`
	RulesPath     string   `yaml:"rules_path,omitempty"` // controller side: default "rules"
}
func (*Config) ConfigBlock() any // not needed on Config; the controller module (Task 10) returns &Config{}
type Module struct{ /* engine, settings, counters behind a mutex */ }
func NewModule(env agent.Env, s *plan.DetectSettings) (*Module, error) // parses s.RuleStream() with LoadOptions{AllowUntested: true}
func (m *Module) Name() string
func (m *Module) Start(ctx context.Context, emit agent.Emit) error
func (m *Module) Health() module.Health
func (rs *RuleSet) Kinds() []string // sorted union of rule kinds, sequence stage-B kinds and profile kinds
func AlertEvent(a Alert) event.Event // event.New(KindAlert, AlertFields{...}); Time = a.Time or now; ID set
```

Rules: the module subscribes with `env.Subscribe(8192, rs.Kinds()...)` and still drops any kind with prefix `detect.` and `controller.fact`; a rule-set parse failure at `Build` keeps the previous module's rule set (`env.Kept("detect.ruleset")`) and reports `degraded` with `Detail` naming the file and error; with no previous set `Build` returns the error. `Health().Info` keys: `rules`, `alert_mode_rules`, `act_mode_rules`, `state_keys`, `profile_keys`; state `disabled` for tier 0 is not this module's business. Profiles are kept across reconfiguration as today (`detect.profiles`). `shortcut: producer gaps (a rule whose kind no enabled module emits) are not reported, upgrade when Harness exposes the enabled manifests`.

- [ ] **Step 1: Remove the skips:**

```go
func TestAlertEventValidates(t *testing.T) {
	t0 := time.Date(2027, 2, 6, 12, 0, 0, 0, time.UTC)
	e := AlertEvent(Alert{RuleID: "D1.x", Title: "t", Severity: "high", Tier: 1, Mode: "alert", Agent: "h1", Time: t0,
		Attack: []string{"T1059"}, Entities: map[string]string{"exe": "/bin/sh"}})
	if err := event.Validate(e); err != nil { t.Fatal(err) }
	f, err := event.Decode[AlertFields](e, KindAlert)
	if err != nil || len(f.ID) != 16 || f.Entities["exe"] != "/bin/sh" || e.Priority != event.PriorityCritical { t.Fatalf("%+v %v", f, err) }
}
func TestManifestValidAndKindsDeclared(t *testing.T) {
	m := Manifest()
	if err := m.Validate(); err != nil { t.Fatal(err) }
	for _, et := range m.Emits { if _, ok := event.Lookup(et.Kind); !ok { t.Fatal(et.Kind) } }
}
func TestKindsCoverSequenceAndProfiles(t *testing.T) { /* a rule set with one count rule on conn, one sequence A=process_start B=file_change, one profile on listener: Kinds() == [conn file_change listener process_start] */ }
func TestModuleNeverFeedsOwnAlerts(t *testing.T) { /* harness (agent.NewHarness) with the detect factory; publish an event matching a rule: exactly one detect.alert; publish a detect.alert: still one */ }
func TestBadRulesKeepPreviousSet(t *testing.T) { /* apply a good config then one whose rule YAML is broken: the first rule still fires, Health().State == module.StateDegraded, Detail names the file */ }
func TestDetectConformance(t *testing.T) {
	conformance.Agent(t, conformance.AgentCase{Factory: factoryNamed(t, "detect"), Default: cfgWithRules(t, 0), Reconfig: cfgWithRules(t, 1),
		KeepKey: "detect.profiles", Load: loadEvents()})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'AlertEvent|Manifest|Kinds|OwnAlerts|BadRules|Conformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified. `AlertEvent` fills `AlertFields` from `Alert`; evidence `Fields` copy the matching event's fields. Move the old function and constant; `capture` keeps its own constant.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/ ./internal/agent/... ./internal/module/...`. Expected: PASS, including `TestPreContractShrinks` with `detect` as a contract module.
- [ ] **Step 5: Commit.** `git commit -am "detect: agent module on the contract"`

---

### Task 3: Loader: declared kinds and canonical fields (T75 rule half); delete the pre-contract aliases

**Files:**
- Create: `internal/detect/fieldcheck.go`
- Modify: `internal/detect/load.go` (`LoadOptions.Declared`), `internal/detect/cond.go` and `rule.go` (call the check from the leaf-condition compile, `refs`, `entities`), `internal/detect/field.go` (delete `aliases`), `internal/agent/mods/detect.go` and `internal/controller/agentconfig.go` (set `Declared: true`), `internal/detect/corpus_test.go` (`Declared: true`)
- Test: `internal/detect/fieldcheck_test.go`

**Interfaces:**
- Consumes: `event.Lookup(kind) (event.Type, bool)`, `event.Type.Fields`.
- Produces:

```go
// LoadOptions gains: Declared bool // every non-pending rule kind must be declared; every field must exist in the declared struct of at least one of the rule's kinds
func FieldSet(kind string) (fields map[string]bool, open bool, ok bool)
// fields: dotted json paths of the payload struct (embedded structs flattened, pointer-to-struct fields as "parent.exe"); open: the payload
// is map[string]any (any path below the declared ones is allowed); ok: kind declared.
```

Rules: envelope names `tag`, `agent`, `kind`, `time`, `host` (alias of `agent`) are always allowed; derived `<field>_net8|_net16|_net24` is allowed when `<field>` is; a path starting with `x_` is rejected (producer-only); a rule in `rules/pending/` (it has `needs:`) is exempt. With several kinds in `event:` a field passes when it exists in at least one (`shortcut: per-kind exactness, upgrade if a rule lists kinds with clashing meanings`). Error text: `rule D1: field "image" is not in event kind process_start (did you mean "exe"?)`; the hint lists the closest declared path by edit distance 2.

- [ ] **Step 1: Write the tests:**

```go
func TestRejectsNonCanonicalField(t *testing.T) {
	for _, f := range []string{"image", "pexe", "src_ip", "dst_port", "direction", "x_start_ticks"} {
		_, err := Parse("t", []byte(ruleOn("process_start", f)), LoadOptions{Declared: true})
		if err == nil || !strings.Contains(err.Error(), f) { t.Errorf("%s accepted: %v", f, err) }
	}
	for _, f := range []string{"exe", "parent.exe", "parent.cmdline", "tag", "agent", "raddr_net16"} {
		kind := "process_start"
		if f == "raddr_net16" { kind = "conn" }
		if _, err := Parse("t", []byte(ruleOn(kind, f)), LoadOptions{Declared: true}); err != nil { t.Errorf("%s: %v", f, err) }
	}
}
func TestRejectsUndeclaredKind(t *testing.T) { /* event: made_up -> error mentioning "not declared"; same text with Declared false parses */ }
func TestOpenPayloadAllowsAnyPath(t *testing.T) { /* winevt.sec_event with fields event_id, target_user parses */ }
func TestAliasesGone(t *testing.T) { /* a process_start event carrying only pexe no longer satisfies parent.exe: the engine does not read old names */ }
func TestCorpusUsesOnlyCanonicalFields(t *testing.T) { /* LoadDir(rulesDir, LoadOptions{Declared: true}) has no error; pending dir exempt */ }
```

`ruleOn(kind, field)` builds a one-rule YAML with an `all: [{<field>: x}]` condition and a positive and a negative inline test. If `TestCorpusUsesOnlyCanonicalFields` fails on a rule W3's rename missed, fix the rule in this commit (the rename recipe is in W3's Global Constraints).

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'Canonical|Undeclared|OpenPayload|Aliases' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `FieldSet` by reflection over `Type.Fields` (cache per kind) and the check in the compile path.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/ ./internal/controller/ ./internal/agent/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect: reject undeclared kinds and non-canonical fields; delete aliases"`

---

### Task 4: Strict rule keys: `module`, `replay`; delete `ir_template` (Known bug 22); default mode `alert`

**Files:**
- Modify: `internal/detect/rule.go` (`ruleDoc` and `Rule`: add `Module string`, `Replay string`; delete `IRTemplate`; default `Mode` becomes `alert`), `internal/detect/engine.go` (`Alert.IRTemplate` deleted), `internal/detect/engine_test.go` (the `ir1` assertions), `rules/linux_exec.yml` and `rules/windows.yml` (delete the two `ir_template` lines), `docs/rules.md`
- Test: `internal/detect/rule_keys_test.go`

**Interfaces:**
- Produces: a rule document requires `module: detect` (any other value, or none, is a load error `module must be detect`); `replay:` accepts `allow` only; a rule that still has `ir_template` fails with the loader's standard unknown-key error; `Rule.Mode` defaults to `alert` (design: every rule starts as alert unless its file says `act`); `Rule.ReplayAllow bool`.

- [ ] **Step 1: Write the tests:**

```go
func TestModuleKeyRequired(t *testing.T) { /* no module: -> error "module"; module: respond -> error */ }
func TestIRTemplateKeyRejected(t *testing.T) {
	y := ruleWith("module: detect\nir_template: web-app-compromise\n")
	if _, err := Parse("t", []byte(y), LoadOptions{}); err == nil || !strings.Contains(err.Error(), "ir_template") { t.Fatal(err) }
}
func TestDefaultModeIsAlert(t *testing.T) { /* a rule with no mode: -> Rule.Mode == "alert"; explicit mode: act stays act */ }
func TestReplayKey(t *testing.T) { /* replay: allow -> ReplayAllow true; replay: yes -> error */ }
func TestNoIRTemplateInTree(t *testing.T) { /* grep-style: no file under rules/ contains "ir_template" */ }
```

Every rule file in the corpus gets `module: detect` on each rule document in this commit (a mechanical edit; the tree move is Task 13). Rules that were relying on the old default `act` get an explicit `mode: act` only if they are in the tier-0 set of Task 28/29 (until then they alert).

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'ModuleKey|IRTemplate|DefaultMode|ReplayKey|NoIRTemplate' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified; update `docs/rules.md` (key list; `ir_template` gone; default mode).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/ ./internal/controller/ ./internal/e2e/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect: module and replay keys; delete ir_template (bug 22); default mode alert"`

---

### Task 5: `lists:` and the `{list: name}` operand

**Files:**
- Create: `internal/detect/lists.go`
- Modify: `internal/detect/rule.go` (`ruleDoc.Lists`), `internal/detect/cond.go` (`in`, `*_any` operands and `distinct`-free; `listArg`), `internal/detect/load.go` (`LoadOptions.Lists`, list-only documents), `internal/agent/mods/detect.go` and `internal/detect/module.go` (pass `plan.DetectSettings.Lists`)
- Test: `internal/detect/lists_test.go`

**Interfaces:**
- Produces:

```go
// LoadOptions gains: Lists map[string][]string // shared lists: rules/lists.yml and the manifest-derived lists, by name
// A document with no id and a top-level `lists:` map is a list document (the shape of rules/lists.yml); its names join the shared lists.
func ParseLists(name string, data []byte) (map[string][]string, error) // strict; names ^[a-z0-9_.\-]+$; no empty list; no duplicate name
```

Rules: a rule's own `lists:` shadows a shared list of the same name; `{ list: name }` is accepted wherever a list of strings is (`in`, `contains_any`, `startswith_any`, `endswith_any` and their `_cs` forms); an unknown list name, an empty list or `{list: a, x: b}` is a load error naming the rule and the list. Manifest lists arrive as `plan.ListFile{Name: "manifest.scored_users"}` entries; the dotted names are valid.

- [ ] **Step 1: Write the tests:**

```go
func TestInlineAndSharedLists(t *testing.T) {
	rs := mustLoad(t, ruleYAMLWithLists(`lists: {shells: [/sh, /bash]}`, `exe: {endswith_any: {list: shells}}`))
	if al := process(rs, ev("process_start", map[string]any{"exe": "/usr/bin/bash"})); len(al) != 1 { t.Fatal(al) }
	if al := process(rs, ev("process_start", map[string]any{"exe": "/usr/bin/vim"})); len(al) != 0 { t.Fatal(al) }
	rs2, err := Parse("t", []byte(ruleYAMLWithLists("", `account: {in: {list: manifest.scored_users}}`)), LoadOptions{Lists: map[string][]string{"manifest.scored_users": {"alice"}}})
	if err != nil || len(process(rs2, ev("auth_event", map[string]any{"account": "Alice"}))) != 1 { t.Fatal(err) }
}
func TestUnknownOrEmptyListIsLoadError(t *testing.T) { /* {list: nope}; lists: {x: []}; {list: a, b: c} */ }
func TestListDocument(t *testing.T) { /* ParseLists on "lists:\n  a: [x]\n" == {"a":{"x"}}; duplicate name -> error; unknown top key -> error */ }
func TestRuleListShadowsShared(t *testing.T) { /* same name in both: the rule's wins */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'Lists|ListDocument|ListShadow' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `listArg` resolution in `compileEnv` (`env.lists` merged per rule).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect: lists and the list operand"`

---

### Task 6: `exceptions:` and suppression records

**Files:**
- Create: `internal/detect/exceptions.go`
- Modify: `internal/detect/rule.go` (`ruleDoc.Exceptions`), `internal/detect/engine.go` (`Options.Exceptions`, check in `Process`), `internal/detect/module.go` (convert `plan.Exception`)
- Test: `internal/detect/exceptions_test.go`

**Interfaces:**
- Produces:

```go
type Exception struct { // an override-origin exception: equality on event fields
	Rule, Name       string
	Fields           map[string]string
	Reason, Owner    string
	Added            time.Time
	Expires          time.Time // zero: none
}
// Options gains: Exceptions []Exception
type ExceptionInfo struct {
	Rule, Name, Reason, Owner string
	Added, Expires            time.Time
	Expired                   bool
	Origin                    string // "rule" | "overrides"
}
func (e *Engine) Exceptions(now time.Time) []ExceptionInfo // sorted by rule, name
```

Rules: a rule's `exceptions:` entries need `name`, `when` (an `all`/`any` condition document), `reason`, `owner`, `added` (YYYY-MM-DD) and optionally `expires` (YYYY-MM-DD, end of that day UTC, or RFC 3339); a missing mandatory field or an unparsable date is a load error. In `Process`, after a rule's condition matches and before `count`/`sequence` state is touched, an event matched by a non-expired exception is skipped silently (it is not counted and raises no alert). Expiry is compared with the event time. Override exceptions with an unknown rule id are kept and reported (`Origin: overrides`); matching is case-insensitive equality of every `Fields` entry.

- [ ] **Step 1: Write the tests:**

```go
func TestRuleExceptionSuppresses(t *testing.T) {
	rs := mustLoad(t, ruleYAMLWithExceptions(`- {name: oc-cron, when: {all: [{parent.exe: {eq: /usr/sbin/crond}}]}, reason: "opencart cron", owner: linux-lead, added: 2026-11-07}`))
	if len(process(rs, ev("process_start", map[string]any{"exe": "/bin/sh", "parent": map[string]any{"exe": "/usr/sbin/crond"}}))) != 0 { t.Fatal("exception ignored") }
	if len(process(rs, ev("process_start", map[string]any{"exe": "/bin/sh", "parent": map[string]any{"exe": "/usr/sbin/sshd"}}))) != 1 { t.Fatal("non-matching event suppressed") }
}
func TestExceptionNeedsReasonOwnerAdded(t *testing.T) { /* each missing -> load error naming the field */ }
func TestExceptionExpiry(t *testing.T) {
	// expires 2026-11-08: an event at 2026-11-08T23:00Z is still excepted, one at 2026-11-09T00:01Z alerts;
	// Exceptions(now after) lists it with Expired true
}
func TestOverrideExceptionByFields(t *testing.T) { /* Options.Exceptions {Rule:"R", Fields:{"exe":"/BIN/SH"}} suppresses exe=/bin/sh; other exe alerts */ }
func TestExceptionedEventDoesNotCount(t *testing.T) { /* count gte 3 rule; 2 excepted + 2 normal events in the window: no alert; a third normal one alerts */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run Exception -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect: exceptions with reason, owner, added and expiry"`

---

### Task 7: `replay` exclusion, engine scope and controller receive time

**Files:**
- Modify: `internal/detect/engine.go` (`Options.Scope`, `Options.ReceiveTime`, replay skip), `internal/detect/module.go` (`Scope: "agent"`)
- Test: `internal/detect/replay_scope_test.go`

**Interfaces:**
- Produces:

```go
// Options gains:
//   Scope string        // "agent" or "controller": only rules of that scope are registered; "" registers all (unit tests)
//   ReceiveTime bool    // windows (count, sequence, jitter) use Options.Clock() instead of ev.Time
```

Rules: an event whose `Fields["replay"]` is boolean true never visits a rule without `replay: allow`, and never enters a `count`, `sequence` or `jitter` window of any rule (the rule-level `allow` lets a rule see it for its condition only; windows still ignore it). The check is on the raw field, so it works for every kind.

- [ ] **Step 1: Write the tests:**

```go
func TestReplayExcluded(t *testing.T) { // review focus 3
	rs := mustLoad(t, countRule("R", "process_start", 3, "10m"))
	eng := NewEngine(rs, Options{})
	for i := 0; i < 5; i++ { // five replayed events: nothing
		if al := eng.Process(evAt("process_start", map[string]any{"exe": "/bin/nc", "replay": true}, i)); len(al) != 0 { t.Fatal(al) }
	}
	for i := 0; i < 3; i++ { eng.Process(evAt("process_start", map[string]any{"exe": "/bin/nc"}, 10+i)) }
	// the replayed five left no state: exactly one alert, from the third live event
}
func TestReplayAllowSeesConditionNotWindow(t *testing.T) { /* replay: allow simple rule fires on a replayed event; the same rule with count does not count it */ }
func TestScopeFiltersRules(t *testing.T) { /* Scope "agent" ignores a scope: controller rule and vice versa */ }
func TestReceiveTimeWindows(t *testing.T) { /* ReceiveTime true, Clock fake: events with old Time (1 h ago) still fill a 1 m window when received together */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'Replay|Scope|ReceiveTime' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified (replay test first in `Process`, then rule loop).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect: replay exclusion, engine scope, receive-time windows"`

---

### Task 8: `rate:` and `detect.suppressed`

**Files:**
- Create: `internal/detect/rate.go`
- Modify: `internal/detect/rule.go` (`ruleDoc.Rate`), `internal/detect/engine.go` (`Engine.Flush`), `internal/detect/field.go` (`host` pseudo field), `internal/detect/module.go` (flush ticker and emit)
- Test: `internal/detect/rate_test.go`

**Interfaces:**
- Produces:

```go
type Suppressed struct {
	Rule   string
	Count  int
	Window time.Duration
	By     map[string]string
}
func (e *Engine) Flush(now time.Time) []Suppressed // summaries of windows that ended; the module calls it every 10 s and on stop
func SuppressedEvent(s Suppressed, at time.Time) event.Event // event.New(KindSuppressed, SuppressedFields{...})
```

Rules: `rate: {max: 10, per: 1m, by: [host, parent.exe]}` (all three keys required; `max` at least 1; `by` fields like `count.by`). Per key and window (tumbling from the first alert), the first `max` alerts pass; the rest are dropped and counted. When the window ends, `Flush` (or the next `Process` for that key) returns one `Suppressed` with the count, never silence. Bounded by `max_keys` like `count`. `host` is an alias of the pseudo field `agent`.

- [ ] **Step 1: Write the tests:**

```go
func TestRateCapsAndSummarises(t *testing.T) {
	rs := mustLoad(t, ruleWithRate("max: 3, per: 1m, by: [agent]"))
	eng := NewEngine(rs, Options{})
	got := 0
	for i := 0; i < 10; i++ { got += len(eng.Process(evAt("process_start", map[string]any{"exe": "/bin/nc"}, i))) }
	if got != 3 { t.Fatalf("passed %d", got) }
	s := eng.Flush(base.Add(2 * time.Minute))
	if len(s) != 1 || s[0].Count != 7 || s[0].Rule != "R" { t.Fatalf("%+v", s) }
	if len(eng.Flush(base.Add(3 * time.Minute))) != 0 { t.Fatal("summary repeated") }
}
func TestRateKeyedByFields(t *testing.T) { /* two different parent.exe values each get their own 3 */ }
func TestRateValidation(t *testing.T) { /* missing max/per/by, max 0, bad duration -> load error */ }
func TestSuppressedEventValidates(t *testing.T) { /* event.Validate(SuppressedEvent(...)) == nil; priority normal */ }
func TestModuleEmitsSuppressedOnTick(t *testing.T) { /* harness: flood a rate:3 rule, advance, one detect.suppressed arrives */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'Rate|Suppressed' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect: rate caps with detect.suppressed summaries"`

---

### Task 9: `jitter` and mode promotion (`rule_modes`, `AppendOverrides`)

**Files:**
- Create: `internal/detect/jitter.go`, `internal/detect/modes.go`, `internal/manifest/overrides_write.go`
- Modify: `internal/detect/rule.go` (`whenDoc.Jitter`), `internal/detect/engine.go` (`Options.RuleModes`), `internal/detect/module.go` (convert `plan.RuleMode`)
- Test: `internal/detect/jitter_test.go`, `internal/detect/modes_test.go`, `internal/manifest/overrides_write_test.go`

**Interfaces:**
- Produces:

```go
// when: jitter: {below: 0.2, min_events: 10, by: [raddr, rport], window: 1h, cooldown: 1h}
//   Keeps the last min_events*2 event times per key (bounded by max_keys); fires when at least min_events events lie in window
//   and the coefficient of variation of the gaps (stddev/mean) is below `below`; then quiet for cooldown (default window).
//   jitter is exclusive with count and sequence; below in (0, 1]; min_events at least 4.
// Options gains: RuleModes map[string]string // rule id -> "act" | "alert"; applied after AlertOnly: AlertOnly wins
func (e *Engine) Mode(ruleID string) string // effective mode of a rule ("" for an unknown rule)

// internal/manifest/overrides_write.go
func AppendOverrides(dir string, fn func(*Overrides) error) error // reads dir/overrides.yml (absent: empty), applies fn, validates, writes atomically (internal/atomicfile), mode 0600 kept
```

Rules for modes: `Alert.Mode` is `Options.RuleModes[rule]` when present, else the rule's `Mode`; then forced to `alert` when `AlertOnly`. A `rule_modes` entry needs `reason`, `owner`, `added` (checked by `AppendOverrides`' validate, not by the engine). `shortcut: AppendOverrides rewrites the file from the struct, so comments in overrides.yml are lost; upgrade to a yaml.Node round trip if operators hand-edit it`.

- [ ] **Step 1: Write the tests:**

```go
func TestJitterFiresOnRegularBeacon(t *testing.T) {
	rs := mustLoad(t, jitterRule("below: 0.2, min_events: 10, by: [raddr], window: 1h"))
	eng := NewEngine(rs, Options{})
	fired := 0
	for i := 0; i < 12; i++ { // 300 s +- 5 s
		fired += len(eng.Process(evAt("conn", map[string]any{"raddr": "198.51.100.9"}, i*300+(i%3)*5)))
	}
	if fired != 1 { t.Fatalf("fired %d", fired) }
}
func TestJitterQuietOnIrregular(t *testing.T) { /* gaps 10 s, 600 s, 40 s, ... CoV > 0.2: no alert; 9 regular events (below min_events): no alert */ }
func TestJitterIgnoresReplay(t *testing.T) { /* twelve regular replay:true events: none */ }
func TestRuleModesOverride(t *testing.T) {
	rs := mustLoad(t, simpleRule("R", "alert"))
	if m := NewEngine(rs, Options{RuleModes: map[string]string{"R": "act"}}).Mode("R"); m != "act" { t.Fatal(m) }
	if m := NewEngine(rs, Options{AlertOnly: true, RuleModes: map[string]string{"R": "act"}}).Mode("R"); m != "alert" { t.Fatal(m) }
	al := NewEngine(rs, Options{RuleModes: map[string]string{"R": "act"}}).Process(ev("process_start", map[string]any{"exe": "/bin/nc"}))
	if al[0].Mode != "act" { t.Fatal(al[0].Mode) }
}
func TestDemotionTakesEffect(t *testing.T) { /* same rule act in file, RuleModes {R: alert}: alert */ }
func TestAppendOverridesAtomicAndValidated(t *testing.T) {
	dir := t.TempDir()
	err := AppendOverrides(dir, func(o *Overrides) error { o.RuleModes = append(o.RuleModes, RuleMode{Rule: "D1.x", Mode: "act", Reason: "lab clean", Owner: "lead", Added: "2027-02-06"}); return nil })
	if err != nil { t.Fatal(err) }
	m, _ := LoadDir(dir, Options{}) // or the overrides-only loader of load.go
	// round trip equals; a RuleMode with empty Reason -> error and the file is unchanged; Mode "kill" -> error
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ ./internal/manifest/ -run 'Jitter|RuleModes|Demotion|AppendOverrides' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/ ./internal/manifest/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect: jitter, rule mode overrides; manifest: AppendOverrides"`

---

### Task 10: `detect` controller module: scope `controller` rules over committed events

**Files:**
- Create: `internal/detect/controller.go`
- Modify: `internal/module/all/all.go` (already imports `internal/detect` through the agent registration; add nothing), `internal/detect/testutil_test.go` (`fakeHost`)
- Test: `internal/detect/controller_test.go`, `internal/detect/controller_conformance_test.go`

**Interfaces:**
- Consumes: `module.Host` (`Config`, `Subscribe`, `Emit`, `Logger`), `module.Register`, `conformance.Controller`, Task 5's `ParseLists`, Task 13's `TreeFiles` (this task uses a directory glob until Task 13 lands; Task 13 switches the call).
- Produces:

```go
type Controller struct{ /* engine, health behind a mutex */ }
func (*Controller) Manifest() module.Manifest // Manifest() with Sides [agent, controller]
func (c *Controller) Start(ctx context.Context, h module.Host) error
func (c *Controller) Health() module.Health
func (*Controller) ConfigBlock() any // &Config{}
func init() { module.Register(&Controller{}) }
```

Rules: `Start` decodes `Config` (`ErrNoConfig` returns, health `unavailable`), loads the rules under `Config.RulesPath` (default `rules`) with `LoadOptions{Declared: true}`, builds `NewEngine(rs, Options{Scope: "controller", ReceiveTime: true, AlertOnly: !cfg.ActEnabled, MaxKeys: cfg.MaxKeys})`, subscribes (`h.Subscribe(rs.Kinds(), 4096)`; the kinds must be in `Manifest().Consumes`) and for each committed event calls `Process` with `Time` replaced by the controller clock (the original time is in `evidence`). Alerts go out through `h.Emit(AlertEvent(a))` (stored under agent `controller`; the controller's alert queue picks `detect.alert` up by kind). A controller alert's `entities` carry the `agent` of the triggering event (`entities.agent`). `shortcut: manifest-derived lists are not available to controller-scope rules, only rules/lists.yml; upgrade when Host exposes the manifest lists`.

- [ ] **Step 1: Remove the skips:**

```go
func TestControllerRuleFiresAcrossAgents(t *testing.T) { // D18b shape: one source authenticating to 3 hosts in 5 minutes
	h := newFakeHost(t, "enabled: true\nact_enabled: false\nrules_path: testdata/rules\n")
	c := &Controller{}
	go c.Start(h.ctx, h)
	for i, agent := range []string{"web", "db", "mail"} {
		h.publish(event.Event{Agent: agent, Kind: "auth_event", Time: time.Now(), Fields: map[string]any{"result": "success", "account": "bob", "service": "ssh", "source": "198.51.100.7"}})
		_ = i
	}
	al := h.waitEmitted(t, "detect.alert", 1)
	f, _ := event.Decode[AlertFields](al[0], KindAlert)
	if f.Rule != "D18b.fanout" || f.Mode != "alert" || f.Entities["source"] != "198.51.100.7" { t.Fatalf("%+v", f) }
}
func TestControllerIgnoresAgentScopeAndReplay(t *testing.T) { /* an agent-scope rule never fires here; replay:true auth events do not count */ }
func TestControllerAlertReachesQueue(t *testing.T) { /* in internal/controller: a detect.alert stored through Host.Emit appears in the operator alert queue (alerts.go recordAgentAlerts); if the ingest hook only covers agent events, extend it to controller-origin events */ }
func TestControllerConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Controller{}, Config: "enabled: true\nrules_path: testdata/rules\n", Now: time.Unix(1e9, 0)})
}
```

`testdata/rules/` holds a copy of the D18b rule in its final form (scope controller, `count` with `distinct: host`... use the corpus rule's text) and one agent-scope rule.

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'ControllerRule|ControllerIgnores|ControllerConformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified; run `go test ./internal/controller/ -run ControllerAlertReachesQueue` and fix `internal/store/hook.go` or `controller/alerts.go` only if that test fails.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS, with `detect` passing the controller conformance checks.
- [ ] **Step 5: Commit.** `git commit -am "detect: controller module evaluates scope controller rules"`

---

### Task 11: `agent.health` carries module state and `Info`; rule `D10.audit-rules-changed`

**Files:**
- Modify: `internal/agent/health.go` (`HealthSource.ModuleHealth`, `report`), `internal/agent/agent.go` (implement `ModuleHealth` over `Supervisor.Health`), `rules/network.yml` (rename the existing rule; add the new one), `rules/profiles.yml` (profile `audit_rules_hash`)
- Test: `internal/agent/health_info_test.go`, `internal/e2e/audit_hash_test.go`

**Interfaces:**
- Consumes: W1 `module.Health`, `(*Supervisor).Health`, `agent.HealthReporter`; W3 Task 6 (`audit` fills `Info["rules_hash"]`, `Info["rules_installed"]`).
- Produces:

```go
// HealthSource gains:
ModuleHealth() map[string]module.Health
// agent.health fields: modules.<name> = {state, restarts, emitted, rate_dropped, spool_drops, last_error, info: map[string]string, gaps: n}
// emission: every interval as today, and immediately when any module's State or Info map differs from the previous report (at most one extra per 5 s).
```

The rule (file `rules/network.yml`, to move in Task 13):

```yaml
id: D10.audit-rules-changed
module: detect
scope: controller
title: Audit rules hash changed or dropped in the heartbeat
severity: high
tier: 1
attack: [T1685]
when:
  event: agent.health
  all:
    - modules.audit.state: {present: true}
  any:
    - not: { modules.audit.info.rules_hash: { in_profile: audit_rules_hash } }
    - modules.audit.info.rules_installed: { eq: "0" }
  count: { window: 1m, gte: 2, by: [agent], cooldown: 30m }   # two reports in a minute, then quiet 30 m
```

(`gte` is at least 2 in the loader; two reports with the bad hash inside a minute is the condition.) Profile in `rules/profiles.yml`: `name: audit_rules_hash`, `event: agent.health`, `key: [agent]`, `value: modules.audit.info.rules_hash`, `learn: 10m`. The old rule becomes `D10.audit-rules-event` (agent scope, same body).

- [ ] **Step 1: Write the tests:**

```go
func TestHealthEventCarriesInfo(t *testing.T) {
	// a test agent with a HealthReporter module whose Info {"rules_hash": "abc"}; the agent.health event Fields["modules"]["m"]["info"]["rules_hash"] == "abc"
}
func TestHealthEmittedOnInfoChange(t *testing.T) { /* change Info; a new agent.health arrives within 6 s although the interval is 1 h; no second one if nothing changes */ }
func TestHealthInfoBounded(t *testing.T) { /* a module with 100 Info keys: the event carries at most 32, keys <= 64 bytes, values <= 256 */ }
// internal/e2e
func TestAuditRulesHashDropRaisesD10(t *testing.T) { // review: Known bug 16's consumer
	// load rules/ (network.yml + profiles.yml) in a controller-scope engine; feed agent.health events for agent h1:
	// 10 minutes of hash H (learning), then two events with hash 0 and rules_installed "0" a minute apart -> one alert D10.audit-rules-changed;
	// a changed hash H2 twice -> one alert; steady H -> none; an agent without an audit module -> none
}
func TestAuditRulesEventRuleKept(t *testing.T) { /* D10.audit-rules-event still fires on audit.rules_changed */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/agent/ ./internal/e2e/ -run 'HealthEvent|HealthEmitted|HealthInfo|AuditRulesHash|AuditRulesEvent' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified (`gap` and `report` otherwise unchanged). If `in_profile` on an absent field behaves differently from the comment, fix the rule, not the engine, and say so in the commit.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/agent/ ./internal/detect/ ./internal/e2e/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "agent: health event carries module info; detect: D10.audit-rules-changed from the heartbeat hash"`

---

### Task 12: Evidence collectors on the agent: `process_tree`, `content_changes`, `binary_copy`

**Files:**
- Create: `internal/detect/collect.go`, `internal/detect/collect_linux.go`, `internal/detect/collect_windows.go`, `internal/detect/collect_other.go`
- Modify: `internal/detect/module.go` (run collectors after an alert is emitted)
- Test: `internal/detect/collect_test.go`

**Interfaces:**
- Consumes: `event.New`, `event.EvidenceBlob` (with Task 1's extra keys), `internal/atomicfile`.
- Produces:

```go
const (MaxItemBytes = 8 << 20; MaxAlertBytes = 64 << 20)
type Collector interface {
	Name() string
	Collect(ctx context.Context, a AlertFields, dst io.Writer) error // writes one item; dst enforces the cap
}
type Collectors struct{ /* by name */ }
func NewCollectors(root string, stateDir string) *Collectors // root "/" on a real host; items go under stateDir/evidence/<alert id>/
func (c *Collectors) Run(ctx context.Context, a AlertFields) []event.Event // one evidence.blob per item; failures recorded, never retried
```

Rules: runs in its own goroutine per alert with a 10 s deadline per collector and at most 2 alerts at once (a third waits, bounded queue of 16; beyond it the alert's items get `error: queue_full`); names in `collect:` that this side does not implement (`freeze_ring`, `transactions_window_10m`, `trace_back`) are skipped without an event (`capture` and the controller own them). `process_tree`: the process in `entities.pid` (Linux `/proc/<pid>`, Windows process snapshot), its ancestors and children, command lines, start times, image hashes, as JSON; `content_changes`: stat and sha256 of `entities.path` and the files of its directory (at most 200); `binary_copy`: a copy of `entities.exe` or `entities.path` with the first 4 bytes zeroed when they are `\x7fELF` or `MZ..` (defanged). A path from an entity is `filepath.Clean`ed, must be absolute, and is read with `O_NOFOLLOW` semantics on Linux (symlink refused). Item over 8 MiB: truncated, `truncated: true`; alert total over 64 MiB: no more items, `error: alert_cap`. `shortcut: items are announced with evidence.blob and kept on the host; upload waits for W11's chunk transfer`.

- [ ] **Step 1: Write the tests:**

```go
func TestProcessTreeCollector(t *testing.T) { /* Linux: start `sleep 30` child of the test process, Collect with its pid: JSON has the child, its parent (the test) and cmdline "sleep 30"; skip with a reason off Linux */ }
func TestContentChangesCollector(t *testing.T) { /* temp dir with 3 files: output lists the 3 with sha256 and size; entity path outside root / relative / containing .. -> error */ }
func TestBinaryCopyDefangs(t *testing.T) { /* a fake ELF file: copy's first 4 bytes are 0; a symlink path is refused; a 9 MiB file is truncated with Truncated true */ }
func TestAlertCap(t *testing.T) { /* eight 9 MiB items: after 64 MiB the next evidence.blob has Error "alert_cap" */ }
func TestRunEmitsBlobEvents(t *testing.T) { /* Collectors.Run for collect [process_tree content_changes freeze_ring]: two evidence.blob events, each event.Validate ok, Alert == the alert id, sha256 of the stored file matches */ }
func TestModuleRunsCollectorsAfterAlert(t *testing.T) { /* harness: a rule with collect: [content_changes] fires; the alert event is emitted before the blob event */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'Collector|Defang|AlertCap|RunEmits|RunsCollectors' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified; Windows process snapshot with `golang.org/x/sys/windows` (`CreateToolhelp32Snapshot`); `collect_other.go` returns `ErrUnsupported`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/ && GOOS=windows go vet ./internal/detect/`. Expected: PASS and no vet output.
- [ ] **Step 5: Commit.** `git commit -am "detect: process_tree, content_changes, binary_copy collectors with evidence.blob"`

---

### Task 13: Move the corpus to `rules/detect/`; rule-id registry (Known bug 2); pending enforcement

**Files:**
- Move (`git mv`): `rules/{auth,linux_exec,linux_persistence,logs,mw-redteam,network,windows,deception,deps}.yml` to `rules/detect/`; `rules/profiles.yml` stays; create `rules/lists.yml`
- Create: `internal/detect/registry.go`, `internal/detect/tree.go`
- Modify: `internal/controller/agentconfig.go` (use `TreeFiles`), `internal/detect/corpus_test.go` and every test that reads `../../rules` (`rulesDir` and e2e), `rules/detect/deps.yml` (ids `D14.new-dependency`, `D14b.external-dependency`, `D14c.dependency-gone` become `DEP1.new-dependency`, `DEP2.external-dependency`, `DEP3.dependency-gone`), `internal/traceback`, `internal/chains`, `docs/*.md` and any test naming those ids (grep `D14`), `docs/rules.md`, `internal/detect/controller.go` (Task 10 switches to `TreeFiles`)
- Test: `internal/detect/registry_test.go`, `internal/detect/tree_test.go`

**Interfaces:**
- Produces:

```go
type NamedFile struct{ Name string; YAML []byte }
func TreeFiles(root string, packs []string) ([]NamedFile, error)
// root/lists.yml, root/profiles.yml, root/detect/*.yml, root/ported/*.yml (sorted; the Name is the path relative to root).
// packs non-empty: only detect/ and ported/ files whose base name without extension is listed. root/pending is never returned.
func LoadTree(root string, o LoadOptions) (*RuleSet, error) // TreeFiles + ParseLists + load, one rule set
func CheckRegistry(root string) []error
// walks root/*/ (detect, ported, pending and any module dir), parses rule documents only (documents with `id:`):
//   1. ids are unique across all files;
//   2. id grammar ^[A-Z]{1,4}[0-9]+[a-z0-9]*(\.[a-z0-9][a-z0-9-]*)?$ ;
//   3. reserved families: ids starting D14 only in documents with `module: devices`; ids starting DEP only with `module: deps` or detect
//      (hosted: `rules/detect/deps.yml` carries `module: detect` until W8); V<n> reserved for vantage (module vantage or detect while hosted).
func PendingErrors(root string, declared func(kind string) bool) []error // each pending rule has `needs:`; one of the form `kind:<kind>` whose kind is declared is an error ("unpark")
```

- [ ] **Step 1: Write the tests:**

```go
func TestRegistryUniqueAcrossTree(t *testing.T) { /* temp tree: same id in detect/a.yml and ported/b.yml -> one error naming both files */ }
func TestRegistryD14ReservedForDevices(t *testing.T) { /* id D14.new-dependency in module detect -> error; in module devices -> ok */ }
func TestRegistryOnRealTree(t *testing.T) { if errs := CheckRegistry("../../rules"); len(errs) != 0 { t.Fatal(errs) } } // fails before the DEP rename (bug 2 regression, T65)
func TestTreeFilesPacks(t *testing.T) { /* packs [auth] returns lists.yml, profiles.yml, detect/auth.yml only */ }
func TestLoadTreeCorpus(t *testing.T) { /* LoadTree("../../rules", LoadOptions{Declared: true}) loads; every inline test passes (RunTests) */ }
func TestPendingRulesStillNeedSomething(t *testing.T) { if errs := PendingErrors("../../rules", func(k string) bool { _, ok := event.Lookup(k); return ok }); len(errs) != 0 { t.Fatal(errs) } }
func TestControllerLoadsTree(t *testing.T) { /* internal/controller: ConfigInputs with RulesPath ../../rules yields the same rule file names as TreeFiles and no file from rules/pending */ }
```

Procedure in Step 3: `git mv`; run `LoadTree` with `Declared: true`; every rule whose kind is not declared yet (the other workstreams' kinds) is moved out of its file into `rules/pending/needs_producer.yml` with `needs: kind:<kind>` (workstream in a YAML comment); the commit message lists them. Update the design's rule-file table in `phylax_design.md` with the new paths.

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ ./internal/controller/ -run 'Registry|TreeFiles|LoadTree|PendingRules|ControllerLoadsTree' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified and as the procedure above.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS; `grep -rn 'D14\.\|D14b\.new\|D14c\.dep' --include=*.go --include=*.yml --include=*.md . | grep -v 'docs/impl/review\|devices'` prints nothing.
- [ ] **Step 5: Commit.** Two commits: `detect: move the corpus to rules/detect with module keys and a rule-id registry`, then `detect: rename the dependency rules DEP1 to DEP3 (bug 2)`.

---

### Task 14: ATT&CK v19 ids from a pinned dataset

**Files:**
- Create: `internal/detect/attack.go`, `internal/detect/attack_v19.txt`, `internal/detect/gen/attackids/main.go`
- Modify: `internal/detect/rule.go` (replace `attackRE` and `revokedAttack` use with `AttackValid`)
- Test: `internal/detect/attack_test.go`

**Interfaces:**
- Produces:

```go
func AttackValid(id string) (ok bool, replacement string) // id in the pinned v19 set -> true; a revoked id with a known replacement -> false, replacement; unknown -> false, ""
// attack_v19.txt (embedded): first line `# source: <url> sha256:<hex> version: 19.0`; then one id per line (techniques and sub-techniques);
// revoked ids kept as `revoked T1562 T1685` lines.
// go run ./internal/detect/gen/attackids <enterprise-attack-19.0.json> > internal/detect/attack_v19.txt (a STIX bundle: attack-pattern objects with external_id, revoked, and revoked-by relationships)
```

- [ ] **Step 1: Write the tests:**

```go
func TestAttackValid(t *testing.T) {
	for _, id := range []string{"T1059", "T1059.001", "T1685", "T1686"} { if ok, _ := AttackValid(id); !ok { t.Errorf("%s", id) } }
	if ok, rep := AttackValid("T1562.001"); ok || rep != "T1685" { t.Errorf("%v %q", ok, rep) }
	if ok, _ := AttackValid("T9999"); ok { t.Error("unknown id accepted") }
}
func TestCorpusAttackIDs(t *testing.T) { /* every rule in LoadTree("../../rules") passes AttackValid (the loader already enforces it) */ }
func TestHeaderPinsSource(t *testing.T) { /* attack_v19.txt first line matches ^# source: https://\S+ sha256:[0-9a-f]{64} version: 19 */ }
```

Procedure: download the pinned bundle (the `mitre-attack/attack-stix-data` release for v19; record URL and sha256 in the header) and run the generator. If the machine has no network, STOP and report; do not write the id list by hand.

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'AttackValid|CorpusAttack|HeaderPins' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the generator, the file and `AttackValid`; a rule with an id that is valid but not in the file fails with the closest suggestion.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/`. Expected: PASS (fix any corpus id the dataset rejects).
- [ ] **Step 5: Commit.** `git commit -am "detect: validate ATT&CK ids against a pinned v19 dataset"`

---

### Task 15: `phylax rules`: `test`, `registry`, `third-party`, `promote`

**Files:**
- Create: `cmd/phylax/rules.go`, `internal/detect/thirdparty.go`, `THIRD_PARTY_RULES.md` (generated)
- Modify: `cmd/phylax/main.go` (dispatch `rules`)
- Test: `cmd/phylax/rules_test.go`, `internal/detect/thirdparty_test.go`

**Interfaces:**
- Consumes: `LoadTree`, `CheckRegistry`, `PendingErrors`, `manifest.AppendOverrides`, `respond.LoadEmbedded`/`respond.RecipeSet` (Task 24; the `promote` check is stubbed with a clear error until then and finished in Task 28).
- Produces:

```go
func ThirdPartyMarkdown(rs *RuleSet) string // table: rule id, upstream id, path, commit, author, licence, file; sorted by id
// phylax rules test [--rules DIR]      runs every inline test, prints `ok N rules, M tests` or the failures, exit 1 on any failure or missing positive/negative test
// phylax rules registry [--rules DIR]  CheckRegistry + PendingErrors + recipe trigger check (recipe triggers name real rule ids), exit 1 on any error
// phylax rules third-party [--rules DIR] [--check]   writes THIRD_PARTY_RULES.md; with --check compares and exits 1 when stale
// phylax rules promote RULE --reason R --owner O [--manifest DIR] [--check-only]
//    checks (1) the rule's inline tests pass, (2) a respond recipe lists the rule as a trigger with tier0 or auto steps, (3) none of those steps is in the click-only set,
//    (4) the rule file's tier is 0; then AppendOverrides adds {rule, mode: act, reason, owner, added: today}. --check-only prints the verdict and writes nothing.
//    demote: `phylax rules promote RULE --mode alert ...` writes the alert record without checks 2 to 4.
```

A ported rule's `source:` must carry `author`, `license`, `id`, `path`, `commit` (the loader's `Source map[string]string` is checked here: `source:` with only `author: Phylax, license: repo` is allowed for own rules).

- [ ] **Step 1: Write the tests:**

```go
func TestRulesTestExitCodes(t *testing.T) { /* run(["rules","test","--rules",fixtureDir]) == 0; a fixture rule with a failing inline test == 1 and the output names rule and test */ }
func TestRulesRegistryCatchesDuplicate(t *testing.T) { /* two files with the same id -> exit 1 */ }
func TestThirdPartyMarkdown(t *testing.T) { /* a ported rule with source {id: sigma-1, path: x.yml, commit: abc, author: A, license: DRL-1.1} appears; a rule with source {author: Phylax, license: repo} does not */ }
func TestThirdPartyFileIsCurrent(t *testing.T) { /* run third-party --check against the repo: exit 0 */ }
func TestPromoteWritesOverride(t *testing.T) { /* a fixture rule with a tier0 recipe: promote writes rule_modes; a rule whose recipe lists proc.kill_tree under tier0: refused; --check-only writes nothing */ }
func TestPromoteRefusesFailingTests(t *testing.T) { /* inline test fails -> exit 1, overrides.yml unchanged */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./cmd/phylax/ ./internal/detect/ -run 'RulesTest|RulesRegistry|ThirdParty|Promote' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified. Add `make rules` (`phylax rules test && phylax rules registry && phylax rules third-party --check`) and run it in the CI conformance job (`.github/workflows/ci.yml`: one added step).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./cmd/phylax/ ./internal/detect/ && make build && bin/phylax rules test`. Expected: PASS and `ok N rules, M tests`.
- [ ] **Step 5: Commit.** `git commit -am "phylax rules: test, registry, third-party, promote; CI step"`

---

### Task 16: Catalogue additions A: Linux, Splunk, kernel, reboot guard, generic exec pack

**Files:**
- Modify: `rules/detect/linux_exec.yml`, `rules/detect/linux_persistence.yml`, `docs/rules.md` (rule index)
- Test: `internal/detect/catalogue_a_test.go`

**Interfaces:**
- Consumes: W3 kinds `audit.module_load`, `audit.af_alg` (payloads in W3 Task 1), `process_start`, `file_change`.
- Produces: these rules, each with `module: detect`, `mode: alert`, `exempt_tagged: true`, ATT&CK ids valid in the v19 file (pick the closest valid id; the tests below check `AttackValid`), a `should_match: true` and a `should_match: false` inline test:

| Id | Event and condition | Tier | Notes |
| --- | --- | --- | --- |
| `D1h.splunkd-spawns-shell` | `process_start`, `parent.exe` ends with `/splunkd` or (`parent.exe` ends `/postgres` and `parent.cmdline` contains `splunk`), `exe` in the shell/interpreter list | 1 | review N4.2 (Splunk 10.0.x exploit) |
| `D2j.splunk-fim` | `file_change`, `path` starts with `/opt/splunk/etc/` or `/opt/splunk/bin/`, untagged, `op` not `attr` | 1 | |
| `D11b3.kmod-syscall` | `audit.module_load` (any) | 1 | A2.Q3: every module load by any tool |
| `D11b4.afalg-socket` | `audit.af_alg`, `uid: {gt: 0}` | 1 | Copy Fail; the `uid` condition must fire on a `json.Number` event (W3 Task 2) |
| `D17f.reboot-shutdown` | `process_start`, `exe` ends with one of `/shutdown`, `/reboot`, `/halt`, `/poweroff`, or `exe` ends `/systemctl` with `cmdline` containing `reboot`, `poweroff` or `halt`, or `exe` ends `/init` with `cmdline` containing ` 0` or ` 6` | 1 | review D337; untagged only |
| `D25.exec-from-tmp` | `process_start`, `exe` starts with `/tmp/`, `/var/tmp/`, `/dev/shm/` or contains `/.` directory component | 1 | N4.5 |
| `D25b.offensive-tool` | `process_start`, `exe` or `cmdline` matches the tool names (impacket, crackmapexec, responder, kerbrute, sharphound, linpeas, pspy, potato, certipy, lazagne, sqlmap, masscan) | 1 | low confidence, stays `alert` permanently (comment says so) |
| `D25c.miner-strings` | `process_start`, `cmdline` contains `stratum+tcp`, `xmrig`, `kinsing` | 1 | |
| `D25d.history-delete` | `process_start`, `cmdline` contains `history -c`, `unset HISTFILE`, `rm` with `.bash_history`, `> /var/log/` truncation | 1 | the weak "diamorphine"/"reptile" keywords are skipped (design) |

- [ ] **Step 1: Write the tests:**

```go
func TestCatalogueARulesPresent(t *testing.T) {
	rs := mustLoadTree(t)
	want := map[string]int{"D1h.splunkd-spawns-shell": 1, "D2j.splunk-fim": 1, "D11b3.kmod-syscall": 1, "D11b4.afalg-socket": 1,
		"D17f.reboot-shutdown": 1, "D25.exec-from-tmp": 1, "D25b.offensive-tool": 1, "D25c.miner-strings": 1, "D25d.history-delete": 1}
	for id, tier := range want {
		r := ruleByID(t, rs, id)
		if r.Tier != tier || r.Mode != "alert" || !r.ExemptTagged() { t.Errorf("%s: tier %d mode %s", id, r.Tier, r.Mode) }
	}
}
func TestAfAlgFiresOnLiveJSONNumber(t *testing.T) { /* build the event with event.New(audit.AFAlg{UID: 1000, ...}) and run it through the real tree engine: D11b4 fires; UID 0: no */ }
func TestRebootGuardIgnoresTaggedAndOtherCommands(t *testing.T) { /* `systemctl status` no; tagged `shutdown -r` no; untagged `shutdown -r now` yes; `init 6` yes */ }
func TestSplunkPostgresSidecar(t *testing.T) { /* postgres whose parent cmdline lacks splunk: no alert */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'CatalogueA|AfAlg|RebootGuard|SplunkPostgres' -v`. Expected: FAIL.
- [ ] **Step 3: Write the rules** from the table (YAML only), `ExemptTagged()` accessor if missing.
- [ ] **Step 4: Run, expect PASS.** Run: `go test ./internal/detect/ && bin/phylax rules test`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect: Linux, Splunk, kernel-load, reboot-guard and generic exec rules"`

---

### Task 17: Catalogue additions B: Windows events, AD and GPO state, ACL tamper, Cobalt Strike and Mythic, D7h

**Files:**
- Modify: `rules/detect/windows.yml`, `rules/detect/mw-redteam.yml`, `rules/pending/needs_producer.yml`
- Test: `internal/detect/catalogue_b_test.go`

**Interfaces:**
- Consumes: `winevt.sec_event` and `winevt.sensor_state` payloads (W3 `internal/winevt/kinds.go`: use the field names the existing Windows rules use, e.g. `event_id`, `target_user`, `subject_user`, `ip`; open the file first), `file_change` GPO fields (`gpo`, `gpo_section`, `sysvol_policy`), `process_start`, `conn`, lists `manifest.scored_users` (shared list, Task 5).
- Produces rules (`module: detect`, `exempt_tagged: true`, inline tests, `mode: alert` unless the table says `act`):

| Id | Condition | Tier |
| --- | --- | --- |
| `D7h.scored-account-deleted` | `winevt.sec_event` event 4726 with `target_user` in `{list: manifest.scored_users}`; **`mode: act`** (tier-0 recipe `recycle_restore`, Task 29); chain seed | 0 |
| `D7i.account-disable-delete` | 4725 or 4726, target not scored | 1 |
| `D7j.universal-group-change` | 4756 | 1 |
| `D8i.lockout-storm` | `count` of 4740 gte 5 in 5 m by `agent` | 1 |
| `D8j.admin-share-nonadmin` | 5140/5145 with share `ADMIN$` or `C$` from a source not in `{list: manifest.admin_sources}` | 1 |
| `D8k.download-cradle` | 4104 script block containing `IEX`, `DownloadString`, `FromBase64String` | 1 |
| `D8l.kdcsvc-cert-mapping` | Kdcsvc events 39, 40, 41 | 1 |
| `D8m.gpo-guest-admin`, `D8n.gpo-anon-restrict`, `D8o.gpo-lockout-extreme`, `D8p.gpo-defender-exclusion` | GPO-state conditions on the `file_change` `gpo` fields / sysvol policy text: Guest added to Administrators, `RestrictAnonymous` lowered, lockout threshold under 3 or over 50, a Defender exclusion path set by policy | 1 |
| `D10l.service-acl-tamper` | 4670 or System 7040 on a service in `{list: manifest.scored_service_names}` | 1 |
| `D13f.cs-process-shape` | `process_start` on a server (`not: {list: manifest.workstations}`): `msedge.exe` or `wmiprvse.exe` with an odd parent (not explorer, svchost, services), or an outbound `conn` from them | 1 |
| `D13g.cs-pipe-tsvcpipe` | `winevt.sec_event` Sysmon 17/18 with pipe name matching `^\\\\TSVCPIPE-` | 1 |
| `D13h.cs-windowsupdate-lure` | `conn`/`dns_query` to `windowsupdate.com` names from a non-Microsoft destination address, or a read of `C:\Windows\beacon.bin` (`file_change`/Sysmon 11 path) | 1 |

`1644` LDAP-enumeration is parked: add `D8q.ldap-enum-1644` to `rules/pending/needs_producer.yml` with `needs: winevt diagnostic logging for event 1644 (hardening pack, W5)`. Lists `manifest.admin_sources`, `manifest.scored_service_names`, `manifest.workstations` are added to the controller's list rendering in Task 38.

- [ ] **Step 1: Write the tests:**

```go
func TestCatalogueBRulesPresent(t *testing.T) { /* each id above: tier and mode as the table; D7h is mode act, all others alert */ }
func TestD7hOnlyForScoredAccounts(t *testing.T) {
	rs := mustLoadTreeWithLists(t, map[string][]string{"manifest.scored_users": {"svc-ecom"}})
	// 4726 target svc-ecom: fires (Mode act); 4726 target tmpuser: D7h does not fire, D7i does
}
func TestLockoutStormNeedsFive(t *testing.T) { /* four 4740 in 5 m: no; the fifth: one alert; per agent */ }
func TestGPODefenderExclusion(t *testing.T) { /* fixture file_change of a Registry.pol-style change with an exclusion path: D8p fires; same change tagged: no */ }
func TestPipeRegexAnchored(t *testing.T) { /* \\TSVCPIPE-1234 matches; \\MyTSVCPIPE does not */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'CatalogueB|D7h|LockoutStorm|GPODefender|PipeRegex' -v`. Expected: FAIL.
- [ ] **Step 3: Write the rules** from the table. Where a field the table needs is not in the W3 payload, use the nearest field the producer does emit, and list the gap as a `shortcut:` comment in the rule file.
- [ ] **Step 4: Run, expect PASS.** Run: `go test ./internal/detect/ && bin/phylax rules test`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect: Windows event, AD and GPO-state, ACL-tamper and C2-shape rules; D7h"`

---

### Task 18: Hand-ported rules (`rules/ported/`) with `source:`

**Files:**
- Create: `rules/ported/{windows.yml,linux.yml}`
- Test: `internal/detect/ported_test.go`

**Interfaces:**
- Produces: ten rules (ids `D26.*`), `module: detect`, `mode: alert`, `tier: 1`, each with `source: {id: <upstream rule id>, path: <path in the upstream repo>, commit: <40-hex>, author: <upstream author>, license: DRL-1.1}`: Cloudflared tunnel (`D26.cloudflared-tunnel`), Velociraptor child process, Raccine uninstall, browser remote debugging (`--remote-debugging-port`), `sc sdset` and hidden-service DACL (pairs with `D10l`), `regini`, ADExplorer snapshot, `certutil -exportPFX`, `whoami /all`, CrackMapExec process patterns. Third-party logic is ported by hand: read the upstream Sigma rule in the SigmaHQ repository at a recorded commit, re-express its detection in this format, never copy the file.

- [ ] **Step 1: Write the tests:**

```go
func TestPortedRulesCarrySource(t *testing.T) {
	rs := mustLoadTree(t)
	n := 0
	for _, r := range rs.Rules {
		if !strings.HasPrefix(r.ID, "D26.") { continue }
		n++
		for _, k := range []string{"id", "path", "commit", "author", "license"} { if r.Source[k] == "" { t.Errorf("%s: source.%s missing", r.ID, k) } }
		if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(r.Source["commit"]) { t.Errorf("%s: commit", r.ID) }
		if r.Mode != "alert" || r.Tier != 1 { t.Errorf("%s", r.ID) }
	}
	if n != 10 { t.Fatalf("ported rules: %d", n) }
}
func TestAlertCarriesSource(t *testing.T) { /* fire one ported rule; AlertFields.Source["license"] == "DRL-1.1" */ }
func TestThirdPartyListCoversPorted(t *testing.T) { /* ThirdPartyMarkdown(tree) mentions all ten ids; THIRD_PARTY_RULES.md is current (phylax rules third-party --check) */ }
```

If the machine cannot reach the upstream repository, STOP and report; do not invent a commit hash.

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'Ported|AlertCarriesSource|ThirdPartyListCovers' -v`. Expected: FAIL.
- [ ] **Step 3: Write the rules**, then `bin/phylax rules third-party` to regenerate `THIRD_PARTY_RULES.md`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test ./internal/detect/ && bin/phylax rules registry && bin/phylax rules third-party --check`. Expected: PASS and exit 0.
- [ ] **Step 5: Commit.** `git commit -am "detect: ten hand-ported rules with source records and THIRD_PARTY_RULES.md"`

---

### Task 19: Catalogue additions C: beacon jitter, controller-scope checks, D22, the pass-the-hash pack (pending), unparking

**Files:**
- Modify: `rules/detect/network.yml`, `rules/detect/auth.yml`, `rules/detect/mw-redteam.yml`, `rules/detect/logs.yml`, `rules/pending/needs_producer.yml`
- Create: `rules/pending/pass_the_hash.yml`
- Test: `internal/detect/catalogue_c_test.go`

**Interfaces:**
- Produces:
  - `D13c.beacon-periodicity` (move out of pending): `scope: controller`, `conn` with `dir: outbound`, `exempt_tagged`, not `rport` in `[53, 123, 67, 68, 137, 138, 5353]`, `jitter: {below: 0.2, min_events: 10, by: [agent, raddr, rport], window: 1h}`; `tier: 1`, `mode: alert`, comment says periodic infrastructure traffic (NTP, DNS, monitoring) makes this noisy and that the list of allowed destinations belongs in `exceptions`.
  - `D18b.credential-fanout` and `D13e.scan-source-rotation`: confirm `scope: controller` and that they use `by: [raddr_net16]` / `distinct`; add the inline multi-agent tests if absent (test events carry `agent:`).
  - `D22.prebake-hunt-trigger`: `agent.enrolled` or `agent.reenrolled` (core kinds), `tier: 1`, `mode: alert`, `replay: allow` is not set.
  - `D21.address-route-neighbour` and the other rules whose `needs: kind:<kind>` kind is now declared (`inventory.row`, `inventory.snapshot`, `logs.line`, `winevt.sec_event`): unparked into `rules/detect/`; run `PendingErrors` until it reports nothing.
  - `rules/pending/pass_the_hash.yml`: five rules `D27.ptH-ntlm-scored`, `D27b.ptH-ntlm-no-service-use`, `D27c.ptH-rc4-ticket`, `D27d.ptH-tgt-unlabelled-source`, `D27e.ptH-two-sources` (design pass-the-hash pack), `scope: controller`, `mode: alert` permanently (comment), each `needs: kind:traceback.label` and a `source_label` condition (W8), each with inline tests that use a `source_label` field. `D10k3.firewall-drift` (`firewall.drift`, tier 0, `mode: alert` until Task 29) is parked with `needs: kind:firewall.drift`.

- [ ] **Step 1: Write the tests:**

```go
func TestBeaconPeriodicityController(t *testing.T) { /* via a controller-scope engine with ReceiveTime false and fake times: 12 outbound conns at 300 s +-4 s from agent a to 203.0.113.5:443: one alert; same with rport 123: none; replay:true: none */ }
func TestFanoutAndScanRotationAreControllerScope(t *testing.T) { /* both rules Scope "controller"; D18b fires on 3 agents in 5 m, not on 2 */ }
func TestD22FiresOnEnrollment(t *testing.T) { /* agent.reenrolled with host h1: alert; agent.start: none */ }
func TestNoParkedRuleHasDeclaredKind(t *testing.T) { /* PendingErrors == nil */ }
func TestPassTheHashPackParksOnLabel(t *testing.T) { /* five rules in pending, each needs kind:traceback.label, each parses with AllowUntested; none in the active set */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'BeaconPeriodicity|FanoutAndScan|D22|NoParkedRule|PassTheHash' -v`. Expected: FAIL.
- [ ] **Step 3: Write the rules** (YAML only).
- [ ] **Step 4: Run, expect PASS.** Run: `go test ./internal/detect/ && bin/phylax rules test && bin/phylax rules registry`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect: beacon jitter, controller-scope checks, D22, pass-the-hash pack parked on W8, unparked rules"`

---

### Task 20: Actions `proc.kill_tree`, `proc.suspend`, `proc.dump` (Linux and the backend interface)

**Files:**
- Create: `internal/actions/proc.go`, `internal/actions/proc_linux.go`, `internal/actions/proc_other.go`
- Modify: `internal/actions/env.go` (`Env.Proc ProcBackend`), `internal/actions/registry.go` (`coreActions` registers the three)
- Test: `internal/actions/proc_test.go`, `internal/actions/proc_linux_test.go`

**Interfaces:**
- Produces:

```go
type ProcInfo struct {
	PID        int
	StartTicks uint64 // Linux: /proc/<pid>/stat field 22; Windows: creation time in 100 ns
	PPID       int
	Exe        string
	Cmdline    string
	Cgroup     string // Linux: unit cgroup path ("" when the process is not alone in a unit)
}
type ProcBackend interface {
	Lookup(pid int) (ProcInfo, error)                       // ErrNoProcess when gone
	Children(pid int) ([]ProcInfo, error)                   // direct children
	Kill(pi ProcInfo) error                                  // pidfd_send_signal(SIGKILL) on Linux; TerminateProcess on Windows; refuses when StartTicks changed
	KillCgroup(path string) error                            // cgroup.kill; ErrUnsupported elsewhere
	Suspend(pi ProcInfo) error                               // SIGSTOP on the pidfd / NtSuspendProcess
	Resume(pi ProcInfo) error
	Dump(pi ProcInfo, w io.Writer, max int64) error          // Linux: readable regions of /proc/<pid>/mem; Windows: MiniDumpWriteDump (Task 21)
}
var ErrNoProcess = errors.New("actions: no such process")
// Actions (all Risk: RiskService, Locks: ["proc:<pid>"]):
//   proc.kill_tree{pid int, start_ticks uint64 (required), tree bool (default true), unit string}
//   proc.suspend{pid, start_ticks}      rollback: Resume
//   proc.dump{pid, start_ticks, path}   writes a defanged dump (ELF/PE magic zeroed in any executable image region, 64 MiB cap) under QuarantineDir
```

Rules: the start time check is mandatory (the pid may have been reused): `Lookup` must return the same `StartTicks` or the action fails `process changed`. `Touches` returns a `TouchService` for every scored service whose unit or process tree contains the pid (the guard then refuses); the action refuses pid 1, the agent's own pid and its ancestors. `tree` kills children first (depth-first, bounded to 4096 processes). When `unit` is set and the cgroup holds only that unit, `KillCgroup` is used. `proc.kill_tree` has no rollback (`Rollback{}`; `Plan.Notes` says not reversible); it is a tier-1 action: respond's CI rejects it under `tier0:` and `auto:` (Task 24).

- [ ] **Step 1: Write the tests:**

```go
func TestKillTreeRefusesReusedPID(t *testing.T) { /* fake backend: Lookup returns StartTicks 10, request has 9 -> error "process changed", Kill not called */ }
func TestKillTreeKillsChildrenFirst(t *testing.T) { /* fake backend records Kill order: grandchild, child, parent */ }
func TestKillTreeRefusesAgentAndPID1(t *testing.T) { /* pid 1 and os.Getpid() refused */ }
func TestKillTreeTouchesScoredService(t *testing.T) { /* guard StaticGuard{Services: ["ecom-http"]} and a backend that says the pid is in unit ecom-http: Execute returns ErrScoringUnsafe */ }
func TestSuspendResumeRollback(t *testing.T) { /* suspend then Rollback data resumes */ }
func TestLinuxKillTreeRealProcess(t *testing.T) { /* linux only: start `sleep 60` and its child shell; proc.kill_tree via the real backend; both gone within 2 s; skip with reason when pidfd_open is unavailable */ }
func TestDumpIsDefanged(t *testing.T) { /* linux: dump a child that has an ELF mapped; no output region starts with \x7fELF */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ -run 'KillTree|Suspend|Dump' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified (`golang.org/x/sys/unix` for `PidfdOpen`, `PidfdSendSignal`; a cgroup v2 `cgroup.kill` write).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/actions/ && GOOS=windows go vet ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: proc.kill_tree, proc.suspend, proc.dump with a Linux backend"`

---

### Task 21: `ProcBackend` on Windows

**Files:**
- Create: `internal/actions/proc_windows.go`
- Test: `internal/actions/proc_windows_test.go`

**Interfaces:**
- Consumes: Task 20's `ProcBackend`, `ProcInfo`, `ErrNoProcess`; `golang.org/x/sys/windows`.
- Produces: `func defaultProc() ProcBackend` for Windows: `Lookup` (`OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION`, `GetProcessTimes` for `StartTicks`, `QueryFullProcessImageName`, parent from a Toolhelp snapshot), `Children` (snapshot), `Kill` (`OpenProcess(PROCESS_TERMINATE)` after re-checking `StartTicks`, `TerminateProcess`), `Suspend`/`Resume` (`NtSuspendProcess`/`NtResumeProcess` through `NewLazySystemDLL("ntdll.dll")`), `Dump` (`MiniDumpWriteDump` through `dbghelp.dll`, `MiniDumpWithFullMemory` capped by `max`, PE headers zeroed afterwards), `KillCgroup` returns `ErrUnsupported`. `shortcut: no Job Object kill for services, upgrade if a lab run shows a service restarts children`.

- [ ] **Step 1: Write the tests** (they run only on Windows; on Linux they are compiled out with a build tag and `go vet GOOS=windows` covers them):

```go
//go:build windows

func TestWindowsLookupSelf(t *testing.T) { b := defaultProc(); pi, err := b.Lookup(os.Getpid()); if err != nil || pi.StartTicks == 0 || !strings.HasSuffix(strings.ToLower(pi.Exe), ".exe") { t.Fatal(pi, err) } }
func TestWindowsKillRefusesReusedPID(t *testing.T) { /* start notepad via cmd /c timeout; Kill with StartTicks+1 -> error; Kill with the real value succeeds */ }
func TestWindowsDumpWritesMDMP(t *testing.T) { /* dump a child; the file starts with MDMP after defanging is NOT zeroed (dump magic is kept); size <= max */ }
```

- [ ] **Step 2: Run.** On Linux: `GOOS=windows go vet ./internal/actions/`. Expected: no output. (The Windows runs happen in the lab task.)
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run.** `GOOS=windows go build ./... && make build-windows`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: Windows ProcBackend (TerminateProcess, NtSuspendProcess, MiniDumpWriteDump)"`

---

### Task 22: Action `dir.snapshot`

**Files:**
- Create: `internal/actions/dirsnap.go`
- Modify: `internal/actions/registry.go`
- Test: `internal/actions/dirsnap_test.go`

**Interfaces:**
- Consumes: `Env.Resolve`, `atomicfile`, `file.hash` helpers in `files.go`.
- Produces: `dir.snapshot{path, dest, max_files, max_bytes, hash}`: a read-only copy of a directory tree into `dest` (a new directory under the agent state directory or a path the caller names; refused when it exists), preserving mode, owner, xattrs and SELinux label (same helper as `file.restore`), skipping symlinks (recorded as entries with `link_target`, never followed), writing `MANIFEST.json` (`path`, `size`, `mode`, `uid`, `gid`, `sha256` when `hash` is true) atomically last. `Spec{Risk: RiskNone, ReadOnly: false}` (it writes `dest`, not the source), `Locks ["path:<dest>"]`, `Touches` none (it reads the source). Defaults: `max_files` 10000, `max_bytes` 1 GiB; over either the action fails and removes the partial copy. Used by `backup` (W10) and available to plans.

- [ ] **Step 1: Write the tests:**

```go
func TestDirSnapshotCopiesTreeWithManifest(t *testing.T) { /* temp tree: 3 files, a subdir, 0640 mode on one; snapshot; every file equal, mode kept, MANIFEST.json lists 3 entries with sha256 */ }
func TestDirSnapshotDoesNotFollowSymlinks(t *testing.T) { /* a link to /etc/passwd inside the tree: dest has a MANIFEST entry with link_target and no copy of the target */ }
func TestDirSnapshotBounds(t *testing.T) { /* max_files 2 with 3 files -> error and dest removed */ }
func TestDirSnapshotRefusesExistingDest(t *testing.T) { /* dest exists -> error, nothing changed */ }
func TestDirSnapshotRollbackRemovesDest(t *testing.T) { /* Capture/Rollback data deletes only the dest it created */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ -run DirSnapshot -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: dir.snapshot"`

---

### Task 23: Action `sysmon.install`

**Files:**
- Create: `internal/actions/sysmon.go`
- Modify: `internal/actions/registry_win.go`, `internal/actions/win_exec.go` (`NewAllowExec` allows `sysmon64.exe`, `sysmon.exe`), `internal/actions/win_env.go` if the executor fake needs a hook
- Test: `internal/actions/sysmon_test.go`

**Interfaces:**
- Produces: `sysmon.install{installer, sha256, config, service}` (Windows; `Risk: RiskService`, `Locks ["sysmon"]`, `Touches` none): verifies the installer file's sha256 against the parameter (a pinned value from the depot) before running it, then runs `installer -accepteula -i <config>` (or `-c <config>` when the `Sysmon64` service already exists) through `Env.Win.Exec` (the allowlisted `Executor`, bounded output, deadline), and verifies by checking that the service is `running` and its driver is loaded. Idempotent: an installed, running Sysmon with the same config hash is `Plan.Done`. Rollback: none (reinstalling is the response; `Plan.Notes` says so). On Linux `Spec` registers nothing (the action is Windows-only, like `win.defender`). Used by recipe `sysmon_reinstall` (Task 28).

- [ ] **Step 1: Write the tests** (against the existing `win_fakes_test.go` fakes):

```go
func TestSysmonInstallVerifiesHashBeforeRun(t *testing.T) { /* wrong sha256 -> error, the fake Executor was never called */ }
func TestSysmonInstallRunsInstallThenVerifies(t *testing.T) { /* fake exec records `-accepteula -i <cfg>`; the fake service manager reports Sysmon64 running -> ok */ }
func TestSysmonInstallUpdatesConfigWhenInstalled(t *testing.T) { /* service exists: args are `-c <cfg>` */ }
func TestSysmonInstallDoneWhenRunningWithSameConfig(t *testing.T) { /* Plan.Done true, no exec */ }
func TestSysmonInstallRefusesPathsOutsideDepot(t *testing.T) { /* installer path not under the depot or state dir -> error */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ -run Sysmon -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/actions/ && GOOS=windows go vet ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: sysmon.install"`

---
