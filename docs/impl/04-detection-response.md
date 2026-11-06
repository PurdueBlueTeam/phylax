# W4: Detection and Response Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move `detect` onto the module contract and finish its engine (`lists`, `exceptions`, `rate`, `replay`, `jitter`, controller-scope evaluation, evidence collectors; `detect` only alerts, S1), build `respond` (the tier-0 runner over the engine's attempt ledger and `autonomy` setting; recipes; the A-AUTO tier-0 set; controller proposals and `Host.RunAuto`) and `content_guard` (golden store, change detection, boot-critical list; its restore is respond's `content_restore` recipe over `file.restore{source: golden}`), and port the rule corpus into `rules/detect/` behind a rule-id registry.

**Architecture:** `internal/detect` keeps its evaluator and gains a module wrapper (agent side) and a controller module (scope `controller` rules over committed events). It has no rule `mode`, no `AlertOnly` and no act switch. `internal/respond` has an agent side that consumes `detect.alert` and runs signed recipes through the agent's own `actions.Env` (dead-man armed for the breaker window, confirmed only when every probe stays green) and a controller side that turns alerts into one-click proposals and `RunAuto` plans. A recipe tied to a rule id and enabled for the host is the only act switch; the module's `act_enabled`, the template's `autonomy: propose|shadow|auto` (`module.Actor`) and the engine's one attempt ledger (count, window and breaker per host, object and kind) decide how far it goes (S1). `internal/content_guard` is agent-only: it detects changes to a short list of files and keeps the plan-tagged golden store; it never writes to scored content. Recipes, rules, lists and plan templates are YAML content under `rules/` and `plans/respond/`; the new action families (`proc.*`, `dir.snapshot`, `guard.snapshot`) plus `sysmon.install` are small Go.

**Tech Stack:** Go 1.27.2 (mise), `gopkg.in/yaml.v3`, `golang.org/x/sys`, `internal/atomicfile`. No new modules in `go.mod`.

**Spec:** `phylax_design.md` (v4): "Rule format" (1731), modules `detect` (2877), `respond` (3096), `content_guard` (3300); "Execution engine" (approval classes, auto conditions, session eviction, the scoring-safety lint exceptions, Processes and Files action families); Known bugs 2 and 22; Execution engine: Autonomy and the attempt ledger (S1); Test matrix T02, T03, T16, T20, T36, T52, T74 (respond half), T75 (rule half), T79 (recipe enablement pass); Appendix D (rules layout). Master plan: `docs/impl/README.md`. Contract names: `docs/impl/01-module-contract.md` (W1) Interfaces blocks; W3 (`docs/impl/03-telemetry.md`) Produces names for kinds and the `json.Number` fix; W5 and W6 plans for the action names recipes call.

## Design gaps and decisions (Task 1 writes each into `phylax_design.md` in the same commit)

1. **The agent `Env` cannot run an action.** `agent.Env` has `Subscribe`, `Keep`, `Fact`, `Health`; the actions environment lives in `agent.ExecConfig`. `respond` and `content_guard` need to execute actions locally, with the dead-man, locks and the scoring guard. Task 1 adds `func (e Env) Actions() *actions.Env` (nil when the agent runs without `ExecConfig`; a module that needs it then reports `unavailable`).
2. **`agent.health` does not carry module `Info`, and is not emitted when it changes.** W1 puts `Health` in the heartbeat but leaves the `agent.health` event as it is, and its `HealthSource` has no module health. Task 11 adds `HealthSource.ModuleHealth()`, copies state and `Info` into `modules.<name>`, and emits at once when a module's state or `Info` changes (the design already says the supervisor does). The Platform page displays it; no rule compares it (S4: the audit-rules hash compare goes).
3. **One rule keeps the id `D10.audit-rules-changed`.** S4 removed the controller-side audit-rules hash compare, so the controller-scope rule on `agent.health` and its profile are not built; the corpus rule on the `audit.rules_changed` event keeps its id and stays agent scope (the `audit` module repairs its own rules).
4. **An alert needs an id before it is sealed.** `evidence.blob` references the alert, the spool assigns `seq` later. `detect.alert` gains `id` (16 hex characters, `sha256(agent|rule|time_ns)`), set by the engine.
5. **`evidence.blob` (W1 Task 5) lacks `collector`, `truncated`, `error`.** Task 1 adds them. Chunk upload of the blob (Wire protocol: file-chunk transfer) is W11's `fetch`/chunk work (Known bug 4); until then the item stays under `StateDir/evidence/<alert id>/` and `evidence.blob` announces it with `chunks: 0` (`shortcut: blobs are announced but not uploaded, upgrade when W11's chunk transfer merges`). The two controller-side collectors (`transactions_window_10m`, `trace_back`) and the controller's `freeze_capture` (Known bug 7, W6) are not built here; the loader accepts the names.
6. **`overrides.yml` has no `exceptions`, recipe-enable record or reset record, and nothing writes it.** Task 1 adds `Overrides.Exceptions`, `Overrides.Recipes` (a `RecipeEnable{Rule, Reason, Owner, Added, Services}` record, the same shape as an exception, naming a rule whose recipe is enabled on the host) and `Overrides.RespondResetEpoch` with their validation; there is no `rule_modes` (S1). The writer `manifest.AppendOverrides(dir, fn)` (atomic read-modify-write; comments in the file are not preserved, `shortcut`) is W1 Task 11a's, and a controller module reaches it as `Host.UpdateOverrides` (W1 Task 17a). The Alerts page's "silence" button (a UI-shell item) calls it; W4 builds no button.
7. **There is no `respond.breaker` or `respond.loop` kind, and no auto-demotion.** The attempt ledger's stop is the core `plan.failed{reason: auto_halted, trigger: repeat|red_check}` (critical), emitted by the agent executor for tier-0 recipes and by the controller engine for `RunAuto` plans; W4 declares no kind for it. `respond.action` carries `rule`, so the Responses page and the Rules page show a recipe's stops against its rule. The controller side of `respond` consumes `detect.alert`, `respond.action` and `plan.failed` (the kind table's consumer column is updated). Demoting a recipe is removing its `Overrides.Recipes` entry (or setting its template to `propose`); nothing writes it back automatically.
8. **An operator reset needs a signed path to the agent.** The five fact subtypes do not fit. `Overrides.RespondResetEpoch` is folded into `RespondSettings.ResetEpoch`; the agent clears every ledger entry (counts and breakers) when the epoch in the signed config exceeds the one it kept. The UI's "reset" button bumps the epoch with `AppendOverrides` and pushes the config. The same epoch resets the ledger entries of `content_restore` (there is no separate guard clear epoch).
9. **The design YAML for `respond` and `content_guard` does not map 1:1 onto the Go settings** (`breaker_window: 2m` against `BreakerWindowSec`; `services: {ecom-http: alert}` against `[]GuardService`). Each module gets a `Config` struct that is the block's YAML (the design YAML, unchanged) and the controller converts it into `plan.RespondSettings` / `plan.ContentGuardSettings`.
10. **Rollback of a tier-0 action reuses the dead-man journal.** The runner calls `actions.Env.Execute` with `Request.Deadman` = breaker window + 30 s, probes for the whole window, then `Confirm`s; a red probe calls `Rollback`. An action that returns no rollback data (`ErrNotReversible`) cannot run at tier 0 and is reported `skipped_guard` (a click proposal follows).
11. **"Scorer-labelled source" is not known on the agent.** `source_block` never blocks an address in `Tier0Settings.NeverBlock` (manifest-listed own addresses, controller, relays, Kali, learned scorer runner ranges, rendered by the controller). Divisor re-draws scorer addresses, so the list can lag (`shortcut`); the trigger (a decoy login or a honey credential, never on a scored port) and the post-block probe are what protect the scorer.
12. **Rates.** The design gives the host cap (`max_per_host_per_min`, 3) and the ledger (count and window per (host, object, kind)). Decision: a small host `Limiter` keeps the host cap; per-object limits are the ledger's alone (the plan's earlier extra "1 per minute per object" is dropped). The ledger takes `Count`/`Window` from the template: `respond`'s `loop` block (3 in 10 minutes) for its recipes, 2 in 10 minutes for `content_restore`, the engine default (2 in 10 minutes) otherwise.
13. **Respond and detect cannot import each other** (no sibling imports). `respond` reads `detect.alert` through its own loose view struct (not `event.Decode`, which is strict and would reject a new alert key); the cross-check "every recipe trigger names a real rule id" runs in `internal/e2e` and in `cmd/phylax` (the binary may import both).
14. **Actions owned by other workstreams are not registered yet** (`fw.apply{op: policy|allow|block|quarantine}`, `service.state`, `task.disable`, `runkey.remove`, `file.restore{source}`, `ad.recycle_restore`, `ad.gpo_unlink`, `session.terminate_predating`, `hunt.persistence`; S4 folded `fw.restore`, `fw.quarantine`, `unit.disable` and `binary.restore_from_depot` into them). `internal/respond/pending.go` lists each with its workstream; the recipe check accepts a listed name, and a test fails when a listed name is registered (delete the entry). The same pattern applies to rules: a rule whose event kind is not declared yet lives in `rules/pending/` with `needs: kind:<kind>`, and `TestPendingRulesStillNeedSomething` fails when that kind has been declared.
15. **Rules layout.** `rules/detect/*.yml` (every rule has `module: detect`), `rules/ported/*.yml` (hand-ported, `module: detect`), `rules/pending/*.yml`, and at the top `rules/lists.yml`, `rules/profiles.yml`. The D15 rules (owned by the `deception` module, S4) stay in `rules/detect/deception.yml` until W9 moves them. All packs go to all hosts unless the block's `packs:` names a subset (`shortcut: no per-OS pack filter, upgrade if the held-memory budget is exceeded`). `D14` is reserved for `devices` (Known bug 2).
16. **Controller-scope rules use receive time and ignore replayed events** (design builder check). The controller module stamps `Time` with its clock before `Process`. The pass-the-hash pack needs a `source_label` field only `traceback` (W8) can supply; the pack ships in `rules/pending/` with `needs:` (open item in the design: the controller enriches events from `traceback` label events by store query; W8 declares the kind).
17. **Fact payload shapes `respond` reads are assumptions the senders must match** (hand-offs, listed in the final task): `scorer_probe_result` from `checks` (W7): id `scorer_probe:<service>`, `Data{"service": string, "ok": bool}`, ttl at least 2 round delays; `gpo_finding` from `ad` (W5): id the GPO GUID, `Data` keys looked up case-insensitively: `affects`, `section`, `item`, `enforced`.
18. **`sysmon.install` has no owner** (W3 gap 8b; W5 did not take it). Built here (Task 23) because the `sysmon_reinstall` recipe needs it.
19. **`Touch.Op = "restore"` (`actions.OpRestore`)** is the marker both `ad.recycle_restore` (W5) and `file.restore{source: golden}` (the core action; W2/W5 own the action, Task 36 here adds the scored-content exception) use. Whichever merges first adds the constant; the second reuses it. `StaticGuard` gains `RestorePaths []string` (Task 36).
20. **`content.guard` is not in the manifest.** `manifest.Content` gains `Guard []string` (Task 34).
21. **`content_guard` is agent-only, so it has no controller side to register its page, tile and host-grid column.** Not built here (`shortcut: no Content guard page; the events show in the event views and the Platform page shows health, upgrade by giving the module a controller side when W10 builds the host x step grid`). Its manifest lists no `Pages`. The "re-take the golden copy" button is a `guard.snapshot` plan proposal; the loop clear is the shared ledger reset epoch (gap 8).
22. **The recipe format needs six step flags the design example does not show:** `optional` (skip silently when an entity is absent), `gate` (a read-only step whose named output must be non-empty or the recipe stops: `yara.scan` before a quarantine), `block` (the `source_block` guards), `os` (`linux` or `windows`), `probe` and `rollback` (the step touches scored state, A-AUTO), plus recipe-level `unscored_hosts_only`. A recipe parameter may contain `${name}`, expanded by the controller per host (Task 38) or, for `${now}`, by the runner.

## Global Constraints

- Go 1.27.2 via mise; `CGO_ENABLED=0`; `make build build-windows vet test race` passes at every commit (linux/amd64 and windows/amd64 both build and vet). `-race` needs `CGO_ENABLED=1`.
- Every package ships tests; tests exercise the real code (no mock of the code under test; fakes only at the edge the package does not own: a fake `actions.Action` registered in a fresh `actions.NewRegistry()` for the runner, a fake `ProcBackend`, a fake ADBackend). A test that needs privileges, Windows or containers calls `t.Skip` with a reason string.
- Commits are small, one logical change, message `area: summary` (for example `detect: lists and the list operator`). No attribution lines of any kind.
- No shelling out in the default path (`sysmon.install` and the Windows `bcdedit` use the existing allowlisted `Executor`). Bounded queues, buffers, decoded sizes, timeouts. Atomic writes through `internal/atomicfile` for state files (golden index, breaker state, block records).
- No compatibility shims, aliases or dual formats: a renamed rule id, field or kind is renamed everywhere (rules, recipes, tests, `docs/rules.md`) in the same commit.
- A module imports only the core packages and the shared libraries listed in W1's Global Constraints. `detect`, `respond` and `content_guard` import each other never.
- Times are UTC. Secrets never appear in events, logs, alerts or config.
- The default is off and propose-only: `act_enabled` false, no recipe enabled (the `recipes` list empty), every action template at `autonomy: propose`, `content_guard` off. An automatic action runs only with `respond.act_enabled` true for the host, safe mode off, the recipe enabled for the host, the template's `autonomy` `auto` (at `shadow` it records and applies nothing), the attempt ledger allowing the attempt, and every probe known and green.
- Tier 0 never runs `proc.kill_tree`, `proc.suspend`, an action of risk `destructive`, a scored-password change outside a `resync`, krbtgt, a device revert, a whole-service restore, `fw.apply{op: quarantine}` or `file.restore` with a `source` other than `golden`. CI rejects a recipe that lists one under `tier0:` or `auto:`.
- A tier-0 step takes its parameters only from the alert's `entities` or from literals in the signed recipe; the value passes the action's typed parameter check and the scoring guard.
- Code style ponytail: the smallest complete change; a known limit carries `// shortcut: <limit>, <when to upgrade>`.
- The design is authoritative; a forced design change edits `phylax_design.md` in the same commit with the reason.

## Review Focus

1. **Unknown means do not act.** No `scorer_probe_result` fact yet, an expired one, a scored service with no `health:` block, a probe that errors: expected a `respond.action` with `skipped_guard` and a click proposal, never an apply (Task 26 `TestUnknownVerdictNeverActs`, Task 30 `TestSkippedTier0BecomesProposal`).
2. **Hostile event values used as action parameters.** A file path with `..` or a newline, a unit name with a space, an entity that the alert does not carry: expected `skipped_guard`, no action call (Task 27 `TestParamMustBeAnEntity`, `TestHostileEntityRefused`).
3. **Replayed history.** An enrollment backscan or a resent spool carries old events flagged `replay: true`: expected no alert, no `count` window entry, no response (Task 7 `TestReplayExcluded`).
4. **The restorer fights the red persistence or a GPO.** A timer disables the firewall every minute; an Enforced GPO reverts Defender: expected the attempt ledger's breaker opens on the third restore (`plan.failed{reason: auto_halted, trigger: repeat}`), a GPO fact turns it into `skipped_gpo` (Task 25 `TestLedgerOpensOnCount`, Task 26 `TestGPOStopsLoop`).
5. **A guarded content file is replaced by a symlink, deleted, or changed while a plan holds the lock.** Expected: the guard never follows the link, reports a deleted listed file as a change with `would_restore`, ignores a tagged or lock-held change and marks the golden stale; the `content_restore` recipe's `file.restore{source: golden}` replaces the link or restores the file (Task 34 `TestSymlinkPathRefused`, Task 35 `TestTaggedChangeMarksStale`, `TestDeletedFileReported`, Task 36 `TestRestoreReplacesSymlink`).

---

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `internal/detect/kinds.go` | `detect.alert`, `detect.suppressed` payloads and `Declare` | 1 |
| `internal/detect/module.go`, `manifest.go`, `config.go` | agent module, manifest, block `Config`, health | 2 |
| `internal/detect/fieldcheck.go` | canonical-field and declared-kind check | 3 |
| `internal/detect/lists.go`, `exceptions.go`, `rate.go`, `jitter.go` | engine additions (no `modes.go`: S1) | 4 to 9 |
| `internal/detect/controller.go` | controller module (scope `controller`) | 10 |
| `internal/detect/collect*.go` | evidence collectors | 12 |
| `internal/detect/registry.go`, `tree.go`, `attack.go`, `attack_v19.txt`, `thirdparty.go` | id registry, rule tree loader, ATT&CK ids, third-party list | 13 to 15 |
| `internal/detect/ui.go` | Rules page, tile | 33 |
| `rules/detect/*.yml`, `rules/ported/*.yml`, `rules/pending/*.yml`, `rules/lists.yml`, `rules/profiles.yml` | rule corpus | 13, 16 to 19 |
| `cmd/phylax/rules.go` | `phylax rules test`, `registry`, `third-party`, `promote` | 15 |
| `internal/actions/proc.go`, `proc_linux.go`, `proc_windows.go`, `proc_other.go`, `dirsnap.go`, `sysmon.go` | `proc.*`, `dir.snapshot`, `sysmon.install` | 20 to 23 |
| `internal/actions/ledger.go` | the engine's attempt ledger (one definition; built in Task 25 unless the engine plan already built it) | 25 |
| `internal/respond/` | `kinds.go`, `recipe.go`, `validate.go`, `pending.go`, `guards.go`, `verdict.go`, `runner.go`, `controller.go`, `config.go`, `manifest.go`, `ui.go` | 24 to 33 |
| `rules/respond/*.yml`, `rules/respond/recipes.go` | recipes (embedded), including `content_restore` | 28, 29, 32, 36 |
| `plans/respond/*.yml` | one-node plan templates for proposals and auto plans | 28, 29, 32 |
| `internal/content_guard/` (package `contentguard`), `content_guard/boot_critical.yml`, `plans/content_guard/guard.snapshot.yaml` | `kinds.go`, `golden.go`, `actions.go`, `watch.go`, `boot.go`, `source.go` (the `golden` source of `file.restore`), `lint.go`, `module.go`, `config.go` (no `restore.go`, no `modes.go`: the restore is the core `file.restore{source: golden}` run by the `content_restore` recipe, S1) | 34 to 37 |
| `internal/controller/genconfig.go` | renders the three blocks into the signed config | 38 |
| `manifest/2027/modules/{detect,respond,content_guard}.yml` | reference blocks | 38 |
| `internal/e2e/detect_respond_test.go` | recorded-alert replay, id cross-checks | 39 |
| `docs/impl/lab/w4-detection-response.md` | lab record | 40 |

---

### Task 1: Seams (Sonnet or Opus)

Done by a stronger model. Declares the four kinds (`detect.alert`, `detect.suppressed`, `respond.action`, `content_guard.change`), writes the settings structs, the package skeletons with stub bodies, the extension fields on W1 and W3 types, the design edits and every skipped test file the later tasks implement. Merges on its own (its own pull request into `v4`); W9 waits for it (it needs `detect.alert`).

**Files:**
- Create: `internal/detect/kinds.go`, `internal/respond/{doc.go,kinds.go,recipe.go,validate.go,pending.go,guards.go,verdict.go,runner.go,controller.go,config.go,manifest.go}`, `internal/content_guard/{doc.go,kinds.go,golden.go,watch.go,boot.go,module.go,config.go}` (package `contentguard`), `rules/respond/recipes.go`, `internal/agent/mods/{respond,content_guard}.go`
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
// No respond.breaker and no respond.loop (S1): the attempt ledger's stop is the core plan.failed{reason: auto_halted} (declared by W1 Task 5, emitted by the executor).
const KindAction = "respond.action" // schema 1, high
const ( // ActionFields.Outcome
	OutApplied = "applied"; OutFailed = "failed"; OutRolledBack = "rolled_back"; OutShadow = "shadow"
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

// ---- internal/content_guard/kinds.go (package contentguard) ----
// One kind (S1, S4): the restore, its probes and its rollback are respond.action events (recipe content_restore); the stop is plan.failed;
// golden_missing and golden_stale are telemetry_gap{source: content_guard, reason} (critical), the guard's sensor-state record.
const KindChange = "content_guard.change" // schema 1, high
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
	Decision      string `json:"decision"`      // alert | ignored_tag | ignored_plan_lock
	WouldRestore  bool   `json:"would_restore"` // the golden hash verifies and the service probe was green; set whether or not a recipe is enabled
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
type RecipeEnable struct { // an overrides.yml record: the recipe tied to Rule is enabled on the hosts it applies to (S1: the only act switch, same shape as Exception)
	Rule     string   `json:"rule"`
	Services []string `json:"services,omitempty"` // content_restore only: limit to these services
	Reason   string   `json:"reason"`
	Owner    string   `json:"owner"`
	Added    string   `json:"added"`
}
// DetectSettings gains: Lists []ListFile `json:"lists,omitempty"`; Exceptions []Exception `json:"exceptions,omitempty"`  (no RuleModes: S1)
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
type Tier0Settings struct { // the design's fields; BreakerWindowSec, LoopCount, LoopWindowSec and MaxPerHostPerMin configure the attempt ledger and the host cap
	MaxPerHostPerMin int      `json:"max_per_host_per_min,omitempty"`
	BreakerWindowSec int      `json:"breaker_window_sec,omitempty"`
	LoopCount        int      `json:"loop_count,omitempty"`
	LoopWindowSec    int      `json:"loop_window_sec,omitempty"`
	BlockExpiresSec  int      `json:"block_expires_sec,omitempty"`
	BlockMaxActive   int      `json:"block_max_active,omitempty"`
	Recipes          []string `json:"recipes,omitempty"` // recipes enabled on this host (the per-rule act switch)
}
type RespondSettings struct {
	ModuleLimits
	module.Actor // ActEnabled and Autonomy (recipe rule id -> propose|shadow|auto; absent means propose)
	Tier0      Tier0Settings `json:"tier0"`
	Protected  []string      `json:"protected_processes,omitempty"`
	Recipes    []RecipeFile  `json:"recipes,omitempty"`
	Services   []HostService `json:"services,omitempty"`
	NeverBlock []string      `json:"never_block,omitempty"` // CIDRs/addresses source_block refuses
	ResetEpoch int           `json:"reset_epoch,omitempty"` // greater than the kept epoch: the agent clears its ledger
}
// ContentGuardSettings, GuardService, GuardBoot as the design (module content_guard, part 4: no Actor, no mode, no promotion), plus
//   GuardService.Health *HealthProbe `json:"health,omitempty"` (the service's probe, run locally);
//   GuardBoot.Candidates []BootCandidate and: type BootCandidate struct{ Path string `json:"path"`; Distro []string `json:"distro,omitempty"`; Resolve string `json:"resolve,omitempty"` /* "initramfs" */ ; Never bool `json:"never,omitempty"` /* never auto-restored */ }
// ModuleSettings gains: Respond *RespondSettings `json:"respond,omitempty"`; ContentGuard *ContentGuardSettings `json:"content_guard,omitempty"`

// ---- internal/manifest/types.go ----
// Overrides gains: Recipes []RecipeEnable `yaml:"recipes,omitempty"`; Exceptions []RuleException `yaml:"exceptions,omitempty"`;
//   RespondResetEpoch int `yaml:"respond_reset_epoch,omitempty"`   (the one ledger reset epoch; no rule_modes, no guard clear epoch)
// type RuleException / RecipeEnable: same fields and json/yaml tags as plan.Exception / plan.RecipeEnable (a RecipeEnable needs reason, owner, added)
// Content gains: Guard []string `yaml:"guard,omitempty" json:"guard,omitempty"`

// ---- module registration ----
// internal/agent/mods/respond.go and content_guard.go: agent.RegisterFactory(agent.Factory{Name, Manifest, Section, Build}) with
//   Build returning ErrUnavailable("seams") until Tasks 27 and 37; internal/respond registers its controller module with module.Register from init (Task 30).
// conformance.PreContract gains nothing: the new modules enter the suite at their conformance task.
```

- [ ] **Step 1: Write the stubs.** Types, constants and signatures exactly as above; function bodies `panic("unimplemented: W4 Task N")` naming the implementing task, except trivial constants. The four `Declare` calls are real (priorities and alert flag as given). `Env.Actions()` returns `e.a.exec.env` or nil. Add `module.Registered` entries only where the module has a controller side (`detect`, `respond`), each a stub whose `Start` returns `module.ErrNoConfig`.
- [ ] **Step 2: Write the skipped tests and their helpers** for Tasks 2 to 39 (each task's Step 1 body, first statement `t.Skip("unimplemented: W4 Task N")`).
- [ ] **Step 3: Apply the design edits.** In `phylax_design.md`: gaps 3 to 9, 11, 12, 15 and 17 to 20 as text in the owning module sections (the `respond` catalogue row becomes "Agent + controller"; the kind table gains `respond.action` and `plan.failed` as consumers of `respond` and the `id` key of `detect.alert`; `evidence.blob` keys; the recipe example's `params_from` is a map `{param: entities.field}`; the Appendix D rules layout line; the Overrides row in Manifest: Files gains `recipes` and `respond_reset_epoch`). Bump "28 core kinds" is W1's; do not touch it.
- [ ] **Step 4: Verify.** Run: `make build build-windows vet test race`. Expected: all pass. Then `go test -v ./internal/... 2>&1 | grep -c 'unimplemented: W4 Task'`. Expected: the number of skipped tests written in Step 2, and no stub panic runs.
- [ ] **Step 5: Commit.**

```bash
git add internal rules cmd phylax_design.md
git commit -m "detect: W4 seams (kinds, settings, package skeletons, skipped tests, design edits)"
```

Open this as its own pull request into `v4` and merge after review.

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

Rules: the module subscribes with `env.Subscribe(8192, rs.Kinds()...)` and still drops any kind with prefix `detect.` and `controller.fact`; a rule-set parse failure at `Build` keeps the previous module's rule set (`env.Kept("detect.ruleset")`) and reports `degraded` with `Detail` naming the file and error; with no previous set `Build` returns the error. `Health().Info` keys: `rules`, `state_keys`, `profile_keys`; `detect` has no act switch (S1), so `Config` carries `enabled` only (no `act_enabled`, no `autonomy`) and `RatePerSec`/`Burst` are optional overrides of the manifest's. Profiles are kept across reconfiguration as today (`detect.profiles`). `shortcut: producer gaps (a rule whose kind no enabled module emits) are not reported, upgrade when Harness exposes the enabled manifests`.

- [ ] **Step 1: Remove the skips:**

```go
func TestAlertEventValidates(t *testing.T) {
	t0 := time.Date(2027, 2, 6, 12, 0, 0, 0, time.UTC)
	e := AlertEvent(Alert{RuleID: "D1.x", Title: "t", Severity: "high", Tier: 1, Agent: "h1", Time: t0,
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

### Task 4: Strict rule keys: `module`, `replay`; delete `ir_template` (Known bug 22); delete rule `mode` and `AlertOnly` (S1)

**Files:**
- Modify: `internal/detect/rule.go` (`ruleDoc` and `Rule`: add `Module string`, `Replay string`; delete `IRTemplate`, `Mode` and the `mode` key), `internal/detect/engine.go` (`Alert.IRTemplate`, `Alert.Mode` and `Options.AlertOnly` deleted), `internal/detect/engine_test.go` (the `ir1` assertions; every use of `Mode`/`AlertOnly`), `internal/agent/mods/detect.go` (the observe/`act_enabled` gate goes with `AlertOnly`; the module no longer reads `ActEnabled`), `rules/linux_exec.yml` and `rules/windows.yml` (delete the two `ir_template` lines), every `rules/*.yml` (delete each `mode:` line, a mechanical edit), `docs/rules.md`
- Test: `internal/detect/rule_keys_test.go`

**Interfaces:**
- Produces: a rule document requires `module: detect` (any other value, or none, is a load error `module must be detect`); `replay:` accepts `allow` only; a rule that still has `ir_template` or `mode` fails with the loader's standard unknown-key error; `Rule.ReplayAllow bool`. `detect` only alerts (S1): there is no rule mode, no `Options.AlertOnly`, no global observe switch and no `Alert.Mode`; whether an alert leads to an action is decided by `respond` (a recipe tied to the rule id, enabled for the host).

- [ ] **Step 1: Write the tests:**

```go
func TestModuleKeyRequired(t *testing.T) { /* no module: -> error "module"; module: respond -> error */ }
func TestIRTemplateKeyRejected(t *testing.T) {
	y := ruleWith("module: detect\nir_template: web-app-compromise\n")
	if _, err := Parse("t", []byte(y), LoadOptions{}); err == nil || !strings.Contains(err.Error(), "ir_template") { t.Fatal(err) }
}
func TestModeKeyRejected(t *testing.T) { /* a rule with `mode: act` or `mode: alert` -> unknown-key error naming mode; no `Mode` field or AlertOnly option exists (compile-time) */ }
func TestReplayKey(t *testing.T) { /* replay: allow -> ReplayAllow true; replay: yes -> error */ }
func TestNoIRTemplateOrModeInTree(t *testing.T) { /* grep-style: no file under rules/ contains "ir_template" or a `mode:` key at rule level */ }
```

Every rule file in the corpus gets `module: detect` on each rule document and loses its `mode:` line in this commit (a mechanical edit; the tree move is Task 13). Which rules lead to an action is no longer a property of the rule: it is the recipes of Tasks 28 and 29 and their per-host enablement.

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'ModuleKey|IRTemplate|ModeKey|ReplayKey|NoIRTemplate' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified; update `docs/rules.md` (key list; `ir_template` and `mode` gone).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/ ./internal/controller/ ./internal/e2e/ ./internal/agent/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect: module and replay keys; delete ir_template (bug 22), rule mode and AlertOnly (S1)"`

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

### Task 9: `jitter` (mode promotion and `rule_modes` removed by S1, 2026-11-06)

Rule promotion is now the per-host enablement of a `respond` recipe plus the template's `autonomy` (Tasks 24 to 28 and 33); `detect` has no `modes.go`, no `Options.RuleModes`, no `Engine.Mode` and no `Overrides.RuleModes`.

**Files:**
- Create: `internal/detect/jitter.go`
- Modify: `internal/detect/rule.go` (`whenDoc.Jitter`)
- Test: `internal/detect/jitter_test.go`

**Interfaces:**
- Produces:

```go
// when: jitter: {below: 0.2, min_events: 10, by: [raddr, rport], window: 1h, cooldown: 1h}
//   Keeps the last min_events*2 event times per key (bounded by max_keys); fires when at least min_events events lie in window
//   and the coefficient of variation of the gaps (stddev/mean) is below `below`; then quiet for cooldown (default window).
//   jitter is exclusive with count and sequence; below in (0, 1]; min_events at least 4.
```

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
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'Jitter' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect: jitter"`

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

Rules: `Start` decodes `Config` (`ErrNoConfig` returns, health `unavailable`), loads the rules under `Config.RulesPath` (default `rules`) with `LoadOptions{Declared: true}`, builds `NewEngine(rs, Options{Scope: "controller", ReceiveTime: true, MaxKeys: cfg.MaxKeys})`, subscribes (`h.Subscribe(rs.Kinds(), 4096)`; the kinds must be in `Manifest().Consumes`) and for each committed event calls `Process` with `Time` replaced by the controller clock (the original time is in `evidence`). Alerts go out through `h.Emit(AlertEvent(a))` (stored under agent `controller`; the controller's alert queue picks `detect.alert` up by kind). A controller alert's `entities` carry the `agent` of the triggering event (`entities.agent`). `shortcut: manifest-derived lists are not available to controller-scope rules, only rules/lists.yml; upgrade when Host exposes the manifest lists`.

- [ ] **Step 1: Remove the skips:**

```go
func TestControllerRuleFiresAcrossAgents(t *testing.T) { // D18b shape: one source authenticating to 3 hosts in 5 minutes
	h := newFakeHost(t, "enabled: true\nrules_path: testdata/rules\n")
	c := &Controller{}
	go c.Start(h.ctx, h)
	for i, agent := range []string{"web", "db", "mail"} {
		h.publish(event.Event{Agent: agent, Kind: "auth_event", Time: time.Now(), Fields: map[string]any{"result": "success", "account": "bob", "service": "ssh", "source": "198.51.100.7"}})
		_ = i
	}
	al := h.waitEmitted(t, "detect.alert", 1)
	f, _ := event.Decode[AlertFields](al[0], KindAlert)
	if f.Rule != "D18b.fanout" || f.Entities["source"] != "198.51.100.7" { t.Fatalf("%+v", f) }
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

### Task 11: `agent.health` carries module state and `Info`

The controller-side audit-rules hash compare (rule `D10.audit-rules-changed` on `agent.health`, its profile `audit_rules_hash`, `TestAuditRulesHashDropRaisesD10`) is removed by S4: `Health.Info` and `agent.health` remain, the Platform page displays the hash, and the `audit` module repairs its own rules (the corpus rule on `audit.rules_changed` keeps its id).

**Files:**
- Modify: `internal/agent/health.go` (`HealthSource.ModuleHealth`, `report`), `internal/agent/agent.go` (implement `ModuleHealth` over `Supervisor.Health`)
- Test: `internal/agent/health_info_test.go`

**Interfaces:**
- Consumes: W1 `module.Health`, `(*Supervisor).Health`, `agent.HealthReporter`; W3 Task 6 (`audit` fills `Info["rules_hash"]`, `Info["rules_installed"]`).
- Produces:

```go
// HealthSource gains:
ModuleHealth() map[string]module.Health
// agent.health fields: modules.<name> = {state, restarts, emitted, rate_dropped, spool_drops, last_error, info: map[string]string, gaps: n}
// emission: every interval as today, and immediately when any module's State or Info map differs from the previous report (at most one extra per 5 s).
```

- [ ] **Step 1: Write the tests:**

```go
func TestHealthEventCarriesInfo(t *testing.T) {
	// a test agent with a HealthReporter module whose Info {"rules_hash": "abc"}; the agent.health event Fields["modules"]["m"]["info"]["rules_hash"] == "abc"
}
func TestHealthEmittedOnInfoChange(t *testing.T) { /* change Info; a new agent.health arrives within 6 s although the interval is 1 h; no second one if nothing changes */ }
func TestHealthInfoBounded(t *testing.T) { /* a module with 100 Info keys: the event carries at most 32, keys <= 64 bytes, values <= 256 */ }
func TestAuditRulesEventRuleKept(t *testing.T) { /* D10.audit-rules-changed (agent scope, on audit.rules_changed) still fires; no rule reads agent.health's rules_hash */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/agent/ ./internal/detect/ -run 'HealthEvent|HealthEmitted|HealthInfo|AuditRulesEvent' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified (`gap` and `report` otherwise unchanged).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/agent/ ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "agent: health event carries module info"`

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

### Task 15: `phylax rules`: `test`, `registry`, `third-party`, `promote` (writes the recipe-enable record, S1)

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
// phylax rules promote RULE --reason R --owner O [--services S,...] [--manifest DIR] [--check-only]
//    checks (1) the rule's inline tests pass, (2) a respond recipe lists the rule as a trigger with tier0 or auto steps, (3) none of those steps is in the click-only set;
//    then AppendOverrides adds a RecipeEnable {rule, services, reason, owner, added: today} to overrides.yml (the recipe is enabled for the host; its autonomy is a separate signed setting). --check-only prints the verdict and writes nothing.
//    demote: `phylax rules promote RULE --remove` deletes the record (checks 2 and 3 skipped). There is no rule mode to write (S1).
```

A ported rule's `source:` must carry `author`, `license`, `id`, `path`, `commit` (the loader's `Source map[string]string` is checked here: `source:` with only `author: Phylax, license: repo` is allowed for own rules).

- [ ] **Step 1: Write the tests:**

```go
func TestRulesTestExitCodes(t *testing.T) { /* run(["rules","test","--rules",fixtureDir]) == 0; a fixture rule with a failing inline test == 1 and the output names rule and test */ }
func TestRulesRegistryCatchesDuplicate(t *testing.T) { /* two files with the same id -> exit 1 */ }
func TestThirdPartyMarkdown(t *testing.T) { /* a ported rule with source {id: sigma-1, path: x.yml, commit: abc, author: A, license: DRL-1.1} appears; a rule with source {author: Phylax, license: repo} does not */ }
func TestThirdPartyFileIsCurrent(t *testing.T) { /* run third-party --check against the repo: exit 0 */ }
func TestPromoteWritesOverride(t *testing.T) { /* a fixture rule with a tier0 recipe: promote writes a recipes record; a rule whose recipe lists proc.kill_tree under tier0: refused; --remove deletes it; --check-only writes nothing */ }
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
- Produces: these rules, each with `module: detect`, `exempt_tagged: true`, ATT&CK ids valid in the v19 file (pick the closest valid id; the tests below check `AttackValid`), a `should_match: true` and a `should_match: false` inline test:

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
		if r.Tier != tier || !r.ExemptTagged() { t.Errorf("%s: tier %d", id, r.Tier) }
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
- Produces rules (`module: detect`, `exempt_tagged: true`, inline tests):

| Id | Condition | Tier |
| --- | --- | --- |
| `D7h.scored-account-deleted` | `winevt.sec_event` event 4726 with `target_user` in `{list: manifest.scored_users}`; recipe `recycle_restore` (Task 29, a controller `RunAuto` plan once enabled); chain seed | 0 |
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
func TestCatalogueBRulesPresent(t *testing.T) { /* each id above: tier as the table; no rule carries a mode */ }
func TestD7hOnlyForScoredAccounts(t *testing.T) {
	rs := mustLoadTreeWithLists(t, map[string][]string{"manifest.scored_users": {"svc-ecom"}})
	// 4726 target svc-ecom: fires; 4726 target tmpuser: D7h does not fire, D7i does
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
- Produces: ten rules (ids `D26.*`), `module: detect`, `tier: 1`, each with `source: {id: <upstream rule id>, path: <path in the upstream repo>, commit: <40-hex>, author: <upstream author>, license: DRL-1.1}`: Cloudflared tunnel (`D26.cloudflared-tunnel`), Velociraptor child process, Raccine uninstall, browser remote debugging (`--remote-debugging-port`), `sc sdset` and hidden-service DACL (pairs with `D10l`), `regini`, ADExplorer snapshot, `certutil -exportPFX`, `whoami /all`, CrackMapExec process patterns. Third-party logic is ported by hand: read the upstream Sigma rule in the SigmaHQ repository at a recorded commit, re-express its detection in this format, never copy the file.

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
		if r.Tier != 1 { t.Errorf("%s", r.ID) }
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
  - `D13c.beacon-periodicity` (move out of pending): `scope: controller`, `conn` with `dir: outbound`, `exempt_tagged`, not `rport` in `[53, 123, 67, 68, 137, 138, 5353]`, `jitter: {below: 0.2, min_events: 10, by: [agent, raddr, rport], window: 1h}`; `tier: 1`, comment says periodic infrastructure traffic (NTP, DNS, monitoring) makes this noisy and that the list of allowed destinations belongs in `exceptions`.
  - `D18b.credential-fanout` and `D13e.scan-source-rotation`: confirm `scope: controller` and that they use `by: [raddr_net16]` / `distinct`; add the inline multi-agent tests if absent (test events carry `agent:`).
  - `D22.prebake-hunt-trigger`: `agent.enrolled` or `agent.reenrolled` (core kinds), `tier: 1`, `replay: allow` is not set.
  - `D21.address-route-neighbour` and the other rules whose `needs: kind:<kind>` kind is now declared (`inventory.row`, `inventory.snapshot`, `logs.line`, `winevt.sec_event`): unparked into `rules/detect/`; run `PendingErrors` until it reports nothing.
  - `rules/pending/pass_the_hash.yml`: five rules `D27.ptH-ntlm-scored`, `D27b.ptH-ntlm-no-service-use`, `D27c.ptH-rc4-ticket`, `D27d.ptH-tgt-unlabelled-source`, `D27e.ptH-two-sources` (design pass-the-hash pack), `scope: controller`, no recipe (comment), each `needs: kind:traceback.label` and a `source_label` condition (W8), each with inline tests that use a `source_label` field. `D10k3.firewall-drift` (`firewall.drift`, tier 0; no recipe is tied to it until Task 29) is parked with `needs: kind:firewall.drift`.

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

### Task 24: `respond` recipe format, loader, validation and the pending-action list

**Files:**
- Create: `internal/respond/recipe.go`, `internal/respond/validate.go`, `internal/respond/pending.go`, `internal/respond/view.go`, `internal/module/all/content.go`
- Modify: `rules/respond/recipes.go` (package `respondrecipes`: `//go:embed *.yml` into `var FS embed.FS`; the embed needs at least one `.yml`, so this task adds `firewall_restore.yml` early or Task 28 lands first in the same pull request), `internal/respond/config.go`
- Test: `internal/respond/recipe_test.go`, `internal/respond/validate_test.go`

**Interfaces:**
- Consumes: `actions.Registry` (`Get`, `Names`), `actions.Spec` (`Risk`, `Validate`), `actions.Action.Touches`, `plan` template loader (`controller.LoadModuleTemplate` is controller-side; here templates are read from an `fs.FS` rooted at `plans/respond`).
- Produces:

```go
type Step struct {
	Action     string            `yaml:"action"`
	Params     map[string]any    `yaml:"params"`
	ParamsFrom map[string]string `yaml:"params_from"` // param -> "entities.<key>"
	Optional   bool              `yaml:"optional"`    // skip silently when an entity is absent
	Gate       string            `yaml:"gate"`        // output key that must be non-empty, else the recipe stops (skipped_guard, "gate")
	Block      bool              `yaml:"block"`       // source_block guards apply (Task 29)
	OS         string            `yaml:"os"`          // "", "linux" or "windows"
	Probe      bool              `yaml:"probe"`       // touches scored state: a known green scorer-mimic verdict is required first
	Rollback   bool              `yaml:"rollback"`    // the action returns rollback data
}
type Proposal struct {
	Title      string            `yaml:"title"`
	Template   string            `yaml:"template"` // plans/respond/<name>.yml
	Params     map[string]string `yaml:"params"`
	ParamsFrom map[string]string `yaml:"params_from"`
	Note       string            `yaml:"note"`
}
type TestAlert struct {
	Rule     string            `yaml:"rule"`
	Tier     int               `yaml:"tier"`
	Agent    string            `yaml:"agent"`
	Entities map[string]string `yaml:"entities"`
}
type RecipeTest struct {
	Name        string    `yaml:"name"`
	Alert       TestAlert `yaml:"alert"`
	WantTier0   []string  `yaml:"want_tier0"`   // action names, in order
	WantPropose []string  `yaml:"want_propose"` // template names
	WantAuto    []string  `yaml:"want_auto"`
	WantError   string    `yaml:"want_error"`   // substring of the Resolve error
}
type Recipe struct {
	Name              string      `yaml:"recipe"`
	Module            string      `yaml:"module"`
	Triggers          []string    `yaml:"triggers"`
	RequiresSensors   []string    `yaml:"requires_sensors"`
	GPOSetting        string      `yaml:"gpo_setting"` // "", firewall, defender, audit
	UnscoredHostsOnly bool        `yaml:"unscored_hosts_only"`
	Collect           []string    `yaml:"collect"`
	Tier0             []Step      `yaml:"tier0"`
	Propose           []Proposal  `yaml:"propose"`
	Auto              []string    `yaml:"auto"`
	Tests             []RecipeTest `yaml:"tests"`
	File              string      `yaml:"-"`
}
type RecipeSet struct{ Recipes []*Recipe }
func Parse(name string, data []byte) (*RecipeSet, error)     // multi-document, strict (KnownFields); recipe, module: respond, triggers and tests mandatory
func LoadFS(fsys fs.FS) (*RecipeSet, error)                    // every *.yml in the root, sorted
func SetContent(fsys fs.FS)                                    // internal/module/all/content.go calls SetContent(respondrecipes.FS)
func Content() fs.FS
func Matches(trigger, ruleID string) bool                      // exact id, or "D1.*": prefix "D1." only (never D17 or D1f)
func (rs *RecipeSet) For(ruleID string) []*Recipe               // sorted by recipe name
type Resolved struct {
	Recipe  *Recipe
	Tier0   []Call            // Call{Action string; Params map[string]any; Step Step}
	Propose []ProposalCall    // ProposalCall{Title, Template string; Params map[string]string; Note string}
	Auto    []string
}
func (r *Recipe) Resolve(a AlertView, now time.Time) (Resolved, error)
type AlertView struct { // loose view of a detect.alert (no import of internal/detect)
	ID, Rule, Agent string
	Tier                  int
	Entities              map[string]string
	Seq                   uint64
	Time                  time.Time
}
func ViewOf(e event.Event) (AlertView, error) // json round trip of Fields into the view; unknown keys ignored; Tier/Rule required
func (rs *RecipeSet) RunTests() []TestResult // TestResult{Recipe, Test string; Err error}
type Validator struct {
	Actions   *actions.Registry
	RuleIDs   map[string]bool // nil: skip the trigger check
	Templates fs.FS           // plans/respond
	Modules   map[string]bool // module names for requires_sensors
}
func (rs *RecipeSet) Validate(v Validator) []error
var ClickOnly = []string{"proc.kill_tree", "proc.suspend", "proc.dump", "ad.account.krbtgt_reset", "backup.restore", "palo.revert", "vyos.apply", "host.exec", "user.set_password", "sql.set_password", "ad.account.reset_password"}
var ClickOnlyCalls = []struct{ Action, Param, Value string }{{"fw.apply", "op", "quarantine"}} // special-case actions folded into general ones (S4): the click-only form is a parameter value
// file.restore under tier0: or auto: must carry the literal params {source: golden}; source depot or backup is propose-only (the depot restore is click-only, D-1)
type Pending struct{ Owner string; Scored bool } // Scored: the action's Touches can name scored state (so a step must say probe and rollback)
var PendingActions = map[string]Pending{
	"fw.apply": {"W6", false}, // op policy | allow | block | quarantine (S4); fw.snapshot is W6's too
	"task.disable": {"W5", false}, "runkey.remove": {"W5", false}, "wmi.subscription_remove": {"W5", false}, // unit disable is service.state (built)
	"ad.recycle_restore": {"W5", true}, "ad.gpo_unlink": {"W5", false}, "file.restore": {"W5", true}, // source golden | depot | backup (S4)
	"hunt.persistence": {"W5", false}, "yara.scan": {"W5", false}, "session.terminate_predating": {"W2", false},
}
```

`Resolve` rules: a `params_from` value must be `entities.<key>` and the alert must carry the key (else an error `entity <key> missing`, unless the step is `Optional`, which is then omitted); a resolved string must have no byte below 0x20 and no 0x7f, at most 4096 bytes, and a value for a parameter named `path`, `exe`, `unit_path` or ending `_path` must be absolute and equal to its `filepath.Clean` (no `..`); `${now}` in a literal param becomes `now` in RFC 3339 UTC; `os` mismatch with `runtime.GOOS` omits the step. `Validate` rules (each an error naming recipe and step): `module: respond`; every trigger is an exact id or `<id-prefix>.*` and, with `RuleIDs`, matches at least one rule; every action is registered or in `PendingActions` (and the entry must not also be registered: `remove it from PendingActions`); no `ClickOnly` action (and no `ClickOnlyCalls` parameter value) and no registered action with `Risk == RiskDestructive` under `tier0:`, a `file.restore` step whose literal `source` is not `golden` under `tier0:` or `auto:`, and no `proc.kill_tree` under `auto:` either (templates under `auto:` are checked in Task 30); a tier-0 step whose action is registered and whose `Touches` for the test alerts' resolved params is non-empty, or whose action is a `Scored` pending one, must set `probe` and `rollback`; a recipe with `tier0:` has at least one `propose:` entry (a skipped tier-0 action becomes a click); every `Proposal.Template` and `auto` name has `<name>.yml` in `Templates` with `module: respond`, and the proposal's `params`+`params_from` keys plus `host` equal the template's `${...}` placeholder set; every `requires_sensors` name is in `Modules`; at least one test, and every test passes `RunTests`.

- [ ] **Step 1: Write the tests:**

```go
func TestParseStrict(t *testing.T) { /* unknown key (ir_template, tier1) -> error; missing triggers -> error; duplicate recipe name across docs -> error */ }
func TestTriggerMatching(t *testing.T) {
	for _, c := range []struct{ trig, id string; want bool }{
		{"D1.*", "D1.service-spawns-shell", true}, {"D1.*", "D17b.x", false}, {"D1.*", "D1f.web", false},
		{"D10k.fw-exec-tamper", "D10k.fw-exec-tamper", true}, {"D10k", "D10k.fw-exec-tamper", false}, {"D1.*", "D1", false},
	} { if got := Matches(c.trig, c.id); got != c.want { t.Errorf("%+v", c) } }
}
func TestResolveBindsEntities(t *testing.T) { /* params_from {path: entities.path} with path /var/www/x.php resolves; missing key -> error "entity path missing"; Optional step omitted */ }
func TestHostileEntityRefused(t *testing.T) { /* path "/var/www/a\nb", "/var/www/../../etc/shadow", "relative.php", 5000 bytes -> Resolve error, each */ }
func TestViewOfIgnoresUnknownKeys(t *testing.T) { /* a detect.alert with a key the view does not know decodes; without rule -> error */ }
func TestValidateRejectsClickOnlyUnderTier0AndAuto(t *testing.T) { /* proc.kill_tree under tier0: error; under propose: ok; a registered RiskDestructive action under tier0: error */ }
func TestValidateScoredStepNeedsProbeAndRollback(t *testing.T) { /* fake registered action whose Touches names a service: step without probe -> error; with both -> ok */ }
func TestValidatePendingAction(t *testing.T) { /* fw.apply is accepted while unregistered; registering a fake fw.apply makes Validate report "remove it from PendingActions" */ }
func TestValidateSpecialCaseCalls(t *testing.T) { /* fw.apply{op: quarantine} under tier0: error, under propose: ok; file.restore{source: depot} under tier0: or auto: error, {source: golden} under tier0: ok */ }
func TestValidateTemplatesAndParams(t *testing.T) { /* missing template file -> error; params mismatch with ${...} -> error naming the extra/missing key */ }
func TestValidateTier0NeedsPropose(t *testing.T) { /* tier0 without propose -> error */ }
func TestRunTestsFailingExpectation(t *testing.T) { /* want_tier0 [fw.apply] but the recipe resolves [win.defender] -> TestResult.Err */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/respond/ -run 'Parse|Trigger|Resolve|Hostile|ViewOf|Validate|RunTests' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified. `Matches`: a trigger ending `.*` is a prefix match on the text up to and including the dot; otherwise equality.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/respond/ ./internal/module/all/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "respond: recipe format, loader, validation, pending-action list"`

---

### Task 25: Tier-0 guards: protected set, host cap, and the engine's attempt ledger (S1)

The per-module loop detector and per-object limiter are replaced by the engine's one attempt ledger (design: Execution engine, Autonomy and the attempt ledger): one entry per (host, object, kind) with count, window and breaker. The same type serves the controller engine's `RunAuto` plans and any other acting module's templates; the agent keeps its own instance in the state directory for tier-0 recipes that run with the link down. If the engine plan has already built `internal/actions/ledger.go`, this task adds only the agent-side use and tests.

**Files:**
- Create: `internal/actions/ledger.go`
- Modify: `internal/respond/guards.go`
- Test: `internal/actions/ledger_test.go`, `internal/respond/guards_test.go`

**Interfaces:**
- Produces (pure, fake-clock testable, state exportable for `Env.Keep`):

```go
type Protected struct{ /* base names, lower case */ }
func NewProtected(extra []string) *Protected
func (p *Protected) Exe(path string) bool // base name in: csrss.exe wininit.exe winlogon.exe services.exe smss.exe lsass.exe svchost.exe systemd sshd, or in extra; Windows and Linux separators

type Limiter struct{ /* per-host window */ }
func NewLimiter(hostPerMin int, now func() time.Time) *Limiter // hostPerMin default 3 (max_per_host_per_min); per-object limits belong to the ledger
func (l *Limiter) Allow(host string) bool // records only when ok

// internal/actions/ledger.go
type LedgerKey struct{ Host, Object, Kind string } // Object "*" means every object of that kind on the host (a red post-check trips the action type)
type LedgerLimit struct{ Count int; Window time.Duration } // engine default {2, 10m}; respond's loop block {3, 10m}; content_restore {2, 10m}
type Ledger struct{ /* entries: attempts in window, breaker open */ }
func NewLedger(now func() time.Time) *Ledger
func (l *Ledger) Attempt(k LedgerKey, lim LedgerLimit) (ok bool, opened bool)
//   refused (ok false) while the breaker is open for k or for {k.Host, "*", k.Kind}; otherwise counts the attempt; opened is true exactly once, when the count reaches lim.Count inside lim.Window
//   (the breaker then opens: the next attempt is refused). A shadow run never calls Attempt.
func (l *Ledger) WouldOpen(k LedgerKey, lim LedgerLimit) bool // the next Attempt would be the Count-th (the GPO check asks this)
func (l *Ledger) Trip(k LedgerKey)                          // red post-check: open the breaker now
func (l *Ledger) Open(k LedgerKey) bool
func (l *Ledger) Reset()                                    // operator reset (signed ResetEpoch)
type LedgerState struct{ Times map[string][]time.Time; Open []string }
func (l *Ledger) Export() LedgerState
func (l *Ledger) Import(LedgerState)
```

Bounds: at most 1024 entries (oldest evicted), at most 16 times per entry. The caller emits `plan.failed{reason: auto_halted, host, object, kind, count, window, trigger: repeat|red_check, lineage, reenable}` (core kind, critical) when `Attempt` returns `opened` or after `Trip`.

- [ ] **Step 1: Write the tests:**

```go
func TestProtectedSet(t *testing.T) {
	p := NewProtected([]string{"myagent.exe"})
	for _, e := range []string{`C:\Windows\System32\LSASS.EXE`, "/usr/lib/systemd/systemd", "/usr/sbin/sshd", `C:\x\myagent.exe`} { if !p.Exe(e) { t.Errorf("%s", e) } }
	if p.Exe("/usr/bin/nc") { t.Error("nc protected") }
}
func TestHostCapAcrossMinuteBoundary(t *testing.T) {
	clk := newClock()
	l := NewLimiter(3, clk.now)
	for i := 0; i < 3; i++ { if !l.Allow("h") { t.Fatal(i) } }
	if l.Allow("h") { t.Fatal("host cap") }
	clk.add(61 * time.Second)
	if !l.Allow("h") { t.Fatal("window did not slide") }
}
// internal/actions
func TestLedgerOpensOnCount(t *testing.T) { // review focus 4
	clk := newClock(); l := NewLedger(clk.now); k := LedgerKey{"h", "fw", "fw.apply"}; lim := LedgerLimit{3, 10 * time.Minute}
	if ok, o := l.Attempt(k, lim); !ok || o { t.Fatal() }
	clk.add(2 * time.Minute); l.Attempt(k, lim)
	clk.add(2 * time.Minute)
	if ok, o := l.Attempt(k, lim); !ok || !o || !l.Open(k) { t.Fatal(ok, o) }
	if ok, _ := l.Attempt(k, lim); ok { t.Fatal("fourth attempt allowed") }
}
func TestLedgerWindowExpires(t *testing.T) { /* three attempts spread over 11 minutes: breaker not opened */ }
func TestLedgerKeysAreIndependent(t *testing.T) { /* another object or another kind on the same host keeps its own count */ }
func TestLedgerTripClosesTheKindOnTheHost(t *testing.T) { /* Trip({h, "*", fw.apply}): Attempt on any object of that kind on h is refused, on h2 allowed */ }
func TestLedgerWouldOpen(t *testing.T) { /* true exactly when the next Attempt is the Count-th */ }
func TestLedgerResetAndExportImport(t *testing.T) { /* round trip keeps counts and the open set; Reset clears both */ }
func TestLedgerBounds(t *testing.T) { /* 2000 distinct keys: tracked <= 1024, no panic */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ ./internal/respond/ -run 'Protected|HostCap|Ledger' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/actions/ ./internal/respond/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: attempt ledger; respond: protected set, host cap"`

---

### Task 26: Probe verdicts, facts and the GPO check (the breaker is the attempt ledger, S1)

**Files:**
- Modify: `internal/respond/verdict.go`
- Test: `internal/respond/verdict_test.go`

**Interfaces:**
- Consumes: `plan.HostService`, `plan.HealthProbe`, `event.ControllerFact`, `event.Decode`.
- Produces:

```go
type Verdict struct {
	Known  bool
	Green  bool
	Detail string // "green", "red:<service>", "unknown:<why>"
}
type Prober struct {
	Services []plan.HostService
	Run      func(ctx context.Context, p plan.HealthProbe) error // runs the read-only probe action through actions.Env.Execute
	Fact     func(id string) (event.ControllerFact, bool)        // agent.Env.Fact: false when never received or expired
}
func (p *Prober) Local(ctx context.Context) Verdict   // no scored service: known green. A scored service with Health nil: unknown ("no health block"). Any probe error: red:<name>.
func (p *Prober) Scorer() Verdict                     // per scored service fact "scorer_probe:<name>": missing or expired -> unknown; Data["ok"]==false -> red; every one ok -> green. No scored service: known green.
func (p *Prober) Watch(ctx context.Context, window, poll time.Duration, needScorer bool) Verdict
// polls Local each `poll` (and Scorer when needScorer) for `window`; returns the first red, else unknown if any poll was unknown and needScorer, else green.
type GPOFacts struct{ /* by id, with receipt time and ttl */ }
func NewGPOFacts(now func() time.Time) *GPOFacts
func (g *GPOFacts) Add(f event.ControllerFact)  // only f.Fact == "gpo_finding"
// The breaker is actions.Ledger (Task 25): a red Watch verdict calls Ledger.Trip, a repeat opens it through Attempt.
func (g *GPOFacts) Covers(setting string) bool  // an unexpired fact whose data (keys matched case-insensitively) has enforced true and affects/section/item containing setting (case-insensitive)
```

Rules: the unknown verdict is never green (`Known` false means the caller must not act). `Watch` returns early on the first red. The fact id is `scorer_probe:<service>`; its `Data` is `{"service": string, "ok": bool}` (hand-off to W7, listed in the last task).

- [ ] **Step 1: Write the tests:**

```go
func TestUnknownVerdictNeverActs(t *testing.T) { // review focus 1
	noHealth := &Prober{Services: []plan.HostService{{Name: "web", Scored: true}}}
	if v := noHealth.Local(context.Background()); v.Known || v.Green { t.Fatalf("%+v", v) }
	noFact := &Prober{Services: []plan.HostService{{Name: "web", Scored: true, Health: &plan.HealthProbe{Action: "net.tcp_probe"}}},
		Run: func(context.Context, plan.HealthProbe) error { return nil }, Fact: func(string) (event.ControllerFact, bool) { return event.ControllerFact{}, false }}
	if v := noFact.Scorer(); v.Known || v.Green { t.Fatalf("%+v", v) } // expired and never-received look the same
	if v := noFact.Local(context.Background()); !v.Known || !v.Green { t.Fatalf("%+v", v) }
}
func TestScorerRedFactIsRed(t *testing.T) { /* fact Data {"service":"web","ok":false} -> Known, !Green, Detail "red:web" */ }
func TestLocalProbeErrorIsRed(t *testing.T) { /* Run returns an error -> red:web */ }
func TestWatchReturnsFirstRed(t *testing.T) { /* Run fails on the 3rd poll: Watch returns red before the window ends (poll 5 ms, window 1 s) */ }
func TestGPOStopsLoop(t *testing.T) {
	g := NewGPOFacts(clk.now)
	g.Add(event.ControllerFact{ID: "{A}", Fact: "gpo_finding", TTL: 30 * time.Minute, Data: map[string]any{"Affects": "Windows Firewall", "Enforced": true}})
	if !g.Covers("firewall") || g.Covers("defender") { t.Fatal() }
	clk.add(31 * time.Minute)
	if g.Covers("firewall") { t.Fatal("expired fact still covers") }
}
func TestGPOFactNotEnforcedDoesNotCover(t *testing.T) { /* Enforced false -> false */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/respond/ -run 'Unknown|ScorerRed|LocalProbe|Watch|BreakerTrip|GPO' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/respond/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "respond: probe verdicts that treat unknown as no, GPO fact check"`

---

### Task 27: `respond` tier-0 runner (agent module)

**Files:**
- Modify: `internal/respond/runner.go`, `internal/respond/manifest.go`, `internal/respond/config.go`, `internal/agent/mods/respond.go`, `internal/module/conformance/allowed.go` (`ModulePackages["respond"]`)
- Test: `internal/respond/runner_test.go`, `internal/respond/conformance_test.go`

**Interfaces:**
- Consumes: Tasks 24 to 26; `agent.Env` (`Subscribe`, `Keep`, `Kept`, `Fact`, `Actions`, `Health`, `Logger`); `actions.Env.Execute`, `Confirm`, `Rollback`, `Request{Action, Params, NodeID, Deadman}`, `actions.Ledger`, `actions.WithTag`, `actions.Tag`, `actions.ErrSafeMode`, `actions.ErrNotReversible`, `actions.ErrScoringUnsafe`; `HealthSource.ModuleHealth` (Task 11); `module.Actor`.
- Produces:

```go
func Manifest() module.Manifest // Name "respond", Sides [agent, controller], OS both, Privilege "root", Default true,
	// Consumes [detect.alert, controller.fact, respond.action, plan.failed], Emits [respond.action],
	// Budget{2, 4, 2, 20, 50 << 10, 1}, Content ["rules/respond","plans/respond"], Pages ["responses","recipes"]
type Config struct { // modules/respond.yml: the design YAML
	module.Common      `yaml:",inline"`
	module.Actor       `yaml:",inline"` // act_enabled and autonomy (recipe rule id -> propose | shadow | auto); this module acts, so it carries both
	Tier0              struct {
		MaxPerHostPerMin int                  `yaml:"max_per_host_per_min"`
		BreakerWindow    time.Duration        `yaml:"breaker_window"`
		Loop             struct{ Count int `yaml:"count"`; Window time.Duration `yaml:"window"` } `yaml:"loop"` // the ledger's limit for respond's recipes
		Block            struct{ ExpiresAfter time.Duration `yaml:"expires_after"`; MaxActive int `yaml:"max_active"` } `yaml:"block"`
		Recipes          []string             `yaml:"recipes"` // recipes enabled on this host: the per-rule act switch (S1)
	} `yaml:"tier0"`
	ProtectedProcesses []string `yaml:"protected_processes"`
	ManifestDir        string   `yaml:"manifest_dir"` // controller side: where AppendOverrides writes (Task 33's reset)
}
func (c Config) Settings() plan.Tier0Settings // seconds, defaults 3, 120, 3, 600, 14400, 20
type Module struct{ /* recipes, guards, ledger, prober, gpo facts, counters */ }
func NewModule(env agent.Env, s *plan.RespondSettings) (*Module, error) // parses s.Recipes; Actions() nil -> error wrapping agent.ErrUnavailable
func (m *Module) Name() string
func (m *Module) Start(ctx context.Context, emit agent.Emit) error
func (m *Module) Health() module.Health
```

Behaviour of `Start` (all outcomes are `respond.action` events built with `event.New`, `Tag` `respond:<alert id>`; the action runs with `actions.WithTag(ctx, actions.Tag{Node: "respond:"+alertID})`):

1. Subscribe `detect.alert` and `controller.fact` (buffer 256). A fact of type `gpo_finding` goes to `GPOFacts.Add`. A `detect.alert` is read with `ViewOf`; the matching recipes are `RecipeSet.For(rule)` restricted to `Tier0.Recipes` (the recipe tied to the rule id and enabled for this host is the only act switch; the alert's `tier` is display only, there is no `mode`). Nothing runs unless `ActEnabled`. The template's `Autonomy[rule]` (absent means `propose`) then decides: `propose` runs nothing (the controller side offers the click); `shadow` goes through steps 2 to 4 and the before-state probe, records `respond.action{outcome: shadow}` with the would-be action and `Before`, and applies nothing (no ledger attempt); `auto` continues to step 5. Recipes run one at a time in name order, alerts through a bounded queue (64; a full queue drops with `Dropped++`).
2. A recipe with `RequiresSensors` whose local module is not `ok` in `env.Health.ModuleHealth()` is suspended: one `skipped_guard` event with `Before` = `suspended: sensor <name> not ok`. `UnscoredHostsOnly` with any scored `HostService` is `skipped_guard`.
3. `Resolve` errors (missing entity, hostile value) are `skipped_guard` with the error in `Before`; the action is never called.
4. For each step, in this order, a failing check ends the step with the named outcome: safe mode (`ae.Safe.On()`) `skipped_safe_mode`; the ledger's breaker open for the step's key `{host, object, kind}` or for `{host, "*", kind}` `skipped_breaker`; `Limiter.Allow(host)` `skipped_rate`; the GPO check (`recipe.GPOSetting != ""`, Windows, and `Ledger.WouldOpen` is true: `GPOFacts.Covers(setting)`) `skipped_gpo`; unknown local verdict (`Prober.Local` not Known) or, for `Probe` steps, unknown scorer verdict `skipped_guard` with `Health` `unknown:<why>`; red before-state `skipped_guard`. (The object is the step's path, account, unit or rule id; the kind is the action name.)
5. Execute: `Ledger.Attempt(key, LedgerLimit{Loop.Count, Loop.Window})` first (refused is `skipped_breaker`; `opened` means this is the last allowed attempt, so after the apply the runner emits `plan.failed{reason: auto_halted, trigger: repeat, lineage}` with `Lineage` from the alert's `parent.exe`/`exe` entities), then `ae.Execute(ctx, actions.Request{Action, Params, NodeID, Deadman: BreakerWindow + 30s})` with a 30 s lock wait (`context.WithTimeout`; a timeout is `skipped_lock`); `ErrScoringUnsafe` and `ErrNotReversible` are `skipped_guard`; other errors `failed`.
6. After a successful execute: `Prober.Watch(window, 10 s, step.Probe)`. Green: `ae.Confirm(deadmanID)` and `applied` with `Health: green`. Red or unknown (for a `Probe` step): `ae.Rollback(deadmanID)`, `rolled_back`, `Ledger.Trip({host, "*", kind})` and `plan.failed{reason: auto_halted, trigger: red_check, reenable: "raise the reset epoch (Responses page, Reset)"}`.
7. State (the ledger) is saved with `env.Keep`; when `s.ResetEpoch` is greater than the kept epoch, `Ledger.Reset()` clears all of it.
8. `Health()`: `ok`; `disabled` detail `tier 0 off` when `ActEnabled` is false or no recipe is enabled; `degraded` when a breaker is open, a recipe step names an action missing on this OS (gap per action) or a required sensor has a gap. `Info`: `recipes`, `breakers_open`, `actions_last_hour`.
`shortcut: the 30 s dead-man grace and the 10 s poll are fixed; make them settings only if a lab run needs it`.

- [ ] **Step 1: Remove the skips:**

```go
func TestAppliedWhenProbesGreen(t *testing.T) {
	f := newRunnerFixture(t, withRecipe(fwRestoreRecipe), withEnabled("firewall_restore"), withAutonomy("D10k.fw-exec-tamper", "auto"), withActEnabled(), withGreenProbes())
	f.alert("D10k.fw-exec-tamper", 0, nil)
	got := f.waitAction(t, "applied")
	if got.Action != "fw.apply" || got.Recipe != "firewall_restore" || got.Health != "green" || f.fake.calls("fw.apply") != 1 || f.confirmed() != 1 { t.Fatalf("%+v", got) }
}
func TestShadowRecordsWithoutApplying(t *testing.T) { /* autonomy shadow: respond.action outcome shadow with Before set, fake.calls == 0, the ledger count unchanged */ }
func TestProposeAutonomyRunsNothing(t *testing.T) { /* autonomy absent or propose: no respond.action, fake.calls == 0 (the controller offers the click) */ }
func TestRedProbeRollsBackAndOpensBreaker(t *testing.T) {
	f := newRunnerFixture(t, withRecipe(fwRestoreRecipe), withEnabled("firewall_restore"), withAutonomy("D10k.fw-exec-tamper", "auto"), withActEnabled(), withProbe(failAfterApply()))
	f.alert("D10k.fw-exec-tamper", 0, nil)
	got := f.waitAction(t, "rolled_back")
	pf := f.waitKind(t, "plan.failed")
	if f.fake.rolledBack() != 1 || pf.Fields["reason"] != "auto_halted" || pf.Fields["trigger"] != "red_check" || pf.Fields["kind"] != "fw.apply" { t.Fatalf("%+v", got) }
	f.alert("D10k.fw-exec-tamper", 0, nil)
	f.clock.add(2 * time.Minute)
	if f.waitAction(t, "skipped_breaker").Action != "fw.apply" { t.Fatal() }
}
func TestUnknownVerdictSkips(t *testing.T) { /* scored service without a health block: skipped_guard, Health "unknown:...", fake.calls == 0 (T74 respond half; also a Probe step with no scorer fact) */ }
func TestParamMustBeAnEntity(t *testing.T) { /* recipe params_from path; alert without that entity: skipped_guard, fake.calls == 0 */ }
func TestHostileEntityRefused(t *testing.T) { /* path "/etc/x\n/y": skipped_guard, no call */ }
func TestActDisabledDoesNothing(t *testing.T) { /* ActEnabled false: no events, no calls; Health disabled */ }
func TestRecipeNotInSignedConfigRefuses(t *testing.T) { /* alert for a rule whose recipe is not in s.Recipes: no calls */ }
func TestRecipeNotEnabledForHostRefuses(t *testing.T) { /* recipe present in s.Recipes but not in Tier0.Recipes: no calls */ }
func TestSafeModeSkips(t *testing.T) { /* ae.Safe.Set(true): skipped_safe_mode; rollback of an earlier armed entry still permitted */ }
func TestHostCapRateLimited(t *testing.T) { /* four alerts for four objects in a minute: three applied, the fourth skipped_rate */ }
func TestLedgerOpensOnThird(t *testing.T) { /* same object restored three times in ten minutes: plan.failed trigger repeat emitted once with lineage, the fourth alert is skipped_breaker */ }
func TestGPOStopsLoop(t *testing.T) { /* gpo_finding fact for firewall present, third restore: skipped_gpo, no plan.failed */ }
func TestLockWaitSkips(t *testing.T) { /* hold the action's lock; the step ends skipped_lock after the wait (test shortens the wait) */ }
func TestNotReversibleSkips(t *testing.T) { /* fake action with Rollback{} and Deadman > 0: skipped_guard */ }
func TestRequiresSensorsSuspends(t *testing.T) { /* ModuleHealth()["audit"] degraded: skipped_guard "suspended" */ }
func TestResetEpochClearsLedger(t *testing.T) { /* trip, reconfigure with ResetEpoch+1: the next alert applies */ }
func TestRespondConformance(t *testing.T) {
	conformance.Agent(t, conformance.AgentCase{Factory: factoryNamed(t, "respond"), Default: respondCfg(t, 0), Reconfig: respondCfg(t, 1), KeepKey: "respond.state", Load: alertEvents()})
}
```

`newRunnerFixture` builds a real `actions.Env` (`actions.NewEnv("h1", t.TempDir())` with `Registry: actions.NewRegistry()` holding only `fakeAction` instances and real `net.tcp_probe`), a deadman manager in `t.TempDir()`, an `agent.Harness` with the respond factory, and a controllable clock; `fakeAction` is an `actions.Action` that records calls, writes a file on `Apply` and restores it from `Capture` data on rollback.

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/respond/ -run 'Applied|Shadow|ProposeAutonomy|RedProbe|UnknownVerdict|ParamMust|HostileEntity|ActDisabled|SignedConfig|NotEnabled|SafeMode|HostCap|LedgerOpens|GPOStops|LockWait|NotReversible|RequiresSensors|ResetEpoch|Conformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified (one goroutine per recipe run, at most 4 at once).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/respond/ ./internal/agent/... ./internal/module/...`. Expected: PASS, `respond` passing the agent conformance checks (link loss: tier 0 keeps running).
- [ ] **Step 5: Commit.** `git commit -am "respond: tier-0 runner over the attempt ledger, with autonomy, guards and dead-man rollback"`

---

### Task 28: Local tier-0 recipes and their plan templates

**Files:**
- Create: `rules/respond/{firewall_restore,defender_restore,sysmon_reinstall,persistence_disable,killlist,service_restart,webshell_quarantine}.yml`, `plans/respond/{restore_firewall,restore_defender,reinstall_sysmon,disable_task,disable_runkey,disable_unit,restart_service,quarantine_file}.yml`
- Modify: `rules/detect/{linux_exec,windows,linux_persistence}.yml` (add any `entities:` key a recipe reads; rules carry no mode, S1)
- Test: `internal/respond/content_test.go`

**Interfaces:**
- Consumes: Task 24's `RecipeSet`, `Validator`; `controller.LoadModuleTemplate`-compatible template format (`id`, `module: respond`, `on_failure`, nodes with `${host}` and one `${name}` per parameter).
- Produces (each recipe has `module: respond`, a `collect:` list, a `propose:` entry that is the click form of its tier-0 step, and tests with `want_tier0`, `want_propose`):

| Recipe | Triggers | Tier-0 steps | gpo_setting / flags |
| --- | --- | --- | --- |
| `firewall_restore` | `D10k.*`, `D10k2.*` (`D10k3.*` joins in Task 19's unparking) | `fw.apply{op: policy}` (restore the declared policy) | `firewall` |
| `defender_restore` | `D10c.*` | `win.defender{ensure_realtime: true, keep: ["${agent_dir}"]}` | `defender` |
| `sysmon_reinstall` | `D10e.*` | `sysmon.install{installer: "${sysmon_installer}", sha256: "${sysmon_sha256}", config: "${sysmon_config}"}` | `requires_sensors: [winevt]` is not set (the sensor is what is broken) |
| `persistence_disable` | `D6q.*`, `D6r.*`, `D6t.*`, `D6t2.*`, `D6u.*`, `D6u2.*`, `D6u3.*` | optional `task.disable{path: entities.task}`, optional `runkey.remove{key: entities.key, value: entities.value}`, optional `wmi.subscription_remove{name: entities.subscription}` | `os: windows` on each |
| `killlist` | `D3c.*`, `D3c2.*` | optional `service.state{unit: entities.unit, state: disabled}`, `task.disable`, `runkey.remove` (as above) | `unscored_hosts_only: true`; never kills a process |
| `service_restart` | `D17c.*` | `service.state{unit: entities.unit, state: running}` with `probe: true, rollback: true` | |
| `webshell_quarantine` | `D2a.*` | `yara.scan{path: entities.path}` with `gate: matches`, then `file.quarantine{path: entities.path}` with `probe: true, rollback: true` | until YARA is wired the gate step is pending and the recipe stays unallowed (`shortcut` comment) |

Plan templates (`plans/respond/<name>.yml`, `module: respond`, one node `target: ${host}`, parameters exactly the `${}` set the proposals use): `restore_firewall` (`fw.apply{op: policy}`), `restore_defender` (`win.defender`; `${agent_dir}`), `reinstall_sysmon` (`sysmon.install`; three params), `disable_task`, `disable_runkey`, `disable_unit` (`service.state`), `restart_service` (`service.state`), `quarantine_file` (`file.quarantine`; `${path}`). Rule edits: the trigger rules above must list the entity keys the recipes read in `entities:` (for example `D6q` lists `task`; `D3c` lists `unit`). Which recipes run is the per-host `recipes` list and the template's `autonomy`, never a rule property (the `webshell_quarantine` recipe stays out of every host's list until the YARA gate exists).

- [ ] **Step 1: Write the tests:**

```go
func TestEmbeddedRecipesValidate(t *testing.T) {
	rs, err := LoadFS(respondrecipes.FS)
	if err != nil { t.Fatal(err) }
	v := Validator{Actions: actions.Core(), RuleIDs: ruleIDsFromTree(t), Templates: os.DirFS("../../plans/respond"), Modules: map[string]bool{"audit": true, "net": true, "winevt": true}}
	for _, e := range rs.Validate(v) { t.Error(e) }
	for _, r := range rs.RunTests() { if r.Err != nil { t.Errorf("%s/%s: %v", r.Recipe, r.Test, r.Err) } }
}
func TestTier0TriggerRulesAreTier0(t *testing.T) { /* for the seven recipes: every rule matched by a tier0 recipe trigger has Tier 0 in the rule file (this is the e2e cross-check of Task 39 run here for the recipes of this task) */ }
func TestRecipeEntitiesAreCarriedByRules(t *testing.T) { /* each params_from entity key appears in the entities: list of every rule the recipe triggers on */ }
func TestFirewallRestoreRecipeResolves(t *testing.T) { /* alert D10k.fw-exec-tamper tier 0 -> Resolve gives [fw.apply]; propose [restore_firewall] */ }
func TestKilllistNeverKills(t *testing.T) { /* no step of killlist is proc.* */ }
```

Rule ids the triggers need come from `LoadTree`; `ruleIDsFromTree` includes `rules/pending`. Where a recipe action is in `PendingActions` the test passes through that path.

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/respond/ -run 'Embedded|Tier0TriggerRules|RecipeEntities|FirewallRestoreRecipe|KilllistNever' -v`. Expected: FAIL.
- [ ] **Step 3: Write the YAML** from the table and the rule edits; `bin/phylax rules test` must stay green.
- [ ] **Step 4: Run, expect PASS.** Run: `go test ./internal/respond/ ./internal/detect/ && bin/phylax rules registry`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "respond: local tier-0 recipes, plan templates and the trigger rule entities"`

---

### Task 29: A-AUTO recipes: `source_block`, `session_evict`, `account_lock`, `palo_block`, `recycle_restore`, `gpo_unlink`

**Files:**
- Create: `rules/respond/{source_block,session_evict,account_lock,palo_block,recycle_restore,gpo_unlink}.yml`, `plans/respond/{unblock_source,evict_sessions,lock_account,palo_block,recycle_restore,gpo_unlink}.yml`
- Modify: `internal/respond/runner.go` (the `block` step guards), `rules/detect/deception.yml` and `rules/detect/windows.yml` (entities; no rule mode, S1), `rules/pending/needs_producer.yml` (`D8r.red-gpo` on `ad.gpo_finding`, `needs: kind:ad.gpo_finding`)
- Test: `internal/respond/block_test.go`, `internal/respond/content_aauto_test.go`

**Interfaces:**
- Produces recipes:

| Recipe | Triggers | Steps |
| --- | --- | --- |
| `source_block` | `D15b.*`, `D15c.*`, `D15d.*`, `D15e.*` (the `deception` module's rules; their `entities:` already carry `source`) | `fw.apply{op: block, ports: non_scored, reason: "confirmed red", owner: respond}` with `params_from {sources: entities.source}`, `block: true`, `rollback: true`; `propose` for a CIDR or scored-port block uses template `block_source` (Task 32) |
| `session_evict` | same four | `session.terminate_predating{source: ..., before: "${now}"}` with `params_from {source: entities.source}`, `os` unset |
| `account_lock` | `D15d.*`, `D15e.*` | optional `user.lock{user: entities.account}` (`os: linux`), optional `ad.account.disable{account: entities.account}` (`os: windows`); the scoring guard refuses scored accounts |
| `palo_block` | `D15b.*`, `D15c.*`, `D15d.*` | no tier-0 steps; `auto: [palo_block]` (controller `RunAuto`, template node `palo.apply`; read the action's `Spec` for its parameters) |
| `recycle_restore` | `D7h.*` (add `target_sid` and `target_dn` to its `entities:`) | no tier-0 steps; `auto: [recycle_restore]` (template node `ad.recycle_restore{sid: ${sid}}` on the alert's agent, the DC) |
| `gpo_unlink` | `D8r.*` | `auto: [gpo_unlink]` (template node `ad.gpo_unlink{guid: ${guid}, link: ${link}}`) |

`block: true` guards (runner, before `Execute`): the `sources` value parses as one address (`netip.ParseAddr`; a CIDR or list is `skipped_guard`); it is not in `RespondSettings.NeverBlock` (addresses and CIDRs); fewer than `BlockMaxActive` blocks are active (`skipped_guard`, "max active"); the post-check is the normal probe; on `applied` the block is recorded in `StateDir/respond/blocks.json` (atomic) with its expiry (`BlockExpiresSec`) and the undo data the `fw.apply{op: block}` action returned; a timer runs that undo at expiry (also on agent start for records already due; there is no separate unblock op, S4); a red probe rolls the block back (the dead-man) and trips the ledger's breaker for the kind. A decoy touch (`D15a`) never triggers (`D15a` severity low, no recipe).

- [ ] **Step 1: Write the tests:**

```go
func TestSourceBlockRefusesOwnAddress(t *testing.T) { /* NeverBlock ["172.20.240.0/24"], source 172.20.240.10 -> skipped_guard, fake.calls == 0 */ }
func TestSourceBlockRefusesCIDRAndList(t *testing.T) { /* sources "198.51.100.0/24" and "a,b" -> skipped_guard */ }
func TestSourceBlockScoredPortsNeverTargeted(t *testing.T) { /* the call's params always carry ports: non_scored (assert on fake.lastParams) */ }
func TestSourceBlockExpires(t *testing.T) { /* applied at t0 with BlockExpiresSec 3600; advance the clock: the block's undo runs once, blocks.json empty; agent restart with a due record undoes it at start */ }
func TestSourceBlockStopsAtMaxActive(t *testing.T) { /* BlockMaxActive 2: the third distinct source is skipped_guard */ }
func TestSourceBlockRedProbeRemovesBlock(t *testing.T) { /* failing probe -> rolled_back, block record removed, ledger breaker open for the kind */ }
func TestAutoRecipesResolve(t *testing.T) { /* D7h alert -> Auto ["recycle_restore"], Tier0 empty; D15b alert -> Tier0 [fw.apply, session.terminate_predating, ...] and Auto ["palo_block"] */ }
func TestAAutoRecipesValidate(t *testing.T) { /* the Task 28 validator on the full embedded set, templates exist, no click-only action under tier0 or auto, propose present */ }
func TestD15aNeverActs(t *testing.T) { /* D15a matches no recipe trigger */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/respond/ -run 'SourceBlock|AutoRecipes|AAutoRecipes|D15aNever' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the block guards and write the YAML. `${now}` handling is already in `Resolve` (Task 24).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/respond/ ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "respond: A-AUTO recipes (source_block, session_evict, account_lock, palo_block, recycle_restore, gpo_unlink)"`

---

### Task 30: `respond` controller side: proposals, `RunAuto`, skipped tier-0 becomes a click

**Files:**
- Modify: `internal/respond/controller.go`, `internal/respond/testutil_test.go` (`fakeHost` records `Propose`, `RunAuto`)
- Test: `internal/respond/controller_test.go`, `internal/respond/controller_conformance_test.go`

**Interfaces:**
- Consumes: `module.Host` (`Subscribe`, `Propose`, `RunAuto`, `Emit`, `Config`, `Logger`), `module.Proposal`, `module.EventRef`, `module.ErrProposed`, `module.Register`.
- Produces:

```go
type Controller struct{ /* recipes, dedupe LRU, health */ }
func (*Controller) Manifest() module.Manifest // Manifest()
func (c *Controller) Start(ctx context.Context, h module.Host) error
func (c *Controller) Health() module.Health
func (*Controller) ConfigBlock() any // &Config{}
func init() { module.Register(&Controller{}) }
```

Rules: `Start` loads `Content()` (embedded recipes) and subscribes to `detect.alert`, `respond.action`, `plan.failed` (committed events, all agents; `plan.failed{reason: auto_halted}` only feeds the Responses page and tile, because the refused attempt's `respond.action` already made the click). The controller reads the recipe-enable records (`Overrides.Recipes`) and the `autonomy` settings through `Host.Config()`; `shortcut: fleet-wide values, not the per-host effective ones, upgrade when Host exposes the rendered per-host respond settings`. For each `detect.alert` seen once (dedupe by `agent|id`, LRU 4096):
- every matching recipe's `propose` entries become `Host.Propose(Proposal{Title, Template, Params, Evidence: []EventRef{{Agent, Seq}}, Reason})` with params `host` = the alert's agent plus the entries' `params` and resolved `params_from`, and `Reason` `tier 1` (or the alert's tier), at once when the recipe is not enabled for the host or its template is at `propose` or `shadow`; when the recipe is enabled at `autonomy: auto` and has `tier0:` steps no proposal is made yet (the agent acts), while each `auto:` template is started with `Host.RunAuto(template, params)` only at `autonomy: auto` (at `propose` the engine's auto conditions turn it into a click proposal on their own); `module.ErrProposed` is not an error (the Host already created the click proposal).
- a `respond.action` whose outcome is `skipped_rate`, `skipped_breaker`, `skipped_guard` or `skipped_lock`, or `failed`, creates the recipe's `propose` entries with `Reason` = the outcome and, for `skipped_guard` with unknown health, `unknown verdict`. `skipped_safe_mode` and `skipped_gpo` make none (safe mode is a deliberate stop; the GPO finding is raised by `ad`).
- a proposal for a `proc.*` template is not created when `Protected.Exe(entities.exe)` is true or the exe is a scored service binary (`Config.ProtectedProcesses`, plus the rendered scored binaries the agent config carries are not visible here: `shortcut: the controller checks the built-in set and Config.ProtectedProcesses only; the agent action refuses scored trees anyway`).
A recipe that fails `Resolve` for an alert is logged and skipped, never fatal.

- [ ] **Step 1: Remove the skips:**

```go
func TestAlertBecomesProposals(t *testing.T) { // T03 shape
	h := newFakeHost(t, "enabled: true\n")
	go (&Controller{}).Start(h.ctx, h)
	h.publish(alertEvent("web1", 42, "D1.service-spawns-shell", 1, map[string]string{"pid": "812", "path": "/var/www/html/x.php", "source": "198.51.100.7"}))
	ps := h.waitProposals(t, 3)
	titles := proposalTemplates(ps)
	if !contains(titles, "kill_tree") || !contains(titles, "quarantine_file") || !contains(titles, "block_source") { t.Fatal(titles) }
	if ps[0].Params["host"] != "web1" || ps[0].Evidence[0] != (module.EventRef{Agent: "web1", Seq: 42}) { t.Fatalf("%+v", ps[0]) }
}
func TestAutoAutonomyStartsAutoPlans(t *testing.T) { /* D7h with recycle_restore enabled at autonomy auto -> RunAuto("recycle_restore", {host: dc1, sid: ...}) once; RunAuto returning ErrProposed is not logged as an error */ }
func TestSkippedTier0BecomesProposal(t *testing.T) { // review focus 1, controller half
	/* alert D10k with firewall_restore enabled at auto (no proposals), then respond.action outcome skipped_guard with health unknown:no health block -> Propose restore_firewall with Reason "unknown verdict"; a skipped_breaker outcome (the ledger refused) makes the same click */
}
func TestProposeAutonomyProposesAtOnce(t *testing.T) { /* recipe enabled at propose or shadow, or not enabled: the click proposals are made when the alert arrives */ }
func TestSafeModeAndGPOMakeNoProposal(t *testing.T) { /* skipped_safe_mode and skipped_gpo: zero proposals */ }
func TestDedupeByAlertID(t *testing.T) { /* the same alert delivered twice: one set of proposals */ }
func TestProtectedProcessGetsNoKillProposal(t *testing.T) { /* entities.exe C:\Windows\System32\lsass.exe -> no kill_tree proposal; other proposals still made */ }
func TestControllerConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Controller{}, Config: "enabled: true\n", Now: time.Unix(1e9, 0)})
}
```

(`web-compromise` and `block_source` are written in Task 32; this test is un-skipped there if run before it, so order the two commits with Task 32's recipe file first in a stacked pull request, or keep `TestAlertBecomesProposals` skipped here with `t.Skip("needs W4 Task 32")` and remove that line in Task 32.)

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/respond/ -run 'AlertBecomes|AutoAutonomy|SkippedTier0|ProposeAutonomy|SafeModeAndGPO|Dedupe|ProtectedProcess|ControllerConformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/respond/ ./internal/controller/ ./internal/module/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "respond: controller side (proposals, RunAuto, skipped tier-0 becomes a click)"`

---

### Task 31: (removed by S1, 2026-11-06)

Auto-demotion of promoted rules and `respond.breaker` are replaced by the engine's attempt ledger (Task 25: one breaker per host, object and kind, which opens `plan.failed{reason: auto_halted}` and turns the next attempt into a click proposal) and by the operator reset (`Controller.Reset` and the `RespondResetEpoch` fold, built in Task 33). Demoting a recipe is removing its `Overrides.Recipes` entry or setting its template to `propose` (Task 15 `promote --remove`); nothing writes a demotion back.

---

### Task 32: Tier-1 and tier-2 recipes and templates

**Files:**
- Create: `rules/respond/{web_compromise,binary_modified,account_changes,zerologon,decoy_followup,c2_followup,credential_theft,scan_followup}.yml`, `plans/respond/{kill_tree,suspend_proc,block_source,isolate_host,restore_file,hunt_persistence,disable_account,secure_channel,close_port}.yml`
- Modify: `internal/respond/controller_test.go` (remove the `t.Skip` of `TestAlertBecomesProposals`)
- Test: `internal/respond/content_tier1_test.go`

**Interfaces:**
- Produces: recipes with no `tier0:` steps (so they need no `propose` duplication) unless stated; every `propose` entry names a template above or one from Tasks 28/29; `collect:` lists the design's collectors. Triggers are rule families expanded to the full ids present in the tree (a trigger that matches no rule fails Task 39).

| Recipe | Triggers (families) | Propose / auto |
| --- | --- | --- |
| `web_compromise` | `D1.*`, `D1e.*`, `D1f.*`, `D17b.*`, `D17d.*` | `kill_tree{pid}`, `quarantine_file{path}`, `block_source{source}` (host block; the title says CIDR warns), `hunt_persistence{user: web}`; `requires_sensors: [audit, net]`; collect `trace_back, process_tree, content_changes, transactions_window_10m, freeze_ring` |
| `binary_modified` | `D5d.*` | `restore_file{path, source: depot, service}`, `quarantine_file{path}`, `hunt_persistence`; alert only (D-1) |
| `account_changes` | `D7a.*`, `D7b.*`, `D7c.*`, `D7d.*`, `D7e.*`, `D7g.*` | `disable_account{account}` (unscored accounts only; the guard refuses scored ones) |
| `zerologon` | `D8b.*` | `auto: [secure_channel]` (nodes `ad.zerologon_check` then `ad.secure_channel{enforce: true}`, `deadman_sec: 120`); the patch reboot gate and krbtgt are not templates (tier 2 checklist text in the proposal `note`) |
| `decoy_followup` | `D15a.*` | `hunt_persistence`; no automatic action |
| `c2_followup` | `D12.*`, `D12b.*`, `D13b.*`, `D13b2.*`, `D13d.*`, `D13e.*`, `D13f.*` | `kill_tree{pid}`, `quarantine_file{path}`, `hunt_persistence`; the sinkhole capture is not collected |
| `credential_theft` | `D8c.*`, `D8e.*`, `D8g.*` | `disable_account{account}`; krbtgt double reset is a tier-2 note |
| `scan_followup` | `V2.*`, `V3.*` | `close_port{port}` |

Templates: `kill_tree` (`proc.kill_tree`, params `pid`, `start_ticks`), `suspend_proc`, `block_source` (`fw.apply{op: block, sources: ${source}, reason, owner}` with no `ports` so a scored-port block of a known red address is allowed by the lint, the CIDR warning comes from `fw.apply`), `isolate_host` (`fw.apply{op: quarantine}`, auto-revert), `restore_file` (`file.restore{source: ${source}}` with `source` golden, depot or backup; the depot form is the binary restore, S4), `hunt_persistence` (`hunt.persistence`), `disable_account` (`user.lock`/`ad.account.disable` by `os`), `secure_channel`, `close_port` (`fw.apply` with the device `palo.apply` variant left to `devices`). `proc.kill_tree` appears only under `propose:`.

- [ ] **Step 1: Write the tests:**

```go
func TestTier1RecipesValidate(t *testing.T) { /* the embedded set (all tasks so far) passes Validate and RunTests; every template referenced exists and its ${} set equals host plus the proposal's params */ }
func TestWebCompromiseProposesTheFour(t *testing.T) { /* Resolve of a D1.service-spawns-shell tier 1 alert with pid, path, source: propose [kill_tree quarantine_file block_source hunt_persistence], Tier0 empty */ }
func TestKillTreeOnlyUnderPropose(t *testing.T) { /* no recipe lists proc.* under tier0 or auto; no auto template contains proc.kill_tree (parse the template nodes) */ }
func TestNoRecipeHasIRTemplate(t *testing.T) { /* strict parse already rejects; assert grep of rules/respond finds none */ }
func TestAllTemplatesAreReferenced(t *testing.T) { /* every plans/respond/*.yml is named by some propose or auto entry (no dead templates) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/respond/ -run 'Tier1Recipes|WebCompromise|KillTreeOnly|NoRecipeHasIR|AllTemplates|AlertBecomes' -v`. Expected: FAIL.
- [ ] **Step 3: Write the YAML** from the table.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/respond/ && bin/phylax rules registry`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "respond: tier-1 and tier-2 recipes and plan templates"`

---

### Task 33: `detect` and `respond` UI: Rules page, Responses page, recipe viewer, tiles

**Files:**
- Create: `internal/detect/ui.go`, `internal/respond/ui.go`, `internal/detect/ui_test.go`, `internal/respond/ui_test.go`, `internal/controller/overrides_fingerprint_test.go`
- Modify: `internal/detect/controller.go`, `internal/respond/controller.go` (register through `h.UI()`; `Reset`)

**Interfaces:**
- Consumes: `ui.Registrar` (`Page`, `Tile`, `Action`), `html/template` (autoescape), `Engine.Exceptions`, `RuleSet.Rules`, `store.Reader`, `manifest.AppendOverrides`, `Config.ManifestDir`.
- Produces: `detect` registers page `rules` ("Rules": file, id, whether a `respond` recipe is enabled for it and at which `autonomy`, tier, inline test count, exceptions with reason, owner, added, expiry and expired highlighted) and tile `alerts` (alert counts by severity in the last hour, rules with an enabled recipe); `respond` registers page `responses` (`respond.action` events newest first, 200 rows, with outcome, host, action, recipe, health), page `recipes` (loaded recipes with triggers, steps, flags), tile `tier0` (state: off when no host has `act_enabled`, propose, shadow or auto by the highest `autonomy` enabled; automatic actions in the last hour; ledger breakers open from `plan.failed{auto_halted}`) and action `reset` (POST, calls `Controller.Reset`; CSRF and auth are the shell's). Every event-derived string passes through `html/template`.

- [ ] **Step 1: Write the tests:**

```go
func TestRulesPageListsRecipesAndExpiredExceptions(t *testing.T) { /* fake registrar; GET the page: contains the rule id, the recipe's autonomy for an enabled rule, the exception reason, and an "expired" marker for an expired one */ }
func TestResponsesPageEscapesHostileStrings(t *testing.T) { /* a respond.action whose target is `<script>alert(1)</script>`: the body contains &lt;script&gt; and no raw <script> */ }
func TestTier0TileStates(t *testing.T) { /* no act_enabled host: "off"; act_enabled with no recipes or all at propose: "propose"; a shadow recipe: "shadow"; an auto recipe: "auto"; with plan.failed stops: count shown */ }
func TestResetActionPostOnly(t *testing.T) { /* GET -> 405; POST -> Reset called once */ }
func TestResetBumpsEpoch(t *testing.T) { /* Reset twice: Overrides.RespondResetEpoch == 2 (the one ledger reset epoch, also for content_restore); without Config.ManifestDir: error and a Health gap "reset off: manifest_dir not set" */ }
func TestOverridesChangeChangesFingerprint(t *testing.T) { /* internal/controller: inputsFingerprint differs before and after AppendOverrides on the manifest dir */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ ./internal/respond/ -run 'RulesPage|ResponsesPage|Tier0Tile|ResetAction|ResetBumps|OverridesChange' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified (plain tables, no new JavaScript). `func (c *Controller) Reset(ctx context.Context) error` calls `manifest.AppendOverrides` to raise `RespondResetEpoch` (needs `Config.ManifestDir`); the epoch is fleet-wide (`shortcut: one epoch for all hosts and action types, upgrade to a per-host map if a lab run needs it`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/ ./internal/respond/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "detect, respond: Rules and Responses pages, recipe viewer, tiles, ledger reset"`

---

### Task 34: `content_guard`: golden store, path safety, `guard.snapshot`

**Files:**
- Modify: `internal/content_guard/golden.go`, `internal/content_guard/boot.go`, `internal/content_guard/config.go`, `internal/manifest/types.go` (`Content.Guard` is added by Task 1; wire validation here), `internal/manifest/validate.go` (a `guard` path must lie under one of the service's `roots` and satisfy `CleanGuardPath`)
- Create: `internal/content_guard/actions.go`
- Test: `internal/content_guard/golden_test.go`, `internal/content_guard/actions_test.go`, `internal/manifest/guard_test.go`

**Interfaces:**
- Consumes: `internal/atomicfile`, `actions.Register(func() []actions.Action)` (W1 Task 2a), `actions.TagFrom`, `plan.ContentGuardSettings`.
- Produces (package `contentguard`):

```go
type GoldenEntry struct {
	Service, Path, SHA256, PlanTag string
	Mode                           uint32
	UID, GID                       int
	XAttrs                         map[string]string // incl. security.selinux
	Taken                          time.Time
	Stale                          bool
	Never                          bool // boot-critical account databases: file.restore refuses them (a click proposal only)
	Boot                           bool // boot-critical entry: file.restore refuses it on a host with no scored-service probe
}
type Golden struct{ /* dir, index behind a mutex */ }
func OpenGolden(dir string, maxBytes int64) (*Golden, error) // dir StateDir/content_guard/golden; index.json written atomically
func (g *Golden) Put(e GoldenEntry, src io.Reader) error     // content addressed golden/<sha256>; error when Bytes()+size > maxBytes
func (g *Golden) Entry(service, path string) (GoldenEntry, bool)
func (g *Golden) Open(sha string) (io.ReadCloser, error)
func (g *Golden) MarkStale(service, path string) error
func (g *Golden) Bytes() int64
func CleanGuardPath(p string) error // absolute, equals filepath.Clean(p), no NUL, none of * ? [ ], not a directory form (no trailing separator)
func RegularNoFollow(p string) (os.FileInfo, error) // Lstat; a symlink, directory or device is an error
// guard.snapshot{service string, paths []string (default: the service's list), boot bool}   (content: plans/content_guard/guard.snapshot.yaml)
//   Spec Risk RiskService, Locks ["content:<service>"], Touches none; refuses (error) a path not on the service's configured list or a path that fails CleanGuardPath or RegularNoFollow;
//   refuses to run without a non-zero actions.Tag (it must be a plan node); re-hashes after the copy; Rollback data restores the previous index entry.
//   boot: resolves GuardBoot.Candidates for this host (distro from /etc/os-release ID, `resolve: initramfs` -> /boot/initramfs-$(uname -r).img or initrd.img-$(uname -r), existing files only) into literal paths first.
func Active() *Module // set by the module on Start (Task 37); the actions read the settings through it
```

- [ ] **Step 1: Write the tests:**

```go
func TestGoldenPutEntryOpen(t *testing.T) { /* Put + Entry + Open round trip; reopen the dir: same index; a crash between blob write and index write leaves no half entry (write index last, atomic) */ }
func TestGoldenDiskBudget(t *testing.T) { /* maxBytes 1 MiB, Put 2 MiB -> error, index unchanged */ }
func TestSymlinkPathRefused(t *testing.T) { // review focus 5
	dir := t.TempDir(); target := filepath.Join(dir, "real"); _ = os.WriteFile(target, []byte("x"), 0o644)
	link := filepath.Join(dir, "index.php"); _ = os.Symlink(target, link)
	if _, err := RegularNoFollow(link); err == nil { t.Fatal("symlink accepted") }
}
func TestGlobAndRelativePathsRefused(t *testing.T) { /* "/var/www/*.php", "/var/www/../x", "var/www/x", "/var/www/", "/x\x00y" -> CleanGuardPath error */ }
func TestSnapshotRefusesUnlistedPath(t *testing.T) { /* service list [/var/www/html/index.php]; snapshot of /etc/passwd -> error, nothing stored (constraint 1) */ }
func TestSnapshotNeedsPlanTag(t *testing.T) { /* Execute without a tag in ctx and NodeID "" -> error (constraint 2) */ }
func TestSnapshotStoresHashModeOwner(t *testing.T) { /* 0640 file: entry.Mode 0640, SHA256 equals sha256 of content, PlanTag set from the tag, Stale false */ }
func TestSnapshotBootResolvesLiteralPaths(t *testing.T) { /* fake root with /etc/fstab, /etc/passwd, /boot/grub/grub.cfg, no netplan: only existing files are snapshotted; passwd and shadow entries have Never true; a candidate containing * is refused */ }
func TestManifestGuardPathMustBeUnderRoots(t *testing.T) { /* services.yml guard path outside roots -> manifest validation error */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/content_guard/ ./internal/manifest/ -run 'Golden|Symlink|GlobAndRelative|Snapshot|ManifestGuard' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified. Copy owner, mode, xattrs and the SELinux label with the same helpers `file.restore` uses; as non-root the owner copy is skipped and the test asserts mode only (`t.Skip` with a reason for the xattr assertion).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/content_guard/ ./internal/manifest/ && GOOS=windows go vet ./internal/content_guard/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "content_guard: golden store, path safety, guard.snapshot"`

---

### Task 35: `content_guard`: watching, the hash sweep and constraints 1 to 3

**Files:**
- Modify: `internal/content_guard/watch.go`
- Test: `internal/content_guard/watch_test.go`

**Interfaces:**
- Consumes: `event.FileChange` (`event.Decode[event.FileChange]`), `event.TelemetryGap`, `Golden`, `actions.Locks.TryAcquire` for the held-lock test, `event.Event.Tag`.
- Produces:

```go
type Outcome struct {
	Service, Path string
	Decision      string             // alert | ignored_tag | ignored_plan_lock
	Change        ChangeFields       // WouldRestore filled
	Gap           *event.TelemetryGap // golden_missing or golden_stale (source content_guard, critical); nil otherwise
}
type Watcher struct{ /* services, golden, locks, probe-green lookup, own-tag prefix "guard:" */ }
func NewWatcher(s *plan.ContentGuardSettings, g *Golden, locks *actions.Locks, probeGreen func(service string) bool) *Watcher
func (w *Watcher) OnFileChange(ev event.Event) []Outcome // constraints 1 to 3
func (w *Watcher) Sweep(now time.Time) []Outcome        // hash every listed path against its golden; a missing file is a change with Op "delete"
func (w *Watcher) Paths() []string                       // every listed path (for health and the audit/winevt watch registration)
```

Rules: (1) an event whose `Path` is not on a listed service's list (or the boot list when enabled) is ignored, nothing read or written; (2) a listed path with no golden entry yields `Gap{reason: golden_missing}` and nothing else; (3) an event with non-empty `Tag` is `ignored_tag`, marks the golden entry stale and yields `Gap{reason: golden_stale}`, except tags with prefix `guard:` (a restore's own write: ignored without marking); a change while `Locks.TryAcquire("content:"+service, lock)` reports busy is `ignored_plan_lock`; otherwise the decision is `alert`. The watcher never writes to a guarded path and has no mode (S1): `Change.WouldRestore` is true when the golden entry exists, is not stale, is not `Never`, its blob re-hashes to `GoldenSHA256` and `probeGreen(service)` is true (a `Boot` entry on a host with no scored service has no probe, so false); it is set whether or not any recipe is enabled, so `propose` and `shadow` show what a restore would do. `Sweep` uses `RegularNoFollow`; a symlink where a file was is a change (`Op: replace`, `decision: alert`); the restore replaces the link (Task 36). Sweep runs every 60 s, every 10 s while a `telemetry_gap` for the file watch is open (Task 37).

- [ ] **Step 1: Write the tests:**

```go
func TestUnlistedPathIgnored(t *testing.T) { /* constraint 1 */ }
func TestNoGoldenGap(t *testing.T) { /* constraint 2: Gap golden_missing, no change decision */ }
func TestTaggedChangeMarksStale(t *testing.T) { // review focus 5
	/* change with Tag "plan:harden-web" -> ignored_tag, Entry.Stale true, Gap golden_stale; Tag "guard:abc" -> ignored, Stale false, no gap */
}
func TestPlanLockHeldIgnored(t *testing.T) { /* hold content:web via Locks.Acquire: ignored_plan_lock */ }
func TestUntaggedChangeIsAlertWithWouldRestore(t *testing.T) { /* untagged change: decision alert, WouldRestore true with a verified golden and a green probe; false with a stale golden, a corrupt blob or a red probe; the file on disk is untouched in every case */ }
func TestAccountDatabaseNeverWouldRestore(t *testing.T) { /* /etc/shadow Never entry: decision alert, WouldRestore false */ }
func TestDeletedFileReported(t *testing.T) { // review focus 5
	/* Sweep with the listed file missing: Outcome decision alert, Change.Op "delete", WouldRestore true; nothing is written by the watcher */
}
func TestSweepCatchesMissedEvent(t *testing.T) { /* change the file without any event: Sweep reports it with current_sha256 != golden */ }
func TestSymlinkReplacementIsAChange(t *testing.T) { /* replace the file by a symlink: Sweep outcome, Change.Op "replace" */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/content_guard/ -run 'Unlisted|NoGolden|TaggedChange|PlanLock|UntaggedChange|AccountDatabase|DeletedFile|SweepCatches|SymlinkReplacement' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified. The re-hash of the file and of the golden blob uses the shared file hasher (integrity's identity cache, S4), not a second hasher.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/content_guard/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "content_guard: watcher and hash sweep (constraints 1 to 3)"`

---

### Task 36: `content_restore` recipe, the `golden` source of `file.restore`, the scored-content lint exception (S1, S4)

`guard.restore`, the module's own probe and rollback code, its loop stop and `RestoreFields`/`StopFields` are removed: the restore is the core action `file.restore{source: golden}` (one file-restore action for golden, depot and backup), run by the `content_restore` recipe in `respond`; its probe and rollback are the action's, its stop is the attempt ledger (limit 2 attempts in 10 minutes per (host, file, kind)), and it is recorded as `respond.action` and `plan.failed`.

**Files:**
- Create: `rules/respond/content_restore.yml` (the recipe; the module owns it, `respond` loads it), `internal/content_guard/source.go` (registers the `golden` source), `internal/content_guard/lint.go`, the rule `D2j.content-guard-change` in `rules/detect/linux_persistence.yml`
- Modify: `internal/actions/guard.go` (`OpRestore`, `StaticGuard.RestorePaths`)
- Test: `internal/content_guard/source_test.go`, `internal/actions/guard_restore_test.go`, `internal/content_guard/lint_test.go`, `internal/respond/content_restore_test.go`

**Interfaces:**
- Consumes: `Golden`, `Watcher`, `plan.HealthProbe`, `actions.Env.Execute`, `actions.Ledger`, `lint.Register`, `lint.Rule`, `lint.Ctx`, the core `file.restore` action and its restore-source hook (`actions.RegisterRestoreSource(name, Source)`; the depot and backup sources register from their modules, the `golden` source from this package; if the action plan has not defined the hook yet, this task defines the one-function interface next to `file.restore`).
- Produces:

```go
const OpRestore = "restore" // actions.OpRestore, in internal/actions/guard.go (reuse if W5 already added it)
// StaticGuard gains: RestorePaths []string // scored content paths a Restore touch may write (the services' content.guard lists)
//   Allow: TouchPath with Op OpRestore passes iff t.Name is in RestorePaths; every other op on scored content is refused as before.
// source.go: the golden source of file.restore{source: golden, path, service}:
//   Plan: golden entry present, not stale, not Never, blob re-hashes to the entry (else error); a Boot entry needs a scored-service probe on the host (else error);
//   Apply: probe before (recorded, a red before-probe does not stop it), write the golden copy atomically with golden mode/owner/xattrs/label (a symlink or other non-regular
//   file at the path is replaced, never followed), keep the replaced file under StateDir/content_guard/replaced/<id>, tag the write `guard:<id>`, probe again (one retry after 5 s, then fail);
//   Verify: hash equals golden; a failed after-probe returns an error, so Execute rolls back to the replaced file.
// rules/respond/content_restore.yml:
//   recipe: content_restore; module: respond; triggers: [D2j.content-guard-change]; collect: [process_tree, content_changes]
//   tier0: [{action: file.restore, params: {source: golden}, params_from: {path: entities.path, service: entities.service}, probe: true, rollback: true}]
//   propose: [{template: restore_file (Task 32), params: {source: golden}, params_from: {path: entities.path, service: entities.service}}]
//   Ledger limit for the template: {Count 2, Window 10m}. Enabled per host, optionally per service (RecipeEnable.Services); autonomy propose | shadow | auto from the respond block.
// rule D2j.content-guard-change: event content_guard.change, decision alert; tier 1; entities service, path, would_restore, writer.exe. (The design names this rule D2j; the plan's
//   existing D2j.splunk-fim is a different rule, so the full ids differ and recipe triggers use the exact id.)
// lint rule CG001 (lint.Register in init): a node of action file.restore with source golden is accepted only when its path is on a service's content.guard list in the manifest
//   and the plan class is click or auto; any other node touching scored content is rejected by the existing rules.
```

- [ ] **Step 1: Write the tests:**

```go
func TestRestoreRollsBackWhenProbeFails(t *testing.T) { // constraint 4; the real actions.Env running file.restore{source: golden}, the probe func fake
	/* golden "good", file "deface"; probe: ok before, error after: file content is "deface" again, the action errors, Execute rolled back */
}
func TestFailedBeforeProbeDoesNotStopRestore(t *testing.T) { /* before probe error, after ok: restored, the before result is recorded */ }
func TestRestoreRefusesNeverStaleAndBootWithoutProbe(t *testing.T) { /* /etc/shadow Never entry, a stale entry, a Boot entry on a host without a scored service: Plan error, nothing written */ }
func TestRestoreReplacesSymlink(t *testing.T) { // review focus 5
	/* the listed path is a symlink to /etc/passwd copy: restored as a regular file with golden content; the link target file is untouched */
}
func TestRestoreWriteCarriesGuardTag(t *testing.T) { /* the tag log records guard:<id> for the path */ }
func TestStaticGuardAllowsRestoreOnlyOnListedPath(t *testing.T) { /* guard Paths [/var/www/html] RestorePaths [/var/www/html/index.php]: OpRestore on index.php allowed; OpModify on it refused; OpRestore on /var/www/html/other.php refused */ }
func TestLintCG001(t *testing.T) { /* file.restore{source: golden} for a path not in content.guard -> finding CG001; listed path in a click plan -> none */ }
func TestRestorePreservesModeOwnerLabel(t *testing.T) { /* mode 0640 restored; xattr/owner assertions skip with a reason when not root */ }
// internal/respond
func TestContentRestoreRecipeResolves(t *testing.T) { /* a D2j.content-guard-change alert -> Tier0 [file.restore{source: golden}], Propose [restore_file]; the recipe validates (source golden is allowed under tier0:) */ }
func TestSecondRestoreStopsViaLedger(t *testing.T) { /* runner fixture, recipe enabled at auto: two restores of one file inside 10 minutes apply and the second opens the ledger (plan.failed auto_halted trigger repeat); a third alert is skipped_breaker and the controller makes the click; after 11 minutes (fresh window) and a reset it applies again */ }
func TestShadowRecordsWouldRestore(t *testing.T) { /* autonomy shadow: respond.action outcome shadow, the file on disk unchanged */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/content_guard/ ./internal/actions/ ./internal/respond/ -run 'RestoreRolls|FailedBefore|RestoreRefuses|RestoreReplaces|GuardTag|StaticGuardAllows|LintCG001|RestorePreserves|ContentRestore|SecondRestore|ShadowRecords' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/content_guard/ ./internal/actions/ ./internal/respond/ ./internal/plan/... && bin/phylax rules registry`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "content_guard: content_restore recipe, golden source of file.restore, scored-content restore exception"`

---

### Task 37: `content_guard` module: change events, boot-critical list, health, conformance

**Files:**
- Modify: `internal/content_guard/{module.go,config.go,boot.go}`, `internal/agent/mods/content_guard.go`, `internal/module/conformance/allowed.go` (`ModulePackages["content_guard"]`)
- Create: `content_guard/boot_critical.yml`, `plans/content_guard/guard.snapshot.yaml`
- Test: `internal/content_guard/module_test.go`, `internal/content_guard/conformance_test.go`

**Interfaces:**
- Consumes: Tasks 34 to 36; `agent.Env`; `module.Manifest`.
- Produces:

```go
func Manifest() module.Manifest // Name "content_guard", Sides [agent], OS both, Privilege "root", Default false, Roles [], Consumes [file_change, process_start, telemetry_gap, controller.fact],
	// Emits [content_guard.change, telemetry_gap], Budget{2, 8, 1, 10, 20 << 10, 64}, Actions [guard.snapshot],
	// Content ["plans/content_guard/guard.snapshot.yaml","content_guard/boot_critical.yml"]
type Config struct { // modules/content_guard.yml: the design YAML
	module.Common `yaml:",inline"` // enabled only: no act_enabled, no autonomy, no mode, no promotion (S1: this module never writes to scored content)
	BootCritical  struct{ Enabled bool `yaml:"enabled"` } `yaml:"boot_critical"`
	ProbeTimeout  time.Duration `yaml:"probe_timeout"`
}
type Module struct{ /* watcher, golden, per-service state, counters */ }
func NewModule(env agent.Env, s *plan.ContentGuardSettings) (*Module, error) // Actions() nil -> wraps agent.ErrUnavailable
func (m *Module) Name() string
func (m *Module) Start(ctx context.Context, emit agent.Emit) error
func (m *Module) Health() module.Health
```

Behaviour: every file change on a listed path emits `content_guard.change` with `decision` and `would_restore` (Task 35); `golden_missing` and `golden_stale` go out as `telemetry_gap{source: content_guard}` (critical). The module restores nothing: the `D2j.content-guard-change` alert and the `content_restore` recipe (Task 36) do, by the recipe's `autonomy` (`propose`, `shadow`, `auto`), so promotion from propose to auto is that one signed setting, made on the shadow data, and there is no module-side promotion, demotion or mode. **Boot-critical**: only when `BootCritical.Enabled` and the host has a scored service (its probe is the gate); with no scored service every entry has `would_restore: false`. `content_guard/boot_critical.yml` lists explicit candidates (no globs): `/etc/fstab`, grub config per distro (`/boot/grub2/grub.cfg` for rocky, `/boot/grub/grub.cfg` for debian and ubuntu), `/boot/efi/EFI/<vendor>/grub.cfg` resolved from the existing vendor directory, the running kernel's initramfs (`resolve: initramfs`), `/etc/ssh/sshd_config`, the host's network config files that exist (netplan `00-installer-config.yaml` and `50-cloud-init.yaml` on Ubuntu, `/etc/network/interfaces` on Debian, the NetworkManager connection files named in `hosts.yml` on Rocky), and `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` flagged `never: true` (watched, never restored automatically); on Windows the BCD store (`\Boot\BCD`, restored with the pre-approved `bcdedit /import`; `shortcut`: a `host.exec` special case, upgrade when `file.restore` gains a registry-hive form), `ntds.dit` excluded. `plans/content_guard/guard.snapshot.yaml` is the plan node hardening plans append for each service they touched.

- [ ] **Step 1: Write the tests:**

```go
func TestChangeEmitsAndNeverWrites(t *testing.T) { /* constraint 6: change -> content_guard.change decision alert; file content unchanged; would_restore true with a verified golden and a green probe */ }
func TestWouldRestoreWithoutAnyRecipe(t *testing.T) { /* no recipe enabled anywhere: the same events, the same would_restore */ }
func TestModuleRejectsActFields(t *testing.T) { /* a block with act_enabled, autonomy, mode or promote -> unknown field error (S4: only acting modules carry them) */ }
func TestBootCriticalNoScoredServiceNotRestorable(t *testing.T) { /* no scored service: every boot entry's would_restore false */ }
func TestBootCriticalListIsExplicitPaths(t *testing.T) { /* boot_critical.yml has no glob character; passwd/shadow/group/sudoers are never: true; fake root: only existing files resolve */ }
func TestGapsAreTelemetryGap(t *testing.T) { /* golden_missing and golden_stale arrive as telemetry_gap{source content_guard} critical, not as a module kind */ }
func TestHealthStates(t *testing.T) { /* no paths unavailable; missing golden degraded naming the path; ok otherwise */ }
func TestGoldenIndexSurvivesReconfiguration(t *testing.T) { /* reconfigure: Golden entries still present (Keep + on-disk index) */ }
func TestContentGuardConformance(t *testing.T) {
	conformance.Agent(t, conformance.AgentCase{Factory: factoryNamed(t, "content_guard"), Default: cgCfg(t, 0), Reconfig: cgCfg(t, 1), KeepKey: "content_guard.state", Load: fileChangeEvents()})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/content_guard/ -run 'ChangeEmits|WouldRestoreWithout|RejectsActFields|BootCritical|GapsAre|HealthStates|GoldenIndexSurvives|Conformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified (sweep timer, change events, gaps).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/content_guard/ ./internal/agent/... ./internal/module/...`. Expected: PASS, `content_guard` passing the agent conformance checks.
- [ ] **Step 5: Commit.** `git commit -am "content_guard: module with change events, boot-critical list, health"`

---

### Task 38: Controller rendering: signed config blocks, lists, overrides, reference module blocks

**Files:**
- Modify: `internal/controller/genconfig.go`, `internal/controller/agentconfig.go` (`ConfigInputs`: overrides already in `Manifest`), `internal/manifest/validate.go`
- Create: `manifest/2027/modules/{detect,respond,content_guard}.yml`, `manifest/schema/modules/{detect,respond,content_guard}.schema.json` (via `-update`), `internal/controller/genconfig_w4_test.go`

**Interfaces:**
- Consumes: Tasks 1, 5, 6, 9, 24, 27, 37; `respondrecipes.FS`; `module.Effective`; `manifest.ModuleBlock.Decode`.
- Produces:

```go
func renderDetect(m *manifest.Manifest, host string, base *plan.DetectSettings) *plan.DetectSettings
//   Lists: manifest.scored_users, manifest.admin_sources, manifest.scored_service_names, manifest.workstations, manifest.service_binaries.<service> for the host's services;
//   Exceptions copied from m.Overrides (rule ids kept; expired exceptions dropped); Packs from the block; MaxKeys from the block (rate and burst default from the manifest). No act fields: detect only alerts (S1).
func renderRespond(m *manifest.Manifest, host string, cfg respond.Config, recipes fs.FS, vars map[string]string) (*plan.RespondSettings, []string)
//   Services: this host's services from services.yml (Scored from the manifest; Health from the first manifest Health entry: tcp_connect -> net.tcp_probe{host: 127.0.0.1, port}, http_get -> net.http_probe{url, expect_status, expect_regex});
//   NeverBlock: every host address, the controller, relays, the Kali, plus Overrides learned scorer ranges when present; Tier0 from cfg.Settings(); Protected; ResetEpoch = m.Overrides.RespondResetEpoch;
//   ActEnabled (effective per host through the overrides `act` list) and Autonomy copied from the block; Tier0.Recipes = the block's list plus the rules of m.Overrides.Recipes that apply to the host (the per-rule act switch).
//   Recipes: each recipe file with ${name} expanded from vars (agent_dir, sysmon_installer, sysmon_sha256, sysmon_config); a recipe with an unresolved variable is omitted and named in the returned warnings.
func renderContentGuard(m *manifest.Manifest, host string, cfg contentguard.Config, boot []byte) (*plan.ContentGuardSettings, []string)
//   Services: content.guard lists of the host's services, Health as above, Lock the service unit lock; BootCritical.Candidates parsed from content_guard/boot_critical.yml (+ the host's NetworkManager connection names for rocky). No mode and no clear epoch (S1).
```

Enablement is `module.Effective(host.Modules[name], block.Enabled, Manifest().Default)`; `respond` and `detect` default on, `content_guard` off. Reference blocks are the design's YAML (`respond.yml` with `act_enabled: false`, `autonomy: {}` and `tier0.recipes: []`; `content_guard.yml` with `enabled: false`, `boot_critical.enabled: false` and `probe_timeout: 30s`; `detect.yml` with `packs` listing every pack file name and no act fields).

- [ ] **Step 1: Write the tests:**

```go
func TestRenderRespondScoredServiceWithoutHealthHasNilProbe(t *testing.T) { /* a scored service without health: HostService.Health nil (the runner then refuses tier 0 there) */ }
func TestRenderRespondNeverBlockHasInfraAddresses(t *testing.T) { /* controller, a relay and the Kali address appear in NeverBlock */ }
func TestRenderRespondDropsRecipeWithUnresolvedVar(t *testing.T) { /* vars lacks sysmon_sha256: sysmon_reinstall omitted, warning names it; other recipes present */ }
func TestRenderDetectListsAndOverrides(t *testing.T) { /* manifest with two scored accounts: list manifest.scored_users has both; overrides with an exception (expired one dropped) appear in the settings; no rule-mode field exists */ }
func TestRenderRespondRecipesAndAutonomy(t *testing.T) { /* a RecipeEnable for D10k in overrides plus autonomy {D10k.fw-exec-tamper: shadow} in the block: Tier0.Recipes contains firewall_restore, Autonomy[D10k.fw-exec-tamper] == shadow, ResetEpoch from RespondResetEpoch; a host outside the record's scope gets neither */ }
func TestRenderContentGuardOnlyListedPaths(t *testing.T) { /* a service with content.guard [/var/www/html/index.php] and roots [/var/www/html]: Paths exactly that one; host without such a service: Services empty and BootCritical disabled */ }
func TestReferenceBlocksDecodeStrictly(t *testing.T) { /* each manifest/2027/modules/{detect,respond,content_guard}.yml decodes into its Config with unknown fields rejected; respond act_enabled false and autonomy empty; content_guard enabled false and rejecting act_enabled */ }
func TestEndToEndConfigCarriesRecipesAndRules(t *testing.T) { /* BuildAgentConfig for a Linux web host: Modules.Detect has rules from the tree, Modules.Respond has >= 7 recipes, Modules.ContentGuard nil unless enabled */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run 'RenderRespond|RenderDetect|RenderContentGuard|ReferenceBlocks|EndToEndConfig' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified; run `go test ./internal/module/all -run Schema -update` for the three schema files.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: render detect, respond and content_guard blocks; reference module blocks"`

---

### Task 39: End-to-end fixtures and cross-module checks (T74 respond half, T75 rule half, T79 recipe enablement)

**Files:**
- Create: `internal/e2e/detect_respond_test.go`, `internal/e2e/testdata/alert_stream.json`
- Modify: `cmd/phylax/rules.go` (the `promote` checks use the real recipes), `internal/module/conformance/allowed.go` (nothing is left in `PreContract` for W4's three modules)

**Interfaces:**
- Consumes: everything above. `internal/e2e` may import any package.
- Produces tests only.

- [ ] **Step 1: Write the tests:**

```go
func TestRecipeTriggersAreRealRules(t *testing.T) { /* every trigger of every embedded recipe matches at least one id in LoadTree + pending (Matches); an unmatched trigger is an error naming recipe and trigger */ }
func TestRecipesAreTiedToTier0Rules(t *testing.T) {
	/* every rule matched by a recipe trigger that has tier0 or auto steps has tier 0 in its file (except rules parked in pending, which are listed in a comment); no rule file has a mode key (S1) */
}
func TestRecipeEntitiesAreRuleEntities(t *testing.T) { /* each params_from entity key of each recipe test alert appears in the entities: list of the rule it names */ }
func TestRecordedAlertStreamOutcomes(t *testing.T) { // fixture replay
	/* testdata/alert_stream.json: a recorded list of detect.alert and controller.fact events with relative times (D10k fw tamper x4, 30 s apart, with firewall_restore enabled at autonomy auto and loop count 3, D17c service stop, D15b decoy login from an own address, a D2a webroot change, a gpo_finding fact);
	   feed it to a harness running the real respond module over fake actions; the exact outcome list is asserted:
	   [applied fw.apply, applied fw.apply, applied fw.apply (the ledger opens: one plan.failed auto_halted trigger repeat), skipped_breaker fw.apply, skipped_guard (D17c, unknown verdict), skipped_guard (source_block own address), no event for D2a] */
}
func TestUnknownFactProposesTier1(t *testing.T) { // T74 respond half
	/* agent side: tier-0 recipe with a Probe step and no scorer fact -> skipped_guard; feed that respond.action to the controller module with a fake Host: Propose called with Reason "unknown verdict"; after a fresh scorer_probe fact, the same alert applies */
}
func TestReplayedBackscanTriggersNothing(t *testing.T) { // review focus 3
	/* a harness with detect and respond: 20 process_start events flagged replay:true that match D1 and D3c: zero detect.alert, zero respond.action */
}
func TestRecipeEnablementPass(t *testing.T) { // T79 recipe enablement
	/* recipe not enabled: the alert is emitted, respond does nothing. enable it through cmd/phylax rules promote (AppendOverrides writes Overrides.Recipes) and set the template autonomy: shadow records respond.action shadow and applies nothing; propose makes the controller click; auto acts. promote --remove stops it. Enablement of a rule whose recipe has no tier-0 steps is refused. */
}
func TestCanaryExemptByFieldNotTag(t *testing.T) { // T75 rule half
	/* net.egress_denied with canary true and empty Tag: D12 does not fire, V3 does; with canary false: D12 fires */
}
func TestNonCanonicalFieldRejectedByLoader(t *testing.T) { /* T75: a rule naming src_ip fails LoadTree with Declared; also covered in Task 3, asserted here against the shipped corpus loader options */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/e2e/ -run 'RecipeTriggers|RecipesAreTied|RecipeEntities|RecordedAlertStream|UnknownFactProposes|ReplayedBackscan|RecipeEnablementPass|CanaryExempt|NonCanonical' -v`. Expected: FAIL (or skipped by the seams until implemented).
- [ ] **Step 3: Fix what the tests find** in the recipes, rules and code of earlier tasks (each fix in the file that owns it, same commit).
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS; `grep -rn 'unimplemented: W4' internal | wc -l` prints 0.
- [ ] **Step 5: Commit.** `git commit -am "e2e: detect and respond fixtures; recipe, rule and enablement cross-checks"`

---

### Task 40: Lab (stronger agent or David)

Runs on the BTaP Proxmox replica (`stacks/ccdc` in btap-infra, the "ccdc27" lab) and GOAD for the AD rows. Records every result in `docs/impl/lab/w4-detection-response.md` (date, commit, VMIDs, test id, pass or fail, measured values, what was not run) and opens an issue per failure. This task does not block the merge; a module's catalogue Status becomes "lab-proven" only from this record.

- [ ] **Step 1: Prepare.** Build the branch, enable `detect` and `respond` with `act_enabled: false` first (the alert-only stage), `content_guard` off; snapshot the VMs.
- [ ] **Step 2: Run these lab tests** (ids from the design's Test matrix):
  - T02: a systemd timer disables the host firewall every minute. Tier 0 restores it; measure restore latency (alert to applied); the loop opens on the third restore and names the timer in `Lineage`.
  - T03: PHP webshell upload, command, file change. `D1.*` and `D17b` fire; the Alerts page shows the four proposals; kill-tree is a click.
  - T11: stop Sysmon; `D10e` fires; `sysmon_reinstall` reinstalls it (Windows member); a log clear fires `D10d`.
  - T16: a hardening plan that breaks a scored page is caught by the probe and rolled back; a forced `fw.apply{op: policy}` on a host whose scored service goes red trips the breaker and rolls back.
  - T17: link drop during a firewall-enforce plan; tier 0 and the dead-man do not fight.
  - T20: Quotient plus Orange traffic for 60 minutes with no red steps, `act_enabled: false`: at most 5 false-positive alerts per hour; record counts by rule.
  - T36: Phylax hardening with no red steps and the tier-0 recipes enabled at `autonomy: auto` with `act_enabled: true`: zero untagged alerts and zero tier-0 actions on our own tagged work.
  - T52: content guard under its six constraints (planted OpenCart index defacement and an SMB SOP file: `content_restore` at `propose` offers the click, at `shadow` records a would-restore and at `auto` restores, and the scorer regex passes; a hand edit under a `phylax claim` window is ignored; a second restore within 10 minutes stops; `rm /etc/fstab` restores at `auto` and proposes at `propose`); T63 Docker volume watch.
  - T38 rows that belong to `detect`: Zerologon, hidden accounts, `chattr +i`, unit capabilities, PHP overrides, OpenCart admin rows, GPO and ACL changes each raise their alert.
  - A-AUTO live rows: a decoy login from a non-own address blocks it on non-scored ports and expires; D7h deletion of a scored test user in AD restores it from the Recycle Bin and the next scorer login passes; a red GPO is unlinked.
  - Reset: open the ledger's breaker with a red probe (`plan.failed` trigger `red_check`), press Reset on the Responses page, the next alert applies.
  - Windows runs of Task 21 (`proc.*` on a Windows member: kill-tree, suspend, dump) and the Windows firewall/Defender/audit recipes under an Enforced GPO (`skipped_gpo`).
- [ ] **Step 3: Record, open issues, and send the hand-offs below to their owners.**

**Hand-offs (to be confirmed by the owners; none blocks W4's merge):**
- W7 (`checks`): `scorer_probe_result` fact: id `scorer_probe:<service>`, `Data{"service": string, "ok": bool}`, ttl at least two round delays, sent to the agent of the host that serves the service.
- W5 (`ad`): `gpo_finding` fact `Data` carries `Affects`, `Section`, `Item` and `Enforced`; respond reads them case-insensitively. W5 also registers the pending actions `ad.recycle_restore`, `ad.gpo_unlink`, `task.disable`, `runkey.remove`, `wmi.subscription_remove`, `file.restore{source}` (with the `golden` source from `content_guard`), `hunt.persistence`, `yara.scan`; each registration deletes its `PendingActions` entry.
- W6 (`firewall`): `fw.apply{op: policy|allow|block|quarantine}` (`block` takes `sources`, `ports: non_scored`, `reason`, `owner` and returns the undo data the expiry runs) and `fw.snapshot`; the unparked `firewall.drift` rule `D10k3`.
- W2: `session.terminate_predating{source, before}` (Tier B); respond's `session_evict` calls it with `before: ${now}`.
- W8 (`traceback`): declare `traceback.label` (with `source_label`) so `rules/pending/pass_the_hash.yml` can be unparked, and make `deps` use ids `DEP1` to `DEP3` (the rules are renamed here).
- W9 (`deception`): the D15 rules live in `rules/detect/deception.yml` until W9 moves them. W5 (`hunt`): consumes `plan.failed{reason: auto_halted, trigger: repeat}` for the targeted hunt on the lineage.
- The engine plan (W2) and the design: the attempt ledger type is built here in `internal/actions/ledger.go` unless the engine plan built it first; the `file.restore` restore-source hook (Task 36) is the same kind of shared definition.
- W10: an Alerts-page "silence" button that calls `manifest.AppendOverrides` with a `RuleException`; the Content guard page and host-grid column (gap 21); `backup.failed` for a scored user deleted with no Recycle Bin entry.
- W11: the chunk transfer of `evidence.blob` items.

---

## Self-review

**1. Spec coverage.** `detect`: evaluator on the contract (Task 2); `lists`, `exceptions`, `rate` (5, 6, 8); `replay` and receive-time windows (7); `jitter` (9); no rule mode, `AlertOnly` or `rule_modes` (4; S1); controller-scope evaluation (10); `agent.health` carries module `Info` (11; the controller rules-hash compare is removed, S4); collectors and `evidence.blob` (12); corpus move, registry, DEP rename (13, bug 2); ATT&CK pinned data (14); `phylax rules` and `THIRD_PARTY_RULES.md` (15); catalogue additions N4.2 to N4.6, D327/D332/D333/D337 items, D7h, hand-ported rules, pass-the-hash (16 to 19); `ir_template` (4, bug 22); canonical fields (3, T75). `respond`: tier table and guards (24 to 27), recipes (28, 29, 32), controller side (30; 31 removed by S1), pages and the ledger reset (33), the attempt ledger and `autonomy` handling (25, 27), processes family and `dir.snapshot` (20 to 23), A-AUTO tier-0 set (27, 29, 38). `content_guard`: golden store, path safety, change detection and boot-critical list (34, 35, 37), the `content_restore` recipe over `file.restore{source: golden}` with the six constraints carried by the golden source, the ledger and the probe (36). Config rendering (38). Tests T02, T03, T16, T20, T36, T52 in the lab (40); T74 respond half, T75 rule half, T79 recipe enablement in CI form (39); T65 bug 2 and bug 22 regressions (13, 4). Deliberate gaps, all recorded above: controller collectors and `freeze_capture` (gap 5), pass-the-hash pack parked (gap 16), content_guard page (gap 21), Windows runs of `proc.*` (lab).

**2. Step scan.** Every code step names a file, an exact signature and the spec values; test steps give names and assertions. Content tasks (16 to 19, 28, 29, 32) give the rule or recipe table and tests that pin tiers and ids; the YAML bodies are left to the implementer on purpose.

**3. Type consistency.** `AlertFields` (Task 1) is used by Tasks 2, 10, 12; `AlertView` (Task 24) is respond's own view and never imports `detect`. `Tier0Settings` field names (`MaxPerHostPerMin`, `BreakerWindowSec`, `LoopCount`, `LoopWindowSec`, `BlockExpiresSec`, `BlockMaxActive`, `Recipes`) are the design's and are read by Tasks 27, 29, 38. `Step` flags (Task 24) are the ones Tasks 27 and 29 act on. `plan.HostService` / `HealthProbe` are produced in Task 1, read by 26 and 38. `ResetEpoch` comes from `Overrides.RespondResetEpoch` (Task 1) and is folded in Task 38; `actions.Ledger` (Task 25) is used by Tasks 26, 27, 29 and 36, and `module.Actor` (W1) by Task 27.

**4. Review Focus.** Unknown verdict: Tasks 26, 27, 30, 39. Hostile parameters: Tasks 24, 27. Replay: Tasks 7, 9, 39. Restorer fights: Tasks 25, 26, 27, 36. Guarded file tricks: Tasks 34, 35, 36.

**5. Proportion.** The design sections W4 owns are about 600 lines; this plan is larger because it carries 40 tasks with tests, as W1 and W3 do. Bodies are signatures and test names; no function body is transcribed.
