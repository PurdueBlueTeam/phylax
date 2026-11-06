# W5: Integrity and Hunting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put `integrity`, `hunt`, `hardening` and `ad` on the module contract, build what the design says is missing (rootkit cross-checks, SUID sweep, YARA wiring, the hunt flow, the hardening pack library, the AD checks, GPO response, SDDL repair, the Recycle Bin), extract the shared libraries `internal/signing` (with sshsig) and `internal/integrity/format`, and fix Known bugs 1, 6 and 9.

**Architecture:** Each module is one package (`internal/integrity`, `internal/hunt`, `internal/hardening`, `internal/ad`) with its agent registration in `internal/agent/mods/<name>.go`. Collection and cleanup are core-style actions registered through an exported `actions.Register`; judging, diffing and scoring are pure functions; each controller side has one writer goroutine for its tables. `hardening` is content (`plans/hardening/`) plus a thin controller module whose health is the template validator. Two shared stateless libraries come first, as seams, because W11 waits on them.

**Tech Stack:** Go 1.27.2 (mise), standard library, `golang.org/x/crypto/ssh` (already in `go.mod`, used only for key parsing in tests and `signing`), `golang.org/x/sys`, `gopkg.in/yaml.v3`, `modernc.org/sqlite` through `store.ModuleDB`. No new modules in `go.mod`.

**Spec:** `phylax_design.md` (v4): the module sections `integrity`, `hunt`, `hardening`, `ad` (Integrity and hunting); "The module contract"; "Core components: Execution engine" (Action families: Registry, Kernel and system, Persistence cleanup, Domain, Integrity, Hunt; Plans; scoring-safety lint); "Shared libraries" (`internal/signing`, `internal/integrity/format`); Known bugs 1, 6, 9; Appendices B, C, D; "Testing and lab" (T01, T12, T19, T31, T32, T34, T38, T61, T65 for bugs 1, 6 and 9, T68, T72, T76, T78). Master plan: `docs/impl/README.md`. Contract names: `docs/impl/01-module-contract.md` (W1).

## Decisions and design gaps (Task 1 applies the design edits in the same commit)

1. **Registry action names follow the code.** The core table says `reg.set`, `reg.delete`, `reg.snapshot`; the code registers `registry.set` and `registry.delete`, and the design says the code's name is final. The table is edited to `registry.set`, `registry.delete`, `registry.snapshot` (new).
2. **`ad.recycle_restored` is in the event-kind table but not in the `ad` manifest's Emits.** Added to Emits.
3. **`plans` (the root embed package) is not on the module import allow list**, but `hardening`'s health is the template validator. Added to `conformance.CoreImports` and the design's core package list by W1 Task 22b (applied to the design in the consistency pass).
4. **Exported action registration is W1's.** `actions.Register(f func() []Action)` and `actions.RegisterUndo` (the exported `registerExtra` and `registerUndo`) are built by W1 Task 2a, the one name every workstream uses; this plan consumes them.
5. **Pack templates and controller templates are one format.** `plans.Template` (vars, `each`, `scoring_note`) is a strict superset of the controller's file template. Packs stay in that form; `vars` values may be `{labels: "<expr>"}`, resolved to host lists from the manifest. `plans.Parse`, `plans.ResolveLabels`, `Template.Module` and `controller.LoadModuleTemplateFor` (the sibling of `LoadModuleTemplate` that takes the label resolver) are W1 Task 22b's; Task 37 here moves the pack files and requires `module:`.
6. **Accepts and decisions are the core operator-command event, not module kinds or tables (S4).** The design gives `integrity`, `hunt` and `ad` no accept or decision kind. A button on the Integrity, Hunts or Active Directory page emits the core `operator.edit` kind (W1; fields `module`, `op`, `subject`, `record`, `by`, `at`) through `Host.Emit`. An accept of any kind (an integrity hash, a hunt finding or triage item, an AD allowlist member) also appends one entry to `manifest.Overrides.Accepted` (`kind`, `subject`, `host`, `reason`, `owner`, `time`) through `Host.UpdateOverrides`; Task 1 adds that one list to W1's `Overrides` if W1 Task 11a did not. The controller's one writer goroutine applies the command events to its own table (`hunt_finding`: `open`/`acked` with an `outcome`). `integrity` and `ad` keep no accept table. Findings use the alert open/ack state.
7. **Per-host ledger composition needs the agent `fetch` handler (bug 4, W11).** Until then the ledger ships with the release and the controller side holds only the tables and the accept path (`shortcut` in Task 18).
8. **The sshsig namespace is `phylax-release`.** The design does not name one. Verify with `ssh-keygen -Y verify -f allowed_signers -I release -n phylax-release -s <file>.sig < <file>`.
9. **The two socket cross-checks wait on W3's `internal/sockets`.** Task 16 runs after W3's seams merge; every other task needs only W1.
10. **`internal/collect/winevt/gpo.go` stays with `winevt`** (W3 moves it); `ad` consumes the fields it derives.
11. **Hunt artifacts travel as one JSON step output capped at 256 KiB** (`shortcut: no chunked transfer until the agent fetch handler exists, W11`). The file inventory is not part of `hunt.baseline_diff`; the ledger sweep covers hashes.
12. **S1-S4 (2026-11-06) remove mechanisms this plan used to build.** No module here has an alert-to-act ladder, rule mode, loop or rate guard: `detect` only alerts, and an action runs as a plan node or a `respond` recipe whose reach is the template's engine setting `autonomy: propose|shadow|auto` with the engine's one attempt ledger keyed by (host, object, kind) (hardening packs carry `PackTarget.Autonomy`; the `ad.gpo_unlink` template carries its own; the four module blocks carry no `act_enabled`). The special-case actions are not built: `binary.restore_from_depot` is `file.restore{source: depot}` (Task 13), `unit.disable` and `unit.mask` are `service.state{state: disabled|masked}` (Task 21), `kernel.module_block` is `file.write` plus a `command.check` node in the bundle (Task 24), `windows.smb1`, `mssql.audit` and `mssql.lock` are `registry.set` and `sql.query` content (Task 37), and `collect.hunt` does not exist because `inventory` is core and the hunt diffs its rows (Task 30). The one file hasher is the integrity identity cache, moved to `internal/integrity/format` so `audit` and `content_guard` can import it (Task 2).

## Global Constraints

- Go 1.27.2 via mise; `CGO_ENABLED=0` for builds, `CGO_ENABLED=1` for `-race`; `make build build-windows vet test race` passes at every commit (linux/amd64 and windows/amd64 both build and vet).
- Every package ships tests; tests exercise the real code (no mocking of the code under test, no tautological asserts). A test that needs privileges, containers, network or a tool calls `t.Skip` with a reason string.
- Commits are small, one logical change, message `area: summary` (for example `integrity: typed verdict events`). No attribution lines of any kind.
- No shelling out in the default path (native Go calls: `/proc`, `/sys`, netlink, the registry, COM, ADSI). Tests may run `ssh-keygen`, `go list`.
- Bounded everything: queues, buffers, decoded sizes, directory walks, timeouts. Atomic writes through `internal/atomicfile` for state files.
- No compatibility shims, aliases or dual formats; renamed things are renamed everywhere in the same commit.
- A module imports only the core packages (`internal/event`, `internal/module`, `internal/agent`, `internal/link`, `internal/plan`, `internal/actions`, `internal/store`, `internal/manifest`, `internal/manifest/render`, `internal/deadman`, `internal/ui`, `internal/vault`, and, by decision 3, `plans`) and the shared libraries (`internal/atomicfile`, `internal/parsers/...`, `internal/checks/probe`, `internal/sockets`, `internal/signing`, `internal/integrity/format`, `internal/inventory/fold`). `internal/enroll` is never importable by a module.
- Times stored in UTC. Secrets never appear in events, logs, plan output or config files.
- `integrity` is alert-only: nothing in it writes, quarantines or restores a file by itself. `hunt` never deletes: disable and quarantine, `chattr -i` applied explicitly and logged first. Scored state is refused by every new action's `Touches` and the scoring-safety lint.
- The design is authoritative; a forced design change edits `phylax_design.md` in the same commit with the reason.
- None of the four modules acts on its own, so none has `act_enabled` in its block (conformance rejects the key). Per-module `rate_per_sec` and `burst` default from the manifest; the settings structs embed `ModuleLimits` only to allow an override.
- Code style ponytail: the smallest complete change; a known limit carries `// shortcut: <limit>, <when to upgrade>`.
- Branch `v4-integrity-hunting`, cut from `v4` after W1 merges.

## Review Focus

1. **Ledger absent, unsigned or mismatching at agent start.** Expected: `degraded`, one `telemetry_gap{source: integrity, reason: ledger_unavailable}`, a retry every 30 s, recovery when the file appears; never a crash and never a verdict judged against an empty ledger (Task 8 `TestLedgerAbsentThenAppears`).
2. **Malformed or hostile sshsig input** (wrong namespace, hash algorithm `sha256`, an RSA key blob, trailing bytes, a truncated blob, a ledger signature given to the release verifier). Expected: a typed error, never a panic, never acceptance (Task 5 `TestSSHSigRejectsMalformed`).
3. **Hunt on a host whose OS has no baseline.** Expected: collected, not diffed, health `degraded` with the gap "no reference for this OS version", no findings invented (Task 34 `TestNoBaselineDegradesNotDiffs`).
4. **The kernel-module block for a module compiled into the kernel** (Known bug 1). Expected: the bundle's `command.check{probe: af_alg_aead}` node fails while the aead socket still opens and says "built in"; the bundle never reports Copy Fail mitigated (Task 24 `TestAFAlgProbeFailsWhenSocketOpens`, Task 40 `TestLocalRootBundleChecksAFAlgAfterWrite`).
5. **Remediation or GPO unlink that would touch scored state.** Expected: the hunt disables the remediation button for a scored service's own unit (Task 35 `TestRemediationRefusedForScoredUnit`), and `ad.gpo_unlink` refuses a GPO a scored service's policy depends on (Task 43 `TestGPOUnlinkRefusesScoredDependency`).

---

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `internal/signing/` | `Signer`, `Verifier`, Ed25519 pair, `ErrBadSignature`, sshsig sign and verify | 2, 4, 5 |
| `internal/integrity/format/` | ledger, verdict logic, on-disk format, deb/rpm/host-db/Winbindex readers, the shared file hasher (`hasher.go`, S4) | 2 |
| `internal/integrity/events.go` | the six `integrity.*` payload structs and `Declare` calls (the ledger-unavailable state is `telemetry_gap`) | 1, 6, 7 |
| `internal/integrity/module.go`, `health.go` | the agent module (moved out of `internal/agent/mods`), manifest, health | 8, 9 |
| `internal/integrity/{suid,crosscheck_*,pam}.go` | SUID sweep, rootkit cross-checks, PAM content checks | 10, 14-16 |
| `internal/integrity/actions.go` | `ledger.sweep`, `ledger.verify_pin`, `yara.scan` (the depot restore is the core `file.restore{source: depot}`, Task 13) | 12 |
| `internal/integrity/controller.go`, `ui.go` | controller side: `ledger_entry` table and writer, Integrity page; an accept is one overrides entry | 18 |
| `cmd/phylax/ledger.go` | `phylax ledger build`, `lookup` | 17 |
| `rules/yara/` | UCF corpus, `LICENSE`, `ATTRIBUTION.md`, `skipped.txt` | 20 |
| `internal/actions/{unit_cleanup,runkey,task_cleanup,mount,selinux,hosts_file}*.go` | `service.state` disabled and masked, `ld_preload.clear`, `caps.clear`, `pkg.unhold`, `task.disable`, `wmi.subscription_remove`, `runkey.remove`, `registry.snapshot`, `file.restore{source: depot}`, `mount.remount`, `selinux.restore`, `hosts.file` | 13, 21-25 |
| `internal/hunt/` | artifact model, collectors, diff, score, controller module, UI | 27-36 |
| `hunt/` | `checks/*.yml`, `killlist.yml`, `heuristics.yml`, `baselines/` | 28-32, 36 |
| `plans/hardening/`, `plans/hunt/`, `plans/ad/` | pack library and hunt and AD plans | 37-40, 36, 43 |
| `internal/hardening/` | controller module, template validator health, lint rules `HD001`, `HD002` | 26, 38 |
| `internal/ad/` | moved `ad.*` actions, `ADBackend` reads, checks, path query, GPO, SDDL, Recycle Bin, agent and controller module | 3, 41-47 |
| `ad/checks.yml`, `ad/service_sddl.yml` | AD check definitions, default service descriptors | 42, 44 |
| `docs/impl/lab/w5-integrity-hunting.md` | lab record | 48 |

---

### Task 1: Seams (Sonnet or Opus)

Done by a stronger model. Writes every exported type, interface and signature named in Tasks 2 to 47 with stub bodies, declares the event kinds, registers the module skeletons, adds the settings fields, writes the skipped tests, and applies the design edits. Merges on its own with Tasks 2 and 3 (one pull request or three, in order) so W11 can start from `internal/signing` and `internal/integrity/format`.

**Files:**
- Create: `internal/integrity/events.go`, `internal/hunt/{events.go,doc.go,module.go}`, `internal/ad/{events.go,doc.go,module.go}`, `internal/hardening/module.go`, `internal/agent/mods/{hunt.go,ad.go}`
- Create: every test file named in Tasks 4 to 47 with its Step 1 test functions, each starting `t.Skip("unimplemented: W5 Task N")`
- Modify: `internal/plan/agentconfig.go` (`ModuleSettings.Hunt *HuntSettings`, `ModuleSettings.AD *ADSettings`, `IntegritySettings` new fields), `internal/module/conformance/allowed.go` (`ModulePackages` entries for the four modules), `internal/module/all/all.go`, `internal/manifest` (`Overrides.Accepted []Accepted`, only if W1 Task 11a did not add it: decision 6), `phylax_design.md` (decision 7's `shortcut` only; the accept and decision path has been in the design since S4, and decisions 1 to 4 and 8 were applied in the consistency pass)
- Modify (zero-value-safe): nothing else

**Interfaces:**
- Consumes: W1's `event.Declare`, `event.Type`, `module.Manifest`, `module.Register`, `module.ControllerModule`, `module.Common`, `agent.Factory`, `plan.ModuleLimits`, `event.TelemetryGap`, the core `operator.edit` kind, `Host.UpdateOverrides`, `actions.Register`, `actions.RegisterUndo` (W1 Task 2a), `plans.Template.Module` and `CoreImports` with `plans` (W1 Tasks 1 and 22b).
- Produces (exact; later tasks use these):

```go
// ---- internal/integrity/events.go ----
package integrity

const (
	KindVerdict           = "integrity.verdict"
	KindPin               = "integrity.pin"
	KindSweepDone         = "integrity.sweep_done"
	KindYara              = "integrity.yara"
	KindCrosscheck        = "integrity.crosscheck"
	KindClaims            = "integrity.claims"
)
// The ledger-unavailable state is not a kind of its own (S4): the module emits event.TelemetryGap{Source: "integrity", Reason: "ledger_unavailable", Detail: "<module> <path>: <error>"} and reports the same state in Health.

// One struct per kind; json tags are the snake_case field names of the design's "Events" table.
// VerdictEvent has one field per key checker.go:224-316 and entryFields write today, plus FirstSweep bool `json:"first_sweep,omitempty"`.
type VerdictEvent struct {
	Path, SHA256 string; Size int64; Verdict, Trigger string; Root, Escalate bool
	PID, PPID int; UID *int; Process, Service string; Flags []string
	ExpectedSHA256, Source, Package, Version, ExpectedSigner, Signer, BadLabel string
	HintOnly bool; HashKnownAt []string; Note string
	RunningSHA256, DiskSHA256, RunningTarget, Library string
	FirstSweep bool
	// remaining keys: see checker.go; every key the emitter writes today has a field
}
type PinEvent struct {
	Host, Service, Path, SHA256, Verdict string; Pinned bool; RunningSHA256 string
}
type SweepDone struct {
	Host string; Sweep string; FirstSweep bool; Files, Verdicts int; DurationMS int64
}
type YaraEvent struct {
	Rule string; Tags []string; Target string; PID int
	Strings []YaraString; Meta map[string]string
}
type YaraString struct{ ID string; Count int; Offset int64 }
type CrosscheckEvent struct {
	Check, Finding, Detail string; PID int; Module, Path string
}
type ClaimsEvent struct{ Packages []PackageClaim }
type PackageClaim struct{ Name, Version string }

func Manifest() module.Manifest // Name "integrity", Sides agent+controller, Privilege root, Default true,
	// Consumes: process_start, winevt.sec_event, file_change, telemetry_gap,
	// Emits: the six kinds and telemetry_gap, Budget {CPUMillisPerSec 8, HeldMB 24, EventsPerSec 2, Burst 20, BytesOutPerMin 100<<10, DiskMB 100},
	// Tables ledger_entry (an accept is one overrides entry, no table), Actions ledger.sweep, ledger.verify_pin, yara.scan,
	// Content ledger/, rules/yara/, Pages /integrity

// ---- internal/hunt/events.go ----
package hunt

const (KindFinding = "hunt.finding"; KindRun = "hunt.run")
type ArtifactRef struct{ Kind, Key string }
type FindingEvent struct {
	ID, Host string; Artifact ArtifactRef; Score, Reason string
	Enrichment map[string]string; Reference, State string
}
type RunEvent struct {
	Host, Trigger string; Collected, Added, Modified, Missing int; DurationMS int64
}
// Artifact is the unit of collection, diff and baseline.
type Artifact struct {
	Kind  string            `json:"kind"`  // cron | unit | timer | runkey | service | task | account | suid | cap | module | listener | file | ...
	Key   string            `json:"key"`   // stable identity within the kind (path, unit name, key\value)
	Attrs map[string]string `json:"attrs,omitempty"`
}
type Collection struct {
	OS        string     `json:"os"`
	Artifacts []Artifact `json:"artifacts"`
	Truncated bool       `json:"truncated,omitempty"`
	Errors    []string   `json:"errors,omitempty"`
}
const MaxCollectionBytes = 256 << 10 // shortcut: one step output, no chunking until the agent fetch handler exists (W11)
func Manifest() module.Manifest // Name "hunt", Sides agent+controller, Privilege root, Default true,
	// Consumes integrity.crosscheck, integrity.verdict, backup.restored, agent.enrolled, agent.reenrolled, plan.failed, ad.finding, inventory.snapshot, inventory.row;
	// Emits hunt.finding, hunt.run; Budget {5, 16, 2, 40, 200<<10, 20}; Tables hunt_finding; Pages /hunts;
	// Actions hunt.baseline_diff hunt.persistence hunt.apps hunt.creds hunt.remote_access (collect.files is a core Collection action: Task 27 registers it from this package until core has it, and it is not in the manifest's Actions)
type Config struct { // controller block modules/hunt.yml
	module.Common     `yaml:",inline"`
	RepeatIntervalSec int      `yaml:"repeat_interval_sec"`
	Baselines         []string `yaml:"baselines"`
	Apps              []string `yaml:"apps"`
	KillList          string   `yaml:"kill_list"`
	AllowedManagementAgents []string `yaml:"allowed_management_agents"`
	Triage            struct{ FirstSweepUnknowns string `yaml:"first_sweep_unknowns"` } `yaml:"triage"`
	Creds             struct{ ADDescriptions bool `yaml:"ad_descriptions"` } `yaml:"creds"`
}

// ---- internal/plan/agentconfig.go ----
type HuntSettings struct {
	ModuleLimits
	RepeatIntervalSec int      `json:"repeat_interval_sec,omitempty"`
	Apps              []string `json:"apps,omitempty"`
	KillList          []string `json:"kill_list,omitempty"`
	AllowedAgents     []string `json:"allowed_management_agents,omitempty"`
	CredPatterns      []string `json:"cred_patterns,omitempty"`
}
type ADSettings struct {
	ModuleLimits
	CheckIntervalSec int                 `json:"check_interval_sec,omitempty"`
	PrivilegedAllow  map[string][]string `json:"privileged_allow,omitempty"`
	Groups           []string            `json:"groups,omitempty"`
	PathQuery        struct{ Enabled bool `json:"enabled"`; MaxDepth int `json:"max_depth,omitempty"` } `json:"path_query"`
	GPO              struct{ Baseline string `json:"baseline,omitempty"` } `json:"gpo"` // the response is the ad.gpo_unlink template's autonomy (S1), not a setting here
	RecycleBin       string   `json:"recycle_bin,omitempty"` // auto (default) | off
	KrbtgtGapMinutes int      `json:"krbtgt_gap_minutes,omitempty"`
	ServiceRepair    []string `json:"service_repair,omitempty"`
}
// IntegritySettings gains, exactly as the design lists: MapsIntervalSec, SuidIntervalSec int; FullRehashEvery int; BytesPerSec int64;
// SuppressSec int; Signers []string; CrosscheckIntervalSec int; Yara YaraSettings.
type YaraSettings struct {
	Files  YaraTarget `json:"files"`
	Memory YaraTarget `json:"memory"`
	Engine string     `json:"engine,omitempty"` // go (default) | yarax
	Dir    string     `json:"dir,omitempty"`    // corpus directory, default <state dir>/yara
}
type YaraTarget struct {
	Enabled bool `json:"enabled"`; IntervalSec int `json:"interval_sec,omitempty"`
	Roots []string `json:"roots,omitempty"`; CPUBudgetMSPerSec int `json:"cpu_budget_ms_per_sec,omitempty"`
}

// ---- internal/ad/events.go ----
const (KindFinding = "ad.finding"; KindGPOFinding = "ad.gpo_finding"; KindGPOBaseline = "ad.gpo_baseline"; KindRecycleRestored = "ad.recycle_restored")
type FindingEvent struct {
	Check, Severity, Object, Detail, Expected string; Path []PathStep; WhenCreated string
}
type PathStep struct{ Principal, Edge, Target string }
type GPOFinding struct {
	GPOGUID, Name, Change, Section, Item string; Enforced bool; Affects string; BaselineHash, CurrentHash string
}
type GPOBaseline struct {
	Count int; Domain, TakenAt string; GPOs []GPORecord
}
type GPORecord struct{ GUID, Name string; Version int; Hash string }
type RecycleRestored struct{ DN, SID string; Scored bool; RestoredByRule string; Verified bool }
func Manifest() module.Manifest // Name "ad", Sides agent+controller, OS windows, Privilege root, Roles domain_controller/controller, Default true;
	// Consumes winevt.sec_event, file_change, process_start, hunt.run, integrity.sweep_done, ad.gpo_finding;
	// Emits the four kinds (decision 2); Budget {3, 8, 1, 20, 50<<10, 20}; Content ad/checks.yml, ad/service_sddl.yml, plans/hardening/dc.service_repair.yaml, plans/ad/; Pages /ad

// ---- internal/hardening/module.go ----
type Config struct {
	module.Common `yaml:",inline"`
	Packs         []PackTarget `yaml:"packs"`
	NoexecTemp    struct{ Hosts []string `yaml:"hosts"`; Paths []string `yaml:"paths"` } `yaml:"noexec_temp"`
	Banner        struct{ TextRef string `yaml:"text_ref"` } `yaml:"banner"`
	PasswordPolicy struct{ ValuesRef string `yaml:"values_ref"` } `yaml:"password_policy"`
	RebootClass   []string `yaml:"reboot_class"`
}
type PackTarget struct{ Pack, Target, Autonomy string } // Autonomy: propose | shadow | auto; empty means auto for a pack without a reboot-class gate, propose otherwise (S1)
func Manifest() module.Manifest // Name "hardening", Sides controller, Privilege none, Default true,
	// Consumes nothing from the bus (HD002 reads the sysmon entry of the host's Health.Info), no Emits, Actions splunk.rest splunk.password, Content plans/hardening, Pages /plans

// ---- internal/actions: Register and RegisterUndo are W1 Task 2a's; nothing to write here ----
```

- [ ] **Step 1: Write the stubs.** Types and constants exactly as above (the full `VerdictEvent` from the emitter's keys). `Declare` calls in each package `init` with schema 1 and the priorities in the design's Events tables (`integrity.verdict` high, `integrity.yara` critical, `integrity.crosscheck` high, `integrity.pin`, `integrity.sweep_done`, `integrity.claims` normal; `hunt.finding` high, `hunt.run` normal; `ad.finding` high, `ad.gpo_finding` high, `ad.gpo_baseline` normal, `ad.recycle_restored` high). Register the three controller modules with `module.Register` (stub `Start` waits for ctx and reports `unavailable` with gap `{"module", "not built (W5)"}`; none declares `act_enabled`), the two new agent factories (`hunt`, `ad`) with `Manifest` set, and add `integrity.Manifest()` to the existing `integrity` factory. Add all four names to `ModulePackages`; do not remove anything from `PreContract` yet (each module's conformance task does). Function bodies: `panic("unimplemented: W5 Task N")` naming the implementing task.
- [ ] **Step 2: Write the skipped tests.** For each of Tasks 4 to 47, create the test file the task names with the Step 1 test functions, each starting `t.Skip("unimplemented: W5 Task N")`. Write for real the helpers they call: `internal/integrity/testhelpers_test.go` (`fakeProc(t, tree map[string]string) string` builds a fake `/proc` or `/sys` tree), `internal/hunt/testhelpers_test.go` (`fixtureCollection`), `internal/ad/fake_test.go` (the fake `ADBackend` copied from `ad_accounts_test.go`, extended in Task 41).
- [ ] **Step 3: Apply the remaining design edit** (decision 7: the `shortcut` for the ledger composition). Decision 6 (accepts and decisions as operator command events plus one overrides entry) is in the design since S4. Decisions 1 to 4 and 8 (`registry.set`/`registry.delete`/`registry.snapshot`, `ad.recycle_restored` in Emits, `plans` and `actions.Register` in the core package list, the sshsig namespace) are already in the design.
- [ ] **Step 4: Verify.** Run: `make build build-windows vet test race`. Expected: all pass. Then `go test -v ./internal/... ./plans/ 2>&1 | grep -c 'unimplemented: W5 Task'`. Expected: a count equal to the number of skipped tests written in Step 2 (no stub panics).
- [ ] **Step 5: Commit.**

```bash
git add internal plans docs phylax_design.md
git commit -m "integrity: W5 seams (kinds, module skeletons, settings, design edits)"
```

---

### Task 2: Seams: `internal/signing` and `internal/integrity/format` (Sonnet or Opus)

Mechanical moves. W11 starts from this task.

**Files:**
- Create: `internal/signing/{signing.go,ed25519.go,sshsig.go}`, `internal/signing/signing_test.go`
- Move (`git mv`): `internal/integrity/{ledger.go,verdict.go,format.go,deb.go,rpm.go,decompress.go,hostdb.go,winbindex.go,pathutil.go}` and their tests (`ledger_test.go`, the format and package tests in `fixtures_test.go`) → `internal/integrity/format/`; `package format`. Also `internal/integrity/cache.go` (the identity cache: device, inode, ctime, size, with a periodic full re-hash) → `internal/integrity/format/hasher.go`, exported as the one shared file hasher (S4): `audit`'s hash sweep (W3), `content_guard`'s golden hashes (W4) and the SUID sweep (Task 10) hash through it, and it sits in `format` because modules may import that shared library but not a sibling module
- Modify: `internal/integrity/{checker,pin,sweep,maps,yara,signature}*.go` (qualify moved names), `internal/agent/mods/integrity*.go`, `internal/depot/{manifest,pack,deploy}.go` and `depot_test.go`, `cmd/phylax/depot.go` (use `signing.Signer`, `signing.Verifier`, `signing.Ed25519Signer`, `signing.Ed25519Verifier`, `signing.ErrBadSignature`)
- Delete: the old paths (no shims)

**Interfaces:**
- Consumes: nothing new.
- Produces:

```go
// ---- internal/signing ----
package signing

type Signer interface{ Sign(msg []byte) ([]byte, error) }
type Verifier interface{ Verify(msg, sig []byte) error }

type Ed25519Signer struct{ Key ed25519.PrivateKey }   // moved from integrity, same behaviour
type Ed25519Verifier struct{ Key ed25519.PublicKey }  // moved
var ErrBadSignature = errors.New("signing: signature invalid") // moved (message text updated)

const ReleaseNamespace = "phylax-release"
// sshsig: the format ssh-keygen -Y sign / -Y verify use. Implemented in Tasks 4 and 5.
type SSHSigner struct{ Key ed25519.PrivateKey; Namespace string } // Namespace "" means ReleaseNamespace
func (s SSHSigner) Sign(msg []byte) ([]byte, error)              // armored signature
type SSHVerifier struct{ Key ed25519.PublicKey; Namespace string }
func (v SSHVerifier) Verify(msg, sig []byte) error
func AllowedSignersLine(pub ed25519.PublicKey, principal string) string // "<principal> namespaces=\"phylax-release\" ssh-ed25519 <base64>"

// ---- internal/integrity/format ---- (names unchanged from today's integrity package)
// Ledger, Entry, Sum, ParseSum, Meta, Source (+ constants), NewLedger, Builder, NewBuilder, NormalizePath,
// Verdict (+ constants Match ... SigInvalid), Result, Judger, Worse,
// Package, ReadDeb, ReadDebFile, ReadRPM, ReadRPMFile, ReadLimits, HostHints, ReadDpkgHints, ReadRPMDBHints,
// ImportWinbindex, WinbindexOptions, MaxLedgerBytes,
// Hasher (the shared file hasher, S4): func NewHasher(maxEntries int) *Hasher; func (h *Hasher) Hash(path string, full bool) (Sum, error) // full ignores the identity cache; func (h *Hasher) Stats() (hits, misses int),
// (*Ledger).Marshal(sg signing.Signer) ([]byte, error), func Unmarshal(data []byte, v signing.Verifier) (*Ledger, error)
```

- [ ] **Step 1: Write the failing test** (`internal/signing/signing_test.go`):

```go
func TestEd25519RoundTripAndReject(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sig, err := Ed25519Signer{Key: priv}.Sign([]byte("m"))
	if err != nil || (Ed25519Verifier{Key: pub}).Verify([]byte("m"), sig) != nil {
		t.Fatal("round trip")
	}
	if err := (Ed25519Verifier{Key: pub}).Verify([]byte("x"), sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
}
func TestHasherSkipsUnchangedFile(t *testing.T) { // internal/integrity/format/hasher_test.go, moved from the cache test
	h := NewHasher(16)
	p := writeTemp(t, "x")
	a, _ := h.Hash(p, false)
	b, _ := h.Hash(p, false)
	if a != b {
		t.Fatal("hash changed")
	}
	if hits, _ := h.Stats(); hits != 1 {
		t.Fatalf("hits %d", hits)
	}
	h.Hash(p, true)
	if hits, _ := h.Stats(); hits != 1 {
		t.Fatal("full re-hash must bypass the cache")
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/signing/ -v`. Expected: FAIL (package or symbols missing).
- [ ] **Step 3: Implement** the moves and the Ed25519 types; `SSHSigner`/`SSHVerifier`/`AllowedSignersLine` are stubs (`panic("unimplemented: W5 Task 4")`). Check `grep -rn 'integrity\.\(Signer\|Verifier\|Ed25519\|ErrBadSignature\|Ledger\|Entry\|Sum\|Verdict\|Package\|ReadDeb\|ReadRPM\)' --include='*.go' .` returns nothing outside `internal/integrity` itself.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS (the moved tests pass unchanged apart from package names).
- [ ] **Step 5: Commit.** `git commit -am "signing: extract Signer and Verifier; integrity/format: extract ledger, package readers and the shared hasher"`

---

### Task 3: Seams: move the `ad.*` actions to `internal/ad` (Sonnet or Opus)

**Files:**
- Move (`git mv`): `internal/actions/{ad_accounts.go,ad_accounts_test.go,ad_netlogon.go,ad_netlogon_test.go,ad_adsi_windows.go,deception_ad.go,deception_ad_windows.go}` → `internal/ad/`; `ad_backend.go` keeps `ADBackend`, `ADObject`, `ResolveMembers` in `internal/actions` (it is a seam interface like `RegistryStore`, and `actions.WinEnv.AD` uses it); the fake directory moves into `internal/ad/fake_test.go`
- Modify: `internal/actions/registry_deception.go` (drop `adHoneyAccount{}`), export the helpers the moved files used (`PathTouch`, `JSONUndo`, ...; list from the compiler), `internal/ad/module.go` (`init` calls `actions.Register(func() []actions.Action { ... })` with the existing ten `ad.*` actions plus `ad.honey_account`)
- Test: the moved tests pass in `internal/ad`

**Interfaces:**
- Consumes: `actions.Register`, `actions.Action`, `actions.Env`, `actions.ADBackend` (Task 1).
- Produces: action names unchanged (`ad.account.audit_groups`, `ad.account.admincount_sweep`, `ad.account.disable`, `ad.account.reset_password`, `ad.account.group_remove`, `ad.account.krbtgt_reset`, `ad.zerologon_check`, `ad.secure_channel`, `ad.dc.rpc_range`, `ad.honey_account`); `internal/actions` imports nothing from `internal/ad`; the agent and controller binaries import `internal/module/all`, which imports `internal/ad`, so `actions.Core()` still lists them.

- [ ] **Step 1: Write the failing test** (`internal/ad/actions_test.go`):

```go
func TestADActionsRegisteredThroughCore(t *testing.T) {
	reg := actions.Core()
	for _, n := range []string{"ad.account.audit_groups", "ad.account.krbtgt_reset", "ad.secure_channel", "ad.honey_account"} {
		if _, err := reg.Get(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/ad/ -run TestADActionsRegistered -v`. Expected: FAIL (`unknown action`).
- [ ] **Step 3: Implement** the moves. Run `go list -deps ./internal/actions | grep internal/ad` and expect no output.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "ad: move the ad.* actions to internal/ad"`

> After Tasks 1 to 3 merge, tell W11 its entry gate (W5 seams) holds.

---

### Task 4: sshsig signing

**Files:**
- Modify: `internal/signing/sshsig.go` (`SSHSigner.Sign`, `AllowedSignersLine`)
- Test: `internal/signing/sshsig_test.go`

**Interfaces:**
- Consumes: `SSHSigner`, `ReleaseNamespace` (Task 2).
- Produces: `func (s SSHSigner) Sign(msg []byte) ([]byte, error)`; `func AllowedSignersLine(pub ed25519.PublicKey, principal string) string`.

Wire format (fixed by OpenSSH `PROTOCOL.sshsig`): armor `-----BEGIN SSH SIGNATURE-----\n` + base64 of the blob in 70-column lines + `\n-----END SSH SIGNATURE-----\n`. Blob: raw `SSHSIG`, `uint32` version 1, `string` public key (`string "ssh-ed25519"`, `string key32`), `string` namespace, `string` reserved (empty), `string` hash algorithm `sha512`, `string` signature (`string "ssh-ed25519"`, `string sig64`). The signed data is raw `SSHSIG`, `string` namespace, `string` reserved, `string` hash algorithm, `string` `sha512(message)`. Every `string` is a big-endian `uint32` length then bytes.

- [ ] **Step 1: Write the failing test:**

```go
func TestSSHSigVerifiesWithSSHKeygen(t *testing.T) {
	kg, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	msg := []byte("release artifact bytes")
	os.WriteFile(filepath.Join(dir, "a.bin"), msg, 0o600)
	sig, err := SSHSigner{Key: priv}.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "a.sig"), sig, 0o600)
	os.WriteFile(filepath.Join(dir, "allowed"), []byte(AllowedSignersLine(pub, "release")+"\n"), 0o600)
	run := func(file string) error {
		c := exec.Command(kg, "-Y", "verify", "-f", "allowed", "-I", "release", "-n", ReleaseNamespace, "-s", "a.sig")
		c.Dir = dir
		in, _ := os.Open(filepath.Join(dir, file))
		defer in.Close()
		c.Stdin = in
		out, err := c.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	}
	if err := run("a.bin"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "b.bin"), []byte("tampered"), 0o600)
	if run("b.bin") == nil {
		t.Fatal("ssh-keygen accepted a tampered file")
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/signing/ -run TestSSHSigVerifiesWithSSHKeygen -v`. Expected: FAIL with `unimplemented: W5 Task 4`.
- [ ] **Step 3: Implement** both functions with `encoding/binary`, `crypto/sha512`, `encoding/base64`; the allowed-signers line uses `namespaces="phylax-release"` and the standard authorized-key base64 of the public key blob.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/signing/`. Expected: PASS (T76 first half).
- [ ] **Step 5: Commit.** `git commit -am "signing: sshsig signer verified by ssh-keygen"`

---

### Task 5: sshsig verification and domain separation

**Files:**
- Modify: `internal/signing/sshsig.go` (`SSHVerifier.Verify`)
- Test: `internal/signing/sshsig_verify_test.go`, `internal/plan/sshsig_isolation_test.go`

**Interfaces:**
- Consumes: `SSHVerifier`, `SSHSigner` (Tasks 2 and 4).
- Produces: `func (v SSHVerifier) Verify(msg, sig []byte) error` returning `ErrBadSignature` (wrapped with the reason) for any failure; bounded: refuses an armored input over 8 KiB.

- [ ] **Step 1: Write the failing tests:**

```go
func TestSSHSigVerifiesKeygenOutput(t *testing.T) {
	kg, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	run(t, dir, kg, "-q", "-t", "ed25519", "-N", "", "-f", "k")
	os.WriteFile(filepath.Join(dir, "f"), []byte("payload"), 0o600)
	run(t, dir, kg, "-Y", "sign", "-f", "k", "-n", ReleaseNamespace, "f")
	pubLine, _ := os.ReadFile(filepath.Join(dir, "k.pub"))
	pk, _, _, _, _ := ssh.ParseAuthorizedKey(pubLine)
	pub := pk.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	sig, _ := os.ReadFile(filepath.Join(dir, "f.sig"))
	if err := (SSHVerifier{Key: pub}).Verify([]byte("payload"), sig); err != nil {
		t.Fatal(err)
	}
	if err := (SSHVerifier{Key: pub}).Verify([]byte("payloaD"), sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestSSHSigRejectsMalformed(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	good, _ := SSHSigner{Key: priv}.Sign([]byte("m"))
	other, _, _ := ed25519.GenerateKey(nil)
	cases := map[string][]byte{
		"empty":           nil,
		"no armor":        []byte("garbage"),
		"truncated":       good[:len(good)/2],
		"trailing bytes":  append(append([]byte{}, good...), "x"...),
		"wrong namespace": mustSign(t, priv, "file", "m"),
		"sha256 hash alg": mustBlobWithHash(t, priv, "sha256", "m"),
		"too large":       bytes.Repeat([]byte("A"), 9<<10),
	}
	for name, sig := range cases {
		if err := (SSHVerifier{Key: pub}).Verify([]byte("m"), sig); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if (SSHVerifier{Key: other}).Verify([]byte("m"), good) == nil {
		t.Error("wrong key accepted")
	}
}

// internal/plan/sshsig_isolation_test.go
func TestConfigVerifierRejectsSSHSig(t *testing.T) {
	// build a signed AgentConfig as agentconfig_test.go does, replace link.Config's signature field with
	// SSHSigner{Key: priv}.Sign(configSigningBytes(canon)), and expect ConfigVerifier.Parse to return an error;
	// then sign normally and expect success.
}
```

`mustSign` and `mustBlobWithHash` are test helpers in the same file (`mustBlobWithHash` re-encodes the blob with another hash algorithm and signs accordingly).

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/signing/ ./internal/plan/ -run 'SSHSig|SSHVerif' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `Verify`: parse armor strictly (exactly one header and footer, no trailing data), decode the blob, require version 1, key type `ssh-ed25519`, key equal to `v.Key`, namespace equal to the verifier's (default `ReleaseNamespace`), reserved empty, hash algorithm `sha512`, and `ed25519.Verify` over the signed data of Task 4.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/signing/ ./internal/plan/ ./internal/depot/`. Expected: PASS (T76 second half).
- [ ] **Step 5: Commit.** `git commit -am "signing: sshsig verifier; plan signing rejects sshsig"`

---

### Task 6: Typed `integrity.verdict` and `integrity.yara` events

**Files:**
- Modify: `internal/integrity/checker.go` (`emit` builds `VerdictEvent` and calls `event.New`; `Config.Emit` stays `func(event.Event)`), `internal/integrity/yara.go` (`YaraSchedule.RunOnce` builds `YaraEvent`), `internal/integrity/events.go` (`Declare` calls become live), `internal/agent/mods/integrity.go`
- Test: `internal/integrity/events_test.go`; existing `checker_test.go` updated to read typed fields

**Interfaces:**
- Consumes: `event.New[T]`, `event.Decode[T]`, `event.Validate` (W1), the structs of Task 1.
- Produces: `Checker.emit` sets `Kind`, `Schema`, `Priority` (critical for `known_bad`, `mismatch` and any escalated verdict, high otherwise, as today) and `Fields` from `VerdictEvent`; `Agent` and `Time` as today. `D5d` and the `chains` hop builder (the former traceback) read `escalate`, `path`, `sha256`, `package`, `expected_sha256`, `signer`, `service`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestVerdictEventDecodesStrictly(t *testing.T) {
	var got []event.Event
	ck := newTestChecker(t, func(e event.Event) { got = append(got, e) }) // helper from checker_test.go
	// judge a path whose hash differs from the ledger entry (verdict mismatch) as root
	ck.CheckExec(ctx, ExecInfo{Path: "/usr/sbin/nologin", PID: 7, UID: 0})
	if len(got) != 1 || event.Validate(got[0]) != nil {
		t.Fatalf("%v", got)
	}
	v, err := event.Decode[VerdictEvent](got[0], KindVerdict)
	if err != nil || v.Verdict != "mismatch" || !v.Escalate || v.Trigger != "exec" || v.Path != "/usr/sbin/nologin" {
		t.Fatalf("%+v %v", v, err)
	}
	if got[0].Priority != event.PriorityCritical {
		t.Fatalf("priority %v", got[0].Priority)
	}
}
func TestYaraEventDeclared(t *testing.T) {
	if _, ok := event.Lookup(KindYara); !ok {
		t.Fatal("integrity.yara not declared")
	}
	// run a YaraSchedule over a temp file matching a one-rule corpus; the emitted event Validate()s and has Rule set
}
func TestIntegrityKindsMatchManifest(t *testing.T) {
	for _, et := range Manifest().Emits {
		if _, ok := event.Lookup(et.Kind); !ok {
			t.Errorf("%s emitted by the manifest but not declared", et.Kind)
		}
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/integrity/ -run 'VerdictEvent|YaraEvent|KindsMatch' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the conversion; replace `KindLedgerMissing` in `mods/integrity.go` with `event.New(event.TelemetryGap{Source: "integrity", Reason: "ledger_unavailable", ...})` (S4: no kind of its own). Update `internal/traceback/obs.go` (the within-host hop builder `chains` calls) and any rule that reads a renamed field name (there are none: the keys are unchanged); run `grep -rn '"integrity\.' --include='*.go' .` and expect only constants.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/integrity/ ./internal/agent/mods/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "integrity: typed verdict and yara events; ledger_unavailable as telemetry_gap"`

---

### Task 7: `integrity.pin`, `integrity.sweep_done`, `integrity.claims`, first-sweep marking

**Files:**
- Modify: `internal/integrity/{pin.go,sweep.go,checker.go}`, `internal/integrity/events.go`
- Create: `internal/integrity/claims.go`
- Test: `internal/integrity/pin_events_test.go`, `internal/integrity/sweep_events_test.go`

**Interfaces:**
- Consumes: `PinEvent`, `SweepDone`, `ClaimsEvent` (Task 1), `format.HostHints` (Task 2).
- Produces:

```go
// CheckPin emits integrity.pin when a pin is first verified and whenever its result changes (kept per path in the Checker).
func (c *Checker) CheckPin(ctx context.Context, p Pin) (PinResult, error) // behaviour extended
// SweepOptions gains FirstSweep bool: verdicts of an unknown, non-root-or-service executable carry FirstSweep (routed to the hunt triage queue by consumers).
// Sweep emits one integrity.sweep_done at the end: Host, Sweep id (UTC timestamp), FirstSweep, Files, Verdicts (count of non-match), DurationMS.
func (c *Checker) Sweep(ctx context.Context, opt SweepOptions) (SweepStats, error)
func ClaimsFromHints(h *format.HostHints) ClaimsEvent // sorted, bounded to 2000 packages
```

- [ ] **Step 1: Write the failing tests:**

```go
func TestPinEventOnlyOnChange(t *testing.T) {
	// two CheckPin calls on an unchanged matching pin -> exactly one integrity.pin (verdict "match", pinned true);
	// replace the file on disk, CheckPin again -> a second integrity.pin with the alerting verdict
}
func TestSweepDoneAndFirstSweep(t *testing.T) {
	// a fake root with one ledger-known file and one unknown non-root file; Sweep(opt{FirstSweep:true})
	// -> one integrity.sweep_done with FirstSweep true, Files 2, Verdicts 1; the unknown's verdict event has FirstSweep true
	// the same sweep with FirstSweep false -> the unknown's verdict has FirstSweep false
}
func TestFirstSweepMismatchStillAlerts(t *testing.T) {
	// a mismatch during a FirstSweep keeps priority critical and Escalate true: only unknowns are triaged
}
func TestClaimsBounded(t *testing.T) {
	// hints with 5000 packages -> ClaimsFromHints returns 2000, sorted by name
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/integrity/ -run 'PinEvent|SweepDone|FirstSweep|ClaimsBounded' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The first-sweep marker lives in the module (Task 8); here only the option and the flag.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/integrity/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "integrity: pin, sweep_done and claims events; first-sweep marking"`

---

### Task 8: Agent module on the contract (move, manifest, health, `Keep`)

**Files:**
- Create: `internal/integrity/module.go` (the `integrityModule` body moved from `internal/agent/mods/integrity.go`), `internal/integrity/health.go`
- Modify: `internal/agent/mods/integrity.go` (registration only), `internal/module/conformance/allowed.go` (remove `integrity` from `PreContract`)
- Create: `internal/integrity/conformance_test.go`, `manifest/schema/modules/integrity.schema.json` (via `-update`), `manifest/2027/modules/integrity.yml`
- Test: `internal/integrity/module_test.go`, `internal/integrity/conformance_test.go`

**Interfaces:**
- Consumes: `agent.Env`, `agent.Emit`, `agent.HealthReporter`, `module.Health`, `conformance.Agent`, `plan.IntegritySettings`.
- Produces:

```go
type Module struct{ /* env, settings, mutex-guarded health, ledger-retry override for tests */ }
func NewModule(env agent.Env, s *plan.IntegritySettings) *Module
func (*Module) Name() string                                    // "integrity"
func (m *Module) Start(ctx context.Context, emit agent.Emit) error
func (m *Module) Health() module.Health
```

`Health`: `ok` with the ledger loaded and hash matching (`Info`: `ledger_entries`, `ledger_os`, `last_sweep`); `degraded` while the ledger is absent, mismatching or unsigned (gap `{"ledger", <error>}`), when a sweep root could not be read (gap `{"sweep_root", path}`) or when `GoScanner` skipped rules (gap names). The identity cache is stored with `env.Keep("integrity.cache", ...)` and recovered with `env.Kept`, so a reconfigure that changes the ledger hash replaces the ledger without re-hashing everything. The first-sweep marker is the file `<StateDir>/integrity.first_sweep_done` written atomically after the first completed sweep; its absence means `SweepOptions.FirstSweep = true`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestIntegrityConformance(t *testing.T) {
	conformance.Agent(t, conformance.AgentCase{
		Factory: factoryNamed(t, "integrity"), // from agent.Registered()
		Default: cfgWithLedger(t, 900), Reconfig: cfgWithLedger(t, 600),
		KeepKey: "integrity.cache", Load: someExecLoad(), // helpers in module_test.go: write a signed ledger into the harness state dir
	})
}
func TestLedgerAbsentThenAppears(t *testing.T) {
	h := newHarnessNoLedger(t)
	h.Run(ctx)
	waitFor(t, func() bool { st, _ := h.Health("integrity"); return st.State == module.StateDegraded })
	if n := countGap(h.Emitted(), "ledger_unavailable"); n != 1 { // telemetry_gap with that reason
		t.Fatalf("emitted %d", n)
	}
	writeSignedLedger(t, h.StateDir()) // retry interval is 20 ms in the test
	waitFor(t, func() bool { st, _ := h.Health("integrity"); return st.State == module.StateOK })
	if n := countGap(h.Emitted(), "ledger_unavailable"); n != 1 {
		t.Fatalf("must not re-emit while retrying: %d", n)
	}
}
func TestLedgerHashMismatchDegrades(t *testing.T) { /* signed config pins another sha256 -> degraded with gap ledger */ }
func TestFirstSweepMarkerWrittenOnce(t *testing.T) { /* first sweep has FirstSweep true and writes the marker; a restarted module sweeps with false */ }
func TestIntegrityManifestMatchesFactory(t *testing.T) {
	f := factoryNamed(t, "integrity")
	if f.Manifest.Name != "integrity" || f.Manifest.Budget.HeldMB != 24 {
		t.Fatalf("%+v", f.Manifest)
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/integrity/ -run 'Conformance|LedgerAbsent|HashMismatch|FirstSweepMarker|ManifestMatches' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the move (behaviour kept; `mods/integrity.go` keeps only `agent.RegisterFactory(Factory{Name, Manifest: integrity.Manifest(), Section, Build})`), `Health`, `Keep`/`Kept`, the marker. Generate the JSON Schema with `go test ./internal/module/all/ -run Schema -update`. Write `manifest/2027/modules/integrity.yml` exactly as the design's Configuration block.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/integrity/ ./internal/agent/... ./internal/module/...`. Expected: PASS, including `TestPreContractShrinks` and `TestNoSiblingImports` with `integrity` as a contract module.
- [ ] **Step 5: Commit.** `git commit -am "integrity: agent module on the contract"`

---

### Task 9: Signers, host hints and the remaining settings

**Files:**
- Modify: `internal/integrity/module.go`, `internal/integrity/maps.go` (add the loop entry `(*Checker).CheckLibraries(ctx, pids []int)` if the built function takes one pid), `internal/agent/mods/integrity.go`
- Test: `internal/integrity/module_settings_test.go`

**Interfaces:**
- Consumes: `plan.IntegritySettings` new fields, `format.ReadDpkgHints`, `format.ReadRPMDBHints`, `SignerAllowlist`.
- Produces: the module passes `Allowlist: SignerAllowlist(s.Signers)`, `Hints` (dpkg `/var/lib/dpkg` or `rpmdb.sqlite` per distro, nil when neither exists), `Suppress: time.Duration(s.SuppressSec)*time.Second`, sweep `BytesPerSec: s.BytesPerSec` (default `32<<20`), the full re-hash every `s.FullRehashEvery` sweeps (default 10), a maps loop every `s.MapsIntervalSec` (default 60) over service processes (pids whose exe is a pinned path), and emits `integrity.claims` once after the ledger loads and after each package-database change (hash of the status file).

- [ ] **Step 1: Write the failing tests:**

```go
func TestSignerAllowlistAcceptsKnownSigner(t *testing.T) { /* settings Signers ["Splunk Inc."]; a fake SignatureVerifier returns valid+that signer for an unknown path -> verdict match with the signer in the note */ }
func TestHintOnlyIsUnknown(t *testing.T)               { /* a dpkg status/md5sums fixture lists the file; the ledger lacks it -> verdict unknown with HintOnly true, never match */ }
func TestFullRehashEveryN(t *testing.T)                { /* FullRehashEvery 3: sweeps 3 and 6 bypass the identity cache (CacheStats hits drop to 0) */ }
func TestMapsLoopFlagsDeletedLibrary(t *testing.T)     { /* fake ProcRoot with a pinned service pid whose maps list "/tmp/x.so (deleted)" -> a verdict with Library set and trigger "library" */ }
func TestClaimsEmittedAfterLedgerLoads(t *testing.T)   { /* one integrity.claims event listing the fixture packages */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/integrity/ -run 'SignerAllowlist|HintOnly|FullRehash|MapsLoop|ClaimsEmitted' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** This closes the two `shortcut` notes in the design ("passes no signer allowlist and no host-hint reader"); remove them from the design in the same commit.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/integrity/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "integrity: signer allowlist, host hints, maps loop and sweep settings wired"`

---

### Task 10: SUID and SGID sweep

**Files:**
- Create: `internal/integrity/suid.go`, `internal/integrity/suid_other.go`
- Modify: `internal/integrity/module.go` (loop on `SuidIntervalSec`, default 300)
- Test: `internal/integrity/suid_test.go`

**Interfaces:**
- Consumes: `Checker.HashFile` (it hashes through `format.Hasher`, the one shared file hasher, S4: no second walk-and-hash and no private cache), `format.Ledger.Judge`.
- Produces:

```go
// SuidSweep walks roots (default DefaultSweepRoots plus /home, /tmp, /var/tmp), hashes files with the setuid or setgid bit,
// judges them, and emits an integrity.verdict (trigger "sweep", flags ["new_suid"] or ["suid_hash_changed"]) for a SUID file not seen
// on the previous sweep, a changed hash, or any alerting verdict. prev is the identity map from the last run (kept with env.Keep).
func (c *Checker) SuidSweep(ctx context.Context, roots []string, prev map[string]string) (cur map[string]string, err error)
```

Windows build: `suid_other.go` returns `nil, ErrUnsupported`; the module does not start the loop there.

- [ ] **Step 1: Write the failing tests:**

```go
func TestSuidSweepFindsNewSuid(t *testing.T) {
	root := t.TempDir()
	f := writeExec(t, root, "bin/su", "ledger-known")
	os.Chmod(f, 0o4755)
	cur, _ := ck.SuidSweep(ctx, []string{root}, nil)                 // first run: baseline, known hash -> no alert
	g := writeExec(t, root, "bin/pwn", "not in ledger")
	os.Chmod(g, 0o4755)
	_, _ = ck.SuidSweep(ctx, []string{root}, cur)
	// want one verdict event for bin/pwn with flags containing "new_suid" and trigger "sweep"
}
func TestSuidHashChangeAlerts(t *testing.T) { /* rewrite bin/su content, keep the bit -> flags suid_hash_changed, verdict mismatch */ }
func TestSuidSweepIgnoresPlainFiles(t *testing.T) { /* 0755 file not reported */ }
func TestSuidSweepUsesSharedHasher(t *testing.T) { /* two sweeps over an unchanged SUID file: Hasher.Stats hits grows, the file is hashed once (S4) */ }
```

(`Copy Fail` control: [[cert-cc-vulnerability-note-vu-260001#e2]]; FIM cannot see the page-cache write, so the hash sweep is the catch.)

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/integrity/ -run Suid -v`. Expected: FAIL.
- [ ] **Step 3: Implement** with a bounded walk (`MaxFiles` 200000, symlinks not followed, one filesystem boundary check skipped: `shortcut: crosses mounts, upgrade if the lab shows network mounts in the roots`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/integrity/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "integrity: SUID and SGID hash sweep"`

---

### Task 11: YARA wiring and the Go-first engine choice

**Files:**
- Modify: `internal/integrity/module.go` (start `YaraSchedule` for files and memory per `Yara` settings), `internal/integrity/yara.go` (`YaraSchedule` takes `CPUBudgetMSPerSec` and pauses between items; dedupe by inode identity is built), `internal/integrity/health.go` (gap per skipped rule)
- Test: `internal/integrity/yara_module_test.go`

**Interfaces:**
- Consumes: `plan.YaraSettings` (Task 1), `LoadCorpusDir`, `GoScanner`, `Matcher.Skipped`.
- Produces: the module scans `Yara.Files.Roots` (default: webroots from pinned service paths, new binaries, `/tmp`, `/var/tmp`, `/dev/shm`) every `Files.IntervalSec` (default 300) and `/proc/<pid>/mem` of service processes every `Memory.IntervalSec`, at low priority; corpus from `Yara.Dir` (default `<state dir>/yara`); `engine: yarax` returns `unavailable` with gap "YARA-X not shipped" (`shortcut: pinned YARA-X binary comes from the depot; upgrade when the UCF load shows skipped rules, W11 delivers the binary`). `ErrCorpusNotBundled` is removed with the stub `BundledC2Corpus`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestYaraFilesScheduleEmitsMatch(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, filepath.Join(dir, "yara", "t.yar"), `rule T { strings: $a = "EVIL_MARKER" condition: $a }`)
	h := newHarnessWithYara(t, dir, plan.YaraSettings{Files: plan.YaraTarget{Enabled: true, IntervalSec: 1, Roots: []string{filepath.Join(dir, "web")}}})
	os.WriteFile(filepath.Join(dir, "web", "x.php"), []byte("<?php EVIL_MARKER"), 0o644)
	h.Run(ctx)
	waitFor(t, func() bool { return countKind(h.Emitted(), KindYara) >= 1 })
}
func TestYaraSkippedRulesDegradeHealth(t *testing.T) { /* a rule using an unsupported regex string -> Health gaps name the rule; state degraded */ }
func TestYaraMemoryScanFakeProc(t *testing.T)       { /* fake ProcRoot with mem file containing the marker -> match event with PID set */ }
func TestYaraDisabledByDefaultFilesOff(t *testing.T) { /* Files.Enabled false -> no schedule goroutine, no events */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/integrity/ -run Yara -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The 17-rule corpus arrives in Task 20; here the tests use fixture rules.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/integrity/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "integrity: YARA schedule wired into the module"`

---

### Task 12: Actions `ledger.sweep`, `ledger.verify_pin`, `yara.scan`

**Files:**
- Create: `internal/integrity/actions.go`
- Modify: `internal/integrity/module.go` (publish the running `*Checker` and `Matcher`)
- Test: `internal/integrity/actions_test.go`

**Interfaces:**
- Consumes: `actions.Register`, `actions.Action`, `actions.Spec`, `Checker.Sweep`, `Checker.CheckPin`.
- Produces: three read-only actions (`Spec.ReadOnly`, risk `none`, no locks, no touches), registered from `init`:

| Action | Params | Output |
| --- | --- | --- |
| `ledger.sweep` | `roots` (list), `full` (bool), `first_sweep` (bool) | `files`, `hashed`, `verdicts` (JSON of counts), `errors` |
| `ledger.verify_pin` | `path` (required) | `flags` (comma list), `verdict`, `running_sha256`, `disk_sha256` |
| `yara.scan` | `path` (required) | `matches` (JSON: rule, tags) |

`shortcut: the actions reach the running module through a package-level handle (one integrity module per process), upgrade if a second instance is ever needed.` With no running module, `Plan`/`Apply` return an error "integrity module not running".

- [ ] **Step 1: Write the failing tests:**

```go
func TestLedgerActionsAreReadOnlyAndRegistered(t *testing.T) {
	for _, n := range []string{"ledger.sweep", "ledger.verify_pin", "yara.scan"} {
		a, err := actions.Core().Get(n)
		if err != nil || !a.Spec().ReadOnly || a.Spec().Risk != actions.RiskNone || len(a.Touches(actions.Params{})) != 0 {
			t.Errorf("%s: %v", n, err)
		}
	}
}
func TestLedgerSweepActionReturnsStats(t *testing.T) { /* publish a test checker over a fake root; Apply with roots=[root] -> Output["files"]=="2" */ }
func TestYaraScanActionMatches(t *testing.T)         { /* publish a matcher with one rule; Apply on a matching temp file -> Output["matches"] contains the rule name; a non-matching file -> "[]" */ }
func TestActionsFailWhenModuleNotRunning(t *testing.T) { /* no handle published -> Apply returns an error mentioning "not running" */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/integrity/ -run 'LedgerActions|LedgerSweepAction|YaraScanAction|NotRunning' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the three actions and the handle (`atomic.Pointer`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/integrity/ ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "integrity: ledger.sweep, ledger.verify_pin and yara.scan actions"`

---

### Task 13: `file.restore{source: depot}` (rewritten by S4, 2026-11-06)

The special action `binary.restore_from_depot` is not built. The design has one file-restore action, the core `file.restore{source: golden|depot|backup}`; this task adds its `depot` branch. The `golden` branch belongs to `content_guard` (W4) and the `backup` branch to the backup plan; each lands with its module. The existing restore of a quarantined file by id (from `file.quarantine`) is unchanged and stays what `file.restore` does when no `source` is given.

**Files:**
- Modify: `internal/actions/files.go` (`file.restore` gains the `source` param and dispatches `depot` to `restoreDepot`)
- Create: `internal/actions/restore_depot.go`
- Test: `internal/actions/restore_depot_test.go`

**Interfaces:**
- Consumes: `actions.Action`, `actions.Env` (`Linux.DepotDir`, `Resolve`), `atomicfile.WriteFile`, `format.Ledger.ByPath` (the shared `internal/integrity/format` library; `internal/actions` is core, so the import is allowed and `integrity` is not imported), `actions.RollbackSnapshot` helper (export from `internal/actions` if the compiler requires: `snapshotRollback` in `linux_kmod.go`, which Task 24 deletes, so move the helper to `files.go` first), the dead-man undo registry (`actions.RegisterUndo`).
- Produces: `file.restore{source: depot, path, from, service}` (`from` is the depot file; risk `service`); `Locks` `packages` and `service:<service>`; `Touches` the binary path of the scored service; `Plan` refuses unless the depot copy's sha256 equals a trusted ledger entry for the path (`Source.Trusted()`); `Capture` stores the replaced file as rollback data; `Apply` writes atomically preserving mode, owner and SELinux label then restarts the service through `env.Services`; `Verify` rehashes the file and calls `env.Probe` (W1) when `service` is set; a red probe returns an error so the executor rolls back. No ledger running: refuses. It stays in the engine's click-only set (a tier-1 plan node; the ledger is alert only, D-1).

- [ ] **Step 1: Write the failing tests:**

```go
func TestRestoreDepotRefusesCopyNotInLedger(t *testing.T) {
	env := restoreEnv(t, "/usr/sbin/smtpd", ledgerHash("good"), depotFile("source/smtpd", "other bytes"))
	if _, err := fileRestore{}.Plan(ctx, env, restoreParams(t, "depot", "/usr/sbin/smtpd", "source/smtpd", "postfix")); err == nil || !strings.Contains(err.Error(), "ledger") {
		t.Fatalf("got %v", err)
	}
}
func TestRestoreDepotWritesAtomicallyAndKeepsMode(t *testing.T) { /* replaced file 0750 -> restored bytes == good, mode 0750, rollback data holds the old bytes */ }
func TestRestoreDepotRollsBackOnRedProbe(t *testing.T)         { /* env.Probe returns an error -> Verify errors; Rollback restores the replaced bytes */ }
func TestRestoreDepotDeclaresServiceTouch(t *testing.T)        { /* Touches contains a path touch on /usr/sbin/smtpd */ }
func TestRestoreWithoutSourceStillRestoresQuarantine(t *testing.T) { /* no source: the id from file.quarantine restores to its original path as before */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ -run 'RestoreDepot|RestoreWithoutSource' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** There is no automatic caller; the one-click proposal comes from the UI (Task 18). Never deletes the replaced file; it is kept as rollback data and as evidence (`file.quarantine` is the separate step).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: file.restore source depot"`

---

### Task 14: Rootkit cross-checks, part A: `/proc` based

**Files:**
- Create: `internal/integrity/crosscheck.go` (catalogue, runner, event emission), `internal/integrity/crosscheck_proc_linux.go`, `internal/integrity/crosscheck_other.go`
- Modify: `internal/integrity/module.go` (loop on `CrosscheckIntervalSec`, default 300; a gap "cross-checks run without root" when `os.Geteuid() != 0`)
- Test: `internal/integrity/crosscheck_proc_test.go`

**Interfaces:**
- Consumes: `CrosscheckEvent`, `fakeProc` helper.
- Produces:

```go
type Finding struct{ Check, Finding, Detail string; PID int; Module, Path string }
type Check func(ctx context.Context, procRoot, sysRoot string) ([]Finding, error)
var Crosschecks = map[string]Check{ // the catalogue; later tasks add entries
	"deleted_exe", "ld_preload", "hidden_process", "cgroup_union": ...
}
func RunCrosschecks(ctx context.Context, procRoot, sysRoot string) ([]Finding, []error) // runs every entry; one failing check does not stop the others
```

Checks (native, `/proc` only): `deleted_exe` (the `exe` link target ends in ` (deleted)` or starts with `memfd:`); `ld_preload` (`/etc/ld.so.preload` non-empty, or `LD_PRELOAD` in `/proc/<pid>/environ` of a service process, or a mapped library outside the ledger); `hidden_process` (brute `stat` of pids 1..`pid_max` against the `readdir` of `/proc`, run twice and only a pid hidden in both runs is reported); `cgroup_union` (the union of every `cgroup.procs` under `/sys/fs/cgroup` against `/proc`).

- [ ] **Step 1: Write the failing tests:**

```go
func TestDeletedAndMemfdExe(t *testing.T) {
	root := fakeProc(t, map[string]string{"100/exe": "-> /tmp/x (deleted)", "101/exe": "-> memfd:payload (deleted)", "102/exe": "-> /usr/bin/ok"})
	fs, _ := Crosschecks["deleted_exe"](ctx, root, "")
	if len(fs) != 2 || fs[0].PID != 100 || fs[1].PID != 101 {
		t.Fatalf("%+v", fs)
	}
}
func TestLDPreloadFileAndEnviron(t *testing.T) {
	root := fakeProc(t, map[string]string{"200/environ": "A=b\x00LD_PRELOAD=/tmp/evil.so\x00", "200/exe": "-> /usr/sbin/sshd"})
	// plus <root>/../etc/ld.so.preload non-empty via the helper's etc support
	fs, _ := Crosschecks["ld_preload"](ctx, root, "")
	// want findings for pid 200 (environ) and one for the preload file
}
func TestHiddenProcessNeedsTwoRuns(t *testing.T)   { /* a pid that stats but is not listed in only one of two runs -> not reported; in both -> reported */ }
func TestCgroupUnionFindsProcOnlyInCgroup(t *testing.T) { /* pid 300 in cgroup.procs but absent from /proc -> finding */ }
func TestRunCrosschecksIsolatesFailures(t *testing.T)   { /* one check errors -> the others still return findings, errs has one entry */ }
func TestCrosscheckEventsEmitted(t *testing.T)          { /* module loop with a fake proc emits integrity.crosscheck events that Validate() */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/integrity/ -run 'DeletedAnd|LDPreload|HiddenProcess|CgroupUnion|RunCrosschecks|CrosscheckEvents' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Each check is bounded (at most 4 million pid probes, 1 MiB per file read).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/integrity/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "integrity: proc cross-checks (deleted exe, preload, hidden process, cgroup union)"`

---

### Task 15: Rootkit cross-checks, part B: `/sys`, kernel taint, BPF; PAM content checks

**Files:**
- Create: `internal/integrity/crosscheck_sys_linux.go`, `internal/integrity/bpf_linux.go`, `internal/integrity/pam.go`
- Test: `internal/integrity/crosscheck_sys_test.go`, `internal/integrity/pam_test.go`

**Interfaces:**
- Consumes: `Crosschecks`, `RunCrosschecks` (Task 14).
- Produces catalogue entries `hidden_module` (`/sys/module/*/refcnt` against `/proc/modules`), `kernel_taint` (`/proc/sys/kernel/tainted` bits 1 (forced), 12 (out-of-tree), 13 (unsigned) and kmsg patterns `taints kernel`, `module verification failed`, `bpf_probe_write_user`), `bpf_programs` (`BPF_PROG_GET_NEXT_ID` through `golang.org/x/sys/unix.Syscall(SYS_BPF)`, minus the agent's own and PID 1's, against the host baseline kept with `Env.Keep`), `pam_exec`, `pam_nullok`, `pam_deny_tamper` (reads `/etc/pam.d/*`: any `pam_exec.so` line; `nullok` in an `auth` stack; `pam_deny.so` removed, reordered after a `sufficient` line, or commented). `shortcut: the BPF lister needs CAP_BPF or CAP_SYS_ADMIN and a kernel that exposes BPF_PROG_GET_NEXT_ID; it reports a gap otherwise, upgrade only if the lab shows a kernel the lister cannot read.`

- [ ] **Step 1: Write the failing tests:**

```go
func TestHiddenModule(t *testing.T) {
	sys := fakeSys(t, map[string]string{"module/evil/refcnt": "1", "module/ext4/refcnt": "2"})
	proc := fakeProc(t, map[string]string{"modules": "ext4 1 0 - Live 0x0\n"})
	fs, _ := Crosschecks["hidden_module"](ctx, proc, sys)
	if len(fs) != 1 || fs[0].Module != "evil" {
		t.Fatalf("%+v", fs)
	}
}
func TestKernelTaintBits(t *testing.T) { /* tainted=4096 (bit 12) and a kmsg line "module verification failed" -> two findings; 0 and quiet kmsg -> none */ }
func TestBPFListerSkipsBaselineAndReportsGap(t *testing.T) { /* injected lister returns ids {1,2,3}; baseline {1,2} -> finding for 3; lister error EPERM -> a gap, no finding */ }
func TestPAMExecNullokDenyTamper(t *testing.T) {
	// auth required pam_deny.so after a sufficient line -> pam_deny_tamper; "auth sufficient pam_unix.so nullok" -> pam_nullok;
	// "session optional pam_exec.so /tmp/x" -> pam_exec; a stock Debian common-auth -> no findings
}
```

(`fakeSys` is added to `testhelpers_test.go` in this task.)

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/integrity/ -run 'HiddenModule|KernelTaint|BPFLister|PAMExec' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The BPF lister takes an injectable `listIDs func() ([]uint32, error)` so tests need no privilege; a privileged real call is a separate test that skips with "needs CAP_BPF".
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/integrity/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "integrity: sysfs, taint, BPF and PAM cross-checks"`

---

### Task 16: Rootkit cross-checks, part C: sockets (after W3's `internal/sockets` merges)

**Files:**
- Create: `internal/integrity/crosscheck_sock_linux.go`
- Test: `internal/integrity/crosscheck_sock_test.go`

**Interfaces:**
- Consumes: `internal/sockets` from W3 (`sock_diag` dump and the inode-to-process join; read its Interfaces block in `03-telemetry.md` before starting and use its exact names), `Crosschecks`.
- Produces catalogue entries `hidden_socket` (sockets `sock_diag` reports that `/proc/net/{tcp,udp,tcp6,udp6}` does not list) and `socket_owner` (a `sock_diag` socket whose owning pid is not in the process list). The Windows cross-check ("process list from several APIs against each other; driver list against the reference") is not built: `shortcut: Windows cross-checks are a gap until the lab shows a Windows rootkit class worth the cost`; the module reports the gap "windows cross-checks not built".

- [ ] **Step 1: Write the failing tests:**

```go
func TestHiddenSocket(t *testing.T) {
	// inject a sockets dumper returning {inode 77 tcp 0.0.0.0:4444} and a /proc/net/tcp fixture without inode 77 -> one finding
}
func TestSocketOwnerNotInProcessList(t *testing.T) { /* dumper maps inode 88 to pid 999 absent from the fake /proc -> finding with PID 999 */ }
func TestSocketChecksSkipWithoutPrivilege(t *testing.T) { /* dumper returns EPERM -> no finding, a gap */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/integrity/ -run 'HiddenSocket|SocketOwner|SocketChecksSkip' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** with the dumper injected as a field of the check closure.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "integrity: socket cross-checks over internal/sockets"`

---

### Task 17: `phylax ledger build` and `lookup`

**Files:**
- Create: `cmd/phylax/ledger.go`, `cmd/phylax/ledger_test.go`

**Interfaces:**
- Consumes: `format.NewBuilder`, `Builder.AddPackage`, `format.ReadDebFile`, `format.ReadRPMFile`, `format.ImportWinbindex`, `(*Ledger).Marshal`, `signing.Ed25519Signer`, `register(command{...})` from `main.go`.
- Produces: `phylax ledger build -os <name> -version <v> -key <ed25519 private key file> -out <file.plx> [-deb dir] [-rpm dir] [-winbindex file.json -winbindex-name <exe>] [-bad hashes.txt]` and `phylax ledger lookup -ledger <file.plx> -pub <public key file> <path|sha256>`; both exit non-zero with a message on bad input; reads are bounded by `format.ReadLimits`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestLedgerBuildThenLookup(t *testing.T) {
	dir := t.TempDir()
	deb := writeTestDeb(t, dir, "usr/bin/hello", "hello bytes") // helper builds a minimal .deb with the format package's test builder
	pub, priv := writeKeyFiles(t, dir)
	out := filepath.Join(dir, "l.plx")
	if err := runLedger(ctx, []string{"build", "-os", "debian-12", "-key", priv, "-out", out, "-deb", filepath.Dir(deb)}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := runLedgerTo(&buf, ctx, []string{"lookup", "-ledger", out, "-pub", pub, "/usr/bin/hello"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), sha256Hex("hello bytes")) {
		t.Fatalf("%s", buf.String())
	}
}
func TestLedgerLookupRejectsWrongKey(t *testing.T) { /* lookup with another public key -> error mentioning signature */ }
func TestLedgerCommandRegistered(t *testing.T)     { /* commands["ledger"] exists */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./cmd/phylax/ -run Ledger -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Reuse how `cmd/phylax/depot.go` reads key files.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "ledger: phylax ledger build and lookup"`

---

### Task 18: `integrity` controller side: ledger table, Integrity page, accept as an overrides entry

**Files:**
- Create: `internal/integrity/controller.go`, `internal/integrity/ui.go`, `internal/integrity/migrations.go`
- Modify: `internal/integrity/events.go` (controller `Module` registered with `module.Register`)
- Test: `internal/integrity/controller_test.go`, `internal/integrity/controller_conformance_test.go`

**Interfaces:**
- Consumes: `module.ControllerModule`, `module.Host` (`Tables`, `Subscribe`, `Query`, `Propose`, `UI`), `store.ModuleDB`, `ui.Registrar`, `conformance.Controller`.
- Produces:

```go
type Controller struct{ /* health, ledger_entry writer channel (cap 64) */ }
func (*Controller) Manifest() module.Manifest      // integrity.Manifest() with Sides [agent, controller]
func (c *Controller) Start(ctx context.Context, h module.Host) error
func (*Controller) Health() module.Health
func (*Controller) ConfigBlock() any               // ControllerConfig{module.Common}
// table: integrity_ledger_entry(host, path, sha256, source, package, version, signer, os, added) only. Accepting a hash is not a table or a kind (S4): it is one core operator.edit command event plus one overrides entry
```

The page `/integrity` is the verdict queue built from `Query().Events` of kind `integrity.verdict` (first-sweep verdicts of verdict `unknown` are excluded; they belong to the Hunts triage). Row buttons: accept this hash (POST action `accept` → `Host.Emit` of `operator.edit{module: integrity, op: accept, subject: <sha256>, record: {path, host, package, version, verdict, reason}}` and one `Host.UpdateOverrides` append of `Accepted{kind: integrity, ...}`; the verdict is then suppressed in the queue and on the agents, and the overrides entry is the record of who accepted what), quarantine as evidence (`Host.Propose` of `plans/hunt/quarantine.yaml` with `host`, `path`), restore from the depot (`Propose` of `plans/integrity/restore.yaml`, template with `host`, `path`, `from`, `service`), hunt this hash everywhere (`Propose` of `plans/hunt/hash_everywhere.yaml`). Host-grid column `ledger sweep clean`: verified when the last `integrity.sweep_done` has no open mismatch, `pending` when a first sweep is pending, `failed` on mismatch or known_bad. `shortcut: per-host ledger composition from integrity.claims needs the agent fetch handler (bug 4, W11); the controller side keeps the tables and the accept path, and the ledger ships with the release.`

- [ ] **Step 1: Write the failing tests:**

```go
func TestAcceptIsOneOverridesEntryAndOneCommandEvent(t *testing.T) {
	h := newFakeHost(t) // module.Host fake over a real store.ModuleDB (conformance helpers)
	c := &Controller{}
	go c.Start(ctx, h)
	c.Accept("deadbeef", "/opt/x", "h1", "vendor build", "alice")
	if got := h.Overrides().Accepted; len(got) != 1 || got[0].Kind != "integrity" || got[0].Subject != "deadbeef" || got[0].Owner != "alice" {
		t.Fatalf("%+v", got)
	}
	if ev := h.Emitted("operator.edit"); len(ev) != 1 || ev[0].Fields["module"] != "integrity" || ev[0].Fields["op"] != "accept" {
		t.Fatalf("%+v", ev)
	}
}
func TestFirstSweepUnknownNotInQueue(t *testing.T) { /* two verdict events: unknown+FirstSweep and mismatch -> queue lists only the mismatch */ }
func TestAcceptedHashSuppressedInQueue(t *testing.T) { /* an overrides Accepted entry for the sha256 of a queued unknown -> it disappears; withdrawing the entry brings it back */ }
func TestControllerConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Controller{}, Config: "enabled: true\n", Now: fixedNow})
}
func TestMigrationsOnlyTouchOwnTables(t *testing.T) { /* every statement names integrity_* */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/integrity/ -run 'Accept|FirstSweepUnknown|ControllerConformance|Migrations' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Create the three plan templates (`plans/integrity/restore.yaml` with `module: integrity`, node `file.restore{source: depot}`, `scoring_note`, `probe`; `plans/hunt/quarantine.yaml` and `plans/hunt/hash_everywhere.yaml` belong to Task 36, add `plans/integrity/restore.yaml` here).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/integrity/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "integrity: controller side (ledger table, Integrity page, accept as an overrides entry)"`

---

### Task 19: Known bug 6: D5d reads `integrity.verdict`

**Files:**
- Modify: `rules/pending/needs_producer.yml` (delete the `D5d.binary-integrity` document), create `rules/integrity.yml` (the corpus directory today is `rules/`; if W4 has already moved the corpus to `rules/detect/`, create the file there and say so in the commit)
- Test: `internal/detect/d5d_test.go` (or the rule loader's existing test file; rule inline tests also run)

**Interfaces:**
- Consumes: the rule loader and replay helper in `internal/detect` (the way `rules_test.go` loads `rules/*.yml`), `integrity.VerdictEvent`.
- Produces: rule

```yaml
id: D5d.binary-integrity
title: Installed binary differs from its package/reference hash or signature
severity: critical
tier: 1
attack: [T1036.005, T1554, T1574]
collect: [process_tree, content_changes, binary_copy]
exempt_tagged: true
when:
  event: integrity.verdict
  all:
    - escalate: true
tests:   # inline tests in the loader's format: an escalated mismatch fires; verdict match_other_version with escalate false does not
```

- [ ] **Step 1: Write the failing test:**

```go
func TestD5dFiresOnEscalatedIntegrityVerdict(t *testing.T) {
	rs := loadCorpus(t) // loads rules/ the way the agent does, excluding pending/
	ev := mustEvent(t, integrity.KindVerdict, integrity.VerdictEvent{Path: "/usr/sbin/smtpd", Verdict: "mismatch", Escalate: true, Service: "postfix"})
	if !fires(rs, "D5d.binary-integrity", ev) {
		t.Fatal("Known bug 6: the ledger verdict does not reach D5d")
	}
	quiet := mustEvent(t, integrity.KindVerdict, integrity.VerdictEvent{Path: "/usr/bin/x", Verdict: "match_other_version"})
	if fires(rs, "D5d.binary-integrity", quiet) {
		t.Fatal("patch drift must not alert")
	}
}
func TestNoRuleWaitsOnBinaryIntegrity(t *testing.T) { /* grep the corpus and rules/pending for "binary_integrity": none */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/detect/ -run 'D5d|BinaryIntegrity' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the move of the rule.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/detect/ ./rules/...`. Expected: PASS (T65, bug 6).
- [ ] **Step 5: Commit.** `git commit -am "rules: D5d reads integrity.verdict (Known bug 6)"`

---

### Task 20: The UCF YARA corpus (needs network)

**Files:**
- Create: `rules/yara/*.yar` (17 files from `nmagill123/compiled-yara-rules-rb2@c2b9d3f`, `custom/`), `rules/yara/LICENSE` (MIT text of that repo), `rules/yara/ATTRIBUTION.md` (upstream path, commit, author, licence per file), `rules/yara/skipped.txt` (golden list of rules `Matcher.Skipped` reports)
- Modify: `THIRD_PARTY_RULES.md` generator input if the repo has one (otherwise create the entries by hand)
- Test: `internal/integrity/ucf_corpus_test.go`

**Interfaces:**
- Consumes: `LoadCorpusDir`, `Matcher.Skipped`.
- Produces: the content; `engine: go` stays the default unless `skipped.txt` lists more than 8 of the 17 rules, in which case the plan records it as an open item and does not change the default (David decides).

- [ ] **Step 1: Write the failing test:**

```go
func TestUCFCorpusLoadsAndSkippedListIsRecorded(t *testing.T) {
	m, err := LoadCorpusDir("../../rules/yara")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(m.Rules()); got+len(m.Skipped) != 17 {
		t.Fatalf("rules %d skipped %d, want 17 files accounted for", got, len(m.Skipped))
	}
	want, _ := os.ReadFile("../../rules/yara/skipped.txt")
	if strings.TrimSpace(string(want)) != strings.Join(sortedNames(m.Skipped), "\n") {
		t.Fatal("skipped.txt is stale; regenerate")
	}
}
func TestCorpusHasLicenseAndAttribution(t *testing.T) { /* both files exist and mention MIT and the commit c2b9d3f */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/integrity/ -run 'UCFCorpus|CorpusHasLicense' -v`. Expected: FAIL.
- [ ] **Step 3: Fetch** the 17 rules (`git clone` the upstream into a scratch directory outside the repo, check out `c2b9d3f`, copy `custom/*.yar`). If the network is unavailable, stop and report; do not write the rules from memory.
- [ ] **Step 4: Run, expect PASS.** Run: `go test ./internal/integrity/`. Expected: PASS. Report the skipped count.
- [ ] **Step 5: Commit.** `git commit -am "yara: import the 17 MIT-licensed UCF rules with attribution"`

---

### Task 21: Persistence cleanup, Linux: `service.state{disabled|masked}`, `ld_preload.clear`, `caps.clear`, `pkg.unhold`

**Files:**
- Modify: `internal/actions/services.go` (`service.state` gains the states `disabled` and `masked`: S4 folds the unit disable and mask, the Cockpit disable and the Splunk sidecar switch-off into this one action, so there is no `unit.disable` or `unit.mask`)
- Create: `internal/actions/preload_caps.go`, `internal/actions/pkg_unhold.go`
- Test: `internal/actions/service_state_cleanup_test.go`, `internal/actions/preload_caps_test.go`, `internal/actions/pkg_unhold_test.go`

**Interfaces:**
- Consumes: `actions.Action`, `Env.Services` (`ServiceManager`), `Env.Resolve`, `atomicfile`, the `systemd_linux.go` D-Bus helpers, the existing `cron.disable` pattern in `linux_cron.go`, `Env.Linux.Attr` for `chattr`.
- Produces (all risk `service`, `Capture` stores the prior state, `Apply` is idempotent, none deletes anything):

| Action | Params | What it does | Locks | Touches |
| --- | --- | --- | --- | --- |
| `service.state{unit, state: disabled}` | `unit`, `state` | disable (unit file untouched); also stops it | `service:<unit>` | the service, op disable |
| `service.state{unit, state: masked}` | `unit`, `state` | symlink to `/dev/null` under `/etc/systemd/system`; rollback restores the previous link or file | `service:<unit>` | the service, op disable |
| `ld_preload.clear` | `unit` (optional) | empties `/etc/ld.so.preload`, or removes `Environment=LD_PRELOAD=` lines from the unit's drop-in; the old content is kept as rollback data and quarantined by copy | `path:/etc/ld.so.preload` or the unit | the path |
| `caps.clear` | `path` | removes file capabilities (`security.capability` xattr), or `AmbientCapabilities=` from a unit via drop-in | `path:<path>` | the path |
| `pkg.unhold` | `name` | removes `apt-mark hold` (dpkg selections) or the dnf `versionlock.list` entry | `packages` | none |

Every action refuses a unit or path that a scored service owns (`Env.Guard` via `Touches`; the executor's guard rejects it). `chattr -i` is applied explicitly through `Env.Linux.Attr` before an edit and logged in the output (`attr_cleared: true`), and the immutable bit is restored by rollback.

- [ ] **Step 1: Write the failing tests:**

```go
func TestServiceStateMaskedRollbackRestoresPriorLink(t *testing.T) {
	env := newLinuxEnv(t) // linux_helpers_test.go
	writeFile(t, env, "/etc/systemd/system/evil.service", "[Service]\nExecStart=/tmp/x\n")
	a := serviceState{}
	p := mustParams(t, a, map[string]any{"unit": "evil.service", "state": "masked"})
	rb, _ := a.Capture(ctx, env, p)
	if _, err := a.Apply(ctx, env, p); err != nil || readlink(t, env, "/etc/systemd/system/evil.service") != "/dev/null" {
		t.Fatalf("apply: %v", err)
	}
	if err := Rollback(ctx, env, a, rb); err != nil || !fileHas(t, env, "/etc/systemd/system/evil.service", "ExecStart=/tmp/x") {
		t.Fatalf("rollback: %v", err)
	}
}
func TestServiceStateMaskedNeverDeletesUnitFile(t *testing.T) { /* the original is moved to the rollback data and the quarantine dir, not removed */ }
func TestLDPreloadClearKeepsOldContent(t *testing.T) { /* /etc/ld.so.preload "/tmp/evil.so\n" -> empty file; rollback restores it; immutable bit cleared first and restored */ }
func TestCapsClearOnFile(t *testing.T)               { /* fake AttrBackend/xattr: security.capability removed; rollback restores */ }
func TestPkgUnholdDpkgAndDnf(t *testing.T)           { /* a fixture /var/lib/dpkg/status-style selections file with "pam hold" -> removed; versionlock.list line removed */ }
func TestCleanupActionsRefuseScoredUnit(t *testing.T) { /* guard with sshd as a scored service: service.state{sshd, disabled} -> Touches reports it and the guard rejects */ }
func TestNoUnitDisableOrMaskAction(t *testing.T)      { /* actions.Core().Get("unit.disable") and "unit.mask" both error */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ -run 'ServiceStateMasked|NeverDeletes|LDPreload|CapsClear|PkgUnhold|RefuseScored|NoUnitDisable' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** and register with `actions.Register` in `registry_linux.go`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: service.state disabled and masked, ld_preload.clear, caps.clear, pkg.unhold"`

---

### Task 22: Persistence cleanup, Windows: `task.disable`, `wmi.subscription_remove`, `runkey.remove`

**Files:**
- Create: `internal/actions/win_cleanup.go`, `internal/actions/win_cleanup_windows.go` (COM implementations, compiled and vetted on Linux CI, untested on Windows)
- Modify: `internal/actions/win_env.go` (`WinEnv.Tasks TaskScheduler`, `WinEnv.WMI WMIStore`), `internal/actions/win_fakes_test.go`
- Test: `internal/actions/win_cleanup_test.go`

**Interfaces:**
- Consumes: `RegistryStore`, `WinEnv`, `registry.set`/`registry.delete` patterns.
- Produces:

```go
type TaskScheduler interface {
	Get(ctx context.Context, path string) (TaskInfo, bool, error)
	SetEnabled(ctx context.Context, path string, enabled bool) error
}
type TaskInfo struct{ Path, Author, Actions string; Enabled bool }
type WMIStore interface {
	Subscriptions(ctx context.Context) ([]WMISub, error) // filter, consumer and binding of the root\subscription namespace
	Remove(ctx context.Context, s WMISub) error
	Restore(ctx context.Context, s WMISub) error
}
type WMISub struct{ Name, Filter, Consumer, Query, Command string }
```

Actions (risk `service`, rollback data holds the prior state; none deletes without keeping a copy): `task.disable{path}` (disable, never delete), `wmi.subscription_remove{name}` (removes the binding, filter and consumer; the full record is the rollback and is written to the quarantine dir), `runkey.remove{key, name}` (limited to `Run`, `RunOnce`, `RunServices` under HKLM and HKCU/WOW6432Node; the value is the rollback; `Touches` autostart). Anything outside the allow list is refused at `Validate`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestTaskDisableRollsBack(t *testing.T)            { /* fake scheduler with an enabled task; Apply -> disabled; Rollback -> enabled */ }
func TestWMIRemoveKeepsRecord(t *testing.T)            { /* fake store with a CommandLineEventConsumer sub; Apply removes; the quarantine dir holds the JSON record; Restore brings it back */ }
func TestRunkeyRemoveOnlyRunKeys(t *testing.T) {
	// key HKLM\Software\Microsoft\Windows\CurrentVersion\Run -> ok; HKLM\SYSTEM\CurrentControlSet\Services\x -> Validate error
}
func TestWinCleanupUnsupportedWithoutBackend(t *testing.T) { /* nil WinEnv.Tasks -> ErrUnsupported */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ -run 'TaskDisable|WMIRemove|RunkeyRemove|WinCleanupUnsupported' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the actions over the interfaces; the COM implementations follow the `win_firewall`/`go-ole` pattern (`go-ole` is already a dependency). `shortcut: the COM backends are untested on a real Windows host; upgrade at the first Windows lab run (T61 host).`
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: task.disable, wmi.subscription_remove, runkey.remove"`

---

### Task 23: Registry family: `registry.snapshot` and `SubKeys`

**Files:**
- Modify: `internal/actions/win_env.go` (`RegistryStore.SubKeys(ctx, key) ([]string, error)`), the Windows `RegistryStore` implementation, `internal/actions/win_fakes_test.go` (`fakeReg.SubKeys`)
- Create: `internal/actions/registry_snapshot.go`
- Test: `internal/actions/registry_snapshot_test.go`

**Interfaces:**
- Consumes: `RegistryStore`, `normRegKey`.
- Produces: `registry.snapshot{key}` (risk `none`, `ReadOnly`, output `values` JSON of name → typed value for one key, bounded to 500 values and 256 KiB), and `RegistryStore.SubKeys` used by `hunt.persistence` (Task 29).

- [ ] **Step 1: Write the failing tests:**

```go
func TestRegistrySnapshotReadsValues(t *testing.T) { /* fake key with two values -> Output["values"] decodes to both */ }
func TestRegistrySnapshotBounded(t *testing.T)     { /* 600 values -> 500 returned, Output["truncated"]=="true" */ }
func TestSubKeysListsChildren(t *testing.T)        { /* fakeReg with keys under HKLM\...\Run\x -> sorted child names */ }
func TestRegistrySnapshotRefusesNonHKLMHKCU(t *testing.T) { /* checkRegKey rejects HKCR */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ -run 'RegistrySnapshot|SubKeys' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** (decision 1: the family keeps the code's names).
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: registry.snapshot and RegistryStore.SubKeys"`

---

### Task 24: Known bug 1: the module block is plan content plus a `command.check`; `selinux.restore`, `hosts.file` (rewritten by S4, 2026-11-06)

The special action `kernel.module_block` (with its `cmdline_fallback` param) is not built, and the old one is deleted. Blocking a kernel module is a `file.write` of a modprobe config in the `linux.local_root_bundle` content (Task 40); a file write verifies only that file, so the bundle follows it with a `command.check` that probes `socket(AF_ALG)` bound to `aead`. This task builds the probe, deletes the old action and adds the two small core actions.

**Files:**
- Delete: `internal/actions/linux_kmod.go`, `linux_kmod_linux.go`, `linux_kmod_other.go` (the `kernel.module_block` action and the line-111-to-120 Verify that is Known bug 1; Task 13 moved `snapshotRollback` out first)
- Modify: `internal/actions/app_probe.go` (`command.check` gains the allowlisted probe `af_alg_aead` in `probeNames`; the AF_ALG probe is injectable through `LinuxEnv.ProbeAFAlg func(alg string) (opens bool, err error)`)
- Create: `internal/actions/selinux_restore.go`, `internal/actions/hosts_file.go`
- Test: `internal/actions/app_probe_afalg_test.go`, `internal/actions/selinux_restore_test.go`, `internal/actions/hosts_file_test.go`

**Interfaces:**
- Consumes: `LinuxEnv`, `atomicfile`, the existing `command.check` probe table.
- Produces: `command.check{probe: af_alg_aead, fail_if_vulnerable}`: opens an `AF_ALG` socket and binds it to `aead` through `ProbeAFAlg`; if the bind succeeds the precondition of Copy Fail is present (the module is loaded or compiled in) and `fail_if_vulnerable` fails the node with `errors.New("AF_ALG aead socket opens: the module is loaded or built in; blacklisting does not mitigate (take the initcall_blacklist branch)")`. `selinux.restore{path}` restores the default SELinux label through the `security.selinux` xattr from the file-contexts database (`shortcut: reads /etc/selinux/targeted/contexts/files/file_contexts literally, no regex compile cache; upgrade if a lab restore is slow`); `hosts.file{entries}` sets named entries in `/etc/hosts` atomically (risk `service`, rollback restores the file, refuses to remove the loopback lines).

- [ ] **Step 1: Write the failing tests:**

```go
func TestAFAlgProbeFailsWhenSocketOpens(t *testing.T) { // Known bug 1, T65
	env := newLinuxEnv(t)
	env.Linux.ProbeAFAlg = func(string) (bool, error) { return true, nil } // compiled in: /proc/modules has no entry, the bind still succeeds
	writeFile(t, env, "/proc/modules", "ext4 1 0 - Live 0x0\n")
	a := commandCheck{}
	p := mustParams(t, a, map[string]any{"probe": "af_alg_aead", "fail_if_vulnerable": true})
	if _, err := a.Apply(ctx, env, p); err == nil || !strings.Contains(err.Error(), "built in") {
		t.Fatalf("the check must fail while the aead socket opens, got %v", err)
	}
}
func TestAFAlgProbePassesWhenBlocked(t *testing.T)   { /* ProbeAFAlg returns false -> Apply nil, Output["opens"]=="false" */ }
func TestKernelModuleBlockActionIsGone(t *testing.T) { /* actions.Core().Get("kernel.module_block") and "modules.disable_loading" both error */ }
func TestSelinuxRestoreSetsDefaultLabel(t *testing.T) { /* fake xattr backend + a one-line file_contexts -> label set; rollback restores the prior label */ }
func TestHostsFileKeepsLoopback(t *testing.T)         { /* entries applied; removing 127.0.0.1 localhost is refused at Validate */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ -run 'AFAlg|KernelModuleBlockActionIsGone|SelinuxRestore|HostsFile' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The bootloader branch (`initcall_blacklist=algif_aead_init`) is content in Task 40, GRUB only (the design's `shortcut`, recorded in the pack file as a comment).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/actions/`. Expected: PASS (T65, bug 1; the bundle half is `TestLocalRootBundleChecksAFAlgAfterWrite` in Task 40).
- [ ] **Step 5: Commit.** `git commit -am "actions: AF_ALG command.check replaces kernel.module_block (Known bug 1); selinux.restore, hosts.file"`

---

### Task 25: Action `mount.remount`

**Files:**
- Create: `internal/actions/mount_linux.go`, `internal/actions/mount_other.go`
- Modify: `internal/actions/linux_env.go` (`LinuxEnv.Mount MountBackend`, default real `mount(2)`)
- Test: `internal/actions/mount_test.go`, `internal/actions/mount_linux_test.go` (privileged, skips)

**Interfaces:**
- Consumes: `LinuxEnv`, `/proc/self/mountinfo` reader.
- Produces: `mount.remount{path, options}` (risk `service`, lock `mounts`, `Touches` the mount options of the path, `Plan` shows the option diff, `Capture` records the prior options, `Apply` uses `mount(2)` with `MS_REMOUNT` and, when `path` is not its own mount, bind-mounts it onto itself first (recorded so rollback unmounts the bind), `Verify` reads `/proc/self/mountinfo` for the options and tries to execute a test binary from the path expecting a refusal when `noexec` was requested, `Rollback` remounts the prior options). The native call is the syscall; the `mount` binary is never run.

```go
type MountBackend interface {
	Mounts() ([]MountInfo, error)
	Remount(path string, flags uintptr, data string) error
	Bind(src, dst string) error
	Unmount(path string) error
}
type MountInfo struct{ Target, Source, FSType string; Options []string }
```

- [ ] **Step 1: Write the failing tests:**

```go
func TestRemountNoexecPlanAndRollback(t *testing.T) {
	fm := newFakeMounts(MountInfo{Target: "/tmp", FSType: "tmpfs", Options: []string{"rw", "nosuid"}})
	env := &Env{Linux: &LinuxEnv{Mount: fm}}
	a := mountRemount{}
	p := mustParams(t, a, map[string]any{"path": "/tmp", "options": []any{"noexec", "nosuid"}})
	rb, _ := a.Capture(ctx, env, p)
	if _, err := a.Apply(ctx, env, p); err != nil || !fm.has("/tmp", "noexec") {
		t.Fatalf("apply %v", err)
	}
	if err := Rollback(ctx, env, a, rb); err != nil || fm.has("/tmp", "noexec") {
		t.Fatalf("rollback %v", err)
	}
}
func TestRemountBindsFirstWhenNotOwnMount(t *testing.T) { /* /var/tmp has no own mount entry -> Bind then Remount; rollback Unmounts the bind */ }
func TestRemountRefusesUnknownOption(t *testing.T)      { /* options ["rw,exec,suid,dev"] parameters validated against a small allow list (noexec nosuid nodev ro exec suid) */ }
func TestRemountPrivileged(t *testing.T)                { /* skips with "needs root and a mount namespace" unless running as root in a user+mount namespace */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ -run 'Remount' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Windows build: the action returns `ErrUnsupported`. The `fstab` write is deliberately not part of this action.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: mount.remount"`

---

### Task 26: Scoring-safety lint rule `HD001` (no noexec remount a scored service needs)

**Files:**
- Create: `internal/hardening/lint.go`
- Test: `internal/hardening/lint_test.go`

**Interfaces:**
- Consumes: `lint.Register`, `lint.Rule`, `lint.Ctx` (W1), `store.Reader`, `manifest.Manifest` (scored services and their pinned binaries, unit `ExecStart` from `services.yml` `process.binaries`).
- Produces: rule `HD001` registered from `init`: a node with action `mount.remount` whose `options` contain `noexec` for `/tmp`, `/dev/shm` or `/var/tmp` is a finding when any scored service on the node's host executes from that path (its binaries or working directory in the manifest, or a `process_start` event in the last 6 hours (`Ctx.Query`) whose `exe` is under the path and whose process has a scored `service`), or when a package-manager run is in progress (a `process_start` of `apt`, `dpkg`, `dnf` or `rpm` with no matching `process_exit`).

- [ ] **Step 1: Write the failing tests:**

```go
func TestHD001RefusesWhenScoredServiceExecsFromTmp(t *testing.T) {
	c := lintCtx(t, withScoredService("h1", "web", "/tmp/web/run.sh"))
	f := hd001.Check(remountNode("h1", "/tmp", "noexec"), c)
	if len(f) != 1 || f[0].Rule != "HD001" {
		t.Fatalf("%+v", f)
	}
}
func TestHD001RefusesWhenAuditHistoryShowsExec(t *testing.T) { /* a process_start with exe /var/tmp/x and service "web" 2 hours ago -> finding */ }
func TestHD001RefusesDuringPackageRun(t *testing.T)           { /* unmatched process_start of dpkg -> finding */ }
func TestHD001AllowsCleanHost(t *testing.T)                   { /* no scored exec from the path -> no finding; a non-noexec remount -> no finding */ }
func TestHD001Registered(t *testing.T)                        { /* lint.Rules() contains HD001 */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/hardening/ -run HD001 -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/hardening/ ./internal/plan/lint/`. Expected: PASS (T68 CI half).
- [ ] **Step 5: Commit.** `git commit -am "hardening: HD001 lint, no noexec remount a scored service needs"`

---

### Task 27: Hunt artifact model, check loader and `collect.files`

**Files:**
- Create: `internal/hunt/artifact.go`, `internal/hunt/checks.go`, `internal/hunt/collect_files.go`, `hunt/checks/README.md` is not created (no docs files); `hunt/checks/.gitkeep` is not created either (Task 28 adds content)
- Test: `internal/hunt/checks_test.go`, `internal/hunt/collect_files_test.go`

**Interfaces:**
- Consumes: `Artifact`, `Collection`, `MaxCollectionBytes` (Task 1), `actions.Register`.
- Produces: the check-definition format and its engine. A check file is YAML, unknown fields are an error, capped at 256 KiB:

```go
type CheckFile struct {
	OS     string  `yaml:"os"`     // linux | windows
	Checks []Check `yaml:"checks"`
}
type Check struct {
	ID    string   `yaml:"id"`
	Kind  string   `yaml:"kind"`            // the artifact kind produced
	Type  string   `yaml:"type"`            // files | grep | registry | subkeys
	Globs []string `yaml:"globs,omitempty"` // files, grep
	Match string   `yaml:"match,omitempty"` // grep: regexp applied per line; the capture group 1 becomes Attrs["ref"]
	Key   string   `yaml:"key,omitempty"`   // registry, subkeys
	Refs  string   `yaml:"refs,omitempty"`  // files: "exec" extracts executable paths from the content
}
func LoadChecks(fsys fs.FS, glob string) ([]CheckFile, error) // strict; bounded
// Collect runs checks natively (no host tools): glob walk with a 20000-entry cap per check, sha256 of regular files up to 16 MiB,
// Attrs: sha256, size, mode, uid, mtime, ctime, owner_pkg (when hints are present), ref.
func Collect(ctx context.Context, env *actions.Env, os string, checks []Check) (Collection, error)
```

Action `collect.files{globs}` (a core Collection action; registered from this package until core has it, and not listed in `hunt`'s manifest): risk `none`, `ReadOnly`, output `artifacts` (JSON `Collection`, truncated at `MaxCollectionBytes` with `truncated=true`), registered from `init`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestLoadChecksRejectsUnknownField(t *testing.T) {
	fsys := fstest.MapFS{"c.yml": {Data: []byte("os: linux\nchecks:\n- {id: a, kind: cron, type: files, globs: [/etc/crontab], bogus: 1}\n")}}
	if _, err := LoadChecks(fsys, "*.yml"); err == nil {
		t.Fatal("unknown field accepted")
	}
}
func TestCollectFilesArtifacts(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/cron.d/x", "* * * * * root /tmp/evil.sh\n")
	c, err := Collect(ctx, &actions.Env{Root: root}, "linux", []Check{{ID: "cron", Kind: "cron", Type: "files", Globs: []string{"/etc/cron.d/*"}, Refs: "exec"}})
	if err != nil || len(c.Artifacts) != 1 || c.Artifacts[0].Key != "/etc/cron.d/x" || c.Artifacts[0].Attrs["ref"] != "/tmp/evil.sh" || c.Artifacts[0].Attrs["sha256"] == "" {
		t.Fatalf("%+v %v", c, err)
	}
}
func TestCollectBounded(t *testing.T)       { /* 30000 matching files -> 20000 artifacts and Truncated true */ }
func TestCollectOutputCap(t *testing.T)     { /* JSON larger than MaxCollectionBytes -> Output["truncated"]=="true" and len(Output["artifacts"]) <= cap */ }
func TestCollectFilesActionReadOnly(t *testing.T) { /* registered, ReadOnly, risk none */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/hunt/ -run 'LoadChecks|CollectFiles|CollectBounded|CollectOutputCap' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/hunt/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "hunt: artifact model, check loader and collect.files"`

---

### Task 28: Linux persistence content and `hunt.persistence`

**Files:**
- Create: `hunt/checks/persistence_linux.yml`, `internal/hunt/persistence.go`
- Test: `internal/hunt/persistence_linux_test.go`

**Interfaces:**
- Consumes: `Collect`, `LoadChecks`, `Check` types (Task 27); `format.HostHints.Owner` for `owner_pkg`.
- Produces: content covering Appendix B and the N5.8 additions as `files`/`grep` checks (one check id per location group: `cron`, `at`, `units`, `timers`, `generators`, `rc`, `profile`, `motd`, `udev`, `pam`, `nss`, `ssh_rc`, `authorized_keys`, `sudoers`, `ld_so`, `apt_hooks`, `dnf_plugins`, `logrotate`, `xinetd`, `polkit`, `grub`, `ifup`, `networkmanager_dispatcher`, `git_hooks`, `modules_load`, `dbus_services`, `resolv_conf`, `xdg_autostart`), plus `grep` checks for unit `Environment=LD_PRELOAD`, `AmbientCapabilities=`, `CapabilityBoundingSet=`, and `chattr +i` state read through `Env.Linux.Attr` for units, sudoers files and webroot files (artifact kind `immutable`). Action `hunt.persistence` (risk `none`, `ReadOnly`) loads the embedded `hunt/checks` for the host OS and returns the `Collection`; the content is embedded with `//go:embed` from a package under `hunt` (`hunt/hunt.go`: `package huntcontent; var FS embed.FS`).

- [ ] **Step 1: Write the failing tests:**

```go
func TestPersistenceLinuxFindsPlantedItems(t *testing.T) {
	root := fixtureRoot(t, map[string]string{
		"etc/cron.d/backdoor":                    "* * * * * root /dev/shm/.x\n",
		"etc/systemd/system/evil.service":        "[Service]\nEnvironment=LD_PRELOAD=/tmp/e.so\nExecStart=/tmp/x\n",
		"etc/ld.so.preload":                      "/tmp/e.so\n",
		"home/bob/.ssh/authorized_keys":          "ssh-ed25519 AAAA attacker\n",
		"etc/pam.d/sshd":                         "auth optional pam_exec.so /tmp/p\n",
		"var/spool/at/a1":                        "x",
	})
	c, err := persistenceCollect(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct{ kind, key string }{{"cron", "/etc/cron.d/backdoor"}, {"unit", "/etc/systemd/system/evil.service"}, {"ld_preload", "/etc/ld.so.preload"}, {"authorized_key", "/home/bob/.ssh/authorized_keys"}, {"pam", "/etc/pam.d/sshd"}, {"at", "/var/spool/at/a1"}} {
		if !hasArtifact(c, want.kind, want.key) {
			t.Errorf("missing %s %s", want.kind, want.key)
		}
	}
	if a := find(c, "unit", "/etc/systemd/system/evil.service"); a.Attrs["env_ld_preload"] != "/tmp/e.so" {
		t.Errorf("%+v", a)
	}
}
func TestPersistenceContentLoadsStrictly(t *testing.T) { /* every embedded check file passes LoadChecks; every check id unique; every kind non-empty */ }
func TestHuntPersistenceActionRegistered(t *testing.T) { /* actions.Core().Get("hunt.persistence") is ReadOnly and risk none */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/hunt/ -run 'PersistenceLinux|PersistenceContent|HuntPersistenceAction' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Verify each added location against the D6o hook-directories rule so the hunt and the rule do not double up (note in the commit message which rule ids overlap).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/hunt/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "hunt: Linux persistence checks and hunt.persistence"`

---

### Task 29: Windows persistence content and collection

**Files:**
- Create: `hunt/checks/persistence_windows.yml`
- Modify: `internal/hunt/checks.go` (`registry` and `subkeys` check types), `internal/hunt/persistence.go` (Windows branch)
- Test: `internal/hunt/persistence_windows_test.go`

**Interfaces:**
- Consumes: `RegistryStore.Get/ValueNames/SubKeys` (Task 23), `WMIStore.Subscriptions` (Task 22), `TaskScheduler`, the `files` type for `C:\Windows\System32\Tasks\**` XML, startup folders and PowerShell profiles.
- Produces: Appendix C coverage: scheduled tasks (XML under `System32\Tasks`, kind `task`, `Attrs.actions`), services (`HKLM\SYSTEM\CurrentControlSet\Services\*` `subkeys` then `ImagePath`, `ServiceDll`, `Start`, `ObjectName`, kind `service`), Run/RunOnce/RunServices (HKLM, HKCU, WOW6432Node; kind `runkey`), Winlogon `Userinit`/`Shell`, AppInit_DLLs, AppCertDlls, IFEO `Debugger` and `GlobalFlag`, SilentProcessExit, LSA `Security Packages`/`Authentication Packages`/`Notification Packages`, WMI subscriptions (kind `wmi`), Netsh helpers (`HKLM\Software\Microsoft\NetSh`), COM hijacks (`HKCU\Software\Classes\CLSID\*\InprocServer32`), startup folders, accessibility binaries (`sethc.exe`, `utilman.exe`, `osk.exe` hashed, kind `accessibility`), PowerShell `$PROFILE` paths, DNS `ServerLevelPluginDll`. BITS jobs and print monitors: `shortcut: BITS jobs, print monitors, time and Winsock providers are not collected; add when a lab run shows the red team using them`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestPersistenceWindowsFindsPlantedItems(t *testing.T) {
	reg := newFakeReg()
	reg.put(`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, "Updater", sz(`C:\Users\Public\u.exe`))
	reg.put(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe`, "Debugger", sz(`C:\Windows\System32\cmd.exe`))
	reg.put(`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, "Security Packages", multi("kerberos", "evilssp"))
	reg.addSubKey(`HKLM\SYSTEM\CurrentControlSet\Services`, "evilsvc")
	reg.put(`HKLM\SYSTEM\CurrentControlSet\Services\evilsvc`, "ImagePath", sz(`C:\ProgramData\x.exe`))
	env := &actions.Env{Win: actions.WinEnv{Reg: reg, WMI: fakeWMI{subs: []actions.WMISub{{Name: "e", Command: "powershell -enc AAAA"}}}}}
	c, err := persistenceCollectWindows(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"runkey", "ifeo", "lsa", "service", "wmi"} {
		if !hasKind(c, k) {
			t.Errorf("missing %s", k)
		}
	}
}
func TestWindowsContentLoads(t *testing.T) { /* persistence_windows.yml passes LoadChecks; registry keys pass normRegKey */ }
func TestWindowsNoBackendIsAGapNotAPanic(t *testing.T) { /* nil Reg -> Collection.Errors names "registry"; other checks still run */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/hunt/ -run 'PersistenceWindows|WindowsContent|WindowsNoBackend' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "hunt: Windows persistence checks"`

---

### Task 30: `hunt.baseline_diff` (rewritten by S4, 2026-11-06; `collect.hunt` is not built)

`inventory` is core-default (S4), so the hunt does not collect what `inventory` already holds: accounts, groups, sudoers, authorized keys, units, tasks, services, drivers, mounts, kernel modules, BPF programs and software arrive as `inventory.row` events and `inventory.snapshot` epochs, and Tasks 33 and 34 diff those rows. There is no `collect.hunt` action. This task collects only the reference artifacts `inventory` does not hold.

**Files:**
- Create: `internal/hunt/baseline_collect.go`
- Create: `hunt/checks/baseline_linux.yml`, `hunt/checks/baseline_windows.yml`
- Test: `internal/hunt/baseline_collect_test.go`

**Interfaces:**
- Consumes: `Collect`, persistence collectors (Tasks 28, 29), `format.Hasher` (Task 2).
- Produces: `hunt.baseline_diff` (`none` risk, `ReadOnly`): the reference artifact set outside `inventory`, returned for the controller diff; the file inventory is excluded too (decision 11). Artifact kinds: `suid` (SUID/SGID set, path and hash through the shared hasher), `cap` (file capabilities), `sysctl` (a fixed list of security sysctls), `service_config` (Apache/httpd, PHP, Postfix, Dovecot, MySQL config files hashed), on Windows the `ifeo`-style values of Task 29 stay with `hunt.persistence`. A host whose `inventory` is `unavailable` reports that gap (Task 34) and the hunt covers only these artifacts and the persistence locations.

- [ ] **Step 1: Write the failing tests:**

```go
func TestBaselineDiffCollectsSuidCapsSysctl(t *testing.T) {
	root := fixtureRoot(t, map[string]string{"usr/bin/su": "x", "proc/sys/kernel/yama/ptrace_scope": "0\n"})
	chmod(t, root, "usr/bin/su", 0o4755)
	c, _ := baselineCollect(ctx, &actions.Env{Root: root})
	if !hasArtifact(c, "suid", "/usr/bin/su") || !hasArtifact(c, "sysctl", "kernel.yama.ptrace_scope") {
		t.Fatalf("%+v", c)
	}
}
func TestBaselineExcludesInventoryTablesAndFileInventory(t *testing.T) { /* no artifact has kind file, account, group, sudoers, kmod or bpf: those are inventory rows */ }
func TestSuidArtifactsCarryHash(t *testing.T)            { /* a 04755 file appears as kind suid with sha256, hashed through format.Hasher */ }
func TestNoCollectHuntAction(t *testing.T)               { /* actions.Core().Get("collect.hunt") errors */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/hunt/ -run 'BaselineDiff|BaselineExcludes|SuidArtifacts|NoCollectHunt' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/hunt/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "hunt: hunt.baseline_diff over what inventory does not hold"`

---

### Task 31: `hunt.apps`

**Files:**
- Create: `hunt/checks/apps/{apache_php,postfix,dovecot,mysql,splunk,opencart,roundcube}.yml`, `internal/hunt/apps.go`
- Test: `internal/hunt/apps_test.go`

**Interfaces:**
- Consumes: `Collect` (adds the `grep` type usage), `web.opencart_audit` (called by plans, not imported). The MySQL and SQL Server audits are `sql.query` nodes whose statements are plan content (S4), not actions.
- Produces: `hunt.apps{apps}` (`none`, `ReadOnly`): for each requested app that is detected (a config path exists), runs its check file. Checks (design "Application references"): Apache/PHP (modules directory and `extension_dir` listing, `disable_functions`, `auto_prepend_file`, unit `Environment=LD_PRELOAD`), Postfix (`master.cf` pipe transports and `content_filter`, `/etc/aliases` lines starting with `|`), Dovecot (`postlogin`, global sieve, passdb/userdb `args = ... script`), Splunk (`$SPLUNK_HOME/etc/apps` list, `inputs.conf` `[script://`, `deploymentclient.conf`), OpenCart (webroot file hashes into the `webroot` artifact set; the reference comparison is the controller diff against `hunt/baselines/opencart-<version>.json`; gated on the detected branch from `system/startup.php`/`index.php` version constants, `shortcut: ships gated on the detected branch, 4.1.0.4 seen, most CVEs target 4.0.2.x`), Roundcube (`web.roundcube_audit` is a separate core action: the check file lists `installer/` presence and reachable `config/`, `logs/`, `temp/` and the plugin directory; `shortcut: the Roundcube audit ships once the webmail product is confirmed`). The MySQL UDF and MSSQL checks are `sql.query` nodes in the plans, with the statements as plan content.

- [ ] **Step 1: Write the failing tests:**

```go
func TestAppsPostfixPipeTransport(t *testing.T) {
	root := fixtureRoot(t, map[string]string{"etc/postfix/master.cf": "smtp inet n - n - - smtpd\nevil unix - n n - - pipe flags=F user=root argv=/tmp/x\n", "etc/aliases": "root: |/tmp/mail.sh\n"})
	c, _ := appsCollect(ctx, &actions.Env{Root: root}, []string{"postfix"})
	if !hasArtifact(c, "postfix_pipe", "master.cf:evil") || !hasArtifact(c, "alias_pipe", "root") {
		t.Fatalf("%+v", c)
	}
}
func TestAppsPHPAutoPrepend(t *testing.T)      { /* php.ini auto_prepend_file=/tmp/p.php -> artifact php_ini with Attrs.auto_prepend_file */ }
func TestAppsSkipUndetected(t *testing.T)      { /* requesting dovecot on a host without it -> no artifacts, no error */ }
func TestAppsOpenCartGatedOnBranch(t *testing.T) { /* version 4.1.0.4 -> webroot hashes collected; an unknown branch -> Collection.Errors names "opencart branch not recognised" */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/hunt/ -run Apps -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/hunt/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "hunt: hunt.apps application reference checks"`

---

### Task 32: `hunt.creds` and `hunt.remote_access`

**Files:**
- Create: `hunt/checks/creds.yml`, `hunt/killlist.yml`, `internal/hunt/creds.go`, `internal/hunt/remote_access.go`
- Test: `internal/hunt/creds_test.go`, `internal/hunt/remote_access_test.go`

**Interfaces:**
- Consumes: `Collect`, `actions.ADBackend` (read of user descriptions through `Find`/`Get` once Task 41 adds the listing method; until then the AD part reports a gap), `Env.Services`, process listing from `/proc`.
- Produces: `hunt.creds` (`none`, `ReadOnly`): file names `*passlist*`, `*.kdbx`, `id_rsa*`, `.env`, `unattend.xml`, `*.pfx` under home directories, webroots and `C:\Users`; output paths and a classification (`name`, `content_looks_like_password` set by a bounded regexp over the first 4 KiB), never the secret; on a DC with `creds.ad_descriptions` it adds AD user Description fields classified the same way. `hunt.remote_access`: the kill list (`hunt/killlist.yml`: Teleport, Webmin, MeshCentral agent, AWS SSM agent, TeamViewer, Tailscale, ngrok, cloudflared, chisel, frp, each with unit/service names, binary names and paths) matched against installed units, services and running process names; `allowed_management_agents` (default Wazuh, Splunk) excluded. Artifact kinds `cred_file`, `ad_description`, `remote_agent` with `Attrs.installed` and `Attrs.running`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestCredsReportsPathNeverContent(t *testing.T) {
	root := fixtureRoot(t, map[string]string{"home/bob/passlist.txt": "admin:Winter2026!\n", "var/www/.env": "DB_PASSWORD=hunter2\n"})
	c, _ := credsCollect(ctx, &actions.Env{Root: root})
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "Winter2026") || strings.Contains(string(b), "hunter2") {
		t.Fatal("secret leaked into the artifact set")
	}
	if a := find(c, "cred_file", "/home/bob/passlist.txt"); a.Attrs["content_looks_like_password"] != "true" {
		t.Fatalf("%+v", a)
	}
}
func TestRemoteAccessKillListMatchesInstalledIdle(t *testing.T) { /* a tailscaled.service unit file present, no process -> installed true running false */ }
func TestRemoteAccessAllowsWazuh(t *testing.T)                  { /* wazuh-agent unit and process -> no artifact */ }
func TestKillListLoadsStrictly(t *testing.T)                    { /* hunt/killlist.yml names all ten agents; unknown field -> error */ }
func TestCredsADDescriptionGapWithoutBackend(t *testing.T)      { /* DC, nil ADBackend -> Collection.Errors names "ad descriptions" */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/hunt/ -run 'Creds|RemoteAccess|KillList' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/hunt/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "hunt: hunt.creds and hunt.remote_access"`

---

### Task 33: Controller pure logic: baseline load, diff, enrich, score, heuristics

**Files:**
- Create: `internal/hunt/diff.go`, `internal/hunt/score.go`, `internal/hunt/baseline.go`, `hunt/heuristics.yml`
- Test: `internal/hunt/diff_test.go`, `internal/hunt/score_test.go`, `internal/hunt/baseline_test.go`

**Interfaces:**
- Consumes: `Artifact`, `Collection`, `signing.Verifier`, `format.Verdict` constants, the core `inventory` rows (`inventory_rows` through `Host.Query`).
- Produces (pure functions):

```go
// ArtifactsFromInventory turns the host's inventory rows (accounts, groups, sudoers, authorized keys, units, tasks, services, drivers, mounts,
// kernel modules, BPF programs) into Artifacts, so the diff below covers them without a second collection (S4).
type InventoryRow struct{ Table, Key string; Row map[string]string }
func ArtifactsFromInventory(rows []InventoryRow) []Artifact
type Baseline struct{ OS string; Artifacts []Artifact }
// LoadBaseline reads hunt/baselines/<os>.json and its detached <os>.json.sig (sshsig); an unsigned or tampered file is an error.
func LoadBaseline(fsys fs.FS, os string, v signing.Verifier) (Baseline, error)

type Diff struct{ Added, Modified, Missing []Artifact }
// Compute diffs by (Kind, Key); Modified compares Attrs["sha256"], Attrs["ref"] and every other Attrs key present in both.
// accepted is the host's live baseline: the Overrides.Accepted entries of kind hunt for this host; an accepted artifact with identical attrs is not reported.
// cur is the hunt's own Collection merged with ArtifactsFromInventory for the host.
func Compute(ref Baseline, accepted []Artifact, cur Collection) Diff

type Enrichment struct{ Hash, Signer, OwnerPkg, LedgerVerdict string; Referrer string }
type Scored struct{ Artifact Artifact; Change string; Score, Reason string; Enrichment Enrichment }
// Score applies the design's High, Medium and Low rules and the heuristics (a hit raises one level, never creates High alone).
func Score(d Diff, enrich func(Artifact) Enrichment, h Heuristics) []Scored

type Heuristics struct{ /* loaded from hunt/heuristics.yml */ }
func LoadHeuristics(fsys fs.FS) (Heuristics, error)
```

High: an unsigned or non-vendor binary referenced by an autostart (`Enrichment.Signer == ""` or ledger `unknown`/`mismatch`/`known_bad`); an unowned file in a system directory; ledger `mismatch`; `/etc/ld.so.preload` content; a new `pam` or NSS module; IFEO debugger; LSA package; `ServerLevelPluginDll`; a unit with `env_ld_preload` or ambient capabilities; an AD privileged-group member outside the allowlist (from `ad.finding`). Medium: added `cron`/`timer`/`task` with a script action; new `suid` or `cap`; added `authorized_key`; `immutable` on a unit, sudoers or webroot file; PHP `disable_functions` or `auto_prepend_file` differences; modified default config. Low: everything else. Heuristics (`hunt/heuristics.yml`): service path under a user directory; LocalSystem service with no description; service name of five characters or fewer; name entropy above 3.5; AD user `Description`, `Company` or `Department` length outliers (more than 3 standard deviations from the host's mean).

- [ ] **Step 1: Write the failing tests:**

```go
func TestComputeAddedModifiedMissing(t *testing.T) {
	ref := Baseline{Artifacts: []Artifact{{Kind: "cron", Key: "/etc/cron.d/a", Attrs: m("sha256", "1")}, {Kind: "cron", Key: "/etc/cron.d/gone"}}}
	cur := Collection{Artifacts: []Artifact{{Kind: "cron", Key: "/etc/cron.d/a", Attrs: m("sha256", "2")}, {Kind: "cron", Key: "/etc/cron.d/new"}}}
	d := Compute(ref, nil, cur)
	if len(d.Added) != 1 || len(d.Modified) != 1 || len(d.Missing) != 1 {
		t.Fatalf("%+v", d)
	}
}
func TestInventoryRowsBecomeArtifacts(t *testing.T) { /* an accounts row "hidden" and a kernel_modules row "evil" -> Artifacts of kind account and kmod that Compute reports as Added against a reference without them */ }
func TestAcceptedBaselineSilencesAdded(t *testing.T) { /* the new artifact in accepted with equal attrs -> Added empty; a changed attr -> reported again */ }
func TestScoreHighMediumLow(t *testing.T) {
	cases := []struct{ a Artifact; enrich Enrichment; want string }{
		{Artifact{Kind: "ld_preload", Key: "/etc/ld.so.preload"}, Enrichment{}, "high"},
		{Artifact{Kind: "runkey", Key: `HKLM\...\Run\u`, Attrs: m("ref", `C:\Users\Public\u.exe`)}, Enrichment{Signer: ""}, "high"},
		{Artifact{Kind: "authorized_key", Key: "/home/b/.ssh/authorized_keys"}, Enrichment{}, "medium"},
		{Artifact{Kind: "profile", Key: "/etc/profile.d/x.sh"}, Enrichment{}, "low"},
	}
	for _, c := range cases {
		s := Score(Diff{Added: []Artifact{c.a}}, func(Artifact) Enrichment { return c.enrich }, testHeuristics())
		if len(s) != 1 || s[0].Score != c.want {
			t.Errorf("%s: %+v", c.a.Kind, s)
		}
	}
}
func TestHeuristicRaisesOneLevelNeverCreatesHigh(t *testing.T) {
	h := testHeuristics()
	low := Artifact{Kind: "service", Key: "ab", Attrs: m("ref", `C:\Users\Public\x.exe`)} // short name, user path, otherwise low
	if got := Score(Diff{Added: []Artifact{low}}, noEnrich, h); got[0].Score != "medium" {
		t.Fatalf("low+hit: %+v", got)
	}
	med := Artifact{Kind: "authorized_key", Key: "/home/b/.ssh/authorized_keys", Attrs: m("ref", "/tmp/x")}
	if got := Score(Diff{Added: []Artifact{med}}, noEnrich, h); got[0].Score != "high" {
		t.Fatalf("medium+hit: %+v", got)
	}
	if got := Score(Diff{}, noEnrich, h); len(got) != 0 {
		t.Fatal("a heuristic must not invent a finding")
	}
}
func TestLoadBaselineRejectsTamper(t *testing.T) { /* a baseline whose .sig does not verify under SSHVerifier -> error; unsigned -> error */ }
func TestEntropyHeuristic(t *testing.T)         { /* "x7Qz9pLmW2" above 3.5, "svchost" below */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/hunt/ -run 'Compute|Accepted|Score|Heuristic|LoadBaseline|Entropy' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** (no I/O in `Compute` and `Score`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/hunt/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "hunt: baseline loader, diff, scoring and heuristics"`

---

### Task 34: `hunt` controller module: runner, triggers, `hunt_finding` table

**Files:**
- Create: `internal/hunt/controller.go`, `internal/hunt/migrations.go`, `internal/hunt/agentmodule.go`
- Modify: `internal/agent/mods/hunt.go` (agent factory over `agentmodule.go`), `internal/module/conformance/allowed.go` (remove `hunt` from `PreContract`)
- Test: `internal/hunt/controller_test.go`, `internal/hunt/conformance_test.go`

**Interfaces:**
- Consumes: `module.Host`, `Host.RunReadOnly`, `Host.Subscribe`, `Host.Query` (including the core `inventory_rows`), `Host.Tables`, `Host.Emit`, `Host.UpdateOverrides`, `Compute`, `Score`, `ArtifactsFromInventory`, `LoadBaseline`, `event.New`, the core `operator.edit` kind, `conformance.Agent`, `conformance.Controller`.
- Produces: `Controller` (ControllerModule) and `AgentModule` (a factory whose module only reports health: `ok`, or `degraded` with gap "cross-checks run without root"):
  - Triggers: `agent.enrolled` (`enroll`), `agent.reenrolled`, `backup.restored` (`restore`), `plan.failed` with `reason: auto_halted` (`lineage`: the attempt ledger's breaker opened, S1), a per-host ticker every `repeat_interval_sec` (default 600; `interval`), and a manual request from the UI (`manual`). Each trigger starts `Host.RunReadOnly("hunt", "prebake", {host, trigger})` (class `auto_readonly`).
  - On the step results for `hunt.baseline_diff`/`hunt.persistence`/`hunt.apps`/`hunt.creds`/`hunt.remote_access` (read from the store through `Query`) merged with the host's `inventory_rows` (the repeat is a diff of the rows that arrived since the last run, not a full collect), the writer goroutine diffs against the OS baseline, enriches (verdict join: latest `integrity.verdict` events for the host, path and hash; package owner from the artifact's `owner_pkg`), scores, writes `hunt_finding` and emits `hunt.finding` (priority high for High) and `hunt.run`.
  - First run on a host: artifacts that exist only because the real image differs (first-sweep `unknown` verdicts and the first diff's extras) are listed in the Triage view, read from the events and the run result; a triage item creates no `hunt_finding` row, and accepting one is one overrides entry.
  - No baseline for the host's OS: the host is collected, not diffed; health `degraded` with gap `no reference for this OS version`.
  - `hunt_finding(id, host, kind, key, score, state, outcome, evidence_json, updated)`: `state` is `open` or `acked` as for any alert, and an acked row has `outcome` `approved`, `rejected`, `accepted` or `remediated`. A row is created by a `hunt.finding` event and moved only by the core `operator.edit` events (module `hunt`, `op` in `approve`, `reject`, `accept`, `remediated`); the buttons emit the event and never write the table (decision 6). `accept` also appends one `Overrides.Accepted{kind: hunt}` entry, which is the host's live baseline that `Compute` reads.

- [ ] **Step 1: Write the failing tests:**

```go
func TestNoBaselineDegradesNotDiffs(t *testing.T) { // Review Focus 3
	h := newHuntHost(t, withOS("debian-12"), noBaselines())
	c := startController(t, h)
	h.deliverCollection("h1", fixtureCollection())
	waitFor(t, func() bool { return c.Health().State == module.StateDegraded })
	if got := c.Health().Gaps; len(got) != 1 || !strings.Contains(got[0].What, "reference") {
		t.Fatalf("%+v", got)
	}
	if n := rowCount(h, "hunt_finding"); n != 0 {
		t.Fatalf("invented %d findings", n)
	}
}
func TestTriggersStartReadOnlyPlans(t *testing.T) {
	for _, kind := range []string{"agent.enrolled", "agent.reenrolled", "backup.restored", "plan.failed"} {
		h := newHuntHost(t)
		startController(t, h)
		h.publishTrigger(kind, "h1") // builds the valid payload; plan.failed carries reason auto_halted
		waitFor(t, func() bool { return h.readOnlyRuns() == 1 })
		if h.lastRun().Template != "prebake" || h.lastRun().Params["trigger"] == "" {
			t.Fatalf("%s: %+v", kind, h.lastRun())
		}
	}
}
func TestRepeatEveryInterval(t *testing.T)    { /* repeat_interval_sec 1 with a fake clock: two runs after 2 s per host */ }
func TestRepeatDiffsInventoryRows(t *testing.T) { /* a new accounts row arrives as inventory.row between two runs -> the second run reports it Added with no collection step for it */ }
func TestFirstRunUnknownsGoToTriage(t *testing.T) { /* first-sweep unknown verdict for /opt/x -> listed in Triage, no hunt_finding row */ }
func TestFindingAndRunEventsEmitted(t *testing.T) { /* High finding -> hunt.finding priority high plus hunt.run with Added/Modified counts */ }
func TestDecisionsAreCommandEvents(t *testing.T)  { /* Approve/Accept/Reject emit operator.edit (module hunt); the row moves open -> acked with outcome only after the writer applies the event; no direct table write; Accept adds exactly one Overrides.Accepted entry */ }
func TestHuntConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Controller{}, Config: "enabled: true\n", Now: fixedNow})
	conformance.Agent(t, conformance.AgentCase{Factory: factoryNamed(t, "hunt"), Default: cfgHunt(900), Reconfig: cfgHunt(600)})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/hunt/ -run 'NoBaseline|Triggers|Repeat|FirstRun|FindingAndRun|Decisions|HuntConformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Remove `hunt` from `PreContract`; generate schemas; write `manifest/2027/modules/hunt.yml` as in the design.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/hunt/ ./internal/module/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "hunt: controller module, triggers, findings table, conformance"`

---

### Task 35: Hunts page, remediation proposals and the scored-state refusal

**Files:**
- Create: `internal/hunt/ui.go`, `internal/hunt/remediate.go`, `plans/hunt/remediate_*.yaml` (nine templates)
- Test: `internal/hunt/ui_test.go`, `internal/hunt/remediate_test.go`

**Interfaces:**
- Consumes: `module.Host.UI`, `Host.Propose`, `module.Proposal`, `manifest.Manifest` (scored services), templates under `plans/hunt/`.
- Produces: the Hunts page (`/hunts`): queue grouped by host with High first, evidence per finding, Triage tab, baseline views, cross-check results; buttons Approve (emit `operator.edit{module: hunt, op: approve}` and `Propose` the remediation template for the artifact kind), Accept (`op: accept` plus one overrides entry), Reject (`op: reject`), Open IR draft (a `Propose` of `report`'s draft template is not available to `hunt`; the button links to `/report/ir?finding=<id>` and `report` (W10) reads `hunt.finding` at High; nothing to build here). Remediation templates, each `module: hunt`, one disable-or-quarantine node, `scoring_note`, `probe`, params `host` and `key`: `remediate_cron` (`cron.disable`), `remediate_unit` (`service.state{state: disabled}`), `remediate_mask` (`service.state{state: masked}`), `remediate_task` (`task.disable`), `remediate_wmi` (`wmi.subscription_remove`), `remediate_runkey` (`runkey.remove`), `remediate_preload` (`ld_preload.clear`), `remediate_caps` (`caps.clear`), `remediate_file` (`file.attr` clear immutable then `file.quarantine`). `Remediation(f Finding) (template string, params map[string]string, err error)` maps a kind to one; it returns `ErrScoredState` when the artifact is a scored service's own unit or path (manifest `services.yml` process units and pinned binaries), and the page shows the button disabled with the reason.

- [ ] **Step 1: Write the failing tests:**

```go
func TestRemediationRefusedForScoredUnit(t *testing.T) { // Review Focus 5
	m := manifestWithScored("h1", "web", "httpd.service")
	_, _, err := Remediation(m, Finding{Host: "h1", Kind: "unit", Key: "/usr/lib/systemd/system/httpd.service"})
	if !errors.Is(err, ErrScoredState) {
		t.Fatalf("got %v", err)
	}
}
func TestRemediationMapsKinds(t *testing.T) {
	for kind, tpl := range map[string]string{"cron": "remediate_cron", "unit": "remediate_unit", "runkey": "remediate_runkey", "task": "remediate_task", "wmi": "remediate_wmi", "ld_preload": "remediate_preload", "cred_file": "remediate_file"} {
		got, params, err := Remediation(testManifest(), Finding{Host: "h1", Kind: kind, Key: "k"})
		if err != nil || got != tpl || params["host"] != "h1" {
			t.Errorf("%s: %s %v %v", kind, got, params, err)
		}
	}
}
func TestRemediationTemplatesNeverDelete(t *testing.T) {
	// load every plans/hunt/remediate_*.yaml via plans.Parse: module hunt, scoring_note and probe set, and no node action in {file.delete, user.delete, pkg.remove, web.remove_dir}
}
func TestApproveCreatesProposalNotApply(t *testing.T) { /* POST approve -> Host.Propose called once with the template and one operator.edit op approve emitted; no RunAuto/RunStanding, no direct table write */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/hunt/ -run 'Remediation|ApproveCreates' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Host-grid column `hunt clean` (verified when the last run has no open High or Medium finding and no pending triage; `pending` while the first run is pending); overview tile `open High findings`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/hunt/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "hunt: Hunts page and remediation proposals"`

---

### Task 36: Hunt plan content: `prebake`, `verify_hardening`, `quarantine`, `hash_everywhere`

**Files:**
- Create: `plans/hunt/prebake.yaml`, `plans/hunt/verify_hardening.yaml`, `plans/hunt/quarantine.yaml`, `plans/hunt/hash_everywhere.yaml`
- Test: `plans/hunt_test.go`

**Interfaces:**
- Consumes: `plans.Parse` (Task 37), the action catalog, `Template.Module`.
- Produces: all four `module: hunt`, validated against the catalog:
  - `prebake` (params `host`, `trigger`, `first_sweep`): nodes `ledger.sweep{first_sweep: ${first_sweep}}` (the controller passes `first_sweep=true` for the triggers `enroll`, `restore` and `reenroll`, else `false`; the sweep is cheap on a warm cache), `collect.inventory` (a differential collection of the tables the reference covers; it sends only changed rows, so running it on every trigger is cheap and `collect.hunt` is not needed), `hunt.baseline_diff`, `hunt.persistence`, `hunt.apps`, `hunt.creds`, `hunt.remote_access`, each read-only, `needs` in parallel, target `${host}`.
  - `verify_hardening`: the post-hardening adversarial verification (D406): `health.check` of the touched services, `net.tcp_probe` of a canary closed port, a `command.check` that the old default password does not authenticate (secret reference, never inline), and the credential verification as a `probe.run` step on the Kali (S4: PCR verification is a `probe.run` step, not a vantage sub-role).
  - `quarantine` (`host`, `path`): `file.attr` (clear immutable) then `file.quarantine`.
  - `hash_everywhere` (`sha256`): `collect.files{hash: ...}` per label `linux` / `windows` host (labels from Task 37).

- [ ] **Step 1: Write the failing tests:**

```go
func TestHuntPlansValidate(t *testing.T) {
	cat, _ := NewCatalog()
	for _, p := range []string{"hunt/prebake.yaml", "hunt/verify_hardening.yaml", "hunt/quarantine.yaml", "hunt/hash_everywhere.yaml"} {
		tpl, err := Load(p)
		if err != nil || tpl.Module != "hunt" {
			t.Fatalf("%s: %v", p, err)
		}
		pl, err := tpl.Expand(cat, map[string]any{"host": "h1", "trigger": "enroll", "first_sweep": "true", "path": "/tmp/x", "sha256": strings.Repeat("a", 64)})
		if err != nil || pl.Validate(cat) != nil {
			t.Fatalf("%s: %v / %v", p, err, pl.Validate(cat))
		}
	}
}
func TestPrebakeIsReadOnly(t *testing.T) { /* every prebake node's action is ReadOnly in the registry */ }
func TestVerifyHardeningNoInlineSecrets(t *testing.T) { /* no param value matches a password-like literal; secret_params used */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./plans/ -run 'HuntPlans|PrebakeIsReadOnly|VerifyHardening' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the four files.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./plans/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "plans: hunt prebake, verify_hardening, quarantine and hash_everywhere"`

---

### Task 37: Pack format: `module:` required, label variables in the packs, move to `plans/hardening/`, Known bug 9

**Files:**
- Move (`git mv`): `plans/first-hour/*.yaml` → `plans/hardening/`
- Modify: `plans/hardening/*.yaml` nodes that name a special-case action become the general one (S4): `windows.smb1` → `registry.set` of the SMB1 value, `mssql.audit`/`mssql.lock` → `sql.query{engine: mssql, statement}`, `kernel.module_block` → `file.write` plus the `command.check{probe: af_alg_aead}` node of Task 40; the special-case actions are deleted from `internal/actions` in the same commit (`ad_netlogon.go`'s `windows.smb1`, `mssql_audit.go`, `mssql_lock.go`)
- Modify: `plans/plans.go` (`//go:embed *.yaml */*.yaml`; `Parse` errors `plan template has no module:` when `Module` is empty; `Paths()` skips `actions.yaml` only; `Parse`, `ResolveLabels` and `Template.Module` themselves are W1 Task 22b's), `plans/actions.yaml` (header), `plans/hardening/*.yaml` (add `module: hardening`; ids keep the `fh.` prefix; replace host-name `vars` with `{labels: ...}` where the host set is a role: `dcs: {labels: "dc"}`, `linux_hosts: {labels: "linux && !workstation"}`), (`controller.LoadModuleTemplateFor` and the W1 call sites passing `c.hostsMatching` are W1 Task 22b's)
- Test: `plans/plans_test.go` (extend), `internal/controller/pack_template_test.go`

**Interfaces:**
- Consumes: W1 Task 22b `plans.Parse`, `plans.ResolveLabels`, `Template.Module`, `controller.LoadModuleTemplateFor`; W1 `manifest.ParseLabels`, `(*Manifest).HostsMatching`.
- Produces: `plans.Parse` refuses a template without `module:` (error `plan template has no module:`; design: a file without `module:` fails CI); every pack file lives under `plans/hardening/` with `module: hardening`.

`plans/actions.yaml` header: replace the "Each is a TODO" text by "Action specs the plan templates use that the agent catalog does not register yet. The file is empty when every template action is implemented; a name listed here must not be registered (the catalog loader refuses it)." (Known bug 9, T65.)

- [ ] **Step 1: Write the failing tests:**

```go
func TestEveryTemplateHasModule(t *testing.T) {
	for _, p := range Paths() {
		tpl, err := Load(p)
		if err != nil || tpl.Module == "" || !strings.HasPrefix(p, tpl.Module+"/") {
			t.Errorf("%s: module %q err %v", p, tpl.Module, err)
		}
	}
}
func TestActionsYamlHeaderNoTodo(t *testing.T) { // Known bug 9
	b, _ := FS.ReadFile("actions.yaml")
	if bytes.Contains(b, []byte("TODO")) {
		t.Fatal("header still says TODO")
	}
}
func TestRunAutoLoadsPackWithLabels(t *testing.T) { /* internal/controller: the real plans/hardening dc pack loads through LoadModuleTemplateFor(c.hostsMatching) against a test manifest with a host labelled dc and yields per-host nodes */ }
func TestParseRequiresModule(t *testing.T) { /* Parse of a pack without module: -> error containing "no module" */ }
func TestNoSpecialCaseActionsInPacks(t *testing.T) { /* no node in plans/ names windows.smb1, mssql.audit, mssql.lock, mysql.audit, kernel.module_block, unit.disable, unit.mask or binary.restore_from_depot, and none of them is registered in actions.Core() (S4) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./plans/ ./internal/controller/ -run 'EveryTemplateHasModule|ParseRequiresModule|ActionsYaml|PackWithLabels|NoSpecialCaseActions' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Other modules' templates in `plans/` (wazuh, splunk, deception) move to `plans/<module>/` with their own workstreams; until then `TestEveryTemplateHasModule` skips the three root-level files that name W9/W11 in a table at the top of the test (`shortcut: root-level templates belong to W9 and W11, delete the skip entries when they move`).
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "plans: module header required, plans/hardening (Known bug 9)"`

---

### Task 38: `hardening` module: config, health and lint `HD002`

**Files:**
- Modify: `internal/hardening/module.go`, `internal/hardening/lint.go`
- Create: `internal/hardening/health.go`, `manifest/2027/modules/hardening.yml`, `internal/hardening/conformance_test.go`
- Modify: `internal/module/conformance/allowed.go` (remove `hardening` from `PreContract`)
- Test: `internal/hardening/module_test.go`

**Interfaces:**
- Consumes: `plans.Paths`, `plans.Load`, `plans.NewCatalog`, `module.Host.Config`, `lint.Register`, `store.Reader.Latest`.
- Produces: `Module` (ControllerModule): `Start` decodes `Config`, validates every template under `plans/hardening/` against the catalog; health `ok` when all validate, `degraded` listing templates that name an action the catalog does not have (gap `{template, "unavailable: <action>"}`); each `PackTarget.Autonomy` is validated against `propose|shadow|auto` and defaults to `auto` for a pack without a reboot-class gate and `propose` for one with (S1: this replaces the module's `auto` allowlist; the engine applies the autonomy and the attempt ledger, this module only carries the value); lint rule `HD002`: a node with action `win.audit_policy.set`, `registry.set` of the Sysmon config, `file.write` of the Sysmon config or `sysmon.install` on a host whose latest `Health.Info` `sysmon` entry (the `agent.health` data the controller stores; `telemetry_gap{reason: sysmon_degraded}` is the same fact) says Sysmon is down, or the `config_hash` differs from `expected_config_hash` with no 4688 fallback active, is a finding ("sensor down: <reason>").

- [ ] **Step 1: Write the failing tests:**

```go
func TestHardeningHealthDegradedOnMissingAction(t *testing.T) {
	m := &Module{templates: fakeTemplates("fh.x", "action.that.does.not.exist")}
	m.validate()
	if h := m.Health(); h.State != module.StateDegraded || h.Gaps[0].What != "fh.x" {
		t.Fatalf("%+v", h)
	}
}
func TestHardeningHealthOKForShippedPacks(t *testing.T) { /* real plans/hardening: ok, or degraded naming only actions from Task 24/25 not yet merged */ }
func TestPackAutonomyDefaults(t *testing.T) { /* a pack without a reboot-class gate defaults to auto, one with a gate to propose; "sometimes" is a config error; the gate: approval node stays a click whatever the value */ }
func TestHD002RefusesWhenSysmonDown(t *testing.T)  { /* latest Health.Info sysmon running=false -> finding naming the reason; running with equal hash -> none; 4688 fallback active -> none */ }
func TestHardeningConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Module{}, Config: "enabled: true\npacks: []\n", Now: fixedNow})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/hardening/ -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Reference-manifest block in `hardening.yml` exactly as the design's Configuration (packs, `noexec_temp`, `banner`, `password_policy`, `reboot_class`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/hardening/ ./internal/module/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "hardening: controller module, template health and HD002 lint"`

---

### Task 39: Pack content A: `win.baseline`, `linux.baseline`, `php.harden`, `remote_access.manifest_only`, service templates

**Files:**
- Create: `plans/hardening/{win.baseline,linux.baseline,php.harden,remote_access.manifest_only}.yaml`, `plans/hardening/templates/{httpd,php,postfix,dovecot,splunk,dns}.yaml` (service configuration templates)
- Test: `plans/hardening_packs_test.go`, `internal/hardening/packs_lint_test.go`

**Interfaces:**
- Consumes: the catalog (existing actions: `registry.set`, `win.defender`, `win.audit_policy.set`, `sysctl.set`, `file.perms`, `file.template`, `service.state`, `health.check`, `command.check`), `lint.Run`.
- Produces content per the design's Baseline packs table. Every pack: `module: hardening`, `scoring_note`, `probe`, one setting per node, `deadman_sec` on link-cutting nodes (default 90), scorer-mimic probe node before and after for touched services, `needs` so a failed before-probe stops the node. `win.baseline`: WDigest off (`UseLogonCredential=0`), LSA PPL (`RunAsPPL`, reboot-class gate), SMB signing, LDAP signing (gated, off by default per the open item), NTLMv2-only session security (never below `LmCompatibilityLevel` 3), Kerberos pre-auth on unscored accounts, Defender exclusions cleared keeping only the agent's directory, ASR in audit mode, PowerShell module, script-block and transcription logging. `linux.baseline`: `kernel.yama.ptrace_scope`, protected symlinks/hardlinks/FIFOs/regular files, `user.max_user_namespaces` where unused, SUID strip on LOLbins no scored service needs, compiler quarantine (`file.quarantine`, not removal); never touches `sshd`, `sudo`, `su`, `passwd` or pinned binaries. `php.harden`: dangerous-function and include-path restrictions, `php -l` and `apachectl -t` validators, probe on the storefront page and the Orange flow, rollback by baseline file; never turns uploads off. `remote_access.manifest_only`: disable undeclared SSH/WinRM/RDP, never a declared one. Service templates carry their lint rules (no `PasswordAuthentication no`, no STARTTLS-required, no `disable_plaintext_auth=yes`).

- [ ] **Step 1: Write the failing tests:**

```go
func TestBaselinePacksValidate(t *testing.T) {
	cat, _ := NewCatalog()
	for _, p := range []string{"hardening/win.baseline.yaml", "hardening/linux.baseline.yaml", "hardening/php.harden.yaml", "hardening/remote_access.manifest_only.yaml"} {
		tpl, err := Load(p)
		if err != nil || tpl.Scoring == "" || tpl.Probe == "" || tpl.Module != "hardening" {
			t.Fatalf("%s: %+v %v", p, tpl, err)
		}
		ov, _ := ResolveLabels(tpl, refHosts) // the reference manifest's hosts
		pl, err := tpl.Expand(cat, ov)
		if err != nil || pl.Validate(cat) != nil {
			t.Fatalf("%s: %v %v", p, err, pl.Validate(cat))
		}
	}
}
func TestPacksPassTheLintOnReferenceManifest(t *testing.T) { /* lint.Run over every expanded pack with the 2027 reference manifest: zero findings */ }
func TestLintRejectsUnsafeVariants(t *testing.T) { // T16/T34 CI half
	for name, node := range map[string]plan.Node{
		"PasswordAuthentication no":  fileWriteNode("h1", "/etc/ssh/sshd_config.d/x.conf", "PasswordAuthentication no\n"),
		"lockout GPO on scored acct": registryNode("h1", `HKLM\...\Lsa`, "LmCompatibilityLevel", "1"),
		"disable_plaintext_auth":     fileWriteNode("h1", "/etc/dovecot/conf.d/10-auth.conf", "disable_plaintext_auth = yes\n"),
		"noexec with scored exec":    remountNode("h1", "/tmp", "noexec"),
	} {
		if len(lint.Run(plan.Plan{Nodes: []plan.Node{node}}, scoredCtx(t))) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
}
func TestNoPackNodeTouchesPinnedBinaries(t *testing.T) { /* linux.baseline nodes never name sshd, sudo, su, passwd paths */ }
func TestPackNodeSettingsAreOnePerNode(t *testing.T)  { /* no node's params contain more than one key besides path/unit/state/validate/deadman */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./plans/ ./internal/hardening/ -run 'BaselinePacks|PassTheLint|UnsafeVariants|PinnedBinaries|OnePerNode' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the content. If a needed lint rejection does not exist in W1's `SS000`, record the missing rule in the report instead of adding it here.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./plans/ ./internal/hardening/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "plans: baseline hardening packs and service templates"`

---

### Task 40: Pack content B: `ad.baseline`, banner and password policy, reboot preflight, noexec, local-root bundle

**Files:**
- Create: `plans/hardening/{ad.baseline,banner.policy,password.policy,preflight.reboot_survival,linux.noexec_temp,dc.service_repair}.yaml`
- Modify: `plans/hardening/linux.local_root_bundle.yaml` (AF_ALG branch and reboot gate)
- Test: `plans/hardening_packs_b_test.go`

**Interfaces:**
- Consumes: Tasks 21 to 25 actions, `ad.recycle_enable` (Task 45, named here, `Missing()` until it merges), `service.sddl_reset` (Task 44), `collect.inventory` (W3), `file.write` and `command.check{probe: af_alg_aead}` (Task 24).
- Produces: `ad.baseline` (first node `ad.recycle_enable`, then `ad.account.admincount_sweep`, `ad.account.group_remove` purge behind its own approval, MAQ 0 through `registry.set`/ADSI, `StrongCertificateBindingEnforcement`, PetitPotam EFS filter, WebClient off); `banner.policy` and `password.policy` read values from `overrides` (`${banner_ref}`, `${password_policy_ref}`; no text and no defaults ship) and end with a node dumping the effective values; `preflight.reboot_survival` (five checks of the design, the post-reboot listener comparison closes the plan); `linux.noexec_temp` (HD001-linted `mount.remount` with options `noexec,nosuid`, verify, rollback; no `fstab` write); `dc.service_repair` (`service.sddl_reset` for RpcSs, W32Time, Netlogon, KDC, ADWS, DNS with DNS and WinRM probes before and after); `linux.local_root_bundle`: `pkexec` chmod (`file.perms`), the `algif_aead` block as a `file.write` of the modprobe blacklist line, a `command.check{probe: af_alg_aead, fail_if_vulnerable: true}` node that `needs` the write (Known bug 1: it fails the bundle while the aead socket still opens), the `sudo -V` check, and a node `module_block_cmdline` (a `file.write` of `initcall_blacklist=algif_aead_init` into the GRUB default command line, with the `validate` hook) behind `gate: approval` that `needs` the preflight; the failed check's message tells the operator to take that branch.

- [ ] **Step 1: Write the failing tests:**

```go
func TestADBaselineEnablesRecycleBinFirst(t *testing.T) {
	pl := expand(t, "hardening/ad.baseline.yaml")
	if pl.Nodes[0].Action != "ad.recycle_enable" || len(pl.Nodes[0].Needs) != 0 {
		t.Fatalf("%+v", pl.Nodes[0])
	}
	for _, n := range pl.Nodes[1:] {
		if !dependsOn(pl, n.ID, pl.Nodes[0].ID) && n.Action != "ad.zerologon_check" {
			t.Errorf("%s does not wait for the Recycle Bin", n.ID)
		}
	}
}
func TestBannerAndPasswordPolicyShipNoText(t *testing.T) { /* no literal banner text or numeric policy default in the files: every value is ${..._ref} */ }
func TestRebootGateIsAClickEvenInAutoPlan(t *testing.T)  { /* the reboot node is gate: approval whatever the pack's autonomy */ }
func TestPreflightClosesWithListenerComparison(t *testing.T) { /* last node is the post-reboot compare and needs the reboot */ }
func TestNoexecPackUsesHD001Path(t *testing.T)          { /* the remount node is linted by HD001 on a host with a scored exec from /tmp (finding) and clean host (none) */ }
func TestLocalRootBundleHasCmdlineBranchBehindGate(t *testing.T) { /* module_block_cmdline needs a gate: approval node which needs preflight.reboot_survival */ }
func TestLocalRootBundleChecksAFAlgAfterWrite(t *testing.T) { // Known bug 1, bundle half
	/* the bundle has no kernel.module_block node; the af_alg_aead command.check needs the modprobe file.write node and has fail_if_vulnerable true */
}
func TestServiceRepairListsSixServices(t *testing.T)    { /* six sddl_reset nodes plus before/after DNS and WinRM probes */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./plans/ -run 'ADBaseline|BannerAndPassword|RebootGate|PreflightCloses|NoexecPack|LocalRootBundle|ServiceRepair' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Actions not yet merged are named in the content and reported by `Catalog.Missing()`; the test tolerates exactly `ad.recycle_enable` and `service.sddl_reset` being missing until Tasks 44 and 45 land.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./plans/`. Expected: PASS (T72 and T68 CI halves; Known bug 1 branch in content).
- [ ] **Step 5: Commit.** `git commit -am "plans: ad.baseline, banner, password policy, reboot preflight, noexec, local-root bundle"`

---

### Task 41: `ADBackend` read methods and the fake

**Files:**
- Modify: `internal/actions/ad_backend.go` (interface), `internal/actions/ad_adsi_windows.go`'s moved copy `internal/ad/adsi_windows.go`, `internal/ad/fake_test.go`
- Test: `internal/ad/backend_fake_test.go`

**Interfaces:**
- Consumes: `ADObject`, `ADBackend`.
- Produces: the added methods (all read-only, each bounded to 10000 results):

```go
type ADBackend interface {
	// existing methods unchanged ...
	ListUsers(ctx context.Context) ([]ADObject, error)            // Description, Company, Department, WhenCreated, SPNs, delegation flags, KeyCredentialLinks, SIDHistory filled
	SPNs(ctx context.Context, dn string) ([]string, error)
	Delegation(ctx context.Context, dn string) (Delegation, error) // Unconstrained, ConstrainedTo []string, RBCD []string
	KeyCredentialLinks(ctx context.Context, dn string) (int, error)
	SIDHistory(ctx context.Context, dn string) ([]string, error)
	ACL(ctx context.Context, dn string) ([]ACE, error)             // principal SID/SAM, right (GenericAll, WriteDacl, WriteOwner, ForceChangePassword, AddMember, Replication), inherited bool
	GPOs(ctx context.Context) ([]GPO, error)                       // GUID, Name, Version, Links []string (gPLink targets), Enforced map[link]bool, Flags, Path
	KrbtgtPwdLastSet(ctx context.Context) (time.Time, error)
	MachineAccountQuota(ctx context.Context) (int, error)
}
type ADObject struct{ /* existing + */ Description, Company, Department string; WhenCreated time.Time }
```

`shortcut: ADBackend reads for ACLs and GPO links are implemented over ADSI on Windows only and compile-checked on Linux CI; upgrade at the first DC lab run.`

- [ ] **Step 1: Write the failing tests:**

```go
func TestFakeADReadMethods(t *testing.T) {
	d := newFakeAD(t)
	d.addUser("svc", withSPN("MSSQLSvc/db:1433"), withDelegation(true), withKeyCreds(1), withSIDHistory("S-1-5-21-0-0-0-519"))
	us, _ := d.ListUsers(ctx)
	if len(us) != 1 {
		t.Fatalf("%+v", us)
	}
	if s, _ := d.SPNs(ctx, us[0].DN); len(s) != 1 {
		t.Fatal("spn")
	}
	if dl, _ := d.Delegation(ctx, us[0].DN); !dl.Unconstrained {
		t.Fatal("delegation")
	}
	if n, _ := d.KeyCredentialLinks(ctx, us[0].DN); n != 1 {
		t.Fatal("key creds")
	}
}
func TestExistingActionsStillPassOnExtendedFake(t *testing.T) { /* go test ./internal/ad: moved action tests compile against the extended interface */ }
func TestADSIImplementsInterfaceOnWindows(t *testing.T)       { /* compile-time: var _ actions.ADBackend = (*adsiBackend)(nil) in adsi_windows.go; the test file asserts via go vet GOOS=windows in the make target */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/ad/ -run 'FakeADRead|ExistingActions' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the interface, the fake and the ADSI methods.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "ad: ADBackend read methods for the continuous checks"`

---

### Task 42: `hunt.ad`: continuous checks, the allowlist audit and the path query

**Files:**
- Create: `ad/checks.yml`, `internal/ad/checks.go`, `internal/ad/pathquery.go`
- Test: `internal/ad/checks_test.go`, `internal/ad/pathquery_test.go`

**Interfaces:**
- Consumes: `ADBackend` (Task 41), `actions.ResolveMembers`, `actions.PrivilegedGroups`, `FindingEvent`. `ADSettings.PrivilegedAllow` is the manifest allowlist plus the `Overrides.Accepted` entries of kind `ad` (the controller merges them when it renders the settings); the check never stores an accept itself.
- Produces:

```go
type Check struct{ Name, Severity string } // loaded from ad/checks.yml, strict
func RunChecks(ctx context.Context, ad actions.ADBackend, s *plan.ADSettings, now time.Time, dropFlag time.Time) ([]FindingEvent, error)
// PathQuery builds a per-run graph from LDAP-readable edges only and returns, for each non-privileged principal that can reach Domain Admins,
// the shortest path (max_depth, default 6) with the edge kind at each step.
func PathQuery(ctx context.Context, ad actions.ADBackend, maxDepth int) ([]FindingEvent, error)
```

Action `hunt.ad` (`none`, `ReadOnly`) runs both and returns the findings as JSON in `Output["findings"]`. Checks (`ad/checks.yml` names): `privileged_member_unexpected` (High, regardless of `whenCreated`; nested groups resolved; `CN=Builtin`), `privileged_new_since_dropflag`, `spn_on_user`, `delegation_unconstrained`, `delegation_constrained`, `delegation_rbcd`, `key_credential_link`, `sid_history`, `adminsdholder_ace`, `domain_replication_right`, `gpo_inventory` (feeds Task 43), `krbtgt_age`, `maq_nonzero`, `dnsadmins_members`, `secure_channel_weak`, `description_outlier`, `description_password_like`. Edges: nested membership, `GenericAll`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, `AddMember` on a privileged group, user or the domain object and AdminSDHolder, delegation to a DC service, write rights on a GPO linked to the domain or the DC OU, SID history, key-credential links.

- [ ] **Step 1: Write the failing tests:**

```go
func TestAllowlistAuditFlagsTempAdmin(t *testing.T) {
	d := fakeDomain(t)
	d.addUser("Administrator").inGroup("Domain Admins")
	d.addUser("Richard G Johnson").inGroup("Domain Admins") // seeded prebaked admin
	fs, _ := RunChecks(ctx, d, &plan.ADSettings{PrivilegedAllow: map[string][]string{"Domain Admins": {"Administrator"}}}, now, drop)
	f := byCheck(fs, "privileged_member_unexpected")
	if len(f) != 1 || f[0].Object != "Richard G Johnson" || f[0].Severity != "high" {
		t.Fatalf("%+v", fs)
	}
}
func TestNestedAdminGroupFound(t *testing.T)   { /* "Admin admin" inside group Helpdesk inside Enterprise Admins -> finding with nesting in Detail */ }
func TestPathQueryWriteDaclEdge(t *testing.T) {
	d := fakeDomain(t)
	d.addUser("alice")
	d.grant("alice", "WriteDacl", "Domain Admins")
	ps, _ := PathQuery(ctx, d, 6)
	if len(ps) != 1 || ps[0].Object != "alice" || ps[0].Path[0].Edge != "WriteDacl" {
		t.Fatalf("%+v", ps)
	}
}
func TestPathQueryDelegationAndGPOEdges(t *testing.T) { /* delegation to a DC service and write right on a GPO linked to the DC OU each yield a path; depth 1 limit hides a 3-hop path */ }
func TestChecksFileLoadsStrictly(t *testing.T)        { /* ad/checks.yml unknown field -> error; every RunChecks name appears in the file */ }
func TestOutlierAndPasswordLikeDescriptions(t *testing.T) { /* 40 users with 20-char descriptions and one 200-char -> description_outlier; "pw: Spring2027!" -> description_password_like */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/ad/ -run 'Allowlist|Nested|PathQuery|ChecksFile|Outlier' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `shortcut: the path query reads LDAP-visible edges only (membership, ACLs, delegation, GPO rights), not session or local-admin edges; upgrade only if a purple-team run shows a path it misses.`
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/ad/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "ad: hunt.ad continuous checks, allowlist audit and path query"`

---

### Task 43: GPO actions: baseline, effective state, unlink, disable, restore

**Files:**
- Create: `internal/ad/gpo.go`, `internal/ad/gpo_actions.go`, `plans/ad/gpo_response.yaml`
- Test: `internal/ad/gpo_test.go`

**Interfaces:**
- Consumes: `ADBackend.GPOs` (Task 41), a new `actions.WinEnv.RSoP RSoPReader` (interface `Effective(ctx) (EffectiveState, error)` over the RSoP WMI classes; fake in tests), `actions.RegisterUndo`, the lint's scored-dependency rule input (`Touches`).
- Produces: `ad.gpo_baseline` and `ad.gpo_effective` (`none`, `ReadOnly`); `ad.gpo_unlink{guid, link}`, `ad.gpo_disable{guid}`, `ad.gpo_restore{guid}` (risk `service`, lock `gpo:<guid>`, `Touches` the policy of the domain or DC OU); `gpo_unlink` removes the `gPLink` entry and keeps the GPO, its rollback re-links; `gpo_disable` sets the GPO flags; `gpo_restore` restores from the baseline copy (SYSVOL tree and object attributes) with the hash taken from the signed step (open item: yes, from the controller's copy). `Touches` refuses (`Plan` error) a GPO a scored service's policy depends on (the DC's DNS/WinRM policy; the list comes from `ADSettings` extension `ScoredGPOs []string`, `json:"scored_gpos,omitempty"`, added here). Plan `plans/ad/gpo_response.yaml` (`module: ad`): `ad.gpo_effective`, then `ad.gpo_unlink`, whose template carries the `autonomy` (default `auto`; S1: this replaces the `gpo.response` setting and the `auto` allowlist, and the engine's attempt ledger replaces any loop guard of its own), `ad.gpo_disable` and `ad.gpo_restore` stay a click; probes of DNS and WinRM before and after.

- [ ] **Step 1: Write the failing tests:**

```go
func TestGPOBaselineHashesTree(t *testing.T)    { /* fake GPOs + a SYSVOL fixture -> baseline output lists GUID, name, version, links, enforced, per-item hashes */ }
func TestGPOUnlinkKeepsGPOAndRollsBack(t *testing.T) {
	d := fakeDomain(t)
	d.addGPO("{A}", "Business GPO", linkedTo("OU=Domain Controllers"), enforced())
	a := gpoUnlink{}
	p := mustParams(t, a, map[string]any{"guid": "{A}", "link": "OU=Domain Controllers"})
	rb, _ := a.Capture(ctx, env(d), p)
	a.Apply(ctx, env(d), p)
	if g := d.gpo("{A}"); g == nil || len(g.Links) != 0 {
		t.Fatalf("%+v", g)
	}
	Rollback(ctx, env(d), a, rb)
	if len(d.gpo("{A}").Links) != 1 {
		t.Fatal("not re-linked")
	}
}
func TestGPOUnlinkRefusesScoredDependency(t *testing.T) { // Review Focus 5
	d := fakeDomain(t)
	d.addGPO("{B}", "DNS server policy", linkedTo("OU=Domain Controllers"))
	_, err := gpoUnlink{}.Plan(ctx, envWithScored(d, "{B}"), mustParams(t, gpoUnlink{}, map[string]any{"guid": "{B}", "link": "OU=Domain Controllers"}))
	if err == nil || !strings.Contains(err.Error(), "scored") {
		t.Fatalf("got %v", err)
	}
}
func TestGPOFindingDiff(t *testing.T)         { /* baseline vs current: new GPO, modified hash, enforced change -> ad.gpo_finding values with Change new/modified/enforced */ }
func TestGPORestoreFromBaselineCopy(t *testing.T) { /* modified GPO restored; hash taken from the param, mismatching copy refused */ }
func TestEffectiveStateReportsBlockedAgentGroup(t *testing.T) { /* RSoP fake with a firewall profile off and a policy blocking the management allow group -> Output flags it */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/ad/ -run GPO -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `shortcut: RSoP through WMI is slow on a loaded DC; the effective-state check is on demand and once per baseline comparison, not continuous.`
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/ad/`. Expected: PASS (T61 CI half).
- [ ] **Step 5: Commit.** `git commit -am "ad: GPO baseline, effective state, unlink, disable and restore"`

---

### Task 44: `service.sddl_reset` and `ad/service_sddl.yml`

**Files:**
- Create: `internal/ad/sddl.go`, `internal/ad/sddl_windows.go`, `ad/service_sddl.yml`
- Modify: `internal/actions/win_env.go` (`WinEnv.SvcSecurity ServiceSecurity`)
- Test: `internal/ad/sddl_test.go`

**Interfaces:**
- Consumes: `actions.RegisterUndo`.
- Produces:

```go
type ServiceSecurity interface { // in internal/actions
	GetSDDL(ctx context.Context, name string) (string, error)
	SetSDDL(ctx context.Context, name, sddl string) error // SetServiceObjectSecurity natively
}
```

`service.sddl_reset{service}` (risk `service`, lock `service:<name>`, `Touches` the service's access): reads the default from `ad/service_sddl.yml` (recorded from the clean reference image; placeholder values are rejected by a test: every entry must parse as SDDL and carry the `BA` and `SY` ACEs), `Plan` is `Done` when equal, `Capture` stores the current SDDL, `Verify` reads it back and checks that Administrators can query and control the service (parsing the descriptor for `BA` with `RP`/`WP`/`DT`/`LC` rights). Entries for RpcSs, W32Time, Netlogon, KDC, ADWS, DNS. `shortcut: ad/service_sddl.yml holds the defaults for the six DC services from one reference image; other builds need their own entry.` The values must come from the lab reference image; until the lab task records them the file carries the stock Windows Server 2022 descriptors marked `source: stock-2022-unverified` and the lab task replaces them.

- [ ] **Step 1: Write the failing tests:**

```go
func TestSDDLResetRestoresDefault(t *testing.T) {
	ss := newFakeSvcSec(map[string]string{"DNS": "D:(A;;GA;;;SY)"}) // Administrators removed: locked service
	a := sddlReset{}
	p := mustParams(t, a, map[string]any{"service": "DNS"})
	rb, _ := a.Capture(ctx, envSec(ss), p)
	if _, err := a.Apply(ctx, envSec(ss), p); err != nil || a.Verify(ctx, envSec(ss), p) != nil {
		t.Fatalf("%v", err)
	}
	Rollback(ctx, envSec(ss), a, rb)
	if ss.get("DNS") != "D:(A;;GA;;;SY)" {
		t.Fatal("rollback")
	}
}
func TestSDDLVerifyFailsWhenAdministratorsCannotControl(t *testing.T) { /* fake keeps a descriptor without BA after SetSDDL -> Verify errors */ }
func TestSDDLDefaultsFileComplete(t *testing.T)    { /* six services present, each parses, each has BA and SY */ }
func TestSDDLUnknownServiceRefused(t *testing.T)   { /* service not in the file -> Validate error */ }
func TestSDDLDoneWhenEqual(t *testing.T)           { /* equal descriptor -> Plan.Done true, Apply skipped */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/ad/ -run SDDL -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "ad: service.sddl_reset with recorded defaults"`

---

### Task 45: AD Recycle Bin: `ad.recycle_enable`, `ad.recycle_restore` (B1)

**Files:**
- Create: `internal/ad/recycle.go`
- Modify: `internal/actions/ad_backend.go` (`ADBackend.ForestFunctionalLevel`, `RecycleBinEnabled`, `EnableRecycleBin`, `DeletedObject`, `Reanimate`), `internal/ad/adsi_windows.go`, `internal/ad/fake_test.go`
- Test: `internal/ad/recycle_test.go`

**Interfaces:**
- Consumes: `ADBackend` (extended here).
- Produces:

```go
// ADBackend additions
ForestFunctionalLevel(ctx context.Context) (int, error)                     // 4 = Windows Server 2008 R2
RecycleBinEnabled(ctx context.Context) (bool, error)
EnableRecycleBin(ctx context.Context) error                                 // enableOptionalFeature on the Partitions container; one way
DeletedObject(ctx context.Context, dn, sid string) (ADObject, bool, error)  // read with the show-deleted control
Reanimate(ctx context.Context, deleted ADObject) error                      // clear isDeleted, set the original distinguishedName; sets no password
```

`ad.recycle_enable` (risk `service`, lock `ad`): reads the forest functional level first; below 4 it does nothing and returns an error carrying the `recycle_bin_ffl` finding text (the agent module turns it into an `ad.finding` High); an enabled bin is `changed: false`; otherwise enable and read back. `ad.recycle_restore{dn|sid}` (risk `service`, lock `accounts`, `Touches` restores a scored user's object, lint exception `Restore` with no password): reanimates; an absent object is `not_found` (a user deleted before enablement is flagged, never re-created). It emits nothing itself; the agent module (Task 46) emits `ad.recycle_restored` from the step output.

- [ ] **Step 1: Write the failing tests:**

```go
func TestRecycleEnableChecksFunctionalLevelFirst(t *testing.T) { // T78
	d := fakeDomain(t, withFFL(3)) // Windows Server 2008 (below 2008 R2)
	_, err := recycleEnable{}.Apply(ctx, env(d), mustParams(t, recycleEnable{}, nil))
	if err == nil || !strings.Contains(err.Error(), "recycle_bin_ffl") || d.recycleEnabled() {
		t.Fatalf("got %v enabled=%v", err, d.recycleEnabled())
	}
}
func TestRecycleEnableIdempotent(t *testing.T) { /* second Apply: Output["changed"]=="false" and no second EnableRecycleBin call */ }
func TestRecycleRestoreKeepsHashAndGroups(t *testing.T) {
	d := fakeDomain(t, withFFL(7), withRecycle())
	u := d.addUser("scoreduser", withHash("H1")).inGroup("Remote Desktop Users")
	d.delete("scoreduser")
	if _, err := (recycleRestore{}).Apply(ctx, env(d), mustParams(t, recycleRestore{}, map[string]any{"sid": u.SID})); err != nil {
		t.Fatal(err)
	}
	if got := d.user("scoreduser"); got.hash != "H1" || !got.inGroup("Remote Desktop Users") || d.passwordSetCalls() != 0 {
		t.Fatalf("%+v", got)
	}
}
func TestRecycleRestoreOfUserDeletedBeforeEnableIsNotFound(t *testing.T) { /* no deleted-object entry -> not_found, no creation */ }
func TestRecycleRestoreDeclaresRestoreTouch(t *testing.T) { /* Touches marks Op restore for the scored-user lint exception */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/ad/ -run Recycle -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `enableOptionalFeature` details are inferred: record `[inferred, verify in the lab replica]` in a code comment.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS (T78 CI half).
- [ ] **Step 5: Commit.** `git commit -am "ad: Recycle Bin enable and restore (B1)"`

---

### Task 46: `ad` agent module on the contract

**Files:**
- Modify: `internal/ad/module.go` (agent module), `internal/agent/mods/ad.go`, `internal/module/conformance/allowed.go` (remove `ad` from `PreContract` once the controller side in Task 47 also conforms; until then this task removes nothing)
- Create: `manifest/2027/modules/ad.yml`
- Test: `internal/ad/agent_test.go`, `internal/ad/agent_conformance_test.go`

**Interfaces:**
- Consumes: `RunChecks`, `PathQuery`, the GPO diff (Task 43), `plan.ADSettings`, `agent.Env.Subscribe(buf, kinds...)`, `winevt.sec_event` and `file_change` with `sysvol_policy: true`.
- Produces: the agent module: loop every `check_interval_sec` (default 600) emitting `ad.finding`; an immediate GPO comparison on a GPO-shaped `winevt.sec_event` (5136, 5137, 5139, 5141 with `gpo: true`) or `file_change` under SYSVOL policies, emitting `ad.gpo_finding` values; on a step output of `ad.recycle_restore` it cannot see steps, so the restore event is emitted by the controller side (Task 47, which sees `agent.step_result`); `ad.recycle_enable`'s `recycle_bin_ffl` result is raised as `ad.finding` check `recycle_bin_ffl` severity high by the periodic loop (it re-reads the level). Health: `unavailable` off a DC (no `ADBackend`), `degraded` while the GPO baseline is not taken, a check could not read an attribute, or RSoP failed; gaps name each; `ok` otherwise. The budget guard: a run over budget is skipped and reported.

- [ ] **Step 1: Write the failing tests:**

```go
func TestADUnavailableOffDC(t *testing.T) { /* no ADBackend in env -> Health unavailable, no events */ }
func TestADLoopEmitsFindings(t *testing.T) { /* fake domain with a temp admin; interval 1 s; ad.finding with check privileged_member_unexpected appears and Validates */ }
func TestGPOEventTriggersImmediateComparison(t *testing.T) { /* publish a winevt.sec_event 5136 with gpo true; an ad.gpo_finding appears well before the 600 s interval */ }
func TestADSettingsDefaults(t *testing.T) { /* zero CheckIntervalSec -> 600; zero PathQuery.MaxDepth -> 6 */ }
func TestADAgentConformance(t *testing.T) {
	conformance.Agent(t, conformance.AgentCase{Factory: factoryNamed(t, "ad"), Default: cfgAD(600), Reconfig: cfgAD(300), Load: gpoEvents()})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/ad/ -run 'ADUnavailable|ADLoop|GPOEvent|ADSettings|ADAgentConformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Write `manifest/2027/modules/ad.yml` as in the design.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/ad/ ./internal/module/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "ad: agent module on the contract"`

---

### Task 47: `ad` controller side: GPO baseline trigger, `gpo_finding` fact, restore events, Active Directory page

**Files:**
- Create: `internal/ad/controller.go`, `internal/ad/ui.go`
- Modify: `internal/module/conformance/allowed.go` (remove `ad` from `PreContract`)
- Test: `internal/ad/controller_test.go`, `internal/ad/controller_conformance_test.go`

**Interfaces:**
- Consumes: `module.Host` (`Subscribe`, `RunReadOnly`, `Control`, `Emit`, `UI`, `Query`), `module.ControlMsg`, W1's fact subtype `gpo_finding`.
- Produces: `Controller`: consumes `hunt.run` and `integrity.sweep_done`; when both are clean for the DC (`hunt.run` with no open High, `integrity.sweep_done` with `Verdicts == 0`) and no `ad.gpo_baseline` exists for it, starts `Host.RunReadOnly("ad", "gpo_baseline", {host})` (the DC's agent never watches for its own hunt); consumes its own `ad.gpo_finding` and sends it to the DC's agent and to the member hosts as `Host.Control(ControlMsg{Type: "fact", Fact: "gpo_finding", ID: guid, Data: ..., TTL: 30*time.Minute})`; watches `agent.step_result` for `ad.recycle_restore` and emits `ad.recycle_restored` (`dn`, `sid`, `scored`, `restored_by_rule`, `verified` false until the next scorer login confirms; the `verified` update is an `ad.recycle_restored` follow-up with the same `dn` when `checks` reports the scored login green: `shortcut: verified stays false until W7's login confirmation event exists, upgrade then`). The Active Directory page lists findings, path results, the GPO baseline with changes, effective-state results; buttons: purge a member (`Propose` `plans/ad/purge_member.yaml`), accept a member into the allowlist (emits `operator.edit{module: ad, op: accept}` and appends one `Overrides.Accepted{kind: ad}` through `Host.UpdateOverrides`, with reason and owner; findings use the alert open/ack state, so `ad` has no decision kind or table), unlink/disable/restore a GPO (`Propose`), run `dc.service_repair`, the two krbtgt steps with the gap shown (`Propose` only, always a click). Host-grid column `AD clean` on the DC.

- [ ] **Step 1: Write the failing tests:**

```go
func TestBaselineStartsAfterCleanHuntAndSweep(t *testing.T) {
	h := newADHost(t)
	c := startController(t, h)
	h.publish("hunt.run", map[string]any{"host": "ad", "added": 0, "modified": 0, "missing": 0})
	h.publish("integrity.sweep_done", map[string]any{"host": "ad", "verdicts": 0, "first_sweep": true})
	waitFor(t, func() bool { return h.readOnlyRuns() == 1 })
	if h.lastRun().Template != "gpo_baseline" {
		t.Fatalf("%+v", h.lastRun())
	}
	h.publish("integrity.sweep_done", map[string]any{"host": "ad", "verdicts": 0})
	time.Sleep(50 * time.Millisecond)
	if h.readOnlyRuns() != 1 {
		t.Fatal("baseline started twice")
	}
}
func TestDirtySweepDoesNotStartBaseline(t *testing.T) { /* verdicts 3 -> no run */ }
func TestGPOFindingSentAsFact(t *testing.T) {
	h := newADHost(t)
	startController(t, h)
	h.emitOwn("ad.gpo_finding", GPOFinding{GPOGUID: "{A}", Change: "new", Enforced: true})
	waitFor(t, func() bool { return len(h.controls()) == 1 })
	if m := h.controls()[0]; m.Fact != "gpo_finding" || m.ID != "{A}" || m.TTL <= 0 {
		t.Fatalf("%+v", m)
	}
}
func TestRecycleRestoredEmittedFromStepResult(t *testing.T) { /* agent.step_result for ad.recycle_restore with sid -> ad.recycle_restored Validate()s, scored from the manifest accounts */ }
func TestAllowlistAcceptIsOneOverridesEntry(t *testing.T) { /* POST accept for a member -> one operator.edit and one Overrides.Accepted entry with reason and owner; no ad table row */ }
func TestKrbtgtButtonsOnlyPropose(t *testing.T) { /* POST krbtgt step 1 -> Host.Propose, never RunAuto or RunStanding */ }
func TestADControllerConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Controller{}, Config: "enabled: true\n", Now: fixedNow})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/ad/ -run 'BaselineStarts|DirtySweep|GPOFindingSent|RecycleRestoredEmitted|AllowlistAccept|KrbtgtButtons|ADControllerConformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Create `plans/ad/{gpo_baseline,purge_member}.yaml` (`module: ad`, read-only baseline; purge with `ad.account.group_remove` and its own approval).
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS, including the static checks with all four W5 modules off `PreContract`.
- [ ] **Step 5: Commit.** `git commit -am "ad: controller side (baseline trigger, gpo_finding fact, restore events, page)"`

---

### Task 48: Lab (stronger agent or David)

Runs the design's lab tests for this workstream on the BTaP Proxmox replica (`stacks/ccdc` in btap-infra, the "ccdc27" lab) and on GOAD for the AD parts. It does not block the merge.

**Files:**
- Create: `docs/impl/lab/w5-integrity-hunting.md`
- Modify: `ad/service_sddl.yml` (replace the `stock-2022-unverified` entries with descriptors read from the clean reference DC), `hunt/baselines/` (signed per-OS reference artifacts built from stock images; the build script lives in `ccdc-lab`, only the signed outputs are committed), `ledger/` (signed ledger indexes from the stock images, built with `phylax ledger build`), `phylax_design.md` (catalogue Status for the four modules: "lab-proven" only from a passed record)

**Tests to run** (ids from the Test matrix; record date, commit, VMIDs, pass or fail, measured values, and what was not run):

| Id | What | Pass means |
| --- | --- | --- |
| T01 | Prebaked set at drop flag | the hunt finds at least 90% and the ledger sweep finds every replaced binary; time to find reported |
| T12 | `LD_PRELOAD` rootkit hiding a process | the cross-checks (`ld_preload`, `hidden_process`) and D11 fire; latency reported |
| T19 (hunt and ledger half) | bulk re-enrollment | the sweep and hunt run automatically; the golden tag is withheld until both are clean (the tag logic is W12/W10; record what is observed) |
| T31 | replaced Postfix `smtpd` proxy, trojaned `nologin`, `LD_PRELOAD` library, `dns.exe` stand-in, an unknown hash executed | alert at first exec; the pinned image mismatch found; D4b fires for the proxy; no automatic restore; one-click `file.restore{source: depot}` passes the probe |
| T32 | package update inside a tagged plan, an untagged update, a patch-level difference | no alert for the tagged one; `match_other_version` or an alert with clear provenance otherwise |
| T34 | first-hour plan library against real Quotient | zero failed rounds attributable to Phylax |
| T38 | Zerologon, hidden accounts, `chattr +i`, unit capabilities, PHP overrides, OpenCart admin rows, AD GPO and ACL changes | each raises its alert |
| T61 | GPO footholds | the `ad.gpo_unlink` template at `autonomy: auto` and the `winevt` GPO events detect the GPO; the chain shows the hop; the GPO and its link are reverted by a plan with the agent link intact |
| T68 | opt-in `noexec` remount | the pre-check refuses when a scored service execs from there; a live remount rolls back on failure |
| T72 | reboot-survival preflight | a change that would stop the host booting is flagged; one that survives is not |
| T76 (sshsig half) | release signatures | an artifact signed by `internal/signing` verifies with plain `ssh-keygen -Y verify` on a machine with no phylax binary |
| T78 | AD Recycle Bin | enable checks the functional level and is idempotent; deleting a scored user triggers D7h and the user returns with the same hash and groups, verified by a scorer login |

Plus: the first load of the 17 UCF rules (record the skipped count and decide `engine`), a seeded temp admin and a nested admin group found by the allowlist and the path query, an Enforced "Business GPO" detected, unlinked and restored, a locked service SDDL repaired with the probes green, a Windows Authenticode sweep on a real Windows host (closes a design `shortcut`), the Windows COM backends of Task 22, and latencies (exec to alert, swap to pin alert, enrollment to first hunt results).

- [ ] **Step 1:** Run each test; write the result rows as they finish.
- [ ] **Step 2:** Open an issue for every failure with the test id and the record link.
- [ ] **Step 3:** Commit the record and the content updates: `git commit -am "lab: W5 integrity and hunting record"`.

---

## Self-review

**1. Spec coverage.** `integrity`: ledger and format (2), events (6, 7), module and health (8), signers and hints and maps and settings (9), SUID (10), YARA (11, 20), actions (12), the depot restore as `file.restore{source: depot}` (13), cross-checks and PAM (14 to 16), CLI (17), controller side (18), D5d and bug 6 (19). `hunt`: collection (27 to 32), diff and scoring (33), module and findings and triggers (34), UI and remediation (35), plans (36). `hardening`: pack format, bug 9 (37), module (38), packs (39, 40), Zerologon and local-root bundle (40), noexec and `mount.remount` (25, 26, 40). `ad`: move (3), reads (41), checks and path query (42), GPO (43), SDDL (44), Recycle Bin (45), agent and controller sides (46, 47). Action families: Registry (23), Kernel and system (24, 25), Files (13), Services (21), Persistence cleanup (21, 22), Domain (3, 42 to 45), Integrity (12), Hunt (27 to 32). S1-S4: no ladders or special-case actions are built (decision 12); the replaced mechanisms are Tasks 13, 21, 24, 30, 34, 37 and 38. Shared libs: signing and sshsig, T76 (2, 4, 5), format (2). Bugs: 1 (24), 6 (19), 9 (37). Not built, with reason: Windows cross-checks, BITS/print-monitor/provider persistence, per-host ledger composition (W11), `ReadProcessMemory`, YARA-X (all carried as `shortcut`s or open items in the design). Two things the design lists that this plan leaves to others: D22 and the other detection rules that complete the hunt (W4 owns `rules/detect/`), and the `report` IR draft from `hunt.finding` (W10).

**2. Step scan.** Each step names its test, signature, command and expected output. Test comments describing fixtures stand for the code the implementer writes from the named helper; helpers are created in Task 1 or in the task that first uses them.

**3. Type consistency.** `Artifact`, `Collection` (Task 1) are used unchanged in Tasks 27 to 34; `VerdictEvent` fields in Tasks 6, 7, 18, 19 match the Task 1 struct; `ADBackend` additions of Task 41 and 45 are the only changes to the interface and Task 43 adds `WinEnv.RSoP`, Task 44 `WinEnv.SvcSecurity`, Task 22 `WinEnv.Tasks` and `WinEnv.WMI`; `plans.Parse` and `ResolveLabels` (Task 37) are what Tasks 36, 39 and 40 call; `Remediation` (Task 35) takes `*manifest.Manifest` in the tests' `testManifest()` helper.

**4. Review Focus.** Items 1 to 5 map to `TestLedgerAbsentThenAppears` (8), `TestSSHSigRejectsMalformed` (5), `TestNoBaselineDegradesNotDiffs` (34), `TestAFAlgProbeFailsWhenSocketOpens` (24), `TestRemediationRefusedForScoredUnit` (35) and `TestGPOUnlinkRefusesScoredDependency` (43).

**5. Proportion.** The design's four sections run about 700 lines; this plan is longer because it holds 48 tasks with tests. No task transcribes a function body.
