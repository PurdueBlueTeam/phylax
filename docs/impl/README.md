# Phylax v4: master implementation plan

Status: draft, 2026-10-31. Implements `phylax_design.md` (v4) on branch `v4`. This file says how the work is split, in what order it runs and how each piece is accepted. The per-workstream plans (`docs/impl/NN-<name>.md`) say what to build, task by task. W1's plan (`01-module-contract.md`) fixes the interfaces every other plan builds on; its Interfaces blocks are the source of the exported names listed below.

## Purpose

Turn the v4 design into working code without losing the Invitational (2026-11-07):

1. Prove today's tree is green (W0).
2. Ship an observe-mode slice for the Invitational on today's v3 code (W2), independent of everything else.
3. Build the module contract (W1): the small core every module plugs into, the conformance suite and the CI gates.
4. Retrofit every existing package onto the contract and build what is missing, one module group per workstream (W3 to W11), plus enrollment (W12) and the C2 fingerprinting lab (W13).

The design is authoritative. Where an implementation forces a design change, the same commit edits `phylax_design.md` and says why (repo `AGENTS.md`). W1 already records its deviations at the top of its plan.

## Execution model

- **Implementers are Claude Haiku subagents, one task each,** run with `superpowers:subagent-driven-development`. Each task is reviewed by a fresh reviewer subagent before the next task starts. A reviewer may reject a task; the implementer redoes it.
- **Haiku tasks are small:** about one package or about 200 lines of change, exact file paths, exact Go signatures, test names with their assertions (the design's values in them), and one verification command with the output that means it passed.
- **The first task of every workstream is a "seams" task done by a stronger model (Sonnet or Opus).** It writes the package skeletons, exported types, interfaces, stub functions, the event-kind declarations of the workstream's modules and the test files the later Haiku tasks implement against. Seams tests are committed with `t.Skip("unimplemented: <WN> Task <M>")` so CI stays green; the Haiku task that implements them deletes the skip line first and watches the test fail. A seams task also moves packages to their `internal/<module>` path when the move is mechanical, so later tasks edit files at their final path.
- **A seams task merges on its own** (its own pull request into `v4`) as soon as it is reviewed. Dependent workstreams wait only for the seams they consume (declared kinds, exported types), not for the whole workstream.
- **The last task of every workstream is a lab task,** run by a stronger agent or by David on the BTaP Proxmox replica (`stacks/ccdc` in btap-infra; the design's "ccdc27" lab, Testing and lab) and, for AD work, on GOAD. It runs the design's lab tests for the workstream (ids from the Test matrix), records the results in `docs/impl/lab/<wN>-<name>.md` (date, commit, VMIDs, test id, pass/fail, measured values, what was not run) and opens issues for failures. The lab task does not block the merge.
- **Two gates, never merged into one:**
  - **Package done** (merge gate): CI green on the branch (`make build build-windows vet test race`, the conformance job) and the package has unit, fixture and conformance tests that exercise the real code. No mocks of the code under test; fakes only at the edge the package does not own (a fake LDAP server, a recorded pcap).
  - **Lab-proven:** the lab task's tests passed. A module's catalogue status becomes "lab-proven" only from a lab record.
- **Branches.** One branch per workstream, `v4-<name>`, cut from the current `v4`, merged back after review by pull request. The repo is in `pr` mode: no direct commits to `main`; `v4` takes merges only. Rebase on `v4` before opening the pull request.
- **Commits.** Small, one logical change, made when the task's tests pass. Message `area: summary` (for example `module: registry and Effective`). No attribution lines of any kind.
- **Every commit** builds and tests clean: `make build build-windows vet test race`. Go 1.27.2 via mise, `CGO_ENABLED=0`.
- **Code style** (ponytail): the smallest complete change, reuse what exists, no speculative options; a known limit gets `// shortcut: <limit>, <when to upgrade>`. Bounded queues, buffers, decompression and timeouts. Atomic writes (`internal/atomicfile`) for critical files.

## How to run a workstream

1. Check the entry gate in the table below (its dependencies merged, or the named seams merged).
2. `git switch v4 && git pull && git switch -c v4-<name>`.
3. Run the seams task (Task 1) with Sonnet or Opus. Open its pull request; merge after review.
4. Run each Haiku task in order with `superpowers:subagent-driven-development`: dispatch the implementer with the task text, the plan's Global Constraints and the Interfaces blocks it consumes; dispatch a fresh reviewer with the task text and the diff; continue only on approval.
5. After the last code task, run the whole-branch review, `make build build-windows vet test race`, and the conformance job. Open the pull request.
6. Run the lab task (stronger agent or David). Commit the lab record on the branch or in a follow-up pull request.
7. Exit gate: the workstream row's exit conditions hold. Update the catalogue's Status column in `phylax_design.md` in the merge (built, partial, missing; "lab-proven" only from a lab record).

## Workstreams

Branch names are `v4-<name>`; plan files are under `docs/impl/`.

| Id | Name (branch) | Goal | Owns (design sections, modules) | Depends on | Entry gate | Exit gate | Plan file |
| --- | --- | --- | --- | --- | --- | --- | --- |
| W0 | proving (`v4-proving`) | Today's tree is green, race-clean, and CI runs on the v4 branches | CI (T45); Testing and lab: CI | none | `v4` head | `make build build-windows vet test race` passes; CI triggers on `v4` and `v4-*`; any race fixed with a regression test | `00-proving.md` |
| W2 | invitational (`v4-invitational`) | Usable observe-mode Phylax for 2026-11-07 on today's v3 code, plus the Tier A and Tier B battle-test pieces and collector scripts C1 to C7 | Operations: The Invitational (observe mode and tiers); `docs/impl/invitational-data.md` (C0 to C9); T70; Known bugs 5, 8, 10, 23; the `session.terminate_predating` action (Tier B eviction) | W0 | W0 merged | Dry run on the replica by 2026-11-05: observe mode leaves host state unchanged (T70); Tier A runs; Tier B pieces run on a canary host; C1 to C7 produce their files; the runbook in the plan is printed. Merged before W1 | `02-invitational.md` |
| W1 | module-contract (`v4-module-contract`) | The module contract as code: typed events, `internal/module`, registries, Host, approval classes, controller executor, facts, lint registry, conformance suite, UI registrar, CI gates | The module contract (all of it); Event kinds (common and core kinds, canonical fields); Core: Execution engine (controller executor, approval classes, auto conditions, lint registration); Wire protocol (`control: fact`); Event store (query API, module tables); UI shell (registrar, Platform module health); Manifest (`modules/<name>.yml`, host `modules:`, labels); Known bugs 11, 17 (core part) | W0 | W0 merged (rebase on W2 when W2 merges) | Package done for every W1 package; conformance job required in CI; `health` and `suricata` pass conformance; every other module listed pre-contract | `01-module-contract.md` |
| W3 | telemetry (`v4-telemetry`) | Retrofit `audit`, `winevt`, `net`; build `logs` and `inventory`; canonical common kinds from every producer; the rename map applied to producers and the rules and traceback code that key on them | Modules `audit`, `winevt`, `net`, `logs`, `inventory`; shared libs `internal/sockets`, `internal/inventory/fold`; Known bugs 15 (net part), 16, 17 (audit part) | W1 | W1 merged | The five modules pass conformance; no old kind name in the tree for these producers; T75 producer fixtures pass | `03-telemetry.md` |
| W4 | detection-response (`v4-detection-response`) | Retrofit `detect` (alerts only: no rule modes); build `respond` (tiers, recipes tied to rule ids) and `content_guard` (its restore is a `respond` recipe); the engine's `autonomy` setting and attempt ledger replace per-module ladders and breakers (S1); port the rule corpus into `rules/detect/` | Modules `detect`, `respond`, `content_guard`; Rule format; Processes action family (`proc.*`); `dir.snapshot`; Known bugs 2, 22 | W1; W3 rename tasks merged | W3 renames merged | Conformance; rule-id registry check in CI; T52, T74 respond half, T75 rule half, T79 rule promotion pass in CI form | `04-detection-response.md` |
| W5 | integrity-hunting (`v4-integrity-hunting`) | Retrofit `integrity`; build `hunt`, `hardening` packs, `ad` | Modules `integrity`, `hunt`, `hardening`, `ad`; shared libs `internal/signing` (sshsig, T76), `internal/integrity/format`; Kernel and system, Persistence cleanup, Registry, Domain, Integrity, Hunt action families; Known bugs 1, 6, 9 | W1 | W1 merged | Conformance; T76 sshsig verifies with `ssh-keygen`; bug regressions pass | `05-integrity-hunting.md` |
| W6 | network (`v4-network`) | Retrofit `firewall`, `capture`, `devices`; build `egress` | Modules `firewall`, `egress`, `capture`, `devices`; Firewall and Devices action families; manifest firewall lint and `nft -c`; Known bugs 7, 12, 13, 14, 19, 20; break `internal/actions` imports of `devices` and `firewall` | W1; W3 seams (`net.*` kinds) | W3 seams merged | Conformance; T77 in CI form; bug regressions pass; `internal/actions` imports no module | `06-network.md` |
| W7 | scoring-creds (`v4-scoring-creds`) | Retrofit `checks`, `scorer`, `vantage`, `creds`; extract `internal/checks/probe`; the executor's `Env.Probe`; PCR verification is the `probe.run` step `pcr_verify` (no action, no verify sub-role), the vantage events are alert-class kinds (no V1-V4 rules), `creds` reads `scorer`'s account groups (no `cred_credlist`), only `creds` has `act_enabled` | Modules `checks`, `scorer`, `vantage`, `creds`; shared lib `internal/checks/probe`; `health.check` action; scored-account eviction rules (T49); Credentials action family | W1; W6 seams (`conn` with `source: capture`, `capture.txn`) | W6 seams merged | Conformance; probe library has no scheduler; T35, T49, T50, T51 CI halves pass | `07-scoring-creds.md` |
| W8 | analysis (`v4-analysis`) | Retrofit `traceback` (the labels and changes analysers only), `chains` (which takes the trace-back as its within-host hop builder, `internal/chains/hops`, and emits one `chains.chain` kind; there is no `traceback.result` and no trace analyser) and `deps` (one guard, the `DEP003` lint; `DEP1` to `DEP3` read the `new` and `learning` flags of `deps.edge`: no `DepsGuard`, no second learning window) as analysers with one writer goroutine each; build `vuln`; none of the four has `act_enabled` | Modules `traceback`, `chains`, `deps`, `vuln`; Known bug 15 (deps part) | W1; seams of W3, W4, W6, W7 | Those seams merged | Conformance incl. analyser determinism (check 10); tables are projections of own events | `08-analysis.md` |
| W9 | deception (`v4-deception`) | Retrofit `decoys` and `honeytokens` into the one `deception` module: one `hosts:` map in `modules/deception.yml`, one seed list, the unprivileged decoy process split, kinds `deception.hit`, `deception.read`, `deception.sighting`, `deception.secrets_unavailable`, `deception.aws_key_seen` (no separate decoys or honeytokens modules, no derived registry copy sent to the decoys, no `honeytokens.generated` kind: generation is an `operator.edit`) | Module `deception`; Deception action family; Known bug 18 | W1; W4 seams (`detect.alert`) | W4 seams merged | Conformance; decoy child process runs unprivileged; bug 18 regression | `09-deception.md` |
| W10 | reports-ops (`v4-reports-ops`) | Retrofit `report` (saved queries are generators under `reports/generators/`: no `reports/queries/`, no `/queries` page; operator edits are `operator.edit`); build `backup` (file restore is `file.restore{source: backup}`; edits are `operator.edit`), `teamfeed`, `notify` (it consumes alert rows, not named kinds); the shell pages no module owns | Modules `report`, `backup`, `teamfeed`, `notify`; Backups action family; UI shell: Overview roles and unstaffed, host x step grid, Since you left; the `work_window` fact sender; Known bug 3 | W1; seams of W4, W5, W7, W8 | Those seams merged | Conformance; T56, T57, T58, T59 CI halves pass | `10-reports-ops.md` |
| W11 | integrations-depot (`v4-integrations-depot`) | Retrofit `depot`, `wazuh`, `splunk`; finish `suricata` (W1 moved it); the agent `fetch` handler | Modules `depot`, `wazuh`, `splunk`, `suricata`; Packages and Integrations action families; Wire protocol `fetch` and chunks; Known bugs 4, 15 (depot part), 17 (wazuh part), 21; break `internal/actions` import of `wazuh` | W1; W5 seams (`internal/signing`, `internal/integrity/format`) | W5 seams merged | Conformance; T40 offline drill in CI form; bug regressions pass | `11-integrations-depot.md` |
| W12 | enrollment (`v4-enrollment`) | Move first contact and enrollment into the core package `internal/enroll`; finish recovery and agent self-protection | Core: Enrollment, bootstrap and recovery (incl. controller restore resend verification); Agent runtime: self-protection (Windows watchdog, Job Object, service DACL), Agent action family (`agent.*`); `phylax set-controller`; T76 enroll half | W1; W7 seams (`internal/checks/probe` ntlm, winrm) | W7 seams merged | `internal/enroll` passes its tests; a module importing it fails the import check; T27, T28 CI halves pass | `12-enrollment.md` |
| W13 | c2-lab (`v4-c2-lab`) | Run the C2 fingerprinting lab, write rules from it, record the sinkhole decision | Testing and lab: C2 fingerprinting lab (T60); `egress` open question 3 | W6 lab task done; W4 merged | W6 lab record exists | Corpus captured per framework; rules committed under `rules/detect/` with fixtures; sinkhole kept or its code deleted per the decision rule (David confirms the threshold) | `13-c2-lab.md` |

### Dependency graph

```text
W0 ──┬── W2 (Invitational; merges first, by 2026-11-07)
     └── W1 ──┬── W3 ──┬── W4 ──┬── W9
              │        │        ├──────────────┐
              │        ├── W6 ──┼── W7 ──┬── W12│
              │        │        │        ├──────┼── W8 ── W10
              ├── W5 ──┼────────┼────────┼──────┘
              │        └── W11 (needs W5 seams)
              └── (W13 after W6 lab and W4)
```

Edges are on seams where the table says so: W6 waits for W3's seams, W7 for W6's, W8 for the seams of W3, W4, W6 and W7, W9 for W4's, W10 for those of W4, W5, W7 and W8, W11 for W5's, W12 for W7's.

**What runs in parallel:**

- Wave 1: W2 and W1, after W0. W2 has the date; W1 rebases on W2 when W2 merges (W2 touches the agent and controller code W1 extends, so W1 takes the conflicts, not W2).
- Wave 2, after W1: W3 and W5 together. W6 starts when W3's seams merge.
- Wave 3: W4 (after W3's renames), W6, W11 (after W5's seams) together; W7 when W6's seams merge.
- Wave 4: W9 (after W4's seams), W12 (after W7's seams), W8 (after the four seams it needs).
- Wave 5: W10. W13 whenever the W6 lab record exists.

Cross-workstream dependency to note: W7 builds the plan options `window: scorer_quiet`, `gate: manual` and `txn:` (W7 Tasks 2 to 7); W5 hardening packs that use `window:` and W10 `backup` nodes depend on those W7 tasks, so W5 and W10 tasks that use `window:` wait for W7 Tasks 2 to 7 to merge. W1 owns the other two core plan options (`expires_after`, `gate: auto`).

Conflict hot spots to watch when two workstreams run together: `internal/plan/agentconfig.go` (every agent module adds or edits its settings struct), `internal/agent/mods/`, `internal/controller/genconfig.go`, `manifest/2027/modules/`, `rules/`. Each workstream touches only its own modules' entries; the seams tasks add struct fields, later tasks fill them.

## Exported names the other plans use

These come from W1's Interfaces blocks (`01-module-contract.md`), which hold the exact signatures. Plans W3 to W13 use these names and no others for the contract.

| Package | Names |
| --- | --- |
| `internal/event` | `Event` (adds `Schema int`, `Tag string`), `Type{Kind, Schema, Priority, Alert, Fields}`, `Declare`, `Lookup`, `Declared`, `New[T]`, `Decode[T]`, `Validate`, `ErrUndeclared`, `ErrKindMismatch`, `ErrSchema`; common kinds `KindProcessStart` ... `KindTelemetryGap` with structs `ProcessStart`, `ProcessExit`, `FileChange`, `Conn`, `Listener`, `AuthEvent`, `DNSQuery`, `TelemetryGap`; core kind structs incl. `ControllerFact`; `Event.WithExtra(key, v)` (`x_` prefix; Decode and Validate ignore it); optional extension fields on the common structs (W3's list, W1 Task 4a), `Replay` |
| `internal/module` | `Side`, `SideAgent`, `SideController`, `Manifest` (+ `Validate`), `Common{Enabled, ActEnabled, Autonomy}`, `State` and its constants, `Gap`, `Usage`, `Health`, `Host`, `ControlMsg`, `Proposal`, `EventRef`, `ControllerModule`, `Analyzer` (`Run(ctx, store.Reader, now)`), `AnalyzerProvider`, `Configurable`, `Register`, `Registered`, `Lookup`, `Effective`, `Schema`, `ErrNoConfig`, `ErrNotInScope`, `ErrProposed`; `Host` also has `Tables()`, `Manifest() *manifest.Manifest`, `UpdateOverrides(fn)`, and `Secrets` accepts prefix grants (`cred/*`) |
| `internal/module/conformance` | `AgentCase`, `Agent(t, AgentCase)`, `ControllerCase`, `Controller(t, ControllerCase)`, `PreContract` (the shrinking list: a retrofit deletes its entry), `AllowedLibraries`, `CoreImports`, `ModulePackages` |
| `internal/module/all` | blank imports of every module package (the binary and the conformance run import it) |
| `internal/agent` | `Factory{Name, Manifest, Section, Build}`, `Registered()`, `ModuleSpec`, `Env` (`Subscribe(buf int, kinds ...string)`, `Keep`, `Kept`, `Fact`), `HealthReporter`, `Harness`, `NewHarness`, `HarnessOptions` |
| `internal/plan` | `ModuleLimits{module.Common; RatePerSec float64; Burst int}`, `ApprovalClass` (`ClassClick`, `ClassAutoReadOnly`, `ClassStanding`, `ClassAuto`), `StandingApproval`, `ControlFact`, `FactSender`, `ExpandTemplate`, `BlockFor`; `Node.ExpiresAfterSec`, `Node.Until` (`GateUntil`, `NoEvent`: `gate: auto`), `StepBody.ExpiresAfterSec` |
| `internal/plan/lint` | `Rule{ID, Doc, Check}`, `Finding`, `Ctx{Manifest, Query, Class}`, `Register`, `Rules`, `Run` |
| `internal/store` | `Reader` (the design's read-only "store.Query"), `Query` (the existing filter struct, gains `Fields`), `ModuleDB` (`Migrate`, `Exec`, `Query`), `(*Store).ModuleDB`; `storetest.New(t, evs...)` (seeded store for module tests, W1 Task 8a) |
| `internal/vault` | `Reader`, `Scoped` (an entry `name/*` is a prefix grant), `Covers` |
| `internal/ui` | `Registrar`, `Cell`, `(*Server).Registrar` |
| `internal/manifest` | `ModuleBlock`, `Manifest.Modules`, `Host.Modules`, `Host.Labels`, `(*Manifest).ModuleEnabled`, `ParseLabels`, `LabelExpr`, `AppendOverrides`, `LearnedListener`, `Overrides.LearnedListeners` |
| `internal/controller` | `(*Controller).EmitController`, `RunModules`, `ModuleHealth`, `AgentHealth`, `RunReadOnly`, `RunStanding`, `RunAuto`, `ReenableAuto`, `CreateStanding`, `RevokeStanding`, `Propose`, `AcceptProposal`, `DismissProposal`, `SendFact`, `LoadModuleTemplate`; `Options.Probe`, `LoadModuleTemplateFor(plansRoot, mod, name, hosts)`, `Options.GatePoll` |
| `internal/actions` | `Register(f func() []Action)` (the one name for exporting action registration; no `RegisterExtra` or `RegisterFamily`), `RegisterUndo`, `Unsupported`, `(*Env).Now()` (the field is `Env.Clock`), `Env.Ext map[string]any`, `Env.Probe func(ctx context.Context, service string) error` |
| `plans` (root package) | `Template.Module`, `Parse`, `ResolveLabels`; on `conformance.CoreImports` (W1 Task 22b) |

## Module to workstream map

Every catalogue module has exactly one owning workstream. "Today" is where the code lives now; "Target" is its path after the retrofit (Appendix D). The owner moves the package, deletes the old path in the same task (no shims), and fixes the module's known bugs.

| Module | Group | Owner | Today | Target |
| --- | --- | --- | --- | --- |
| `audit` | Telemetry | W3 | `internal/collect/audit`, `internal/agent/mods/audit_linux.go` | `internal/audit` |
| `winevt` | Telemetry | W3 | `internal/collect/winevt`, `internal/agent/mods/winevt.go` | `internal/winevt` |
| `net` | Telemetry | W3 | `internal/collect/net`, `internal/agent/mods/net.go` | `internal/net`, `internal/sockets` |
| `logs` | Telemetry | W3 | none | `internal/logs` |
| `inventory` | Telemetry | W3 | none (`collect.inventory` in `internal/actions`) | `internal/inventory`, `internal/inventory/fold` |
| `detect` | Detection and response | W4 | `internal/detect`, `internal/agent/mods/detect.go`, `rules/*.yml` | `internal/detect`, `rules/detect/` |
| `respond` | Detection and response | W4 | `internal/detect` (act mode), `internal/actions` | `internal/respond` |
| `content_guard` | Detection and response | W4 | none | `internal/content_guard` |
| `integrity` | Integrity and hunting | W5 | `internal/integrity`, `internal/agent/mods/integrity.go` | `internal/integrity`, `internal/integrity/format` |
| `hunt` | Integrity and hunting | W5 | `internal/actions` (`hunt.*`, `collect.*`) | `internal/hunt`, `hunt/` |
| `hardening` | Integrity and hunting | W5 | `plans/first-hour`, `plans/*.yaml`, `internal/actions` | `plans/hardening/` (content), actions stay core |
| `ad` | Integrity and hunting | W5 | `internal/actions/ad_*.go`, `internal/collect/winevt/gpo.go` | `internal/ad`, `ad/` |
| `firewall` | Network | W6 | `internal/firewall`, `internal/actions/*firewall*` | `internal/firewall` |
| `egress` | Network | W6 | `internal/collect/net/egress.go` (input) | `internal/egress` |
| `capture` | Network | W6 | `internal/capture`, `internal/agent/mods/capture.go`, `internal/controller/capture_ingest.go` | `internal/capture` |
| `devices` | Network | W6 | `internal/devices/...`, `internal/actions/dev_*.go`, `internal/controller/devexec_run.go`, `dir_devices.go` | `internal/devices` |
| `checks` | Scoring and credentials | W7 | `internal/checks`, `internal/controller/checks_*.go` | `internal/checks`, `internal/checks/probe` |
| `scorer` | Scoring and credentials | W7 | `internal/scorer` | `internal/scorer` |
| `vantage` | Scoring and credentials | W7 | `internal/vantage` | `internal/vantage` |
| `creds` | Scoring and credentials | W7 | `internal/creds`, `internal/scorer/pcr.go`, `csv.go` | `internal/creds` |
| `traceback` | Analysis | W8 | `internal/traceback` | `internal/traceback` |
| `chains` | Analysis | W8 | `internal/chains`, `internal/store/chains.go` | `internal/chains` (tables move into the module) |
| `deps` | Analysis | W8 | `internal/deps`, `rules/deps.yml` | `internal/deps` |
| `vuln` | Analysis | W8 | none | `internal/vuln` |
| `deception` | Deception | W9 | `internal/decoys`, `internal/honeytokens`, `internal/agent/mods/deception.go`, `internal/controller/deception_*.go`, `internal/actions/deception_*.go` | `internal/deception` (decoy child process included; decoys and honeytokens merge) |
| `report` | Reports and generators | W10 | `internal/report`, `internal/controller/report_*.go` | `internal/report`, `reports/` |
| `backup` | Operations | W10 | none (dump actions in `internal/actions`) | `internal/backup` |
| `teamfeed` | Operations | W10 | none | `internal/teamfeed` |
| `notify` | Operations | W10 | none | `internal/notify` |
| `depot` | Integrations and depot | W11 | `internal/depot`, `internal/depot/gotools`, `cmd/phylax/depot.go` | `internal/depot` |
| `wazuh` | Integrations and depot | W11 | `internal/integrations/wazuh`, `internal/actions/app_wazuh.go` | `internal/wazuh` |
| `splunk` | Integrations and depot | W11 | `internal/integrations/splunk`, `internal/actions/splunk_*.go` | `internal/splunk` |
| `suricata` | Integrations and depot | W11 | `internal/integrations/suricata` (W1 moves it to `internal/suricata` as its controller-side worked example; W11 owns everything after the move) | `internal/suricata` |

The core-default `health` agent module is core, not a catalogue module; W1 retrofits it as the agent-side worked example.

### Core work not owned by a module

| Core item (design section) | Workstream |
| --- | --- |
| Event envelope, kinds, `internal/module`, conformance, CI gates (The module contract) | W1 |
| Controller executor, approval classes, auto conditions, the per-template `autonomy` setting and the attempt ledger (host, object, kind), lint registry (Execution engine) | W1 |
| `control: fact`, `controller.fact`, fact subtypes, `work_window` supervisor effect (Wire protocol) | W1 |
| Query API, module tables (Event store) | W1 |
| UI registrar, Platform page module health (UI shell) | W1 |
| `modules/<name>.yml`, host `modules:`, labels and label expressions, module block JSON Schema (Manifest) | W1 |
| Plan template `target: {labels: ...}` expansion (Plans) | W5 (first user: hardening packs) |
| Dead-man fire reconciled while connected (bug 8), real executor always wired (bug 5) | W2 |
| `session.terminate_predating` (Local accounts) | W2 (interactive admin identities; interactive logon types only, never a session owning a manifest service process); W7 adds the scored-account rules |
| Agent `fetch` handler and chunk transfers (bug 4, Wire protocol) | W11 |
| Enrollment, bootstrap, controller recovery and resend verification; self-protection; `agent.*` actions | W12 |
| Overview roles and unstaffed, host x step grid, Since you left (UI shell, Operations) | W10 |
| Spool and link torture (T29), controller restart (T18), relay end to end (T47) | lab tasks of W1 (T18, T29) and W12 (T47) |

## Known bugs to workstreams

| Bug | Summary | Workstream |
| --- | --- | --- |
| 1 | `kernel.module_block` verify passes when built in | W5 |
| 2 | Rule id collision `D14`; rule-id registry check | W4 (the registry and the rename of `rules/deps.yml` ids to `DEP1`-`DEP3`) |
| 3 | Stale Typst references | W10 (report); W11 checks `depot/` |
| 4 | Agent `fetch` handler is a no-op | W11 |
| 5 | Placeholder step handler; `phylax agent` must always wire the real executor | W2 |
| 6 | Ledger alerts do not reach D5d | W5 |
| 7 | Controller never sends `freeze_capture` | W6 |
| 8 | Dead-man fires while connected not reconciled | W2 |
| 9 | `plans/actions.yaml` header says TODO | W5 |
| 10 | Reference `services.yml` lacks DNS and FTP | W2 |
| 11 | No `shortcut:` comments; `t.Skip` without reason | W1 (the CI guard and the fixes it forces) |
| 12 | Sinkhole on with no catcher; nat redirect bypasses NFLOG | W6 |
| 13 | Capture ring in the Go heap against the 80 MB footprint | W6 |
| 14 | Shadow would-drops share the deny NFLOG group | W6 |
| 15 | Sibling imports (`net`→`deps`, `depot`→`integrity`, `gotools`→`net`) | W1 (the import check), W3 (`net`, `internal/sockets`), W8 (`deps` subscribes), W11 (`depot` uses `internal/signing` and `internal/sockets`) |
| 16 | Heartbeat does not carry the audit rules hash | W1 (`HealthReporter`, heartbeat `Health`), W3 (`audit` fills `Health.Info`) |
| 17 | Controller-origin events under the wrong agent; undeclared kinds | W1 (controller event chain, `suricata`), W3 (`audit`), W11 (`wazuh`), every retrofit (its own kinds) |
| 18 | Honeytoken attribution rewrites stored alerts | W9 |
| 19 | `icmp.iputils_pattern` wrong for 64-bit | W6 |
| 20 | Device health hook runs no probe | W6 (W1 adds `Env.Probe`, W7 supplies the probe) |
| 21 | Depot package actions declare no touches | W11 |
| 22 | `ir_template` rule key survives | W4 |
| 23 | Windows hosts given the `capture` role | W2 (reference manifest) |

T65 holds the regression tests; each owning workstream adds its bug's test in the task that fixes it.

## Plan files to be written

W1's plan exists. The others are written next, one agent each, from this README, the design sections in the Owns column and W1's Interfaces blocks. Each follows `superpowers:writing-plans` exactly: header (Goal, Architecture, Tech Stack, Spec), Global Constraints (copy W1's and add the workstream's), Review Focus, Task 1 = seams (Sonnet or Opus), Haiku tasks with Files, Interfaces (Consumes and Produces with exact Go signatures), checkbox steps (failing test with assertions as code, run and expect FAIL, implement the exact signature, run and expect PASS, commit), the last task = lab, and a self-review.

| Plan file | Workstream | Must cover (beyond the module sections' own parts) | Lab tests |
| --- | --- | --- | --- |
| `00-proving.md` | W0 | Run `make build build-windows vet test race`; fix every race with a regression test; add `v4` and `v4-*` to the CI triggers. Two or three tasks; no seams task needed (state why) | T45 |
| `02-invitational.md` | W2 | Built on v3 code, no W1 names. Observe-mode reference config (safe mode at start, detect alert-only, firewall render shadow-only, no `capture` role on Windows, DNS and FTP in `services.yml`); Tier A list and Tier B pieces (T+0 admin rotation with `session.terminate_predating` for admin and service accounts, tier-0 responses on non-scored targets, hardening with the dead-man, red-IP blocks on non-scored ports); bugs 5 and 8; collector scripts C1 to C7 from `invitational-data.md` (shell and PowerShell, read-only, with an output-format test each; pick their directory and record it in Appendix D, see W1 gaps); a one-page runbook for the day; T70 as an automated test where possible | T70, dry run of C0 to C9 |
| `03-telemetry.md` | W3 | Seams declares every `audit.*`, `winevt.*`, `net.*`, `logs.*`, `inventory.*` kind and moves the packages; producers emit canonical common kinds with `event.New`; the rename map applied in one commit per producer together with `rules/*.yml` and `internal/traceback/obs.go`; `internal/sockets` extraction; `net` stops calling `deps` | T11, T12, T21, T29, T43, T69, T71, T75 |
| `04-detection-response.md` | W4 | Seams declares `detect.*`, `respond.*`, `content_guard.*`; rule loader rejects non-canonical fields and `ir_template`; `replay:`, `rate:`, `jitter`; rule-id registry; `rules/detect/` move; respond tiers using `Env.Fact` and `Host.RunAuto`/`Propose` | T02, T03, T16, T20, T36, T52, T74, T79 |
| `05-integrity-hunting.md` | W5 | Seams declares the module kinds and extracts `internal/signing` and `internal/integrity/format` (merge early: W11 waits on it); sshsig; hardening packs as content under `plans/hardening/` with `module:`; template label expansion; AD Recycle Bin (B1) | T01, T31, T32, T34, T38, T61, T68, T72, T76, T78 |
| `06-network.md` | W6 | Seams declares `firewall.*`, `egress.*`, `capture.*`, `devices.*` and moves `devices`; break `internal/actions` → `devices`/`firewall` imports; inbound auto-enforce and allow-back (A-AUTO); device commits probed through `Env.Probe` | T05, T06, T13, T17, T44, T62, T67, T77 |
| `07-scoring-creds.md` | W7 | Seams extracts `internal/checks/probe` (merge early: W12 waits on it) and declares the kinds; supplies `controller.Options.Probe`; `round_clock`, `scorer_probe_result`, `creds_txn` fact senders | T14, T15, T30, T35, T37, T39, T49, T50, T51 |
| `08-analysis.md` | W8 | Seams declares kinds and the module tables (no `traceback.result`; one `chains.chain` kind); the hop builder moves into `internal/chains/hops`; analysers pure over `store.Reader`; one writer goroutine per module; `DEP###` lint rules via `lint.Register` (`DEP003` is the one deps guard) | T03 (trace-back half), T33 |
| `09-deception.md` | W9 | Seams declares the `deception.*` kinds and merges the two packages; decoy child process split; `deception.sighting` instead of rewriting alerts | T08, T09, T10, T24 |
| `10-reports-ops.md` | W10 | Seams declares kinds (operator edits are `operator.edit`, saved queries are generators); `work_window` fact sender (`teamfeed`); backups under a standing approval; Overview roles, grid, Since you left | T53, T54, T55, T56, T57, T58, T59 |
| `11-integrations-depot.md` | W11 | Seams declares kinds and moves `wazuh`, `splunk`; agent `fetch`; `suricata.analyze_pcap` in the controller executor; `packages` from `services.yml` | T40, T41, T63 |
| `12-enrollment.md` | W12 | `internal/enroll` (SSH push, WinRM push, one-liner, bootstrap handler, tokens, `set-controller`); emits `agent.enrolled`, `agent.reenrolled`, `enroll.*` through `EmitController`; restore resend verification | T19, T22, T23, T27, T28, T47, T48 |
| `13-c2-lab.md` | W13 | Mostly lab: capture plan per framework, rule-writing tasks with fixtures, the sinkhole decision record and the follow-up deletion or reorder task | T60, T62 |

## Design gaps found while writing W1

Recorded here so the other plan writers do not trip on them; W1's plan resolves each (top of `01-module-contract.md`, "Deviations"), and its seams task updates the design text in the same commit.

1. Import cycle: `module.Host` takes `plan.Plan` while `plan.ModuleLimits` embeds `module.Common`. Resolved: Host's plan methods take a template name and parameters (content before code); `internal/module` does not import `internal/plan`.
2. `store.Query` is already the event filter struct; the read-only query interface is `store.Reader`.
3. A controller module that owns tables has no write path in the design's `Host`. Added `Host.Tables()`.
4. The `auto` allowlist's home is unspecified. Added `auto:` to `module.Common`.
5. Canonical fields are missing for `dns_query` and `telemetry_gap`; `process_start` lists both `pexe`/`pcomm`/`pcmdline` and `parent.*`. W1 fixes both structs (see its Task 4).
6. The shape of `hosts.yml` `modules:` is unspecified. Chosen: a map of module name to bool.
7. `Proposal` has no fields in the design; controller-module registration has no mechanism; event `Type` has no alert flag. W1 defines all three.
8. Default priority per kind is not in the kind table. W1 takes it from today's emitters.
9. Collector scripts (W2) have no home in Appendix D.
10. `internal/actions` (core) imports the modules `devices`, `firewall` and `wazuh`; W6 and W11 break those edges.
11. Conformance check 6 (60 s of link loss) costs a minute per module; W1 runs it at full length in the CI conformance job and at 2 s under `-short`.
12. `Analyzer.Run` has no context, so a run over its deadline cannot be stopped. W1 adds `ctx`.
13. `act_enabled` is per module block; the Invitational tiers flip it "for named hosts", which has no designed per-host form. W1 keeps it fleet-wide with a `shortcut:`; W2 does tiers with v3 switches. Since S4 the key exists only on the modules that act (`respond`, `firewall`, `hardening`, `ad`, `content_guard`, `creds`, through `module.Actor`, which also carries `autonomy`), and the design now has the per-host form (`overrides.yml` `act:`).
14. `RunAuto` has no argument for the triggering event the audit must record; W1 uses a reserved `trigger` parameter.
15. The kind table has 29 core rows; the design's summary says 28.
16. `plan.ModuleLimits.RatePerSec` becomes `float64` (the design's type); today it is `int`.
