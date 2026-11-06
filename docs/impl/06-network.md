# W6: Network Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the four network modules (`firewall`, `egress`, `capture`, `devices`) on the module contract, break the `internal/actions` imports of `devices` and `firewall`, build what the design adds (inbound auto-enforce with allow-back, conntrack flush, quarantine, source blocks, shadow summarizer, egress ranking and suggestions, `freeze_capture`, TFTP and NTP parsers, device pollers and `D14`, backups, rotation, licence gating) and fix Known bugs 7, 12, 13, 14, 19 and 20.

**Architecture:** Each module is one package (`internal/firewall`, `internal/egress`, `internal/capture`, `internal/devices`) with an agent registration in `internal/agent/mods/<name>.go` where it has an agent side and a `module.ControllerModule` where it has a controller side. A module that owns an action family registers it from its package (`actions.Register`), so `internal/actions` imports no module. Module backends reach actions through `actions.Env.Ext`, set by the code that builds the `Env` (the agent binary, the controller executor). Policy comes from the manifest renderer (`internal/manifest/render`, core) into the signed `AgentConfig`; the agent applies it only through plan nodes or, for the allow-back, under `act_enabled`.

**Tech Stack:** Go 1.27.2 (mise), standard library, existing deps only (`github.com/google/nftables`, `github.com/mdlayher/netlink` (already in `go.mod`, becomes direct), `modernc.org/sqlite`, `gopkg.in/yaml.v3`, `golang.org/x/{net,sys,crypto}`). No new modules in `go.mod`.

**Spec:** `phylax_design.md` (v4): Network (`firewall`, `egress`, `capture`, `devices`, all 12 parts each), "The module contract", "Execution engine" (action contract, controller executor and approval classes, `fw.*` and device action families, scorer-mimic probe, dead-man), "Wire protocol" (`control: freeze_capture`), "Manifest" (module blocks, firewall lint), Known bugs 7, 12, 13, 14, 19, 20, Testing and lab (T02, T05, T06, T13, T17, T44, T60, T62, T65, T67, T77). Master plan: `docs/impl/README.md`. Contract names: `docs/impl/01-module-contract.md` (W1).

## Deviations and additions (applied by Task 1 to `phylax_design.md` in the same commit, each with its reason)

1. **`internal/devices` root becomes the module; the adapter types move to `internal/devices/adapter`.** `palo` and `vyos` import the `Adapter`, `Tx`, `SafeChange` types that live in the root today; the module imports `palo` and `vyos`, so the root cannot hold both. Appendix D gains `devices/adapter/`.
2. **Actions leave `internal/actions`.** The exported hooks are W1 Task 2a's, under the one registration name: `actions.Register(f func() []Action)`, `actions.RegisterUndo(kind, fn)`, `actions.Unsupported(what string) error`, `(*Env).Now() time.Time` (the old field `Env.Now` is renamed `Env.Clock`) and `Env.Ext map[string]any` (backends owned by modules, keyed by module name). `WinEnv.Firewall`, `WinEnv.Devices`, `LinuxEnv.Firewall`, `DeviceDirectory` and `FirewallBackend` are deleted from `actions` here (Tasks 2 and 3). W11 uses the same hooks for `wazuh`. (This plan formerly called the registration hook `Register`; it is `Register` everywhere now.)
3. **The inbound `gate: auto` is evaluated by the `firewall` controller module before it calls `RunAuto`**, because its condition reads the nested would-drop summary (groups by coverage), which the core's generic `gate: auto` (W1 Task 27a: time, probe, absence of an event) cannot express. The plan template `plans/firewall/enforce-inbound.yaml` holds only the enforce node and the probe; the module checks the shadow summary (no `coverage: scored` group), that safe mode is off and `act_enabled`, and then `RunAuto`; otherwise it `Propose`s. A template may still add a core `gate: auto` with `until: {after: ..., probe: '*'}` for the minimum shadow time.
4. **`module.Host.Manifest() *manifest.Manifest`** is W1 Task 17a's (`internal/module` may import `internal/manifest`: it imports no repo package). The shadow verdict (`declared`, `undeclared`, `scored`), the egress allow table and the device inventory all read the manifest.
5. **`Host.Control` accepts `Type: "freeze_capture"`** from module `capture` only (`Data`: `rule`, `alert_time`, `addrs`; no `Fact`, `ID` or `TTL`). The design says a module may send only facts, but Known bug 7 needs the controller side of `capture` to send `freeze_capture`, and the core cannot know which agents saw a flow. `plan.ControlFreezeCapture = "freeze_capture"`; `link.ProtoMinor` rises by 1.
6. **`fw.apply` takes `destinations`** (outbound destination blocks) beside `sources` (inbound). The design says "block the destination for this host (`fw.apply` with a drop in the `egress` group)" but names only `sources`. Exactly one of the two is given.
7. **`firewall.allow_back` gains `probe`** (`ok`, `failed`, `unavailable`): the agent-side probe may not exist (no `Env.Probe` on the agent until W7), and the event must say so.
8. **Prefix and group constants are core.** `render.PrefixShadowInput = "phylax-shadow-input: "`, `PrefixShadowOutput`, `PrefixInputDeny = "phylax-input-deny: "`, `PrefixEgressDeny = "phylax-egress-deny: "`, `DefaultDenyLogGroup = 100`, `DefaultShadowLogGroup = 101`. `net` (W3) reads them from `render`; it cannot import `firewall`.
9. **`learned_listeners` is written through W1's `Host.UpdateOverrides`** (Task 17a over `manifest.AppendOverrides`, Task 11a) as `manifest.LearnedListener{Host, Proto, Port, Reason, Observed}` entries of `overrides.yml`, rendered like a service listener into the `learned` group (any source). The controller side of `firewall` writes one when `learned_listeners` is true and a consumed `firewall.allow_back` event carries a scored port or scorer-like sender (Task 14).
10. **Controller-scope rule evaluation is `detect`'s (W4).** `internal/controller/capture_ingest.go` is that evaluator; W6 only deletes the `net.flow` translation from it (capture emits `conn` itself) and moves rule content `D13e` and `D18b` to `rules/capture/` once W4 has moved `rules/network.yml` (Task 28 is ordered after W4's move).
11. **`plans/egress/patch_window.yaml` uses W1's `expires_after` node option** (Task 22a: `expires_after: 30m` in a template; the dead-man machinery with the confirm turned off), so Task 19 writes the template and a real test.
12. **`D4c`, the `D13c` jitter operator and the retirement of the learned `egress.exes` profile are W4's** (the design assigns `rules/detect/egress.yml` to `detect`). W6 renders the seeded profile `egress.allow` (Task 17) and ships `rules/egress/beacon.yml` only when W4 has the operator (Task 18 note).
13. **Per-device vault keys are served by W1's prefix grants** (Task 9a, 17a: a module block that names `cred/*` lets `Host.Secrets("cred/*")` read `cred/<device>/<account>`). `devices.Module` still receives its directory through `Attach(dir Directory)`, called from `cmd/phylax/serve.go` with the same `*controller.Directory` the executor uses (`controller.Options.Backends["devices"]`), because the pooled adapters are shared with the executor. `shortcut: the device Directory stays in internal/controller until W11 splits the Splunk half out of it, then it moves into internal/devices`.
14. **`Directory.ScoredServices(ctx, device)`** supplies the probe list for a device commit: every scored service name in the manifest (a Palo is on every scored path).

## Global Constraints

- Go 1.27.2 via mise; `CGO_ENABLED=0`; `make build build-windows vet test race` passes at every commit (linux/amd64 and windows/amd64 both build and vet; `-race` runs with `CGO_ENABLED=1`).
- Every package ships tests; tests exercise the real code (no mocking of the code under test, no tautological asserts). Fakes only at an edge the package does not own: the kernel (nftables, conntrack, AF_PACKET), the Windows COM firewall, the Palo and VyOS (the existing `palotest` and `vyostest` stateful fakes). A test that needs privileges or containers calls `t.Skip` with a reason string.
- Commits are small, one logical change, message `area: summary` (for example `firewall: conntrack flush`). No attribution lines.
- No shelling out in the default path. Bounded everything: queues, buffers, decoded sizes, timeouts. Atomic writes through `internal/atomicfile`. Times stored in UTC. Secrets never appear in events, logs or config files.
- No compatibility shims, aliases or dual formats; renamed things are renamed everywhere in the same commit (the old kind names `net.txn`, `net.flow`, `net.scan`, `http_request`, `net.connection_opened` in capture's output, `device_config` are deleted, not aliased).
- A module imports only the core packages (`internal/event`, `internal/module`, `internal/agent`, `internal/link`, `internal/plan`, `internal/actions`, `internal/store`, `internal/manifest`, `internal/manifest/render`, `internal/deadman`, `internal/ui`, `internal/vault`) and the shared libraries (`internal/atomicfile`, `internal/parsers/...`, `internal/checks/probe`, `internal/sockets`, `internal/signing`, `internal/integrity/format`, `internal/inventory/fold`). `egress` does not import `firewall`, `capture` does not import `devices`, nothing imports `net` or `detect`.
- Scored ports are allow-any-source in every mode (shadow, enforce, quarantine); a block never names an address the manifest lists as ours; a conntrack flush never touches a flow carrying the management mark `0x7068` or a flow on a scored port.
- Windows: `capture` is unavailable (cut, review D235); firewall shadow is evaluated by `net`, not installed. Known limits carry `// shortcut: <limit>, <when to upgrade>`.
- The design is authoritative; a forced design change edits `phylax_design.md` in the same commit with the reason.

## Review Focus

1. **A scored UDP service under inbound enforce (TFTP 69, NTP 123).** Expected: protected only because the manifest lists it as scored (never hard-coded), accepted from any source in the rendered policy, and an unlisted UDP port is dropped. Task 5 `TestScoredUDPAcceptedFromAnySource`, `TestUnscoredUDPDropped`.
2. **A conntrack flush that cuts the scorer's in-flight check or the agent link.** Expected: flows with the management mark or on scored ports survive every flush (policy tighten, block, quarantine). Task 8 `TestFlushSparesMarkedAndScored`.
3. **An allow-back flood from a scanner hitting a scored port from many sources.** Expected: at most `max_per_hour` (5) allow-backs per host; the rest raise the alert without changing the policy, and an allow-back is never undone automatically. Task 13 `TestAllowBackRateLimited`.
4. **A device commit when the scorer-mimic probe cannot run or is red.** Expected: red inside the revert window reverts through the device protocol; a nil `Env.Probe` never reads as green (output says `probed=false`). Task 32 `TestRedProbeRevertsPaloCommit`, `TestNilProbeNotGreen`.
5. **`freeze_capture` for a rule that fires twice, for an address in no ring, or while the disk budget is full.** Expected: the repeat extends the same hold (same id), an empty ring yields an evidence event with `error`, nothing blocks the capture loop. Task 26 `TestFreezeCaptureRepeatExtendsHold`, `TestFreezeCaptureNoMatchingPackets`.

---

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `internal/actions/{registry,env,win_env}.go` | `Register`, `RegisterUndo`, `Unsupported`, `Env.Now`, `Env.Ext` (W1 Task 2a); no module imports | W1 2a, 2, 3 |
| `internal/firewall/events.go`, `manifest.go`, `config.go`, `module.go` | event payloads, manifest, config block, agent module | 1, 12 |
| `internal/firewall/actions.go`, `actions_apply.go`, `actions_win.go` | `fw.*`, `firewall.allow`, `win.firewall` | 2, 9, 10 |
| `internal/firewall/{verdict,conntrack_linux}.go` | verdict function, conntrack flush | 8 |
| `internal/firewall/allowback.go` | allow-back | 13 |
| `internal/firewall/controller.go`, `shadow.go` | controller side, summarizer, inbound auto trigger | 14, 15 |
| `internal/manifest/render/{policy,nft,windows,check,egress}.go` | block group, prefixes, lints, egress profile | 5, 11, 17 |
| `internal/egress/` | module, ranking, suggestions | 16-19 |
| `internal/capture/` | module, kinds, settings, freeze, source check | 20-27 |
| `internal/parsers/{tftp,ntp}/` | new parsers | 23, 24 |
| `internal/devices/adapter/` | `Adapter`, `Tx`, `SafeChange` (moved) | 1 |
| `internal/devices/{module,actions,poll,backup,config}.go` | module, actions, pollers, backups | 3, 29-35 |
| `internal/agent/mods/{firewall,capture}.go`, `internal/agent/handlers.go` | agent registrations; `freeze_capture` control | 12, 21, 26 |
| `internal/controller/genconfig_network.go` | `FirewallSettings`, `CaptureSettings`, memory budget | 11, 21, 25 |
| `manifest/2027/modules/{firewall,egress,capture,devices}.yml` | reference blocks | 4 |
| `plans/{firewall,egress,devices}/`, `rules/{capture,devices,egress}/` | content | 15, 19, 28, 30, 35 |
| `docs/impl/lab/w6-network.md` | lab record | 36 |

---

### Task 1: Seams (Sonnet or Opus)

Done by a stronger model. Writes the package moves, exported hooks, kind declarations with payload structs, module skeletons and manifests, the settings structs, the skipped tests of Tasks 2 to 35 and the design-text deviations. Merges on its own as a pull request into `v4`; W7 waits for the `capture.*` kinds in it.

**Files:**
- Move (`git mv`, delete old paths, update every import): `internal/devices/{devices,runner,diff}.go` and `runner_test.go` → `internal/devices/adapter/` (package `adapter`); `palo` and `vyos` import `internal/devices/adapter`.
- Create: `internal/firewall/{events,manifest,config,module,controller}.go`, `internal/egress/{events,manifest,config,module}.go`, `internal/capture/{kinds,manifest,config,controller}.go`, `internal/devices/{events,manifest,config,module}.go`, skipped test files named in later tasks (`storetest.New` is W1 Task 8a).
- Modify: `internal/actions/{win_env.go,linux_env.go}` (delete `WinEnv.Firewall`, `WinEnv.Devices`, `LinuxEnv.Firewall`), `internal/module/host.go` (`freeze_capture`; `Manifest()` is W1's), `internal/plan/agentconfig.go` (`Modules.Firewall`, `Modules.Capture`), `internal/plan/control.go`, `internal/link/message.go` (`ProtoMinor`), `internal/module/all/all.go` (blank imports `firewall`, `egress`, `capture`, `devices`), `internal/module/conformance/allowed.go` (`ModulePackages`: the four; `PreContract`: add the four names, each deleted by its retrofit task), `phylax_design.md`.
- Test: `internal/actions/imports_test.go` (written in Task 3).

**Interfaces:**
- Consumes: W1's `event.Declare`, `event.Type`, `module.Manifest`, `module.Common`, `module.ControllerModule`, `module.Register`, `module.Host.Manifest`, `agent.Factory`, `plan.ModuleLimits`, `plan.BlockFor`, `actions.Register`, `actions.RegisterUndo`, `actions.Unsupported`, `Env.Now`, `Env.Ext`, `storetest.New`.
- Produces (exact):

```go
// ---- internal/actions (core): W1 Task 2a's, consumed here ----
// Register(f func() []Action), RegisterUndo(kind, fn) (panics on a duplicate kind), Unsupported(what) error, (*Env).Now() time.Time, Env.Ext map[string]any

// ---- internal/module/host.go ----
// Host.Manifest() is W1 Task 17a's. Control accepts ControlMsg{Type: "freeze_capture", Hosts: [...], Data: {"rule": string, "alert_time": RFC 3339, "addrs": []string}}
// from module "capture" only; any other Type besides "fact" is ErrNotInScope.

// ---- internal/plan ----
const ControlFreezeCapture = "freeze_capture"
type FirewallSettings struct { // json block "firewall"
	ModuleLimits
	Deadman        time.Duration      `json:"deadman,omitempty"`
	ConntrackFlush bool               `json:"conntrack_flush"`
	QuarantineSec  int                `json:"quarantine_revert_sec,omitempty"`
	DriftCheckSec  int                `json:"drift_check_sec,omitempty"`
	ShadowLogGroup uint16             `json:"shadow_log_group,omitempty"`
	InboundMode    string             `json:"inbound_mode,omitempty"`  // enforce | shadow (the block's inbound.mode)
	OutboundMode   string             `json:"outbound_mode,omitempty"` // shadow | enforce
	AllowBack      AllowBackSettings  `json:"allow_back"`
	Block          []BlockEntry       `json:"block,omitempty"`
	Policy         *render.HostPolicy `json:"policy,omitempty"`     // Linux
	WinPolicy      *render.WinPolicy  `json:"win_policy,omitempty"` // Windows
}
type AllowBackSettings struct {
	Enabled    bool `json:"enabled"`
	MaxPerHour int  `json:"max_per_hour,omitempty"`
}
type BlockEntry struct{ CIDR, Reason, Owner, Added, Expires string } // json tags cidr, reason, owner, added, expires (all omitempty but cidr)
type CaptureSettings struct { // json block "capture"; the design's struct plus Services as map[uint16]string
	ModuleLimits
	Interface     string            `json:"interface,omitempty"`
	Exclude       []string          `json:"exclude,omitempty"`
	LocalAddrs    []string          `json:"local_addrs,omitempty"`
	RingMB        int               `json:"ring_mb,omitempty"`
	HoldMB        int               `json:"hold_mb,omitempty"`
	FlowBytes     int               `json:"flow_bytes,omitempty"`
	DiskBudgetMB  int               `json:"disk_budget_mb,omitempty"`
	FreezeBeforeS int               `json:"freeze_before_sec,omitempty"`
	FreezeAfterS  int               `json:"freeze_after_sec,omitempty"`
	MaxWindows    int               `json:"max_windows,omitempty"`
	ScanThreshold int               `json:"scan_threshold,omitempty"`
	ScanWindowS   int               `json:"scan_window_sec,omitempty"`
	ScoredPorts   []uint16          `json:"scored_ports,omitempty"`
	Services      map[uint16]string `json:"services,omitempty"`
	StatsEverySec int               `json:"stats_every_sec,omitempty"`
}
// ModuleSettings gains: Firewall *FirewallSettings `json:"firewall,omitempty"`; Capture *CaptureSettings `json:"capture,omitempty"`

// ---- internal/manifest/render (core): constants ----
const (
	PrefixShadowInput = "phylax-shadow-input: "; PrefixShadowOutput = "phylax-shadow-output: "
	PrefixInputDeny = "phylax-input-deny: "; PrefixEgressDeny = "phylax-egress-deny: "
	DefaultDenyLogGroup uint16 = 100; DefaultShadowLogGroup uint16 = 101
)

// ---- internal/store/storetest: storetest.New(t, evs...) is W1 Task 8a's, consumed here ----

// ---- kinds (Declare in init; Schema 1; priority and alert per the design's kind table) ----
// firewall: firewall.applied (high), firewall.drift (high), firewall.restored (high), firewall.allow_back (critical, Alert true),
//           firewall.quarantine (critical), firewall.shadow_summary (normal)
// egress:   egress.candidate (high), egress.suggest_block (normal)
// capture:  capture.txn (normal), capture.flow (bulk), capture.scan (high), capture.http_request (normal),
//           capture.evidence (high), capture.stats (normal), capture.source_check (high)
// devices:  devices.config (high), devices.change (high), devices.deny (normal), devices.traffic (normal),
//           devices.backup (normal), devices.version (normal), devices.finding (high), devices.capture (high)
```

Payload structs (one per kind, `<Kind>Event`, JSON tags are the design's key-field names, optional fields `omitempty`):

```go
// internal/firewall/events.go
type AppliedEvent struct {
	Host string `json:"host"`; Mode string `json:"mode"`; Node string `json:"node,omitempty"`
	PrevHash string `json:"prev_hash,omitempty"`; Hash string `json:"hash"`; Changed bool `json:"changed"`
	DeadmanArmed bool `json:"deadman_armed"`; ForeignTables []ForeignTable `json:"foreign_tables,omitempty"`
}
type DriftEvent struct {
	Group string `json:"group"`; Diff []string `json:"diff"`; ForeignMayBlock bool `json:"foreign_may_block,omitempty"`
}
type RestoredEvent struct{ Reason, Node, Hash string } // json reason (deadman|verify_failed|drift|panic_open), node, hash
type AllowBackEvent struct {
	Host string `json:"host"`; Port uint16 `json:"port"`; Proto string `json:"proto"`; Source string `json:"source"`
	Reason string `json:"reason"` /* scored_port | scorer_like */; RuleAdded string `json:"rule_added"`
	DroppedSinceMS int64 `json:"dropped_since_ms"`; Proposal string `json:"proposal,omitempty"`; Probe string `json:"probe"`
}
type QuarantineEvent struct {
	Host string `json:"host"`; Reason string `json:"reason"`; Expires string `json:"expires"`; FlowsDeleted int `json:"flows_deleted"`
}
type ShadowGroup struct {
	Dir, Proto, Src, Dst string; DPort uint16; Count int; First, Last, Process, Coverage string // json dir, proto, src, dst, dport, count, first, last, process, coverage
}
type ShadowSummaryEvent struct {
	Since string `json:"since"`; Groups []ShadowGroup `json:"groups"`; Total int `json:"total"`; ProposalID int64 `json:"proposal_id,omitempty"`
}
// internal/egress/events.go
type CandidateEvent struct {
	Rank int `json:"rank"`; Host string `json:"host,omitempty"`; Exe string `json:"exe,omitempty"`; ExeSHA256 string `json:"exe_sha256,omitempty"`
	RAddr string `json:"raddr"`; RPort uint16 `json:"rport"`; Hosts []string `json:"hosts"`; Attempts int `json:"attempts"`
	FirstSeen string `json:"first_seen"`; LastSeen string `json:"last_seen"`; NewBinary bool `json:"new_binary"`; Periodic bool `json:"periodic"`
	IntervalMean float64 `json:"interval_mean,omitempty"`; IntervalCV float64 `json:"interval_cv,omitempty"`
	Lineage []string `json:"lineage,omitempty"`; Class string `json:"class"`; Baseline bool `json:"baseline,omitempty"`
}
type SuggestBlockEvent struct {
	ProposalID int64 `json:"proposal_id"`; Host string `json:"host"`; What string `json:"what"` /* destination | kill_process */
	Evidence []module.EventRef `json:"evidence"`
}
```

`capture.*` and `devices.*` payload structs carry exactly the keys the code writes today (`capture/events.go`, `httpevent.go`, `freeze.go`, `module.go`; `devices.ConfigEvent` fields for `devices.config`) plus the design's key-field list for the new kinds (`devices.deny`, `devices.traffic`, `devices.backup`, `devices.version`, `devices.finding`, `devices.capture`, `capture.source_check {agree, sample, firewall_sources, recovered}`). `capture.flow` keeps its private shape; the common `conn` kind is W1's.

Manifests are the design's part 3 of each module, verbatim (Budget numbers, `Default`, `Tables`, `Content`, `Actions`, `Pages`, `Evidence`), with `Emits` the kinds above and `Consumes` as the design lists. Config structs are the design's part 4 (`firewall.Config` and `devices.Config` as written; `egress.Config` as written; `capture.Config` with the YAML keys of part 4), each embedding `module.Common` inline. Module types: `firewall.Controller` (controller side, `module.Register` in `init`; agent side is the factory of Task 12), `egress.Module`, `capture.Controller`, `devices.Module` with `Attach(dir Directory)`; all with stub bodies returning an `unavailable` health with the gap `{"module", "not built (W6 Task N)"}`.

- [ ] **Step 1: Move `internal/devices` types** to `internal/devices/adapter`; run `go build ./... && GOOS=windows go build ./...`. Expected: builds.
- [ ] **Step 2: Add `freeze_capture`, the settings structs and constants** exactly as above (the `actions` hooks and `Host.Manifest` already exist from W1). `ProtoMinor` rises by 1 (write the new value in `plan/control.go`'s comment).
- [ ] **Step 3: Declare the kinds, write payloads, manifests, config structs and stub modules;** add the four names to `PreContract` and `ModulePackages`; blank-import the four packages in `module/all`.
- [ ] **Step 4: Confirm `storetest.New`** (W1 Task 8a) seeds a chain the module tests below can read: write one smoke test in `internal/firewall` that seeds two `net.shadow_drop` events and reads them back.
- [ ] **Step 5: Write every skipped test file named in Tasks 2 to 35** with the tests of each task's Step 1, first statement `t.Skip("unimplemented: W6 Task N")`.
- [ ] **Step 6: Apply the 14 deviations to `phylax_design.md`** (module sections, Appendix D, the control table, Known bug text unchanged).
- [ ] **Step 7: Verify.** Run: `make build build-windows vet test race`. Expected: all pass. Then `go test -v ./internal/... 2>&1 | grep -c 'unimplemented: W6 Task'` equals the number of skipped tests written in Step 5.
- [ ] **Step 8: Commit.**

```bash
git add internal docs phylax_design.md
git commit -m "network: W6 seams (adapter move, action hooks, kinds, settings, skipped tests, design deviations)"
```

Open as its own pull request into `v4`; merge after review.

---

### Task 2: Firewall actions leave `internal/actions`

**Files:**
- Move: `internal/actions/linux_firewall.go`, `linux_firewall_linux.go`, `win_firewall.go` → `internal/firewall/actions.go`, `actions_linux.go`, `actions_win.go` (package `firewall`); their tests (`linux_*_test.go` cases for `firewall.allow`, the `win.firewall` cases of `win_misc_test.go`, `fakeFW` of `win_fakes_test.go`) → `internal/firewall/actions_test.go`, `actions_win_test.go`
- Modify: `internal/actions/{win_env.go,linux_env.go,registry_win.go,registry_linux.go,win_native_windows.go}` (delete `WinEnv.Firewall`, `LinuxEnv.Firewall`, `FirewallBackend`, the registrations and the import of `internal/firewall`); `internal/firewall/module.go` (the `init` registration)
- Test: `internal/firewall/actions_test.go`

**Interfaces:**
- Consumes: W1 Task 2a hooks (`actions.Register`, `RegisterUndo`, `Unsupported`, `Env.Now`, `Env.Ext`), `actions.LockFirewall`, the existing `firewall.LinuxManager`, `WinManager`, `WinBackend`.
- Produces:

```go
// internal/firewall
const ExtKey = "firewall" // actions.Env.Ext key
type Backend interface {  // the host firewall as the actions see it (was actions.FirewallBackend)
	Policy(ctx context.Context) (*render.HostPolicy, error)
	Apply(ctx context.Context, hp *render.HostPolicy) error
	Snapshot(ctx context.Context) (json.RawMessage, error)
	Restore(ctx context.Context, snap json.RawMessage) error
}
type WinFactory func() (WinBackend, error)               // Env.Ext["firewall.win"]; default NewComBackend on Windows
func BackendFor(env *actions.Env) (Backend, error)       // Env.Ext[ExtKey] if set, else the real nft backend over the package declared-policy state (Linux); actions.Unsupported elsewhere
func SetDeclared(hp *render.HostPolicy)                  // package state shared by the agent module and the actions (atomic pointer)
func Declared() *render.HostPolicy
```

Behaviour is unchanged: `firewall.allow` and `win.firewall` keep names, params, rollback kinds (`firewall.allow.undo` is renamed `fw.restore.undo`; `win.firewall.restore` unchanged); `NftFirewall` becomes the default `Backend` built from `Declared`/`SetDeclared` instead of a field on `LinuxEnv`.

- [ ] **Step 1: Move the tests first and make them fail to compile against the new package** (they use `firewall.Backend`, `env.Ext`). The assertions stay (inbound allow added keyed by comment tag, `from: any` required on a scored port, rollback restores kernel and declared policy). Add one new test:

```go
func TestRegisteredFromPackage(t *testing.T) {
	reg := actions.Core() // blank import of this package registers the family
	for _, n := range []string{"firewall.allow", "win.firewall"} {
		if _, err := reg.Get(n); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/firewall/ -run 'Allow|WinFirewall|Registered' -v`. Expected: FAIL (compile errors, then the registration missing).
- [ ] **Step 3: Move the files and fix the references** with the W1 Task 2a hooks (`registerUndo` → `actions.RegisterUndo`, `env.now()` → `env.Now()`, `unsupported(...)` → `actions.Unsupported(...)`, `pkgNameRe` → a local `regexp` of the same pattern, `env.lx().Firewall` and `env.Win.Firewall` → `BackendFor(env)` / `env.Ext["firewall.win"]`). `init` calls `actions.Register(familyActions)`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/firewall/ ./internal/actions/ && GOOS=windows go vet ./internal/firewall/ ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "firewall: own firewall.allow and win.firewall; actions no longer import firewall"`

---

### Task 3: Device actions leave `internal/actions`; the import guard

**Files:**
- Move: `internal/actions/dev_actions.go`, `dev_directory.go`, `dev_actions_test.go` → `internal/devices/actions.go`, `directory.go`, `actions_test.go`
- Modify: `internal/actions/{win_env.go,registry_win.go}` (delete `WinEnv.Devices`, `DeviceDirectory`, the device registrations, the `devices` import), `internal/controller/devexec_run.go` (`devExec.env` sets `Ext: map[string]any{"devices": x.dir, ...}`; the Splunk entry stays `Win.Splunk` until W11), `internal/devices/module.go` (`init` registers the family)
- Create: `internal/actions/imports_test.go`
- Test: `internal/devices/actions_test.go`, `internal/actions/imports_test.go`

**Interfaces:**
- Consumes: Task 1 hooks; `adapter.Adapter`, `palo.Adapter`, `vyos.Adapter`, `render.PaloIntent`, `render.VyOSIntent`.
- Produces:

```go
// internal/devices
const ExtKey = "devices"
type Directory interface { // was actions.DeviceDirectory
	Palo(ctx context.Context, device string) (*palo.Adapter, error)
	VyOS(ctx context.Context, device string) (*vyos.Adapter, error)
	PaloIntent(ctx context.Context, device string) (*render.PaloIntent, error)
	VyOSIntent(ctx context.Context, device string) (*render.VyOSIntent, error)
	ConsoleAck(ctx context.Context, device string) bool
	ScoredServices(ctx context.Context, device string) []string // deviation 14
}
func directoryFor(env *actions.Env) (Directory, error) // env.Ext[ExtKey], else actions.Unsupported("network devices")
```

`*controller.Directory` gains `ScoredServices` (sorted names of manifest services with `Scored` true) and is passed in `Ext`. The compile-time assertion `var _ devices.Directory = (*Directory)(nil)` sits in `internal/controller/dir_devices.go`.

- [ ] **Step 1: Write the guard (new) and move the action tests.**

```go
// internal/actions/imports_test.go
func TestActionsImportNoModule(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"internal/devices", "internal/firewall", "internal/capture", "internal/egress"} {
		for _, p := range strings.Fields(string(out)) {
			if strings.Contains(p, "/phylax/"+banned) {
				t.Fatalf("internal/actions imports %s (Known gap 10)", p)
			}
		}
	}
}
```

W11 appends `internal/wazuh` to the list. The moved tests keep their assertions (`palo.permitted_ips` refuses a permit-all entry, `palo.apply` needs console ack, `vyos.apply` rolls back on a failed health check).

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ -run ImportNoModule -v && go test ./internal/devices/ -run 'Palo|Vyos|Dev' -v`. Expected: FAIL (the import still exists; compile errors in the moved tests).
- [ ] **Step 3: Move and rewire.** `devParam`, `devBase`, `txOpts` etc. go with the file. The controller executor builds `Ext` once per node Env. `init` in `internal/devices` calls `actions.Register`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/actions/ ./internal/devices/... ./internal/controller/ && GOOS=windows go vet ./...`. Expected: PASS (the existing `devexec_test.go` passes unchanged except its Env assertions).
- [ ] **Step 5: Commit.** `git commit -am "devices: own the device actions; actions imports no module"`

---

### Task 4: Egress and firewall policy move to module blocks; dead limits deleted (Known bug 13, part 1)

**Files:**
- Create: `manifest/2027/modules/firewall.yml`, `egress.yml`, `capture.yml`, `devices.yml` (the YAML of each design part 4, `enabled: true`, `act_enabled: false`, egress `sinkhole: { enabled: false, port: 7480 }`)
- Modify: `internal/manifest/types.go` (delete `Policy.Egress`, `Limits.PacketRingMaxBytes`, `PacketRingFreePct`, keep `Policy.Firewall` for the lint), `internal/manifest/helpers.go` (`Policy.DenyLogGroup`, `SinkholePort` become methods of `Manifest` reading the egress block), `manifest/2027/policy.yml` and `manifest/two-segment/policy.yml` (delete `egress:` and `limits:`), `manifest/schema/policy.yml.schema.json`, `internal/manifest/render/{policy,nft}.go` and `internal/manifest` callers of `Policy.Egress`
- Test: `internal/manifest/modules_net_test.go`

**Interfaces:**
- Consumes: W1's `Manifest.Modules`, `ModuleBlock.Decode`, `ModuleEnabled`.
- Produces:

```go
// internal/manifest
func (m *Manifest) Egress() EgressPolicy      // decodes Modules["egress"]; zero value when absent; EgressPolicy and Sinkhole types unchanged
func (m *Manifest) DenyLogGroup() uint16      // Egress().DenyLogGroup, default render-free constant 100
func (m *Manifest) SinkholePort() uint16      // 0 unless Egress().Sinkhole.Enabled
```

`EgressPolicy` keeps `Allow`, `Sinkhole`, `CanaryPorts`, `DenyLogGroup`; the block's extra keys (`exe_alerts`, `rank`) are the egress module's own and ignored here through a tolerant decode of the three shared keys only (`shortcut: shared keys decoded tolerantly, the module's own strict Config validates the full block`).

- [ ] **Step 1: Write the failing tests.**

```go
func TestReferenceSinkholeOff(t *testing.T) {
	m := mustLoad(t, "../../manifest/2027")
	if m.SinkholePort() != 0 {
		t.Fatal("reference manifest must leave the sinkhole off (Known bug 12)")
	}
	if m.DenyLogGroup() != 100 || !reflect.DeepEqual(m.Egress().CanaryPorts, []uint16{4444, 8888, 9001}) {
		t.Fatalf("%+v", m.Egress())
	}
}
func TestPolicyYAMLHasNoRingFields(t *testing.T) {
	b, _ := os.ReadFile("../../manifest/2027/policy.yml")
	if bytes.Contains(b, []byte("packet_ring")) {
		t.Fatal("dead field packet_ring_* must be deleted (Known bug 13)")
	}
}
func TestEgressBlockRendersSameHostPolicy(t *testing.T) {
	// golden: render.BuildHostPolicy for "rocky-ecom" before this task (testdata/rocky-ecom.policy.json from the commit parent) equals the result now,
	// except SinkholePort 0
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/manifest/... -run 'Sinkhole|PolicyYAML|EgressBlock' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the move; update `render` to call `m.DenyLogGroup()`/`m.SinkholePort()`; regenerate the policy schema; fix every test that wrote `Policy.Egress` literals.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "manifest: egress and firewall settings move to module blocks; sinkhole off; ring limits deleted"`

---

### Task 5: Renderer: block group, log prefixes, firewall lints

**Files:**
- Modify: `internal/manifest/render/{policy,nft,windows,check}.go`
- Test: `internal/manifest/render/block_test.go`, `internal/manifest/render/render_test.go`

**Interfaces:**
- Consumes: Task 1 constants; `plan.BlockEntry` is not imported (render stays below plan): the caller passes `[]render.BlockSpec`.
- Produces:

```go
const GroupBlock Group = "block"
type BlockSpec struct{ CIDR netip.Prefix; Reason, Owner, Added, Expires string }
// Rule gains: Block *BlockSpec `json:"block,omitempty"`
// HostPolicy gains: ShadowLogGroup uint16 `json:"shadow_log_group,omitempty"`; InputDenyLog bool `json:"input_deny_log,omitempty"` (inbound default-drop logs through DenyLogGroup with PrefixInputDeny)
func (hp *HostPolicy) WithBlocks(in []BlockSpec, out []BlockSpec) (*HostPolicy, error) // adds GroupBlock drop rules ahead of service accepts; Dir In for sources, Out for destinations; refuses an empty Reason, Owner or Added
func BuildHostPolicy(m *manifest.Manifest, name string) (*HostPolicy, error)           // now sets ShadowLogGroup = DefaultShadowLogGroup and InputDenyLog = true for servers
const (
	RuleBlockOwnAddress = "FW111" // a block names an address the manifest lists as ours (controller, agents, Kali, devices)
	RuleBlockWide       = "FW112" // a block CIDR wider than /24 (warning)
	RuleStage0Scored    = "FW113" // windows_stage0 blocks a scored port
)
// CheckHostPolicy: FW108 accepts GroupBlock drops that carry Block with Reason, Owner and Added; FW101 still requires scored ports accepted from any source,
// and a block on a scored port is an error unless the rule is limited to non-scored ports (the caller expands ports: non_scored to the unscored set)
```

- [ ] **Step 1: Write the failing tests.**

```go
func TestBlockGroupAheadOfServiceAccepts(t *testing.T) {
	hp := mustPolicy(t, "rocky-ecom")
	b, err := hp.WithBlocks([]render.BlockSpec{{CIDR: netip.MustParsePrefix("198.51.100.7/32"), Reason: "scanner", Owner: "net-lead", Added: "2026-11-07"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := indexOf(b.Rules, func(r Rule) bool { return r.Group == GroupBlock })
	svc := indexOf(b.Rules, func(r Rule) bool { return r.Group == GroupService && r.Dir == In })
	if first < 0 || first > svc {
		t.Fatalf("block rules must precede service accepts: %d %d", first, svc)
	}
	if got := CheckHostPolicy(mustManifest(t), b); hasID(got, RuleBlindDrop) {
		t.Fatalf("FW108 must accept a block with reason, owner and date: %v", got)
	}
}
func TestBlockNeedsReasonOwnerDate(t *testing.T) {
	if _, err := mustPolicy(t, "rocky-ecom").WithBlocks([]BlockSpec{{CIDR: netip.MustParsePrefix("198.51.100.7/32")}}, nil); err == nil {
		t.Fatal("block without reason, owner and date accepted")
	}
}
func TestBlockOwnAddressRefused(t *testing.T) { // FW111
	// a block of the controller's address (from the reference topology) -> CheckHostPolicy returns FW111 as SevError
}
func TestBlockWideCIDRWarns(t *testing.T) { // FW112
	// 198.51.100.0/23 -> SevWarn FW112; /24 -> none
}
func TestScoredUDPAcceptedFromAnySource(t *testing.T) { // Review Focus 1
	// manifest fixture with scored services tftp (udp/69) and ntp (udp/123) on one host: both have an In accept with no Peers
}
func TestUnscoredUDPDropped(t *testing.T) {
	// the same host without those services scored: no accept rule for udp/69 or udp/123 in the policy
}
func TestServersLogInputDenyOnShadowGroup(t *testing.T) {
	hp := mustPolicy(t, "rocky-ecom")
	if !hp.InputDenyLog || hp.ShadowLogGroup != 101 || hp.DenyLogGroup != 100 {
		t.Fatalf("%+v", hp)
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/manifest/render/ -run 'Block|UDP|InputDeny' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `nft.go` and `windows.go` render `GroupBlock` rules (drop, with a comment `block: <reason> owner=<owner> added=<date>`); the nft text of an inbound default-drop host ends the input chain with a rate-limited log rule (`limit rate 100/second burst 200`, group `DenyLogGroup`, prefix `PrefixInputDeny`) before the policy.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/manifest/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "render: block group, input-deny log, FW111-FW113, shadow log group"`

---

### Task 6: Translator: per-direction modes, shadow group, deny logs, nat log (Known bugs 12 and 14)

**Files:**
- Modify: `internal/firewall/{doc.go,translate_linux.go,manager_linux.go}`
- Test: `internal/firewall/translate_linux_test.go`, `internal/firewall/kernel_linux_test.go` (privileged cases)

**Interfaces:**
- Consumes: Task 5 (`ShadowLogGroup`, `InputDenyLog`, `GroupBlock`, prefixes).
- Produces:

```go
// ApplyOptions gains InMode, OutMode Mode; Mode is the shorthand that sets both when they are empty.
// Translate honours them per hook: a hook in ModeShadow installs accept policy plus a would-drop log rule;
// a hook in ModeEnforce installs the drop policy and its deny log.
func (o ApplyOptions) modes() (in, out Mode)
```

- [ ] **Step 1: Write the failing tests.**

```go
func TestShadowUsesOwnLogGroup(t *testing.T) { // Known bug 14
	rs := translate(t, serverPolicy(), ApplyOptions{Mode: ModeShadow})
	deny := logGroups(rs, "phylax-egress-deny: ")
	shadow := logGroups(rs, render.PrefixShadowOutput)
	if len(shadow) != 1 || shadow[0] != 101 || len(deny) != 0 {
		t.Fatalf("shadow %v deny %v: a would-drop must not use the deny group", shadow, deny)
	}
}
func TestEnforceInboundShadowOutbound(t *testing.T) { // T77 shape
	rs := translate(t, serverPolicy(), ApplyOptions{InMode: ModeEnforce, OutMode: ModeShadow})
	in := chain(rs, "phylax", "input")
	out := chain(rs, "phylax", "output")
	if in.Policy != nftables.ChainPolicyDrop || out.Policy != nftables.ChainPolicyAccept {
		t.Fatalf("policies %v %v", in.Policy, out.Policy)
	}
	if got := logPrefixes(in); !contains(got, render.PrefixInputDeny) {
		t.Fatalf("enforced inbound must log %q: %v", render.PrefixInputDeny, got)
	}
	if got := logPrefixes(out); !contains(got, render.PrefixShadowOutput) || contains(got, "phylax-egress-deny: ") {
		t.Fatalf("outbound shadow must log would-drops only: %v", got)
	}
}
func TestShadowNeverDropsInvalid(t *testing.T) { /* existing behaviour kept: no invalid-state drop in a shadow hook */ }
func TestSinkholeRedirectLogsFirst(t *testing.T) { // Known bug 12
	hp := serverPolicy()
	hp.SinkholePort = 7480
	nat := table(translate(t, hp, ApplyOptions{Mode: ModeEnforce}), render.TableNAT)
	c := nat.Chains[0]
	iLog := indexOfLog(c.Rules, "phylax-egress-deny: ")
	iRedir := indexOfRedir(c.Rules)
	if iLog < 0 || iLog > iRedir {
		t.Fatalf("the nat chain must log the denied flow before redirecting it: log %d redirect %d", iLog, iRedir)
	}
}
func TestNoSinkholeNoNatTable(t *testing.T) { /* SinkholePort 0: Ruleset has no phylax_nat table */ }
func TestBlockRulesBeforeServiceAccepts(t *testing.T) { /* Task 5 policy with a block: the drop is ahead of the service accept in the input chain, nothing else changes */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/firewall/ -run 'Shadow|Sinkhole|EnforceInbound|BlockRules' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** in `Translate`: the per-hook `shadow` flag from `modes()`; `shadowGroup(hp)` returns `hp.ShadowLogGroup` (default 101, never the deny group); the outbound deny log only when the out hook is enforced; the inbound deny log (`PrefixInputDeny`, `limit rate 100/second burst 200`, group `DenyLogGroup`) only when the in hook is enforced; the nat chain gets a rate-limited NFLOG rule (deny group, `PrefixEgressDeny`) immediately before the redirect, after the allow-return rules. `ApplyRuleset` reads the modes only through `Translate`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/firewall/`. Expected: PASS (privileged kernel tests skip with reason without root).
- [ ] **Step 5: Commit.** `git commit -am "firewall: per-direction modes, own shadow log group, nat log before redirect (bugs 12, 14)"`

---

### Task 7: `nft -c` on every rendered file; the privileged CI job

**Files:**
- Create: `internal/manifest/render/nftcheck_test.go`
- Modify: `.github/workflows/ci.yml`, `Makefile`
- Test: `internal/manifest/render/nftcheck_test.go`

**Interfaces:**
- Consumes: `render.NFT(hp *HostPolicy) string` (the existing nft text renderer; rename the call if the exported name differs).
- Produces: `TestRenderedNftChecks` runs `nft -c -f <file>` for every Linux host of `manifest/2027` and `manifest/two-segment`, in shadow and enforce renderings and with a block entry; `make privileged` = `sudo -E go test -count=1 -v -run 'NftChecks|Kernel|AFPacket' ./internal/manifest/render/ ./internal/firewall/ ./internal/capture/ | tee /tmp/priv.log && ! grep -q -- '--- SKIP' /tmp/priv.log` (a required job does not skip).

- [ ] **Step 1: Write the test.**

```go
func TestRenderedNftChecks(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil || os.Geteuid() != 0 {
		t.Skip("nft -c needs the nft binary and root; runs in the privileged CI job")
	}
	for _, dir := range []string{"../../../manifest/2027", "../../../manifest/two-segment"} {
		m := mustLoad(t, dir)
		for _, name := range manifest.SortedKeys(m.Hosts) {
			if m.Hosts[name].IsWindows() {
				continue
			}
			hp, err := BuildHostPolicy(m, name)
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range variants(hp) { // enforce, shadow, enforce with one block entry
				f := filepath.Join(t.TempDir(), name+".nft")
				os.WriteFile(f, []byte(NFT(v)), 0o600)
				if out, err := exec.Command(nft, "-c", "-f", f).CombinedOutput(); err != nil {
					t.Fatalf("%s/%s: %v\n%s", dir, name, err, out)
				}
			}
		}
	}
}
```

- [ ] **Step 2: Run, expect SKIP without root, PASS with.** Run: `go test ./internal/manifest/render/ -run NftChecks -v` (skips) then `sudo -E go test -count=1 -run NftChecks -v ./internal/manifest/render/` (PASS on a machine with nftables; if a rendering fails, fix the renderer in this task).
- [ ] **Step 3: Add the CI job** `privileged` (ubuntu-latest, `sudo apt-get install -y nftables`, `make privileged`), required next to `race`.
- [ ] **Step 4: Verify.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "ci: privileged job; nft -c on every rendered host policy"`

---

### Task 8: Verdict function and conntrack flush

**Files:**
- Create: `internal/firewall/verdict.go`, `internal/firewall/conntrack_linux.go`, `internal/firewall/conntrack_other.go`
- Test: `internal/firewall/verdict_test.go`, `internal/firewall/conntrack_linux_test.go`

**Interfaces:**
- Consumes: `render.HostPolicy`; `github.com/mdlayher/netlink` for the kernel edge.
- Produces:

```go
const MgmtMark uint32 = 0x7068
type Flow struct {
	Dir    render.Direction
	Proto  string
	Src    netip.AddrPort
	Dst    netip.AddrPort
	Marked bool // the conntrack mark is MgmtMark
}
func Verdict(hp *render.HostPolicy, f Flow) render.Action // management flows (Marked or GroupMgmt match) accept; then group rules in order; then the chain default for f.Dir
func Affected(old, new *render.HostPolicy, flows []Flow, scored []uint16) []Flow // old accepts, new drops, not Marked, neither port in scored
type Conntrack interface {
	List(ctx context.Context) ([]Flow, error)
	Delete(ctx context.Context, f Flow) error
}
func NewConntrack() (Conntrack, error) // netlink NFNL_SUBSYS_CTNETLINK; actions.Unsupported-style error off Linux (conntrack_other.go)
func FlushAffected(ctx context.Context, ct Conntrack, old, new *render.HostPolicy, scored []uint16) (int, error)
func FlushSources(ctx context.Context, ct Conntrack, blocked []netip.Prefix, scored []uint16) (int, error) // flows whose original source is blocked, minus flows on scored ports
func FlushAllButMgmt(ctx context.Context, ct Conntrack, scored []uint16) (int, error)                      // quarantine
```

- [ ] **Step 1: Write the failing tests** (an in-memory `Conntrack` is the kernel edge; the pure functions are the code under test).

```go
func TestVerdictScoredPortOpenToAnySource(t *testing.T) {
	hp := mustServerPolicy(t) // ecom-http scored tcp/80
	f := Flow{Dir: render.In, Proto: "tcp", Src: ap("203.0.113.9:40000"), Dst: ap("172.20.241.30:80")}
	if Verdict(hp, f) != render.Accept {
		t.Fatal("scored port must accept any source")
	}
	f.Dst = ap("172.20.241.30:8081")
	if Verdict(hp, f) != render.Drop {
		t.Fatal("unlisted inbound port must drop")
	}
}
func TestAffectedOnlyNewlyDropped(t *testing.T) {
	old, nw := mustServerPolicy(t), tightened(t) // nw removes an egress allowance to 10.0.0.9:3306
	flows := []Flow{
		out("172.20.241.30:50000", "10.0.0.9:3306"), // allowed by old, dropped by new
		out("172.20.241.30:50001", "172.20.240.10:88"), // allowed by both
	}
	got := Affected(old, nw, flows, nil)
	if len(got) != 1 || got[0].Dst.Port() != 3306 {
		t.Fatalf("%v", got)
	}
}
func TestFlushSparesMarkedAndScored(t *testing.T) { // Review Focus 2
	ct := &memConntrack{flows: []Flow{
		{Dir: render.In, Proto: "tcp", Src: ap("198.51.100.7:1111"), Dst: ap("172.20.241.30:80")},              // blocked source, scored port
		{Dir: render.In, Proto: "tcp", Src: ap("198.51.100.7:1112"), Dst: ap("172.20.241.30:9999")},            // blocked source, unscored
		{Dir: render.In, Proto: "tcp", Src: ap("198.51.100.7:1113"), Dst: ap("172.20.241.30:22"), Marked: true}, // management
	}}
	n, err := FlushSources(ctx, ct, []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")}, []uint16{80})
	if err != nil || n != 1 || len(ct.flows) != 2 {
		t.Fatalf("deleted %d, left %d: %v", n, len(ct.flows), err)
	}
}
func TestFlushAllButMgmtKeepsScored(t *testing.T) { /* quarantine: only unmarked flows off scored ports are deleted */ }
func TestConntrackNetnsFlush(t *testing.T) { t.Skip("needs root and a network namespace; runs in the privileged job") /* spawn flows, FlushSources, read back */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/firewall/ -run 'Verdict|Affected|Flush' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Verdict` mirrors the rule order the translator emits (mgmt first, then rules in `hp.Rules` order for the direction, peers matched by prefix and ports by `LocalPorts`/`RemotePorts`/ranges, then the default). The netlink code lists with `IPCTNL_MSG_CT_GET` dump and deletes with `IPCTNL_MSG_CT_DELETE` by tuple; `shortcut: IPv4 and IPv6 TCP/UDP only, upgrade if a lab run shows red holding another protocol`. Windows flush is `SetTcpEntry(MIB_TCP_STATE_DELETE_TCB)` in `internal/firewall/win_flush_windows.go` behind the same `Conntrack` interface; `shortcut: Windows flush covers IPv4 TCP only, UDP and IPv6 flows age out; upgrade if a lab run shows red holding such a session after a block`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/firewall/ && GOOS=windows go vet ./internal/firewall/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "firewall: verdict function and conntrack flush that spares management and scored flows"`

---

### Task 9: `fw.snapshot`, `fw.restore`, `fw.apply` (policy)

**Files:**
- Create: `internal/firewall/actions_apply.go`
- Modify: `internal/firewall/actions.go` (family list), `internal/firewall/module.go` (the applied-event queue)
- Test: `internal/firewall/actions_apply_test.go`

**Interfaces:**
- Consumes: Task 2 (`Backend`, `BackendFor`, `Declared`), Task 6 (modes), Task 8 (`FlushAffected`); `actions.Action`, `Spec`, `Params`, `LockFirewall`.
- Produces: registered actions

| Action | Params | Spec |
| --- | --- | --- |
| `fw.apply` | `op` enum `policy`\|`block`\|`unblock` default `policy`; `mode` enum `shadow`\|`enforce`; `in_mode`, `out_mode` same enum; `sources`, `destinations`, `ports` (Task 10) | `Risk: RiskLockout`, `Runs: RunsAgent`, `Locks: [LockFirewall]` |
| `fw.snapshot` | none | `Risk: RiskNone`, `ReadOnly: true`, writes `<evidence>/fw-snapshot-<ts>.json` atomically |
| `fw.restore` | `from` enum `declared`\|`snapshot` default `declared`; `snapshot` path | `Risk: RiskLockout` |

```go
// internal/firewall (package state, bounded)
func appliedQueue() chan AppliedEvent // cap 16, drop-oldest; drained by the agent module (Task 12)
// rollback kind registered with actions.RegisterUndo: "fw.restore.undo" (kernel snapshot and declared policy)
```

Behaviour of `fw.apply op: policy`: Plan computes the diff between current kernel state and the translated declared policy (`changed: false` when equal, the no-op case); Capture takes the snapshot (`Backend.Snapshot`) as the rollback; Apply translates (refusing a default-drop policy without management, `ErrNoManagement`), replaces in one batch, reads back (a mismatch returns `ErrVerify` after rolling back), calls `FlushAffected` with the previous declared policy when `conntrack_flush` and the new policy tightens, records the new declared policy and pushes an `AppliedEvent`; Verify compares the kernel hash with the declared hash. `mode` sets both directions; `in_mode`/`out_mode` override per hook. On Windows `mode: shadow` is accepted and installs nothing (`shortcut: Windows shadow is evaluated by net from sensor data, not installed; upgrade only if a lab run shows would-drops it missed`), `enforce` applies `WinPolicy` through `WinManager`.

- [ ] **Step 1: Write the failing tests** (a fake `Backend` at the kernel edge; Windows uses the existing `fakeFW` backend).

```go
func TestApplyNoopWhenEqual(t *testing.T) {
	env, be := testEnv(t, serverPolicy())
	out := run(t, env, "fw.apply", map[string]any{"mode": "enforce"})
	out2 := run(t, env, "fw.apply", map[string]any{"mode": "enforce"})
	if !out.Changed || out2.Changed {
		t.Fatalf("changed %v then %v; the second apply of an equal policy is a no-op", out.Changed, out2.Changed)
	}
	if be.applies != 1 {
		t.Fatalf("backend applied %d times", be.applies)
	}
}
func TestApplyRefusesDefaultDropWithoutManagement(t *testing.T) {
	hp := serverPolicy()
	hp.Rules = dropMgmt(hp.Rules)
	env, _ := testEnv(t, hp)
	if _, err := runErr(t, env, "fw.apply", map[string]any{"mode": "enforce"}); !errors.Is(err, ErrNoManagement) {
		t.Fatalf("got %v", err)
	}
}
func TestApplyVerifyFailureRollsBack(t *testing.T) {
	env, be := testEnv(t, serverPolicy())
	be.corruptReadBack = true
	if _, err := runErr(t, env, "fw.apply", map[string]any{"mode": "enforce"}); !errors.Is(err, ErrVerify) {
		t.Fatalf("got %v", err)
	}
	if be.state != be.initial {
		t.Fatal("the failed apply must leave the previous state")
	}
}
func TestApplyInboundOnly(t *testing.T) { // T77 shape
	env, be := testEnv(t, serverPolicy())
	run(t, env, "fw.apply", map[string]any{"in_mode": "enforce", "out_mode": "shadow"})
	if be.lastOpts.InMode != ModeEnforce || be.lastOpts.OutMode != ModeShadow {
		t.Fatalf("%+v", be.lastOpts)
	}
}
func TestApplyTightenFlushesOnlyAffected(t *testing.T) { /* testEnv with a memConntrack: a tightening policy deletes the newly dropped flow only; scored-port and marked flows stay */ }
func TestApplyEmitsAppliedEvent(t *testing.T) {
	env, _ := testEnv(t, serverPolicy())
	run(t, env, "fw.apply", map[string]any{"mode": "enforce"})
	ev := <-appliedQueue()
	if ev.Mode != "enforce" || !ev.Changed || ev.Hash == "" {
		t.Fatalf("%+v", ev)
	}
}
func TestSnapshotThenRestore(t *testing.T) { /* fw.snapshot writes the file; fw.restore from: snapshot returns the backend to it; from: declared reapplies Declared() */ }
func TestWindowsApplyAndShadow(t *testing.T) { /* fakeFW: enforce applies WinPolicy rules in the Phylax groups only; shadow changes nothing and reports "evaluated" */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/firewall/ -run 'Apply|Snapshot|WindowsApply' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the three actions and the shared helper `applyPolicy(ctx, env, be, hp, opts) (changed bool, err error)` used again by Tasks 10 and 13.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/firewall/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "firewall: fw.apply policy, fw.snapshot, fw.restore as module actions"`

---

### Task 10: `fw.apply` source and destination blocks; `fw.quarantine`

**Files:**
- Modify: `internal/firewall/actions_apply.go`
- Create: `internal/firewall/quarantine.go`
- Test: `internal/firewall/block_test.go`, `internal/firewall/quarantine_test.go`

**Interfaces:**
- Consumes: Task 5 (`WithBlocks`, `BlockSpec`), Task 8 (`FlushSources`, `FlushAllButMgmt`), Task 9 helpers.
- Produces:

```go
// fw.apply params for op block|unblock: sources (comma list of addresses/CIDRs, inbound), destinations (outbound), ports ("non_scored" or empty), reason, owner (required for block)
// fw.quarantine params: reason; the revert window is FirewallSettings.QuarantineSec (default 600); Risk RiskLockout; refuses the controller host
func Quarantine(hp *render.HostPolicy, scored []uint16) *render.HostPolicy // management, ICMP, DHCP, scored inbound open to any source, declared dependency egress of scored services, drop everything else
```

Lint inside Plan: exactly one of `sources`, `destinations`; every address parses; a CIDR wider than /24 adds a warning to the plan output; an address in the manifest's own set (via `Env.Guard`/`Declared()` management peers) is refused; `ports: non_scored` expands to the host's unscored ports so no scored port is dropped; `unblock` removes entries by CIDR. A block on a destination that is a declared dependency of a scored service on this host is refused.

- [ ] **Step 1: Write the failing tests.**

```go
func TestBlockAddsGroupAndFlushesSource(t *testing.T) {
	env, be, ct := testEnvWithConntrack(t, serverPolicy(), flowsFrom("198.51.100.7"))
	run(t, env, "fw.apply", map[string]any{"op": "block", "sources": "198.51.100.7", "reason": "scanner", "owner": "net-lead", "ports": "non_scored"})
	if !hasBlock(be.declared, "198.51.100.7/32") {
		t.Fatal("block missing from the declared policy")
	}
	if ct.deleted != 1 { // the flow on the unscored port; the scored-port flow survives
		t.Fatalf("deleted %d", ct.deleted)
	}
}
func TestBlockRefusesOwnAddress(t *testing.T) {
	env, _, _ := testEnvWithConntrack(t, serverPolicy(), nil)
	if _, err := runErr(t, env, "fw.apply", map[string]any{"op": "block", "sources": "172.20.240.10", "reason": "x", "owner": "o"}); err == nil {
		t.Fatal("blocking the controller address accepted")
	}
}
func TestBlockDestinationNeverCutsDependency(t *testing.T) {
	// destinations: the DC address of a declared depends_on edge of a scored service -> error naming the dependency
}
func TestUnblockRemovesEntry(t *testing.T) { /* block then unblock: declared policy equals the original */ }
func TestBlockWideCIDRWarns(t *testing.T) { /* /23 -> Output.Warnings contains FW112 text; the apply still succeeds */ }
func TestQuarantineKeepsScoredAndMgmt(t *testing.T) {
	q := Quarantine(serverPolicy(), []uint16{80, 22})
	if Verdict(q, flowIn("203.0.113.9:1", "172.20.241.30:80")) != render.Accept {
		t.Fatal("scored inbound must stay open in quarantine")
	}
	if Verdict(q, flowOut("172.20.241.30:5", "198.51.100.7:443")) != render.Drop || Verdict(q, flowIn("203.0.113.9:1", "172.20.241.30:3306")) != render.Drop {
		t.Fatal("everything else must drop")
	}
}
func TestQuarantineRevertsAfterWindow(t *testing.T) { /* action rollback data restores the previous declared policy and kernel snapshot; QuarantineEvent.Expires = now + 10m */ }
func TestQuarantineRefusedOnController(t *testing.T) { /* Env.Host is the controller host in the guard -> error "refused: quarantining the controller host would cut every agent" */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/firewall/ -run 'Block|Quarantine|Unblock' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Blocks go into `FirewallSettings.Block`'s declared form (`render.BlockSpec`) held in the package state with the declared policy, so drift compares against the new intent and rollback restores both. A `QuarantineEvent` is pushed on a second package queue drained by the module.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/firewall/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "firewall: source and destination blocks, fw.quarantine with auto-revert"`

---

### Task 11: `FirewallSettings` in the signed config; Windows stage 0

**Files:**
- Create: `internal/controller/genconfig_network.go`
- Modify: `internal/controller/genconfig.go` (one call each for firewall and capture blocks), `internal/manifest/render/windows.go` (`Stage0`)
- Test: `internal/controller/genconfig_network_test.go`, `internal/manifest/render/stage0_test.go`

**Interfaces:**
- Consumes: Task 1 `plan.FirewallSettings`, Task 4 `Manifest.Modules["firewall"]`, Task 5 `BlockSpec`; `render.BuildHostPolicy`, `render.BuildWinPolicy` (the existing Windows builder).
- Produces:

```go
// internal/controller (core imports only core packages here)
func firewallSettings(in ConfigInputs, host string, h manifest.Host, hp *render.HostPolicy) *plan.FirewallSettings
// internal/manifest/render
type Stage0 struct{ ManagementPorts []uint16; TeamSubnets []netip.Prefix }
func (wp *WinPolicy) WithStage0(m *manifest.Manifest, host string, s Stage0) (*WinPolicy, []manifest.Finding) // allow-inbound plus blocks of ManagementPorts minus every scored port, from outside TeamSubnets; FW113 error if a scored port would be blocked
```

Rendering: `Policy` for non-Windows hosts, `WinPolicy` for Windows, `Deadman` default 90s, `ConntrackFlush` from the block (default true), `QuarantineSec` 600, `DriftCheckSec` 60, `ShadowLogGroup` 101, `InboundMode`/`OutboundMode` from `inbound.mode`/`outbound.mode`, `AllowBack{Enabled, MaxPerHour 5}`, `Block` from the block's `block:` list. `Enabled` follows `Manifest.ModuleEnabled(host, "firewall", true)`.

- [ ] **Step 1: Write the failing tests.**

```go
func TestFirewallSettingsRenderedForEveryHost(t *testing.T) {
	cfg, _, err := BuildAgentConfig(refInputs(t), "rocky-ecom")
	if err != nil {
		t.Fatal(err)
	}
	f := cfg.Modules.Firewall
	if f == nil || !f.Enabled || f.Policy == nil || f.Deadman != 90*time.Second || f.ShadowLogGroup != 101 || f.QuarantineSec != 600 || f.DriftCheckSec != 60 {
		t.Fatalf("%+v", f)
	}
	if f.InboundMode != "enforce" || f.OutboundMode != "shadow" || !f.AllowBack.Enabled || f.AllowBack.MaxPerHour != 5 {
		t.Fatalf("%+v", f)
	}
	win, _, _ := BuildAgentConfig(refInputs(t), "ad")
	if win.Modules.Firewall.WinPolicy == nil || win.Modules.Firewall.Policy != nil {
		t.Fatal("Windows hosts carry WinPolicy only")
	}
}
func TestHostModulesOverrideDisablesFirewall(t *testing.T) { /* hosts.yml modules: {firewall: false} on one host -> Enabled false there, true elsewhere */ }
func TestStage0NeverBlocksScoredPort(t *testing.T) {
	wp, fs := mustWinPolicy(t, "mssql").WithStage0(refManifest(t), "mssql", Stage0{ManagementPorts: []uint16{22, 3389, 5985, 5986, 445}})
	if hasID(fs, RuleStage0Scored) {
		t.Fatalf("%v", fs)
	}
	for _, p := range blockedInboundPorts(wp) {
		if p == 3389 { // RDP is scored on the MSSQL host in the 2027 reference
			t.Fatal("scored RDP must stay open")
		}
	}
}
func TestStage0ScoredBlockIsError(t *testing.T) { /* a hand-built Stage0 policy that blocks a scored port -> FW113 SevError */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ ./internal/manifest/render/ -run 'FirewallSettings|HostModules|Stage0' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The agent factory fingerprint (Task 12) includes `Policy`'s `Hash`, so a manifest change replaces the module but never applies the policy (Apply stays a plan node).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/ ./internal/manifest/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: firewall settings in the signed config; windows stage 0"`

---

### Task 12: Firewall agent module: registration, drift, events, health, conformance

**Files:**
- Create: `internal/agent/mods/firewall.go`, `internal/firewall/module.go` (replace the stub), `internal/firewall/health.go`, `internal/firewall/conformance_test.go`
- Modify: `internal/module/conformance/allowed.go` (remove `firewall` from `PreContract` only when Task 14 also lands: the entry covers both sides; remove it in Task 14)
- Test: `internal/firewall/module_test.go`, `internal/firewall/conformance_test.go`

**Interfaces:**
- Consumes: Task 1 manifest and settings, Task 9/10 queues, W1 `agent.Factory`, `agent.HealthReporter`, `module.Health`, `event.New`.
- Produces:

```go
// internal/firewall
func Factory() agent.Factory // Name "firewall", Manifest, Section (enabled when Modules.Firewall != nil && Enabled; fingerprint over Policy hash and every setting), Build
type AgentModule struct{ /* unexported */ }
func (*AgentModule) Name() string
func (*AgentModule) Start(ctx context.Context, emit agent.Emit) error // drift loop every DriftCheckSec (0 disables), drains the applied/quarantine/restored queues, emits through event.New
func (*AgentModule) Health() module.Health
// internal/agent/mods/firewall.go: func init() { agent.RegisterFactory(firewall.Factory()) }
```

Health: `ok` when the declared policy equals the kernel and management invariants hold; `degraded` for inbound in shadow, drift in a non-management group, a foreign table that may block, Windows COM unavailable; outbound in shadow is `ok` with Detail `outbound in shadow`; `unavailable` with Gap `{"nftables", "kernel or privilege lacks it"}` without netlink access; `error` when `managementIntact` fails. Gaps: foreign firewall present (firewalld, ufw, docker), Windows Firewall service stopped.

- [ ] **Step 1: Write the failing tests.**

```go
func TestDriftEmitsPerGroup(t *testing.T) {
	h, be := harness(t, serverPolicy(), settings(withDrift(50*time.Millisecond)))
	be.mutate(removeRuleInGroup(render.GroupService)) // kernel edge: someone deleted a service rule
	evs := h.WaitFor("firewall.drift", 2*time.Second)
	d, _ := event.Decode[DriftEvent](evs[0], "firewall.drift")
	if d.Group != "service" || len(d.Diff) == 0 {
		t.Fatalf("%+v", d)
	}
}
func TestManagementDriftReportedSeparately(t *testing.T) { /* a removed mgmt rule emits a DriftEvent with Group "mgmt" and Health becomes error */ }
func TestForeignTableReportedOnce(t *testing.T) { /* a foreign table that may block -> one DriftEvent{ForeignMayBlock:true} across three ticks, Health degraded with a gap naming it */ }
func TestAppliedAndRestoredEvents(t *testing.T) { /* run fw.apply then a deadman-style restore through the harness: firewall.applied then firewall.restored{Reason:"deadman"} */ }
func TestInboundShadowIsDegraded(t *testing.T) { /* InboundMode shadow -> Health.State degraded; OutboundMode shadow alone -> ok */ }
func TestFirewallConformance(t *testing.T) {
	conformance.Agent(t, conformance.AgentCase{Factory: Factory(), Default: cfgWithFirewall(false), Reconfig: cfgWithFirewall(true), KeepKey: "firewall.declared", Load: nil})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/firewall/ -run 'Drift|Foreign|Applied|Inbound|Conformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Build` returns `agent.ErrUnavailable` (wrapped) without netlink access, building `LinuxManager` with `firewall.Handlers` so the dead-man handlers `fw.nft.restore` and `fw.win.restore` are registered on the agent (they were unused before); `Keep("firewall.declared", policy)` carries the declared policy across reconfiguration; `SetDeclared` is called from `Build` with the signed `Policy`. Windows: `WinManager` over `NewComBackend`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/firewall/ ./internal/agent/mods/ && GOOS=windows go vet ./...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "firewall: agent module with drift check, events and health"`

---

### Task 13: Allow-back

**Files:**
- Create: `internal/firewall/allowback.go`
- Modify: `internal/firewall/module.go` (subscribe)
- Test: `internal/firewall/allowback_test.go`

**Interfaces:**
- Consumes: `net.ingress_denied` (W3 seams; payload keys `raddr`, `lport`, `proto`, `scored_port`, `scorer_like`), Task 9 `applyPolicy`, `Env.Subscribe(buf, kinds...)`.
- Produces:

```go
type allowBack struct{ /* per-host hourly counter, bounded */ }
func (a *allowBack) onDenied(ctx context.Context, ev event.Event) error // scored_port or scorer_like true: add an any-source accept for lport/proto keyed by comment tag "phylax:allow:<port>/<proto>"; flush nothing; push AllowBackEvent; run Env.Probe when present
// Rule: requires FirewallSettings.ActEnabled and AllowBack.Enabled; at most MaxPerHour (default 5) per host per rolling hour; beyond that or without act_enabled it emits the alert event with RuleAdded "" and changes nothing; an allow-back is never undone automatically.
```

`AllowBackEvent.Probe`: `ok`, `failed` (still keeps the rule, alerts), `unavailable` (no probe). `Proposal` is the manifest fix text ("add scored listener tcp/<port> to services.yml") — the controller side (Task 14) turns the event into a `Propose`.

- [ ] **Step 1: Write the failing tests.**

```go
func TestAllowBackOnScoredPort(t *testing.T) { // T77 core
	h, be := harness(t, inboundEnforced(), settings(withAct(true)))
	h.Publish(ingressDenied("203.0.113.9", 8443, "tcp", true, false))
	ev := h.WaitFor("firewall.allow_back", 2*time.Second)[0]
	a, _ := event.Decode[AllowBackEvent](ev, "firewall.allow_back")
	if a.Port != 8443 || a.Reason != "scored_port" || a.RuleAdded == "" || a.Probe != "unavailable" {
		t.Fatalf("%+v", a)
	}
	if Verdict(be.declared, flowIn("198.51.100.1:5", "172.20.241.30:8443")) != render.Accept {
		t.Fatal("port must be open to any source after the allow-back")
	}
}
func TestAllowBackOnScorerLikeSender(t *testing.T) { /* scorer_like true on an unlisted port -> Reason "scorer_like" and the same rule */ }
func TestAllowBackIgnoresPlainDeny(t *testing.T) { /* scored_port false, scorer_like false: nothing changes, no event */ }
func TestAllowBackRateLimited(t *testing.T) { // Review Focus 3
	h, _ := harness(t, inboundEnforced(), settings(withAct(true), withMaxPerHour(5)))
	for i := 0; i < 8; i++ {
		h.Publish(ingressDenied("203.0.113.9", uint16(9000+i), "tcp", true, false))
	}
	evs := h.WaitFor("firewall.allow_back", 2*time.Second)
	added := 0
	for _, e := range evs {
		if a, _ := event.Decode[AllowBackEvent](e, "firewall.allow_back"); a.RuleAdded != "" {
			added++
		}
	}
	if added != 5 || len(evs) != 8 {
		t.Fatalf("rules added %d of %d events; beyond the limit it alerts without changing the policy", added, len(evs))
	}
}
func TestAllowBackNeedsActEnabled(t *testing.T) { /* act_enabled false: event with RuleAdded "" , policy unchanged */ }
func TestAllowBackWorksWithLinkDown(t *testing.T) { /* harness EmitErr returns an error: the rule is still added (local behaviour) */ }
func TestAllowBackProbeRuns(t *testing.T) { /* Env.Probe set: a green probe -> Probe "ok"; a red one -> "failed" and the rule stays */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/firewall/ -run AllowBack -v`. Expected: FAIL.
- [ ] **Step 3: Implement** with the lock `LockFirewall` shared with plan nodes (an allow-back waits for a running node's lock for at most 5 s, then is dropped with a `telemetry_gap`). `shortcut: rate limit and counters are in memory per agent run, upgrade if a lab run shows restarts resetting the limit`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/firewall/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "firewall: automatic allow-back for dropped scored-port and scorer-like inbound"`

---

### Task 14: Firewall controller side: would-drop summarizer and proposals

**Files:**
- Create: `internal/firewall/shadow.go`, `internal/firewall/controller.go` (replace the stub), `internal/firewall/shadow_conformance_test.go`
- Modify: `internal/module/conformance/allowed.go` (remove `firewall` from `PreContract`)
- Test: `internal/firewall/shadow_test.go`

**Interfaces:**
- Consumes: `net.shadow_drop` (keys `dir`, `proto`, `src`, `dst`, `sport`, `dport`, `prefix`, process fields `exe`, `comm`), `module.Host` (`Query`, `Manifest`, `Propose`, `Tables`, `Emit`), `storetest.New`.
- Produces:

```go
func Summarize(ctx context.Context, q store.Reader, m *manifest.Manifest, now time.Time, since time.Duration) (ShadowSummaryEvent, error) // pure
func Coverage(m *manifest.Manifest, host, dir, proto string, dport uint16) string                                     // "declared" | "undeclared" | "scored"
func (c *Controller) Analyzers() []module.Analyzer // "firewall.shadow": Inputs ["net.shadow_drop"], Every 60s
// table firewall_shadow_summary(host TEXT, dir TEXT, proto TEXT, src TEXT, dst TEXT, dport INTEGER, count INTEGER, first TEXT, last TEXT, coverage TEXT); written by the module's one writer goroutine from its own firewall.shadow_summary events
```

Rules: groups by (dir, proto, src, dst, dport) with count, first, last and the owning process for outbound; `scored` coverage emits the summary at once with that group first (a scored port would be dropped: a rendering bug); the summary never proposes a source restriction on a scored port; an outbound group with a process and an undeclared destination proposes a `depends_on` edge or `egress.allow` entry (a `Proposal` whose template is `plans/firewall/adopt.yaml`, a manifest-edit plan, params `host`, `kind`, `to`, `ports`); an inbound group on an undeclared port proposes nothing unless the port has a listener ("adopt as service"). Same store and `now` give the same output (analyser determinism).

- [ ] **Step 1: Write the failing tests** (golden table from a fixture store).

```go
func TestSummarizeGoldenTable(t *testing.T) {
	st := storetest.New(t, shadowFixture()...) // 3 outbound drops rocky-ecom -> 10.0.0.9:3306 by /usr/sbin/mysqld, 2 inbound drops to :8081, 1 inbound drop to scored :80
	got, err := Summarize(ctx, st, refManifest(t), fixtureNow, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 6 || got.Groups[0].Coverage != "scored" || got.Groups[0].DPort != 80 {
		t.Fatalf("a group on a scored port must sort first with coverage scored: %+v", got.Groups)
	}
	golden(t, "testdata/shadow_summary.golden.json", got)
}
func TestSummarizeDeterministic(t *testing.T) { /* two runs, same bytes */ }
func TestCoverageVerdicts(t *testing.T) { /* ecom-http tcp/80 inbound -> scored; a declared depends_on tcp/3306 outbound -> declared; tcp/9999 -> undeclared */ }
func TestOutboundUndeclaredProposesEdge(t *testing.T) { /* module run with a fake Host recording Propose: one proposal with Params{"kind":"egress.allow","to":"10.0.0.9","ports":"3306"} and Evidence refs of the drop events */ }
func TestNoSourceRestrictionOnScoredPort(t *testing.T) { /* no proposal whose params restrict a scored port */ }
func TestInboundUndeclaredNoProposalWithoutListener(t *testing.T) {}
func TestShadowSummaryTableIsProjection(t *testing.T) { /* delete the table rows, replay the module's events through the writer -> same rows */ }
func TestLearnedListenerWrittenToOverrides(t *testing.T) { /* config learned_listeners true; a consumed firewall.allow_back (reason scored_port, host h1, port 8081/tcp) calls Host.UpdateOverrides once: Manifest().Overrides.LearnedListeners holds {h1, tcp, 8081}; the same event replayed adds no second entry; learned_listeners false writes nothing */ }
func TestAllowBackEventProposesManifestFix(t *testing.T) { /* a firewall.allow_back event consumed by the controller side yields one Proposal with the Proposal text as Reason */ }
func TestFirewallControllerConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Controller{}, Config: "enabled: true\n", Seed: shadowFixture(), Now: fixtureNow})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/firewall/ -run 'Summarize|Coverage|Proposes|NoSource|Projection|LearnedListener|ControllerConformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Consumes` also lists the module's own `firewall.allow_back` and `firewall.shadow_summary` (declared table kinds; the writer reads them). When `Config.LearnedListeners` is true, an `allow_back` event with a rule added appends a `manifest.LearnedListener{Host, Proto, Port, Reason, Observed}` through `Host.UpdateOverrides` (skipped when an entry with the same host, proto and port exists; W1 Tasks 11a and 17a).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/firewall/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "firewall: controller side with would-drop summarizer and proposals"`

---

### Task 15: Inbound auto-enforce trigger and plan templates

**Files:**
- Create: `plans/firewall/enforce-host.yaml`, `plans/firewall/enforce-inbound.yaml`, `plans/firewall/adopt.yaml`, `internal/firewall/autoenforce.go`, `internal/firewall/plans_test.go`
- Test: `internal/firewall/autoenforce_test.go`

**Interfaces:**
- Consumes: `module.Host.RunAuto(template, params)`, `Propose`, `module.ErrProposed`, Task 14 `Summarize`.
- Produces:

```go
// plans/firewall/enforce-host.yaml (click plan, module: firewall): baseline snapshot, fw.apply mode shadow, gate: approval (outbound review), fw.apply out_mode enforce deadman 90s, health.check
// plans/firewall/enforce-inbound.yaml (auto class, module: firewall): fw.apply in_mode enforce out_mode shadow deadman 90s; health.check probe scorer_mimic; on_failure rollback_plan
func (c *Controller) enforceInbound(ctx context.Context, host string) error // precondition then RunAuto("enforce-inbound", {"host": host}); else Propose with Reason = the failed condition
```

Preconditions (all must hold; the first failing one is the `Reason`): `act_enabled`; the host has an `ok` or `degraded` firewall health with inbound `shadow` installed (a `firewall.applied` event with `mode: shadow` after the last enforce); `Summarize` over the host has no group with `coverage: scored`; `FirewallSettings.InboundMode == "enforce"`. Called when `firewall.applied` with `mode: shadow` arrives for a host (the install-in-shadow step of `enforce-host`) and when the operator accepts the proposal.

- [ ] **Step 1: Write the failing tests.**

```go
func TestInboundAutoWhenClean(t *testing.T) { // T77: no review click inbound
	h := newHost(t, withAct(true), withSummary(cleanSummary()))
	if err := (&Controller{}).enforceInboundWith(h, "rocky-ecom"); err != nil {
		t.Fatal(err)
	}
	if h.autoRuns != 1 || h.lastTemplate != "enforce-inbound" || h.proposals != 0 {
		t.Fatalf("%+v", h)
	}
}
func TestInboundProposesWhenScoredCoverage(t *testing.T) {
	h := newHost(t, withAct(true), withSummary(scoredSummary()))
	_ = (&Controller{}).enforceInboundWith(h, "rocky-ecom")
	if h.autoRuns != 0 || h.proposals != 1 || !strings.Contains(h.lastReason, "scored") {
		t.Fatalf("%+v", h)
	}
}
func TestInboundProposesWithoutActEnabled(t *testing.T) { /* act_enabled false: proposal, no RunAuto */ }
func TestInboundProposesOnErrProposed(t *testing.T) { /* RunAuto returns module.ErrProposed (probe cannot run): no second proposal is created by the module */ }
func TestOutboundEnforceNeverAuto(t *testing.T) {
	// no code path calls RunAuto with a template that sets out_mode enforce: parse every plans/firewall/*.yaml,
	// templates on the module's auto allowlist ("enforce-inbound") have no node with params out_mode: enforce
}
func TestPlanTemplatesLoadAndLint(t *testing.T) { /* each template parses (unknown fields are errors), names module: firewall, nodes use registered actions with valid params; enforce-host has exactly one gate: approval node between the shadow and the out_mode enforce node */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/firewall/ -run 'Inbound|Outbound|PlanTemplates' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the trigger on the module's `Subscribe` of its own `firewall.applied` events (`Consumes` includes it) and the templates. The module block's `auto:` default is `[enforce-inbound]`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/firewall/ ./plans/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "firewall: inbound auto-enforce behind the shadow-summary check; enforce plans"`

---

### Task 16: `egress` module: config, manifest, sinkhole validation (Known bug 12)

**Files:**
- Modify: `internal/egress/{config,module,manifest}.go` (replace the Task 1 stubs), `internal/module/conformance/allowed.go` (remove `egress` from `PreContract` in Task 18, when the analyser lands)
- Test: `internal/egress/config_test.go`, `internal/egress/module_test.go`

**Interfaces:**
- Consumes: Task 4 (`Manifest.Egress()`), W1 `Host.Config`, `module.ErrNoConfig`.
- Produces:

```go
type Config struct { // the design's part 4, module.Common inline
	module.Common `yaml:",inline"`
	DenyLogGroup  uint16               `yaml:"deny_log_group"`
	CanaryPorts   []uint16             `yaml:"canary_ports"`
	Allow         []manifest.EgressAllow `yaml:"allow"`
	ExeAlerts     struct{ Mode string `yaml:"mode"`; Classes []string `yaml:"classes"`; SweepAtStart bool `yaml:"sweep_at_start"` } `yaml:"exe_alerts"`
	Rank          struct{ Window time.Duration `yaml:"window"`; Periodic struct{ MinIntervals int `yaml:"min_intervals"`; MaxCV float64 `yaml:"max_cv"` } `yaml:"periodic"` } `yaml:"rank"`
	Sinkhole      *manifest.Sinkhole   `yaml:"sinkhole"`
}
const catcherBuilt = false // flips only with the C2 lab decision (T60) and a catcher module
func (c Config) Validate() error // mode must be "alert"; classes subset of declared|lan|public; rank.window > 0; periodic.max_cv in (0,1]; sinkhole.enabled with !catcherBuilt is an error naming T60; each Allow entry has a reason and a /16 or narrower peer (EG001)
func (*Module) Start(ctx context.Context, h module.Host) error // Config + Validate; invalid config: health error, no restart loop
```

- [ ] **Step 1: Write the failing tests.**

```go
func TestReferenceBlockValidates(t *testing.T) {
	var c Config
	mustDecodeFile(t, "../../manifest/2027/modules/egress.yml", &c)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Rank.Window != 30*time.Minute || c.Rank.Periodic.MinIntervals != 10 || c.Rank.Periodic.MaxCV != 0.2 || c.DenyLogGroup != 100 {
		t.Fatalf("%+v", c)
	}
}
func TestSinkholeEnabledRefused(t *testing.T) { // Known bug 12: no catcher exists
	c := validConfig()
	c.Sinkhole = &manifest.Sinkhole{Enabled: true, Port: 7480}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "T60") {
		t.Fatalf("got %v", err)
	}
}
func TestBlockingModeRefused(t *testing.T) { c := validConfig(); c.ExeAlerts.Mode = "block"; if c.Validate() == nil { t.Fatal("egress is alert-only (A-AUTO)") } }
func TestWideAllowRefused(t *testing.T) { /* allow to 10.0.0.0/8 -> EG001-style error */ }
func TestStartWithoutConfigIsUnavailable(t *testing.T) { /* fake Host whose Config returns module.ErrNoConfig -> Start returns it; Health unavailable with a gap */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/egress/ -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `Config`, `Validate`, `Start` (waits on `ctx` for now; Task 18 adds the analyser). Reference block `manifest/2027/modules/egress.yml` already written in Task 4.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/egress/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "egress: module config with sinkhole refused until a catcher exists"`

---

### Task 17: Egress allow table rendered into the host's detect profile

**Files:**
- Create: `internal/manifest/render/egress.go`
- Modify: `internal/controller/genconfig.go` (append the seed to `detectSeeds`)
- Test: `internal/manifest/render/egress_test.go`, `internal/controller/genconfig_network_test.go`

**Interfaces:**
- Consumes: `manifest.Services[].Process.Binaries` (pinned binaries), `depends_on`, `plan.ProfileSeed`.
- Produces:

```go
type EgressEntry struct{ Exe, Class, Source string } // Source: the manifest path that granted it ("services.yml:ecom-http depends_on mysql")
func EgressTable(m *manifest.Manifest, host string) (entries []EgressEntry, warnings []manifest.Finding)
// Seed profile name "egress.allow": key exe, value class (declared | lan | public). Rules: every pinned binary of a service on the host may reach "declared" (its depends_on peers);
// the agent binary may reach "declared" (the controller); per-OS pre-approved tools (apt, dnf, yum, dpkg at /usr/bin/..., Sysmon installer) get "public".
// A service without process.binaries yields a warning FindingID "EG003" (SevWarn) and no entries.
```

The agent-side rule `D4c` reads this profile; the rule and the retirement of the learned `egress.exes` profile are W4's (deviation 12).

- [ ] **Step 1: Write the failing tests.**

```go
func TestEgressTablePinnedBinariesAndAgent(t *testing.T) {
	es, ws := EgressTable(refManifest(t), "rocky-ecom")
	if len(ws) != 0 {
		t.Fatal(ws)
	}
	want := map[string]string{"/usr/sbin/httpd": "declared", "/usr/sbin/mysqld": "declared", "/usr/bin/dnf": "public"}
	for _, e := range es {
		delete(want, e.Exe) // only for entries with the expected class
		_ = e
	}
	if !coversAll(es, want) {
		t.Fatalf("missing %v in %v", want, es)
	}
	if !hasExeClass(es, agentPathPlaceholder, "declared") {
		t.Fatal("the agent binary may reach the controller")
	}
}
func TestServiceWithoutBinariesWarns(t *testing.T) { /* strip process.binaries from one service -> EG003 warning naming it, no entries for it */ }
func TestEgressSeedInAgentConfig(t *testing.T) {
	cfg, _, _ := BuildAgentConfig(refInputsWithRules(t), "rocky-ecom")
	var found bool
	for _, s := range cfg.Modules.Detect.Seeds {
		if s.Profile == "egress.allow" && len(s.Values) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("the signed detect settings must carry the egress.allow profile")
	}
}
func TestEgressTableDeterministic(t *testing.T) { /* two renders, identical order (sorted by exe, then class) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/manifest/render/ ./internal/controller/ -run 'EgressTable|EgressSeed|WithoutBinaries' -v`. Expected: FAIL.
- [ ] **Step 3: Implement**; the seed is added only when the egress module is enabled on the host (`ModuleEnabled(host, "egress", true)`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/manifest/... ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "render: seeded per-executable egress table in the signed detect settings"`

---

### Task 18: Egress ranking analyser and candidate table

**Files:**
- Create: `internal/egress/rank.go`, `internal/egress/table.go`, `internal/egress/conformance_test.go`
- Modify: `internal/egress/module.go`, `internal/module/conformance/allowed.go` (remove `egress` from `PreContract`)
- Test: `internal/egress/rank_test.go`

**Interfaces:**
- Consumes: `net.egress_denied` (keys `exe`, `exe_sha256`, `raddr`, `rport`, `attributed`, `attempts`, `canary`, `pid`, `lineage`), `devices.deny` (keys `src`, `dst`, `dport`, `count`, `first`, `last`), `integrity.pin`, `store.Reader`.
- Produces:

```go
func Rank(ctx context.Context, q store.Reader, cfg Config, now time.Time) ([]CandidateEvent, error) // pure; emits only groups new or changed since their last egress.candidate (reads its own events)
// grouping: (exe_sha256 else exe path, raddr, rport) over cfg.Rank.Window; canary-tagged denials excluded
// ordering key, lexicographic: new_binary desc, attributed desc, host count desc, first-seen-after-baseline desc, attempts desc; ties by (raddr, rport, exe)
// periodic: CV of intervals < Rank.Periodic.MaxCV over >= MinIntervals intervals (secondary flag, never in the key)
func (m *Module) Analyzers() []module.Analyzer // "egress.rank": Inputs ["net.egress_denied","devices.deny"], Every 60s
// table egress_candidate(host, exe, exe_sha256, raddr, rport, rank, attempts, first_seen, last_seen, new_binary, periodic); one writer goroutine from the module's own egress.candidate events
```

- [ ] **Step 1: Write the failing tests** (fixture store via `storetest.New`).

```go
func TestRankOrder(t *testing.T) { // the design's key, asserted
	st := storetest.New(t, deniedFixture()...) // A: unknown binary, attributed, 2 hosts; B: pinned service binary, attributed; C: unattributed, 9 attempts
	got, err := Rank(ctx, st, defaultCfg(), fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Exe != "/tmp/.x/agentd" || !got[0].NewBinary || got[len(got)-1].Exe != "" {
		t.Fatalf("new unattributed-last order violated: %+v", got)
	}
}
func TestPeriodicBeaconFlaggedWithJitter10(t *testing.T) {
	st := storetest.New(t, beaconFixture(10*time.Second, 0.10, 12)...) // 12 intervals of ~10 s, jitter 10%
	got, _ := Rank(ctx, st, defaultCfg(), fixtureNow)
	if !got[0].Periodic || got[0].IntervalCV >= 0.2 {
		t.Fatalf("%+v", got[0])
	}
}
func TestHighJitterNotPeriodicButStillRanks(t *testing.T) {
	st := storetest.New(t, beaconFixture(10*time.Second, 0.60, 12)...)
	got, _ := Rank(ctx, st, defaultCfg(), fixtureNow)
	if got[0].Periodic || got[0].Attempts != 12 {
		t.Fatalf("a high-jitter beacon still ranks on binary and destination: %+v", got[0])
	}
}
func TestCanaryDenialsExcluded(t *testing.T) { /* canary:true events never appear */ }
func TestDeterministicTwice(t *testing.T) { /* same store, same now: byte-identical JSON */ }
func TestEmitsOnlyOnChange(t *testing.T) { /* run 1 emits; add its output to the store; run 2 with no new denials emits nothing; a rank-bucket change emits again */ }
func TestPaloDenyCountsWhenAgentDead(t *testing.T) { /* devices.deny rows with src host and no net.egress_denied still produce a candidate with Class and Hosts */ }
func TestEgressCandidateTableIsProjection(t *testing.T) {}
func TestBoundedOnLargeStore(t *testing.T) { /* 50k denied events: Rank returns within 2 s and at most 200 candidates (shortcut: top 200 by key) */ }
func TestEgressConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Module{}, Config: referenceBlock(t), Seed: deniedFixture(), Now: fixtureNow})
}
```

`D13c` (`rules/egress/beacon.yml`) is added in this task only if W4's `jitter` operator has merged; otherwise `t.Skip("needs the jitter operator (W4)")` in `TestBeaconRuleFixtures`.

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/egress/ -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `shortcut: top 200 candidates per run, upgrade if a lab run shows legitimate candidates cut off`. Health: `degraded` when a host with default-deny sent no `net.egress_denied` and `net` reports `net.sensor_degraded`; gaps per design part 9.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/egress/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "egress: ranking analyser with periodic flag; candidate table"`

---

### Task 19: Egress suggestions and plan templates

**Files:**
- Create: `internal/egress/suggest.go`, `plans/egress/block_destination.yaml`, `plans/egress/kill_executable.yaml`, `plans/egress/patch_window.yaml`
- Test: `internal/egress/suggest_test.go`, `plans/egress/plans_test.go`

**Interfaces:**
- Consumes: `module.Host.Propose`, `detect.alert` (rule `D4c.exe-egress-class` fields `exe`, `exe_sha256`, `host`, `raddr`, `rport`; the kind is in `Consumes`), `egress.candidate`.
- Produces:

```go
func (m *Module) suggest(ctx context.Context, h module.Host, alert event.Event) error // Proposal for the destination block and, separately, for kill_process; emits SuggestBlockEvent per proposal
func destinationBlockable(man *manifest.Manifest, host, addr string, port uint16) error // refuses a destination that is a declared dependency of a scored service on host
// plans/egress/block_destination.yaml: fw.apply op block destinations ${addr} reason ${reason} owner ${owner} (click class)
// plans/egress/kill_executable.yaml: proc.kill_tree then file.quarantine (tier 2, click class)
// plans/egress/patch_window.yaml: one fw.apply node (op: allow, the depot-miss destination) with `expires_after: 30m`; class click
```

- [ ] **Step 1: Write the failing tests.**

```go
func TestSuggestCreatesTwoProposalsAndNothingRuns(t *testing.T) { // T67 module half
	h := newFakeHost(t) // records Propose, RunAuto, RunStanding, RunReadOnly
	if err := suggest(t, h, d4cAlert("rocky-ecom", "/tmp/x", "203.0.113.9", 443)); err != nil {
		t.Fatal(err)
	}
	if len(h.proposals) != 2 || h.proposals[0].Template != "block_destination" || h.proposals[1].Template != "kill_executable" {
		t.Fatalf("%+v", h.proposals)
	}
	if h.autoRuns+h.standingRuns+h.readOnlyRuns != 0 {
		t.Fatal("egress is click-only: nothing may run by itself (A-AUTO)")
	}
}
func TestDestinationBlockRefusedForDependency(t *testing.T) {
	err := destinationBlockable(refManifest(t), "rocky-ecom", "10.0.0.9", 3306) // ecom mysql dependency
	if err == nil {
		t.Fatal("a destination block must never cut a declared dependency of a scored service")
	}
}
func TestSuggestEmitsEvents(t *testing.T) { /* two egress.suggest_block events: What destination and kill_process, ProposalID set, Evidence refs the alert */ }
func TestEgressPlanTemplates(t *testing.T) { /* block_destination parses, module: egress, node fw.apply with op block; kill_executable nodes proc.kill_tree and file.quarantine, risk destructive so click-only */ }
func TestPatchWindowTemplate(t *testing.T) { /* LoadModuleTemplate(plansRoot, "egress", "patch_window") with params {host, destination}: the fw.apply node has ExpiresAfterSec 1800 and module "egress"; plan.Validate passes against the core catalog */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/egress/ ./plans/egress/ -v`. Expected: FAIL.
- [ ] **Step 3: Implement**; an alert whose host has the egress module disabled is ignored.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/egress/ ./plans/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "egress: one-click block suggestions and plan templates"`

---

### Task 20: `capture` kinds renamed; `conn` emitted by the module

**Files:**
- Modify: `internal/capture/{events,httpevent,module,flow}.go`, `internal/controller/capture_ingest.go` (delete the flow translation), `rules/deception.yml`, `rules/mw-redteam.yml`, `rules/network.yml` and `rules/profiles.yml` (only the capture kind names; the file move is W4's), `internal/honeytokens/akia.go` and tests, `internal/controller/capture_test.go`
- Test: `internal/capture/kinds_test.go`, `internal/capture/module_test.go`

**Interfaces:**
- Consumes: Task 1 payloads, `event.New`, `event.KindConn`/`event.Conn`.
- Produces: `capture.txn`, `capture.flow`, `capture.scan`, `capture.http_request`, `capture.evidence`, `capture.stats` built with `event.New` (the Converter returns typed values); for every ended flow where the host's addresses are known the module also emits `conn` with `Op: "closed"`, `Source: "capture"`, `Dir` set, `State` = the handshake value, `CommunityID`, `DurationMS`, `BytesOut`, `BytesIn`, `Service`; the old kind strings appear nowhere (`grep -rn '"net.txn"\|"net.flow"\|"net.scan"\|"http_request"' --include='*.go' --include='*.yml' .` is empty outside `docs/`).

- [ ] **Step 1: Write the failing tests.**

```go
func TestEmittedKindsAreDeclaredCaptureKinds(t *testing.T) {
	evs := runFixtureCapture(t, "testdata/http_session.pcap") // existing fixture builder
	for _, e := range evs {
		if err := event.Validate(e); err != nil {
			t.Fatalf("%s: %v", e.Kind, err)
		}
		if strings.HasPrefix(e.Kind, "net.") || e.Kind == "http_request" {
			t.Fatalf("old kind %s survived the rename", e.Kind)
		}
	}
}
func TestFlowAlsoEmitsConn(t *testing.T) {
	evs := runFixtureCapture(t, "testdata/http_session.pcap")
	c := firstOfKind(t, evs, "conn")
	cn, err := event.Decode[event.Conn](c, "conn")
	if err != nil || cn.Source != "capture" || cn.Op != "closed" || cn.Dir == "" || cn.CommunityID == "" {
		t.Fatalf("%+v %v", cn, err)
	}
}
func TestNoConnWhenLocalAddrsUnknown(t *testing.T) { /* cfg.LocalAddrs empty and no interface addresses: capture.flow only, no conn (dir would be unknown) */ }
func TestControllerNoLongerTranslatesFlows(t *testing.T) { /* internal/controller: the scan test from capture_test.go still raises P88 from the module's conn events; grep for kindFlow in capture_ingest.go is empty */ }
func TestHoneytokenAkiaReadsCaptureHTTPRequest(t *testing.T) { /* existing akia tests with the new kind */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/capture/ ./internal/controller/ ./internal/honeytokens/ -run 'Kinds|Conn|Translates|Akia' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the rename in one commit with the rule and test edits. Rule files keep their ids; only `kind:` and field-source names change (`net.flow`-based `D13e` and `D18b` now read `conn` with `source: capture`).
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "capture: capture.* kinds through event.New; conn from the module; old names deleted"`

---

### Task 21: `CaptureSettings` in the signed config; agent registration; conformance

**Files:**
- Create: `internal/controller/genconfig_network.go` (capture part), `internal/capture/agent.go`, `internal/capture/conformance_test.go`
- Modify: `internal/agent/mods/capture.go` (shrinks to the registration and `Subscribe` wiring), `internal/capture/module.go`, `internal/module/conformance/allowed.go` (remove `capture` from `PreContract`), `docs/capture.md` (the section on `capture.json`)
- Delete: `captureFile`, `CaptureFile`, the `capture.json` read
- Test: `internal/controller/genconfig_network_test.go`, `internal/capture/agent_test.go`, `internal/capture/conformance_test.go`

**Interfaces:**
- Consumes: Task 1 `CaptureSettings`, `agent.Factory`, `agent.HealthReporter`.
- Produces:

```go
func Factory() agent.Factory // Name "capture", Manifest (OS ["linux"], Roles ["capture"]), Section: enabled when roles contain "capture" && Modules.Capture != nil && Enabled; Build reads CaptureSettings only
func (m *Module) Health() module.Health // ok | degraded (kernel drops above 1% of packets, ring or hold full, parser panics, sheds, seal key missing) | unavailable (not Linux, no CAP_NET_RAW, no interface); Usage.HeldBytes = ring bytes + hold bytes
func captureSettings(in ConfigInputs, host string, h manifest.Host) *plan.CaptureSettings // controller: nil for Windows hosts and hosts without the capture role; defaults per the design: ring 256, hold 256, flow 1 MiB, disk 512, freeze 5m/10m, max_windows 8, scan 20 per 10 s
```

The seal key stays `<state>/capture.seal` (32-byte hex; absent: credential fields dropped and named in `secrets_dropped`); `shortcut: seal key is a local file with no distribution, upgrade with seal_key_ref when the vault can deliver per-host secrets in the signed config`. `OrgNets` still loads `<state>/orgnets.json`.

- [ ] **Step 1: Write the failing tests.**

```go
func TestCaptureSettingsDefaultsAndRole(t *testing.T) {
	cfg, _, _ := BuildAgentConfig(refInputs(t), "ubuntu-wkst") // has the capture role in the reference
	c := cfg.Modules.Capture
	if c == nil || c.RingMB != 256 || c.HoldMB != 256 || c.FlowBytes != 1<<20 || c.DiskBudgetMB != 512 || c.FreezeBeforeS != 300 || c.FreezeAfterS != 600 || c.MaxWindows != 8 || c.ScanThreshold != 20 || c.ScanWindowS != 10 {
		t.Fatalf("%+v", c)
	}
	win, _, _ := BuildAgentConfig(refInputs(t), "ad")
	if win.Modules.Capture != nil {
		t.Fatal("Windows hosts get no capture block (Known bug 23)")
	}
}
func TestReferenceManifestNoCaptureRoleOnWindows(t *testing.T) { /* load manifest/2027, every Windows host's roles lack "capture" */ }
func TestBuildFromSettingsOnly(t *testing.T) { /* a StateDir containing a capture.json is ignored; settings drive ring and ports */ }
func TestCaptureUnavailableOffLinux(t *testing.T) { /* runtime.GOOS faked through the Factory's goos field: Build returns agent.ErrUnavailable wrapped */ }
func TestSealKeyMissingDegradesAndDropsSecrets(t *testing.T) { /* no capture.seal: Health degraded with a gap; a Login7 fixture yields secrets_dropped and the password string appears in no emitted event or spool file */ }
func TestCaptureConformance(t *testing.T) {
	conformance.Agent(t, conformance.AgentCase{Factory: Factory(), Default: cfgWithCapture(t, finiteSource), Reconfig: cfgWithCapture(t, finiteSourceBigRing), KeepKey: "", Load: nil})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/controller/ ./internal/capture/ -run 'CaptureSettings|NoCaptureRole|FromSettings|Unavailable|Seal|Conformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The conformance fixture uses a finite pcap source (the module stays up for freezes after it ends); Windows reports `unavailable` with the gap `{"AF_PACKET", "Windows packet capture is cut"}`.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "capture: signed CaptureSettings replace capture.json; agent factory and health on the contract"`

---

### Task 22: `icmp.iputils_pattern` for 64-bit iputils (Known bug 19)

**Files:**
- Modify: `internal/parsers/icmp/icmp.go`
- Test: `internal/parsers/icmp/icmp_test.go`

**Interfaces:**
- Consumes: existing `icmp.Echo`.
- Produces: `iputilsPattern(p []byte) bool` is true when the payload is a 8-byte (32-bit timeval) or 16-byte (64-bit timeval) timestamp followed by the incrementing bytes `0x10, 0x11, ...` to the end of the payload; Go-ping payloads still report false.

- [ ] **Step 1: Write the failing test.**

```go
func TestIputilsPattern64Bit(t *testing.T) { // Known bug 19: a 56-byte payload = 16-byte timeval + 0x10..0x37
	p := make([]byte, 56)
	copy(p, []byte{0x5a, 0x1f, 0x2b, 0x65, 0, 0, 0, 0, 0xc1, 0x9d, 0x04, 0, 0, 0, 0, 0})
	for i := 16; i < 56; i++ {
		p[i] = byte(0x10 + i - 16)
	}
	req := echoReq(p) // ICMP echo request message around the payload
	tx, ok := Echo("cid", netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), false, req, time.Unix(1, 0))
	if !ok || tx.Attr["icmp.iputils_pattern"] != "true" || tx.Attr["icmp.payload_len"] != "56" {
		t.Fatalf("%+v", tx.Attr)
	}
}
func TestIputilsPattern32BitStillTrue(t *testing.T) { /* existing 8-byte timeval case */ }
func TestIputilsPatternBrokenByteFalse(t *testing.T) { /* flip byte 30 of the 64-bit payload: false */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/parsers/icmp/ -run Iputils -v`. Expected: FAIL (`false` for the 64-bit payload).
- [ ] **Step 3: Implement** by trying offsets 8 and 16 (`for _, off := range []int{8, 16}`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/parsers/icmp/ ./internal/capture/`. Expected: PASS (the `lab_test.go` replay stays skipped when the pcaps are absent).
- [ ] **Step 5: Commit.** `git commit -am "icmp: iputils pattern for 64-bit timeval (bug 19)"`

---

### Task 23: TFTP parser

**Files:**
- Create: `internal/parsers/tftp/tftp.go`, `internal/parsers/tftp/tftp_test.go`
- Modify: `internal/capture/engine.go` (UDP dispatch next to `dns.Datagram`), `internal/capture/config.go` services map
- Test: `internal/parsers/tftp/tftp_test.go`, `internal/capture/engine_test.go`

**Interfaces:**
- Consumes: `txn.Txn`, the DNS datagram wiring as the pattern.
- Produces:

```go
func Datagram(cid string, src, dst netip.AddrPort, payload []byte, ts time.Time) (txn.Txn, bool) // proto "tftp"
// types: "rrq" | "wrq" (Attr tftp.opcode, tftp.filename, tftp.mode), "data" first block (tftp.block, tftp.size, tftp.sha256, final when size < 512), "error" (tftp.error_code)
// shortcut: follows a single transfer on port 69 only, upgrade if a packet shows a server that answers from a random port
```

The engine maps UDP 69 to `tftp` only when it appears in `Services`/`services_extra`; the controller adds it to `CaptureSettings.Services` only when the manifest lists a scored service on that port (Task 21's `captureSettings`).

- [ ] **Step 1: Write the failing tests.**

```go
func TestTFTPReadRequest(t *testing.T) {
	pkt := append([]byte{0, 1}, []byte("boot.cfg\x00octet\x00")...) // RRQ
	tx, ok := Datagram("cid", ap("10.0.0.5:40000"), ap("10.0.0.9:69"), pkt, time.Unix(1, 0))
	if !ok || tx.Proto != "tftp" || tx.Attr["tftp.opcode"] != "rrq" || tx.Attr["tftp.filename"] != "boot.cfg" || tx.Attr["tftp.mode"] != "octet" {
		t.Fatalf("%+v", tx)
	}
}
func TestTFTPFinalShortBlock(t *testing.T) { /* DATA block 3 of 100 bytes: tftp.final true, tftp.size 100, tftp.sha256 set */ }
func TestTFTPRejectsGarbage(t *testing.T) { /* opcode 9, truncated header, unterminated filename: ok false, no panic */ }
func TestTFTPByteByByteIndependence(t *testing.T) {}
func FuzzTFTP(f *testing.F) { /* seeds: RRQ, WRQ, DATA, ERROR; never panics, tx bounded */ }
func TestEngineParsesTFTPOnlyWhenMapped(t *testing.T) { /* pcap with UDP/69: no capture.txn without services_extra {69: tftp}; one with it */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/parsers/tftp/ ./internal/capture/ -run 'TFTP' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** (attribute values clipped to 512 bytes, filenames to 255).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/parsers/tftp/ ./internal/capture/ && go test -run xxx -fuzz FuzzTFTP -fuzztime 10s ./internal/parsers/tftp/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "parsers: tftp over UDP 69 for capture"`

---

### Task 24: NTP parser

**Files:**
- Create: `internal/parsers/ntp/ntp.go`, `internal/parsers/ntp/ntp_test.go`
- Modify: `internal/capture/engine.go`
- Test: `internal/parsers/ntp/ntp_test.go`, `internal/capture/engine_test.go`

**Interfaces:**
- Produces: `func Datagram(cid string, src, dst netip.AddrPort, payload []byte, ts time.Time) (txn.Txn, bool)` — proto `ntp`; client request (mode 3) and server reply (mode 4); attributes `ntp.version`, `ntp.mode`, `ntp.stratum`, `ntp.poll`, `ntp.refid` (four ASCII characters for stratum 0 or 1, dotted quad otherwise); packets shorter than 48 bytes are rejected; extension fields are ignored.

- [ ] **Step 1: Write the failing tests.**

```go
func TestNTPClientRequest(t *testing.T) {
	p := make([]byte, 48)
	p[0] = 0x23 // LI 0, version 4, mode 3
	tx, ok := Datagram("cid", ap("10.0.0.5:123"), ap("10.0.0.9:123"), p, time.Unix(1, 0))
	if !ok || tx.Proto != "ntp" || tx.Attr["ntp.version"] != "4" || tx.Attr["ntp.mode"] != "3" || tx.Type != "request" {
		t.Fatalf("%+v", tx)
	}
}
func TestNTPServerReplyRefid(t *testing.T) {
	p := make([]byte, 48)
	p[0], p[1] = 0x24, 1 // version 4, mode 4, stratum 1
	copy(p[12:16], "GPS\x00")
	tx, _ := Datagram("cid", ap("10.0.0.9:123"), ap("10.0.0.5:123"), p, time.Unix(1, 0))
	if tx.Attr["ntp.stratum"] != "1" || tx.Attr["ntp.refid"] != "GPS" || tx.Type != "reply" {
		t.Fatalf("%+v", tx)
	}
}
func TestNTPShortPacketRejected(t *testing.T) {}
func FuzzNTP(f *testing.F) {}
func TestEngineParsesNTPOnlyWhenMapped(t *testing.T) {}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/parsers/ntp/ -v`. Expected: FAIL.
- [ ] **Step 3: Implement** and wire UDP 123 like Task 23.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/parsers/ntp/ ./internal/capture/ && go test -run xxx -fuzz FuzzNTP -fuzztime 10s ./internal/parsers/ntp/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "parsers: ntp over UDP 123 for capture"`

---

### Task 25: Capture ring inside the memory budget (Known bug 13)

**Files:**
- Modify: `internal/controller/genconfig_network.go`, `internal/plan/agentconfig.go` (comment on `Budgets`), `internal/capture/module.go` (`Health.Usage`), `svcinstall` flag help text
- Test: `internal/controller/genconfig_network_test.go`, `internal/capture/budget_test.go`

**Interfaces:**
- Consumes: Task 21 `CaptureSettings`, `plan.Budgets.MemoryLimitMB` (applied by the agent through `debug.SetMemoryLimit`).
- Produces: `AgentConfig.Budgets.MemoryLimitMB = 80 + RingMB + HoldMB` for a host with a capture block (80 otherwise, the core footprint); `capture.Manifest.Budget.HeldMB` equals the default `ring_mb + hold_mb` minus 0 (512); the heartbeat's capture block reports `Usage.HeldBytes` from the ring and hold actual bytes.

- [ ] **Step 1: Write the failing tests.**

```go
func TestCaptureHostMemoryLimitIncludesRing(t *testing.T) { // Known bug 13
	cfg, _, _ := BuildAgentConfig(refInputs(t), "ubuntu-wkst")
	c := cfg.Modules.Capture
	if cfg.Budgets.MemoryLimitMB != 80+c.RingMB+c.HoldMB {
		t.Fatalf("limit %d; the ring and hold are Go heap and must be inside the limit", cfg.Budgets.MemoryLimitMB)
	}
	other, _, _ := BuildAgentConfig(refInputs(t), "rocky-ecom")
	if other.Budgets.MemoryLimitMB != 80 {
		t.Fatalf("hosts without capture keep the 80 MB footprint: %d", other.Budgets.MemoryLimitMB)
	}
}
func TestManifestHeldMatchesDefaults(t *testing.T) {
	d := defaultCaptureSettings()
	if Manifest.Budget.HeldMB != d.RingMB+d.HoldMB {
		t.Fatalf("manifest %d vs defaults %d", Manifest.Budget.HeldMB, d.RingMB+d.HoldMB)
	}
}
func TestHealthReportsHeldBytes(t *testing.T) { /* after replaying a pcap, Health().Usage.HeldBytes > 0 and <= ring+hold */ }
func TestNoPacketRingPolicyFields(t *testing.T) { /* grep-style: no Go or YAML file defines packet_ring_max_bytes or packet_ring_free_pct (done in Task 4; guard kept) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ ./internal/capture/ -run 'MemoryLimit|HeldMatches|HeldBytes' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The installer's `--memory-max` help text says a capture host needs `80M + ring_mb + hold_mb` plus headroom; `shortcut: MemoryMax is fixed at install, upgrade when enrollment (W12) derives it from the signed config`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/ ./internal/capture/ ./cmd/phylax/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "capture: ring and hold inside the agent memory limit (bug 13)"`

---

### Task 26: Controller-scope `freeze_capture` (Known bug 7)

**Files:**
- Create: `internal/capture/controller.go` (replace the stub), `internal/capture/freezecontrol.go`
- Modify: `internal/agent/handlers.go` (the `freeze_capture` case), `internal/plan/control.go`, `internal/controller/host.go` (`Control` accepts `freeze_capture` from `capture`), `internal/capture/freeze.go` (`OnAlert` reused unchanged)
- Test: `internal/capture/freezecontrol_test.go`, `internal/agent/freeze_test.go`, `internal/controller/host_control_test.go`

**Interfaces:**
- Consumes: Task 1 (`ControlFreezeCapture`, `Host.Control`), `detect.alert` (fields `rule`, `time`, `scope`, `collect` (list), `entities`, `evidence` refs of `{agent, seq}`), `store.Reader.Event`.
- Produces:

```go
func (c *Controller) onAlert(ctx context.Context, h module.Host, alert event.Event) error // alert.scope == "controller" and collect contains "freeze_ring": resolve the agents of the evidence events (those with the capture role), collect remote addrs from the alert entities, send Control{Type: "freeze_capture", Hosts: agents, Data: {rule, alert_time, addrs}}
// agent side (internal/agent/handlers.go): a verified freeze_capture control is turned into a bus-only synthetic detect.alert {rule, collect: ["freeze_ring"], entities: addrs, time: alert_time} and published with a.publish; never spooled; strict decode, at most 64 addrs
```

The agent reuses the freeze path, so the hold id (hash of rule and addresses) and windows are the same as for a local alert.

- [ ] **Step 1: Write the failing tests.**

```go
func TestControllerScopeAlertSendsFreeze(t *testing.T) { // Known bug 7
	h := newFakeHost(t, withEvents(flowEventsFrom("h1", "h2")))
	err := (&Controller{}).onAlert(ctx, h, controllerAlert("D13e", "freeze_ring", []string{"198.51.100.7"}, evidenceRefs("h1", 4, "h2", 9)))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.controls) != 1 {
		t.Fatalf("%d controls", len(h.controls))
	}
	m := h.controls[0]
	if m.Type != "freeze_capture" || !reflect.DeepEqual(sorted(m.Hosts), []string{"h1", "h2"}) || m.Data["rule"] != "D13e" || m.Data["addrs"].([]string)[0] != "198.51.100.7" {
		t.Fatalf("%+v", m)
	}
}
func TestAgentScopeAlertSendsNothing(t *testing.T) { /* scope agent, or collect without freeze_ring: no control */ }
func TestHostControlOnlyCaptureMaySendFreeze(t *testing.T) { /* controller.hostFor(capture).Control(freeze) ok; hostFor(other).Control(freeze) -> module.ErrNotInScope; bad data (65 addrs, empty rule) rejected */ }
func TestFreezeControlFreezesRing(t *testing.T) { // end to end on the agent harness
	h := captureHarness(t, finiteSourceWithPackets("198.51.100.7"))
	h.Control(freezeControl("D13e", time.Now(), []string{"198.51.100.7"})) // signed control through the harness
	ev := h.WaitFor("capture.evidence", 3*time.Second)[0]
	e, _ := event.Decode[EvidenceEvent](ev, "capture.evidence")
	if e.Rule != "D13e" || e.Packets == 0 || e.Path == "" {
		t.Fatalf("%+v", e)
	}
}
func TestFreezeCaptureRepeatExtendsHold(t *testing.T) { // Review Focus 5
	/* send the same control twice: Freezer holds one window (same id), a final evidence event once, Skipped() == 0 */
}
func TestFreezeCaptureNoMatchingPackets(t *testing.T) {
	/* an address in no ring: a capture.evidence event with Error set and Packets 0; the module keeps running */
}
func TestUnknownControlStillRefused(t *testing.T) {} // regression: agent.control_refused for a made-up kind
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/capture/ ./internal/agent/ ./internal/controller/ -run 'Freeze|HostControl' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The controller module subscribes to `detect.alert` (in its `Consumes`). A host not connected is skipped and logged (the ring may already have evicted the packets: `shortcut: no retry for an offline agent, upgrade if a lab run shows lost freezes`). `link.ProtoMinor` was raised in Task 1.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/capture/ ./internal/agent/ ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "capture: controller sends freeze_capture for controller-scope freeze_ring alerts (bug 7)"`

---

### Task 27: Source-address check

**Files:**
- Create: `internal/capture/sourcecheck.go`, `internal/capture/conformance_controller_test.go`
- Modify: `internal/capture/controller.go`, `internal/module/conformance/allowed.go` (remove `capture` from `PreContract` if Task 21 left it for the controller side; the entry covers both sides)
- Test: `internal/capture/sourcecheck_test.go`

**Interfaces:**
- Consumes: `conn` events (inbound, `source: capture`, `raddr`, `lport`), `devices.traffic` (keys `src`, `dst`, `dport`, `nat_src`, `count`), `Host.Tables`.
- Produces:

```go
func SourceCheck(ctx context.Context, q store.Reader, m *manifest.Manifest, now time.Time) (SourceCheckEvent, bool, error) // false until both inputs exist; compares the first-minutes inbound sources to scored services with the Palo traffic log
// agree: every sampled flow's source equals a devices.traffic src; firewall_sources: every inbound source on scored ports is the Palo's inside address; recovered: traffic-log sources are available to traceback and scorer (devices.traffic present)
func (c *Controller) Analyzers() []module.Analyzer // "capture.source_check": Inputs ["conn","devices.traffic"], Every 60s; emits once per change; table capture_source_check(window TEXT, agree INTEGER, firewall_sources INTEGER, sample INTEGER)
```

- [ ] **Step 1: Write the failing tests.**

```go
func TestSourceCheckAgrees(t *testing.T) { /* fixture: 20 inbound conn events from 203.0.113.x to scored :80 and devices.traffic rows with the same srcs -> Agree true, FirewallSources false, Sample 20 */ }
func TestSourceCheckAllFromFirewall(t *testing.T) {
	st := storetest.New(t, inboundFrom("172.20.240.200", 30), palo("203.0.113.5", 30)...) // every capture source is the Palo; the log has the real ones
	ev, ok, err := SourceCheck(ctx, st, refManifest(t), fixtureNow)
	if err != nil || !ok || ev.Agree || !ev.FirewallSources || !ev.Recovered {
		t.Fatalf("%+v %v %v", ev, ok, err)
	}
}
func TestSourceCheckWaitsForBothInputs(t *testing.T) { /* no devices.traffic: ok false, no event */ }
func TestSourceCheckDeterministic(t *testing.T) {}
func TestSourceCheckTableProjection(t *testing.T) {}
func TestCaptureControllerConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Controller{}, Config: "enabled: true\n", Seed: sourceCheckFixture(), Now: fixtureNow})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/capture/ -run 'SourceCheck|ControllerConformance' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `devices.traffic` is optional: without it the check never fires and health carries the gap `{"source check", "no Palo traffic log"}`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/capture/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "capture: source-address check against the Palo traffic log"`

---

### Task 28: Controller-scope rule content under `rules/capture/`

Order: after W4 has moved `rules/network.yml` into `rules/detect/` (check `ls rules/detect/network.yml`; if absent, do this task last and note it in the lab record).

**Files:**
- Create: `rules/capture/flows.yml` (rules `D13e`, `D18b` moved with their inline tests, `module: capture`), `internal/capture/rules_test.go`
- Modify: the W4-owned source file (delete the two rules)
- Test: `internal/capture/rules_test.go`

**Interfaces:**
- Consumes: the W4 rule loader (`detect.Parse`), which already reads `module:` and `rules/<module>/` dirs.
- Produces: the two rules and their fixtures under the new path; the controller-scope scan test of `internal/controller/capture_test.go` still raises `P88`/`D13e`.

- [ ] **Step 1: Write the failing test.**

```go
func TestCaptureRulesLoadAndPassInlineTests(t *testing.T) {
	rs, err := detect.Parse("controller", mustRead(t, "../../rules/capture/flows.yml"), detect.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(rs)
	if !reflect.DeepEqual(ids, []string{"D13e", "D18b"}) {
		t.Fatalf("%v", ids)
	}
	if fails := rs.RunInlineTests(); len(fails) != 0 {
		t.Fatal(fails)
	}
}
func TestRulesNotDuplicatedInDetectDir(t *testing.T) { /* the rule-id registry check: D13e and D18b are defined once */ }
```

(The test is in package `capture_test` and imports `detect` only as a test dependency; `go list -deps` of the package, not of its tests, is what the sibling-import check reads. If W1's check parses test imports, move this test to `internal/e2e`.)

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/capture/ -run CaptureRules -v`. Expected: FAIL.
- [ ] **Step 3: Move** the rules unchanged (ids, tiers, fixtures); update `ManifestScorerSources` comments to point at the new path.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/capture/ ./internal/controller/ ./internal/detect/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "capture: controller-scope rules D13e and D18b live under rules/capture"`

---

### Task 29: `devices` on the contract: config, manifest, `Attach`, health, conformance

**Files:**
- Modify: `internal/devices/{config,module,manifest}.go` (replace stubs), `cmd/phylax/serve.go` (build the `Directory`, `controller.Options.Backends`, `devices.Module.Attach`), `internal/controller/controller.go` (`Options.Backends map[string]any`, put into the executor `Env.Ext`), `internal/module/conformance/allowed.go` (remove `devices`)
- Test: `internal/devices/module_test.go`, `internal/devices/conformance_test.go`

**Interfaces:**
- Consumes: Task 3 `Directory`, `Host.Config`, `Host.Manifest`.
- Produces:

```go
func (c Config) Validate() error // poll intervals >= 5s, backup.keep in 1..500, capture.max_seconds <= 600, max_bytes <= 1 GiB
func (m *Module) Attach(d Directory)                                 // before RunModules; nil directory => unavailable with gap {"devices", "no device directory (controller not wired)"}
func (m *Module) Start(ctx context.Context, h module.Host) error     // declared devices from h.Manifest().Devices; none declared => health disabled-like "ok" with detail "no devices declared" (Default true only when devices.yml declares devices)
func (m *Module) Health() module.Health // ok | degraded (a device unreachable on a fresh connection, a poll late by 2 intervals, foreign pending change or lock, licence flag missing, backups failing) | error (a change rolled back and could not confirm, management path lost); gaps: devices without soft dead-man or native confirm (PAN-OS)
```

- [ ] **Step 1: Write the failing tests.**

```go
func TestReferenceDevicesBlockValidates(t *testing.T) {
	var c Config
	mustDecodeFile(t, "../../manifest/2027/modules/devices.yml", &c)
	if err := c.Validate(); err != nil || c.Deadman != 90*time.Second || c.Poll.SystemInfo != 10*time.Second || c.Poll.Jobs != 15*time.Second || c.Poll.Logs != 30*time.Second || c.Poll.ConfigHash != 5*time.Minute || c.Backup.Every != 30*time.Minute || c.Backup.Keep != 48 {
		t.Fatalf("%+v %v", c, err)
	}
}
func TestUnattachedIsUnavailable(t *testing.T) {}
func TestHealthGapsListPaloWithoutDeadman(t *testing.T) {
	m := startedModule(t, fakeDirectory(withPalo("palo1")))
	var found bool
	for _, g := range m.Health().Gaps {
		found = found || strings.Contains(g.What, "palo1") && strings.Contains(g.Why, "console")
	}
	if !found {
		t.Fatal("PAN-OS has no commit confirm: the gap must say lockout-class changes need the console acknowledgement")
	}
}
func TestUnreachableDeviceDegrades(t *testing.T) {}
func TestNoDevicesDeclaredIsDisabledNotError(t *testing.T) {}
func TestDevicesConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Module{}, Config: "enabled: true\n", Seed: nil, Now: fixtureNow})
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/devices/ -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `serve.go` builds one `*controller.Directory` and passes it to both `Options.Backends["devices"]` and `Attach`. The module package keeps every poller behind one `ctx` and one `errgroup`-style wait so `Start` returns only after all goroutines exit.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "devices: controller module with config, attach, health and conformance"`

---

### Task 30: Device pollers, `devices.config` and tamper rule `D14`

**Files:**
- Create: `internal/devices/poll.go`, `rules/devices/tamper.yml`, `internal/devices/tamper_test.go`
- Modify: `internal/devices/module.go`
- Test: `internal/devices/poll_test.go`, `internal/devices/tamper_test.go`

**Interfaces:**
- Consumes: `adapter.Adapter.Drift`, `Events`, `Admins`, `Info`, `adapter.ConfigEvent`; the stateful fakes `palotest` and `vyostest`; `event.New`.
- Produces:

```go
type poller struct{ /* per device: last-good snapshot, cursor, last hash */ }
func (m *Module) pollOnce(ctx context.Context, device string) error // Drift against last-good, new config-log entries after the stored cursor, foreign locks and pending changes; one ConfigEvent per adapter.ConfigEvent
// intervals from Config.Poll; devices behind a relay work through the Directory (Palo(ctx, device) already dials via the splice)
// Ours: true only inside a transaction window of this controller (the executor reports windows to the module via the plan id tag on the Tx) and matching the actor
// rules/devices/tamper.yml: D14.device-tamper (module: devices, scope: controller, tier 1): devices.config where ours is false and change in (commit, admin_add, key_change, oob) or (login with an unknown actor); inline tests below
```

- [ ] **Step 1: Write the failing tests.**

```go
func TestForeignCommitEmitsConfigEventNotOurs(t *testing.T) { // T13 CI form
	f := palotest.New(t)
	m := moduleWithPalo(t, f)
	f.ExternalCommit("evil-admin", "set rulebase security rules allow-all") // a second admin commits
	if err := m.PollOnce(ctx, "palo1"); err != nil {
		t.Fatal(err)
	}
	e := lastOfKind(t, m.emitted, "devices.config")
	c, _ := event.Decode[ConfigEvent](e, "devices.config")
	if c.Change != "commit" || c.Ours || c.Actor != "evil-admin" || c.Device != "palo1" {
		t.Fatalf("%+v", c)
	}
}
func TestOwnCommitMarkedOursWithPlanTag(t *testing.T) {
	/* run palo.apply through the action against palotest; poll: the commit event has Ours true and Tag == the plan id; no foreign-change event */
}
func TestUnknownAdminLoginAndNewAPIKey(t *testing.T) { /* palotest.AddAdmin / NewAPIKey -> admin_add / key_change events, Ours false */ }
func TestAllowAboveBlockDiffDetected(t *testing.T) {}
func TestCursorSurvivesRestart(t *testing.T) { /* poll, new Module on the same state dir: no duplicate events for the old entries */ }
func TestVyOSCommitLogSignatureNewerThanStored(t *testing.T) { /* vyostest: an out-of-band commit is reported once */ }
func TestD14RuleInlineTests(t *testing.T) {
	rs, err := detect.Parse("controller", mustRead(t, "../../rules/devices/tamper.yml"), detect.LoadOptions{})
	if err != nil || len(rs.RunInlineTests()) != 0 {
		t.Fatal(err, rs.RunInlineTests())
	}
}
func TestD14IdUnique(t *testing.T) { /* rule-id registry: rules/deps.yml no longer defines D14 (W8 renames; skip with reason when deps.yml still has it) */ }
```

(`detect` appears only in a test; if W1's import check reads test files, move `TestD14RuleInlineTests` to `internal/e2e`.)

- [ ] **Step 2: Run, expect FAIL.** Run: `go test -short ./internal/devices/ -run 'Foreign|Ours|Unknown|AllowAbove|Cursor|VyOS|D14' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Cursors persist as one JSON file per device under the module's state area (`atomicfile`); `shortcut: cursors in files, upgrade to the module table if devices grow past a handful`. `Tables` lists `device_snapshot` (last-good hash and time per device, written by the single writer from `devices.config` and `devices.change` events).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/devices/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "devices: drift pollers, devices.config events and rule D14"`

---

### Task 31: Deny-log and traffic-log pulls

**Files:**
- Create: `internal/devices/logs.go`
- Modify: `internal/devices/devices.go` adapters? No: `internal/devices/palo/adapter.go` (`TrafficLog` read), `internal/devices/module.go`
- Test: `internal/devices/logs_test.go`, `internal/devices/palo/palo_test.go`

**Interfaces:**
- Consumes: `palo.Adapter.Events(ctx, EventFilter{Source: "traffic"})` (extended to carry `action`, `src`, `dst`, `dport`, `proto`, `app`, `rule`, `nat_src`, `nat_dst`, `dir`), `palotest` traffic-log support.
- Produces:

```go
type tuple struct{ Src, Dst string; DPort uint16 }
func aggregate(entries []adapter.Event, window time.Duration) []DenyEvent // one event per (src, dst, dport) per 10 s window with count, first, last; a scan cannot flood the bus
func (m *Module) pullLogs(ctx context.Context, device string) error      // every Poll.Logs: outbound denies -> devices.deny (when DenyLog.Enabled); inbound sessions to the public pool -> devices.traffic during TrafficLog.FirstMinutes after the first poll or on demand (TrafficOnDemand(ctx, device, d time.Duration))
```

Cursors per device survive a controller restart (same file mechanism as Task 30).

- [ ] **Step 1: Write the failing tests.**

```go
func TestDenyAggregatedPerTuplePerWindow(t *testing.T) {
	entries := scan(t, "10.0.0.7", "198.51.100.9", 500, time.Second) // 500 deny lines over 10 s to one dport, plus 3 other dports
	got := aggregate(entries, 10*time.Second)
	if len(got) != 4 {
		t.Fatalf("one event per tuple per window, got %d", len(got))
	}
	if got[0].Count != 500 && got[0].DPort != 443 {
		t.Fatalf("%+v", got[0])
	}
}
func TestOnlyOutboundDenyBecomesDenyEvent(t *testing.T) {}
func TestTrafficPullOnlyInFirstMinutesOrOnDemand(t *testing.T) { /* clock after 16 minutes: no devices.traffic; TrafficOnDemand re-enables for the requested duration */ }
func TestTrafficCarriesNatSource(t *testing.T) { /* devices.traffic.NatSrc is the translated source */ }
func TestDenyLogDisabledByConfig(t *testing.T) {}
func TestCursorSurvivesControllerRestart(t *testing.T) {}
func TestBoundedPullPerPoll(t *testing.T) { /* at most 5000 entries read per poll; the rest next poll; shortcut comment */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/devices/... -run 'Deny|Traffic|Aggregated|Cursor|Bounded' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** with `shortcut: 5000 log entries per poll, upgrade if a lab run shows the cursor falling behind`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/devices/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "devices: aggregated deny and traffic log pulls with persistent cursors"`

---

### Task 32: Scorer-mimic probe inside the device commit (Known bug 20)

**Files:**
- Modify: `internal/devices/actions.go`, `internal/devices/palo/adapter.go` (`HealthCheck(flows, extra)` unchanged), `internal/devices/vyos/adapter.go`
- Test: `internal/devices/probe_test.go`

**Interfaces:**
- Consumes: `actions.Env.Probe func(ctx context.Context, service string) error` (W1 Task 1/29), Task 3 `Directory.ScoredServices`, the stateful fakes.
- Produces:

```go
func probeExtra(env *actions.Env, services []string) func(context.Context) error // runs env.Probe(ctx, svc) for each service, one retry after 5 s then fail, first error returned; nil when env.Probe is nil
// palo.apply, vyos.apply and palo.permitted_ips pass probeExtra(...) as HealthCheck's extra argument; Output["probed"] = "true" | "false"
```

- [ ] **Step 1: Write the failing tests.**

```go
func TestRedProbeRevertsPaloCommit(t *testing.T) { // Known bug 20; T44 CI form
	f := palotest.New(t)
	env := deviceEnv(t, f)
	env.Probe = func(_ context.Context, svc string) error { return errors.New(svc + " red") }
	_, err := runAction(t, env, "palo.apply", map[string]any{"scope": "policy", "device": "palo1"})
	if err == nil {
		t.Fatal("a red probe inside the commit window must fail the change")
	}
	if f.RunningHash() != f.LastGoodHash() {
		t.Fatal("the commit must have been reverted through the device protocol")
	}
}
func TestGreenProbeConfirms(t *testing.T) {
	env := deviceEnv(t, palotest.New(t))
	var probed []string
	env.Probe = func(_ context.Context, svc string) error { probed = append(probed, svc); return nil }
	out, err := runAction(t, env, "palo.apply", map[string]any{"scope": "policy", "device": "palo1"})
	if err != nil || len(probed) == 0 || out.Output["probed"] != "true" {
		t.Fatal(err, probed, out.Output)
	}
}
func TestNilProbeNotGreen(t *testing.T) { // Review Focus 4
	out, err := runAction(t, deviceEnvNoProbe(t), "palo.apply", map[string]any{"scope": "policy", "device": "palo1"})
	if err != nil || out.Output["probed"] != "false" {
		t.Fatalf("a nil probe must be reported as not probed: %v %v", out.Output, err)
	}
}
func TestRedProbeRevertsVyOSViaSoftRevert(t *testing.T) { /* vyostest: the timer fires or the explicit revert runs; running config equals the saved one */ }
func TestProbeRetriesOnce(t *testing.T) { /* first call red, second green: the commit stands; two red: reverted; total calls 2 */ }
func TestProbeBoundedByDeadman(t *testing.T) { /* a probe that blocks: the health callback ends within 3/4 of the dead-man (existing runner bound) and the change is reverted */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/devices/ -run 'Probe' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Directory.ScoredServices` comes from Task 3; an empty list means no probe (reported `probed=false`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/devices/... ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "devices: scorer-mimic probe inside the device commit window (bug 20)"`

---

### Task 33: `palo.revert`, `device.rotate_admin`, licence gating

**Files:**
- Create: `internal/devices/rotate.go`
- Modify: `internal/devices/palo/{adapter,tx}.go` (`RotateAdmin`, licence read), `internal/devices/vyos/adapter.go` (`RotateAdmin`), `internal/devices/adapter/devices.go` (`Adapter.RotateAdmin`, `Caps.PacketCapture`, `Info.Licence`), `internal/devices/actions.go`
- Test: `internal/devices/rotate_test.go`, `internal/devices/palo/palo_test.go`, `internal/devices/vyos/vyos_test.go`

**Interfaces:**
- Produces:

```go
type RotateSpec struct{ Account string; NewSecret string } // NewSecret generated by the action, never logged
// Adapter gains: RotateAdmin(ctx context.Context, s RotateSpec) (Creds, error)
// Info gains: Licence map[string]bool; Caps gains PacketCapture bool (from the licence read once at Info)
// actions: palo.revert (Risk lockout, NeedsConsoleAck, params: device, to "last_good"|"snapshot", snapshot path): granular replay of the recorded XML or load of phylax-pre-<id>.xml
//          device.rotate_admin (Risk lockout, params: device, account default Config.Account): rotate in a transaction, fresh-connection probe with the new secret, write it to the vault BEFORE the old one is retired
// Directory gains: PutSecret(ctx, device, account string, secret vault.Secret) error
```

- [ ] **Step 1: Write the failing tests.**

```go
func TestRotateWritesVaultBeforeRetiringOld(t *testing.T) {
	f, v := palotest.New(t), newRecordingVault()
	env := deviceEnv(t, f, withVault(v))
	if _, err := runAction(t, env, "device.rotate_admin", map[string]any{"device": "palo1", "account": "phylax"}); err != nil {
		t.Fatal(err)
	}
	if !(v.putAt < f.OldSecretRetiredAt) {
		t.Fatal("the new secret must be in the vault before the old one is retired")
	}
}
func TestRotateFailedProbeKeepsOldSecret(t *testing.T) { /* fresh-connection login with the new secret fails: the device still accepts the old one, the vault is unchanged, error returned */ }
func TestRotateSecretNeverInOutput(t *testing.T) { /* Output and logs do not contain the new secret */ }
func TestPaloRevertReplaysRecordedXML(t *testing.T) { /* apply then palo.revert to last_good: running hash equals the pre-apply hash */ }
func TestPaloRevertNeedsConsoleAck(t *testing.T) {}
func TestLicenceGateRefusesCapture(t *testing.T) {
	f := palotest.New(t, palotest.WithLicence(map[string]bool{"threat": true})) // no packet-capture entitlement
	a, _ := deviceDirectory(t, f).Palo(ctx, "palo1")
	if a.Caps().PacketCapture {
		t.Fatal("capability flag must follow the licence")
	}
}
func TestVyOSRotateAdmin(t *testing.T) {}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/devices/... -run 'Rotate|Revert|Licence' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The Palo rotation is `set mgt-config users <account> phash` in the management scope (additive style: new key first, probe, then the old API key invalidated); the VyOS one `set system login user <account> authentication plaintext-password` over SSH with the soft-revert timer armed. The T+0 console rotation of `admin` and `vyos` stays manual (not this action).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/devices/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "devices: palo.revert, device.rotate_admin and licence-aware capability flags"`

---

### Task 34: Scheduled backups and `ftd.export`

**Files:**
- Create: `internal/devices/backup.go`, `internal/devices/ftd.go`, `plans/devices/backup.yaml`
- Test: `internal/devices/backup_test.go`, `internal/devices/ftd_test.go`

**Interfaces:**
- Consumes: `adapter.Snapshot`, `ssh` client from `golang.org/x/crypto/ssh`, `Host.Tables`, the controller state snapshot key (passphrase-derived; supplied to the module by `Attach` options `WithBackupKey(key []byte)`).
- Produces:

```go
func (m *Module) backupOnce(ctx context.Context, device string) (BackupEvent, error) // snapshot, AES-GCM with the backup key, keep the last Backup.Keep in table device_backup (device, hash, size, listed_at, ciphertext BLOB), copy over SSH to each Backup.Targets entry by piping to the target (no SFTP), emit devices.backup with hash, size, targets[], listed_at, error
// triggers: every Backup.Every and after every devices.change with rolled_back false
// actions: device.backup (Risk none, ReadOnly false, params: device) runs backupOnce; ftd.export (Risk none, ReadOnly true, params: device, commands default ["show access-control-config"]) runs the commands over SSH to the FTD CLI, writes the output to an evidence file, never changes the device
// plans/devices/backup.yaml: module devices, one node device.backup per declared device, standing-approval friendly
```

- [ ] **Step 1: Write the failing tests.**

```go
func TestBackupRoundTripEncrypted(t *testing.T) {
	m, key := moduleWithKey(t)
	ev, err := m.backupOnce(ctx, "palo1")
	if err != nil || ev.Error != "" {
		t.Fatal(err, ev.Error)
	}
	blob := m.rowCiphertext(t, ev.Hash)
	if bytes.Contains(blob, []byte("<config")) {
		t.Fatal("the stored backup must be encrypted")
	}
	plain := decrypt(t, key, blob)
	if sha256Hex(plain) != ev.Hash {
		t.Fatal("hash must be of the plaintext snapshot")
	}
}
func TestBackupKeepsLastN(t *testing.T) { /* Keep 3, five backups: three rows, oldest dropped */ }
func TestBackupFailingTargetReportedNotFatal(t *testing.T) { /* one SSH target refuses: BackupEvent.Error names it, the controller copy exists, Health degraded */ }
func TestBackupAfterConfirmedChange(t *testing.T) {}
func TestBackupPipesOverSSHWithoutSFTP(t *testing.T) { /* an in-process ssh server that rejects the sftp subsystem accepts "cat > path"; the file arrives */ }
func TestFTDExportReadOnly(t *testing.T) { /* fake SSH CLI records commands: only "show ..." commands run; a command not starting with "show " is refused by the action's param check */ }
func TestBackupPlanTemplate(t *testing.T) {}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/devices/ -run 'Backup|FTD' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `shortcut: copy by piping to the target over SSH, no SFTP client; upgrade only if a target forbids shell commands`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/devices/... ./plans/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "devices: encrypted scheduled backups, ftd.export"`

---

### Task 35: Palo packet capture, version and findings audit, plans content

**Files:**
- Create: `internal/devices/audit.go`, `internal/devices/capture.go`, `plans/devices/kali_path.yaml`
- Modify: `internal/devices/palo/adapter.go` (`Capture`), `plans/first-hour/palo.mgmt_lockdown.yaml` (audit node)
- Test: `internal/devices/audit_test.go`, `internal/devices/capture_test.go`

**Interfaces:**
- Produces:

```go
func (m *Module) auditDevice(ctx context.Context, device string) ([]FindingEvent, VersionEvent, error) // devices.version from Info (vendor, version, serial, licence); findings: mgmt_profile_open, globalprotect_exposed, default_admin, permitted_ip_any, gated by Config.Audit flags
// Adapter gains: Capture(ctx, CaptureSpec) (Capture, error) // CaptureSpec{Filter, Stage (receive|firewall|transmit|drop), Seconds, MaxBytes}
// action palo.capture (Risk service, params: device, filter, stage, seconds): refused unless Config.Capture.Enabled and Caps.PacketCapture; bounded by max_seconds and max_bytes; creates a capture filter, pulls the file, removes the filter; stores evidence; emits devices.capture
// shortcut: capture stages and limits are not verified against the licensed PAN-OS VM, the lab (T44 follow-up) fixes the parameter set
```

- [ ] **Step 1: Write the failing tests.**

```go
func TestVersionEventForVulnModule(t *testing.T) {
	v := auditVersion(t, palotest.New(t, palotest.WithVersion("11.0.2")))
	if v.Vendor != "panos" || v.Version != "11.0.2" || v.Serial == "" {
		t.Fatalf("%+v", v)
	}
}
func TestFindingsOnOpenMgmtAndGlobalProtect(t *testing.T) {
	fs := auditFindings(t, palotest.New(t, palotest.WithUntrustMgmtProfile("http", "ssh"), palotest.WithGlobalProtectPortal()))
	if !hasKind(fs, "mgmt_profile_open") || !hasKind(fs, "globalprotect_exposed") {
		t.Fatalf("%v", fs)
	}
}
func TestDefaultAdminFinding(t *testing.T) { /* palotest with admin "admin" still configured -> default_admin */ }
func TestAuditFlagsOff(t *testing.T) { /* Audit.MgmtProfiles false: no mgmt_profile_open finding */ }
func TestCaptureRefusedWhenDisabled(t *testing.T) {}
func TestCaptureRefusedWithoutLicenceFlag(t *testing.T) {}
func TestCaptureBoundedAndFilterRemoved(t *testing.T) {
	f := palotest.New(t, palotest.WithPacketCapture())
	out, err := runAction(t, captureEnv(t, f, enabled(120, 100<<20)), "palo.capture", map[string]any{"device": "palo1", "filter": "dst 172.20.241.30 and dport 80", "stage": "receive", "seconds": 600})
	if err == nil {
		t.Fatalf("seconds above max_seconds must be refused: %v", out)
	}
	_, err = runAction(t, captureEnv(t, f, enabled(120, 100<<20)), "palo.capture", map[string]any{"device": "palo1", "filter": "dst 172.20.241.30 and dport 80", "stage": "receive", "seconds": 30})
	if err != nil || f.CaptureFilters() != 0 {
		t.Fatal(err, f.CaptureFilters())
	}
}
func TestMgmtLockdownPlanHasAuditNode(t *testing.T) {}
func TestKaliPathTemplateLoads(t *testing.T) {}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/devices/... ./plans/... -run 'Version|Findings|DefaultAdmin|AuditFlags|Capture|Lockdown|Kali' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** with `palotest` gaining the three options named above (profile, GlobalProtect, packet capture); new fake behaviour is test support in the existing fake package.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "devices: version and findings audit, gated Palo packet capture, device plans"`

---

### Task 36: Lab (stronger agent or David)

**Files:**
- Create: `docs/impl/lab/w6-network.md`

Run on the BTaP replica (`stacks/ccdc`: `rocky-ecom`, `ubuntu-email` and `ubuntu-wkst` as Linux hosts, `win11` and `ad` as Windows hosts, the Kali, the licensed PAN-OS VM and a VyOS 1.4 image, the Palo in `palo1`), from a build of the merged branch. Record date, commit, VMIDs, test id, pass/fail, measured values and what was not run; open an issue for every failure. This task does not block the merge.

- [ ] **Step 1: T77 (inbound enforcement and allow-back).** Enforce inbound-only on `rocky-ecom` with `enforce-inbound` under `act_enabled`: an unlisted port is dropped, scored ports, management, dependency flows stay, outbound stays in shadow (`net.shadow_drop` events appear, no `net.egress_denied`). Plant a scorer-like probe (the Kali sending Quotient-shaped checks) to an unrendered port: `firewall.allow_back` within seconds, the port open. Force a failure (kill the agent link before confirm): the dead-man rolls the policy back. Confirm no `out_mode: enforce` runs without the review gate click.
- [ ] **Step 2: T02 and T17.** Disable the host firewall with a timer: tier 0 (`respond`, W4) restores it; record latency. Cut the link during an enforce plan: the agent dead-man rolls back, the controller reconciles a fire that happened while connected (W2's fix).
- [ ] **Step 3: T05, T06, T62, T67.** With default-deny egress on `rocky-ecom` and `win11`, run an implant callback (Linux binary, Windows service): `D12` fires with owner and hash (5157 on Windows); `egress.candidate` ranks the new binary first; a sleep-masked Mythic and Cobalt Strike beacon (campaign 07) is detected through denied egress and the per-executable allowlist (`D4c`, W4); the "block this?" proposals appear and nothing blocks until a click. Record detection rate and latency.
- [ ] **Step 4: T13 and T44.** Add a Palo rule as a second admin: `D14` fires, latency reported. Run the safe-change protocol on the licensed PAN-OS VM and the VyOS image: failed health rolls back, a foreign pending change blocks the node, the soft-revert timer fires when the connection is lost, a red scorer-mimic probe reverts the commit (bug 20 on real devices). Record whether `commit-confirm action reload` exists on VyOS 1.4.0 and what the Palo capture parameter set needs (stages, limits).
- [ ] **Step 5: Capture on a real NIC.** Run `capture` under load on `rocky-ecom` (drop counts, ring sizing against `MemoryMax`, CPU against the budget, VLAN or bonded interface if available); run the freeze end to end: a controller-scope `D13e` scan raises `freeze_capture`, the evidence pcap is pulled by `fetch` (needs W11's `fetch` handler; mark as not run if absent). Check the source-address check against the real Palo (does it NAT inbound sources?).
- [ ] **Step 6: Conntrack and quarantine.** Hold an SSH session open from the Kali, block its address with `fw.apply op: block`: the session dies, a scored-port flow from the same address does not (with `ports: non_scored`). Quarantine a scored host: scored ports and dependencies stay up, a scorer check in flight is not cut, the revert fires after 10 minutes.
- [ ] **Step 7: Record and commit.** Write the results to `docs/impl/lab/w6-network.md`. `git commit -m "lab: W6 network results"`.

---

## Self-review

**1. Spec coverage** (module sections, all four, part by part):

- `firewall` part 2 table: nft translate/apply/snapshot/restore/drift built and kept (Task 6, 9, 12); registered `fw.apply`, `fw.snapshot`, `fw.restore`, `fw.quarantine` (Tasks 9, 10); conntrack flush (8); `fw.quarantine` (10); source blocks (5, 10); Windows shadow evaluation is `net` work (W3), `fw.apply` Windows shadow is a no-op with a shortcut (9); would-drop summarizer (14); periodic drift (12); `firewall.allow` and `win.firewall` (2). Part 4 settings and block (4, 11); part 5 events (1, 12-14); part 6 inbound auto, allow-back, scored allow-any-source, blocks, shadow groups, apply protocol, quarantine, restore, drift, stage 0 (5, 6, 9-13, 15); part 8 UI page, grid column and tile: **not planned** (the UI registrar is W1; the `/firewall` page, the grid column `firewall applied` and the Overview tile are one follow-up task for whoever owns the Traffic and Platform pages, W10; recorded in the report); part 9 health (12); part 11 tests (each task); part 12 Docker forward chain and Rocky coexistence are open items, untouched.
- `egress`: config, sinkhole bug 12 (4, 6, 16), allow table (17), ranking (18), suggestions (19), `D4c` and `D13c` (W4, noted), sinkhole decision (W13), patch window (deferred, deviation 11), Traffic page folding (W10).
- `capture`: kinds and `conn` (20), settings and role/Windows (21), bug 19 (22), TFTP/NTP (23, 24), bug 13 (4, 21, 25), bug 7 (26), source check (27), rules move (28), `fetch` (W11), seal distribution (open, shortcut in 21).
- `devices`: module (29), pollers and `D14` (30), deny/traffic (31), probe bug 20 (32), rotate, revert, licence (33), backups and `ftd.export` (34), capture and audit (35), manifest block and T+0 checklist rows (Task 4 for the block; checklist rows are core Enrollment, W12).
- Core: `internal/actions` imports no module (Tasks 1-3, guard test); Known bugs 7, 12, 13, 14, 19, 20 each have a failing-first test (26, 4/6/16, 4/25, 6, 22, 32). T65 entries for these six live in those tests; the W3-side half of bug 14 (`net` never reads a shadow record as `egress_denied`) is W3's.

**2. Step scan.** Every step names its file, signature and test; no "TBD". Test bodies that are comments describe fixture setup the implementer writes from the named helper (`harness`, `testEnv`, `moduleWithPalo`, `deviceEnv`, `storetest.New`); the seams task creates each helper listed in the skipped test files.

**3. Type consistency.** `Backend` (Task 2) is used by 9, 10, 13; `applyPolicy` (9) by 10 and 13; `Verdict`, `Flow`, `Conntrack` (8) by 9, 10, 13 and the quarantine test; `BlockSpec` (5) by 10 and 11; `AppliedEvent`, `AllowBackEvent`, `QuarantineEvent`, `ShadowSummaryEvent` (1) by 9, 10, 12-14; `CaptureSettings` (1) by 21, 25; `Directory` (3) by 29-35; `probeExtra` only in 32. Names in the lab task match.

**4. Review Focus.** Five lines, each with a named test in the owning task (5, 8, 13, 32, 26).

**5. Proportion.** The plan is about a fifth the size of the four module sections it implements; no function body is transcribed.

**What I did not check:** whether `internal/store` seals a chain the way `storetest.New` needs (Task 1 Step 4 settles it), whether `palotest` can express the commit-log and licence options Tasks 30, 33 and 35 assume (they extend the existing fake), and whether W1's static check reads test-file imports (the two tests that load `detect` are flagged for `internal/e2e` if it does).
