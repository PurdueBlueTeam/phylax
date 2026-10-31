#### `devices`

**1. Purpose and evidence.**

The `devices` module manages the network devices in the path of the scored services, agentlessly, from the controller: the Palo Alto firewall (PAN-OS XML API) and the VyOS router (SSH for changes, HTTP for reads). It owns one safe-change protocol that every device change goes through, drift detection with the tamper rule `D14`, deny-log and traffic-log pulls, scheduled config backups, an on-demand Palo-side packet capture, admin credential rotation after first contact, and a read-only config export for a Cisco FTD if one appears.

Evidence that it matters for points:

- The network is the scored path: every service reaches the scorer through VyOS and the Palo (core: topology). A lockout there is the worst self-inflicted outage, so the adapter exposes primitives and one runner owns the protocol [DA §4] (review D18, D170).
- PAN-OS has no commit-confirm, and VyOS's `commit-confirm` reboots the router into the saved config while its HTTP API commits immediately and cannot roll back [DA §0]. So each device needs its own revert mechanism, and the runner refuses a lockout-class change on a device without one unless the Network role confirms the console is ready (review D409, D410).
- Default credentials are public and the red team knows them (`admin:Changeme123` for the Palo, `vyos:vyos` for VyOS) [PKT §2]. The unpatched PAN-OS 11.0.2 is on the first-hour list: management lockdown to the controller's address [SV R2.4], and its software version matches known exploited PAN-OS vulnerabilities (CVE-2024-3400, CVE-2024-0012 and CVE-2024-9474, CVE-2026-0257) [[known-exploited-vulnerabilities#e1]], [[vulns-network]] (review D524).
- Device tampering by red (a commit we did not make, an unknown admin, an allow above a block, a new role or API key) is a detection (`D14`); the adapter diff and the Palo config log are the evidence (review D334).
- Palo deny logs cover hosts whose agent is dead or whose host firewall an implant disabled (review D219).
- TOOL26T asked for a `TeamXX-CF` export from `show access-control-config`, so a Firepower existed in 2026 (injects report #7); SOFT08T [[soft08t]] asked for a firewall backup (review D417, N6.1).
- The Palo's packet capture settles "is the scorer even getting through?" without guessing; David finds it interesting and it stays, gated on the device's licence and capability flag (review D244, area 6 answer).

**2. Status and code.**

Status: partial. The adapters and the safe-change runner are built and tested against stateful fakes. No test contacts a real device (`docs/devices.md`). The controller-side pollers, rule `D14`, rotation, backups and capture are not built.

| Piece | State | Where |
| --- | --- | --- |
| `Adapter` and `Tx` interfaces, capability flags, `SafeChange` runner (lockout refusal without a dead-man or console ack; undo on a context that ignores cancellation; granular rollback with snapshot fallback; health bounded to 3/4 of the dead-man) | built | `internal/devices/{devices,runner,diff}.go` |
| PAN-OS XML client (form POST, `X-PAN-KEY`, bounded responses, job polls with deadlines), adapter, `Tx` | built | `internal/devices/palo`, `palo/xmlapi`, `palo/tx.go`, `palo/translate.go` |
| VyOS adapter (HTTP reads; SSH with a pinned host key, one new connection per call; soft-revert timer) | built | `internal/devices/vyos` |
| Manifest rendering of device intent (`render.PaloIntent`, `render.VyOSIntent`, `Adapter.Translate`) | built | `internal/manifest/render/devices.go` |
| Controller-side execution, device directory and pooled adapters, vault-backed credentials | built | `internal/controller/{devexec_run,dir_devices}.go` |
| Actions `palo.permitted_ips`, `palo.commit`, `palo.apply`, `palo.snapshot`, `vyos.snapshot`, `vyos.apply` | built | `internal/actions/dev_actions.go` |
| First-hour plans `palo.mgmt_lockdown` and `net.vyos_review` | built | `plans/first-hour/` |
| Actions `palo.revert`, `device.rotate_admin`; `Adapter.RotateAdmin` | missing | |
| Drift pollers (system info, jobs, logs, running-config hash) emitting `devices.config`; rule `D14` | missing (the adapter's `Drift` and `Events` exist; nothing calls them from the controller) | |
| Palo deny-log pull (`devices.deny`) and traffic-log pull (`devices.traffic`) | missing | |
| Licence-aware gating | missing (the adapter does not read the licence) | |
| Scheduled config backups | missing | |
| Palo-side packet capture (`Adapter.Capture`) | missing; the interface keeps the method | |
| FTD read-only export | missing | |
| Scorer-mimic probes in the health callback | hook only: `Adapter.HealthCheck(flows, extra)` takes an `extra` function and callers pass `nil` | |

**3. Capability manifest.**

```go
module.Manifest{
	Name:      "devices",
	Sides:     []module.Side{module.SideController},
	OS:        nil,
	Privilege: "none",
	Roles:     []string{"controller"},        // plus device_proxy hosts as transports
	Consumes:  nil,                            // polls devices; reads no events
	Emits:     []event.Type{ /* part 5 */ },
	Budget: module.Budget{CPUMillisPerSec: 20, HeldMB: 32, EventsPerSec: 5, Burst: 50,
		BytesOutPerMin: 262144, DiskMB: 200},
	Default:  true,  // when devices.yml declares devices; otherwise disabled
	Tables:   []string{"device_snapshot", "device_backup"},
	Content:  []string{"plans/first-hour", "plans/devices", "rules/devices"},
	Actions:  []string{"palo.apply", "palo.commit", "palo.permitted_ips", "palo.snapshot", "palo.revert", "palo.capture", "vyos.apply", "vyos.snapshot", "device.rotate_admin", "device.backup", "ftd.export"},
	Pages:    []string{"/devices"},
	Evidence: []string{"known-exploited-vulnerabilities#e1", "soft08t"},
}
```

Numbers are starting caps: the module is poll-driven and idle between polls. Disk holds the last-good snapshots and backups (encrypted configs).

**4. Configuration.**

`devices.yml` stays the device inventory (the topology file set; Manifest), and `modules/devices.yml` holds behaviour.

```yaml
# manifest/devices.yml (inventory)
devices:
  palo1: { vendor: panos, mgmt: 172.20.240.200, segment: lan }
  vyos1: { vendor: vyos,  mgmt: 172.16.0.254, segment: lan, via: palo1, external_ip: "172.31.{{ 20 + team }}.2" }
  # fields in code: vendor (panos | vyos | ftd), mgmt, segment, via, external_ip, ports, adapter, proxy
```

```yaml
# manifest/modules/devices.yml
devices:
  account: phylax                  # the dedicated API account; secret at creds.VaultKey(device, account)
  deadman: 90s                     # soft-revert timer on VyOS; default for lockout-class changes
  lock_wait: 0s                    # 0 fails fast on a foreign lock
  poll:                            # drift and log pulls (Palo)
    system_info: 10s
    jobs: 15s
    logs: 30s                      # config, system and traffic logs; also the deny-log pull
    config_hash: 5m                # running-config hash against the last known-good
  deny_log: { enabled: true }      # D219: outbound deny entries for the egress module
  traffic_log: { first_minutes: 15, on_demand: true }   # inbound session sources (capture source check)
  backup:
    every: 30m                     # and after every confirmed change
    keep: 48
    targets: [ubuntu-wkst]         # declared hosts, over SSH; uses the controller backup targets by default
  capture:                         # Palo-side packet capture
    enabled: false                 # on only after the licence and capability check passes
    max_seconds: 120
    max_bytes: 104857600
  audit:
    kev_check: true               # emit devices.version for the vuln module
    mgmt_profiles: true           # interface management profiles
    globalprotect: true
```

```go
type Config struct {
	Account    string        `yaml:"account"`
	Deadman    time.Duration `yaml:"deadman"`
	LockWait   time.Duration `yaml:"lock_wait"`
	Poll       struct{ SystemInfo, Jobs, Logs, ConfigHash time.Duration } `yaml:"poll"`
	DenyLog    struct{ Enabled bool } `yaml:"deny_log"`
	TrafficLog struct {
		FirstMinutes int  `yaml:"first_minutes"`
		OnDemand     bool `yaml:"on_demand"`
	} `yaml:"traffic_log"`
	Backup struct {
		Every   time.Duration `yaml:"every"`
		Keep    int           `yaml:"keep"`
		Targets []string      `yaml:"targets"`
	} `yaml:"backup"`
	Capture struct {
		Enabled    bool          `yaml:"enabled"`
		MaxSeconds int           `yaml:"max_seconds"`
		MaxBytes   int64         `yaml:"max_bytes"`
	} `yaml:"capture"`
	Audit struct{ KEVCheck, MgmtProfiles, GlobalProtect bool } `yaml:"audit"`
}
```

Device credentials are in the vault and are generated at competition time. They are never in the manifest.

**5. Events.**

Consumed: none. The module polls the devices; our own commits are told from foreign ones by the transaction window and actor (`ours`), not by an event.

Emitted:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `devices.config` | 1 | high | `device`, `change` (`diff`, `commit`, `login`, `login_fail`, `lock`, `admin_add`, `admin_del`, `key_change`, `oob`, `pending`), `actor`, `src_ip`, `detail`, `path`, `ours` (true only inside our own Tx window and matching our actor), `tag` (plan id when ours), `when` |
| `devices.change` | 1 | high | `device`, `plan`, `node`, `scope` (`policy`, `management`), `risk`, `before_hash`, `after_hash`, `rolled_back`, `tainted[]`, `commit` (job id, warnings) |
| `devices.deny` | 1 | normal | one outbound deny entry from the Palo traffic log: `device`, `src`, `dst`, `dport`, `proto`, `app`, `rule`, `when` |
| `devices.traffic` | 1 | normal | inbound session entries for scored services during the check window: `device`, `src`, `dst`, `dport`, `nat_src`, `nat_dst`, `rule`, `when` |
| `devices.backup` | 1 | normal | `device`, `hash`, `size`, `targets[]`, `listed_at`, `error` |
| `devices.version` | 1 | normal | `device`, `vendor`, `version`, `serial`, `licence` (feature flags), for the `vuln` module's KEV match |
| `devices.finding` | 1 | high | `device`, `kind` (`mgmt_profile_open`, `globalprotect_exposed`, `default_admin`, `permitted_ip_any`), `detail` |
| `devices.capture` | 1 | high | `device`, `filter`, `stage`, `path`, `bytes`, `sha256`, `error` |

**6. Behaviour.**

*The adapter.* The adapter exposes primitives and the controller owns the protocol, so the same runner works for every device [DA §4]:

```go
type Adapter interface {
	Kind() Kind; Caps() Caps; Close() error
	Info(ctx) (Info, error)               // liveness, version, clock, licence
	Probe(ctx) error                      // fresh connection + auth + one read (the lockout canary)
	RotateAdmin(ctx, RotateSpec) (Creds, error)       // not built
	Snapshot(ctx, label) (Snapshot, error); Diff(ctx, a, b Snapshot) (Diff, error)
	Drift(ctx, lastGood Snapshot) (DriftReport, error)    // emits ConfigEvents for D14
	Begin(ctx, TxOptions) (Tx, error)     // Preflight, Lock, Stage, Pending, Validate, Commit, Confirm, Rollback, Close
	Admins(ctx) (AdminState, error); Events(ctx, EventFilter) ([]Event, Cursor, error)
	Capture(ctx, CaptureSpec) (Capture, error)         // kept per the area 6 answer; not built
}
```

The built interface has no `RotateAdmin`, `Capture` or `Facts` (the research proposal's `Facts` is dropped). Capability flags say what is native: config lock, scoped commit, staged diff, validate, native confirm, soft dead-man, rollback, connection events, audit log. `Capture` is gated on a further flag (`PacketCapture`, from the licence check), so an unlicensed device refuses it before any call. A lockout-risk transaction on a device with neither a soft dead-man nor a native confirm is refused until the Network role acknowledges that the console is ready (`ConsoleAck`).

*The runner.* `devices.SafeChange` runs: preflight, lock, snapshot, stage, pending check, validate, commit (with a dead-man where the device has one), a health callback on fresh connections, then confirm or roll back. A foreign pending change refuses the change. The undo runs on a context that ignores cancellation and falls back from granular rollback to restoring the snapshot. A `Tainted` Tx (a foreign change seen during the window) means the new snapshot is not trusted as last-known-good unseen.

*Palo Alto (PAN-OS 11.0.2).* Our own thin XML-API client (about 300 lines in the v3 estimate: form POST, `encoding/xml`, `X-PAN-KEY`, pinned TLS, context deadlines), because the maintained SDK lacks lock, commit and operational helpers and its tags cannot be fetched; typed rule CRUD may use the SDK behind our interface [DA §1.15]. It never issues a plain commit, only `commit partial admin`. Every address object, service, NAT entry and rule we create carries the `phylax-managed` tag, and `Stage` refuses to edit or delete an untagged item (`ErrNotManaged`). The safe-change protocol [DA §1.12]:

1. Preflight: system info, jobs idle, config and commit locks free, no foreign pending changes (journal entries by another admin, or any entry when the device names no admin and the path is not ours), running-config hash equals the last known-good.
2. Take the config lock; snapshot the running config and the prior XML of each touched path; save `phylax-pre-<id>.xml` on the device.
3. Stage the change (tagged); check that pending changes contain only our paths.
4. Validate (a full validation job) and refuse on failure.
5. Commit with an admin-scoped partial commit; poll to completion.
6. Health (`HealthCheck`): `test security-policy-match` for each scored flow (the action must be allow), a fresh-connection API call, and the scorer-mimic probes from the Kali and the LAN.
7. On pass: new last-known-good, a named saved copy, release the lock. On fail: granular revert (replay the prior XML recorded at Stage) and a second commit; if that fails, load the whole-config fallback. If the management path is lost, alert and use the console.

PAN-OS has no commit-confirm, so management-path edits (permitted IPs, management profiles, services, the API account) are their own commit, additive first and never combined with service rules: add the new permitted entry, commit, verify with a brand-new connection, then remove the old entry in a second commit. Palo management lockdown to the controller's address is first-hour mitigation #2 for the unpatched 11.0.2 [SV R2.4].

*VyOS (1.4).* HTTP API for reads (`/show`, `/retrieve`); SSH (`x/crypto/ssh`, pinned host key, one new connection per call) for changes. Commands are restricted to `set` and `delete` with plain words and balanced quotes. It never uses `commit-confirm`, `rollback N` or a reboot. The soft-revert protocol [DA §2.4]:

1. Preflight: latest commit equals last known, `compare` empty.
2. Save the running config to an archive file (`pre-<id>.boot` under `/config/archive/phylax`, not `/config/config.boot`).
3. Arm a `systemd-run --on-active=<T> --unit=phylax-revert sg vyattacfg -c 'vbash ... load pre; commit'` timer (90 s default).
4. Apply with a plain commit.
5. Health from a new connection: for the lockout class a fresh SSH and HTTPS probe, then scorer-mimic probes, interfaces and routes.
6. On pass: stop the timer, `save`, record the new last-known-good. On fail: run the revert and alert.

The config is not saved until the health check passes, so a surprise reboot returns to the previous boot config. `Close` deliberately leaves an armed timer, so a controller that dies mid-change is still covered. Lockout classes: `service ssh`, `service https`, `system login`, management-path interfaces, NAT and policy on the path to the controller, the default route. Off-box `commit-archive` records every commit (review D416). Whether `commit-confirm action reload` exists on the installed 1.4.0 image is a lab check; if it does, native confirm replaces the timer.

*Drift and tamper detection* (review D414, D334). The controller polls each Palo at the configured intervals (system info 10 s, jobs 15 s, logs 30 s, running-config hash every 5 minutes) [DA §1.13]. The adapter's `Drift` returns a canonical running-config hash, the config-log entries after the stored sequence, foreign locks and foreign pending changes, and emits `ConfigEvent`s. For VyOS: a sorted `show configuration commands` hash, commit-log signatures newer than the stored one, the `/config/config.boot` hash and `compare saved`. Each event is marked `ours` only inside our own Tx window and matching our actor, with the plan id as `tag`. Rule `D14` (content in `rules/devices/tamper.yml`, controller scope) fires on: a commit we did not make, an unknown admin login, an `allow` rule above a block rule, a new admin role or API key, and a diff against the last known-good that no plan explains. Licence-aware gating: the adapter reads the licence once (`Info`) and disables actions that need a missing subscription; the same flag gates `Capture`. Drift polls work through the device-proxy role when the controller cannot reach the device directly.

*Deny-log and traffic-log pulls.* Every 30 s the Palo adapter reads new traffic-log entries after a cursor. Outbound denies become `devices.deny` (covers hosts whose agent is dead or whose host firewall an implant disabled; consumed by `egress`). During the first `traffic_log.first_minutes` after enrolment, and on demand, inbound entries to the public pool become `devices.traffic` with the NAT-translated source, for `capture`'s source-address check (review D238). Cursors are kept per device and survive a controller restart.

*Reaching devices* (review D418, D419). The Palo's management is on the LAN. VyOS (`172.16.0.254`) is reached through the Palo with a rule from the controller. Device management access lists allow only the controller (or a device-proxy host). The relay or device-proxy role splices a fresh connection on `phylax/splice`; the device's TLS stays end to end. **First contact with a device stays manual**: change the admin password on the console in the first minutes (core: the T+0 console phase), then the adapter takes over with a dedicated API account (`account`, default `phylax`) whose secret is in the vault.

*Credentials after takeover* (review D170). `device.rotate_admin` rotates the dedicated account (and any other admin the operator selects) through the adapter's `RotateAdmin`, in a transaction with a fresh-connection probe, and writes the new value to the vault before the old one is retired. The T+0 console rotation of `admin` and `vyos` is not this action.

*Management lockdown plan* (review D524). `palo.mgmt_lockdown` (first-hour plan) stays additive: add the controller to `permitted-ip`, commit, probe with a new connection, remove the broad entry, commit. It is extended to audit interface management profiles and GlobalProtect: any interface in the untrust zone with a management profile that allows HTTP, HTTPS, SSH, ping beyond what the manifest declares, or an exposed GlobalProtect portal or gateway, raises a `devices.finding`. The `Info` software version is emitted as `devices.version` so the `vuln` module matches it to the KEV PAN-OS entries (the former KEV check merges into `vuln`). The VyOS review plan (`net.vyos_review`) takes a snapshot, saves `show configuration commands`, and rotates the `vyos` account.

*Scheduled config backups* (review N6.1). `device.backup` snapshots each device every `backup.every` and after every confirmed change, encrypts it with the same passphrase-derived key as the controller's state snapshots, keeps the last `keep` in the controller store, and copies it over SSH to the declared `targets`. A listing (hash, time, target, size) is shown on the page and is also the input for the `report` module's firewall-export generator (N10.5). The copy uses the SSH client already vendored; `shortcut: copy by piping to the target over SSH, no SFTP client; upgrade only if a target forbids shell commands`.

*Palo-side packet capture* (review D244, kept). The adapter turns on the Palo's packet capture for a chosen service and window with a filter (source, destination, port, protocol) and a stage (receive, firewall, transmit, drop), pulls the file through the API and stores it as evidence. This settles whether the scorer is getting through. It is used on demand only, never left running: PAN-OS packet capture has its own limits, depends on the licence and can load the firewall [DA §1.9]. It is refused unless `capture.enabled` and the device's capability flag allow it, is bounded by `max_seconds` and `max_bytes`, and the action is read-mostly (it creates a capture filter and removes it afterwards). The pcap can be handed to Suricata or Zeek like a host slice. `shortcut: capture stages and limits are not verified against the licensed PAN-OS VM; the lab (T44 follow-up) fixes the parameter set`.

*Cisco FTD.* No adapter (review D417; area 6 answer). `ftd.export` is a read-only action: over SSH to the FTD CLI it runs `show access-control-config` (and the other `show` commands a generator needs) and writes the output to an evidence file. It never changes the device. If a packet shows an FTD, the printed checklist and hand-taken snapshots remain the change path.

**7. Actions and content.**

| Action | Risk | Locks | Scorer-visible touches | Notes |
| --- | --- | --- | --- | --- |
| `palo.apply` (`scope: policy` or `management`, `remove_old`) | service (policy), lockout (management) | none (device protocol locks) | the scored flows in the rendered intent | Built. Needs console ack on PAN-OS. Health requires every scored flow to match an allow rule. |
| `palo.permitted_ips` | lockout | none | none | Built. `add`/`remove` lists; always followed by `palo.commit` and a fresh-connection probe in the plan. |
| `palo.commit` | none | none | none | Built. Commits only our admin's pending paths. |
| `palo.snapshot`, `vyos.snapshot` | none | none | none | Built. Canonical running config to an evidence file. |
| `palo.revert` | lockout | none | restores previous policy | Missing. Granular replay of the recorded XML, or load of the saved `phylax-pre-<id>.xml`. |
| `vyos.apply` (`scope`, `outbound_interface`) | lockout | none | the scored NAT and policy in the intent | Built. Soft-revert timer. |
| `palo.capture` | service | none | none (reads), loads the firewall | Missing. Gated. |
| `device.rotate_admin` | lockout | none | none | Missing. |
| `device.backup` | none | none | none | Missing. |
| `ftd.export` | none | none | none | Missing. |

Device actions run on the controller (`RunsController`) against an `Env` whose host is the device name; no signed step is issued (the controller is both ends) and the result is recorded unsigned. Their rollback is the device protocol's own, so the executor's dead-man is not armed.

Content: `plans/first-hour/palo.mgmt_lockdown.yaml`, `plans/first-hour/net.vyos_review.yaml`, `plans/devices/backup.yaml` (the scheduled backup), `plans/devices/kali_path.yaml` (the Kali-to-controller rule and static NAT, entered by the Network role at T+0 and then managed here), `rules/devices/tamper.yml` (`D14`). `D14` keeps its id; the dependency rules that reuse `D14` in `rules/deps.yml` are renumbered in the `deps` section (Known bug 2, review D334).

**8. UI.**

Page `/devices`: per device the kind, version, licence flags, link state, last drift poll, last-good hash and its age, the admin sessions and configured admins, drift events with `ours` marked, the audit findings, the backup listing with download, and the capture control when allowed. A device change shows its `devices.change` record with before/after hashes and the rollback result. Host x step grid: none (devices are not hosts); Overview tile: devices with drift or a failed last change. The T+0 checklist rows for the Palo and VyOS are rendered from the manifest (Enrollment).

**9. Health.**

- `ok`: every declared device reachable by the adapter's `Probe` and pollers current.
- `degraded`: a device unreachable over a fresh connection; the poll is late; a foreign pending change or lock is held; a licence flag is missing; backups failing.
- `error`: a change that rolled back and could not confirm the rollback; the management path to a device lost.
- Gaps: devices without a soft dead-man or native confirm (PAN-OS) are listed so the operator knows lockout-class changes need a console acknowledgement; hosts behind a device proxy that is down.

**10. Scoring safety.**

- The devices are on the scored path, so every change is guarded in order: the rendered intent is linted (scored services stay allow-any-source; the scored flows must still match allow; static NAT for scored services intact); the transaction takes a snapshot, a lock and a dead-man or console ack; the health callback checks policy match, a fresh connection and the scorer-mimic probes; failure undoes the change.
- Edits touch only `phylax-managed` items on the Palo. Management-path edits are additive and separate from service rules.
- The VyOS config is not saved until the health check passes, and the soft-revert timer outlives the controller.
- Backups, snapshots, drift polls, log pulls and `ftd.export` are read-only.
- Palo capture is on demand, bounded and gated; it is not run on a schedule.
- Alert-only stage: observe mode (the Invitational) runs the pollers, backups and snapshots only; no `palo.apply` or `vyos.apply` runs on a scored device until a plan is approved, and the first apply is on a non-scored rule set.

**11. Tests.**

- Built: `palotest` and `vyostest` are stateful fakes (PAN-OS candidate/running/journal/lock/jobs/config log/permitted-IP applied on new connections; a VyOS SSH server with a vbash interpreter, real firing timers and an HTTP API). They drive the adapter and runner tests: failed health rolls back, foreign pending changes block a node, the soft-revert timer fires when the connection is lost (T44's logic), additive management edits, granular and snapshot rollback, the lockout refusal without a dead-man. `dev_actions_test.go` and `devexec_test.go` cover the actions and the controller-side execution.
- To add: the pollers and `D14` fixtures (a commit by another admin, an unknown login, an allow above a block, a new API key, our own commit marked `ours`); deny and traffic pull cursors; backup round trip with encryption and a failing target; `RotateAdmin` with a probe; the licence gate; the Palo capture request builder against the fake; `ftd.export` against a fake CLI.
- Lab: T13 (Palo rule added by an extra admin raises `D14`), T44 against the licensed PAN-OS VM and a VyOS 1.4 image (its data plane is the largest unknown), the Palo inbound NAT question, and whether `commit-confirm action reload` exists.

**12. Limits and open items.**

- `shortcut: backups are copied by SSH piping, no SFTP; see part 6`.
- `shortcut: the Palo capture parameter set is unverified against a licensed VM; see part 6`.
- **Scorer-mimic probes in the health callback.** The v3 protocol runs them inside the transaction. The adapter's health hook takes an `extra` function and callers pass `nil`. The controller `Host` interface has no probe call, and modules do not import `checks`. Options: the executor passes a probe callback into controller-side actions, or the plan runs a `health.check` node after the device node and rolls back on failure (the device commit is then outside the Tx window). Needs a core decision; recommendation is the callback, so the revert stays inside the protocol.
- **Pollers, `D14`, rotation, `palo.revert`, backups, capture, licence gating** are all unbuilt (part 2); `D14` has no rule file in `rules/` today.
- **Adapter naming.** The core action table lists `palo.apply`, `palo.commit`, `palo.snapshot`, `palo.revert`, `vyos.apply`, `device.rotate_admin`. This section adds `palo.permitted_ips`, `palo.capture`, `vyos.snapshot`, `device.backup` and `ftd.export` (the first and third are built).
- **Event naming.** The adapter's `ConfigEvent` is documented as the source of `device_config` events; they are renamed `devices.config`.
- **VyOS `commit-confirm action reload`** on the 1.4.0 image is unknown until the lab.
- **A second Palo segment or a Palo behind the relay** works through the device-proxy transport; it has no end-to-end test (the relay itself has none either; core Testing).
- **Cisco FTD.** No adapter unless a packet shows an FTD with a change need; the export suffices for now.
