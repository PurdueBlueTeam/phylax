#### `content_guard`

An opt-in agent module that restores declared scored content and boot-critical files from golden copies, under six safety constraints, and starts alert-only. It is new in v4; v3 had no such module.

**1. Purpose and evidence**

- **What it does.** The scorer compares service content every round: web pages against regexes, SMB SOP files, FTP files, DNS A records. A defacement fails the check until a human acts. The guard watches only files the manifest lists by path, and when one changes outside our own work it alerts, then (once switched to act) restores the golden copy and proves the service still passes.
- **Evidence.** EKU's Tyr restored content automatically and the team cites it as a competitor feature [[malfindor-eku-ccdc#e5]], [[malfindor-eku-ccdc#e8]] (single-team evidence, so the module is opt-in and starts alert-only). Red deleted `/etc/fstab` and rebooted mail servers [[how-to-win-ccdc-dealing-with-red-team#e2]] and razed boxes on day 2 [[how-to-win-ccdc-dealing-with-red-team#e3]]: a host that will not boot is a total outage and recovery costs points, which is the boot-critical watchlist (review N5.6). Parts already exist in the code base: file-change events, golden backups, probes and the respond guards.
- **Evidence against and tension with D-1.** D-1 bars automatic restore for binaries because a ledger can be incomplete and a restore can destroy evidence. Content is different: the golden copy is exact, the declared list is short and the scorer demands it. The guard never touches binaries; those are `integrity`. It can also fight an inject that asks us to change the same content, so it is off by default per service and exempts plan-tagged changes (review A4.Q1).
- **Decisions applied.** Review N4.1 and A4.Q1, A4.Q3 (the six constraints), N5.6 merged here (A5.Q3).

**2. Status and code**

Status: **missing**. No code. Parts it will use: `file_change` events from `audit` and `winevt` (with writer pid, exe and auid, and `tag`), the lock and tag framework (`internal/actions/lock.go`, `tag.go`), the scoring guard (`guard.go`), `file.hash`, `file.restore`, `file.quarantine`, the `net.http_probe` and `net.tcp_probe` actions, and the controller's scorer-mimic probe (`checks`).

To build: the golden store, the watch loop, the restore sequence with its probe and rollback, the loop stop, the `guard.snapshot` and `guard.restore` actions, the per-service switch, and the boot-critical default list.

**3. Capability manifest**

| Field | Value |
| --- | --- |
| Name | `content_guard` |
| Sides | agent |
| OS | both |
| Privilege | root |
| Roles | any host with a service that declares `content.guard` paths, or any host that enables the boot-critical list |
| Consumes | `file_change`, `process_start` (to see a service restart after a restore), `telemetry_gap` |
| Emits | `content_guard.change` (schema 1, high), `content_guard.restore` (schema 1, high), `content_guard.stop` (schema 1, critical) |
| Budget | CPU 2 ms/s, held 8 MB (hash index of guarded paths), 1 event/s, burst 10, 20 KB/min out, disk 64 MB (golden copies of declared files; large content roots are not copied, only the listed files) |
| Default | opt-in, per service (the service's `content.guard` list) and per host (the boot-critical list) |
| Tables | none |
| Content | `plans/hardening/guard.snapshot.yaml` (the plan node that takes golden copies), `rules/respond/boot_critical.yml` (default boot-critical list per OS) |
| Actions | `guard.snapshot` (service risk; locks `content:<service>`; touches the listed paths read-only), `guard.restore` (service risk; locks `content:<service>` and the service lock; touches the listed path; declared scored content) |
| Pages | Content guard (state per service and per file) |
| Evidence | [[malfindor-eku-ccdc#e5]], [[malfindor-eku-ccdc#e8]], [[how-to-win-ccdc-dealing-with-red-team#e2]], [[how-to-win-ccdc-dealing-with-red-team#e3]] |

**4. Configuration**

```yaml
# manifest/services.yml (per service; the list lives with the service, not the module)
services:
  ecom-http:
    content:
      roots: [/var/www/html]
      guard: [/var/www/html/index.php]      # constraint 1: only files listed by path
# manifest/modules/content_guard.yml
content_guard:
  mode: alert                  # alert | act, per service in the map below; default alert for every service
  services: { ecom-http: alert }
  boot_critical:
    enabled: false             # per host in hosts.yml; the defaults are the OS lists below
    mode: alert
  loop: { count: 2, window: 10m }     # constraint 5: the second restore of the same file within 10 minutes stops and alerts
  probe_timeout: 30s
```

```go
// package plan (new)
type ContentGuardSettings struct {
	ModuleLimits
	Services     []GuardService `json:"services"`
	BootCritical GuardBoot      `json:"boot_critical"`
	LoopCount    int            `json:"loop_count,omitempty"`      // default 2
	LoopWindowSec int           `json:"loop_window_sec,omitempty"` // default 600
}
type GuardService struct {
	Name  string   `json:"name"`
	Paths []string `json:"paths"`             // services.yml content.guard, nothing else
	Mode  string   `json:"mode"`              // "alert" (default) or "act"
	Probe string   `json:"probe,omitempty"`   // the service's scorer-mimic probe name
	Lock  string   `json:"lock,omitempty"`    // service lock to respect
}
type GuardBoot struct {
	Enabled bool     `json:"enabled"`
	Mode    string   `json:"mode"`
	Paths   []string `json:"paths,omitempty"` // OS defaults when empty
}
```

**5. Events**

Consumed: `file_change` (path, op, writer fields, `tag`, `sha256`), `process_start` and `telemetry_gap` (a file-watch gap means a guarded path is unwatched and the guard falls back to the hash sweep).

Emitted:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `content_guard.change` | 1 | high | `service`, `path`, `op`, `golden_sha256`, `current_sha256`, `writer` (pid, exe, auid), `mode`, `decision` (`alert`, `restore`, `ignored_tag`, `ignored_plan_lock`) |
| `content_guard.restore` | 1 | high | `service`, `path`, `golden_sha256`, `probe` (before and after results), `result` (`restored`, `rolled_back`, `probe_failed`) |
| `content_guard.stop` | 1 | critical | `service`, `path`, `reason` (`loop`, `probe_failed`, `golden_missing`), `count` |

**6. Behaviour**

The six constraints (review A4.Q3) are the whole behaviour:

1. **Only files listed by path in `services.yml`.** The guard has no glob and no directory watch of its own; the list is `content.guard`. Roots are for other modules. A path that is not on the list is never read or written by this module.
2. **Restore only from the plan-tagged golden copy.** A golden copy is written by the `guard.snapshot` action, which runs as a node of a plan, so it carries the plan id and the file hash at the time. Hardening plans end with a `guard.snapshot` node for each service they touched, after the node's scorer-mimic probe passed and the host's ledger sweep and hunt are clean. Golden copies live in `StateDir/content_guard/golden/<sha256>` with an index of path, hash, plan tag and time. There is no other source of restore data. If the file is not in the index the guard emits `content_guard.stop` with `golden_missing` and does nothing else.
3. **Ignore changes under a plan tag, or while a plan holds the service lock.** A `file_change` with a non-empty `Tag` is ignored (decision `ignored_tag`), as is any change that arrives while the service's lock is held (`ignored_plan_lock`). This is what makes the guard coexist with injects: an inject change made by hand through a `phylax claim` work window is tagged and is not fought. After the tagged change, the operator takes a new snapshot (the grid shows the guard column amber until they do).
4. **A scorer-mimic probe after each restore.** `guard.restore` runs the service's probe before and after, using the same bounded probe as any plan node (one retry after 5 s, then fail). If the probe fails after the restore, the guard rolls its own restore back (it keeps the replaced file as the rollback data), emits `content_guard.restore` with `probe_failed` and alerts. A failed "before" probe (the service is already down) does not stop the restore, since restoring content is the point, but the result is recorded.
5. **The second restore of the same file within 10 minutes stops and alerts.** The count is per file, 2 in 10 minutes. After it, the guard stops acting on that file (`content_guard.stop` with `loop`) until an operator clears it, because a second restore means someone or something is writing back, and fighting it hides the cause. This pairs with `respond`'s loop detection, which opens a targeted hunt on the lineage.
6. **Starts alert-only per service.** Every service is `mode: alert` until the manifest switches that service to `act`. In alert mode a change emits `content_guard.change` and the Content guard page offers the restore as a one-click button (the plan node `guard.restore`); in act mode the same restore runs locally, in seconds, with the link down.

Other rules of the module:

- **Detecting the change.** The primary signal is the `file_change` event (audit or Sysmon), and the source of truth is a periodic hash of each listed path (the same hash-sweep principle as `audit`). The sweep covers a missed event and a watch gap.
- **A restore is `guard.restore`,** an agent action with the full action contract (Plan, Capture, Apply, Verify). It writes atomically with owner, mode, xattrs and SELinux label copied from the golden entry. It does not delete anything; a listed file that was deleted is restored, a file that appears but was not listed is ignored.
- **A restore is declared scored-content access.** The scoring-safety lint says scored content is untouched; the guard's restore is the one explicit exception (core anti-goals). The lint allows `guard.restore` only for paths on the service's own `content.guard` list, and only when the module is in act mode or a human approved the proposal.
- **Boot-critical watchlist (review N5.6, merged here).** A second list the guard watches per host, defaults per OS, mode alert unless the host enables `act`:

  | OS | Default list |
  | --- | --- |
  | Linux | `/etc/fstab`, `/boot/grub*/grub.cfg` (and `/boot/efi/EFI/*/grub.cfg`), the initramfs image for the running kernel, `/etc/ssh/sshd_config`, the host's network config (`/etc/netplan/*`, `/etc/NetworkManager/system-connections/*`, `/etc/sysconfig/network-scripts/*`, `/etc/systemd/network/*`), `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers` |
  | Windows | the BCD store (`\Boot\BCD`), `boot.ini`-style files where present, the DC's `ntds.dit` is excluded (it is locked and backed up by the `backup` module) |

  `/etc/passwd`, `/etc/shadow`, `/etc/group` and `/etc/sudoers` are watched but **never restored automatically**, even in act mode: scored passwords change only through the PCR transaction on the host, and a restore of an account database could silently revert one (decision on scored passwords, core lint). A change to them alerts (D7a, D7b) and the restore is a one-click proposal. A boot-critical golden copy must be taken after the host's last account change; the plans that change accounts end with the snapshot node.
- **Windows BCD** is restored with the pre-approved `bcdedit /import` (`host.exec`), because BCD is a registry hive file that is held open. `shortcut` below.
- **Off-box copy.** The boot-critical files are also copied to the controller by the `backup` module's golden backup, so a host that no longer boots can be repaired from the console; the guard's local golden copy is for a running host.

**7. Actions and content**

| Action | Risk | Locks | Scorer-visible touches | What it does |
| --- | --- | --- | --- | --- |
| `guard.snapshot` | service | `content:<service>` | reads the listed paths | Copies each listed file into the golden store with its hash, owner, mode, xattrs, SELinux label and the plan tag; refuses a path not on the service's list; verifies by re-hashing |
| `guard.restore` | service | `content:<service>`, the service lock | modifies the listed path (scored content, the lint exception) | Probe, atomic write of the golden copy, probe again; rolls back to the replaced file on a failed probe |

Content: the `guard.snapshot` plan node appended to every service hardening plan (`plans/hardening/`), and the default boot-critical lists in `rules/respond/boot_critical.yml`. A tier-0 recipe `content_restore` in `respond` is not needed: the guard is its own tier-0 mechanism and does not go through `respond`, so the two cannot loop each other (they both honour the same file-change tags and locks).

**8. UI**

The Content guard page lists each guarded file: golden hash, current hash, mode, last change, last restore, probe result, and the one-click restore and clear-loop buttons. Host-grid column: "content guarded" (verified when every listed file matches its golden copy; amber when a snapshot is stale after a tagged change; failed on a `content_guard.stop`). Overview tile: files guarded, changes in the last hour, stops open.

**9. Health**

`ok` when every listed file is watched and its golden copy exists. `degraded` when a path is on the list but has no golden copy, or a watch gap forces the sweep-only fallback (the gap is named), or when the golden store is over its disk budget. `unavailable` on a host with no listed paths. Detail: files guarded per service, mode per service, loops open.

**10. Scoring safety**

- Restoring scored content is the highest-risk automatic action in the platform, so it carries all six constraints, starts alert-only and is opt-in per service.
- It touches only files whose content the scorer already expects (the golden copy is exactly what passed the probe when it was taken).
- Never a binary, never a configuration file the manifest does not list, never an account database automatically, never a directory.
- The probe after the restore is the circuit breaker; a failed probe rolls the restore back, so a restore can never leave a service worse than the defaced state without an alert.
- The loop stop prevents the guard from fighting an inject or an attacker.
- Alert-only first: the Invitational runs the guard in alert mode on every scored server (tier A). Act mode is allowed on one scored server in the second half and elsewhere only after a lab run in which a planted defacement was restored and the probe passed.

**11. Tests**

- Unit: constraint 1 (an unlisted path is ignored), constraint 2 (no golden entry: stop), constraint 3 (tagged change and held lock ignored), constraint 4 (a golden copy that makes the probe fail is rolled back; use the `test.failverify` action), constraint 5 (second restore in 10 minutes stops), constraint 6 (alert mode emits and does not write), atomic write preserving labels (SELinux image test), the account-database exclusion from act, a missed event caught by the sweep.
- Fixture: a recorded `file_change` stream including a plan-tagged change, a work-window change and an untagged deface.
- Conformance: starts with no config, rejects unknown fields, survives link loss, reconfiguration keeps the golden index, `go test -race`.
- Lab: a planted defacement of the OpenCart index and of an SMB SOP file (the scorer's regex fails, then passes after restore), a `rm` of `/etc/fstab` on a lab VM (restored in act mode, proposal in alert mode), and a hand edit under a `phylax claim` window (ignored). T16 (a forced change breaking a scored page is caught by the probe) covers the rollback.

**12. Limits and open items**

- `shortcut: the Windows BCD restore uses host.exec of bcdedit /import, upgrade to a native BCD hive write only if a lab run shows bcdedit fails on a DC.`
- `shortcut: guarded files are copied whole into the golden store, so a very large listed file costs disk; upgrade to a chunked, deduplicated store if a service lists files above a few hundred MB.`
- Open: where the golden copy is held. This section keeps it in the agent's own state directory so the guard works with the link down, written only by plan-tagged `guard.snapshot`. The `backup` module's golden backup is a separate copy on the controller. Recommendation: keep them separate, and let a golden backup restore push a fresh snapshot through a plan node, so no module reads another's files.
- Open: how the lint allows `guard.restore` as the one scored-content write. Recommendation: the action declares a `Restore` touch kind that the guard accepts only for paths on a service's `content.guard` list.
- Core changes: `Touch` gains a restore marker for the lint exception; `Modules.ContentGuard` in the signed config; `content.guard` is already in the `services.yml` reference example.
