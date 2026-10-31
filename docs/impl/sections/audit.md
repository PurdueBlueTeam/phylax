#### `audit`

##### 1. Purpose and evidence

`audit` is the Linux process and file sensor. It reads the kernel audit subsystem over netlink, installs and guards Phylax's own audit rules, reassembles multi-record audit events into `process_start` and `file_change` events, reports every loss of events as a `telemetry_gap`, and runs a throttled hash sweep of the watched trees as the source of truth for file changes. v3 had two modules, `proc` and `fim`, with one row per OS each. In v4 they are split by source: `audit` is the Linux half of both, `winevt` is the Windows half. The event kinds stay the common ones (`process_start`, `file_change`), so one rule covers both operating systems.

Why it matters for points:

- Most detections start from a process start with full argv, parent and user (the D-rules in `detect`), and content tampering on a scored service is scored directly, so the file source has to be reliable (review D70, D72).
- The kernel records audit events even when the agent has just been killed, so edits to persistence paths and to the agent's own files are still reported after a restart [OA §5.6].
- A single audit record carries argv, cwd, exe, ppid, uid and tty atomically, which `/proc` polling cannot do for short-lived processes [OA §0.1, OA §4].
- The red team disables audit as part of defence evasion (rule D10 family), so the sensor has to notice its own blinding [OA §5.1]. UCF's RedBaron2 alerts when its own BPF program count drops (`misc/bpf.rs:125@85aae3f`); `audit` does the same with a hash of its loaded rules (review D91).

Evidence against alternatives, and the decision:

- Decision 7 and review D88: audit over netlink plus `sock_diag` is the chosen path. Falco as a second host sensor was rejected (SEMO, UCI): a second daemon and a second rule language. Only Falco's rule logic is ported, into `detect` content.
- Review D89 (proc connector cross-check) is cut. One exec source is the norm, and no peer cross-checks with a proc connector. The code never had it.
- Review D92 (optional eBPF exec sensor) is cut and A2.Q2 confirmed it. UCF RB2 needs BTF, goes blind without it (`main.rs:85-101`), is about 14k lines, and the red team built RB2-specific breaks [[ccdc-the-great-the-good-and-the-ok#e10]]. Elastic's eBPF probes fail on some kernels (its `EXCLUSIONS.md`). A kernel rootkit blinds audit and eBPF alike. Reopen only if the exec-storm load test (v3 T43: 50, 200 and 1000 execs per second; audit must keep 99% or more at 200 per second with every miss reported as a `telemetry_gap`) fails in the lab.

##### 2. Status and code

Status: built (code and unit tests; nothing lab-proven).

- `internal/collect/audit`: `module.go` (module, status, verify loop, gaps, rate limit), `config.go`, `rules.go` (persistence watch list, rule rendering, hashing, kernel rule classification), `guard.go` (install, verify, repair), `rawnl.go` (netlink reader, 16 MiB receive buffer), `assemble.go` and `handle.go` (reassembly and event building), `proctable.go` and `procenv.go` (`/proc` enrichment), `sweep.go` (hash sweep). Tests include a real-kernel test that runs in a container with only `AUDIT_CONTROL` and `AUDIT_READ` (`PHYLAX_AUDIT_DOCKER=1`).
- `internal/agent/mods/audit_linux.go`: the factory.
- Uses `go-libaudit`'s reassembler and sequence-gap detection.

Missing or different from the design:

- The heartbeat does not yet carry the rules hash. `Status` holds `RulesHash` and a verify loop emits `audit.rules_changed`, but nothing reads `Status()` into the heartbeat. Review D91 asked whether the v3 "audit status" block already covered this; it covers the status, not a hash that the controller can compare. Wiring `HealthReporter` fixes it (see Health).
- No audit rule for module loads (A2.Q3). The rule text is `detect` content, but the rule builder needs a place for it (see Behaviour).
- No filesystem-type check: unsupported filesystems (NFS, overlayfs, btrfs quirks) are not reported as a coverage gap yet (review D98).
- No `process_exit` events (see Events).
- Container awareness (N7.6) is partial: `cgroup` is on every `process_start`; nothing resolves it to a service.
- The `net_connect` kind and the `audit.rules_changed` kind are not yet declared with `event.Declare`.

##### 3. Capability manifest

```go
module.Manifest{
	Name:      "audit",
	Sides:     []module.Side{module.SideAgent},
	OS:        []string{"linux"},
	Privilege: "root", // CAP_AUDIT_CONTROL and CAP_AUDIT_READ in the initial namespaces
	Roles:     nil,    // any Linux host
	Consumes:  nil,
	Emits: []event.Type{ /* process_start v1, file_change v1, conn v1, telemetry_gap v1, audit.rules_changed v1 */ },
	Budget: module.Budget{
		CPUMillisPerSec: 150, HeldMB: 96, EventsPerSec: 2000, Burst: 4000,
		BytesOutPerMin: 24 << 20, DiskMB: 1,
	},
	Default:  true, // core-default
	Tables:   nil,
	Content:  nil, // the rule builder takes its path lists from config; detection rules are in `detect`
	Actions:  []string{"audit.rules", "audit.immutable"}, // registered by the core Logging action row; implemented against this module's rule set
	Pages:    nil, // sensor state shows on the Platform page
	Evidence: []string{"[[ccdc-the-great-the-good-and-the-ok#e10]]", "[OA §0.1]", "[OA §4]", "[OA §5.1]", "[OA §5.2]", "[OA §5.6]"},
}
```

`EventsPerSec` and `Burst` are the code's defaults (`RatePerSec` 2000, `Burst` 4000). The CPU, held-memory and bytes-out numbers are initial limits to be replaced by the first lab measurement (held memory is dominated by the process table, 16384 entries, the reader queue of 16384 records and one sweep snapshot of up to 200000 entries). `shortcut: budget numbers are estimates, replace with measured values after the first T43 and Invitational runs`.

`Actions`: `audit.rules` and `audit.immutable` are the core Logging actions from the execution engine's catalogue. `audit.rules` must use this module's rule set so that a plan change to audit rules and the guard do not fight (the guard repairs anything with a `phylax` key that is missing, and deletes stale `phylax`-keyed rules). That interaction is an open item.

##### 4. Configuration

`modules/audit.yml`, rendered per host into the signed agent config as `modules.audit` (`plan.AuditSettings`). A nil block disables the module. Unknown fields are an error.

```yaml
# modules/audit.yml
rate_per_sec: 2000        # emitted events per second; excess is dropped and reported as telemetry_gap{reason: rate_limited}
burst: 4000
web_roots: []             # service content roots and upload dirs; filled from services.yml per host; watched recursively and swept
service_binaries: []      # declared binaries of the host's services; watched like persistence paths; filled from services.yml
extra_watches: []         # additional persistence paths (files or directories)
net_rules: false          # add connect/accept audit rules (high volume); the controller turns it on for default-deny hosts
sweep_interval_sec: 300   # 0 means 300; negative disables
```

```go
// package plan (built)
type AuditSettings struct {
	ModuleLimits                       // RatePerSec, Burst
	WebRoots         []string `json:"web_roots,omitempty"`
	ServiceBinaries  []string `json:"service_binaries,omitempty"`
	ExtraWatches     []string `json:"extra_watches,omitempty"`
	NetRules         bool     `json:"net_rules,omitempty"`
	SweepIntervalSec int      `json:"sweep_interval_sec,omitempty"`
}
```

Values the factory fills itself: `ExcludePaths` is the module's `StateDir` (feedback-loop exclusion); `SelfPaths` is the agent binary and `StateDir`, watched under key `phylax_self`. The following stay at the code's defaults and are not in the signed config; they move into the block only if a lab run shows a need (ponytail: no speculative options):

| Setting | Default |
| --- | --- |
| mode (`auto`: multicast when auditd runs, else unicast) | auto |
| backlog limit | 8192 |
| verify interval | 10 s |
| sweep files per second, hash size limit, entries, depth, start delay | 400, 8 MiB, 200000, 8, 5 s |
| argv caps (args, bytes per arg, total bytes, paths per file event) | 512, 4096, 32768, 16 |
| reader queue | 16384 records |

##### 5. Events

Consumed: none.

Emitted (all with `Agent` set by the spool, `Schema` 1 unless noted):

| Kind | Priority | Key fields |
| --- | --- | --- |
| `process_start` (common) | high, normal when the exec failed | `pid`, `ppid`, `uid`, `gid`, `euid`, `egid`, `auid`, `ses`, `tty`, `comm`, `exe`, `image`, `exec_path`, `argv`, `argc`, `cmdline`, `argv_truncated`, `argv_incomplete`, `proctitle`, `cwd`, `syscall`, `success`, `exit`, `key`, `audit_serial`, `source: audit`, `boot_id`, `start_ticks`, `cgroup`, `env` (loader-injection variables only), `parent{pid, exe, comm, cmdline, start_ticks, live, unresolved}`, `pexe`, `pcomm` |
| `file_change` (common) | critical for audit-reported changes, high for sweep-found ones | audit: `op`, `path`, `old_path`, `paths`, `dirs`, `paths_truncated`, `self_tamper`, the identity fields above, `writer_cmdline`, `writer_start_ticks`. Sweep: `source: sweep`, `op` (`create`, `delete`, `modify`, `attr`), `path`, `content_changed`, `writer_known: false`, `size`, `mode`, `uid`, `gid`, `sha256`, `old_sha256`, `target`, `is_dir` |
| `conn` (common) | normal | only with `net_rules`: `family`, `addr`, `port`, `direction`, identity fields. Retrofit: the code emits this as `net_connect`; the old name is accepted as an alias for one release. `source: audit` separates it from the `net` module's socket-table events |
| `telemetry_gap` (common) | high | `source: audit`, `reason` (`sequence_gap`, `enobufs`, `queue_overflow`, `kernel_lost`, `rate_limited`, `sweep_overflow`), `count`, `count_exact`, `from`, `to` |
| `audit.rules_changed` | critical | `source`, `reason` (comma list of `audit_disabled`, `reader_displaced`, `rules_changed`, `never_rule`, `install_failed`), `expected_hash`, `actual_hash`, `missing`, `missing_count`, `stale_count`, `repaired`, `never_rules`, `failed_count`, `failed`, and when known `enabled`, `audit_pid`, `lost`, `backlog` |

Priority notes: file changes under the watch rules are critical because content and persistence tampering is the most scored class. `process_start` is high because `detect` wants it immediately. Both fit the common-kind schema, so the Windows module emits the same field names where the data exists (`exe`, `cmdline`, `pid`, `ppid`, `pexe`, `pcomm`).

`process_exit` is not emitted (see Limits).

##### 6. Behaviour

**Reader.** The module opens the audit control socket (it needs `CAP_AUDIT_CONTROL` in the initial namespaces) and a separate reader socket. Mode `auto` chooses multicast when auditd is running (its pid is registered and alive), which leaves auditd running; this matters because RHEL-family hosts refuse manual auditd stops and Splunk may read `audit.log`. With no auditd, or a kernel older than 3.16, the module takes the unicast role and becomes the audit pid. A unicast request while another reader is registered is an error. The audit pid and failure mode are only touched when the module may manage settings.

**Sized on purpose.** Backlog 8192 to start (raised only if the kernel's is lower; a locked configuration is not fatal), failure mode `log` (never panic), a 16 MiB socket receive buffer, and a dedicated reader goroutine that copies each record into a bounded queue and never blocks on I/O [OA §5.1]. A full queue drops the record and counts `queue_overflow`. `ENOBUFS` from the socket records `enobufs`. Records outside 1300-1399 (control replies, user-space and SELinux/AVC records) are ignored.

**Reassembly and caps.** `go-libaudit`'s reassembler joins the records of one event (2048 in flight, 2 s). `SYSCALL`, `EXECVE`, `CWD`, `PATH` and `PROCTITLE` records become one `process_start` or `file_change`. An argv over the caps is truncated and flagged; an event whose argv is incomplete falls back to `proctitle`.

**Process identity.** A process is identified by `(pid, start_ticks, boot_id)`. On every exec event the module reads `/proc/<pid>` at once (cgroup, `exe`, command line, start time) and treats the audit record as authoritative if the read fails or if `/proc` now shows a different image (a reused pid keeps only live identity ticks, never the image fields). Parents resolve from `/proc` at event time, else from a table of earlier exec events: exited entries live for 2 minutes (at most 16384) so late children still resolve their parents. For a successful exec, only the loader-injection environment variables (the `LD_*` family; `procenv.go`) are attached, and only when `/proc` still describes the process that exec'd.

**Own noise.** Events whose pid is the agent's own, and file events whose every touched path is under the exclusion list (spool, state, logs), are dropped and counted (`own_dropped`). The agent's own binary, unit and state directory are watched under key `phylax_self`; a change there sets `self_tamper: true` (review D101, D104: kernel-side watches on our own files, so the kernel records edits even if the agent was just killed and the restarted agent ships them).

**Rules.** The module installs only rules whose key starts with `phylax` and never touches foreign rules:

- Exec: `-a always,exit -F arch=b64 -S execve,execveat -k phylax_exec` (and `b32` on amd64 and arm64).
- Network (optional): `-S connect,accept,accept4 -F success=1 -k phylax_net`, b64 only (32-bit x86 has no such syscalls).
- Persistence and content: for each path in the fixed list (accounts, sudoers, PAM, `ld.so` files, systemd unit directories, cron and at spools, sshd config, `/root/.ssh`, shell startup files, `rc.local`, `init.d`, udev rules, `modules-load.d`, `/etc/audit`; Appendix B), plus `extra_watches`, `service_binaries` and `web_roots`: an existing directory gets `-a always,exit -F dir=<p> -F perm=wa -k phylax_fim` (`dir=` is recursive, unlike `-w`, which sees only direct children); an existing file or a missing file in an existing parent gets `-w <p> -p wa -k phylax_fim`. Each mount is watched separately by this construction. Paths containing whitespace or quotes are skipped from the rules and left to the sweep.
- Self: the same two forms under `phylax_self`.

`fork`/`clone` rules are not installed in the code; lineage comes from the exec records plus `/proc` and the process table. This differs from the v3 text ("plus `fork`/`clone` with the thread-clone filter"); the code's choice is kept because an exec-only stream already gives parents, and `fork`/`clone` multiply the event rate for little gain.

**Module-load rule (A2.Q3, to build).** There is no `kernel.modules_disabled` lock: it is one-way, does nothing against modules the image already ships, and risks breaking later loads. Instead the rule builder adds `-a always,exit -F arch=b64 -S init_module,finit_module -k phylax_kmod` (and `b32`), so any module load emits an event regardless of tool. The existing detection rules key on the `insmod` and `modprobe` command names only (`rules/linux_exec.yml:219`); the new `detect` rule matches on the `phylax_kmod` key. The rule is a fixed line in the rule set, not a config option. The event arrives as `process_start`-shaped data without `EXECVE`; it needs a small `kmod_load` branch in `Assemble` (open item: either a new common kind or a `file_change`-style kind owned by `audit`, `audit.module_load`).

**Verify loop (every 10 s).** Reads the kernel status and rules and checks:

- the enabled flag (re-enabled when managed) and, in unicast mode, that this process is still the reader (`reader_displaced`; re-registered when managed);
- the lost counter (increases become `kernel_lost` gaps);
- the hash of the rules with our keys against the baseline taken after install; a mismatch reinstalls what is missing, deletes stale phylax-keyed rules, re-baselines, and emits `audit.rules_changed` with `repaired: true`. Rules that failed to install at start-up are not counted as tampering, because "missing" is computed against the read-back baseline;
- foreign `never` rules (`-a never,...`, `task,never`), reported as `never_rule` when their number changes. The module does not delete foreign rules.

An audit rule flush by the red team (`auditctl -D`) is therefore seen within 10 s and repaired. D10 in `detect` consumes `audit.rules_changed`. Plan-driven rule changes must carry the plan tag and update the baseline through the module, otherwise the guard reports its own plan as tampering (open item).

**Heartbeat hash (review D91, decision 14).** The audit health in the heartbeat includes the rules hash (`rules_hash`), the count of installed and failed rules, audit pid, backlog and kernel-lost counters. The controller compares the hash with the last value it saw for the host; a change or a drop to no rules is a tier-1 alert even if `audit.rules_changed` was lost with the link. This is the analogue of UCF's own-BPF-count check.

**Loss is visible.** Sequence gaps found by the reassembler, `ENOBUFS`, queue overflow, rate-limit drops and kernel-lost increases are accumulated and flushed once a second as `telemetry_gap` events with an exact-or-estimate flag. v3 also described a `/proc`-diff backfill at lower confidence (`source=backfill`, review D90); the code does not do it. See Limits.

**Hash sweep (the file source of truth).** Every `sweep_interval_sec` (default 5 min, first pass after 5 s) the module walks the watch paths and web roots, plus the self paths, depth 8, at most 200000 entries, at 400 files per second, and diffs against the previous snapshot (creates, deletes, content and attribute changes). Files over 8 MiB are compared by size and mtime only. Changes the audit stream already reported since the previous sweep started are skipped, so a sweep event means "audit did not see it" (`writer_known: false`). At most 500 sweep events per pass; the overflow is counted as `sweep_overflow`. v3 hashed only changed files each pass and re-hashed everything on a slower cadence; the code re-hashes every file each pass within the rate limit, which is simpler and bounded. `shortcut: full re-hash each sweep, add a changed-files-only fast pass if a lab run shows the sweep costs more than its CPU budget`.

**Containers (N7.6).** For a service with `runtime: docker` or `podman`, the manifest gives the controller the published-port listeners, the container's mount namespace for pins, and the volumes as content roots. For `audit` this means: volume paths on the host are ordinary `web_roots` and are watched and swept normally; processes inside a container are seen by the host's audit (the initial namespace) and carry the container's `cgroup`, from which the controller resolves the service. Files in the container's writable layer on `overlayfs` under `/var/lib/docker` are not reliably visible to path watches; they are reported as a coverage gap (see Health) rather than silently missed.

##### 7. Actions and content

Actions: `audit.rules` and `audit.immutable` (core Logging row; `audit -e 2` is the explicit late plan step with a reboot as rollback, review D102, and the agent's replace-binary action clears and re-sets the immutable bit). The module registers no actions of its own.

Content: none. Detection rules over its events live in `rules/linux_exec.yml`, `rules/linux_persistence.yml` and the other `detect` files; the fixed persistence path list is code (it is the kernel-facing part of Appendix B) and the host-specific paths come from config.

##### 8. UI

No page of its own. The Platform page shows the module's state, its gaps and the rules hash per host. A host-grid column is not needed. Alerts and `telemetry_gap` counts reach the Platform page's telemetry-gap section through the core.

##### 9. Health

Implements `agent.HealthReporter`. States:

- `ok`: rules installed (`rules_failed` 0), enabled, reader attached, no `never` rules.
- `degraded`: some rules failed to install, a foreign `never` rule exists, the module is rate-limiting, or the receive buffer overflowed in the last interval.
- `unavailable`: not root or no audit netlink (reported as `ErrUnavailable` by the factory with the reason).
- `over_budget` and `restarting` are set by the supervisor.

Gaps reported (each a `Gap{What, Why}`):

- `rules`: names of rules the kernel refused.
- `never rules present` with the first lines.
- `unsupported filesystem under <path>` for NFS, overlayfs, FUSE and similar mounts that carry a watch path (to build with a `statfs` type check at start and on the verify loop; review D98).
- `unicast reader displaced` while it lasts.

`Health.Detail` carries `rules_hash=<first 12 hex>` and the mode (`multicast` or `unicast`) so the heartbeat shows both. If the full hash must travel in a typed field instead of free text, that is a core change (see Limits). Usage reports the self-timed handler CPU, bytes held in the process table, queue and snapshot, events and bytes out, and drops (rate-limited plus queue overflow).

##### 10. Scoring safety

The module never writes to a host except for audit kernel state: it adds and removes its own `phylax`-keyed rules, may enable audit, set the backlog, failure mode and (unicast) audit pid. It never changes a scored service, account or file. Risks it does carry and how they are bounded:

- Load: audit rules on a busy web server could slow syscalls. The rule set is exec plus path watches with a bounded event rate and a drop-with-report policy; the network rules are off unless needed. The first lab load test (T43) and the Invitational (questions R7 and O3 in `docs/impl/invitational-data.md`: exec and event rates, cost per module) set the real numbers.
- Audit failure mode `log`, never `panic`, so a full backlog cannot halt a scored host.
- `audit -e 2` is never automatic.
- Exempt by behaviour, not address: the module has no source-address logic at all.

Alert-only by construction. Responses to what it sees (restore rules, kill, disable unit) are `respond` tier decisions on `detect` events, not this module's.

##### 11. Tests

Unit and fixture tests (built): assembly from recorded `testdata/*.log` (exec, failed exec, many args, hex-encoded names, file create, modify, rename, net connect), process table (parent resolves after exit, pid reuse is not trusted), own-process and own-path exclusion, sequence-gap and `ENOBUFS` to `telemetry_gap`, rate limit and token-bucket refill, rule lines parse and cover the required paths, reconcile installs and the hash is stable, flushed rules are detected, reinstalled and reported, a single deleted rule, a foreign `never` rule and disabled audit are detected, kernel-lost counter becomes a gap, install failure is reported, start against a control client. A real-kernel test runs in a container with only the two audit capabilities and cleans up its keyed rules.

To add: a test for the module-load rule, the filesystem-type gap, the `HealthReporter` output and the heartbeat rules hash; the retrofit alias test for `net_connect` to `conn`.

Conformance (module contract): starts with no config (`Section` returns disabled), reaches `ok` or `unavailable` within 10 s on a fixture host, stops within 5 s, emits only declared kinds, survives link loss (every `emit` error is counted, none is fatal), survives reconfiguration (a new web root replaces the module; no `Keep` state is needed because the rule baseline is re-read from the kernel), `go test -race`.

Lab tests (v3 ids, to be renumbered with the Testing section): T43 exec storm, T01 prebaked set present (file and exec evidence), T02 firewall disabled by timer (D10 path), T12 `LD_PRELOAD` rootkit hiding a process (the `env` field and the sweep), T36 hardening with no red steps (no untagged `file_change` from our own plans).

##### 12. Limits and open items

- `shortcut: audit sees only the initial namespaces, so processes in containers appear with the host pid and cgroup but their in-container paths are not mapped; resolve cgroup to service in the controller and add a container-aware pin only when the 2027 stack is known to use Docker`.
- `shortcut: no process_exit events; add -S exit_group rules only if a rule needs exit times`. v3 listed "process start and exit"; the code, and every rule so far, uses starts only, and exited parents are kept in the TTL table.
- `shortcut: no /proc-diff backfill after an event loss; gaps are reported, not filled, add the backfill (source=backfill, lower confidence) if the lab shows gaps that matter for trace-back`. Review D90 kept the backfill; the code has the gap half only. If it is built, it belongs to this module.
- `shortcut: the sweep re-hashes everything each pass within a rate limit, add a changed-files-only pass if the CPU budget needs it`.
- Open: the heartbeat rules hash needs a typed place in `module.Health`. `Detail` text works; a `map[string]string` field (`Info`) would be cleaner. Core change request.
- Open: plan-driven audit rule changes (`audit.rules`) must update the guard's baseline or tag the change; otherwise the verify loop repairs the plan's change. Agree the hook with the `exec` core.
- Open: the module-load rule needs a declared event kind (see Behaviour).
- Open: honey-file read detection (v3 mentioned fanotify) belongs to `honeytokens`; if it uses `perm=r` audit watches the rule set needs a hook for other modules' watches without a sibling import (config-rendered `extra_watches` with a key suffix is the likely answer).
- Open: unsupported filesystem gap detection is unbuilt.
- The audit failure mode, backlog and mode knobs are not in the signed config; add them if a lab run needs them.
