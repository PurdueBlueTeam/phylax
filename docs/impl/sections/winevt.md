#### `winevt`

##### 1. Purpose and evidence

`winevt` is the Windows telemetry module. It subscribes to Windows event log channels with `EvtSubscribe`, renders each event to XML, maps it to normalised events (`process_start`, `auth_event`, `conn`, `file_change` and the Windows-only security events), keeps a bookmark per channel so a restart resumes exactly where it stopped, watches the state of Sysmon and falls back to Security 4688 when Sysmon is not running. It is the Windows half of what v3 split into `proc`, `fim` and `logs`: process events, file and registry events, and the event-log side of authentication. Linux counterparts are `audit` (process and file) and `logs` (authentication).

Why it matters for points:

- Windows hosts carry the AD, SMB, RDP, MSSQL and WinRM scored services, and most credential-theft, lateral-movement and persistence detections (D6 to D10 in `detect`) are written against Sysmon and Security events (Appendix A).
- Sysmon is the main Windows sensor [OA §5.4]. Without it the module still produces process starts from 4688 with command-line auditing, so the sensor degrades instead of going dark.
- Prebaked persistence predates the agent, so a one-time backscan of the existing logs at enrollment finds what is already there. DePaul ships Hayabusa rules for this [[pet4yserb-rrepo-windows#e1]] and Chainsaw is named in [[winning-at-ccdc-and-cptc-tips-for#e10]] (review D94).
- Log clearing (1102, 104) and Sysmon stop or reconfigure (Sysmon 4, 16) are defence-evasion signals (rule D10), and the DC's DNS analytical log with Sysmon 22 shows hosts that tried to resolve names outside the zone (review D220).

Decisions applied: review D93 and D95 keep Sysmon under randomised names with config as code, reinstall as tier 0, and the 4688 fallback. Review D94 adds the enrollment backscan. Decision 12: the MWCCDC Defender Toolkit is not run by us, so there is no coexistence work. The WMI process trace is not shipped and an in-house ETW consumer is not planned (v3).

Evidence against: a second Windows agent (Wazuh or Velociraptor) duplicates collection and adds a remote-command path (review D353, OSS-EDR report), so Wazuh is optional (`wazuh`) and not a replacement.

##### 2. Status and code

Status: built (code and unit tests; the Windows boundary is untested off Windows and nothing is lab-proven).

- `internal/collect/winevt`: `pipeline.go` (module, per-channel workers, bounded queues, gap accounting, Sysmon loop), `wevtapi_windows.go` and `source_windows.go` (the `wevtapi.dll` calls through `golang.org/x/sys/windows`, no cgo), `record.go` (XML parser), `mapper.go` (field mapping), `filter.go` (server-side XPath, client-side drops), `bookmark.go`, `sysmon.go` (`SysmonConfigXML`, schema 4.90, service classification), `sysmon_windows.go` (read-only service manager probe), `sysmon_config.xml`, `gpo.go` (Group Policy field derivation), `platform_other.go`.
- `internal/agent/mods/winevt.go`: the factory.
- Everything except the `wevtapi` calls is platform independent and tested on Linux with recorded event XML (`testdata/`). The subscription design follows Elastic Beats' `winlogbeat/sys/wineventlog` (Apache-2.0); no code is copied.

Missing:

- No Sysmon install or reinstall. The module only probes; the core `sysmon.install` and `sysmon.config` actions (`host.exec` of the pinned installer) and the tier-0 recipe that calls them are unbuilt.
- No enrollment backscan. `Config.FromOldest` starts channels with no bookmark at the oldest record, but is not in the signed settings and has no time window or backscan marking.
- No channel for the DC DNS analytical log, the Windows Firewall operational log or the Netlogon log tail (v3 listed all three under `logs`). Channel sizes are not raised and the analytic channel is not enabled by any action yet (`eventlog.size` is in the core catalogue; there is no enable action).
- Event kinds `process_end`, `auth_success`, `auth_fail`, `net_connect`, `sec_event` and `sensor_state` are not declared and not yet mapped to the common kinds.

##### 3. Capability manifest

```go
module.Manifest{
	Name:      "winevt",
	Sides:     []module.Side{module.SideAgent},
	OS:        []string{"windows"},
	Privilege: "root", // SYSTEM; reading Security and Sysmon needs it
	Roles:     nil,
	Consumes:  nil,
	Emits: []event.Type{ /* process_start v1, process_exit v1, auth_event v1, conn v1, file_change v1, dns_query v1, telemetry_gap v1,
	                         winevt.sec_event v1, winevt.sensor_state v1 */ },
	Budget: module.Budget{
		CPUMillisPerSec: 100, HeldMB: 64, EventsPerSec: 500, Burst: 1000,
		BytesOutPerMin: 12 << 20, DiskMB: 1,
	},
	Default:  true, // core-default on Windows
	Tables:   nil,
	Content:  []string{"sysmon"}, // sysmon_config.xml is embedded in the binary; the hash is pinned in the release
	Actions:  []string{"sysmon.install", "sysmon.config", "auditpol.set", "eventlog.size"}, // core Logging actions that act on this module's sources
	Pages:    nil,
	Evidence: []string{"[OA §5.4]", "[OA §5.6]", "[[pet4yserb-rrepo-windows#e1]]", "[[winning-at-ccdc-and-cptc-tips-for#e10]]"},
}
```

The numbers are initial limits, not measurements. Event volume is unmeasured: question R7 and O3 in `docs/impl/invitational-data.md` (Windows event rates per host, cost per module) set the real values. `shortcut: budget numbers are estimates, replace with Invitational measurements`.

##### 4. Configuration

`modules/winevt.yml` becomes `modules.winevt` in the signed config (`plan.WinevtSettings`). A nil block disables the module. No channels means the built-in defaults.

```yaml
rate_per_sec: 500            # emitted events per second; excess is dropped and reported
burst: 1000
channels: []                 # empty = the defaults below
#  - { name: Security, include: [4624, 4625], all: false, exclude: [] }
sysmon_hints: []             # service and driver names Sysmon was installed under (written by the install action; randomised per event)
```

```go
// package plan (built)
type WinChannel struct {
	Name    string `json:"name"`
	Include []int  `json:"include,omitempty"`
	All     bool   `json:"all,omitempty"`
	Exclude []int  `json:"exclude,omitempty"`
}
type WinevtSettings struct {
	ModuleLimits
	Channels    []WinChannel `json:"channels,omitempty"`
	SysmonHints []string     `json:"sysmon_hints,omitempty"`
}
```

Default channels and event ids (`filter.go`; Appendix A is the reference table):

| Channel | Event ids |
| --- | --- |
| Security | 1102, 4624, 4625, 4648, 4662, 4670, 4688, 4697, 4698, 4699, 4702, 4719, 4720, 4722, 4724, 4728, 4729, 4732, 4733, 4738, 4739, 4741, 4742, 4756, 4757, 4768, 4769, 4771, 4776, 4781, 4929, 5136, 5137, 5139, 5140, 5141, 5145 |
| System | 104, 7045, 5827 to 5831 |
| Microsoft-Windows-Sysmon/Operational | 1 to 8, 10 to 14, 16 to 23, 25, 26, 255 |
| Microsoft-Windows-PowerShell/Operational | 4104 |
| Microsoft-Windows-Windows Defender/Operational | 1116, 1117, 5001, 5004, 5007, 5010, 5012 |
| Microsoft-Windows-TaskScheduler/Operational | 106, 140, 141 |
| Microsoft-Windows-WMI-Activity/Operational | 5861 |

Security 5156 and 5157 (Windows Filtering Platform allow and block) are mapped by the code but are not in the default include list; the controller adds them for default-deny hosts (see `net` and `firewall`).

Module internals that stay at the code's defaults (not in the signed config): per-channel queue 4096 events, wait for queue room 2 s, retry of a missing channel 30 s, gap flush 5 s, bookmark save 1 s, Sysmon probe 60 s, first start with no bookmark reads future events only. The module's `DropRule` (drop an event id when a field matches, for example 4769 tickets for machine accounts on a busy DC) exists in `Channel` but is not in `WinChannel`; add `drop` to the signed settings if the Invitational shows a noisy channel.

Sysmon configuration is not a YAML setting. It is the embedded `sysmon_config.xml` (sysmon-modular's Balanced profile structure, pinned to Sysmon schema 4.90, plus the CCDC includes: children of scored services, LSASS access, named pipes, WMI, DNS, image loads for service binaries, file deletes only in web roots), and its sha256 is `SysmonConfigSHA256()`. The release pins the tested Sysmon version and hash.

##### 5. Events

Consumed: none.

Emitted:

| Kind | Priority | Key fields |
| --- | --- | --- |
| `process_start` (common) | normal | Sysmon 1: `pid` or `process_id`, `exe`, `comm`, `cmdline`, `ppid`, `pexe`, `pcomm`, `pcmdline`, `cwd`, `user`, hashes (`sha1`, `md5`, `sha256`, `imphash`), Sysmon `ProcessGuid`. 4688 fallback adds `sensor: "4688"`, `logon_id`, and takes the creator process as parent. Common to both: `channel`, `provider`, `event_id`, `record_id`, `host` |
| `process_exit` (common) | normal | Sysmon 5. The code emits it as `process_end`; the old name is an alias for one release |
| `auth_event` (common) | high | 4624 (`result: success`), 4625 (`result: fail`): `account`, `domain`, `source`, `source_port` (cleaned IP), `logon_type` (number) and `logon_type_name`, `method` (authentication package), `process`, `workstation`, `service: "windows"`, `machine_account`, `anonymous_logon`, `target_logon_id`, and `status`, `sub_status`, `failure_reason` for failures. Code kinds `auth_success` and `auth_fail` are aliases; the existing rules (`rules/auth.yml`) and `internal/traceback/obs.go` key on the alias names until they are retrofitted |
| `conn` (common) | normal | Sysmon 3: `proto`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `dst_host`, `initiated`, `dir` (`out` or `in`), the process fields. The code emits `net_connect`; alias for one release |
| `file_change` (common) | normal | Sysmon 11, 23 and 26 (create, delete): `path`, the writer process; `gpo` and `sysvol_policy` fields from `gpo.go` when the path is under SYSVOL policies. Registry changes (Sysmon 12 to 14) are `winevt.sec_event` with `category: registry` and `op`. `actor_exe` and `actor_pid` name the writer |
| `dns_query` (common) | bulk | Sysmon 22: `query`, `query_results`, the process. The code emits it today as `winevt.sec_event` with `category: dns_query`; the retrofit promotes it to the common kind so `audit`-side and Windows DNS rules can share one condition |
| `telemetry_gap` (common) | high | `source: "winevt:<channel>"` (or `winevt` for module-level), `reason`, `count`, `from`, `to`, `channel`, `from_record`, `to_record` |
| `winevt.sec_event` | high (critical for log clears and Sysmon state) | `category` and the category's fields. Categories as built: Sysmon `file_time_changed` (2), `sysmon_state` (4), `sysmon_config` (16, with `config_hash`), `sysmon_error` (255), `driver_load` (6), `image_load` (7), `remote_thread` (8), `process_access` (10, with `granted_access` and `target_lsass`), `registry` (12 to 14), `pipe` (17, 18), `wmi` (19 to 21), `dns_query` (22), `process_tampering` (25), `sysmon_other`; Security `explicit_credentials` (4648), `service_install` (4697, System 7045), `scheduled_task` (4698, 4699, 4702, Task Scheduler 106, 140, 141, with `task_command`, `task_arguments`, `task_run_as`), `account_change`, `group_change`, `computer_account_change`, `ad_access` (4662), `ad_object_change` (5136, 5137, 5139, 5141, with `gpo` fields), `permission_change` (4670), `audit_policy_change` (4719), `log_cleared` (1102, System 104), `kerberos` (4768, 4769, 4771), `ntlm_validation` (4776), `share_access` (5140, 5145), `ad_replica_removed` (4929), `wfp_connection` (5156, 5157), `security_other`; System `netlogon_secure_channel` (5827 to 5831 with `zerologon_signal`), `service_state`, `system_other`; Defender `defender_detection` (1116, 1117), `defender_action`, `defender_tamper` (5001, 5004, 5007, 5010, 5012), `defender_other`; PowerShell `script_block` (4104, with `script_block_text`); `wmi_subscription` (5861); `unknown` and `other`. The event ids per category are in `mapper.go` and Appendix A |
| `winevt.sensor_state` | critical | `sensor: "sysmon"`, `present`, `running`, `driver_running`, `service_name`, `driver_name`, `renamed`, `config_hash`, `expected_config_hash`, `fallback` (`"4688"` when Sysmon is not running). Emitted at start and whenever the probe result changes |

Fields are strings from the event XML unless a number is safe to parse. Long values are cut and the cut fields listed in `truncated`. Sysmon `ProcessGuid` is the join key for the Process record in the store (Sysmon GUID alias).

##### 6. Behaviour

**Subscriptions.** One worker per channel. The server-side query is an XPath over `EventID`, with consecutive ids collapsed into ranges and a cap of 18 clauses (the Windows subset allows about 22); over the cap, the query becomes `*` and the client-side include list filters. A channel missing at start (Sysmon not yet installed) is retried every 30 s; one `channel_unavailable` gap is emitted for the outage, not one per retry. A failed subscription is retried with the same rule (`subscription_error`).

**Bookmarks.** After each batch the worker stores the opaque bookmark for the channel, but only after the batch's events have been handed to the agent's spool. A restart repeats at most the last in-flight events after a crash and never skips any, and a clean stop neither repeats nor loses events. This includes events logged while the agent was down. Writes are atomic (`internal/atomicfile`) and coalesced to one per second. A corrupt bookmark file is moved aside to `.corrupt`, an empty store is used and a `bookmark_file_corrupt` gap is emitted. A bookmark that points at a record that no longer exists (log cleared or wrapped) is dropped, a `bookmark_stale` gap is emitted and the channel resubscribes from the oldest record. A record id that goes backwards is marked `record_id_reset` (the log was cleared).

**Backpressure and loss.** Each channel has a bounded queue of 4096 events. If the queue stays full for 2 s the event is dropped and counted as a `queue_full` gap with its record id range. Parse errors (`parse_error`) and refused emits (`emit_refused`) are gaps too. Gap records are accumulated per reason and flushed every 5 s. The reader never blocks on the network.

**Clears and tamper.** Security 1102 and System 104 map to `winevt.sec_event{category: log_cleared}` at critical priority. Channel sizes should be raised at hardening (`eventlog.size`, core action) so a flood does not wrap the log between bookmarks. Sysmon 4, 16 and 255 map to critical `sysmon_state`, `sysmon_config` and `sysmon_error` events; `sysmon_config` carries the config hash, comparable with the embedded config's hash.

**Sysmon.**

- *Install (reference procedure).* The Sysinternals license does not allow redistribution, so the controller fetches Sysmon from Microsoft during the cache sync and checks it against the hash pinned in the release; agents get it from the controller's depot (`depot`). The core `sysmon.install` action installs it with `host.exec` (pre-approved, hash-pinned) with no reboot, under a randomised service name and a renamed driver (`-d`, `-i`) [OA §5.6, §5.4]. The names are written to `sysmon_hints` in the signed config so the probe can find the renamed service.
- *Probe.* Every 60 s a read-only service manager probe classifies the services: by exact hint, stock names (`Sysmon`, `Sysmon64`, `SysmonDrv`), the version resource product name, the service description ("System Monitor service", "System Monitor driver") and the image file name. The result gives present, running, driver running, renamed and config hash. A change emits `winevt.sensor_state`.
- *Reinstall as tier 0 (review D93, D95).* If Sysmon is removed, stopped or reconfigured, `respond` runs `sysmon.install` and `sysmon.config` as a tier-0 action: it only restores Phylax's own sensor, touches nothing scored, and is idempotent. The module itself does not run it.
- *Fallback order:* Sysmon, then Security 4688 with command-line auditing, which the hardening pack enables natively (`auditpol.set`). 4688 produces `process_start` only while Sysmon is not present and running, so there are no duplicates; before the first probe the fallback is on (duplicates beat a blind start).

**Self-exclusion.** Process, network and file events whose `exe` is the agent's own binary are dropped (case-insensitive path compare), which avoids feedback and keeps the randomised path out of the stream (D-8).

**Group Policy.** GPO changes arrive three ways: directory events (5136, 5137, 5141 on `groupPolicyContainer` objects), file events under `SYSVOL\<domain>\Policies` (Sysmon 11, 23, 26) and share access (5145 on SYSVOL). `gpo.go` adds `gpo`, `gpo_guid`, `sysvol_policy`, `gpo_section` (machine or user) and `gpo_item` (`gpp_scheduledtasks`, `gpp_groups`, `gpp_other`, `scripts`, `registry_pol`, `security_template`, `other`) to all three, so the `ad` module's GPO rules are written against the shape, not one producer's literals.

**Scorer logons.** 4624 and 4625 carry the source address and logon type; the scorer's pattern (N failures then a success from one source within about 100 ms) is exempted in `detect`, by behaviour, never by address [Q §9.6].

**Enrollment backscan (review D94, to build).** On the first start after enrollment (no bookmark file), the module runs a one-time backscan of the last N hours (default 24, setting `backscan_hours`) of Security, System, PowerShell and Task Scheduler, and Sysmon if it is already installed, using a `TimeCreated[timediff(@SystemTime) <= N*3600000]` filter on the server-side query. The events are mapped like live ones, carry the original `Time` and `fields.backscan: true`, and go through the same on-host rule evaluation; findings arrive as alerts with the historical time. Backscan events are bulk priority and are not forwarded as telemetry unless a rule fires on them, to protect the slow link. After the backscan the live subscription starts from future events. This does the job that Hayabusa and Chainsaw do for incident response, with our own rules (hand-ported, no Sigma importer). Rules need to know about `backscan`: a rule that reasons about "now" (a new untagged service install while no plan runs) must not fire on a three-hour-old install that no longer says anything about the present. The rule format (core) needs one condition for this (open item).

**DC DNS analytical log (review D220).** On a domain controller the `Microsoft-Windows-DNSServer/Analytical` channel is added in `channels` with an explicit include list, and Sysmon 22 gives the same signal on any host with Sysmon. The out-of-zone-query detection is `detect` content. Enabling an analytic channel needs a host action; none exists yet (open item).

**Fields kept off the wire.** The module maps security events to minimal field sets and does not forward full XML; PowerShell script block text is forwarded (it is the evidence) and capped.

##### 7. Actions and content

The module registers no actions of its own. It depends on core Logging actions: `sysmon.install`, `sysmon.config` (the pre-approved `host.exec` of the pinned Sysmon binary, with the embedded config), `auditpol.set` (4688 command-line, DC and member profiles; `internal/actions` has `win.audit_policy.set`), and `eventlog.size`.

Content: the embedded Sysmon config (`sysmon_config.xml`), and the Windows detection rules in `rules/windows.yml`, which are `detect`'s.

##### 8. UI

No page of its own. The Platform page shows, per Windows host, the module state, the Sysmon state (present, running, renamed, config hash matches or not, whether the 4688 fallback is active), per-channel counters (received, emitted, filtered, dropped, resets) and any gap. A host-grid column "Sysmon healthy" (`cell` verified, drifted when the config hash differs, failed when Sysmon is absent) is registered by `hardening`, which owns the install step, not by this module.

##### 9. Health

Implements `agent.HealthReporter`. States:

- `ok`: every channel `ok` and Sysmon healthy.
- `degraded`: a channel is `unavailable` or in `error`, Sysmon is not running (fallback active), a bookmark was reset, or events were dropped in the last interval.
- `unavailable`: not Windows.

Gaps reported: `Sysmon not running; process events come from 4688 (no hashes, no network or file events)`, `channel <name> missing`, `channel <name> subscription error: <err>`, `Security log cleared / bookmark reset: events between <times> are lost`, `queue overflow on <name>`, `Sysmon config differs from the pinned config`. `Health.Detail` carries the Sysmon service name only when it is not stock, to avoid putting the randomised name where it does not need to be; the full state is in `winevt.sensor_state`.

##### 10. Scoring safety

Read-only: the module reads event logs and the service list and writes only its bookmark file under `StateDir/winevt`. It touches no scored service. The pieces that act on the host (Sysmon install, audit policy, log sizes) are core actions with their own lint: `win.audit_policy.set` is a Phylax-visible change but not scorer-visible, and `sysmon.install` loads a driver, which is the one risk (a driver install on a scored DC or SQL host). It therefore runs as a plan node with a dead-man window outside scorer bursts, on one low-risk host first, and the tier-0 reinstall is limited to restoring a previously installed Sysmon (never first install). Log volume on a busy DC is bounded by the channel include lists and the per-module rate limit; 4769 machine-account tickets and similar noise can be dropped client-side.

Alert-only stage: all telemetry is passive. The 4688-only mode produces less data but is also passive.

##### 11. Tests

Built: parser and mapper tests over recorded XML for each mapped event (`testdata/sec4624.xml`, `sec4624_dcmachine.xml`, `sec4625.xml`, `sec4662.xml`, `sec4670.xml`, `sec4688.xml`, `sec4697.xml`, `sec4698.xml`, `sec4720.xml`, `sec4728.xml`, `sec1102.xml`, `ps4104.xml`, `def1116.xml`, `def5001.xml`, `def5007.xml`); filter and XPath tests (clause cap, range collapse, drop rules); bookmark tests (atomic, coalesced, corrupt file); module tests: mapped events reach the emit function, restart resumes without loss or duplication, first run starts at future events, filtering and malformed XML, backpressure produces a gap, a refused emit is counted as a gap, a stale bookmark resubscribes from the oldest record, a missing channel retries and succeeds, Sysmon sensor state and the 4688 fallback switch, a corrupt bookmark file reports a gap and continues, one channel's error does not kill the others, config validation; GPO field derivation; Sysmon classification (stock, renamed, driver-only).

To add: backscan (window, marking, no live duplicates), `HealthReporter` output, the alias tests for old kind names, an XPath test for the 18-clause cap with the added channels.

Windows-only tests (`wevtapi_windows.go`, the probe): need a Windows runner in CI and the lab; skipped with a clear message elsewhere.

Conformance: starts with no config (disabled), reaches `ok` or `unavailable` within 10 s on a fixture host (a fixture `Source` is injected), stops within 5 s, emits only declared kinds, survives link loss (emit refusal becomes `emit_refused` gaps, bookmarks still advance), survives reconfiguration (changed channel list replaces the module; bookmarks persist in `StateDir`, not in memory), `go test -race`.

Lab tests (v3 ids): T11 log clear and Sysmon stopped (campaign 03: D10 fires, Sysmon reinstalled, heartbeat intact), T07 DCSync (4662 with replication rights), T24 Defender's reaction to the agent and to Sysmon, T36 no untagged alerts during our own hardening.

##### 12. Limits and open items

- `shortcut: no ETW consumer, so no events from providers that only exist in ETW; add one only if the lab shows a detection that needs it`.
- `shortcut: the module reads only the channels in the include lists; unlisted event ids are invisible, add ids as rules need them`.
- `shortcut: bookmark is stored after the spool accepts the batch, not after the controller acknowledges it, so events spooled but not yet delivered survive in the spool, not the bookmark`. This differs from v3 ("per acknowledged batch"); the spool already guarantees delivery, so the code's choice is kept.
- Sysmon install, tier-0 reinstall and the Sysmon config update path are unbuilt (`sysmon.install`, `sysmon.config`, a `respond` recipe). The binary comes from the depot; the pinned hash is in the release.
- Enrollment backscan is unbuilt; it needs a `backscan_hours` setting, event marking, and a rule-format condition so rules can opt in or out of replayed events.
- DC DNS analytical, Windows Firewall operational and Netlogon channels need an action that enables an analytic or operational channel; nothing in the catalogue does.
- Kind mapping to the common kinds (`process_end` to `process_exit`, `auth_success` and `auth_fail` to `auth_event`, `net_connect` to `conn`, `sec_event` and `sensor_state` to `winevt.*`) is part of the retrofit. The rule files and `internal/traceback/obs.go` currently use the old names.
- Windows connection tables (`GetExtendedTcpTable`) and denied-connection attribution by 5157 are not in this module; Windows listeners and egress live in `net` (which today is Linux-only), with 5156 and 5157 arriving here as `wfp_connection` events. Decide in the `net` section which module owns the 5157-to-process join.
- Whether several people can view one console at once is unknown; not relevant to this module.
