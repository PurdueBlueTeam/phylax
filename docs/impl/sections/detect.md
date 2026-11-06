#### `detect`

Detection runs on the host, so it keeps working with the link down. Detections favour behaviour and allowlists over signatures, because the red team can read our rules (the rule format itself is a core section, "Rule format"). This module is the evaluator and the rule catalogue. Responses are the `respond` module's job; `detect` only decides that something matched and how loudly.

**1. Purpose and evidence**

- **What it does.** The agent side subscribes to every event the agent's other modules emit, evaluates the YAML rules loaded from the signed config, and emits `detect.alert`. The controller side evaluates `scope: controller` rules, which need events from several agents (D18b credential fan-out, D13e scan-source rotation, the pass-the-hash pack), over the committed event stream.
- **Evidence that it matters.** Most red actions in 2026 were already covered by rules written from our own history: the redteam report found most red actions covered; the Postfix and DNS proxy binaries (D4b), the `startup_check.py` SSH-key spreader (D9), firewall-killer timers (D10), prebaked default-credential access (D18: red sprays defaults first [[discord-2026q-rt-debrief#e1]]), Zerologon then `secretsdump` as red's top AD path (D8b: [[discord-2026q-rt-debrief#e10]]). Local detection with the link down is principle 4.
- **Evidence against, and how it is handled.** The scorer and our own hardening cause more false positives than the red team [DR §3]. The controls are in the core "Rule format" section (tag exemption, behavioural scorer exemption, exceptions, rate caps) and are applied to every rule below. Peer evidence: UCF's v1 engine killed processes on all 15 rules; v2 ships hand rules as alert, which supports alert-first (`flying-ace-engine/src/lib.rs`, `lib.rs:10,257@85aae3f`). UCF also embeds Rhai expressions in rules; we do not (anti-goal).
- **Decisions applied.** The Sigma importer is cut (review D314, A4.Q2: it was a compiler for no demonstrated gain; UCF's `sigma_to_rhai.py` produced 117 untested rules with an unknown-field fallback of `true`; sigpwny's 2,410 Sigma searches were unusable and none were scheduled; no other team imports Sigma). About ten rules are hand-ported instead. The scheduled Splunk searches from Sigma are cut (review D318). Rules D19 and D20 are cut (review D339: no evidence red used a promiscuous NIC or allowed-protocol abuse against us). The sinkhole leg of D13 is dropped (review D333, D222; the sinkhole decision is deferred to the C2 fingerprinting lab, see `egress`).

**2. Status and code**

Status: **built** for the evaluator and about 95 rules; **partial** for the catalogue (parked rules wait for producers) and for evidence collection.

| Piece | Where | State |
| --- | --- | --- |
| Evaluator: loader, conditions, `count`, `sequence`, learned profiles, alert construction | `internal/detect` (`load.go`, `cond.go`, `field.go`, `engine.go`, `profile.go`, `rule.go`) | built |
| Agent module: subscribes to the bus, evaluates, emits `detect.alert` at critical priority, keeps profiles across a reconfiguration | `internal/agent/mods/detect.go` | built |
| Settings | `plan.DetectSettings` (`internal/plan/agentconfig.go`) | built; `lists`, `exceptions`, `rate` are not yet in the loader |
| Rules | `rules/auth.yml`, `linux_exec.yml`, `linux_persistence.yml`, `logs.yml`, `mw-redteam.yml`, `network.yml`, `windows.yml`, `deception.yml`, `deps.yml`, `profiles.yml` | built; `rules/pending/needs_producer.yml` holds 16 rules whose producer is missing |
| Controller-side rule evaluation | none | missing |
| Host-side evidence collectors named in `collect:` | none (the alert carries the names; `capture` reads `freeze_ring`) | missing |

What is missing, in order of effect:

1. **`lists:`, `exceptions:` and `rate:`** (core "Rule format"). The loader rejects unknown keys, so these are additions to `load.go` and the engine. Until they exist, allowlists are `profiles` seeded from the manifest, and suppression is not possible without editing rule text.
2. **Controller-side evaluation** of `scope: controller` rules. The agent loader parses the scope but the controller does not run them.
3. **The catalogue gaps below** (N4.2 to N4.6, D327, D332, D333, D337 additions, the `init_module` rule, the pass-the-hash pack, hand-ported rules).
4. **Evidence collectors.** The engine records `collect:` names in the alert. Of the names in use, only `freeze_ring` has a consumer (`internal/capture/freeze.go`), and the controller never sends `freeze_capture` for controller-scope collects (Known bug 7). The host-side collectors (`process_tree`, `content_changes`, `binary_copy`) and the controller-side ones (`transactions_window_10m`, trace-back timeline) are to be built; see Behaviour, "Evidence collection".
5. **`ir_template` is removed from rules.** The code still has the field. IR drafts come from the drafter by attack narrative (review D354, area 10), so the key is deleted from the loader and the corpus in the retrofit.

Rule ids owned by other modules are in the catalogue table's "Owner" column; their rule files stay in `rules/` and are loaded by `detect`.

**3. Capability manifest**

| Field | Value |
| --- | --- |
| Name | `detect` |
| Sides | agent, controller |
| OS | both |
| Privilege | root (reads the bus only; needs no privilege itself, runs in the agent process) |
| Roles | any host; controller side on the controller |
| Consumes | `process_start`, `file_change`, `conn`, `listener`, `auth_event`, `dns_query`, `telemetry_gap`, plus module kinds named by rules: `net.egress_denied`, `net.canary_result`, `audit.rules_changed`, `sec_event`, `log_line`, `http_request`, `decoy.hit`, `honey.read`, `deps.edge`, `deps.edge_gone`, `integrity.verdict`, `integrity.crosscheck`, `inventory.*` (when enabled), `ad.finding`. Code names (`auth_success`, `net.connection_opened`, ...) are accepted aliases until the retrofit renames them |
| Emits | `detect.alert` (schema 1, critical), `detect.suppressed` (schema 1, normal) |
| Budget | CPU 10 ms/s, held 16 MB, 5 events/s, burst 50, 200 KB/min out, disk 1 MB. Starting values; the Invitational collector replaces them with measured numbers (`docs/impl/invitational-data.md`) |
| Default | core |
| Tables | none (alerts are core `alert` rows) |
| Content | `rules/` (all rule files), `rules/lists.yml`, `rules/profiles.yml`; hand-ported packs under `rules/ported/` |
| Actions | none |
| Pages | Alerts (shell page; this module supplies rows), Rules (Settings sub-page listing rules, tests, exceptions, expired exceptions) |
| Evidence | [[discord-2026q-rt-debrief#e1]], [[discord-2026q-rt-debrief#e10]], [[mnccdc-redteam-gpo#e3]], [[mnccdc-redteam-gpo#e6]], [[redefiningreality-cobalt-strike#e4]], [[how-to-win-ccdc-dealing-with-red-team#e2]] |

**4. Configuration**

```yaml
# manifest/modules/detect.yml
detect:
  # detect only alerts (S1): no act_enabled, no per-rule mode; `respond` acts from its recipes
  max_keys: 4096            # per-rule bound on count and sequence state
  rate_per_sec: 5           # module emit limit (ModuleLimits)
  burst: 50
  packs: [linux_exec, linux_persistence, network, auth, windows, logs, deception, deps, mw-redteam, ported]   # rule files loaded; default is every file for the host's OS
  # Not configured here: the profile seeds (scored accounts, service comms, dependencies,
  # rotation-pending accounts, device admins) are rendered from the manifest per host.
```

```go
// package plan (built, extended)
type DetectSettings struct {
	ModuleLimits
	Rules      []RuleFile    `json:"rules,omitempty"`      // signed rule documents for this host
	Seeds      []ProfileSeed `json:"seeds,omitempty"`      // manifest-derived static profiles: the behavioural scorer exemption
	MaxKeys    int           `json:"max_keys,omitempty"`
	Lists      []ListFile    `json:"lists,omitempty"`      // NEW: rules/lists.yml plus manifest-derived lists
	Exceptions []Exception   `json:"exceptions,omitempty"` // NEW: suppression records from overrides, keyed by rule id
}
```

`detect` only alerts (S1): a rule has no `mode`, the engine has no `AlertOnly`, and the module does not read `act_enabled`. Safe mode (core) suspends `respond` separately.

**5. Events**

Consumed: the kinds in the manifest above. A rule names exactly one kind or a list of kinds in `when.event`; the engine indexes rules by kind, so an event only visits rules for its kind.

Emitted:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `detect.alert` | 1 | critical | `rule`, `title`, `severity` (info..critical), `tier` (0, 1, 2), `message`, `attack` (ATT&CK v19 ids), `collect` (collector names), `entities` (fields copied from the matching event: path, exe, account, source, ...), `evidence` (up to the last three matching events, each with kind, time, fields), `source` (upstream attribution for ported rules) |
| `detect.suppressed` | 1 | normal | `rule`, `count`, `window`, `by` (one summary per window when a rule's `rate:` cap is exceeded; never silence) |

`detect.alert` events are never fed back into the engine (the module drops any event whose kind starts with `detect.`).

**6. Behaviour**

*Evaluation.*

- A rule is a YAML document with a mandatory event kind, `all` and `any` condition lists, and optionally one `count` or one `sequence`. Loading is strict: unknown keys, unknown operators, a condition with zero or two keys, a regex that does not compile or matches the empty string, an empty list item, a rule without both a `should_match: true` and a `should_match: false` test, a revoked ATT&CK id (the T1562 family fails with "use T1685/T1686"), and duplicate rule ids are load errors, never silent. `docs/rules.md` is the field reference; the core section is the format.
- `count` keeps state per key (`by` fields; `agent` is a pseudo field) and fires when `gte` events, or `gte` distinct values of `distinct`, arrive within `window`, then stays quiet for `cooldown`. Address fields have derived forms `<field>_net8`, `_net16`, `_net24`, so a scanner that rotates source addresses is keyed by its /16 (`by: [raddr_net16]`, used by D13e). State per rule is bounded by `max_keys`: expired keys are pruned first, then the least recently seen evicted. Windows use event time, so replays and tests with a fake clock are deterministic.
- `sequence` is stage A then stage B within `within`, keyed by `by`; one pending A per key; A is consumed on a match.
- **Learned profiles** (`in_profile`) are the baseline mechanism. A profile learns the values of one field per key (for example the children of each scored service) for a window after the first event of each key, then the condition is true only for values learned or seeded. While the window is open the condition is true, so rules stay quiet while learning. `Engine.Seed` fills static lists (`accounts.scored`, `rotation.pending`, `service.dependencies`, `device.admins`, `reference.windows_tasks`, `scored.service_comms`) and marks a seeded learned profile as already learned, which is how manifest baselines skip the learning window. Profiles are exported on reconfiguration and restored (`Keep`), so a config push does not reopen a learning window.
- **Tags.** `exempt_tagged: true` skips any event with a non-empty envelope `Tag`. The plan engine and work windows set the tag on every event kind they cause. The net module tags its canary probes `canary`, so D12 exempts them and V3 deliberately does not set `exempt_tagged`.
- **Scorer behaviour is exempted by behaviour, never by address** (Divisor re-draws addresses). Brute-force thresholds sit above Quotient's `BadAttempts` burst and are per (agent, source, account); fan-out rules exclude `accounts.scored`; D9e additionally exempts the scorer's N-failures-then-success pattern from one source within about 100 ms [Q §9.6]. NTLM WinRM and SMB network logons by the scorer look like pass-the-hash to some public rules [DR §3, inferred], so the pass-the-hash rules take the learned scorer accounts and the traffic label as context (below).
- **The agent excludes itself** by its randomised install path and hash (D5h reports anyone else touching those paths, with `self_tamper: true` on the file event).

*Evidence collection (to build).* When a rule with `collect:` fires, the agent-side collectors run before the attacker can clean up and the results ship as chunks tied to the alert:

| Collector | Runs on | What it gathers |
| --- | --- | --- |
| `process_tree` | agent | the matching process, its ancestors and children from `/proc` or the Windows process list, with command lines, start times and image hashes |
| `content_changes` | agent | stat and hash of the `entities` paths and their directory |
| `binary_copy` | agent | a defanged copy (ELF or PE magic zeroed) of the offending file, as in `proc.dump` |
| `freeze_ring` | agent (`capture`) | `capture` reads the name from the alert and freezes the packet ring |
| `transactions_window_10m` | controller | protocol transactions from the source and to the host, plus or minus 10 minutes, from the store |
| `trace_back` | controller | the trace-back timeline from the `traceback` module for the affected host |

The controller sends `freeze_capture` for controller-scope rules; that is the fix for Known bug 7. Collectors are bounded in time and size, and a failed collector is recorded on the alert, never retried in a loop.

*Hand-ported third-party logic.* Third-party rules are ported by hand, never imported. A ported rule carries `source:` with the upstream id, path, commit, author and licence; it reaches the alert, the UI and the IR drafter, and a generated `THIRD_PARTY_RULES.md` lists them. Licence policy [DR §6]: Sigma (Detection Rule License 1.1, attribution required), Splunk security_content, Falco, osquery packs, sysmon-modular and Atomic Red Team may be ported with attribution; Elastic (ELv2) and Wazuh (GPL-2.0) logic is re-implemented from the idea and the upstream id is cited in `source:`; the UIUC and Wayne State files are not used. Same CI as any rule: an inline test per rule, ATT&CK ids and tier. Why not a native Sigma evaluator, kept as rationale: 10,377 match values cost about 46 MB of heap and 14.5 ms per event unindexed against an 80 MB, 3% agent budget, and Sigma is 77% Windows and 7% Linux, mostly `status: test` [DR §4].

*The detection catalogue.* Ids continue v2's D1 to D17 and the coverage spec's D18 onward [COV §4]. The 81 proposed rules P01 to P81 [PR] are the backlog, each a tested file under `rules/` when its producer exists (readiness classes: A shipped event types, A* needs the exec feed, B needs an engine feature, C needs a producer). The mapping from a proposed rule to its id is in the rule id (`D18.default-cred-logon` is P01). Appendix I of the design groups the backlog.

| ID | Detects | Data | Logic | Tier | Owner |
| --- | --- | --- | --- | --- | --- |
| D1 | Service process spawns a shell or tool; stray processes of scored users; sshd child interpreter; web server and Windows service children | `process_start` | Parent in a scored service's tree and child not in its learned profile, or any shell, interpreter or download tool. D1b/D1g Windows names under `w3wp`, `dns.exe`, `ftpsvc`, SQL. D1d a scored account's process whose parent is not sshd, login or its service. D1e interpreter or network tool whose parent is sshd. D1f web-server unit starting a shell, recon utility or downloader | 1 | detect |
| D2 | Content or config tampering; mounts over content; PHP ini semantics; app admin rows; web log attacks; dangerous webroot extensions; mail hooks; DB plugins | `file_change`, semantic parsers, SQL pollers, access logs | Untagged change in a content root or config (D2a); D2b new bind or overlay mount on content roots (needs `inventory`); D2c effective PHP config loses `disable_functions` entries or gains `auto_prepend_file`, `extension=` (needs a php.ini parser); D2d new or changed `oc_user` or `ps_employee` row (needs a SQL poller); D2e web-log attack strings; D2g executable or double-extension file in a content tree; D2h/D2i Postfix `master.cf` pipes, aliases, Dovecot post-login, `mysql.func`, `plugin_dir` | 0 if a webshell signature matches, else 1 | detect |
| D3 | New listener; risky listener; remote-access inventory; known local-root exec | `listener`, `process_start` | Listening socket not in any service, decoy or learned baseline (the baseline comes from the manifest); D3d risky ports; D3c/D3c2 Tailscale, ngrok, chisel, frp, cloudflared, VNC, WSL feature, OpenSSH on Windows; D3e PwnKit-shaped `pkexec` with no arguments | 1 | detect |
| D4 | Unexpected outbound connection; relay or proxy behaviour | `conn`, Sysmon 3, Palo traffic | D4: an established connection from a server process to a peer outside its declared dependencies. D4b: a service whose profile says `outbound: none` has an established external peer and near-symmetric bytes in and out (the regional's Postfix proxy signature; Postfix and DNS proxy binaries were seen in 2026) | 1 | detect |
| D5 | Fileless or hidden execution; capabilities; masquerade; writes to binary directories; new SUID | `process_start`, `file_change`, `sec_event` | D5a deleted or memfd executable; D5b connection owned by a deleted-exe process; D5c new file capability; D5e/D5e2/D5e3 system-name masquerade, typo-squats, kernel-thread masquerade; D5f/D5g writes to `/usr/bin`, new SUID; D5h agent self-tamper. `LD_PRELOAD` is D6d3. **D5d binary integrity is owned by `integrity`** | 1 | detect (D5d integrity) |
| D6 | Persistence created or altered; package holds; unit environment and capabilities; shell hooks; immutable flag; suspicious service install; SSH persistence files; PAM changes; task content; WMI; autoruns; IFEO; DNS plugin DLL | `file_change`, `sec_event`, `process_start` | Any untagged write to a persistence location (Appendices B and C, extended by the hunt's N5.8 list). D6c `apt-mark hold` or versionlock on PAM, ssh, sudo or libc. D6d unit `Environment=LD_PRELOAD` or ambient capabilities a service does not need. D6e `.screenrc`, `PROMPT_COMMAND`, `command_not_found` hooks. **D6f `chattr +i`/`+a` outside a plan tag.** D6g unsigned SYSTEM service. D6q task content (outside System32, encoded PowerShell, the `\Microsoft\` folder hiding a non-stock task). D6r WMI subscriptions, D6t/D6t2 autorun keys, D6u/D6u2/D6u3 IFEO, LSA packages, accessibility binaries | 0 on Windows registry/task/WMI persistence (disable, never delete), 1 elsewhere | detect |
| D7 | Account changes; sudoers; UID 0 and shell invariants; Windows account events; hidden `$` accounts; privileged group adds | `file_change`, `sec_event` 4720, 4722, 4724, 4738, 4728, 4732, 4756, 4781 | Account created, enabled, renamed, reset or elevated outside our plans; D7b `/etc/sudoers.d`; D7d `uid==0 && name!=root`; D7e a hidden machine-style account; D7g Guest or built-in Administrator enabled (tier 0) | 1 | detect |
| D8 | Credential theft; Zerologon; LSASS; DCSync; AD object changes; Kerberos anomalies; hive and NTDS dumps; **GPO state** | Sysmon 10 and 1; Security 4662, 4742, 4768, 4769, 5136/5137, 4670, 4741; System/Netlogon 5827-5831; Kdcsvc 39-41 | D8c LSASS read by a non-allowlisted process. D8b Zerologon: System 5829 (Netlogon vulnerable-connection) or Security 4742 by ANONYMOUS LOGON on a DC machine account, or a burst of `DC$` network logons [DR §0, SV R2.4]. D8e DCSync (4662 replication rights from a non-DC). D8g RC4 ticket bursts, AS-REP without pre-auth. D8d GPO, ACL, delegation and `gPLink` changes. **New (review D327):** GPO-state rules for Guest in Administrators, `RestrictAnonymous`, extreme lockout thresholds and Defender exclusions set through policy [[mnccdc-redteam-gpo#e3]], [[mnccdc-redteam-gpo#e6]]; Kdcsvc events 39 to 41 for certificate-mapping abuse [[kb5014754-certificate-based#e6]] | 1 | detect |
| D9 | Lateral movement and remote admin; SSH peer push; services backed by shares; SSH brute force | `auth_event`, Security 4624 (types 3, 10), 4648, 5140/5145, Sysmon 17/18 | Admin logon from a source other than the controller after rotation; admin-share access; remote service creation; D9b `ssh` client on a server connecting to another declared host; D9c FTP or IIS root on a UNC path; D9e failures per source and account **with the scorer's N-failures-then-success pattern exempt** [Q §9.6]; D9f SSH reverse tunnel | 1 | detect |
| D10 | Defense evasion: firewall, Defender, audit policy, log clearing, Sysmon tamper, monitoring config, timestomp | `audit.rules_changed`, `telemetry_gap`, `sec_event`, `process_start` | Firewall changed or disabled (D10k/D10k2); Defender protection off or new exclusion (D10c); audit policy changed or logs cleared (D10d, D10g); Sysmon stopped (D10e); monitoring config changed (D10i); agent or monitoring service stopped (D10h); timestomp (D10j). **The audit rules hash in the heartbeat dropping or changing is the signal for D10.audit-rules-changed** (see `audit`); `auditctl -D` and `iptables -F` by untagged actors | 0 (restore) and 1 | detect |
| D11 | Rootkit indicators; kernel modules; BPF programs | `integrity.crosscheck`, `inventory`, Sysmon 6 | Hidden PIDs, sockets or modules; BPF programs outside the baseline; kernel taint change; unsigned or new driver. D11b/D11b2 kernel module load by command or file | 1 | `hunt` (checks run by `integrity`); D11b in detect |
| D12 | Denied egress | `net.egress_denied`, Palo deny logs | **The first denied outbound connection from a server is the primary C2 signal** (review D332: a 300 s sleep needs about 50 minutes of data to show periodicity [[redefiningreality-cobalt-strike#e4]]); D12b repeated attempts from one process to one destination escalate | 1 | detect (analysis in `egress`) |
| D13 | C2 pipes and beacons; reverse shells | `sec_event` 17/18, `process_start`, `http_request`, `net.egress_denied` | D13b default C2 or PsExec named pipe; D13b2 reverse-shell command shape; D13c beacon periodicity (jitter below 20% over at least 10 intervals; needs an interval-variation operator); D13d C2 HTTP profile; D13e scan-source rotation. **New (review D333):** Cobalt Strike and Mythic rules: `msedge.exe` or `wmiprvse.exe` making outbound connections or with an odd parent on a server; the pipe regex `TSVCPIPE-*` on Sysmon 17/18; a Windows-Update user agent or a `www.windowsupdate.com` certificate to a non-Microsoft destination; any read of `C:\Windows\beacon.bin` [[redefiningreality-cobalt-strike#e2]], [[redefiningreality-cobalt-strike#e4]], [[redefiningreality-cobalt-strike#e6]]. The sinkhole-capture leg is dropped | 1 | detect |
| D14 | Network device tampering | adapter diff, device logs | Owned by `devices`. The dependency rules that used `D14` are renamed `DEP1` to `DEP3` (Known bugs) | 1 | devices |
| D15 | Decoy interaction; credential-file access | `decoy.hit`, `honey.read`, DC events | Owned by `decoys` and `honeytokens`. Severity by depth: connect (info), login or command (high), honey credential or key used anywhere (critical) | 1 | decoys, honeytokens |
| D16 | Scorer check change | check discovery | Owned by `scorer` | info | scorer |
| D17 | Service change; config moved; service stopped without a plan tag; destructive commands; web-admin brute force | change events, `process_start` | Untagged change to a scored service's content, config, behaviour or identity, with trace-back attached (D2a, D17b); D17b `moved_from`/delete on configs; D17c stop, disable, mask or kill of a scored unit (tier-0 restart under the circuit breaker); D17d `rm -rf`, `dd of=/dev/sd*`, `vssadmin delete`; D17e web-admin brute force (needs the access-log parser). **New (review D337):** a reboot and shutdown guard for `shutdown`, `reboot`, `halt`, `poweroff`, `init 0/6` and `systemctl reboot` by a non-operator session or an untagged context. The boot-critical file watchlist (fstab, grub, initramfs, passwd, shadow, sshd_config, network config, BCD) is in `content_guard` | 1 (0 for restart) | detect |
| D18 | Default or old-credential logon; credential fan-out | `auth_event` | A successful login for an account in `rotation.pending`, or with a default credential, or from an unknown source; D18b one source authenticating to at least 3 hosts within 5 minutes (controller correlation). Scorer sources are excluded by behaviour. Red sprays defaults first [[discord-2026q-rt-debrief#e1]] | 1 | detect |
| D21-D23 | Address or route change; re-infection hunt trigger; USB attach | `inventory`, `enroll`, `log_line` | D21 address, route or neighbour entry differs from the manifest topology (needs `inventory`). D22 starts the prebake hunt after any restore or re-enrollment. D23 USB attach is tier 0 on the controller host (redteam item 10 [[2025-minnesota-and-indiana-ccdc-debrief#e4]]) and tier 1 elsewhere. **D19 and D20 are cut** | 1 (0 on the controller host for D23) | detect |
| V1-V4 | Vantage alerts from the Kali | Kali probes, scans, canaries | Owned by `vantage` | info/1 | vantage |
| DEP1-DEP3 | Dependency learned, external, gone | `deps.edge`, `deps.edge_gone` | Owned by `deps` | 1-2 | deps |

*Additions to the catalogue, each as content.* All are alert-only first unless stated.

- **Splunk exploit rule on Linux** (review N4.2): `splunkd` or its postgres sidecar spawning a shell or interpreter, plus FIM on Splunk `etc/` and `bin/`. Only a Windows `splunkd.exe` rule exists today (`rules/windows.yml:90`). Splunk 10.0.x has no workaround short of upgrade [[security-hardening-in-splunk-enterprise#e3]]; KEV [[known-exploited-vulnerabilities#e4]]. One rule.
- **Copy Fail** (review N4.3, CVE-2026-31431): audit `socket(AF_ALG=38)` by a non-root user. FIM cannot see the page-cache write, so the second control is a short-cadence SUID hash sweep, which is `integrity` content. [[cert-cc-vulnerability-note-vu-260001#e2]]
- **Module load by any tool** (A2.Q3): an audit syscall rule on `init_module` and `finit_module` makes every module load emit an event, so a load by any tool alerts. Existing rules key on `insmod` and `modprobe` comm only (`rules/linux_exec.yml:219`, D11b). The audit rule text is installed by `audit`; the detection rule is `D11b3.kmod-syscall`, matching the `process_start`-adjacent syscall record. There is no `kernel.modules_disabled` lock: it is one-way, does nothing against prebaked modules and risks breaking later loads.
- **Service and tool ACL tamper** (review N4.4): Security 4670 and System 7040 on scored services. Red locked a DNS service so even Administrator got Access Denied [[ccdc-journey-zero-to-nationals#e5]]. Pairs with the `service.sddl_reset` action in `ad`.
- **Generic exec pack** (review N4.5), in `linux_exec.yml` and `windows.yml`: exec from `/tmp`, `/var/tmp`, `/dev/shm` or a dot-directory; offensive-tool names and arguments (Impacket, CME, Responder, Kerbrute, SharpHound, linpeas, pspy, Potato, Certipy, LaZagne, sqlmap, masscan); miner strings (stratum, xmrig, kinsing); Falco-style log clear and shell-history deletion. Peer: RnDSweats `SaltyBoxes/CustomScripts/falco/ccdc_extended_rules.yaml@92cae3b`. Tool-name rules are low confidence (a rename defeats them) so they stay alert-only; the weak keyword rules for "diamorphine" and "reptile" are skipped.
- **Windows event rules** (review N4.6): 4740 lockout storm, 4725/4726 disable and delete, 4756 universal group change, 5140/5145 `ADMIN$` or `C$` from a non-admin source, 4104 download cradles (IEX, DownloadString, encoded), 1644 LDAP enumeration. Event 1644 needs the diagnostic-logging registry setting turned on first, which is a `winevt` and `hardening` item. Peer: cyberuci LOCS `windows.json`, CyberHawks `cyberhawks.zeek`.
- **Pass-the-hash pack** (A7.Q7, content, size S). Red dumps every AD hash, so the scored users' hashes may be replayed. Rules over `auth_event` and Kerberos `sec_event`: an NTLM network logon (type 3) or new-credentials logon (type 9) by a **scored account** (`list: scorer.accounts`) from a source that is not labeled scorer by behaviour; an NTLM success for a scored account on a host where the scorer's service does not use NTLM; RC4 (`0x17`) TGT or service tickets for a scored account where AES is the norm; a TGT request for a scored account from a source with no scorer label; and a scored account used from two sources at once. The scorer label is the traffic label (`traceback`), joined on the controller (`scope: controller`), so the scorer's own NTLM WinRM and SMB logons never match. **These rules are alert-only and permanent: NTLM is never restricted and Protected Users is never applied to scored accounts** (NTLM and its transport stay, core lint).
- **Hand-ported rules** (review D315 to D317), about ten from the sigpwny slop set (`files/sigma-savedsearches.conf`), each with a `source:` block: Cloudflared tunnel, Velociraptor child process, Raccine uninstall, browser remote debugging, `sc sdset` and hidden-service DACL (pairs with the ACL rule above), `regini`, ADExplorer snapshot, `certutil -exportPFX`, `whoami /all`, and CrackMapExec process patterns.

*What the catalogue is tuned against.* Traffic generators send suspicious traffic from random addresses [PKT Systems 5], so bare connections are info-level, blocking is one click, and severities are tuned against that noise. A success metric is five or fewer false-positive alerts per hour from scorer and orange traffic only (core).

**7. Actions and content**

Actions: none. Content shipped (all under `rules/`, loaded only when `detect` is enabled):

| File | Rules |
| --- | --- |
| `linux_exec.yml` | D1, D1e, D1f, D3c, D3e, D5a, D5c, D5e3, D5g, D6c, D6d3 (in `mw-redteam.yml`), D6f, D6n, D7d, D7f, D9b, D10g, D10h, D10j, D10k, D11b, D13b2, D15b.cred-file-access, D17c, D17d |
| `linux_persistence.yml` | D2a, D2g, D2h, D2i, D5f, D5h, D6a, D6c2, D6d, D6e, D6h, D6i, D6l, D6o, D7a, D7b, D10i, D11b2, D17b |
| `network.yml` | D3, D3d, D4, D4b, D5b, D10.audit-rules-changed, D10.telemetry-gap, D12, D12b, V3 |
| `auth.yml` | D9e, D18, D18b |
| `windows.yml` | D1g, D3c2, D5e, D5e2, D6g, D6p, D6p2, D6q, D6r, D6t, D6t2, D6u, D6u2, D6u3, D7c, D7e, D8b, D8c, D8d, D8e, D8g, D8h, D10c, D10d, D10e, D10j2, D10k2, D13b |
| `mw-redteam.yml` | D5f.msedge-inject-shape, D5g.trolling-payload-shape, D6d3, D6g2, D6v, D7g, D9f, D13d, D13e (P82 to P90, from the Midwest red team's public tooling) |
| `logs.yml` | D2e, D23 (D19 deleted) |
| `deception.yml`, `deps.yml` | D15a to D15g (owned by `decoys`/`honeytokens`); the dependency rules, renamed DEP1 to DEP3 |
| `rules/pending/needs_producer.yml` | D2b, D2c, D2d, D6d2, D6s, D9c, D11c, D13c, D14b-d, D17e, D21, D22, and D5d until `integrity` is wired; each names its missing producer in `needs:`. D19b and D20 are deleted |
| `profiles.yml` | the learned and static profile declarations |

`go test ./internal/detect` runs every inline test in `rules/` and validates `rules/pending/` without running its tests. The v4 additions above are listed in the order they are built, and each ships with its test.

**8. UI**

The shell's Alerts and incidents page lists `detect.alert` rows with evidence, one-click proposals (supplied by `respond`'s recipes) and the pivot. The Rules page (a Settings sub-page registered by this module) lists loaded rules by file, the `respond` recipe and autonomy enabled for them, their tests, exceptions with reason, owner, added date and expiry, and expired exceptions highlighted. Silencing an alert in the Alerts page writes an exception to `overrides.yml`; this module only reads it. Overview tile: alert counts by severity and the number of rules with an enabled recipe. Host-grid column: none.

**9. Health**

States: `ok`; `degraded` when the signed rule set failed to load (the previous set keeps running) or when profiles were rebuilt from empty after a restore; `over_budget` per the contract. Gaps reported: a rule whose producer is missing on this host (for example the `inventory` rules on a host without that module), reported by rule count and by the first ten rule ids; the evidence collectors not yet built; `lists:` or `exceptions:` entries that failed to parse. Detail carries rules loaded, rules with an enabled recipe, `count` and `sequence` state sizes against `max_keys`, and profile keys. `degraded` means some detection is not running on this host; the Platform page shows which.

**10. Scoring safety**

- Detection never touches the scored path. The module reads events and emits alerts; it holds no action.
- The risks are false positives that cause a response and rules that read like scorer behaviour. Both are handled by the controls above, and by the rule that an action runs only through a `respond` recipe tied to the rule id and enabled for the host, with the template's `autonomy` and the attempt ledger (see `respond`).
- Brute-force and fan-out thresholds never count the scorer's `BadAttempts`; scored accounts are excluded from fan-out by profile.
- Every rule with `tier: 0` is on unscored state by construction: Windows registry, task and WMI persistence, Defender settings and audit settings. D17c's tier-0 restart is the only tier-0 rule that touches a scored unit, and `respond` runs it under the circuit breaker.
- Alert-only start: every rule starts without a recipe enabled. A rule that fires more than five times an hour on scorer and orange traffic alone is fixed or given an exception before its recipe is enabled for a host (core success metric).

**11. Tests**

- Unit: the loader's strictness cases, each operator, `count` and `sequence` with a fake clock, profile learning and seeding, state bounds and pruning, regex compile once (benchmark), and the tag exemption on every event kind.
- Fixture: every rule has a `should_match: true` and a `should_match: false` test; `phylax rules test` runs them locally and CI fails on a missing or failing test. Tests use inline events (`event:` or `events:` with `at:` offsets) as built; a captured record from the lab can be referenced as a fixture file where an inline event is too large.
- CI registry check: one rule-id namespace across all modules (prevents the old `D14` collision), ATT&CK ids validated against a pinned v19 dataset with revoked ids kept as aliases (review D344), and `THIRD_PARTY_RULES.md` regeneration.
- Conformance: starts with no config (disabled), reconfigures without losing profiles (`Keep`), survives link loss, rejects unknown config fields, `go test -race`.
- Lab (ids from the design's test matrix): T03 webshell (D1 and D17), T07 DCSync, T08 Kerberoasting with the honey SPN, T11 log clear and Sysmon stop, T12 `LD_PRELOAD` rootkit (D11), T20 scorer and orange traffic for 60 minutes with no red steps (false-positive count), T36 Phylax hardening with no red steps (zero untagged alerts), T37 `BadAttempts` and scorer fingerprints (no brute-force alert with the runner address changed each round), T38 Zerologon, hidden accounts, `chattr +i`, unit capabilities, PHP overrides, OpenCart admin rows and GPO and ACL changes each raise their alert. T42 (Sigma import) is deleted with the importer.

**12. Limits and open items**

- `shortcut: lists, exceptions and rate are not in the loader yet, so manifest allowlists use seeded profiles and suppression needs a rule edit; build them before the first lab run that exercises suppression.`
- `shortcut: controller-scope rules are parsed but not evaluated; D18b, D13e and the pass-the-hash pack are inert until the controller evaluator exists.`
- `shortcut: evidence collectors are names only; upgrade by building the host and controller collectors above before any recipe is enabled for auto.`
- `shortcut: the Windows firewall, Sysmon and 1644 diagnostic-logging prerequisites for some rules are not verified on a real host; upgrade at the first Windows lab run.`
- Open: how a controller-scope rule reads the traffic label of a source. The pass-the-hash pack needs a `source_label` field from `traceback`. Recommendation: the controller enriches each event it evaluates with the latest label for its source address from the `traceback` label events, by store query, so no module imports another.
- Open: whether hand-ported rules live in a `rules/ported/` directory or beside the rules they resemble. Recommendation: `rules/ported/`, so `THIRD_PARTY_RULES.md` generation is one directory walk.
- Open (sinkhole): the C2 fingerprinting lab decides whether first-bytes fingerprints discriminate; only then does a sinkhole-capture rule return. Until then D13 has no sinkhole leg.
- Core changes needed: the `exceptions`/`lists`/`rate` loader additions (core "Rule format" already specifies them); the controller `Host.Subscribe` feed for controller-scope rules.
