# Module-section brief for the Phylax v4 design

Status: phase 1 output, 2026-10-31. Input for the agents writing the module sections of `phylax_design.md` (v4). Every non-cut row of `docs/impl/review.md` (D and N ids) is assigned to exactly one module or to one core or placeholder section below; the coverage script in the last section checks that. Line references `L<n>` are to the v3 design (`git show v3:phylax_design.md`).

## How to use this brief

- Write the module's section in `phylax_design.md` under its heading, following the module section template in that file, replacing the `<!-- MODULE SECTION: ... -->` line.
- Apply every row listed for the module: its Call and Why in review.md, then the "Answers from David" (they override the rows), then "What David prefers". The notes below summarise the answers that touch the module; they do not replace reading the rows.
- Carry over v3 text from the listed line ranges for kept rows, rewrite changed ones, and keep the rationale, evidence citations (`[[vault-id#eN]]`, `[XX §n]`), procedures and edge cases. Completeness over brevity.
- Cut rows do not appear in module sections. They have one line each in the design's "Removed in v4" appendix (already written).
- Interfaces (event envelope, module manifest, factories, analyzers, UI registration) are defined in the design's "The module contract" section. Use those names.
- Do not edit core sections. If a module needs a core change, add it under the module's "Limits and open items" and flag it in your report.

## Modules

### Telemetry

#### `audit`

- **Runs on:** agent (Linux)
- **Status:** built
- **Default:** core
- **Code:** `internal/collect/audit`, `internal/agent/mods/audit_linux.go`
- **v3 text to carry over:** L511 (proc row), L513 (fim row, Linux column), L538-545 (Linux process events), L555-558 (files), L1339 (audit ruleset hash in D10)
- **Review rows:** D70 D72 D88 D90 D91 D98
- **Answers and notes:**
  - Decision 7: kernel audit over netlink plus sock_diag; no proc connector (D89 cut), no eBPF (D92 cut, A2.Q2 yes: reopen only if T43 fails).
  - D91: heartbeat carries a hash of Phylax's own loaded audit rules; alert on change or drop (decision 14, David yes). Check whether the L564 audit-status block already covers it.
  - A2.Q3: no `kernel.modules_disabled`; add an audit syscall rule on `init_module`/`finit_module` so any module load emits an event (the rule text itself is detect content).
  - v3 modules `proc` and `fim` are split by source in code: `audit` (Linux) and `winevt` (Windows). Say so in the section; the event kinds stay `process_start`, `file_change`.
  - N7.6 container awareness (process in a container, overlay paths) touches this module; the manifest field is core.

#### `winevt`

- **Runs on:** agent (Windows)
- **Status:** built
- **Default:** core
- **Code:** `internal/collect/winevt` (incl. `sysmon_config.xml`, `gpo.go`), `internal/agent/mods/winevt.go`
- **v3 text to carry over:** L511/L513/L514 Windows columns, L546-550 (Windows), L1001 (DC DNS analytical log)
- **Review rows:** D93 D95 D94 D220
- **Answers and notes:**
  - D94: add a one-time backscan at enrollment (last N hours of Security, System, PowerShell, TaskScheduler through the rules), Hayabusa/Chainsaw-style.
  - D93/D95: Sysmon randomised names, sysmon-modular Balanced plus CCDC includes, reinstall as tier 0, 4688 fallback.
  - Decision 12: no MWCCDC Defender Toolkit coexistence work.

#### `net`

- **Runs on:** agent (Linux, Windows)
- **Status:** built
- **Default:** core
- **Code:** `internal/collect/net` (sockdiag, nflog, egress, canary, communityid), `internal/agent/mods/net.go`
- **v3 text to carry over:** L512, L516 (egress row), L551-554, L994-1001 (logging denied egress)
- **Review rows:** D71 D96 D97 D75 D218
- **Answers and notes:**
  - D75/D218: v3 `egress` collection lives in `net` in code (NFLOG plus sock_diag join; Windows 5157). The controller-side analysis is the `egress` module.
  - The canary sender (`collect/net/canary.go`) is here; canary listeners and verdicts belong to `vantage`.

#### `logs`

- **Runs on:** agent (Linux)
- **Status:** missing (rules in `rules/logs.yml` exist; no Linux tailer; Windows channels come through `winevt`)
- **Default:** core
- **Code:** none yet; consumers `internal/traceback/obs.go`, `rules/logs.yml`
- **v3 text to carry over:** L514, L1071 (HTTPS detail from access logs)
- **Review rows:** D73
- **Answers and notes:**
  - Auth events (`auth_success`, `auth_fail`) from sshd, Cockpit, web admin logins feed scorer-account learning (D251, area 7 revision) and chains.
  - N5.11 (ModSecurity audit log as a source) is cut; do not add it.

#### `inventory`

- **Runs on:** agent (Linux, Windows) + controller
- **Status:** missing
- **Default:** opt-in (reference manifest enables it)
- **Code:** none yet (`collect.inventory` action exists in `internal/actions`)
- **v3 text to carry over:** L522, L763 (collection actions), L1581-1592 (hunt collection uses it)
- **Review rows:** D81 N2.1
- **Answers and notes:**
  - A2.Q1 yes: one module, installed software versions included (feeds N5.1 `vuln`).
  - Table contract: differential snapshots (added, removed, changed rows, epoch, persisted on host); Linux domain-join probe seeding `depends_on` proposals.
  - N2.1 `probe.run{name, params}`: typed read-only ad-hoc queries over inventory tables and hunt checks; no SQL/VQL. A10.Q3: the evidence run (N10.3) and inject queries (N10.6) fold into `probe.run`.
  - Drift (D201/D191/D213, core manifest) depends on this producer.

### Detection and response

#### `detect`

- **Runs on:** agent + controller (correlation rules)
- **Status:** built
- **Default:** core
- **Code:** `internal/detect`, `internal/agent/mods/detect.go`, `rules/*.yml`, `rules/pending/`
- **v3 text to carry over:** L518, L1324-1350 (detection catalog), L1314-1321 (Sigma text: keep only the hand-port parts), L1353 (false-positive controls, content parts)
- **Review rows:** D77 D315 D316 D317 D319 D320 D321 D323 D325 D326 D322 D327 D328 D329 D330 D332 D333 D337 D338 D339 N4.2 N4.3 N4.4 N4.5 N4.6
- **Answers and notes:**
  - Rule format, CI tests, override mode, ATT&CK mapping and suppression records are core (section Rule format); this module is the evaluator plus the catalogue.
  - A4.Q2: Sigma importer cut; hand-port about ten slop rules (D315-D317 list).
  - A2.Q3: `init_module`/`finit_module` audit rule content.
  - A7.Q7: ADD a pass-the-hash rule pack (NTLM 4624 type 3/9 and Kerberos anomalies by scored users from non-scorer sources; content, S). Never restrict NTLM or use Protected Users on scored users.
  - D332/D333: first denied connection is the primary C2 signal; sinkhole leg pending the C2 fingerprinting lab (A6.Q4 framework list); add Cobalt Strike/Mythic rules.
  - D339: keep D21, D22, D23 (USB tier 0 on the controller host); cut D19, D20.
  - D337: reboot/shutdown guard; the boot-critical watchlist (N5.6) merged into `content_guard`.
  - Rule ids owned elsewhere: D5d (integrity), D11 (hunt), D14 (devices), D15 (decoys), D16 (scorer), V1-V4 (vantage), dependency rules (deps; Known bug 2).

#### `respond`

- **Runs on:** agent
- **Status:** partial (tier-0 responses not enabled; `act_enabled` left off)
- **Default:** core
- **Code:** `internal/detect` (act mode), `internal/actions` (response actions), `internal/agent/mods/detect.go`
- **v3 text to carry over:** L519, L1355-1389 (tiers, guards, recipes)
- **Review rows:** D78 D346 D347 D348 D349 D350 D351 D352 D353 D354
- **Answers and notes:**
  - D346: GPO check: if an Enforced GPO reverts the fix, stop the restore loop and raise the GPO finding (N5.3 in `ad`).
  - D347: block by CIDR with a warning; blocks carry the conntrack delete (D155 in `firewall`). Area-3 answer: blocking known red IPs/CIDRs on scored ports is allowed; narrowing a scored port to a source allowlist is not.
  - D348: mark new reservation as costly; prefer in-place golden restore.
  - D354: recipes as YAML next to rules; no IR template per recipe.
  - What David prefers: automatic actions beyond tier 0 are one-click suggestions, never silent.

#### `content_guard`

- **Runs on:** agent
- **Status:** missing
- **Default:** opt-in per service
- **Code:** none yet (parts: `fim` events, `backup` golden copies, `checks` probes, respond guards)
- **v3 text to carry over:** none (new); related L1359 (tier 0), L1906-1913 (golden backups)
- **Review rows:** N4.1 N5.6
- **Answers and notes:**
  - A4.Q1/A4.Q3 constraints: only files listed by path in services.yml; restore only from the plan-tagged golden copy; ignore changes under a plan tag or while a plan holds the service lock; scorer-mimic probe after each restore, roll back our restore and alert on failure; second restore of the same file within 10 min stops and alerts; starts alert-only per service until switched to act.
  - A5.Q3: N5.6 boot-critical watchlist (fstab, grub, initramfs, passwd, shadow, sshd_config, network config, BCD) merges here.

### Integrity and hunting

#### `integrity`

- **Runs on:** agent + controller (ledger build and lookup)
- **Status:** partial (no `binary_integrity` producer; YARA stub)
- **Default:** core
- **Code:** `internal/integrity`, `internal/agent/mods/integrity.go`, `internal/actions` (ledger.*, binary.restore_from_depot), `cmd/phylax` ledger
- **v3 text to carry over:** L271, L520, L524 (scan row), L762, L1394-1465 (whole ledger section), L1449 (YARA)
- **Review rows:** D14 D23 D79 D83 D368 D356 D358 D359 D357 D360 D361 D362 D363 D364 D365 D366 D367 D369 D398 D399 D165 D324 N5.9
- **Answers and notes:**
  - D79/Known bug 6: emit `binary_integrity` so D5d fires.
  - Area 5: no real competition images exist; reference ledgers come from stock images of announced OS versions plus vendor mirrors and Winbindex; extra image files show as unknown at the first sweep and go to the hunt triage queue, not alerts.
  - A5.Q1: YARA keeps scheduled low-priority memory scanning inside the CPU budget as well as file-mode scans; corpus includes the 17 MIT UCF rules with attribution.
  - N5.9: YARA scan on FIM write, as a response recipe (`yara.scan` takes a path).
  - D398/D399: add PAM content hunts (`pam_exec.so`, `nullok`, `pam_deny` tamper).
  - D-1 stands: alert only, no automatic restore.

#### `hunt`

- **Runs on:** agent (collection actions) + controller (diff, queue)
- **Status:** partial (no 10-min repeat)
- **Default:** core
- **Code:** `internal/actions` (hunt.*, collect.*), controller hunt queue (location to confirm), `internal/integrity` (cross-checks run here)
- **v3 text to carry over:** L521 (crossview row), L568 (cross-source tripwires), L1340 (D11), L1562-1616, L1630-1643, L2346-2389 (Appendices B and C, kept as appendices)
- **Review rows:** D80 D103 D331 D391 D393 D394 D392 D395 D396 D397 D400 D403 D405 D406 D407 D408 N5.8
- **Answers and notes:**
  - D80 (David yes): cross-checks as hunt content run by `integrity`: memfd/deleted exe, LD_PRELOAD, BPF program lister (BPF_PROG_GET_NEXT_ID), `/sys/module/*/refcnt` vs `/proc/modules`, brute `/proc/N` walk vs getdents, `cgroup.procs` union vs `/proc`, taint bits. No separate crossview module.
  - D103: drop the connector leg; keep sock_diag vs /proc/net and process-list checks.
  - D395 heuristics; D396 each High finding produces its own IR draft (report).
  - D400: Roundcube is the webmail (area 7 revision), so `web.roundcube_audit` is built; gate OpenCart checks on the detected branch; Docker docroot; drop IIS.
  - Area 7 revision: organizers seed AD with temp admins and user comments; credential hunts read AD descriptions.
  - D392/D356: stock images, not real images (area 5 answer).

#### `hardening`

- **Runs on:** content (plans) over core actions
- **Status:** partial (first-hour plans built; baseline packs missing)
- **Default:** core
- **Code:** `plans/first-hour`, `plans/*.yaml`, `internal/actions` (linux_*, win_*)
- **v3 text to carry over:** L715 (after enrollment), L760 (service config templates), L1966-1982 (first-hour ordering, for D523), L2479-2495 (Appendix H; move into this section)
- **Review rows:** D163 N3.2 D523 D525 D526 D527 D528 D529 D530 D532 D425 N5.2 N5.5 N5.7
- **Answers and notes:**
  - D523/D425: Zerologon becomes a T+0 console step ahead of enrollment and domain rotation if the DC is unpatched.
  - D526/Known bug 1: probe AF_ALG; built-in module needs `initcall_blacklist=algif_aead_init` behind a reboot gate.
  - N5.7/P2: noexec,nosuid on /tmp, /dev/shm, /var/tmp by live remount with a pre-check and remount rollback, opt-in per host; lint that no scored service execs there.
  - A5.Q3 cuts: N5.10 exec gate, N5.11 ModSecurity, D531 Dropbear change. D524 KEV match merges into N5.1.
  - N3.2 reboot-survival preflight is a plan template; reboots are costly (no snapshots).
  - D163: drop IIS; PHP hardening template with scorer-mimic probe and rollback.

#### `ad`

- **Runs on:** agent (on the DC) + content
- **Status:** partial (actions built; GPO response missing)
- **Default:** core (on hosts with the `domain_controller` role)
- **Code:** `internal/actions` (ad_*.go, deception_ad*.go), `internal/collect/winevt/gpo.go`
- **v3 text to carry over:** L751, L1617-1629 (Active Directory hunt), L1715-1717 (Zerologon ordering, krbtgt)
- **Review rows:** D153 D401 D402 N5.3 N5.4 D426
- **Answers and notes:**
  - D153: privileged-group purge stores prior membership as rollback and prints re-add commands.
  - D401: allowlist of expected privileged accounts plus the 'who can reach DA' path query (area 5 answer keeps it).
  - N5.3 GPO response; N5.4 `service.sddl_reset` + `dc.service_repair`.
  - Area 7 revision: ~500 duplicate AD groups to consolidate (inject-like task) is a likely request; consider only as a read-only report unless asked.
  - N11.5 AD/DNS/CA/GPO record-level backup lives in `backup` (uses `ad` actions).

### Network

#### `firewall`

- **Runs on:** agent
- **Status:** built
- **Default:** core
- **Code:** `internal/firewall`, `internal/actions/linux_firewall*.go`, `internal/actions/win_firewall.go`, `internal/manifest/render`
- **v3 text to carry over:** L753, L813-815 (shadow mode, Linux policy), L962-976 (what's allowed out)
- **Review rows:** D155 D156 D181 D180 D214 D215 N6.2
- **Answers and notes:**
  - D155: conntrack delete for affected flows on fw.apply, fw.quarantine and source blocks.
  - D180/N6.2: shadow mode plus a summarizer that shows 'what would be dropped' as a manifest diff to approve; never narrows sources on scored ports (decision 13).
  - Never-block rules derive from the manifest's scored services, never hard-coded ports (area 7 lint correction).
  - The render of policies (D202, D210, D211) is core manifest.

#### `egress`

- **Runs on:** controller (analyzer) + content
- **Status:** partial (analysis unverified; sinkhole nft render only; per-exe missing)
- **Default:** core
- **Code:** `internal/collect/net/egress.go` (input), controller analyzer (location to confirm), sinkhole render bits in `internal/manifest/render` / `internal/firewall`
- **v3 text to carry over:** L516-517, L962-1016 (egress section: allowlist, learn-then-enforce, analysis, sinkhole, gaps), L1880 (Egress page)
- **Review rows:** D216 D221 D76 D222 D470
- **Answers and notes:**
  - D216 (P1, David yes): alert-only allowlist of which programs may connect out, seeded from approved `depends_on` edges plus ledger service binaries; automatic blocking only as a one-click 'block this?' suggestion.
  - D221: pure function over the store; rank by first-seen and binary; periodicity secondary.
  - D76/D222 sinkhole: deferred to the C2 fingerprinting lab (A6.Q4: Mythic Apollo/Poseidon + Gaia, Sliver, Havoc, Metasploit, Empire, Realm imix, chisel/ligolo-ng/frp/ngrok; Cobalt Strike via public profiles and pcaps). Keep the sinkhole only if first-bytes fingerprints discriminate. Code stays until then.
  - D470: Egress page folds into the Traffic page; drop sinkhole captures from it unless the lab keeps the sinkhole.
  - D84/D217 patch proxy cut: patches come from the depot (`depot`).

#### `capture`

- **Runs on:** agent (Linux) + controller (ingest)
- **Status:** built (controller never sends `freeze_capture`)
- **Default:** core (hosts with the `capture` role)
- **Code:** `internal/capture`, `internal/parsers/*`, `internal/agent/mods/capture.go`, `internal/controller/capture_ingest.go`, `docs/capture.md`
- **v3 text to carry over:** L515, L1036-1080 (capture tiers, mechanics, parsers, pulled pcaps)
- **Review rows:** D74 D231 D234 D236 D232 D233 D237 D238 D239 D240 D241 D243
- **Answers and notes:**
  - D235 Windows raw-socket capture cut: Windows coverage from Sysmon 3, 5156/5157 and Palo logs.
  - D240: add TFTP and NTP parsers (N7.1). D241: keep TDS and TLS; LDAP only if an LDAP check is scored; cut Splunk REST parsing. D242 cut.
  - D237/Known bug 7: controller must send `freeze_capture` for controller-scope collects.
  - D244 Palo-side pcap is in `devices` (kept per area 6 answer).

#### `devices`

- **Runs on:** controller
- **Status:** built
- **Default:** core (when devices.yml declares devices)
- **Code:** `internal/devices`, `internal/devices/palo`, `internal/devices/vyos`, `internal/actions/dev_*.go`, `internal/controller/devexec_run.go`, `dir_devices.go`
- **v3 text to carry over:** L18/L275, L767, L1000 (Palo deny pull), L1073-1076 (Palo-side capture), L1343 (D14), L1644-1696 (device adapters), L2486, L2493 (Appendix H rows)
- **Review rows:** D18 D170 D409 D410 D411 D412 D413 D414 D415 D416 D417 D418 D419 N6.1 D219 D244 D334 D524 D531
- **Answers and notes:**
  - A6.Q1: Cisco FTD read-only config export only, no adapter (N10.5 pairs).
  - D244 KEEP (David finds it interesting), gated on the licence/capability flag; D409 keeps `Capture` in the adapter interface.
  - D524: also audit interface management profiles and GlobalProtect; KEV match of `sw-version` merges into N5.1 `vuln`.
  - D531: Dropbear change cut; plan stays.
  - N6.1: scheduled config backups to a declared host.
  - D334/Known bug 2: dependency rules reuse D14; renumber those in `deps`.

### Scoring and credentials

#### `checks`

- **Runs on:** controller + agents with `check_runner`
- **Status:** built (no controller scheduler yet, docs/ui.md)
- **Default:** core
- **Code:** `internal/checks`, `internal/controller/checks_hub.go`, `checks_ops.go`, `internal/vantage/checkrunner.go`
- **v3 text to carry over:** L268, L1081-1137 (active checks; scorer model paragraphs go to `scorer`), L1162-1169 (checks view)
- **Review rows:** D12 D245 D252 D253 D254 D255 D256 D257 D258 D259 D260 D261 D262 D264 D263 D265 D266 D267 D268 D269 N7.1 N7.2 N8.1
- **Answers and notes:**
  - N7.1 TFTP and NTP check types; never-block lint only when TFTP/NTP is scored in the manifest (area 7).
  - A7.Q3: Orange customer flows (N7.2) are multi-step flow checks inside `checks`, run from Kali and LAN; reuse as the lab Orange traffic generator (D511).
  - N8.1 (area 8 answer): service doctor collect plan runs on the first failed check of a scored service (read-only; once per failure streak; re-run on demand).
  - D177 scorer-mimic probe contract is core (execution); this module supplies the probe library, probe users chosen per credlist.

#### `scorer`

- **Runs on:** controller
- **Status:** built
- **Default:** core
- **Code:** `internal/scorer` (clock, discovery, fingerprint, fptable, sla, csv, pcr)
- **v3 text to carry over:** L84-96 (v3 scorer-model change table, carried into core Environment), L1085-1108 (scorer model, round clock), L1138-1161 (credentials the scorer uses, discovery, SLA), L2460-2477 (Appendix G, kept as appendix)
- **Review rows:** D246 D247 D248 D249 D250 D251 D270 D271 D272 D273 D274 D275 D276 D277 D278 D279 D280 N7.5 D336
- **Answers and notes:**
  - Area 7 revision: Quotient is not reachable from inside; D251 learning from observed logins (scorer-labeled traffic plus auth events) is the primary source of scored accounts, kept, not deleted. Quotient's list is not an input.
  - D278-D280: no portal read and no paste-the-list primary path; service status from our own checks plus an optional hand-entered Up/Down note.
  - D277: accrual configurable (`reset` or `per_round`, phase schedule) as plain scorer config, not an event profile.
  - N7.5 points-at-risk view.
  - Quotient facts (area 3): `GET /api/credlists` exists for teams, service-to-credlist mapping is admin-only; Timeout < Delay - Jitter, default Timeout = Delay/2 (`engine/config/config.go:356`). These are recorded in core Environment; the module uses the measured round delay.

#### `vantage`

- **Runs on:** agent (Kali roles) + controller
- **Status:** built
- **Default:** core (Kali)
- **Code:** `internal/vantage` (canary, checkrunner, compare, scan, verify)
- **v3 text to carry over:** L1349 (V1-V4), L1466-1503 (the Kali section)
- **Review rows:** D370 D371 D372 D373 D374 D375 D376 D377 D378 D379 D340 D341 D342 D343
- **Answers and notes:**
  - D376: verify per credlist. D377: diff against the scored set only, alert on a missing scored port, full scan before each day's organizer scan window.
  - D379: keep Zerologon check-only and SMB/WinRM exposure; cut NAT-behaviour, blocked-source and Palo-load probes.
  - D340 V2: also diff against red's dangerous-port list and alert on a scored port closed.
  - D45 Kali path render is core topology.

#### `creds`

- **Runs on:** controller + content
- **Status:** partial (not keyed per credlist; no revert state)
- **Default:** core
- **Code:** `internal/creds`, `internal/scorer/pcr.go`, `internal/scorer/csv.go`, `internal/vault`
- **v3 text to carry over:** L764, L1697-1742 (credentials, PCR as a transaction), L2456-2459 (Appendix F, move into this section)
- **Review rows:** D420 D421 D422 D423 D424 D427 D428 D429 D430 D167 D431 D432 D433 N7.3
- **Answers and notes:**
  - Decision 5: never mass-rotate. D424: scored users rotate only on evidence of compromise or leak.
  - Area 7 revision: PCRs are entered by a human in Quotient outside the environment; no clipboard (A7.Q5). Phylax generates a short typeable list of (credlist, user, new password) and verifies by login afterwards. `pcr.submit` is moot.
  - Cross-cutting idea 4: key by (account, credlist) everywhere; N7.3 revert re-sync re-applies on the host or generates PCRs back.
  - A7.Q6 is open (PCR policy vs full AD dumps); A7.Q8: rotated scored passwords live in the existing age vault.
  - D432/D433: no admin accounts are scored (decision 10), so admins rotate freely at T+0.
  - N7.4 T+0 admin rotation is core enrollment.

### Analysis

#### `traceback`

- **Runs on:** controller (analyzer)
- **Status:** built
- **Default:** core
- **Code:** `internal/traceback`
- **v3 text to carry over:** L1170-1217 (traffic labels, what counts as a change, the trace-back chain)
- **Review rows:** D281 D282 D283 D284 D285 D286 D287 D288 D290 D291 D289 D292
- **Answers and notes:**
  - D289: drop IIS.
  - D286 queries as content.
  - Rewrite as pure functions over store queries (N1.3).

#### `chains`

- **Runs on:** controller (analyzer)
- **Status:** built (one test file)
- **Default:** core
- **Code:** `internal/chains`, `internal/store/chains.go`
- **v3 text to carry over:** L272, L1218-1262 (attack chains)
- **Review rows:** D15 D293 D294 D295 D296 D297 D298 D299 D300 D301 D302 D303 D304 D305
- **Answers and notes:**
  - D15: rewrite as pure functions over store queries with fixture tests; least-tested large package.
  - D304: campaign merge is a view only; one IR per narrative or persistence mechanism.

#### `deps`

- **Runs on:** agent (collector) + controller (graph)
- **Status:** built
- **Default:** core
- **Code:** `internal/deps`, `docs/deps.md`, `rules/deps.yml`
- **v3 text to carry over:** L1020-1035 (service dependency discovery)
- **Review rows:** D223 D224 D225 D226 D227 D228 D230 D229
- **Answers and notes:**
  - D229/Known bug 2: rename D14/D14b/D14c to DEP1-3; one rule-id namespace with a CI registry check (cross-cutting idea 3).

#### `vuln`

- **Runs on:** controller (analyzer) over `inventory`
- **Status:** missing
- **Default:** opt-in
- **Code:** none yet
- **v3 text to carry over:** none (new)
- **Review rows:** N5.1
- **Answers and notes:**
  - A5.Q2: KEV plus the vault's vendor advisories (Splunk, PAN-OS, OpenCart); no hand-maintained advisory file.
  - D524 PAN-OS KEV match merges here (A5.Q3). Feeds the version/CVE generator table (D492 in `report`).
  - Unknown when backports can't be judged; no distro OVAL feeds in the first cut.

### Deception

#### `decoys`

- **Runs on:** agent (unprivileged decoy process)
- **Status:** built (decoy process not split yet, docs/agent.md)
- **Default:** opt-in per host (decoys.yml)
- **Code:** `internal/decoys`, `internal/agent/mods/deception.go`, `internal/controller/deception_*.go`, `pools/`
- **v3 text to carry over:** L487, L523, L1504-1522 (intro, principles), L1540-1550 (decoy services), L1556-1561 (exposure), L1344 (D15)
- **Review rows:** D64 D82 D198 D206 D382 D383 D385 D386 D387 D388 D390 D335
- **Answers and notes:**
  - A9.Q1: keep the built extra decoys (D383 = KEEP), LAN-only, opt-in per host in decoys.yml.
  - D389 public decoys cut: organizer scans score extraneous services.
  - D514 keeps decoy tests (area 13 answer).

#### `honeytokens`

- **Runs on:** agent + controller (registry)
- **Status:** built
- **Default:** opt-in per host (decoys.yml)
- **Code:** `internal/honeytokens`, `internal/actions/deception_*.go`, `internal/controller/deception_registry.go`
- **v3 text to carry over:** L1523-1539 (honeytokens incl. LSASS decoy session), L1551-1555 (decoy content)
- **Review rows:** D380 D381 D384
- **Answers and notes:**
  - A7.Q7: honey AD accounts are part of the policy against full AD dumps.
  - Honey web paths never on scored content (D386).

### Reports and generators

#### `report`

- **Runs on:** controller
- **Status:** partial
- **Default:** core
- **Code:** `internal/report`, `internal/controller/report_*.go`, `inject-kit/`, `plans/wazuh.evidence.yaml`, `docs/report.md`
- **v3 text to carry over:** L952-953 (generated artifacts), L1898-1900, L1915-1943 (IR drafter, inject kit)
- **Review rows:** D208 D487 D488 D489 D490 D492 D493 N10.1 N10.2 N10.3 N10.4 N10.5 N10.6 D438
- **Answers and notes:**
  - Decision 6 and A10.Q1: generators only; prewritten inject material is a separate set outside Phylax. Cut policy, plan, risk-register and framework templates; keep one memo shell.
  - A10.Q4: generators prioritise on-screen views that screenshot well from outside; files are secondary, moved out via the team Nextcloud (writable from inside). D489's Nextcloud fallback becomes the file-export path (manual upload; no integration unless trivial).
  - A10.Q3: evidence run (N10.3) and inject queries (N10.6) are `probe.run` uses (inventory).
  - Decision 7 / Known bug 3: fpdf, drop every Typst reference.
  - D208 checklists move to the UI grid (core).

### Operations

#### `backup`

- **Runs on:** agent (dump actions) + controller (store)
- **Status:** missing
- **Default:** opt-in (reference manifest enables it)
- **Code:** none yet (`mysql.dump` and related actions exist in `internal/actions`)
- **v3 text to carry over:** L1898-1913 (service backups)
- **Review rows:** D481 D482 D483 D484 D485 D486 N11.5
- **Answers and notes:**
  - A11.Q2: services' own dump tools (`mysqldump`, `sqlcmd`, `Backup-GPO`) as labeled actions; Go reimplementations acceptable where simpler.
  - D486: compare record counts before and after restores (data loss is a per-user penalty).
  - A10.Q2 (tentative): generic restore of a service's golden backup onto a different declared host; no hot-site plans.
  - Golden copies feed `content_guard`.

#### `teamfeed`

- **Runs on:** agent CLI + controller
- **Status:** missing
- **Default:** opt-in
- **Code:** none yet (rides the existing control channel)
- **v3 text to carry over:** none (new); related L1992 (captain's list), strategy §6.4 manual change log
- **Review rows:** N11.1
- **Answers and notes:**
  - A11.Q3 yes: `phylax say` and `phylax claim <host>` only; a claim tags a work window.

#### `notify`

- **Runs on:** controller
- **Status:** missing
- **Default:** opt-in
- **Code:** none yet
- **v3 text to carry over:** none (new)
- **Review rows:** N11.3
- **Answers and notes:**
  - Local audible alarm first; optional webhook sink (title, severity, host only) needs an egress allowance.

### Integrations and depot

#### `depot`

- **Runs on:** controller + agent (fetch)
- **Status:** partial (no cache pipeline; agent `fetch` handler is a no-op)
- **Default:** core
- **Code:** `internal/depot`, `internal/depot/gotools`, `cmd/phylax/depot.go`, `depot/recipes`, `internal/actions/linux_pkg.go`
- **v3 text to carry over:** L270, L1455-1458 (local depot), L1784-1819 (offline-first), L981-993 (patch windows: replace with depot installs), L761 (packages)
- **Review rows:** D13 D21 D207 D25 D451 D453 D452 D26 D442 D443 D444 D445 D446 D447 D448 D449 D450 D164
- **Answers and notes:**
  - D442-D445: one signed index with a priority field instead of four tiers; remove Typst; add vendor fixed builds and the KEV feed.
  - D446-D450: drop repo/proxy rule reasoning; needs the agent `fetch` handler (D117, core wire).
  - D164: `pkg.install` from the depot over `fetch`; `pkg.repair` preflight; reboot-survival gate (N3.2 in hardening).
  - D26: `phylax tools` Go-native fallbacks stay.
  - Pre-quals week: nothing in the repo can change after the repo freeze; event-specific data must be learnable or enterable at runtime.

#### `wazuh`

- **Runs on:** content (plans) + controller health
- **Status:** partial
- **Default:** opt-in
- **Code:** `internal/integrations/wazuh`, `internal/actions/app_wazuh.go`, `plans/wazuh.deploy.yaml`
- **v3 text to carry over:** L765 (integration actions), L1743-1775 (OSS alongside, Wazuh deploy)
- **Review rows:** D168 D434 D435 D436 D437
- **Answers and notes:**
  - D168 lists all integration actions: `wazuh.deploy`, `wazuh.health` here; `splunk.hec_setup` belongs in the `splunk` section and `suricata.analyze_pcap` in `suricata`; `av.clamav` is cut (D441).
  - D438 Wazuh evidence pack is a `report` evidence-run recipe.
  - Placement is config (decision 4).

#### `splunk`

- **Runs on:** controller (HEC forwarder) + content
- **Status:** built
- **Default:** opt-in
- **Code:** `internal/integrations/splunk`, `internal/actions/splunk_*.go`, `plans/splunk.forwarding.yaml`
- **v3 text to carry over:** L1754, L1776-1779 (Splunk forwarding)
- **Review rows:** D440
- **Answers and notes:**
  - D440: small dashboards pack (service health, lateral movement, process tree by ProcessGuid, on top of logons, group changes, services, firewall events); recognise the organizer's pre-installed toolkit and audit rules so they don't read as tamper. No Defender Toolkit coexistence work (area 12 answer).

#### `suricata`

- **Runs on:** controller (offline over pulled pcaps)
- **Status:** built (readers)
- **Default:** opt-in
- **Code:** `internal/integrations/suricata`
- **v3 text to carry over:** L1751, L1780-1783 (Suricata and Zeek)
- **Review rows:** D439
- **Answers and notes:**
  - D439: Zeek `ignore_checksums`, Suricata `-k none` for offloaded-NIC pcaps; runs only on demand.

## Core and placeholder sections

Rows below are already applied in the phase-1 core sections (or belong to a placeholder section that a later phase writes). Listed so the coverage is complete.

### Summary and Conventions (decisions table)

- **Target:** `core:conventions`
- **v3 text:** L5-67
- **Review rows:** D1 D2 D3 D4 D5 D6 D8 D9 D7

### Design principles

- **Target:** `core:principles`
- **v3 text:** L279-295
- **Review rows:** D27 D28 D29 D30 D32 D33 D34 D35 D36 D37 D38 D40 D41 D31 D39

### The module contract

- **Target:** `core:contract`
- **v3 text:** L502-504 (module config blocks); new
- **Review rows:** N1.1 N1.2 N1.3

### Core components: Architecture overview

- **Target:** `core:architecture`
- **v3 text:** L239-277
- **Review rows:** D11 D16 D17

### Core components: Topology, relays and firewall layers

- **Target:** `core:topology`
- **v3 text:** L297-390
- **Review rows:** D44 D48 D46 D47 D111 D49 D50 D51 D45

### Core components: Trust model

- **Target:** `core:trust`
- **v3 text:** L392-478
- **Review rows:** D52 D53 D54 D55 D56 D57 D58 D60 D61

### Core components: Agent runtime

- **Target:** `core:agent-runtime`
- **v3 text:** L480-500, L528-533, L560-589
- **Review rows:** D62 D63 D65 D66 D67 D68 D87 D99 D100 D101 D104 D102 D105 D106 D107 D534

### Core components: Wire protocol and spool

- **Target:** `core:wire`
- **v3 text:** L590-679
- **Review rows:** D108 D109 D110 D113 D114 D115 D116 D117 D118 D119 D120 D121 D122 D123 D124 D125 D126 D127 D128 D129 D130 D131 D132 D133 D134

### Core components: Enrollment, bootstrap and recovery

- **Target:** `core:enrollment`
- **v3 text:** L681-735
- **Review rows:** D19 D24 D135 D136 D137 D138 D139 D140 D141 D142 D143 D144 D145 D146 D147 D148 D149 N7.4

### Core components: Execution engine

- **Target:** `core:execution`
- **v3 text:** L737-848, L1390-1392
- **Review rows:** D69 D85 D86 D150 D151 D152 D154 D158 D161 D166 D157 D159 D160 D162 D169 D171 D172 D173 D174 D175 D176 D177 D178 D179 D182 D184 D183 D185 D186 D187 D188 D189 D190 D355 N3.1 N3.3 N3.4

### Core components: Manifest

- **Target:** `core:manifest`
- **v3 text:** L850-960
- **Review rows:** N1.4 D42 D43 D192 D193 D194 D195 D196 D197 D199 D200 D201 D191 D213 D203 D204 D205 D209 D212 D202 D210 D211 N7.6

### Core components: Event store and vault

- **Target:** `core:store`
- **v3 text:** L1820-1862, L1894-1896
- **Review rows:** D454 D455 D457 D458 D456 D459

### Core components: UI shell

- **Target:** `core:ui`
- **v3 text:** L1864-1892, L1948-1950
- **Review rows:** D59 D460 D461 D462 D463 D465 D466 D467 D464 D468 D469 D471 D472 D473 D474 D475 D476 D477 D479 D478 D494 D503 N11.4 N11.6

### Core components: Rule format

- **Target:** `core:rules`
- **v3 text:** L1267-1310, L1351-1353
- **Review rows:** D306 D307 D308 D309 D310 D311 D312 D22 D313 D344 D345

### Operations (placeholder)

- **Target:** `section:operations`
- **v3 text:** L1944-1994
- **Review rows:** D495 D496 D497 D498 D499 D500 D501 D502 D504 D505

### Testing and lab (placeholder)

- **Target:** `section:testing`
- **v3 text:** L1995-2105
- **Review rows:** N13.1 D506 D507 D508 D509 D510 D511 D512 D513 D514 D515 D516 D517

### Appendices

- **Target:** `section:appendices`
- **v3 text:** L2298-2498
- **Review rows:** D518 D533 D519 D520 D522 D521

## Cut rows

One line each in the design's "Removed in v4" appendix; not assigned to any section.

- **Cut:** D20 D112 D89 D92 D314 D318 D404 D235 D242 D389 D491 D10 D84 D217 D441 N3.5 N5.10 N5.11 N11.2 D480
- **Not cut although the row's call was CUT (answers override):** D76 D222 (sinkhole, deferred to the C2 fingerprinting lab), D244 (Palo-side pcap kept), D383 (extra decoys kept, LAN-only, opt-in), D489 (Nextcloud fallback becomes the file-export path).
- **Partial cuts inside kept rows:** D157 `modules.disable_loading` action deleted; D339 rules D19 and D20; D379 NAT-behaviour, blocked-source and Palo-load probes; D241 Splunk REST parser; D163/D289/D400 IIS; D490 policy, plan, risk-register and framework templates; D85 typed parameters; D531 Dropbear change; D278-D280 portal read and paste input; D430/D167 `pcr.submit`; D168 `av.clamav`; D442-D445 Typst.

## Coverage check

Run from the repo root:

```sh
python3 - <<'EOF'
import re
from collections import Counter
rows = []
for line in open("docs/impl/review.md"):
    if line.startswith("| D") or line.startswith("| N"):
        rows += [t.rstrip(".") for t in re.findall(r"[DN][\d.]+", line.split("|")[1])]
brief = open("docs/impl/modules.md").read().split("## Coverage check")[0]
assigned, cut = Counter(), set()
for line in brief.splitlines():
    if line.startswith("- **Review rows:**"):
        assigned.update(line.split(":**", 1)[1].split())
    elif line.startswith("- **Cut:**"):
        cut.update(line.split(":**", 1)[1].split())
missing = [r for r in rows if r not in cut and assigned[r] == 0]
dupes = [r for r, n in assigned.items() if n > 1]
unknown = [r for r in assigned if r not in rows]
both = [r for r in cut if assigned[r]]
print(f"review rows {len(rows)}, cut {len(cut)}, assigned {len(assigned)}")
print("missing", missing, "duplicated", dupes, "unknown", unknown, "cut-and-assigned", both)
assert not (missing or dupes or unknown or both)
print("OK: every non-cut D and N id is assigned exactly once")
EOF
```

