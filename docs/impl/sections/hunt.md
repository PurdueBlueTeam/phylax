#### `hunt`

Every team starts from identical images of known OS versions, and the red team may already hold persistence at drop flag. The hunt diffs each live host against a clean reference, repeats on a cadence and after every restore, scores what differs, and turns approved findings into remediation that disables and quarantines but never deletes. It also holds the rootkit cross-check catalogue (run by `integrity`), the application reference checks and the credential-file hunt.

**1. Purpose and evidence**

- **What it does.** Agent-side collection actions gather the same artifacts natively on each host; the controller diffs them against the reference, enriches and scores each difference, and feeds a review queue in the UI. Approved items become a remediation plan. Accepted items become the host's live baseline in overrides, so the hunt stays quiet after review.
- **Evidence.** Prebaked persistence was most of red's 2026 access (redteam report), and prebaked items are not changes, so change monitoring cannot see them [COV §6.10, TTP X-2]. The firewall-killer timer is a known prebake. "We thought it was done but it wasn't": checklists were untested [[discord-2026q-lessons#e1]], which is why the post-hardening verification is part of the hunt content. Persistence points come only through IRs [[xixsaucexix-century-2026#e5]], so each High finding also produces its own IR draft.
- **Evidence against.** There are no real competition images (review area 5), so the reference is a stock build and the image's own extras show as differences at first. The triage queue exists for that case; extras are not alerts. A hunt on a rootkitted host can be lied to (see the cross-checks).
- **Decisions applied.** Review D80 (cross-checks as hunt content), D103, D331, D391 to D397, D400, D403 to D408, N5.8. D404 (`hunt.pii`) is cut (no evidence it scores).

**2. Status and code**

Status: **partial**. The pieces exist as separate actions; the hunt as a flow does not.

| Piece | Where | State |
| --- | --- | --- |
| Application audit actions: `web.opencart_audit`, `mysql.audit`, `mssql.audit`, `win.defender.audit`, `ad.account.audit_groups`, `ad.zerologon_check` | `internal/actions` | built |
| Remediation actions: `file.quarantine`, `file.restore`, `file.attr`, `systemd.dropin`, `win.defender`, `ssh.authorized_keys` | `internal/actions` | built |
| Ledger sweep, verdict events, the check loop | `internal/integrity` | built (module `integrity`) |
| Hunt collection actions `hunt.baseline_diff`, `hunt.persistence`, `hunt.apps`, `hunt.creds`, `hunt.remote_access`, `collect.inventory`, `collect.files` | none registered | missing |
| Reference artifacts (file inventory, autostarts, accounts, kernel, service config) per OS | none | missing (lab build) |
| Controller diff, enrichment, scoring, review queue, `hunt_finding` table | none (the controller hunt queue location is unconfirmed) | missing |
| The 10-minute repeat and the post-restore trigger | none (D22 is a parked rule, `rules/pending/needs_producer.yml`) | missing |
| Rootkit cross-checks | none | missing (specified here, run by `integrity`) |
| Kill list, credential-file hunt, Roundcube audit | none | missing |

**3. Capability manifest**

| Field | Value |
| --- | --- |
| Name | `hunt` |
| Sides | agent (collection actions), controller (diff, queue, scoring) |
| OS | both |
| Privilege | root |
| Roles | any host; controller side on the controller |
| Consumes | `integrity.crosscheck`, `integrity.verdict` with `first_sweep`, `enroll`, `respond.loop`, `ad.finding` (for the AD part of the queue), `inventory.*` when that module is enabled |
| Emits | `hunt.finding` (schema 1, high), `hunt.run` (schema 1, normal) |
| Budget | CPU 5 ms/s average (collection runs as a low-priority burst), held 16 MB, 2 events/s, burst 40, 200 KB/min out, disk 20 MB |
| Default | core |
| Tables | `hunt_finding` (id, host, artifact, score, state: open, approved, rejected, accepted, remediated; evidence references) |
| Content | `hunt/checks/*.yml` (persistence, application, credential-file checks), `hunt/killlist.yml`, `hunt/heuristics.yml`, `hunt/baselines/` (signed reference artifacts per OS, release assets in the cache's first tier), `plans/hunt/` |
| Actions | `hunt.baseline_diff`, `hunt.persistence`, `hunt.apps`, `hunt.creds`, `hunt.remote_access`, `collect.inventory`, `collect.files` (all `none` risk, read-only; `hunt.ad` is the `ad` module's) |
| Pages | Hunts (the review queue and the baseline views) |
| Evidence | [[dannygaev-ccdc2025#e7]], [[bluescreenofwin-stanford-ccdc-25#e16]], [[cyberuci-ccdc#e11]], [[xixsaucexix-century-2026#e5]], [[known-exploited-vulnerabilities#e1]], [[2026-mw-regional-bcom12t-response#e1]], [[nvd#e1]], [[discord-2026q-lessons#e1]] |

**4. Configuration**

```yaml
# manifest/modules/hunt.yml
hunt:
  repeat_interval_sec: 600        # re-run on every host; also after every restore, re-enrollment or reset (D22)
  baselines: [rocky-9, ubuntu-22.04, debian-12, server-2019, server-2022, windows-11]
  apps: [opencart, roundcube, apache_php, postfix, dovecot, mysql, mssql, dns, smb, splunk]   # filtered by detected product and branch
  kill_list: hunt/killlist.yml    # remote-access agents hunted and tier-0 disabled unless the manifest allows them
  allowed_management_agents: [wazuh, splunk]
  triage:
    first_sweep_unknowns: queue   # extras of the stock image go to the queue, never to alerts
  creds:
    ad_descriptions: true         # read AD user descriptions as part of the credential hunt
```

```go
// package hunt (controller side) and plan.HuntSettings (agent side)
type HuntSettings struct {
	ModuleLimits
	RepeatIntervalSec int      `json:"repeat_interval_sec,omitempty"` // default 600
	Apps              []string `json:"apps,omitempty"`
	KillList          []string `json:"kill_list,omitempty"`           // names resolved from hunt/killlist.yml
	AllowedAgents     []string `json:"allowed_management_agents,omitempty"`
	CredPatterns      []string `json:"cred_patterns,omitempty"`       // from hunt/checks/creds.yml
}
```

**5. Events**

Consumed: as in the manifest. `enroll` and `respond.loop` start a targeted run; `integrity.crosscheck` and first-sweep `integrity.verdict` become findings.

Emitted:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `hunt.finding` | 1 | high for High, normal otherwise | `id`, `host`, `artifact` (kind and key), `score` (high, medium, low), `reason` (the matching trigger or heuristic), `enrichment` (hash, signer, owner package, ledger verdict, file times, referrer), `reference` (what the baseline said), `state` |
| `hunt.run` | 1 | normal | `host`, `trigger` (`enroll`, `interval`, `restore`, `lineage`, `manual`), `collected`, `added`, `modified`, `missing`, `duration_ms` |

**6. Behaviour**

*Reference builds.* One scripted build per announced OS version (Packer templates in the lab repo), with the same roles the competition hosts run. These are stock images (review D392, area 5): there is no real competition image, so the build records the stock state and the image's own extras are triaged at the first run. Each build records:

| Artifact | Linux | Windows |
| --- | --- | --- |
| File inventory with hashes (feeds the ledger) | `/usr`, `/bin`, `/sbin`, `/lib*`, `/etc`, `/opt` | `System32`, `SysWOW64`, `drivers`, `Program Files` |
| Ownership and signing | Which package owns each file | Authenticode signer for every executable |
| Autostarts | Enabled units and timers, generators, cron, at, rc, profile.d, motd, udev, PAM, NSS, loader config | Services, scheduled tasks (XML), Run keys, WMI subscriptions, LSA packages, IFEO, Appendix C |
| Accounts | passwd, group, sudoers | Local users and groups |
| Kernel | Modules, sysctls, BPF programs, file capabilities, SUID set | Drivers with signers |
| Service config | Distro defaults for Apache or httpd, PHP, Postfix, Dovecot, MySQL | Clean DNS, SQL Server and Splunk-on-Windows config where relevant (IIS is dropped: it is not in the 2027 environment [[vulns-windows]]) |

References ship as signed release assets in the cache's first tier. The persistence locations that the collection covers are in Appendix B (Linux) and Appendix C (Windows). Extensions from the peer review (review N5.8, cheap additions to the paths and checks, content only):

- Linux: `/var/spool/at*`, `/etc/xinetd.d`, polkit rules, GRUB, `if-*.d` and `network-scripts`, NetworkManager dispatcher scripts, `.git/hooks`, `/etc/modules-load.d`, D-Bus service files, systemd timers, `/etc/resolv.conf`.
- Windows: COM hijacks (`HKCU\...\CLSID\*\InprocServer32`), `HKLM\Software\Microsoft\NetSh`, PowerShell `$PROFILE`, BITS jobs, startup folders.

Peer: RnDSweats Falco PERSIST group and `persistenceHunter.ps1@92cae3b`. Verify against D6o (hook directories) before adding so rules do not double up.

*The live hunt.* A read-only plan that runs on every host in parallel with credential rotation. It runs first at enrollment, then **every 10 minutes and after every restore, re-enrollment or reset**, because prebaked items are not changes and a restored host can be re-infected [COV §6.10, TTP X-2]. D22 (the re-infection trigger) starts the post-restore run. The diff uses Go-native collection actions, without trusting host tools.

1. **Collect** the same artifacts natively (`hunt.persistence`, `collect.inventory`, `collect.files`). If the `inventory` module is enabled on the host, the repeat reuses its differential snapshots instead of a full collect.
2. **Diff** against the reference plus the host's accepted baseline: added, modified and missing items.
3. **Enrich** each finding with hash, signer, owner, package, ledger verdict, file times (watching for timestomping), and what references it.
4. **Score:**
   - **High:** an unsigned or non-vendor binary referenced by any autostart; an unowned file in a system directory; a modified packaged binary (ledger `mismatch`); `/etc/ld.so.preload` content; a new PAM or NSS module; IFEO debuggers; LSA packages; a non-stock IIS module (only if IIS is present); `ServerLevelPluginDll` on the DNS service; a service unit with `LD_PRELOAD` or unneeded ambient capabilities; any member of a privileged AD group outside the allowlist (`ad`).
   - **Medium:** added cron, timer or task with a script action; new SUID file or file capability; added SSH key; `chattr +i` on a unit, sudoers file or webroot file; PHP `disable_functions` or `auto_prepend_file` differences; modified default config.
   - **Low:** everything else that differs.
   - **Heuristics (review D395),** from `hunt/heuristics.yml`: a service path under a user directory; a LocalSystem service with no description; a service name of 5 characters or fewer; a name with entropy above 3.5 [[dannygaev-ccdc2025#e7]], [[bluescreenofwin-stanford-ccdc-25#e16]]; and AD users whose Description, Company or Department length is an outlier [[cyberuci-ccdc#e11]]. A heuristic hit raises the score by one level; it never creates a High alone.
5. **Review** in the UI as a queue. Approved items become a remediation plan that disables and quarantines (moves, with metadata) but **never deletes**. `chattr -i` is applied explicitly and logged before a remove. Each High finding also produces its own IR draft (the `report` module consumes `hunt.finding` at High) (review D396).
6. **Triage queue.** At the first run on a host, items that exist only because the real image differs from the stock reference (the first-sweep `unknown` items) are listed under Triage, not scored as findings, until the operator accepts them into the host's baseline.

*Remediation actions* are the core persistence-cleanup family: `cron.disable`, `unit.disable`, `unit.mask`, `task.disable`, `wmi.subscription_remove`, `runkey.remove`, `ld_preload.clear`, `caps.clear`, `pkg.unhold`, plus `file.quarantine` and `file.attr`. Every hunt finding ends there.

*Keeping the baseline current (review D407, D408).* Accepted findings and inject changes go into overrides as the host's live baseline. Later hunts diff against reference plus overrides. Each host also keeps an **expected-state baseline** (systemd units, kernel modules, services, listeners, scheduled tasks) from the manifest and the first clean sweep, so drift is a diff against known state. Drift items offer adopt or revert (core Manifest: drift).

*Rootkit cross-checks* (review D80, D103, D331; David: yes). They are hunt content run by `integrity` on a timer, with no separate module. Native calls only. Peer: UCF RedBaron2 `misc/{lkm,walk,bpf,kmsg}.rs@85aae3f`.

| Check | Method | Finding |
| --- | --- | --- |
| Deleted or memfd executable | `readlink /proc/*/exe` for `(deleted)` or `memfd:` | process running from an unlinked file (D5a) |
| `LD_PRELOAD` | `/proc/<pid>/environ`, `/etc/ld.so.preload`, `/proc/<pid>/maps` | injected library in a service |
| BPF program lister | `BPF_PROG_GET_NEXT_ID` syscall, minus self and PID 1, against the host baseline | a hooking program outside the baseline (D11c) |
| Hidden module | `/sys/module/*/refcnt` against `/proc/modules` | module present in sysfs, absent from the list |
| Hidden process | a brute `/proc/N` stat walk against `getdents` on `/proc`, two runs to avoid races | PID that stats but is not listed |
| Cgroup union | the union of every `cgroup.procs` against `/proc` | process in a cgroup but not in `/proc` |
| Kernel taint | `/proc/sys/kernel/tainted` bits and kmsg patterns (`taints kernel`, `module verification failed`, `bpf_probe_write_user`) | unsigned or forced module load, hooking helper use |
| Hidden socket | `sock_diag` against `/proc/net/{tcp,udp,tcp6,udp6}` | socket the kernel reports and `/proc` hides |
| Process list against sockets | the process list against `sock_diag`-owned pids | owner pid not in the process list |
| Windows | process list from several APIs against each other; driver list against the reference | hidden process, unsigned or new driver (Sysmon 6) |

The proc connector is not used (review D89 cut), so the audit-against-connector leg of the v3 cross-source tripwires is dropped. Stolen-key detection (one agent key used from two places) is a controller check in the core self-protection list. The BPF lister is in Go about the size of UCF's (about 80 lines); `shortcut` below on kernels that restrict the syscall.

*Remote-access agent kill list (review D397).* A signed, editable list in `hunt/killlist.yml` of management agents that are hunted and tier-0 disabled unless the manifest allows them: Teleport, Webmin, MeshCentral agent, AWS SSM agent, TeamViewer, Tailscale, ngrok, cloudflared, chisel, frp [WT §9.1]. The manifest's "approved management agents" exception covers Wazuh and Splunk. D3c is the runtime rule; the hunt finds installed but idle ones.

*Application references (review D400).*

| Component | Reference | Check |
| --- | --- | --- |
| OpenCart (if present) | Vendor archive for the **detected version and branch** | Hash every webroot file. Unknown scripts and modified core files (`framework.php`-style backdoors) go to the top. Extra `oc_user` rows. The check is gated on the detected branch (4.1.0.4 was seen [[2026-mw-regional-bcom12t-response#e1]]; most CVEs target 4.0.2.x [[nvd#e1]]) and resolves a Docker docroot from the manifest's container volumes |
| Roundcube (the 2027 webmail) | Vendor archive for the version | `web.roundcube_audit`: version against KEV (11 Roundcube CVEs are on KEV [[known-exploited-vulnerabilities#e1]]), `installer/` present, reachable `config/`, `logs/`, `temp/`, plugin directory diff against the vendor release. Built once the product is known; area 7 revision names Roundcube |
| Apache or httpd, PHP | Package defaults | Modules directory and `extension_dir` against the package; `disable_functions`; `auto_prepend_file`; unit `Environment=LD_PRELOAD` |
| Postfix | Package defaults and ledger | `master.cf` pipe transports and content filters; `/etc/aliases` pipes; the binaries |
| Dovecot | Package defaults | Post-login scripts, global sieve scripts, passdb and userdb pointing at scripts |
| MySQL | Package defaults | User-defined functions, plugin directory, accounts with FILE or SUPER, `mysql.user` diff (`mysql.audit`) |
| SQL Server (MSSQL) | Clean install | `xp_cmdshell` state, `sa`, sysadmins, linked servers, Agent jobs, the account used by the 1433 check (`mssql.audit`) |
| DNS, SMB | Reference config | DNS forwarders and `ServerLevelPluginDll`; share list and the SOP directory ACLs |
| Splunk | Splunk's own file manifest | Files differing from it; non-stock apps; scripted inputs; deployment-server settings |

IIS is dropped from the table (not in the 2027 environment). The AD checks are in `ad`.

*The firewall-killer (review D403).* Red teams often plant something that disables host firewalls on a timer. The hunt looks for its trigger (timers, cron entries, units and scheduled tasks that touch firewall state). If it does not find it, D10 catches the execution and records the lineage. Three restores of the same object in 10 minutes open an incident and a targeted hunt on the culprit's lineage (`respond.loop`).

*Credential-file hunt (review D405).* Names such as `*passlist*`, `*.kdbx`, `id_rsa*`, `.env`, `unattend.xml`, with reads logged. Credential files are red's second door. On a DC, the hunt also reads AD user Description fields, because the organizers seed AD with "temp admins" and comments on users (MW Discord 2026-10-26, area 7 revision). Findings are `hunt.finding` at Medium, High when the content looks like a password.

*Post-hardening adversarial verification (review D406).* After a hardening plan, a probe from the Kali and the controller proves that the default and old passwords fail, the new key works, a canary port is closed and scored checks pass [WT §9.2]. This is plan content (`plans/hunt/verify_hardening.yaml`) that reuses the probe actions and the `vantage` credential verification; it adds no code. "We thought it was done but it wasn't" [[discord-2026q-lessons#e1]].

**7. Actions and content**

| Action | Risk | Locks | Scorer-visible touches | What it does |
| --- | --- | --- | --- | --- |
| `hunt.baseline_diff` | none | none | none | Collects the reference artifact set and returns it for the controller diff |
| `hunt.persistence` | none | none | none | Collects autostart and persistence locations (Appendices B and C and the N5.8 additions) with enrichment |
| `hunt.apps` | none | none | none | Runs the application reference checks above for the detected products |
| `hunt.creds` | none | none | none | Credential-file names and AD descriptions; reports paths and a classification, never the secret |
| `hunt.remote_access` | none | none | none | Finds kill-list agents installed or running |
| `collect.inventory`, `collect.files` | none | none | none | General collection used by the plans |

Content: the check files and baselines named in the manifest, the kill list, `hunt/heuristics.yml`, the prebake plan `plans/hunt/prebake.yaml` (collect, diff, enrich, score) and `plans/hunt/verify_hardening.yaml`. Detection rules that complete the hunt: D6, D11, D22 and the kill-list rule D3c.

**8. UI**

The Hunts page: the review queue grouped by host with the High findings first, per-finding evidence, buttons to approve (create the remediation plan), accept (write to overrides), reject, and open an IR draft; the Triage tab for first-run extras; the baseline views per host (reference plus accepted); the cross-check results. Overview tile: open High findings. Host-grid column: "hunt clean" (verified when the last run has no open High or Medium finding and no pending triage; amber while the first run is pending). A host cannot be tagged golden until this column is verified (core re-enrollment).

**9. Health**

`ok` when the last run completed on schedule. `degraded` when a run is late or partial, when a baseline for the host's OS is missing (the host is then collected but not diffed), or when a sensor the checks need has a gap. Gaps: "no reference for this OS version", "BPF lister unavailable on this kernel", "cross-checks run without root". Detail: last run per host, findings open per score.

**10. Scoring safety**

- Collection and diff are read-only. Hash reads and directory walks are low priority and bounded.
- Remediation is the only change, and it is a plan: disable and quarantine, never delete, `chattr -i` applied explicitly and logged first. The plan's nodes touch persistence points, not scored state; the scoring-safety lint rejects a node that would quarantine scored content or stop a scored service, and the approval record names the approver.
- A finding that is also a scored service component (a scored daemon's own unit) is shown as such and its remediation is disabled; the operator must choose a plan that keeps the service.
- Alert-only stage: hunting itself never acts; the kill-list tier-0 disable is the single automatic action, and it applies only to unscored remote-access agents (the guard refuses scored state). It starts as an alert until the `respond` recipe is enabled for the host.

**11. Tests**

- Unit: diff correctness (added, modified, missing) on fixture artifact sets; each score trigger and heuristic on fixture findings; the triage routing; the baseline merge with overrides; kill-list matching.
- Fixture: the Contaminator (review D513) plants prebaked implant sets in golden images; the hunt must find 90% or more (core metric).
- Cross-check tests on a fake `/proc` and `/sys` tree (hidden pid, hidden module, hidden socket); BPF lister behind a build tag that skips with a clear message without privilege.
- Conformance: starts with no baselines (degraded, not a crash), survives link loss, reconfiguration, `go test -race`.
- Lab: T01 (prebaked set at drop flag), T19 (bulk re-enrollment: hunt and ledger automatic, golden tag withheld until clean), T12 (`LD_PRELOAD` rootkit), T02 (the firewall timer is found by loop detection and the hunt). Latency from enrollment to first results is measured and reported.

**12. Limits and open items**

- `shortcut: the BPF program lister needs CAP_BPF or CAP_SYS_ADMIN and a kernel that exposes BPF_PROG_GET_NEXT_ID; it reports a gap otherwise, upgrade only if the lab shows a kernel the lister cannot read.`
- `shortcut: the reference is a stock image build, so a real image's extras need the triage queue; upgrade to a recorded real image only if the event provides one.`
- `shortcut: the Roundcube audit ships once the webmail product is confirmed, and the OpenCart check ships gated on the detected branch.`
- Open: whether the 10-minute repeat requires the `inventory` module on the host. Recommendation: no; the hunt collects on its own and reuses inventory snapshots when `inventory` is enabled. Inventory remains opt-in.
- Open: where the controller hunt queue lives in the code base. The brief says "to confirm"; it is the `hunt` package's controller side with its own table, `hunt_finding`.
- Open: AD duplicate-group consolidation (about 500 duplicate groups across 10 departments was an inject-like task [MW Discord 2026-10-26]). Recommendation: a read-only report as an AD check only if asked, no remediation (`ad`).
- Core changes: the persistence-cleanup actions named above (the core table lists them; most are not built); `collect.inventory` and `collect.files` as core Collection actions; the `first_sweep` routing from `integrity`.
