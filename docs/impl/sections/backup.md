#### `backup`

##### Purpose and evidence

`backup` takes copies of each service's content, data and configuration, pulls them to the controller, and restores them on request. With no per-VM scrub and no VM snapshots, a service backup is the only undo for a big mistake or for razing. It also holds the off-host copy of the boot-critical files that `content_guard` watches, and the record-level AD, DNS, GPO and CA backups that recover scored DNS records and AD logins quickly.

Evidence that it matters for points:

- **No reset, costly recovery.** A new lab reservation is the only reset, recovery services cost points and vulnerabilities reappear [[2027-mw-invitational-packet#e39]]. In-place restore from our own copy is the cheap path.
- **Razing.** Red deletes `fstab` and reboots, or wipes content, in the lunch window; teams need fresh copies before lunch and before day 2 [[how-to-win-ccdc-dealing-with-red-team#e3]] (review D502).
- **Data loss is penalised per user.** Mailboxes, users and rows lost in a migration or restore cost points [[2027-mw-invitational-packet#e35]]. Hence record counts before and after every restore (review D486).
- **Recovery injects.** Eight linked injects (SCEN40T to SCEN47T) at the 2026 regional asked for hot-site recovery [[2026-mw-regional-scen40t#e1]], [[scen43t#e1]]. Phylax builds only the generic part (restore a service's golden backup onto a different declared host, review A10.Q2, tentative). It builds no hot-site plans.
- **Peers.** DePaul `dns_bak.ps1` [[pet4yserb-rrepo-windows#e3]], UCI [[cyberuci-locs#e12]], UW-Stout [[uwstout-ccdc-windows#e3]], CPP [[cpp-cyber-blue#e31]]; UCI `windows/Domain Controller/adcs_backup.ps1` and `dns.ps1`@f2af5a1.

Backups are pulled to the controller, so a restore never depends on a compromised host's own copy.

##### Status and code

Status: **missing**. There is no `backup` package. Existing parts it builds on: `file.hash`, `dir.snapshot` and `file.restore` (`internal/actions/files.go`), the MySQL actions (`app_mysql.go`: `mysql.audit`, `mysql.lock`, `mysql.set_password`, `mysql.exec`), `mssql.exec` and the MSSQL helpers, `collect.files`, content-addressed `chunk` transfer, and the controller's own state snapshot (`internal/store/backup.go`, which backs up the controller, not services).

**Conflict with the core Databases row.** The core action-family table lists `mysql.dump` and `mysql.set_password` under Databases. The code has no `mysql.dump`. This module registers its own dump and restore actions (below); the core row's `mysql.dump` should be removed or renamed to `backup.sql`.

##### Capability manifest

| Field | Value |
| --- | --- |
| Name | `backup` |
| Sides | agent (dump, archive and restore actions), controller (set store, schedule, gating, restore plans) |
| OS | both |
| Privilege | root (agent) |
| Roles | any host that carries a service with backup scope; `domain_controller` for AD actions |
| Consumes | `agent.step_result`, `scorer.round` (quiet windows), `checks.result`, `integrity.verdict`, `hunt.completed` (golden gate) |
| Emits | `backup.taken`, `backup.restored`, `backup.verified`, `backup.failed` |
| Budget (agent) | CPU 300 ms/s averaged over a dump (it runs at nice 19 and idle I/O class), held 32 MB, 0.2 events/s, burst 5, bytes out 20 MB/min as bulk chunks (shaped by the link's token bucket), disk 512 MB staging, deleted after the controller acknowledges the pull |
| Budget (controller) | CPU 100 ms/s, held 32 MB, disk quota from config (default 8192 MB) |
| Default | opt-in (the reference manifest enables it) |
| Tables | `backup_sets` (id, host, service, kind, time, bytes, sha256, golden flag, counts), `backup_counts` (per set: source, name, count) |
| Content | `plans/backup/` (restore plans), `backups/counts/` (the count specifications per service kind) |
| Actions | `backup.files`, `backup.sql`, `backup.splunk`, `backup.ad`, `backup.dns`, `backup.gpo`, `backup.adcs`, `backup.boot`, `backup.verify`, `backup.restore` |
| Pages | `/backups` |
| Evidence | the vault citations in the first part |

##### Configuration

```yaml
# manifest/modules/backup.yml
enabled: true
schedule:
  periodic: 30m              # for changing data: databases, mail, uploads, AD, Splunk apps
  quiet_window: true         # start jobs just after a scorer burst ends; run anyway if no round clock yet
  max_duration: 5m           # a job over this is stopped and reported; the service keeps priority
retention:
  periodic_keep: 6           # per service; oldest periodic is pruned first
  pre_change_keep: 10
  as_found: keep             # never pruned automatically
  golden: keep               # never pruned automatically
quota_mb: 8192               # controller store; a warning at 70%, a refusal to take periodic sets at 95%
copies:
  golden_to_targets: true    # copy golden sets once to the manifest's backup targets
```

What each service backs up comes from `services.yml` (its `content` roots, `data` entries and configuration files), not from this block; each `data` entry may list the tables, mailboxes or zones to count (`count: [oc_user, oc_order]`). The Go settings:

```go
// package backup (internal/backup)
type Settings struct {
	Periodic     time.Duration `json:"periodic"`
	QuietWindow  bool          `json:"quiet_window"`
	MaxDuration  time.Duration `json:"max_duration"`
	PeriodicKeep int           `json:"periodic_keep"`
	PreChangeKeep int          `json:"pre_change_keep"`
	QuotaMB      int           `json:"quota_mb"`
	GoldenToTargets bool       `json:"golden_to_targets"`
}
```

##### Events

Consumed: `agent.step_result` (the result of a backup or restore node), `scorer.round` (burst times), `checks.result` (a service's health), `integrity.verdict` and `hunt.completed` (the host's ledger sweep and hunt are clean).

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `backup.taken` | 1 | normal | `set`, `host`, `service`, `kind` (`as_found`, `golden`, `periodic`, `pre_change`, `boot`), `bytes`, `sha256`, `members` (path to sha256), `counts`, `duration_ms`, `tag` |
| `backup.restored` | 1 | high | `set`, `host`, `service`, `target_host`, `counts_before`, `counts_after`, `counts_set`, `lost` (rows or items the restore removes), `probe` (result of the scorer-mimic probe), `pre_change_set` |
| `backup.verified` | 1 | normal | `set`, `ok`, `checks` (hash match, dump end-marker, count re-derivation) |
| `backup.failed` | 1 | high | `host`, `service`, `kind`, `stage`, `reason` (including `tool_hash_mismatch`) |

##### Behaviour

###### Backup kinds

| Kind | When | Use |
| --- | --- | --- |
| As-found | After enrollment, before any remediation on that host | Forensic evidence. Never restored blindly; it may contain implants. |
| Golden | Right after a service's hardening passes its health checks **and** the host's ledger sweep and hunt are clean | The restore point for that service. A host restored or re-enrolled cannot be tagged golden until both are clean again [COV X-2]. |
| Periodic | Every 30 minutes for changing data (database, mail, uploads, AD, Splunk apps) | Keeps restores from losing orders and mail |
| Pre-change | Before any tier-2 action, before a restore, before Palo and VyOS changes (the device configs themselves are `devices`' backups) | Undo for big changes |
| Boot | Before day 2 and before lunch, and after any change to a boot file | The boot-critical set, kept off the host for recovery from razing (see below) |

**Scope** is declared per service in `services.yml`: content roots, upload directories, data entries and configuration files, plus, by kind, the AD database objects, SQL databases, the SMB SOP share and the Splunk apps. A kind of service with no declared scope is reported as "no backup scope" on the grid and the Overview, not skipped silently.

**Golden gate.** The controller tags a set golden only when it holds a passing `checks.result` for the service after the hardening plan's last node, an `integrity.verdict` sweep with no open finding for the host, and a `hunt.completed` with no unresolved High finding. Until then the set exists as `pending` and the grid cell stays amber. Taking the set is read-only, so it runs without a click; tagging it golden is the gate.

**Where sets live.** Each set is stored encrypted at rest (`age`, like evidence files) on the controller under its own directory, with a manifest of member hashes. The set's hash is also in the hash-chained `backup.taken` event, so a replaced set shows as a mismatch. With `golden_to_targets`, a golden set is also copied once to the manifest's backup targets (the same ones the controller state snapshot uses). The core spec says golden service backups are copied once to those targets; this module does that.

###### Dump and archive mechanisms

The services' own tools are used where they exist, as labelled actions, because they are what the service trusts at restore and because a tampered dump tool shows up in the integrity ledger (review D485, A11.Q2). Go reimplementations are accepted where they are simpler.

| Data | Method | Notes |
| --- | --- | --- |
| Files, uploads, configuration | Go archive (`archive/tar`, zstd), recording mode, owner, xattrs and SELinux label per member | Native; no host binary. SDDL is recorded for Windows files and shares. |
| MySQL and MariaDB | `mysqldump --single-transaction --quick --routines --events` as a pinned `host.exec` | The tool's hash is checked against the ledger before every run. A mismatch refuses the run and emits `backup.failed` with `tool_hash_mismatch`, which is an alert. Credentials come from the vault secret the service declares, passed through a 0600 temporary defaults file, never on the command line. No `FLUSH TABLES WITH READ LOCK` and no `--lock-all-tables`: a lock on a scored database fails scored checks. |
| SQL Server | `BACKUP DATABASE ... TO DISK ... WITH COPY_ONLY, COMPRESSION` issued by Go (`go-mssqldb`) | SQL Server's own backup engine through the driver, simpler than `sqlcmd`. A `sqlcmd` fallback is a labelled `host.exec`. |
| Splunk | Go archive of `$SPLUNK_HOME/etc/apps`, `etc/system/local` and `etc/users` | Configuration and apps. Index data is not backed up unless a service entry asks for it. |
| Mail | Go archive of Maildir or mbox spools, Postfix and Dovecot configuration, `/etc/aliases` | Counts mailboxes and messages. |
| SMB SOP share | Go archive with SDDL, plus a file list with hashes | The scorer compares the SOP files, so hashes are recorded. |
| AD (record level) | LDAP export of users, groups, OUs, computers, group memberships, ACLs on selected containers, SPNs, to JSON (`ad.dump_objects`) | No password hashes: LDAP cannot read them. See restore. |
| DNS | Go through the DNS server's WMI provider (`MicrosoftDNS_*`) to JSON, per zone; `dnscmd /ZoneExport` as a labelled fallback | Scored DNS records are exactly what this recovers. |
| GPO | GPMC COM `BackupAll`; `Backup-GPO` through a labelled `host.exec` as fallback | Records the `gPLink` of each GPO and the SYSVOL contents. |
| CA (if present) | `certutil -backup` as a pinned `host.exec` | Only when `services.yml` declares an `adcs` service. |
| Containers | `runtime: docker` services: the dump tool runs inside the container (`docker exec`, labelled), volumes are archived as content roots | The 2027 stack is unverified; the Docker ecom variant is in the lab (review N7.6). |
| Boot files | Go copy of `/etc/fstab`, `/etc/crypttab`, bootloader config (`grub.cfg`, `/boot/loader/entries`), `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/ssh/sshd_config` and `sshd_config.d`, network configuration, `initramfs` module list; Windows: the BCD store by `bcdedit /export` as a labelled `host.exec`, the network and firewall configuration | `content_guard` watches the same set (review N5.6); this kind keeps the off-host copy for the console |

A full NTDS database backup (`ntdsutil ifm`) is available as a labelled action. There is no plan that restores it, because that needs a DSRM reboot; `shortcut: no full NTDS restore plan, upgrade only if a lab run shows record-level restore cannot recover something a scored check needs`.

###### Running a backup

1. The controller schedule (or a plan node) proposes a job. With `quiet_window` it starts just after a scorer burst ends, so a dump's I/O does not coincide with the checks.
2. The agent action takes the service lock for its duration, opens the plan or window tag (`backup:<id>`) so detection recognises the dump tool's process, and runs at nice 19 with an idle I/O class.
3. The job has a `max_duration`. A job over it is stopped, partial output is deleted, and `backup.failed` is emitted. The service keeps priority.
4. The result is verified on the agent (member hashes, the dump's end marker, counts), staged under `StateDir/backup/`, and pulled to the controller as chunks at bulk priority. The staging copy is deleted when the controller acknowledges the pull.
5. The controller stores the set, writes `backup_sets`, emits `backup.taken` and applies retention: periodic sets beyond `periodic_keep` are pruned oldest first; as-found and golden sets are never pruned automatically. At 95% of quota periodic sets are refused with a warning; golden and pre-change sets still go in.

**Relation to `content_guard`.** `content_guard` keeps its own on-host golden store (`guard.snapshot`, written as a node at the end of a hardening plan) and restores only from it. `backup` does not feed that store. The two overlap in one place: the boot-critical files that `content_guard` watches are also in the `boot` set and in golden sets on the controller, so a host that no longer boots can be repaired from the console. Both are taken after the host's last account change.

###### Record counts

A count specification per service kind lives in `backups/counts/` and says what is counted: MySQL and MariaDB exact `COUNT(*)` for the tables the service lists (default: every table of the declared database, taken from `information_schema` as a quick scan and exact for the listed ones); mailboxes and messages per mailbox; AD users, groups and memberships; DNS records per zone; SQL Server row counts of the listed tables; the SOP share's file count and bytes; Splunk apps. Counts are taken at backup time and stored with the set, and taken again before and after every restore (review D486).

###### Restore

A restore is a plan (`plans/backup/restore.<kind>.yaml`), risk class `destructive`, needing its own approval record with the approver's name. It always proceeds in the same order:

1. **Pre-change set.** A fresh `pre_change` set of the live state is taken first, so the restore is itself undoable.
2. **Counts before.** The live counts are read.
3. **Dry-run diff with loss.** The plan shows live count against set count for each item. If the live state has more than the set (a restore would drop rows, mailboxes or users), the diff says "restoring loses N", and a gate requires a named approval for the loss. This is the data-loss guard.
4. **Apply.** Files restore through the atomic file actions (temp file and rename, preserving mode, owner and label; the `validate` hook runs for configuration files). SQL restores through the service's own tool or `RESTORE DATABASE ... WITH REPLACE`. AD, DNS and GPO restore record by record: an object that is missing is re-created, an object whose attributes differ is set back, and nothing the set does not mention is deleted. A re-created AD user gets its password from the vault's current value for that (account, credlist), so a scored login keeps matching what Quotient holds; if the vault has none, a password is generated and the account is marked `needs_sync` for `creds`.
5. **Counts after, then re-check.** Counts are read again and compared with the set. The scored content (SOP files, web pages, DNS answers) is re-checked against the learned values, and the scorer-mimic probe runs (the core rule: a failed after-probe rolls the node back, here to the pre-change set).
6. `backup.restored` carries `counts_before`, `counts_after`, `counts_set`, `lost` and the probe result.

Restore times are measured on every run and shown in the next dry run ("last measured: 41 s on rocky-ecom"). They are reported, not targets (decision 9).

**Restore onto a different declared host** (generic DR; tentative, review A10.Q2). The plan `restore.to_host` takes a set and a `target` host. Preconditions it checks and shows before approval: the target is declared in `hosts.yml`; its OS family matches; the service's packages are present (an `inventory` probe); there is room. It restores content, data and configuration and verifies by probe on the target. Pointing the scored address at the target is not part of it (internal addressing does not change [PKT Systems 6-7]); the operator or a `devices` plan does that. There are no hot-site plans.

**Razing recovery.** Red can delete `fstab` and reboot. If the host does not boot, the console is the only way in; a fresh `boot` set on the controller gives the Linux or Windows lead the exact files to put back from the console, and a typeable file listing. Boot sets are taken before day 2 and before lunch, and after any plan node that changes a boot-critical file (the `boot` set kind is the last node of such a plan). `shortcut: restoring boot files from a dead host is a console job, upgrade if the lab razing run shows a typed procedure is too slow`.

###### Hand-offs to other modules

- `content_guard` keeps its own on-host golden copies; `backup` holds the off-host copy of the same boot-critical files (no event coupling).
- `report` reads `backup.taken` and `backup.restored` for the backup schedule and restore times.
- `creds` is not touched: `backup` never writes a scored password; it uses the vault value read-only when re-creating an account.
- Device configurations (Palo, VyOS) are `devices`' scheduled backups; controller state is the core snapshot.

##### Actions and content

| Action | Risk | Locks | Scorer-visible touch |
| --- | --- | --- | --- |
| `backup.files` | none | service | reads scored content |
| `backup.sql` | service | service | reads scored data (bounded duration, no table locks) |
| `backup.splunk` | none | service | reads scored data |
| `backup.ad`, `backup.dns`, `backup.gpo`, `backup.adcs` | none | `accounts` for `backup.ad` | reads AD and DNS records |
| `backup.boot` | none | none | reads boot files |
| `backup.verify` | none | none | none |
| `backup.restore` | destructive | service (and `accounts`, `firewall` where the kind touches them) | writes scored content or data; approval, pre-change set and probe required |

Plans: `plans/backup/restore.files.yaml`, `restore.mysql.yaml`, `restore.mssql.yaml`, `restore.mail.yaml`, `restore.ad.yaml`, `restore.dns.yaml`, `restore.sop.yaml`, `restore.to_host.yaml`, and `backup.golden.yaml` (take, verify, gate, tag). Counts specs in `backups/counts/`.

##### UI

`/backups` lists, per host and service, the sets with kind, time, size, counts and verification state; each row has "Verify now" and "Restore...". The restore button creates the restore plan and shows its dry-run diff with loss. Overview tile: golden coverage ("5 of 9 scored services have a verified golden set"). Host x step grid column **backed up**: `verified` when a verified golden exists; `pending` with only an as-found; `drifted` when the golden is older than the last hardening change on that service; `failed` when the last job failed; `n/a` for hosts with no backup scope.

##### Health

- Agent: `ok` when the last job per service succeeded; `degraded` with a gap per problem: `mysqldump not found at pinned path`, `dump tool hash mismatch: <path>`, `no backup scope declared for <service>`, `job exceeded max_duration`, `staging disk low`.
- Controller: `degraded` at 70% of quota, `error` if the set directory is unwritable. Shows the age of the newest golden set per scored service.

##### Scoring safety

A dump reads scored state and can load a scored service. The controls: no table or global locks; nice 19 and idle I/O; the quiet-window start; a hard `max_duration`; the service lock so a plan does not change the service at the same time. A restore writes scored content or data, so it is `destructive`: its own approval with the approver's name, a pre-change set first, the loss gate, and a scorer-mimic probe after with rollback to the pre-change set. The module never creates a database user or changes a grant, and never writes a scored password. Its dump tools are pinned by ledger hash, so a replaced tool is refused and alerts. Everything it stores holds password hashes and mail, so sets are encrypted at rest and never rendered in the UI.

##### Tests

- Unit: archive round trip preserving mode, owner, xattrs and SELinux label (runs against SELinux-enforcing images in the privileged job); `RESTORE` and `mysqldump` against real MySQL and MariaDB containers; count specification parsing; retention and quota pruning; the golden gate over fixture events (missing probe, open hunt finding, open ledger finding); the loss gate (live greater than set); tool hash mismatch refusal; stage-by-stage failure cleanup (partial output deleted). Tests needing SQL Server or a DC skip with a clear message when absent.
- Conformance: the shared suite, plus a fixture that kills the agent mid-dump and checks that staging is cleaned on restart.
- Lab: T53 (backup, golden gate, restore with counts, tamper), T54 (restore onto a different declared host), T55 (razing: `fstab` delete plus reboot, then recovery from the boot set), T52 (content guard, whose boot-critical set is also in the boot set), T34 (hardening against real Quotient, with golden sets taken and restored).

##### Limits and open items

- `shortcut: no scratch restore, a set is verified by hashes, the dump end marker and counts, upgrade if a lab run produces a corrupt dump that passes those`.
- `shortcut: record-level AD restore cannot restore password hashes, so re-created users get a vault or generated password, upgrade only if lab runs show an inject needs original hashes`.
- `shortcut: index data for Splunk is not backed up, upgrade if a scored check reads indexed events that a restore must preserve`.
- `shortcut: ADCS backup only when an adcs service is declared, there is no evidence a CA is scored`.
- Open: generic DR onto another host is tentative (review A10.Q2); how the scored address follows the service is out of scope here.
- Open: the 2027 container stack (`runtime: docker`) is unverified; Kubernetes manifest backup is designed only if a packet shows Kubernetes (UCI `linux-toolbox/k8solver.sh`@f2af5a1).
- Naming dependency: `hunt.completed`, `integrity.verdict` and `checks.result` must carry a host (or service) field and a time the golden gate can compare with the hardening plan's last node.
- Core change: remove `mysql.dump` from the core Databases row (see Status). Optionally, the grid column set in the UI shell lists "backed up" already; no other change.
- Complexity register line: `backup` | restore from our own copy, off the host, with counts | services' own tools, pinned by ledger hash; no new listener; staging deleted after the pull.
