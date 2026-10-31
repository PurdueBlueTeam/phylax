#### `inventory`

##### 1. Purpose and evidence

`inventory` is the producer of "what is on this host now, and what changed". It collects named tables of host state (accounts, groups, sudoers, authorized keys, systemd units, scheduled tasks, services, drivers, mounts, kernel modules, BPF programs, network interfaces and addresses, installed software and versions, domain membership), keeps the previous snapshot on the host, and sends only the differences: rows added, removed and changed, with an epoch. It also owns `probe.run`, the typed read-only ad-hoc query ("ask every host one question") over those tables. There is no SQL and no query language.

Why it matters for points:

- It is the producer that drift detection, hunts, generators and the version matcher all need. The review found that the inventory module does not exist, and that 17 rules are parked for lack of producers (review D81). Four of them wait on this module directly (`D11c` BPF programs, `D2b` mount over content, `D19b` promiscuous interface, `D21` address or route change; `D6d2` unit environment waits on the `units` table).
- Persistence and account changes are the main red-team foothold: added accounts, authorized keys, units with `LD_PRELOAD`, scheduled tasks (D6 and D7 in `detect`). A differential table sees them whichever tool the red team used.
- Versions of installed software feed the version-driven vulnerability matcher (`vuln`, review N5.1): the software changes every year, and a matcher driven by versions does not go stale.
- The recurring "inventory" and "port table" inject artifacts and the user and group listings are queries over these tables (`report`).
- A one-question-to-every-host tool saves the team from running commands by hand on each box. Peer evidence: osquery's differential logging and query packs, UCI's `linux-inventory/ident.sh`@f2af5a1, Velociraptor artifacts (OSS-EDR report).

Evidence against, and the limit it sets: SQL (osquery) and VQL (Velociraptor) need an interpreter and a table zoo on the host, and an interpreter is an exfiltration path if a controller key is stolen. This module therefore has fixed tables and typed probes only (anti-goal: no query language on hosts). A2.Q1 settled that this is one module, with installed-software versions included.

Not in this module: listeners and connections. `net` already emits them as differential `listener` and `conn` events with owners and a baseline flag, which is exactly this module's contract for sockets, so a second walk of the socket table here would duplicate it. Review D81 lists listeners among the tables; they are covered by `net`.

##### 2. Status and code

Status: missing. Nothing exists except the `collect.inventory` action name in the execution engine's catalogue (`internal/actions`) and plan fixtures that call it. No parser or collector code, no `plan.InventorySettings`, no factory.

To build: `internal/inventory` (the agent collectors, the diff engine, the probe interpreter, the controller fold) and `internal/agent/mods/inventory*.go`. Content: `inventory/probes/*.yml` and `inventory/software/*.yml`.

##### 3. Capability manifest

```go
module.Manifest{
	Name:      "inventory",
	Sides:     []module.Side{module.SideAgent, module.SideController},
	OS:        nil, // both; the tables differ per OS
	Privilege: "root",
	Roles:     nil,
	Consumes:  []string{"inventory.row", "inventory.snapshot"}, // controller side
	Emits: []event.Type{ /* inventory.snapshot v1, inventory.row v1, inventory.probe_result v1, telemetry_gap v1 */ },
	Budget: module.Budget{
		CPUMillisPerSec: 60, HeldMB: 48, EventsPerSec: 50, Burst: 400,
		BytesOutPerMin: 6 << 20, DiskMB: 8,
	},
	Default:  false, // opt-in; the reference manifest enables it on every host
	Tables:   []string{"inventory_rows", "inventory_epochs"},
	Content:  []string{"inventory/probes", "inventory/software"},
	Actions:  []string{"collect.inventory", "probe.run"},
	Pages:    []string{"/inventory"},
	Evidence: []string{"review D81", "review N2.1", "review N5.1", "[[known-exploited-vulnerabilities#e1]]"},
}
```

Numbers are initial limits. The baseline snapshot of the first collection is the burst: it is sent once per table, in bulk priority and in chunks of at most 500 rows. `shortcut: budget numbers are estimates, replace with Invitational measurements (O3 in docs/impl/invitational-data.md)`.

##### 4. Configuration

`modules/inventory.yml`, rendered per host into `modules.inventory` (agent) and read by the controller side.

```yaml
rate_per_sec: 50
burst: 400
tables: []                    # empty = the OS defaults below
interval_sec: 60              # fast tables
software_interval_sec: 900    # installed software and versions
resnapshot_hours: 6           # full snapshot event per table in addition to diffs
max_rows: 20000               # per table; more is a truncation gap
```

```go
// package plan (new; ModuleSettings gains `Inventory *InventorySettings`)
type InventorySettings struct {
	ModuleLimits
	Tables              []string `json:"tables,omitempty"`
	IntervalSec         int      `json:"interval_sec,omitempty"`
	SoftwareIntervalSec int      `json:"software_interval_sec,omitempty"`
	ResnapshotHours     int      `json:"resnapshot_hours,omitempty"`
	MaxRows             int      `json:"max_rows,omitempty"`
}
```

Tables (the table contract: every table has a name, a schema version, typed columns, key columns, a Go-native collector and a default interval):

| Table | Linux | Windows | Key | Notes |
| --- | --- | --- | --- | --- |
| `accounts` | `/etc/passwd` and `/etc/shadow` fields: `name`, `uid`, `gid`, `shell`, `home`, `locked`, `empty_password`, `hash_algo`, `last_change`, `expires`, `in_sudo` | local users: `name`, `sid`, `enabled`, `locked`, `password_never_expires`, `last_logon`, `privileges` | name | A password hash is never read into a row; only whether one is set, its algorithm and its aging |
| `groups` | `/etc/group`: `name`, `gid`, `members` | local groups with members (SID and name) | name | |
| `sudoers` | `/etc/sudoers`, `/etc/sudoers.d/*`: `file`, `who`, `hosts`, `runas`, `nopasswd`, `command` | n/a | file + line | Parsed, not shelled |
| `authorized_keys` | per user: `user`, `file`, `type`, `fingerprint`, `comment`, `options` | n/a | user + fingerprint | Fingerprint, not the key blob |
| `units` | systemd units: `name`, `fragment_path`, `enabled`, `active`, `exec_start`, `user`, `environment`, `ambient_caps`, `drop_ins` | n/a | name | The `LD_PRELOAD` and ambient-capability fields feed D6d |
| `tasks` | cron (all spools and `/etc/cron.*`), at, systemd timers: `kind`, `owner`, `schedule`, `command` | Task Scheduler: `name`, `path`, `author`, `principal`, `run_level`, `command`, `arguments`, `xml_sha256`, `enabled` | kind + owner + id | Windows reads the task XML under `System32\Tasks` |
| `services` | n/a | Windows services: `name`, `display_name`, `image_path`, `start_type`, `account`, `state` | name | |
| `drivers` | `kernel_modules` (`/proc/modules`: `name`, `size`, `used_by`, `taint`) | kernel drivers: `name`, `image_path`, `state` | name | Rootkit and unsigned-driver rules (D11) |
| `mounts` | `/proc/self/mountinfo`: `source`, `target`, `fstype`, `options` | n/a | target + source | D2b needs a mount over a content root; the noexec hardening (N5.7) reads `options` |
| `bpf_programs` | `id`, `type`, `name`, `tag` | n/a | id | Via the BPF syscall; D11c |
| `interfaces` | netlink links: `name`, `flags`, `promisc`, `kind`, `mac`, `mtu`; `addresses`; `routes`; `neighbours` | adapter table: `name`, `addresses`, `gateway`, `dns` | name (per table) | D19b and D21; `manifest_match` is computed in `detect` against the manifest topology, not here |
| `software` | dpkg status or rpm database (`name`, `version`, `arch`, `source`), plus product versions | installed programs, OS build, UBR, hotfixes, SQL Server build, product versions | name + source | Feeds `vuln` |
| `domain_join` | `source`, `realm_or_domain`, `servers`, `method` (see Behaviour) | n/a (the manifest declares AD membership) | source | Seeds `depends_on` proposals in `deps` |

Defaults: every table above for the host's OS, collected every 60 s, except `software` (15 min) and `domain_join` (at start and hourly). A host entry may list `tables` to restrict.

Probe definitions are content, `inventory/probes/*.yml`:

```yaml
module: inventory
name: accounts_uid0
doc: Accounts with uid 0 other than root
table: accounts
where: [{ col: uid, op: eq, value: 0 }, { col: name, op: ne, value: root }]
select: [name, shell, home, locked]
limit: 100
params: []
tests: [ ... ]
```

Predicates are typed (`eq`, `ne`, `in`, `re`, `prefix`, `gt`, `lt` on one column; `${param}` substitutes a declared, typed parameter). No joins, no expressions, no aggregation except `count`. A probe has at most 16 predicates, a result limit of at most 1000 rows, and declares each parameter's type, bounds and pattern, validated before it runs. Probes cannot read files other than the tables' own sources.

Software product versions are content, `inventory/software/*.yml`: product, file path glob, a RE2 with one capture group, and the `product` name (for example Splunk's `etc/splunk.version`, OpenCart's `VERSION` constant in `index.php`, Roundcube's version constant). A new product is a new YAML file.

##### 5. Events

Consumed: controller side reads `inventory.snapshot` and `inventory.row` from the store.

Emitted:

| Kind | Priority | Key fields |
| --- | --- | --- |
| `inventory.snapshot` | bulk | `table`, `schema`, `epoch`, `reason` (`baseline`, `epoch_change`, `periodic`, `requested`), `rows` (the whole table, at most 500 per event, with `part` and `parts`), `count`, `collected_at` |
| `inventory.row` | normal (high for the tables rules treat as persistence: `accounts`, `groups`, `sudoers`, `authorized_keys`, `units`, `tasks`, `services`, `drivers`, `bpf_programs`) | `table`, `epoch`, `op` (`added`, `removed`, `changed`), `key`, `row`, `old` (for `changed`: only the changed columns' old values), `changed_cols`. At most 200 per table per collection; beyond that one `inventory.row` with `op: overflow` and the count |
| `inventory.probe_result` | normal | `probe`, `params`, `host`, `columns`, `rows`, `truncated`, `collected_at`, `live` (true if the table was re-collected for this probe) |
| `telemetry_gap` (common) | high | `source: inventory`, `reason` (`collect_failed`, `table_truncated`, `state_lost`, `row_overflow`), `table`, `count` |

Per-row events are what the rule engine can match: a rule says `event: inventory.row`, `table: mounts`, `op: added`, and conditions on `row`. The parked rules `D11c`, `D2b`, `D19b`, `D21` and `D6d2` in `rules/pending/needs_producer.yml` are retargeted to these events (their event names `bpf_prog_new`, `mount_new`, `net_iface`, `net_addr_change`, `unit_parsed` stop existing; this is a content change in `detect`'s corpus).

##### 6. Behaviour

**The table contract.** Each table's collector returns rows with a fixed schema and a key. A collection compares the rows with the stored snapshot (by key and by a hash of the other columns) and produces three sets: added, removed, changed. The snapshot is stored on the host under `StateDir/inventory/<table>.json`, written atomically (`internal/atomicfile`), together with the table's `epoch`.

**Epochs.** An epoch is a counter persisted per table on the host. It rises when the baseline is retaken: first collection of the table, a lost or corrupt state file, a schema change, a reconfiguration that added the table, or an operator's re-baseline. A new epoch starts with an `inventory.snapshot{reason: baseline|epoch_change}` event and no row events (the baseline is not "everything added"). Within an epoch every change is a row event. The controller therefore can tell a restart or lost state from a real change: an epoch change with a snapshot is not an alert, while a missing epoch (a gap between epochs for a host) is a `state_lost` gap. Without an epoch, every agent restart would look like a mass of additions.

**Persistence and reconciliation.** Because the snapshot is on the host, a restart does not lose the baseline, and changes made while the agent was down are found at the first collection after it comes back. Changes made by a plan (tagged work) carry the plan tag through the envelope's `Tag` where the engine stamps it, so rules exempt them with one condition, and the drift check marks them as the plan's expected result. After a plan node runs, the engine requests a `collect.inventory` for the affected tables so the diff arrives while the tag window is still open.

**Collection cost.** Collectors read procfs and a few small files and are bounded: `max_rows` per table, one table at a time, a single goroutine per module, jittered start so all hosts do not collect together. The `software` table is rate-limited and reads the package database once, then re-reads only when the database file's mtime changes. The `rpm` database on RHEL 9 is SQLite (`/var/lib/rpm/rpmdb.sqlite`), read with the pure-Go driver already in the binary; the Berkeley DB format of older RPM versions is not read (`shortcut`, see Limits). dpkg uses `/var/lib/dpkg/status`.

**Software versions (review N5.1).** Packages and product versions (dpkg or rpm; Splunk, OpenCart, Roundcube from their version files; on Windows the OS build, update build revision (UBR) and hotfix list, and the SQL Server build) are rows in `software`. PAN-OS and VyOS versions come from the device adapters (`devices`), not from agents. Backported distribution packages cannot be judged by version alone, so the matcher reports `unknown` there; this module only supplies the facts.

**Linux domain-join probe (review D81).** On Linux the module reads the files that say a host is joined to a domain, without running `realm`, `net ads` or any other host binary: `sssd.conf` (`[domain/…]` sections: `ad_domain`, `ad_server`, `krb5_realm`, `id_provider`), `krb5.conf` (`default_realm`, `[realms]` `kdc` and `admin_server`), `smb.conf` (`security`, `realm`, `workgroup`), and `resolv.conf` or the systemd-resolved state for the search domain and DNS servers. Only these keys are read; other keys in those files may hold secrets (`ldap_default_authtok`) and are never read into a row. Each source gives one `domain_join` row. `deps` reads the rows and proposes `depends_on` edges from the host to the DC.

**probe.run (review N2.1).** `probe.run{name, params}` is a core action row whose implementation lives here. The controller creates a read-only, signed step per target host; the agent looks the probe up in its signed content, validates the parameters, and runs it over the current snapshot (default) or, if the probe says `live: true`, re-collects the table first. The result returns as the step result and as an `inventory.probe_result` event; a result over 256 KiB is stored as a file and fetched in chunks. The evidence run (review N10.3: a captioned command output for a deliverable) and inject queries (N10.6) are probes (A10.Q3), so their typed probe names appear here as content, for example `accounts_uid0`, `authorized_keys_for{user}`, `units_enabled`, `mounts_without_noexec{path}`, `software_version{name}`, `interfaces_promisc`. `report` calls them by name and renders the output as a figure with host, Central time and the probe name.

*Why this is not a query language:* the available tables, columns and operators are fixed in signed content; a probe cannot name a table that is not collected, cannot join, cannot evaluate an expression and cannot read an arbitrary file. A stolen controller key therefore reveals what the tables hold and nothing else the agent could read.

**Controller side.** The module's controller side folds `inventory.snapshot` and `inventory.row` events into two tables it owns (`inventory_rows`: host, table, key, row, first seen, last seen; `inventory_epochs`: host, table, epoch, baseline time) so the UI can show current state. Other modules read inventory from events, not from these tables (module contract). A consumer needs the latest snapshot plus the row events after it. A shared fold helper would save each consumer from re-implementing this (see Limits).

**Linux and Windows differences.** Windows collectors use the native APIs: the service control manager, the registry, `NetUserEnum`, `GetAdaptersAddresses`, and the task XML files under `System32\Tasks`; Linux collectors read procfs, `/etc` files, the BPF syscall and netlink. Nothing runs a host binary. `shortcut: Windows scheduled tasks are read from the XML files only, not cross-checked against the TaskCache registry tree, so a task whose XML was removed but whose registry entry remains is not seen, add the cross-check if the hunt shows such persistence`.

**Containers (N7.6).** For `runtime: docker` services, `software` also lists the container image and tag from the Docker or Podman state files (`/var/lib/docker/containers/*/config.v2.json`, read-only), and `mounts` shows the volumes; both feed the container-aware pins and content roots. `shortcut: container metadata is read from the engine's state files, no engine API call, add the API only if the state files are not readable in the 2027 stack`.

##### 7. Actions and content

Actions (core `Collection` row; this module implements them): `collect.inventory{tables}` forces a collection and a diff and, with `snapshot: true`, a fresh `inventory.snapshot`; `probe.run{name, params}`. Both are read-only: risk class none, no lock, no scorer-visible touch, no approval record beyond the plan signature, usable in safe mode.

Content: `inventory/probes/*.yml` (probe catalogue with inline tests over fixture tables) and `inventory/software/*.yml` (version-file parsers with inline tests). Both go through the content CI (schema, tests, the module field).

##### 8. UI

Registered through `ui.Registrar`:

- Page `/inventory`: per host, the tables with last change times and the row-event timeline; an "Ask" form that picks a probe, fills its parameters and a label expression for the target hosts, runs it and shows grouped results (identical outputs collapsed as "14 same, 2 differ", outliers first, per-host status). This is the ad-hoc hunt.
- Overview tile: untagged inventory changes in the last hour, by table.
- Host-grid column "inventory baselined" (`verified` once every enabled table has an epoch and a snapshot; `pending` while the baseline is running; `failed` on a collection error).

##### 9. Health

Implements `agent.HealthReporter`. States:

- `ok`: every enabled table collected within twice its interval.
- `degraded`: a table failed or was truncated, state files were lost (epoch bumped), or the module hit its budget.
- `unavailable`: not root, or the table sources are missing (for example no BPF syscall permission).

Gaps: `<table>: collection failed: <err>`, `<table> truncated at max_rows`, `rpm database format not readable (Berkeley DB)`, `bpf_programs: no permission (needs CAP_BPF or CAP_SYS_ADMIN)`, `inventory state lost on this host, new epoch`. The Platform page also shows each table's age.

##### 10. Scoring safety

Read-only on the host: it reads state and writes only its own snapshots under `StateDir`. It touches no scored service. It opens no listener and runs no host binary. Load is bounded by the intervals, the row caps and one collector at a time. Reading `/etc/shadow` for aging and algorithm happens in the agent as root, and no hash leaves the host. `probe.run` and `collect.inventory` are read-only plan steps. Alert-only by construction.

##### 11. Tests

To build: per-collector fixture tests (recorded `passwd`, `shadow`, `group`, `sudoers`, `mountinfo`, `modules`, unit files, cron spools, dpkg status, an rpm sqlite fixture, sssd/krb5/smb samples, Windows registry and task XML fixtures); diff engine tests (add, remove, change, no-op, key collision, epoch rules, lost state, schema bump, row caps); persistence across restart; baseline sends a snapshot and no row events; probe interpreter tests (each operator, parameter validation, limit, rejection of an unknown column, unknown table, oversize results); a test that no probe definition names a column the table does not have; the rule tests for the retargeted parked rules over `inventory.row` events; the controller fold (snapshot plus rows equals the table).

Conformance: starts with no config (disabled), starts with default config on a fixture host (fixture procfs and `/etc`), stops within 5 s, reports health, emits only declared kinds, respects the budget under a 20000-row fixture, survives link loss (snapshots are on disk, events are retried by the spool), survives reconfiguration (a new table list keeps the existing tables' epochs through `Keep`), `go test -race`; analyser determinism for the controller fold (same store, same output).

Lab tests: T12 (LD_PRELOAD rootkit: the `units` and `kernel_modules` rows), the prebake hunt T01 (reference diff uses the same tables), the Invitational questions E5 (what is running at drop flag), E7 (local accounts on every host), E3 (versions of every scored product) as data for the baseline.

##### 12. Limits and open items

- `shortcut: rpm Berkeley DB databases are not read, only the SQLite format; the 2027 images are Rocky 9 / Debian 12 / Ubuntu 22.04 where it is enough, add a reader only if an older RPM host appears`.
- `shortcut: per-row events are capped at 200 per table per collection; a larger burst is an overflow marker with a count, because a mass change should be one alert, not thousands`.
- `shortcut: Windows tasks from XML files only`, `shortcut: container metadata from state files` (see Behaviour).
- `shortcut: collection is periodic (60 s), not event-driven, so a change that is made and reverted between two collections is not seen; the audit module's file watches cover the persistence paths for that case`.
- Open: listeners are not an inventory table because `net` covers them (decision applied here; confirm).
- Core change request: consumers of inventory facts (drift in the core manifest, `report`, `hunt`, `vuln`, `deps`) each need current state. The contract says modules read events, not tables. Add one stateless shared library, `internal/inventory/fold` (types and one pure function folding a snapshot plus row events into rows), to the allowed shared libraries list; otherwise each consumer writes it.
- Core change request: a shared stateless socket library (`internal/sockets`: sock_diag dump and inode-to-process join) would let `net`, the depot's Go-native `ss` and `lsof` and future `listeners` probes share one implementation. `internal/depot/gotools` imports `internal/collect/net` today.
- Open: the exact list of Windows tables for persistence (Run keys, IFEO, LSA packages, Winlogon, WMI subscriptions) belongs to `hunt.persistence`, not to `inventory`; the boundary is that a hunt compares against a reference build while inventory reports change over time. If the prebake hunt reuses the same collectors, they should live in one place (`inventory`) and `hunt` should call `collect.inventory`. Settle when `hunt` is written.
- Open: `probe.run` parameter types that take a path must name an allowed root per probe; no probe takes an arbitrary path yet.
