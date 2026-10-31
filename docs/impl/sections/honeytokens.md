#### `honeytokens`

**1. Purpose and evidence.**

The `honeytokens` module plants fake credentials, keys and files that nothing legitimate ever uses, unique per host, and recognises their use. A token's origin tells you which host was looted and roughly when. It has three parts:

- the controller side: a generator and a registry of tokens, their secrets in the vault, the deploy plan, and attribution of later sightings to the host they came from;
- the agent side: a file-read watcher for honey files (fanotify on Linux, file auditing on Windows) and, on Windows servers, the decoy credential kept alive in LSASS;
- content: the `D15d`-`D15g` rules and the seeds that feed them.

The module uses the `decoys` module's listeners as one place a token can be sighted (`D15c`), through the shared registry configuration, not through code.

Evidence that it matters for points:

- Use of a honey credential is near-certain compromise, and tokens are cheap (review D381). Honey credentials in LSASS catch the `secretsdump`/`mimikatz` path red uses most [[how-to-win-ccdc-dealing-with-red-team]] (review D380).
- Red dumps every AD hash once it holds a DC ("one DC's worth of plaintext", MW Discord 2026-10-26); the policy against that is prevention (Zerologon first at T+0, the DCSync rule), honey AD accounts, a pass-the-hash rule pack and selective rotation on evidence, never mass rotation (review A7.Q7). A pass-the-hash attempt with a stolen honey-account hash needs no cracking, and it shows up as a logon or Kerberos event for an account nobody uses.
- Honey files are cheap, high-signal detections (review D384).
- Peer evidence: none for an open CCDC platform with per-host registry attribution; the closest are generic canary tokens. Stated as a limit: the pools are in the public repo, so a careful attacker may recognise some decoys; per-host values are what the repo cannot reveal.

**2. Status and code.**

Status: built for file, key, credential and AD tokens; the LSASS session and four v3 token kinds are not.

| Piece | State | Where |
| --- | --- | --- |
| Generator (`Generator.ForHost` over a `HostSpec`), registry with uniqueness checks (ID, secret, account, fingerprint, SPN, host+path), `Seeds()`, `Attribute()` | built | `internal/honeytokens/{generate,token}.go` |
| Kinds: `ssh_key`, `db_cred`, `shell_history`, `passwords_file`, `browser_cred`, `aws_key`, `honey_file`, and AD `ad_spn`, `ad_asrep`, `ad_admin` | built | `token.go` |
| Honey-file read watcher: fanotify (Linux); Windows via SACL and Security 4663 through `winevt` | Linux built; the Windows SACL is set by no action | `watch.go`, `fanotify_linux.go` |
| `akiascan`: derives `aws_access_key_id` from AKIA-pattern key ids in `http_request`, `net.sinkhole_capture` and `dns_query` events | built; the hook, with `capture.http_request` now a producer | `akia.go` |
| Controller: `GenerateHoneytokens` (secrets to the vault as `honeytoken/<id>/<name>`, metadata to the store), registry load, seeds, alert attribution, deploy plan | built | `internal/controller/deception_*.go` |
| Actions `file.plant` (secret content, `only_if_absent`), `ad.honey_account` (kerberoast SPN, AS-REP roastable, admin lookalike) | built; the AD action is lab-untested | `internal/actions/deception_{plant,ad,ad_windows,secrets}.go`, `registry_deception.go` |
| Rules `D15d`-`D15g` | built | `rules/deception.yml` |
| LSASS decoy logon session | missing | |
| Token kinds: honey OpenCart admin, honey DNS record, honey SQL login, honey SMB file | missing (a `honey_file` covers the SMB file when planted on the share's neighbour directory) | |
| Honey web paths | missing | |
| SACL setting for 4663 on Windows honey files | missing | |
| UI button or CLI for `GenerateHoneytokens` | missing | |

**3. Capability manifest.**

```go
module.Manifest{
	Name:      "honeytokens",
	Sides:     []module.Side{module.SideAgent, module.SideController},
	OS:        nil,                      // fanotify on Linux; SACL and the LSASS session on Windows
	Privilege: "root",                    // fanotify needs CAP_SYS_ADMIN; the LSASS session needs SYSTEM
	Roles:     []string{"decoys"},        // tokens are declared in decoys.yml for hosts with the decoys role; AD tokens run on domain_controller
	Consumes:  []string{"detect.alert", "http_request", "dns_query", "capture.http_request"},
	Emits:     []event.Type{ /* honeytokens.read, honeytokens.sighting, honeytokens.generated, honeytokens.secrets_unavailable */ },
	Budget: module.Budget{CPUMillisPerSec: 3, HeldMB: 4, EventsPerSec: 5, Burst: 20,
		BytesOutPerMin: 32768, DiskMB: 1},
	Default:  false,                      // opt-in per host in decoys.yml
	Tables:   []string{"honeytoken"},     // today one record in the store's meta table
	Content:  []string{"rules/honeytokens", "plans/deception.deploy.yaml", "pools"},
	Actions:  []string{"file.plant", "ad.honey_account", "win.lsass_decoy"},
	Pages:    []string{"/deception"},
	Evidence: []string{"how-to-win-ccdc-dealing-with-red-team"},
}
```

**4. Configuration.**

Tokens are declared per host in `decoys.yml` (the file it shares with `decoys`); module knobs are in `modules/honeytokens.yml`.

```yaml
# manifest/decoys.yml (per host)
decoys:
  rocky-ecom:
    honey_files: [/root/passwords.xlsx, /var/backups/backup.sql, /root/.ssh/id_rsa_old]
    honeytokens: [{ kind: ssh_key, at: /root/.ssh/id_rsa_backup }, { kind: db_cred, at: /var/www/html/.env.bak }]
  ad:
    domain: corp.example           # needed for the AD kinds on a domain controller
    honeytokens: [{ kind: ad_spn }, { kind: ad_asrep }, { kind: ad_admin }]
```

```yaml
# manifest/modules/honeytokens.yml
honeytokens:
  ad_ou: "OU=Decoys"               # separate OU under the domain DN
  lsass_decoy: { enabled: true, check_every: 60s }   # Windows servers
  ignore_exe: []                   # extra executables whose opens of honey files are not sightings
  plant_only_if_absent: true       # fixed true: a real .env or .bash_history survives
```

`plant_only_if_absent` is shown for clarity; it is not a setting that can be false. Token kinds in `decoys.yml` are validated against the generator's kinds. `ad_ou` defaults to `OU=Decoys,<domain DN>`.

```go
// package plan, as built: the tokens ride in DeceptionSettings.Tokens and WatchPaths.
type HoneyToken struct {
	ID, Host, Kind, Path, User, Secret, Fingerprint, SPN string
}
```

At retrofit these move to `modules.honeytokens` (see `decoys`, part 12), with an added `LSASSDecoy` section (account, secret reference).

**5. Events.**

Consumed: `detect.alert` (controller side: attribute an alert to a token), and `http_request` / `capture.http_request`, `dns_query` (agent side: the `akiascan` derivation; it watches the agent's own bus). `net.sinkhole_capture` is a consumed kind only if the sinkhole survives (see `egress`).

Emitted:

| Kind (code name) | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `honeytokens.read` (`honey.read`) | 1 | critical | `path`, `pid`, `exe`, `host`, `severity: critical`; when the registry knows the path: `honeytoken`, `token_origin`, `token_kind` |
| `honeytokens.sighting` | 1 | critical | controller side: `alert_id`, `rule`, `honeytoken`, `token_origin`, `token_kind`, `source`. Replaces rewriting the alert: stored events are hash-chained and are never rewritten |
| `honeytokens.generated` | 1 | normal | `hosts[]`, `tokens` (ids and kinds only), `plan_id` |
| `honeytokens.secrets_unavailable` | 1 | high | the vault was locked at start; decoys cannot recognise honey passwords until the secrets reload |
| derived `aws_access_key_id` events | 1 | high | a copy of the source event with `aws_access_key_id` and `derived_from` set, which `D15g` matches against `honeytoken.aws_keys` |

The existing code applies `Registry.Attribute` to incoming `detect.alert` events and adds `honeytoken`, `token_origin` and `token_kind` entities (`alerts.go`); the v4 contract emits `honeytokens.sighting` and lets the alert page join, so alerts are not mutated. Until the retrofit lands, the existing mutation of the alert's entities stays.

**6. Behaviour.**

*Every token is unique to its host* and recorded in the controller's registry. The generator draws values from `crypto/rand` and the registry refuses any ID, secret, account, fingerprint, SPN or host+path already registered, so two hosts never share one; this is what makes a sighting attributable. Names and values come from `pools/`.

*Token kinds.* The first table is built; the second is the v3 set that is not yet.

| Kind | Planted at (default) | Sighted when it shows up at |
| --- | --- | --- |
| `ssh_key`: a fake ed25519 private key, with its SHA-256 fingerprint | `/root/.ssh/id_rsa_backup` on each Linux host | The SSH decoy recognises the fingerprint (`D15c`) |
| `db_cred`: fake DB or app credentials | `/var/www/html/.env.bak` (Linux), `C:\inetpub\wwwroot\web.config.bak` (Windows) | Logins to MySQL, decoy services or the web admin page, by any service seeing the account (`D15d`) |
| `shell_history`: an inline password in the shell history | `/root/.bash_history`; PowerShell `ConsoleHost_history.txt` | That password tried anywhere. History files are tokens but are **not** watched: the shell itself opens them at every login, which would alert on the legitimate owner |
| `passwords_file`, `browser_cred` | `/root/passwords.txt`, `chrome_passwords.csv` (Linux and Windows paths) | A read (`D15f`) and use of the credential (`D15d`) |
| `aws_key`: an `AKIA` plus 16 base32 characters key id and a 40-character secret, a canary format, not a real credential | `/root/.aws/credentials`, `C:\Users\Administrator\.aws\credentials` | The key id appears in an HTTP request, a DNS name or a sinkhole capture (`D15g`, via `akiascan`) |
| `honey_file`: a read-watched file with no credential (`passwords.xlsx`, `backup.sql`, `id_rsa_old`) | Paths from `decoys.yml` | Any open: fanotify on Linux, Security 4663 on Windows (`D15f`) |
| `ad_spn`: a kerberoast bait account with an SPN such as `MSSQLSvc/sql07.<domain>:1433` | DC, in the decoy OU | Ticket requests (4769, 4768) or any logon attempt (`D15e`, `D15d`) |
| `ad_asrep`: pre-auth disabled | DC, decoy OU | AS-REP request (4768) or logon (`D15e`) |
| `ad_admin`: an administrator lookalike ("legacy") | DC, decoy OU | A logon attempt or an NTLM validation (4776, `D15d`) |

| v3 kind not yet built | Planted at | Sighted when | Needed |
| --- | --- | --- | --- |
| LSASS decoy credential | Windows servers | Failed authentication for that account on the DC (4625, 4771) | `win.lsass_decoy`; see below |
| Honey OpenCart admin with a unique password | ecom database | That login attempted on the admin page | `mysql.exec` insert plus a login-attempt seed in `honeytoken.accounts` from the web admin log (`logs` module) |
| Honey DNS record that nothing uses | DNS zone | Any query for it | A DNS-zone record action (the `ad` module's DNS family) and a `honeytoken.names` seed for `dns_query` |
| Honey SQL login and honey SMB file on the MSSQL host | MSSQL, the SOP share's neighbour directory | That login attempt; an open of the honey file (4663) | `mssql.exec` create login (login failure 18456 seeded) and a `honey_file` with a SACL |

*Honey AD accounts* (review D381, A7.Q7). `ad.honey_account` creates a plain user in a separate OU (`OU=Decoys,<domain DN>`), with no group memberships, a long random password (two generated passwords concatenated), `logon_rights: none`, created disabled and enabled after the password is set. Variants: one with an SPN (kerberoast), one with pre-auth disabled (AS-REP roastable), and one that looks like an admin (`pools/admin_names.txt`). They are bait for a full AD dump: every hash dumped includes theirs, and a pass-the-hash or Kerberos request for them is a critical alert with no cracking needed. Honey accounts are not privileged (no memberships), so the `ad` module's privileged-account allowlist must list them as expected via `list: honeytoken.accounts` to avoid a finding for an admin-looking name. Audit policy must log 4768, 4769, 4771 and 4776 on the DC (the `ad` and `hardening` modules set it).

*LSASS decoy session* (review D380; missing). On Windows servers the agent keeps a logon session alive whose credential sits in LSASS, the one reliable way to tell that LSASS was dumped. Design: the agent calls `LogonUserW` with `LOGON32_LOGON_NEW_CREDENTIALS` (the `runas /netonly` mechanism) for the decoy account and its secret and keeps the token handle open. That logon type stores the supplied credential in the logon session without validating it against any DC. A credential dumper sees the account and password; using it elsewhere fails authentication at the DC (4625, 4771, 4776), which `D15d` and `D15e` match. On a domain-joined host the decoy account is a honey AD account, on a standalone host a name that does not exist. A 60-second check (`check_every`) recreates the session when the handle is gone (Defender or a reboot killed it). **Complexity flag:** the agent holds a logon session on each Windows server; it is bounded (one session per host, one handle) and recreated, not repaired. The NEW_CREDENTIALS behaviour on Server 2019 and 2022 is not yet proven in the lab (T10).

*Honey files* (review D384). Opening one alerts. Linux: fanotify on the planted path (`NewFanotify`; unavailable when not Linux or not root, `ErrWatchUnavailable`); the `honeywatch` module emits `honeytokens.read` with the pid and executable, ignoring the agent's own pid and a list of executables (the agent's hash sweep must not touch honey files). Windows: a SACL on the file and Security 4663 through `winevt` (`D15f` matches `event_id: 4663` with `object_name` in the `honeytoken.paths` profile); no action sets the SACL yet. `file.plant` never replaces an existing file (`only_if_absent`): a real `.bash_history` or `.env` survives, verify then only checks existence, and the controller does not yet learn that a plant was skipped (part 12).

*Honey web paths* (review D384, D386). A honey web path is a file the web server could serve, unlinked from every page and never part of scored content. The planting plan places it only in a directory the service declares as `honey_ok` in `services.yml` (default: none), never in a declared content root with a regex check and never over an existing file, so the lint can prove scored content is untouched. Its read by the web server's process raises `D15f` via fanotify; the source address comes from the access log (`logs`) and the trace-back. Unguessable paths mentioned only in breadcrumbs (a honey file's contents) are the same mechanism. Missing.

*Deploy and registry.* `Controller.DeceptionPlan` generates the missing tokens for the hosts and returns the plan from `plans/deception.deploy.yaml`: an approval gate, a `deception.decoy_check` per decoy host (from `decoys`) and a `plant.<token>` node per planting step (`file.plant`, `ad.honey_account`). Secrets never travel in plans: plan nodes name their secret parameters (`secret_params`) and a vault entry per parameter (`secret_refs`, only entries under `honeytoken/`). The plan JSON, its hash, the stored plan body, the signed step params, diffs and results hold only those names. The controller resolves the entries into the step's secrets blob when it issues the step (the digest is signed with the step), and the agent hands it to the action through its context (`actions.WithSecrets`); `file.plant` diffs say "content not shown", and the AD action scrubs the password from backend errors. There is no plaintext password parameter. `GenerateHoneytokens` writes every secret to the vault as `honeytoken/<id>/<name>`, stores the metadata (no secrets) as one record in the store's `meta` table (to become the module's `honeytoken` table), and only then swaps the live registry and pushes the changed configs. Calling it again generates nothing for hosts that already have tokens. Without a vault it is refused. If the vault is locked at start the registry loads without secrets, `honeytokens.secrets_unavailable` fires, and decoys cannot recognise honey passwords until `ReloadHoneytokenSecrets` runs (after unlock). The registry is part of the controller state snapshot (core: recovery).

*Detection feed.* `Registry.Seeds()` becomes `Detect.Seeds` (`honeytoken.accounts`, `.spns`, `.paths`, `.aws_keys`) in every host's signed config that has rules, so `D15d`-`D15g` fire wherever the event shows up; a registry change bumps the config version and agents re-seed. `Registry.Attribute` maps an alert's fields to the token and its origin host.

*Canary AWS key ids.* The `akiascan` module (hosts with rules) watches the agent's own `http_request`, `net.sinkhole_capture` and `dns_query` events for AKIA-pattern key ids (case-insensitive so DNS labels match; bounded in depth, size and count) and emits a copy of the event with `aws_access_key_id` and `derived_from` set. It adds nothing to an event that already carries the field and never rescans its own output. Since `capture` now emits `capture.http_request`, a producer exists on hosts with the `capture` role (outbound requests to a cloud API with the canary key are seen on the wire in the clear only for HTTP; TLS requests are invisible, which the `akiascan` doc notes).

*Severity.* A honeytoken sighting is critical wherever it shows up: `D15c` (at a decoy), `D15d` (any logon or auth event naming a honey account or key id, success or failure), `D15e` (4769/4768/4771/4776 for a honey SPN or account), `D15f` (honey file read, `honeytokens.read` or 4663), `D15g` (canary AWS key id).

**7. Actions and content.**

| Action | Risk | Locks | Scorer-visible touches | Notes |
| --- | --- | --- | --- | --- |
| `file.plant` | service | the path's lock (`lockForPath`) | a path touch (modify) on the planted file; the scoring guard rejects scored content paths, and an existing file is never replaced | Built. Secret content from the step's secrets blob; `only_if_absent`; no plaintext secret parameter. |
| `ad.honey_account` | service | `ad:honey` | an account touch (modify) on the new honey account, in a separate OU with no memberships | Built. Needs a directory backend that can create accounts (the Windows ADSI layer on a DC agent); `ErrNoADBackend` otherwise. No automatic rollback. |
| `win.lsass_decoy` | service | `accounts` | none | Missing. Starts or checks the decoy logon session; the periodic check is a module loop, not a plan step. |

Content: `rules/honeytokens/` holds `D15d.honeytoken-auth`, `D15e.honey-kerberos`, `D15f.honey-file-read` and `D15g.canary-aws-key` with inline tests (they move from `rules/deception.yml`); the seeded profiles `honeytoken.accounts`, `honeytoken.spns`, `honeytoken.paths`, `honeytoken.aws_keys` come from the registry; `plans/deception.deploy.yaml` (shared with `decoys`); `pools/` supplies names, filenames and content.

**8. UI.**

The Deception page (shared with `decoys`) lists, per host, the planted tokens (kind, path or account, planted time, sightings; secret values are never shown), the registry state (vault locked, secrets unavailable), the deploy plan button and a regenerate button for a host whose `decoys.yml` entry changed, and the honey-file watch state. Every sighting shows the `token_origin` host ("this credential was planted on rocky-ecom") and links to the alert and the trace-back. Host x step grid column: `honeytokens planted` (verified when the plan's nodes and verify steps passed and the watch is armed). Overview tile: sightings in the last hour.

**9. Health.**

- `ok`: tokens planted, watchers armed, the vault unlocked.
- `degraded`: fanotify unavailable (not root or not Linux; honey files unwatched); the LSASS session could not be created or was recreated; the vault locked (secrets unavailable); a planted token whose file no longer exists; a skipped plant that the registry still counts.
- `error`: the registry rejects a duplicate; a plan failed half way (the DC action has no rollback).
- Gaps: Windows honey files without a SACL; honey web paths not planted because no service declares `honey_ok`.

**10. Scoring safety.**

- Tokens are fake and unused by any legitimate path, so a legitimate user or the scorer should never touch one. The AD honey accounts are not scored accounts and have no group memberships. They live in a separate OU.
- Planting adds files and one AD OU of accounts; it never replaces an existing file, never writes under scored content, and the lint rejects a plant under a declared content root. Honey web paths are placed only where a service declares them acceptable.
- The scorer's learned accounts are exempt from `D15d` by behaviour: a honey account is never in `accounts.scored`.
- The AD action and the agent LSASS session run on a DC or server and are an additive state change with no automatic effect.
- Alert-only: the module only observes and alerts; blocking a source that touched a token is a separate one-click response in `respond`.

**11. Tests.**

- Built: generator and registry uniqueness (`TestUniqueAcrossHostsAndKinds`, `TestRegistryRefusesCollisions`), token contents, Windows plan, AD accounts, attribution and matching, bad input, the watch module, a real fanotify read, `file.plant` secrets and `only_if_absent`, `ad.honey_account` through a backend (hygiene, directory binding, missing backend), generation with the vault and a locked vault, plan holds no secret, foreign vault entries refused, honey alert attribution, section fingerprint follows the tokens, AKIA scanning and the derived event matching `D15g`.
- To add: LSASS decoy session on a Windows lab host (create, dump with a credential tool, use elsewhere, DC events, recreate after kill); the four missing kinds; honey web path planting and the `honey_ok` lint; the SACL action; `honeytokens.sighting` emission; the vault unlock triggering `ReloadHoneytokenSecrets`; conformance entries.
- Lab: T08 (Kerberoasting including the honey SPN: `D8` and `D15` critical), T09 (honey SSH key against the SSH decoy), T10 (LSASS dump, then the decoy credential used: critical naming the origin host), T24 (Defender does not quarantine the agent, decoys or the LSASS session), `ad.honey_account` against a real DC.

**12. Limits and open items.**

- `shortcut: ad.honey_account sets no deny-logon rights and relies on the account having no memberships; upgrade to an explicit deny-logon right set on the OU once a lab DC run shows what the GPO machinery allows`.
- `shortcut: no automatic rollback of ad.honey_account; upgrade by disabling the account in a rollback step`.
- `shortcut: the controller does not learn that file.plant skipped an existing file, so the token stays registered and the path watched; upgrade by having the step result carry skipped=true and the registry drop the token`.
- Windows honey-file SACLs are set by no action; `D15f`'s 4663 path cannot fire until one exists.
- The honeytoken secrets of every host are in each decoy host's signed config. See `decoys`, part 12, for the salted-hash proposal; undecided.
- `GenerateHoneytokens` is an API: there is no CLI or UI button, a changed `decoys.yml` for a host that already has tokens does not regenerate them, and a vault unlock does not trigger `ReloadHoneytokenSecrets` by itself.
- The registry is a single `meta` record; the contract wants a declared `honeytoken` table with migrations in the package.
- `ad.honey_account` and `file.plant` are not in the core action table (the `ad.*` family is owned there by `ad`); this module owns both. `win.lsass_decoy` is new.
- Honey web paths need a `honey_ok` field in `services.yml` (core manifest schema).
- Sinkhole dependency: `net.sinkhole_capture` is an `akiascan` input only if the sinkhole is kept (`egress`).
- Honey AD accounts need audit logging of 4768, 4769, 4771 and 4776 on the DC; if the `hardening` pack is not applied, the Kerberos rule cannot fire.
