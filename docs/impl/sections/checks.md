#### `checks`

**1. Purpose and evidence.**

`checks` keeps a live, editable list of active checks: our own end-to-end tests of each service, built to behave like Quotient, plus the scorer-mimic probes the execution engine runs before and after a plan node, the multi-step Orange customer flows, and the service doctor that explains why a scored service is down. The list is kept in step with the scorer by proposals from the `scorer` module (check discovery); `checks` never reads scorer traffic itself.

Evidence that it matters for points:

- Uptime dominates. SLA was 13% of our 2026 regional losses and each service carries equal weight [[2026-mw-regional-scorecard-t7-services#e2]]. A service we cannot check is a blind spot worth one service's share.
- TFTP and NTP were scored at the 2026 and 2025 regionals [[2026-mw-regional-packet#e19]], [[2025-mw-regional-packet#e28]], about 1/7 of uptime each. A scored service with no check type is a blind spot.
- Orange Team (customer service) is a scored component with the highest average (27.5/100) in 2026 [[2026-mw-regional-scorecard-t7#e4]]; the White Team uses Orange results [[2026-mw-regional-packet#e11]]; manual checks "may not align" with scoring [[2026-wr-regional-packet#e20]]. Orange breaks on changes our service checks do not cover (a broken cart, a mail that sends but never lands).
- Our own changes cause outages and red gets blamed for them [[how-to-win-ccdc-scoring#e3]]. The doctor and the before/after probes say which.
- Quotient is lax in places (a 404 passes with no regex; an SSH command passes on any output) and strict-where-lax checks catch what the scorer will not [Q §9.7]. Quotient's transport details come from its source [Q §0, Q §2, Q §9.11].
- Peer evidence: DSU `cyber/doctor.sh@be21b75` runs a per-service diagnosis when a check fails (orchestration report).

**2. Status and code.**

Probe library: built (`internal/checks`, 16 check types, unit tests against local fake servers: `ssh_test.go`, `smb_test.go`, `web_dns_test.go`, `ntlmserver_test.go`, `lineproto_test.go`). Controller side: partial. `internal/controller/checks_hub.go` stores results (`check_results`) and advances SLA streaks; `checks_ops.go` renders the per-service view. The agent module that runs checks on a schedule is `CheckRunner` in `internal/vantage/checkrunner.go` (built). Missing:

- No controller scheduler (docs/ui.md): the controller does not yet run its own probes on an interval; only the `check_runner` role does.
- TFTP and NTP check types, Orange flows, the service doctor, the check lifecycle in the UI (add, edit, pause, retire, accept current response), and the proposal records.
- Check records come from `services.yml` `health` blocks and accepted proposals; no code renders them yet.

Retrofit changes the contract forces:

1. `CheckRunner` moves from `internal/vantage` to `internal/checks` and registers as the `checks` agent module (`internal/agent/mods/checks.go`). It has nothing Kali-specific except the target allowlist, which becomes a config field. The Kali runs the same module with the role `check_runner` and its public-address allowlist. `vantage` keeps the Kali-only parts.
2. The probe library is stateless, so it is a shared library the other modules may import. It moves to the subpackage `internal/checks/probe` (`Run`, `Faithful`, `Sweep`, `AuthOnly`, `Spec`, `Item`, `Cred`, `Result`, `Options`). `vantage` (credential verification) imports only that subpackage, never the module package. This matches the contract's shared-library rule, which names the protocol clients in `internal/checks`.
3. The hub stops importing `internal/scorer`. It emits `checks.result` events; the `scorer` module consumes them to advance its SLA tracker (it owns the tracker). The hub keeps only the store tables `checks` and `check_results`, which move out of the core migrations into this module's migrations.
4. The kind `vantage.check` becomes `checks.result`. The controller accepts the old name as an alias for one release.

Files: `internal/checks/*.go` (module, scheduler, flows, doctor), `internal/checks/probe/*.go` (library), `internal/agent/mods/checks.go`, `internal/controller/checks_hub.go`, `internal/controller/checks_ops.go` (to be folded into the module), `checks/` content directories.

**3. Capability manifest.**

| Field | Value |
| --- | --- |
| Name | `checks` |
| Sides | agent (the `check_runner` role), controller |
| OS | linux, windows (the AD host is a `check_runner`) |
| Privilege | `root` on the agent (the ICMP probe tries an unprivileged datagram socket first and falls back to a raw socket); `none` on the controller |
| Roles | `check_runner` (agent), `controller` |
| Default | core |
| Budget (agent) | 40 CPU ms/s, 24 MB held, 5 events/s, burst 20, 60 KB out/min, 5 MB disk |
| Budget (controller) | 60 CPU ms/s, 48 MB held, 10 events/s, 120 KB out/min, 20 MB disk |
| Tables | `checks`, `check_results` |
| Content | `checks/checks` (check templates per service kind), `checks/flows` (Orange flows), `checks/doctor` (collect plans per service kind) |
| Actions | none; the doctor uses the core `collect.*` and `probe.run` actions; probes run through the scorer-mimic probe contract of the execution engine |
| Pages | `/services`, `/checks`, `/checks/{id}`, `/flows` |
| Evidence | the citations in part 1 |

The budget numbers are starting values; the lab run sets them.

**4. Configuration.**

`modules/checks.yml` (manifest) and the agent block `modules.checks` in the signed `AgentConfig`:

```yaml
# modules/checks.yml
interval: 45s                 # one faithful pass over a runner's checks; jittered +-10%
sweep_every: 10               # every 10th pass of a check also runs the union sweep
min_gap: 250ms                # between probe starts on one runner
max_concurrent: 2             # probes in flight on one runner
max_defer: 45s                # longest wait for a quiet window before a pass skips the check
probe_timeout: auto           # auto = min(10s, Delay/2) once the delay is measured; a duration overrides
strict: true                  # StrictOK is computed and Result.OK follows it
bad_attempts: 0               # SSH BadAttempts failures before the real login; off, see Scoring safety
red_after: 2                  # consecutive failed faithful probes that open an alert
latency_warn: 0.7             # alert when a probe takes longer than this fraction of Delay/2
vantages: [controller, lan, kali]   # where each check runs unless the check says otherwise
doctor:
  enabled: true
  on: first_failure           # once per failure streak; "Run again" in the UI re-runs it
  timeout: 30s
flows:
  enabled: false              # flows with side effects stay off until an operator enables each flow
  interval: 5m
allowlist: []                 # agent only: our own public addresses a runner may probe (rendered from the manifest)
```

```go
// package checks (controller block); the agent block is ChecksSettings in internal/plan.
type Config struct {
	Interval, MinGap, MaxDefer, ProbeTimeout time.Duration
	SweepEvery, MaxConcurrent, RedAfter      int
	Strict                                   bool
	BadAttempts                              int
	LatencyWarn                              float64
	Vantages                                 []string
	Doctor                                   DoctorConfig // Enabled, On, Timeout
	Flows                                    FlowsConfig  // Enabled, Interval
}

type ChecksSettings struct { // plan.ModuleSettings.Checks; nil = disabled
	Interval, MinGap, MaxDefer, ProbeTimeout time.Duration
	SweepEvery, MaxConcurrent                int
	Strict                                   bool
	BadAttempts                              int
	Allowlist                                []string
	Checks                                   []Spec // the learned item and credential unions; credentials by vault reference, resolved per signed step
}
```

A check record (`checks` table, and `services.yml` `health:` blocks): service, type, parameters, expected result, interval, vantages, origin (`manifest`, `discovered` or `manual`), state (`active`, `paused`, `retired`, `proposed`), mode, result history. Check templates under `checks/checks/<kind>.yml` give the defaults per service kind. Every UI change is written to the manifest overrides and takes effect at once.

**5. Events.**

Consumes: `scorer.proposal` (new, update and stale check proposals), `scorer.clock` (the quiet window and measured delay), `scorer.item_set` (learned item and credential unions per service), `deps.graph` (dependency edges for doctor probes), `inventory.probe_result` (doctor reads), `telemetry_gap` (a gap near a failure is shown with the diagnosis), and `creds.state` (so a probe uses the current vault version of a rotated scored password and does not run during a PCR transaction's `host_changed` interval with the old one).

Emits:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `checks.result` | 1 | normal | `id`, `type`, `service`, `host`, `port`, `item`, `user`, `mode` (`faithful`, `sweep`, `auth`), `vantage`, `ok`, `scorer_ok`, `strict_ok`, `class`, `err` (credential-free), `strict_issues`, `elapsed_ms`, `steps` |
| `checks.deferred` | 1 | bulk | `id`, `vantage`, `reason` (no quiet window in `max_defer`) |
| `checks.refused` | 1 | high | `id`, `vantage`, `target` (a target outside the allowlist; this is a bug or an attack) |
| `checks.red` | 1 | high | `service`, `check`, `vantage`, `streak`, `class`, `diff` (response diff against the last pass), `trace` (reference to the latest trace-back); alert class |
| `checks.latency` | 1 | normal | `service`, `check`, `elapsed_ms`, `limit_ms` |
| `checks.compare` | 1 | high when not `both_ok` | `service`, `check`, `class` (`both_ok`, `service_down`, `path_broken`, `scorer_content`, `internal_only`), `external`, `lan` result refs; the vantage rule V1 matches it |
| `checks.flow` | 1 | normal | `flow`, `vantage`, `ok`, `failed_step`, `steps[]` (name, ok, elapsed, class), `effects` |
| `checks.diagnosis` | 1 | high | `service`, `host`, `streak_id`, `causes[]` (rank, cause, evidence, source step) |

A red check opens an alert through the core alert pipeline: alert-class events (priority high or critical) become alert rows. `checks.refused` keeps the name and fields the code uses today.

**6. Behaviour.**

*What the scorer does, as far as the checks depend on it.* The scorer runs a burst every `Delay ± Jitter`. Each check draws one random sub-item and one random credential per round with one attempt [Q §0.2]. A broken item or one wrong password therefore fails only some rounds, and a service has to be learned over many rounds. A round is all-or-nothing: if any task result is missing at the deadline the whole round is discarded and SLA streaks neither advance nor reset [Q §3]. Config hot-reloads, and checks have launch and stop times and can be toggled per team [Q §9.9]. The rest of the scorer model is in the core Environment section and in the `scorer` module.

*Where checks run.* The controller (once its scheduler exists), `check_runner` agents on the LAN, and the Kali against the public addresses `172.25.(20+T).x`. Each check runs every 30-60 s per vantage, outside the burst. A runner asks for a quiet window as long as the probe timeout and waits up to `max_defer`; if none opens it skips that pass and emits `checks.deferred`. Probe starts are `min_gap` apart with at most `max_concurrent` in flight, so probes stay below knife-edge volume.

*Check types.* Each probe reproduces Quotient's client with the same Go libraries where possible, so fingerprints match without effort [Q §9.11]:

| Type | Behaviour reproduced |
| --- | --- |
| http, https | `GET`, `Host: ip:port` always with the port, a random browser User-Agent, `Accept-Encoding: gzip`, keep-alives off, a fresh transport, TLS verify off, no SNI for an IP, redirects followed. Status is checked only if set, then the regex; neither set passes on any response (as the scorer does). Run for every learned URL |
| dns | One UDP A or MX query, RD set, no EDNS, the same query repeated after a deadline. Only A answers are compared, so MX never passes (`scorer_limit`) |
| ping | ICMP echo, 24-byte payload (8-byte timestamp plus 16-byte tracker), seq 0, random id, 5 s. Without `net.ipv4.ping_group_range` or raw-socket privilege the result is `config`, not a false red |
| tcp, rdp | Bare connect; `rdp` sends no RDP bytes, as upstream. The Kali adds an authentication probe with `xfreerdp /auth-only` (a pre-approved host tool), the only way to check RDP with authentication without our own RDP client |
| ssh | A banner from a 19-string OpenSSH/PuTTY/Windows list, `3des-cbc` appended to the ciphers, password auth (x/crypto sends `none` first), `pty-req xterm` 80x40, ECHO off, `shell`, one typed line, wait `Timeout/8`, read. Contains or regex on stdout. This catches slow profile scripts, `PermitTTY no` and `nologin` shells. `BadAttempts` is off |
| ftp | `USER`, `PASS` (anonymous without a credential), `FEAT`, `TYPE I`, `OPTS UTF8 ON`, `EPSV`, `RETR`, `QUIT`; regex xor SHA-256 |
| smb | Own SMB2 client (dialects 2.0.2 and 2.1), NTLMv2 with flags `0xe2888215` (key exchange, no seal), an empty domain replaced by the challenge's TargetName (a bare username hits the local account database of a member server), tree `\\ip:445\share`, Create, Read, Close, Tree Disconnect, Logoff; signing when the server requires it; guest with no credential |
| smtp | `EHLO localhost`, `AUTH PLAIN` over plaintext when a credential exists and AUTH is advertised, `MAIL FROM:<u> BODY=8BITMIME`, `RCPT TO:<another credlist user>`, `DATA` with a 16-hex subject and 64-hex body; no STARTTLS |
| imap, pop3 | IMAP `LOGIN`, `LIST "" "*"`, `LOGOUT`; POP3 `USER`, `PASS`, `NOOP`, `STAT`, `QUIT`. An encrypted variant verifies the certificate, as the scorer does |
| winrm | `POST /wsman` unauthenticated first, then NTLM Negotiate and Authenticate on the same connection, shell create, `powershell.exe -EncodedCommand` (default `hostname`), receive, delete. Any stderr fails. No message sealing, so a service with `AllowUnencrypted=false` fails here as it fails the scorer |
| ldap | Hand-written BER simple bind as `user@domain` (389 cleartext, 636 TLS) |
| mssql | TDS 7.4 PRELOGIN, TLS inside TDS when the server answers ON or REQ, LOGIN7 (SQL auth), a SQL batch, first column of any row equals or matches. The real scorer script is unknown |
| splunk | Basic-auth `GET /services/server/info` on 8089; with a `Query`, REST login then `/services/search/jobs/export` compared with the expected output, until the real logic is seen |
| tftp | New. UDP RRQ for a small learned file in octet mode, read the DATA blocks with ACKs, compare SHA-256. Added with the lint rule that applies only when TFTP is a scored service in the manifest (review N7.1) |
| ntp | New. A mode-3 client query over UDP 123; pass when a mode-4 reply arrives with a sane stratum and a time within a configured skew of the runner's clock (review N7.1) |

TFTP and NTP are small. The scorer's exact logic for them is unknown, so until the `scorer` module sees it they are learned by burst, port and account, like MSSQL and Splunk.

*Two modes per check.* The **faithful sample** picks one random item and one random credential like the scorer and judges the response as the scorer would: it tells us what the scorer will see this round. The **union sweep** tests every learned item with a random credential (not the full item-by-credential product, to keep volume low), at a low rate: it finds the one broken item that hides for rounds [Q §9.8]. A credential-wide sweep is a loop over `AuthOnly`. The `AuthOnly` mode logs in with a given credential and asks for no item; the `vantage` module uses it for password verification.

*Verdicts.* Every `Result` carries `ScorerOK` (what Quotient would conclude, blind spots included) and, in strict mode, `StrictOK` with `StrictIssues`; `OK` is the verdict for the mode used. Failure classes separate "service unhealthy" (`unreachable`, `timeout`, `auth`, `protocol`) from "scorer would fail on content" (`content`), "the scorer itself cannot pass this" (`scorer_limit`, the MX case) and "the spec is unusable" (`config`: no credential, bad regex). Strict mode adds: web status 2xx when none is configured and the body SHA-256; DNS MX compared and all expected A addresses present; FTP and SMB file regex and hash both when both are set, empty files flagged; SSH output must contain the expected string and must not look like an error; SMTP final `250` after DATA; IMAP `SELECT INBOX`; POP3 well-formed `STAT`; WinRM exit code 0 and non-empty output; LDAP non-empty password; RDP an X.224 confirm. Passwords never appear in `Err`, `Debug` or events; they pass through `vault.RedactString`.

*Red, latency, comparison.* A check turns red after `red_after` (2) consecutive failed faithful probes at one vantage. A red check opens an alert with the response diff and the latest trace-back attached. The scorer's timeout is `Delay/2` by default, so `checks.latency` fires when a response takes more than `latency_warn` of it [SP §A14]. Vantage points are read side by side: red from the Kali but green from the LAN is `path_broken` (the Palo or NAT path); red from the LAN is `service_down`; a pass on both with a content difference is `scorer_content`; red only on the LAN is `internal_only`. The Kali is the closest to the scorer's own position.

*Orange flows.* A flow is a multi-step check on scored services, run from the Kali and the LAN, that behaves like a customer rather than like Quotient. It uses a browser-like client with a cookie jar, a Phylax-owned test customer (never a scored user; the account is flagged `orange_visible: false` in `accounts.yml`), and carries the `us` label by its vantage. Steps are typed operations over the existing probe clients, so a flow adds no new protocol code:

```yaml
# checks/flows/ecom-purchase.yml
module: checks
id: orange.ecom-purchase
vantages: [kali, lan]
effects: [creates_order]           # shown in the UI; a flow with effects is off until enabled
steps:
  - { name: home,     http: { get: "/", expect_status: 200 } }
  - { name: product,  http: { get: "/index.php?route=product/product&product_id={{ product_id }}", capture: { token: 'name="csrf" value="([^"]+)"' } } }
  - { name: add,      http: { post: "/index.php?route=checkout/cart.add", form: { product_id: "{{ product_id }}", quantity: 1 }, expect_status: 200 } }
  - { name: checkout, http: { post: "/index.php?route=checkout/confirm", form: { csrf: "{{ token }}" }, expect_regex: "order" } }
```

The 2027 ecom product is unverified; the URLs above are the OpenCart shape from 2026 and are replaced from the packet. Other shipped flows: webmail send and read (SMTP send as the test user, then IMAP or Roundcube read of the same subject), and an AD user logon over RDP (`xfreerdp /auth-only` from the Kali). A flow reports per step in `checks.flow`; the first failed step names the break. Read-only flows run by default once enabled; flows with `effects` need an operator to enable each one, because a cart or a sent mail leaves data on a scored service. The lab reuses the same flow files, run from many random source addresses, as the Orange traffic generator (D511), so the lab and the live flows cannot drift apart.

*Service doctor.* When a scored service's check fails (the first failed faithful probe of a failure streak, not `scorer_limit`, not a `config` failure), the controller sends a read-only `collect` plan from `checks/doctor/<service kind>.yml` to the service's host. Once per failure streak; "Run again" in the UI re-runs it. The plan collects:

- a config test with the service's own validator in check mode (`sshd -t`, `apachectl -t` or `httpd -t`, `nginx -t`, `named-checkconf`, `postfix check`), the same pre-approved hash-pinned tools the `validate` hook uses;
- the listener and its bind address against the manifest (from the `probe.run` listeners table);
- recent error lines from the service's journal or log (read natively from the journal files; `shortcut: reads the journal through host.exec journalctl until a native reader exists, replace when the logs module has one`);
- SELinux denials (AVC records in the audit log) on Rocky;
- disk space and inodes (`statfs`), and the process state of the unit;
- probes of each dependency from the manifest `depends_on` and the high-confidence edges of `deps.graph` (a plain TCP connect from the host).

Each collected item is matched by a content rule (`when`, `cause`, `weight`) and the causes are ranked by weight into one `checks.diagnosis` event shown on the red check. D282-D285 explain what we changed; the doctor explains why the service is down now.

*Check proposals.* The `scorer` module emits `scorer.proposal` events ("Scorer started checking X" with a sample request and a pre-filled check, "update the existing check", "possibly stale: no scorer counterpart for 5 rounds"). `checks` stores them as records in state `proposed` and shows them in the UI. A human click turns a proposal into a check; nothing is ever removed automatically. **Make this a check** also creates a check from any observed request.

*The checks view.* Per service, two columns: our active checks with their latest result from each vantage, and the scorer checks observed recently with when each was last seen. Each pair is marked matched, proposed or stale. A change feed sits below. A strip shows the round clock, learned Delay and Jitter, the SLA streak per service and dropped rounds (all from `scorer` events).

*Credentials for probes.* A probe needs the scored user's current password. It comes from the vault (the controller resolves `cred/<host>/<account>` for scored accounts and sends it in the signed step for that probe; the Kali holds it in memory only, never on disk). Plaintext protocols also let the parsers record a pair the scorer used, encrypted field by field. A scored user whose password the vault does not hold runs without a credential and shows as `config: no credential`; it is never guessed.

**7. Actions and content.**

No new action. The module uses the core `collect.files`, `collect.inventory` and `probe.run`. Content shipped:

- `checks/checks/<kind>.yml`: one template per service kind (http, https, dns, ping, tcp, rdp, ssh, ftp, smb, smtp, imap, pop3, winrm, ldap, mssql, splunk, tftp, ntp) with default items and expectations.
- `checks/flows/*.yml`: `orange.ecom-purchase`, `orange.webmail-roundtrip`, `orange.ad-rdp-logon`.
- `checks/doctor/*.yml`: one collect plan with ranked causes per service kind.

**8. UI.**

- `/services`: per service, our checks at each vantage with the SLA streak and penalties (level `ok`, `warn` at threshold-2, `critical` at threshold-1), the doctor's ranked causes, the proposals, and a link to the `/changes` feed of `traceback`.
- `/checks` and `/checks/{id}`: history (200 results), add, edit, pause, retire, **Accept current response** after a legitimate change, **Make this a check**.
- `/flows`: each flow, its steps, effects, and an enable switch.
- Overview tile: red checks, `path_broken` count, services with a doctor diagnosis.
- No host-grid column.

**9. Health.**

States: `ok`; `degraded` when a runner defers more than half its passes (no quiet window) or the controller scheduler is behind; `unavailable` when no clock feed has arrived and the module runs on its jittered-interval fallback (gap: "no round-clock feed; probes are not aligned to the scorer's bursts"); `over_budget`. Gaps: a check type without a credential, ICMP without privilege, `xfreerdp` absent on the Kali (RDP auth probe unavailable), `checks.refused` events seen. Degraded means results exist but their alignment or coverage is reduced.

**10. Scoring safety.**

The module is the heaviest active user of scored services, so it limits itself:

- Probes are one connection per probe with a hard deadline on every socket; none leaks the way the scorer's check goroutines do. `max_concurrent`, `min_gap` and the quiet-window gate keep them below burst volume.
- Targets are an allowlist of our own addresses; hostnames are refused, because an allowlist of IPs cannot vouch for what a name resolves to. The scorer, other teams and global assets are never targets.
- A probe logs in as a scored user, so its logins count as logins. `bad_attempts` stays 0: we never send deliberate failed logins, because a lockout policy somewhere would count them (the scorer's own `BadAttempts` is exempt from lockout and brute-force rules by behaviour, not ours).
- The SMTP faithful probe sends mail to a credlist user at the faithful rate, so mailboxes grow; the rate is bounded and mailbox quota is a lab measurement (part 12).
- Flows with side effects are off until enabled, and listed with their `effects`.
- The doctor is read-only.
- Alert-only stage: in observe mode checks run (they only read, apart from SMTP and enabled flows), flows with `effects` stay disabled, and the doctor collects without any follow-up action.
- The execution engine's scorer-mimic probe (before and after a plan node) calls this library. It uses two different scored users, chosen per credlist so each list the service draws from is exercised. A failed "after" probe rolls the node back; a failed "before" probe stops it. Probes are bounded (one retry after 5 s, then fail).

**11. Tests.**

- Unit: every probe against a local fake server (`ssh_test.go`, `smb_test.go` with `ntlmserver_test.go`, `web_dns_test.go`, `lineproto_test.go`, `misc_test.go`); strict-mode cases; credential redaction; quiet-window gate and allowlist (`checkrunner_test.go`); `Compare` classification.
- New: TFTP and NTP against fake servers; flow runner with a fake web app (cookie jar, capture, form post, effects flag); doctor ranking from fixture collect output; check lifecycle (proposal, accept, retire, accept-current-response writes an override).
- Conformance: starts with no config (disabled), reaches `ok` or `unavailable` within 10 s, stops cleanly, emits only declared kinds, respects its budget under a 40-check fixture, survives 60 s of failing `Emit`, survives reconfiguration with `Keep` state (the pass counters).
- Lab (v3 ids; the v4 matrix renumbers them): T14 (a Quotient config hot-adds an HTTP path, a DNS record and a custom check: a proposal within one round), T15 (check discovery accuracy over 2 hours with Orange traffic: 100% of Quotient's checks proposed, 0 false proposals), T16 (a hardening plan breaks a scored page, `PermitTTY` or a mail plaintext setting: the lint rejects it; if forced, the probe is red in 60 s and the node rolls back), T20 (60 minutes of Quotient plus Orange traffic, 5 or fewer false-positive alerts per hour), T34 (hardening against real Quotient: 0 failed rounds attributable to Phylax), T39 (faithful checks against Quotient's results: 98% agreement or more, after calibration). New lab tests: TFTP and NTP against a Quotient configured with them; each Orange flow against the lab ecom and mail host; a doctor run for each injected failure (stopped unit, broken config, full disk, SELinux denial, dependency down).

**12. Limits and open items.**

- `shortcut: SMB 2.0.2 and 2.1 only, no encryption or pre-auth integrity, NTLM MIC not sent; a server that insists on SMB3 encryption or 3.1.1 reports a protocol failure, upgrade if a lab run shows Quotient passing such a server.`
- `shortcut: WinRM has no message sealing (masterzen NTLM transport); a service with AllowUnencrypted=false fails here as it fails the scorer, upgrade only if Quotient is seen using sealing.`
- `shortcut: MSSQL decodes only common column types (nvarchar, varchar, int family, bit); others return a protocol failure only when an output comparison needs them. The real scorer script is unknown, upgrade when it is seen.`
- `shortcut: SMTP, LDAP and HTTPS TLS verification is off because the scorer's is unspecified; IMAP and POP3 verify as documented. Upgrade when the scorer's behaviour is captured.`
- `shortcut: doctor reads the journal with journalctl through host.exec, replace with a native reader.`
- `shortcut: the union sweep samples one random credential per item, not the item-by-credential product; a credential-wide sweep is a loop over AuthOnly, add it if a lab run shows a credential-specific failure hiding.`
- Open: the runner's quiet-window gate needs the round-clock estimate on the agent. Proposed: `scorer.clock` is carried to runners in the signed config block (`modules.checks.clock`: delay, jitter, last burst, window), refreshed when the estimate changes and extrapolated between refreshes. The core wire protocol has no message for it. Until it exists a runner uses its fallback (jittered intervals, `unavailable` health gap).
- Open: whether the controller scheduler or the `check_runner` on `ubuntu-wkst` is the in-LAN vantage. Both are specified; the lab picks.
- Open: mailbox growth from SMTP probes and the real quota of the 2027 mail host.
- Open: the exact Orange flows depend on the 2027 ecom and webmail products (Roundcube is expected). Flows are replaced from the packet.
- Core change: alert rows from controller-origin alert-class events (confirm the ingest hook covers events with agent `controller`).
- Core change: the shared-library list should name `internal/checks/probe` (see Status and code, item 2).
- Cross-section: the `checks.compare` event and rule V1 are specified here and in `vantage`. The `scorer` module owns the SLA tracker; `checks.result` with `mode: faithful` feeds it.
