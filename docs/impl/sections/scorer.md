#### `scorer`

**1. Purpose and evidence.**

`scorer` is the controller's model of Quotient, learned only by watching what reaches our hosts. It estimates the round clock and the quiet windows between bursts, recognises scorer traffic by behaviour, learns the service set and the item set per service, learns which accounts the scorer logs in with, tracks SLA streaks, and ranks services by points at risk. Every time-sensitive action in Phylax uses its windows: scored-password changes, active-check scheduling, hardening on scored services, the Kali's scans, and the eviction cutoff for scored-account sessions.

Evidence that it matters for points:

- The window is what makes a scored-password change safe: a PCR is entered inside the quiet part of the interval, so at most one failed round per affected user [Q §5, Q §9.1].
- Scorer-account learning is the primary source of scored accounts because Quotient is not reachable from inside the environment (review D251, area 7 revision). Quotient shows teams the users it scores with and no admin accounts are used for scoring (MW Discord 2026-10-22, decision 10). It has several credential lists, possibly per service. The red team does not have the scoring user list.
- Uptime dominates and SLA penalties come from failure streaks; dropped rounds are not incidents [Q §9.5, Q §9.12]. Accrual differs by event (the 2026 WR regional used 35 then 20 per round; the Quotient default is 5 consecutive failures per penalty) [[2026-wr-regional-packet#e6]], [[dbaseqp-quotient-9000379b7d#e6]].
- Equal weight per service and about 6,132 points per service at the 2026 regional [[2026-mw-regional-scorecard-t7-services#e2]] through [[2026-mw-regional-scorecard-t7-services#e8]], so the team needs to know which red service to fix first.
- Detection rules need a behavioural scorer exemption because Divisor re-draws source addresses and known-source rules would break [DR §3]. The exemption and the `scorer.accounts` rule list come from here.
- The scorer sends failed logins on purpose (`BadAttempts`) [Q §9.6, SH never-list 1]. NTLM logons by the scorer look like pass-the-hash to some public rules [DR §3].
- The portal lags the engine [[2026-mw-regional-packet#e17]], so any hand-entered Up/Down note is advisory.
- The fingerprint table (Appendix G) is data for scorer recognition; the lab runs real Quotient for ground truth.

Quotient facts the module relies on (`dbaseqp/Quotient@a845408`): `Timeout < Delay - Jitter` is enforced and the default Timeout is `Delay/2` (`engine/config/config.go:356`). The team API `GET /api/credlists` returns each credlist's name, path, usernames and format (`engine/credentials.go:158`, needs `EasyPCR`); the service-to-credlist mapping is admin-only. None of that is reachable from inside, so it is not an input. The module uses the measured round delay.

**2. Status and code.**

The pure-logic libraries are built with tests: `internal/scorer/clock.go` (round clock), `fingerprint.go` and `fptable.go` (recognition), `discovery.go` (services, items, proposals, accounts), `sla.go` (streaks). Not built or not wired:

- The controller does not feed any of it yet. Only `WebOps.SetScorer` (`internal/controller/webops.go`) accepts an `Estimator` and a tracker, and nothing creates the estimator or discovery from stored capture events. The transaction parser (`internal/parsers/txn`) already produces `scorer.Features`.
- SLA accrual `per_round` with a phase schedule: the tracker implements the `reset` form only (threshold consecutive failures per penalty, counter resets).
- The points-at-risk analyser, round-gap events, the hand-entered Up/Down note, credlist grouping, and the `sysadmin` change below.
- The portal read and the paste-the-list inputs of v3 are not built and are dropped (review D278-D280).

Moves that follow from the module contract:

1. `internal/scorer/pcr.go` and `csv.go` move to `creds` (the PCR transaction is a credentials concern). They read the window from `scorer.clock` events and no longer import `scorer`.
2. The `Scripted` PCR path and `Submit` are deleted; PCRs are entered by a human outside the environment (`creds`).
3. The `sysadmin` special case in `discovery.go` (`isScoredLocked` treats `sysadmin` as scored until marked otherwise) is removed. No admin accounts are scored (decision 10). If the scorer is ever seen logging in as `sysadmin`, the learner marks it scored by observation like any other account.
4. `Discovery.MarkScored` and `MarkNotScored` stay as operator overrides written to `overrides.yml`; their comment about `GET /api/credlists` is dropped.
5. `ExpectedVerifyRounds` stays and is used by `creds`' verification wait through the event's `rounds_expected` field.

Files: `internal/scorer/*.go`, `internal/controller/checks_hub.go` (SLA wiring moves here), `rules/scorer/fingerprints.json` (the table, JSON-loadable per event with `ParseTable`).

**3. Capability manifest.**

| Field | Value |
| --- | --- |
| Name | `scorer` |
| Sides | controller |
| OS | n/a |
| Privilege | `none` |
| Roles | `controller` |
| Default | core |
| Budget | 80 CPU ms/s, 64 MB held, 8 events/s, burst 40, 80 KB out/min (to the store), 30 MB disk |
| Tables | `scorer_round`, `scorer_service`, `scorer_item`, `scorer_account`, `scorer_note` |
| Content | `rules/scorer` (fingerprint table) |
| Actions | none |
| Pages | `/scorer` (round clock, services, learned accounts), strip and tiles on `/services` and the Overview |
| Evidence | part 1 |

The estimator and discovery are stream processors with in-memory state. They are rebuilt on start by replaying the last `replay_window` of stored capture events and the tables above, as the SLA tracker already rebuilds from its round log. The points-at-risk calculation is an analyser (pure, no state between runs).

**4. Configuration.**

Two places. Facts about the event live in `scorer.yml` and `overrides.yml` (entered or learned at runtime); tunables live in `modules/scorer.yml`.

```yaml
# scorer.yml (manifest, facts)
scorer:
  engine: quotient
  identifier: "{{ 20 + team }}"
  credlists: {}                         # names as Quotient shows them; learned groups get labels L1, L2 until renamed
  timing: { delay: unknown, jitter: unknown, timeout: unknown }   # estimated from capture; measured values go to overrides
  sla: { threshold: 5, accrual: reset, penalty: 5 }               # or accrual: per_round with phases
  # phases: [{ until: "2026-11-07T18:00Z", per_round: 35 }, { per_round: 20 }]

# modules/scorer.yml (tunables)
clock:
  default_delay: 60s        # used only until one interval is seen (confidence <= 0.35)
  default_jitter: 5s
  min_conns: 15             # new connections that make a burst
  core_window: 100ms        # the min_conns must fall within this (observed 25-55 ms)
  join_gap: 1s              # a connection this close to the previous one joins the burst
  min_bursts: 10            # bursts before the estimate stops being provisional
  safety_after: 2s          # quiet time kept after a burst's last connection
  safety_before: 3s         # margin before the earliest predicted next start
  enqueue_pad: 2s           # hazard before a burst's first connection
  plausible_dev: 0.35       # max |interval - m*Delay| / Delay for a plausible round
  max_bursts: 128
discovery:
  learn_rounds: 2           # distinct rounds that make a service learned (must happen within 3)
  stale_rounds: 5           # rounds without scorer traffic before "possibly stale"
  blocked_rounds: 2         # missed rounds, while other services are seen, before a block is suspected
  max_items: 4096
  max_samples: 3            # raw first-bytes samples kept per service (custom protocols)
classify:
  scorer_min: 0.8           # classifier score that labels a connection "scorer"
  likely_min: 0.5
fingerprints: rules/scorer/fingerprints.json
replay_window: 6h
risk:
  points_per_service: unknown   # prior is equal weight; the 2026 regional figure (about 6,132) is a starting estimate
  event_minutes: unknown
```

```go
// package scorer
type Config struct {
	Clock       ClockConfig       // as built: durations, MinConns, MinBursts, PlausibleDev, MaxBursts
	Discovery   DiscoveryConfig   // LearnRounds, StaleRounds, BlockedRounds, MaxItems, MaxSamples
	SLA         SLAConfig         // Threshold, Accrual ("reset" | "per_round"), Penalty, Phases []Phase, MaxRounds
	Classify    struct{ ScorerMin, LikelyMin float64 }
	Fingerprints string
	ReplayWindow time.Duration
	Risk        struct{ PointsPerService float64; EventMinutes int }
}
```

**5. Events.**

Consumes:

| Kind | From | Used for |
| --- | --- | --- |
| `capture.flow`, `capture.txn` | `capture` | connection starts for bursts; parsed exchanges for fingerprints, items and credentials |
| `auth_event` (common) | `audit`, `winevt`, `logs` | logins with source and account, for SSH and domain accounts the network cannot show |
| `checks.result` | `checks` | faithful results advance the probe-fed SLA streak |
| `devices.deny` | `devices` | Palo deny entries attached to a blocked-service alert |
| `traceback.change` | `traceback` | cause of lost uptime in the risk view |
| `scorer.note` | the UI | hand-entered Up/Down verdicts |

The exact capture and devices kind names are confirmed against those sections (part 12).

Emits:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `scorer.round` | 1 | normal | `round`, `start`, `end`, `conns`, `services[]`, `accounts[]`, `sources[]` (address, score), `dropped` (a round gap: the whole team's burst is missing), `provisional` |
| `scorer.clock` | 1 | normal | `delay`, `jitter`, `timeout_est`, `confidence`, `provisional`, `bursts`, `last_burst_end`, `next_earliest`, `next_latest`, `window_start`, `window_end`, `min_window`, `eviction_cutoff` (empty until the delay is measured) |
| `scorer.service` | 1 | normal | `host`, `port`, `proto`, `type_guess`, `fingerprints[]`, `rounds`, `learned`, `custom` (no native check) |
| `scorer.item_set` | 1 | bulk | `service`, `items` (count), `coverage` (Good-Turing), `size_estimate` (Chao1), `rounds_to_all` (k*H_k), `users[]` (names only, never passwords) |
| `scorer.account` | 1 | normal | `user`, `service`, `host`, `proto`, `how` (capture, auth_event), `ok`, `fail`, `first_seen`, `last_seen`, `group` (inferred credlist label) |
| `scorer.proposal` | 1 | normal | `kind` (`new`, `update`, `stale`), `service`, `sample`, `prefilled` check, `rounds_silent` |
| `scorer.blocked` | 1 | high | `service`, `rounds_missed`, `window`, `deny_refs[]` (an upstream block: other services were seen, this one was not) |
| `scorer.silent` | 1 | normal | `since`; the scorer stopped checking everything (not "healthy") |
| `scorer.sla` | 1 | high | `service`, `level` (`warn` at threshold-2, `critical` at threshold-1, `penalty`), `streak`, `penalties`, `source` (`probe`, `capture`, `note`) |
| `scorer.risk` | 1 | normal | `services[]` ranked by points at risk: `service`, `weight`, `lost_points`, `points_per_minute_down`, `down_since`, `cause` (`ours`, `red`, `platform`, `unknown`) |

`scorer.round.sources` is the interface traffic labels use: a flow is `scorer` when it falls inside a burst of a `scorer.round` and its source is listed there. Addresses are never a label on their own.

**6. Behaviour.**

*The scorer model beyond the core table.* Credentials are copied into tasks at enqueue time, so a PCR landing during the enqueue pass can give a mixed snapshot; changes go in the quiet part of the interval, after a burst [Q §5]. A round is all-or-nothing: a missing task result at the deadline discards the round, and SLA streaks neither advance nor reset [Q §3]. MSSQL login and query, Splunk query and 8089, and RDP with authentication have no native Quotient type; MW runs custom scripts or a fork, so those are fingerprinted by burst, port and account until seen [Q §2.2]. Config hot-reloads with a 1 s debounce, so discovery runs the whole event and silence means "the scorer stopped checking", not "healthy" [Q §9.9]. Passive toward the scorer: we observe what it sends to our hosts. We never connect to, scan or probe its addresses and never break a scored service on purpose to see what it does.

*Round clock.* On the controller, over flows and transactions from all hosts:

1. A **burst** is at least `min_conns` (15) new scorer-attributed connections to the team's hosts inside `core_window` (100 ms; the observed span is 25-55 ms), joined while gaps are at most `join_gap` (1 s; retries were seen about 1 s later).
2. Delay and Jitter come from single-round intervals. A lattice fit rejects spurious bursts and recognises dropped rounds (interval = m x Delay), a MAD test rejects residual outliers, Delay = the mean, and Jitter = max(sqrt(3) x std, half the range) because the scorer draws uniformly. After `min_bursts` (10) the estimate is no longer provisional. Before that the estimator publishes the upstream defaults at low confidence when it has seen no interval, and once any interval is seen it uses what was observed, at confidence 0.35 or less (lab rounds ran 20 +- 5; a 60 s guess would put the window end past the next burst). That is the code's choice and it differs from v3, which said "publish the defaults before 10 bursts"; the code is followed.
3. The **quiet window** is `[last burst end + safety_after, earliest next start - safety_before]`. `Hazard(t)` marks burst and enqueue-pass times (`enqueue_pad` before a burst's first connection).
4. A missing burst for the whole team is a **round gap**: `scorer.round.dropped`, not an outage [Q §9.12]. A discarded round is unobservable from capture, so the SLA tracker receives it through `Discard(round)` from a round gap or the operator.
5. Everything time-sensitive uses the window: PCR transactions (`creds`), active-check scheduling (`checks`: our probes never sit inside a burst), `threshold - 2` SLA alerts, and the Kali's scans and probes. The eviction cutoff is the **measured round delay**: `scorer.clock.eviction_cutoff`. A session older than it is not a scorer check in flight. It stays empty until the estimate is non-provisional, and scored-account eviction is flag-only while it is empty (execution engine, session eviction).

*Recognising scorer traffic.* The classifier scores one exchange against the fingerprint table (Appendix G) and the generic hints. Score = the noisy-or of matched positive rules and hints, multiplied by `(1 - w)` for each contradiction. Generic hints: burst membership, one-shot per service per round, and a learned credential. The source address counts only on top of behaviour (3%). The HTTP User-Agent is not a rule (it is random). Protocols without a native Quotient check (MSSQL, Splunk, RDP-with-auth) are capped at 0.7 and labelled by burst, port and account. Verdicts: `scorer` at 0.8 or more, `likely_scorer` at 0.5, `not_scorer` when a contradiction dominates and the score is under 0.3, else `unknown`. The table is data (`rules/scorer/fingerprints.json`, versioned) and the hashes are re-learned each event because library versions change [Q §6]. Quotient does not publish its custom scripts, so the first bytes of each exchange are kept (up to `max_samples`) and a check can be rebuilt from them.

*Check discovery.* Requests are grouped per service into observed checks with the variable parts templated. A service is **learned** after `learn_rounds` (2) distinct rounds, which must happen within 3. The item set stays partial with a coverage estimate (Good-Turing coverage, Chao1 size, and `k x H_k` expected rounds to see all `k` equally likely items: about 4 for 3 items, 11 for 5, 29 for 10 [SP §A2]) and keeps growing for the whole event. Against the active list (`checks`), `Compare` yields proposals: **new** ("Scorer started checking X"), **update** (the request changed), **stale** (no scorer counterpart for `stale_rounds`, 5). Nothing is removed automatically. A **block** is suspected when a round reaches the other services and no scorer traffic reaches one for `blocked_rounds` (2); the alert carries the Palo deny logs of that window. A service seen before and now silent while others are seen is flagged; all silent is `scorer.silent`.

*Scorer-account learning (primary source of scored accounts).* A user name is learned from an exchange that the classifier labels `scorer`, from two inputs: parsers on the capture side (SMTP `AUTH PLAIN`, IMAP `LOGIN`, FTP `USER`, SMB NTLM user names, WinRM NTLM, TDS login7) and host `auth_event`s for what the network cannot show (the SSH user name is inside the encrypted channel; Security 4624/4625 on Windows). A host `auth_event` counts when its source and time match a scorer-labelled burst. Failed logins that carry a random-UUID password (`BadAttempts`) are not learned from: they are not real credentials. Each learned account is marked `scored`, written to `overrides.yml` (runtime facts) and published as `scorer.account`; marking only adds protection, so it is automatic. Removing a mark (`MarkNotScored`) is an operator action. Marked accounts are never locked, deleted, renamed, expired or rotated outside a PCR transaction (the lint, `creds`).

*Credlist grouping.* Quotient's credlist names and the service-to-credlist mapping are not visible from inside. The module infers groups from observation: services whose observed user sets are equal or overlap form one group, labelled `L1`, `L2` and so on; a user seen on services of two groups sits on both lists. The operator renames groups to Quotient's names, and merges or splits them, in the Settings page (written to `overrides.yml`). The first PCR is the check: the scorer's next passing login by that user on the service confirms the mapping. Credentials are keyed by (account, credlist) everywhere (`creds`).

*SLA.* The tracker counts consecutive failed scorer attempts per service as Quotient does: the penalty is global, the counter resets after each penalty, a pass resets it, and a discarded round neither advances nor resets it. State is recomputed by replaying a round log, so `Discard(round)` and an operator verdict correct history exactly. Alerts at `threshold - 2`, `threshold - 1` and at the penalty. The threshold starts at 5 and is replaced by the observed value when known. Inputs, in the order preferred: (1) capture-inferred outcomes (refused, reset, timeout, auth failure, wrong content, from the scorer's exchange and the service's reply); (2) our own faithful probes (`checks.result`), which today drive the streak in `checks_hub.go`; (3) a hand-entered Up/Down note typed by an operator (`scorer.note`: round or time, service, pass or fail), used as a verdict that `Verdict(round, svc, pass)` applies to history, and counted in `Calibration()` as agreement or disagreement with the inferred outcome. The note is advisory because the portal lags the engine. Unknown outcomes neither advance nor reset. **Accrual** is plain scorer configuration, not an event profile: `reset` (threshold failures cost the penalty and the counter resets; the default) or `per_round` with a phase schedule (every failed round costs points, rate changing at a time; the WR regional used 35 then 20). With `per_round` the first failed round alerts, since it already costs.

*Points at risk (review N7.5).* An analyser over `scorer.sla`, `checks.red` and `traceback.change`. The prior is equal weight per service. It computes, per service, the points lost so far, the points per minute while down and the cause of lost uptime: `ours` (an untagged change of ours or a failed plan node), `red` (an untagged change by red, or a chain), `platform` (a Phylax fault) or `unknown`. It emits `scorer.risk`, which tells the team which red service to fix first. Absolute points are shown only when `points_per_service` and `event_minutes` are known; otherwise relative weights.

**7. Actions and content.**

No actions. Content: `rules/scorer/fingerprints.json` (Appendix G as data, with the generic weights). The detection rules that exempt the scorer take `list: scorer.accounts` (rendered into agent config from the learned accounts) and the burst exemption from here; those rules belong to `detect`.

**8. UI.**

- `/scorer`: the round clock (Delay, Jitter, confidence, last burst, next window, dropped rounds), services learned with coverage, learned accounts and credlist groups (rename, merge, split, mark not scored), proposals and stale flags, the fingerprint verdicts of recent exchanges, and the Up/Down note form.
- A strip on `/services` and the Overview: round clock, SLA streak per service, points at risk ranking.
- Overview tile: round-clock confidence and SLA streaks at `warn` or worse.
- No host-grid column.

**9. Health.**

States: `ok`; `degraded` while the estimate is provisional (fewer than `min_bursts`) or no capture feed arrives for a host that should have one; `unavailable` when no capture events reach the controller. Gaps: "round clock provisional", "no fingerprint table loaded", "capture not feeding from <host>" (scorer traffic that reaches an uncaptured host is invisible), "scorer silent". Degraded means the window is advisory: `creds` refuses to start a scored change without a window of confidence at least 0.5 unless an operator overrides.

**10. Scoring safety.**

The module touches no scored state: it reads events. Its output gates other modules' risky actions, so wrong output is the risk. The mitigations: a provisional estimate keeps confidence at 0.35 or less so the PCR gate refuses; the eviction cutoff is empty until measured; a session or flow that cannot be classified is never treated as non-scorer; labels come from behaviour and burst membership, never from an address. Alert-only stage: in observe mode the module only learns and publishes; consumers act on nothing.

**11. Tests.**

- Unit (built): `clock_test.go` (bursts, lattice fit, dropped rounds, jitter estimate, window and hazard), `fingerprint_test.go`, `discovery_test.go` (learning, coverage, proposals, stale, blocked, accounts), `sla_test.go` (replay, discard, verdict, accrual).
- New: `per_round` accrual with phases; credlist grouping from fixture user sets; points-at-risk from a fixture store (identical output twice from the same store and `now`); replay rebuild equals the live state; `sysadmin` is not special-cased.
- Conformance: starts with no capture feed, stops cleanly, emits only declared kinds, respects its budget under a 10-service fixture, survives link loss and reconfiguration (the estimator is rebuilt by replay, no `Keep` needed beyond the overrides).
- Lab (v3 ids): T30 (round clock: 20 bursts with jitter, a discarded round, a team-wide missing burst: Delay and Jitter within 1 s, the dropped round is not an incident), T37 (`BadAttempts` and scorer fingerprints with the runner address changed each round: no brute-force or lockout alert, scorer-labelled by behaviour), T15 and T14 (shared with `checks`), T39 for SLA agreement. New: account learning accuracy against Quotient's real user lists (100% of the accounts the scorer used in the window); credlist grouping against a Quotient with two lists. Invitational measurements S1-S14 (`docs/impl/invitational-data.md`) are the first real data.

**12. Limits and open items.**

- `shortcut: SLA accrual is implemented for reset only; per_round with phases is specified here and not yet in sla.go, upgrade before an event that uses it.`
- `shortcut: fingerprints for MSSQL, Splunk, RDP-with-auth, TFTP and NTP are burst/port/account only (score capped at 0.7), upgrade when the first bytes of the real scripts are captured.`
- `shortcut: SSH user names reach discovery only through host auth_event (the channel is encrypted); a host without the logs module cannot contribute SSH accounts.`
- `shortcut: credlist groups are inferred from user-set overlap; two lists with identical user sets look like one, upgrade only if the first PCR shows a mismatch.`
- Open: `capture.flow` and `capture.txn` are the capture section's kinds; `devices.deny` entries are outbound denies, so a blocked inbound scored service is attached through `devices.traffic` instead. Use both when attaching Palo logs to a blocked-service alert.
- Open: the real Delay, Jitter, Timeout, SLA threshold, Divisor and the credlist count are measured at the Invitational (S1, S2, S9, S12, S14).
- Open: how the round-clock estimate reaches agents (see `checks`, Limits). `creds` and `vantage` need the same feed.
- Core change: a plan option that holds an approved plan until a `scorer.clock` window opens (see `creds`).
- Cross-section: the SLA tracker moves here from `checks_hub.go`; the Overview strip shows `scorer.sla` and `scorer.risk`.
