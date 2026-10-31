#### `chains`

**1. Purpose and evidence.**

D-2: attack chains built from network and other telemetry, kept lightweight. A chain is an ordered list of hops. It is not a graph engine: there is no graph database, no query language and no whole-system provenance graph. It is a table of hops, about a dozen linking rules and a timeline view. The aim is the IR rubric: half of the red-team lead's marks go to remediating the attack path (who or what placed the thing, how the account was compromised, proof the hole is closed) [TTP §0, PRO §3]. Every incident is shown as a chain with a remediation item per hop.

Evidence that it matters for points:

- Remediation of the attack path is half of the red-team lead's rubric [TTP §0, PRO §3]; IR reports need IPs, timelines, cracked passwords, impact and remediation [PKT Scoring 5].
- A multi-topic IR scores only its best item, and duplicates and stock OS behaviour score negative [[xixsaucexix-century-2026#e6]]. Each IR covers one narrative or one persistence mechanism. This is why campaigns are a view and not the unit of an IR (review D304).
- East-west movement on the flat LAN never crosses the Palo, so per-host agents stitched by Community ID are the only way to see it (core, Environment). Palo logs cover attackers who killed the agent.
- Target metric: 100% of expected hops for purple-team campaigns 01 and 03 (Success metrics).

**2. Status and code.**

Built, with one test file (`internal/chains/chains_test.go`) and the scenario harness shared with trace-back (`internal/traceback/tbtest`). It is the least-tested large package (2.9k lines), so the retrofit is mostly tests (review D15). Code: `internal/chains/{types,build,build2,attack,remediate,group,timeline,describe,persist}.go`, `internal/store/chains.go`. The controller builds a chain on demand from the alert page (`webops.go`: `SeedFromAlert`, `Builder.Build`, `Save`, `SyncCampaigns`); there is no event-driven seeding.

What differs from v3 and is followed or changed:

- Perimeter hops from Palo traffic logs (v3) are not in the code. Specified below, missing.
- `Group` merges chains into campaigns and `SyncCampaigns` persists them. Kept as a view (review D304): the campaign never decides an IR. The persisted `campaigns` row only keeps a stable id for the UI.
- `Chain.IRSection` returns the whole chain. The IR unit is a narrative or a persistence mechanism, so `chains` adds `Units()` (below) for the `report` module.
- The builder reads the store through `store.Store` and writes with `Save`. It becomes an analyser: the build step is a pure function of store queries; persistence is a separate step in the module's `Start`.

**3. Capability manifest.**

| Field | Value |
| --- | --- |
| Name | `chains` |
| Sides | controller (analyser) |
| OS | n/a |
| Privilege | `none` |
| Roles | `controller` |
| Default | core |
| Budget | 150 CPU ms/s during a run, 64 MB held, 2 events/s, 100 KB out/min, 20 MB disk |
| Tables | `chains`, `hops`, `remediation_items`, `campaigns` (moved from the core migrations) |
| Content | `rules/chains/links.yml` (lateral ports, noisy execs, ignored accounts, ATT&CK map) |
| Actions | none (remediation items link to existing actions through proposals) |
| Pages | `/chains`, `/chains/{id}` |
| Evidence | part 1 |

Analyser `chains.build`. Inputs: `detect.alert` (severity high or critical), `traceback.change` (untagged), `checks.red`, `decoys.hit`, `honeytokens.sighting`, `integrity.verdict`; runs on trigger and every 5 minutes to extend open chains.

**4. Configuration.**

```yaml
# modules/chains.yml
window: 2h                  # expansion bound either side of the seed
max_hops: 12
account_window: 120s        # "same account within N seconds"
stitch_skew: 10s            # clock skew allowed when matching a connection across hosts
gap_slack: 10m              # an agent gap this near a hop lowers its confidence (x0.6)
seed_severity: high         # lowest alert severity that seeds a chain
ignore_accounts: [root, system, local service, network service, anonymous logon, nobody, "-"]
noisy_execs: [ls, cat, pwd, clear, sleep, "true", "false", echo, date, tty, dircolors, locale]
lateral_ports: rules/chains/links.yml
```

```go
// package chains
type Config struct {
	Window, AccountWindow, StitchSkew, GapSlack time.Duration
	MaxHops                                    int
	SeedSeverity                               string
	IgnoreAccounts, NoisyExecs                 []string
	Offset func(agent string) time.Duration
	Hosts  map[string]string // address -> agent
	Label  func(addr string) string // replaced by traceback.source events
}
```

**5. Events.**

Consumes: `detect.alert`, `traceback.change`, `traceback.result`, `traceback.source` (labels), `checks.red`, `decoys.hit`, `honeytokens.sighting`, `integrity.verdict`, and for the hops: `auth_event`, `conn`, `process_start`, `file_change`, `capture.flow` (Community ID), `devices.traffic` (Palo), `telemetry_gap`, `creds.txn` and `inventory.row` (to verify remediation items).

Emits:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `chains.chain` | 1 | normal | `chain`, `seed` (kind, ref), `hops[]` (see below), `confidence`, `truncated`, `notes[]` |
| `chains.item` | 1 | normal | `chain`, `hop`, `kind` (`close_entry`, `remove_persistence`, `rotate_credential`, `block_source`, `remove_artifact`), `state` (`open`, `applied`, `verified`), `by`; state changes from operators and from verification |
| `chains.campaign` | 1 | bulk | `campaign`, `chains[]`, `keys` (source, account, hash, C2); the view's cache |

**6. Behaviour.**

*Hops.*

| Kind | Meaning | Built from |
| --- | --- | --- |
| `access` | A source reaches a host through a service and account | Authentication events with a source address: Security 4624 and 4625 (types 3 and 10), 4768, 4769, 4776; sshd auth lines; web logins from transaction logs; device logins |
| `exec` | A process runs on a host | Process lineage and trace-back |
| `change` | A file, config, account or persistence entry changes | `file_change`, account events, persistence detections |
| `move` | Host A reaches host B | SSH, SMB, WinRM, RDP, WMI, PsExec-style service creation, DCSync; found by cross-host stitching |
| `egress` | A host reaches outside | Denied egress, Palo traffic logs, allowed-but-unknown connections |

A hop row holds: chain id, order, kind, source host and address, destination host and address, account, process reference (host, pid, exe, cmdline, sha256), protocol, ports, Community ID, service, path (and whether it is a persistence mechanism), start and end, technique (ATT&CK v19), a readable "what", the **link method**, the **confidence**, notes, evidence references, the cause hop (`cause` = order of the hop it follows from, -1 for a root) and its remediation items.

*Building hops from data we already have.*

1. **Authentication with source.** Each successful login with a source address is an `access` candidate, coalesced per host, source and account within the account window. Failed logins before it are evidence, and 5 or more mean T1110.
2. An inbound connection merges into the login on the same host and source (a few seconds apart). Connections with no login become `access` hops only when something attaches to them.
3. **Cross-host stitching.** An inbound flow is matched to another host's outbound record by Community ID with each host's measured clock offset applied, else by swapped 5-tuple within `stitch_skew` (10 s): `move`, confidence 0.95. A login from a known host with an outbound connection to this host just before: 0.75. A source address of a known host and nothing else: 0.6. An outbound connection to a lateral port or managed host with no partner: `move` marked `unmatched`, 0.5. Other outbound destinations: `egress`. An unmatched side is kept at lower confidence. Where the Palo is in the path (the outside leg) the tuple is translated, so the match goes through the Palo's session log and its NAT fields.
4. **Within a host,** a process, file change or Security event attaches to the session whose socket it or an ancestor owned (0.95 and 0.9; 0.85 and 0.8 without start ticks), else to the login of the same account within the account window (120 s, refreshed by activity), 0.6.
5. A seed that no session explains is run through `traceback.trace` and grafted with its confidence.
6. **Perimeter.** Palo traffic logs cover anything crossing the perimeter, including attackers who killed the agent. Missing in the code; needs the `devices.traffic` event.

DCSync (Security 4662 with replication rights) is a `change` hop (T1003.006) because that event carries no source address to stitch on. Own (tagged) activity, `scorer` and `us` sources (from `traceback.source`) and changes found only by a sweep with no writer are excluded. Short utility execs (`noisy_execs`) are dropped unless something follows from them.

*Seeding, bounds and grouping.* A chain starts from any high-severity alert, untagged service change, red check, decoy hit, honeytoken use or ledger alert. Extension goes backward (how did this get here: the inbound hop and its source's earlier hops) and forward (what did this source or account do next), breadth-first from the seed over cause links and over a shared source address, account (not root, system or machine accounts) or binary hash, bounded by +-`window` (2 h) and `max_hops` (12, nearest to the seed first, seed always kept). A hop whose cause fell outside is marked, never silently re-parented. `Truncated` and a note say when the bound cut something.

*Confidence.* Every hop records how it was linked: an exact 5-tuple or Community ID, the same account within N seconds, lineage within a host, the source address alone, or a time-window guess. The hop carries the method and confidence of its weakest link. A recorded agent gap within `gap_slack` of a hop on its host multiplies the confidence by 0.6 and adds a note. The chain confidence is the minimum hop. Network-only hops (an agent dead or lying) are shown at lower confidence. The timeline marks time-window and unmatched hops as guesses and never presents a guess as fact.

*Campaigns: a view only (review D304).* `Group` merges chains that share an outside access source, an account, a binary SHA-256 or a C2 destination (union-find; internal pivot addresses are not keys). The campaign list is shown on `/chains` as a filter and a summary. It is never the unit of an IR, a remediation list or an incident. The v3 text "one IR per campaign is the pattern that worked for other teams" is withdrawn: a multi-topic IR scores only its best item [[xixsaucexix-century-2026#e6]].

*IR units.* `Units(chain)` returns the pieces `report` drafts as separate IRs: one **narrative unit** (the access path: entry, account compromise, movement and the exec it enabled, with its remediation items) and one **persistence unit** per `change` hop flagged `Persistence` (a cron entry, a unit, a task, a hidden account, a changed `authorized_keys`, a planted binary), each with its own hop, evidence and items. A persistence mechanism found on three hosts is three hops and one unit when it is the same mechanism (same method and artifact hash). The IR drafter takes one unit and produces one IR.

*Remediation items.* One item per hop, with a state (`open`, `applied`, `verified`) and a checkbox. The kinds, from the hop:

- access: close the entry (service, account, vulnerability), rotate the credential used (only when the account is not scored; a scored account becomes a `creds` proposal, never an automatic rotation), block the source (only if it is outside).
- move: close the path, rotate.
- change: remove persistence (path, created account, group membership, task) or remove the artifact.
- DCSync: rotate `krbtgt` (the `ad` module's action; two resets).
- egress: block the destination.
- exec: only when the binary is in a temp or user path.

A given action appears once, on its earliest hop. `Verify` marks items verified from later telemetry: a password reset of the account (`krbtgt` needs two), deletion of the path, removal from the group, deletion of the task, a binary matching the ledger, a clean re-hunt. `close_entry` and `block_source` cannot be proven from events and stay manual. Items link to existing actions through `Propose` (a block on the Palo, `unit.disable`, `file.quarantine`); nothing is applied automatically.

*Output.* A timeline view, not a graph canvas, one row per hop: time (Central, UTC alongside), host, what happened, ATT&CK technique, link method and confidence (`Level` maps confidence to high, medium, low). `Chain.IRSection(loc)` gives the IR drafter the attack-path and remediation text parts: rows, remediation lines with verified state, techniques, sources, accounts, hosts, caveats and `ProofClosed`.

*What it does not do.* No syscall-level provenance, no general graph traversal, no ad-hoc queries and no machine-learned linking. Rules of bounded size, tested against the purple-team campaigns.

**7. Actions and content.**

No actions. Content: `rules/chains/links.yml` (lateral ports, ATT&CK technique per hop kind and trigger, persistence classes). Technique mapping follows [TTP] and [EMU].

**8. UI.**

- `/chains`: open chains with confidence, campaign filter, seeds.
- `/chains/{id}`: the timeline, one row per hop, with a checkbox per remediation item and its state, the broken or low-confidence links marked, and buttons that turn an item into a proposal.
- Incident page (shell): the chain timeline and the remediation checklist are shown there.
- Overview tile: open chains and unverified remediation items.
- No host-grid column.

**9. Health.**

States: `ok`; `degraded` when inputs are missing for hops (no capture from a host, no Palo log feed, agent gaps near a seed) or a run hit its CPU budget; `unavailable` when the store cannot be queried. Gaps: "no Palo traffic-log feed (perimeter hops missing)", "no Community ID from <host>". Degraded means chains may miss hops and say so in their notes.

**10. Scoring safety.**

Read-only analysis. It never touches scored state. A remediation item that would touch scored state (rotate a scored credential, block a source on a scored port) is a `Propose` the operator confirms, and the lint governs the resulting plan (no narrowing of a scored port to a source allowlist; a CIDR block carries a warning). Chains exclude `scorer` and `us` sources from joining, so the scorer is never presented as an attacker. Alert-only stage: alert-only by nature.

**11. Tests.**

- Unit (existing): `chains_test.go` over the synthetic streams from `tbtest`. Required rewrite as fixture tests (review D15): one fixture store per linking rule (login with source; merge of connection into login; Community ID stitch; swapped 5-tuple stitch with skew; known-host login; unmatched lateral port; within-host session join; same-account join; seed graft through trace-back; DCSync as change); bounds (window, `max_hops`, `Truncated`); confidence (agent gap x0.6, minimum over the chain); exclusions (tagged, scorer and us sources, sweep-only); `Group` keys; `Units` (narrative plus persistence); remediation (one action once, verification); persistence round trip; identical output twice for the same store and `now`.
- Conformance: analyser rule (identical output, switchable alone, within budget on a 10k-event fixture).
- Lab (v3 ids): T33 (attack chains for campaigns 01 and 03: 100% of expected hops present, each with a link method and confidence; a two-hop SSH chain stitched by 5-tuple; one campaign per attacker; remediation checklist items verify). The purple-team campaigns come from the lab repo.

**12. Limits and open items.**

- `shortcut: cross-host stitching assumes measured clock offsets and a 10 s skew; a host with a bad clock produces unmatched hops, tighten only if the lab shows false matches.`
- `shortcut: campaigns are merged by exact shared keys; no similarity matching, add only if the lab shows one attacker split into several campaigns.`
- `shortcut: the persistence-mechanism identity for Units is method plus artifact hash; two different cron entries with different payloads are two units, which is intended, but a payload re-encoded per host is also two.`
- Open: the Palo `devices.traffic` event (inbound entries with NAT-translated source, pulled during the first minutes after enrolment and on demand) and `devices.deny` come from the `devices` section; perimeter hops use them and wait for the code.
- Open: chain extension is run on trigger and every 5 minutes; whether the periodic run is needed or trigger-only is enough is a lab question.
- Core change: none. The persistence step in `Start` writes the module's own tables from its own events.
- Cross-section: `report` drafts IRs per `Units`; `creds` receives `rotate_credential` proposals for scored accounts; `traceback` provides labels and trace-back results; `ad` owns the `krbtgt` action.
