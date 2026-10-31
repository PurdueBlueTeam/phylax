# Phylax — Design Doc

Version 4, Oct 31, 2026 · @David. Supersedes v3 (Oct 22, 2026; `git show v3:phylax_design.md`). Status: phase 1. The core sections are written; the module sections are placeholders that follow the module template and are written next, from the brief in `docs/impl/modules.md`.

## Summary

Phylax is the Purdue Blue Team's defence platform for CCDC. It is one Go binary that runs as `phylax serve` on a controller host inside the competition LAN and as `phylax agent` on every other host. Agents open outbound TLS connections to the controller and never listen for management. The controller holds the manifest (the declared description of the environment), the event store, the plan engine, the analysers, the device adapters and a web UI bound to localhost on the controller's console. Every change to a host goes through a plan: a DAG of typed, Go-native actions that the team can see, dry-run, lint for scoring safety, approve and watch run, with a dead-man rollback on the agent for anything that could cut the link.

Version 4 keeps the v3 architecture and reorganises the design around a **module contract**. A small core (link, spool, execution engine, event store, manifest, UI shell) carries everything else. Every capability above the core is a module: one package with one config block, declared typed events in and out, a capability manifest (OS, privileges, roles, resource budget), a health report and its own tests. Modules never import each other. They talk only through typed events on the bus, and the controller's analysers are pure functions over event-store queries. Rules, plans and checks are content (YAML) wherever content can do the job. A new module is off unless the manifest enables it, and every module passes a shared conformance suite in CI.

What Phylax does, by module group (the catalogue near the end lists every module and its status):

1. **Telemetry.** Kernel audit over netlink and `sock_diag` on Linux, Sysmon and the event logs through `EvtSubscribe` on Windows, file watches with a hash sweep as the source of truth, application and auth logs, and differential inventory snapshots. Every loss of telemetry is reported as a gap.
2. **Detection and response.** Rules run on the host and keep working with the link down. Responses come in three tiers by reversibility: tier 0 automatic and reversible on unscored state, tier 1 one-click, tier 2 manual with a checklist. An opt-in content guard restores declared scored content from golden copies under strict limits.
3. **Integrity and hunting.** An integrity ledger of every binary that matters, alert only (D-1), with YARA over files and memory; a prebake hunt against reference baselines; hardening plan packs; Active Directory checks and GPO response.
4. **Network.** Host firewalls rendered from the manifest with shadow mode and default-deny egress, per-executable egress alerts, packet capture with protocol parsers, and adapters for the Palo Alto and VyOS devices.
5. **Scoring and credentials.** Quotient-faithful active checks from the LAN and from the Kali outside the Palo, a model of Quotient's round clock and check set learned from passive capture, scorer-account learning from observed logins, SLA streaks, and selective scored-password changes as a host change plus a typed PCR list that a human enters in Quotient.
6. **Analysis.** Trace-back from a change to its cause, lightweight attack chains across hosts, service dependency discovery and a version-driven vulnerability matcher.
7. **Deception.** LAN-only decoys in an unprivileged process and per-host honeytokens, including honey AD accounts.
8. **Reports and generators.** IR drafts per attack narrative or persistence mechanism, and generators for the recurring inject artifacts (inventories, port tables, diagrams, firewall exports, evidence captures). No prewritten inject responses.
9. **Operations.** Service backups and restores, a team change feed (`phylax say`, `phylax claim`) and local alerting.
10. **Integrations and depot.** An offline-first, content-addressed cache and trusted tool depot, and optional Wazuh, Splunk forwarding and Suricata/Zeek.

The 2027 environment is the reference: one flat LAN (`172.20.240.0/24`) behind one Palo Alto, a VyOS router above it, and a Kali VM on a VyOS side leg outside the Palo. Quotient scores the services. Relays remain for other shapes. Quotient, the inject portal and the scoreboard are not reachable from inside the environment, there is no clipboard between the consoles and the outside, there are no VM snapshots and reboots are costly. About a week of environment access before the qualifier comes after the repository freeze, so anything event-specific must be learnable or enterable at runtime.

How this document is organised: goals and constraints; the environment and scorer model; design principles; the module contract; the core components, each fully specified; the module catalogue with one section per module from a fixed template; then operations, testing, the complexity register, risks, known bugs and appendices. The "Removed in v4" appendix lists every capability v3 had that v4 drops, one line each with the reason.

### Conventions

- **Owner decisions.** `D-1` to `D-9` are the owner's decisions of 2026-10-22 (`ccdc-private/strategy/phylax-proposals.md` §0). They stand, with D-6 replaced (see the table below). The re-review of 2026-10-31 (`docs/impl/review.md`) added the decisions in the second table; its "Answers from David" sections are applied throughout.
- **Review rows.** `review D172` or `review N7.3` is a row of `docs/impl/review.md`; its `L<n>` evidence points at the v3 design. Review rows are cited with the word "review" because the bare form collides with rule ids.
- **Rule ids.** `D1`, `D5d`, `D18`, `V2` are detection rules (the catalogue in the `detect` module). Dependency rules move to `DEP1` to `DEP3` (Known bugs). Rule ids are one namespace, checked by a registry test in CI.
- **Vault evidence.** `[[card-id#eN]]` cites evidence item N of a card in the team knowledge base (`ccdc-private/knowledge-base`).
- **Source tags.** v3's research citations stay as `[tag §n]`, all under `ccdc-private/`:

| Tag | File |
| --- | --- |
| `Q` | `research/topics/quotient.md` |
| `SP` | `research/topics/scoring-platforms.md` |
| `OA` | `research/topics/oss-agents.md` |
| `DA` | `research/topics/device-apis.md` |
| `SH` | `research/topics/scoring-safe-hardening.md` |
| `TTP` | `research/topics/red-team-ttps.md` |
| `DR` | `research/topics/detection-rules.md` |
| `WT` | `research/topics/winners-tooling.md` |
| `SV` | `research/topics/software-vulns.md` |
| `EMU` | `research/topics/red-team-emulation.md` |
| `COV` | `strategy/phylax-detection-coverage.md` |
| `PR` | `strategy/phylax-proposed-rules.md` (rules P01–P81, all untested) |
| `CR` | `strategy/phylax-code-review.md` (findings on the discarded pre-v3 code; they are requirements) |
| `PRO` | `strategy/phylax-proposals.md` |
| `PKT` | `team-packets/2027-preview.md` |
| `LAB` | `strategy/lab-ccdc27.md` |
| `RT` | `lab/red-team/README.md` and `lab/red-team/campaigns/` |
| `IJ` | `injects/by-code/` |

- **Peer and upstream code** is cited as `owner/repo path@commit` (for example `dbaseqp/Quotient engine/credentials.go:158@a845408`).
- **Implementation notes** for each area live in `docs/*.md` (`docs/agent.md`, `docs/protocol.md`, `docs/controller.md`, `docs/ui.md`, `docs/manifest.md`, `docs/capture.md`, `docs/rules.md` and others). Where an implementation note and this design disagree, this design wins and the note gets fixed in the same commit, or the design changes with the reason (repo `AGENTS.md`).
- **Times** are stored in UTC and displayed in America/Chicago, the time zone injects use.
- **Status words** in the catalogue: built (code and unit tests; nothing is lab-proven yet), partial, missing.
- **Shortcuts.** A known limit in code carries a `shortcut: <limit>, <when to upgrade>` comment. A known limit in this design is written under the module's "Limits and open items".

**Owner decisions (2026-10-22), as they stand in v4:**

| Id | Decision | v4 status |
| --- | --- | --- |
| D-1 | Binary integrity ledger, alert only | Stands. The ledger never restores anything by itself; restore is one click [PRO §2, COV §6] |
| D-2 | Lightweight attack chains | Stands. Rows and linking rules, no graph engine [TTP §0, PRO §3] |
| D-3 | The Kali as an external vantage point | Stands. It sits outside the Palo, on the scorer's side of the NAT [PKT §2, PRO §4] |
| D-4 | Controller on the LAN | Stands, as configuration: controller placement is just a manifest setting. There are no event profiles |
| D-5 | Offline-first caches | Stands. The internet is available but slow and never a dependency [PKT §4.3] |
| D-6 | Full rewrite, no triage by milestone | Replaced: the scope is whatever survives the 2026-10-31 review, and accepted items are not cut for time |
| D-7 | Check discovery, active checks, traffic labels and rotation rebuilt around Quotient | Stands. Scored accounts are learned from observed logins because Quotient is unreachable from inside the environment (review D7, D251) |
| D-8 | Obscurity is allowed | Stands. Randomised names and paths; nothing depends on them staying secret [OA §5.6, WT §9.8] |
| D-9 | OSS may run alongside | Stands. Wazuh, Splunk forwarding and Suricata/Zeek are opt-in modules |

**Review decisions (2026-10-31):**

| # | Decision |
| --- | --- |
| 1 | Every capability is a module under the module contract. Small core: link, spool, execution, event store, manifest, UI shell. Content before code. New capabilities are off unless the manifest enables them. |
| 2 | Cut code is deleted; git history is the archive. |
| 3 | Competition rules are out of scope for this design (packet rules, repository rules, tooling limits, "ask officials" items). Scoring mechanics stay valid evidence: how Quotient checks services, how points accrue, organizer scans scoring extraneous services, Orange Team as a scored component. |
| 4 | No event profiles. Controller placement is configuration. |
| 5 | Never mass-rotate credentials. Learn which accounts the scorer uses. |
| 6 | No prewritten inject responses in Phylax; only generators for recurring artifacts. Prewritten material lives outside Phylax. |
| 7 | The design follows the code where the code chose reasonably: kernel audit over netlink plus `sock_diag` (no proc connector); pure-Go PDF (`go-pdf/fpdf`, no Typst). |
| 8 | D-1 to D-9 stand, with D-6 replaced as above. |
| 9 | No time goals. Latencies are measured and reported, not targeted. |
| 10 | Quotient facts from the MWCCDC Discord (2026-10-22): no admin accounts are scored; several credential lists, possibly per service; PCRs take effect immediately; Quotient does not know about reverts; team-pack admin passwords leak within seconds, so admin and service credential rotation is a T+0 console action ahead of enrollment. |
| 11 | No AI or MCP assistant module and no operator-AI rulebook (MWCCDC does not use AI). |
| 12 | The MWCCDC Defender Toolkit is not run by us; no coexistence work. |
| 13 | Never restrict source addresses on scored service ports. Quotient uses many source IPs. It is an explicit scoring-safety lint rule. Blocking known red-team addresses on a scored port is allowed; narrowing a scored port to a source allowlist is not. |
| 14 | Peer-platform review accepted: the convergence board (host x step grid), rootkit cross-checks as hunt content, a hash of our own audit rules in the heartbeat. |

## Goals

1. **Harden every host without failing a scored check.** Rotate admin and service credentials, enforce host firewalls and run the hardening packs on every host, losing no action to a dropped connection and causing no failed scorer round.
2. **Run on Linux and Windows alike** from first contact, with every sensor's state and every gap visible on one Platform page.
3. **Change scored passwords selectively and safely.** Only on evidence of compromise or leak, as a host change inside a scorer quiet window plus a short typed PCR list, verified by a login afterwards, with at most one failed scorer round per affected user.
4. **Know what the scorer checks.** Learn the scorer's service set and item set from passive capture, learn which accounts it uses from observed logins, propose a new check when the scorer starts one, and flag checks it has stopped using. Operators can add, edit or remove active checks at any time.
5. **Label every connection** to a scored service as scorer, us or other, by behaviour and never by address, and flag attack-like traffic within "other".
6. **Detect any change** to a service's content, configuration or behaviour, and build the trace-back to its cause automatically.
7. **Detect a modified or replaced binary** at first execution, for pinned service binaries continuously, and at rest by sweep. Alert only; restoring is one click (D-1).
8. **Show every incident as an attack chain** with a remediation item per hop.
9. **Know whether a service is up for the scorer** from outside the Palo with checks that reproduce Quotient's transport, and know when the perimeter or the egress policy drifts.
10. **Catch C2** through denied egress and per-executable egress alerts, attributed to a process and a binary hash.
11. **Turn red-team looting into precise alerts** (decoys, honeytokens) that say which host was looted and roughly when.
12. **Draft incident reports and recurring inject artifacts** from data Phylax already holds, rendered for an on-screen view first and a file second.
13. **Work from the cache alone.** No decision in the event depends on a live internet fetch.
14. **Adapt to a new environment by editing the manifest or entering facts at runtime,** never by changing code. After the repository freeze nothing in the repo can change.
15. **Keep the platform small and checkable.** Every capability is a module that passes the conformance suite; a module without evidence that it matters is a cut candidate at the next review.

## Non-goals

- **No AI or MCP assistant,** and no operator-AI rulebook (review decision 11).
- **No prewritten inject responses.** Phylax ships generators only (decision 6).
- **No inject or scoreboard tracking.** Phylax cannot reach the inject portal, the scoreboard or anything behind Authentik from inside the environment. Inject boards, scoreboard screenshots and submission records live outside Phylax ("Phylax is not a Jira board of inject-related things").
- **No event profiles** (invitational, regional, nationals). Differences between events are manifest and scorer configuration (decision 4).
- **No reasoning about competition rules** in this design (decision 3). David handles rules with the organizers.
- **No mass credential rotation** (decision 5). Admin and service accounts rotate at T+0; scored users rotate only on evidence.
- **No multi-viewer UI.** One controller screen; no SSH tunnel or remote UI access (review A11.Q1).
- **A full EDR.** No kernel drivers and no eBPF sensor (review D92).
- **Any contact with scorer or red-team infrastructure.** We observe only what reaches our hosts and what we send from our own vantage points to our own addresses.
- **Anything inline in the scoring path.**
- **Tamper-proofing on hosts the red team owns.** Obscurity and fast recovery are used instead.
- **A general graph or provenance engine.** Attack chains are rows and a few linking rules (D-2).
- **Dynamic topology:** relay election, backup relays, auto-discovery of the controller.
- **An agent self-update system.** One narrow action replaces the binary.
- **Submitting PCRs or anything else to Quotient.** PCRs are entered by a human on a machine outside the environment.

## Anti-goals

Things the design actively prevents, because each one has cost points or would:

- **Narrowing a scored port to a set of sources.** Quotient uses many source IPs; any rule touching scored inbound is allow-any-source (decision 13).
- **An automatic action on scored state** (scored accounts, scored service configuration, scored content) without a human, except the opt-in content guard's restore of declared files under its constraints.
- **A silent automatic action beyond tier 0.** Anything stronger is offered as a one-click suggestion ("block this?").
- **A second module depending on a sibling's internals.** Modules talk through typed events only; a sibling import fails CI.
- **A query language or expression language on hosts.** No SQL, VQL or embedded scripting in rules or probes; typed probes and declarative rules only. A scoring-safety lint cannot reason about arbitrary expressions, and a host query interpreter is an exfiltration path for a stolen controller key.
- **A new listener, daemon or host-binary dependency on the scored path** without a complexity-register line.
- **Event-specific facts that need a commit.** Anything learned at the event (scorer accounts, credlist names, round delay, team number, new services) is learnable or enterable at runtime and written to overrides.
- **The integrity ledger acting by itself** (D-1).
- **Prewritten inject text dressed as a generator.** A generator renders facts Phylax holds; it never ships answer prose.

## Success metrics

No time goals (decision 9). Latencies are measured and reported in lab runs so regressions show; they are not targets.

| Metric | Target | Measured by |
| --- | --- | --- |
| Hardening-induced failed scorer rounds | 0, other than at most one per user whose scored password is changed | Real Quotient in the lab |
| Actions lost to disconnects | 0 | Agent dead-man journals and step results |
| Modules passing the conformance suite | 100% of enabled modules | CI |
| Scored-password changes confirmed by a passing scorer login and our own verify | 100% | Lab, Quotient admin API |
| Reverted credentials detected and re-synced after a host or AD revert | 100% | Lab revert scenario |
| Scorer services discovered | 100% | Quotient in the lab |
| Scorer accounts learned from observed logins | 100% of accounts the scorer used in the window | Quotient in the lab |
| False checks invented from noise | 0 over a two-hour run | Orange-flow traffic in the lab |
| Kali-run faithful check agrees with the scorer's own result | 98% of rounds or more, after calibration | Quotient admin API vs Phylax |
| Planted prebaked implants found by the first hunt | 90% or more | Contaminated golden images |
| Attack chain completeness | 100% of expected hops for purple-team campaigns 01 and 03 | Purple-team runs |
| Trace-back reaches the source IP for webshell-driven changes | 90% or more | Lab red-team campaigns |
| Denied callbacks attributed to a process | 100% | Lab implants |
| False-positive alerts from scorer and orange traffic only | 5 per hour or fewer | Dry run with all simulators |
| Untagged alerts during our own hardening | 0 | Purple-team false-positive run |
| Cache-only operation | All plans, checks and ledger lookups work with no internet | Offline drill |
| Measured and reported (no target) | First contact to heartbeat; change detected to alert; binary replaced to alert; alert to IR draft | Lab runs, reported per release |

## Environment and scorer model

The 2027 environment (the 2026 Midwest Invitational packet; its labels say "2027 State") is the reference case. Infrastructure changes every year, so nothing in the core depends on specific hosts. Packet citations use the Invitational numbering [PKT §n]. Competition rules are not reasoned about here (decision 3); the facts below are what the environment and the scorer do.

### The environment

| Fact | Source | What it means for the design |
| --- | --- | --- |
| One flat LAN `172.20.240.0/24` behind one Palo Alto; VyOS above it; the Kali on a VyOS side leg `172.17.0.0/24` outside the Palo. Palo management is on the LAN (`172.20.240.200`); VyOS is reached through the Palo. | [PKT §2, §6] | East-west traffic never crosses the Palo, so per-host telemetry and cross-host stitching carry the weight. No in-LAN host needs a relay. |
| Scored services: HTTP and HTTPS content, SMTP, POP3/IMAP and webmail (Roundcube), FTP, DNS, SSH on the Linux hosts, ping, Splunk query and management on 8089, SMB share with planted SOP files, RDP with authentication, MSSQL 1433 login and query, WinRM PowerShell on the AD host. TFTP and NTP were scored at the 2026 regional and may return. | [PKT §3], [[2027-mw-invitational-packet#e22]], [[2026-mw-regional-packet#e19]], MW Discord 2026-10-26 | Parsers, checks and the scorer model cover all of these. The reference `services.yml` declares DNS and an FTP placeholder (Known bugs). |
| Each scored service carries equal weight; uptime points dominate (SLA was 13% of our 2026 regional losses). | [[2026-mw-regional-scorecard-t7-services#e2]] | A service we cannot check is a blind spot worth one service's share of uptime. |
| Orange Team (customer service) is a scored component at regionals, with the highest average (27.5/100) in 2026; the White Team uses Orange results. | [[2026-mw-regional-scorecard-t7#e4]], [[2026-mw-regional-packet#e11]] | Multi-step flow checks on scored services (the `checks` module). |
| The organizer's perimeter assessment scores extraneous or missing services on public addresses. | [[2026-mw-regional-scorecard-t7#e3]] | No public decoys; the Kali path listener is filtered to the Kali source; perimeter scans diff against the scored set. |
| Traffic generators send traffic, some malicious, from random source IPs. | [PKT Systems 5] | Detections and decoy severities are tuned against that noise. |
| Business tasks add or change services; hand changes during injects are certain. | [PKT Business tasks] | Drift detection with adopt-or-revert keeps the manifest true. |
| No per-VM scrub and no VM snapshots. A new lab reservation is the only reset; recovery services cost points and vulnerabilities reappear. Reboots are costly. | [PKT Systems 10], [[2027-mw-invitational-packet#e30]], [[2027-mw-invitational-packet#e39]] | Every destructive action needs its own revert path. Reboot-class changes get a reboot-survival preflight. In-place golden restore is preferred to a new reservation. Re-enrollment handles "all hosts are new". |
| Containerizing a service on the same platform is allowed; the 2026 regional ecom was OpenCart 4.1.0.4 in Docker. | [[2027-mw-invitational-packet#e29]], [[bcom12t]] | `services.yml` has `runtime: host, docker or podman` (2027 stack unverified). |
| Data loss during a migration is a per-user point penalty. | [[2027-mw-invitational-packet#e35]] | Restores compare record counts before and after. |
| ICMP is scored and must be maintained. | [PKT Play 12] | ICMP echo is never blocked; the lint enforces it. |
| Internal addressing and hostnames do not change. | [PKT Systems 6–7] | Nothing renumbers anything. |
| IR reports need IPs, timelines, cracked passwords, impact and remediation; half the red-team lead's rubric is attack-path remediation. A multi-topic IR scores only its best item; duplicates and stock OS behaviour score negative. | [PKT Scoring 5], [TTP §0], [[xixsaucexix-century-2026#e6]] | One IR draft per attack narrative or persistence mechanism. |
| Inject responses are PDFs or uploaded files; times are US Central. | [PKT NISE], TOOL26T | Generators render to screen first, then PDF or files. |
| Default credentials at drop flag: every host `sysadmin:Changeme1!`, Palo `admin:Changeme123`, VyOS `vyos:vyos`. The red team knows them. | [PKT §2] | T+0 console rotation ahead of enrollment. |
| Organizers seed AD with "temp admins" and comments on users. | MW Discord 2026-10-26 | Privileged-account allowlist in AD checks; credential hunts read AD descriptions. |
| Operating systems: Rocky 9 (SELinux enforcing, firewalld), Ubuntu 22.04, Debian 12, Server 2019 and 2022, Windows 11; kernels 5.14 (heavy backports), 5.15, 6.1. Supported more widely: Windows 10 or Server 2016 and newer, Linux 3.2 and newer. | [PKT §6, OA §6] | CI builds and tests both OSes; SELinux-aware file actions. |

### Access facts

- **Quotient is not reachable from inside the environment,** and there is no good way to move the scored-user list inside. Scored accounts are learned from observed logins. Service status comes from our own checks, with an optional hand-entered Up/Down note (review D251, D278-D280, area 7 revision).
- **The inject portal, the scoreboard and anything behind Authentik are not reachable from inside.** The team Nextcloud is expected to be writable from inside and is the path for files leaving the environment (manual upload; verify at the Invitational).
- **No clipboard** between the consoles and the machine where Quotient is used (review A7.Q5). Anything a human carries out is short and typeable.
- **Console access through NETLAB** is always available as break-glass and is the only way in before credentials are known. Whether several people can view one console at once is unknown.
- **The internet** is available from every host and slow. It is a bonus, never a dependency (D-5).
- **The pre-qualifier access week.** About a week of access to the CCDC environment comes before the qualifier but after the repository deadline, so no code or other repository content can change then. Everything event-specific must be learnable or enterable at runtime.
- **The team packet arrives well before the event,** so the manifest is written from the packet and committed as usual (review Invitational D1).
- **The Invitational (2026-11-07, four hours)** is a data-collection and battle-test event; see Operations.

### Assumptions about the infra

- **Shape.** The reference is one flat LAN behind one Palo Alto, a VyOS router above it and a Kali on a VyOS side leg. The manifest also describes multi-segment shapes (2026 had two segments), so relays stay.
- **The controller host** is the Ubuntu workstation by default; placement is configuration. It has a DHCP address on the LAN and no public address of its own. The address must not change during the event; if it does there is a manual command per agent (Enrollment).
- **The red team** may already have persistence on hosts at drop flag and starts at drop flag [TTP §1].
- **Scorer** is Quotient. Delay, Jitter, Timeout, SLA threshold, Divisor and debug visibility are unknown until measured [Q §0].
- **Free disk** on the controller host must hold one event's data plus the caches. Measure at the Invitational (collector E14 in `docs/impl/invitational-data.md`).

### The scorer model (Quotient)

Quotient was built and run in Docker and its checks read against source [Q §0]. What the design relies on:

| Fact | Source | Consequence |
| --- | --- | --- |
| The scorer runs a periodic burst every `Delay ± Jitter`. | [Q §3, Q §9.2] | Phylax estimates both from capture (the `scorer` module) and gates risky changes into quiet windows. |
| Quotient enforces `Timeout < Delay − Jitter`; the default Timeout is `Delay/2`. | `dbaseqp/Quotient engine/config/config.go:356@a845408` | A session older than the measured round delay is not a scorer check in flight. Session eviction uses this (Execution engine). |
| Sources are not stable: Docker NAT, and Divisor re-draws sources every round. Quotient uses many source IPs. | [Q §6] | The scorer is identified by behaviour (fingerprint table, Appendix G), never by address. Never narrow sources on scored ports. |
| One random item and one random credential per check per round. | [Q §9.8, SP §A2] | Discovery learns the item set over the whole event; checks test the learned union. |
| Quotient is lax in places: a 404 passes with no regex; SSH commands pass on any output. | [Q §9.7] | Our checks reproduce the scorer's exact transport and are stricter than Quotient where it is lax. |
| SLA penalties come from failure streaks; dropped rounds are not incidents. Accrual differs by event (WR used 35 then 20 per round; Quotient default 5×1). | [Q §9.5, §9.12], [[2026-wr-regional-packet#e6]], [[dbaseqp-quotient-9000379b7d#e6]] | SLA accrual is scorer configuration, not an event profile. |
| The scorer sends failed logins on purpose (`BadAttempts`). | [Q §9.6, SH never-list 1] | Exempt from lockout and brute-force rules by behaviour. |
| Quotient shows teams the users it scores with; no admin accounts are used for scoring. The red team does not have the scoring user list. | MW Discord 2026-10-22, decision 10 | Admin accounts rotate at T+0. Scored accounts are few and known to the scorer only. |
| Quotient keeps several credential lists (credlists), possibly per service; one password change may need PCRs on several lists. | decision 10 | Credentials are keyed by (account, credlist) everywhere. |
| The team API `GET /api/credlists` (needs `EasyPCR`) returns each credlist's name, path, usernames and format. The service-to-credlist mapping is admin-only (`/api/admin/checks`, `/api/admin/teamchecks`). | `dbaseqp/Quotient engine/credentials.go:158@a845408` | Useful only where Quotient is reachable; from inside, service-to-credlist is inferred from observed auth events. |
| PCRs are submitted inside Quotient and take effect immediately. Never use "Reset to Defaults"; roll back with a PCR of the old value. No shared passwords and none of 40 or more characters. | decision 10, [Q §5], Quotient issue #107, [[issues-dbaseqp-quotient#e9]] | Host change, then the PCR, inside one quiet window. Generated scored passwords are 16–24 characters from a safe set. |
| Quotient does not know about reverts: after a host or AD revert the passwords roll back on the host but Quotient keeps the new ones. | decision 10 | A revert triggers a re-sync per credlist (the `creds` module). |
| Team-pack admin passwords leak fast: full domain dump about 10 s after drop flag at Nationals, cleartext about 20 s. Red dumps every AD hash ("one DC's worth of plaintext"). | decision 10, MW Discord 2026-10-26 | Admin and service rotation is a T+0 console action. Scored-user policy: prevent the dump (Zerologon first, DCSync rule), honey AD accounts, pass-the-hash rules, selective rotation on evidence (review A7.Q7). |
| Quotient's SSH check can authenticate with a private key. | [[dbaseqp-quotient-9000379b7d#e10]] | The lint covers `authorized_keys` edits for scored users. |
| The portal lags the engine. | [[2026-mw-regional-packet#e17]] | A hand-entered Up/Down note is advisory, never ground truth for a single round. |

## Design principles

1. **Simplicity first, enforced by the module contract.** One binary, one transport, one source of truth, a small core, and every capability above it a module that meets the contract or is a cut candidate. Content (rules, plans, checks YAML) before code. Each module has one line in the complexity register; a new listener, daemon, host-binary dependency in a default path or runtime discovery mechanism needs its own line before it is built. Simplicity means fewer mechanisms and fewer moving parts: merge duplicates, reuse existing actions and content, and add nothing new to the scored path.
2. **Hosts dial out.** No host opens an inbound port for management. The relay host, the LAN decoys and the Kali path port on the controller are the declared exceptions.
3. **Go-native by default.** Agent actions call OS interfaces (syscalls, netlink, D-Bus, Win32, COM and WMI, LDAP, database drivers), not host binaries. Running a host binary is an explicit action, labeled in the UI.
4. **Detect and act on the host; correlate and report on the controller.** Detection and tier-0 response keep working while the link is down. Cross-host logic lives on the controller.
5. **One source of truth.** Firewall policy, plans, checks, decoys, agent configs and generated artifacts come from the manifest. Manual changes are adopted into overrides or reverted. Facts learned at the event are written to overrides, never committed.
6. **Passive in the scoring path.** Capture, replay and observe. Never intercept scored traffic.
7. **Trust only off-host data,** and treat everything an agent sends as untrusted input.
8. **Humans approve anything destructive or anything that touches scored state.** Automatic actions beyond tier 0 are offered as one-click suggestions, never run silently. Detection that could suggest a restore only alerts.
9. **Static, declared topology.** No election, discovery or failover. A new infra shape is a new manifest.
10. **One TLS connection per logical stream.** No multiplexing layer.
11. **Never break the scorer.** Anything that can touch a scored service must be provably safe: zero failed checks, alert-only first, the scorer-mimic probe after, bounded retries. Every plan node is linted against the scoring-safety rules, which derive their never-block lists from the manifest's scored services, and never narrows sources on a scored port [SH never-list, Q §9.4].
12. **Offline-first.** Every dependency is cached before it is needed. A live fetch is an optimisation, never a requirement (D-5).
13. **Fail closed, and off unless enabled.** No unsigned step runs, no unauthenticated mutating endpoint exists, no module runs without its config, and a new capability is off unless the manifest enables it. A degraded sensor is reported, not silently skipped [CR §3, OA §0.10].
14. **Obscurity is a cheap extra layer, not a security boundary** (D-8). Names and paths are randomised per event; nothing depends on them staying secret.
15. **OSS is an optional sensor.** Phylax owns orchestration, integrity, chains and checks. OSS tools add detection and evidence where they are cheaper than building, run as opt-in modules, and report health like any other module (D-9).
16. **Evidence decides.** Every module states the evidence that it matters for points. Detection depth is valued: detection and hunting are not cut for simplicity alone, only when there is no evidence they matter. A module without evidence starts off and is a cut candidate at the next review.
17. **Learn or enter at runtime.** Anything specific to one event (team number, scorer accounts, credlist names, round delay, a new service) is learned from observation or entered in the UI, because the repository is frozen before the access week.

## The module contract

Every capability above the core is a module. The contract makes "modular, not bloated" checkable: CI fails a module that breaks it, and a module that cannot meet it is a cut candidate (review N1.1, N1.2, N1.3; review decision 1).

### What a module is

A module is:

1. **One Go package** (`internal/<name>`, with optional subpackages it alone uses). The package holds the module's agent side, its controller side, or both. Agent-side registration stays in `internal/agent/mods/<name>*.go` because sensor packages import `internal/agent` (docs/agent.md); that file is part of the module.
2. **One config block**, a typed Go struct with JSON tags, under `modules.<name>` in the signed agent config (agent side) and in the manifest file `modules/<name>.yml` (Manifest; it replaces the module sections of v3's `policy.yml`). Unknown fields are an error. The block's JSON Schema is generated from the struct and checked by manifest CI.
3. **Declared typed events in and out.** Every event kind the module emits is declared with a schema version; every kind it consumes is listed. It emits nothing undeclared.
4. **A capability manifest:** sides, OS, privileges, roles, resource budget, default state, owned store tables, content directories and evidence.
5. **A health report:** state, coverage gaps and self-measured budget use, published in every heartbeat (agent) or on the Platform page (controller).
6. **Its own tests,** plus the shared conformance suite.
7. **No sibling imports.** A module imports only the core packages and the shared libraries listed below, never another module. Modules talk only through typed events on the bus. Controller analysers read the event store through the query API and write their findings as events.
8. **Content before code.** Rules, plans and checks are YAML under the module's content directories; a capability that content over existing actions can deliver gets no new Go.
9. **Off unless the manifest enables it,** except the modules the catalogue marks core-default, which run wherever their OS and role conditions hold.

**Core packages** a module may import: `internal/event`, `internal/module`, `internal/agent` (agent side: `Env`, `Emit`, `RegisterFactory`), `internal/link` (message types only), `internal/plan` (config and step types), `internal/actions` (the action framework: `Action`, `Env`, `Register`, locks, tags, guard), `internal/store` (the read-only query API and the module table migration hook), `internal/manifest` (types), `internal/ui` (the registrar), `internal/vault` (scoped secret reader).

**Shared libraries** (no state, no events, no goroutines that outlive a call) a module may import: `internal/atomicfile`, `internal/parsers/*`, the protocol clients in `internal/checks` (`ntlm`, `smb`, `winrm`, `ssh`, `mssql`, `ldap`, `web`), `internal/integrity` ledger format readers. A shared library that grows state or events becomes a module.

**Core modules that are not optional:** `health` (agent), the execution engine's `exec` (agent), link and spool. They implement the same interfaces so the Platform page and the conformance suite treat them uniformly.

### Event envelope

The envelope is `internal/event.Event` as built, with two fields added. Both are covered by the hash chain.

```go
// package event
type Event struct {
	Agent    string         `json:"agent"`            // host identity; "controller" for controller-origin events
	Seq      uint64         `json:"seq"`              // per-agent sequence, assigned by the spool
	Time     time.Time      `json:"time"`             // host clock, display only; ordering comes from Seq
	Kind     string         `json:"kind"`             // declared kind (see below)
	Schema   int            `json:"schema"`           // NEW: schema version of Kind, set by event.New
	Priority Priority       `json:"prio"`             // critical, high, normal, bulk
	Tag      string         `json:"tag,omitempty"`    // NEW: plan or work-window tag (Execution: tagging)
	Fields   map[string]any `json:"fields,omitempty"` // the typed payload, encoded
	PrevHash string         `json:"prev"`
	Hash     string         `json:"hash"`
}
```

`Tag` moves out of `Fields` into the envelope so every event type carries it (v3 "the tag reaches every event type") and rules exempt tagged events with one condition. Adding the two fields changes the canonical encoding, so the protocol minor version rises and the controller accepts both forms for one release.

**Kinds** come in two classes:

- **Common kinds** describe one thing several producers report: `process_start`, `process_exit`, `file_change`, `conn`, `listener`, `auth_event`, `dns_query`, `telemetry_gap`. They are declared in `internal/event/kinds.go` with one Go struct each, and the manifest of every producer lists them under `Emits`. Rules match on common kinds so one rule covers Linux and Windows (audit and winevt both emit `process_start`).
- **Module kinds** are `<module>.<name>` (`detect.alert`, `integrity.verdict`, `capture.flow`, `scorer.round`). Only the named module may emit them.

Existing kind names in the code (`proc.exec`, `exec`, `fim`, `login` and others) are mapped to declared kinds during the retrofit; the old names are accepted as aliases by the controller for one release.

**Typed events.** A declared kind has a Go struct. Modules build and read events through generic helpers, so a field name typo is a compile error and a schema mismatch is a decode error:

```go
// package event
type Type struct {
	Kind     string   // "process_start" or "<module>.<name>"
	Schema   int      // starts at 1; bump on any change a consumer would notice
	Priority Priority // default priority for this kind
	Fields   any      // zero value of the payload struct, for docs, schema generation and the conformance suite
}

func Declare(t Type)                                   // from init; panics on a duplicate kind
func Lookup(kind string) (Type, bool)
func New[T any](kind string, v T) (Event, error)       // sets Kind, Schema, Priority, Fields; error if undeclared or T mismatches
func Decode[T any](e Event, kind string) (T, error)    // strict: wrong kind, unknown schema or unknown field is an error
```

A consumer declares the schema versions it understands; the controller stores events of any version and analysers skip versions they do not know, reporting the count in their health.

### The capability manifest

```go
// package module (internal/module, new; imports internal/event and the interface types of store, vault and ui, nothing else)
type Side string

const (
	SideAgent      Side = "agent"
	SideController Side = "controller"
)

type Budget struct {
	CPUMillisPerSec int     // self-timed work inside handlers and loops, averaged over 10 s
	HeldMB          int     // bytes the module holds in its own queues, caches and maps (self-reported)
	EventsPerSec    float64 // sustained emit rate; becomes agent.ModuleSpec.Rate
	Burst           int     // becomes agent.ModuleSpec.Burst
	BytesOutPerMin  int     // encoded bytes handed to the spool (agent) or the store (controller)
	DiskMB          int     // files under the module's own state directory
}

type Manifest struct {
	Name      string       // package name, config block key and module-kind prefix
	Sides     []Side       // where it runs
	OS        []string     // "linux", "windows"; empty means both
	Privilege string       // "root" (root or SYSTEM), "user" (runs unprivileged), "none" (controller only)
	Roles     []string     // host roles that make it eligible (relay, capture, check_runner, scanner, canary, decoys, domain_controller, controller); empty means any host
	Consumes  []string     // event kinds read: agent Subscribe filter, or controller query inputs
	Emits     []event.Type // every kind it may emit
	Budget    Budget
	Default   bool         // true only for core-default modules; false means off unless the manifest enables it
	Tables    []string     // controller store tables it owns; migrations ship in the package
	Content   []string     // content directories it loads, e.g. "rules/detect", "plans/hardening", "checks/checks"
	Actions   []string     // action names it registers in the agent or device executor
	Pages     []string     // UI routes it registers
	Evidence  []string     // vault citations for points impact
}
```

The manifest is static Go data returned by the module and published by `phylax modules` (a CLI listing) and in the agent's `hello` capabilities block, so the controller knows what each agent can run before it sends config. It replaces v3's free-form capabilities block and the planned `phylax doctor` (review D87).

### Agent modules

The agent interfaces are the ones built in `internal/agent`, extended with the manifest and an optional health method:

```go
// package agent (built)
type Emit func(event.Event) error // never blocks on the network; error means dropped and counted

type Module interface {
	Name() string
	Start(ctx context.Context, emit Emit) error // runs until ctx ends; error or panic is a crash, restarted with backoff
}

// NEW, optional: a module that knows more about its health than the supervisor does.
type HealthReporter interface {
	Health() module.Health
}

type ModuleSpec struct {
	Module     Module
	Rate       float64 // from Manifest.Budget.EventsPerSec unless the config lowers it
	Burst      int
	Subscriber bool    // calls Env.Subscribe from Start; the agent holds start-up events for it
}

type Factory struct {
	Name     string
	Manifest module.Manifest                                              // NEW
	Section  func(cfg *plan.AgentConfig) (fingerprint string, enabled bool) // its config block
	Build    func(env Env, cfg *plan.AgentConfig) (ModuleSpec, error)      // ErrUnavailable when it cannot run here
}

type Env struct {
	Host     string
	StateDir string // the module gets StateDir/<name>; nothing else is writable to it by contract
	Logger   *slog.Logger
	PlanKey  ed25519.PublicKey
	Health   HealthSource
	// Subscribe(kinds ...string) filters by kind (NEW: v3 code takes only a buffer size).
	// Keep/Kept hand state to a replacement after a reconfiguration.
}
```

`plan.ModuleSettings` grows one pointer field per agent module (`Modules.Detect`, `Modules.Integrity` and so on, as built); a nil pointer means disabled. The reconciler (built) builds, replaces or removes modules as fingerprints change and records `running`, `disabled`, `unavailable: why` or `error: why` per module.

**On-host bus.** `Env.Subscribe` is the agent's bus (built): every event a module emits, after its rate limit and before the spool, goes to bounded subscriber channels that drop rather than block. A module may consume only kinds in its `Consumes` list; the supervisor filters. Local detection and the content guard are subscribers.

### Controller modules and analysers

The controller side mirrors the agent side. Today controller features are methods on `controller.Controller` that call each other; the retrofit moves each into its module package behind these interfaces.

```go
// package module
type Host interface {
	Config(v any) error                                     // decode the module's manifest block, strict
	Query() store.Query                                     // read-only event-store queries
	Emit(e event.Event) error                               // controller-origin events, stored under agent "controller"
	Subscribe(kinds []string, buf int) (<-chan event.Event, func()) // events as they are committed
	Propose(p Proposal) error                               // a one-click suggestion or a plan draft; never applies
	Secrets(names ...string) (vault.Reader, error)          // only the secret names its config declares
	UI() ui.Registrar
	Logger() *slog.Logger
}

type ControllerModule interface {
	Manifest() Manifest
	Start(ctx context.Context, h Host) error // background work (schedulers, pollers, device sessions)
	Health() Health
}

// An analyser is a pure function over store queries: same store contents and same `now`, same output.
type Analyzer struct {
	Name     string
	Inputs   []string                                            // kinds it reads; also the trigger set
	Every    time.Duration                                       // periodic run; 0 means on trigger only
	Run      func(q store.Query, now time.Time) ([]event.Event, error)
}
```

An analyser holds no state between runs; anything it must remember it writes as an event or into a table it owns. That is what makes traceback, chains, deps, SLA, egress ranking and the vulnerability matcher testable from fixture stores and switchable one at a time (review N1.3, cross-cutting idea 7). Analysers run on the controller's analysis worker with a per-run deadline and a per-module CPU budget; a run over budget is stopped and reported.

`Proposal` is the one route from a module to change: a typed suggestion ("block 10.0.0.5 on the Palo", "restore /var/www/html/index.php from golden", "disable unit x") with evidence references, rendered as a one-click button that creates and approves a plan through the normal engine. Modules never sign or send steps themselves.

**Store tables.** The core owns only `host`, `service`, `event`, `alert` and `incident` (plus plans, approvals, audit and UI accounts). A module that needs its own tables declares them in `Tables`, ships the migrations in its package, and only it writes them. Other modules read a module's findings from its events, not its tables.

**UI.** A module registers its pages, overview tiles and host-grid columns through `ui.Registrar` (UI shell). The shell has no module-specific code; a disabled module's pages disappear.

### Health and budgets

```go
// package module
type State string // "ok", "degraded", "unavailable", "disabled", "over_budget", "restarting", "error"

type Gap struct{ What, Why string } // e.g. {"overlayfs under /var/lib/docker", "audit watches cannot see it"}

type Usage struct {
	CPUMillis uint64 // self-timed since the last report
	HeldBytes uint64
	Events    uint64
	BytesOut  uint64
	Dropped   uint64 // rate-limited plus spool-refused
}

type Health struct {
	State  State
	Detail string
	Gaps   []Gap
	Usage  Usage
}
```

The supervisor fills `State`, `Events` and `Dropped` for every module (built: `ModuleStatus`). A module that implements `HealthReporter` adds gaps, detail and its own usage. The heartbeat's per-module block carries the whole `Health`, so a runaway rule shows as one module's CPU climbing (review D67, cross-cutting idea 13).

**Budgets are enforced in two layers.** The process as a whole is capped by systemd `MemoryMax` and `CPUQuota` or a Windows Job Object, with `debug.SetMemoryLimit` set below the cap. Per module, Go cannot attribute RSS or CPU to goroutines, so usage is self-measured: modules time their own handler and loop work and count the bytes they hold. The supervisor's budget hook (built) stops a module whose self-reported usage exceeds its budget for three consecutive intervals, marks it `over_budget` and restarts it after backoff. `shortcut: per-module CPU and memory are self-reported approximations, upgrade only if a lab run shows a module misreporting`.

### Configuration

- The manifest enables modules per host with a `modules:` list in `hosts.yml` (or for every host matching a label expression), plus each module's block in `modules/<name>.yml`. Core-default modules are enabled unless the host's entry turns them off.
- The controller renders each host's `AgentConfig` from the manifest (built: `controller/agentconfig.go`, `genconfig.go`); each agent module's block becomes its `ModuleSettings` field. The signed config carries the module blocks, the rule files the host's modules need and the budgets.
- Event-specific values are entered in the UI and written to `overrides.yml` (Manifest), never to the module's base block.

### Content before code

Content lives in the repository under `rules/`, `plans/` and `checks/`, one subdirectory per owning module where a module owns several files (`rules/detect/`, `plans/hardening/`). Every content file names its module (`module: hardening`) and is loaded only when that module is enabled on the target. Content gets the same CI as code: schema validation, inline tests, the scoring-safety lint for plans, and the rule-id registry check. A capability that content over existing actions can deliver gets no new Go; when content cannot express something, the smallest action or rule operator that unblocks it is added to the core or the owning module, not a new mechanism.

### Isolation

- **No sibling imports**, checked in CI by `go list -deps` per module package against the allowed set above.
- **No shared mutable state** between modules: no package-level variables written after `init`, no shared maps. Data moves as events.
- **No module writes another module's tables, files or config.**
- **A module's agent side writes only under `StateDir/<name>`** and to the spool. Host changes go through actions in plans or tier-0 responses, never through ad-hoc writes.

### The conformance suite

`internal/module/conformance` runs against every registered module in CI (review N1.2, N13.1). A module fails CI unless it:

1. **Starts with no config:** `Section` reports disabled, or `Build` returns `ErrUnavailable`, never a crash.
2. **Starts with its default config** on a fixture host and reaches `ok` or `unavailable` within 10 s.
3. **Stops cleanly:** returns within 5 s of context cancel and leaves no goroutines (checked with a goroutine leak detector).
4. **Reports health** within one heartbeat interval, with a non-empty `Gaps` entry for every declared OS or privilege it lacks.
5. **Emits only declared kinds,** every event decoding strictly against its declared schema version.
6. **Respects its budget** under its fixture load (events per second, self-reported CPU and held bytes).
7. **Survives link loss:** keeps running and keeps local behaviour when `Emit` returns errors for 60 s.
8. **Survives reconfiguration:** a changed config replaces it without losing `Keep` state.
9. **Has no sibling imports** and **rejects unknown config fields.**
10. **Passes `go test -race`** for its package.
11. **For analysers:** produces identical output twice from the same fixture store and `now`.

### Retrofit order

The module contract, the module registry and the event bus come first, then the existing modules are retrofitted one by one (review A1.Q1). Order: `event` additions and `internal/module`; the conformance suite; the controller `Host` and registrar; then each built module as its area is implemented. Until a module is retrofitted it is listed on the Platform page as "pre-contract", and new code may not depend on its internals.

## Core components

The core is the part every module depends on: the link and spool, the execution engine, the event store and vault, the manifest and the UI shell, plus the agent runtime that hosts agent modules and the enrollment path that gets agents onto hosts. Each section below is complete; modules only extend it through the contract.

### Architecture overview

Phylax is one Go binary that runs in two modes: `phylax serve` on the controller and `phylax agent` on every host, including the controller and the Kali (review D16, D17). Hosts always open the TLS connections, outbound. The controller holds the manifest, the event store, the vault, the plan engine, the controller modules (analysers, device adapters, active checks) and the web UI. The agent hosts the agent modules, executes signed plan steps and keeps a crash-safe spool. One binary means one release artifact per OS, and the agent and controller can never disagree on the protocol version. **Complexity:** every host carries the controller's code too, which makes the binary bigger (Agent runtime, footprint).

`phylax serve` keeps its process (review D11): link, store, execution and UI shell are core; everything else in it is a registered controller module.

Maintenance commands in the same binary: `phylax init` (fetch and verify the release, start the cache sync; review D19), `phylax cache` (build and sync), `phylax rules test`, `phylax ledger` (build and look up), `phylax set-controller` (review D24), `phylax modules` (list modules and their manifests), `phylax depot` and `phylax tools` (Integrations and depot), and the team-feed commands `phylax say` and `phylax claim` (the `teamfeed` module).

```text
                         ┌────────────────────────────────────────────┐
  VyOS side leg          │  LAN 172.20.240.0/24 (flat, one Palo)       │
  172.17.0.0/24          │                                            │
  ┌──────────┐  Palo     │  rocky-ecom .10   ubuntu-email .15          │
  │  Kali    │◄─rule────►│  debian-splunk .20  ad .100  mssql .120     │
  │ agent:   │  (one     │  win11-wkst (DHCP)                          │
  │ check_   │  port,    │  ubuntu-wkst (DHCP)  ◄── phylax serve       │
  │ runner,  │  Kali     │                          (controller, UI    │
  │ scanner, │  source   │  every host: phylax agent, dials out        │
  │ canary   │  only)    │  Palo mgmt .200, VyOS via Palo              │
  └──────────┘           └────────────────────────────────────────────┘
        every arrow points toward the controller; Quotient's runners
        reach our public addresses 172.25.(20+T).x through VyOS and the Palo
```

| Component | Runs on | Responsibility |
| --- | --- | --- |
| `phylax serve` core | Controller | Accepts agent connections (link). Holds the event store (SQLite) and the vault. Compiles the manifest into agent configs, plans and firewall policy. Runs the plan engine. Hosts controller modules. Serves the UI shell on its own localhost listener. |
| Controller modules | Inside `phylax serve` | Analysers (scorer, traceback, chains, deps, egress, vuln), active checks, device adapters, reports, integrations, depot. See the catalogue. |
| `phylax agent` core | Every host | Link, spool, the execution engine (`exec`), the supervisor and the `health` module. Runs as root or SYSTEM. |
| Agent modules | Hosts chosen by OS, role and the manifest | Telemetry, detection, response, integrity, capture, decoys (in one unprivileged child process), vantage roles. See the catalogue. |
| Agent roles | Hosts chosen in the manifest | `relay`, `device_proxy`, `check_runner`, `scanner`, `canary`, `decoys`, `capture`, `domain_controller`, `controller`. Roles are manifest switches that make modules eligible. |
| Sysmon | Windows hosts | The main Windows sensor, installed and kept alive by the `winevt` module under renamed driver and service. |
| Optional OSS | Chosen hosts | Wazuh, Splunk HEC forwarding, Suricata and Zeek over pulled pcaps, as opt-in modules. Never on the critical path. |

### Topology, relays and firewall layers

Topology is declared, not discovered. The manifest lists the segments, the controller host, and one relay host for each segment that cannot reach the controller directly. The 2027 layout needs no relay for any LAN host. The Kali is the one host outside the LAN, and it reaches the controller through a declared firewall rule.

#### The reference manifest (2027)

```yaml
# manifest/topology.yml
team: 12                                   # placeholder; entered at runtime if it changes (overrides)
controller:
  host: ubuntu-wkst                        # DHCP on the LAN; placement is configuration
  agent_port: 7443                         # agent streams and bootstrap downloads only
  ui: 127.0.0.1:8443                       # separate listener, login required
segments:
  lan:
    cidr: 172.20.240.0/24
    firewall: palo1                        # mgmt 172.20.240.200, on this LAN
    uplink: vyos1                          # reached through the Palo's outside zone
    nat: { public_pool: "172.25.{{ 20 + team }}.0/24", mode: static_1to1_same_octet }
  kali_leg:
    cidr: 172.17.0.0/24
    firewall: vyos1                        # no Palo between this leg and the Core side of VyOS
    controller_path:                       # how an agent here reaches the controller
      via: static_nat
      public: "172.25.{{ 20 + team }}.30"  # free address in the pool; maps to the controller
      allow_from: kali                     # the Palo rule and the host rule allow only the Kali's translated source
      port: 7443
devices:
  palo1: { vendor: panos, mgmt: 172.20.240.200, segment: lan }
  vyos1: { vendor: vyos,  mgmt: 172.16.0.254,  segment: lan, via: palo1 }
```

```yaml
# manifest/hosts.yml
hosts:
  rocky-ecom:      { segment: lan, ip: 172.20.240.10,  public: "172.25.{{ 20 + team }}.10",  os: { family: rhel,    distro: rocky,   version: "9" },      roles: [capture, decoys], labels: [web, linux] }
  ubuntu-email:    { segment: lan, ip: 172.20.240.15,  public: "172.25.{{ 20 + team }}.15",  os: { family: debian, distro: ubuntu,  version: "22.04" },  roles: [capture, decoys], labels: [mail, linux], domain_member: ad }
  debian-splunk:   { segment: lan, ip: 172.20.240.20,  public: "172.25.{{ 20 + team }}.20",  os: { family: debian, distro: debian,  version: "12" },     roles: [capture, decoys], labels: [splunk, linux] }
  ad:              { segment: lan, ip: 172.20.240.100, public: "172.25.{{ 20 + team }}.100", os: { family: windows, version: "server-2022" },           roles: [capture, check_runner, domain_controller], labels: [windows, dc] }
  mssql:           { segment: lan, ip: 172.20.240.120, public: "172.25.{{ 20 + team }}.120", os: { family: windows, version: "server-2019" },           roles: [capture, decoys], labels: [windows, sql], domain_member: ad }
  ubuntu-wkst:     { segment: lan, ip: dhcp, os: { family: debian, distro: ubuntu, version: "22.04" },       roles: [controller, capture, check_runner], labels: [workstation] }
  win11-wkst:      { segment: lan, ip: dhcp, os: { family: windows, version: "11" },                        roles: [capture], labels: [workstation, windows] }
  kali:            { segment: kali_leg, ip: 172.17.0.2, os: { family: debian, distro: kali, version: "2026.2" }, roles: [check_runner, scanner, canary], labels: [vantage] }
```

The public addresses use the same last octet as the internal ones. The workstations and the Kali go out through VyOS source NAT (`172.31.(20+team).2`), so they have no public address of their own [PKT §2]. Hosts with the `decoys` role never decoy on a scored port and never on a public address (the `decoys` module).

#### Roles and links

- **Agents in the controller's segment** dial the controller directly. On the 2027 LAN that is every host but the Kali (review D44).
- **The Kali agent** dials the controller's public address through VyOS and the Palo, under one Palo rule and one static NAT.
- **Agents in a segment that cannot reach the controller** dial their segment's relay, which splices each connection through. Chained segments chain relays (review D46, D47, D111).
- **Link direction is always child to parent** (review D48). A segment that can make no outbound connection at all would need the direction flipped for that one link; not built unless an infra requires it.
- **A dead relay** cuts its segment off. Agents there keep detecting, responding and spooling locally until it is back (review D49). Restore it with the console one-liner. No backup relay unless lab testing shows relay loss is a real problem.

#### How the relay works

The relay is a dumb splicer, which keeps it simple and keeps it from being worth attacking. It is part of the core link (the `relay` role switches it on):

- It listens on one port and accepts connections only from the source addresses in its segment's manifest entry.
- For each accepted connection it opens a new outbound TCP connection to its parent and copies bytes both ways, with deadlines and a connection cap. The agent's TLS session runs end to end to the controller, so the relay never sees plaintext and holds no agent keys.
- It keeps one outbound control connection to the controller (ALPN `phylax/relay`, its own identity), used only to receive device-proxy and bootstrap requests.
- For a **device-proxy request** the relay checks the target against its manifest allowlist, opens a connection to the device, opens a fresh outbound connection to the controller (ALPN `phylax/splice`), and splices the two. The device's own TLS stays end to end. Bootstrap downloads for hosts behind a relay use the same splice.
- Each splice records only metadata: source, destination, bytes, duration.
- There is no multiplexing layer anywhere. Every logical stream is its own TCP connection.
- **Status:** built, with no end-to-end relay test yet; that test is a gate (Testing).

#### One connection, hop by hop (Kali to controller)

Each hop needs an allow rule only in the direction the connection is opened, since all of them track connection state (review D45).

| Hop | Rule | Address used |
| --- | --- | --- |
| Kali host firewall, outbound | Allow TCP to the controller's public address on the agent port | Public address |
| VyOS | Routes; source NAT to `172.31.(20+T).2` on the way out | Kali becomes the VyOS external address |
| Palo, outside to inside | Static NAT: controller public address to its internal address; allow only from the VyOS external address, only on the agent port, tagged `phylax-managed` | After NAT, the Palo sees the controller's internal address |
| Controller host firewall, inbound | Allow the agent port from the LAN agents' addresses and from the Kali's translated source only | As seen after translation |

The public NAT listener is filtered to the Kali's source address only: the organizer's perimeter assessment scores extraneous services on public addresses [[2026-mw-regional-scorecard-t7#e3]], and an agent port open to everyone is one. The controller's internal address is DHCP. A static NAT needs a fixed target, so this path depends on a DHCP reservation or on a manual rule update if the lease changes [PKT §2]. The Network role enters the Palo rule by hand at T+0; the `devices` module takes over afterwards.

#### What each firewall layer is for

- **The Palo** guards the boundary between the LAN and the outside. A host implant cannot change it without device credentials. It is also the only place that sees outside-to-LAN traffic.
- **Host firewalls** are the only control on traffic inside the flat LAN, which never crosses the Palo. An implant can disable them. Tier 0 restores them and alerts (the `firewall` and `respond` modules).
- **VyOS** is the path for every service. A lockout there is catastrophic, so changes follow the soft-revert protocol (the `devices` module).

#### Rule hygiene and bring-up

- **Separate, tagged groups** (review D50). Management rules (agent links, device access) live in their own nftables table, Windows Firewall rule group and Palo tag. Restore and drift detection treat them separately from service, dependency, decoy and inject-change rules.
- **Bring-up order** (review D51):
  1. **T+0 console phase** (Enrollment): admin and service credentials rotated on the consoles; the Palo management lockdown, the Kali-to-controller rule and the static NAT entered by the Network role from the checklist Phylax renders from the manifest.
  2. First contact installs the agents.
  3. Host firewalls get the management allows first, then default-deny outbound, under the dead-man switch (Execution engine).
- **Controller address.** If it changes, the static NAT is updated by hand and every agent is pointed at the new address with `phylax set-controller` on its console.

### Trust model

The controller and its unlocked keys are the only fully trusted component. Agents are trusted to report on their own host only while that host is clean. Relays, the network, host binaries, DNS and clocks are not trusted at all. The Kali is a workstation outside the Palo and is treated as an untrusted vantage point. Every mechanism below exists to keep a compromise of one host from spreading through our own tooling (review D52, D53).

#### Adversary assumptions

The red team can:

- get root or SYSTEM on any server, possibly on a workstation, possibly before drop flag
- read our full source, rules and this document
- watch or tamper with traffic inside the LAN, and across segments if they own the router
- move system clocks
- kill, patch or impersonate our agent on a host they own
- replay anything they capture
- feed crafted strings (process names, file paths, HTTP paths, usernames) into anything we log
- reach every default credential in the packet, and dump every AD hash once they hold a DC (MW Discord 2026-10-26)
- reach any local process on the controller host that is not ours

#### Trust boundaries

| Component | Trusted for | Not trusted for | If compromised |
| --- | --- | --- | --- |
| Controller host and its unlocked keys | Everything; it is the root of trust | — | Total loss: the attacker can sign plans for every host and read the vault, including the few rotated scored passwords. |
| UI session (one login) | Launching and approving actions | — | Same as controller compromise. Bound to localhost with a login, so the attacker needs the controller host and the password. |
| Release signing key (kept off the competition network) | Which binaries are ours | — | Malicious builds. Never present in the environment. |
| Agent | Reporting what it sees while its host is clean | Truth about a compromised host; anything about other hosts | The attacker can lie for that one host, flood, replay its own history, or impersonate that host. Nothing more. |
| Kali agent | Reporting what an outside client sees | Anything else; it holds scored credentials only in memory during probes | The attacker can falsify external verdicts and read credentials in memory. Cannot command other hosts. |
| Relay | Moving bytes | Reading or altering content | Can drop or delay its segment's traffic. Cannot read, forge or command. |
| Optional OSS (Wazuh manager and others) | Extra detections and evidence | Anything on the critical path | The Wazuh manager can push code to its agents; its host is a tier-0 asset (the `wazuh` module). |
| Network devices (after rotation) | Enforcing policy | Staying unchanged | Detected by config diff; reverted from snapshot. |
| Host OS, host binaries, DNS, clocks, the network | Nothing | Everything | Assumed hostile from the start. |

#### Mechanisms

**Identity with pinned keys, no certificate authority** (review D54).

- Each agent generates its own ECDSA P-256 keypair at install and enrolls with a one-time token. The controller records the public key against the host's identity. P-256 is used everywhere because Windows SChannel (PowerShell's download path on Server 2019 and Windows 10) cannot negotiate Ed25519 server certificates [CR §2].
- The agent carries the controller's public-key hash from its bootstrap bundle.
- Both sides verify each other by key hash, not by a certificate chain, and ignore certificate dates. Moving the clock cannot break authentication.
- A stolen agent key impersonates only that host.

**Signed commands, separate from the transport** (review D55).

- Every plan step, every signed config and every control message is signed with an Ed25519 plan-signing key held only in controller memory, unlocked by passphrase.
- The step signature covers a canonical encoding (RFC 8785 JSON) of the whole step except the signature itself: plan id, node, target host identity, epoch, sequence, action, phase, parameters, a digest of the secrets blob, a digest of the rollback data, the dead-man deadline, risk class and approval record, including the approver's name [CR §3.2].
- Verification is mandatory. An agent with no plan key refuses every step and control.
- Each agent persists the highest `(epoch, seq)` it has accepted, separately for steps, controls and configs, and rejects anything not strictly greater, and any step for an unexpected plan id. The epoch rises only when the controller is restored from a snapshot (Enrollment: controller recovery).
- The transport key and the plan-signing key are different.

**Bounded agent power** (review D56). The agent runs as root or SYSTEM because it has to, but it executes only typed actions from the catalog. `host.exec` needs an explicit approval and is labeled in the UI. Pre-approved host tools are an explicit, hash-pinned list (YARA-X, `nmap` and `xfreerdp` on the Kali, the Sysmon installer, package managers installing from the depot, the services' own dump tools in backup actions).

**Per-host secrets only.** A plan step carries only the secrets its host needs. The Kali gets scored credentials only for the probes it runs, held in memory, never written to disk.

**Every endpoint is authenticated** (review D57). There is no "loopback means trusted" [CR §3.1].

| Surface | Listener | Authentication |
| --- | --- | --- |
| Agent and relay streams | `agent_port`, ALPN `phylax/*` | Mutual key pinning |
| Bootstrap downloads | `agent_port`, no ALPN | Serves only the signed binary and a bootstrap config bound to a one-time token. Mints nothing. |
| Operator UI and API | `127.0.0.1:8443` only | Login (argon2id), HttpOnly SameSite=Strict cookie, CSRF token on every state change. The CLI uses an API token created in the UI. |
| Token minting, plans, responses, approvals | UI listener only | Session plus CSRF, plus approval records for risky nodes |

**Agent data is evidence, never instructions** (review D58).

- Events are sequenced and hash-chained. The controller acknowledges what it stores. A root attacker can forge future events but cannot rewrite acknowledged ones, and gaps are visible.
- Every message is validated against its schema, with per-agent size and rate limits. Every event is validated against its declared kind and schema version.
- Nothing an agent sends is ever executed, or used to build a command or a query.

**The web UI treats every agent-supplied string as hostile** (UI shell).

**Time is for display only.** Ordering comes from per-host sequence numbers. Each heartbeat carries the host clock, and timelines apply the measured offset.

**The controller host gets the hardest hardening** (review D60). Inbound: only the agent port, from declared sources (LAN agents and the Kali's translated source). The UI is on localhost. SSH disabled. Secrets in memory only, encrypted at rest. Its own agent reports to it like any other host. Other local users and processes get nothing from the UI without the password.

**Obscurity (D-8; review D61).** The agent's install path, binary name, service name and unit name are randomised per event from a secret in the vault (built: `cmd/phylax/agent.go`, `--secret`). Sysmon's driver and service are renamed. The controller's own detections exclude the agent by its randomised path and hash, not by name. Release binaries are never mutated per host, so the signature always verifies. This raises the cost for scripted kill lists [OA §5.6, WT §9.8]. It is not a boundary.

#### Where trust is weakest

- **First contact.** A host that is already backdoored at drop flag can tamper with the agent install. Its first hunt results and its ledger sweep matter more than its heartbeats.
- **Windows.** Go calls through `ntdll` and `kernel32`, so a userland hook there affects our agent. On Linux, Go skips libc and is immune to `LD_PRELOAD`, but not to kernel rootkits.
- **The Kali.** Its verdicts are good evidence about the public path and poor evidence about anything else.
- **The controller.** The single root of trust, accepted deliberately in exchange for simplicity. A breach exposes every rotated scored password in the vault; that is one reason scored rotation is selective (review A7.Q6, A7.Q8).

### Agent runtime

The agent is the agent mode of the single static binary, running as a supervised service. It hosts agent modules, executes plan steps and holds a crash-safe spool while the link is down. Roles and the manifest switch modules on. It builds and runs on Windows as on Linux; CI cross-builds linux/amd64 and windows/amd64 with `CGO_ENABLED=0` [CR §6] (review D62).

#### Process model

- **Main process,** root or SYSTEM: everything except decoys. Modules run as supervised goroutines with panic recovery and exponential restart backoff (1 s to 60 s, reset after a 30 s stable run), and each crash emits `agent.module_crash` (built; review D63). Shared state is behind locks or channels; `go test -race` is a CI gate, because a concurrent map write is a fatal error no recover can catch [CR §3.5].
- **Decoy process,** unprivileged (a dedicated user on Linux, a low-privilege service account on Windows): every decoy listener and the fake shell. A second process, kept because decoys are the agent code most exposed to attackers. Status: the split is not done yet (docs/agent.md); the `decoys` module section carries it.
- **Config comes only from the controller** as signed `config` messages delivered at `welcome` and on change (review D65). The bootstrap file carries the controller pin and the host identity; module blocks, rules, ledger references and budgets arrive signed. An agent without config reports itself unconfigured and runs no module except `health` [CR §3.4]. The agent persists the last good config and runs it on restart without a controller.

#### Footprint

| Measure | Target | Enforced by |
| --- | --- | --- |
| Binary size | 40 MB or less, 15 MB or less compressed | CI fails the build above it (`make size`; review D66). No agent-only build tag. |
| Memory | 80 MB RSS or less steady, excluding the packet ring and kernel-held memory (reported separately in the heartbeat) | `debug.SetMemoryLimit` plus systemd `MemoryMax` or a Windows Job Object as the hard cap; per-module self-reported held bytes (review D67) |
| CPU | 3% average; a 5 s burst of one core at most | systemd `CPUQuota` or the Job Object; per-module self-timed budgets; sweeps run at low priority; capture drops packets before slowing the host |
| Disk | Spool 200 MB cap; packet ring the smaller of 2 GB or 10% of free disk | Oldest low-priority data shed first; alerts and evidence never shed (review D68) |

Kernel-held memory is reported in the heartbeat (audit backlog, inotify watches, the AF_PACKET ring) [OA §5.7] but not accounted per module.

#### What "Go-native" means

- **Allowed by default:** calling the OS's own interfaces from Go: syscalls, netlink, `/proc` and `/sys`, D-Bus for systemd, Win32 APIs, COM and WMI, the event log API, LDAP and database drivers (review D86).
- **Escape hatch:** `host.exec` (Execution engine).
- **Complexity:** COM and WMI from Go (Windows Firewall, Task Scheduler, WMI subscriptions, Defender settings) is fiddly code and the largest chunk of Windows work. If one COM interface fights back, that one action uses `host.exec` and gets a complexity-register line.

#### Capabilities and the heartbeat

- **`hello` capabilities block** (review D87): kernel features, which sensors each module chose, and every registered module's manifest. This is the one capability probe; the Platform page shows it.
- **Heartbeat** every 5 s (review D99): sequence, host clock, spool depth and congestion state, safe mode, shed count, the config status (reserved module name `config`), and each module's `Health` block. Module-specific health such as audit status, fanotify overflow counts, the Sysmon service and config hash, and the hash of our own loaded audit rules comes from the owning module's `Health.Detail` and `Gaps`. Silence means the agent is down; present-but-degraded means a sensor was tampered with or overloaded.

#### Self-protection and tamper detection

No open Linux agent prevents a root user from stopping it. The goal is to raise the cost for scripted kill lists, detect fast and recover automatically [OA §5.6]:

1. **Heartbeat with sensor health** (above).
2. **Service hardening** (review D100): `Restart=always`, `RestartSec=1`, `StartLimitIntervalSec=0`, `Type=notify` with `WatchdogSec` and `sd_notify`, `OOMScoreAdjust=-900`, `MemoryMax`, `CPUQuota`, `NoNewPrivileges`, `UMask=0077` (built). Windows: automatic LocalSystem service, recovery actions restart forever (built), a protected service DACL and a Job Object cap (to build). The watchdog is `sd_notify` only today; finishing the Windows half is a core task.
3. **Kernel-side watches on our own files** (review D101): binary, unit, config, audit rule files, through the `audit` module's file watches on Linux and `winevt` on Windows. The kernel records edits even if the agent was just killed, and the restarted agent ships them. A tier-1 alert fires if the agent binary hash changes (review D104).
4. **Opt-in immutability** (review D102): `chattr +i` on the agent binary and unit, and audit `-e 2` as an explicit late plan step with a reboot as rollback. Neither is automatic; the agent's replace-binary action clears and re-sets the bit. Already a plan step (`actions/linux_attr.go`), no new code.
5. **Cross-source tripwires** are hunt content (the `hunt` module).
6. **Assume the host key is stolen:** the controller alerts when one key is used from two places at once.
7. **Randomised names and paths** (D-8).

#### Windows Defender

An unsigned binary that captures packets, runs fake services and keeps a decoy credential session in LSASS can look like malware (review D105).

- Test the agent against current Defender definitions in the lab before every release.
- If it is flagged, hardening keeps exactly one Defender exclusion (the agent's randomised install directory) and alerts on any other exclusion.
- **Complexity:** an exclusion is a hole, even a narrow one. The only alternative is code signing, which is not practical.

#### Lifecycle

| Stage | What happens |
| --- | --- |
| Install | First contact copies the binary and a bootstrap config to a randomised path, installs a systemd unit or Windows service with automatic restart, then enrolls (review D106, `internal/svcinstall`). |
| Steady state | Supervised by systemd or the service manager. Config and rules hot-reload from signed config messages. |
| Killed or disabled | The controller sees the heartbeat stop and raises an alert (review D534). If the host is unreachable by other means, restore from the console one-liner. |
| Binary replacement | One action, `agent.replace_binary`: verify the signed binary, swap, restart, roll back if no heartbeat returns within 30 s. |
| Uninstall | One action, for cleanup after the competition (review D107). |

### Wire protocol and spool

Each agent holds one long-lived TLS 1.3 connection to the controller, with both sides pinning keys. Over it run length-prefixed, compressed JSON messages in strict priority order. Anything that is not agent messaging gets its own connection, told apart by ALPN. The full specification is `docs/protocol.md`.

#### TLS and pinning

- TLS 1.3 only for every agent, relay and splice connection. Bootstrap downloads also accept TLS 1.2, because Windows 10, Server 2016 and Server 2019 cannot do TLS 1.3 and the console one-liner uses the host's own stack (review D108).
- Self-signed ECDSA P-256 certificates. Verification is replaced by a check of the peer's public-key hash against the pinned value, with dates ignored.
- The controller pins each agent's key at enrollment. Agents and relays pin the controller's key from their bootstrap config.
- The TLS handshake runs in a per-connection goroutine with a pending-handshake cap and a short deadline, never in the accept loop [CR §3.3] (review D109). Go's `tls.NewListener` defers the handshake: call `HandshakeContext` before reading the negotiated ALPN (repo `AGENTS.md`).
- One listener on the controller, `agent_port`, serves every connection type. The ALPN value picks the handler (review D110, D111, D113):

| ALPN | Opened by | Purpose |
| --- | --- | --- |
| `phylax/agent` | Agent (direct or spliced), including the Kali | All agent messaging |
| `phylax/relay` | Relay | The relay's control connection |
| `phylax/splice` | Relay | One device-proxy or bootstrap stream |
| None, or `http/1.1` | A host being bootstrapped from the console | Download of the agent binary and a bootstrap config bound to a one-time token. Serves only these downloads. |

The operator UI is not on this listener. Four connection types on one port is still one listener and one firewall rule, and each handler is small.

#### Framing

- Each message is a 4-byte length, a type byte (bit `0x40` flags compression) and a JSON body. Batches of events are compressed with zstd (pure Go) with a hard decoder memory cap and a size check before decompression [CR §3.6] (review D114).
- **JSON over protobuf, deliberately:** readable under pressure, no code generation.
- Maximum message size: 4 MB. Anything larger (pcap slices, files, binaries, depot blobs) moves as content-addressed 256 KB chunks, resumable, with `chunk_have` for resume (review D115).
- Every connection has read and write deadlines and TCP keepalive. Send queues are bounded per priority. Handlers run off the receive loop so a slow handler cannot stall acknowledgments or `control` messages (review D116).

#### Messages

| Direction | Message | Notes |
| --- | --- | --- |
| Agent → controller | `hello` | Host id, agent version and protocol minor, roles, capabilities block with module manifests, last sequence, dead-man entries of plan nodes, token if not yet enrolled |
| Controller → agent | `welcome` | Confirms enrollment; the first signed `config` follows |
| Agent → controller | `heartbeat` | Every 5 s: sequence, host clock, spool depth and congestion state, safe mode, shed count, per-module health, config status |
| Agent → controller | `events` | Batch of events, each with its sequence number |
| Agent → controller | `step_result` | Per-phase outcome with before and after state, signed result kept for resend |
| Both | `chunk`, `chunk_have` | Content-addressed transfers: evidence, pcap slices and collected files up; step payloads, depot blobs, ledger files and the agent binary down |
| Controller → agent | `ack` | Highest contiguous sequence stored (after the store commit) |
| Controller → agent | `step` | A signed plan step |
| Controller → agent | `config` | Signed `AgentConfig`: module blocks, rules, ledger references, budgets |
| Controller → agent | `fetch` | Request for a pcap slice, a file, a depot blob or raw telemetry |
| Controller → agent | `control` | Signed: safe mode, freeze capture, dead-man confirm, step status |
| Relay ↔ controller | `relay_request` | Device-proxy and bootstrap splice requests on the relay control connection |
| Controller → agent | `token_issue` | Re-enrollment token delivery where needed |

**The agent `fetch` handler is a no-op today** (`internal/agent/handlers.go:41`; Known bugs). Depot pulls, ledger delivery, package installs from the depot and pcap slices all depend on it, so implementing it is a core task (review D117-D119): the agent answers `fetch` by streaming the requested object as chunks at bulk priority, bounded by the per-agent fetch cap, and the controller pushes depot blobs the same way in reverse.

#### Priority

The sender drains its queues in strict order, and every message is sent at its real priority (review D120):

1. Heartbeats, alerts, acknowledgments and dead-man confirmations
2. Plan steps and step results
3. Evidence attached to alerts
4. Transactions and flows
5. Other telemetry
6. Bulk transfers (pcap slices, files, binaries, depot blobs), shaped by a token bucket

#### Reliability

- **Spool and acknowledge** (review D121). Every event has a per-host sequence number. The agent resends from the last acknowledged sequence after every reconnect, and the controller discards duplicates.
- **Reconnect** with jittered backoff from 1 s to 30 s, round-robin over the bootstrap's controller list (review D122).
- **Per-agent limits** on message rate, bytes per minute and concurrent fetches (review D123). SQLite writes are batched in transactions.
- **Congestion states** reported to the controller: warning at 90% of the spool cap, full, flood, recovered at 70% [OA §5.8] (review D124).
- **Reorder buffer with gap records** (review D125): the controller's per-agent reorder buffer understands spool gap records (a gap covers `from..to`, so plain contiguous-sequence tracking would stall), and acks only after the store commit. `welcome` and `ack` carry no epoch or hash; the epoch travels in the signed config and steps (docs/protocol.md §6, §9).

#### Signed agent config

The signed config is the typed `AgentConfig` (`internal/plan/agentconfig.go`, docs/protocol.md §8a; review D126), generated per host by the controller from the manifest and rules, signed with the plan key, host-bound and replay-protected by a durable `(epoch, version)` mark on the agent. Versions move only when a host's content changes. It carries `roles`, `modules` (one block per agent module, nil means off), and `budgets`. The agent persists the last good config and runs it on restart without a controller; modules start, stop and reconfigure through the factory registry.

#### The spool

The spool is segment files, not one file [CR §3.10, OA §5.8] (review D129-D134, built in `internal/spool`):

- Append-only segments of 4 to 16 MB holding length-prefixed, CRC-checked frames. `fsync` on a bounded interval and immediately for alert-class events. A small index file holds the chain head and last-acknowledged sequence.
- **Startup repair:** scan the last segment and truncate to the last valid frame, so a torn write never bricks the agent.
- **Acknowledgment-driven deletion** of whole segments below the controller's cumulative ack, oldest first and only when space is needed, so a restored controller can ask for acknowledged data again. The chain head is persisted before any deletion.
- **Shedding is admission control, not segment deletion.** The controller store accepts each agent's chain only in contiguous sequence order, so the spool is one sequence-ordered log and transport reads it in order; priority acts at admission. Each class may fill unacknowledged space only up to its limit (critical 97%, high 90%, normal 75%, bulk 50% of the cap). An event over its class limit is not stored: it consumes its sequence number, and one **gap record** (`kind: spool.gap`, fields `from`, `to`, `count`, `class` ∈ {critical, high, normal, bulk, mixed, unknown}; `seq = to+1`; `PrevHash` bridges to the last stored event) announces the dropped run before the next stored event. History is never rewritten, and bulk can never crowd out alerts. A crash that loses a mid-log tail is reconciled at restart with a `class: unknown` gap up to the recorded head, so no sequence number is reused. Gap records are hash-chained, not separately signed. Shed order within a class: raw log lines, connection churn, flows on unscored ports.
- **Bounded RAM:** a small write buffer and an in-memory index only.
- Collection is decoupled from transport: modules write through a bounded queue, and a down link never blocks sensors or local response.
- Crash tests (kill -9 at random points, disk full, clock jumps) are a gate (Testing).

#### Volume and envelope

- **Shipped continuously:** alerts, heartbeats, process starts, connection changes, file changes on watched paths, selected log lines, flows, protocol transactions on scored ports, denied-egress attempts, decoy sightings, ledger verdicts (review D127).
- **Kept on the host until fetched:** the packet ring, raw sampler output, full log files.
- **Design envelope** (review D128): outages of up to 60 s on any link; event-to-controller latency of 10 s or less while the link is up. These size buffers and timeouts; they are budget targets, not competition time goals.

### Enrollment, bootstrap and recovery

The controller gets its binaries from a signed release. Before any agent exists, the team rotates admin and service credentials from the consoles (the T+0 console phase). Then the controller installs agents over SSH on Linux, over WinRM on Windows servers, and by a typed console one-liner as break-glass. Each install enrolls with a one-time token. A new reservation resets everything, so bulk re-enrollment is a first-class path. The controller itself can be restored from an encrypted snapshot kept on another host.

#### Getting binaries into the environment

1. **CI builds and signs** a release: static binaries for linux/amd64 and windows/amd64, rules and other content, YARA rules, ledger indexes, the cache index, and the pinned hash of the tested Sysmon release. Signed with an Ed25519 key that never enters the competition environment (review D135).
2. **The first binary.** The platform driver downloads `phylax` for the controller host from the GitHub release (kept small because the link is slow) and verifies it with `ssh-keygen -Y verify` (review D136). The public key to verify against is printed on the driver's checklist.
3. **`phylax init`** downloads the rest of the release, verifies it against the key compiled into `phylax`, then starts `phylax cache sync` in the background (review D19).
4. **Fallbacks,** in order: the same signed artifacts committed under `dist/`, then a build from vendored source with a Go toolchain (review D137).
5. **`phylax init` reports which channel worked** and how fast.

#### The T+0 console phase

T+0 is a console phase, not an agent phase (cross-cutting idea 5; review N7.4, A1.Q3). Team-pack admin passwords leak within seconds (a full domain dump about 10 s after drop flag at Nationals, cleartext about 20 s; decision 10), and red sprays defaults at once [[discord-2026q-rt-debrief#e1]]: 18 default-credential shells in 2026 [[how-to-win-ccdc-dealing-with-red-team]]. So before enrollment, on the consoles:

1. **Admin and service credential rotation, by hand.** Every host's `sysadmin`, root and local Administrator, the domain admins and service accounts, the Palo `admin` and VyOS `vyos` accounts. No admin accounts are scored (decision 10), so admins rotate freely. Scored users are not touched. The new values are generated by Phylax from the vault once the controller is up, or from the printed T+0 sheet when it is not yet; either way the operator enters them in the vault so first contact can use them.
2. **Zerologon first on the DC** if the build is unpatched: build check, secure channel enforcement, Spooler off, SMBv1 off, before any domain rotation (the `hardening` module, `dc.zerologon_first`; review D523, D425). Red had AD through Zerologon right away [[discord-2026q-rt-debrief#e10]]; only 2 teams mitigated it in 2025 [[2025-minnesota-and-indiana-ccdc-debrief#e2]].
3. **Network devices:** Palo management lockdown (additive), the Kali-to-controller rule and static NAT, VyOS snapshot then admin rotation.

Phylax's first job afterwards is to record what was done (operators tick the T+0 steps in the host x step grid; UI shell) and, once agents arrive, to evict sessions that predate the rotation (Execution engine: session eviction). The checklist for this phase is rendered from the manifest and printed in advance, since the UI may not be up yet.

#### First contact

| Method | When | How |
| --- | --- | --- |
| SSH push (preferred on Linux) | Linux hosts, reachable from the controller, with the rotated admin credentials | Built-in Go SSH client (review D138). Details below. |
| WinRM | Windows servers with WinRM enabled (Server 2019 and 2022 by default) | Built-in Go WinRM client with NTLM and message encryption, reusing `internal/checks/ntlm.go` and `winrm.go`. Basic auth and `AllowUnencrypted` are never used (review D139, A1.Q2: build the WinRM client; no SMB-drop variant). |
| Console one-liner | Windows 11 (no WinRM by default), the Kali, Windows hosts that expose only OpenSSH, anything unreachable, and break-glass | Typed on the NETLAB console. ASCII only, short, no assumption that paste works. Downloads the binary and bootstrap config over the bootstrap connection type, checks the hash, installs (review D140). |

**The SSH push** is built from peers' working parts (COAL `coordinate-root/ssher.go@6ffc1f5`, Stanford `bootstrap/geist.sh@9485770`, UCI ember `core/ssh.go`@f2af5a1), taking only their fan-out and verify steps:

- A shell-sentinel probe confirms a usable shell; hosts with broken SSH go on a list with the next step named.
- The binary and bootstrap are uploaded base64 over stdin (no partial file on disk), with an SFTP fallback, to the randomised path; the service is installed and started.
- A banner check routes Windows OpenSSH to the console one-liner.
- A hostname check compares the host's name with the manifest entry and stops on a mismatch.
- Failures fall into a fixed set of classes (auth refused, no shell, no space, SELinux denial, timeout, hostname mismatch), and each class names its next step in the UI.
- Fan-out across hosts with a 30 s per-host timeout; success is verified by a fresh login and the agent's first heartbeat.
- Host keys are recorded at first contact and checked on later contacts. Password SSH is used only because it is what the hosts allow at T+0; hardening later follows the manifest.
- An optional single-session variant (install, rotate admin, verify by fresh login, kill old sessions) is not the default, because T+0 rotation is done by hand on the consoles (A1.Q3).

The one-liner carries two pins: the controller's public-key hash (`curl --pinnedpubkey`, or a validation callback in PowerShell, which also enables TLS 1.2 on older builds) and the download's hash. The UI generates the full command for each host [SP §A18].

**Bootstrap config contents** (review D141): the controller addresses and port, the controller key pin, the host's manifest identity, the randomised install parameters, the plan-signing public key, a one-time enrollment token that expires after 10 minutes, and the initial roles.

#### Enrollment

1. The UI mints a token bound to a host identity. Only a logged-in operator can do this (review D142).
2. The agent generates its keypair and connects with `phylax/agent`, presenting the token.
3. The controller records the key, binds the token to that key and replies `welcome`. The agent persists its `enrolled` flag only after `welcome`. Until then the same key may re-present the same token, so a dropped connection never wedges enrollment [CR §3.7].
4. Token consumption is atomic. A wrong-host claim does not burn a token.
5. Host identity is the manifest name plus the enrolled key, never an IP address (review D143).

#### After enrollment

SSH, WinRM and RDP are treated like any other service. If the manifest does not declare them for a host, hardening disables them, with the console as break-glass (review D144). On 2027 hosts the manifest declares SSH on the Linux hosts, WinRM on the AD host and RDP on the MSSQL host, because they are scored. Session eviction runs for every account rotated at T+0 as soon as the host's agent is up.

#### Re-enrollment after a reset

- A per-VM reset does not exist in 2027. A new reservation resets all hosts, so the UI offers **Re-enroll all**: it revokes every old key, issues fresh tokens and runs first contact again in dependency order, after the T+0 console phase is repeated on the new hosts (review D145).
- Every rotated credential is marked `reverted` per (account, credlist), and the hardening plans run again from zero. Every action is idempotent.
- **Quotient re-sync.** Quotient does not know about reverts: after a revert the host has the old passwords and Quotient keeps the new ones. Each reverted scored credential is either re-applied on the host or a PCR back to the old value is generated, per credlist, and the host's scored changes are blocked until it is resolved (the `creds` module, review N7.3).
- A host reset in a variant event restores its default credentials and, for the DC, rolls back every domain change. The domain credentials are marked reverted and the AD plans re-run.
- A new key claiming to be an existing host is always an alert until an operator approves it (review D146).
- After any restore or re-enrollment the prebake hunt and the ledger sweep run automatically, and the host cannot be tagged golden until both are clean [COV X-2].

#### Changing the controller address

If the address changes, run `phylax set-controller <address:port>` on each affected host's console (review D24). The Palo NAT target for the Kali path is updated by hand. Nothing is automatic.

#### Controller recovery

**State snapshot** (review D147). Every 15 minutes, and after every enrollment, plan completion and vault change, `phylax serve` writes an encrypted snapshot to each backup target in the manifest. It holds state, not event data (target: under 10 MB): the controller's keys, enrolled agent keys with their last acknowledged sequence and chain hash, the manifest and overrides, the vault, plans and node status, active checks, the honeytoken registry, ledger overrides and incidents without bulk evidence. It is encrypted with a key derived from the operator passphrase (`age`, scrypt mode). Built in `store/backup.go` and `vault`.

**Restore starts a new epoch** (review D148). Install `phylax` on the replacement machine, fetch the latest snapshot, unlock it and start. The restored controller raises the epoch, so agents accept steps in the higher epoch despite sequence numbers the lost controller used after the snapshot. After a restore the controller asks each agent to resend everything its spool still holds, verifies that the chain passes through the snapshot's recorded sequence and hash, and marks anything missing as a gap with the reason "controller restored". The resend verification is not finished; it is a core task.

**Restart safety** (review D149). After any restart the controller accepts and stores agent traffic immediately. Plan signing and secret access stay locked until the passphrase is entered. Packet captures, evidence files and the cache are not in the snapshot; golden service backups are copied once to the backup targets.

### Execution engine

All change goes through plans. A plan is a DAG whose nodes are typed actions on specific hosts or devices, with dependency edges and optional approval gates. Every plan shows a dry-run diff and a scoring-safety lint result before anything runs. Lockout-risk actions roll themselves back on the agent if it cannot confirm. The engine is core (`internal/plan`, `internal/actions`, `internal/deadman`, `internal/agent/exec.go`, `internal/controller/plans.go`); modules contribute actions and plan content.

#### The action contract

An action is Go code in the agent (or a device adapter on the controller) with four parts: **check** (is it already done, and what would change?), **apply**, **verify** and **rollback** (review D150). Each action declares a parameter schema, a risk class (`none`, `service`, `lockout`, `destructive`), the resources it locks and the **scorer-visible properties it touches** (for the lint). The framework is built:

```go
// package actions (built)
type Action interface {
	Spec() Spec                                              // name, parameter schema, risk class, platforms
	Locks(p Params) []string                                 // named per-host resources
	Touches(p Params) []Touch                                // scorer-visible properties, for the scoring guard
	Plan(ctx context.Context, env *Env, p Params) (Plan, error)        // read-only check and dry-run diff
	Capture(ctx context.Context, env *Env, p Params) (Rollback, error) // undo data, taken under the locks before Apply
	Apply(ctx context.Context, env *Env, p Params) (Output, error)
	Verify(ctx context.Context, env *Env, p Params) error             // post-condition
}
```

A module that owns an action family registers it from its package (`actions.Register`), and lists it in its manifest's `Actions`. The executor runs steps off the receive loop (8 at once; excess is answered `failed`), under the locks, inside the dead-man window from the step, and rolls back by itself on an apply or verify failure (review D69).

#### Action families

The core owns the general families that many modules' plans use. Module-owned families are listed for completeness and specified in their module sections.

| Family | Actions | Linux | Windows | Owner |
| --- | --- | --- | --- | --- |
| Files | `file.write`, `file.template`, `file.perms`, `file.quarantine`, `file.restore`, `file.hash`, `file.attr` (clear or set immutable), `dir.snapshot` | Native; atomic temp-and-rename that copies mode, owner, xattrs and SELinux label; `validate` hook | Native | core (review D151) |
| Local accounts | `user.set_password`, `user.lock`, `user.create`, `user.delete`, `group.members`, `ssh.authorized_keys`, `session.terminate_predating` | Edit `/etc/shadow` and friends under the shadow-utils lock (`lckpwdf`), atomically, preserving aging fields and labels; SHA-512 crypt; clears and restores `chattr +i` on `/etc/shadow` and `/etc/passwd` | `NetUserSetInfo`, `NetLocalGroup*`, WTS session APIs | core (review D152, N3.1, N3.3) |
| Services | `service.state`, `service.config` | systemd over D-Bus; `validate` hook on config | Service control manager APIs | core (review D154) |
| Registry | `reg.set`, `reg.delete`, `reg.snapshot` | — | Native registry API | core (review D158) |
| Kernel and system | `sysctl.set`, `module.block`, `hosts.file`, `selinux.restore` | `/proc/sys`, modprobe config | — | core (review D157). The unused `modules.disable_loading` action is deleted. `module.block` verify is fixed (Known bugs). |
| Persistence cleanup | `cron.disable`, `unit.disable`, `unit.mask`, `task.disable`, `wmi.subscription_remove`, `runkey.remove`, `ld_preload.clear`, `caps.clear`, `pkg.unhold` | Native file edits, D-Bus | Task Scheduler and WMI through COM; registry | core (review D159). Every hunt finding ends here; disable and quarantine, never delete. |
| Processes | `proc.kill_tree` (pidfd plus start-time check; `cgroup.kill` for units), `proc.suspend`, `proc.dump` | Signals, cgroup freeze, `/proc/<pid>/mem` | `TerminateProcess`; `MiniDumpWriteDump` | core (review D160). Collected samples and dumps are defanged (ELF or PE magic zeroed) so a stored sample cannot execute or trip AV. |
| Logging | `audit.rules`, `audit.immutable`, `auditpol.set`, `eventlog.size`, `sysmon.install`, `sysmon.config` | Kernel audit over netlink | Native audit-policy API; `sysmon.install` uses `host.exec` | core (review D161) |
| Databases | `mysql.exec`, `mysql.set_password`, `mysql.dump`, `mssql.exec` (read-mostly), `mssql.set_password` | Go MySQL driver | `go-mssqldb` over TCP or shared memory | core (review D162) |
| Collection | `collect.files`, `collect.inventory`, `hunt.baseline_diff`, `hunt.persistence`, `hunt.ad`, `probe.run`, `yara.scan` | Native, except `yara.scan` (pinned YARA-X) | Same | core (review D166); probes and hunt checks are owned by `inventory` and `hunt` |
| Agent | `agent.replace_binary`, `agent.config`, `agent.set_controller`, `agent.safe_mode`, `agent.rename` | Native | Native | core (review D169) |
| Escape hatch | `host.exec` | Approval required (or pinned pre-approval); labeled everywhere | Same | core (review D85) |
| Firewall | `fw.apply`, `fw.snapshot`, `fw.restore`, `fw.quarantine` | `google/nftables` over netlink | Windows Firewall through COM | `firewall` |
| Domain | `ad.*`, `ldap.modify`, `ad.krbtgt_reset`, `ad.netlogon_enforce`, `ad.gpo_*`, `service.sddl_reset` | — | DC agent | `ad` |
| Integrity | `ledger.sweep`, `ledger.verify_pin`, `binary.restore_from_depot` | Native | Native | `integrity` |
| Packages | `pkg.install`, `pkg.upgrade`, `pkg.reinstall`, `pkg.repair`, `pkg.fetch_to_depot` | From the depot over `fetch` | Windows Update Agent COM | `depot` |
| Backups | service dumps and restores | Services' own dump tools as labeled actions | Same | `backup` |
| Credentials | `pcr.generate`, `pcr.verify` | — | — | `creds` |
| Integrations | `wazuh.deploy`, `wazuh.health`, `splunk.hec_setup`, `suricata.analyze_pcap` | Pinned installers from the cache | Same | `wazuh`, `splunk`, `suricata` |
| Devices | `palo.apply`, `palo.commit`, `palo.snapshot`, `palo.revert`, `vyos.apply`, `device.rotate_admin` | Controller-side adapters | — | `devices` |

**SELinux** (review D171). Rocky 9 runs SELinux enforcing. File actions write a temporary file and rename it into place, so the new file would get its directory's default label, which is wrong for files such as `/etc/shadow` (`shadow_t`). File actions copy the original file's label (or use the policy default for new files) before the rename and check it in verify. The agent's install path gets a `bin_t` label so systemd runs it unconfined. Unit tests run against SELinux-enforcing images.

**Windows COM and WMI** (review D86): built in Go, with a `host.exec` fallback per action recorded in the complexity register.

#### The `validate` hook

`file.write`, `file.template` and `service.config` take an optional typed validator that runs on the temporary file before the atomic rename (review N3.4, cross-cutting idea 14). A validator failure aborts the node before anything changes. Validators: `sshd -t -f %s`, `visudo -cf %s`, `apachectl -t` or `httpd -t` with the candidate config, `nginx -t -c %s`, `named-checkconf %s`, `postfix check` against a staged config directory, `php -l %s`, `nft -c -f %s`. A bad config that the scoring lint cannot see is a full outage, and this is the check Ansible gets for free (`ansible-ccdc roles/ssh_hardening/tasks/sshd_config.yml@51b4ae4`). Validators are pre-approved, hash-pinned host tools (they are the services' own binaries; the ledger judges them). Pairs with the dead-man.

#### `host.exec`

Needed for the unforeseen (review D85). It runs a binary on the host, needs its own approval record and is labeled "runs a host binary" everywhere. Pre-approved, hash-pinned tools may run without a per-node approval: package managers installing from the depot, the Sysmon installer, YARA-X, the validators above, the services' own dump tools in backup actions, and `nmap` and `xfreerdp` on the Kali. Every default-plan use of `host.exec` has a complexity-register line.

#### Session eviction

A password change does not end existing SSH, WinRM, SMB or RDP sessions, so every rotation and every block ends with session eviction (review N3.1): `session.terminate_predating{account | source, before}` plus a post-rotation check for sessions older than the rotation. Without it the T+0 rotation leaves red in.

The rule for which sessions are evicted (review A3.Q1, final):

- **Admin and service accounts:** plain eviction of every session that began before the rotation.
- **Scored accounts:** a failed scored check is unacceptable, so automatic eviction applies only to sessions that (a) began before the rotation, (b) have outlived the **measured round delay** (Quotient enforces `Timeout < Delay − Jitter`, so a session that old is not a scorer check in flight), and (c) are not scorer-labeled by the traffic labels. Until a round delay has been measured, scored-account eviction is flag-only. Any session that cannot be classified is flagged, never killed. Eviction on scored accounts runs inside the quiet window right after the host change.

#### The scoring-safety lint

Every plan node declares which scorer-visible properties it touches. The lint rejects a plan, at template time and at run time on the agent (`actions/guard.go`, `guard_manifest.go`, `linux_lint.go`), if a node matches a rule below [SH never-list] (review D172-D176). The rules are content: the guard's data is rendered per host from the manifest (`phylax guard <host>`), and never-block lists derive from the manifest's scored services, never from hard-coded ports (review area 7 lint correction).

| Rule | Rejects |
| --- | --- |
| No lockout machinery on any scored account | `pam_faillock`, fail2ban, sshguard, Windows lockout GPO, SQL `CHECK_POLICY` lockout, tighter Splunk lockout |
| No SSH change that breaks the scorer's login | `PasswordAuthentication no`, `PermitTTY no`, `ForceCommand`, `nologin` or `rbash` shells for scored users, `AllowUsers` that omits a scored user, slow profile scripts, any `authorized_keys` edit for a scored user (Quotient's SSH check can use a private key [[dbaseqp-quotient-9000379b7d#e10]]; SEMO's `master-ubuntu-ecom.sh` deletes every `authorized_keys`, which is the class of change this catches) |
| No mail change that refuses plaintext | STARTTLS required, `disable_plaintext_auth=yes`, `smtpd_tls_auth_only`, reject-on-unknown-sender checks, postscreen on 25 |
| **Never narrow sources on a scored port** | Any host, Palo or VyOS rule that restricts a scored port to a source allowlist, including log-first and shadow stages. Scored inbound is allow-any-source. Blocking a known red-team address or CIDR on a scored port is allowed; a CIDR block carries a warning because red scanners re-address after every run (decision 13, review area 3 answer) |
| Management-port blocks stay on management ports | A Windows stage-0 block of management ports from outside the declared team subnets never includes a scored port (review D202) |
| ICMP echo stays | No ICMP drop, `icmp_echo_ignore_all=1`, zone protection that drops ping |
| Scored UDP services stay open | When TFTP (69) or NTP (123) is a scored service in the manifest, nothing blocks it; otherwise default-deny applies as usual |
| NTLM and its transport stay | No NTLM deny, no `LmCompatibilityLevel` below 3 for the scored paths, no Protected Users for scored accounts, no required encryption the scorer cannot do (SMB encrypt, WinRM `AllowUnencrypted=false` on 5985, FTPS-only, MSSQL ForceEncryption) without a scorer-mimic pass |
| Anonymous FTP stays where the FTP check uses it | Disabling anonymous FTP on a scored FTP service |
| Scored content is untouched | Web pages with regexes, SMB SOP files, FTP files, DNS A records, the Splunk data and the SQL table the checks read |
| No kill of a scored service as a response | Downtime scores zero and repeated failures trigger an SLA penalty |
| Scored passwords change only through the PCR transaction | A scored-account password change on the host alone (review D432; the `creds` module) |
| No exec-from-temp lockdown that a scored service needs | A `noexec` remount of `/tmp`, `/dev/shm` or `/var/tmp` when a scored service's processes exec from there (review N5.7, the `hardening` module) |

Where an organizer-set "insecure" value is the reason the scorer works, the pre-change baseline snapshot says so [SH intro]. The verdict table for each service in `ccdc-private/research/topics/scoring-safe-hardening.md` is the source of the rule data.

#### The scorer-mimic probe

Each node that touches a learned service runs the **scorer-mimic probe** for that service before and after (review D177). A probe reproduces Quotient's exact transport for one service (the probe library is the `checks` module). It uses two different scored users, chosen per credlist so each list the service draws from is exercised. A failed "after" probe rolls the node back. A failed "before" probe stops the node: the service is already down and the change would hide the cause. Probes are bounded (one retry after 5 s, then fail) so a flapping service cannot hold a plan open.

#### Plans

A plan is YAML: a list of nodes with an action, a target, parameters, dependencies and options (review D178). Plans are templates that select targets from the manifest, so one "harden every Linux web server" template expands to concrete per-host nodes. A target is a host name, a service name, or a label expression (review N1.4, cross-cutting idea 12): `target: {labels: "linux && !workstation"}`. The UI and CLI accept short selectors (an alias prefix, or `.30` for the host whose address ends in `.30`).

```yaml
plan: harden-rocky-ecom
module: hardening
nodes:
  baseline:  { action: collect.inventory, target: rocky-ecom }
  fw_shadow: { action: fw.apply, target: rocky-ecom, params: { mode: shadow }, needs: [baseline] }
  review_fw: { gate: approval, needs: [fw_shadow], note: "Check would-be drops before enforcing" }
  fw_enf:    { action: fw.apply, target: rocky-ecom, params: { mode: enforce }, needs: [review_fw], deadman: 90s }
  php:       { action: file.template, target: rocky-ecom, params: { path: /etc/php.d/99-phylax.ini, validate: php_lint } }
  oc_admin:  { action: mysql.exec, target: rocky-ecom, params: { op: rotate_admin_row } }
  reload:    { action: service.state, target: rocky-ecom, params: { unit: httpd.service, state: reloaded }, needs: [php] }
  verify:    { action: health.check, target: ecom-http, needs: [reload, fw_enf], probe: scorer_mimic }
on_failure: stop_dependents     # or: continue | rollback_plan
```

The UI shows plans as a DAG (a table with `needs` edges today; docs/ui.md), coloring each node live. Branches run in parallel (review D184). A gate pauses its dependents. The health check runs only when everything it depends on is done. Plan templates live in `plans/<module>/` as `plans/<name>.yml|yaml` (unknown fields are an error; the file is capped at 256 KiB).

#### Plan, approve, apply

1. **Plan.** The controller expands the template and sends every node's **check** to its agent. Each check reports what it would change (review D182).
2. **Diff and lint.** The UI shows each node: unchanged, will change (with a readable diff, secrets redacted), blocked by a lock, or rejected by the scoring-safety lint.
3. **Approve.** One click approves the whole plan. Approval gates pause execution at that node. `host.exec`, `destructive` and `lockout` nodes always need their own approval record, which the plan engine enforces and the signature covers (review D183). **Every approval records the approver's name**, including a verbal tier-2 approval given by a captain who is off the keyboard: the driver enters "approved by <name>" and the record carries both the driver's login and the named approver [[how-to-win-ccdc-team-dynamics#e1]].
4. **Apply.** Nodes run as soon as their dependencies finish, in parallel across hosts and within a host where locks allow.
5. **On failure** the plan's policy decides (review D179): stop the failed node's dependents (default), continue, or roll back the whole plan in reverse order. Only `rollback_plan` plans give their nodes the rollback window that makes agents keep rollback data.

**Grouped multi-host results** (cross-cutting idea 15). A node that ran on many hosts shows its results grouped: identical outputs collapse ("14 same, 2 differ"), outliers first, with per-host status. The host x step grid uses the same grouping.

#### Dead-man switch

For any node marked `deadman` (the default for `lockout`-class actions) the **agent** runs the whole protocol [CR §2 dead-man] (review D185, built in `internal/deadman`):

1. Before applying, the agent snapshots the affected state, writes an **armed record** to its journal (node id, snapshot reference, deadline) and arms a timer, default 90 s. Alongside the in-process timer it arms an **OS-level one-shot timer** (a transient systemd timer on Linux, a scheduled task on Windows) that runs `phylax agent rollback <id>`. That timer fires even if the agent crashes or is killed mid-window.
2. After applying, it opens a **fresh connection** to its controller or relay and completes a handshake.
3. If that works, the controller sends a signed `control: deadman_confirm` and the agent disarms both timers and deletes the armed record. If not, the agent rolls back on its own when the timer fires and reports the rollback once reconnected. On start-up, an expired armed record triggers a rollback before anything else.
4. **Hosts that carry other links** (review D186). On a relay host, or on the controller host, a change can cut off every agent behind it while the host's own link stays up. For a `deadman` node there, the controller also asks dependent agents (one behind each relay, or one on the LAN and the Kali for the controller) to open fresh connections, and confirms only if those succeed.

There is no SSH involved, so the dead-man covers the agent's own link, which is the link that matters. Safe mode never prevents a rollback. **Known gap:** a dead-man that fires while the agent is still connected is not reconciled on the controller until the next reconnect (docs/controller.md); the fix is to send the `agent.deadman_fired` event at critical priority and have the controller mark the node rolled back on receipt (Known bugs).

#### Locks

Each host has named resource locks: `firewall`, `accounts`, `sshd`, `packages`, `audit`, and one per service (review D187). Plan nodes and tier-0 responses take the same locks, by the same names. While a plan node holds `firewall`, automatic firewall restores on that host wait. A node holds its locks only while it runs, not while the plan waits at a gate. Each successful node updates the host's declared state, so a tier-0 restore during a gate restores what the plan has applied so far.

#### Safe mode

One switch in the UI sends a signed `control: safe_mode` to every agent (review D188, `actions/safemode.go`). It suspends tier-0 responses and any running plan applies; checks and rollbacks still work. Detection and collection keep running. Steps run off the receive loop, so the control message is never stuck behind a long apply. Agents stay in safe mode across restarts until told otherwise (`<state>/safe_mode`). Safe mode pairs with the rule engine's global `override_mode: alert`.

#### Tagging and adoption

- Everything an action creates (firewall rules, units, tasks, accounts, files) is tagged with the plan id, so detection can tell our changes from anyone else's (review D189).
- **The tag reaches every event type** through the envelope's `Tag` field (review D190). `process_start` events from a plan step, account-change events, `chattr`, `auditctl`, `useradd`, package-manager runs and patch or work-window runs all carry the plan or window tag. Rules exempt tagged events instead of guessing from process names. This is how our own hardening, which runs `chattr +i`, `auditctl -D`, firewall commits and Defender exclusions, produces no untagged alerts [DR §3, PR E6].
- **Work windows:** a `phylax claim <host>` from the team feed opens a tagged window for hand work (the `teamfeed` module).
- Changes made by hand during an inject are flagged as drift. An operator either adopts them into the manifest overrides with one click, or reverts them (Manifest: drift).

#### Audit trail

Every action, automatic or manual, writes an event: what triggered it, before and after state, the undo, the approver, and the health result afterwards (review D355). This is the containment section of every IR report, and the answer when the White Team asks why something changed. UI requests are also audited before the handler runs (`ui.Server.Handle`; a request is refused if the audit write fails).

### Manifest

The manifest is a set of YAML files, validated against a JSON Schema in CI and again when `phylax serve` loads it (review D192, D193). It is the only place infra facts live. Plans, agent configs, firewall rules, checks, decoys and generated artifacts are all produced from it. Changes made during the competition, including facts learned or entered at runtime, are written by the UI into `overrides.yml`, never into the base files. Implementation notes: `docs/manifest.md`, `internal/manifest`.

#### Files

| File | Declares |
| --- | --- |
| `topology.yml` | Controller host and ports, segments, relays, NAT mappings, the Kali path, backup targets (review D42) |
| `hosts.yml` | Hosts: segment, internal and public address, OS, default credentials reference, roles, `labels`, `modules` (enable or disable per host), `domain_member` (the DC a host joins), `rpc_range` (the DC's pinned RPC range) (review D43, N1.4) |
| `services.yml` | Services: kind, scored flag, listeners, `runtime` (`host`, `docker` or `podman`), process identity and binary pins, content roots, data, dependencies, health checks, transport (review D194, N7.6) |
| `accounts.yml` | Managed accounts: scope, scored flag, `credlists` (a list: one account can sit on several Quotient lists), rotation policy, files that embed them (review D195) |
| `scorer.yml` | The scorer: engine (`quotient`), team Identifier scheme, known or estimated Delay, Jitter, Timeout, SLA threshold and accrual (`reset` or `per_round`, phase schedule), credlist names as learned or entered (review D196) |
| `devices.yml` | Network devices: vendor, management address, segment, adapter, which relay proxies them (review D197) |
| `decoys.yml` | Decoys and honeytokens per host (the `decoys` and `honeytokens` modules' config) |
| `integrations.yml` | Opt-in sensors: Wazuh, Suricata, Zeek, Splunk HEC, with pinned versions and hosts (review D199) |
| `modules/<name>.yml` | One config block per module. Replaces v3's catch-all `policy.yml` sections (review D200). Response tiers, protected processes, retention, limits and depot priorities live in their owning modules' blocks. |
| `overrides.yml` | Competition-day changes from the UI: adopted drift, inject changes, accepted findings, suppression records, runtime facts (team number, learned scored accounts and credlists, measured scorer timing) (review D201) |

Secrets never appear in the manifest. It refers to them by name (`secret: ecom.db`), and values live in the controller's vault.

**`runtime: docker or podman`** (review N7.6). The 2026 regional ecom was OpenCart 4.1.0.4 in Docker [[bcom12t]], [[2026-mw-regional-scorecard-t7-services#e11]], and containerizing on the same platform is allowed [[2027-mw-invitational-packet#e29]]. A containerized service declares its container name or image, its published-port listeners (the host listener is `docker-proxy` or the netfilter DNAT, not the service binary), process and ledger pins resolved inside the container's mount namespace, and volumes as content roots. Telemetry, integrity and checks modules read these fields; how each handles containers is in its section. The 2027 stack is unverified. Kubernetes manifest backup is designed only if Kubernetes appears in a packet (UCI `linux-toolbox/k8solver.sh`@f2af5a1 is the reference).

#### Examples

```yaml
# services.yml (2027 reference, excerpt)
services:
  ecom-http:
    host: rocky-ecom
    kind: http
    scored: true
    runtime: host                        # or docker: { container: opencart, image: ... }
    listen: [{ proto: tcp, port: 80 }, { proto: tcp, port: 443 }]
    process: { unit: httpd.service, binaries: [/usr/sbin/httpd], pin: true }
    transport: { plaintext: true, tls_verify: false }
    content:
      roots: [/var/www/html]
      upload_dirs: [/var/www/html/image/catalog]
      normalize: [opencart_token, csrf, session_cookie, timestamps]
      guard: [/var/www/html/index.php]   # content_guard: files restored from golden, opt-in per service
    data: [{ kind: mysql, database: opencart }]
    outbound: none                       # feeds rule D4b (relay or proxy behaviour)
    health: [{ http_get: "/", expect_status: 200, track_content: true }]
  ecom-ssh:
    host: rocky-ecom
    kind: ssh
    scored: true                         # SSH is scored on the Linux hosts: never disabled
    listen: [{ proto: tcp, port: 22 }]
    process: { unit: sshd.service, binaries: [/usr/sbin/sshd], pin: true }
    transport: { auth: password, pty: true, shell: true }   # what the scorer does [Q §2]
  email-mail:
    host: ubuntu-email
    kind: mail
    scored: true
    listen: [{ proto: tcp, port: 25 }, { proto: tcp, port: 110 }, { proto: tcp, port: 143 }]
    process: { units: [postfix.service, dovecot.service], binaries: [/usr/lib/postfix/sbin/master, /usr/sbin/dovecot], pin: true }
    transport: { plaintext: true, starttls: never }
    depends_on: [{ egress: ldap, to: ad, ports: [389] }, { egress: kerberos, to: ad, ports: [88] }]
    outbound: [ad]
  email-webmail:
    { host: ubuntu-email, kind: http, scored: true, listen: [{ proto: tcp, port: 80 }], app: roundcube }
  ad-dns:
    { host: ad, kind: dns, scored: true, listen: [{ proto: udp, port: 53 }, { proto: tcp, port: 53 }] }
  ad-winrm:
    host: ad
    kind: winrm
    scored: true
    listen: [{ proto: tcp, port: 5985 }]
    transport: { auth: ntlm, encryption: none }
  ftp:
    { host: TBD, kind: ftp, scored: true, listen: [{ proto: tcp, port: 21 }], placeholder: true }   # host per packet; scored [[2027-mw-invitational-packet#e22]]
  mssql-sql:
    { host: mssql, kind: mssql, scored: true, listen: [{ proto: tcp, port: 1433 }] }
  mssql-rdp:
    { host: mssql, kind: rdp, scored: true, listen: [{ proto: tcp, port: 3389 }] }
  mssql-smb:
    { host: mssql, kind: smb, scored: true, listen: [{ proto: tcp, port: 445 }], content: { roots: ['D:\SOPs'] } }
  splunk:
    { host: debian-splunk, kind: splunk, scored: true, listen: [{ proto: tcp, port: 8000 }, { proto: tcp, port: 8089 }] }
```

```yaml
# accounts.yml and scorer.yml (excerpt)
accounts:
  sysadmin@linux:  { scope: local, hosts: [rocky-ecom, ubuntu-email, debian-splunk], scored: false, rotation: t0_console }   # no admin accounts are scored
  mail-users:      { scope: domain, scored: true, credlists: [learned], rotation: on_evidence, learn_from: scorer }
scorer:
  engine: quotient
  identifier: "{{ 20 + team }}"
  credlists: {}                           # names learned or entered at runtime; PCR lists use the list name Quotient shows
  timing: { delay: unknown, jitter: unknown, timeout: unknown }   # estimated from capture; written to overrides
  sla: { threshold: unknown, accrual: reset }                     # or per_round with a phase schedule
```

#### What it generates

| Output | From | Used by |
| --- | --- | --- |
| Host firewall policy (management, service, dependency and decoy groups) | topology, services, decoys | `firewall` actions |
| Windows stage-0 firewall option: allow inbound plus a computed block of management ports from outside the declared team subnets | topology, hosts | `firewall` (first stage only; default-deny stays the end state; never scored ports) (review D202) |
| Palo and VyOS rules, objects, NAT, including the Kali path | topology, services, devices | `devices` |
| Egress allowlists | `depends_on`, topology | Host and network firewalls |
| Domain membership allowances | `domain_member`, `rpc_range` | Host firewalls of members and the DC (review D210, D211) |
| Agent configs (roles, module blocks, rules, ledger references, budgets) | hosts, services, modules, decoys | `config` messages (review D203) |
| Plan targets and the scoring-safety constraints per service and host | hosts, services, accounts | Plan templates, the lint, `phylax guard` (review D204) |
| Active checks and scorer-mimic probes | `health` and `transport` blocks plus accepted proposals | `checks`, `vantage` (review D205) |
| Honeytoken and decoy configs | decoys (values generated at competition time) | `decoys`, `honeytokens` |
| Cache plan | hosts' OS versions, integrations | `depot` |
| Generated artifacts (inventory, service list, port matrix, diagram, firewall export) and the T+0 checklists | Everything | `report`, the UI grid, printed sheets |

#### Rules

- **No hand-edited generated files** (review D209). Change the manifest or an override.
- **Domain membership is declared, never inferred** (review D210, D211). A host with `domain_member: <dc>` gets the full member-to-DC allowance set rendered on its host firewall (and on the Palo and VyOS when the pair crosses segments), and the DC with the `domain_controller` role gets the matching inbound rules: DNS 53, Kerberos 88 and 464, LDAP 389 and 636, global catalog 3268 and 3269, SMB 445 (SYSVOL, Netlogon), RPC endpoint mapper 135 plus the RPC dynamic range, and NTP 123/udp. Without them default-deny egress breaks domain auth and every scored check that uses domain accounts. The DC's dynamic RPC range is pinned with `rpc_range` (the plans apply it on the DC); unpinned, 49152-65535 is opened and the lint warns. The lint errors on a Windows host in a segment with a DC that is not a member while a scored service or account uses domain auth. Ports accept ranges (`port_range`, `port_ranges`).
- **Manifest CI** (review D212): schema validity, dependency cycles, a firewall lint that fails if any scored port, declared dependency, DHCP, ICMP or IPv6 need would be blocked, `nft -c` on every rendered nftables file, the rule-id registry, and rendering of every output for the reference manifest.
- **Labels** (review N1.4). Hosts carry labels; plans, hunts, probes and approvals target a label expression (`&&`, `||`, `!`, parentheses). Roles may already express part of a grouping; a label is used when no role fits. Labels are declared in `hosts.yml` and may be added at runtime through overrides.
- **Drift and adoption** (review D201, D191, D213). Drift detection compares declared state with what agents observe: undeclared listeners, services, scheduled tasks, accounts and outbound peers (from the `inventory` module's differential snapshots). Hand changes during injects are certain; each drift item offers adopt (write to overrides) or revert (a plan). An **unmanaged-host sweep** (a periodic Kali `scanner` subnet scan for hosts not in the manifest, with OS and name fingerprints, as in UCI ember `core/scan.go`@f2af5a1) feeds the same adoption queue.

### Event store and vault

The controller keeps everything in one SQLite database, a directory of encrypted evidence files and the depot cache. Secrets live in an encrypted vault and are held in memory only after the passphrase is entered (`internal/store`, `internal/vault`).

#### Storage

- **SQLite** in WAL mode, pure Go, one file, with indexes on the hot queries and full-text search over transcripts and command lines (review D454). Event inserts are batched in transactions. Agent alert rows are written inside the ingest transaction (`store.SetIngestHook`), so a crash can never leave a stored alert event without its row; rows are idempotent and replayed on start.
- **Query API.** Modules read through `store.Query`: events by kind, host, time range and field equality; full-text search; the core tables; and their own tables. No module issues raw SQL against another module's tables.
- **Evidence directory:** pcap slices, collected files, memory dumps. Each file is encrypted at rest with `age` and referenced from the database by hash (review D455).
- **Cache directory:** the content-addressed depot (the `depot` module).
- **Retention** (review D456): indefinite for the event. The Platform page shows free disk and warns at 70% and 85%. The first lever is compressing raw transaction bodies older than a day.

#### Secrets

- **The vault** is one `age`-encrypted file: device and host credentials, generated passwords (including the few rotated scored passwords; review A7.Q8), honeytoken values, the controller's private keys and the plan-signing key (review D457).
- **Unlocking:** the passphrase is entered in the UI after every start. Decrypted values exist only in memory. A module reads only the secret names its config declares (`Host.Secrets`).
- **Credentials seen in traffic** are encrypted field by field before storage and masked until revealed (review D458). Parsers mark credential fields. Kept because the alternative is a plaintext database full of passwords on the box everyone wants.

#### Data model

The core owns the records every module joins on (review D459). Modules declare and own their other tables (contract: store tables).

| Record | Identity | Owner |
| --- | --- | --- |
| Host | Manifest name + enrolled key | core |
| Service | Manifest name (Quotient display names map to `<box>-<display>`) | core |
| Event | Agent + sequence | core |
| Alert | Rule + host + key records | core |
| Incident | A set of alerts, changes and chains with a timeline | core |
| Plan, node, approval, audit entry | Plan id + node id; approver name | core |
| Process | Host + PID + start time (+ Sysmon GUID alias) | common kinds; tables owned by telemetry modules where needed |
| Connection | Host + 5-tuple + start time, and Community ID | `net`, `capture` |
| File | Host + path, with a hash history | `audit`/`winevt`, `integrity` |
| Ledger entry | OS + version + path + sha256 + source | `integrity` |
| Account | Scope + name; credlists; scored flag; PCR state per credlist | `creds` |
| Source | IP address, with labels (scorer, red, us, other) and fingerprints | `traceback`, `scorer` |
| Scorer round | Burst time, services seen, credentials seen, estimated Delay and Jitter | `scorer` |
| Change | The changed record + before and after | `traceback` |
| Hop, chain, campaign, remediation item | As in the `chains` module | `chains` |

Correlation joins on these identities, never on loose text matching.

#### Controller backups

Encrypted state snapshots go to the backup targets declared in the manifest every 15 minutes and after every key or vault change. Restore needs only the passphrase and starts a new epoch (Enrollment: controller recovery).

### UI shell

The UI is server-rendered on its own `127.0.0.1` listener, with one login. It is the team's shared screen on the controller console: there is no remote or multi-viewer access (review D494, A11.Q1). Implementation: `internal/ui`, `docs/ui.md`.

#### Built with

- Go `html/template` plus htmx (review D460). Live updates by htmx polling (2 s for plan nodes, 5 s for the dashboard); Server-Sent Events only if polling proves too slow. All assets are vendored and embedded; no CDN, no Node at runtime, no JavaScript graph library. DAGs and chain timelines are tables today; server-side SVG is a later option.
- **Access:** its own listener, `127.0.0.1` only (a non-loopback address is refused). One login (argon2id; the `admin` operator's password is printed once on first start), HttpOnly SameSite=Strict cookie, CSRF token on every non-GET, strict CSP, every request audited before its handler runs.

#### Hostile-string handling

Process names, command lines, paths, usernames, HTTP paths and decoy-shell input are all attacker-controlled (review D59). Required:

- `html/template` auto-escaping; no raw HTML from data.
- A strict Content Security Policy with no inline scripts and only vendored assets.
- An HttpOnly, SameSite=Strict session cookie, and CSRF tokens on every state-changing request.
- Evidence files served as downloads, never rendered inline.
- Request bodies size-capped.

#### Module registration

The shell has no module-specific code (review D460). A module registers:

```go
// package ui
type Registrar interface {
	Page(route, title string, h http.Handler)                      // authenticated, CSRF-checked, audited (Server.Handle)
	Tile(name string, render func(ctx context.Context) (template.HTML, error)) // an overview tile
	GridColumn(step string, cell func(ctx context.Context, host string) Cell)  // a host x step grid column
	Action(name string, h http.Handler)                            // a one-click button endpoint that creates a plan
}

type Cell struct {
	State  string // "verified", "pending", "failed", "drifted", "n/a", "manual"
	Detail string
	Link   string
}
```

Pages registered by a disabled module disappear (review D464, D468, D469, D471-D474). Templates escape everything; a module cannot inject raw HTML except through `template.HTML` it built from escaped parts, which code review checks.

#### Shell pages

| Page | Shows | Owner |
| --- | --- | --- |
| Overview | Hosts, services, open incidents, the round clock and SLA streaks, platform problems, unstaffed roles, the safe-mode switch, and module tiles (review D461) | shell |
| Host x step grid | The convergence board (below) | shell; columns from modules |
| Plans | Templates, the plan DAG with live node status, diffs, lint results, approvals with approver names, rollback (review D462) | shell (execution engine) |
| Alerts and incidents | Queue, evidence, trace-back, one-click actions and proposals, IR draft button, and a **pivot** on IP, host, user, domain and process GUID over the full-text store (review D463; verify first that no pivot exists) | shell; actions from modules |
| Platform | One page (review D475-D477, D479): per agent link state and lag, spool depth and congestion, clock offset, safe mode, config status, every module's health with gaps and budget use, telemetry gap counts; per relay connections, bytes and errors; the controller's CPU, memory, disk, database size and last snapshot; cache progress (from `depot`) and integration health (from opt-in integration modules). Anything degraded shows on the Overview. Replaces v3's separate Integrations and Cache pages. | shell |
| Settings | Manifest overrides, the adoption queue, suppression records, runtime facts, secrets unlock (review D478) | shell |
| Audit, Account | Audit log (filter by operator and action); password change | shell |
| Checks, Credentials, Services, Chains, Integrity, Traffic, Vantage, Deception, Hunts, Devices, Reports | Registered by `checks`, `creds`, `checks`/`traceback`, `chains`, `integrity`, `capture` (with egress folded in), `vantage`, `decoys`/`honeytokens`, `hunt`, `devices`, `report` (review D465-D467, D464, D468-D474) | modules |

#### The host x step grid

One grid with a row per host and a column per step (review N11.6, N11.4; decision 14). Columns come from the T+0 checklist and from modules: enrolled, T+0 creds rotated, sessions evicted, firewall applied, backed up, hardened (per plan pack), ledger sweep clean, hunt clean, creds handled. Each cell is verified, pending, failed, drifted, n/a or manual:

- **Steps the platform can read tick themselves** from plan and ledger state, and are refreshed by re-running the node's `check`. A step the platform sees as not done stays amber even if someone ticked it ("sometimes we thought something was done but it wasn't", "Checklists were untested" [[discord-2026q-lessons#e1]]).
- **Manual steps** (the T+0 console rotation, device console work) need an owner tick with the person's name.
- UCI's Northstar board sets the flags by hand and its own notes warn it "may be stale" (cyberuci-bonfire-regionals#e3); ours computes them.
- The grid replaces v3's printed per-role checklists; a print view is the fallback (review D503).
- Grouped results (Execution engine) feed it.

### Rule format

Detection rules are YAML content, delivered in the agent's signed config and hot-reloaded without a restart (review D306-D311). The `detect` module evaluates them on the agent; controller correlation rules use the same format over store queries. The language is deliberately small and declarative: no expressions, no scripting. A rule the scoring-safety lint and a reviewer cannot read at a glance is not allowed (peer evidence against: UCF puts Rhai expressions in rules, `flying-ace-engine/src/lib.rs`).

```yaml
id: D1.service-spawns-shell
module: detect
mode: act                       # act (may trigger tier-0 or propose tier-1) | alert; a global override forces alert
when:
  event: process_start          # mandatory event kind; the engine indexes rules by it
  all:
    - parent.service.scored: true
    - not: { exe: { in_profile: parent.service } }
    - not: { tag: { present: true } }       # exempt our own tagged plan and work-window activity
  any:
    - image: { endswith_any: { list: unix_shells_and_tools } }
    - image: { endswith_any: { list: windows_lolbins } }
lists:
  unix_shells_and_tools: [/sh, /bash, /dash, /python3, /perl, /nc, /ncat, /socat, /curl, /wget, /busybox]
  windows_lolbins: [\cmd.exe, \powershell.exe, \pwsh.exe, \certutil.exe, \bitsadmin.exe, \whoami.exe, \net.exe, \net1.exe, \rundll32.exe, \mshta.exe, \regsvr32.exe]
exceptions:
  - name: opencart-cron
    when: { all: [ { parent.exe: { eq: /usr/sbin/crond } }, { cmdline: { contains: "opencart/system/cron" } } ] }
    reason: "OpenCart's own cron task runs php-cli"
    owner: linux-lead
    added: 2026-11-07
    expires: 2026-11-08            # optional
rate: { max: 10, per: 1m, by: [host, parent.exe] }   # above it: one "suppressed N" summary event per window
severity: high
tier: 1
collect: [process_tree, content_changes, transactions_window_10m, freeze_ring]
attack: [T1505.003, T1059]       # ATT&CK v19 ids; validated in CI
tests:
  - { name: php-exec,      event: lab/tests/fixtures/webshell_php_exec.json, should_match: true }
  - { name: health-script, event: lab/tests/fixtures/cgi_health.json,       should_match: false }
  - { name: opencart-cron, event: lab/tests/fixtures/opencart_cron.json,    should_match: false }
source: { author: Phylax, license: repo }   # hand-ported rules carry upstream id, path, commit, author and licence
```

#### Format elements

- **`lists:`** named value lists, referenced from conditions with `{ list: name }`. Lists may also come from the manifest (`list: manifest.scored_users`, `list: manifest.service_binaries.ecom-http`), so allowlists come from the manifest without forking rule text (Falco-style; review D306, area 1 answer). Shared lists live in `rules/lists.yml`.
- **`exceptions:`** per-rule named exceptions with their own `when`, and mandatory `reason`, `owner` and `added`, optional `expires`. **Suppression records are exceptions** (cross-cutting idea 10, review D345, A4.Q3): silencing an alert in the UI writes an exception to overrides with reason, owner, date and optional expiry, so the team can always see why something is quiet. There is one suppression mechanism; no separate low-level override rules (peer evidence against: CyberHawks `rules/1000-aurora.xml` level-3 overrides hide the why; dbarr914's whitelist CSVs had the right columns and were empty). An expired exception stops applying and shows as expired on the Settings page.
- **`rate:`** a per-rule cap keyed by fields; above it the engine emits one `detect.suppressed` summary event per window with the count, never silence (Wazuh anti-flooding [gk]).
- **Not in v4:** `macros:`, `maturity:` and `requires:` (A4.Q3: simplicity trims). A rule's applicability comes from its `event` kind and the modules enabled on the host.

#### Engine requirements

All of these were missing from the discarded pre-v3 engine [CR §5, PR E1–E9]; the built engine (`internal/detect`) has them, plus the v4 additions marked.

| Requirement | Why |
| --- | --- |
| Exactly one key per condition, enforced by schema validation; deterministic evaluation | A multi-key map was evaluated on a random key |
| Operators `eq`, `in`, `re`, `contains`, `startswith`, `endswith` (and `_any` forms), `gt`, `lt`, `cidr`, `in_profile`, `present`; string matching case-insensitive by default with an explicit case-sensitive flag | Hand-porting public rules is then mechanical |
| `count` with `by` and `distinct`, per host, source, account or process, not one global window per rule | A global SSH-failure count cannot tell the scorer from an attacker |
| Parent fields on process events (`parent.exe`, `parent.cmdline`, `parent.service`) | Every parent-based public rule needs them |
| Actor on file events (pid, exe, auid) | Package managers are excluded by process, or by window tag where the actor is unknown |
| The plan or work-window `tag` on every event kind (envelope field) | Our own hardening must not alert |
| Direction and service on connection events | D3 fires on every listener without it, D4 never fires |
| Regexes compiled once at load; the dedupe map is pruned; cooldown keys include the process start time | PID reuse suppressed alerts; regex recompilation cost CPU |
| `collect:` is executed when the rule fires, and the evidence ships with the alert | Evidence has to be gathered before the attacker cleans up |
| `lists:`, `exceptions:` with suppression fields, `rate:` (v4) | Allowlists from the manifest; visible suppression; no alert floods |
| Inline `tests:` with fixtures; CI fails a rule with no test or a failing test; `phylax rules test` runs them locally (review D312, D22) | "CI rejects a rule without a test" must be real |
| ATT&CK v19 ids, validated in CI against a pinned dataset; revoked ids (the T1562 family, replaced by T1685 and T1686) kept as aliases (review D344) [DR §5] | Three shipped rule files used revoked ids; IRs cite techniques |
| One rule-id namespace with a registry check in CI | The `D14` collision (Known bugs) |
| A global `override_mode: alert` that makes every rule alert only, paired with safe mode for responses (review D313) | UCF RB2's pattern (`lib.rs:10,257@85aae3f`); its v1 killed on all 15 rules and v2 ships hand rules as alert, which supports alert-first |

#### False-positive controls

The scorer and our own hardening are the main sources, more than the red team [DR §3] (review D345). The controls, all in content or the envelope:

- A **behavioural scorer exemption**, never address-based, because Divisor re-draws addresses and known-source and first-seen rules would break. The scorer's learned accounts and its N-failures-then-success pattern are rule context (`list: scorer.accounts`).
- The **plan and work-window tag** on every event kind.
- **Exempting the agent** by randomised path and hash.
- **Thresholds generated from check discovery.**
- **Exec-based rules at tier 1,** so an operator typing the same command costs one click.
- **Suppression records** as exceptions with reason, owner and expiry.
- NTLM WinRM and SMB network logons by the scorer look like pass-the-hash to some public rules [DR §3, inferred], so those rules take the scorer's learned accounts as context.

Third-party logic is hand-ported, never imported. A hand-ported rule carries `source:` with the upstream id, path, commit, author and licence, which reaches the alert, the UI and the IR drafter; a generated `THIRD_PARTY_RULES.md` lists them. The licence policy is in the `detect` section.

## Module catalogue

Every capability above the core. "Core" in the last column means the module runs by default wherever its OS and role conditions hold; "opt-in" means it is off unless the manifest enables it (decision 1). Status is from the 2026-10-22 implementation status report plus spot checks; nothing is lab-proven yet.

| Module | Group | Runs on | Does | Status | Default |
| --- | --- | --- | --- | --- | --- |
| `audit` | Telemetry | Agent, Linux | Process, file-watch and connect telemetry from kernel audit over netlink; hash sweep; audit health and rule-hash check | built | core |
| `winevt` | Telemetry | Agent, Windows | Sysmon (renamed, config as code) and event logs through `EvtSubscribe` with bookmarks; 4688 fallback; enrollment backscan | built | core |
| `net` | Telemetry | Agent | Listeners and connections with owning process via `sock_diag` and fd-inode join; Community ID; denied egress via NFLOG and 5157; canary sender | built | core |
| `logs` | Telemetry | Agent, Linux | Application and auth log tailing (sshd, Cockpit, web admin, access logs) into `auth_event` and log events | missing | core |
| `inventory` | Telemetry | Agent + controller | Differential snapshots (listeners, accounts, tasks, services, units, mounts, software versions); typed `probe.run` queries | missing | opt-in |
| `detect` | Detection and response | Agent + controller | Rule evaluation on every event, locally; the detection catalogue (D1-D23) and hand-ported rule packs | built | core |
| `respond` | Detection and response | Agent | Tier-0 responses with guards, tier-1 one-click proposals, tier-2 checklists, response recipes | partial | core |
| `content_guard` | Detection and response | Agent | Restores declared scored content and boot-critical files from plan-tagged golden copies, alert-only until switched to act | missing | opt-in |
| `integrity` | Integrity and hunting | Agent + controller | Binary integrity ledger (alert only), exec-time hashing, service pinning, sweeps, YARA over files and memory | partial | core |
| `hunt` | Integrity and hunting | Agent + controller | Prebake hunt against reference baselines, rootkit cross-checks, persistence and credential-file hunts, application reference checks, review queue | partial | core |
| `hardening` | Integrity and hunting | Content over core actions | Plan packs: first-hour mitigations, baseline Windows/AD/Linux hardening, banners and password policy, service config templates, reboot-survival preflight, noexec temp mounts | partial | core |
| `ad` | Integrity and hunting | Agent on the DC | Domain actions, continuous AD checks, privileged-account allowlist and path query, GPO response, DC service repair, krbtgt reset | partial | core |
| `firewall` | Network | Agent | Host firewall apply, shadow mode with a would-drop summary, quarantine, conntrack flush, default-deny egress | built | core |
| `egress` | Network | Controller | Denied-egress analysis and ranking, per-executable egress allowlist alerts, the sinkhole question | partial | core |
| `capture` | Network | Agent (Linux) + controller | Packet ring, flows, TCP reassembly, protocol parsers, freeze on alert | built | core |
| `devices` | Network | Controller | Palo Alto and VyOS adapters with safe-change protocols, drift, deny-log pull, config backups, Palo-side pcap, FTD export | built | core |
| `checks` | Scoring and credentials | Controller + check runners | Quotient-faithful active checks and scorer-mimic probes, multi-step Orange flows, service doctor | built | core |
| `scorer` | Scoring and credentials | Controller | Round clock, bursts and quiet windows, scorer fingerprints and check discovery, scorer-account learning, SLA streaks, points at risk | built | core |
| `vantage` | Scoring and credentials | Agent on the Kali + controller | Faithful checks through the public path, credential verification, perimeter scans, egress canaries, Zerologon check-only | built | core |
| `creds` | Scoring and credentials | Controller | Credential inventory per (account, credlist), password generation, selective scored changes as host change plus a typed PCR list, revert re-sync | partial | core |
| `traceback` | Analysis | Controller | Traffic labels, change detection, trace-back from a change to its cause | built | core |
| `chains` | Analysis | Controller | Hops, cross-host stitching, chains, campaign view, remediation items | built | core |
| `deps` | Analysis | Agent + controller | Service dependency discovery and `depends_on` proposals | built | core |
| `vuln` | Analysis | Controller | Version-driven matcher against cached CISA KEV and vault vendor advisories | missing | opt-in |
| `decoys` | Deception | Agent (unprivileged process) | LAN-only decoy services and the fake shell | built | opt-in |
| `honeytokens` | Deception | Agent + controller | Per-host honeytokens, honey files, LSASS decoy session, honey AD accounts | built | opt-in |
| `report` | Reports and generators | Controller | IR drafter, pre-submit validator, deliverable-coverage skeletons, generated artifacts, evidence runs, traffic reports, device exports | partial | core |
| `backup` | Operations | Agent + controller | As-found, golden, periodic and pre-change service backups; AD/DNS/CA/GPO record-level backup; restores with record counts | missing | opt-in |
| `teamfeed` | Operations | Agent CLI + controller | `phylax say` and `phylax claim` from any enrolled host; claims open tagged work windows | missing | opt-in |
| `notify` | Operations | Controller | Local audible alarm and an optional webhook sink | missing | opt-in |
| `depot` | Integrations and depot | Controller + agent | Content-addressed cache with one signed index, trusted tool depot, package installs from the depot, `phylax tools` fallbacks | partial | core |
| `wazuh` | Integrations and depot | Content + controller | Wazuh deploy plan and health, active response off | partial | opt-in |
| `splunk` | Integrations and depot | Controller | Splunk HEC forwarding and a small dashboards pack | built | opt-in |
| `suricata` | Integrations and depot | Controller | Suricata and Zeek offline over pulled pcap slices, joined by Community ID | built | opt-in |

The brief for writing each section (review rows, answers, v3 line ranges, code packages) is `docs/impl/modules.md`.

### Module section template

Every module section has these parts, in this order. A part that does not apply says so in one line.

1. **Purpose and evidence.** What the module does and the evidence that it matters for points (vault citations, research tags, peer evidence for and against). A module without evidence says so and starts off.
2. **Status and code.** built, partial or missing; the packages and files; what is missing.
3. **Capability manifest.** Sides, OS, privilege, roles, budget (CPU ms/s, held MB, events/s, bytes out/min, disk MB), default (core or opt-in), owned tables, content directories, actions, pages.
4. **Configuration.** The config block as manifest YAML with every field, and the typed Go settings struct.
5. **Events.** Consumed kinds; emitted kinds with schema version, priority and key fields.
6. **Behaviour.** How it works: mechanisms, procedures, thresholds and edge cases, carried over from v3 where kept.
7. **Actions and content.** Actions it registers (with risk class, locks and scorer-visible touches); rules, plans and checks it ships.
8. **UI.** Pages, overview tiles and host-grid columns.
9. **Health.** States, coverage gaps it reports, what degraded means.
10. **Scoring safety.** What it can touch on the scored path, the lint rules and probes that guard it, its alert-only stage.
11. **Tests.** Unit and fixture tests, conformance notes, lab tests by id.
12. **Limits and open items.** Known limits (`shortcut:` lines), open questions, and any core change it needs.

### Telemetry

#### `audit`

<!-- MODULE SECTION: audit — to be written -->

#### `winevt`

<!-- MODULE SECTION: winevt — to be written -->

#### `net`

<!-- MODULE SECTION: net — to be written -->

#### `logs`

<!-- MODULE SECTION: logs — to be written -->

#### `inventory`

<!-- MODULE SECTION: inventory — to be written -->

### Detection and response

#### `detect`

<!-- MODULE SECTION: detect — to be written -->

#### `respond`

<!-- MODULE SECTION: respond — to be written -->

#### `content_guard`

<!-- MODULE SECTION: content_guard — to be written -->

### Integrity and hunting

#### `integrity`

<!-- MODULE SECTION: integrity — to be written -->

#### `hunt`

<!-- MODULE SECTION: hunt — to be written -->

#### `hardening`

<!-- MODULE SECTION: hardening — to be written -->

#### `ad`

<!-- MODULE SECTION: ad — to be written -->

### Network

#### `firewall`

<!-- MODULE SECTION: firewall — to be written -->

#### `egress`

<!-- MODULE SECTION: egress — to be written -->

#### `capture`

<!-- MODULE SECTION: capture — to be written -->

#### `devices`

<!-- MODULE SECTION: devices — to be written -->

### Scoring and credentials

#### `checks`

<!-- MODULE SECTION: checks — to be written -->

#### `scorer`

<!-- MODULE SECTION: scorer — to be written -->

#### `vantage`

<!-- MODULE SECTION: vantage — to be written -->

#### `creds`

<!-- MODULE SECTION: creds — to be written -->

### Analysis

#### `traceback`

<!-- MODULE SECTION: traceback — to be written -->

#### `chains`

<!-- MODULE SECTION: chains — to be written -->

#### `deps`

<!-- MODULE SECTION: deps — to be written -->

#### `vuln`

<!-- MODULE SECTION: vuln — to be written -->

### Deception

#### `decoys`

<!-- MODULE SECTION: decoys — to be written -->

#### `honeytokens`

<!-- MODULE SECTION: honeytokens — to be written -->

### Reports and generators

#### `report`

<!-- MODULE SECTION: report — to be written -->

### Operations

#### `backup`

<!-- MODULE SECTION: backup — to be written -->

#### `teamfeed`

<!-- MODULE SECTION: teamfeed — to be written -->

#### `notify`

<!-- MODULE SECTION: notify — to be written -->

### Integrations and depot

#### `depot`

<!-- MODULE SECTION: depot — to be written -->

#### `wazuh`

<!-- MODULE SECTION: wazuh — to be written -->

#### `splunk`

<!-- MODULE SECTION: splunk — to be written -->

#### `suricata`

<!-- MODULE SECTION: suricata — to be written -->

## Operations

What the code must support on game day. Team runbooks (timelines, callouts, seat rotation) are procedures; they are kept here in outline because the platform's order of operations depends on them (cross-cutting idea 8).

### Game day order

<!-- SECTION: game day order — to be written. Rows: review D496-D501 (re-order around the T+0 console phase; keep the order, drop the minute targets), D502 (day 2: fresh golden backups and off-box boot files before day 2 and before lunch), D504 (verbal callout before tier-2, safe mode and each scored-password change), D505 (SOC seat rotation with a "since you left" digest). v3 text: L1966-1993. -->

The order, without minute targets (decision 9): T+0 console phase (Enrollment); `phylax init` and the UI; first contact and enrollment; session eviction for everything rotated at T+0; as-found backups, capture, round-clock estimation, check discovery, scorer-account learning, ledger sweep and prebake hunt start on each enrolled host; hunt and ledger review; firewall plans in shadow mode, review, enforce; hardening packs with probes and golden backups as each passes; decoys and honeytokens; scored-password changes only on evidence, inside quiet windows.

### Roles

<!-- SECTION: roles — to be written. Row: review D495 (nine roles plus a role-merge map for 4, 6 and 8 players; show unstaffed roles on the overview). v3 text: L1952-1964. The Credentials role now carries the typed PCR list to the Quotient machine outside the environment (no clipboard). -->

### The Invitational: observe mode and battle-test tiers

The Invitational (2026-11-07, four hours) is largely for instrumenting the environment and collecting data; `docs/impl/invitational-data.md` lists the open questions it can answer and the collectors (review I1, I2). The collection kit need not be minimal.

- **Observe mode** (I1). Phylax runs with every module alert-only and safe mode on, plus standalone collector scripts as a fallback. Observe mode is configuration, not an event profile: `override_mode: alert`, safe mode on at start, `act_enabled` off, the content guard and eviction in alert-only, firewall render in shadow only.
- **Tier A, everywhere** (I2): external checks, hunts, the ledger, YARA, decoys, honeytokens, firewall shadow mode, alert-only content guard, service doctor and session eviction, scorer learning.
- **Tier B, on non-scored accounts and one canary host:** T+0 admin rotation plus eviction, tier-0 responses on non-scored targets, hardening packs with the dead-man, red-IP blocks on non-scored ports.
- **Tier C, only in the second half:** one deliberate scored-password change of a single scored user, and hardening on one scored server.
- **Ground rules from the collection plan:** observe only except the timed T+0 rotation and the one scored-password change; no config edits, restarts, reboots, firewall changes or extra accounts outside the tiers; every record in UTC with the host's clock offset; results leave the environment over the network, never typed.

### The pre-qualifier access week

About a week of environment access comes after the repository deadline. Nothing in the repo changes then. The week is for entering runtime facts (team number, observed services, measured scorer timing, learned accounts) into overrides, rehearsing the T+0 phase, and checking cache and depot state; any finding that needs code waits for the next event.

## Testing and lab

<!-- SECTION: testing and lab — to be written. Rows: review N13.1 (conformance suite in CI plus `go test -race` as a required gate), D506 (lab-first acceptance), D507-D508 (ccdc27 replica; add a Docker-hosted ecom variant and Roundcube on the mail host), D509-D510 (simulator with real Quotient; add multiple credlists and a revert scenario), D511 (Orange traffic from the `checks` flow probes), D512 (purple-team runbooks; add GPO footholds, sleep-masked Mythic/Cobalt Strike beacons, razing by fstab delete plus reboot, a T+0 credential spray; the C2 fingerprinting lab for the sinkhole decision), D513 (contaminator), D514 (acceptance matrix renumbered; drop tests for cut items; keep decoy and sinkhole tests), D515-D516 (CI gates; make `-race` and the privileged job required), D517 (cadence). v3 text: L1995-2105. Add the end-to-end relay test and the conformance suite. -->

## Complexity register

One line per module, plus the core items. Each line says why the complexity earns its place and what bounds it. Any new listener, daemon, host-binary dependency in a default path, runtime discovery mechanism or new kind of state needs a line before it is built.

| Item | Why it is worth it | How it is bounded |
| --- | --- | --- |
| One binary for agent and controller | One artifact per OS; no version skew | Size gate in CI |
| Relay and device-proxy splicing | Segments and devices the controller cannot reach | Dumb splice, no state, no keys; declared statically; unused on the 2027 LAN |
| Four connection types on one port | One listener and one firewall rule | Small handler per ALPN; UI on a separate localhost listener |
| Kali inbound path (one port, one source, static NAT) | The only way for an outside vantage point to report | One Palo rule, one host rule, Kali source only, pinned keys |
| Module contract (registry, typed events, conformance suite) | Makes the platform's size and isolation checkable | One small package; CI enforces it |
| Dead-man with OS timers | Risky changes roll back even if the agent dies | Journal plus one transient timer per armed node |
| Go-native Windows actions through COM and WMI | Avoids trusting host binaries | `host.exec` fallback per action, recorded here |
| Field-level encryption of captured credentials | No plaintext passwords on the controller's disk | Parsers mark credential fields |
| Defender exclusion | The agent may be flagged | Exactly one path |
| `validate` hook validators as host tools | Catch a broken config before it is live | Services' own binaries, hash-pinned, ledger-judged |
| Obscurity measures | Raise the cost of scripted kill lists | Names and paths only; no mutated binaries |
| `audit` … `suricata` | <!-- one line per module, written with each module section --> | |

### Watch list

- Any second listener on the controller beyond `agent_port` and the localhost UI, or any listener on a host that is not a declared decoy, relay or Kali-path port.
- `host.exec` creeping into default plans.
- Rules or parsers that need state shared across hosts at the agent. Cross-host logic belongs on the controller.
- Configuration that can be changed on hosts without going through the manifest.
- A feature that needs a live internet fetch at the event.
- A module that imports a sibling, or a controller feature that is still a method on `Controller` after its area is implemented.
- Anything that makes the integrity ledger act without a human.

## Risks and open questions

<!-- SECTION: risks — to be written. Carry over the v3 risk table (L2240-2266) minus rule-driven rows and rows for cut items; drop the "questions for competition officials" list (decision 3); keep only lab questions that are still open (L2284-2296). -->

Open questions that are genuinely open (not decided anywhere):

1. **Scored-password policy against full AD dumps** (review A7.Q6). Red dumps every AD hash, and a Phylax breach exposes every rotated password. The PCR process stays (selective, timed, verified, revert re-apply); research on how Quotient-region teams handle this is running.
2. **`pcr.submit`.** Moot while Quotient is unreachable from inside (area 7 revision). It would return only if Quotient became reachable and the organizers agreed (review A7.Q2); never the reset endpoint.
3. **The sinkhole** (review D76, D222). Deferred to the C2 fingerprinting lab: keep it only if first-bytes fingerprints discriminate; the code stays until then.
4. **Containerized scored services** (review N7.6). The 2027 stack is unverified; the Docker ecom variant is designed but unconfirmed.
5. **Generic restore onto a different host** (review A10.Q2) is tentative.
6. **The team Nextcloud** as the file-export path: expected writable from inside, unverified.
7. **Multiple viewers on one NETLAB console:** unknown; it decides how much of the team sees the one controller screen.
8. **Quotient's real configuration** (Delay, Jitter, Timeout, SLA threshold, Divisor, debug visibility, credlist count): measured at the Invitational.
9. **Per-module CPU and memory accounting** is self-reported; whether that is good enough is a lab question.
10. **Duplicate AD groups inject** (~500 groups across 10 departments, MW Discord 2026-10-26): whether Phylax should offer a read-only consolidation report.

## Known bugs to fix

From the 2026-10-31 review; each is fixed in the owning module or core section's implementation.

1. **`kernel.module_block` Verify passes when the module is built in** (`internal/actions/linux_kmod.go:111-120`). It only compares the modprobe.d file. If `algif_aead` is compiled in, `linux.local_root_bundle` reports Copy Fail mitigated while it is not [[cert-cc-vulnerability-note-vu-260001#e6]]. Fix: probe `socket(AF_ALG)` bind to `aead`; if built in, use `initcall_blacklist=algif_aead_init` behind a reboot gate. Core (kernel family) and `hardening`.
2. **Rule id collision `D14`.** `rules/deps.yml:15,54,84` define `D14.new-dependency`, `D14b`, `D14c`, while D14 is network device tampering. Rename to `DEP1`-`DEP3`; add the rule-id registry check. `deps`.
3. **Stale Typst references** in v3 (cache tier 1, templates, complexity register, repo layout). The code uses fpdf (`docs/report.md`). Removed from v4; `report`, `depot`.
4. **Agent `fetch` handler is a no-op** (`internal/agent/handlers.go:41`). Depot and cache pulls cannot work. Core (wire).
5. **Placeholder step handler** rejects with "step execution not implemented" when `ExecConfig` is unset (`internal/agent/handlers.go:31,37`). Add a test that `phylax agent` always wires the real executor. Core (execution).
6. **Ledger alerts do not reach detection.** Rule D5d waits on a `binary_integrity` event nothing emits (`rules/pending/needs_producer.yml`). `integrity`.
7. **The controller never sends `freeze_capture`** for controller-scope `freeze_ring` collects (`docs/capture.md`). `capture`.
8. **Dead-man fires while connected are not reconciled until the next reconnect** (`docs/controller.md`). Core (execution).
9. **`plans/actions.yaml` header** still says "Each is a TODO" although the file has no stubs. Core.
10. **Reference `services.yml` lacks DNS and FTP**, both scored [[2027-mw-invitational-packet#e22]]. Core (manifest; the examples above add them).
11. **No `shortcut:` comments** anywhere although 70 `t.Skip` calls exist; known limits are not recorded. All modules.

## Appendices

### A. Windows event reference

Verify every ID on the target builds before a rule depends on it. Firewall operational-log IDs in particular differ between Server 2019 and Windows 11.

| Log | ID | Meaning | Used by |
| --- | --- | --- | --- |
| Sysmon | 1, 5 | Process created, terminated | `proc`, D1, D8, D9 |
| Sysmon | 2 | File creation time changed (timestomping) | Hunt enrichment |
| Sysmon | 3 | Network connection | `net`, D4, trace-back |
| Sysmon | 4, 16 | Sysmon state change, config change | D10 |
| Sysmon | 6 | Driver loaded | D11 |
| Sysmon | 7 | Image loaded | Integrity ledger, change detection |
| Sysmon | 8 | CreateRemoteThread | D5 |
| Sysmon | 10 | Process access (LSASS) | D8 |
| Sysmon | 11 | File created | `fim`, D2, D6, trace-back |
| Sysmon | 12, 13, 14 | Registry create or delete, value set, rename | D6 |
| Sysmon | 17, 18 | Named pipe created, connected | D9, D13b |
| Sysmon | 19, 20, 21 | WMI filter, consumer, binding | D6 |
| Sysmon | 22 | DNS query | D12 |
| Sysmon | 25 | Process tampering | D5 |
| Security | 1102 | Security log cleared | D10 |
| Security | 4624, 4625, 4648 | Logon, failed logon, explicit credentials | D9, D15, D18, chains |
| Security | 4662 | Directory object operation (replication rights mean DCSync) | D8 |
| Security | 4663 | Object access (honey files) | D15 |
| Security | 4670, 4741, 4742, 4929 | Permissions changed; computer account created and changed; AD replica source naming context removed | D8b (4742 by ANONYMOUS LOGON), D8d |
| Security | 4688 | Process created, with command line (fallback) | `proc` |
| Security | 4697 | Service installed | D6 |
| Security | 4698, 4699, 4702 | Scheduled task created, deleted, updated | D6 |
| Security | 4719 | Audit policy changed | D10 |
| Security | 4720, 4722, 4724, 4738, 4781 | User created, enabled, password reset, changed, renamed | D7 |
| Security | 4728, 4732, 4756 | Member added to global, local, universal group | D7 |
| Security | 4768, 4769, 4771, 4776 | TGT, service ticket, pre-auth failure, NTLM validation | D8, D15, chains |
| Security | 5136, 5137 | Directory object modified or created (GPOs, ACLs) | D6, D7, D8d |
| Security | 5140, 5145 | Network share accessed | D9 |
| Security | 5156, 5157 | Connection allowed or blocked by the Windows Filtering Platform | `egress`, D12 |
| System | 104 | Event log cleared | D10 |
| System | 7045 | Service installed | D6 |
| System / Netlogon | 5827–5831 | Netlogon secure channel denials and allowances (5829 is the vulnerable-connection event used for Zerologon) | D8b |
| Task Scheduler Operational | 106, 140, 141 | Task registered, updated, deleted | D6 |
| WMI-Activity Operational | 5861 | Permanent event subscription | D6 |
| Defender Operational | 1116, 1117 | Detection, action taken | Context |
| Defender Operational | 5001, 5004, 5007, 5010, 5012 | Protection disabled, configuration changed | D10 |
| PowerShell Operational | 4103, 4104 | Module logging, script block logging | D1, D8 |
| DNS Server | 515–519, 541 | Zone and record changes | S-2 hunts, D17 |
| Firewall With Advanced Security | Varies by build | Rule added, modified, deleted; profile changed | D10 |

### B. Linux persistence locations

Watched by `fim` and checked by the hunt:

- **Scheduling:** `/etc/crontab`, `/etc/cron.*/`, `/var/spool/cron/`, `/var/spool/at/`, systemd timers
- **systemd:** units in `/etc/systemd/system/`, `/usr/lib/systemd/system/`, user units, drop-ins, generators; unit `Environment=`, `AmbientCapabilities`, `CapabilityBoundingSet`
- **Boot:** `/etc/rc.local`, `/etc/init.d/`, `/etc/modules-load.d/`, `/etc/modprobe.d/`
- **Login and shell:** `/etc/profile`, `/etc/profile.d/`, `/etc/bash.bashrc`, `/etc/environment`, `/etc/inputrc`, per-user dotfiles including `.screenrc`, `.tmux.conf`, `.vimrc`, `.inputrc`; `/etc/update-motd.d/`, `~/.ssh/rc`, `/etc/ssh/sshrc`
- **Authentication:** `/etc/pam.d/`, PAM module directories, `pam_exec`, `/etc/nsswitch.conf` and NSS libraries, all `authorized_keys`, plus `AuthorizedKeysFile` and `AuthorizedKeysCommand`
- **Accounts:** `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, `/etc/sudoers.d/`
- **Loader:** `/etc/ld.so.preload`, `/etc/ld.so.conf.d/`, `LD_PRELOAD` in service environments, `/proc/<pid>/maps` of services
- **Package hooks and holds:** apt `Pre-Invoke` and `Post-Invoke`, dnf plugins, `apt-mark hold`, `versionlock.list`
- **Device events:** `/etc/udev/rules.d/`
- **Log rotation:** `/etc/logrotate.d/` postrotate scripts
- **Web:** `php.ini` and `conf.d` (`auto_prepend_file`, `auto_append_file`, `disable_functions`, `extension=`), PHP `extension_dir`, `.htaccess`, Apache modules and `Include` lines
- **Mail:** Postfix `master.cf` and content filters, `/etc/aliases` command pipes, Dovecot post-login and global sieve
- **Database:** MySQL UDFs (`mysql.func`), plugin directory, `mysql.user`, application admin tables
- **Kernel:** loaded modules, BPF programs, module-loading state
- **Privilege:** SUID and SGID files, file capabilities, immutable and append-only attributes
- **Mounts:** bind, overlay and tmpfs mounts over content and persistence directories
- **Splunk:** `$SPLUNK_HOME/etc/apps`, scripted inputs, `outputs.conf`, deployment-server settings
- **Desktop:** XDG autostart on workstations

### C. Windows persistence locations

- Scheduled tasks (including GPO-deployed), with content review and the `\Microsoft\` folder
- Services (binary path, `ServiceDll`, failure actions), including unsigned SYSTEM services and masquerade names
- Run, RunOnce and RunServices keys (HKLM, HKCU, WOW6432Node); startup folders
- Winlogon `Userinit`, `Shell`, `Notify`; AppInit_DLLs; AppCertDlls
- Image File Execution Options (`Debugger`, `GlobalFlag`); SilentProcessExit
- LSA Security, Authentication and Notification packages
- WMI event filters, consumers and bindings
- Netsh helpers, print monitors, time providers, Winsock providers
- COM hijacks under `HKCU\Software\Classes\CLSID`
- BITS jobs
- IIS native and managed modules, handlers, ISAPI filters, FTP roots on UNC paths
- DNS `ServerLevelPluginDll`, forwarders and zones on the DC
- Accessibility binaries (`sethc.exe`, `utilman.exe`, `osk.exe`) replaced or redirected
- PowerShell profiles (all scopes)
- Accounts: hidden accounts ending in `$`, RID hijacking, Guest enabled, nested privileged groups
- AD: GPOs and SYSVOL, AdminSDHolder, delegation, SID history, `gPLink`
- Optional features: WSL, OpenSSH server, VNC, Chocolatey, remote-access tools
- SQL Server: `xp_cmdshell`, Agent jobs, linked servers, startup procedures


### D. Repository layout

<!-- SECTION: repository layout — to be written. Row: review D521 (drop the "declared competition repo" reasoning; keep lab, Terraform, Packer and red-team material in the private lab repo). Update the tree for v4: module packages, `internal/module`, content directories per module, no Typst, no `rules/imported/`, no `internal/cache` (the depot holds the cache). v3 text: L2390-2427. -->

### E. Glossary

| Term | Meaning |
| --- | --- |
| Action | A typed, Go-native operation with check, apply, verify and rollback |
| Plan | A DAG of actions on specific targets, with dependencies and approval gates |
| Dead-man switch | Rollback that fires on the agent unless it re-establishes its link after a risky change |
| Relay | An agent role that splices its segment's connections to the controller |
| Device proxy | An agent role that splices the controller to a network device's management interface |
| Spool | The agent's crash-safe, sequenced, hash-chained local store of events awaiting acknowledgment |
| Active check | Our own end-to-end test of a service, managed in the UI |
| Scorer-mimic probe | An active check that reproduces Quotient's exact transport for one service |
| Faithful sample, union sweep | The two modes of an active check: one random item and credential as the scorer does, and every learned item |
| Burst, round | One scorer pass over every service; rounds start `Delay ± Jitter` apart |
| PCR | Quotient's password change request: CSV `username,password`, effective immediately in Quotient; entered by a human outside the environment |
| Credlist | A named list of scored accounts in Quotient; PCR uses its path |
| Discovered check | A check the scorer was observed running, proposed as an active check |
| Trace-back | The chain from a change back to the request and source that caused it |
| Hop, chain, campaign | One step of an intrusion; an ordered list of hops; chains merged by shared source, account, hash or C2 |
| Integrity ledger | Reference hashes with provenance used to judge binaries and libraries; alert only |
| Depot | Local known-good copies of binaries and packages used for restores |
| Vantage point | A place from which checks run: controller, in-LAN runner, or the Kali |
| Community ID | A hash of a flow's endpoints that joins records across tools |
| Honeytoken | A fake credential, key or path, unique per host, whose use reveals where it was stolen |
| Tier 0, 1, 2 | Response levels: automatic, one-click, manual with checklist |
| Safe mode | Global switch that suspends automatic responses and plan execution |


### F. PCR list rules

Moved into the `creds` module section (v3 Appendix F, L2456-2459).

### G. Scorer fingerprint table (Quotient at commit `9000379`)

Library versions follow the Go and module versions of whatever build runs at the event; re-learn the hashes each event [Q §6].

| Layer | Observed behaviour |
| --- | --- |
| Timing | A burst of about 15 SYNs per team per box within 25–55 ms every `Delay ± Jitter`; all teams in the same sub-second window |
| SSH | Banner is one of 27 strings; KEXINIT is constant (HASSH `a7230c16…` for the real login, `0a07365c…` for `BadAttempts` logins); `none` then `password`; `pty-req xterm 40x80`; `shell`; one typed line; about 1.3 s dwell; `Failed password` immediately followed by `Accepted password` from the same runner |
| HTTP | `GET`, `Host: ip:port` with the port, a random old User-Agent (a non-signal), `Accept-Encoding: gzip`, `Connection: close`, nothing else |
| TLS | Go ClientHello, no SNI, no ALPN, about 1.5 KB; JA4 `t13i131000_f57a46bbacb6_ab7e3b40a677` for Go 1.25 |
| DNS | A (or MX) question, RD set, no EDNS, random id and port; a duplicate query on deadline |
| ICMP | go-ping, 24-byte payload, seq 0, random id |
| SMTP | `EHLO localhost`, `AUTH PLAIN`, `MAIL FROM:<u> BODY=8BITMIME`, `RCPT TO:<other user>`, 16-hex subject, 64-hex body |
| IMAP, POP3, FTP | IMAP: 6-character tag, `LOGIN`, `LIST "" "*"`, `LOGOUT`. POP3: `USER`, `PASS`, `NOOP`, `STAT`. FTP: `USER`, `PASS`, `FEAT`, `TYPE I`, `OPTS UTF8 ON`, `EPSV`, `RETR`, `QUIT` |
| SMB | Negotiate, NTLM (flags `0xe2888215`, no Seal), tree `\\ip:445\share`, the domain in AUTH is the server's own name |
| WinRM | `POST /wsman`, `Go-http-client/1.1`, SOAP shell-create first without Authorization |
| RDP, tcp | Handshake, zero payload, held open 6 ms to 100 s with keepalives |
| Custom (MSSQL, Splunk, RDP-with-auth) | Script-defined; label by burst, port and account only |

### H. First-hour mitigations

Moved into the `hardening` module section (v3 Appendix H, L2479-2495).

### I. Rule backlog

The 81 proposed rules [PR] group as: credentials and accounts (P01–P05, P14–P16), Zerologon and AD (P06, P62–P64, P68–P69), local-root and exposure (P07–P09), web and database (P10–P11, P39–P42, P44, P48–P49), Linux persistence and evasion (P12–P13, P17–P25, P27–P32, P38), integrity and masquerade (P26, P60–P61), network and covert channels (P33–P35, P45, P73–P74, P79), services and sabotage (P50–P53, P75–P78), Windows persistence (P43, P46–P47, P54–P59), defense evasion (P65–P67), devices (P70–P72), and re-infection and hardware (P80–P81). Each ships when its producer exists and its fixture passes.

### J. Removed in v4

One line per capability v3 had that v4 drops, with the reason. Cut code is deleted; git history is the archive (decision 2). Review ids in parentheses.

**Cut rows:**

- `phylax doctor` capability probe (D20): duplicate of the `hello` capabilities block and the Platform page; one probe, shown in the UI.
- Patch proxy module `patch_proxy` (D84, D217): a new listener and protocol to maintain; packages install from the depot over `fetch`, plus a time-boxed egress allowance for misses.
- ALPN `phylax/patch` (D112): goes with the patch proxy.
- Proc connector cross-check and divergence alerts (D89): the code chose audit over netlink plus `sock_diag`; one exec source is the norm.
- Optional eBPF exec sensor (D92): audit is the chosen path and a kernel rootkit blinds audit and eBPF alike; reopen only if the exec-storm test (T43) fails.
- Sigma importer `phylax rules import-sigma` (D314): no code, about 98 hand rules exist, and an importer is a compiler to maintain; hand-port the rules we want.
- Sigma-derived scheduled searches on Splunk (D318): duplicates on-host detection; bulk Sigma searches were unusable at the one team that tried.
- `hunt.pii` personal-data scan (D404): no evidence it scores.
- Windows raw-socket capture with `SIO_RCVALL` (D235): unbuilt and unreliable; Windows network coverage comes from Sysmon 3, 5156/5157 and Palo logs.
- Kerberos metadata parsing and file carving from HTTP, FTP and SMB (D242): no evidence it scores or speeds an IR; Sysmon and DC events cover Kerberos.
- Decoys on public addresses (D389): the organizer's perimeter assessment scores extraneous services, so public decoys lose points; decoys stay inside the LAN.
- Pre-written inject drafts (D491): decision 6, no prewritten inject responses.
- Session recording (D10): no design and no code; the action audit trail covers what we need, and no peer credits recordings with a win.
- ClamAV on Windows (D441): Defender is already there and protected by tier 0.
- Offline bundle collection mode (N3.5): simplicity (A4.Q3); the console one-liner already covers unreachable hosts.
- Exec-time YARA gate on `FAN_OPEN_EXEC_PERM` (N5.10): a hung permission event blocks exec on a scored host (A5.Q3).
- ModSecurity plus CRS plan (N5.11): simplicity, and turning the engine on can fail scored web checks (A5.Q3).
- Event archive and export (N11.2): Phylax cannot reach the portals; records live outside Phylax (area 11 answer).
- Inject tracker and board (D480): inject tracking is out of scope (area 11 answer).

**Parts removed from kept rows:**

- `modules.disable_loading` action (D157): unused; `kernel.modules_disabled` is one-way and does nothing against prebaked modules (A2.Q3, A3.Q2).
- Detection rules D19 promiscuous NIC and D20 allowed-protocol abuse (D339): no evidence red used them against us.
- Kali NAT-behaviour, blocked-source and Palo-load probes (D379): no evidence they score.
- Splunk REST parser (D241): the check and logs cover it.
- IIS templates, request linking and reference checks (D163, D289, D400): IIS is not in the 2027 environment.
- Policy, plan, risk-register and framework inject templates (D490): decision 6; one memo shell stays as a generator.
- NISE upload integration (D489): a human uploads in a browser; the Nextcloud fallback becomes the file-export path.
- Typed regex parameters for pre-approved `host.exec` tools (D85): simplicity (A4.Q3).
- Dropbear host-key regeneration in `net.vyos_review` (D531): simplicity (A5.Q3).
- Rule-format `macros:`, `maturity:` and `requires:` (D306-D311): simplicity (A4.Q3).
- Quotient portal poll, pasted credlists and pasted Up/Down table as primary inputs (D278-D280): Quotient is unreachable from inside; an optional hand-entered Up/Down note remains.
- `pcr.submit` (D430, D167): PCRs are entered by a human outside the environment.
- `av.clamav` integration action (D168): goes with D441.
- Typst in the cache, templates and controller (D442-D445, D490; Known bug 3): decision 7, pure-Go PDF.
- Four cache tiers (D442-D445): one signed index with a priority field.
- In-process kernel-memory accounting (D67): enforce through systemd and the Job Object; report kernel-held memory only.
- Agent-only build tag (D66): deferred in v3 round 4 and not needed.
- Separate Integrations and Cache UI pages (D475, D476): folded into the Platform page.
- Separate Egress and C2 page (D470): folded into the Traffic page.
- Printed per-role checklists as the primary form (D503): replaced by the host x step grid; print is the fallback.
- Separate `crossview` and `scan` agent modules (D80, D83): their checks are hunt content and `integrity` work.
- Process-connector leg of the cross-source tripwires (D103): goes with D89.
- Sinkhole leg of rule D13 (D333): pending the C2 fingerprinting lab.
- Campaign merge as the unit of an IR (D304): a view only; one IR per narrative or persistence mechanism.
- `rotation: pcr_transaction` for all mail users (D195): no mass rotation.
- `sysadmin` protected until the PCR list says otherwise (D433): no admin accounts are scored.
- Account-guessing inference in scorer-account learning: never built as a separate path; learning from observed logins stays (area 7 revision).

**Removed v3 positions:**

- Goals with minute targets (T+25, T+40, 30 s to heartbeat, 5 minutes to an IR draft): decision 9.
- The "multi-user access" non-goal's SSH-tunnel escape hatch: A11.Q1, one controller screen.
- Reasoning from competition rules (the packet's source-filtering penalty wording, repository and tooling rules, "questions for competition officials"): decision 3. The scoring mechanics behind them stay.
- Event-specific behaviour by profile: decision 4.
- The build plan, effort estimate and milestones (v3 §Build plan): replaced by the review's scope and the per-module retrofit order; no time goals.
