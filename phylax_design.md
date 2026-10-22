# Phylax — Design Doc

Oct 22, 2026 · @David

## Summary

Version 3. This is the design for a complete rewrite. The earlier Go code is discarded and nothing here is built around it. The architecture of v2 survives where the evidence still supports it: one Go agent on every host, everything sent outbound to one controller on ubuntu-wkst, operators driving a web UI bound to localhost, work planned as a DAG of typed, Go-native actions that you can see, approve and watch run.

The 2027 environment is the reference case: one flat LAN (`172.20.240.0/24`) behind one Palo Alto, a VyOS router above it, and a Kali VM on a VyOS side leg outside the Palo. Scoring is done by Quotient. Relay support stays for other shapes, but no in-LAN host needs a relay.

On top of hardening and response, the platform does these things:

1. **Keeps active checks in step with the scorer.** It models Quotient's round clock, burst, credential pool and item sampling, and it discovers what the scorer checks from passive capture.
2. **Labels all traffic** to our services as the scorer, us, or everyone else, by behaviour and never by address.
3. **Notices any change to our services** within a minute, and traces each change back to its cause.
4. **Keeps an integrity ledger of every binary** that matters and alerts when one is modified or replaced, including the ones that were already replaced at drop flag. Alert only.
5. **Builds lightweight attack chains** across hosts from the telemetry it already has, merges them into campaigns, and turns them into remediation lists for incident reports.
6. **Uses the Kali as an external vantage point:** Quotient-faithful checks through the public path, PCR credential verification, external perimeter scans and egress canaries.
7. **Rotates scored credentials as a two-system transaction** (host plus Quotient PCR), timed to the scorer's round clock.
8. **Runs offline-first.** Every reference hash, package, rule set and tool is cached locally before it is needed, because the internet is slow.
9. **Orchestrates optional open-source sensors** (Wazuh, Sysmon, Suricata and Zeek, YARA, Splunk forwarding). Nothing on the critical path depends on them.

Simplicity is a hard requirement. Every place this design adds complexity is marked **Complexity flag**, and all of them are collected in the complexity register near the end.

### Conventions

- **Decision ids.** `D-1` to `D-9` are the owner's decisions of 2026-10-22 (`ccdc-private/strategy/phylax-proposals.md` §0). Detection ids (`D1`, `D5d`, `D18`) are rules. They are unrelated.
- **Source tags.** Non-obvious decisions cite the research that supports them, as `[tag §n]`. All files are under `ccdc-private/`.

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
| `CR` | `strategy/phylax-code-review.md` (findings on the discarded code; they are requirements here) |
| `PRO` | `strategy/phylax-proposals.md` |
| `PKT` | `team-packets/2027-preview.md` |
| `LAB` | `strategy/lab-ccdc27.md` |
| `RT` | `lab/red-team/README.md` and `lab/red-team/campaigns/` |
| `IJ` | `injects/by-code/` (SVRA12T, SOFT04A, TOOL29T, SOCS30T) |

## What changed from v2

Every change below has either an owner decision or research evidence behind it.

### Decisions

| Change | Why |
| --- | --- |
| Complete rewrite; build the full design, no triage by milestone | D-6. The old code was reviewed and found mostly unwired, fail-open in places and Linux-only [CR §1] |
| New: binary integrity ledger (alert only) | D-1. In 2026 the red team replaced Postfix with a proxy and `dns.exe` with a kill-switch build; v2's FIM is silent about prebaked binaries [PRO §2, COV §6] |
| New: lightweight attack chains | D-2. Half of the red-team lead's IR rubric is remediating the attack path [TTP §0]; v2's trace-back stops at the host boundary [PRO §3] |
| New: the Kali as an external vantage point | D-3. It sits outside the Palo, on the scorer's side of the NAT [PKT §2, PRO §4] |
| The controller stays on the LAN (ubuntu-wkst) | D-4. Running it on the Kali would need outbound access from the LAN to the Kali |
| Offline-first: caches for hashes, packages, rules, tools and the Sysmon binary | D-5. Internet is available but slow; no proxy is mentioned in the packet [PKT §4.3] |
| Check discovery, active checks, traffic labels and rotation rebuilt around Quotient | D-7. Quotient was built and run in Docker, and its checks read against source [Q §0] |
| Obscurity is allowed: randomised agent name and path, renamed Sysmon driver and service | D-8. Reverses v2's "no hiding" principle [OA §5.6, WT §9.8] |
| OSS may run alongside Phylax; Wazuh gets a deploy plan | D-9. Injects for endpoint protection and central logging recur [IJ SVRA12T, SOFT04A, TOOL29T, SOCS30T] |

### Environment (the 2027 packet)

| Change | Why |
| --- | --- |
| Reference manifest is the flat 2027 layout; relays stay as an option | One LAN, one Palo, Kali on a VyOS leg; relays are moot for in-LAN hosts [PKT §6] |
| East-west traffic never crosses the Palo, so per-host capture and cross-host stitching carry the weight | Same LAN segment [PKT §6, PRO §1] |
| Scored services: SSH, ping, IMAP and webmail, Splunk query and 8089, SMB share, RDP, MSSQL 1433, WinRM, plus HTTP/DNS/mail/FTP. TFTP and NTP are gone | [PKT §3] |
| Scored passwords change through Quotient PCR, not tickets. PCR is a transaction with the host change | [PKT §6, Q §5, Q §9.1] |
| `sysadmin` may be scored; it is protected until the PCR list says otherwise | The packet drops the "admin accounts are unscored" sentence [PKT §4.3] |
| No per-VM scrub: a whole new reservation is the only reset, so re-enrollment handles "everything is new" in bulk | [PKT §4.3] |
| Hardening plans never disable SSH, WinRM or RDP where scored; the manifest declares them | These are scored on Linux hosts, the AD host and the MSSQL host [PKT §6] |
| OS matrix: Rocky 9 (SELinux, firewalld), Ubuntu 22.04, Debian 12, Server 2019 and 2022, Windows 11. Fedora and Oracle drop out of the reference set but stay supported | [PKT §6, OA §6] |
| Four-hour single sitting: cold-start speed matters more than in a two-day event | [PKT §5.7] |
| Palo management is on the LAN (`172.20.240.200`); VyOS is reached through the Palo | [PKT §2] |

### Scorer model (Quotient)

| Change | Why |
| --- | --- |
| The scorer is a periodic burst at `Delay ± Jitter`; Phylax estimates both from capture | [Q §3, Q §9.2] |
| The scorer is identified by behaviour (fingerprint table), never by address | Docker NAT, Divisor re-draws sources every round [Q §6] |
| Discovery learns a service in 3 rounds and its item set over the whole event; checks test the learned union | One random item and one random credential per check per round [Q §9.8, SP §A2] |
| Active checks reproduce the scorer's exact transport and are stricter than Quotient where it is lax | Quotient passes a 404 with no regex; SSH commands pass on any output [Q §9.7] |
| SLA streaks are tracked per service; dropped rounds are not incidents | [Q §9.5, Q §9.12] |
| Scorer failed logins (`BadAttempts`) are exempt from lockout and brute-force detection | [Q §9.6, SH never-list 1] |
| A read-only portal poll is designed but needs organizer approval; the default is operator-fed verdicts | [Q §4.4] |
| The "never do these" list is a machine-checked lint on every plan | [SH never-list] |

### Agent and platform (from the research and the code review)

| Change | Why |
| --- | --- |
| Linux exec telemetry: kernel audit over netlink is primary; the proc connector is a cross-check; eBPF is a gated option | The proc connector carries no argv and drops events [OA §0.1, OA §4] |
| FIM: audit directory watches plus a hash sweep that is the source of truth; fanotify only for honey files | inotify is non-recursive, has no actor and overflows [OA §5.2, CR §3.12] |
| Network attribution: `sock_diag` plus an fd-inode join, audit `connect` where affordable, Community ID on every flow | Polling misses short connections [OA §5.3] |
| Windows from day one: Sysmon plus `EvtSubscribe` with persisted bookmarks, Sysmon config as code | The old code did not build for Windows [CR §6, OA §5.4] |
| The spool is segment files with CRC frames, tail repair and gap records | The old spool bricked on a torn write or a shed [CR §3.10, OA §5.8] |
| Telemetry loss is visible: `telemetry_gap` events and a per-module health block in every heartbeat | Every source can lose events silently [OA §0.10] |
| Self-protection is detection plus recovery, with systemd watchdog, immutable bit and audit watches on our own files | No open agent has real Linux tamper resistance [OA §5.6] |
| Resource caps are enforced twice: in-process and by systemd or a Windows Job Object | In-process limits are cooperative [OA §5.7] |
| Response uses pidfd, `cgroup.kill` and a quarantine nftables table with an auto-revert timer | [OA §5.9] |
| Rules carry inline tests, an alert or act mode and a global alert-only override; Sigma is imported at build time | [OA §5.5, DR §4, WT §9.5] |
| ATT&CK ids are v19 and validated in CI against a pinned dataset | Three shipped rule files used revoked ids [DR §5] |
| TLS identities are ECDSA P-256; plan signing stays Ed25519 | Windows SChannel cannot negotiate Ed25519 server certificates, which would break the PowerShell bootstrap [CR §2] |
| TLS 1.3 only on agent streams; 1.2 only for bootstrap downloads | [CR §2 trust model] |

### Requirements taken from the code review

| Change | Why |
| --- | --- |
| Every endpoint is authenticated; the operator UI is on its own `127.0.0.1` listener with a login and CSRF; the agent port serves only agent streams and bootstrap downloads; "loopback means trusted" is gone | [CR §3.1] |
| A real agent-side dead-man switch: persisted state, an OS-level timer that survives an agent crash, rollback without waiting for a reconnect | [CR §2 dead-man] |
| Step signatures are mandatory and cover the whole step; agents enforce strictly increasing `(epoch, seq)` and the plan id | [CR §3.2] |
| TLS handshakes run per connection, never in the accept loop; queues, decompression and per-agent rates are bounded; deadlines everywhere | [CR §3.3, CR §3.6] |
| Enrollment is idempotent and cannot wedge after a dropped connection | [CR §3.7] |
| Critical files (`/etc/shadow` and others) are replaced atomically, preserving aging fields and SELinux labels | [CR §3.9] |
| Generated nftables is validated with `nft -c` in CI and never drops DHCP, ICMP or IPv6 blindly; the sinkhole redirect lives in a `nat` chain | [CR §3.8] |
| Modules are configured from the manifest through the signed `config` message in production, not only in tests | [CR §3.4] |
| `go test -race` is a CI gate; module panics and fatal map races are designed out | [CR §3.5] |

### Detection, response and tooling

| Change | Why |
| --- | --- |
| Detection catalog extended: Zerologon, binary integrity, service proxying, hidden accounts, `chattr`, unit capabilities, PHP overrides, DB-level changes, AD change events, covert channels, and more | [COV §6, PR] |
| The prebake hunt re-runs every 10 minutes and after every restore, re-enrollment or reset | Prebaked items are not "changes" [COV §6.10, TTP X-2] |
| Adopted from winning teams: remote-access kill list, post-hardening adversarial verification, scheduled YARA with a C2 corpus, learn-then-enforce egress keyed on binary hash, session recording, `hunt.pii`, stateless break-glass credentials, opt-in immutable tail, expected-state baselines | [WT §9] |
| First-hour mitigations from the vulnerability research become plans | [SV R2.4] |
| Device adapters follow the safe-change protocol per device. VyOS gets an SSH-armed soft revert, not `commit-confirm` (which reboots). PAN-OS gets our own thin XML-API client | [DA §1.12, DA §2.4, DA §1.15] |
| The lab is the ccdc27 replica with a real Quotient as scorer; purple-team runbooks give the campaigns and the metrics | [LAB, RT] |
| v2's "cut list" is replaced by a sequencing section; nothing is downscoped | D-6 |

### Kept from v2

One binary in two modes. Agents dial out. Pinned keys, no PKI. Signed plan steps. Go-native actions with an approved `host.exec` escape hatch. Plans as DAGs with dry-run diffs. Per-host locks and safe mode. Tiered response. Deception with record-only decoys. The prebake hunt against reference builds. Controller snapshots with epochs. Localhost UI with a login. The complexity register discipline. The test-first lab approach.

## Goals

1. Rotate credentials and enforce host firewalls on every host within 25 minutes of drop flag, and finish service hardening by T+40, losing no action to a dropped connection.
2. Have an agent heartbeating within 30 seconds of first contact, on Linux and Windows alike.
3. Complete every scored-account password change as one host-plus-PCR transaction, with at most one failed scorer round per affected user.
4. Learn the scorer's service set within 3 rounds, grow its item set for the whole event, propose a new check within one round of the scorer starting it, and flag checks it has stopped using. Operators can add, edit or remove active checks at any time.
5. Label every connection to a scored service as scorer, us or other, and flag attack-like traffic within "other".
6. Detect any change to a service's content, configuration or behaviour within 60 seconds, and build the trace-back automatically.
7. Detect a modified or replaced binary: within 5 seconds of its first execution, within 60 seconds for a pinned service binary, and within 15 minutes at rest. Alert only; restoring is one click.
8. Show every incident as an attack chain with a remediation item per hop, and merge related chains into one campaign.
9. Know whether a service is up for the scorer from outside the Palo, with checks that reproduce Quotient's transport, and know within a day's scan cycle that the perimeter or the egress policy has drifted.
10. Catch C2 attempts through denied egress and the sinkhole, attributed to a process and a binary hash.
11. Turn red-team looting into precise alerts that say which host was looted and roughly when.
12. Draft an incident report in 5 minutes or less, and a routine inject in 10 minutes or less.
13. Work with the cache alone: no decision in the event depends on a live internet fetch.
14. Adapt to a new infra shape by editing the manifest, not the code.
15. Never cause a scoring failure by hardening: every plan node is checked against the scoring-safety rules and verified with the scorer's own transport.

## Non-goals

- A full EDR. No kernel drivers; eBPF only as a gated optional sensor behind the same event schema.
- Any contact with scorer or red-team infrastructure. We observe only what reaches our hosts and what we send from our own vantage points to our own addresses.
- Anything inline in the scoring path.
- Automatic actions on scored state (scored accounts, scored service config) without a human. The integrity ledger never restores anything by itself (D-1).
- Tamper-proofing on hosts the red team owns. Obscurity and fast recovery are used instead.
- A general graph or provenance engine. Attack chains are rows and a few linking rules.
- Dynamic topology: relay election, backup relays, auto-discovery.
- An agent self-update system. One narrow action replaces the binary.
- Multi-user access, roles or remote UI access.
- Replacing the organizers' portals. The PCR step stays a human act in the Quotient portal unless the organizers approve scripting it.

## Success metrics

| Metric | Target | Measured by |
| --- | --- | --- |
| Cold-start hardening of all servers | Credentials and firewalls in 25 min or less; services by T+40 | ccdc27 lab dry run |
| Actions lost to disconnects | 0 | Agent checkpoint logs |
| First contact to heartbeat | 30 s or less, Linux and Windows | Lab test T21 |
| Hardening-induced failed scorer rounds | 0, other than one per PCR user | Real Quotient in the lab (T34) |
| PCR transactions confirmed by a passing scorer login | 100% | Lab, Quotient admin API |
| Scorer services discovered | 100% within 3 rounds | Quotient in the lab (T14, T15) |
| Scorer round clock estimate (Delay, Jitter) | Within 1 s after 10 bursts | Lab (T30) |
| False checks invented from noise | 0 over 2 hours | Orange-team traffic (T15) |
| New scorer check proposed | Within one round | Hot-reloaded `event.conf` (T14) |
| Kali-run faithful check agrees with the scorer's own result | 98% of rounds or more, after calibration | Quotient admin API vs Phylax (T39) |
| Service change detected | 60 s or less | Lab defacement and config tamper tests |
| Replaced binary alerted at first exec | 5 s or less | Lab (T31) |
| Replaced pinned service binary alerted | 60 s or less | Lab (T31) |
| Planted prebaked implants found | 90% or more by T+15 min | Contaminated golden images (T01) |
| Attack chain completeness | 100% of expected hops for campaigns 01 and 03 | Purple-team runs (T33) |
| Trace-back reaches the source IP for webshell-driven changes | 90% or more | Lab red-team campaigns |
| Denied callback attributed to a process | 60 s or less | Lab implants |
| Alerts to IR draft | 5 min or less | Timed dry run |
| False-positive alerts, scorer and orange traffic only | 5 per hour or fewer | Dry run with all simulators (T20) |
| Untagged alerts during our own hardening | 0 | Purple-team false-positive run (T36) |
| Cache-only operation | All plans, checks and ledger lookups work with no internet | Offline drill (T40) |

## Constraints and assumptions

The competition rules shape this design more than any technology choice does. The 2027 environment (the 2026 Midwest Invitational packet; the labels in it say "2027 State") is the reference case, but infra changes every year, so nothing below depends on specific hosts. Packet citations use the Invitational numbering [PKT §6].

### From the team packet

| Constraint | Packet section | What it means for the design |
| --- | --- | --- |
| Public services must be generally available from all source IPs. Filtering by source "may incur a penalty when detected". Single malicious IPs may be blocked. No knife-edge access. | Systems 9 | The scorer is identified by behaviour, not by address. Blocking is single-IP and one-click. The block action double-checks the IP against scorer fingerprints. Host and Palo plans never restrict scored ports by source. |
| Traffic generators send traffic, some of it malicious, from random source IPs. There is no Orange Team in the Invitational packet; earlier events had one. | Systems 5 | Detections and decoy severities are tuned against that noise. The lab keeps an orange-team simulator for regionals. |
| Scored checks: HTTP and HTTPS content, SMTP, POP3/IMAP/webmail, FTP, DNS, SSH, ping, Splunk query, Splunk management on 8089, SMB share with planted SOP files, RDP with authentication, MSSQL 1433 login and query, WinRM PowerShell on the AD host. Other scored services may appear and discovering them is the team's job. | Functional services | Parsers, probes and the scorer model cover all of these. Check discovery matters more, not less. |
| Business tasks add or change services. A "water facility" theme appears in the SMB check. | Business tasks | The manifest is the single source of truth. An inject change is a manifest edit plus a plan. |
| Scored-account passwords are changed by the team in Quotient's PCR tab: CSV `username,password`, immediate, no scoring manager. Blue Team members may change passwords but not usernames. | Play 11, intro | Rotation of a scored account is a host-plus-PCR transaction (§ Credentials). Usernames are never changed. `sysadmin` is the only default account listed and may be scored. |
| Individual service tracking is available to teams in Quotient. Blue Team should use service reports and internal testing. | Scoring 2 | An operator-fed or read-only polled verdict channel is legitimate, subject to organizer confirmation (§ Active checks). |
| Competition systems have internet access, monitored. No proxy is mentioned. Free and open-source software only; no free trials unless directed. | Internet 1, Software | The internet is slow (D-5). Everything is cached. Wazuh and other OSS are allowed. No trial software. |
| No per-VM scrub. A new lab reservation is the reset; service scores are retained. | Systems 10 | Re-enrollment must handle "all ten VMs are new". Every destructive action needs a revert path of its own. |
| Containerizing is allowed only on the same platform. Moving a system to another VM is not. | Systems 8, Play 8 | Phylax does not move services. Hardening is in place. |
| Maintain ICMP on all competition devices and systems. Ping is also scored. | Play 12 | ICMP echo is never blocked on hosts, Palo or VyOS. Egress policy and canaries respect it. |
| User workstations can't be re-tasked. This covers the Ubuntu workstation, Windows 11 and Kali. | Systems 11 | The controller runs on the Ubuntu workstation; the Kali runs checks and scans. Both need confirming with officials (§ Risks and open questions). |
| Internal addressing and hostnames can't change. | Systems 6–7 | Nothing in the design renumbers anything. |
| Teams own any scoring breakage their defenses cause. | Play 12 | Every automatic action is followed by a health check. There is a global safe mode, and a scoring-safety lint on every plan. |
| IR reports need IPs, timelines, cracked passwords, impact and remediation. IR is a fixed 20% of the score together with red-team assessment. | Scoring 5 | Chains, trace-back timelines and decoy sightings feed the IR drafter. Half the red-team lead's rubric is attack-path remediation [TTP §0]. |
| Inject responses are PDFs. NISE (now `injects.ccdc.events`) times are US Central. | NISE | Drafters render PDF. Everything stores UTC and displays America/Chicago. |
| The Red Team has no access outside the Cyber Stadium perimeter. | Rules | The Kali sits outside the Palo but inside the stadium. It still sees only what the red team sees at the perimeter [PKT §2]. |

### Assumptions about the infra

- **Shape.** The reference is one flat LAN behind one Palo Alto, a VyOS router above it, and a Kali on a VyOS side leg. The manifest also describes multi-segment shapes (2026 had two segments), so the relay design stays.
- **The controller host** is the Ubuntu workstation. It has a DHCP address on the LAN and no public address of its own. The address must not change during the event; if it does, there is a manual command per agent (§ Enrollment).
- **Operating systems:** Windows 10 or Server 2016 and newer, Linux with kernel 3.2 and newer. The reference set is Rocky 9, Ubuntu 22.04, Debian 12, Server 2019 and 2022, Windows 11. Kernel generations to expect: Ubuntu 22.04 5.15, Debian 12 6.1, Rocky 9 5.14 with heavy backports [OA §6].
- **Credentials at drop flag.** Every host has `sysadmin:Changeme1!`; the Palo has `admin:Changeme123`; VyOS has `vyos:vyos` [PKT §2]. The red team knows them.
- **The red team** may already have persistence on hosts at drop flag, and starts at the drop flag [TTP §1].
- **Console access through NETLAB** is always available as break-glass, and is the only way in before credentials are known.
- **Internet** is available from every host and slow. Treat it as a bonus, never a dependency.
- **Scorer** is Quotient. Delay, Jitter, Timeout, SLA threshold, Divisor and debug visibility are unknown until measured [Q §0].
- **Free disk:** the Ubuntu workstation disk must hold one event's data plus the caches. The Invitational is a four-hour session; the regional is two days. Measure in the lab.

## Architecture overview

Phylax is one Go binary that runs in two modes: `phylax serve` on the controller and `phylax agent` on every host. Hosts always open the TLS connections, outbound. The controller holds the plans, the event store, the analysis engines, the device adapters and the web UI. The agent does all on-host work, plus whichever roles the manifest gives its host. One binary means one release artifact per OS, and the agent and controller can never disagree on the protocol version. **Complexity flag:** every host carries the controller's code too, which makes the binary bigger (§ The agent, footprint targets).

Maintenance commands live in the same binary: `phylax init`, `phylax doctor` (capability probe), `phylax cache` (build and sync), `phylax rules` (test and import), `phylax ledger` (build and look up), `phylax set-controller`.

```text
                         ┌────────────────────────────────────────────┐
  VyOS side leg          │  LAN 172.20.240.0/24 (flat, one Palo)       │
  172.17.0.0/24          │                                            │
  ┌──────────┐  Palo     │  rocky-ecom .10   ubuntu-email .15          │
  │  Kali    │◄─rule────►│  debian-splunk .20  ad .100  mssql .120     │
  │ agent:   │  (one     │  win11-wkst (DHCP)                          │
  │ check_   │  port)    │  ubuntu-wkst (DHCP)  ◄── phylax serve       │
  │ runner,  │           │                          (controller, UI    │
  │ scanner, │           │  every host: phylax agent, dials out        │
  │ canary   │           │  Palo mgmt .200, VyOS via Palo              │
  └──────────┘           └────────────────────────────────────────────┘
        every arrow points toward the controller; Quotient's runners
        reach our public addresses 172.25.(20+T).x through VyOS and the Palo
```

Every connection is opened by the host side. The Kali agent dials the controller through VyOS and the Palo, which needs one declared firewall rule and a static NAT (§ The Kali as an external vantage point). Relays exist only for segments that cannot reach the controller.

### Components

| Component | Runs on | Responsibility |
| --- | --- | --- |
| `phylax serve` | Controller (ubuntu-wkst) | Accepts agent connections. Holds the event store (SQLite) and the encrypted secrets vault. Compiles the manifest into plans, agent configs and firewall policy. Runs plans, correlation, check discovery, the round-clock model, trace-back, the integrity ledger, attack chains and the drafters. Talks to network devices through adapters. Serves the web UI on its own localhost listener. |
| Active checker | Controller, as a module of the main process | Runs the active checks on its own scheduler, with per-check timeouts and panic recovery. Its list is managed in the UI and fed by check discovery, but it shares no code with discovery. |
| Web UI | Controller, `127.0.0.1` only, separate listener | Server-rendered with htmx, live updates over Server-Sent Events. Login, session cookie and CSRF on every state-changing request. |
| Cache and depot | Controller | Content-addressed store of packages, reference hashes, rule sets, tools and installers. Cache-through proxy for patch windows. See § Offline-first. |
| Integrity ledger | Controller | Reference hashes with provenance for binaries and libraries, and the lookup service agents use through the controller. See § Binary integrity ledger. |
| Chain builder | Controller | Builds hops, chains and campaigns from events. See § Attack chains. |
| `phylax agent` | Every host, including the controller and Kali | Collection, local detection, automatic responses, action execution, packet capture, decoys, exec-time hashing, and a crash-safe spool of everything it observes. Runs as root or SYSTEM, plus one unprivileged child process for decoys. |
| Agent roles | Hosts chosen in the manifest | `relay`, `device_proxy`, `check_runner`, `scanner`, `canary`, `decoys`, `capture`. All are config switches on the same binary. |
| Device adapters | Inside `phylax serve` | Palo Alto (PAN-OS XML API) and VyOS (SSH, with HTTP reads) as the reference. Cisco FTD (FDM) is an optional third, built when an infra includes it. |
| Sysmon | Windows hosts | Process, network, registry, file, WMI, DNS and image-load events, which the agent reads. Installed and kept alive by the agent, under a renamed driver and service. |
| Optional OSS sensors | Chosen hosts | Wazuh manager and agents, Suricata and Zeek on pulled pcaps, YARA-X, Splunk HEC forwarding. Deployed and health-checked by Phylax; never on the critical path. See § OSS alongside Phylax. |

### Design principles

1. **Simplicity first.** One binary, one transport, one source of truth. Each new listener, daemon, host-binary dependency or runtime discovery mechanism needs an entry in the complexity register.
2. **Hosts dial out.** No host opens an inbound port for management. The relay host and the decoys are the declared exceptions.
3. **Go-native by default.** Agent actions call OS interfaces (syscalls, netlink, D-Bus, Win32, COM and WMI, LDAP), not host binaries. Running a host binary is an explicit action that's labeled in the UI.
4. **Detect and act on the host; correlate and report on the controller.** Detection and automatic response keep working while the link is down.
5. **One source of truth.** Firewall policy, plans, health checks, decoys and roles are generated from the manifest. Manual host changes are adopted back into it or reverted.
6. **Passive in the scoring path.** Capture, replay and observe. Never intercept scored traffic.
7. **Trust only off-host data,** and treat everything an agent sends as untrusted input.
8. **Humans approve anything destructive or anything that touches scored state.** Detection that could suggest a restore only alerts.
9. **Static, declared topology.** No election, discovery or failover. A new infra shape is a new manifest.
10. **One TLS connection per logical stream.** No multiplexing layer.
11. **Never break the scorer.** Every plan node is linted against the scoring-safety rules and verified with the scorer's own transport [SH never-list, Q §9.4].
12. **Offline-first.** Every dependency is cached before it is needed. A live fetch is an optimisation, never a requirement (D-5).
13. **Fail closed.** No unsigned step runs, no unauthenticated mutating endpoint exists, no module runs without its config. A degraded sensor is reported, not silently skipped [CR §3, OA §0.10].
14. **Obscurity is a cheap extra layer, not a security boundary** (D-8). Names and paths are randomised per event; nothing depends on them staying secret.
15. **OSS is an optional sensor.** Phylax owns orchestration, integrity, chains and checks. OSS tools add detection and evidence where they are cheaper than building, and their health is monitored like any other module (D-9).

## Topology, relays and firewalls

Topology is declared, not discovered. The manifest lists the segments, the controller host, and one relay host for each segment that can't reach the controller directly. The 2027 layout needs no relay for any LAN host. The Kali is the one host outside the LAN, and it reaches the controller through a declared firewall rule.

### The reference manifest (2027)

```yaml
# manifest/topology.yml
team: 12                                   # placeholder; public pool is 172.25.(20+team).0/24
controller:
  host: ubuntu-wkst                        # DHCP on the LAN; reservation requested (§ Risks)
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
      public: "172.25.{{ 20 + team }}.30"  # free address in the pool; maps to the controller (§ Kali vantage)
      allow_from: kali                     # the Palo rule allows only the Kali's source address
      port: 7443
devices:
  palo1: { vendor: panos, mgmt: 172.20.240.200, segment: lan }
  vyos1: { vendor: vyos,  mgmt: 172.16.0.254,  segment: lan, via: palo1 }
```

```yaml
# manifest/hosts.yml
hosts:
  rocky-ecom:      { segment: lan, ip: 172.20.240.10,  public: "172.25.{{ 20 + team }}.10",  os: { family: rhel,    distro: rocky,   version: "9" },      roles: [capture, decoys] }
  ubuntu-email:    { segment: lan, ip: 172.20.240.15,  public: "172.25.{{ 20 + team }}.15",  os: { family: debian, distro: ubuntu,  version: "22.04" },  roles: [capture, decoys] }
  debian-splunk:   { segment: lan, ip: 172.20.240.20,  public: "172.25.{{ 20 + team }}.20",  os: { family: debian, distro: debian,  version: "12" },     roles: [capture, decoys] }
  ad:              { segment: lan, ip: 172.20.240.100, public: "172.25.{{ 20 + team }}.100", os: { family: windows, version: "server-2022" },           roles: [capture, check_runner] }
  mssql:           { segment: lan, ip: 172.20.240.120, public: "172.25.{{ 20 + team }}.120", os: { family: windows, version: "server-2019" },           roles: [capture, decoys] }
  ubuntu-wkst:     { segment: lan, ip: dhcp, os: { family: debian, distro: ubuntu, version: "22.04" },       roles: [controller, capture, check_runner] }
  win11-wkst:      { segment: lan, ip: dhcp, os: { family: windows, version: "11" },                        roles: [capture] }
  kali:            { segment: kali_leg, ip: 172.17.0.2, os: { family: debian, distro: kali, version: "2026.2" }, roles: [check_runner, scanner, canary] }
```

The public addresses are the same last octet as the internal ones. The workstations and the Kali go out through VyOS source NAT (`172.31.(20+team).2`), so they have no public address of their own [PKT §2]. Hosts with the `decoys` role never decoy on a scored port (§ Deception).

### Roles and links

- **Agents in the controller's segment** dial the controller directly. On the 2027 LAN that is every host but the Kali.
- **The Kali agent** dials the controller's public address through VyOS and the Palo, under one Palo rule and one static NAT.
- **Agents in a segment that cannot reach the controller** dial their segment's relay, which splices each connection through. Chained segments chain relays. This is v2's relay design, unchanged, for other infra shapes.
- **Link direction is always child to parent.** A segment that can make no outbound connection at all would need the direction flipped for that one link. **Complexity flag:** not built unless an infra actually requires it.
- **A dead relay** cuts its segment off. Agents there keep detecting, responding and spooling locally until it's back. Restore it with the console one-liner. No backup relay unless lab testing shows relay loss is a real problem.

### How the relay works

The relay is a dumb splicer, which keeps it simple and keeps it from being worth attacking:

- It listens on one port and accepts connections only from the source addresses in its segment's manifest entry.
- For each accepted connection it opens a new outbound TCP connection to its parent and copies bytes both ways, with deadlines and a connection cap. The agent's TLS session runs end to end to the controller, so the relay never sees plaintext and holds no agent keys.
- It keeps one outbound control connection to the controller (TLS, its own identity), used only to receive device-proxy and bootstrap requests.
- For a **device-proxy request**, the relay checks the target against its manifest allowlist, opens a connection to the device, opens a fresh outbound connection to the controller, and splices the two. The device's own TLS stays end to end.
- Each splice records only metadata: source, destination, bytes, duration.

There's no multiplexing layer anywhere. Every logical stream is its own TCP connection.

### One connection, hop by hop (Kali to controller)

Each hop needs an allow rule only in the direction the connection is opened, since all of them track connection state.

| Hop | Rule | Address used |
| --- | --- | --- |
| Kali host firewall, outbound | Allow TCP to the controller's public address on the agent port | Public address |
| VyOS | Routes; source NAT to `172.31.(20+T).2` on the way out | Kali becomes the VyOS external address |
| Palo, outside to inside | Static NAT: controller public address to its internal address; allow only from the VyOS external address, only on the agent port, tagged `phylax-managed` | After NAT, the Palo sees the controller's internal address |
| Controller host firewall, inbound | Allow the agent port from the LAN agents' addresses and from the Kali's translated source | As seen after translation |

The controller's internal address is DHCP. A static NAT needs a fixed target, so this path depends on a DHCP reservation, or on a manual rule update if the lease changes [PKT §2]. The Network role enters the Palo rule by hand at T+0; the adapter takes over afterwards.

### What each firewall layer is for

- **The Palo** guards the boundary between the LAN and the outside. A host implant can't change it without device credentials. It is also the only place that sees outside-to-LAN traffic.
- **Host firewalls** are the only control on traffic inside the flat LAN, which never crosses the Palo. An implant can disable them. The agent restores them automatically and alerts.
- **VyOS** is the path for every service. A lockout there is catastrophic, so changes follow the soft-revert protocol (§ Network devices).

### Rule hygiene and bring-up

- **Separate, tagged groups.** Management rules (agent links, device access) live in their own nftables table, Windows Firewall rule group and Palo tag. Restore and drift detection treat them separately from service rules, decoy rules and inject changes.
- **Bring-up order:**
  1. Network firewall rules for the Kali link and the controller's static NAT, entered by hand on the device consoles by the Network role from a printed checklist that `phylax` renders from the manifest. Palo management lockdown goes in the same pass, additively (§ Network devices).
  2. First contact installs the agents.
  3. Host firewalls get the management allows first, then default-deny outbound, under the dead-man switch (§ Execution).
- **Controller address.** If it changes, the static NAT is updated by hand and every agent is pointed at the new address with a local command (§ Enrollment).

## Trust model

The controller and its unlocked keys are the only fully trusted component. Agents are trusted to report on their own host only while that host is clean. Relays, the network, host binaries, DNS and clocks aren't trusted at all. The Kali is a workstation outside the Palo and is treated as an untrusted vantage point. Every mechanism below exists to keep a compromise of one host from spreading through our own tooling.

### Adversary assumptions

The red team can:

- get root or SYSTEM on any server, possibly on a workstation, possibly before drop flag
- read our full source, rules and this document
- watch or tamper with traffic inside the LAN, and across segments if they own the router
- move system clocks
- kill, patch, or impersonate our agent on a host they own
- replay anything they capture
- feed crafted strings (process names, file paths, HTTP paths, usernames) into anything we log
- reach every default credential in the packet and any local process on the controller host that isn't ours

### Trust boundaries

| Component | Trusted for | Not trusted for | If compromised |
| --- | --- | --- | --- |
| Controller host and its unlocked keys | Everything; it's the root of trust | — | Total loss: attacker can sign plans for every host. |
| UI session (one login) | Launching and approving actions | — | Same as controller compromise. Bound to localhost with a login, so the attacker needs the controller host and the password. |
| Release signing key (kept off the competition network) | Which binaries are ours | — | Malicious builds. Never present in the environment. |
| Agent | Reporting what it sees while its host is clean | Truth about a compromised host; anything about other hosts | Attacker can lie for that one host, flood, replay its own history, or impersonate that host. Nothing more. |
| Kali agent | Reporting what an outside client sees | Anything else; it holds scored credentials only in memory during probes | Attacker can falsify external verdicts and read credentials in memory. Cannot command other hosts. |
| Relay | Moving bytes | Reading or altering content | Can drop or delay its segment's traffic. Can't read, forge or command. |
| Optional OSS (Wazuh manager and others) | Extra detections and evidence | Anything on the critical path | The Wazuh manager can push code to its agents; treat its host as a tier-0 asset (§ OSS alongside Phylax). |
| Network devices (after rotation) | Enforcing policy | Staying unchanged | Detected by config diff; reverted from snapshot. |
| Host OS, host binaries, DNS, clocks, the network | Nothing | Everything | Assumed hostile from the start |

### Mechanisms

**Identity with pinned keys, no certificate authority.**

- Each agent generates its own ECDSA P-256 keypair at install and enrolls with a one-time token. The controller records the public key against the host's identity. P-256 is used everywhere because Windows SChannel (PowerShell's download path on Server 2019 and Windows 10) cannot negotiate Ed25519 server certificates [CR §2].
- The agent carries the controller's public-key hash from its bootstrap bundle.
- Both sides verify each other by key hash, not by a certificate chain, and ignore certificate dates. Moving the clock can't break authentication.
- A stolen agent key impersonates only that host.

**Signed commands, separate from the transport.**

- Every plan step is signed with an Ed25519 plan-signing key held only in controller memory, unlocked by passphrase.
- The signature covers a canonical encoding (RFC 8785 JSON) of the whole step except the signature itself: plan id, node, target host identity, epoch, sequence, action, phase, parameters, a digest of the secrets blob, a digest of the rollback data, the dead-man deadline, risk class and approval record [CR §3.2].
- Verification is mandatory. An agent with no plan key refuses every step.
- Each agent persists the highest `(epoch, seq)` it has accepted and rejects anything not strictly greater, and any step for an unexpected plan id. The epoch rises only when the controller is restored from a snapshot (§ Controller recovery).
- The transport key and the plan-signing key are different.

**Bounded agent power.** The agent runs as root or SYSTEM because it has to, but it only executes typed actions from the catalog. `host.exec` needs an explicit approval and is labeled in the UI. The pre-approved host tools are an explicit, hash-pinned list (YARA-X, `nmap` on the Kali, the Sysmon installer, package managers inside patch windows).

**Per-host secrets only.** A plan step carries only the secrets its host needs. The Kali gets scored credentials only for the probes it runs, held in memory, never written to disk.

**Every endpoint is authenticated.** There is no "loopback means trusted" [CR §3.1].

| Surface | Listener | Authentication |
| --- | --- | --- |
| Agent and relay streams | `agent_port`, ALPN `phylax/*` | Mutual key pinning |
| Bootstrap downloads | `agent_port`, no ALPN | Serves only the signed binary and a bootstrap config bound to a one-time token. Mints nothing. |
| Operator UI and API | `127.0.0.1:8443` only | Login (argon2id), HttpOnly SameSite=Strict cookie, CSRF token on every state change. CLI uses an API token created in the UI. |
| Token minting, plans, responses, approvals | UI listener only | Session plus CSRF, plus approval records for risky nodes |

**Agent data is evidence, never instructions.**

- Events are sequenced and hash-chained. The controller acknowledges what it stores. A root attacker can forge future events but can't rewrite acknowledged ones, and gaps are visible.
- Every message is validated against its schema, with per-agent size and rate limits.
- Nothing an agent sends is ever executed, or used to build a command or a query.

**The web UI treats every agent-supplied string as hostile.** Process names, command lines, paths, usernames, HTTP paths and decoy-shell input are all attacker-controlled. Required:

- Go `html/template` auto-escaping; no raw HTML from data.
- A strict Content Security Policy with no inline scripts and only vendored assets.
- An HttpOnly, SameSite=Strict session cookie, and CSRF tokens on every state-changing request.
- Evidence files served as downloads, never rendered inline.
- Request bodies are size-capped.

**Time is for display only.** Ordering comes from per-host sequence numbers. Each heartbeat carries the host clock, and timelines apply the measured offset.

**The controller host gets the hardest hardening.** Inbound: only the agent port, from declared sources. The UI is on localhost. SSH disabled. Secrets in memory only, encrypted at rest. Its own agent reports to it like any other host. Other local users and processes get nothing from the UI without the password.

**Obscurity (D-8).** The agent's install path, binary name, service name and unit name are randomised per event from a secret in the vault. Sysmon's driver and service are renamed. The controller's own detections exclude the agent by its randomised path and hash, not by name. Release binaries are never mutated per host, so the signature always verifies. This raises the cost for scripted kill lists [OA §5.6, WT §9.8]. It is not a boundary.

### Where trust is weakest

- **First contact.** A host that's already backdoored at drop flag can tamper with the agent install. Its first hunt results and its ledger sweep matter more than its heartbeats.
- **Windows.** Go calls through `ntdll` and `kernel32`, so a userland hook there affects our agent. On Linux, Go skips libc and is immune to `LD_PRELOAD`, but not to kernel rootkits.
- **The Kali.** Its verdicts are good evidence about the public path, and poor evidence about anything else.
- **The controller.** The single root of trust, accepted deliberately in exchange for simplicity.

## The agent

The agent is the agent mode of the single static Phylax binary, running as a supervised service. It collects, detects, responds, executes plan steps, captures packets and runs decoys, all locally. It sends everything outbound and holds a crash-safe local spool while the link is down. Roles from the manifest switch extra modules on. A host can hold several roles at once. It builds and runs on Windows from the first milestone, and CI cross-builds both OSes with `CGO_ENABLED=0` [CR §6].

### Process model

- **Main process,** root or SYSTEM: everything except decoys. Modules run as supervised goroutines with panic recovery and exponential restart backoff. Shared state is behind locks or channels; `go test -race` is a CI gate, because a concurrent map write is a fatal error no recover can catch [CR §3.5].
- **Decoy process,** unprivileged (a dedicated user on Linux, a low-privilege service account on Windows): every decoy listener and the fake shell. **Complexity flag:** a second process, kept because decoys are the agent code most exposed to attackers.
- **Config comes only from the controller,** as signed `config` messages delivered at hello and on change. The bootstrap file carries the controller pin and the host identity; the module list, watches, services, checks and rules arrive signed. An agent without config reports itself as unconfigured and runs no module [CR §3.4].

### Footprint targets

| Measure | Target | Enforced by |
| --- | --- | --- |
| Binary size | 40 MB or less, 15 MB or less compressed. If first contact is too slow, a build tag produces an agent-only variant. | CI fails the build above it |
| First contact to heartbeat | 30 s or less | Lab test T21 |
| Memory | 80 MB RSS or less steady, excluding the packet ring and kernel-held memory (reported separately in the heartbeat) | `debug.SetMemoryLimit`, plus systemd `MemoryMax` or a Windows Job Object as the hard cap |
| CPU | 3% average; a 5 s burst of one core at most | Per-module token buckets, plus `CPUQuota` or Job Object. Hash sweeps run at low priority. Capture drops packets before slowing the host. |
| Disk | Spool 200 MB cap; packet ring the smaller of 2 GB or 10% of free disk | Oldest low-priority data dropped first; alerts and evidence never dropped |

Kernel-held memory is counted too: audit backlog, inotify watches, the AF_PACKET ring and any BPF maps [OA §5.7].

### Modules

Each module has its own config block and on/off switch. A module that panics is restarted on its own and reported.

| Module | Does | Linux | Windows |
| --- | --- | --- | --- |
| `link` | Outbound TLS, reconnect, priorities, bounded queues | Native | Native |
| `spool` | Segment-file spool, hash chain, gap records, heartbeat every 5 s with clock reading and a sensor-health block | Native | Native |
| `exec` | Runs signed plan steps off the receive loop: typed actions with check, apply, verify, rollback; agent-side dead-man | Native; `host.exec` on approval | Same |
| `proc` | Process start and exit with lineage, user, command line, service attribution, image hash | Kernel audit `EXECVE` via `go-libaudit` as truth; proc connector as redundancy; `/proc/<pid>` read at each event | Sysmon 1 and 5 via `EvtSubscribe` with bookmarks; Security 4688 fallback |
| `net` | Listeners, connections, owning process, direction and service | `sock_diag` netlink plus an fd-inode join; audit `connect` on default-deny hosts | `GetExtendedTcpTable`, UDP table, Sysmon 3 |
| `fim` | File changes on persistence paths, content roots, configs, with actor | Audit directory watches; hash sweep as truth; fanotify for honey-file reads | `ReadDirectoryChangesW`, USN journal, Sysmon 11–14, SACL auditing (4663) with a periodic verifier |
| `logs` | App and OS logs into events, including `auth_success` and `auth_fail` | File tail with parsers (sshd, Cockpit, web admin logins) | `EvtSubscribe` on Security, System, Sysmon, PowerShell, Defender, Task Scheduler, Firewall, DNS Server, WMI-Activity, Netlogon log tail |
| `capture` | Packet ring, flows with Community ID, protocol transactions | AF_PACKET TPACKET_v3 mapped ring | Raw socket with `SIO_RCVALL` |
| `egress` | Denied outbound attempts, attributed to a process | NFLOG over netlink plus the `sock_diag` join | Security 5157 (agent's own link excluded) |
| `sinkhole` | Catches denied outbound TCP and records the first bytes | nftables `nat` redirect to a loopback catcher | Not available |
| `detect` | Rule evaluation on every event | Native | Native |
| `respond` | Tier-0 actions, with guards | Native | Native |
| `integrity` | Exec-time hashing, loaded-library checks, service binary pinning, sweeps, ledger lookups | Native | Native, plus Authenticode and catalog checks |
| `crossview` | Hidden PIDs, sockets and modules; memfd or deleted executables; `LD_PRELOAD`; BPF programs | Native | Process list from several APIs; driver list against baseline |
| `inventory` | Differential snapshots: listeners, accounts, tasks, services, units, mounts, capabilities, BPF programs, interfaces | Native | Native |
| `decoys` | Network decoys and the fake shell (in the decoy process) | Native | Native |
| `scan` | YARA sweeps (scheduled, low priority) | Pre-approved pinned YARA-X | Same |
| `relay`, `device_proxy`, `check_runner`, `scanner`, `canary` | Roles described elsewhere | Native | Native |
| `patch_proxy` | Loopback HTTP proxy for patch windows | Native | Native |

### What "Go-native" means here

- **Allowed by default:** calling the OS's own interfaces from Go. That means syscalls, netlink, `/proc` and `/sys`, D-Bus for systemd, Win32 APIs, COM and WMI, the event log API, LDAP, and database drivers.
- **Escape hatch:** `host.exec`, which runs a binary on the host. It needs approval in the UI and is labeled "runs a host binary" everywhere. Pre-approved, hash-pinned tools: package managers inside patch windows, the Sysmon installer, YARA-X, and `nmap` and `xfreerdp` on the Kali.
- **Complexity flag:** COM and WMI from Go (Windows Firewall, Task Scheduler, WMI subscriptions, Defender settings) is fiddly code and the largest chunk of Windows work. If one COM interface fights back, use `host.exec` for that one action and record it in the register.

### Telemetry sources

Phase 1 uses mechanisms that work on every target kernel. `phylax doctor` and the agent's start-up probe publish a `capabilities` block and which sensor is active, so a coverage gap shows in the UI [OA §6].

- **Linux process events.**
  - The kernel audit subsystem is the truth. An `execve` or `execveat` record carries argv, cwd, exe, ppid, uid and tty atomically [OA §0.1, OA §4]. The agent installs its own rules (plus `fork`/`clone` with the thread-clone filter) and joins the read-only multicast group, which leaves auditd running. RHEL-family hosts refuse manual auditd stops, and Splunk may read `audit.log`. If no auditd runs, or the kernel is older than 3.16, the agent takes the unicast role.
  - Audit is sized on purpose: backlog 8192 to start (tuned by the load test), a large socket receive buffer, failure mode log not panic, a dedicated reader goroutine that parses and enqueues and never blocks on I/O [OA §5.1].
  - The netlink proc connector is a second opinion and lineage hint. A divergence between connector exec events and audit exec events is itself an alert (audit tampered with or overloaded).
  - On every exec event the agent reads `/proc/<pid>` at once (cgroup, systemd unit, `exe` target, start time) and treats the audit record as authoritative if the read fails. A process is identified by `(pid, start_time, boot_id)`; exited entries live in a short-TTL table so late children still resolve their parents.
  - **Loss is visible.** The agent uses `go-libaudit`'s sequence-gap detection and the connector's per-CPU `seq`, emits `telemetry_gap{source, count, from, to}`, and backfills from a `/proc` diff marked `source=backfill`, lower confidence [OA §5.1].
  - **Audit health** is checked on a timer (enabled flag, our pid still the reader, ruleset hash, lost and backlog counters, no `-a never,task`) and reported in every heartbeat. D10 restores the rules.
  - **eBPF is a gated option** behind the same `process_start` schema (`cilium/ebpf`, pre-built objects, runtime feature probing, BTF required, audit as fallback). It is built only if the exec-storm load test shows audit missing more than 1% at 200 execs per second, or the lab shows a kernel where audit is unusable [OA §0.2].
- **Windows.**
  - Sysmon is installed by the agent using `host.exec` (no reboot). The Sysinternals license doesn't let us redistribute it, so the controller fetches it from Microsoft during cache sync and checks it against a hash pinned in our release; agents get it from the controller cache. The driver and service are installed under randomised names (`sysmon -d`, `-i`) [OA §5.6, §5.4].
  - The Sysmon config is code: sysmon-modular's Balanced profile pinned to the installed Sysmon version, plus CCDC includes (children of scored services, LSASS access, named pipes, WMI, DNS, image loads for service binaries, file deletes only in web roots), volume-tested per host role [OA §5.4].
  - The agent reads channels through `EvtSubscribe` (adapted from winlogbeat's cgo-free wrapper) with a bookmark persisted after each acknowledged batch. A restart resumes exactly where it stopped, including events logged while the agent was down. Channel sizes are raised and clears (1102, 104) alert.
  - If Sysmon is removed or reconfigured, the agent reinstalls it as a tier-0 action and falls back to Security 4688 with command-line auditing, which it enables natively. Fallback order: Sysmon, 4688. The WMI process trace is not shipped. An in-house ETW consumer is not planned.
- **Network.**
  - Connections come from `sock_diag` plus an inode-to-pid walk of `/proc/<pid>/fd`, refreshed only for unmapped inodes between full walks. Every flow record carries a Community ID so host data joins Palo and Suricata data by string [OA §5.3].
  - Short connections are caught by audit `connect` rules on hosts with default-deny egress, filtered by uid where possible.
  - The agent's own TLS link and spool writes are excluded from every stream, which avoids the documented feedback loop [OA §5.2, §5.3].
- **Files.**
  - Audit directory watches (`-a always,exit -F dir=… -F perm=wa`) are recursive and give the actor (pid, exe, auid). Each mount is watched separately. Where audit gives only an inode, the sweep or the `PATH` record resolves the name [OA §5.2].
  - The hash sweep is the source of truth: it walks trees and diffs against a baseline database, including creations and deletions, rate-limited and low priority, hashing only changed files each pass and re-hashing everything on a slower cadence. Events trigger an immediate re-stat and re-hash of that path.
  - Unsupported filesystems (NFS, overlayfs, btrfs quirks) are reported as a coverage gap. A small hand-rolled inotify loop is a fallback only.

### Agent self-protection and tamper detection

No open Linux agent prevents a root user from stopping it. The goal is to raise the cost for scripted kill lists, detect fast and recover automatically [OA §5.6]:

1. **Heartbeat with sensor health:** module states, audit status, connector and fanotify overflow counts, Sysmon service and config hash, binary hash, uptime, clock, kernel-held memory. Silence means the agent is down; present-but-degraded means a sensor was tampered with or overloaded.
2. **Service hardening:** `Restart=always`, `RestartSec=1`, `StartLimitIntervalSec=0`, `WatchdogSec` with `sd_notify`, `OOMScoreAdjust=-900`, `MemoryMax`, `CPUQuota`. Windows: recovery actions set to restart forever, a protected service DACL.
3. **Kernel-side watches on our own files** (binary, unit, config, audit rule files). The kernel records edits even if the agent was just killed, and the restarted agent ships them.
4. **Opt-in immutability:** `chattr +i` on the agent binary and unit; audit `-e 2` as an explicit late plan step with a reboot as rollback. Neither is automatic, and the agent's replace-binary action clears and re-sets the bit.
5. **Cross-source tripwires:** exec via audit against the connector, listeners via `sock_diag` against `/proc/net`, the process list against `sock_diag`-owned pids.
6. **Assume the host key is stolen:** the controller sees one key used from two places as an alert.
7. **Randomised names and paths** (D-8), and a tier-1 alert if the agent binary hash changes.

### Windows Defender

An unsigned binary that captures raw packets, runs fake services and keeps a decoy credential session in LSASS can look like malware.

- Test the agent against current Defender definitions in the lab before every release.
- If it's flagged, hardening keeps exactly one Defender exclusion (the agent's randomised install directory) and alerts on any other exclusion.
- **Complexity flag:** an exclusion is a hole, even a narrow one. The only alternative is code signing, which isn't practical.

### Lifecycle

| Stage | What happens |
| --- | --- |
| Install | First contact copies the binary and a bootstrap config to a randomised path (§ Enrollment), installs a systemd unit or Windows service with automatic restart, then enrolls. |
| Steady state | Supervised by systemd or the service manager. Config and rules hot-reload from signed config messages. |
| Killed or disabled | The controller sees the heartbeat stop. If the host is unreachable by other means, restore from the console one-liner. |
| Binary replacement | One action, `agent.replace_binary`: verify the signed binary, swap, restart, and roll back if no heartbeat returns within 30 s. |
| Uninstall | One action, for cleanup after the competition. |

## Wire protocol and data flow

Each agent holds one long-lived TLS 1.3 connection to the controller, with both sides pinning keys. Over it run length-prefixed, compressed JSON messages in strict priority order. Anything that isn't agent messaging gets its own connection, told apart by ALPN, the protocol name sent during the TLS handshake.

### TLS and pinning

- TLS 1.3 only for every agent, relay, splice and patch connection. Bootstrap downloads also accept TLS 1.2, because Windows 10, Server 2016 and Server 2019 can't do TLS 1.3 and the console one-liner uses the host's own stack.
- Self-signed ECDSA P-256 certificates. Verification is replaced by a check of the peer's public-key hash against the pinned value, with dates ignored.
- The controller pins each agent's key at enrollment. Agents and relays pin the controller's key from their bootstrap config.
- The TLS handshake runs in a per-connection goroutine with a pending-handshake cap and a short deadline. It never runs in the accept loop [CR §3.3].
- One listener on the controller, `agent_port`, serves every connection type. The ALPN value picks the handler:

| ALPN | Opened by | Purpose |
| --- | --- | --- |
| `phylax/agent` | Agent (direct or spliced), including the Kali | All agent messaging |
| `phylax/relay` | Relay | The relay's control connection |
| `phylax/splice` | Relay | One device-proxy or bootstrap stream |
| `phylax/patch` | Agent | One proxied HTTP connection during a patch window |
| None, or `http/1.1` | A host being bootstrapped from the console | Download of the agent binary and a bootstrap config bound to a one-time token. Serves only these downloads. |

The operator UI is not on this listener.

**Complexity flag:** five connection types on one port. It's still one listener and one firewall rule, and each handler is small.

### Framing

- Each message is a 4-byte length, a type byte, and a JSON body. Batches of events are compressed with zstd (pure Go) with a hard decoder memory cap and a size check before decompression [CR §3.6].
- **JSON over protobuf, deliberately:** readable under pressure, no code generation.
- Maximum message size: 4 MB. Anything larger (pcap slices, files, binaries) moves as content-addressed 256 KB chunks, resumable.
- Every connection has read and write deadlines and TCP keepalive. Send queues are bounded per priority. Handlers run off the receive loop so a slow handler can't stall acknowledgments or `control` messages.

### Messages

| Direction | Message | Notes |
| --- | --- | --- |
| Agent → controller | `hello` | Host id, agent version, roles, `capabilities` block (kernel features, sensors chosen), last acknowledged sequence, token if not yet enrolled |
| Controller → agent | `welcome` | Confirms enrollment, carries the first signed `config` |
| Agent → controller | `heartbeat` | Every 5 s: sequence, host clock, spool depth and congestion state, per-module health block |
| Agent → controller | `events` | Batch of telemetry, alerts, transactions and flows, each with its sequence number |
| Agent → controller | `step_result` | Per-action check, apply, verify outcome with before and after state |
| Agent → controller | `chunk` | Evidence, pcap slices, collected files |
| Controller → agent | `ack` | Highest contiguous sequence stored |
| Controller → agent | `step` | A signed plan step |
| Controller → agent | `config` | Signed module config, rules, profiles, ledger shards, check list |
| Controller → agent | `fetch` | Request for a pcap slice, a file or raw telemetry |
| Controller → agent | `chunk` | Payloads for steps: files, packages, the agent binary |
| Controller → agent | `control` | Safe mode, freeze capture, patch window, dead-man confirm |

### Priority

The sender drains its queues in strict order, and every message is sent at its real priority:

1. Heartbeats, alerts, acknowledgments and dead-man confirmations
2. Plan steps and step results
3. Evidence attached to alerts
4. Transactions and flows
5. Other telemetry
6. Bulk transfers (pcap slices, files, binaries), shaped by a token bucket

### Reliability

- **Spool and acknowledge.** Every event has a per-host sequence number. The agent resends from the last acknowledged sequence after every reconnect, and the controller discards duplicates.
- **Reconnect** with jittered backoff from 1 s to 30 s.
- **Per-agent limits** on message rate, bytes per minute and concurrent fetches. SQLite writes are batched in transactions.
- **Congestion states** reported to the controller: warning at 90% of the spool cap, full, flood, recovered at 70% [OA §5.8].

### The spool

The spool is segment files, not one file [CR §3.10, OA §5.8]:

- Append-only segments of 4 to 16 MB holding length-prefixed, CRC-checked frames. `fsync` on a bounded interval and immediately for alert-class events. A small index file holds the chain head and last-acknowledged sequence.
- **Startup repair:** scan the last segment and truncate to the last valid frame, so a torn write never bricks the agent.
- **Acknowledgment-driven deletion** of whole segments below the controller's cumulative ack. Acknowledged data stays until space is needed, so a restored controller can ask for it again.
- **Shedding drops whole low-priority segments** and appends a gap record (sequence range, count, class, time, hash bridge) to the chain. History is never rewritten. Alerts, evidence, heartbeats and step results live in segment sets that are never dropped. Shed order: raw log lines, connection churn, flows on unscored ports.
- **Bounded RAM:** a small write buffer and an in-memory index only.
- Collection is decoupled from transport: modules write through a bounded queue, and a down link never blocks sensors or local response.
- Crash tests (kill -9 at random points, disk full, clock jumps) are a milestone gate (T29).

### Volume

- Shipped continuously: alerts, heartbeats, process starts, connection changes, file changes on watched paths, selected log lines, flows, protocol transactions on scored ports, denied-egress attempts, sinkhole captures, decoy sightings, ledger verdicts.
- Kept on the host until fetched: the packet ring, raw sampler output, full log files.

### Performance envelope

Design for outages of up to 60 s on any link. Latency from event to controller is 10 s or less while the link is up.

## Enrollment, bootstrap and recovery

The controller gets its binaries from a signed release. On the flat LAN it installs agents over SSH where it can, WinRM where it must, and a typed console one-liner as break-glass. Each install enrolls with a one-time token. A new reservation resets everything, so bulk re-enrollment is a first-class path. The controller itself can be restored from an encrypted snapshot kept on another host.

### Getting binaries into the environment

1. **CI builds and signs** a release: static binaries for linux/amd64 and windows/amd64, rules, YARA rules, ledger indexes, the cache index, and the pinned hash of the tested Sysmon release. Signed with an ed25519 key that never enters the competition environment.
2. **The first binary.** The platform driver downloads `phylax` for ubuntu-wkst from the GitHub release (slow, so it is kept small) and verifies it with `ssh-keygen -Y verify`. The public key to verify against is printed on the driver's checklist.
3. **`phylax init`** downloads the rest of the release and verifies it against the key compiled into `phylax`, then starts `phylax cache sync` in the background (§ Offline-first).
4. **Fallbacks,** in order: the same signed artifacts committed under `dist/` (the packet says nothing about the repo this year, so confirm), then a build from vendored source with a Go toolchain.
5. **`phylax init` reports which channel worked** and how fast.

### First contact

| Method | When | How |
| --- | --- | --- |
| SSH (preferred) | Linux hosts with the default `sysadmin` credentials, reachable from the controller | Built-in Go SSH client. Uploads the agent binary and bootstrap config to a randomised path, installs the service, starts it. |
| WinRM | Server 2019 and 2022 (enabled by default) | Built-in Go WinRM client with NTLM and message encryption. Basic auth and `AllowUnencrypted` are never used. |
| Console one-liner | Windows 11 (no WinRM by default), the Kali, anything unreachable, or break-glass | Typed on the NETLAB console. ASCII only, short, no assumption that paste works. Downloads the binary and bootstrap config over the bootstrap connection type, checks the hash, installs. |

The one-liner carries two pins: the controller's public-key hash (`curl --pinnedpubkey`, or a validation callback in PowerShell, which also enables TLS 1.2 on older builds) and the download's hash. The UI generates the full command for each host [SP §A18].

**Bootstrap config contents:** the controller's address and port, the controller key pin, the host's manifest identity, the randomised install parameters, a one-time enrollment token that expires after 10 minutes, and the initial roles.

### Enrollment

1. The UI mints a token bound to a host identity. Only a logged-in operator can do this.
2. The agent generates its keypair and connects with `phylax/agent`, presenting the token.
3. The controller records the key, binds the token to that key, and replies `welcome`. The agent persists its `enrolled` flag only after `welcome`. Until then the same key may re-present the same token, so a dropped connection never wedges enrollment [CR §3.7].
4. Token consumption is atomic. A wrong-host claim does not burn a token.
5. Host identity is the manifest name plus the enrolled key, never an IP address.

### After enrollment

SSH, WinRM and RDP are treated like any other service. If the manifest doesn't declare them for a host, hardening disables them, with the console as break-glass. On 2027 hosts the manifest declares SSH on the Linux hosts, WinRM on the AD host and RDP on the MSSQL host, because they are scored.

### Re-enrollment after a reset

- A per-VM reset does not exist in 2027. A new reservation resets all hosts, so the UI offers **Re-enroll all**: it revokes every old key, issues fresh tokens and runs first contact again with the default credentials in dependency order.
- The vault marks every rotated credential as reverted, and the hardening plans run again from zero. Every action is idempotent.
- A host reset in a variant event restores its default credentials and, for the DC, rolls back every domain change. The domain credentials are marked reverted and the AD plans re-run.
- A new key claiming to be an existing host is always an alert until an operator approves it.
- After any restore or re-enrollment, the prebake hunt and the ledger sweep run automatically, and the host cannot be tagged golden until both are clean [COV X-2].

### Changing the controller address

If the address changes, run `phylax set-controller <address:port>` on each affected host's console. The Palo NAT target for the Kali path is updated by hand. Nothing is automatic.

### Controller recovery

**State snapshot.** Every 15 minutes, and after every enrollment, plan completion and vault change, `phylax` writes an encrypted snapshot to each backup target in the manifest. It holds state, not event data (target: under 10 MB): the controller's keys, enrolled agent keys with their last acknowledged sequence and chain hash, the manifest and overrides, the vault, plans and node status, active checks, the honeytoken registry, the ledger overrides and incidents without bulk evidence. It is encrypted with a key derived from the operator passphrase (`age`, scrypt mode).

**Restore starts a new epoch.** Install `phylax` on the replacement machine, fetch the latest snapshot, unlock it, and start. The restored controller raises the epoch, so agents accept steps in the higher epoch despite sequence numbers the lost controller used after the snapshot. After a restore the controller asks each agent to resend everything its spool still holds, verifies that the chain passes through the snapshot's recorded sequence and hash, and marks anything missing as a gap with the reason "controller restored".

**Restart safety.** After any restart, the controller accepts and stores agent traffic immediately. Plan signing and secret access stay locked until the passphrase is entered. Packet captures, evidence files and the cache are not in the snapshot; golden service backups are copied once to the backup targets.
