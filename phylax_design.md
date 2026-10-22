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


Implementation notes (2026-10-22): the controller's per-agent reorder buffer understands spool gap records (a gap covers `from..to`, so plain contiguous-sequence tracking would stall), and acks only after the store commit. `welcome` and `ack` carry no epoch or hash; the epoch travels in the signed config and steps. See docs/protocol.md §6 and §9.

Implementation notes (2026-10-22, agent config): the signed config is the typed `AgentConfig` (docs/protocol.md §8a), generated per host by the controller from the manifest and rules, signed with the plan key, host-bound and replay-protected by a durable `(epoch, version)` mark on the agent. Versions only move when a host's content changes. The agent persists the last good config and runs it on restart without a controller; modules start, stop and reconfigure through a factory registry, and local detection runs on the agent's own event stream with alerts as Critical `detect.alert` events and tier-0 responses off. The config status travels in heartbeats under the reserved module name `config`. See docs/agent.md and docs/controller.md.
### The spool

The spool is segment files, not one file [CR §3.10, OA §5.8]:

- Append-only segments of 4 to 16 MB holding length-prefixed, CRC-checked frames. `fsync` on a bounded interval and immediately for alert-class events. A small index file holds the chain head and last-acknowledged sequence.
- **Startup repair:** scan the last segment and truncate to the last valid frame, so a torn write never bricks the agent.
- **Acknowledgment-driven deletion** of whole segments below the controller's cumulative ack, oldest first and only when space is needed, so a restored controller can ask for acknowledged data again. The chain head is persisted before any deletion.
- **Shedding is admission control, not segment deletion** (changed during implementation, 2026-10-22). The controller store accepts each agent's chain only in contiguous sequence order, so the spool is one sequence-ordered log and transport reads it in sequence order; priority acts at admission. Each class may fill unacknowledged space only up to its limit (critical 97%, high 90%, normal 75%, bulk 50% of the cap). An event over its class limit isn't stored: it consumes its sequence number, and one **gap record** (`kind: spool.gap`, fields `from`, `to`, `count`, `class` ∈ {critical, high, normal, bulk, mixed, unknown}; `seq = to+1`; `PrevHash` bridges to the last stored event) announces the dropped run before the next stored event. History is never rewritten, and bulk can never crowd out alerts. A crash that loses a mid-log tail is reconciled at restart with a `class: unknown` gap up to the recorded head, so no sequence number is reused. Gap records are hash-chained, not separately signed. Shed order within a class: raw log lines, connection churn, flows on unscored ports.
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

## Execution: actions, plans and the DAG

All change goes through plans. A plan is a DAG whose nodes are typed actions on specific hosts or devices, with dependency edges and optional approval gates. Every plan shows a dry-run diff and a scoring-safety lint result before anything runs. Lockout-risk actions roll themselves back on the agent if it can't confirm.

### Actions

An action is Go code in the agent (or a device adapter in `phylax`) with four parts: **check** (is it already done?), **apply**, **verify** and **rollback**. Each action declares a parameter schema, a risk class (`none`, `service`, `lockout`, `destructive`), the resources it locks and the **scorer-visible properties it touches** (for the lint below).

**Action catalog v3**

| Area | Actions | Linux implementation | Windows implementation |
| --- | --- | --- | --- |
| Files | `file.write`, `file.template`, `file.perms`, `file.quarantine`, `file.restore`, `file.hash`, `file.attr` (clear or set immutable), `dir.snapshot` | Native; atomic temp-and-rename that copies mode, owner, xattrs and SELinux label | Native |
| Local accounts | `user.set_password`, `user.lock`, `user.create`, `user.delete`, `group.members`, `ssh.authorized_keys` | Edit `/etc/shadow` and friends under the shadow-utils lock (`lckpwdf`), atomically, preserving aging fields and labels; SHA-512 crypt hashes | `NetUserSetInfo`, `NetLocalGroup*` |
| Domain | `ad.set_password`, `ad.user`, `ad.group_members`, `ad.spn`, `ad.delegation_clear`, `ldap.modify`, `ad.krbtgt_reset`, `ad.netlogon_enforce` | — | Run by the DC's agent through the domain-aware APIs, LDAP and the registry |
| Services | `service.state`, `service.config` | systemd over D-Bus | Service control manager APIs |
| Firewall | `fw.apply` (declared groups, shadow or enforce), `fw.snapshot`, `fw.restore`, `fw.quarantine` (isolate with auto-revert) | `google/nftables` over netlink; one atomic table replace; separate management table; validated in CI with `nft -c` | Windows Firewall through COM in our own rule group |
| Kernel and system | `sysctl.set`, `module.block`, `modules.disable_loading`, `hosts.file`, `selinux.restore` | `/proc/sys`, modprobe config | — |
| Registry | `reg.set`, `reg.delete`, `reg.snapshot` | — | Native registry API |
| Persistence cleanup | `cron.disable`, `unit.disable`, `unit.mask`, `task.disable`, `wmi.subscription_remove`, `runkey.remove`, `ld_preload.clear`, `caps.clear`, `pkg.unhold` | Native file edits, D-Bus | Task Scheduler and WMI through COM; registry |
| Processes | `proc.kill_tree` (pidfd plus start-time check; `cgroup.kill` for units), `proc.suspend`, `proc.dump` | Signals, cgroup freeze, `/proc/<pid>/mem` | `TerminateProcess`; `MiniDumpWriteDump` |
| Logging | `audit.rules`, `audit.immutable`, `auditpol.set`, `eventlog.size`, `sysmon.install`, `sysmon.config` | Kernel audit over netlink | Native audit-policy API; `sysmon.install` uses `host.exec` |
| Databases | `mysql.exec`, `mysql.set_password`, `mysql.dump`, `mssql.exec` (read-mostly), `mssql.set_password` | Go MySQL driver | Go MSSQL driver (`go-mssqldb`) over TCP or shared memory |
| Services' config | Templates for Apache or httpd, PHP, Postfix, Dovecot, Splunk, IIS, DNS | `file.template` + `service.state` | Native XML edit of `applicationHost.config` |
| Packages | `pkg.install`, `pkg.upgrade`, `pkg.reinstall`, `pkg.fetch_to_depot` | `host.exec` of apt or dnf inside a patch window | Windows Update Agent COM inside a patch window |
| Integrity | `ledger.sweep`, `ledger.verify_pin`, `binary.restore_from_depot` | Native | Native |
| Collection | `collect.files`, `collect.inventory`, `hunt.baseline_diff`, `hunt.persistence`, `hunt.pii`, `hunt.ad`, `yara.scan` | Native, except `yara.scan` | Same |
| Credentials | `pcr.generate` (controller), `pcr.verify` (Kali probe), `pcr.submit` (off unless the organizers approve scripting) | — | — |
| Integrations | `wazuh.deploy`, `wazuh.health`, `splunk.hec_setup`, `suricata.analyze_pcap`, `av.clamav` | `host.exec` of pinned installers from the cache | Same |
| Agent | `agent.replace_binary`, `agent.config`, `agent.set_controller`, `agent.safe_mode`, `agent.rename` | Native | Native |
| Devices (in `phylax`) | `palo.apply`, `palo.commit`, `palo.snapshot`, `palo.revert`, `vyos.apply`, `device.rotate_admin` | XML API, SSH | — |
| Escape hatch | `host.exec` | Approval required (or pinned pre-approval); labeled everywhere | Same |

**SELinux.** Rocky 9 runs SELinux enforcing. File actions write a temporary file and rename it into place, so the new file would get its directory's default label. That's wrong for files such as `/etc/shadow` (`shadow_t`). File actions copy the original file's label (or use the policy default for new files) before the rename and check it in verify. The agent's install path gets a `bin_t` label so systemd runs it unconfined. Unit tests run against SELinux-enforcing images.

**Complexity flag:** `yara.scan` has no pure-Go engine. It runs the pinned YARA-X static binary as an approved tool, at low priority, on a schedule (§ Binary integrity ledger).

### The scoring-safety lint

Every plan node declares which scorer-visible properties it touches. The lint rejects a plan, at template time and at run time, if a node matches the never-do list [SH never-list]:

| Rule | Examples that the lint rejects |
| --- | --- |
| No lockout machinery on any scored account | `pam_faillock`, fail2ban, sshguard, Windows lockout GPO, SQL `CHECK_POLICY` lockout, tighter Splunk lockout |
| No SSH change that breaks the scorer's login | `PasswordAuthentication no`, `PermitTTY no`, `ForceCommand`, `nologin` or `rbash` shells for scored users, `AllowUsers` that omits a credlist user, slow profile scripts |
| No mail change that refuses plaintext | STARTTLS required, `disable_plaintext_auth=yes`, `smtpd_tls_auth_only`, reject-on-unknown-sender checks, postscreen on 25 |
| No source filtering of a scored service | Any host or Palo rule restricting a scored port by source |
| ICMP echo stays | No ICMP drop, `icmp_echo_ignore_all=1`, zone protection that drops ping |
| NTLM and its transport stay | No NTLM deny, no `LmCompatibilityLevel` below 3 for the scored paths, no Protected Users for scored accounts, no required encryption the scorer can't do (SMB encrypt, WinRM `AllowUnencrypted=false` on 5985, FTPS-only, MSSQL ForceEncryption) without a scorer-mimic pass |
| Scored content is untouched | Web pages with regexes, SMB SOP files, FTP files, DNS A records, the Splunk data and the SQL table the checks read |
| No kill of a scored service as a response | Downtime scores zero and 5 failures trigger an SLA penalty |
| Scored passwords change only by PCR transaction | See § Credentials |

Each node that touches a learned service runs the **scorer-mimic probe** for that service before and after (§ Active checks), with two different credlist users. A failed "after" probe rolls the node back. The verdict table for each service in `ccdc-private/research/topics/scoring-safe-hardening.md` is the source of the rule data; where an organizer-set "insecure" value is the reason the scorer works, the pre-change baseline snapshot says so [SH intro].

### Plans

A plan is YAML: a list of nodes with an action, a target, parameters, dependencies and options. Plans are templates that select targets from the manifest, so one "harden every Linux web server" template expands to concrete per-host nodes.

```yaml
plan: harden-rocky-ecom
nodes:
  baseline:  { action: collect.inventory, target: rocky-ecom }
  creds:     { action: user.set_password, target: rocky-ecom, params: { user: root, secret: ecom.root } }
  fw_shadow: { action: fw.apply, target: rocky-ecom, params: { mode: shadow }, needs: [baseline] }
  review_fw: { gate: approval, needs: [fw_shadow], note: "Check would-be drops before enforcing" }
  fw_enf:    { action: fw.apply, target: rocky-ecom, params: { mode: enforce }, needs: [review_fw], deadman: 90s }
  php:       { action: file.template, target: rocky-ecom, params: { path: /etc/php.d/99-phylax.ini } }
  oc_admin:  { action: mysql.exec, target: rocky-ecom, params: { op: rotate_admin_row } }
  reload:    { action: service.state, target: rocky-ecom, params: { unit: httpd.service, state: reloaded }, needs: [php] }
  verify:    { action: health.check, target: ecom-http, needs: [reload, fw_enf], probe: scorer_mimic }
on_failure: stop_dependents     # or: continue | rollback_plan
```

The UI draws plans as a DAG, coloring each node live. Branches run in parallel. A gate pauses its dependents. The health check runs only when everything it depends on is done.

**Shadow mode.** `fw.apply` with `mode: shadow` shows what a policy would drop without dropping it. On Linux it installs the policy with a log rule in place of each drop. On Windows, where rules can only allow or block, the agent evaluates the proposed policy against its connection table and capture flows and reports what would have been dropped. Windows shadow windows should run a few minutes.

**The Linux host firewall policy** [CR §3.8]: one `phylax` table replaced atomically in a single netlink batch. It always accepts established and related, loopback, DHCP where the host uses it, ICMP echo-request in and echo-reply out plus the types PMTU needs, ICMPv6 (neighbour discovery, router advertisements, echo), and the management group (a separate table) for the controller link. It allows scored ports from any source. Everything else inbound is dropped, and outbound is default-deny with the declared dependencies. Rocky 9's firewalld stays running with its own table; Phylax's table is a second base chain at an earlier priority, and a drop in either wins. CI runs `nft -c -f` on every rendered file in a privileged job, and every apply starts with a dry-run check on the host. The sinkhole redirect is in a `type nat` output chain.

### Plan, approve, apply

1. **Plan.** `phylax` expands the template and sends every node's **check** to its agent. Each check reports what it would change.
2. **Diff and lint.** The UI shows the DAG with each node marked: unchanged, will change (with a readable diff), blocked by a lock, or rejected by the scoring-safety lint.
3. **Approve.** One click approves the whole plan. Approval gates pause execution at that node. `host.exec`, `destructive` and `lockout` nodes always need their own approval record, which the plan engine enforces and the signature covers.
4. **Apply.** Nodes run as soon as their dependencies finish, in parallel across hosts and within a host where locks allow.
5. **On failure,** the plan's policy decides: stop the failed node's dependents (default), continue, or roll back the whole plan in reverse order.

### Dead-man switch

For any node marked `deadman` (default for `lockout`-class actions) the **agent** runs the whole protocol [CR §2 dead-man]:

1. Before applying, the agent snapshots the affected state, writes an **armed record** to disk (node id, snapshot reference, deadline) and arms a timer, default 90 s. Alongside the in-process timer, it arms an **OS-level one-shot timer** (a transient systemd timer on Linux, a scheduled task on Windows) that runs `phylax agent rollback <id>`. That timer fires even if the agent crashes or is killed mid-window.
2. After applying, it opens a **fresh connection** to its controller or relay and completes a handshake.
3. If that works, the controller sends a `control: confirm` and the agent disarms both timers and deletes the armed record. If not, the agent rolls back on its own when the timer fires and reports the rollback once reconnected. On start-up, an expired armed record triggers a rollback before anything else.
4. **Hosts that carry other links.** On a relay host, or on the controller host, a change can cut off every agent behind it while the host's own link stays up. For a `deadman` node there, the controller also asks dependent agents (one behind each relay, or one on the LAN and the Kali for the controller) to open fresh connections, and confirms only if those succeed.

There's no SSH involved, so the dead-man covers the agent's own link, which is the link that matters. Safe mode never prevents a rollback.

### Locks

Each host has named resource locks: `firewall`, `accounts`, `sshd`, `packages`, `audit`, and one per service. Plan nodes and tier-0 responses take the same locks, by the same names. While a plan node holds `firewall`, automatic firewall restores on that host wait. A node holds its locks only while it runs, not while the plan waits at a gate. Each successful node updates the host's declared state, so a tier-0 restore during a gate restores what the plan has applied so far.

### Safe mode

One switch in the UI sends `control: safe_mode` to every agent. It suspends tier-0 responses and any running plan nodes. Detection and collection keep running. Steps run off the receive loop, so the control message is never stuck behind a long apply. Agents stay in safe mode across restarts until told otherwise.

### Tagging and adoption

- Everything an action creates (firewall rules, units, tasks, accounts, files) is tagged with the plan id, so detection can tell our changes from anyone else's.
- **The tag reaches every event type.** `process_start` events from a plan step, `sec_event` account changes, `chattr`, `auditctl`, `useradd`, package-manager runs and patch-window runs all carry the plan or window tag. Rules exempt tagged events instead of guessing from process names. This is how our own hardening, which runs `chattr +i`, `auditctl -D`, firewall commits and Defender exclusions, produces no untagged alerts [DR §3, PR E6].
- Changes made by hand during an inject are flagged as drift. An operator either adopts them into the manifest overrides with one click, or reverts them.

## Manifest

The manifest is a set of YAML files, validated against a JSON Schema in CI and again when `phylax` loads it. It's the only place infra facts live. Plans, agent configs, firewall rules, health checks, decoys and inject artifacts are all generated from it. Changes made during the competition are written by the UI into an overrides file, never into the base files.

### Files

| File | Declares |
| --- | --- |
| `topology.yml` | Controller host and ports, segments, relays, NAT mappings, the Kali path, backup targets |
| `hosts.yml` | Hosts: segment, internal and public address, OS, default credentials reference, roles, `domain_member` (the DC a host joins), `rpc_range` (the DC's pinned RPC range) |
| `services.yml` | Services: kind, scored flag, listeners, process identity and binary pins, content roots, data, dependencies, health checks, transport |
| `accounts.yml` | Managed accounts: scope, scored flag and credlist, rotation policy, files that embed them |
| `scorer.yml` | The scorer: engine (`quotient`), team Identifier scheme, portal URL, known or estimated Delay, Jitter, Timeout, SLA threshold, credlist paths, portal poll setting |
| `devices.yml` | Network devices: vendor, management address, segment, adapter, which relay proxies them |
| `decoys.yml` | Decoys per host: listeners, honey files, honeytokens, exposure |
| `integrations.yml` | Optional sensors: Wazuh, Suricata, Zeek, Splunk HEC, with pinned versions and hosts |
| `policy.yml` | Response tiers, protected processes, retention, limits, patch-window allowlist, cache tiers |
| `overrides.yml` | Competition-day changes from the UI: adopted drift, inject changes, accepted findings |

Secrets never appear in the manifest. It refers to them by name (`secret: ecom.db`), and values live in the controller's vault.

### Examples

```yaml
# services.yml (2027 reference, excerpt)
services:
  ecom-http:
    host: rocky-ecom
    kind: http
    scored: true
    listen: [{ proto: tcp, port: 80 }, { proto: tcp, port: 443 }]
    process: { unit: httpd.service, binaries: [/usr/sbin/httpd], pin: true }
    transport: { plaintext: true, tls_verify: false }
    content:
      roots: [/var/www/html]
      upload_dirs: [/var/www/html/image/catalog]
      normalize: [opencart_token, csrf, session_cookie, timestamps]
    data: [{ kind: mysql, database: opencart }]
    outbound: none                       # feeds D4b relay-proxy
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
  ad-winrm:
    host: ad
    kind: winrm
    scored: true
    listen: [{ proto: tcp, port: 5985 }]
    transport: { auth: ntlm, encryption: none }
  mssql-sql:
    host: mssql
    kind: mssql
    scored: true
    listen: [{ proto: tcp, port: 1433 }]
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
  sysadmin@linux:  { scope: local, hosts: [rocky-ecom, ubuntu-email, debian-splunk], scored: unknown, credlist: linux, rotation: pcr_transaction }
  mail-users:      { scope: domain, scored: true, credlist: mail, rotation: pcr_transaction, learn_from: scorer }
scorer:
  engine: quotient
  portal: https://quotient.ccdc.events/
  identifier: "{{ 20 + team }}"
  credlists:                              # PCR calls use the path, never the display name
    linux: { path: linux.credlist }
    mail:  { path: mail.credlist }
  poll_portal: ask_organizers            # off | operator_paste | cookie_poll
```

### What it generates

| Output | From | Used by |
| --- | --- | --- |
| Host firewall policy (management, service, dependency and decoy groups) | topology, services, decoys | `fw.apply` actions |
| Palo and VyOS rules, objects, NAT, including the Kali path | topology, services, decoys, devices | Device adapters |
| Egress allowlists | `depends_on`, topology | Host and network firewalls |
| Agent configs (roles, modules, rules, profiles, paths, service pins, ledger shards) | hosts, services, decoys, policy | `config` messages |
| Plan targets and the scoring-safety constraints per service | hosts, services, accounts | Plan templates, the lint |
| Health checks and scorer-mimic probes | `health` and `transport` blocks plus accepted suggestions | Active checker, Kali, in-LAN runners |
| Honeytokens and decoy configs | decoys (values generated at competition time) | Decoy actions, token registry |
| Cache plan | hosts' OS versions, integrations | `phylax cache` |
| Inject artifacts: asset inventory, service list, port matrix, network diagram | Everything | Drafters |
| Printed per-role checklists | Everything | Humans |

### Rules

- **No hand-edited generated files.** Change the manifest or an override.
- **Domain membership is declared, never inferred.** A host with `domain_member: <dc>` gets the full member-to-DC allowance set rendered on its host firewall (and on the Palo and VyOS when the pair crosses segments), and the DC with the `domain_controller` role gets the matching inbound rules: DNS 53, Kerberos 88 and 464, LDAP 389 and 636, global catalog 3268 and 3269, SMB 445 (SYSVOL, Netlogon), RPC endpoint mapper 135 plus the RPC dynamic range, and NTP 123/udp. Without them default-deny egress breaks domain auth and every scored check that uses domain accounts. The DC's dynamic RPC range is pinned with `rpc_range` (the plans apply it on the DC); unpinned, 49152-65535 is opened and the lint warns. The lint errors on a Windows host in a segment with a DC that is not a member while a scored service or account uses domain auth. Ports accept ranges (`port_range`, `port_ranges`).
- **CI checks:** schema validity, dependency cycles, a firewall lint that fails if any scored port, declared dependency, DHCP, ICMP or IPv6 need would be blocked, and rendering of every output for the reference manifest.
- **Drift detection** compares declared state with what agents observe: undeclared listeners, services, scheduled tasks, accounts and outbound peers.

## Egress policy and C2 hunting

Servers get almost no outbound access: their agent link plus the service dependencies the manifest declares. Patches come through the controller's cache in short windows. Every denied outbound attempt is logged at the host and at the Palo, attributed to a process, and analyzed for beaconing. On Linux, denied connections are caught by a sinkhole that records what the implant would have said.

### What's allowed out

| Allowance | Who gets it | Notes |
| --- | --- | --- |
| Agent link | Every host | To the controller (the Kali: through the declared path) |
| Declared dependencies | Per service, from `depends_on` | For example mail host to the DC on LDAP and Kerberos; DNS to the DC |
| Patch window | One host, time-boxed | Through the loopback proxy only (below) |
| Canary probes | Agents, rate-limited | To the Kali's canary ports, tagged and expected to fail (§ The Kali) |

Everything else is dropped at the host firewall and at the Palo. Network-layer default-deny still holds when a host implant disables the host firewall. The workstations are different: they have PAT internet access, and are not covered by server egress rules.

### Learn-then-enforce by binary identity

Default-deny by destination is blind to which process is allowed. Each server gets a profile of (executable hash, destination class) seeded from a learning window, then enforced. The key is the hash, not the path, because a path allowlist is trivially bypassed [WT §9.4]. An unknown binary reaching an allowed destination raises D4. The agent's own link is allowlisted by its randomised path and hash.

### Patch windows and the cache

Internet access is slow, so most patches never go to the internet. The controller's cache holds the package set for each announced OS (§ Offline-first). A patch window works like this:

1. An operator opens a window for a host in the UI, for example 15 minutes. The window has a tag.
2. The agent starts an HTTP proxy on `127.0.0.1`. It's loopback only.
3. Each proxied connection becomes its own `phylax/patch` TLS connection to the controller.
4. The controller serves from its cache first. On a miss it fetches through the internet path, but only from the `policy.yml` allowlist (distro mirrors, Microsoft update endpoints), logs the request and stores the result in the cache.
5. Package actions run with the host's package manager pointed at the loopback proxy. The host needs no outbound rule and no DNS.
6. When the window closes, the proxy stops. Everything that ran during the window carries the window's tag, and the ledger expects the changed hashes (it pre-resolves the new package versions before the window opens).

**Complexity flag:** the controller becomes a forwarding, caching proxy. It's bounded by the allowlist, the time box, and one connection per proxied stream.

### Logging denied egress

| Vantage point | Mechanism | What it gives |
| --- | --- | --- |
| Linux host | The nftables drop rule also sends the packet to an NFLOG group. Rules drop rather than reject, so the blocked socket keeps retrying and the agent finds the owning process through the `sock_diag` join. Audit `connect` records are the only evidence if the process died within a second. | The first packet of every denied attempt, with process and binary hash |
| Windows host | Blocked-connection auditing, Security 5157, outbound only; the agent's own link is excluded | Process id, application path, destination, port |
| Palo | The adapter pulls deny entries for outbound sessions every 30 s | Coverage when an implant has killed our agent or disabled the host firewall |
| DNS | The DC's DNS analytical log, and Sysmon 22 | Which servers tried to resolve names outside the zone |

### Analysis on the controller

The denied-egress view groups attempts by binary hash and destination: attempt counts, first and last seen, timing (interval mean, jitter, regularity), spread across hosts, and process lineage and persistence from the trace-back data. Periodic callbacks (jitter below 20% over at least 10 intervals) escalate (D13c). The result is a ranked list of likely C2 destinations and the binaries reaching for them.

### Sinkhole (Linux)

- Denied outbound TCP from servers is redirected by an nftables `nat` output rule to a catcher the agent runs on a loopback port. The catcher completes the handshake and records the first bytes the implant sends, up to 16 KB or 10 s.
- HTTP beacons: method, path, headers, user agent, then a plain 404 and close. TLS: the ClientHello (SNI, ALPN, JA4), closed without completing the handshake. Anything else: raw first bytes, then close.
- It never sends meaningful responses, never connects anywhere, and never runs anything it receives.
- Windows can't redirect connections without a driver, so it gets denied-egress logging only.

**Complexity flag:** the sinkhole adds a loopback listener and redirect rules. It's bounded by being Linux-only, record-only and size-capped.

### Gaps

Egress filtering does nothing against inbound command channels: a webshell on a scored port, or a bind shell. Those are covered by process-lineage detection (D1), change trace-back, the integrity ledger and the packet ring.

## Service monitoring: capture and health checks

Two independent systems watch the services. **Capture** is passive: every host records its own traffic into a packet ring, and ships flow records and parsed protocol transactions continuously. On the flat LAN this is the only east-west visibility, because LAN traffic never crosses the Palo. It feeds check discovery, traffic labeling, trace-back, attack chains and IR. The **active checker** runs the active checks described in the next section. Neither sits in the path of scored traffic.

### Capture tiers

| Tier | Contents | Lives on | Shipped |
| --- | --- | --- | --- |
| Full packets | Every packet. Full length on scored ports, decoy ports and sinkhole traffic; first 128 bytes elsewhere. A per-flow byte cutoff keeps bulk transfers from evicting evidence. | Host packet ring: the smaller of 2 GB or 10% of free disk | On request as a filtered time slice; automatically around alerts |
| Flow records | One record per connection: endpoints, ports, Community ID, start and end, bytes and packets each way, handshake result, resets, timeouts, hashes of the first bytes each way, owning process when known | Agent spool | Continuously |
| Transactions | Parsed exchanges on declared service ports | Agent spool | Continuously |

### Capture mechanics

- **Linux:** AF_PACKET TPACKET_v3 with a memory-mapped ring, one pipeline per capture thread, kernel filters built in Go (`x/net/bpf`), no libpcap. The ring is on disk and exports real pcap, so Wireshark and Suricata can read slices [OA §5.10].
- **Windows:** one raw socket per interface with `SIO_RCVALL`. It needs no driver, but only sees the IP layer.
- **Complexity flag:** two things about Windows capture need proving in the lab before we rely on it: whether outbound packets are fully captured, and how it behaves alongside Windows Firewall. If coverage is partial, Windows services fall back to logs (IIS, DNS analytical, Sysmon 3, Security 5156/5157) for transactions, and capture is used for flows only.
- **Bounded and passive.** Under load the agent drops packets rather than slowing the host, and reports drop counts.
- **Scans are aggregated.** One "source X touched N ports" record.
- **No feedback loop.** The agent's own traffic to the controller is excluded.
- **Freeze on alert.** Any alert freezes the ring from 5 minutes before to 10 minutes after for the hosts involved. New packets keep being recorded in a continuation segment; freezing never drops the post-alert packets. The controller pulls that slice automatically, filtered to the IPs involved.
- **Source-address check at drop flag.** Host capture can fingerprint the scorer by behaviour whatever the source, but the labeling of external sources needs real addresses. The controller compares captured sources with the Palo's traffic logs in the first minutes and warns loudly if every inbound connection appears to come from the firewall. In that case it recovers sources from the Palo's traffic logs.

### Protocol parsers

All are Go-native, built on passive TCP reassembly (including out-of-order segments, IPv6 and VLAN), each isolated so a parser bug only affects its own protocol. The set follows what Quotient actually sends [Q §6, Q §9.13, SP §A4].

| Phase | Parsers |
| --- | --- |
| 1 | HTTP/1.x; DNS over UDP and TCP; ICMP echo; SSH (banner, KEXINIT and HASSH, auth method, PTY request, shell, typed stdin line); SMTP; IMAP; POP3; FTP control with data-channel linkage; SMB2 with NTLM (negotiate, session setup flags, tree connect path, create, read); WinRM over HTTP (`/wsman`, NTLM exchange); bare TCP connect-and-hold (RDP, tcp) |
| 2 | TDS (MSSQL pre-login, login7, SQL batch); Splunk REST over HTTP on 8000 and 8089; TLS handshake metadata (SNI, ALPN, JA3, JA4, certificate); LDAP binds and searches; generic first-bytes fingerprint for unknown protocols, so a service added by an inject is fingerprinted before anyone writes a parser |
| 3 | Kerberos metadata; file carving from HTTP, FTP and SMB transfers |

TFTP and NTP are no longer scored; their parsers drop from phase 1 but the generic fingerprint covers them if a future packet restores them.

**HTTPS.** Passive capture can't see inside modern TLS. For HTTPS services we get handshake metadata from packets, request details from the server's own access logs (custom formats set by hardening), and response content from active checks. The scorer's Go TLS ClientHello is distinctive (§ Active checks).

### Palo-side capture

The Palo can capture packets on a filter and serve them through its API. The adapter turns that on for a chosen service and window and pulls the result. This settles "is the scorer even getting through?" without guessing. **Complexity flag:** PAN-OS packet capture has its own limits and can load the firewall. It's used on demand only, never left running [DA §1.9].

### Pulled pcaps and optional analysis

Frozen slices are real pcap files. The controller can run Suricata and Zeek over a slice offline, join their output to Phylax flows by Community ID, and attach the result to the incident (§ OSS alongside Phylax).

## Active checks and check discovery

The platform keeps a live, editable list of **active checks**: our own end-to-end tests of each service, built to behave like Quotient. The scorer's checks change during the event, so the list is kept in step by watching scorer traffic passively. The design follows how Quotient was measured to behave, not how a generic scorer might [Q §0]. Several numbers (Delay, Jitter, Timeout, SLA threshold, Divisor, debug visibility, the MSSQL, Splunk and RDP scripts) are unknown until the event and are measured, not assumed.

### The scorer model

| Fact | Consequence for Phylax | Source |
| --- | --- | --- |
| One burst per round for every team at once. A team's checks hit its hosts within about 25–55 ms, from up to five runner addresses. The next round starts `Delay ± Jitter` after the last one started (upstream defaults: 60 s ± 5 s). | Cluster inbound new connections into bursts, estimate Delay and Jitter after about 10 bursts, and align everything to the clock | [Q §3] |
| Each check picks one random sub-item and one random credential per round, with one attempt | A broken item or one wrong password fails only some rounds. A service has to be learned over many rounds | [Q §0.2] |
| Credentials are copied into tasks at enqueue time. A PCR landing during the enqueue pass can give a mixed snapshot | Rotate only in the quiet part of the interval, after a burst | [Q §5] |
| A round is all-or-nothing. If any task result is missing at the deadline, the whole round is discarded: SLA streaks neither advance nor reset | One missing burst is not an outage. Dropped rounds are not incidents | [Q §3] |
| Source addresses are runner addresses behind Docker NAT, or re-drawn each round by Divisor | Never label by address; addresses are advisory | [Q §6] |
| SLA penalty is global (per-check overrides are ignored): `SlaThreshold` consecutive failures cost `SlaPenalty` and reset the counter | Track streaks per service, alert at threshold minus 2 | [Q §4.2] |
| Upstream `rdp` and `tcp` checks open a TCP connection and never close it; a `web` check with no status or regex passes a 404; DNS MX never passes; an SSH command with no `Contains` passes on any output | Our checks are stricter where Quotient is lax | [Q §0.5] |
| `BadAttempts` makes N failed SSH logins with a random-UUID password for the real username right before the real login | Exempt from lockout and brute-force detection | [Q §2, SH §1.1] |
| MSSQL login and query, Splunk query and 8089, and RDP with authentication have no native Quotient type; MW runs custom scripts or a fork | Fingerprint by burst, port and account until seen; record what arrives | [Q §2.2] |
| Config hot-reloads with a 1 s debounce; checks have launch and stop times and can be toggled per team | Discovery runs all event; silence is "scorer stopped checking", not "healthy" | [Q §9.9] |

### Round clock estimator

On the controller, over flows and transactions from all hosts:

1. A **burst** is at least 15 new connections to a team's hosts within about 60 ms. The first burst after the competition starts sets the alarm.
2. After about 10 bursts the estimator publishes `Delay`, `Jitter`, the last burst's end and the **quiet window** `[burst end + safety, next start − safety]`. Before 10 bursts it publishes the upstream defaults at low confidence.
3. Everything time-sensitive uses the window: PCR transactions, active-check scheduling (our probes never sit inside a burst), `threshold − 2` SLA alerts and the Kali's probes.
4. A missing burst for the whole team is recorded as a "scorer round gap" and not treated as an outage [Q §9.12].

### Active checks

- **Run by** the checker module on the controller, by `check_runner` agents on the LAN, and by the Kali (§ The Kali as an external vantage point), every 30–60 s per check, outside the burst window.
- **Check types**, each implemented with the same Go libraries Quotient uses where possible, so fingerprints match without effort [Q §9.11]:

| Type | What it does | Notes |
| --- | --- | --- |
| HTTP and HTTPS | `GET` with `Host: <ip>:<port>`, `Accept-Encoding: gzip`, `Connection: close`, no other headers, TLS verification off, redirects followed. Status and content hash, plus the scorer's regex | Run for every learned URL |
| DNS | UDP A (and MX, which cannot pass in Quotient) queries, no EDNS, one retry | Compare all learned records |
| ICMP | Echo, 24-byte payload, privileged raw socket | |
| SSH | Password login (`none` then `password`), PTY `xterm 40x80`, `shell`, type one command, wait `Timeout/8`, read | The scorer-mimic probe; catches slow profiles, `PermitTTY no`, `nologin` shells |
| SMB | NTLMv2 with an empty domain (so the server's own name is used), tree `\\ip:445\share`, open and read the learned file, compare regex or SHA-256 | A bare username hits the local account database of a member server |
| WinRM | `POST /wsman` over NTLM, run the learned command, compare stdout | |
| SMTP | `EHLO localhost`, `AUTH PLAIN` over plaintext, `MAIL FROM`, `RCPT TO` a local mailbox, `DATA`, `QUIT`; no STARTTLS | |
| IMAP, POP3 | Plaintext `LOGIN` and `LIST`; `USER`, `PASS`, `NOOP`, `STAT` | |
| FTP | `USER`, `PASS`, `FEAT`, `TYPE I`, `EPSV`, `RETR` of each learned file, `QUIT` | |
| MSSQL | TDS pre-login, login7, run a learned query, compare the first rows | `go-mssqldb`; the real script is unknown |
| Splunk | REST login on 8089 then a search export; and Basic auth `GET /services/server/info` | Until the real logic is seen |
| RDP | TCP connect and hold, and an authentication probe (CredSSP/NTLM) on the Kali with `xfreerdp /auth-only` | The bare connect is what upstream does; the packet says "with authentication" |
| LDAP, TCP | Simple bind; connect with banner match | |

- **Each check has:** a service, a type, its parameters, the expected result, an interval, its vantage points, an origin (`manifest`, `discovered` or `manual`), a state (`active`, `paused`, `retired`), a mode (below) and a result history.
- **Two modes per check.** The **faithful sample** picks one random item and one random credential like the scorer, and checks the response as the scorer would. The **union sweep** tests every learned item and every learned credential in turn, at a low rate. Faithful tells us what the scorer will see this round; union finds the one broken item that hides for rounds [Q §9.8].
- **Strict where Quotient is lax.** A check can report "scorer would likely fail" (status, content, hash or regex drift against the last response seen next to a scorer success) separately from "service unhealthy" (refused, reset, timeout, wrong auth) [Q §9.7].
- **Managed in the UI:** add from a template or from any observed request (**Make this a check**), edit, pause, retire, and **Accept current response** after a legitimate change. Every change is written to the manifest overrides and takes effect immediately.
- **Results:** a check turns red after 2 consecutive failures. A red check opens an alert with the response diff and the latest trace-back attached.
- **Latency warning.** The scorer's default timeout is `Delay/2`; our probes alert when a response approaches it [SP §A14].
- **Vantage points side by side.** Red from the Kali but green from inside the LAN points at the Palo or NAT path. Red from inside points at the service. The Kali is the closest to the scorer's own position (§ The Kali).

### Credentials the scorer uses

Discovery builds, per service, the set of accounts the scorer authenticates with, from observed logins (SSH banner and auth, SMTP `AUTH PLAIN`, IMAP `LOGIN`, FTP `USER`, SMB NTLM user names, WinRM NTLM, TDS login7). Each learned account is marked `scored`. With organizer approval, `GET /api/credlists` on the portal lists the usernames per credlist directly [Q §4.3]. Marked accounts are never locked, deleted, renamed, expired or rotated outside a PCR transaction. `sysadmin` is treated as scored until shown otherwise.

### Check discovery

1. **Recognize scorer traffic** by behaviour. A connection is scored on burst membership, one-shot-per-service-per-round, protocol fingerprint match (table in Appendix G) and use of a learned credential. Source IP is a hint, never a rule, because runners sit behind NAT or Divisor [Q §6].
2. **Group its requests per service** into observed checks, with variable parts templated. Rotating users, URLs, records or files become one check with a set of values. The service (port, protocol, account usage) is learned within 3 rounds. The **item set** is marked partial with a coverage estimate (expected rounds to see all `k` equally likely items is `k·H_k`: about 4 for 3 items, 11 for 5, 29 for 10) and keeps growing the whole event [SP §A2].
3. **Compare against the active list:**
   - **Not covered:** a proposal, "Scorer started checking X", with a sample request and a pre-filled check.
   - **Covered, but the request changed:** a proposal to update the existing check.
   - **Active check with no scorer counterpart for 5 rounds:** flagged as possibly stale. Nothing is ever removed automatically.
4. **Mark scored accounts** (above).
5. **Spot blocked checks.** If a round reaches the other services but no scorer traffic reaches one of them, that's an upstream block. An alert fires with the Palo's deny logs for that window attached.
6. **Learn unknown scorer logic.** Services without a native Quotient check (MSSQL, Splunk, RDP-with-auth) are fingerprinted by burst timing, port and account use; the first bytes of each exchange are stored so the check can be rebuilt.

**Rules of engagement.** Discovery is strictly passive toward the scorer. We observe what it sends to our hosts. We never connect to, scan or probe its addresses, and never break a scored service on purpose to see what the scorer does.

### SLA tracking and operator-fed verdicts

- Per learned service, a failure streak is inferred from capture (refused, reset, timeout, auth failure, wrong content) and alerts at `threshold − 2`. A pass resets it; after a penalty it restarts. The threshold starts at the upstream default of 5 and is replaced by the observed value once known [Q §9.5].
- Passive capture shows what the scorer sent and how the service replied, not whether Quotient called it pass or fail. Ground truth enters in one of three ways, in the order we would prefer: (1) a **read-only poll** of the team's own pages (`GET /api/services/{team}`, `/api/metadata`, `/api/credlists`) at most once per round, using a session cookie an operator pastes, only if the organizers approve; (2) the operator **pasting the Up/Down table**; (3) neither, and Phylax runs on inference. The poll never calls `POST /api/pcrs/*` [Q §4.4].
- If debug text is shown to teams, it contains the usernames and passwords the scorer used and the exact failing step. Portal cookies and that text are credentials: stored encrypted, never forwarded, never logged [Q §9.14].

### The checks view

Per service, two columns side by side: our active checks with their latest results from each vantage point, and the scorer checks observed recently, with when each was last seen. Each pair is marked **matched**, **proposed** or **stale**. Below that is a change feed. A strip shows the round clock, the learned Delay and Jitter, the SLA streak per service, and any dropped rounds.

**Complexity flag:** recognizing scorer traffic is heuristic. It's bounded by requiring a human click for every proposal, and by acceptance tests against Quotient's own ground truth in the lab.

**Deliberately out of scope:** learning the scorer's pass criteria from NISE, byte-exact replay of scorer traffic, and keeping scorer profiles across seasons.

## Traffic labeling, change detection and trace-back

Every connection to our services is labeled scorer, us or other. Any change to a service is detected within a minute. Each change our own plans didn't make starts an automatic trace-back: from the changed thing, to the process that changed it, to the network request that drove that process, to the source and everything else it did. The result is an incident, which the chain builder turns into hops (§ Attack chains).

### Traffic labels

| Label | How it's assigned |
| --- | --- |
| `us` | Our active checker, the Kali and its scans, agents, relays and device adapters. Known sources and connection types. A canary probe or plan step carries its tag. |
| `scorer` | Learned by check discovery: burst membership, fingerprint, learned credentials. Never from address alone. |
| `other` | Everything else: traffic generators, the red team. Within it, `attack-like` is flagged by detections: scans, exploit payloads, webshell requests, decoy hits. |

Red-team sources learned from decoy hits and detections are tagged as such, so later connections from them are labeled on sight. The red team won't always look malicious and may imitate the scorer, so the working question is "is this neither the scorer nor us?"

### What counts as a change

| Change | Detected by |
| --- | --- |
| Served content on disk (webroots, FTP root, zone data, mail store structure, the SMB SOP files) | `fim` with hashes |
| What the service returns | Active checks, and our answers to scorer requests |
| Configuration (Apache or httpd, IIS, PHP, Postfix, Dovecot, DNS, `.htaccess`, `auto_prepend_file`, Splunk apps) | `fim`, plus semantic parsers for PHP ini and unit files |
| Runtime behaviour: new child processes, listeners, outbound connections or loaded modules under the service | `proc`, `net`, Sysmon 7, the integrity module |
| The service's own binary or libraries | The integrity ledger |
| Identity: accounts, groups or permissions the service depends on | `fim` on account files; Security events on Windows |
| App-level data (OpenCart admin rows, database users, UDFs) | Read-only SQL pollers |
| Network devices: rules, NAT, admins | Device adapter config diff |

Changes made by our own plans carry the plan's tag and quietly update the baseline. Anything untagged raises an alert.

### The trace-back chain

Triggered automatically by any untagged change, red health check, or high-severity detection on a service:

1. **The change.** For example, `index.php` modified at 14:03:12.
2. **The writer.** The file event now carries the actor (audit watches on Linux, Sysmon 11 on Windows).
3. **Its lineage.** For example, `sh` ← `httpd` worker ← `httpd` parent, from the agent's process records.
4. **The request.** The agent maps the worker to the client connection it was serving, and the transaction log gives the parsed request. How the mapping works depends on the stack:
   - **The worker owns the client socket** (Apache prefork with mod_php, most simple daemons): the socket records give the connection directly.
   - **php-fpm behind Apache or nginx:** the worker holds only the FastCGI socket. The agent follows it to the front-end process. If that process serves one connection at a time, the match is exact. If it serves many, the match is by time and script path in the transaction log, marked lower confidence.
   - **IIS:** http.sys accepts every connection, so socket tables show PID 4. Hardening adds `REMOTE_PORT` to the IIS log fields. The agent maps `w3wp` to its site through its application pool, matches the request by time and path in that site's log, and the client address and port then give the exact connection.
5. **The source.** That connection's source address and its label.
6. **Everything else from that source:** earlier transactions, scans, login attempts and decoy hits, across every host. This usually reveals first contact and the foothold.
7. **Evidence.** The packet ring around the window is frozen and pulled, and files involved are hashed and collected.

When the chain breaks, the timeline says which link is missing instead of guessing: encrypted traffic (HTTPS details only from server logs), in-memory changes with no writer, agent gaps, and short-lived processes (the agent queries sockets at the moment of the exec or file event, not only on a timer).

**Complexity flag:** the request link (step 4) is the hardest part. It has a dedicated lab test with quick webshell requests. If it misses too often, the fallback is time-window correlation, marked lower confidence.

## Attack chains

D-2 asks for chains built from network and other telemetry, kept lightweight. A chain is an ordered list of hops. It is **not** a graph engine: there is no graph database, no query language, no whole-system provenance graph. It is a table of hops, about a dozen linking rules, and a timeline view. The aim is the IR rubric: half of the red-team lead's marks go to remediating the attack path (who or what placed the thing, how the account was compromised, proof the hole is closed) [TTP §0, PRO §3].

### Hops

| Kind | Meaning | Built from |
| --- | --- | --- |
| `access` | Source reaches a host through a service and account | Authentication events with source address: Security 4624 and 4625 (types 3 and 10), 4768, 4769, 4776; sshd auth lines; web logins from transaction logs; device logins |
| `exec` | A process runs on a host | Process lineage from `proc`, trace-back |
| `change` | A file, config, account or persistence entry changes | `fim`, account events, persistence detections |
| `move` | Host A reaches host B | SSH, SMB, WinRM, RDP, WMI, PsExec-style service creation, DCSync, found by cross-host stitching |
| `egress` | A host reaches outside | Denied egress, sinkhole captures, Palo traffic logs, allowed-but-unknown connections |

Each hop row holds: chain id, kind, source host and address, destination host, account, process reference, 5-tuple and Community ID, start and end, technique (ATT&CK v19), evidence references, **link method**, **confidence**, and a remediation item.

### Building hops from data we already have

1. **Authentication with source.** Every login event becomes an `access` hop candidate, with the account and the source address.
2. **Cross-host stitching by 5-tuple.** An outbound connection recorded by host A's `net` module is matched to an inbound session on host B by Community ID, with each host's measured clock offset applied. Every LAN host has an agent, and on the flat LAN that's the only way to see east-west movement. Where the Palo is in the path (the outside leg), the tuple is translated, so the match goes through the Palo's session log and its NAT fields. An unmatched side is kept and marked lower confidence.
3. **Within a host,** process lineage and trace-back join `exec` and `change` hops to the `access` hop that created the session: the sshd child tree, the `w3wp` request, the WinRM `wsmprovhost`, the service created by a remote caller.
4. **Perimeter.** Palo traffic logs cover anything crossing the perimeter, including attackers who killed the agent.

### Seeding, bounds and grouping

- **Seeding.** A chain starts from any high-severity alert, untagged service change, red check, decoy hit, honeytoken use or ledger alert.
- **Extension** goes backward (how did this get here: the inbound hop and its source's earlier hops) and forward (what did this source or account do next), bounded by ±2 hours and a hop limit of 12.
- **Campaigns.** Chains that share a source address, an account (the hidden domain admin, a stolen key), a binary hash or a C2 destination merge into one campaign. One IR per campaign is the pattern that worked for other teams.

### Output

- **A timeline view,** not a graph canvas, with one row per hop: time (Central, UTC alongside), host, what happened, ATT&CK technique, link method and confidence.
- **A remediation item per hop:** close the entry (service, account, vulnerability), remove the persistence, rotate the credential that was used, block the source. Each item has a state (`open`, `applied`, `verified`) and a checkbox, and verification is automatic where possible (the account's password changed, the persistence is gone and a re-hunt is clean, the binary matches the ledger).
- **Feeds the IR drafter:** the incident's "attack path" and "remediation" sections come from the hops and their items.

### Confidence

Every hop records how it was linked: an exact 5-tuple, the same account within N seconds, lineage within a host, or a time-window guess. Network-only hops (an agent dead or lying) are shown, marked lower confidence. The timeline never presents a guess as fact.

### What it deliberately does not do

No syscall-level provenance, no general graph traversal, no ad-hoc queries, no machine-learned linking. Rules of bounded size, tested against the purple-team campaigns (chain completeness is a metric: T33).

**Complexity flag:** cross-host stitching depends on clock offsets and NAT-aware joins. It is bounded by exact-tuple matching first, per-hop confidence, and a lab test against campaigns 01 and 03.

## Detection and response

Detections favor behavior and allowlists over signatures, because the red team can read our rules. They run on the host, so they fire with the link down. Responses come in three tiers by reversibility. Only reversible actions on unscored state run automatically, and every automatic action is followed by a health check.

### Rule format

Rules are YAML, delivered in the agent's signed config and hot-reloaded without a restart. The language is deliberately small, and the engine has the pieces the research found necessary [PR "Engine and telemetry work", OA §5.5, WT §9.5].

```yaml
id: D1.service-spawns-shell
mode: act                       # act (may trigger tier-0/1 responses) | alert; a global override forces alert
when:
  event: process_start          # mandatory event type; the engine indexes rules by it
  all:
    - parent.service.scored: true
    - not: { exe: { in_profile: parent.service } }
    - not: { tag: { present: true } }       # exempt our own tagged plan and patch-window activity
  any:
    - image: { endswith_any: [/sh, /bash, /dash, /python3, /perl, /nc, /ncat, /socat, /curl, /wget, /busybox] }
    - image: { endswith_any: [\cmd.exe, \powershell.exe, \pwsh.exe, \certutil.exe, \bitsadmin.exe, \whoami.exe, \net.exe, \net1.exe, \rundll32.exe, \mshta.exe, \regsvr32.exe] }
severity: high
tier: 1
collect: [process_tree, content_changes, transactions_window_10m, freeze_ring]
attack: [T1505.003, T1059]       # ATT&CK v19 ids; validated in CI
ir_template: web-app-compromise
tests:
  - { name: php-exec,     event: lab/tests/fixtures/webshell_php_exec.json, should_match: true }
  - { name: health-script, event: lab/tests/fixtures/cgi_health.json,       should_match: false }
source: { author: Phylax, license: repo }   # imported rules carry upstream id, commit, author, licence
```

Engine requirements, all of which the discarded engine lacked [CR §5, PR E1–E9]:

| Requirement | Why |
| --- | --- |
| Exactly one key per condition, enforced by schema validation; deterministic evaluation | A multi-key map was evaluated on a random key |
| Operators `eq`, `in`, `re`, `contains`, `startswith`, `endswith` (and `_any` forms), `gt`, `lt`, `cidr`, `in_profile`, `present`; string matching case-insensitive by default with an explicit case-sensitive flag | Sigma translation is then mechanical |
| `count` with `by` and `distinct`, per host, source, account or process, not one global window per rule | A global SSH-failure count cannot tell the scorer from an attacker |
| Parent fields on process events (`parent.exe`, `parent.cmdline`, `parent.service`) | Every parent-based public rule needs them |
| Actor on file events (pid, exe, auid) | Package managers are excluded by process, or by window tag where the actor is unknown |
| The plan or patch-window `tag` on every event type, not only files | Our own hardening must not alert |
| Direction and service on connection events | D3 fires on every listener without it, D4 never fires |
| Regexes compiled once at load; the dedupe map is pruned; cooldown keys include the process start time | PID reuse suppressed alerts; regex recompilation cost CPU |
| `collect:` is executed when the rule fires, and the evidence ships with the alert | Evidence has to be gathered before the attacker cleans up |
| Inline `tests:` with fixtures; CI fails a rule with no test or a failing test; an `attack:` id that is revoked or unknown fails | "CI rejects a rule without a test" must be real |
| A global `override_mode: alert` that makes every rule alert only (and safe mode does the same for responses) | UCF's pattern |

Rules, plans and the Sigma output live in the public repo. The rule text is ours.

### Sigma: build-time import, not an agent evaluator

The decision [DR §4, OA §5.5]: **no Sigma evaluator on the agents; yes as a build-time input.**

- A Go tool, `phylax rules import-sigma` (run in CI, never shipped to hosts), built on `sigma-go`'s parser (MIT), translates a **curated allow-list of Sigma rule ids** (about 118 are cited in the research) into Phylax YAML. A pre-pass expands `windash`; `fieldref`, `base64offset`, aggregation and correlation are rejected.
- Output goes through the same CI as hand-written rules: a lab-test fixture per rule, ATT&CK v19 ids, tiers and `collect`. A rule that no telemetry can feed stays disabled until the producer exists.
- `source:` carries the upstream id, path, commit, author and licence into the alert, the UI and the IR drafter, as the Detection Rule License requires [DR §6]. A generated `THIRD_PARTY_RULES.md` lists them.
- Field names follow Sigma and Sysmon (`Image`, `CommandLine`, `ParentImage`, `User`, `OriginalFileName`, snake_case for Windows `EventData` keys) so translation is mechanical; the 4688 fallback cannot feed rules that need `OriginalFileName` or hashes.
- Why not native: 10,377 match values cost about 46 MB of heap and 14.5 ms per event unindexed; the agent budget is 80 MB and 3% CPU. Sigma is 77% Windows and 7% Linux, and mostly `status: test` [DR §4].
- **Licensing:** vendor Sigma (DRL 1.1, with attribution), Splunk security_content, Falco, osquery packs, sysmon-modular and Atomic Red Team. **Re-implement** Elastic (ELv2) and Wazuh (GPL-2.0) logic and cite the upstream id in `source:`. Do not use the UIUC or Wayne State files [DR §6].
- **Optional:** the same translation can emit scheduled searches for the Splunk host with schedules enabled, as secondary hunting (§ OSS alongside Phylax).

### Detection catalog

The ids continue v2's D1–D17 and the coverage spec's D18 onward [COV §4]. The 81 proposed rules P01–P81 [PR] are the backlog; each becomes a tested `rules/*.yml` file. Their readiness classes (A: shipped event types; A*: needs the exec feed; B: needs an engine feature; C: needs a producer that did not exist) map to milestones M4 to M7.

| ID | Detects | Data | Logic | Tier |
| --- | --- | --- | --- | --- |
| D1 | Service process spawns a shell or tool; stray processes of scored users; sshd child interpreter; web server and Windows service children | `proc`, Sysmon 1 | Parent in a scored service's tree and child not in its profile, or any shell, interpreter or download tool. D1b: Windows names under `w3wp`, `dns.exe`, `ftpsvc`. D1d: a scored account's process whose parent is not sshd, login or its service. | 1 |
| D2 | Content or config tampering; mounts over content; PHP ini semantics; app admin rows; web log attacks; dangerous webroot extensions; mail hooks; DB plugins | `fim`, semantic parsers, SQL pollers, access logs | Untagged change in a content root or config; D2b new bind or overlay mount on content roots; D2c effective PHP config loses `disable_functions` entries or gains `auto_prepend_file`, `extension=`; D2d new or changed `oc_user` or `ps_employee` row; D2h/D2i Postfix `master.cf` pipes, aliases, Dovecot post-login, `mysql.func`, `plugin_dir` | 0 if a webshell signature matches, else 1 |
| D3 | New listener; risky listener; remote-access inventory; known local-root exec | `net`, `inventory` | Listening socket not in any service, decoy or profile (the baseline comes from the manifest); Tailscale, ngrok, chisel, frp, cloudflared, VNC, WSL feature, OpenSSH on Windows; PwnKit-shaped exec | 1 |
| D4 | Unexpected outbound connection; relay or proxy behaviour | `net`, Sysmon 3, Palo traffic | D4: an established connection from a server process to a peer outside its declared dependencies. D4b: a service whose profile says `outbound: none` has an established external peer and near-symmetric bytes in and out (the regional's Postfix proxy signature) | 1 |
| D5 | Fileless or hidden execution; **binary integrity**; capabilities; masquerade; writes to binary directories; new SUID | `crossview`, `integrity`, Sysmon 8/25, xattr walk | D5: deleted or memfd executable, `LD_PRELOAD`, anonymous executable memory, remote threads. **D5d: a binary, library or pinned service image does not match the ledger (§ Binary integrity ledger).** D5c: new file capability. D5e: system-name masquerade (`ISASS.EXE`, `SVCH0ST`) or wrong parent. D5f/D5g: writes to `/usr/bin`, new SUID outside a patch window | 1 (alert only for D5d) |
| D6 | Persistence created or altered; package holds; unit environment and capabilities; shell hooks; immutable flag; suspicious service install; SSH persistence files; PAM changes; task content; WMI; autoruns; IFEO; IIS modules; DNS plugin DLL | `fim`, audit, Security 4697/4698/4702, System 7045, Task Scheduler 106, Sysmon 12–14 and 19–21, D-Bus | Any untagged write to a persistence location (Appendices B and C). D6c `apt-mark hold` or versionlock on PAM, ssh, sudo or libc. D6d unit `Environment=LD_PRELOAD` or ambient capabilities a service doesn't need. D6e `.screenrc`, `PROMPT_COMMAND`, `command_not_found` hooks. **D6f `chattr +i`/`+a` outside a plan tag (our own hardening is tagged).** D6g unsigned SYSTEM service. D6q task content (outside System32, encoded PowerShell, the `\Microsoft\` folder hiding a non-stock task) | 0 (disable, never delete) |
| D7 | Account changes; sudoers; UID 0 and shell invariants; Windows account events; hidden `$` accounts; privileged group adds | `fim`, Security 4720, 4722, 4724, 4738, 4728, 4732, 4756, 4781 | Account created, enabled, renamed, reset or elevated outside our plans; D7b `/etc/sudoers.d`; D7d `uid==0 && name!=root`; D7e a hidden machine-style account | 1 |
| D8 | Credential theft; **Zerologon**; LSASS; DCSync; AD object changes; Kerberos anomalies; hive and NTDS dumps | Sysmon 10 and 1; Security 4662, 4742, 4768, 4769, 5136/5137, 4670, 4741; System/Netlogon 5827–5831 | LSASS read by a non-allowlisted process; D8b **System 5829 (Netlogon vulnerable-connection) or Security 4742 by ANONYMOUS LOGON on a DC machine account, or a burst of `DC$` network logons**, plus a continuous check of `FullSecureChannelProtection` and the build number [DR §0, SV R2.4]; DCSync (4662 replication rights from a non-DC); RC4 ticket bursts; D8d GPO, ACL, delegation and `gPLink` changes | 1 |
| D9 | Lateral movement and remote admin; SSH peer push; services backed by shares; SSH brute force | Security 4624 (types 3, 10), 4648, 5140/5145; Sysmon 17 and 18; auth logs | Admin logon from a source other than the controller after rotation; admin-share access; remote service creation; D9b `ssh` client on a server connecting to another declared host; D9c FTP or IIS root on a UNC path; D9e failures per source and account, **with the scorer's N-failures-then-success pattern from the same source within about 100 ms exempt** [Q §9.6] | 1 |
| D10 | Defense evasion: firewall, Defender, audit policy, log clearing, Sysmon tamper, monitoring config, timestomp | Audit ruleset hash every 10 s, Firewall log, Defender 5001/5007, Security 4719/1102, System 104, Sysmon 4/16, heartbeat gaps | Firewall changed or disabled; Defender protection off or new exclusion; audit policy changed; logs cleared; Sysmon stopped; agent silent; `auditctl -D` and `iptables -F` by untagged actors | 0 (restore) and 1 |
| D11 | Rootkit indicators; kernel modules; BPF programs | `crossview`, `inventory`, Sysmon 6 | Hidden PIDs, sockets or modules; BPF programs outside the baseline; kernel taint change; unsigned or new driver | 1 |
| D12 | Denied egress | `egress`, Palo deny logs | Any denied outbound attempt from a server; periodic attempts escalate | 1 |
| D13 | Sinkhole catch; C2 pipes; beacon periodicity | `sinkhole`, flows, Sysmon 17/18 | Any capture; HTTP or TLS beacons with framework fingerprints escalate; jitter below 20% over at least 10 intervals | 1 |
| D14 | Network device tampering; policy order and role changes | Adapter diff, Palo config and system logs, VyOS commit log | Commit we didn't make; unknown admin login; an `allow` rule above a block rule; new admin role or API key; diff against last known-good | 1 |
| D15 | Decoy interaction; credential-file access | `decoys`, DC events, service logs | Severity by depth: connect (info), login or command (high), honey credential or key used anywhere (critical) | 1 |
| D16 | Scorer check change | Check discovery | New, changed or stale scorer checks; scorer traffic missing for a service | Info |
| D17 | Service change; config moved; service stopped without a plan tag; destructive commands; web-admin brute force | Change detection, D-Bus, `proc` | Untagged change to a scored service's content, config, behaviour or identity, with trace-back attached; D17b `moved_from`/delete on configs; D17c `UnitStopped` for a scored unit (tier-0 restart under the circuit breaker); D17d `rm -rf`, `dd of=/dev/sd*`, `shutdown`, `vssadmin delete` by non-operator sessions | 1 (0 for restart) |
| D18 | **Default or old-credential logon; credential fan-out** | sshd, 4624, Cockpit, web admin, device auth | A successful login for an account in `rotation_pending`, or with a default credential, or from an unknown source; D18b one source authenticating to at least 3 hosts within 5 minutes (controller correlation). Scorer sources are excluded by behaviour, never by address | 1 |
| D19–D23 | Promiscuous NIC; allowed-protocol abuse (NTP, DNS, ICMP volume and shape); address or route changes; re-infection hunt trigger; USB attach | `net`, flows, `enroll` events | See [PR]; D22 starts the prebake hunt after any restore or re-enrollment | 1 |
| V1–V4 | **Vantage alerts** (from the Kali): V1 external probe red or disagreeing with the in-LAN probe; V2 newly open public port; V3 egress canary leak; V4 PCR credential verification failed | Kali probes, scans, canaries | See § The Kali as an external vantage point | Info/1 |

Every rule in the repo carries an ATT&CK v19 mapping (T1685 and T1686 replace the revoked T1562 family; the old ids stay as aliases), its test, its tier, its mode and its IR template [DR §5].

**False-positive controls.** The scorer and our own hardening are the main sources, more than the red team [DR §3]. The controls: behavioural scorer exemption (never address-based, because Divisor re-draws addresses and known-source and first-seen rules would break), the plan and patch-window tag on every event type, exempting the agent by randomised path and hash, thresholds generated from check discovery, and keeping exec-based rules at tier 1 so an operator typing the same command costs one click. NTLM WinRM and SMB network logons by the scorer look like pass-the-hash to some public rules [DR §3, inferred], so those rules take the scorer's learned accounts as context.

### Response tiers

| Tier | Who decides | Actions |
| --- | --- | --- |
| 0: automatic | The agent, locally, in seconds, even with the link down | Restore the declared host firewall; re-enable Defender protection and remove new exclusions; reinstall or restart Sysmon and restore audit rules; disable (never delete) untagged scheduled tasks, cron entries, units and Run keys; restart a stopped scored unit under the circuit breaker; quarantine a new webroot script that matches a webshell signature |
| 1: one-click | Operator in the UI, with the evidence on screen | Kill a process tree (pidfd with start-time check; `cgroup.kill` for units); suspend instead of kill to preserve memory; quarantine a file; **restore a binary from the depot**; block a single source IP on the Palo; isolate a host (quarantine table with auto-revert); lock an unscored account; kill sessions; restart a service; restore a file from baseline or backup; roll back a plan node |
| 2: manual with checklist | Operator, with a verbal callout to the team | Scored-account rotation (PCR transaction); krbtgt reset; full service restore; device config revert; requesting a new reservation (resets everything) |

The integrity ledger is alert only (D-1): D5d never runs tier 0, and its one-click response is explicit.

### Guards on automatic actions

- **Protected processes** are never killed: OS-critical processes (`csrss`, `wininit`, `winlogon`, `services`, `smss`, `lsass`, core `svchost` instances, `systemd`), the sshd listener if declared, our agent, and anything inside a scored service's declared tree.
- **Scored accounts** are never touched automatically.
- **Rate limit:** at most 3 tier-0 actions per host per minute, keyed per object, not per recipe. Beyond that they become tier-1 proposals.
- **Circuit breaker:** a real post-action health check (the scorer-mimic probe) runs after every tier-0 action. If it goes red within 2 minutes, that action type is disabled on that host and escalated.
- **Loop detection:** the same restore of the same object 3 times in 10 minutes opens an incident and a targeted hunt on the culprit's lineage.
- **Locks and safe mode** apply. **Every network, account or process-control action has a timeout and a verified rollback** [OA §5.9].
- **No scripts:** response actions are typed and native. Wazuh active response is disabled (§ OSS alongside Phylax).

### Response recipes

| Trigger | Collected automatically | Proposed actions | IR template |
| --- | --- | --- | --- |
| D1 or D17 via webshell | Trace-back timeline, process tree, content diff, transactions from the source ±10 min, ring slice | Kill tree, quarantine file, block source IP, hunt persistence by the web user, rotate unscored app and DB credentials | Web application compromise |
| D5d binary modified | Ledger verdict, signer, package owner, expected file and source, process tree, network behaviour | Quarantine as evidence, restore from the depot, restart, scorer-mimic verify, hunt the same hash everywhere | Service binary replaced |
| D7 | Creating session and its source | Disable account, kill sessions, review group memberships | Unauthorized account |
| D8b Zerologon | Netlogon events, source, build and registry state | Enforce the secure channel, patch or filter RPC, propose krbtgt double reset and privileged credential rotation (tier 2) | Domain controller compromise |
| D10 firewall disabled | Lineage of the disabler, recent persistence | Tier 0 restores; propose disabling the trigger | Defense evasion |
| D12 or D13 | Owning process, binary hash, sinkhole capture, persistence | Kill, quarantine, remove persistence, hunt the same hash on all hosts | Malware callback |
| D8 | Source account and host, logon session, tools seen | Disable source account, plan credential resets, krbtgt double reset | Credential compromise |
| D14 | Config diff, admin session | Revert to known-good, rotate device admin | Network device compromise |
| D15 with a honey credential | Token origin, every use of the token | Treat the origin host as compromised; hunt it; rotate real credentials stored nearby | Credential theft from host X |
| V2 or V3 | The Kali scan diff or canary report, the Palo rule set | Close the port or the egress path | Perimeter misconfiguration |

### Audit trail

Every action, automatic or manual, writes an event: what triggered it, before and after state, the undo, and the health result afterwards. This is the containment section of every IR report, and the answer when the White Team asks why something changed.

## Binary integrity ledger

D-1: detect red-team-modified or replaced binaries continuously, and **alert only**. At the 2026 regional the red team replaced the Postfix binary with a proxy to their Kali and replaced `dns.exe` with a build that had a remote kill switch. In 2020 teams saw trojaned `nologin` and `dash`. These are prebaked, so they are not "changes", and file-change monitoring stays silent. The old design checked binaries once, in the first-15-minutes hunt [PRO §2, COV L-8/S-1/S-2].

### Truth sources, never the host alone

In order of trust. The host's own package database is a hint only, because an attacker with root can edit it.

| Rank | Source | What it gives | Where it comes from |
| --- | --- | --- | --- |
| 1 | **Lab reference ledgers** | Path to sha256, size, mode, owner package, signer, for each OS and role we have images for | Built in the lab from the same ISOs and cloud images as the packet's OS versions (Rocky 9, Ubuntu 22.04, Debian 12, Server 2019 and 2022, Windows 11), signed, shipped in the release as compressed indexes |
| 2 | **Windows signatures plus Winbindex** | Authenticode and catalog verification natively (`WinVerifyTrust`); exact sha256 for every Microsoft binary version of the builds in play | Winbindex data fetched and trimmed in CI for the three builds; cached (D-5) |
| 3 | **Vendor packages** | For the exact package versions found on the host, the real file hashes | The controller downloads the `.deb` or `.rpm` from the distro mirror (prefetched for announced OS versions, cached), extracts and hashes the contents. This survives an attacker who edited the host's `dpkg` md5sums or RPM database |
| 4 | **Host package metadata** | `dpkg` md5sums, RPM SQLite digests | Hint only; used to guess which package version to fetch, never as proof |

The controller fetches the version the host *claims* and the distro's current version. A binary that matches neither is a mismatch. Third-party signed software (Splunk, SQL Server, Sysinternals) is accepted against a signer allowlist from the manifest.

### Verdicts

| Verdict | Meaning |
| --- | --- |
| `match` | Hash equals a truth-source entry for this path and version |
| `match_other_version` | Hash is a known-good for a different version of the package (patch-level drift; informational) |
| `unknown` | Path or hash appears in no source (an unpackaged binary in a system directory) |
| `mismatch` | The path is known and the hash equals no known version |
| `sig_invalid` | Authenticode or catalog failed, or the signer is not on the allowlist (Windows) |

### When it checks

- **At enrollment:** a full sweep of system binaries, libraries, service binaries, drivers, and scheduled-task and autostart targets against the ledger. This replaces the one-time T+15 hunt for binaries, and the hunt re-runs it.
- **At every exec:** the agent hashes the executable (cached by device, inode, ctime and size) and looks it up. An `unknown` or `mismatch` hash running as root, as a service account, or as a scored service's process raises D5d. On Windows the hash comes from Sysmon 1 (and 6 for drivers, 7 for image loads).
- **Loaded libraries:** for service processes, file-backed mappings in `/proc/<pid>/maps` are checked against the ledger at start and every 60 s. This catches `LD_PRELOAD`, a replaced `.so`, and a PHP or Apache module that is not package-owned. Windows: Sysmon 7.
- **Periodic:** pinned service binaries every 60 s; all system paths every 15 minutes, hashing only files whose device, inode, size, mtime or ctime changed, with a full re-hash on a slower cadence. The sweeps are low priority and rate-limited.
- **After every restore, re-enrollment or reset,** a full sweep runs before the host may be tagged golden.
- **Around patch windows,** the controller pre-resolves the hashes of the packages the window will install, so expected changes are `match` and others stay alerts.

### Service binary pinning

The manifest (or discovery) ties each scored service to its process and its binaries (`pin: true`). The agent checks the running image (`/proc/<pid>/exe`, including `(deleted)`, memfd and a replaced inode) against the on-disk file **and** the ledger. That catches "swapped but not yet restarted" and "restarted on the trojan".

### Behavioural corroboration

Severity rises when the same binary shows service-inappropriate behaviour, because a ledger can be incomplete and a rootkit can lie to hashing:

| Signal | Example |
| --- | --- |
| Outbound from a service that has none | Postfix to a non-relay host; `dns.exe` to an unexpected peer (D4b) |
| Near-symmetric bytes in and out on a service socket | The proxy signature |
| A new listener, child shell or unusual module load | D1, D3, Sysmon 7 |
| Running image differs from the file on disk | Pinning check |

These would have caught the regional's Postfix proxy even without a ledger entry.

### YARA, scheduled

The `scan` module runs the pinned YARA-X binary every 5 minutes over process memory and files, deduplicated by inode and at low priority, with a C2 corpus: Sliver, Mythic (Apollo and Poseidon), Realm, Sentinel, chisel, ligolo, pamspy, sshsnake, watershell, Cobalt Strike and Metasploit stagers [WT §2.3, §9.3]. Process memory reading is the agent's job (`/proc/<pid>/mem`, `ReadProcessMemory`); whether the scanner takes streams or needs a file is lab-tested. Rules come from public sets with their licences checked before use; the UCF rule set's licence is unknown. Detections raise D5 or D5d at tier 1 with a quarantine proposal. **Complexity flag:** YARA is the one host binary in a default path; it is pre-approved, hash-pinned and CPU-capped.

### The alert and the response

The alert carries the hash, the ledger verdict, the signer, the owning package, the expected file and its source, the process tree and the network behaviour. **There is no automatic restore.** The one-click tier-1 response is: quarantine the file as evidence (hash, mtime, copy), restore the known-good file from the **local depot** (service binaries; command tools are in the [trusted tool depot](#trusted-tool-depot)), restart the service, and verify with the scorer-mimic probe.

### The local depot

See also the [trusted tool depot](#trusted-tool-depot) for command-line tools. Known-good copies of service binaries and their packages for the announced OS versions, plus the vendor packages the ledger fetched. It is a signed release asset (small tier) and a controller cache (large tier), so a restore never depends on the internet (D-5). DePaul's "offline depot" is the model [PRO §2].

### Limits

- A root attacker can lie to the agent (a hooked `readdir`, a rootkit). Cross-view (`crossview`) and behavioural corroboration are the mitigation. Hypervisor-level verification isn't available.
- The first-contact trust gap: the ledger's own code runs on a possibly backdoored host. Hashing uses only native Go calls, never host tools.
- A ledger is only as complete as the images behind it. `unknown` is a prompt to look, not proof, and `match_other_version` keeps patch drift from flooding the queue.
- Expected false positives: package updates outside a tagged window, self-built binaries, and files modified by the organizers' images. The queue lets an operator accept a hash into the overrides.

## The Kali as an external vantage point

D-3: the Kali sits on VyOS's side leg, outside the Palo. From there it reaches our services through the same NAT and policy path as the scorer. Neither the controller nor the in-LAN runners see that path [PKT §2, PRO §4]. **The controller stays on the LAN** (D-4), because moving it to the Kali would require allowing outbound access from the LAN to it.

### The Kali agent

The Kali runs the same agent with the roles `check_runner`, `scanner` and `canary`. It dials the controller outbound through VyOS and the Palo, under the one declared rule and static NAT (§ Topology). It is installed by the console one-liner. It stays a workstation: it runs checks and scans and nothing else. This needs confirming with the organizers (§ Risks and open questions).

| Aspect | Rule |
| --- | --- |
| Trust | Untrusted vantage point. It cannot command other hosts. Its verdicts are evidence about the public path only. |
| Secrets | Scored credentials are delivered in signed steps for a probe, held in memory, never written to disk, and rotated if the Kali is suspected. |
| Targets | Only our own public addresses from the manifest. The scorer, other teams, the White and Red Teams and global assets are never targets. |
| Labeling | The Kali's translated source address is registered as `us`, so our probes and scans never look like the red team. |
| Rate | Probes stay out of the scorer's burst window and below knife-edge volume; scans run at a low rate. |

### Quotient-faithful checks through the public path

The `check_runner` on the Kali runs the same probes as the in-LAN runners (§ Active checks), against the **public** addresses `172.25.(20+T).x`. They reuse Quotient's client behaviour: plaintext protocols, SSH password with PTY and shell and a typed command, NTLM for SMB and WinRM, one random item and credential per faithful run plus a full sweep of the learned item union [SP §A, Q §9]. This is the primary "is it up for the scorer" signal. A mismatch with the in-LAN probe is V1, and it tells you whether the fault is the service or the Palo/NAT path.

### PCR credential verification

After every PCR transaction, the Kali logs in with the new credential through the public path before the rotation step is marked done (§ Credentials). A failed login is V4 and starts the rollback.

### External perimeter scans

A scheduled scan of our public IPs: full-range TCP connect scan at a low rate, plus UDP probes on common ports with protocol-specific payloads (DNS, NTP, SNMP, TFTP, IKE). The Kali's `nmap` is a pre-approved host tool for service detection. Results are diffed against the declared exposure (the services marked scored, plus declared decoys). Anything newly open is V2. Durkee's debrief called out "far too many ports open… port 135 open" [PKT §7]. The output doubles as evidence for the recurring perimeter-scan injects (18 of 22 events [PRO §4]).

### Egress canaries

The Kali listens on a set of ports. Agents periodically (rate-limited, tagged) try to reach it on ports that policy should block, from servers and workstations, and report "blocked as expected" or "leak" (V3). It proves the egress policy and the Palo rules from the inside. Canary traffic carries its tag, so it never raises D12 or the beacon analysis.

### What opens up

Because the Kali is an external vantage point, it can also: run the zero-day style checks the red team would try against our perimeter (a Zerologon check-only tester against the DC's public path, an SMB and WinRM exposure check), measure the Palo's NAT behaviour (do inbound connections keep the real source?), confirm that blocked sources stay blocked, and record what the public path looks like when the Palo is under load. Each is a probe type on the same `check_runner`, not a new subsystem.

**Complexity flag:** the Kali adds an inbound path to the controller (one port, one source, pinned keys), scored credentials in a less-trusted place, and a host tool or two (`nmap`, `xfreerdp`). It is bounded by single-purpose roles, memory-only credentials, and the fact that every Kali verdict is advisory.

## Deception

Three kinds of deception turn red-team curiosity into precise, low-noise alerts:

- **Honeytokens:** fake credentials, keys and paths, unique per host, planted where attackers loot.
- **Decoy services:** fake SSH with a full fake shell, and other bait ports, reachable from inside the LAN and from outside.
- **Decoy content:** honey files and web paths that nothing legitimate ever touches.

A token's origin tells you which host was looted and roughly when.

### Principles

- **Declared like services.** Decoys are listed in `decoys.yml`. Host-firewall and Palo rules are generated for them.
- **Isolated.** All decoy listeners and the fake shell run in the agent's unprivileged decoy process.
- **Record only.** Nothing received is ever executed. Decoys never connect back, and never touch red-team infrastructure.
- **Never on scored ports,** and never change any content the scorer fetches. In 2027, SSH, WinRM and RDP are scored on specific hosts; decoys of those kinds go only on hosts where the service is not scored (for example SSH on the Windows hosts, WinRM and RDP on the Linux hosts).
- **Generated at competition time.** Token values, banners, honey paths and fake data are generated when the plan runs. The pools are in the public repo, so a careful attacker may recognise some decoys; per-host values are what the repo can't reveal. Banners and decoy ports are randomised per event too (D-8).
- **Severity follows depth.** Info: connecting. High: logging in or running commands. Critical: using a honey credential or key anywhere.

### Honeytokens

Every token is unique to its host and recorded in the controller's token registry.

| Token | Planted at | Sighted when it shows up at |
| --- | --- | --- |
| Fake SSH private key (`/root/.ssh/id_rsa_backup`) | Each Linux host | The SSH decoy recognizes its fingerprint |
| Fake DB or app credentials | `.env`, config backups, `web.config` | Logins to MySQL, decoy services, the web admin page |
| Fake shell history with an inline password | Root and admin home directories | That password tried anywhere |
| Decoy credential in LSASS (a `runas /netonly`-style logon session kept alive by the agent) | Windows servers | Failed authentication for that account on the DC (4625, 4771) |
| Honey AD accounts: one with an SPN, one with pre-auth disabled, one that looks like an admin | DC, in a separate OU | Ticket requests (4769, 4768) or any logon attempt |
| Honey OpenCart admin with a unique password | ecom database | That login attempted on the admin page |
| Honey DNS record that nothing uses | DNS zone | Any query for it |
| Honey SQL login and honey SMB file on the MSSQL host | MSSQL, the SOP share's neighbour directory | That login attempt; an open of the honey file (4663) |

**Complexity flag:** the LSASS decoy session needs the agent to keep a logon session alive on each Windows server. It's one of the few ways to tell that LSASS was dumped. If Defender or a reboot kills it, the agent recreates it.

### Decoy services

| Decoy | Behavior |
| --- | --- |
| SSH on 22 (where real SSH is absent or not scored) | Full fake shell: accepts a login after a few attempts, presents a believable filesystem and command set, records every keystroke, never executes anything. Banner randomized per host. |
| MySQL, Redis, Telnet on hosts that don't run them | Protocol-correct handshake and login prompts; credentials recorded |
| WinRM (5985) and RDP (3389) on hosts where those are not scored | Connect and negotiate only; credentials recorded where the protocol offers them |
| Fake admin web panel on an unused port | Login page that records every credential tried |

There's no SMB decoy: Windows holds port 445 on every host. **Complexity flag:** the fake shell is the largest decoy by far. It's isolated in the unprivileged process, has no real filesystem or command execution behind it, and has its own fuzz tests in CI.

### Decoy content

- **Honey files** (`passwords.xlsx`, `backup.sql`, `id_rsa_old`). Opening one alerts: fanotify on Linux, file auditing (4663) on Windows.
- **Honey web paths** in each webroot, plus unguessable paths mentioned only in breadcrumbs.

### Exposure

- **Inside the LAN:** a connection from one of our own servers to a decoy means that server is compromised. This is more useful on a flat LAN, where nothing else watches east-west.
- **Outside, through the Palo:** decoys on public addresses get found by external probing. Their source IPs are tagged as red team, which feeds traffic labeling. The Kali's own address is exempt.
- **Noise:** traffic generators can send suspicious traffic from random IPs, so bare connections are info-level, and blocking stays one click.

## Prebaked implant hunting

Every team starts from identical images of known OS versions. We build clean reference VMs of the same versions in the lab, record their known-good state, and diff each live host against it in the first 15 minutes. **The hunt then repeats every 10 minutes, and after every restore, re-enrollment or reset**, because prebaked items are not changes and a restored host can be re-infected [COV §6.10, TTP X-2]. The diff runs as Go-native collection actions, without trusting host tools.

### Reference builds

One scripted build per OS version announced (Packer templates in the lab repo), with the same roles the competition hosts run. Each build records:

| Artifact | Linux | Windows |
| --- | --- | --- |
| File inventory with hashes (feeds the ledger) | `/usr`, `/bin`, `/sbin`, `/lib*`, `/etc`, `/opt` | `System32`, `SysWOW64`, `drivers`, `Program Files` |
| Ownership and signing | Which package owns each file | Authenticode signer for every executable |
| Autostarts | Enabled units and timers, generators, cron, at, rc, profile.d, motd, udev, PAM, NSS, loader config | Services, scheduled tasks (XML), Run keys, WMI subscriptions, LSA packages, IFEO, Appendix C |
| Accounts | passwd, group, sudoers | Local users and groups |
| Kernel | Modules, sysctls, BPF programs, file capabilities, SUID set | Drivers with signers |
| Service config | Distro defaults for Apache or httpd, PHP, Postfix, Dovecot, MySQL | Clean IIS, DNS, SQL Server and Splunk-on-Windows config where relevant |

References ship as signed release assets in the cache's first tier.

### Live hunt

The hunt is a read-only plan that runs on every host in parallel with credential rotation. Target: results in the UI by T+15 min.

1. **Collect** the same artifacts natively.
2. **Diff** against the reference: added, modified and missing items.
3. **Enrich** each finding with hash, signer, owner, package, ledger verdict, file times (watching for timestomping), and what references it.
4. **Score:**
   - **High:** an unsigned or non-vendor binary referenced by any autostart; an unowned file in a system directory; a modified packaged binary (ledger `mismatch`); `/etc/ld.so.preload` content; a new PAM or NSS module; IFEO debuggers; LSA packages; a non-stock IIS module; `ServerLevelPluginDll` on the DNS service; a service unit with `LD_PRELOAD` or unneeded ambient capabilities.
   - **Medium:** added cron, timer or task with a script action; new SUID file or file capability; added SSH key; `chattr +i` on a unit, sudoers file or webroot file; PHP `disable_functions` or `auto_prepend_file` differences; modified default config.
   - **Low:** everything else that differs.
5. **Review** in the UI as a queue. Approved items become a remediation plan that disables and quarantines (moves, with metadata) but never deletes. `chattr -i` is applied explicitly and logged before a remove.

### Remote-access agent kill list

A signed, editable list of management agents that are hunted and tier-0 disabled unless the manifest allows them: Teleport, Webmin, MeshCentral agent, AWS SSM agent, TeamViewer, Tailscale, ngrok, cloudflared, chisel, frp [WT §9.1]. The manifest's "approved management agents" exception covers Wazuh and Splunk.

### Package verification without host tools

- **Debian and Ubuntu:** the agent reads the per-package checksum lists under `/var/lib/dpkg/info/` and hashes files itself. This is a hint; the ledger's vendor-package truth is the proof.
- **Rocky:** the RPM database is SQLite, which the agent reads with its own library.
- Package holds (`apt-mark hold`, `versionlock`) on PAM, ssh, sudo and libc are flagged.

### Application references

| Component | Reference | Check |
| --- | --- | --- |
| OpenCart (if present on Rocky) | Vendor archive for the detected version | Hash every webroot file. Unknown scripts and modified core files (`framework.php`-style backdoors) go to the top. Extra `oc_user` rows. |
| Apache or httpd, PHP | Package defaults | Modules directory and `extension_dir` against the package; `disable_functions`; `auto_prepend_file`; unit `Environment=LD_PRELOAD` |
| Postfix | Package defaults and ledger | `master.cf` pipe transports and content filters; `/etc/aliases` pipes; the binaries |
| Dovecot | Package defaults | Post-login scripts, global sieve scripts, passdb and userdb pointing at scripts |
| MySQL | Package defaults | User-defined functions, plugin directory, accounts with FILE or SUPER, `mysql.user` diff |
| SQL Server (MSSQL) | Clean install | `xp_cmdshell` state, `sa`, sysadmins, linked servers, Agent jobs, the account used by the 1433 check |
| IIS, DNS, SMB | Reference config | Modules, handlers, ISAPI filters; DNS forwarders and `ServerLevelPluginDll`; share list and the SOP directory ACLs |
| Splunk | Splunk's own file manifest | Files differing from it; non-stock apps; scripted inputs; deployment-server settings |

### Active Directory

There's no clean reference for a domain the competition built, so the DC's agent runs generic checks **every 10 minutes**, not only at T+15:

- members of every privileged group, including nested membership (a group inside Enterprise Admins), objects in unusual OUs and `CN=Builtin`, and `whenCreated` compared with the drop flag
- SPNs on user accounts; unconstrained, constrained and resource-based delegation
- `msDS-KeyCredentialLink` and SID history
- non-default access-control entries on AdminSDHolder and the domain object, especially replication rights
- every GPO with its links, modification time, contents (tasks, scripts, registry preferences) and SYSVOL writes
- `krbtgt` password age, machine account quota, DnsAdmins membership, `FullSecureChannelProtection`, the build number

Event-driven detection covers the same ground between runs (5136, 5137, 4670, 4741, 4742, 4929) [COV T-6].

### The firewall-killer

Red teams often plant something that disables host firewalls on a timer. The hunt should find its trigger. If it doesn't, D10 catches the execution and records the lineage. Three restores of the same object in 10 minutes open an incident and a targeted hunt.

### Other hunts

- **`hunt.pii`:** a scan for personal data in files and databases, for scenarios that involve PII and for the exposure statement in IRs [WT §9.6].
- **Credential files:** names such as `*passlist*`, `*.kdbx`, `id_rsa*`, `.env`, `unattend.xml`, with reads logged.
- **Post-hardening adversarial verification:** after a hardening plan, a probe from the Kali and the controller proves that the default and old passwords fail, the new key works, a canary port is closed and scored checks pass [WT §9.2].

### Keeping the baseline current

Accepted findings and inject changes go into overrides as the host's live baseline. Later hunts diff against reference plus overrides. Each host also keeps an **expected-state baseline** (systemd units, kernel modules, services, listeners, scheduled tasks) from the manifest and the first clean sweep, so drift is a diff against known state.

## Network devices and credentials

Network devices are managed agentlessly by adapters inside `phylax`, reached directly (the Palo's management is on the LAN) or through the device-proxy role. Credentials are generated at competition time, held in the controller's vault, and rotated by plans in dependency order. Scored accounts are changed only as PCR transactions.

### Device adapters

The adapter exposes primitives and the controller owns the safe-change protocol, so the same runner works for every device [DA §4]:

```go
type Adapter interface {
    Kind() Kind; Caps() Caps; Close() error
    Info(ctx) (Info, error)               // liveness, version, clock, licence
    Probe(ctx) error                      // fresh connection + auth + one read (the lockout canary)
    RotateAdmin(ctx, RotateSpec) (Creds, error)
    Snapshot(ctx, label) (Snapshot, error); Diff(ctx, a, b) (Diff, error)
    Drift(ctx, lastGood Snapshot) (DriftReport, error)   // emits device_config events
    Begin(ctx, TxOptions) (Tx, error)     // Preflight, Lock, Stage, Pending, Validate, Commit, Confirm, Rollback, Close
    Admins(ctx) (AdminState, error); Events(ctx, EventFilter) ([]Event, Cursor, error)
    Capture(ctx, CaptureSpec) (Capture, error)
}
```

Capability flags say what is native: config lock, scoped commit, validate, native confirm, soft dead-man, rollback, connection events. A lockout-risk transaction on a device with no way to revert is refused until the Network role acknowledges that the console is ready.

**Palo Alto (PAN-OS 11.0.2).** Our own thin XML-API client (about 300 lines: form POST, `encoding/xml`, `X-PAN-KEY`, pinned TLS, context deadlines), because the maintained SDK lacks lock, commit and operational helpers and its tags cannot be fetched. Typed rule CRUD may use the SDK behind our interface [DA §1.15]. Every rule and object we create carries a `phylax-managed` tag; the adapter edits only tagged items. The safe-change protocol [DA §1.12]:

1. Preflight: system info, jobs idle, config and commit locks free, no foreign pending changes, running-config hash equals last known-good.
2. Take the config lock; snapshot the running config and the prior XML of each touched path.
3. Stage the change (tagged); check that pending changes contain only our paths.
4. Validate (a full validation job) and refuse on failure.
5. Commit with an admin-scoped partial commit; poll to completion.
6. Health: `test security-policy-match` for each scored flow, scorer-mimic probes from the Kali and the LAN, a fresh-connection API call.
7. On pass: new last-known-good, a named saved copy, release the lock. On fail: granular revert and a second commit; if the management path is lost, alert and use the console.

PAN-OS has no commit-confirm, so management-path edits (permitted IPs, management profiles, services, the API account) are their own commit, additive first (add the new permitted entry, commit, verify with a brand-new connection, then remove the old), and never combined with service rules. Palo management lockdown to the controller's address is first-hour mitigation #2 for the unpatched 11.0.2 [SV R2.4]. The adapter reads the licence once and disables actions that need a missing subscription. Drift polls (system info 10 s, jobs 15 s, logs 30 s, running-config hash every 5 min) feed D14 [DA §1.13].

**VyOS (1.4).** SSH with the Go SSH client for lockout-class changes, HTTP reads for state. VyOS's `commit-confirm` **reboots the router** into the saved config, and the HTTP API commits immediately and cannot roll back [DA §0]. So the protocol arms its own soft revert [DA §2.4]:

1. Preflight: latest commit equals last known, `compare` empty.
2. Save the running config to an archive file (not `/config/config.boot`).
3. Arm a `systemd-run` timer (90 s default, run through `sg vyattacfg`) that loads the snapshot and commits.
4. Apply with a plain commit.
5. Health from a new connection: scorer-mimic probes, interfaces and routes.
6. On pass: stop the timer, `save`, record the new last-known-good. On fail: run the revert and alert.

The config is not saved until the health check passes, so a surprise reboot returns to the previous boot config. Lockout classes: `service ssh`, `service https`, `system login`, management-path interfaces, NAT and policy on the path to the controller, the default route. Off-box `commit-archive` records every commit. Whether `commit-confirm action reload` exists on the installed 1.4.0 image is a lab check; if it does, native confirm replaces the timer.

**Cisco FTD (FDM).** Not in the 2027 environment. Built only if an infra includes it: pending changes are global, there is no per-admin deploy and no REST rollback, and connection events come by syslog [DA §3]. Until then it falls back to console, a printed checklist and hand-taken snapshots.

**Reaching devices.** The Palo's management is on the LAN. VyOS (`172.16.0.254`) is reached through the Palo with a rule from the controller. Device management access lists allow only the controller (or a device-proxy host).

**First contact** with devices stays manual: change the admin password on the console in the first minutes, then the adapter takes over with new credentials and a dedicated API account.

### Credentials

**Inventory.** Every account in `accounts.yml`, plus whatever discovery finds: local accounts on every host, domain accounts, and service and app accounts (MySQL, OpenCart admin, Splunk, SQL Server, the Palo and VyOS). Each has a `scored` flag (declared, or learned from the scorer), a credlist, a rotation policy, and the files and services that embed it.

**Generation.**

- Passphrases of four or more words plus digits for unscored human accounts, easy to type on a console.
- **For scored accounts,** 16 to 24 characters from `[A-Za-z0-9._+=-]`. That avoids `@ : /` (which break the MySQL DSN builder), shell metacharacters (custom checks pass the password through a shell), and the quote-stripping edge cases of the PCR page [Q §9.1].
- **Stateless break-glass credentials** for unscored accounts are derived (HMAC of the passphrase, host, account and epoch), so a lost controller can regenerate them from a printed secret. Scored accounts stay under PCR. [WT §9.10]
- Held in the vault, in memory once unlocked. Never in the repo, never in logs, masked in the UI until revealed.

**Rotation order:**

1. **T+0 to 5, by hand on consoles:** the Palo and VyOS admin accounts.
2. **T+2 to 10, first-contact plans with the dead-man switch:** root and administrator on every host and the domain administrator, then our own admin accounts. `sysadmin` is rotated only after the PCR list is checked (below).
3. **T+10 to 30:** unscored service and app accounts. Each rotation updates the files that embed the credential in the same plan, then runs the scorer-mimic probe.
4. **Scored accounts:** only as PCR transactions.

**Zerologon ordering.** On the DC, the plan first reads the build, `FullSecureChannelProtection` and Netlogon events. If the secure channel is not enforced, enforce or patch it, or filter RPC to the DC, *before* any domain password rotation, because a vulnerable DC lets the attacker reset the machine account and dump the new hashes anyway. Server 2022 is expected to ship the fix [SV R2.4].

**krbtgt.** A double reset invalidates forged tickets. With a single DC there's no replication delay, but every Kerberos ticket dies. Test in the lab whether AD-backed IMAP and POP3 survive it, and run it right after a scorer round passes.

### PCR as a transaction

A scored account is a record {host password(s), Quotient password, last observed scorer login, state}. The state machine [Q §5, Q §9.1]:

| State | Meaning | Next |
| --- | --- | --- |
| `stable` | Host and Quotient agree, last scorer login passed | `planned` |
| `planned` | New password generated (rules above); waiting for the quiet window | `applying` |
| `applying` | In the window `[burst end + safety, next start − safety]` the host change runs on every host where the user exists, and the PCR CSV (one block per credlist **path**, never the display name) is shown to the operator | `pending` |
| `pending` | The human has pasted the CSV; the operator confirms the portal's reply (`count` equals the number of lines, `skipped` empty) | `verifying` |
| `verifying` | The Kali logs in with the new credential through the public path (V4 on failure), then the account waits for a **passing scorer login by that user** in the next bursts (a random credential per check means it can take several rounds: expect about `k ln k` rounds to see all `k` users) | `confirmed` |
| `confirmed` | Recorded; the account leaves "pending" | `stable` |
| `failed` | Next burst shows a failed login for that user | Roll back: resubmit the old value through PCR and revert the host |

Rules:

- **Both changes must land before the next enqueue.** The burst is over within seconds; the usable window is at least `Delay − Jitter − burst length` (about 50 s at upstream defaults). The order of the two changes does not matter, but a gap costs one failed round for that user's draws, not for the whole service. Never submit a PCR during an enqueue pass: credential reads are not atomic.
- **Never use "Reset to Defaults".** It rewrites every user in the credlist to the known defaults. Rollback is a PCR with the old value.
- **The CSV generator** emits `username,password` lines with no leading or trailing spaces, a comma on every line (a line with no comma stores an empty password), no password that starts and ends with a quote, case-exact usernames, and one block per credlist path. It reads back `count` and `skipped` and refuses to continue on a mismatch.
- **The PCR step stays human** (a portal login), unless the organizers approve scripting it; the `pcr.submit` action is off until then.
- **A host change without a PCR, or the reverse, is a bug.** The lint rejects any plan that changes a scored account on the host alone.
- **`sysadmin`:** protected until the PCR list (or `GET /api/credlists`) shows whether it is a scored user. If it is, it rotates by transaction; if not, it rotates freely.
- **After rotation,** any successful admin authentication from a source other than the controller is a D9 alert, because no legitimate actor has those credentials.

## OSS alongside Phylax

D-9: OSS tooling next to Phylax is allowed. The v2 design removed Wazuh, Velociraptor and Ansible to save complexity. v3 keeps Velociraptor and Ansible out (they duplicate the controller) but allows optional sensors where they are cheaper than building. The principle: **Phylax owns orchestration, integrity, chains and checks; OSS tools are optional sensors whose health Phylax monitors. Nothing on the critical path depends on them.** Evidence: [OA, IJ, SV R2.3.6, PRO §10].

| Tool | Role | Where | How Phylax uses it |
| --- | --- | --- | --- |
| **Wazuh** | Secondary detection (FIM, rootcheck, SCA), central dashboard, and the evidence for endpoint-protection and central-logging injects | Manager on the Ubuntu workstation if it has the RAM, otherwise the Debian Splunk host under a cgroup cap; agents on every host | `wazuh.deploy` and `wazuh.health` plans; alerts imported as low-priority context; screenshots and agent lists for injects |
| **Sysmon** | Windows telemetry (the main Windows sensor) | Windows hosts | Installed and kept alive by the agent, renamed (D-8) |
| **Suricata and Zeek** | Protocol logs and signatures over pulled pcaps | The controller | Offline analysis of frozen slices; output joined by Community ID. Not live: the flat LAN has no tap |
| **Sigma** | Detection logic | Build time | The importer in § Detection |
| **YARA-X** | Scheduled memory and file scans with a C2 corpus | Every host (`scan`) | Pre-approved, pinned, low priority |
| **Splunk** | The environment's SIEM (also scored) | Debian Splunk host | Phylax alerts and Palo logs forwarded over HEC into a dedicated index; optional scheduled searches from the Sigma importer |
| **ClamAV** | Windows anti-malware for the endpoint-protection inject | Windows hosts | `av.clamav` plan with hourly and on-access scanning |

### Wazuh deploy plan

The injects recur: "Configure End-Point Protection Software" (SVRA12T in 2026 quals, where we deployed a Wazuh manager and agents; SOFT04A in the 2026 regional; 6 events across 4 seasons) and central logging (SOCS30T, TOOL29T; 16 events in 9 seasons). So the inject kit includes a `wazuh.deploy` plan, deployed early so it is ready when the inject lands and adds detection the whole time [IJ, PRO §10].

| Decision | Setting |
| --- | --- |
| Version | Pinned: **manager and agents 4.14.9 or newer**, agent not newer than the manager. The 4.7 and 4.14.3 URLs in older playbooks are vulnerable (CVE-2025-24016 and the 2026 `authd` and API bugs). If no fixed version can be cached, skip Wazuh rather than run 4.7 [SV R2.3.6] |
| Packages | The offline bundle (manager, indexer, dashboard, agent MSI/deb/rpm) is in the cache before the event; nothing is downloaded at install time (D-5) |
| Manager placement | A trusted Linux host that is not scored. Default: the Ubuntu workstation if the lab shows at least 8 GB RAM headroom; otherwise the Debian Splunk host with a memory cap (the scored Splunk Web must not starve). Measured in the lab |
| Exposure | Ports 1514, 1515, 55000 and 443 allowed only from our hosts. `authd` uses a password and is stopped after enrollment. The dashboard and API credentials are rotated and held in the vault |
| Manager risk | Whoever owns the manager owns every agent through pushed config (SCA and command policies), so the manager's host is a tier-0 asset. Remote commands are disabled on agents; **Wazuh active response is disabled**, because response is Phylax's and typed |
| Agent groups | FIM, rootcheck and SCA groups pre-configured; log collection for the services' logs; syscollector on |
| Health | `wazuh.health` polls the API read-only: agents connected, last keepalive, manager CPU and memory. A disconnected agent or a dead manager is a platform alert, since the red team may kill it |
| Evidence pack | The agent list export, a generated test alert, the group configuration and dashboard screenshots (taken by a human) saved into the inject kit for the PDF response |
| Order | Deploy after credentials and firewalls (T+45 to 90 in the event timeline) |
| Uninstall | A plan removes it if it misbehaves |

Wazuh rules are GPL-2.0: Phylax reads Wazuh alerts but does not copy its rule text.

### Splunk forwarding

`splunk.hec_setup` creates a HEC token and a dedicated `phylax` index on the Splunk host. It touches no index the scored query searches (the Splunk check reads specific data [SH §11]). The controller forwards alerts, incidents, firewall and Palo logs and the chain timeline as JSON. It's optional, off the critical path, and a good source of "central logging" evidence for injects. The Sigma importer can emit scheduled searches for the same host, with `enableSched` set (UIUC's converted searches never ran on a schedule [DR §4]).

### Suricata and Zeek

When an alert freezes the ring, the pulled pcap can be analysed offline on the controller. Suricata (ET Open rules, cached) produces alerts and `eve.json` with Community IDs; Zeek produces protocol logs. The results attach to the incident and the trace-back. Neither runs live.

## Offline-first: caches and depots

D-5: every host should have internet, but it's slow. Phylax treats the internet as an optimisation and builds everything it needs into caches before the event, so no decision waits on a download. This is also the safe course for rules that change from event to event (the proxy and repo rules this year are unclear [PKT §4.4]).

### What is cached, in tiers

Sizes are estimates to be measured in M0. A tier must be complete before the features that need it start.

| Tier | Contents | Approx size | Needed by |
| --- | --- | --- | --- |
| 0: in the release | `phylax` binaries, rules (hand-written and Sigma-derived), YARA C2 corpus, Sysmon config, decoy pools, inject-kit templates, ATT&CK dataset, ledger indexes (path to hash, compressed) for the announced OS versions, the cache index | tens of MB | Everything at `init` |
| 1: fetched at init, small and critical | Sysmon (fetched from Microsoft; not redistributable), YARA-X binaries, Typst, Winbindex extract for Server 2019, 2022 and Windows 11, the Wazuh offline bundle and agent installers, Suricata rules, the nmap/xfreerdp pins for the Kali | hundreds of MB | Telemetry, ledger on Windows, OSS deploys |
| 1b: release asset | The tool depot (signed manifest + static tools, § Trusted tool depot); Windows Sysinternals fetched at init | tens of MB | Operator response, `phylax depot` |
| 2: background, large | The depot: distro packages for the service stacks (httpd, php, postfix, dovecot, openssh, sudo, polkit and their dependency closure) per OS, the exact vendor package versions for ledger proofs, security-relevant OS updates, optionally Windows cumulative updates | GB | Patch windows, restores, ledger vendor proofs |

### How caches are built and refreshed

- **Build.** `phylax cache build` runs in CI on a schedule and on release. It produces a content-addressed set of blobs (sha256, size, source URL, licence, tier), an index signed by the release key, and a changelog. Ledger indexes are rebuilt from the lab images, Winbindex and the distro mirrors. Weekly builds; a final rebuild the day before the event.
- **Publish.** Signed release assets on GitHub (primary), `dist/` in the repo (fallback), vendor mirrors directly (last).
- **Sync.** `phylax cache sync` runs on the controller from T+0, resumable and chunked, bandwidth-capped so it doesn't starve the first-contact traffic, in tier order, verifying every hash. The Platform page shows each tier's progress. Features that need an incomplete tier show "waiting for cache" instead of failing.
- **Cache-through.** Any in-event fetch (a patch window miss, an unknown package version) goes through the controller, is logged, and is stored for later. A fetch that fails degrades the feature (a ledger verdict becomes `unknown`), never the platform.
- **Refresh at the event.** Only the index delta is fetched at the event: new blobs since the last build, in tier order. If the internet is too slow, the previous complete set is already enough.
- **Offline drill.** A lab test runs the whole cold start with the internet blocked (T40).

**Complexity flag:** the cache is a content-addressed store with a signed index, a CI build job and a sync client. It is bounded by tiers, by reusing the release signing path, and by the rule that no feature requires a live fetch.

### Trusted tool depot

Operators and Phylax must not trust host tools during a response: the red team replaces binaries (Postfix, `dns.exe`, `nologin`, `dash`). The depot is DePaul's offline depot of known-good static tools [PRO §2, patterns idea 4], signed with the same release key as the ledger (`integrity.Signer`).

- **Signed manifest.** Name, version, OS/arch, sha256, size, source URL, licence, build recipe and applet names. Content-addressed store; tools deploy to a hidden per-event directory (D-8, derived from the event secret) with mode 0700/0500.
- **Linux:** static musl builds from reproducible recipes (`depot/recipes`, not run in CI): busybox, coreutils, procps-ng, iproute2, lsof, net-tools, tcpdump, strace, curl, socat, OpenSSH client, file, findutils, grep, tar, gzip, xz; nmap optional. GPL tools ship with the pinned source reference. **Windows:** our own Go tools plus Sysinternals fetched from Microsoft at `phylax init` (no redistribution; pinned hash, as for Sysmon).
- **Use.** `phylax depot run|shell` re-hashes the tool before every use and executes the hashed bytes from a sealed memfd, with a rebuilt environment (PATH = depot only, no `LD_*`). `phylax depot verify|list`. `phylax tools ps|ss|ls|hash|lsof` are Go-native fallbacks reading `/proc` and netlink when not even a static binary can be copied in.
- **Network.** Only the controller fetches (cache path, tier 1 for vendor downloads); agents get tools from the controller. Details: `docs/depot.md`.
- **Limits.** Defeats replaced binaries and poisoned environments, not a kernel rootkit. The static binaries need a lab build (T-depot): build, fill source hashes, pack and sign, run `depot verify`/`run` on each target OS image.

## Controller

The controller is one Go process. It keeps everything in one SQLite database, a directory of encrypted evidence files and the cache. Secrets live in an encrypted vault and are held in memory only after the passphrase is entered. The web UI is server-rendered, on its own `127.0.0.1` listener, with one login. A platform-health view makes sure a degraded platform is never mistaken for a quiet network.

### Processes and ports

| Process | Listens on | Role |
| --- | --- | --- |
| `phylax serve` | `agent_port` on the controller's address (agents, relays, splices, patch streams, bootstrap downloads); `127.0.0.1:8443` for the UI | Everything, including the active checks and the cache |

### Storage

- **SQLite** in WAL mode, pure Go, one file, with indexes on the hot queries. Events, incidents, plans, flows, transactions, hops and ledger verdicts go here, plus full-text search over transcripts and command lines. Event inserts are batched in transactions.
- **Evidence directory:** pcap slices, collected files, memory dumps, sinkhole captures. Each file is encrypted at rest with `age` and referenced from the database by hash.
- **Cache directory:** the content-addressed depot (§ Offline-first).
- **Retention:** indefinite for the event. The UI shows free disk and warns at 70% and 85%. The first lever is compressing raw transaction bodies older than a day.

### Secrets

- **The vault** is one `age`-encrypted file: device and host credentials, generated passwords, honeytoken values, the controller's private keys, the plan-signing key and portal cookies.
- **Unlocking:** the passphrase is entered in the UI after every start. Decrypted values exist only in memory.
- **Credentials seen in traffic** are encrypted field by field before storage and masked until revealed. Parsers mark credential fields. **Complexity flag:** kept because the alternative is a plaintext database full of passwords on the box everyone wants.

### Data model

| Record | Identity |
| --- | --- |
| Host | Manifest name + enrolled key |
| Service | Manifest name (portal names are `<box>-<display>`) |
| Process | Host + PID + start time (+ Sysmon GUID alias) |
| Connection | Host + 5-tuple + start time, and Community ID |
| File | Host + path, with a hash history |
| Ledger entry | OS + version + path + sha256 + source |
| Account | Scope + name; credlist; scored flag; PCR state |
| Source | IP address, with labels (scorer, red, us, other) and fingerprints |
| Scorer round | Burst time, services seen, credentials seen, estimated Delay and Jitter |
| Change | The changed record + before and after |
| Alert | Rule + host + key records |
| Hop, Chain, Campaign | Hop = kind, endpoints, link method and confidence; chain = ordered hops; campaign = merged chains |
| Remediation item | Hop + action + state |
| Incident | A set of alerts, changes and a campaign with a timeline |

Correlation joins on these identities, never on loose text matching.

### Web UI

- **Built with** Go `html/template` plus htmx, live updates over Server-Sent Events. All assets are vendored and embedded; no CDN, no Node at runtime. Plan DAGs and chain timelines are laid out in Go and rendered as server-side SVG.
- **Access:** its own listener, `127.0.0.1` only. One login (argon2id), HttpOnly SameSite=Strict cookie, CSRF tokens, strict CSP.

| Page | Shows |
| --- | --- |
| Overview | Hosts, services, open incidents, the round clock and SLA streaks, scorer status, safe-mode switch |
| Plans | Templates, the plan DAG with live node status, diffs, lint results, approvals |
| Alerts and incidents | Queue, evidence, trace-back, one-click actions, IR draft button |
| Chains | Campaigns, chain timelines, remediation checklist per hop |
| Checks | Active checks (add, edit, pause, retire), scorer checks observed, proposals, change feed, vantage-point comparison |
| Credentials | Scored accounts, PCR transactions and their state, the CSV generator |
| Services | Health from each vantage point, content history, changes |
| Integrity | Ledger verdicts, the unknown/mismatch queue, pins, depot status |
| Traffic | Flows and transactions with labels; packet slices; freeze and pull |
| Egress and C2 | Denied attempts by binary and destination; sinkhole captures |
| Vantage | Kali probes, external scan diffs, canary results |
| Deception | Decoy hits, honeytoken registry and sightings |
| Hunts | Baseline-diff findings queue |
| Devices | Palo and VyOS snapshots, diffs, logs |
| Integrations | Wazuh, Suricata, Splunk health and evidence packs |
| Cache | Tier progress, pending blobs |
| Platform | Self-health |
| Settings | Manifest overrides, adoption queue, secrets unlock |

### Platform self-health

For each agent: link state and lag, spool depth and congestion state, capture drop counts, audit and sensor health, `telemetry_gap` counts, clock offset, which modules run or failed, safe mode. For each relay: connections spliced, bytes and errors. For the controller: CPU, memory, disk, database size, cache progress and the time of the last state snapshot. For each integration: connected agents and keepalive. Anything degraded shows on the overview page.

### Backing up the controller

Encrypted state snapshots go to the backup targets declared in the manifest every 15 minutes and after every key or vault change. Restore needs only the passphrase and starts a new epoch (§ Enrollment).

## Service backups, IR drafter and inject kit

Service data is backed up by agent actions and pulled to the controller, so restores never depend on a compromised host's own copy. Incidents become IR drafts with one click, and inject deliverables come from templates and manifest-generated facts. Both render to PDF. With no per-VM scrub, backups are the only undo for a big mistake.

### Service backups

| Kind | When | Use |
| --- | --- | --- |
| As-found | T+5–10 min, before any remediation | Forensic evidence. Never restored blindly; it may contain implants. |
| Golden | Right after each service's hardening passes its health checks and the host's ledger sweep and hunt are clean | The restore point for that service |
| Periodic | Every 30 min for changing data (database, mail, uploads, AD, Splunk apps) | Keeps restores from losing orders and mail |
| Pre-change | Before any tier-2 action, and before the Palo and VyOS changes | Undo for big changes |

- **What's included** comes from each service's `content`, `data` and config entries in the manifest, plus the AD database (via a native export), SQL databases, the SMB SOP share and the Splunk apps.
- **Native where possible:** archives and file copies in Go, MySQL and SQL Server dumps through their drivers. **Complexity flag:** native dumps reimplement part of `mysqldump`; test them against a real restore before trusting them.
- **Restores** are plan templates per service with measured times. The restore re-checks the scored content (SOP files, web pages, DNS answers) against the learned values, because the scorer compares them.

### IR drafter

**Input:** an incident, which already holds its trace-back timeline, chains and campaign, alerts, sources, accounts, files, hashes, evidence and the response audit trail.

| Section | Filled from |
| --- | --- |
| Header: team number only, incident id, times in Central time | Manifest, incident |
| Summary | Recipe template sentence, edited by hand |
| Timeline | Chain hops with clock offsets applied, Central time with UTC alongside |
| Source and destination | Addresses, ports and protocols from flows and transactions; hostnames from the manifest |
| Accounts and credentials | Accounts used or created; credentials stolen or cracked (D8, honeytoken sightings); what was rotated after |
| Affected systems and services | Hosts and services, and whether scoring was affected (health and scorer history) |
| Technique | ATT&CK ids from the rules, in plain words |
| Evidence | Hashes, ledger verdicts, log excerpts, packet excerpts, quarantined files |
| Attack path and remediation | The chain's remediation items, with their verified state, and the proof the hole is closed |
| Containment | The response audit trail |

This maps onto the red-team lead's rubric: proof, time of compromise, how it was detected, what the attack was and its impact, how it was mitigated, and (half the marks) remediation of the attack path [TTP §0]. Rendering: Markdown with front matter through Typst (one static binary on the controller) to PDF and self-contained HTML. One to two pages, exploitation and unsolicited access only, every claim traced to evidence. The upload path (NISE at `injects.ccdc.events`) is tested at the first event, with the Nextcloud share and a browser print as fallbacks.

### Inject kit

- **Templates** (Typst, team number only): memo, status report, change record; policies (acceptable use, passwords and accounts, backup and recovery, logging and monitoring, patching, remote access, incident response); plans (disaster recovery, business continuity, incident response); risk register; framework mappings (NIST CSF 2.0, 800-53, 800-171, 800-82 for the water-facility theme, ISO 27001, CIS v8, CMMC).
- **Pre-written drafts** with placeholders filled from the manifest at render time.
- **Generated artifacts:** asset inventory, network and data-flow diagram, port and protocol matrix, user and group listing, firewall policy summary, backup schedule with restore times, logging coverage matrix.
- **Integration evidence packs:** the Wazuh pack (agent list, test alert, group config, screenshots), ClamAV settings, Splunk dashboards and the external scan report (from the Kali), for the recurring endpoint-protection, central-logging and perimeter-scan injects.
- **Inject tracker** in the UI: received and due times (Central), owner, deliverable, linked manifest change, status, submitted time. Submit several minutes early; last-minute rejections are common [SP §8].

**Complexity flag:** Typst is a host binary on the controller. Acceptable because the controller is the trusted host; it isn't shipped to any agent.

## Competition-day operations

The first hour is choreographed: fixed roles, pre-built plans, and one UI showing what's running, blocked and red. The 2027 Invitational is a four-hour sitting, so cold-start speed matters. The localhost-only UI means the controller console is the team's shared screen. That's the biggest operational constraint in this design.

### The one-screen constraint

The web UI is only reachable on ubuntu-wkst itself. Whoever can see that VM's console can drive the platform; everyone else works on other consoles by hand. If NETLAB lets several people view the same VM console, the whole team watches one screen. If not, one person (the platform driver) owns the UI. **Complexity flag in reverse:** keeping it localhost is the simple choice, and the cost is human bandwidth. If dry runs show the driver becoming the bottleneck, the smallest change is an SSH tunnel from one other workstation to the UI port, with the login still required. Decide after the dry runs.

### Roles

| Role | Owns |
| --- | --- |
| Captain | Inject triage, White Team communication, tier-2 approvals |
| Platform driver | The UI on ubuntu-wkst: plans, approvals, safe mode, re-enrollment |
| Network | Palo and VyOS consoles in the first minutes, the Kali path rules, then device plans and drift |
| Linux lead | Linux console work and break-glass; reviews Linux hunt findings |
| Windows and AD lead | Windows console work and break-glass (including the Windows 11 and Kali one-liners); reviews Windows, AD and ledger findings |
| Credentials and PCR | The Quotient portal: pastes each PCR block, reports `count` and `skipped`; works with the driver on transaction windows |
| SOC | Alert queue, chains and incidents with the driver; IR drafts |
| Inject writer | Inject drafts and generated artifacts, including the Wazuh evidence pack |
| Floater | Health checks, backups and restores, decoy hits, whatever is red |

### First 90 minutes (from drop flag)

| Time | Who | What |
| --- | --- | --- |
| T+0–2 | Captain | Read the inject portal. Confirm the team number in the manifest. Ask Quotient for the PCR credlist usernames if approved. |
| T+0–8 | Network | Rotate Palo and VyOS admin on the consoles. Palo: additive management lockdown to the controller; the Kali-to-controller rule and static NAT. VyOS: snapshot first. |
| T+0–5 | Platform driver | `phylax init`: fetch and verify the release, set the passphrase, check the controller address, start the UI. The cache sync starts. |
| T+2–12 | Platform driver | First-contact plans: SSH for Linux, WinRM for the AD and MSSQL hosts. The Windows lead runs the Windows 11 and Kali console one-liners. Agents enroll. |
| T+5–10 | Automatic | As-found backups; capture, round-clock estimation and check discovery start; source-address check against the Palo; ledger sweep and prebake hunt start on each enrolled host |
| T+5–15 | SOC + leads | Review the hunt and ledger queues. Zerologon check on the DC (build, registry, events) before any domain rotation. |
| T+10–25 | Platform driver + Credentials | Rotate unscored accounts. Then scored accounts as PCR transactions inside the quiet windows, one service at a time. |
| T+10–25 | Platform driver + Network | Firewall plans: shadow mode, review would-be drops, enforce, with scorer-mimic checks. Palo policy with the Kali verifying. |
| T+15–40 | Platform driver | Service hardening plans from the first-hour library (Splunk Postgres sidecar off, local-root bundle, Cockpit off, Spooler off, MSSQL and OpenCart items), with probes. Golden backups as each passes. |
| T+20–45 | SOC | Approve hunt remediations. Confirm Sysmon and all modules on every host. |
| T+30–60 | Floater | Decoys and honeytokens deployed, including honey AD accounts. |
| T+45–90 | Driver + inject writer | Wazuh deploy and evidence pack. Review discovered checks: accept, edit or reject. |
| Ongoing | All | Incidents, chains, injects, patch windows, periodic backups, drift adoption, PCR transactions for any later credential change |

### Day 2 start (regional)

Check the Platform page for every agent's link, gaps and modules. Review overnight changes and chains. Device drift check. Re-run health checks. Confirm the controller snapshot is fresh.

### Human factors

- A printed one-page checklist per role, generated from the manifest, including the PCR rules.
- A verbal callout before any tier-2 action, before turning safe mode on or off, and before each PCR submit.
- The captain keeps the list of open incidents and injects due in the next 30 minutes.
- Rotate the SOC seat every 90 minutes.

## Testing and the lab

With AI-assisted development, writing code is rarely the bottleneck. Proving it under realistic conditions is. Every capability is demonstrated in the replica lab, with injected link drops, against a real Quotient scorer and a scripted red team, before it goes on the competition checklist. Each milestone spends at least as long in the lab as in the editor.

### The lab (ccdc27)

The lab is the 2027-style replica built in `btap-infra` (branch `ccdc27-lab`, stack `ccdc27`), at team number 1 [LAB]. The 2026 replica stays stopped while it runs, because both share bridges.

| VMID | Name | Role in the Phylax tests |
| --- | --- | --- |
| 6001 | vyos | VyOS 1.4.x: soft-revert tests, NAT, the Kali leg |
| 6002 | palo | PA-VM 11.0.2: safe-change protocol, partial commit, logs, licence behaviour |
| 6010 | rocky-ecom | Rocky 9 with SELinux enforcing, OpenCart |
| 6015 | ubuntu-email | Postfix, Dovecot, webmail |
| 6020 | debian-splunk | Splunk 10.0.2 |
| 6030 | ubuntu-wkst | The Phylax controller |
| 6040 | kali | The external vantage and the attack operator host |
| 6050 | scorer | Ubuntu with **real Quotient** in Docker on the core segment (ground truth) |
| 6100 | ad | Server 2022 AD/DNS/WinRM |
| 6120 | mssql | Server 2019 with SQL Server, the SOP share, RDP |
| 6130 | win11 | Windows 11 workstation |

Every VM has a `clean-baseline` snapshot taken after provisioning and before every test. Clocks are synchronised from one NTP source before a run. Phase 3 (services per the packet) and phase 4 (realism: documented prebakes and a Quotient config with the packet's checks) of the lab plan are prerequisites of M2 and M4 [LAB].

### Simulators

| Simulator | Does | Notes |
| --- | --- | --- |
| **Scorer: real Quotient** | Runs the packet's checks with the MW reconstruction, the MSSQL and Splunk stand-in scripts, `BadAttempts`, PCR, hot-reloaded `event.conf`, SLA arithmetic; admin API gives ground truth (`/api/engine/tasks`, round times, true source addresses) | Delay 60/Jitter 10/Timeout 30 for realism, 20/5/10 for fast iteration [Q §8]. Divisor is not run (it needs host networking and privileges); source rotation is simulated with several runner addresses |
| Fault injector | Kills a runner to produce a discarded round; pauses a service to force timeouts; changes a stored item | For SLA and dropped-round tests |
| Orange team | Browses and buys on ecom, sends and reads mail, from many source addresses | Reuses Quotient-like clients; kept for regionals |
| Red team: purple-team runbooks | The five campaigns (default creds, Zerologon check and DCSync, lateral movement, lunch disruption, re-infection after restore), run by a human operator from the Kali with Atomic Red Team, impacket, netexec, evil-winrm | Technique mapping: [EMU]. Techniques with no public emulation use the contaminator and fixtures |
| Contaminator | Plants prebaked implants in golden images before drop flag | The set below |

**Prebaked set.**

- **Linux:** cron, timers and a firewall-disabling timer; `update-motd`; PAM backdoor module; `ld.so.preload`; PHP `auto_prepend_file`; Postfix pipe transport; alternate-path `authorized_keys`; SUID shell; LKM and eBPF rootkit samples (lab only). Added by the coverage spec [COV §5]: a replaced Postfix `smtpd` proxying to a second lab host; an apache or httpd unit with `Environment=LD_PRELOAD` and `AmbientCapabilities`; a PHP extension that overrides `disable_functions`; `chattr +i` on a unit and a sudoers.d file; a bind mount over a webroot directory; `apt-mark hold libpam-modules`; a `.screenrc` hook; a `PROMPT_COMMAND` callback; `nologin` replaced by a bash copy; a promiscuous NIC; NTP and DNS TXT covert-channel traffic; a self-propagating SSH key installer; a defanged cron wiper; a backdoor inside an existing core file (`framework.php` style); an extra `oc_user` row.
- **Windows:** firewall-disabling scheduled task; service in a writable path; WMI subscription; IFEO debugger; LSA package; IIS native module; Run key; hidden admin; `dns.exe` replaced with a forwarding stub and command listener; FTP root pointing at an SMB share; `LSASS` to `ISASS.EXE`; a hijacked `\Microsoft\Windows\Windows Error Reporting` task; a Mythic-style unsigned SYSTEM service; WSL and Chocolatey launch; OpenSSH server and VNC listener.
- **AD:** extra Domain Admin and a nested fake group inside Enterprise Admins; SPN on a user; RBCD; GPO immediate task; DCSync ACE; `ServerLevelPluginDll`; a Defender exclusion; audit policy off. Zerologon itself needs an isolated, unpatched lab DC (a lab-build decision); on the Server 2022 AD only the check-only tester runs [RT].
- **Network:** VyOS task-scheduler script; an extra Palo admin; a Palo allow rule above a block rule; a custom admin role.

### Test matrix

T01–T27 are carried over and revised. T28 onward are new.

| ID | Scenario | Pass when |
| --- | --- | --- |
| T01 | Prebaked set present at drop flag | 90% or more found by T+15 min; ledger sweep finds every replaced binary |
| T02 | Timer disables the host firewall | Restored in 10 s or less; trigger identified via loop detection |
| T03 | PHP webshell upload, command, file change | D1 and D17 fire in 10 s or less; trace-back reaches the source IP and request; IR draft in 5 min or less |
| T04 | ASPX webshell on IIS (stand-in host) | Same as T03 |
| T05 | Implant callbacks under default-deny egress (Linux) | D12 in 10 s or less; owning process and hash in 60 s or less; sinkhole captures the beacon |
| T06 | Implant callbacks on Windows | D12 with process and path from 5157 in 60 s or less |
| T07 | DCSync from a non-DC account (campaign 02) | D8 in 30 s or less |
| T08 | Kerberoasting incl. the honey SPN | D8 and D15 (critical) in 30 s or less |
| T09 | Honey SSH key used against the SSH decoy | D15 critical, naming the origin host |
| T10 | LSASS dump, then the decoy credential used | D15 critical, naming the origin host |
| T11 | Log clear and Sysmon stopped (campaign 03) | D10; Sysmon reinstalled; heartbeat intact |
| T12 | LD_PRELOAD rootkit hiding a process | D11 in 120 s or less |
| T13 | Palo rule added by an extra admin | D14 in 5 min or less |
| T14 | Quotient `event.conf` hot-adds an HTTP path, a DNS record and a custom check mid-run | D16 and a check proposal within one round |
| T15 | Check discovery accuracy over 2 hours with orange traffic | 100% of Quotient's checks proposed; 0 false proposals; dropped checks flagged stale within 5 rounds; item set coverage grows |
| T16 | A hardening plan breaks a scored page, an SSH `PermitTTY`, or a mail plaintext setting | The lint rejects it; if forced, the scorer-mimic probe is red in 60 s or less and the node rolls back |
| T17 | Link drops during an SSH-reconfigure and firewall-enforce plan; a Palo or controller-host change that cuts agents off | Agent-side dead-man rolls back with no reconnect; no lockout; no lost node |
| T18 | Controller restart mid-plan | No lost or duplicated events; plan resumes after unlock |
| T19 | New reservation: bulk re-enrollment (campaign 05) | All hosts back to hardened in 10 min or less per host; hunt and ledger automatic; golden tag withheld until clean |
| T20 | Quotient plus orange traffic for 60 min, no red steps | 5 or fewer false-positive alerts per hour |
| T21 | First contact; agent then killed and disabled (Linux and Windows) | Heartbeat in 30 s or less; silence detected in 15 s or less |
| T22 | Relay host killed (multi-segment variant) | Segment marked dark; local detection continues; console restore works |
| T23 | Controller lost mid-plan; restore on another machine from an older snapshot | Agents reconnect after `set-controller`; no re-enrollment; new epoch accepted; spools resent and chain-checked; gaps marked |
| T24 | Defender on, current definitions | Agent, decoys and the LSASS decoy run without quarantine (or with the single exclusion) |
| T25 | Crafted strings in process names, paths, HTTP paths and decoy-shell input | Nothing executes or renders as markup in the UI |
| T26 | Windows raw-socket capture under load | Measured inbound and outbound coverage; drop counts reported |
| T27 | Console bootstrap on Windows 10 or 11, Server 2019 and Linux (SChannel with an ECDSA cert) | Agent enrolls; a wrong controller key aborts before the token is sent; a tampered binary is never run |
| T28 | Auth: every UI and agent-port endpoint without a session, token or pinned key | All refused; token minting only from the UI; the agent port serves only agent streams and bootstrap downloads |
| T29 | Spool torture: kill -9 at random during writes, disk full, shedding, 10-minute and 6-hour partitions | Starts every time; tail repaired; gaps marked; chain verifies; RSS bounded |
| T30 | Round clock: 20 bursts with jitter, a discarded round, a team-wide missing burst | Delay and Jitter within 1 s; the dropped round is not an incident |
| T31 | Integrity: replaced Postfix (`smtpd` proxy), trojaned `nologin`, `LD_PRELOAD` library, replaced `dns.exe` stand-in, an unknown hash executed | Alert at first exec in 5 s or less; pinned service image mismatch in 60 s or less; D4b fires for the proxy; no automatic restore; one-click restore from the depot passes the probe |
| T32 | Integrity false positives: package update inside a patch window, an untagged update, a patch-level difference | Tagged window yields no alert; untagged update yields `match_other_version` or an alert with clear provenance |
| T33 | Attack chains (campaigns 01 and 03) | 100% of expected hops present, each with a link method and confidence; a two-hop SSH chain stitched by 5-tuple; one campaign per attacker; remediation checklist items verify |
| T34 | Hardening against real Quotient: the first-hour plan library (SSH, mail, WinRM, SMB, RDP, Splunk, DNS) | 0 failed scorer rounds attributable to Phylax |
| T35 | PCR transaction: normal, PCR mid-enqueue, wrong order, mismatched CSV, password with edge characters | At most one failed round per affected user; verification via Kali and the scorer's next login; rollback never uses "Reset to Defaults" |
| T36 | Phylax hardening with no red steps | 0 untagged alerts |
| T37 | `BadAttempts` and scorer fingerprints (SSH HASSH, HTTP headers, SMTP subject shape) | No brute-force or lockout alert; scorer-labeled by behaviour with the runner address changed each round |
| T38 | Zerologon, hidden accounts, `chattr +i`, unit capabilities, PHP overrides, OpenCart admin rows, AD GPO and ACL changes | Each raises its D8b, D7e, D6f, D6d, D2c, D2d, D8d alert |
| T39 | Kali vantage: faithful checks against Quotient's results; a Palo rule that blocks the public path but not the LAN; a newly opened port; an egress leak | Agreement at 98% or more; V1 localizes the fault; V2 and V3 fire |
| T40 | Offline drill: cold start with the internet blocked, cache from a prior sync | All plans, ledger lookups, restores and Wazuh deploy work; missing tiers shown as waiting |
| T41 | Wazuh deploy to all hosts, kill the manager, kill an agent | Deployed in 20 min or less; `wazuh.health` alerts; evidence pack produced; no scored service degraded |
| T42 | Sigma import: allow-list through CI | Every imported rule has a fixture and a licence record; revoked ATT&CK ids rejected |
| T43 | Exec-storm load test (50, 200, 1000 execs per second) | 99% or more at 200 per second, and every miss accompanied by a `telemetry_gap`; decides the eBPF sensor |
| T44 | Safe-change protocols on the Palo and VyOS | Failed health rolls back; foreign pending changes block the node; the soft-revert timer fires when the connection is lost |
| T45 | Race detector | `go test -race ./...` clean in CI |

### CI

- **Static builds** for both OSes with `CGO_ENABLED=0`, a size check, signed artifacts. `GOOS=windows go build` is a required job.
- **`go test -race`** on every package; a privileged job runs `nft -c`, AF_PACKET, systemd D-Bus and SELinux-enforcing container tests.
- **Unit tests** for every action (check, apply, verify, rollback) against Rocky, Ubuntu and Debian containers, and Windows runners.
- **Parser and normalizer tests** from recorded captures, including the Quotient pcaps from the lab; fuzzing for every parser and the fake shell.
- **Rule tests:** every rule has inline fixtures; ATT&CK ids validated against the pinned v19 dataset; Sigma imports regenerate deterministically.
- **Manifest tests:** schema, cycles, the firewall lint, rendering of every output, and a lint that every plan template passes the scoring-safety rules.
- **UI tests** for escaping (T25) and for the authentication surface (T28).
- **Cache build** job and an offline-sync smoke test.

### Cadence

- Weekly purple-team session on one campaign; the runbook's metrics table (time to detect, attribute, respond; chain completeness; detection rate; false positives against the scorer and against our own hardening) is filled in after each run [RT].
- A 24-hour soak test per release on the full lab.
- A monthly full dry run with all simulators and fault injection.
- Two full timed dry runs in the final three weeks before each major event, in competition roles.

## Build plan

One developer (David), building the whole design. There is no cut list: every capability here is in a milestone. What the plan controls is **order**, so that whatever date arrives, the highest-value gates have passed first. Each milestone ends when its gate tests pass in the lab, under fault injection. Week 1 starts the Monday after approval of this design.

### Effort

The code review put the remaining work for the old scope at about 115–150 developer-days even with 22.8k lines already written [CR §8]. This is a rewrite, plus Windows from day one (20–25 D), the Quotient model (15 D), the ledger (10–12 D), chains (6–8 D), the Kali vantage (5 D), integrations (8–10 D), the cache (5 D), and a larger rule and test corpus (25–30 D). The estimate is **about 230–290 developer-days**, or about 30 weeks at the integrated-and-lab-proven rate of about 4 to 5 days per week. It is an estimate, not a commitment: the largest uncertainties are Windows COM and capture, and PAN-OS behaviour on the licensed lab VM.

### Calendar anchors

| Date | Event | What it means for the plan |
| --- | --- | --- |
| Sat Nov 7, 2026 | Invitational (4 hours) | Weeks 2–3 at most. Phylax is not expected to run it; use the date to measure Quotient's real config and fingerprints (Delay, Jitter, SLA threshold, banners, user lists) and to rehearse the hand playbooks |
| Jan–Feb 2027 | Qualifier | Gates M0–M5 (about week 12 to 14) |
| Mar 2027 | Regional | Gates M0–M8 (about week 20 to 22) |
| Spring 2027 | Nationals | All gates and two timed dry runs |

If a gate is not ready for an event, the hand playbooks and the parts of Phylax that have passed their gates are used. That is a scheduling fact, not a reduction of scope.

### Sequencing

Order follows dependency and risk:

1. **Everything rides on the link, security core and execution,** so they come first: M1 and M2.
2. **Windows is built with them, not after.** Three of the five servers are Windows, including the DC. Every milestone has Windows work and Windows gate tests.
3. **Unknowns are retired early.** Early lab experiments settle the largest risks: Windows capture coverage (T26), SChannel bootstrap with an ECDSA cert (T27), Defender's reaction (T24), the licensed PAN-OS VM's data plane (T44), and the exec-storm result that decides the optional eBPF sensor (T43).
4. **The scorer model precedes credentials and hardening.** The round clock, fingerprints and the scorer-mimic probes (M5 part 1) are needed by PCR transactions and by the hardening gate. Therefore M3 uses real Quotient in the lab from the start and the probe library is built alongside.
5. **Detection precedes the ledger's alerts and chains,** because they consume the same events: M4 then M6.
6. **Features that need organizer answers** (portal polling, scripting PCR, the Kali's scope) are built behind switches, defaulting to the safe behaviour, so an answer later changes a setting.
7. **The lab and the rule corpus grow in parallel,** one purple-team campaign per milestone.

### Milestones and gates

| Milestone | Weeks | Delivers | Gate |
| --- | --- | --- | --- |
| M0 Foundations and lab | 1–2 | Repo layout, written protocol spec, manifest schema and the 2027 reference manifest, CI skeleton (cross-builds, `-race`, privileged job), ccdc27 lab phases 1–3 usable, real Quotient with the MW reconstruction, Palo and VyOS lab devices, cache build skeleton, measurements: Quotient fingerprints from the lab pcaps | Lab reproduces the 2027 topology; manifest renders a valid firewall policy (`nft -c`) and the Palo and VyOS rules; Quotient runs the packet's checks |
| M1 Link, security core and enrollment | 3–6 | Agent link with ECDSA pinning; UI listener with login and CSRF; segment-file spool; bounded queues and deadlines; enrollment (idempotent), SSH, WinRM and console first contact, including **Windows service install and SChannel bootstrap**; relay splicing; signed config; platform health; `phylax doctor` | T18, T21 (Linux and Windows), T27, T28, T29, T45, T26 measured |
| M2 Execution | 5–9 | Action catalog (Linux and Windows core), plans, dry-run diff, DAG in the UI, scoring-safety lint, agent-side dead-man with OS timers, mandatory complete signatures with replay protection, locks, safe mode, `fw.apply` for nftables and Windows Firewall, atomic account actions, tag propagation | T16 (lint and rollback), T17, T18; cold-start hardening of the ccdc27 servers in 25 min or less |
| M3 Devices, credentials, PCR | 8–11 | Palo adapter (own XML client, safe-change protocol), VyOS adapter (soft revert), credential vault and generation, rotation order, **PCR transaction** engine and CSV generator, Zerologon-first DC plan, first-hour mitigation plan library | T34, T35, T44; first-hour list runs on ccdc27 without a failed Quotient round |
| M4 Telemetry and detection | 9–14 | Audit, proc connector, `sock_diag`, audit watches, hash sweep, `inventory`; Sysmon and `EvtSubscribe`, 4688 fallback; rule engine with all required operators; tier-0 and tier-1 responses; denied-egress logging; reference builds; the hunt plan (10-minute repeat); rule corpus waves 1–2 (classes A, A*, B) | T01, T02, T07, T11, T12, T13, T36, T43 |
| M5 Capture, scorer model and checks | 11–16 | Packet ring (Linux, Windows), flows with Community ID, phase 1–2 parsers, the round-clock estimator, fingerprint table, active checks and scorer-mimic probes, discovery with union learning, SLA tracking, traffic labels, change detection, trace-back, portal verdict channel | T03, T04, T14, T15, T20, T30, T37 |
| M6 Integrity ledger, chains, Kali vantage | 15–20 | Ledger builder and truth sources, exec-time hashing, library checks, pinning, depot, scheduled YARA; hop model, stitching, campaigns, timeline view, remediation items; Kali agent roles, faithful checks, PCR verification, scans, canaries; rule corpus wave 3 (classes C: Windows producers, AD, device, controller correlation) | T31, T32, T33, T38, T39 |
| M7 Deception, C2, caches, integrations and reporting | 18–24 | Decoys with the fake shell, honeytokens, sinkhole, patch windows with cache-through, the full cache pipeline, service backups, IR drafter with chains, inject kit, Wazuh deploy and evidence pack, Splunk HEC, Suricata and Zeek offline, Sigma importer | T05, T06, T08, T09, T10, T24, T25, T40, T41, T42 |
| M8 Recovery, hardening of Phylax itself, UI completeness | 22–26 | Controller snapshot and restore with epochs, resend verification, self-protection (watchdog, immutable bit, audit immutability), obscurity (randomised names), resource budgets with dual enforcement, all UI pages, remaining actions | T22, T23, T19; footprint targets measured |
| M9 Dry runs and freeze | 26–30 | Two full timed dry runs in competition roles, soak test, the five purple-team campaigns with the metrics table filled in, fixes, release freeze, the controller-loss drill | All success metrics measured; all T-tests pass |

Milestones overlap on purpose (M2 and M1, M3 and M2). One developer does one thing at a time, so overlap means the lab, the next milestone's design and the previous milestone's soak run while code is written. After M9, the work continues per event: measuring the real scorer config, updating the manifest and caches, and adding rules from new debriefs.

### Beyond the first full pass

eBPF exec sensor (only if T43 says audit is not enough), Palo-side capture automation, file carving, a Cisco FTD adapter when an infra includes one, and any ETW work are triggered by evidence rather than scheduled. They are not cut; they are conditional on the lab saying they are needed.

## Complexity register

Every place this design adds complexity is listed here, with why it earns its place and what keeps it bounded. The second table lists what we deliberately didn't build. Any new feature that adds a listener, a daemon, a host-binary dependency in a default path, runtime discovery, or a new kind of state has to be added here before it's built.

### Accepted complexity

| Item | Why it's worth it | How it's bounded | Section |
| --- | --- | --- | --- |
| Relay role | Segments the controller can't reach need a path | Dumb splice, no state, no keys; declared statically; unused on the 2027 LAN | Topology |
| Device-proxy and bootstrap splicing | Devices and first contact in other segments | Same splice code as the relay; allowlist | Topology, Enrollment |
| Five connection types on one port | One listener and one firewall rule | Small handler per type, selected by ALPN; the UI is on a separate localhost listener | Wire protocol |
| Kali inbound path (one port, one source, static NAT) | The only way for an outside vantage point to report | One Palo rule, pinned keys, advisory verdicts | The Kali |
| Scored credentials on the Kali | Quotient-faithful checks and PCR verification need them | Memory only, per-probe delivery, rotation if suspected | The Kali |
| Patch-window caching proxy | Hosts patch without any outbound rule, on a slow internet | Loopback only; time-boxed; allowlist; cache-first | Egress |
| Content-addressed cache with a signed index | Offline-first operation | Tiers; reuses the release signing path; no live-fetch dependency | Offline-first |
| Go-native Windows actions through COM and WMI | Avoids trusting host binaries | Largest test effort; `host.exec` fallback per action, recorded here | The agent |
| Windows agent from day one | Three of five servers and the DC are Windows | CI cross-build gate; Windows gate tests per milestone | The agent |
| Reading the Linux audit subsystem directly, with the connector as a cross-check | Atomic exec records; no auditd binary to trust | Multicast reader beside auditd; health check; load test | The agent |
| Optional eBPF exec sensor | Only if audit proves insufficient | Gated by T43; same schema; audit fallback | The agent |
| Separate decoy process | Decoys face attackers | Same binary, unprivileged | The agent |
| Full fake shell | Records what the red team actually does | No real filesystem or execution; fuzz-tested | Deception |
| LSASS decoy session | One of the few ways to know LSASS was dumped | Recreated if killed | Deception |
| Packet capture with TCP reassembly and parsers | Discovery, trace-back, chains, IR evidence | Bounded ring; drops before slowing hosts; parsers isolated and phased | Service monitoring |
| Windows raw-socket capture | Capture without a driver | Lab-proven first; logs as fallback | Service monitoring |
| Scorer recognition heuristics and round-clock estimator | The point of the feature | Every proposal needs a click; acceptance tests against real Quotient | Active checks |
| Scorer-mimic probes using Quotient's client libraries | Scoring-safe verification | Same libraries as the scorer; strict in content | Active checks |
| Binary integrity ledger | Replaced binaries are prebaked and invisible to FIM | Alert only; truth sources off-host; verdict classes; behavioural corroboration | Ledger |
| YARA-X as a host binary in a default path | Full YARA semantics for the C2 corpus | Pinned hash, low priority, cgroup cap | Ledger |
| Local depot | Restores without the internet | Signed assets and a cache tier | Ledger, Offline-first |
| Attack chains and campaigns | IR remediation marks; cross-host visibility | Rows and linking rules, no graph engine; per-hop confidence | Attack chains |
| Cross-host stitching | The only east-west visibility on the flat LAN | Exact tuple first; clock offsets; NAT-aware join | Attack chains |
| Trace-back request linking | Turns a change into a source IP | Falls back to time-window correlation, lower confidence | Trace-back |
| Sinkhole | Learns what implants would say | Linux only; record-only; capped | Egress |
| Sigma importer | Borrows Windows detection logic cheaply | Build-time only; allow-list; fixtures; licence records | Detection |
| Wazuh manager and agents | Recurring injects; extra detection | Pinned fixed version; optional; active response off; manager is a tier-0 asset; health-checked | OSS alongside |
| Suricata and Zeek over pulled pcaps | Protocol logs and signatures | Offline only; optional | OSS alongside |
| Obscurity measures | Raise the cost of scripted kill lists | Names and paths only; no mutated binaries; not a boundary | Trust model |
| PCR transaction state machine | Two-system credential changes must not fail the scorer | One state record per account; human submit; rollback by PCR | Credentials |
| Field-level encryption of captured credentials | No plaintext passwords on the controller's disk | Parsers mark credential fields | Controller |
| Native database dumps | Avoids host tools on a possibly compromised host | Restore-tested before trusted | Backups |
| Defender exclusion | The agent may be flagged | Exactly one path | The agent |
| Typst on the controller | Good PDFs with little code | Controller only | IR and injects |
| One binary for agent and controller | One artifact per OS; no version skew | Size measured and compressed in transit; agent-only build tag if needed | Architecture |

### Refused or deferred

| Not built | Why | What we do instead |
| --- | --- | --- |
| Dynamic relays, election, failover, backup relays | Moving parts | Static relays in the manifest; console restore |
| Automatic controller address updates | The address is stable in practice | `phylax set-controller` and a Palo NAT edit |
| Agent self-update system | Rarely needed | One `agent.replace_binary` action |
| Multi-user UI, roles, remote UI access | Competition use only | One localhost login; an SSH tunnel if dry runs demand it |
| Stream multiplexing | A protocol inside the protocol | One TLS connection per stream |
| Protobuf | Code generation and opaque debugging | Length-prefixed JSON with zstd |
| Certificate authority, PKI, cert expiry | Clock dependency | Pinned keys |
| Velociraptor, Ansible, a second SIEM | Duplicate the controller | The agent, controller and adapters; Splunk as an output |
| Automatic restore from the integrity ledger | D-1: alert only | One-click tier 1 |
| A general graph or provenance engine | D-2: keep it lightweight | Hops, rules and a timeline |
| Running Sigma on agents | Memory and CPU; mostly unfit rules | Build-time import |
| Kernel drivers; custom eBPF as a foundation | Large risk surface | Audit, Sysmon; eBPF only if T43 requires |
| In-house ETW consumer | cgo or GPL libraries; Sysmon covers it | Sysmon plus event logs |
| Containerization of services | Rules forbid moving; effort | Harden in place |
| Link-direction flipping for no-outbound segments | No known infra needs it | Documented limitation |
| A JavaScript graph library | Weakens the CSP | DAG and timelines as server-side SVG |
| Scorer reverse-engineering beyond discovery | More heuristics and state | Discover and mirror current checks |
| Scripting the Quotient portal without approval | Rules and risk | A human pastes the CSV |
| Wazuh active response | Script execution with server-chosen arguments | Typed Phylax responses |

### Watch list: things that would quietly break simplicity

- Any second listener on the controller (the UI listener is the only one beyond `agent_port`), or any listener on a host that isn't a declared decoy, relay or Kali-path port.
- `host.exec` creeping into default plans. Every default-plan use belongs in this register.
- Rules or parsers that need state shared across hosts at the agent. Cross-host logic belongs on the controller.
- Configuration that can be changed on hosts without going through the manifest.
- A new feature that needs a live internet fetch at the event.
- New features justified by "might be useful" rather than by a test in the matrix.
- Anything that makes the integrity ledger act without a human.

## Risks and open questions

The largest risks are the single developer's schedule against a full scope, the unknown Quotient configuration, the controller as the single root of trust, rulings we haven't confirmed (workstation use, the Kali, decoys on public addresses), and the volume of Windows work.

### Risks

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Full scope against one developer's calendar | High | High | Dependency-first sequencing; every gate usable on its own; hand playbooks as the fallback for any event before a gate; no scope change without the owner |
| Controller compromised | Low | Critical | Separate authenticated UI listener, one inbound agent port, SSH off, secrets in memory, separate signing key |
| Controller lost | Medium | High | Encrypted snapshots every 15 min; drill T23 |
| Quotient's real config differs from the reconstruction (Delay, SLA, custom scripts, Divisor, debug) | High | Medium | All model parameters are estimated at the event; defaults at low confidence; switches for portal polling |
| Our scorer-mimic probes diverge from the real checks | Medium | High | Same client libraries; lab ground truth; calibrate against the portal; union plus faithful modes |
| A hardening plan breaks a scored check | Medium | High | The lint, the probe before and after, rollback, the golden restore |
| PCR race fails a user for several rounds | Medium | Medium | Quiet-window rule; Kali verification; rollback by PCR; protect `sysadmin` until known |
| The Kali is out of bounds, in the red team's reach, or may not run our agent | Medium | Medium | Ask early; the in-LAN runners and passive logic work without it; memory-only credentials |
| Controller DHCP address changes, breaking the Palo NAT target for the Kali | Medium | Medium | Request a reservation; `set-controller`; manual NAT edit; Kali features degrade only |
| Go-native Windows work (COM, WMI, raw sockets, EvtSubscribe) takes longer than planned | High | Medium | `host.exec` fallback per action; capture falls back to logs; Windows gates in every milestone |
| SChannel cannot complete the PowerShell bootstrap | Medium | High | ECDSA P-256 everywhere; T27 early in M1 |
| Defender flags the agent | Medium | High | Lab test per release; one scoped exclusion; randomised path |
| Palo rewrites source addresses on inbound NAT | Medium | High | Detected at drop flag; sources recovered from the Palo's traffic logs |
| The PAN-OS lab VM is unlicensed and behaves differently from the event's | Medium | High | Test on the lab VM early; adapter reads the licence and disables actions needing subscriptions |
| Integrity ledger false positives from patch drift | Medium | Medium | Truth sources off-host; `match_other_version`; window tags; accept-hash queue |
| Chain mislinks present guesses as facts | Medium | Medium | Per-hop confidence and link method; exact-tuple first |
| Cache incomplete or stale at the event | Medium | Medium | Tiered sync, offline drill T40, features show "waiting" |
| Wazuh manager exposure or resource starvation | Medium | Medium | Pinned fixed version, host choice by measurement, active response off, kill-and-skip option |
| Obscurity breaks our own detections or hunts | Low | Low | Controller knows the per-event names; detections key on path and hash |
| Red team reads the repo and tunes around detections | High | Medium | Behavioural and allowlist detections; per-event values generated at the event |
| Telemetry loss hides an attack | Medium | High | `telemetry_gap` events, health block, cross-source tripwires, load test T43 |
| Four-hour window: the platform driver becomes the bottleneck | Medium | Medium | Dry runs; pre-built plans; SSH tunnel as the documented next step |
| No PAN-OS or Windows licences in the lab for some variants | Medium | Medium | Evaluation licences requested in M0 |

### Questions for competition officials (ask before the season)

1. May the controller run on a user workstation (the Ubuntu one), with one inbound agent port?
2. May the Kali run our agent, our checks and our scans of our own public addresses? Is it in the red team's scope?
3. Is a DHCP reservation, or keeping the current lease, acceptable for the controller's address?
4. Is a static NAT and a Palo rule from the Kali to the controller acceptable?
5. May a Quotient-authenticated, read-only poll of the team's own pages run once per round? Is scripting the PCR endpoint allowed?
6. What are Quotient's Delay, Jitter, Timeout, SLA threshold and Divisor settings, and is `ShowDebugToBlueTeam` on? (Measure at the Invitational if not told.)
7. Which accounts are scored (the PCR list), and is `sysadmin` among them?
8. Are decoy services on our public addresses acceptable (fake SSH and others on non-scored ports)?
9. Can several team members view the same VM console at once?
10. Is the inject portal (or Nextcloud) reachable from inside the competition VMs, for PDF upload?
11. What does "access to the Internet, monitored" allow and how fast is it? Is there still a proxy and a repo rule at quals?
12. Are Wazuh, Suricata, ClamAV and YARA acceptable as free and open-source tools in the environment?
13. Which host serves the FTP and HTTPS checks, if scored?

### Internal questions to settle in the lab

- Windows raw-socket capture coverage, inbound and outbound, under load (T26).
- Whether the Palo preserves source addresses on inbound NAT, and what the VyOS leg does to the Kali's address.
- Socket-to-process linking speed for quick webshell requests.
- Whether AD-backed IMAP and POP3 survive a krbtgt double reset.
- Defender's reaction to the agent, decoys and the LSASS decoy session.
- RAM and disk headroom on ubuntu-wkst for the controller, the cache and a Wazuh manager.
- Whether `commit-confirm action reload` exists on VyOS 1.4.0.
- What an unlicensed PA-VM does on the data plane.
- Whether the YARA-X scanner can take process memory streams.
- Whether the SQL Server and Splunk custom scripts resemble our stand-ins once seen.
- How SMB NTLM with no domain behaves against a Windows member server (the Quotient research only observed Samba).

## Appendices

### A. Windows event reference

Verify every ID on the target builds in M4. Firewall operational-log IDs in particular differ between Server 2019 and Windows 11.

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

The declared competition repo is visible to every team (this year's rule is unclear), so the lab and red-team material live in a separate private repo.

```text
phylax/                        # declared competition repo
  cmd/phylax/                  # the one binary: serve, agent, init, doctor, cache, rules, ledger
  internal/agent/              # agent mode: module host, supervisor, roles
  internal/link/               # TLS pinning, framing, connection types, bounded queues
  internal/spool/  internal/store/  internal/plan/  internal/actions/
  internal/collect/            # proc, net, fim, logs, capture, egress, crossview, inventory
  internal/integrity/          # ledger client, hashing, pinning, depot
  internal/parsers/            # one package per protocol (incl. smb2, winrm, tds, ssh)
  internal/scorer/             # round-clock estimator, fingerprints, SLA, PCR transaction
  internal/checks/             # active checks, scorer-mimic probes, discovery
  internal/traceback/  internal/chains/  internal/detect/  internal/decoys/
  internal/vantage/            # Kali roles: probes, scans, canaries
  internal/cache/              # content-addressed store, sync client
  internal/integrations/       # wazuh, splunk hec, suricata/zeek, clamav
  internal/devices/palo/  internal/devices/vyos/  internal/devices/ftd/
  internal/ui/                 # templates, SVG DAG and timeline layout, vendored htmx
  manifest/                    # schema + example manifests (2027 reference, two-segment variant)
  plans/                       # plan templates (incl. the first-hour library)
  rules/                       # detection rules (YAML), each with inline tests
  rules/imported/              # Sigma-derived rules + THIRD_PARTY_RULES.md
  yara/                        # C2 corpus
  pools/                       # decoy banners, honey filenames, fake-shell content
  inject-kit/                  # Typst templates and pre-written drafts
  dist/                        # signed binaries, fallback delivery
  docs/

ccdc-lab/                      # private, never declared
  terraform/  packer/  netem/  proxy/
  reference/                   # baseline and ledger builders
  quotient/                    # lab scorer config, stand-in check scripts
  sim/orange/  sim/contaminator/  sim/faults/
  redteam/                     # campaigns, results
```

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
| PCR | Quotient's password change request: CSV `username,password`, effective at the next enqueue |
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

### F. PCR CSV rules

One block per credlist path. Each line `username,password`. No leading or trailing spaces (the portal doesn't trim). A comma on every line. Case-exact usernames. No password that starts and ends with the same quote character (the portal strips them). Passwords 16–24 characters from `[A-Za-z0-9._+=-]`. A duplicated username: the last line wins. Check the reply: `count` equals the line count and `skipped` is empty. Roll back by a PCR with the old value, never "Reset to Defaults". [Q §5]

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

### H. First-hour mitigations as plans

Each is a plan template with a scoring-safe verdict and a probe [SV R2.4, SH].

| Plan | Does | Scoring note |
| --- | --- | --- |
| `dc.zerologon_first` | Build and registry check, enforce or patch the secure channel, Spooler off, SMBv1 off | No NTLM disabling; patch needs a reboot (DNS and WinRM briefly down) |
| `palo.mgmt_lockdown` | Additive permitted-IP restriction to the controller | Management is not scored; verified with a new connection |
| `splunk.sidecar_off` | `[postgres] disabled = true`, change the default admin, list apps and inputs | Keeps 8000 and 8089 open and the scored Splunk user |
| `linux.local_root_bundle` | `chmod 0755 /usr/bin/pkexec`, block `algif_aead`, check `sudo -V`, unprivileged user namespaces if unused | Breaks polkit GUI auth only |
| `rhel.cockpit_off` | Disable Cockpit on Rocky | Not scored |
| `web.opencart` | Remove `install/`, rename the admin directory, rotate the admin password, trim modules | Leaves the storefront content untouched |
| `mail.checks` | Open-relay check, hash Postfix and Dovecot binaries, remove unscored webmail if outdated | Keeps plaintext listeners and AD-backed auth |
| `mssql.baseline` | `@@VERSION`, `xp_cmdshell` off, trim sysadmins, review linked servers and Agent jobs | Leaves the login the 1433 check uses |
| `net.vyos_review` | Snapshot, `show configuration commands`, rotate `vyos` | Soft-revert protocol |
| `ssh.safe` | `LoginGraceTime 20`, `MaxStartups`, `X11Forwarding no` | No password-auth, TTY or `AllowUsers` changes for scored users |

### I. Rule backlog

The 81 proposed rules [PR] group as: credentials and accounts (P01–P05, P14–P16), Zerologon and AD (P06, P62–P64, P68–P69), local-root and exposure (P07–P09), web and database (P10–P11, P39–P42, P44, P48–P49), Linux persistence and evasion (P12–P13, P17–P25, P27–P32, P38), integrity and masquerade (P26, P60–P61), network and covert channels (P33–P35, P45, P73–P74, P79), services and sabotage (P50–P53, P75–P78), Windows persistence (P43, P46–P47, P54–P59), defense evasion (P65–P67), devices (P70–P72), and re-infection and hardware (P80–P81). Each ships when its producer exists and its fixture passes.
