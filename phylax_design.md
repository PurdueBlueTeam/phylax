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
