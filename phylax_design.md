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
