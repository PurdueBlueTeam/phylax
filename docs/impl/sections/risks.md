The largest risks are the unknown Quotient configuration, the controller as the single root of trust, the T+0 console phase being manual and the first thing red attacks, the amount of Windows work, and the unverified paths that files and sound need to leave the controller. The v3 risk about schedule against scope stays, with the v4 change that scope is not cut for time (decision D-6 replaced).

### Risks

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Scope is large and no accepted item is cut for time | High | High | Dependency-first sequencing (module contract and bus first, then retrofit); every gate usable on its own; hand playbooks as the fallback for any event before a gate; a module without evidence starts off; no scope change without the owner |
| Controller compromised | Low | Critical | Separate authenticated UI listener, one inbound agent port, SSH off, secrets in memory, separate signing key |
| Controller lost | Medium | High | Encrypted snapshots every 15 min; drill T23 |
| Quotient's real configuration differs from the reconstruction (Delay, SLA, custom scripts, Divisor, debug, credlist count) | High | Medium | Every model parameter is estimated from capture at the event; defaults held at low confidence; measured at the Invitational (S1 to S9). Quotient is not reachable from inside, so there is no portal poll to fall back on; an optional hand-entered Up/Down note is advisory only |
| Our scorer-mimic probes diverge from the real checks | Medium | High | Same client libraries; lab ground truth through the Quotient admin API (T39); union plus faithful modes; calibrate against the hand-entered Up/Down note and the organizers' post-event check log |
| A hardening plan breaks a scored check | Medium | High | The lint (including never narrowing sources on a scored port), the probe before and after, rollback, the golden restore |
| A scored-password change fails a user for several rounds | Medium | Medium | Quiet-window rule; Kali verification and the scorer's next login; rollback by a typed list of the old values; scored changes happen only on evidence (decision 5) |
| A typo in the typed PCR list at the Quotient machine | Medium | Medium | A short list (credlist, user, password) from `pcr.generate`; the human check on screen; verification by login per credlist; the rollback list is printed with it; the typing time is measured (O8) |
| Red dumps every AD hash and a Phylax breach exposes every rotated password | Medium | High | Prevent the dump (Zerologon first at T+0, the DCSync rule); honey AD accounts; pass-the-hash pack; selective rotation on evidence; rotated scored passwords live in the age vault; policy is open question 1 |
| T+0 console rotation is wrong or late: team-pack admin passwords leak within seconds | High | High | Rehearsed (T48); a printed sheet generated from the manifest; the grid records who did each step; Phylax's first job afterwards is to evict sessions that predate the rotation; Zerologon is done before any domain rotation |
| A host or the AD is reverted and Quotient keeps the new passwords | Medium | High | Revert detection and a per-credlist re-sync that blocks further scored changes on that host until resolved (T51) |
| The Kali is in the red team's reach or cannot run our agent | Medium | Medium | In-LAN runners and passive logic work without it; its credentials are memory-only; its verdicts are treated as external-view evidence only |
| Controller DHCP address changes, breaking the Palo NAT target for the Kali | Medium | Medium | Hold or request a reservation; `set-controller`; manual NAT edit; Kali features degrade only |
| Go-native Windows work (COM, WMI, `EvtSubscribe`) takes longer than planned | High | Medium | `host.exec` fallback per action, each recorded in the complexity register; Windows gates in the lab matrix |
| SChannel cannot complete the PowerShell bootstrap | Medium | High | ECDSA P-256 everywhere; T27 early |
| Defender flags the agent | Medium | High | Lab test per release (T24); one scoped exclusion; randomised path |
| The Palo rewrites source addresses on inbound NAT | Medium | High | Detected at the first look (Invitational S3); sources recovered from the Palo's traffic logs; traffic labels work by behaviour, never address |
| The PAN-OS lab VM is unlicensed and behaves differently from the event's | Medium | High | Test on the lab VM early (T44); the adapter reads the licence and disables actions that need subscriptions |
| Integrity ledger false positives from patch drift | Medium | Medium | Truth sources off-host; `match_other_version`; window tags; accept-hash queue; first-sweep unknowns go to the hunt's triage queue, not to alerts |
| Chain mislinks present guesses as facts | Medium | Medium | Per-hop confidence and link method; exact-tuple first; guessed hops labelled in the IR |
| Cache incomplete or stale at the event | Medium | Medium | One signed index with a priority field; offline drill T40; features show "waiting" |
| Wazuh manager exposure or resource starvation | Medium | Medium | Pinned fixed version, host choice by measurement, active response off, kill-and-skip option |
| Obscurity breaks our own detections or hunts | Low | Low | The controller knows the per-event names; detections key on path and hash |
| Red team reads the repo and tunes around detections | High | Medium | Behavioural and allowlist detections; per-event values generated at the event; lab payloads and campaign runbooks kept in the private repo |
| Telemetry loss hides an attack | Medium | High | `telemetry_gap` events, the health block, cross-source tripwires, load test T43 |
| The platform driver becomes the bottleneck on the one controller screen | Medium | Medium | Dry runs; pre-built plans; the role-merge map; `phylax say` and `claim`; the `notify` alarm and webhook; the "since you left" digest. No SSH tunnel (A11.Q1) |
| Files and sound cannot leave the controller: Nextcloud not writable from inside, no audio in NETLAB | Medium | Medium | The on-screen views are the primary artifact and screenshot from the console; files stay on controller disk and are carried out later; the visual alarm and banner work without sound; both paths are checked at the Invitational |
| A claimed work window hides attacker activity | Low | Medium | Windows are short, visible on the Overview and in the audit log, and bound to change-class exemptions only as far as the rules allow (the `teamfeed` section) |
| The content guard fights an inject that changes the same content, or loops | Low | Medium | Off by default per service; plan-tagged changes exempt; a second restore within 10 minutes stops and alerts (T52) |
| A restore loses data (a per-user penalty) | Low | High | Counts before and after; the loss gate needs a named approval; a pre-change set is taken first (T53) |
| Razing: the host does not boot after a deleted boot file | Medium | High | Fresh `boot` sets before lunch and before day 2; the boot-critical watchlist; console recovery rehearsed (T55) |
| A module breaks the contract during the retrofit and drags the platform | Medium | Medium | Modules show as "pre-contract" until retrofitted; the conformance suite and the sibling-import check are required in CI (T46) |
| Per-module CPU and memory are self-reported and may be wrong | Medium | Low | The whole process is capped by the OS (systemd, Job Object); T71 compares the report with measurement |
| No PAN-OS or Windows licences in the lab for some variants | Medium | Medium | Evaluation licences requested early |
| Containerised scored services in 2027 behave differently from the Docker variant | Medium | Medium | The `runtime` field and the variant host (T63); the stack is unverified until a packet shows it |

### Questions to settle in the lab

The open lab questions from v3, minus those that depended on cut items (the Windows raw-socket capture question went with that capture). Each says what answers it.

| Question | Answered by |
| --- | --- |
| Does the Palo preserve source addresses on inbound NAT, and what does the VyOS leg do to the Kali's address? | Lab, and Invitational S3 |
| Is socket-to-process linking fast enough for quick webshell requests? | T03 |
| Do AD-backed IMAP and POP3 survive a krbtgt double reset? | Lab (campaign 05 variant) |
| What does Defender do to the agent, the decoys and the LSASS decoy session? | T24, Invitational O4 |
| How much RAM and disk headroom does `ubuntu-wkst` have for the controller, the cache and a Wazuh manager? | Invitational E14, lab sizing |
| Does `commit-confirm action reload` exist on VyOS 1.4.0? | T44 |
| What does an unlicensed PA-VM do on the data plane? | T44 |
| Can the YARA-X scanner take process memory streams? | Lab, the `integrity` module's memory-scan test |
| Do the SQL Server and Splunk custom scripts resemble our stand-ins once seen? | Invitational S4 |
| How does SMB NTLM with no domain behave against a Windows member server? (The Quotient research only observed Samba.) | Invitational S6 |
| Do first-bytes fingerprints discriminate the common C2 frameworks, so that the sinkhole stays? | T60 |
| Does the NETLAB console carry audio, and can several people view one console? | Invitational O2 |
| Is the team Nextcloud writable from inside, and how fast? | Invitational export test (collector C6) |
| Do per-module self-reported CPU and memory match what the OS measures? | T71 |

### Open questions
