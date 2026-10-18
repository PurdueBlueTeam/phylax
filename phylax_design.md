# Phylax — Design Doc

Oct 17, 2026 · @David

## Summary

Version 2. The platform has one Go agent on every host, which sends everything outbound to one controller on ubuntu-wkst. A segment that can't reach the controller directly reaches it through a relay: the same agent binary with its relay role switched on. Operators drive everything from a web UI bound to localhost on the controller. Work is planned as a DAG of typed, Go-native actions that you can see, approve and watch run.

On top of hardening and response, the platform does four things:

1. **Keeps active checks in step with the scorer, discovering what it checks** from passive capture.
2. **Labels all traffic** to our services as the scorer, us, or everyone else.
3. **Notices any change to our services** within a minute.
4. **Traces each change back to its cause**, ready for an incident report.

Simplicity is a hard requirement. Every place this design adds complexity is marked **Complexity flag**, and all of them are collected in the complexity register near the end.

### What changed from v1

- **Direction.** Agents dial out to the controller. No host has an inbound management port. The only inbound exceptions are the relay host (its segment's agents connect to it) and the decoys, which are inbound on purpose.
- **Go-native actions instead of shell scripts.** Steps call OS interfaces directly. Running a host binary is an explicit, approved escape hatch.
- **One controller and one event store,** with a localhost web UI. The TUI and multi-user features are gone.
- **Removed:** Wazuh, Velociraptor, Ansible, self-update, and dynamic topology. Sysmon stays on Windows.
- **Added as first-class:** packet capture, check discovery with an editable set of active checks, change trace-back, a C2 sinkhole, deception, and Palo-side packet capture (phase 3).
- **Deferred:** containerization. It isn't needed to meet the goals, and it's a large source of complexity.

### Goals

1. Rotate credentials and enforce host firewalls on every host within 25 minutes of drop flag, and finish service hardening by T+40, losing no action to a dropped connection.
2. Have an agent heartbeating within 30 seconds of first contact.
3. Discover which checks the scorer is running and keep our active checks in step: learn its initial set within 3 rounds, propose a new check within one round of the scorer starting it, and flag checks it has stopped using. Operators can add, edit or remove active checks at any time.
4. Label every connection to a scored service as scorer, us or other, and flag attack-like traffic within "other".
5. Detect any change to a service's content, configuration or behavior within 60 seconds, and build the trace-back timeline automatically.
6. Catch C2 attempts through denied egress and the sinkhole, attributed to a process and a binary hash.
7. Turn red-team looting into precise alerts that say which host was looted and roughly when.
8. Draft an incident report in 5 minutes or less, and a routine inject in 10 minutes or less.
9. Adapt to a new infra shape by editing the manifest, not the code.

### Non-goals

- A full EDR. No kernel drivers, no custom eBPF.
- Any contact with scorer or red-team infrastructure. We observe only what reaches our hosts.
- Anything inline in the scoring path.
- Automatic actions on scored state (scored accounts, scored service config) without a human.
- Tamper-proofing on hosts the red team owns.
- Dynamic topology: relay election, backup relays, auto-discovery.
- An agent self-update system. One narrow action replaces the binary.
- Multi-user access, roles or remote UI access.

### Success metrics

| Metric | Target | Measured by |
| --- | --- | --- |
| Cold-start hardening of all servers | Credentials and firewalls in 25 min or less; services by T+40 | Lab dry run |
| Actions lost to disconnects | 0 | Agent checkpoint logs |
| First contact to heartbeat | 30 s or less | Lab test T21 |
| Scorer checks discovered at drop flag (simulator ground truth) | 100% within 3 rounds | Scorer simulator (T15) |
| False checks invented from noise | 0 over 2 hours | Orange-team simulator (T15) |
| New scorer check proposed | Within one round | Simulator adds a check (T14) |
| Service change detected | 60 s or less | Lab defacement and config tamper tests |
| Trace-back reaches the source IP for webshell-driven changes | 90% or more | Lab red-team campaigns |
| Denied callback attributed to a process | 60 s or less | Lab implants |
| Planted prebaked implants found | 90% or more by T+15 min | Contaminated golden images |
| Alerts to IR draft | 5 min or less | Timed dry run |
| False-positive alerts | 5 per hour or fewer | Dry run with all simulators |

## Constraints and assumptions

The competition rules shape this design more than any technology choice does. The 2026 Midwest regional topology is the reference case, but the infra may change, so nothing below depends on specific hosts.

### From the team packet

| Constraint | Packet section | What it means for the design |
| --- | --- | --- |
| Public services must stay reachable from nominally all source IPs. No subnet blocks or scorer-only ACLs. | Systems 10 | The scorer is identified by behavior, not by IP. Blocking is single-IP and one-click. |
| Traffic generators and the Orange Team send traffic, some of it malicious, from random source IPs. | Team ID; Systems 5 | Detections and decoy severities are tuned against that noise. The lab includes an orange-team simulator. |
| HTTP and HTTPS content is compared to an expected result. FTP file presence and POP3 command output are checked. HTTPS, TFTP and NTP may be checked. | Functional services | Content changes are first-class alerts. Parsers cover these protocols. |
| Business tasks may add or change services. | Business tasks | The manifest is the single source of truth. An inject change is a manifest edit plus a plan. |
| Scored-account password changes go through a support ticket. | Play 10 | Scored accounts are learned from the scorer and protected from automatic rotation. |
| Team repos are copied to Nextcloud and visible to all teams. | Systems 16 | No secrets in the repo. Detection logic is assumed public. Tokens, banners and passwords are generated at competition time. |
| No USB media. Only freely available internet resources, through a proxy. | Play 3; Systems 15 | Binaries are delivered as public, signed GitHub releases with a repo-committed fallback. |
| No offensive activity against other teams, the White Team, the Red Team or global assets. | Play 8 | Strictly passive toward the scorer. Decoys and the sinkhole record only; nothing connects back. |
| User workstations can't be re-tasked. | Systems 12 | The controller and relay run on workstations. This needs confirming with officials (§ Risks and open questions). |
| Internal addressing and hostnames can't change. | Systems 6–7 | Nothing in the design renumbers anything. |
| VM resets restore the initial state. | Systems 11 | Re-enrollment is part of the feature set. Plans are re-runnable from zero. |
| Teams own any scoring breakage their defenses cause. | Play 11 | Every automatic action is followed by a health check. There's a global safe mode. |
| IR reports need IPs, timelines, cracked passwords, impact and remediation, and are judged on exploitation. | Scoring 5–6 | Trace-back timelines and decoy sightings feed the IR drafter. |
| Inject responses are PDFs. NISE times are US Central. | NISE | Drafters render PDF. Everything stores UTC and displays America/Chicago time (CST or CDT, whichever is in effect). |

### Assumptions about the infra

- **Segments.** The network is one or more segments, each behind its own firewall, with NAT between them and the outside. The manifest describes whatever shape the year brings.
- **The controller host** is a Linux workstation (ubuntu-wkst in 2026). Its address is stable for the duration of the competition. DHCP is acceptable as long as the lease doesn't change. If it does change, there's a manual command on each agent (§ Enrollment).
- **Every segment the controller can't reach** has at least one non-scored host that can run the relay role, ideally a workstation.
- **Operating systems:** Windows 10 or Server 2016 and newer; Linux kernel 3.2 and newer. This is what current Go supports. Nothing older is expected.
- **The red team sits outside the perimeter** and comes in through the firewalls. They may already have persistence on hosts at drop flag.
- **Console access through NETLAB** is always available as break-glass, and is the only way in before credentials are known.
- **Free disk:** the ubuntu-wkst disk is large enough to retain everything for both days. This needs measuring (§ Risks and open questions).

## Architecture overview

Phylax is one Go binary that runs in two modes: `phylax serve` on the controller and `phylax agent` on every host. Hosts always open the TLS connections, outbound. The controller holds the plans, the event store, the analysis engines, the device adapters and the web UI. The agent does all on-host work, plus whichever roles the manifest gives its host. One binary means one release artifact per OS, and the agent and controller can never disagree on the protocol version. **Complexity flag:** every host carries the controller's code too, which makes the binary bigger (§ The agent, footprint targets).

&#91;embedded content: architecture v2 · hosts dial out, relays splice other segments\]

Every arrow points toward the controller: connections are always opened by the host side. The relay is the only host that accepts connections, and only from its own segment.

### Components

| Component | Runs on | Responsibility |
| --- | --- | --- |
| `phylax serve` | Controller (ubuntu-wkst) | Accepts agent and relay connections. Holds the event store (SQLite) and the encrypted secrets vault. Compiles the manifest into plans, agent configs and firewall policy. Runs plans, correlation, check discovery, trace-back and the drafters. Talks to network devices through adapters. Serves the web UI on localhost. |
| Active checker | Controller, as a module of the main process | Runs the active checks on its own scheduler, with per-check timeouts and its own panic recovery, so one slow or crashing check can't stall the rest. Its list is managed in the UI and fed by check discovery, but it shares no code with discovery. |
| Web UI | Controller, `127.0.0.1` only | Server-rendered with htmx, live updates over Server-Sent Events. One login. Plan DAGs, alerts, the checks view, traffic, changes, decoys, evidence, platform health. |
| `phylax agent` | Every host, including the controller and relay hosts | Collection, local detection, automatic responses, action execution, packet capture, decoys, and a spool of everything it observes. Runs as root or SYSTEM, plus one unprivileged child process for decoys. |
| Agent roles | Hosts chosen in the manifest | `relay` (forwards its segment's agent connections to the controller); `device_proxy` (reaches a network device's management interface for the controller); `check_runner` (runs health checks from inside its segment); `decoys`; `capture`. All roles are config switches on the same binary. |
| Device adapters | Inside `phylax serve` | Palo Alto (PAN-OS XML API) and VyOS (SSH) in v2. One adapter per vendor, behind one interface. |
| Sysmon | Windows hosts | Process, network, registry, file, WMI and DNS events, which the agent reads. Installed and kept alive by the agent. |

### Design principles

1. **Simplicity first.** One binary, one transport, one source of truth. Each new listener, daemon, host-binary dependency or runtime discovery mechanism needs an entry in the complexity register.
2. **Hosts dial out.** No host opens an inbound port for management. The relay host and the decoys are the declared exceptions.
3. **Go-native by default.** Agent actions call OS interfaces (syscalls, netlink, D-Bus, Win32, COM and WMI, LDAP), not host binaries. Running a host binary is an explicit action that's labeled in the UI.
4. **Detect and act on the host; correlate and report on the controller.** Detection and automatic response keep working while the link is down.
5. **One source of truth.** Firewall policy, plans, health checks, decoys and roles are generated from the manifest. Manual host changes are adopted back into it or reverted.
6. **Passive in the scoring path.** Capture, replay and observe. Never intercept scored traffic.
7. **Trust only off-host data,** and treat everything an agent sends as untrusted input.
8. **Humans approve anything destructive or anything that touches scored state.**
9. **Static, declared topology.** No election, discovery or failover. A new infra shape is a new manifest.
10. **One TLS connection per logical stream.** No multiplexing layer. Relays, device proxying and patch windows each open their own connections.

## Topology, relays and firewalls

Topology is declared, not discovered. The manifest lists the segments, the controller host, and one relay host for each segment that can't reach the controller directly. Every agent then has exactly one outbound destination, and every firewall rule follows from that.

### Declaring it

```yaml
# manifest/topology.yml
controller:
  host: ubuntu-wkst
  agent_port: 7443          # the only inbound port on the controller besides localhost UI
  ui: 127.0.0.1:8443
segments:
  linux:
    cidr: 172.20.242.0/24
    firewall: palo1
    # controller lives here: agents dial it directly
  windows:
    cidr: 172.20.240.0/24
    firewall: palo2
    relay: { host: win11-wkst, port: 7444 }
    nat:                    # how this segment appears to the controller's side
      relay_public: "172.25.{{ 20 + team }}.144"
      controller_public: "172.25.{{ 20 + team }}.200"   # static inbound NAT on palo1, to be created
```

The controller's public address in this example is a placeholder. It has to be a free address in the team's public pool, mapped by a static NAT rule on the controller's firewall.

### Roles and links

- **Agents in the controller's segment** dial the controller directly.
- **Agents in another segment** dial their segment's relay. The relay splices each connection through to the controller.
- **Chained segments** (reachable only through another segment) chain relays. Each relay dials its parent relay or the controller.
- **Link direction is always child to parent in v2.** A segment that can make no outbound connection at all would need the direction flipped for that one link. **Complexity flag:** not built unless an infra actually requires it.
- **A dead relay** cuts its segment off from the controller. Agents there keep detecting, responding and spooling locally until it's back. Restore it with the console one-liner (§ Enrollment). There's no backup relay in v2; add a static backup only if lab testing shows relay loss is a real problem.

### How the relay works

The relay is a dumb splicer, which keeps it simple and keeps it from being worth attacking:

- It listens on one port and accepts connections only from the source addresses in its segment's manifest entry.
- For each accepted connection it opens a new outbound TCP connection to its parent and copies bytes both ways. The agent's TLS session runs end to end to the controller, so the relay never sees plaintext and holds no agent keys.
- It keeps one outbound control connection to the controller (TLS, its own identity), used only to receive device-proxy and bootstrap requests.
- For a **device-proxy request** ("connect me to 172.20.240.200:443"), the relay checks the target against its manifest allowlist, opens a connection to the device, opens a fresh outbound connection to the controller, and splices the two. The device's own TLS stays end to end.
- Each splice records only metadata: source, destination, bytes, duration.

There's no multiplexing layer anywhere. Every logical stream is its own TCP connection.

### One connection, hop by hop

An agent in another segment reaching the controller crosses every firewall layer. Each hop needs an allow rule only in the direction the connection is opened, since all of them track connection state.

| Hop | Rule | Address used |
| --- | --- | --- |
| Agent host firewall, outbound | Allow TCP to the relay on its port | Relay's internal address |
| Relay host firewall, inbound | Allow its port from the segment's agent addresses only | Agents' internal addresses |
| Relay host firewall, outbound | Allow to the controller on the agent port | Controller's public address |
| Segment firewall (Palo 2), outbound | Allow relay to controller's public address on the agent port, translating the relay to its public address | Both public |
| Upstream router (VyOS) | Routes only | — |
| Controller's segment firewall (Palo 1), inbound | Translate the controller's public address to its internal one, allowed only from the relay's public address | Relay public → controller internal |
| Controller host firewall, inbound | Allow the agent port only from the relay's public address and the local segment's agent addresses | As seen after translation |

Each rule uses the address as it appears at that point, before or after translation. The manifest's `nat` block is what lets the generator get this right. Hand-written rules get it wrong more than anything else, so it has a dedicated lab test.

### What each firewall layer is for

- **Network firewalls** guard the boundaries between segments. A host implant can't change them without device credentials.
- **Host firewalls** are the only control on traffic within a segment, which never crosses the Palo. An implant can disable them. The agent restores them automatically and alerts.

### Rule hygiene and bring-up

- **Separate, tagged groups.** Management rules (agent, relay and device-proxy links) live in their own group: an nftables table, a Windows Firewall rule group, a Palo tag. Restore and drift detection treat them separately from service rules, decoy rules and inject changes.
- **Bring-up order:**
  1. Network firewall rules for the relay links and the controller's static NAT, entered by hand on the device consoles by the Network role. The adapters can't do this step: a device in another segment is only reachable through that segment's relay, which needs these rules first, so both Palos are done the same way. `phylax` renders the exact rules from the manifest onto Network's printed checklist, so nothing is composed on the day. The adapters take over once the relays are up.
  2. First contact installs the agents.
  3. Host firewalls get the management allows first, then default-deny outbound, under the dead-man switch (§ Execution).
- **Controller address.** The design assumes ubuntu-wkst keeps its address for the whole competition. If it changes, the controller's static NAT rule is updated by hand and every agent is pointed at the new address with a local command (§ Enrollment). There's no automatic address-update mechanism.

## Trust model

The controller and its unlocked keys are the only fully trusted component. Agents are trusted to report on their own host only while that host is clean. Relays, the network, host binaries, DNS and clocks aren't trusted at all. Every mechanism below exists to keep a compromise of one host from spreading through our own tooling.

### Adversary assumptions

The red team can:

- get root or SYSTEM on any server, possibly on a workstation, possibly before drop flag
- read our full source, rules and this document
- watch or tamper with traffic inside a segment, and across segments if they own the router
- move system clocks
- kill, patch, or impersonate our agent on a host they own
- replay anything they capture
- feed crafted strings (process names, file paths, HTTP paths, usernames) into anything we log

### Trust boundaries

| Component | Trusted for | Not trusted for | If compromised |
| --- | --- | --- | --- |
| Controller host and its unlocked keys | Everything; it's the root of trust | — | Total loss: attacker can sign plans for every host. Everything else assumes this doesn't happen. |
| UI session (one login) | Launching and approving actions | — | Same as controller compromise. Bound to localhost, so the attacker needs the controller host first. |
| Release signing key (kept off the competition network) | Which binaries are ours | — | Malicious builds. Never present in the environment. |
| Agent | Reporting what it sees while its host is clean | Truth about a compromised host; anything about other hosts | Attacker can lie for that one host, flood, replay its own history, or impersonate that host. Nothing more. |
| Relay | Moving bytes | Reading or altering content | Can drop or delay its segment's traffic (visible as heartbeat gaps). Can't read, forge or command. |
| Network devices (after rotation) | Enforcing policy | Staying unchanged | Detected by config diff; reverted from snapshot. |
| Host OS, host binaries, DNS, clocks, the network | Nothing | Everything | Assumed hostile from the start |

### Mechanisms

**Identity with pinned keys, no certificate authority.**

- Each agent generates its own keypair at install and enrolls with a one-time token. The controller records its public key against the host's identity.
- The agent carries the controller's public key from its bootstrap bundle.
- Both sides verify each other by key, not by a certificate chain, and ignore certificate dates. Moving the clock can't break authentication.
- A stolen agent key impersonates only that host.

**Signed commands, separate from the transport.**

- Every plan step sent to an agent is signed with a plan-signing key held only in controller memory, unlocked by passphrase.
- Agents verify the signature, the expected plan id, and an epoch plus a monotonic sequence number. The epoch rises only when the controller is restored from a snapshot (§ Controller recovery). A hostile relay or network can't inject or replay commands.
- The transport key and the plan-signing key are different, so leaking one doesn't give you the other.

**Bounded agent power.** The agent runs as root or SYSTEM because it has to, but it only executes typed actions from the catalog. `host.exec` needs an explicit approval and is labeled in the UI. This won't stop a compromised controller, but it limits the damage from bugs and from any forged step that somehow passes verification.

**Per-host secrets only.** A plan step carries only the secrets its host needs. A new MySQL password goes to ecom and nowhere else, so owning one host leaks that host's credentials and no others.

**Agent data is evidence, never instructions.**

- Events are sequenced and hash-chained. The controller acknowledges what it stores. A root attacker can forge future events but can't rewrite acknowledged ones, and gaps are visible.
- Every message is validated against its schema, with per-agent size and rate limits.
- Nothing an agent sends is ever executed, or used to build a command or a query.

**The web UI treats every agent-supplied string as hostile.** Process names, command lines, paths, usernames, HTTP paths and decoy-shell input are all attacker-controlled. Rendered carelessly, they become stored cross-site scripting that rides the operator's session and approves plans. Required:

- Escape all output by default; no raw HTML from data.
- A strict Content Security Policy with no inline scripts and only vendored assets.
- An HttpOnly, SameSite=Strict session cookie, and CSRF tokens on every state-changing request.
- Evidence files served as downloads, never rendered inline.

**Time is for display only.** Ordering comes from per-host sequence numbers. Each heartbeat carries the host clock, and timelines apply the measured offset.

**The controller host gets the hardest hardening.**

- Inbound: only the agent port, from declared sources. The UI is on localhost.
- SSH disabled.
- Secrets in memory only; encrypted at rest.
- Its own agent reports to it like any other host. That catches mistakes and opportunistic attacks, not a skilled attacker who already has root.

### Where trust is weakest

- **First contact.** A host that's already backdoored at drop flag can tamper with the agent install. Its first hunt results matter more than its heartbeats.
- **Windows.** Go calls through `ntdll` and `kernel32` on Windows, so a userland hook in those libraries affects our agent too. On Linux, Go skips libc and is immune to LD\_PRELOAD tricks, but not to kernel rootkits.
- **The controller.** It's the single root of trust. That's accepted deliberately, in exchange for simplicity.

## The agent

The agent is the agent mode of the single static Phylax binary, running as a supervised service. It collects, detects, responds, executes plan steps, captures packets and runs decoys, all locally. It sends everything outbound to the controller (or its relay) and holds a local spool while the link is down. Roles from the manifest switch extra modules on. A host can hold several roles at once.

### Process model

- **Main process,** root or SYSTEM: everything except decoys.
- **Decoy process,** unprivileged (a dedicated user on Linux, a low-privilege service account on Windows): every decoy listener and the fake shell. It's started and supervised by the main process and talks to it over a local pipe. Low ports such as 22 reach it through firewall redirects, so it never needs privileges. **Complexity flag:** a second process. Kept because decoys are the agent code most exposed to attackers, and a bug there must not hand out root.
- **No hiding, no obfuscation.** The repo is public anyway, and tricks would add failure modes.

### Footprint targets

| Measure | Target | Enforced by |
| --- | --- | --- |
| Binary size | Measured in M1. Target: 40 MB or less, 15 MB or less compressed for transfer. If first contact is too slow, a build flag produces an agent-only variant. | CI fails the build above it |
| First contact to heartbeat | 30 s or less | Lab test T21 |
| Memory | 80 MB RSS or less steady, excluding the packet ring | Self-limit; alert above it |
| CPU | 3% average; a 5 s burst of one core at most | Self-throttles sampling; capture drops packets before slowing the host |
| Disk | Spool 200 MB cap; packet ring the smaller of 2 GB or 10% of free disk | Oldest low-priority data dropped first; alerts and evidence never dropped |

### Modules

Each module has its own config block and on/off switch. A module that panics is restarted on its own and reported; it doesn't take the agent down.

| Module | Does | Linux | Windows |
| --- | --- | --- | --- |
| `link` | Outbound TLS to controller or relay, reconnect, priorities | Native | Native |
| `spool` | Sequenced, hash-chained event segments; heartbeat every 5 s with clock reading | Native | Native |
| `exec` | Runs signed plan steps: typed actions with check, apply, verify, rollback | Native actions; `host.exec` on approval | Same |
| `proc` | Process start and exit with lineage, user, command line, service attribution | Netlink proc connector plus `/proc` reads; cgroup for the systemd unit; kernel audit records | Sysmon 1 and 5 through `EvtSubscribe`; Security 4688 fallback; service map from the service manager |
| `net` | Listeners, connections, owning process | `sock_diag` netlink every 2 s, plus on demand | `GetExtendedTcpTable` and UDP table every 2 s; Sysmon 3 |
| `fim` | File changes on persistence paths, content roots, configs | inotify plus a hash sweep every 5 min; fanotify for read alerts on honey files | `ReadDirectoryChangesW` plus Sysmon 11–14; file auditing (4663) for honey files |
| `logs` | App and OS logs into events | Native file tail | `EvtSubscribe` on Security, System, PowerShell, Defender, Task Scheduler, Firewall, DNS analytical; native file tail for IIS and FTP logs |
| `capture` | Packet ring, flows, protocol transactions | AF\_PACKET with a memory-mapped ring; filters built in Go | Raw socket with `SIO_RCVALL` |
| `egress` | Denied outbound attempts, attributed to a process | NFLOG over netlink | Security 5157 |
| `sinkhole` | Catches denied outbound TCP and records what the implant would have sent | nftables redirect to a loopback catcher | Not available (would need a driver) |
| `detect` | Rule evaluation on every event | Native | Native |
| `respond` | Tier-0 actions, with guards | Native | Native |
| `crossview` | Hidden PIDs, sockets and modules; memfd or deleted executables; `LD_PRELOAD`; BPF programs | Native | Process list from several APIs; driver list against baseline |
| `decoys` | Network decoys and the fake shell (in the decoy process) | Native | Native |
| `relay`, `device_proxy`, `check_runner` | Roles described elsewhere | Native | Native |
| `patch_proxy` | Loopback HTTP proxy for patch windows | Native | Native |

### What "Go-native" means here

- **Allowed by default:** calling the OS's own interfaces from Go. That means syscalls, netlink, `/proc` and `/sys`, D-Bus for systemd, Win32 APIs, COM and WMI, the event log API, LDAP, and database drivers.
- **Escape hatch:** `host.exec`, which runs a binary on the host. It's allowed, needs approval in the UI, and is labeled "runs a host binary" everywhere it appears.
- **Expected `host.exec` uses:**
  - Package managers (apt, dnf) during patch windows
  - Sysmon's installer
  - Odd service CLIs with no API, such as `dnscmd`
  - GPO edits
- **Complexity flag:** COM and WMI from Go (Windows Firewall, Task Scheduler, WMI subscriptions, Defender settings) is fiddly code. It's the largest chunk of Windows work and deserves the most tests. If a particular COM interface fights back, use `host.exec` for that one action and record it in the register, rather than sinking a week into it.

### Telemetry sources

- **Linux.**
  - Process events come from the netlink proc connector, which needs nothing installed. The agent reads `/proc/<pid>` immediately on each exec event, to beat processes that exit quickly.
  - The agent also reads the kernel audit subsystem directly over netlink (`go-libaudit`) and installs our rules itself, so it trusts no auditd binary. It joins the read-only multicast group (kernel 3.16 and newer), which leaves auditd running. That matters because RHEL-family systems refuse to stop auditd by hand (`RefuseManualStop=yes`), and anything reading `audit.log`, such as Splunk, keeps working. On older kernels, where there can only be one reader, the agent takes that role and stops auditd. Restarting auditd can flush our rules; the ruleset-hash check (D10) catches that and reinstalls them.
- **Windows.**
  - Sysmon is installed by the agent using `host.exec` (no reboot needed), with our config. The Sysinternals license doesn't let us redistribute it, so `phylax init` fetches it from Microsoft through the competition proxy and checks it against a hash pinned in our release. The controller then ships it to agents like any other payload. If the fetch fails, Windows hosts run on the Security 4688 fallback below. The agent reads its channel through `EvtSubscribe`.
  - If Sysmon is removed or reconfigured, the agent reinstalls it as a tier-0 action. Meanwhile it falls back to Security 4688 with command-line auditing, which it enables natively.

### Local detection rules

Rules are YAML, delivered in the agent's config and hot-reloaded without a restart. The language is deliberately small: field matches, list membership, profile lookups, negation, and count-over-window thresholds. There's no general query language. Cross-host correlation happens on the controller.

```yaml
id: D1.service-spawns-shell
when:
  event: process_start
  all:
    - parent.service.scored: true
    - not: { exe: { in_profile: parent.service } }
  any:
    - name: [sh, bash, dash, python3, perl, nc, ncat, socat, curl, wget, busybox, base64]
    - name: [cmd.exe, powershell.exe, pwsh.exe, certutil.exe, bitsadmin.exe, whoami.exe,
             net.exe, net1.exe, rundll32.exe, mshta.exe, regsvr32.exe]
severity: high
tier: 1
collect: [process_tree, content_changes, transactions_window_10m, freeze_ring]
attack: [T1505.003, T1059]
test: lab/tests/webshell_php_exec.yml
```

The `collect` list runs on the host the moment the rule fires, so evidence is gathered before the attacker cleans up. It ships with the alert.

### Platforms

- **Supported:** Windows 10 or Server 2016 and newer; Linux with kernel 3.2 or newer (current Go's floor).
- **Linux variations:** features detected at start include cgroup v2, proc connector access, the audit API and AF\_PACKET ring version. The agent reports which modules are running, so a coverage gap shows in the UI instead of failing silently.

### Windows Defender

An unsigned binary that captures raw packets, runs fake services and keeps a decoy credential session in LSASS can look like malware.

- Test the agent against current Defender definitions in the lab before every release.
- If it's flagged, hardening keeps exactly one Defender exclusion (the agent's install directory) and alerts on any other exclusion, since red teams love adding them.
- **Complexity flag:** an exclusion is a hole, even a narrow one. The only alternative is code signing, which isn't practical for this team.

### Lifecycle

| Stage | What happens |
| --- | --- |
| Install | First contact copies the binary and a bootstrap config (§ Enrollment). It installs a systemd unit or Windows service with automatic restart, then enrolls. |
| Steady state | Supervised by systemd or the service manager. Config and rules hot-reload from signed config steps. |
| Killed or disabled by the red team | The controller sees the heartbeat stop. If the host is unreachable by any other means, restore it from the console one-liner. |
| Binary replacement | One action, `agent.replace_binary`: verify the signed binary, swap, restart, and roll back if no heartbeat returns within 30 s. This is the only update path. There's no self-update system. |
| Uninstall | One action, for cleanup after the competition. |

## Wire protocol and data flow

Each agent holds one long-lived TLS 1.3 connection to the controller, with both sides pinning keys. Over it run length-prefixed, compressed JSON messages in strict priority order. Anything that isn't agent messaging (relay control, device proxying, patch windows, console bootstrap) gets its own connection, told apart by ALPN, the protocol name sent during the TLS handshake.

### TLS and pinning

- TLS 1.3 only, Go's standard library, for every connection type except bootstrap. Bootstrap also accepts TLS 1.2, because Windows 10, Server 2016 and Server 2019 can't do TLS 1.3, and the console one-liner uses the host's own TLS stack.
- Self-signed certificates. Verification is replaced by a check of the peer's public-key hash against the pinned value, with dates ignored.
- The controller pins each agent's key at enrollment. Agents and relays pin the controller's key from their bootstrap config.
- One listener on the controller, `agent_port`, serves every connection type. The ALPN value picks the handler:

| ALPN | Opened by | Purpose |
| --- | --- | --- |
| `phylax/agent` | Agent (direct or spliced through a relay) | All agent messaging |
| `phylax/relay` | Relay | The relay's control connection |
| `phylax/splice` | Relay | One device-proxy or bootstrap stream |
| `phylax/patch` | Agent | One proxied HTTP connection during a patch window |
| None, or `http/1.1` | A host being bootstrapped from the console | Download of the agent binary and bootstrap config with a one-time token. Stock tools (curl, PowerShell) can't send a custom ALPN value, so any connection without a `phylax/*` value goes to the bootstrap handler, which serves only these downloads. |

**Complexity flag:** five connection types on one port. It's still one listener and one firewall rule, and each handler is small. That's simpler than five ports.

### Framing

- Each message is a 4-byte length, a type byte, and a JSON body. Batches of events are compressed with zstd (pure Go).
- **JSON over protobuf, deliberately.** It's readable when debugging under pressure, needs no code generation, and compression makes the bandwidth difference irrelevant at this volume.
- Maximum message size: 4 MB. Anything larger (pcap slices, files, binaries) moves as content-addressed 256 KB chunks, compressed with zstd first where that helps (the Phylax binary roughly halves).

### Messages

| Direction | Message | Notes |
| --- | --- | --- |
| Agent → controller | `hello` | Host id, agent version, roles, capabilities detected, last acknowledged sequence |
| Agent → controller | `heartbeat` | Every 5 s: sequence, host clock, spool depth, module status |
| Agent → controller | `events` | Batch of telemetry, alerts, transactions and flows, each with its sequence number |
| Agent → controller | `step_result` | Per-action check, apply, verify outcome with before and after state |
| Agent → controller | `chunk` | Evidence, pcap slices, collected files |
| Controller → agent | `ack` | Highest contiguous sequence stored. The agent keeps acknowledged events until it needs the space, so a restored controller can ask for them again. |
| Controller → agent | `step` | A signed plan step |
| Controller → agent | `config` | A signed config and rules update |
| Controller → agent | `fetch` | Request for a pcap slice, a file or raw telemetry for a time window |
| Controller → agent | `chunk` | Payloads for steps: files, packages, the agent binary |
| Controller → agent | `control` | Safe mode on or off, freeze capture window, patch window open or close |

### Priority

The sender drains its queues in strict order:

1. Heartbeats, alerts and acknowledgments
2. Plan steps and step results
3. Evidence attached to alerts
4. Transactions and flows
5. Other telemetry
6. Bulk transfers (pcap slices, files, binaries)

A queued bulk transfer never delays an alert.

### Reliability

- **Spool and acknowledge.** Every event has a per-host sequence number. The agent resends from the last acknowledged sequence after every reconnect, and the controller discards duplicates by host and sequence. Neither a controller restart nor a link drop loses or duplicates data. Restoring the controller from a snapshot is different (§ Controller recovery).
- **Reconnect** with jittered backoff from 1 s to 30 s.
- **Chunked transfers resume.** The receiver reports which chunks it already has.
- **Limits** per agent: message rate, total bytes per minute, and concurrent fetches. An agent over its limit is throttled, never allowed to starve the others.

### Volume

- Shipped continuously: alerts, heartbeats, process starts, connection changes (not every sample), file changes on watched paths, selected log lines, flows, protocol transactions on scored ports, denied-egress attempts, sinkhole captures, decoy sightings.
- Kept on the host until fetched: the packet ring, raw sampler output, full log files.
- When the spool nears its cap, it first drops events the controller has already acknowledged, oldest first. Then it sheds unacknowledged data in this order: raw log lines, connection churn, flows on unscored ports. Unacknowledged alerts, evidence, heartbeats and step results are never shed.

### Performance envelope

Design for outages of up to 60 s on any link. Latency from event to controller is 10 s or less while the link is up.

## Enrollment, bootstrap and recovery

The controller gets its binaries from a signed release. It installs agents over SSH where it can, WinRM where it must, and a typed console one-liner as break-glass. Each install enrolls with a one-time token. After a VM reset, an operator re-enrolls the host, which revokes its old key. The controller itself can be restored from an encrypted state snapshot kept on another host.

### Getting binaries into the environment

1. **CI builds and signs** a release: static binaries for linux/amd64 and windows/amd64, YARA rules, reference baselines, and the pinned hash of the Sysmon release we tested (Sysmon itself can't be redistributed; § The agent). The release is signed with an ed25519 key that never enters the competition environment.
2. **The first binary.** The platform driver downloads the `phylax` binary for ubuntu-wkst through the competition proxy (browser or `curl`) and verifies it with `ssh-keygen -Y verify`, which every stock Ubuntu install has. Each release also carries an OpenSSH-format signature from the same ed25519 key. The public key to verify against is printed on the driver's checklist, not taken from the repo or the download, since either could be tampered with.
3. **`phylax init`** on ubuntu-wkst then downloads the rest of the release through the competition proxy and verifies the signature against the public key compiled into `phylax`.
4. **Fallbacks,** in order (the first binary is verified the same way):
   - The same signed artifacts committed under `dist/` in the repo (check that the Nextcloud copy keeps binaries)
   - A build from vendored source with a Go toolchain
5. **`phylax init` reports which channel worked,** which also tells you early what the proxy allows.

### First contact

| Method | When | How |
| --- | --- | --- |
| SSH (preferred) | Host has SSH and known default credentials, and the controller can reach it | `phylax` uses its built-in Go SSH client with the manifest's default credentials. It uploads the agent binary and bootstrap config, installs the service, and starts it. |
| WinRM | Windows host with no SSH where WinRM is enabled (the default on Server 2012 and newer, not on Windows 10 or 11) | `phylax` uses a built-in Go WinRM client, same steps. The client must do NTLM with message encryption: WinRM over HTTP refuses unencrypted traffic by default, and we don't weaken that. Basic auth and `AllowUnencrypted` are never used. |
| Console one-liner | Anything the controller can't reach, the relay host first in another segment, or break-glass | The operator generates a one-time token in the UI and types a short command on the NETLAB console. It downloads the binary and bootstrap config from the controller over the bootstrap connection type (TLS 1.2 or 1.3, no custom ALPN), checks its hash, and installs. |

The console one-liner uses the host's own download tool (`curl`, or PowerShell's web client), so it counts as `host.exec` by nature. That's acceptable for break-glass. The typed command carries two pins. The controller's public key (curl's `--pinnedpubkey`, or a certificate-validation callback in PowerShell, which also turns on TLS 1.2 for older builds) means the token is never sent to an impostor. The download's hash means a tampered download fails. The UI generates the full command for each host, so nobody composes it under pressure.

**Bootstrap config contents:** the controller's address and port (or the relay's), the controller's public-key pin, the host's manifest identity, a one-time enrollment token that expires after 10 minutes, and the initial roles.

### Bringing up another segment

1. **The relay host first**, via the console one-liner, or via WinRM if the controller can already reach it. It enrolls through the static NAT path.
2. **Bootstrap window.** For each other host in the segment, the controller asks the relay to splice an SSH or WinRM session to that host's management port. That's the device-proxy mechanism with a temporary allowlist entry. First contact then proceeds as normal.
3. **The window closes** after the segment's agents have enrolled. The relay's allowlist goes back to declared devices only.

### Enrollment

1. The agent generates its keypair and connects with `phylax/agent`, presenting the token.
2. The controller checks the token against the host identity it was issued for, records the agent's public key, and marks the token used.
3. Host identity is the manifest name plus the enrolled key, never an IP address.

### After enrollment

SSH and WinRM are treated like any other service. If the manifest doesn't declare them for a host, they get disabled as part of that host's hardening plan, with the console as break-glass.

### Re-enrollment after a VM reset

- A reset wipes the agent, so the host stops reporting. The UI shows it as silent, not deleted.
- An operator clicks **Re-enroll** for that host. That revokes the old key, issues a fresh token, and runs first contact again with the default credentials, since the reset restored them.
- The host's hardening plan then re-runs from zero. Every action is idempotent, so this is just another run.
- There's no automatic re-enrollment: a new key claiming to be an existing host is always an alert until an operator approves it.
- **A reset undoes credentials too.** It restores the host's default credentials, so the vault marks that host's rotated credentials as reverted, and the hardening plan rotates them again.
- **A DC reset is a domain-wide event.** It rolls back every domain account, group, GPO and ACL change, the krbtgt resets, and the honey AD accounts. The UI marks every domain credential in the vault as reverted, re-runs the domain rotation, AD hardening and honey-account plans, and re-raises the support tickets for scored domain accounts.

### Changing the controller address

If the controller's address changes, run `phylax set-controller <address:port>` on each affected host's console, relay hosts first. Agents behind a relay don't need it, because they dial the relay. There's deliberately nothing automatic here.

### Controller recovery

**State snapshot.** Every 15 minutes, and after every enrollment, plan completion and vault change, `phylax` writes an encrypted snapshot to every host the manifest lists as a backup target (for example, the relay host). It holds state, not event data, so it stays small (target: under 10 MB) and quick to ship:

- the controller's private keys (TLS and plan-signing)
- the enrolled agent keys, with each agent's last acknowledged sequence number and chain hash
- the manifest and overrides
- the secrets vault
- plans and their node status, active checks, and the honeytoken registry
- incidents and alerts, without bulk evidence

It's encrypted with a key derived from the operator passphrase (`age` in scrypt mode), so the target host holds an opaque blob.

**Restore starts a new epoch.** Install `phylax` on the replacement machine, fetch the latest snapshot, unlock it with the passphrase, and start. Because the snapshot includes the controller's keys, every agent still trusts it. A snapshot can be up to 15 minutes old, so the restored controller doesn't pretend to continue where the lost one stopped:

- **Commands.** Plan steps carry an epoch number as well as a sequence number. A restore raises the epoch, and agents accept any sequence in a higher epoch, so steps the lost controller sent after the snapshot can't block the restored one. Raising the epoch takes the plan-signing key, so a hostile relay or network still can't replay old steps.
- **Events.** Agents don't delete acknowledged events right away; they keep them until the spool needs the space. After a restore, the controller asks each agent to resend everything it still holds. It checks that the resent chain passes through the sequence number and hash the snapshot recorded for that agent, so a compromised agent can't rewrite history from before the snapshot. Anything no spool still holds is marked on timelines as a gap, with the reason "controller restored".
- **Address.** If the address changed, use `set-controller` as above.

**Restart safety.**

- After any restart, the controller accepts and stores agent traffic immediately.
- Plan signing and secret access stay locked until an operator enters the passphrase in the UI.
- Agents resend from their last acknowledgment, and duplicates are discarded.

Packet captures, evidence files and older telemetry are not in the snapshot, because of their size. They're encrypted at rest (§ Controller) and would be lost along with the machine, apart from what agent spools can resend. Golden service backups are the exception: each is also copied once to the backup targets, because restores depend on them.

## Execution: actions, plans and the DAG

All change goes through plans. A plan is a DAG whose nodes are typed actions on specific hosts or devices, with dependency edges and optional approval gates. Every plan shows a dry-run diff before anything runs. The UI draws the DAG and colors each node live as it runs. Lockout-risk actions roll themselves back if the agent can't reach the controller afterwards.

### Actions

An action is Go code in the agent (or a device adapter in `phylax`) with four parts: **check** (is it already done?), **apply**, **verify** and **rollback**. Each action declares a parameter schema, a risk class (`none`, `service`, `lockout`, `destructive`) and the resources it locks.

**Action catalog v1**

| Area | Actions | Linux implementation | Windows implementation |
| --- | --- | --- | --- |
| Files | `file.write`, `file.template`, `file.perms`, `file.quarantine`, `file.restore`, `file.hash`, `dir.snapshot` | Native | Native |
| Local accounts | `user.set_password`, `user.lock`, `user.create`, `user.delete`, `group.members`, `ssh.authorized_keys` | Edit `/etc/shadow`, `/etc/passwd` and `/etc/group` directly with locking, keeping their SELinux labels; SHA-512 crypt hashes | `NetUserSetInfo`, `NetLocalGroup*` APIs |
| Domain | `ad.set_password`, `ad.user`, `ad.group_members`, `ad.spn`, `ad.delegation_clear`, `ldap.modify` | — | Run by the DC's agent through the domain-aware user APIs and LDAP |
| Services | `service.state` (start, stop, enable, disable, mask), `service.config` | systemd over D-Bus | Service control manager APIs |
| Firewall | `fw.apply` (declared groups), `fw.snapshot`, `fw.restore` | nftables over netlink | Windows Firewall through COM, in our own rule group |
| Kernel and system | `sysctl.set`, `module.block`, `modules.disable_loading`, `hosts.file` | `/proc/sys`, modprobe config | — |
| Registry | `reg.set`, `reg.delete`, `reg.snapshot` | — | Native registry API |
| Persistence cleanup | `cron.disable`, `unit.disable`, `task.disable`, `wmi.subscription_remove`, `runkey.remove`, `ld_preload.clear` | Native file edits, D-Bus | Task Scheduler and WMI through COM; registry |
| Processes | `proc.kill_tree`, `proc.dump` | Signals; reads `/proc/<pid>/mem` | `TerminateProcess`; `MiniDumpWriteDump` |
| Logging | `audit.rules`, `auditpol.set`, `eventlog.size`, `sysmon.install`, `sysmon.config` | Kernel audit over netlink | Native audit-policy API; `sysmon.install` uses `host.exec` |
| Databases | `mysql.exec`, `mysql.set_password`, `mysql.dump` | Go MySQL driver; dump written natively in Go | — |
| Services' config | Templates for Apache, PHP, Postfix, Dovecot, IIS, FTP | `file.template` + `service.state` | Native XML edit of `applicationHost.config` |
| Packages | `pkg.install`, `pkg.upgrade` | `host.exec` of apt or dnf inside a patch window | Windows Update Agent COM API inside a patch window, with the WinHTTP proxy pointed at the loopback proxy |
| Collection | `collect.files`, `collect.inventory`, `hunt.baseline_diff`, `hunt.persistence`, `yara.scan` | Native, except `yara.scan` | Same |
| Agent | `agent.replace_binary`, `agent.config`, `agent.set_controller`, `agent.safe_mode` | Native | Native |
| Devices (in `phylax`) | `palo.apply`, `palo.commit`, `palo.snapshot`, `palo.revert`, `vyos.apply`, `device.rotate_admin` | XML API, SSH | — |
| Escape hatch | `host.exec` | Approval required; labeled everywhere | Same |

**SELinux.** Fedora and Oracle run SELinux in enforcing mode. File actions write a temporary file and rename it into place, so the new file would get its directory's default label. That's wrong for files such as `/etc/shadow` (`shadow_t`) and `/etc/passwd` (`passwd_file_t`), and can break logins. File actions copy the original file's label onto the replacement before the rename, use the policy default for new files, and check the label in verify. Unit tests run against SELinux-enforcing images.

**Complexity flag:** `yara.scan` has no pure-Go engine. It ships the YARA binary as a `host.exec` tool and runs only on demand, never continuously.

### Plans

A plan is YAML: a list of nodes with an action, a target, parameters, dependencies and options. Plans are written as templates that select targets from the manifest, so one "harden every Linux web server" template expands to concrete per-host nodes.

```yaml
plan: harden-ecom
nodes:
  creds:     { action: user.set_password, target: ubuntu-ecom, params: { user: root, secret: ecom.root } }
  ssh_off:   { action: service.state, target: ubuntu-ecom, params: { unit: ssh.service, state: disabled },
               needs: [creds], deadman: 90s }
  fw_shadow: { action: fw.apply, target: ubuntu-ecom, params: { mode: shadow }, needs: [creds] }
  review_fw: { gate: approval, needs: [fw_shadow], note: "Check would-be drops before enforcing" }
  fw_enf:    { action: fw.apply, target: ubuntu-ecom, params: { mode: enforce }, needs: [review_fw], deadman: 90s }
  db_pw:     { action: mysql.set_password, target: ubuntu-ecom, params: { user: opencart, secret: ecom.db } }
  app_cfg:   { action: file.template, target: ubuntu-ecom, params: { path: /var/www/html/config.php }, needs: [db_pw] }
  php:       { action: file.template, target: ubuntu-ecom, params: { path: /etc/php/8.3/apache2/conf.d/99-phylax.ini } }
  reload:    { action: service.state, target: ubuntu-ecom, params: { unit: apache2.service, state: reloaded },
               needs: [app_cfg, php] }
  palo:      { action: palo.apply, target: palo1, params: { services: [ecom-http] } }
  check:     { action: health.check, target: ecom-http, needs: [reload, fw_enf, palo] }
on_failure: stop_dependents     # or: continue | rollback_plan
```

&#91;embedded content: example plan DAG · harden-ecom, 11 nodes\]

The UI draws plans like this, coloring each node as it runs. The credential, database and PHP branches run in parallel; enforcement waits for a human; the health check runs only once everything it depends on is done.

**Shadow mode.** `fw.apply` with `mode: shadow` shows what a policy would drop without dropping it. On Linux it installs the policy with a log rule in place of each drop. Windows Firewall rules can only allow or block, so on Windows shadow mode installs nothing. Instead the agent evaluates the proposed policy against its connection table (`net`, every 2 s) and its capture flows, and reports the connections the policy would have dropped. Very short connections can slip between samples, so shadow windows on Windows should run for a few minutes.

### Plan, approve, apply

1. **Plan.** `phylax` expands the template and sends every node's **check** to its agent. Each check reports what it would change.
2. **Diff.** The UI shows the DAG with each node marked: unchanged, will change (with a readable diff), or blocked by a lock.
3. **Approve.** One click approves the whole plan. Approval gates inside the plan pause execution at that node until clicked. `host.exec` nodes and `destructive` nodes always need their own approval.
4. **Apply.** Nodes run as soon as their dependencies finish, in parallel across hosts and within a host where locks allow. Each node's status streams live into the DAG view.
5. **On failure,** the plan's policy decides what happens: stop the failed node's dependents (default), continue, or roll back the whole plan in reverse order of completion.

### Dead-man switch

For any node marked `deadman` (default for `lockout`-class actions):

1. Before applying, the agent snapshots the affected state and arms a timer (default 90 s).
2. After applying, it opens a fresh connection to its controller or relay and completes a handshake.
3. If that works, the controller confirms and the timer is cancelled. If not, the agent rolls back on its own when the timer fires and reports the rollback once reconnected.
4. **Hosts that carry other links.** On the relay host and the controller host, a change can cut off every agent behind it while the host's own link stays up. For a `deadman` node there, the controller also asks agents that depend on the host to open fresh connections: one agent behind the relay, or one agent in each segment for the controller. It confirms only if those succeed before the timer fires. Otherwise it withholds confirmation and the host rolls back.

There's no SSH involved, so the dead-man covers the agent's own link, which is the link that matters.

### Locks

Each host has named resource locks: `firewall`, `accounts`, `sshd`, `packages`, `audit`, and one per service. Plan nodes and tier-0 responses take the same locks. While a plan node holds `firewall` on a host, automatic firewall restores on that host wait until it's released. A node holds its locks only while it runs, not while the plan waits at an approval gate. Each successful node updates the host's declared state, so a tier-0 restore during a gate restores what the plan has applied so far (for example, the shadow-mode policy), never the state from before the plan.

### Safe mode

One switch in the UI sends `control: safe_mode` to every agent. It immediately suspends tier-0 responses and any running plan nodes. Detection and collection keep running. It's for the moment our own automation is clearly making things worse. Turning it off is just as explicit. Agents stay in safe mode across restarts until told otherwise.

### Tagging and adoption

- Everything an action creates (firewall rules, units, tasks, accounts, files) is tagged with the plan id, so detection can tell our changes from anyone else's.
- Changes made by hand during an inject are flagged as drift. An operator either adopts them into the manifest overrides with one click, or reverts them.

## Manifest

The manifest is a set of YAML files, validated against a JSON Schema in CI and again when `phylax` loads it. It's the only place infra facts live. Plans, agent configs, firewall rules, health checks, decoys and inject artifacts are all generated from it. Changes made during the competition are written by the UI into an overrides file, never into the base files.

### Files

| File | Declares |
| --- | --- |
| `topology.yml` | Controller host and ports, segments, relays, NAT mappings, backup targets for controller snapshots |
| `hosts.yml` | Hosts: segment, internal and public address, OS, default credentials reference, roles |
| `services.yml` | Services: kind, scored flag, listeners, process identity, content roots, data, dependencies, health checks |
| `accounts.yml` | Managed accounts: scope, scored flag (also learned from the scorer), rotation policy, files that embed them |
| `devices.yml` | Network devices: vendor, management address, segment, adapter, which relay proxies them |
| `decoys.yml` | Decoys per host: listeners, honey files, honeytokens, exposure (inside, outside or both) |
| `policy.yml` | Response tiers, protected processes, retention, limits, patch-window allowlist |
| `overrides.yml` | Competition-day changes from the UI: adopted drift, inject changes, accepted findings |

Secrets never appear in the manifest. It refers to them by name (`secret: ecom.db`), and values live in the controller's vault.

### Examples

```yaml
# hosts.yml
team: 12
hosts:
  ubuntu-ecom:
    segment: linux
    ip: 172.20.242.30
    public_ip: "172.25.{{ 20 + team }}.11"
    os: { family: debian, distro: ubuntu, version: "24.04" }
    default_creds: defaults.ubuntu-ecom
    roles: [capture, decoys, check_runner]
  win11-wkst:
    segment: windows
    ip: 172.20.240.100
    os: { family: windows, version: "11-24h2" }
    default_creds: defaults.win11-wkst
    roles: [relay, device_proxy, check_runner, capture]
```

```yaml
# services.yml
services:
  ecom-http:
    host: ubuntu-ecom
    kind: http
    scored: true
    listen: [{ proto: tcp, port: 80 }]
    process: { unit: apache2.service }
    content:
      roots: [/var/www/html]
      upload_dirs: [/var/www/html/image/catalog]
      normalize: [opencart_token, csrf, session_cookie, timestamps]
    data: [{ kind: mysql, database: opencart }, { kind: dir, path: /var/www/html/image }]
    depends_on: [{ service: ecom-mysql }, { egress: dns, to: server-ad-dns }]
    health:
      - { http_get: "/", expect_status: 200, track_content: true }
  webmail-pop3:
    host: fedora-webmail
    kind: pop3
    scored: true
    listen: [{ proto: tcp, port: 110 }]
    process: { unit: dovecot.service }
    depends_on:
      - { egress: ldap, to: server-ad-dns, ports: [389] }
      - { egress: kerberos, to: server-ad-dns, ports: [88] }
    health:
      - { pop3_login: { account: health.pop3 }, expect: "+OK" }
  ssh-ecom:
    host: ubuntu-ecom
    kind: ssh
    scored: false
    state: disabled          # SSH is just a service: disabled unless declared otherwise
```

```yaml
# decoys.yml
decoys:
  ubuntu-ecom:
    listeners: [{ kind: ssh_shell, port: 22, exposure: both }, { kind: mysql, port: 3306, exposure: inside }]
    files: [{ path: /root/backup_db.sql, kind: honey_file }]
    tokens: [ssh_key, env_db_creds, bash_history]
  server-ad-dns:
    ad: [honey_spn_account, asrep_account, admin_lookalike]
    tokens: [lsass_decoy_session]
```

### What it generates

| Output | From | Used by |
| --- | --- | --- |
| Host firewall policy (management, service, dependency and decoy groups) | topology, services, decoys | `fw.apply` actions |
| Palo and VyOS rules, objects, NAT | topology, services, decoys, devices | Device adapters |
| Egress allowlists | `depends_on`, topology | Host and network firewalls |
| Agent configs (roles, modules, rules, profiles, paths) | hosts, services, decoys, policy | `config` messages |
| Plan targets | hosts, services, accounts | Plan templates |
| Health checks | `health` blocks plus accepted suggestions | Active checker |
| Honeytokens and decoy configs | decoys (values generated at competition time) | Decoy actions, token registry |
| Inject artifacts: asset inventory, service list, port matrix, network diagram | Everything | Drafters |
| Printed per-role checklists | Everything | Humans |

### Rules

- **No hand-edited generated files.** If something needs to differ, change the manifest or an override.
- **CI checks:** schema validity, dependency cycles, a firewall lint that fails if any scored port or declared dependency would be blocked, and rendering of every output for the reference manifest.
- **Drift detection** compares declared state with what agents observe: undeclared listeners, services, scheduled tasks, accounts and outbound peers. Each finding is adopted or remediated.

## Egress policy and C2 hunting

Servers get almost no outbound access: their agent link plus the service dependencies the manifest declares. Patches come through the controller in short windows. Every denied outbound attempt is logged at the host and at the network firewall, attributed to a process, and analyzed for beaconing. On Linux, denied connections are caught by a sinkhole that records what the implant would have said.

### What's allowed out

| Allowance | Who gets it | Notes |
| --- | --- | --- |
| Agent link | Every host | To the controller, or to the segment's relay |
| Declared dependencies | Per service, from `depends_on` | For example webmail → DC on LDAP and Kerberos; DNS to the DC; NTP to the chosen source; outbound SMTP only if mail must leave |
| Relay's link to the controller | Relay hosts | Plus device-proxy targets from the allowlist |
| Patch window | One host, time-boxed | Through the loopback proxy only (below) |

Everything else is dropped at the host firewall and at the segment firewall. Network-layer default-deny still holds when a host implant disables the host firewall.

### Patch windows

1. An operator opens a window for a host in the UI, for example 15 minutes.
2. The agent starts an HTTP proxy on `127.0.0.1` on that host. It's loopback only, so it isn't reachable from the network.
3. Each proxied connection becomes its own `phylax/patch` TLS connection to the controller.
4. The controller forwards it to the competition web proxy, but only to an allowlist from `policy.yml` (distro mirrors, Microsoft update endpoints). It logs every request.
5. Package actions run with the host's package manager pointed at the loopback proxy. The host needs no outbound rule and no DNS, since the controller resolves names.
6. When the window closes, the proxy stops and its connections are dropped.

Why this way: shipping packages inside plans would make the controller resolve dependencies for three distros. Letting the host's own package manager do it is far simpler. **Complexity flag:** the controller becomes a forwarding proxy. It's bounded by the allowlist, the time box, and one connection per proxied stream.

### Logging denied egress

| Vantage point | Mechanism | What it gives |
| --- | --- | --- |
| Linux host | The nftables drop rule also sends the packet to an NFLOG group, which the agent reads over netlink | The first packet of every denied attempt. Rules use drop, not reject: the blocked socket keeps retrying, so the agent can find the owning process and binary hash through `sock_diag` while it's still trying. |
| Windows host | The agent enables auditing of blocked connections natively and reads Security 5157, keeping outbound only | Process id, application path, destination, port |
| Segment firewall | The Palo adapter pulls deny entries for outbound sessions every 30 s | Coverage when an implant has killed our agent or disabled the host firewall |
| DNS | The DC's DNS analytical log | Which servers tried to resolve names outside the zone |

### Analysis on the controller

The denied-egress view groups attempts by binary hash and destination:

- **Attempt counts,** first and last seen
- **Timing:** interval mean, jitter and how regular it is. Low variation means beaconing.
- **Spread:** how many hosts are reaching for the same destination, which suggests one implant family across hosts
- **Process lineage and persistence** for each binary, from the trace-back data

The result is a ranked list of likely C2 destinations and the binaries reaching for them. Each row can start a response recipe or an IR draft.

### Sinkhole (Linux)

- **How it works.** Denied outbound TCP from servers is redirected by nftables to a catcher the agent runs on a loopback port. The catcher completes the handshake and records the first bytes the implant sends, up to 16 KB or 10 s.
- **HTTP beacons:** it records the method, path, headers and user agent, then answers with a plain 404 and closes. These often identify the framework outright.
- **TLS:** it records the ClientHello (SNI, ALPN, JA4) and closes without completing the handshake.
- **Anything else:** raw first bytes, then close.
- **It never** sends meaningful responses, never connects anywhere, and never runs anything it receives. It's entirely on our own host, which keeps it inside the rules.
- **Windows** can't redirect connections without a driver, so it gets denied-egress logging only.

**Complexity flag:** the sinkhole adds a loopback listener and redirect rules. It's bounded by being Linux-only, record-only and size-capped.

### Gaps

Egress filtering does nothing against inbound command channels: a webshell on a scored port, or a bind shell. Those are covered by process-lineage detection (D1), change trace-back and the packet ring.

## Service monitoring: capture and health checks

Two independent systems watch the services. **Capture** is passive: every host records its own traffic into a packet ring, and ships flow records and parsed protocol transactions continuously. It feeds check discovery, traffic labeling, trace-back and IR. The **active checker** runs the active checks described in the next section. Neither sits in the path of scored traffic.

### Capture tiers

| Tier | Contents | Lives on | Shipped |
| --- | --- | --- | --- |
| Full packets | Every packet. Full length on scored ports, decoy ports and sinkhole traffic; first 128 bytes elsewhere. | Host packet ring: the smaller of 2 GB or 10% of free disk | On request as a filtered time slice; automatically around alerts |
| Flow records | One record per connection: endpoints, ports, start and end, bytes and packets each way, handshake result, resets, timeouts, hashes of the first bytes each way, owning process when known | Agent spool | Continuously |
| Transactions | Parsed exchanges on declared service ports: HTTP requests and responses, mail and FTP command transcripts, DNS questions and answers, and so on | Agent spool | Continuously |

### Capture mechanics

- **Linux:** AF\_PACKET with a memory-mapped ring, one socket per interface. Kernel filters are built in Go from the manifest (`x/net/bpf`), with no libpcap.
- **Windows:** one raw socket per interface with `SIO_RCVALL`. It needs no driver, but only sees the IP layer.
- **Complexity flag:** two things about Windows capture need proving in the lab before we rely on it: whether outbound packets are fully captured, and how it behaves alongside Windows Firewall. If coverage is partial, Windows services fall back to logs (IIS, DNS analytical, FTP) for transactions, and capture is used for flows only.
- **Bounded and passive.** Under load the agent drops packets rather than slowing the host, and reports drop counts so you know when coverage was partial.
- **Scans are aggregated.** One "source X touched N ports" record, not thousands of flows.
- **No feedback loop.** The agent's own traffic to the controller is excluded.
- **Freeze on alert.** Any alert freezes the ring from 5 minutes before to 10 minutes after for the hosts involved, so rotation can't overwrite the evidence. The controller pulls that slice automatically, filtered to the IPs involved.
- **Source-address check at drop flag.** Host capture can only fingerprint the scorer by source if the Palo preserves source addresses on inbound NAT. The controller compares captured sources with the Palo's traffic logs in the first minutes, and warns loudly if every inbound connection appears to come from the firewall. In that case it switches to recovering sources from the Palo's traffic logs (§ Risks).

### What full packets add

- **Unknown protocols:** raw reverse shells, custom implant protocols, anything without a parser. You can read what the attacker typed and what came back.
- **Asking questions later:** pull the last hour of packets for a host to the controller and open them in Wireshark there, for protocols nothing parses yet. Wireshark is a host tool on the trusted controller, like Typst.
- **Turning real requests into checks:** the exact request the scorer sent, ready to base an active check on.
- **Recovering dropped tools** from plaintext transfers, and hashing them.
- **Debugging our own failures:** resets, handshake errors, malformed responses.
- **IR evidence:** the credentials actually used, commands sent and data taken.

### Protocol parsers

All are Go-native, built on passive TCP reassembly, and each is isolated so a parser bug only affects its own protocol.

| Phase | Parsers |
| --- | --- |
| 1 | HTTP/1.x; SMTP; POP3; IMAP; FTP control channel with data-channel linkage; DNS over UDP and TCP |
| 2 | TLS handshake metadata (SNI, ALPN, JA4, certificate); NTP; TFTP; SSH banners; generic first-bytes fingerprint for unknown protocols, so a service added by an inject is fingerprinted before anyone writes a parser |
| 3 | LDAP binds and searches and Kerberos metadata (for cross-segment dependencies like POP3 → AD); file carving from HTTP and FTP transfers |

**HTTPS.** Passive capture can't see inside modern TLS. For HTTPS services we get handshake metadata from packets, request details from the server's own access logs (custom formats set by hardening), and response content from active checks requesting the same pages.

### Palo-side capture (phase 3)

The Palo can capture packets on a filter and serve them through its API. The adapter turns that on for a chosen service and window and pulls the result. This shows traffic that never reached the host, which settles "is the scorer even getting through?" without guessing. **Complexity flag:** PAN-OS packet capture has its own limits and can load the firewall. It's used on demand only, never left running.

### Active checks

The active checker and check discovery are one feature, described in the next section.

## Active checks and check discovery

The platform keeps a live, editable list of **active checks**: our own end-to-end tests of each service. Scorer checks change during the competition, so the list isn't set up once. The platform watches scorer traffic passively and keeps the list in step:

- it proposes a new check when the scorer starts testing something we don't cover
- it flags a check the scorer seems to have stopped using

Operators add, edit, pause or retire checks at any time from the UI.

### Active checks

- **Run by** the checker module in the controller every 30–60 s per check, from the controller and from `check_runner` agents inside each segment.
- **Check types:**
  - HTTP and HTTPS fetch with status and normalized content hash
  - SMTP send, then POP3 or IMAP retrieval of the same message
  - DNS query with expected answers
  - FTP listing and file hashes
  - TFTP fetch with hash
  - NTP query
  - TCP connect with banner match
- **Each check has:** a service, a type, its parameters (path, account, record, file), the expected result, an interval, its vantage points, an origin (`manifest`, `discovered` or `manual`), a state (`active`, `paused`, `retired`) and its result history.
- **Managed in the UI:**
  - Add a check from a template, or from any observed request with **Make this a check**.
  - Edit parameters and expected values.
  - Pause or retire a check.
  - After a legitimate change (an inject that edits a page, for example), click **Accept current response** to reset the expected result.

  Every change is written to the manifest overrides and takes effect immediately, with no restart.
- **Results:** a check turns red after 2 consecutive failures, to avoid flapping. A red check opens an alert with the response diff and the latest trace-back for that service attached.
- **Two vantage points, side by side.** Red from the controller but green from inside the segment points at the firewall path, not the service. Neither is the scorer's own position, so green is evidence, not proof.

### Check discovery

1. **Recognize scorer traffic.** Scorer traffic tends to sweep most services within a short window, repeat on a rhythm, and keep the same client fingerprint and accounts. Those signals label it `scorer`, a label traffic labeling also uses. Source IP is a hint, never a rule.
2. **Group its requests per service** into observed checks, with variable parts templated. Rotating POP3 users or product IDs become one check with a set of values.
3. **Compare against the active list:**
   - **Not covered:** a proposal, "Scorer started checking X", with a sample request and a pre-filled check. Accept, edit or reject with one click.
   - **Covered, but the request changed:** a proposal to update the existing check.
   - **Active check with no scorer counterpart for 5 rounds:** flagged as possibly stale, with a suggestion to pause it. Nothing is ever removed automatically.
4. **Mark scored accounts.** Any account the scorer authenticates with is marked `scored`, so credential rotation for it goes through the support-ticket workflow.
5. **Spot blocked checks.** If a round reaches the other services but no scorer traffic reaches one of them, that's an upstream block. An alert fires with the Palo's deny logs for that window attached.

**Rules of engagement.** Discovery is strictly passive. We observe what the scorer sends to our hosts, and never connect to, scan or probe its addresses; the packet treats that as grounds for disqualification. We also never break a scored service on purpose to see what the scorer does.

### The checks view

Per service, two columns side by side:

- our active checks, with their latest results
- the scorer checks observed recently, with when each was last seen

Each pair is marked **matched**, **proposed** or **stale**. Below that is a change feed of every scorer check that appeared, changed or went quiet, newest first.

**Complexity flag:** recognizing scorer traffic is heuristic. It's bounded by requiring a human click for every proposal, and by acceptance tests against the scorer simulator's ground truth.

**Deliberately out of scope:** learning the scorer's pass criteria from NISE, byte-exact replay of scorer traffic, and keeping scorer profiles across seasons. These are listed in the complexity register.

## Traffic labeling, change detection and trace-back

Every connection to our services is labeled scorer, us or other. Any change to a service is detected within a minute. Each change our own plans didn't make starts an automatic trace-back: from the changed thing, to the process that changed it, to the network request that drove that process, to the source and everything else it did. The result is an incident timeline, ready for an IR report.

### Traffic labels

| Label | How it's assigned |
| --- | --- |
| `us` | Our active checker, agents, relays and device adapters. Known sources and connection types. |
| `scorer` | Learned by check discovery: round participation, rhythm, client and stack fingerprint, scored accounts |
| `other` | Everything else: orange-team users, traffic generators and the red team. Within it, `attack-like` is flagged by detections: scans, exploit payloads, webshell requests, decoy hits. |

Red-team sources learned from decoy hits and detections are tagged as such, so later connections from them are labeled on sight. The red team won't always look malicious and may imitate the scorer, so the working question is "is this neither the scorer nor us?" When something changes, `other` traffic to that service is where to look first.

### What counts as a change

| Change | Detected by |
| --- | --- |
| Served content on disk (webroots, FTP root, zone data, mail store structure) | `fim` with hashes |
| What the service returns | Active checks, and our answers to scorer requests |
| Configuration (Apache, IIS, PHP, Postfix, Dovecot, DNS, `.htaccess`, `auto_prepend_file`) | `fim` |
| Runtime behavior: new child processes, listeners, outbound connections or loaded modules under the service | `proc`, `net`, Sysmon 7 |
| Identity: accounts, groups or permissions the service depends on | `fim` on account files; Security events on Windows |
| Network devices: rules, NAT, admins | Device adapter config diff |

Changes made by our own plans carry the plan's tag and quietly update the baseline. Anything untagged raises an alert.

### The trace-back chain

Triggered automatically by any untagged change, red health check, or high-severity detection on a service:

1. **The change.** For example, `index.php` modified at 14:03:12.
2. **The writer.** The file event gives the writing process (fanotify or audit on Linux, Sysmon 11 on Windows).
3. **Its lineage.** For example, `sh` ← `apache2` worker (running mod\_php) ← `apache2` parent, from the agent's process records.
4. **The request.** The agent maps the worker to the client connection it was serving at that moment, and the transaction log gives the parsed request (for example, the webshell POST). How the mapping works depends on the stack:
   - **The worker owns the client socket** (Apache prefork with mod\_php, most simple daemons): the agent's socket records give the connection directly.
   - **php-fpm behind Apache or nginx:** the worker holds only the FastCGI socket. The agent follows it to the front-end process. If that process serves one connection at a time, the match is exact. If it serves many (Apache's event MPM, nginx), the match is by time and script path in the transaction log, marked lower confidence.
   - **IIS:** http.sys in the kernel accepts every connection, so socket tables and Sysmon 3 show PID 4, not `w3wp`. Hardening adds the client port (`REMOTE_PORT`) to the IIS log fields. The agent maps `w3wp` to its site through its application pool, matches the request by time and path in that site's log, and the client address and port then give the exact connection.
5. **The source.** That connection's source address and its label.
6. **Everything else from that source:** earlier transactions, scans, login attempts and decoy hits, across every host. This usually reveals first contact and the foothold.
7. **Evidence.** The packet ring around the window is frozen and pulled, and files involved are hashed and collected.

The output is an incident: an ordered timeline ending at the change, with sources, accounts, files, hashes and evidence attached. It's ready for the IR drafter.

### Where the chain breaks

When the chain breaks, the timeline says which link is missing instead of guessing:

- **Encrypted traffic:** HTTPS request details come from server logs only.
- **In-memory changes** with no file write are visible as behavior changes, but there's no writer to trace from.
- **Agent gaps:** periods when the agent was down are marked on the timeline.
- **Short-lived processes and quick requests:** the link from worker process to connection depends on sampling being fast enough. On Linux the agent queries sockets at the moment of the exec or file event, not only on the 2 s timer. On IIS, the log match above doesn't depend on sampling, but it's only as precise as the log timestamps (one second).

**Complexity flag:** the request link (step 4) is the hardest part of the feature. It has a dedicated lab test with quick webshell requests. If it misses too often, the fallback is time-window correlation (requests to that service from `other` sources in the seconds before the change), marked as lower confidence.

## Detection and response

Detections favor behavior and allowlists over signatures, because the red team can read our rules. They run on the host, so they fire with the link down. Responses come in three tiers by reversibility. Only reversible actions on unscored state run automatically, and every automatic action is followed by a health check.

### Detection catalog

| ID | Detects | Data | Logic | Tier |
| --- | --- | --- | --- | --- |
| D1 | Service process spawns a shell or tool | `proc`, Sysmon 1 | Parent in a scored service's tree; child not in its profile, or any shell, interpreter or download tool | 1 |
| D2 | Content or config tampering | `fim`, health checks | Untagged change in a content root or service config; new script-extension file in a webroot | 0 if it matches a webshell signature, else 1 |
| D3 | New listener | `net` | Listening socket not in any service, decoy or profile | 1 |
| D4 | Unexpected outbound connection | `net`, Sysmon 3, Palo traffic | Established connection from a server process to a peer outside its declared dependencies | 1 |
| D5 | Fileless or hidden execution | `crossview`, Sysmon 8 and 25 | Deleted or memfd executable; `LD_PRELOAD`; anonymous executable memory in non-JIT processes; remote threads; process tampering | 1 |
| D6 | Persistence created | `fim`, audit, Security 4697, 4698 and 4702, System 7045, Task Scheduler 106, Sysmon 12–14 and 19–21 | Any untagged write to a persistence location (appendix) | 0 (disable) |
| D7 | Account changes | `fim` on account files; Security 4720, 4722, 4724, 4738, 4728, 4732, 4756, 4781 | Account created, enabled, renamed, reset or elevated outside our plans | 1 |
| D8 | Credential theft | Sysmon 10 and 1; Security 4662, 4768, 4769 | LSASS read by a non-allowlisted process; hive dumps; `ntdsutil` or shadow copies on the DC; DCSync (4662 replication rights from a non-DC); RC4 ticket bursts; pre-auth-disabled ticket requests | 1 |
| D9 | Lateral movement and remote admin | Security 4624 (types 3, 10), 4648, 5140; Sysmon 17 and 18; auth logs | Any admin logon from a source other than the controller after rotation; admin-share access; remote service creation; PsExec-style pipes; SSH or WinRM appearing when not declared | 1 |
| D10 | Defense evasion | Audit, ruleset hash every 10 s, Firewall operational log, Defender 5001 and 5007, Security 4719 and 1102, System 104, Sysmon 4 and 16, heartbeat gaps | Firewall changed or disabled; Defender protection disabled or new exclusion; audit policy changed; logs cleared; Sysmon stopped; agent silent | 0 (restore) and 1 |
| D11 | Rootkit indicators | `crossview`, Sysmon 6 | Hidden PIDs, sockets or modules; unexpected BPF programs; kernel taint change; unsigned or new driver | 1 |
| D12 | Denied egress | `egress`, Palo deny logs | Any denied outbound attempt from a server; periodic attempts escalate | 1 |
| D13 | Sinkhole catch | `sinkhole` | Any capture; HTTP or TLS beacons with framework fingerprints escalate | 1 |
| D14 | Network device tampering | Adapter config diff, Palo config and system logs, VyOS logs | Commit we didn't make; unknown admin login; diff against last known-good | 1 |
| D15 | Decoy interaction | `decoys`, DC events, service logs | Severity by depth: connect (info), login or command (high), honey credential or key used anywhere (critical) | 1 |
| D16 | Scorer check change | Check discovery | New, changed or stale scorer checks; scorer traffic missing for a service | Info to operator |
| D17 | Service change | Change detection | Untagged change to a scored service's content, config, behavior or identity, with trace-back attached | 1 |

Every rule in the repo carries an ATT&CK mapping, its test case, its tier and its IR template. CI rejects a rule without a test.

### Response tiers

| Tier | Who decides | Actions |
| --- | --- | --- |
| 0: automatic | The agent, locally, in seconds, even with the link down | Restore the declared host firewall; re-enable Defender protection and remove new exclusions; reinstall or restart Sysmon and restore audit rules; disable (never delete) untagged scheduled tasks, cron entries, units and Run keys; quarantine a new webroot script that matches a webshell signature |
| 1: one-click | Operator in the UI, with the evidence on screen | Kill a process tree; quarantine a file; block a single source IP on the Palo; lock an unscored account; kill sessions; restart a service; restore a file from baseline or backup; roll back a plan node |
| 2: manual with checklist | Operator, with a verbal callout to the team | Scored-account rotation (ticket first); krbtgt reset; full service restore; device config revert; requesting a VM reset (costs points) |

### Guards on automatic actions

- **Protected processes** are never killed: OS-critical processes (`csrss`, `wininit`, `winlogon`, `services`, `smss`, `lsass`, core `svchost` instances, `systemd`), the sshd listener if declared, our agent, and anything inside a scored service's declared tree.
- **Scored accounts** are never touched automatically.
- **Rate limit:** at most 3 tier-0 actions per host per minute. Beyond that, they become tier-1 proposals.
- **Circuit breaker:** if a health check goes red within 2 minutes of a tier-0 action, that action type is disabled on that host and escalated.
- **Loop detection:** the same restore 3 times in 10 minutes opens an incident and a targeted hunt on the culprit's lineage, instead of restoring forever.
- **Locks and safe mode** apply (§ Execution).

### Response recipes

| Trigger | Collected automatically | Proposed actions | IR template |
| --- | --- | --- | --- |
| D1 or D17 via webshell | Trace-back timeline, process tree, content diff, transactions from the source ±10 min, ring slice | Kill tree, quarantine file, block source IP, hunt persistence by the web user, rotate unscored app and DB credentials | Web application compromise |
| D7 | Creating session and its source | Disable account, kill sessions, review group memberships | Unauthorized account |
| D10 firewall disabled | Lineage of the disabler, recent persistence | Tier 0 restores; propose disabling the trigger | Defense evasion |
| D12 or D13 | Owning process, binary hash, sinkhole capture, persistence | Kill, quarantine, remove persistence, hunt the same hash on all hosts | Malware callback |
| D8 | Source account and host, logon session, tools seen | Disable source account, plan credential resets (ticket for scored ones), krbtgt double reset | Credential compromise |
| D14 | Config diff, admin session | Revert to known-good, rotate device admin | Network device compromise |
| D15 with a honey credential | Token origin (which host was looted, when), every use of the token | Treat the origin host as compromised; hunt it; rotate real credentials stored nearby | Credential theft from host X |

### Audit trail

Every action, automatic or manual, writes an event: what triggered it, before and after state, the undo, and the health result afterwards. This is the containment section of every IR report, and the answer when the White Team asks why something changed.

## Deception

Three kinds of deception turn red-team curiosity into precise, low-noise alerts:

- **Honeytokens:** fake credentials, keys and paths, unique per host, planted where attackers loot.
- **Decoy services:** fake SSH with a full fake shell, and other bait ports, reachable from inside the segment and from outside.
- **Decoy content:** honey files and web paths that nothing legitimate ever touches.

A token's origin tells you which host was looted and roughly when.

### Principles

- **Declared like services.** Decoys are listed in `decoys.yml`. Host-firewall and Palo rules are generated for them. They're the deliberate exception to "no inbound".
- **Isolated.** All decoy listeners and the fake shell run in the agent's unprivileged decoy process (§ The agent).
- **Record only.** Nothing received is ever executed. Decoys never connect back, and never touch red-team infrastructure.
- **Never on scored ports,** and never change any content the scorer fetches.
- **Generated at competition time.** Token values, banners, honey paths and fake data are generated by `phylax` when the plan runs. The pools and the fake shell's code are in the public repo, so a red teamer who studies it can recognize some decoys, for example a honey filename taken from `pools/`. What the repo can't reveal is the per-host values: which credentials, keys and unguessable paths are planted where. Pools stay large and realistic so that matching against them is slow and inconclusive, and the deception design assumes a careful attacker spots some decoys.
- **Severity follows depth.**
  - **Info:** connecting.
  - **High:** logging in or running commands.
  - **Critical:** using a honey credential or key anywhere, because only someone who looted a host has it.

### Honeytokens

Every token is unique to its host and recorded in the controller's token registry (where, when, what). A sighting anywhere is matched back to its origin.

| Token | Planted at | Sighted when it shows up at |
| --- | --- | --- |
| Fake SSH private key (e.g. `/root/.ssh/id_rsa_backup`) | Each Linux host | The SSH decoy recognizes its fingerprint |
| Fake DB or app credentials | `.env` files, config backups, `web.config` connection strings | Logins to MySQL, decoy services, the web admin page |
| Fake shell history with an inline password | Root and admin home directories | That password tried anywhere |
| Decoy credential in LSASS (a `runas /netonly`-style logon session kept alive by the agent) | Windows servers | Failed authentication for that account on the DC (4625, 4771), meaning LSASS on that host was dumped |
| Honey AD accounts: one with an SPN, one with pre-auth disabled, one that looks like an admin | DC, in a separate OU, no mailboxes | Ticket requests (4769, 4768) or any logon attempt |
| Honey OpenCart admin with a unique password | ecom database | That login attempted on the admin page |
| Honey DNS record that nothing uses | DNS zone | Any query for it, meaning the zone was enumerated. Zone transfer attempts are logged too. |

**Complexity flag:** the LSASS decoy session needs the agent to keep a logon session alive on each Windows server. It's worth it, because it's one of the few ways to tell that LSASS was dumped. If Defender or a reboot kills it, the agent recreates it.

### Decoy services

| Decoy | Behavior |
| --- | --- |
| SSH on 22 (where real SSH is disabled) | Full fake shell: accepts a login after a few attempts (or any honey key), presents a believable filesystem and command set, records every keystroke and command, never executes anything. Banner and host details randomized per host. |
| MySQL, Redis, Telnet on hosts that don't run them | Protocol-correct handshake and login prompts; credentials recorded |
| WinRM (5985) and RDP (3389), on hosts where those services are off | Connect and negotiate only; credentials recorded where the protocol offers them |
| Fake admin web panel on an unused port | Login page that records every credential tried |

There's no SMB decoy: Windows holds port 445 on every host, and the DC needs it.

**Complexity flag:** the full fake shell is the largest decoy by far. It's isolated in the unprivileged process, has no real filesystem or command execution behind it, and has its own fuzz tests in CI.

### Decoy content

- **Honey files** (`passwords.xlsx`, `backup.sql`, `id_rsa_old`). Opening one alerts: fanotify on Linux, file auditing (4663) on Windows.
- **Honey web paths** in each webroot as separate files (`/backup.zip`, `/.git/config`, `/admin-old/`), plus unguessable paths mentioned only in breadcrumbs. Hits on bait names are context; hits on unguessable paths mean someone followed a breadcrumb.

### Exposure

- **Inside the segment:** a connection from one of our own servers to a decoy means that server is compromised and the attacker is moving sideways.
- **Outside, through the Palo:** decoys are reachable on public addresses, so the red team finds them while probing from outside. Their source IPs are tagged as red team, which feeds traffic labeling.
- **Noise:** the packet says traffic generators can send suspicious traffic from random IPs, so some outside hits won't be the red team. That's why bare connections are info-level, and blocking stays one click rather than automatic. The block action double-checks the IP against learned scorer sources, although the scorer has no reason to touch decoys.

## Prebaked implant hunting

Every team starts from identical images of known OS versions. We build clean reference VMs of the same versions in the lab, record their known-good state, and diff each live host against it in the first 15 minutes. Anything added to or changed in a system location is suspect until explained. The diff runs as Go-native collection actions, without trusting host tools.

### Reference builds

One scripted build per OS version announced for the season (Packer templates in the lab repo), with the same roles the competition hosts run. Each build records:

| Artifact | Linux | Windows |
| --- | --- | --- |
| File inventory with hashes | `/usr`, `/bin`, `/sbin`, `/lib*`, `/etc`, `/opt` | `System32`, `SysWOW64`, `drivers`, `Program Files` |
| Ownership and signing | Which package owns each file | Authenticode signer for every executable |
| Autostarts | Enabled units and timers, generators, cron, at, rc, profile.d, motd, udev, PAM, NSS, loader config | Services, scheduled tasks (XML), Run keys, WMI subscriptions, LSA packages, IFEO, and the rest of the appendix list |
| Accounts | passwd, group, sudoers | Local users and groups |
| Kernel | Modules, sysctls, BPF programs | Drivers with signers |
| Service config | Distro defaults for Apache, PHP, Postfix, Dovecot, MySQL | Clean IIS and FTP config |

References ship as signed release assets, not in the repo, because of their size.

### Package verification without host tools

Patch levels on the competition images may differ from our builds. Package metadata closes that gap natively:

- **Debian and Ubuntu:** the agent reads the per-package checksum lists under `/var/lib/dpkg/info/` and hashes files itself.
- **Fedora and Oracle:** recent RPM databases are SQLite files, which the agent reads with its own SQLite library.

Modified packaged files, including changed config files, show up regardless of patch level. The reference diff then covers what packages can't: unowned files, autostarts and unsigned binaries.

### Live hunt

The hunt is a read-only plan that runs on every host in parallel with credential rotation. Target: results in the UI by T+15 min.

1. **Collect** the same artifacts natively.
2. **Diff** against the reference: added, modified and missing items.
3. **Enrich** each finding with hash, signer, owner, package, file times (watching for timestomping), and what references it.
4. **Score:**
   - **High:**
     - an unsigned or non-vendor binary referenced by any autostart
     - an unowned file in a system directory
     - a modified packaged binary
     - `/etc/ld.so.preload` content
     - a new PAM or NSS module
     - IFEO debuggers; LSA packages
     - a non-stock IIS module
     - `ServerLevelPluginDll` on the DNS service
   - **Medium:** added cron, timer or task with a script action; new SUID file; added SSH key; modified default config.
   - **Low:** everything else that differs.
5. **Review** in the UI as a queue. Approved items become a remediation plan that disables and quarantines (moves, with metadata) but never deletes. Quarantined files are IR evidence.

### Application references

| Component | Reference | Check |
| --- | --- | --- |
| OpenCart | Vendor archive for the detected version | Hash every webroot file. Unknown scripts and modified core files go to the top of the queue. |
| Postfix | Package defaults | `master.cf` pipe transports and content filters; `/etc/aliases` command pipes |
| Dovecot | Package defaults | Post-login scripts, global sieve scripts, passdb and userdb pointing at scripts |
| MySQL | Package defaults | User-defined functions, plugin directory, accounts with FILE or SUPER |
| IIS and FTP | Reference config | Modules, handlers, ISAPI filters, virtual directories, FTP custom providers |
| Splunk | Splunk's own file manifest | Files differing from it; non-stock apps |

### Active Directory

There's no clean reference for a domain the competition built, so the DC's agent runs generic LDAP checks:

- members of every privileged group, and accounts with `adminCount=1` outside them
- SPNs on user accounts; unconstrained, constrained and resource-based delegation
- `msDS-KeyCredentialLink` and SID history
- non-default access-control entries on AdminSDHolder and on the domain object, especially replication rights
- every GPO with its links, modification time and contents (tasks, scripts, registry preferences)
- `krbtgt` password age, machine account quota, DnsAdmins membership

### The firewall-killer

Red teams often plant something that disables host firewalls on a timer. The hunt should find its trigger. If it doesn't, D10 catches the execution and records the parent lineage. Three restores in 10 minutes open an incident and a targeted hunt on that lineage.

### Keeping the baseline current

Accepted findings and inject changes go into overrides as the host's live baseline. Later hunts diff against reference plus overrides.

## Network devices and credentials

Network devices are managed agentlessly by adapters inside `phylax`, reached directly or through the device-proxy role in their segment. Credentials are generated at competition time, held in the controller's vault, and rotated by plans in dependency order. Scored accounts are learned from the scorer and protected.

### Device adapters

Every adapter implements the same operations:

| Operation | What it does |
| --- | --- |
| `rotate_admin` | Change the admin password and create a dedicated API account, so the tool isn't using the human's login |
| `snapshot` | Export the running config (at first contact as "as found", and after every change we make). Also save a named copy on the device itself for fast revert. |
| `apply` | Render rules, objects and NAT from the manifest, push as a candidate, commit |
| `drift` | Every 5 minutes, diff the running config against the last known-good; alert on any commit we didn't make |
| `logs` | Pull traffic, threat, system and config logs every 30 s |
| `capture` | On-demand packet capture on a filter (Palo, phase 3) |
| `revert` | Load the last known-good snapshot and commit |

**Palo Alto.** Uses the PAN-OS XML API through Palo Alto's Go client (`pango`). Ansible and Python are gone from the controller.

- Every rule and object we create carries a `phylax-managed` tag, and the adapter only ever edits tagged items. Anything untagged is either the red team or a teammate's manual inject change, and drift flags it for adoption or removal.
- PAN-OS has no commit-confirm, so management-path rules are never changed in the same commit as anything else, and every generated policy is tested in the lab first. The console is break-glass.

**VyOS.** SSH with the Go SSH client. Every change uses VyOS's `commit-confirm`, so a change that cuts us off reverts by itself. The hunt also checks for VyOS persistence: task-scheduler entries, scripts under `/config/scripts`, extra users, static routes, NAT and policy routes.

**Other vendors** (FTD, Fortinet, pfSense, Cisco) get adapters only when an infra actually includes them. An unknown device falls back to console management, a printed checklist, and hand-taken config snapshots.

**Reaching devices.** A device in the controller's segment is reached directly. A device in another segment is reached through a `device_proxy` host there (§ Topology), with the device's management address on that host's allowlist. Device management access lists allow only the controller or the proxy host's address.

**First contact** with network devices stays manual: change the admin password on the console in the first minutes. Then the adapter takes over with the new credentials.

### Credentials

**Inventory.** Every account in `accounts.yml`, plus whatever discovery finds: local accounts on every host, domain accounts, and service and app accounts (MySQL, OpenCart admin, Splunk, network devices). Each has a `scored` flag (declared, or learned from the scorer), a rotation policy, and the files and services that embed it.

**Generation.**

- Passphrases of four or more words plus digits, generated by `phylax` at competition time, easy to type on a console.
- Held in the vault, in memory once unlocked. Never in the repo, never in logs, masked in the UI until revealed.
- A printed sheet is allowed as reference material.

**Rotation order:**

1. **T+0–5 min, by hand on consoles:** network device admins. These hold the network.
2. **T+2–10 min, first-contact plans with the dead-man switch:** root and admin accounts on every host, the domain administrator, then our own admin accounts.
3. **T+10–30 min:** unscored service and app accounts. Each rotation updates the files that embed the credential in the same plan, then runs a health check.
4. **Scored accounts:** only through the competition's password-change policy. `phylax` drafts the support-ticket text (team number, service, account, new value as required). Rotation is held until the ticket is acknowledged.

**krbtgt.** A double reset invalidates forged tickets. With a single DC there's no replication delay, but every existing Kerberos ticket dies. Test in the lab whether AD-backed POP3 and domain FTP survive it, and run it right after a scoring round passes.

**After rotation.** Any successful admin authentication from a source other than the controller is a D9 alert, because no legitimate actor has those credentials anymore.

## Controller

The controller is one Go process. It keeps everything in one SQLite database and a directory of encrypted evidence files. Secrets live in an encrypted vault and are held in memory only after the passphrase is entered. The web UI is server-rendered, bound to localhost, with one login. It includes a platform-health view so a degraded platform is never mistaken for a quiet network.

### Processes and ports

| Process | Listens on | Role |
| --- | --- | --- |
| `phylax serve` | `agent_port` on the controller's address (agents, relays, splices, patch streams, bootstrap); `127.0.0.1` for the UI | Everything, including the active checks |

### Storage

- **SQLite** in WAL mode, pure Go, one file. Events, incidents, plans, specs, flows and transactions go here, plus full-text search over transcripts and command lines.
- **Evidence directory:** pcap slices, collected files, memory dumps, sinkhole captures. Each file is encrypted at rest with `age` to the controller's key and referenced from the database by hash.
- **Retention:** indefinite, as decided. The UI shows free disk space and warns at 70% and 85% used. If space runs short, the first lever is compressing raw transaction bodies older than a day.

### Secrets

- **The vault** is one `age`-encrypted file: device and host credentials, generated passwords, honeytoken values, the controller's private keys and the plan-signing key.
- **Unlocking:** the passphrase is entered in the UI after every start. Decrypted values exist only in memory.
- **Credentials seen in traffic** (for example the scorer's POP3 password in a transcript) are encrypted field by field before storage and masked in the UI until revealed. **Complexity flag:** this means parsers must mark which fields are credentials. It's kept because the alternative is a plaintext database full of passwords on the box everyone wants.

### Data model

One set of core records, so the same thing seen by different sources is one thing:

| Record | Identity |
| --- | --- |
| Host | Manifest name + enrolled key |
| Service | Manifest name |
| Process | Host + PID + start time (PIDs get reused, so start time disambiguates). Sysmon's process GUID is kept as an alias on Windows. |
| Connection | Host + 5-tuple + start time |
| File | Host + path, with a hash history |
| Account | Scope (local, domain, app, device) + name |
| Source | IP address, with labels (scorer, red, us, other) and fingerprints |
| Change | The changed record + before and after |
| Alert | Rule + host + key records |
| Incident | A set of alerts and changes with a timeline |

Correlation joins on these identities, never on loose text matching.

### Web UI

- **Built with** Go templates plus htmx, live updates over Server-Sent Events. All assets are vendored and embedded in the binary; no CDN, no Node at runtime.
- **Plan DAGs** are laid out in Go and rendered as server-side SVG. That avoids a JavaScript graph library and keeps the Content Security Policy strict.
- **Access:** bound to `127.0.0.1` only. One login, with the password set at first start, an HttpOnly and SameSite=Strict session cookie, and CSRF tokens. All the output-escaping rules from the trust model apply.

| Page | Shows |
| --- | --- |
| Overview | Hosts, services, open incidents, scorer status, safe-mode switch |
| Plans | Templates, the plan DAG with live node status, diffs, approvals |
| Alerts and incidents | Queue, evidence, trace-back timelines, one-click actions, IR draft button |
| Checks | Active checks (add, edit, pause, retire), scorer checks observed, proposals, change feed |
| Services | Health checks from each vantage point, content history, changes |
| Traffic | Flows and transactions with labels; packet slices; freeze and pull |
| Egress and C2 | Denied attempts by binary and destination; sinkhole captures |
| Deception | Decoy hits, honeytoken registry and sightings |
| Hunts | Baseline-diff findings queue |
| Devices | Palo and VyOS snapshots, diffs, logs |
| Platform | Self-health (below) |
| Settings | Manifest overrides, adoption queue, secrets unlock |

### Platform self-health

For each agent:

- link state, and lag behind the controller
- spool depth
- capture drop counts
- clock offset
- which modules are running or failed
- whether it's in safe mode

For each relay: connections spliced, bytes and errors. For the controller: CPU, memory, disk, database size, and the time of the last state snapshot. Anything degraded shows on the overview page, not just here.

### Backing up the controller

Encrypted state snapshots (keys, vault, manifest, enrollments, plans and incidents, but no event data) go to the backup targets declared in the manifest every 15 minutes and after every key or vault change. Restore needs only the passphrase and starts a new epoch (§ Enrollment).

## Service backups, IR drafter and inject kit

Service data is backed up by agent actions and pulled to the controller, so restores never depend on a compromised host's own copy. Incidents become IR drafts with one click, and inject deliverables come from templates and manifest-generated facts. Both render to PDF.

### Service backups

| Kind | When | Use |
| --- | --- | --- |
| As-found | T+5–10 min, before any remediation | Forensic evidence. Never restored blindly; it may contain implants. |
| Golden | Right after each service's hardening passes its health checks | The restore point for that service |
| Periodic | Every 30 min for changing data (database, mail, uploads) | Keeps restores from losing orders and mail |
| Pre-change | Before any tier-2 action | Undo for big changes |

- **What's included** comes from each service's `content`, `data` and config entries in the manifest.
- **Native where possible:** archives and file copies in Go, database dumps through the MySQL driver, IIS config read directly. DNS zone export may need `host.exec` of `dnscmd` until a native path is proven. **Complexity flag:** native MySQL dumps reimplement part of `mysqldump`. Test them against a real restore before trusting them.
- **Pulled** to the controller as chunks and stored with the evidence (encrypted at rest).
- **Restores** are plan templates per service, with times measured in the lab and recorded in the manifest:
  1. Stop the service.
  2. Restore content, data and config from the chosen backup.
  3. Start the service.
  4. Run the health checks.

### IR drafter

**Input:** an incident, which already holds its trace-back timeline, alerts, sources, accounts, files, hashes, evidence and the response audit trail.

**Sections,** following the packet's requirements:

| Section | Filled from |
| --- | --- |
| Header: team number only, incident id, times in Central time | Manifest, incident |
| Summary | Recipe template sentence, edited by hand |
| Timeline | Incident events with clock offsets applied, Central time with UTC alongside |
| Source and destination | Addresses, ports and protocols from flows and transactions; hostnames from the manifest |
| Accounts and credentials | Accounts used or created; credentials stolen or cracked (D8, honeytoken sightings); what was rotated after |
| Affected systems and services | Hosts and services, and whether scoring was affected (health and scorer history) |
| Technique | ATT&CK ids from the rules, in plain words |
| Evidence | Hashes, log excerpts, packet excerpts, quarantined files |
| Containment and remediation | The response audit trail, plus the recipe's remediation list, edited by hand |

**Rendering.** Markdown with front matter, rendered by Typst (one static binary, on the controller only) to PDF and self-contained HTML.

**Quality rules:**

- One to two pages.
- Report exploitation and unsolicited access only, not scanner noise or configuration findings. The packet penalizes frivolous reports.
- Every claim traces to the incident's evidence.

**Upload path, still open.** NISE is used from a browser. Plan for three routes and test them at the qualifier:

1. A browser on ubuntu-wkst, if NISE is reachable through the proxy.
2. The Nextcloud share as a bridge.
3. The HTML render printed to PDF from a browser on the physical workstation.

### Inject kit

- **Templates** (Typst, team number only):
  - memo, status report, change record
  - policies: acceptable use, passwords and accounts, backup and recovery, logging and monitoring, patching, remote access, incident response
  - plans: disaster recovery, business continuity, incident response
  - risk register
  - framework mappings: NIST CSF 2.0, 800-53, 800-171, ISO 27001 Annex A, CIS v8, CMMC level 2
- **Pre-written drafts** of every policy and plan, with placeholders filled from the manifest at render time.
- **Generated artifacts:**
  - asset inventory
  - network and data-flow diagram, from topology and dependencies
  - port and protocol matrix
  - user and group listing
  - firewall policy summary
  - backup schedule with restore times
  - logging coverage matrix
- **Inject tracker** in the UI: received and due times (Central), owner, deliverable, linked manifest change, status, submitted time.

**Complexity flag:** Typst is a host binary on the controller. It's acceptable because the controller is the trusted host; it isn't shipped to any agent.

## Competition-day operations

The first hour is choreographed: fixed roles, pre-built plans, and one UI showing what's running, blocked and red. The localhost-only UI means the controller console is the team's shared screen. That's the biggest operational constraint in this design, so it's flagged first.

### The one-screen constraint

The web UI is only reachable on ubuntu-wkst itself. Whoever can see that VM's console can drive the platform; everyone else works on other consoles by hand.

- If NETLAB lets several people view the same VM console, the whole team watches one screen and one person drives.
- If not, one person (the platform driver) owns the UI and relays to the room verbally.

**Complexity flag in reverse:** keeping it localhost is the simple choice, and the cost is human bandwidth. If dry runs show the driver becoming the bottleneck, the smallest change is an SSH tunnel from one other workstation to the UI port. That's a deliberate, narrow exception, not remote access in general. Decide after the dry runs.

### Roles

| Role | Owns |
| --- | --- |
| Captain | NISE, inject triage, White Team communication, tier-2 approvals |
| Platform driver | The UI on ubuntu-wkst: plans, approvals, safe mode, re-enrollment |
| Network | Device consoles in the first minutes, then device plans and drift |
| Linux lead | Linux console work and break-glass; reviews Linux hunt findings |
| Windows and AD lead | Windows console work and break-glass; relay host first contact; reviews Windows and AD findings |
| SOC | Alert queue and incidents with the driver; trace-back review; IR drafts |
| Inject writer | Inject drafts and generated artifacts |
| Floater | Health checks, backups and restores, decoy hits, whatever is red |

### First 90 minutes (from drop flag)

| Time | Who | What |
| --- | --- | --- |
| T+0–2 | Captain | Read NISE. Confirm the team number in the manifest. |
| T+0–8 | Network | Rotate Palo and VyOS admin on the consoles. Enter the relay-link rules and the controller's static NAT from the printed checklist. |
| T+0–5 | Platform driver | `phylax init`: fetch and verify the release, set the passphrase, check the controller address, start the UI. |
| T+0–10 | Windows lead | Relay host first contact via the console one-liner, once Network confirms the relay-link rules. |
| T+2–12 | Platform driver | First-contact plans for every host: SSH where possible, WinRM where needed, through the relay for other segments. Agents enroll. |
| T+5–10 | Automatic | As-found backups; capture and check discovery start; source-address check against the Palo |
| T+5–15 | SOC + leads | Hunt plan (baseline diff, package verification, AD checks). Review the queue. |
| T+10–20 | Platform driver | Credential rotation plans (unscored), with the dead-man switch |
| T+10–25 | Platform driver + Network | Firewall plans: shadow mode, review would-be drops, enforce, with health checks |
| T+15–40 | Platform driver | Service hardening plans with health checks. Golden backups as each passes. |
| T+20–45 | SOC | Approve hunt remediations. Confirm Sysmon and all agent modules on every host (Platform page). |
| T+30–60 | Floater | Decoys and honeytokens deployed, including honey AD accounts. |
| T+45–90 | Captain + driver | Review discovered checks: accept, edit or reject proposals |
| Ongoing | All | Incidents, injects, patch windows as needed, periodic backups, drift adoption |

### Day 2 start

- Check the Platform page for every agent's link, gaps and modules.
- Review everything that changed overnight, if the environment kept running.
- Device drift check. Re-run health checks. Confirm the controller snapshot is fresh.

### Human factors

- A printed one-page checklist per role, generated from the manifest.
- A verbal callout before any tier-2 action, and before turning safe mode on or off.
- The captain keeps the list of open incidents and injects due in the next 30 minutes.
- Rotate the SOC seat every 90 minutes.

## Testing and the lab

With AI-assisted development, writing code is rarely the bottleneck. Proving it under realistic conditions is. Every capability is demonstrated in a replica lab, with injected link drops, against a scripted red team, a scorer simulator and an orange-team noise generator, before it goes on the competition checklist. Each milestone spends at least as long in the lab as in the editor.

### Replica lab

- **Proxmox,** matching NETLAB's backend, built by Terraform and Packer from the private lab repo.
- **Topology variants** from the same code, so the static-topology design is tested on more than one shape:
  - flat single segment
  - two segments with NAT (the 2026 shape)
  - three chained segments
  - one segment that allows no outbound at all (to confirm the documented limitation)
- **Hosts** from the reference templates, then contaminated with prebaked implants.
- **Firewalls:** PAN-OS VMs if lab licenses can be obtained, otherwise nftables routers as stand-ins for topology tests only. The Palo adapter needs a real PAN-OS (§ Risks). VyOS as in the competition.
- **Proxy:** Squid with an allowlist, to rehearse release delivery and patch windows.
- **Fault injection** on every router link:
  - random link drops of 5–60 s
  - a forced DHCP change on the controller

### Simulators

| Simulator | Does | Configurable |
| --- | --- | --- |
| Scorer | HTTP and HTTPS content checks against expected files; SMTP send then POP3 retrieve with AD accounts; DNS; FTP file presence; TFTP; NTP. Writes its own ground truth: checks, pass and fail, timing, client fingerprint. | Interval and jitter; sources; adding and changing checks mid-run; pass criteria |
| Orange team | Browses and buys on ecom, sends and reads mail, uses FTP, from many source addresses | Volume; benign versus malicious mix (scanners, credential stuffing) |
| Red team | Scripted campaigns: Sliver, Mythic and Havoc implants; PHP and ASPX webshells; Impacket; Atomic Red Team; decoy probing; honeytoken use | Campaign per scenario |
| Contaminator | Plants prebaked implants in golden images before drop flag | Implant set and timers |

**Prebaked set.**

- **Linux:**
  - cron, timers and a firewall-disabling timer
  - update-motd script
  - PAM backdoor module
  - `ld.so.preload` library
  - PHP `auto_prepend_file`
  - Postfix pipe transport
  - alternate-path `authorized_keys`
  - SUID shell
  - LKM and eBPF rootkit samples (lab only)
- **Windows:**
  - firewall-disabling scheduled task
  - service in a writable path
  - WMI subscription
  - IFEO debugger
  - LSA package
  - IIS native module
  - Run key
  - hidden admin
- **AD:** extra Domain Admin, SPN on a user, RBCD, GPO immediate task, DCSync ACE, `ServerLevelPluginDll`.
- **Network:** VyOS task-scheduler script; an extra Palo admin.

### Test matrix

| ID | Scenario | Pass when |
| --- | --- | --- |
| T01 | Prebaked set present at drop flag | 90% or more found by T+15 min |
| T02 | Timer disables the host firewall | Restored in 10 s or less; trigger identified via loop detection |
| T03 | PHP webshell upload, command, file change | D1 and D17 fire in 10 s or less; trace-back reaches the source IP and request; IR draft in 5 min or less |
| T04 | ASPX webshell on IIS | Same as T03 |
| T05 | Implant callbacks under default-deny egress (Linux) | D12 in 10 s or less; owning process and hash in 60 s or less; sinkhole captures the beacon |
| T06 | Implant callbacks on Windows | D12 with process and path from 5157 in 60 s or less |
| T07 | DCSync from a non-DC account | D8 in 30 s or less |
| T08 | Kerberoasting incl. the honey SPN | D8 and D15 (critical) in 30 s or less |
| T09 | Honey SSH key used against the SSH decoy | D15 critical, naming the origin host |
| T10 | LSASS dump, then the decoy credential used | D15 critical, naming the origin host |
| T11 | Log clear and Sysmon stopped | D10; Sysmon reinstalled; heartbeat intact |
| T12 | LD\_PRELOAD rootkit hiding a process | D11 in 120 s or less |
| T13 | Palo rule added by an extra admin | D14 in 5 min or less |
| T14 | Scorer adds an HTTP path and a DNS name mid-run | D16 and a check proposal within one round |
| T15 | Check discovery accuracy over 2 hours | 100% of the simulator's checks proposed; 0 false proposals; dropped checks flagged stale within 5 rounds |
| T16 | A hardening plan breaks a scored page | Health check red in 60 s or less; one-click rollback works |
| T17 | Link drops during an SSH-disable and firewall-enforce plan; a relay-host firewall change that blocks its segment's agents | Dead-man behaves correctly, including rolling back the relay change; no lockout; no lost node |
| T18 | Controller restart mid-plan | No lost or duplicated events; plan resumes after unlock |
| T19 | VM reset mid-run | Re-enrollment flow; host back to hardened in 10 min or less |
| T20 | Orange-team noise for 60 min | 5 or fewer false-positive alerts per hour |
| T21 | First contact; agent then killed and disabled | Heartbeat in 30 s or less; silence detected in 15 s or less |
| T22 | Relay host killed | Segment marked dark; local detection continues; console restore works |
| T23 | Controller lost mid-plan; restore on another machine from a snapshot older than the last steps sent | Agents reconnect after `set-controller`; no re-enrollment; the restored controller's steps are accepted under the new epoch; spooled events are resent and chain-checked; any remaining gap is marked |
| T24 | Defender on, current definitions | Agent, decoys and the LSASS decoy run without quarantine (or with the single exclusion) |
| T25 | Crafted strings (script tags, terminal escapes) in process names, paths, HTTP paths and decoy-shell input | Nothing executes or renders as markup in the UI |
| T26 | Windows raw-socket capture under load | Measured inbound and outbound coverage; drop counts reported |
| T27 | Console bootstrap on Windows 10, Server 2016 and Linux | Agent enrolls; a wrong controller key aborts before the token is sent; a tampered binary is never run |

### CI

- **Static builds** for both OSes, a size check, and signed artifacts.
- **Unit tests** for every action (check, apply, verify, rollback) against containers for Ubuntu, Fedora and Oracle, and Windows runners.
- **Parser and normalizer tests** from recorded captures; fuzzing for every parser and the fake shell.
- **Rule tests:** each rule has a fixture that must fire and a benign one that must not.
- **Manifest tests:** schema, cycles, the firewall lint, and rendering of every output.
- **UI tests** for output escaping (T25 as an automated test).

### Cadence

- Weekly purple-team session on one scenario.
- A 24-hour soak test per release, on the full lab topology.
- A monthly full dry run with all simulators and fault injection.
- Two full timed dry runs in the final three weeks, in competition roles, with metrics recorded against the success table.

## Build plan

Seven milestones over about 16 weeks. Each ends with its gate tests passing in the lab. Week numbers count from the start of work. Anchor week 16 at least a week before the first competition once its date is known. Nothing goes on the competition checklist until its gate has passed under fault injection.

&#91;embedded content: build plan v2 · 7 milestones over 16 weeks\]

The link and execution work (M1, M2) comes first because every other feature rides on it. Capture, check discovery and deception land by week 14, leaving two dry runs before the freeze.

### Milestones and gates

| Milestone | Weeks | Delivers | Gate |
| --- | --- | --- | --- |
| M0 Foundations | 1–2 | Repo layout, manifest schema v0, written protocol spec, lab replica with fault injection and proxy, PAN-OS lab license request, CI skeleton, scorer simulator v0 | Lab reproduces the 2026 topology; manifest renders a correct firewall policy for it |
| M1 Link and enrollment | 3–6 | Agent link, spool and heartbeat; `phylax serve` with SQLite; TLS pinning and connection types; enrollment; SSH and WinRM first contact; console bootstrap; relay splicing; Platform page | T18, T21, T22, T27 |
| M2 Execution | 5–9 | Core action catalog (files, accounts, services, firewall, registry, persistence cleanup, logging); plans; dry-run diff; DAG in the UI; dead-man; locks; safe mode; Palo and VyOS adapters (apply, snapshot, drift) | Cold-start hardening of all servers (credentials and firewalls in 25 min or less, services by T+40); T16, T17 |
| M3 Telemetry and detection | 7–11 | `proc`, `net`, `fim`, `logs`; Sysmon management; audit ownership; rule engine; tier-0 and tier-1 responses; denied-egress logging; reference builds; hunt plan | T01, T02, T07, T11, T12, T13 |
| M4 Capture and checks | 9–13 | Packet ring (Linux and Windows); flows; phase-1 parsers; active checks; check discovery; traffic labels; change detection; trace-back | T03, T04, T14, T15, T26 |
| M5 Deception, C2 and reporting | 11–14 | Decoys including the fake shell; honeytokens and registry; sinkhole; patch windows; service backups; IR drafter; inject kit | T05, T06, T08, T09, T10, T24, T25 |
| M6 Dry runs and freeze | 14–16 | Two full timed dry runs; fixes; release freeze; controller-loss drill | T19, T20, T23; all success metrics measured |

After the first competition, or earlier if time allows: phase-2 and phase-3 parsers, Palo-side capture, file carving, extra device adapters.

### Cut list, in order, if behind

1. Palo-side capture and phase-3 parsers. They're already after M6.
2. The LSASS decoy session.
3. Windows raw-socket capture, falling back to logs for Windows transactions.
4. Check discovery for protocols other than HTTP and DNS. Add those checks by hand.
5. Decoy services other than SSH.
6. Precise request linking in trace-back; keep the time-window fallback.

**Never cut:**

- link, spool and enrollment
- plans, with the dead-man switch and safe mode
- firewall and egress policy
- D1, D2 and D17
- active checks
- trace-back, at least with the time-window fallback
- the IR drafter

## Complexity register

Every place this design adds complexity is listed here, with why it earns its place and what keeps it bounded. The second table lists what we deliberately didn't build. Any new feature that adds a listener, a daemon, a host-binary dependency in a default path, runtime discovery, or a new kind of state has to be added here before it's built.

### Accepted complexity

| Item | Why it's worth it | How it's bounded | Section |
| --- | --- | --- | --- |
| Relay role | Segments the controller can't reach need a path | Dumb splice, no state, no keys; one per segment, declared statically | Topology |
| Device-proxy and bootstrap splicing | Network devices and first contact in other segments | Same splice code as the relay; allowlist; bootstrap window closes after enrollment | Topology, Enrollment |
| Five connection types on one port | Keeps one listener and one firewall rule | Small handler per type, selected by ALPN | Wire protocol |
| Patch-window proxy | Hosts patch without any outbound rule | Loopback only; time-boxed; controller allowlist; one connection per stream | Egress |
| Go-native Windows actions through COM and WMI | Avoids trusting host binaries | Largest test effort; `host.exec` fallback per action if a COM interface fights back, recorded here | The agent |
| Reading the Linux audit subsystem directly | No auditd binary to trust | Read-only multicast reader beside auditd; installs and re-checks its own rules; stops auditd only on kernels older than 3.16 | The agent |
| Separate decoy process | Decoys face attackers; bugs must not give root | Same binary, unprivileged, supervised | The agent |
| Full fake shell | Records what the red team actually does | No real filesystem or execution; fuzz-tested | Deception |
| LSASS decoy session | One of the few ways to know LSASS was dumped | Recreated by the agent if killed; first on the cut list | Deception |
| Packet capture with TCP reassembly and parsers | Check discovery, trace-back, IR evidence | Bounded ring; drops before slowing hosts; parsers isolated and phased | Service monitoring |
| Windows raw-socket capture | Capture without a driver | Lab-proven before relied on; logs as fallback | Service monitoring |
| Check discovery heuristics | The point of the feature | Every proposal needs a click; acceptance tests against simulator ground truth | Active checks |
| Trace-back request linking | Turns a change into a source IP | Falls back to time-window correlation, marked lower confidence | Trace-back |
| Sinkhole | Learns what implants would say | Linux only; record-only; size and time caps | Egress |
| Field-level encryption of captured credentials | No plaintext passwords on the controller's disk | Parsers mark credential fields; one helper encrypts them | Controller |
| Native MySQL dump | Avoids `mysqldump` on a possibly compromised host | Restore-tested before trusted | Backups |
| Defender exclusion | The agent may be flagged | Exactly one path; any other exclusion alerts | The agent |
| Typst on the controller | Good PDFs with little code | Controller only, never shipped to agents | IR and injects |
| Palo-side capture (phase 3) | Shows traffic that never reached the host | On demand only | Service monitoring |
| One binary for agent and controller | One release artifact per OS; no version skew between agent and controller | Size measured in M1 and compressed in transit; an agent-only build flag if first contact gets slow | Architecture, The agent |

### Refused or deferred

| Not built | Why | What we do instead |
| --- | --- | --- |
| Dynamic relays, election, failover, backup relays | Adds moving parts and fights minimal outbound rules | Static relays in the manifest; console restore |
| Automatic controller address updates | The address is stable in practice | `phylax set-controller` on the console |
| Agent self-update system | Rarely needed | One `agent.replace_binary` action |
| Multi-user UI, roles, remote UI access | Competition use only | One localhost login. Revisit an SSH tunnel only if dry runs show a bottleneck. |
| Stream multiplexing | A protocol inside the protocol | One TLS connection per logical stream |
| Protobuf | Code generation and opaque debugging | Length-prefixed JSON with zstd |
| Certificate authority, PKI, cert expiry | Clock dependency, more parts | Pinned keys |
| Wazuh, Velociraptor, Ansible, a SIEM | Slow to deploy or redundant | The agent, the controller, device adapters |
| Kernel drivers or custom eBPF | Large risk surface | OS interfaces, Sysmon, kernel audit |
| Containerization of services | Large effort; not needed for the goals | Harden in place. Revisit after the first competition. |
| Link-direction flipping for no-outbound segments | No known infra needs it | Documented limitation; build if an infra demands it |
| JavaScript graph library | Weakens the Content Security Policy, adds dependencies | DAG layout in Go, rendered as SVG |
| Scorer reverse-engineering beyond discovery: pass criteria from NISE, byte-exact replay, cross-season profiles | Not a goal; more heuristics and more state | Discover the scorer's current checks and mirror them as active checks |

### Watch list: things that would quietly break simplicity

- Any second listener on the controller, or any listener on a host that isn't a declared decoy or relay port.
- `host.exec` creeping into default plans. Every default-plan use belongs in this register.
- Rules or parsers that need state shared across hosts at the agent. Cross-host logic belongs on the controller.
- Configuration that can be changed on hosts without going through the manifest.
- New features justified by "might be useful" rather than by a test in the matrix.

## Risks and open questions

The largest risks are the controller as the single root of trust, rulings we haven't confirmed (workstation use, listeners, decoys on public addresses), and the volume of Go-native Windows work. Each has a fallback that keeps the team competitive.

### Risks

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| Controller compromised | Low | Critical | Localhost UI, one inbound port from declared sources, SSH off, secrets in memory, plan-signing key separate from transport keys |
| Controller lost (reset, crash, disk) | Medium | High | Encrypted snapshots every 15 min to other hosts; restore drill (T23) |
| Workstation re-tasking ruling goes against running a controller or relay on workstations | Low–medium | High | Ask before the season. The fallback is a non-scored server, which changes only the manifest. |
| Platform driver becomes the bottleneck (one screen) | Medium | Medium | Dry runs measure it; a narrow SSH tunnel to the UI is the documented next step |
| Go-native Windows work (COM, WMI, raw sockets) takes longer than planned | High | Medium | `host.exec` fallback per action; raw capture falls back to logs; tracked in the register |
| Defender flags the agent | Medium | High | Lab test per release; one tightly scoped exclusion |
| Palo rewrites source addresses on inbound NAT, blinding check discovery on hosts | Medium | High | Detected at drop flag. The Palo's traffic logs record the real source and the translated source port, so the controller rejoins each host transaction to its real source by port and time. Labeling and discovery keep working, with the 30 s log-pull delay added. |
| A relay host dies | Medium | Medium | Segment keeps working locally; console restore; consider a static backup only if the lab says so |
| Controller address changes mid-competition | Low | High | Console `set-controller`; ask officials about a DHCP reservation |
| Trace-back can't link requests to processes reliably | Medium | Medium | Time-window fallback marked lower confidence; dedicated lab test |
| Red team reads the repo and tunes around detections | High | Medium | Behavioral and allowlist detections; values generated at competition time |
| No PAN-OS VMs in the lab (licenses) | Medium | High | Request evaluation licenses in M0. Without them, M2's gate isn't passed until the Palo adapter's apply, drift and commit ordering have been tested on a borrowed or trial device. |
| Scope is too large for the team | High | High | Milestone gates, cut list, never-cut list; complexity register |
| ubuntu-wkst disk too small for indefinite retention | Medium | Medium | Disk alerts; compress old transaction bodies; pcaps only on demand |

### Questions for competition officials (ask before the season)

1. May the controller run on a user workstation, with one inbound port for our agents?
2. May a relay run on a workstation in another segment, with one inbound port for its segment's agents?
3. Is a DHCP reservation, or keeping the current lease, acceptable for the controller's address?
4. Are decoy services on our public addresses acceptable (fake SSH and others on non-scored ports)?
5. Can several team members view the same VM console in NETLAB at once?
6. Is NISE (or Nextcloud) reachable from inside the competition VMs, for PDF upload?
7. Does the proxy allow GitHub release assets, the Sysinternals download site, distro mirrors and Microsoft Update for patch windows?
8. Which of our repos are copied into Nextcloud, and are binaries preserved?
9. Which hosts serve the HTTPS, TFTP and NTP checks, if scored?
10. May we add a static NAT on a free address in our public pool, so a relay in another segment can reach the controller?

### Internal questions to settle in the lab

- Windows raw-socket capture coverage, inbound and outbound, under load (T26).
- Whether the Palo preserves source addresses on inbound NAT in the competition config.
- Socket-to-process linking speed for quick webshell requests.
- Whether AD-backed POP3 and domain FTP survive a krbtgt double reset.
- Defender's reaction to the agent, decoys and the LSASS decoy session.
- Exact free disk, CPU and memory on ubuntu-wkst in the competition image.
- Whether a native DNS zone export path exists, so `dnscmd` can be dropped.

## Appendices

### A. Windows event reference

Verify every ID on the target builds in M3. Firewall operational-log IDs in particular differ between Server 2019 and Windows 11.

| Log | ID | Meaning | Used by |
| --- | --- | --- | --- |
| Sysmon | 1, 5 | Process created, terminated | `proc`, D1, D8, D9 |
| Sysmon | 2 | File creation time changed (timestomping) | Hunt enrichment |
| Sysmon | 3 | Network connection | `net`, D4, trace-back |
| Sysmon | 4, 16 | Sysmon state change, config change | D10 |
| Sysmon | 6 | Driver loaded | D11 |
| Sysmon | 7 | Image loaded (filtered) | Change detection |
| Sysmon | 8 | CreateRemoteThread | D5 |
| Sysmon | 10 | Process access (LSASS) | D8 |
| Sysmon | 11 | File created | `fim`, D2, D6, trace-back |
| Sysmon | 12, 13, 14 | Registry create or delete, value set, rename | D6 |
| Sysmon | 17, 18 | Named pipe created, connected | D9 |
| Sysmon | 19, 20, 21 | WMI filter, consumer, binding | D6 |
| Sysmon | 22 | DNS query | D12 |
| Sysmon | 25 | Process tampering | D5 |
| Security | 1102 | Security log cleared | D10 |
| Security | 4624, 4625, 4648 | Logon, failed logon, explicit credentials | D9, D15 |
| Security | 4662 | Directory object operation (replication rights mean DCSync) | D8 |
| Security | 4663 | Object access (honey files) | D15 |
| Security | 4688 | Process created, with command line (fallback) | `proc` |
| Security | 4697 | Service installed | D6 |
| Security | 4698, 4699, 4702 | Scheduled task created, deleted, updated | D6 |
| Security | 4719 | Audit policy changed | D10 |
| Security | 4720, 4722, 4724, 4738, 4781 | User created, enabled, password reset, changed, renamed | D7 |
| Security | 4728, 4732, 4756 | Member added to global, local, universal group | D7 |
| Security | 4768 | TGT requested (pre-auth type 0 means AS-REP roastable) | D8, D15 |
| Security | 4769 | Service ticket requested (0x17 means RC4) | D8, D15 |
| Security | 4771 | Kerberos pre-auth failed | D15 |
| Security | 5136 | Directory object modified (GPOs, ACLs) | D6, D7 |
| Security | 5140, 5145 | Network share accessed | D9 |
| Security | 5157 | Connection blocked by the Windows Filtering Platform | `egress`, D12 |
| System | 104 | Event log cleared | D10 |
| System | 7045 | Service installed | D6 |
| Task Scheduler Operational | 106, 140, 141 | Task registered, updated, deleted | D6 |
| Defender Operational | 1116, 1117 | Detection, action taken | Context |
| Defender Operational | 5001, 5007 | Real-time protection disabled, configuration changed | D10 |
| PowerShell Operational | 4103, 4104 | Module logging, script block logging | D1, D8 |
| Firewall With Advanced Security | Varies by build | Rule added, modified, deleted; profile changed | D10 |

### B. Linux persistence locations

Watched by `fim` and checked by the hunt:

- **Scheduling:** `/etc/crontab`, `/etc/cron.*/`, `/var/spool/cron/`, `/var/spool/at/`, systemd timers
- **systemd:** units in `/etc/systemd/system/`, `/usr/lib/systemd/system/`, user units, drop-ins, generators
- **Boot:** `/etc/rc.local`, `/etc/init.d/`, `/etc/modules-load.d/`, `/etc/modprobe.d/`
- **Login and shell:** `/etc/profile`, `/etc/profile.d/`, `/etc/bash.bashrc`, `/etc/environment`, per-user dotfiles, `/etc/update-motd.d/`, `~/.ssh/rc`, `/etc/ssh/sshrc`
- **Authentication:** `/etc/pam.d/`, PAM module directories, `pam_exec`, `/etc/nsswitch.conf` and NSS libraries, all `authorized_keys`, plus `AuthorizedKeysFile` and `AuthorizedKeysCommand`
- **Accounts:** `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, `/etc/sudoers.d/`
- **Loader:** `/etc/ld.so.preload`, `/etc/ld.so.conf.d/`, `LD_PRELOAD` in service environments
- **Package hooks:** apt `Pre-Invoke` and `Post-Invoke` configuration, dnf plugins
- **Device events:** `/etc/udev/rules.d/`
- **Log rotation:** `/etc/logrotate.d/` postrotate scripts
- **Web:** `php.ini` and `conf.d` (`auto_prepend_file`, `auto_append_file`), `.htaccess`, Apache modules and `Include` lines
- **Mail:** Postfix `master.cf` and content filters, `/etc/aliases` command pipes, Dovecot post-login and global sieve
- **Database:** MySQL UDFs and plugin directory
- **Kernel:** loaded modules, BPF programs, module-loading state
- **Privilege:** SUID and SGID files, file capabilities
- **Desktop:** XDG autostart on workstations

### C. Windows persistence locations

- Scheduled tasks (including GPO-deployed); services (binary path, `ServiceDll`, failure actions)
- Run, RunOnce and RunServices keys (HKLM, HKCU, WOW6432Node); startup folders
- Winlogon `Userinit`, `Shell`, `Notify`; AppInit\_DLLs; AppCertDlls
- Image File Execution Options (`Debugger`, `GlobalFlag`); SilentProcessExit
- LSA Security, Authentication and Notification packages
- WMI event filters, consumers and bindings
- Netsh helpers, print monitors, time providers, Winsock providers
- COM hijacks under `HKCU\Software\Classes\CLSID`
- BITS jobs
- IIS native and managed modules, handlers, ISAPI filters
- DNS `ServerLevelPluginDll` on the DC
- Accessibility binaries (`sethc.exe`, `utilman.exe`, `osk.exe`) replaced or redirected
- PowerShell profiles (all scopes)
- Accounts: hidden accounts ending in `$`, RID hijacking, Guest enabled

### D. Repository layout

The declared competition repo is visible to every team, so the lab and red-team material live in a separate private repo.

```text
phylax/                 # declared competition repo
  cmd/phylax/                  # the one binary: serve, agent, init, CLI
  internal/agent/              # agent mode: modules and roles
  internal/link/               # TLS pinning, framing, connection types
  internal/spool/  internal/store/  internal/plan/  internal/actions/
  internal/collect/            # proc, net, fim, logs, capture, egress, crossview
  internal/parsers/            # one package per protocol
  internal/checks/  internal/traceback/  internal/detect/  internal/decoys/
  internal/devices/palo/  internal/devices/vyos/
  internal/ui/                 # templates, SVG DAG layout, vendored htmx
  manifest/                    # schema + example manifests per infra shape
  plans/                       # plan templates
  rules/                       # detection rules (YAML), each with a test
  pools/                       # decoy banners, honey filenames, fake-shell content
  inject-kit/                  # Typst templates and pre-written drafts
  checks/                      # active-check templates per service kind
  dist/                        # signed binaries, fallback delivery
  docs/

ccdc-lab/                      # private, never declared
  terraform/  packer/  netem/  proxy/
  reference/                   # baseline builders
  sim/scorer/  sim/orange/  sim/contaminator/
  redteam/
```

### E. Glossary

| Term | Meaning |
| --- | --- |
| Action | A typed, Go-native operation with check, apply, verify and rollback |
| Plan | A DAG of actions on specific targets, with dependencies and approval gates |
| Dead-man switch | Rollback that fires unless the agent re-establishes its link after a risky change |
| Relay | An agent role that splices its segment's connections to the controller |
| Device proxy | An agent role that splices the controller to a network device's management interface |
| Spool | The agent's sequenced, hash-chained local store of events awaiting acknowledgment |
| Active check | Our own end-to-end test of a service, managed in the UI |
| Discovered check | A check the scorer was observed running, proposed as an active check |
| Trace-back | The chain from a change back to the request and source that caused it |
| Honeytoken | A fake credential, key or path, unique per host, whose use reveals where it was stolen |
| Tier 0, 1, 2 | Response levels: automatic, one-click, manual with checklist |
| Safe mode | Global switch that suspends automatic responses and plan execution |
