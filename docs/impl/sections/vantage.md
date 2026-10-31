#### `vantage`

**1. Purpose and evidence.**

D-3: the Kali sits on VyOS's side leg, outside the Palo. From there it reaches our services through the same NAT and policy path as the scorer. Neither the controller nor the in-LAN runners see that path [PKT §2, PRO §4]. `vantage` is everything the Kali does that the in-LAN hosts cannot: external perimeter scans diffed against the scored set, egress canary listeners, per-credlist password verification through the public path, and the Kali-only probes (Zerologon check-only, SMB and WinRM exposure). The Kali also runs the `checks` module with its public-address allowlist; that is the primary "is it up for the scorer" signal and is specified in `checks`.

The controller stays on the LAN (D-4), because moving it to the Kali would require allowing outbound access from the LAN to it.

Evidence that it matters for points:

- Uptime dominates and the scorer's own path is the Palo and the NAT. A fault there is invisible from the LAN [[2026-mw-regional-scorecard-t7-services#e2]].
- The organizer's perimeter assessment scores extraneous or missing services on public addresses [[2026-mw-regional-scorecard-t7#e3]]. Organizers scan in a window each day [[2026-mw-regional-scorecard-t7-services#e10]], so a scan before that window finds what they would find. Durkee's debrief called out "far too many ports open… port 135 open" [PKT §7]. Perimeter-scan injects appeared in 18 of 22 events [PRO §4]; the scan output is the evidence for them.
- Red uses Zerologon and exposed management protocols; only 2 teams mitigated Zerologon in 2025 [[2025-minnesota-and-indiana-ccdc-debrief#e2]], [[discord-2026q-rt-debrief#e10]]. A check-only tester from outside proves the DC's public path is closed.
- The egress canary proves the egress policy and the Palo rules from the inside, and gives the firewall-deny proof for injects (review N10.3).
- Verifying a new password through the public path before the human submits the PCR catches a broken host change before it costs a scored round [Q §5].

**2. Status and code.**

Built (`internal/vantage`, with tests): `scan.go` (TCP and UDP scanner, `DiffExposure`), `canary.go` (listener, dedup, rate limit), `verify.go` (`VerifyService`, `RemoteVerifier`, `LocalTransport`), `vantage.go` (allowlist, kinds), `compare.go` (V1 classification), `checkrunner.go` (moves to `checks`, see that section). Missing:

- The Zerologon check-only tester and the SMB and WinRM exposure probes (review D379, kept). Neither is in the code.
- The `xfreerdp /auth-only` RDP probe on the Kali (specified in `checks`, built here as a pre-approved host tool wrapper).
- The dangerous-port diff and the "scored port closed" alert, the pre-window scan schedule, per-credlist verification (the code verifies every public service of the account and succeeds only if all accept; the per-credlist form is below).
- Controller-side wiring: nothing creates the V1-V4 alerts yet, and the Kali agent's roles and allowlist are not yet rendered from the manifest.
- Cut: the NAT-behaviour, blocked-source and Palo-load probes (review D379; no evidence they score).

Retrofit: `Compare` moves to `checks` (it classifies check results and emits `checks.compare`). `VerifyService` is imported by nobody else; it receives `checks/probe` as a shared library. The agent module names `vantage.scanner`, `vantage.verify` and `vantage.canary` become one agent module `vantage` with three sub-roles switched by the manifest roles `scanner`, `canary` and `check_runner`.

The Kali-to-controller path (VyOS source NAT, Palo static NAT, one Palo rule, host allows) is core topology (review D45). The public NAT listener is filtered to the Kali's source address only, because the organizer scan scores extraneous services on public addresses. This section relies on it and does not render it.

**3. Capability manifest.**

| Field | Value |
| --- | --- |
| Name | `vantage` |
| Sides | agent (the Kali), controller |
| OS | linux (the Kali) |
| Privilege | `root` (raw ICMP for the check runner; `nmap`-class service detection), `none` on the controller |
| Roles | `scanner`, `canary` (agent); `controller` |
| Default | core on hosts with the Kali roles; the rest of the fleet does not run it |
| Budget (agent) | 60 CPU ms/s, 32 MB held, 3 events/s, burst 20, 40 KB out/min, 10 MB disk (scan reports) |
| Budget (controller) | 20 CPU ms/s, 16 MB held, 2 events/s, 20 KB out/min, 5 MB disk |
| Tables | `vantage_scan`, `vantage_exposure` |
| Content | `rules/vantage` (V1-V4 correlation rules, dangerous-port list) |
| Actions | `pcr.verify` (shared with `creds`: the Kali side handles the signed step), `probe.zerologon_check` |
| Pages | `/vantage` |
| Evidence | part 1 |

**4. Configuration.**

```yaml
# modules/vantage.yml
allowlist: [172.25.{{ 20 + team }}.0/24]   # our own public addresses; hostnames are refused; rendered from hosts.yml
scan:
  interval: 15m                   # between scans
  first_delay: 2m
  tcp: { from: 1, to: 65535, rate: 100, concurrency: 32, connect_timeout: 1s }
  udp: { rate: 20, wait: 1s, probes: [dns, ntp, snmp, tftp, ike] }
  quiet_wait: 30s                 # a scan waits for a quiet window of this length when the clock feed is present
  pre_window: []                  # times of the organizers' daily scan; entered at runtime, a full scan starts 10 minutes before each
  dangerous_ports: rules/vantage/dangerous_ports.yml
canary:
  listen: 0.0.0.0
  tcp_ports: [4444, 8080, 8443, 9001, 1337]   # ports that policy should block; the real set comes from the egress policy
  udp_ports: [5353, 4444]
  dedup: 30s
  max_events_per_sec: 5
  max_conns: 64
  read_timeout: 2s
verify:
  timeout: 10s
exposure_probes: { zerologon: true, smb: true, winrm: true }
```

```go
// package vantage; the agent block is VantageSettings in internal/plan (nil = disabled).
type Config struct {
	Allowlist []string
	Scan      ScanConfig   // as built: TCPFrom/To, Rate, Concurrency, ConnectTimeout, UDP, UDPWait, UDPRate, Interval, Delay
	PreWindow []time.Time
	Canary    CanaryConfig // Listen, TCPPorts, UDPPorts, DedupWindow, MaxEvents, MaxConns, ReadTimeout
	Verify    VerifyConfig // Timeout; Targets is built from the learned credlist groups
	Probes    struct{ Zerologon, SMB, WinRM bool }
}
```

**5. Events.**

Consumes: `scorer.clock` (quiet windows), `scorer.account` (which public service each account is on, per credlist group), `checks.compare` and `checks.result` (rule V1), signed `pcr.verify` and `probe.zerologon_check` steps (not events), the manifest's scored set (config, not an event), and the agents' `net.canary_result` reports (the `net` module's canary sender; see Behaviour).

Emits:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `vantage.scan` | 1 | normal | `hosts`, `tcp_open[]`, `udp_open[]`, `duration`, `evidence` (nmap-like text used by the perimeter-scan injects) |
| `vantage.exposure_change` | 1 | high | `host`, `port`, `proto`, `change` (`newly_open`, `closed`, `declared_closed`, `dangerous_open`), `scored` |
| `vantage.canary_hit` | 1 | high | `host` (the tag), `source`, `port`, `proto`, `suppressed` |
| `vantage.pcr_verify` | 1 | normal; critical on failure | `account`, `credlist`, `service`, `ok`, `err` (credential-free) |
| `vantage.probe` | 1 | normal | `probe` (`zerologon`, `smb_exposure`, `winrm_exposure`), `host`, `result`, `evidence` |
| `vantage.refused` | 1 | high | `target`, `reason` (outside the allowlist) |

Controller correlation rules (content, `rules/vantage/vantage.yml`, evaluated by the `detect` engine on the controller): V1 (an external probe red or disagreeing with the in-LAN probe, from `checks.compare` with class `path_broken`, `scorer_content` or `internal_only`), V2 (`vantage.exposure_change` `newly_open`, `dangerous_open`, or a scored port `closed`), V3 (`vantage.canary_hit`: an egress leak), V4 (`vantage.pcr_verify` failed). Severity info or 1 (V1-V4 are context for the operator, not responses).

**6. Behaviour.**

*The Kali agent.* The same agent with the roles `check_runner`, `scanner` and `canary`. It dials the controller outbound through VyOS and the Palo, under the one declared rule and static NAT. It is installed by the console one-liner. It stays a workstation: it runs checks and scans and nothing else.

| Aspect | Rule |
| --- | --- |
| Trust | Untrusted vantage point. It cannot command other hosts. Its verdicts are evidence about the public path only. |
| Secrets | Scored credentials arrive in signed steps for a probe, are held in memory and are never written to disk; they are rotated if the Kali is suspected. |
| Targets | Only our own public addresses from the manifest (`Allowlist`). Hostnames are refused, because an allowlist of public IPs cannot vouch for what a name resolves to. The scorer, other teams, the White and Red Teams and global assets are never targets; a refused target emits `vantage.refused`. |
| Labelling | The Kali's translated source address is registered as `us`, so our probes and scans never look like the red team. |
| Rate | Probes stay out of the scorer's burst window and below knife-edge volume. Scans run at a low rate. |

*Quotient-faithful checks through the public path.* The `checks` module on the Kali probes the public addresses `172.25.(20+T).x` with the same library and the same faithful and sweep modes. A mismatch with the in-LAN probe is V1 and tells you whether the fault is the service (both red) or the Palo and NAT path (`path_broken`).

*PCR verification, per credlist (review D376).* `pcr.verify` is a signed step the controller sends to the Kali for one (account, credlist). The step carries the credential as a `vault.Secret`, which redacts itself in JSON, so the transport serialises it explicitly. The Kali's `VerifyService` runs `AuthOnly` against the public services of that credlist group only (each list's service, not every service the account might be on) and succeeds only if every one accepts the credential. No public service or a non-allowlisted target is a failure. A failed verification is V4. In the PCR process (`creds`) it runs right after the host change and before the human submits the PCR, so a host change that did not take costs no scored round. `LocalTransport` runs it in-process for the lab.

*External perimeter scans (review D377).* A scheduled TCP connect scan of `[1, 65535]` on each of our public IPs, in random order per host, paced by a token bucket (100 attempts/s, 32 workers), plus UDP probes with protocol payloads for DNS 53, NTP 123, SNMP 161, TFTP 69 and IKE 500. A UDP reply means open; ICMP unreachable or silence does not. The `nmap` binary is a pre-approved host tool for service detection. The result is diffed against **the scored set only** (the services marked scored; there are no public decoys, because the organizer scan scores extraneous services). `DiffExposure(declared, observed, scanned)` yields:

- `newly_open`: a port open that is not a scored service (V2). An undeclared port alerts once until it closes.
- `missing`: a scored port closed (V2, `closed` on a scored port). This is the alert that catches a firewall or service change that took a scored service off the public address.
- `dangerous_open`: an open port that is also on the red team's usual-target list (`rules/vantage/dangerous_ports.yml`: 135, 139, 445 where SMB is not scored, 3389 where RDP is not scored, 23, 5985 and 5986 where WinRM is not scored, and the database and cache ports 3306, 5432, 6379, 27017, 9200). The list is content from [TTP]; whether a port on it is scored comes from the manifest.
- A cancelled scan emits nothing, so it cannot look like closed ports.
- The scan waits for a `quiet_wait` (30 s) quiet window when the clock feed is present, and runs at a low rate otherwise.
- **Pre-window scan.** The operator enters the times of the organizers' daily scan in Settings (written to `overrides.yml`); a full-range scan starts 10 minutes before each, so what the organizers would find is found first.
- `Report.Text()` is the evidence for the recurring perimeter-scan injects. Durkee's "port 135 open" case is the dangerous-port rule.

*Egress canaries.* The Kali listens on a set of TCP and UDP ports that policy should block. Agents (the `net` module's canary sender; rate-limited, tagged) periodically try to reach it on those ports from servers and workstations and report blocked or leak. The agent sends `PHYLAX-CANARY/1 host=<name> nonce=<hex>`; the listener replies `ACK <nonce>`, so the agent knows it reached the Kali, and emits `vantage.canary_hit` carrying the tagged host name. The Kali sees translated source addresses, so the tag is the reliable identity; the resolver is only a fallback. Hits are deduplicated per (source, port, host) for 30 s with a `suppressed` count, rate-limited globally (5/s, burst 20), and the handlers and dedup table are bounded. Canary traffic carries its tag, so it never raises the egress rules or the beacon analysis. A leak is V3. It proves the egress policy and the Palo rules from the inside.

*Kali-only probes (review D379, kept).*

- **Zerologon check-only.** A tester against the DC's public path that tests the Netlogon secure-channel handshake for the vulnerability without changing any password. It reports `vulnerable`, `not_vulnerable` or `inconclusive` (the Server 2022 AD is expected to ship the fix [SV R2.4]). It never runs the exploit's password reset. Used after enrollment to confirm that the T+0 console step on the DC (enforce or patch first) held.
- **SMB and WinRM exposure.** Whether SMB 445 and WinRM 5985/5986 on each public address accept a connection and what they negotiate (SMB dialects, signing required, WinRM auth methods advertised). These are fingerprint reads, not logins.

Each is a probe type on the Kali runner, not a new subsystem.

**7. Actions and content.**

Actions (executed by the Kali agent): `pcr.verify` (risk `none`; locks none; touches no scorer-visible property; it is a login by a scored user, so it counts against `checks`' login rate), `probe.zerologon_check` (risk `none`; read-only against the DC). Content: `rules/vantage/vantage.yml` (V1-V4), `rules/vantage/dangerous_ports.yml`.

**8. UI.**

`/vantage`: per public address the open ports against the scored set, the last scan time and the diff; canary results by host; verification history; the Kali's link, clock offset and allowlist; a **Scan now** button; the field for the organizers' scan times. Overview tile: Kali link state and open V-alerts. A host-grid column is not needed: perimeter state is per service, shown on `/services`.

**9. Health.**

States: `ok`; `degraded` when the scan is behind schedule, the clock feed is absent (scans are unaligned), or a probe tool is missing (`xfreerdp`, `nmap`); `unavailable` when the Kali agent is down or its allowlist is empty (gap: "no public addresses declared"). Gaps: "Kali not connected", "no quiet-window feed", "UDP probes limited (no raw socket)". If the Kali is lost, nothing else degrades; the external verdicts are advisory.

**10. Scoring safety.**

- The Kali never targets anything outside the allowlist, so it cannot probe the scorer or other teams. The refusal is a hard check in the agent, not in the controller.
- Scans are connect scans at a low rate, outside the burst when a clock feed exists. They run against our own public addresses, where a stray SYN storm could look like an attack to the organizer. The rate cap is 100 attempts/s.
- Verification logins use the real credential and count as a login by a scored user. They are single, bounded, and happen right after a host change inside the quiet window.
- Zerologon is check-only; it must never reset a machine password. The tester is the one probe whose misuse would break a scored service (the AD host), so it is in the lint's never-list for plans and is runnable only as the named action.
- Scored credentials live on the Kali in memory only, for the length of a probe. A stolen Kali exposes only what a verification held at that moment.
- Alert-only stage: all probes are reads. In observe mode the Kali scans, verifies nothing (no PCR runs) and canaries only.

**11. Tests.**

- Unit (built): `scan_test.go` (ordering, rate bucket, UDP replies, diff, cancel), `canary_test.go` (tag, ACK, dedup, rate, bounds), `verify_test.go` (all-must-pass, allowlist refusal, secret redaction), `core_test.go`, `checkrunner_test.go` (moves with the runner).
- New: per-credlist verification targets; `dangerous_open` and scored-port-closed diffs; pre-window scan scheduling; Zerologon tester against a fake Netlogon server that reports vulnerable and patched; SMB and WinRM exposure parsing; V1-V4 rule fixtures.
- Conformance: starts with no config (disabled), refuses a non-allowlisted target, stops cleanly, emits only declared kinds, respects its budget during a full-range fixture scan, survives link loss (scan results spool), survives reconfiguration.
- Lab (v3 ids): T39 (Kali vantage: faithful checks against Quotient's results; a Palo rule that blocks the public path but not the LAN; a newly opened port; an egress leak: agreement 98% or more, V1 localises the fault, V2 and V3 fire), T35 (PCR transaction, shared with `creds`: verification via the Kali and the scorer's next login). New: a closed scored port raises V2; the Zerologon tester against an unpatched lab DC (a lab-build decision, v3 note) and the patched Server 2022 AD; the pre-window scan.

**12. Limits and open items.**

- `shortcut: UDP scanning treats silence as closed or filtered; a UDP service that answers only valid requests is missed, add payloads per service kind if the lab finds one.`
- `shortcut: the scan is a connect scan, not a SYN scan, so it completes handshakes against scored services at the scan rate; upgrade only if a lab run shows the scored services noticing it.`
- `shortcut: the canary port set is configured by hand until the egress policy renders it, then take it from the rendered deny rules.`
- Open: whether the Kali can be an agent at all in the 2027 rules is an organizer question and outside this design (review decision 3); the module is configuration, so a different external position changes only the allowlist.
- Open: the Zerologon tester needs a lab DC that is unpatched; a lab-build decision.
- Open: the organizers' scan window (time and frequency) is unknown until observed; the pre-window times are entered at runtime.
- Open: the Kali's sustained rate against a Palo with session limits is unmeasured.
- Core change: the Kali's `check_runner` and `scanner` roles need the round-clock feed (see `checks`, Limits).
- Cross-section: `net` owns the canary sender; the wire format `PHYLAX-CANARY/1` is the contract between the two modules and is fixed here. `checks` owns `Compare` and the `checks.compare` event that rule V1 reads.
