#### `egress`

**1. Purpose and evidence.**

The `egress` module is the controller-side half of the egress policy and the C2 hunt. It does three things:

1. Ranks denied outbound attempts (from the `net` module, and from Palo deny logs when a host's agent is dead) into a list of likely C2 destinations and the binaries reaching for them.
2. Keeps the per-executable egress allowlist: which programs may connect out, and to what class of destination. A connection from an executable that is not on the list raises an alert. It never blocks by itself; blocking is a one-click "block this?" suggestion (review D216, P1 answer).
3. Holds the open question of the sinkhole (a loopback catcher for denied TCP) until the C2 fingerprinting lab decides whether it earns its keep (review D76, D222, area 6 answer).

What it relies on, and does not own: the host firewall's default-deny and the NFLOG rule (`firewall`), denied-connection capture and process attribution (`net`), the Palo deny-log pull (`devices`), the manifest's declared dependencies (`deps` proposes them, the manifest holds them).

Evidence that it matters for points:

- Servers get almost no outbound access, so the first denied outbound connection is the best C2 signal we have (review D75, D218, D332). 18 default-credential shells in 2026 [[how-to-win-ccdc-dealing-with-red-team]] mean implants are planted early and call out.
- Default-deny by destination is blind to which process is allowed. A permitted-port connection from a webshell child or an unexpected binary goes unseen, and dependency discovery learns destinations per service, not which process may use them (review D216). Keying on executable identity, not a path allowlist, because a path allowlist is trivially bypassed [WT §9.4].
- Network-layer default-deny still holds when a host implant disables the host firewall, because the Palo logs and denies the same outbound attempts (v3 Egress policy and C2 hunting).
- Peer evidence for: UCF RB2 `firewall/dispatcher.rs` (`make_decision`) and `firewall/sockets.rs:165` (`clean_active_sockets`)@85aae3f decide per process and sweep established sockets at start-up. Peer evidence against enforcement: UCF's enforcement kills the offending process, and its own Woodstock ships `enforcing: false`. So this module alerts only.

**2. Status and code.**

Status: partial. The denied-egress producer and the detection rules exist; the analyser, the allowlist content and the one-click suggestions do not.

| Piece | State | Where |
| --- | --- | --- |
| Denied outbound attribution (NFLOG plus `sock_diag` join, 5-tuple dedup, canary tagging, bounded memory) | built | `internal/collect/net/{egress,nflog,sockdiag}*.go`, emits `net.egress_denied` |
| Deny rule and NFLOG group in the rendered policy | built | `internal/manifest/render/nft.go`, `internal/firewall/translate_linux.go` |
| Windows denied egress (Security 5157, outbound, agent link excluded) | built by `winevt` mapping | `internal/collect/winevt` |
| Rules `D12` (denied egress), `D12b` (five attempts in 30 minutes by exe, destination and port), `V3` (canary leak), `D4` (established outbound from an exe not in `egress.exes`, learned over 15 minutes) | built | `rules/network.yml`, `rules/profiles.yml` |
| `D13c` periodic beacon (needs a `jitter` operator and `scope: controller`) | pending | `rules/pending/needs_producer.yml` |
| Controller analyser ranking C2 candidates (D221) | missing (no code) | |
| Per-executable allowlist seeded from the manifest, startup sweep (D216) | missing; `D4` learns instead of seeding | |
| One-click block suggestions | missing | |
| Sinkhole: nft redirect render and the `policy.egress.sinkhole` setting | partial: renderer and translator exist; no catcher listener exists, nothing emits `net.sinkhole_capture` | `internal/manifest/render/nft.go`, `internal/firewall/translate_linux.go`, `internal/manifest/helpers.go` |
| Palo deny-log pull every 30 s (D219) | missing (`devices` owns it) | |

**3. Capability manifest.**

```go
module.Manifest{
	Name:      "egress",
	Sides:     []module.Side{module.SideController},
	OS:        nil,
	Privilege: "none",
	Roles:     []string{"controller"},
	Consumes:  []string{"net.egress_denied", "conn", "net.canary_result", "devices.deny", "integrity.verdict"},
	Emits:     []event.Type{ /* egress.candidate, egress.suggest_block */ },
	Budget: module.Budget{CPUMillisPerSec: 20, HeldMB: 16, EventsPerSec: 2, Burst: 20,
		BytesOutPerMin: 65536, DiskMB: 0},
	Default:  true,
	Tables:   []string{"egress_candidate"},
	Content:  []string{"rules/egress", "plans/egress"},
	Actions:  nil,
	Pages:    nil, // folded into the Traffic page (review D470)
	Evidence: []string{"how-to-win-ccdc-dealing-with-red-team"},
}
```

`Consumes` includes `integrity.verdict` to learn which binaries are pinned service images and `devices.deny` for the Palo-side denies; both are optional inputs and the analyser works without them.

**4. Configuration.**

The block is `modules/egress.yml`. It absorbs the `egress` section of v3's `policy.yml` (the renderer reads these fields through the manifest).

```yaml
# manifest/modules/egress.yml
egress:
  deny_log_group: 100          # NFLOG group for denied egress (render)
  canary_ports: [4444, 8888, 9001]   # Kali canary ports; probes are expected to be blocked
  allow: []                    # extra allowances beyond the agent link and depends_on: { host, to, ports, proto, reason }
  exe_alerts:
    mode: alert                # the only mode; blocking is a suggestion
    classes: [declared, lan, public]
    sweep_at_start: true       # established sockets at agent start are checked once
  rank:
    window: 30m
    periodic: { min_intervals: 10, max_cv: 0.2 }   # jitter below 20% over 10 or more intervals
  sinkhole: { enabled: false, port: 7480 }         # decided by the C2 lab (part 12)
```

```go
// package plan: the agent-side seed is a rule profile, so no new ModuleSettings field is needed.
// The controller module's own block:
type Config struct {
	DenyLogGroup uint16        `yaml:"deny_log_group"`
	CanaryPorts  []uint16      `yaml:"canary_ports"`
	Allow        []EgressAllow `yaml:"allow"`
	ExeAlerts    struct {
		Mode         string   `yaml:"mode"` // "alert"
		Classes      []string `yaml:"classes"`
		SweepAtStart bool     `yaml:"sweep_at_start"`
	} `yaml:"exe_alerts"`
	Rank struct {
		Window   time.Duration `yaml:"window"`
		Periodic struct {
			MinIntervals int     `yaml:"min_intervals"`
			MaxCV        float64 `yaml:"max_cv"`
		} `yaml:"periodic"`
	} `yaml:"rank"`
	Sinkhole *manifest.Sinkhole `yaml:"sinkhole"`
}
```

The 2027 reference `policy.yml` has `sinkhole: { enabled: true, port: 7480 }`. Moving to this block sets it to `false`, for the reasons in part 12.

**5. Events.**

Consumed: `conn` (common kind from `net`, used by the `D4c` rule on the agent and for the start-up sweep), `net.egress_denied` (producer: `net`; fields `dir`, `proto`, `laddr`, `lport`, `raddr`, `rport`, `community_id`, `attributed`, `attempts`, `nflog_group`, `exe`, `exe_sha256`, `comm`, `pid`, `tag`), `net.canary_result`, `devices.deny`, `integrity.verdict`.

Emitted:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `egress.candidate` | 1 | high | `rank`, `exe`, `exe_sha256`, `raddr`, `rport`, `hosts[]`, `attempts`, `first_seen`, `last_seen`, `new_binary` (not in the allow table or the ledger's service binaries), `periodic` (bool), `interval_mean`, `interval_cv`, `lineage` (parent chain when the trace-back has it) |
| `egress.suggest_block` | 1 | normal | `proposal_id`, `host`, `what` (`destination`, `kill_process`), evidence references |

The unlisted-executable alert is a `detect.alert` from rule `D4c` (part 6), not an `egress.*` event. Its entities are `host`, `exe`, `exe_sha256`, `raddr`, `rport`, `class` and `baseline` (true for the start-up sweep).

**6. Behaviour.**

*What is allowed out.* The firewall renders this; the module owns the policy inputs.

| Allowance | Who gets it | Notes |
| --- | --- | --- |
| Agent link | Every host | To the controller (the Kali: through the declared path) |
| Declared dependencies | Per service, from `depends_on` | For example mail host to the DC on LDAP and Kerberos; DNS to the DC |
| `egress.allow` entries | The listed host or every server | Each has a reason; the lint rejects an allowance wider than a /16 (`EG001`) |
| Domain allowances | Domain members and the DC | Rendered from `domain_member` and `rpc_range` (core manifest) |
| Canary probes | Agents, rate-limited | To the Kali's canary ports, tagged and expected to fail (`vantage`, `net`) |

Everything else is dropped at the host firewall and at the Palo. Workstations have PAT internet access and are not covered by server egress rules.

*Patches without a patch proxy.* The v3 patch proxy (a loopback HTTP proxy with a `phylax/patch` stream) is cut (review D84, D217). Packages come from the depot over `fetch`, installed by `pkg.install` (the `depot` module). For a miss, an operator opens a time-boxed egress allowance for one host: a plan from `plans/egress/` that applies a tagged allow for the distro mirror addresses and removes it after the window (default 15 minutes, maximum 30; the existing lint `EG002` checks the window and the upstream list). Everything that runs in the window carries the window's tag, and the integrity ledger expects the changed hashes. How the allowance expires is open (part 12).

*Logging denied egress.*

| Vantage point | Mechanism | What it gives |
| --- | --- | --- |
| Linux host | The nftables drop rule also sends the packet to an NFLOG group. Rules drop rather than reject, so the blocked socket keeps retrying and the agent finds the owning process through the `sock_diag` join (the `net` module). Audit `connect` records are the only evidence if the process died within a second. | The first packet of every denied attempt, with process and binary hash |
| Windows host | Blocked-connection auditing, Security 5157, outbound only; the agent's own link is excluded | Process id, application path, destination, port |
| Palo | The `devices` adapter pulls deny entries for outbound sessions every 30 s | Coverage when an implant has killed our agent or disabled the host firewall |
| DNS | The DC's DNS analytical log and Sysmon 22 (`winevt` content, review D220) | Which servers tried to resolve names outside the zone |

Attribution details (built): the denied 5-tuple is held for up to `AttributeWithin` (3 s) while the agent looks for the owning socket; repeats within `Dedup` (30 s) are counted in the next report's `attempts`; at most 256 pending and 8192 remembered tuples; over the bound the event is sent unattributed and counted.

*Analysis on the controller* (review D221). The analyser `egress.rank` is a pure function over the store (`Inputs: net.egress_denied, devices.deny`, `Every: 60 s`). It groups denied attempts in the last `rank.window` by (executable hash, destination address and port), falling back to the path when the hash is missing, and emits one `egress.candidate` per group. The ranking key, in order:

1. `new_binary`: the executable is not in the host's allow table and is not a pinned service binary. A binary the ledger has never seen reaching out is the strongest signal.
2. Attributed over unattributed (an event with no owning process still ranks, below attributed ones).
3. Number of hosts that tried the same destination.
4. First-seen: a destination first seen after the host's baseline ranks above one seen since enrolment.
5. Attempt count.

Periodicity is a secondary flag, never part of the key (review D332): the analyser computes the coefficient of variation of the intervals per group and sets `periodic` when the CV is below `max_cv` over at least `min_intervals` intervals (v3: jitter below 20% over at least 10 intervals; rule `D13c`). A beacon with jitter set high still ranks on binary and destination. Canary-tagged denials are excluded. Without a weighting study the order above is a lexicographic key, not a score; weights are not tuned.

*Per-executable egress alerts* (review D216; P1 answer). The allow table maps an executable (path, hash when known) to the destination classes it may reach:

- `declared`: a peer in the manifest (a `depends_on` edge or an `egress.allow` entry).
- `lan`: any address in the host's segments.
- `public`: anything else.

Seeding: one learner, not two. The table is rendered by the controller from the manifest alone: for every service, its pinned binaries (`services.yml` `process.binaries`, which the ledger judges) are allowed to reach that service's `depends_on` peers; the agent's own randomised path and hash may reach the controller; package managers and the Sysmon installer are listed per OS as pre-approved tools. Dependency discovery (`deps`) proposes new `depends_on` edges; once an operator approves one (written to `overrides.yml`), the table grows by the owning service's binaries. There is no separate learning window for this table. The 15-minute learned `egress.exes` profile of `D4` is retired in favour of the seeded profile.

The check runs on the agent as content, so it works with the link down: the profile `egress.allow` (key: exe, value: class) is delivered as `ProfileSeed` entries in the host's signed `DetectSettings`. Rule `D4c.exe-egress-class` (module `egress`, `scope: agent`, `mode: alert`, `tier: 1`, `exempt_tagged: true`) fires on a `conn` event (`op: opened`) with `dir: outbound` and `state: established` when the connecting executable is not in the profile for the connection's class, and the destination is not a loopback or the controller. Alerts carry the executable, hash, destination, process tree and a `collect: [process_tree, transactions_window_10m]` block as `D4` does. Scorer traffic is inbound, so it does not match.

*Startup sweep.* When the `net` module starts it already emits the established sockets of the first poll with `baseline: true` (as it does for listeners). `D4` ignores baseline events (`baseline: {present: false}`); `D4c` does not, when `sweep_at_start` is set, so an implant that was already connected when the agent started is caught once (UCF `clean_active_sockets` pattern). The alert carries `baseline: true`, and an operator can accept it into the table with the exception mechanism (suppression record with reason, owner and expiry).

*Suggestions, never silent.* For an unlisted-executable alert the alert page offers "block this?" as a `Proposal` with two forms, each a normal plan the operator approves:

- block the destination for this host (`fw.apply` with a drop in the `egress` group, followed by the conntrack flush for the destination);
- `proc.kill_tree` and `file.quarantine` of the executable (tier 2, with the `respond` checklist).

Neither runs without a click. A block can never target a scored service's own dependency (`depends_on` is protected by the lint). `shortcut: no per-executable enforcement; nft socket cgroupv2 per systemd unit is a later step [inferred, unverified], upgrade only if the lab alert rate shows the false-positive rate is low enough to enforce`.

*Gaps.* Egress filtering does nothing against inbound command channels: a webshell on a scored port, a bind shell. Those are covered by process-lineage detection (D1), change trace-back, the integrity ledger and the packet ring.

*Sinkhole (pending the C2 lab).* The v3 design redirected denied outbound TCP to a loopback catcher run by the agent, which recorded the first bytes (16 KB or 10 s), the HTTP request line and headers, the TLS ClientHello (SNI, ALPN, JA4), and closed without sending anything meaningful. It was Linux only and record-only. David's decision (area 6): do not cut it yet. Stand up the common C2 frameworks, capture their traffic, and decide from the results whether first-bytes fingerprints discriminate between frameworks. If they do, the sinkhole is kept and built; if not, it is cut with its render code. The code stays until the lab runs.

The lab list (A6.Q4): Mythic with the Apollo and Poseidon agents and a Gaia redirector, Sliver, Havoc, Metasploit, Empire, Realm `imix`, and the tunnelling tools chisel, ligolo-ng, frp and ngrok. Cobalt Strike only from public malleable profiles and public pcaps. For each: the first bytes, TLS/JA4, HTTP shape, timing and, on Windows, named-pipe names. Results become rules (content). Keep criterion: the fingerprints separate at least the frameworks red teams actually use against us and cost a listener that the NFLOG path cannot replace. NFLOG alone already gives process, destination and port; first bytes rarely change the response, which is why the earlier call was to cut.

**7. Actions and content.**

No actions. Content:

| File | What |
| --- | --- |
| `rules/egress/exe_class.yml` | `D4c.exe-egress-class` with inline tests (unlisted exe to a public address; listed service binary to its dependency; baseline socket at start; scored-service inbound ignored; tagged window exempt) |
| `rules/egress/beacon.yml` | `D13c` once the engine has a jitter operator, `scope: controller` |
| `plans/egress/patch_window.yaml` | Time-boxed egress allowance for a depot miss (see part 6) |
| `plans/egress/block_destination.yaml` | The destination-block form of the one-click suggestion |
| `rules/network.yml` (owned by `net` today) | `D4`, `D12`, `D12b`, `V3` stay with their current owner until the retrofit moves them; `D12`/`D12b` are the egress-denied rules this module's page reads |

**8. UI.**

No page of its own: egress folds into the Traffic page (review D470), which shows the ranked candidates (executable, hash, destination, hosts, attempts, first and last seen, periodic flag), the unlisted-executable alerts with the "block this?" buttons, the allow table per host with the manifest source of each entry, and canary results. Sinkhole captures appear there only if the lab keeps the sinkhole. The Overview shows the top candidate count.

**9. Health.**

- `ok`: candidates are being recomputed on schedule.
- `degraded`: no `net.egress_denied` events from a host that has default-deny (the NFLOG reader is down; `net` reports `net.sensor_degraded`); a server with default-deny egress whose agent is silent and no Palo deny pull is configured; the allow table could not be rendered for a host (a service lacks `process.binaries`).
- Gaps: hosts without attribution (Windows without 5157 auditing; a process that died inside one second), hosts where the NFLOG group is shared with shadow logging.

**10. Scoring safety.**

- The module takes no action on the scored path. Alerts only; suggestions need a click.
- The destination block form is a host egress block, never a source narrowing, and the lint refuses it when it would cut a declared dependency of a scored service.
- The time-boxed allowance widens egress for a fixed window; it cannot narrow anything.
- The sinkhole, if enabled, redirects only denied TCP (everything allowed is returned before the redirect), but see part 12: in the current render the redirect pre-empts the deny log.

**11. Tests.**

- Built: attribution tests in `internal/collect/net`, the rules' inline tests (`D4`, `D12`, `D12b`, `V3`).
- To add: analyser fixtures (a store with denies from two hosts, a periodic beacon with jitter 10%, a non-periodic one with high jitter, a canary-tagged denial; the ranking order asserted; identical output twice for the same `now`); allow-table rendering from the reference manifest (the pinned binaries of each service appear, the agent path appears, a service without `process.binaries` yields a warning); `D4c` tests above; the proposal builder (a destination block never cuts a dependency).
- Lab: T05 (implant callbacks under default-deny egress: `D12` fires, owner and hash found), T06 (Windows, 5157), and the C2 fingerprinting lab, which also holds the sinkhole tests that review D514 keeps.

**12. Limits and open items.**

- **Sinkhole decision.** Pending the C2 fingerprinting lab (part 6). Two defects to fix before it can be enabled: (a) no catcher listener exists, and nothing emits `net.sinkhole_capture`; (b) in the current rendering the nat redirect at priority -100 sends denied TCP to loopback, where the filter chain's `iif/oif lo accept` rule takes it before the deny-log rule, so enabling the sinkhole silences the NFLOG attribution that the rest of this module depends on. If it is kept, the nat chain must log (NFLOG) before the redirect, and the catcher returns as a separate Linux agent module that consumes `net.egress_denied` (the `net` section: it does not belong in `net`). Because of (b) this module sets the reference `sinkhole.enabled` to `false`.
- **Expiry of a time-boxed allowance** needs a primitive the execution engine does not have: a plan `delay` node, or a dead-man armed without a confirm. Recommendation: the second, because it also fires if the controller dies. Needs a decision in the core.
- **Destination class vocabulary** (`declared`, `lan`, `public`) is a first cut. A service that talks to a CDN or a cloud API would need more; the lab run decides.
- **False-positive rate of `D4c`** is unmeasured. The mode stays alert; the Invitational (observe mode) is the first data.
- **Palo deny pull** is a `devices` task; until it exists, a host with a dead agent has no egress coverage.
- `D13c` waits for a `jitter` operator in the rule engine (core: Rule format).
- The `D4` learned profile and its 15-minute window are retired by this section; the retrofit must change `rules/profiles.yml` (`egress.exes`) and `rules/network.yml` together.
