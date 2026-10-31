#### `firewall`

**1. Purpose and evidence.**

The `firewall` module applies the host firewall policy that the manifest renders for each host. On Linux it installs one `phylax` nftables table, a separate management table and a NAT table over netlink. On Windows it manages rules in the `Phylax *` rule groups through the Windows Firewall COM API. It provides shadow mode (see what a policy would drop before dropping it), a would-drop summarizer, host quarantine with auto-revert, a conntrack flush after every change that should end existing sessions, and default-deny egress for servers.

Evidence that it matters for points:

- The firewall is the biggest single lever on a flat LAN. East-west traffic never crosses the Palo, so host firewalls are the only control between hosts (core: "What each firewall layer is for").
- Default-deny egress is the C2 control. Servers get the agent link, declared dependencies and nothing else. The first denied connection is the best C2 signal (review D214, D215; D332).
- Shadow mode is how a firewall change is made without breaking scoring. UCI's `linux-toolbox/firewall.sh@f2af5a1` does the same thing in a cruder form (LOG chains, `DROP-ALL` commented out, `iptables-save` to `/root/iptables-<epoch>.rules`); the orchestration report judged ours better (review D180).
- A new rule does not kill existing sessions. Red teams keep established connections open through a firewall change [[neccdc-red-team-advice#e6]], [[mid-atlantic-ccdc-2021-red-team-debrief#e8]] (review D155, D156, D181). Hence the conntrack flush.
- The summarizer follows UCI's `scripts/fw.go` (`fwp`)@f2af5a1, which digests firewall logs by proto, source, destination and port. It is the step between log-first and default-deny (review N6.2).
- A timer that disables the host firewall is a tier-0 restore case (lab test T02), so apply, snapshot, drift detection and restore are one package.

**2. Status and code.**

Status: partial. The firewall manager is built and tested; the action wiring and several behaviours are not.

| Piece | State | Where |
| --- | --- | --- |
| nftables translate, apply in one atomic batch, snapshot, restore, drift, read-back verify, `PanicOpen` | built | `internal/firewall/{translate,manager,kernel,model}_linux.go`, `doc.go` |
| Windows Firewall translate, apply, snapshot, restore, drift, `PanicOpen` against a `WinBackend` interface (COM backend on Windows, fake on Linux) | built, COM backend lab-untested | `internal/firewall/win_{manager,state,com_windows}.go` |
| Dead-man arming inside apply (`fw.nft.restore`, `fw.win.restore` handlers) | built | `internal/firewall`, `internal/deadman` |
| Rendering: `HostPolicy`, nft text, Windows rules, domain allowances, canary rules, lint `FW101`-`FW110` | built (core manifest) | `internal/manifest/render` |
| Registered actions `firewall.allow` (inbound allow delta on the declared policy) and `win.firewall` | built | `internal/actions/linux_firewall*.go`, `win_firewall.go` |
| Actions `fw.apply`, `fw.snapshot`, `fw.restore`, `fw.quarantine` as named in the core action table | missing: the manager exists but is not registered as these actions and not wired into the agent (`cmd/phylax/agent.go` builds no `LinuxManager`) | |
| Conntrack flush | missing | |
| `fw.quarantine` | missing (no code; `policy.yml` response tier t1 names it) | |
| Source block of known red addresses (`fw.apply op: block`) | missing | |
| Windows shadow evaluation | missing (`Apply` returns `ErrShadowUnsupported`; the evaluator is not written) | |
| Would-drop summarizer | missing | |
| Periodic drift check calling `DetectDrift` | missing | |

The names `firewall.allow` and `win.firewall` are what the code registers today. The core action table lists `fw.apply`, `fw.snapshot`, `fw.restore` and `fw.quarantine` for this module. The design keeps the core names for the new actions, keeps `firewall.allow` and `win.firewall` as the delta actions (they edit the declared policy and re-apply it). Source blocks are `fw.apply` with `op: block`, the form the `respond` section uses. This is a naming addition to the core action table; see part 12.

**3. Capability manifest.**

```go
module.Manifest{
	Name:      "firewall",
	Sides:     []module.Side{module.SideAgent, module.SideController}, // agent applies; controller runs the summarizer
	OS:        nil,                                                    // linux and windows
	Privilege: "root",                                                 // netlink nftables, Windows Firewall COM
	Roles:     nil,                                                    // every host
	Consumes:  []string{"net.shadow_drop", "net.egress_denied"},
	Emits:     []event.Type{ /* part 5 */ },
	Budget: module.Budget{CPUMillisPerSec: 5, HeldMB: 8, EventsPerSec: 2, Burst: 20,
		BytesOutPerMin: 65536, DiskMB: 20},
	Default:  true,
	Tables:   []string{"firewall_shadow_summary"},
	Content:  []string{"plans/firewall"},
	Actions:  []string{"fw.apply", "fw.snapshot", "fw.restore", "fw.quarantine", "firewall.allow", "win.firewall"},
	Pages:    []string{"/firewall"},
	Evidence: []string{"neccdc-red-team-advice#e6", "mid-atlantic-ccdc-2021-red-team-debrief#e8", "2026-mw-regional-scorecard-t7#e3"},
}
```

Budget numbers are starting caps; the agent-side module is idle between applies, so CPU and held memory are small. Snapshots on disk are the only disk use.

**4. Configuration.**

The block is `modules/firewall.yml`. The policy itself is not configured here: it is rendered from `topology.yml`, `hosts.yml`, `services.yml` and `decoys.yml` (Manifest: what it generates), so this block holds only behaviour.

```yaml
# manifest/modules/firewall.yml
firewall:
  deadman: 90s                  # dead-man window armed by fw.apply in enforce mode
  shadow_min: { linux: 10m, windows: 5m }   # a plan template's review gate refuses sooner
  conntrack_flush: true         # delete existing flows a change should end
  quarantine: { revert_after: 10m }
  drift_check: 60s              # DetectDrift against the declared policy; 0 disables
  windows_stage0:               # first-stage Windows option; default-deny stays the end state
    enabled: false
    management_ports: [22, 3389, 5985, 5986, 445]   # minus every scored port in the manifest
    team_subnets: []            # sources allowed to reach management ports
  block:                        # known red-team addresses; never a source allowlist
    - { cidr: "198.51.100.7/32", reason: "scanner seen in the 2026-11-07 run", owner: net-lead, added: 2026-11-07 }
```

`icmp`, `dhcp` and `ipv6` stay in the schema only for the lint: they are always rendered as allow, and a manifest asking for `drop` fails the lint (`SS006`, `FW002`). They are not module settings.

```go
// package plan (new section under ModuleSettings; today the firewall has no section)
type FirewallSettings struct {
	ModuleLimits
	Deadman        time.Duration  `json:"deadman,omitempty"`
	ConntrackFlush bool           `json:"conntrack_flush"`
	QuarantineSec  int            `json:"quarantine_revert_sec,omitempty"`
	DriftCheckSec  int            `json:"drift_check_sec,omitempty"`
	Block          []BlockEntry   `json:"block,omitempty"`
	Policy         *render.HostPolicy `json:"policy"`       // the declared policy for this host (Linux)
	WinPolicy      *render.WinPolicy  `json:"win_policy"`   // Windows
}
type BlockEntry struct{ CIDR, Reason, Owner, Added, Expires string }
```

The declared policy travels in the signed config, so the agent can restore and detect drift with the link down. A change to the manifest bumps the config version; the new policy is applied only by a plan node (`fw.apply`), never by the config message alone.

**5. Events.**

Consumed:

| Kind | From | Use |
| --- | --- | --- |
| `net.shadow_drop` | `net` | Would-drop records from the shadow rules, both directions, with `prefix` (`phylax-shadow-input:` or `phylax-shadow-output:`), proto, src, dst, dport and, for outbound, the owning process |
| `net.egress_denied` | `net` | Enforced denies, to list what default-deny is blocking |

Emitted:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `firewall.applied` | 1 | high | `host`, `mode` (`enforce`, `shadow`), `node`, `prev_hash`, `hash`, `changed`, `deadman_armed`, `foreign_tables` (name, family, hooked, may_block) |
| `firewall.drift` | 1 | high | `group` (`mgmt`, `base`, `service`, `dependency`, `decoy`, `egress`, `domain`, `canary`), `diff` (first N differences), `foreign_may_block` |
| `firewall.restored` | 1 | high | `reason` (`deadman`, `verify_failed`, `drift`, `panic_open`), `node`, `hash` |
| `firewall.quarantine` | 1 | critical | `host`, `reason`, `expires`, `flows_deleted` |
| `firewall.shadow_summary` | 1 | normal | controller side: `since`, `groups[]` (`dir`, `proto`, `src`, `dst`, `dport`, `count`, `first`, `last`, `process`, `coverage`), `total`, `proposal_id` |

`coverage` says what the manifest says about the group: `declared`, `undeclared` or `scored` (a scored port would be dropped, which is a rendering bug and is raised at once).

The old name `net.shadow_drop` does not exist yet; it is a `net` module addition (part 12).

**6. Behaviour.**

*Layers and tables.* The rules are in separate groups (review D50): `base` (loopback, established, ICMP, ICMPv6, DHCP, DHCPv6), `mgmt` (agent link, relay, device access), `service` (declared listeners), `dependency` (`depends_on` egress), `decoy`, `egress` (`modules/egress.yml` allowances), `domain` (member to DC allowances) and `canary` (egress canary probes, expected blocked). Linux uses three tables:

- `phylax_mgmt` at priority -10: accept-policy chains that match management flows and set the conntrack mark `0x7068`. It never drops.
- `phylax` at priority 0: always accepts loopback, drops invalid state, accepts established and related, accepts packets carrying the management mark, then the group rules, then the chain policy (drop for servers in both directions; workstations keep an accept output policy because they have PAT internet access). The outbound chain ends with a rate-limited NFLOG rule (`limit rate 100/second burst 200`, group `deny_log_group`, prefix `phylax-egress-deny: `) before the policy drops. Rules drop rather than reject, so a blocked socket keeps retrying and the `net` module can attribute it by `sock_diag` join.
- `phylax_nat`: only when the sinkhole is enabled (see `egress`).

The tables are declared, deleted and redefined in one netlink batch, so the kernel swaps them atomically and nothing outside them is touched (CR §3.8). The package never edits a foreign table (firewalld on Rocky 9, ufw, docker): it only reads them and reports them in `foreign_tables`, flagging any whose hooked chain can block what ours accepts. Our table is a second base chain at an earlier priority, and a drop in either wins, so firewalld stays running (review D181). `Translate` refuses a default-drop policy with no management rule (`ErrNoManagement`), and `managementIntact` checks the structural invariants of the result (management table present with accept-policy chains, main chains accept the mark before anything can drop it) before and after every apply.

The Windows policy maps groups to rule groups (`Phylax Base`, `Phylax Mgmt`, and so on). Windows has no loopback or established rules (the firewall is stateful and exempts loopback), block rules win over allow rules, and the servers' default is Block both ways with `DeniedEgressAudit` set so Security 5157 is logged (the `winevt` module reads it). Only rules in our groups are touched.

*Always-allowed traffic.* ICMP echo is never blocked and ICMPv6 neighbour discovery stays (scored ping; the lint enforces it). DHCP is allowed where the host uses it. The domain allowance set is rendered for every member and its DC (Manifest rules); without it default-deny breaks Kerberos, LDAP and every scored check that uses domain accounts.

*Scored ports are allow-any-source.* Every scored listener gets an accept rule with no peer restriction (`FW101`). This holds in shadow and log-first stages as well (decision 13; review D180). A known red address or CIDR may be dropped on a scored port, because that removes a named source and narrows nothing; a CIDR block carries a warning because red scanners re-address after each run (lint, review area 3 answer). Never-block lists come from the manifest's scored services, never from hard-coded ports, so UDP 69 and 123 are protected only when TFTP or NTP is a scored service in the manifest (review area 7 lint correction).

*Source blocks.* `fw.apply` with `op: block` and a `sources` list adds a `block` group of drop rules for named addresses, placed ahead of the service accepts, to the declared policy and re-applies it. `op: unblock` removes entries. It is the tier-1 action behind a "block this address?" suggestion (`respond`). The group is new: the renderer needs a `GroupBlock`, and the blind-drop check (`FW108`, "a drop rule may only be a canary") must accept `block` entries that carry a reason, an owner and an added date. A block entry may not name an address the manifest lists as ours (controller, agents, the Kali, device management).

*Shadow mode* (review D180). `fw.apply` with `mode: shadow` shows what a policy would drop without dropping it.

- Linux: the policy is installed with every drop replaced by a log rule and accept chain policies. The would-be drop of each hook is logged with `limit rate 100/second burst 200`, prefix `phylax-shadow-input:` or `phylax-shadow-output:`, NFLOG group `deny_log_group` (or 1 when unset). Shadow never drops, not even invalid packets. The `net` module's NFLOG reader turns these into `net.shadow_drop` events. The `phylax_nat` table is not installed in shadow.
- Windows: rules can only allow or block, so shadow is evaluated, not installed. The agent evaluates the proposed policy against its connection table and recent connection events (Sysmon 3, Security 5156/5157) and reports what would have been dropped. Windows packet capture is cut (review D235), so flows from `capture` are not an input. A Windows shadow window should run a few minutes (`shadow_min.windows`). `shortcut: the Windows evaluator sees only connections the sensors saw, not a full packet view; upgrade only if a lab run shows would-drops it missed`.
- A plan template's review gate (Execution engine) sits between the shadow node and the enforce node. The gate shows the summarizer's table.

*Would-drop summarizer* (review N6.2). The controller-side analyser `firewall.shadow` reads `net.shadow_drop` events and groups them by direction, proto, source, destination and destination port, with `since` and proto filters in the UI. Each group shows its count, first and last time, the owning process for outbound drops and the manifest's verdict (`declared`, `undeclared`, `scored`). It is a pure function over the store. The output is a proposed manifest diff the operator approves before enforcing:

- Outbound group with an attributed process and a destination the manifest does not allow: propose a `depends_on` edge or an `egress.allow` entry written to `overrides.yml`.
- Inbound group on an undeclared port: propose nothing by default (an undeclared listener is a finding for `inventory`), with an "adopt as service" button only when the port has a listener.
- The summarizer never proposes a source restriction on a scored port, and a group on a scored port raises `firewall.shadow_summary` with `coverage: scored` immediately, because it means the render is wrong.

The proposal goes through `Propose`; the button creates an overrides edit and a re-render, not a firewall change.

*Apply protocol.* `fw.apply` runs under the `firewall` lock inside the plan's dead-man window (default 90 s, `lockout` risk):

1. Translate the declared policy and check management invariants.
2. Snapshot the current state of our tables (and on Windows, our rule groups); arm the dead-man with the snapshot as rollback data. The Linux dead-man handler restores exactly that snapshot (`fw.nft.restore`).
3. Replace in one batch. The kernel batch is atomic; a failed batch leaves the old state and cancels the dead-man.
4. Read back and diff against what was declared. A difference, or a broken management invariant, fires the dead-man immediately (it journals the outcome) and the action fails.
5. Flush conntrack for the flows the change should end (below).
6. The plan's `health.check` node runs the scorer-mimic probe for each service the host serves. Confirmation by the controller disarms the dead-man.

A policy equal to the current state is a no-op (`changed: false`).

*Conntrack flush* (review D155, D156, D181). A new rule does not end an existing session, so `fw.apply` (policy changes and `op: block`) and `fw.quarantine` delete the flows the change affects. On Linux this is a netlink conntrack delete (family `NFNL_SUBSYS_CTNETLINK`, filtered by source, destination, proto and port), not the `conntrack` binary. The set of flows is:

- For `fw.apply op: block`: every flow whose original source is a blocked address.
- For `fw.quarantine`: every flow except the management group and flows on scored ports (below).
- For `fw.apply` that tightens a policy: only flows the previous policy allowed and the new one does not. Flows allowed by both are left alone. It never flushes the whole table, and never touches flows carrying the management mark or flows on scored ports, so a scorer check in flight is not cut.

On Windows the equivalent is deleting TCP table entries for the affected connections (`SetTcpEntry` with `MIB_TCP_STATE_DELETE_TCB`). `shortcut: Windows flush covers IPv4 TCP only, UDP and IPv6 flows age out; upgrade if a lab run shows red holding such a session after a block`.

*Quarantine* (`fw.quarantine`). There is no v3 procedure beyond "isolate with auto-revert"; this is the v4 specification. The action replaces the host's policy with: the management group, ICMP and DHCP, scored inbound ports open to any source (decision 13 and the lint's no-kill rule: downtime scores zero), the declared dependency egress of the scored services on the host, and a drop for everything else in both directions. It then flushes the other flows. A dead-man armed for `revert_after` (default 10 minutes) restores the previous policy unless an operator confirms. It is a tier-1 one-click response and the restore on revert is the same snapshot restore as the apply dead-man. On a host with no scored service it isolates fully apart from management.

*Restore and tier-0.* A tier-0 response (the `respond` module) that finds the firewall disabled or flushed calls `fw.restore`, which reapplies the declared policy from the signed config. It takes the same `firewall` lock as plan nodes: while a node holds it, automatic restores on that host wait, and a restore during a plan gate restores what the plan has applied so far (Execution engine: locks). `PanicOpen` (accept-everything placeholder, management table deleted too) exists as a last-resort recovery action; it is console-triggered only.

*Drift.* Every `drift_check` interval the agent compares the kernel state with the declared ruleset (`DetectDrift`) and emits `firewall.drift` per group. The management group is reported separately (review D50). Foreign tables that may block are reported once. A drift in a service or base group on a scored host is tier-0 restorable when the `respond` module's guard allows it.

*Windows stage 0* (review D202). When `windows_stage0.enabled` is set, the renderer produces an allow-inbound policy plus a computed block of management ports from outside the declared team subnets (UCI `windows/Dovetail/minutezero.ps1` Block_Below/Between/Above@f2af5a1). It is scorer-safe when the scorer's address is unknown and is only a first stage. The management port list is reduced by every scored port in the manifest (on 2027 hosts: RDP on the MSSQL host, WinRM on the AD host, SMB on the MSSQL host stay open), and the lint rejects a stage-0 policy that blocks a scored port. Default-deny is the end state.

*Domain-joined hosts and Rocky.* On a Rocky host SELinux is enforcing and firewalld runs; the package needs no file writes for nftables (netlink), so no label issue arises there. Docker-published ports (the host listener is `docker-proxy` or netfilter DNAT) need a rule on the forward path as well; see part 12.

**7. Actions and content.**

| Action | Risk | Locks | Scorer-visible touches | Notes |
| --- | --- | --- | --- | --- |
| `fw.apply` (`op: policy` with `mode: shadow` or `enforce`, the default; `op: block` or `unblock` with `sources`) | lockout (policy), service (block) | `firewall` | listening ports in the rendered policy; for a block, the scored ports of the host | Dead-man armed (default 90 s) for policy changes. Read-back verify. Flush as above. Lint: a block names addresses only; a CIDR wider than /24 warns; never an address in the manifest's own set. |
| `fw.snapshot` | none | `firewall` | none | Owned tables or rule groups plus a summary of foreign tables, stored as evidence. |
| `fw.restore` | lockout | `firewall` | listening ports in the restored policy | From a snapshot or from the declared policy. |
| `fw.quarantine` | lockout | `firewall` | all scored ports and dependencies stay open | Auto-revert; tier 1. |
| `firewall.allow` | lockout | `firewall` | the listed ports | Built. Adds or replaces an inbound allow keyed by comment tag; lint-rejected when `from` is not `any` on a scored port. |
| `win.firewall` | lockout | `firewall` | the listed ports | Built. One rule in the `Phylax Service` group. |

The declared-policy delta actions (`firewall.allow`, and `fw.apply op: block`) change the agent's declared policy as well as the kernel, so drift detection compares against the new intent. Their rollback restores both the kernel snapshot and the declared policy (built for `firewall.allow`).

Content: `plans/firewall/enforce-host.yaml` (the shadow, review-gate, enforce, probe sequence of the plan example in the Execution engine) and the harden-host plan packs of `hardening` reference it. The never-block and source rules are lint data rendered from the manifest, not rules in this module.

**8. UI.**

- Page `/firewall`: per host the declared policy by group, the last apply (mode, time, hash, result), drift state and foreign tables that may block. The shadow summary table with filters (`since`, proto, direction), the verdict column and the "approve into manifest" button. The block list with reason, owner and added date. A quarantine control with the countdown.
- Host x step grid column `firewall applied` (verified when the kernel hash equals the declared hash and the mode is enforce; amber while the host is still in shadow).
- Overview tile: hosts in shadow mode, hosts with drift, active quarantines.

**9. Health.**

- `ok`: declared policy applied and equal to the kernel state; management invariants hold.
- `degraded`: shadow mode (not enforcing); drift in a non-management group; a foreign table may block; Windows COM backend unavailable and the module fell back to `host.exec` for an action.
- `unavailable`: no netlink nftables access (not root, kernel without nf_tables). Gap: `{"nftables", "kernel or privilege lacks it"}`.
- `error`: management invariant broken in the kernel; a failed restore. Raised as a critical alert with the console break-glass instruction.

Gaps reported: foreign firewall present (firewalld, ufw, docker), Windows Firewall service stopped, shadow evaluator coverage on Windows.

**10. Scoring safety.**

- The module touches the scored path by design: it decides which packets reach scored services. Everything that follows is a guard on that.
- Lint (rendering and run time): scored inbound is allow-any-source (`FW101`, the explicit rule of decision 13); ICMP, ICMPv6, DHCP, DHCPv6 stay (`FW102`-`FW104`); declared dependencies are never blocked (`FW105`); agent link present (`FW106`); no blind drops (`FW108`); domain allowances present (`FW110`); management-port blocks never include a scored port (review D202); UDP 69/123 protected only when scored.
- Alert-only stage: shadow mode is the alert-only stage. A host enforces only after a review gate, and the first enforce on a scored host runs under the dead-man with the scorer-mimic probe afterwards (a failed probe rolls back).
- Quarantine keeps scored ports and dependencies open, so quarantining a scored server never kills a service.
- The conntrack flush leaves scored-port flows alone.
- The dead-man covers the case where the host firewall change cuts the agent link; on the controller host it also asks dependent agents to open fresh connections (Execution engine: dead-man, hosts that carry other links).

**11. Tests.**

- Built: translate and diff tests, snapshot and restore round trips, the dead-man restore handler, `managementIntact`, Windows manager against the fake backend, and a privileged kernel test that applies and reads back a ruleset (`internal/firewall/kernel_linux_test.go`, skipped without privilege). `nft -c -f` runs on every rendered file in the CI privileged job. Lint tests for `FW101`-`FW110`.
- To add: conntrack flush (spawn flows in a network namespace, apply a tightening policy, assert only the affected flows die and scored-port and management flows survive); shadow summary fixture store (golden table and the manifest diff); quarantine round trip with revert; `fw.apply op: block` lint (scored port, CIDR warning, own address refused); Windows shadow evaluator against recorded connection lists; the conformance suite entries (starts with no config, survives link loss, budget).
- Lab: T02 (timer disables the host firewall, restored in time, trigger identified), T16 (a change that breaks a scored service is caught), T17 (link drops during a firewall-enforce plan, dead-man rolls back), T44 is the device equivalent in `devices`.

**12. Limits and open items.**

- `shortcut: Windows shadow is evaluated from sensor data, not installed; see part 6`.
- `shortcut: Windows conntrack flush covers IPv4 TCP only; see part 6`.
- Names: the core action table lists `fw.apply`, `fw.snapshot`, `fw.restore`, `fw.quarantine`; this section also registers `firewall.allow` and `win.firewall` (built), and gives `fw.apply` an `op` parameter (`policy`, `block`, `unblock`) that the `respond` section already uses. The core table needs those names added.
- Needs from `net`: `net.shadow_drop` (both directions, with the `prefix`). Today `net` reads NFLOG for outbound denies only. In the current renderer a shadow-mode output policy emits both the deny-log rule and the shadow rule on the same NFLOG group, so a shadow would-drop also appears as `net.egress_denied`; the shadow rule should use its own group, or the `prefix` must distinguish them. Undecided; recommendation is a separate group number.
- Needs from the renderer (core manifest): `GroupBlock`, the `FW108` exemption, and the `windows_stage0` option. The renderer already builds the nat sinkhole chain; see `egress` for why that chain pre-empts the deny log.
- Wiring: the agent builds no `LinuxManager` and registers none of the `fw.*` names; the `FirewallSettings` section in `plan.ModuleSettings` does not exist.
- Docker-published ports (the 2026 ecom was OpenCart in Docker): the host listener is `docker-proxy` or a DNAT rule. The `phylax` table's input chain does not see DNATed forward traffic. A `forward` chain with the same group rules is needed when a service has `runtime: docker`. Not designed or built; open until the 2027 stack is known.
- Time-boxed egress allowances for depot misses need an expiry primitive; see `egress`.
- Rocky 9 coexistence beyond "second base chain at earlier priority" (a firewalld reload deleting our table is not possible, but a firewalld rule that drops what we accept is) is only reported, not fixed.
- Quarantine of the controller host is refused (it would cut every agent).
