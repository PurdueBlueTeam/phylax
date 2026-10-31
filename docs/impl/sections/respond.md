#### `respond`

Responses come in three tiers by reversibility. Only reversible actions on unscored state run automatically, and every automatic action is followed by a health check. This module holds the tier policy, the guards on automatic actions and the response recipes. It owns no actions: it runs the core families' actions, the `firewall` actions and the module-owned actions through the execution engine.

**1. Purpose and evidence**

- **What it does.** On the agent it consumes `detect.alert` events with `mode: act` and `tier: 0`, runs the recipe's tier-0 actions locally in seconds, even with the link down, under the guards below, and records each in the audit trail. For tier 1 and tier 2 it supplies the controller with the recipe: what to collect and which one-click actions to offer on the alert.
- **Evidence.** Red plants firewall-killer timers (a known prebake), disables Defender and audit, and drops persistence at drop flag [TTP §1], so a response that waits for a human loses minutes on the cheap, reversible cases. Restore of a host firewall within seconds is the success metric the lab measures (T02). Against automatic action on a scored host: Wazuh active response and Velociraptor `execve` are lateral-movement paths, and a Tetragon-style kill-on-match policy can kill `sshd` on a scored host [gk]; UCF's v1 killed on all 15 rules and its v2 ships hand rules as alert (`lib.rs:10,257@85aae3f`). Hence tier 0 is narrow, guarded, alert-first and off until enabled (David: automatic actions beyond tier 0 are one-click suggestions, never silent).
- **Decisions applied.** Review D346 (GPO check), D347 (CIDR blocks with a warning, conntrack delete), D348 (new reservation is costly), D349 to D352 (the four guards stay), D353 (no scripts), D354 (recipes as YAML next to rules, no IR template per recipe).

**2. Status and code**

Status: **partial**. Tier-0 responses are not enabled (`act_enabled` is left off).

| Piece | State |
| --- | --- |
| `mode` and `tier` on every alert; `act_enabled` global switch | built (`internal/detect`, `internal/agent/mods/detect.go`) |
| Response actions: `file.quarantine`, `file.restore`, `user.lock`, `service.state` and `service.config`, `win.defender`, `win.firewall`, `firewall.allow`, `systemd.dropin`, `ssh.authorized_keys`, `group.members` | built (`internal/actions`) |
| Locks, tags, safe mode, scoring guard (`StaticGuard`) | built (`actions/lock.go`, `tag.go`, `safemode.go`, `guard.go`) |
| The tier-0 runner (guards, rate limit, circuit breaker, loop detection) | missing |
| Recipes and the recipe loader | missing |
| Tier-1 proposals on the controller | missing |
| Action names named in the tier table but not yet in `internal/actions`: `fw.restore`, `fw.quarantine`, `audit.rules`, `sysmon.install`, `cron.disable`, `unit.disable`, `task.disable`, `runkey.remove`, `proc.kill_tree`, `proc.suspend`, `session.terminate_predating`, `binary.restore_from_depot` | missing (owned by the core families and by `firewall`, `audit`, `winevt`, `integrity`) |

**3. Capability manifest**

| Field | Value |
| --- | --- |
| Name | `respond` |
| Sides | agent (tier 0 runner), controller (recipes to proposals; a few lines in the same package) |
| OS | both |
| Privilege | root |
| Roles | any host |
| Consumes | `detect.alert`, `file_change` (for the scan-on-write recipe), `ad.gpo_finding`, `telemetry_gap` |
| Emits | `respond.action` (schema 1, high), `respond.breaker` (schema 1, critical), `respond.loop` (schema 1, critical) |
| Budget | CPU 2 ms/s, held 4 MB, 2 events/s, burst 20, 50 KB/min out, disk 1 MB |
| Default | core |
| Tables | none |
| Content | `rules/respond/` (recipes) |
| Actions | none registered; runs actions of other families |
| Pages | Responses (audit view of automatic actions), recipe viewer under Settings |
| Evidence | [[mnccdc-redteam-gpo#e4]], [[mnccdc-redteam-nmap-agent-go#e3]], [[agrapplernamedsam-redscanner#e2]], [[2027-mw-invitational-packet#e39]], [[neccdc-red-team-advice#e6]], [[mid-atlantic-ccdc-2021-red-team-debrief#e8]] |

The catalogue lists `respond` as agent only. The controller needs the recipes to build tier-1 buttons, so the section needs a small controller side (see part 12).

**4. Configuration**

```yaml
# manifest/modules/respond.yml
respond:
  tier0:
    enabled: false              # master switch for automatic actions; off until the lab and the Invitational have run alert-only
    max_per_host_per_min: 3     # beyond this, further tier-0 actions become tier-1 proposals
    breaker_window: 2m          # a red health check inside this window disables the action type on that host
    loop: { count: 3, window: 10m }
    recipes: [firewall_restore, defender_restore, audit_restore, sysmon_reinstall, persistence_disable, service_restart, webshell_quarantine]   # recipes allowed to act on this host; default none
  protected_processes: []       # additions to the built-in protected set (below)
```

```go
// package plan (new)
type RespondSettings struct {
	ModuleLimits
	Tier0 Tier0Settings `json:"tier0"`
	Protected []string  `json:"protected_processes,omitempty"`
	Recipes   []RecipeFile `json:"recipes,omitempty"` // signed recipe documents; the agent runs only these
}
type Tier0Settings struct {
	Enabled          bool     `json:"enabled"`
	MaxPerHostPerMin int      `json:"max_per_host_per_min,omitempty"` // default 3
	BreakerWindowSec int      `json:"breaker_window_sec,omitempty"`   // default 120
	LoopCount        int      `json:"loop_count,omitempty"`           // default 3
	LoopWindowSec    int      `json:"loop_window_sec,omitempty"`      // default 600
	Allowed          []string `json:"allowed,omitempty"`              // recipe names
}
```

**5. Events**

Consumed: `detect.alert` (the `mode`, `tier`, `rule`, `entities` and `evidence` fields); `file_change` in a declared content root (scan-on-write); `ad.gpo_finding` (the GPO check); `telemetry_gap` (a gap on a sensor a recipe depends on suspends that recipe and says why).

Emitted:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `respond.action` | 1 | high | `rule`, `recipe`, `action`, `target`, `outcome` (`applied`, `failed`, `rolled_back`, `skipped_safe_mode`, `skipped_guard`, `skipped_rate`, `skipped_breaker`, `skipped_lock`, `skipped_gpo`), `before`, `after`, `undo`, `health` (the post-action check result), `tag` |
| `respond.breaker` | 1 | critical | `action`, `host`, `reason` (the red check), `reenable` (how an operator re-enables it) |
| `respond.loop` | 1 | critical | `object`, `recipe`, `count`, `window`, `lineage` (process tree of the last restorer if known) |

**6. Behaviour**

*Tier table.*

| Tier | Who decides | Actions |
| --- | --- | --- |
| 0: automatic | The agent, locally, in seconds, even with the link down | Restore the declared host firewall (management group first); re-enable Defender protection and remove new exclusions (the agent's install directory is the one kept exclusion); reinstall or restart Sysmon and restore audit rules; disable (never delete) untagged scheduled tasks, cron entries, units and Run keys; restart a stopped scored unit under the circuit breaker; quarantine a new webroot script that matches a webshell signature |
| 1: one-click | The operator in the UI, with the evidence on screen | Kill a process tree (`pidfd` with start-time check; `cgroup.kill` for units); suspend instead of kill to preserve memory; quarantine a file; **restore a binary from the depot**; block a source address **or CIDR** on the Palo or a host firewall, with a warning and a conntrack delete; isolate a host (`fw.quarantine`, auto-revert); lock an unscored account; kill sessions; restart a service; restore a file from baseline or backup; roll back a plan node |
| 2: manual with checklist | The operator, with a verbal callout to the team | Scored-account rotation (the PCR transaction, `creds`); krbtgt reset (`ad`); full service restore; device config revert; requesting a new reservation, which is **costly**: recovery services cost points and vulnerabilities reappear [[2027-mw-invitational-packet#e39]], so in-place golden restore is preferred |

The integrity ledger is alert only (D-1): D5d never runs tier 0 and its one-click response is explicit.

*Where tier-0 authority comes from.* An agent runs no unsigned step (principle 13). Tier 0 does not break that: the signed `AgentConfig` carries the `respond` block with the recipe documents. The agent runs only recipes in that block, for alerts whose rule id the recipe names. The alert and the events behind it are agent data and never build a command; a recipe parameter that comes from an event field (a path, a unit name, a task name) is passed through the action's typed parameter check and the scoring guard, and must name an object the alert's `entities` carry. A recipe that is not in the signed config cannot run.

*Guards on automatic actions.* All apply to tier 0 and the first four also bound tier-1 proposals.

- **Protected processes are never killed:** OS-critical processes (`csrss`, `wininit`, `winlogon`, `services`, `smss`, `lsass`, core `svchost` instances, `systemd`), the `sshd` listener if declared, our agent, and anything inside a scored service's declared tree. Tier 0 does not kill processes at all; the list also guards tier-1 proposals.
- **Scored accounts are never touched automatically.** The scoring guard (`actions/guard.go`) refuses a touch of a scored account, a scored service stop, or scored content, and its refusal is `skipped_guard`.
- **Rate limit.** At most 3 tier-0 actions per host per minute, keyed per object, not per recipe. Beyond that they become tier-1 proposals (the alert is marked `proposal`).
- **Circuit breaker.** A real post-action health check runs after every tier-0 action: the local probe of the affected scored service from the agent (the `net.tcp_probe` and `net.http_probe` actions against the declared `health:` block), and the controller's scorer-mimic probe when the link is up. If either goes red within the breaker window (default 2 minutes), that action type is disabled on that host, `respond.breaker` is emitted and the alert escalates. An operator re-enables it.
- **Loop detection.** The same restore of the same object 3 times in 10 minutes opens an incident (`respond.loop`) and a targeted hunt on the culprit's lineage, and the loop stops. This also finds firewall-killer timers when the hunt did not [TTP X-2].
- **Locks and safe mode apply.** Tier 0 takes the same named locks as plan nodes (`firewall`, `accounts`, `sshd`, `packages`, `audit`, service locks). While a plan node holds a lock the automatic action for that resource waits. Safe mode suspends tier 0 entirely (`skipped_safe_mode`); detection continues. Each successful plan node updates the host's declared state, so a restore during a gate restores what the plan has applied so far.
- **Every network, account or process-control action has a timeout and a verified rollback** [OA §5.9].
- **No scripts.** Response actions are typed and native. Wazuh active response is off (`wazuh`).
- **GPO check (review D346).** On a domain-joined Windows host, a restore that an Enforced GPO reverts would loop. Before the third restore of a Windows firewall, Defender or audit setting, `respond` looks for an `ad.gpo_finding` covering that setting on the host (the `ad` module's effective-state check). If one exists it stops the restore loop, emits `respond.action` with `skipped_gpo` and raises the GPO finding, because a local fix loses to an Enforced GPO (`ad`, GPO response; [[mnccdc-redteam-gpo#e4]]).

*Blocking sources.* A source block (tier 1) may be a single address or a CIDR. A CIDR block carries a warning because red scanners re-address after every run [[mnccdc-redteam-nmap-agent-go#e3]], [[agrapplernamedsam-redscanner#e2]]. Every block carries the conntrack delete for affected flows (`firewall`, review D155): a new rule does not kill existing sessions [[neccdc-red-team-advice#e6]], [[mid-atlantic-ccdc-2021-red-team-debrief#e8]]. Blocking a known red-team address or CIDR on a scored port is allowed; narrowing a scored port to a source allowlist is not, and the scoring-safety lint enforces it (decision 13).

*Recipes.* A recipe is YAML next to the rules (`rules/respond/<name>.yml`), triggered by rule ids, naming what to collect and which actions to run or propose. It has no IR-template field: IR drafts come from the drafter per attack narrative (review D354, `report`).

```yaml
recipe: web-compromise
module: respond
triggers: [D1, D1f, D17]            # rule id prefixes
collect: [trace_back, process_tree, content_changes, transactions_window_10m, freeze_ring]
tier0: []                           # none: a webshell command is investigated first
propose:                            # one-click actions on the alert
  - { action: proc.kill_tree,     params_from: entities.pid }
  - { action: file.quarantine,    params_from: entities.path }
  - { action: fw.apply,           params_from: entities.source, params: { op: block }, note: "host block; palo.apply for the Palo; CIDR warns; conntrack delete included" }
  - { action: hunt.persistence,   params: { user: web } }
  - { action: user.set_password,  params_from: entities.account, note: "unscored app and DB accounts only; the guard refuses scored ones" }
tests: [ ... ]                      # same inline-test form as rules
```

| Trigger | Collected automatically | Proposed actions | Notes |
| --- | --- | --- | --- |
| D1 or D17 via webshell | Trace-back timeline, process tree, content diff, transactions from the source plus or minus 10 minutes, ring slice | Kill tree, quarantine file, block source IP or CIDR, hunt persistence by the web user, rotate unscored app and DB credentials | |
| D5d binary modified | Ledger verdict, signer, package owner, expected file and source, process tree, network behaviour | Quarantine as evidence, restore from the depot, restart, scorer-mimic verify, hunt the same hash everywhere | alert only (D-1) |
| D7 | Creating session and its source | Disable account, kill sessions, review group memberships | unscored accounts only |
| D8b Zerologon | Netlogon events, source, build and registry state | Enforce the secure channel, patch or filter RPC, propose krbtgt double reset and privileged credential rotation (tier 2) | |
| D10 firewall disabled | Lineage of the disabler, recent persistence | Tier 0 restores; propose disabling the trigger | tier 0 |
| D12 or D13 | Owning process, binary hash, persistence | Kill, quarantine, remove persistence, hunt the same hash on all hosts | the sinkhole capture is not collected |
| D8 | Source account and host, logon session, tools seen | Disable source account, plan credential resets, krbtgt double reset | scored accounts only through PCR |
| D14 | Config diff, admin session | Revert to known-good, rotate device admin | via `devices` |
| D15 with a honey credential | Token origin, every use of the token | Treat the origin host as compromised; hunt it; rotate real credentials stored nearby | |
| V2 or V3 | The Kali scan diff or canary report, the Palo rule set | Close the port or the egress path | |
| `file_change` in a content root (review N5.9) | The written file | `yara.scan{path}` immediately (the scan is read-only); on a match, tier 0 quarantine of a signature-matched webroot script, else a tier-1 quarantine proposal | content only: needs no new Go if `yara.scan` takes a path |

The webshell tier-0 quarantine applies only to a new script outside the declared scored content paths; the scoring guard refuses anything under scored content. A change to declared scored content is the `content_guard` module's business.

*Audit trail.* Every action, automatic or manual, writes an event: what triggered it, before and after state, the undo, the approver (tier 1 and 2), and the health result afterwards (review D355). This is the containment section of every IR report and the answer when the White Team asks why something changed.

**7. Actions and content**

Actions: none registered. Content: the recipes in `rules/respond/`, one file per recipe in the table above plus `firewall_restore`, `defender_restore`, `audit_restore`, `sysmon_reinstall`, `persistence_disable` and `service_restart` (the tier-0 set). CI validates a recipe the way it validates a rule: schema, inline tests, every `action` exists in the registry, every tier-0 action is unscored-state by its `Touches`, every `triggers` id exists in the rule-id registry.

**8. UI**

Alert page: the recipe's `collect` results and its buttons (tier 1) with approver prompts for tier 2; each button creates and approves a plan through the normal engine (`Host.Propose`), so it appears in Plans with its lint result. A Responses page lists `respond.action` events by host, with outcome and undo. Overview tile: tier-0 state (off, alert-only, or on), breakers open, loops open. The safe-mode switch is a shell control. Host-grid column: none.

**9. Health**

`ok` when tier 0 is configured as intended; `disabled` for tier 0 when `enabled: false` (the module still builds proposals); `degraded` when an action type's breaker is open, when a recipe's action is missing on this OS, or when a sensor a recipe depends on has a gap. Gaps: each missing action name from the status table, per host. Detail: recipes loaded, tier-0 actions in the last hour, breakers.

**10. Scoring safety**

This module is where an automatic change can reach a scored host, so the limits are structural:

- Tier 0 acts only on unscored state: host firewalls (restored to the manifest-rendered policy, which already allows every scored port from any source), Defender and audit settings, Sysmon, untagged persistence, and one scored-unit restart.
- The restart of a stopped scored unit is the single scored-state action. It is allowed because a stopped scored service scores zero, runs under the circuit breaker, takes the service lock, and is checked by the local probe and the scorer-mimic probe afterwards.
- The scoring-safety lint rules apply at run time on the agent through `actions/guard.go`: no kill of a scored service as a response, scored accounts untouched, scored content untouched, never narrowing a scored port to a source allowlist.
- A response that would change the same object three times in ten minutes stops (loop detection) rather than fight, which covers a GPO or a persistent red process.
- Alert-only stage: `tier0.enabled: false` is the default and each recipe is enabled per host. The Invitational runs tier-0 only on non-scored targets and on one canary host (tier B); automatic action on scored servers waits for the lab and for Invitational data.

**11. Tests**

- Unit: each guard in isolation (protected set, rate limit across a minute boundary, breaker with the `test.failverify` action and a red probe, loop with three restores), safe mode blocking a tier-0 action while a rollback still runs, lock waiting, GPO check stopping a loop, the recipe loader rejecting unknown keys and unknown actions, and a recipe not in the signed config refusing to run.
- Fixture: replay a recorded `detect.alert` stream and assert the exact `respond.action` outcomes.
- Conformance: starts with tier 0 off, rejects unknown config fields, survives link loss (tier 0 keeps working), `go test -race`.
- Lab: T02 (a timer disables the host firewall: restored, trigger identified by loop detection), T11 (Sysmon reinstalled after a stop), T17 (link drop during a firewall-enforce plan; tier 0 and the dead-man do not fight), T36 (hardening with no red steps, zero tier-0 actions on our own tagged work), T16 (a forced breaking change is caught by the probe and rolled back).

**12. Limits and open items**

- `shortcut: the circuit breaker's local probe checks only the transport the declared health block describes; with the link down there is no scorer-mimic probe, upgrade by running the check library's probe on the host if a lab run shows a local pass with a scorer fail.`
- `shortcut: a webshell signature match uses the integrity module's YARA corpus through the scan-on-write recipe; until YARA is wired the quarantine is tier 1 only.`
- Open: the catalogue lists `respond` as agent only; the recipe-to-proposal step is on the controller. Recommendation: change the catalogue row to "Agent + controller" and register the controller side as a small `ControllerModule`.
- Open: whether the tier-0 breaker's red check can be fed by the `checks` module result on the controller with the link up. Recommendation: yes, through the existing `checks` result events, so no sibling import.
- Open: enabling tier 0 per label. Recommendation: per host in `hosts.yml` through the `modules:` list plus the recipe list above; no label shortcut until the lab has run each recipe alert-only.
- Core changes: the signed `AgentConfig` gains `Modules.Respond`; the retrofit adds the `respond.*` kinds; the action names in the status table are added by the owning families.
