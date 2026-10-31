#### `ad`

Active Directory on the domain controller: the domain actions, continuous checks of the directory's state, the privileged-account allowlist and the "who can reach Domain Admins" path query, Group Policy response, domain controller service repair and the krbtgt reset. It runs only on hosts with the `domain_controller` role. AD is where red gets the most shells [[how-to-win-ccdc-dealing-with-red-team]].

**1. Purpose and evidence**

- **What it does.** The agent on the DC reads the directory natively (ADSI as SYSTEM, behind the `ADBackend` interface), compares it with what is expected, and emits findings. Its actions change the directory under the same plan, lint and rollback rules as any other action. Event-driven AD detection (5136, 5137, 4670, 4741, 4742, 4929, GPO changes) is detection content in `detect`; this module supplies the periodic checks that run between events and the actions that fix what they find.
- **Evidence.**
  - Prebaked privileged accounts are real: a "Richard G Johnson" Domain Admin [[2026-mw-regional-winterknight-dms]] and an "Admin admin" account in a nested group [[2026-mw-qualifier-ir-ad#e1]]. The organizers also seed AD with "temp admins" and comments on users (MW Discord 2026-10-26).
  - Red reaches Domain Admins by paths, not only by membership [[discord-2026q-rt-debrief#e11]].
  - Red deployed seven "Business GPOs" that local fixes could not beat [[mnccdc-redteam-gpo]], [[mnccdc-redteam-gpo#e4]], [[mnccdc-redteam-gpo#e6]].
  - Red locked a DNS service so even Administrator got Access Denied, and reverting the DC did not fix it for that team [[ccdc-journey-zero-to-nationals#e5]], [[bluescreenofwin-stanford-ccdc-25#e19]].
  - Zerologon then `secretsdump` is red's top AD path [[discord-2026q-rt-debrief#e10]]; a full domain dump arrives about 10 seconds after drop flag at Nationals (decision 10).
- **Decisions applied.** Review D153, D401 (allowlist plus path query, kept in area 5), D402, D426, N5.3, N5.4. Zerologon ordering (D425) is merged into the T+0 console step and the `hardening` plan.

**2. Status and code**

Status: **partial**. The actions are built; the continuous checks, the path query, GPO response and DC service repair are not.

| Piece | Where | State |
| --- | --- | --- |
| `ADBackend` interface and the ADSI implementation (membership, enable, adminCount, password, find by SAM name) | `internal/actions/ad_backend.go`, `ad_adsi_windows.go` | built; reads for SPNs, delegation, key credentials, SID history, ACLs, GPOs, `krbtgt` age, MAQ are not in the interface |
| `ad.account.audit_groups` (nested resolution, allowlist, optional fail) | `ad_accounts.go` | built |
| `ad.account.admincount_sweep`, `ad.account.disable`, `ad.account.reset_password`, `ad.account.group_remove`, `ad.account.krbtgt_reset` | `ad_accounts.go` | built, with rollback data (below) |
| `ad.zerologon_check`, `ad.secure_channel`, `ad.dc.rpc_range`, `windows.smb1` | `ad_netlogon.go` | built |
| `ad.honey_account` | `deception_ad.go`, `deception_ad_windows.go` | built; used by `honeytokens` |
| Group Policy field derivation on events (`sysvol_policy`, `gpo_guid`, `gpo_section`, `gpo_item`, `gpo`) | `internal/collect/winevt/gpo.go` | built |
| GPO rules (D6v, D8d) | `rules/mw-redteam.yml`, `rules/windows.yml` | built (in `detect`) |
| Continuous AD checks every 10 minutes (`hunt.ad`), the "who can reach DA" query | none | missing |
| GPO baseline, `ad.gpo_unlink`, `ad.gpo_disable`, `ad.gpo_restore`, effective-state check | none | missing |
| `service.sddl_reset` and the `dc.service_repair` plan | none | missing |

**Names follow the code.** The core action table lists `ad.krbtgt_reset` and `ad.netlogon_enforce`; the built actions are `ad.account.krbtgt_reset` and `ad.secure_channel`. This section uses the code names (part 12 asks the core table to follow).

**3. Capability manifest**

| Field | Value |
| --- | --- |
| Name | `ad` |
| Sides | agent (on the DC) |
| OS | windows |
| Privilege | root (SYSTEM) |
| Roles | `domain_controller` |
| Consumes | `sec_event` (5136, 5137, 5139, 5141 with `gpo: true`; 4662; 4742), `file_change` with `sysvol_policy: true`, `process_start` |
| Emits | `ad.finding` (schema 1, high), `ad.gpo_finding` (schema 1, high), `ad.gpo_baseline` (schema 1, normal) |
| Budget | CPU 3 ms/s average (a check run is a short low-priority burst), held 8 MB, 1 event/s, burst 20, 50 KB/min out, disk 20 MB (GPO baseline copies) |
| Default | core, on hosts with the `domain_controller` role |
| Tables | none |
| Content | `ad/checks.yml` (check definitions), `ad/service_sddl.yml` (default service security descriptors from the clean reference image), `plans/hardening/dc.service_repair.yaml`, `plans/ad/` |
| Actions | `ad.account.audit_groups`, `ad.account.admincount_sweep`, `ad.account.disable`, `ad.account.reset_password`, `ad.account.group_remove`, `ad.account.krbtgt_reset`, `ad.secure_channel`, `ad.zerologon_check`, `ad.dc.rpc_range`, `ad.honey_account`, `hunt.ad` (the check run), and new: `ad.gpo_baseline`, `ad.gpo_effective`, `ad.gpo_unlink`, `ad.gpo_disable`, `ad.gpo_restore`, `service.sddl_reset` |
| Pages | Active Directory (findings, path query results, GPO baseline) |
| Evidence | see part 1 |

**4. Configuration**

```yaml
# manifest/modules/ad.yml (applies to hosts with the domain_controller role)
ad:
  check_interval_sec: 600            # continuous checks
  privileged_allow:                  # constraint: any other member of a privileged group is High, regardless of whenCreated
    "Domain Admins": [Administrator]
    "Enterprise Admins": [Administrator]
    "Schema Admins": [Administrator]
    "Administrators": [Administrator, Domain Admins, Enterprise Admins]
  groups: [Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, Server Operators, Print Operators, DnsAdmins, Group Policy Creator Owners, Key Admins, Enterprise Key Admins]   # code default (PrivilegedGroups)
  path_query: { enabled: true, max_depth: 6 }
  gpo:
    baseline: first_clean_sweep      # baseline at the first sweep and hunt that come back clean
    response: propose                # propose (one click) | alert
  krbtgt: { gap_minutes: 600 }       # ticket lifetime; both resets are needed to invalidate golden tickets
  service_repair: [RpcSs, W32Time, Netlogon, KDC, ADWS, DNS]
```

```go
// package plan (new agent section) and actions (existing backend)
type ADSettings struct {
	ModuleLimits
	CheckIntervalSec int                 `json:"check_interval_sec,omitempty"` // default 600
	PrivilegedAllow  map[string][]string `json:"privileged_allow,omitempty"`
	Groups           []string            `json:"groups,omitempty"`
	PathQuery        struct {
		Enabled  bool `json:"enabled"`
		MaxDepth int  `json:"max_depth,omitempty"`
	} `json:"path_query"`
	GPO struct {
		Baseline string `json:"baseline,omitempty"`
		Response string `json:"response,omitempty"`
	} `json:"gpo"`
	KrbtgtGapMinutes int      `json:"krbtgt_gap_minutes,omitempty"`
	ServiceRepair    []string `json:"service_repair,omitempty"`
}
```

The allowlist is the set of accounts the team expects to hold privilege. Organizer-seeded "temp admins" are not on it unless an operator accepts them (acceptance goes to overrides, with reason and owner).

**5. Events**

Consumed: as above; a GPO-shaped `sec_event` or `file_change` triggers an immediate GPO comparison between scheduled runs.

Emitted:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `ad.finding` | 1 | high for High, normal otherwise | `check` (name), `severity`, `object` (DN or SAM name), `detail`, `expected`, `path` (for the path query: the principal-to-DA chain with the edge kind at each step), `whenCreated` |
| `ad.gpo_finding` | 1 | high | `gpo_guid`, `name`, `change` (`new`, `modified`, `linked`, `unlinked`, `enforced`, `deleted`), `section`, `item`, `enforced`, `affects` (the effective setting the GPO sets, such as a firewall profile, Defender exclusion or audit policy), `baseline_hash`, `current_hash` |
| `ad.gpo_baseline` | 1 | normal | `count`, `domain`, `taken_at`, the GPO list with GUID, name, version and hash |

**6. Behaviour**

*Continuous checks, every 10 minutes.* There is no clean reference for a domain the competition built, so the DC's agent runs generic checks (`hunt.ad`, definitions in `ad/checks.yml`), not only at enrollment. It reports:

- members of every privileged group, including nested membership (a group inside Enterprise Admins), objects in unusual OUs and `CN=Builtin`, and `whenCreated` compared with the drop flag;
- **the privileged-account allowlist** (review D401): any DA, EA or Builtin member who is not on the allowlist is High, regardless of `whenCreated`;
- SPNs on user accounts; unconstrained, constrained and resource-based delegation;
- `msDS-KeyCredentialLink` and SID history;
- non-default access-control entries on AdminSDHolder and the domain object, especially replication rights;
- every GPO with its links, modification time, contents (tasks, scripts, registry preferences) and SYSVOL writes (the GPO part feeds the response below);
- `krbtgt` password age, machine account quota, DnsAdmins membership, `FullSecureChannelProtection`, the build number;
- AD user Description, Company and Department length outliers and descriptions that look like passwords (the credential hunt in `hunt` reads the same data; this module emits the facts).

Event-driven detection covers the same ground between runs (5136, 5137, 4670, 4741, 4742, 4929; review D402) [COV T-6]; those rules are in `detect`.

*"Who can reach DA" (review D401, kept in area 5).* A light path query over the principals the agent can read, run once per check cycle on the DC. It builds a small in-memory graph for that run from LDAP-readable edges only: group membership (nested), ACL edges on privileged objects (`GenericAll`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, `AddMember` on a privileged group, user or the domain object and on AdminSDHolder), delegation to a DC service, write rights on a GPO linked to the domain or the DC OU, SID history and key-credential links on privileged accounts. For each non-privileged principal that can reach Domain Admins, it reports the shortest path with the edge kind at each step, as `ad.finding` events with the `path` field, depth bounded by `path_query.max_depth`. It holds nothing between runs and is not a graph engine (D-2 limits chains to rows and linking rules; this is a query inside one agent run). Source: [[discord-2026q-rt-debrief#e11]].

*Privileged-group purge (review D153).* `ad.account.group_remove` removes direct members from a privileged group. Members that are only nested through another group are reported so the nesting group can be dealt with. The built-in Administrator and the last enabled Domain Admin are refused, and scored accounts keep their access groups. **The prior membership is stored as the rollback** (`Capture` records an `addmember` undo for each direct member removed, in the shared AD undo format), so a rollback re-adds them. The step output should also print the re-add commands as text, after the pattern in UCI `windows/Dovetail/minutezero.ps1@f2af5a1`, which writes `Add-ADGroupMember` undo lines to `privileges.txt` before the purge; the printed form is small and still to be added to the action's output. `ad.account.disable` and `ad.account.reset_password` refuse scored accounts, the built-in Administrator, `krbtgt` and the last enabled domain admin; `ad.account.reset_password` is for unscored accounts, scored ones change only inside a PCR transaction.

*krbtgt (review D426).* `ad.account.krbtgt_reset` kills forged tickets after the dump red will have. It is destructive and not reversible, takes `step` 1 or 2, requires `confirm: krbtgt@<domain DN>`, and enforces a gap between the steps of at least `gap_minutes` (default 600, the ticket lifetime) measured from the password's last-set time, because both resets are needed to invalidate golden tickets and a second reset inside the ticket lifetime would break valid sessions. This follows the built action; v3 said "a double reset after a passing round" and did not name the gap. Test in the lab whether AD-backed IMAP and POP3 survive the reset, and run step 1 right after a scorer round passes. With a single DC there is no replication delay, but every Kerberos ticket dies.

*Zerologon (review D425).* The ordering rule is in the `hardening` module (the T+0 console step ahead of enrollment, then `dc.zerologon_first`). This module provides the actions it uses: `ad.zerologon_check` (read-only; never fails because a DC is vulnerable, the verdict is in the output) and `ad.secure_channel` (enforce `FullSecureChannelProtection=1`; denies vulnerable channels, never NTLM). `ad.dc.rpc_range` pins the DC's dynamic RPC range to the manifest's `rpc_range` so the firewall can be exact (it takes effect after the endpoint mapper restarts).

*Group Policy response (review N5.3).* Local tier-0 fixes lose to an Enforced GPO, and a block-all GPO that cuts the agent link starts a restore loop. The response is:

1. **Baseline** (`ad.gpo_baseline`) of the SYSVOL policy tree and every GPO object (GUID, name, version, links, enforced flag, per-item hashes) at the first clean sweep and hunt of the DC. The baseline is stored on the DC and copied to the controller as chunks.
2. **Detect** with the existing event rules (D6v, D8d) and the periodic comparison. Each change emits `ad.gpo_finding`.
3. **Effective-state check** (`ad.gpo_effective`, read-only): query the resultant set of policy through the RSoP WMI classes for the settings that matter (firewall profile state, Defender exclusions, audit policy, local group membership, scheduled tasks) instead of reading registry keys, because a registry value can be rewritten by the next policy refresh. It also reports whether any policy blocks the agent's management allow group.
4. **Respond** with one-click actions, each a plan node with rollback: `ad.gpo_unlink` (remove the `gPLink` entry, keeping the GPO), `ad.gpo_disable` (set the GPO's flags), `ad.gpo_restore` (restore the GPO from the baseline copy). In `response: propose` these are proposals on the alert; the scoring lint refuses any GPO change that would alter a scored service's policy, such as a lockout threshold or an NTLM restriction.
5. **The agent link survives a GPO firewall.** The management allows live in their own Windows Firewall rule group (core "Rule hygiene"), the link is the dead-man's confirmation channel, and `respond` stops a restore loop when `ad.gpo_finding` says an Enforced GPO is reverting the fix (review D346).

*DC service repair (review N5.4).* `service.sddl_reset` resets a service's security descriptor to its default, using `SetServiceObjectSecurity` natively (service risk; lock `service:<name>`; touches the service's access). The defaults come from `ad/service_sddl.yml`, recorded from the clean reference image at lab time, not typed from memory. Verify reads the descriptor back and checks that Administrators can query and control the service. The `dc.service_repair` plan runs it for RpcSs, W32Time, Netlogon, KDC, ADWS and DNS, compares the descriptor of each, resets the ones that differ, verifies each service's state, and runs the DNS and WinRM scorer-mimic probes before and after. The detection rule for the tamper (4670, 7040, `sc sdset`) is in `detect`.

*Honey AD accounts.* `ad.honey_account` creates an enabled decoy account with no logon rights, an optional SPN (a Kerberoast trap) and optionally no required pre-auth (an AS-REP trap). The `honeytokens` module owns policy and placement; this module owns the action because it needs the `ADBackend`.

*Record-level backup.* AD, DNS, CA and GPO record-level backup and restore (review N11.5) are specified in `backup`; they use the read primitives and `ad.gpo_*` actions defined here.

**7. Actions and content**

| Action | Risk | Locks | Scorer-visible touches | What it does |
| --- | --- | --- | --- | --- |
| `ad.account.audit_groups` | none | none | none | Reads privileged groups, resolves nesting, reports members outside the allowlist; `fail_on_unexpected` fails the step |
| `ad.account.admincount_sweep` | service | `accounts` | none | Clears stale `adminCount=1` on objects no longer in a protected group; `report_only` reports |
| `ad.account.disable` | lockout | `accounts` | disables an account (refuses scored, built-in Administrator, krbtgt, last DA) | Disables domain accounts; rollback re-enables |
| `ad.account.reset_password` | lockout | `accounts` | sets a password (scored accounts refused outside a PCR transaction) | Resets an unscored account password |
| `ad.account.group_remove` | lockout | `accounts` | removes from a group (scored accounts keep their access groups) | Group purge with stored undo |
| `ad.account.krbtgt_reset` | destructive | `accounts` | sets the `krbtgt` password | Two-step reset with the gap enforced; needs `confirm` |
| `ad.secure_channel` | lockout | none | Netlogon secure-channel enforcement | Zerologon enforcement; `report_only` option |
| `ad.zerologon_check` | none | none | none | Read-only verdict |
| `ad.dc.rpc_range` | service | none | RPC port range | Pins the dynamic range |
| `ad.honey_account` | service | `accounts` | creates a decoy account | Honey AD account |
| `hunt.ad` | none | none | none | Runs the continuous checks and the path query |
| `ad.gpo_baseline`, `ad.gpo_effective` | none | none | none | Baseline and RSoP read |
| `ad.gpo_unlink`, `ad.gpo_disable`, `ad.gpo_restore` | service | `gpo:<guid>` | policy of the domain or the DC OU (the lint refuses changes affecting a scored service) | Unlink, disable, restore from baseline; rollback restores the prior link or flags |
| `service.sddl_reset` | service | `service:<name>` | the service's access | Reset to the recorded default |

Content: `ad/checks.yml`, `ad/service_sddl.yml`, `plans/hardening/dc.service_repair.yaml`, the GPO-response plan `plans/ad/gpo_response.yaml`, and the detection rules D6v, D7c, D7e, D7g, D8b, D8c, D8d, D8e, D8g (in `detect`).

**8. UI**

The Active Directory page lists open findings (privileged members outside the allowlist, delegation, SPNs, key credentials, SID history, ACE anomalies), the shortest "who can reach DA" path per principal, the GPO baseline with changes since, and the effective-state results. Buttons: purge a member (creates the plan), accept a member into the allowlist (writes to overrides with reason and owner), unlink, disable or restore a GPO, run `dc.service_repair`, and the two krbtgt steps (with the gap shown). Host-grid column on the DC: "AD clean" (verified when the allowlist audit has no unexpected member and no unresolved GPO finding).

**9. Health**

`ok` when the ADSI backend answers and the last check run finished on schedule. `degraded` when a check could not read an attribute (a missing permission or an unsupported domain level), when the GPO baseline is not yet taken, or when the RSoP query failed. `unavailable` off a DC. Gaps: each check that could not run and why. Detail: last run duration, findings by severity, baseline age.

**10. Scoring safety**

- Scored accounts: refused by `disable`, `group_remove` (they keep their access groups, so RDP and WinRM logins stay), `reset_password` (only inside a PCR transaction); the built-in Administrator, `krbtgt` and the last Domain Admin are refused everywhere.
- Scored services on the DC (DNS, WinRM): `service.sddl_reset` is restore-to-default and ends with the DNS and WinRM probes; the repair plan runs before and after.
- Zerologon enforcement denies vulnerable channels and never NTLM (core lint). The patch is a separate approved reboot gate with the preflight (`hardening`).
- Lockout-class actions carry the dead-man switch and the rollback data above.
- GPO changes that would set lockout, NTLM restrictions or required encryption the scorer cannot do are rejected by the lint.
- Alert-only stage: the continuous checks and the baseline are read-only; every write is a one-click plan. The Invitational runs the checks and the baseline on the DC (tier A) and the actions only on non-scored accounts (tier B).

**11. Tests**

- Unit (built, extend): the action tests in `ad_accounts_test.go` and `ad_netlogon_test.go` (nested resolution, cycles, refusals, the krbtgt gap, rollback); new tests for the allowlist audit, the path query on a fake directory (a nested group, a `WriteDacl` edge, a delegation edge, a GPO write right), the GPO baseline diff, `service.sddl_reset` verify on a fake security descriptor, and the printed re-add commands.
- Fixture: recorded 5136/5137/5141 events and SYSVOL file events through the GPO field helpers (`gpo_test.go`).
- Conformance: starts off a DC as `unavailable`, survives link loss, reconfiguration, `go test -race`.
- Lab (a Windows Server 2022 DC with a member): T07 (DCSync), T08 (Kerberoasting with the honey SPN), T38 (Zerologon, hidden accounts, AD GPO and ACL changes each raise their alert), a seeded temp admin and a nested admin group found by the allowlist and the path query, an Enforced "Business GPO" detected, unlinked and restored with the agent link intact, and a locked service SDDL repaired with the probes green. Latencies are measured and reported.

**12. Limits and open items**

- `shortcut: ADBackend exposes only membership, enable, adminCount and password operations; the continuous checks need read methods for SPNs, delegation, key credentials, SID history, ACLs, GPO objects, krbtgt age and MAQ; add them to the interface before the first DC lab run.`
- `shortcut: the path query reads LDAP-visible edges only (membership, ACLs, delegation, GPO rights), not session or local-admin edges; upgrade only if a purple-team run shows a path it misses.`
- `shortcut: RSoP through WMI is slow on a loaded DC and the effective-state check is on demand and once per baseline comparison, not continuous.`
- `shortcut: ad/service_sddl.yml holds the defaults for the six DC services from one reference image; other builds need their own entry.`
- Open: AD duplicate-group consolidation (about 500 duplicate groups across 10 departments was an inject-like task [MW Discord 2026-10-26, area 7 revision]). Recommendation: only a read-only duplicate-group report as an AD check if the task is asked; no remediation action without a request.
- Open: whether `ad.gpo_restore` restores from the controller's copy when the DC's own baseline copy was tampered with. Recommendation: yes, the controller holds the baseline copy as chunks and the action takes the hash from the signed step.
- Core changes: the core action table should use `ad.account.krbtgt_reset` and `ad.secure_channel`; `service.sddl_reset` and `ad.gpo_*` are added to the Domain family; `ADBackend` read methods; `Modules.AD` in the signed config.
