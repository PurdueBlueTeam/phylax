#### `hardening`

Plan packs: YAML plan templates over the core actions that harden hosts without failing a scored check. This module is content, not code. It carries the first-hour mitigations, the baseline Windows, AD and Linux packs, banner and password-policy plans, service configuration templates, the reboot-survival preflight and the noexec temp-mount plan.

**1. Purpose and evidence**

- **What it does.** Every pack is a plan template (core "Plans") that selects its targets from the manifest, shows a dry-run diff and a scoring-safety lint result before anything runs, takes the dead-man switch where a node can cut the link, runs the scorer-mimic probe after, and records rollback data. The pack library is what the team runs after the T+0 console phase and enrollment.
- **Evidence.** Every winning team ships hardening as its minute-zero core: UCI [[cyberuci-locs#e2]] to [[cyberuci-locs#e10]], CPP [[cpp-cyber-blue#e21]] to [[cpp-cyber-blue#e28]], Stanford [[bluescreenofwin-stanford-ccdc-25#e6]], DSU [[dsu-defsec-ace#e2]]. Red had AD through Zerologon right away [[discord-2026q-rt-debrief#e10]] and only 2 teams mitigated it in 2025 [[2025-minnesota-and-indiana-ccdc-debrief#e2]]. The injects ask for banners in 16 events and a password policy in 15 (`injects/frequency.md`), and "add banners to Ansible" is a team lesson [[discord-2026q-lessons#e2]]. A reboot that loses a scored service is a full outage and there are no snapshots, only a power cycle or a new reservation [[2027-mw-invitational-packet#e30]]; patch only what matters [[how-to-win-ccdc-dealing-with-red-team#e8]].
- **Evidence against careless hardening.** UCI's `php.sh@f2af5a1` appends `file_uploads=off` and `max_execution_time=3` and restarts the web servers with no probe, which is exactly what the lint and the probe exist to prevent. SEMO's `master-ubuntu-ecom.sh` deletes every `authorized_keys`, the class of change the lint catches. Every setting below goes through the lint.
- **Decisions applied.** Review D163, D425, D523, D525 to D530, D532, N3.2, N5.2, N5.5, N5.7. IIS is dropped (not in the 2027 environment [[vulns-windows]]). The exec gate, ModSecurity and the Dropbear change are cut (review A5.Q3).

**2. Status and code**

Status: **partial**. The first-hour plans exist; the baseline packs and the new plans do not.

| Piece | Where | State |
| --- | --- | --- |
| Plan template loader and validator (variables, `each` expansion, gates, dead-man seconds, catalog check) | `plans/plans.go`, `plans/plans_test.go` | built |
| First-hour plans: `dc.zerologon_first`, `linux.local_root_bundle`, `mail.checks`, `mssql.baseline`, `net.vyos_review`, `palo.mgmt_lockdown`, `rhel.cockpit_off`, `splunk.sidecar_off`, `ssh.safe`, `web.opencart` | `plans/first-hour/*.yaml` | built; the files move to `plans/hardening/` in the retrofit, ids keep the `fh.` prefix |
| Actions used: `ad.zerologon_check`, `ad.secure_channel`, `windows.smb1`, `windows.hotfix`, `service.state`, `file.perms`, `file.hash`, `kernel.module_block`, `sysctl.set`, `command.check`, `web.remove_dir`, `web.rename_dir`, `sql.query`, `mssql.audit`, `mssql.lock`, `net.http_probe`, `net.tcp_probe`, `splunk.rest`, `splunk.password`, `cockpit.disable`, `palo.permitted_ips`, `palo.commit`, `win.defender`, `win.audit_policy.set`, `systemd.dropin`, `service.config`, `file.write` | `internal/actions` | mostly built |
| Baseline Windows, AD and Linux packs | none | missing |
| Banner and password-policy plans | none | missing |
| Reboot-survival preflight template | none | missing |
| Noexec temp-mount plan and the action it needs (`mount.remount`) | none | missing |
| Service config templates with validators (httpd, PHP, Postfix, Dovecot, Splunk, DNS) | partial (`file.write`/`service.config` exist; templates and the `validate` hook are not all wired) | partial |
| `kernel.module_block` verify for a built-in module | `internal/actions/linux_kmod.go:111-120` | bug (Known bug 1), see Behaviour |

**3. Capability manifest**

| Field | Value |
| --- | --- |
| Name | `hardening` |
| Sides | controller (the plan engine loads the templates; agents run the actions) |
| OS | both |
| Privilege | none (controller); the actions run as root or SYSTEM through `exec` |
| Roles | any host; packs target by label |
| Consumes | none of its own |
| Emits | none of its own; plan, step and audit events are the execution engine's |
| Budget | none (content); each action runs inside the executor's limits |
| Default | core |
| Tables | none |
| Content | `plans/hardening/` |
| Actions | none registered |
| Pages | Plans (the pack library, a shell page); host-grid columns "hardened" per pack |
| Evidence | see part 1; also [[kb5014754-certificate-based#e3]], [[cert-cc-vulnerability-note-vu-260001#e6]] |

**4. Configuration**

```yaml
# manifest/modules/hardening.yml
hardening:
  packs:                                   # which packs apply to which hosts (label expressions)
    - { pack: dc.zerologon_first,   target: "dc" }
    - { pack: win.baseline,         target: "windows && !workstation" }
    - { pack: ad.baseline,          target: "dc" }
    - { pack: linux.baseline,       target: "linux && !workstation" }
    - { pack: linux.local_root_bundle, target: "linux" }
    - { pack: ssh.safe,             target: "linux" }
    - { pack: php.harden,           target: "web" }
  noexec_temp:                             # opt in per host (live remount, no reboot)
    hosts: []
    paths: [/tmp, /dev/shm, /var/tmp]
  banner:    { text_ref: overrides.banner }          # event text, entered at runtime
  password_policy: { values_ref: overrides.password_policy }   # values come from the inject; no defaults ship
  reboot_class: [kernel_cmdline, windows_cu, lsa_ppl, smb1_client, boot_start]   # changes that require the preflight
```

```go
// package hardening (controller side)
type HardeningSettings struct {
	Packs      []PackTarget `json:"packs"`
	NoexecTemp struct {
		Hosts []string `json:"hosts,omitempty"`
		Paths []string `json:"paths,omitempty"`
	} `json:"noexec_temp"`
	BannerRef         string   `json:"banner_ref,omitempty"`
	PasswordPolicyRef string   `json:"password_policy_ref,omitempty"`
	RebootClass       []string `json:"reboot_class,omitempty"`
}
type PackTarget struct{ Pack, Target string }
```

The banner text and the password-policy values are event facts: the inject text defines them, so they are entered in the UI and written to `overrides.yml`. The repository holds the plan, never the text (anti-goal: event-specific facts that need a commit; non-goal: prewritten inject text).

**5. Events**

None of its own. Plan and step events, approvals and the audit trail are the execution engine's. The pack states appear in the host x step grid through the plan and node status (core UI shell).

**6. Behaviour**

*Rules every pack follows.*

- One setting per node, so the dry-run diff, the lint and the rollback are per setting.
- Every node declares the scorer-visible properties it touches (action `Touches`); the lint and the agent-side guard reject a node that would break the scorer (core lint table). The pre-change baseline snapshot says when an organizer-set "insecure" value is the reason the scorer works [SH intro].
- Config writes use the `validate` hook (`sshd -t`, `visudo -cf`, `apachectl -t`/`httpd -t`, `nginx -t`, `named-checkconf`, `postfix check`, `php -l`, `nft -c`).
- Nodes that can cut the link carry `deadman_sec` (default 90).
- Each pack ends with the scorer-mimic probe for the services it touched (before and after; a failed "after" rolls the node back; a failed "before" stops the node).
- A pack that ends with a passing probe ends with `guard.snapshot` for each service it touched if `content_guard` is enabled, then the golden backup (`backup`) and the ledger sweep and hunt clean-check.
- Order after the T+0 console phase and enrollment: as-found backups; firewall plans (shadow, review, enforce; `firewall`); service hardening packs with probes; golden backups as each passes. Zerologon on the DC comes before any domain rotation.
- After enrollment (the core "After enrollment" rule): SSH, WinRM and RDP are treated like any other service. A node `remote_access.manifest_only` disables any remote-management service the manifest does not declare for that host, with the console as break-glass. On the 2027 hosts SSH on the Linux hosts, WinRM on the AD host and RDP on the MSSQL host are declared because they are scored.

*Pack library.* The first ten are the first-hour mitigations (v3 Appendix H, moved here). Each is a plan template with a scoring-safe verdict and a probe [SV R2.4, SH]:

| Plan | Does | Scoring note |
| --- | --- | --- |
| `dc.zerologon_first` | Build and registry check, enforce or patch the secure channel, Spooler off, SMBv1 off | No NTLM disabling; the patch needs a reboot (DNS and WinRM briefly down), so it is a separate approved gate |
| `palo.mgmt_lockdown` | Additive permitted-IP restriction to the controller (specified with `devices`, which also audits interface management profiles and GlobalProtect) | Management is not scored; add, commit, verify with a new connection, then remove the old entry in a separate commit |
| `splunk.sidecar_off` | `[postgres] disabled = true`, change the default admin, list apps and inputs (covers CVE-2026-20253, review D525) | Keeps 8000 and 8089 open and the scored Splunk user |
| `linux.local_root_bundle` | `chmod 0755 /usr/bin/pkexec`, block `algif_aead`, check `sudo -V`, unprivileged user namespaces if unused | Breaks polkit GUI auth only |
| `rhel.cockpit_off` | Disable Cockpit on Rocky (review D527) | Not scored |
| `web.opencart` | Remove `install/`, rename the admin directory, rotate the admin password, trim modules (review D528) | Leaves the storefront content untouched; gated on the detected OpenCart branch (4.1.0.4 seen [[2026-mw-regional-bcom12t-response#e1]]) and handles a Docker docroot |
| `mail.checks` | Open-relay check, hash Postfix and Dovecot binaries, remove unscored webmail if outdated (review D529) | Keeps plaintext listeners and AD-backed auth |
| `mssql.baseline` | `@@VERSION`, `xp_cmdshell` off, trim sysadmins, review linked servers and Agent jobs (review D530) | Leaves the login the 1433 check uses |
| `net.vyos_review` | Snapshot, `show configuration commands`, rotate `vyos` (specified with `devices`; the Dropbear host-key change is cut) | Soft-revert protocol |
| `ssh.safe` | `LoginGraceTime 20`, `MaxStartups`, `X11Forwarding no` (review D532) | No password-auth, TTY or `AllowUsers` changes for scored users |

*Zerologon: a T+0 console step, then a plan (review D523, D425).* If the DC build is unpatched, the Zerologon check, secure channel enforcement, Spooler off and SMBv1 off are done on the DC console at T+0, before enrollment and before any domain rotation, because a vulnerable DC lets the attacker reset the machine account and dump the new hashes anyway (v3 L1715; Server 2022 is expected to ship the fix [SV R2.4]). The core T+0 section carries the console step. After enrollment `dc.zerologon_first` runs as the verification and repair plan: `check` is read-only (`ad.zerologon_check`: build and update revision against the August 2020 fix, `FullSecureChannelProtection`, the vulnerable-channel allow-list and event 5829 in the last 7 days), `secure-channel` enforces (`ad.secure_channel`, lockout risk, `deadman_sec: 120`, denies vulnerable channels, never NTLM), and the cumulative-update gate stays a separate approved reboot window. The plan is idempotent: if the console step was done, every node reports unchanged.

*`linux.local_root_bundle` and the built-in module case (review D526, Known bug 1).* `kernel.module_block` writes a modprobe blacklist and verifies only that file's content. If `algif_aead` is compiled into the kernel it never appears in `/proc/modules`, the file is written, verify passes and the bundle reports Copy Fail mitigated while it is not [[cert-cc-vulnerability-note-vu-260001#e6]]. The fix: the node first probes `socket(AF_ALG)` bound to `aead` (the Copy Fail precondition); if the module is built in, the node falls back to `initcall_blacklist=algif_aead_init` on the kernel command line, behind a reboot gate and the preflight below. The action change belongs to the core family; the bundle's plan only chooses the branch.

*Reboot-survival preflight (review N3.2).* Reboots are costly: no VM snapshots, and a reboot that loses a scored service is a full outage. The template `preflight.reboot_survival` runs before any node whose action is in the host's `reboot_class` (kernel command line, a Windows cumulative update, LSA protected process light, the SMB1 client driver, a boot-start type change) and has no new Go:

1. Scored services are enabled at boot (`service.state` check mode: unit enabled, service start type automatic).
2. Docker or Podman restart policy is `always` or `unless-stopped` on scored containers.
3. The firewall rules are persisted (the nftables unit enabled and the file current; the Windows Firewall policy is persistent by design).
4. Splunk boot-start is enabled; the SQL service start type is automatic.
5. A listener snapshot (`collect.inventory`) is taken before; after the reboot the same snapshot is compared with it and any scored listener that did not come back fails the plan and names the service.

The reboot itself is a gate with its own approval record, and the post-reboot comparison is the node that closes the plan.

*Noexec temp mounts (review N5.7, A5.Q3: yes, opt-in per host).* Blocks the common drop-and-run from temp directories without an LSM. A plan, not a reboot:

1. **Pre-check (lint).** Refuse the node if any scored service executes from the path: its unit's `ExecStart`, working directory or `TMPDIR`, the paths its processes were seen executing from in the audit history of the last hours, and the ledger paths of its pinned binaries. Also refuse if a package manager run is in progress. This is a scoring-safety lint rule: no `noexec` remount of `/tmp`, `/dev/shm` or `/var/tmp` when a scored service needs it (core lint table).
2. **Remount.** Where the path is its own mount or tmpfs, `mount -o remount,noexec,nosuid`. Where `/tmp` is not its own mount, bind-mount it onto itself first, then remount the bind. No reboot. The native call is the mount syscall through a new core action, `mount.remount` (the agent does not run the `mount` binary).
3. **Verify.** Read `/proc/self/mountinfo` for the options, then try to execute a test binary from the path and expect a refusal.
4. **Rollback.** Remount with `exec,suid` and, if the node created the self-bind, unmount it.
5. **Persistence.** Writing the options into `fstab` is a separate, later step with its own approval, never part of this node.

Installers and package scriptlets can exec from `/tmp` and `/var/tmp`; plans that run `pkg.*` on a host with the flag lift it for the node (tagged) and restore it (part 12).

*Baseline packs (review N5.2).* Content over existing actions; every setting is its own node and goes through the lint. These are the sets every winning team ships at minute zero. The nodes that need a scorer-mimic probe are marked.

| Pack | Settings | Scoring notes |
| --- | --- | --- |
| `win.baseline` | WDigest off (`UseLogonCredential=0`); LSA protected process light (`RunAsPPL`, reboot-class); SMB signing; LDAP signing; NTLMv2-only session security; Kerberos pre-auth required on unscored accounts; Defender exclusions cleared (`win.defender`, keeps exactly the agent's directory); ASR rules (audit mode first); PowerShell module, script-block and transcription logging (also turns on event 4104 for the Windows event rules) | **SMB signing and NTLMv2-only need scorer-mimic probes** (SMB and WinRM). NTLM is never denied and `LmCompatibilityLevel` is never set below 3 (lint). Requiring LDAP signing also rejects simple binds over a cleartext connection, which AD-backed Dovecot or Postfix auth may use (the email host depends on LDAP 389 to the DC), so that node is gated on a mail login probe and on the DC's actual LDAP behaviour in the lab |
| `ad.baseline` (DC only) | `ms-DS-MachineAccountQuota` 0; privileged-group purge (`ad`); `adminCount` sweep; relay and certificate bundle: `StrongCertificateBindingEnforcement` [[kb5014754-certificate-based#e3]], the PetitPotam (EFS RPC) filter, WebClient service off | The privileged-group purge keeps scored accounts' access groups and refuses the built-in Administrator and the last enabled Domain Admin (the action refuses itself) |
| `linux.baseline` | `kernel.yama.ptrace_scope`; protected symlinks, hardlinks, FIFOs and regular files; `user.max_user_namespaces` where unused; SUID strip on LOLbins that no scored service needs; compiler quarantine (moved with metadata, not removed) | Sysctls via `sysctl.set` with a persisted drop-in. Never touches `sshd`, `sudo`, `su`, `passwd` or the pinned scored binaries |
| `remote_access.manifest_only` | Disable undeclared SSH, WinRM and RDP | Never a declared (scored) one |
| `php.harden` | PHP template below | Scorer-mimic probe and rollback |

*Service configuration templates (review D163).* Templates are plan content, not Go: `file.template` plus the `validate` hook plus a graceful `service.state` reload, for Apache or httpd, PHP, Postfix, Dovecot, Splunk and DNS. Each template carries the lint rules for its service (no `PasswordAuthentication no`, no STARTTLS-required, no `disable_plaintext_auth=yes`, and so on). The PHP template sets only dangerous-function and include-path restrictions from the pre-change baseline, validates with `php -l` and `apachectl -t`, and runs the scorer-mimic probe on the storefront page plus the multi-step Orange flow before and after, with rollback by restoring the baseline file and reloading. It never turns uploads off and never shortens execution time without the probe.

*Banners and password policy (review N5.5).* Plans, not prewritten answers. A `banner.policy` plan writes `/etc/issue`, `/etc/issue.net`, `/etc/motd` and the `sshd` `Banner` (validated with `sshd -t`), and on Windows the legal-notice caption and text registry values, from `overrides.banner`. A `password.policy` plan sets `pwquality` and `login.defs` on Linux and the local or domain password policy on Windows, from `overrides.password_policy`, and each plan ends with a node that dumps the effective values (`pwquality.conf` and `login.defs` readings, `net accounts`, `secedit` export) as evidence for the evidence run (`report`). Lockout stays out: faillock, fail2ban and any Windows lockout threshold are rejected by the lint wherever a scored account can authenticate, so account-lockout settings apply only to hosts and OUs with no scored accounts. A Windows legal notice appears before the logon screen and may interrupt an RDP login, so the Windows banner node on the RDP host is gated on the RDP scorer-mimic probe.

**7. Actions and content**

No action is registered here. New actions this content needs from the core: `mount.remount` (Kernel and system family; risk `service`; locks `mounts`; touches the mount options of a path; rollback remounts the prior options). The verify fix for `kernel.module_block` is a core family change.

Content: the ten first-hour plans, `win.baseline`, `ad.baseline`, `linux.baseline`, `remote_access.manifest_only`, `php.harden`, `banner.policy`, `password.policy`, `preflight.reboot_survival`, `linux.noexec_temp`, in `plans/hardening/`. A template looks like this in the form the loader accepts today (the retrofit adds the `module: hardening` header):

```yaml
id: fh.dc.zerologon_first
module: hardening
name: Zerologon first on DCs, Spooler off, SMBv1 off
on_failure: stop_dependents
scoring_note: No NTLM disabling. Patch needs a reboot (DNS and WinRM briefly down) so it is a separate approved gate.
probe: DNS query and WinRM auth succeed against each DC after the step
vars: { dcs: [win-dc, win-dc2] }          # rendered from the manifest by label in the retrofit
nodes:
  - { id: check, each: dcs, action: ad.zerologon_check, target: "${host}", params: {} }
  - { id: secure-channel, each: dcs, action: ad.secure_channel, target: "${host}", needs: [check], deadman_sec: 120, params: { enforce: true } }
  - { id: spooler-off, each: dcs, action: service.state, target: "${host}", needs: [check], params: { unit: Spooler, state: stopped, enable: disabled } }
  - { id: smb1-off, each: dcs, action: windows.smb1, target: "${host}", needs: [check], params: { enabled: false } }
  - { id: patch-gate, gate: true, needs: [secure-channel, spooler-off, smb1-off], note: "Approve the reboot window before applying the cached cumulative update." }
  - { id: patch, each: dcs, action: windows.hotfix, target: "${host}", needs: [patch-gate], params: { kb: cached-latest-cu, reboot: true } }
```

**8. UI**

The Plans page lists the pack library with each pack's dry-run, lint result and scoring note. The host x step grid has one "hardened" column per pack (verified from plan and node status; refreshed by re-running the node's `check`; a manual tick is not enough). Plans show approver names. Banner and password-policy values are entered on the Settings page and stored in overrides.

**9. Health**

Content-only, so health is the plan loader's: `ok` when every template validates against the action catalog; `degraded` listing templates that name an action the catalog does not have yet (the missing actions in part 2), which are shown as unavailable on the Plans page and cannot be run. CI fails a template with an unknown action, a missing `scoring_note` or a node whose `Touches` the lint rejects.

**10. Scoring safety**

This is the module with the most contact with the scored path, so the safety is mandatory and layered:

- The core scoring-safety lint (template time and run time on the agent) judges every node. No lockout machinery on scored accounts, no SSH change that breaks the scorer's login, no mail change that refuses plaintext, never narrowing sources on a scored port, ICMP stays, scored UDP services stay, NTLM and its transport stay, anonymous FTP stays where used, scored content untouched, no kill of a scored service, scored passwords change only through the PCR transaction, no noexec remount that a scored service needs.
- Each pack declares a `scoring_note` and a `probe`. The probe runs before and after for every touched service, using two scored users chosen per credlist.
- Dead-man on lockout-risk nodes; locks; rollback data; one setting per node.
- Reboot-class changes go through the preflight and a gate with an approval record naming the approver.
- Alert-only stage: a pack's first run on any host is a dry run plus the plan's `check`; the Invitational runs packs on non-scored accounts and one canary host, then on one scored server in the second half (tier C), as the review set out.
- The Invitational is the data source for the open lab questions (SMB signing, LDAP signing, legal notice and RDP): it records them and does not change scored hosts blindly.

**11. Tests**

- Unit: `plans_test.go` validates every embedded template against `internal/plan` and the action catalog; new tests assert each pack's nodes have `Touches` that the guard accepts for the reference manifest, and that the lint rejects a deliberately unsafe variant of each pack (a `PasswordAuthentication no` node, a lockout GPO, a source-restricted scored port, a `noexec` remount with a scored service exec path).
- Manifest CI: render every pack for the reference manifest and for a manifest with a Docker service.
- Action tests with fixtures: the `kernel.module_block` AF_ALG branch with a fake `/proc/modules` and a fake socket probe; `mount.remount` on a tmpfs in a privileged lab test (skipped with a clear message otherwise); `php -l`/`apachectl -t` validators on a candidate file.
- Lab: T16 (a hardening plan that breaks a scored page, an SSH `PermitTTY` or a mail plaintext setting is rejected by the lint; if forced, the probe is red and the node rolls back), T17 (link drop during an SSH-reconfigure and firewall-enforce plan; the dead-man rolls back), T34 (the first-hour library against real Quotient: zero failed rounds attributable to Phylax), T36 (hardening with no red steps: zero untagged alerts), T38 (Zerologon check in the lab).

**12. Limits and open items**

- `shortcut: plan variables name hosts directly (dcs, linux_hosts, rocky-web); upgrade to label-expression targets in the retrofit so one template expands from the manifest.`
- `shortcut: the SMB signing, LDAP signing, NTLMv2-only and Windows legal-notice nodes ship with probes but their effect on Quotient's checks is unverified; upgrade at the first lab run against a real Quotient.`
- `shortcut: kernel.module_block falls back to a kernel command-line change that is bootloader-specific (GRUB on the 2027 distros); other loaders are unsupported.`
- Open: whether package-installing nodes lift a noexec flag on the host. Recommendation: yes, inside a tagged window, restored on completion (a node in the install plans), because rpm and dpkg scriptlets can exec from `/var/tmp`.
- Open: whether the LDAP-signing node ships in `win.baseline` or is left to a manual decision after the lab shows the email host's bind type. Recommendation: ship it gated and off until the lab result is in.
- Open (area 7 revision): consolidating about 500 duplicate AD groups is a likely inject; a read-only report only, if asked (`ad`).
- Core changes: the `mount.remount` action; the `kernel.module_block` verify fix; label-expression plan targets; `module:` header on plan templates; the preflight's use of `collect.inventory`.
