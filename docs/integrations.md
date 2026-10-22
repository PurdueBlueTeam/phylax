# Integrations: Wazuh, Splunk HEC, Suricata/Zeek

Optional sensors (design: "OSS alongside Phylax"). Nothing on the critical path depends on them.

## Plan templates (`plans/`)

YAML templates, embedded and validated by package `plans` against `internal/plan` and the action catalog
(`actions.Core()` plus `plans/actions.yaml`). `vars` hold per-event values (hosts, addresses); a node with
`each: <listvar>` expands to one node per host (`id.host`, target `${host}`); a `needs` on an expanded node
points at the same host's instance when the dependent is expanded over the same list. Empty `risk` takes the
action's catalog risk.

- `wazuh.deploy`: manager (default ubuntu-wkst, or the Splunk host capped) and agents pinned to 4.14.9, packages from
  the depot (`depot:wazuh/<version>`), firewall to our hosts only, active response and remote commands off,
  `authd` password then disabled after enrollment, FIM/rootcheck+syscollector/SCA agent groups, health gates.
- `wazuh.evidence`: health, agent list export, group config hashes, test alert, human screenshot gate.
- `splunk.forwarding`: HEC token and dedicated `phylax` index, firewall for 8088, probe, syslog fallback input.
- `first-hour/`: `dc.zerologon_first`, `palo.mgmt_lockdown`, `splunk.sidecar_off`, `linux.local_root_bundle`,
  `rhel.cockpit_off`, `web.opencart`, `mail.checks`, `mssql.baseline`, `net.vyos_review`, `ssh.safe` (Appendix H).
  Plan ids are prefixed `fh.`. Host names in `vars` are placeholders; the controller overrides them from the manifest.

### Actions the plan templates need

`plans/actions.yaml` now holds only the stubs still missing (`catalog.Missing()` lists them; a stub is rejected once
the real action exists). Implemented in `internal/actions` (specs register on every platform so the Linux controller
validates Windows plans; the backends come from `Env.Win`):

- Registry and Windows: `registry.set` / `registry.delete` (prior value captured, dead-man rollback; refuses
  LmCompatibilityLevel < 3, NTLM deny, NTLM message-integrity/confidentiality, lockout names, WinRM AllowUnencrypted=0,
  SMB EncryptData, MSSQL ForceEncryption, autostart/logon keys; RDP/WinRM/SMB-server disables become service touches
  the scoring guard refuses where scored), `windows.smb1`, `windows.hotfix` (cached MSU only, wusa), `win.service.config`
  (Spooler off on DCs via `dc_only`; core services never disabled), `win.audit_policy.set` (auditpol, 4688 command line,
  dc/member profiles), `win.defender` / `win.defender.audit` (exclusion audit and removal), `win.firewall` (allow rule in
  Phylax's own COM rule group, snapshot restore), `agentopt.set` (Wazuh `local_internal_options.conf`).
- Active Directory: `ad.zerologon_check` (read-only), `ad.secure_channel` (FullSecureChannelProtection, build and 5829),
  `ad.dc.rpc_range`, `ad.account.audit_groups` (recursive), `ad.account.admincount_sweep`, `ad.account.disable`,
  `ad.account.reset_password`, `ad.account.group_remove`, `ad.account.krbtgt_reset` (destructive, two steps, confirm
  string, ticket-lifetime gap).
- Devices (controller side, `Env.Win.Devices`): `palo.permitted_ips` (own management commit), `palo.commit` (verifies the
  fresh connection and a clean candidate; the commit itself is inside the safe-change run of the step before it),
  `palo.apply` (policy or management scope), `palo.snapshot`, `vyos.snapshot`, `vyos.apply`.
- Splunk: `splunk.rest` (GET only, no search endpoints), `splunk.password`, `splunk.hec_setup` (new index + token via
  8089, never rebinds an existing token), `splunk.sidecar_off`.

`Path` parameters now validate platform-independently (`IsAbsPath`: POSIX, drive and UNC paths), so `file.write`
accepts Windows paths on a Linux controller; `agentopt.set` additionally allows only `local_internal_options.conf`.

Still stubs (Linux/app agent or later): `pkg.install`, `pkg.remove`, `firewall.allow` (use `win.firewall` on Windows),
`ini.set`, `xml.set`, `web.remove_dir`, `web.rename_dir`, `kernel.module_block`, `sysctl.set`, `command.check`,
`sql.query`, `net.http_probe`, `net.tcp_probe`, `wazuh.health`, `wazuh.capture`, `wazuh.test_alert`.
Palo steps stay their own commits (no commit-confirm on PAN-OS).

## Wazuh (`internal/integrations/wazuh`)

API client: JWT auth with re-auth on 401, `/manager/info`, `/agents`, `Health` (active, disconnected,
never-connected). Version pin: `CheckManager` refuses a manager < 4.14.9 (CVE-2025-24016 and the 2026 bugs),
`CheckAgents` refuses any agent newer than the manager; comparison is numeric. TLS verify is on unless
`InsecureTLS` (lab self-signed certs) or a CA is given. Alerts come from the Wazuh indexer
(`wazuh-alerts-*`, the manager API has no alert query); `Poller` imports them as `wazuh.alert` events (normal
priority, de-duplicated at the time boundary). Read-only; Wazuh rule text is never copied (GPL-2.0).

## Splunk HEC (`internal/integrations/splunk`)

`Forwarder.Send` never blocks: a bounded queue (default 1024) drops and counts on overflow. Batches by count
(100) / bytes (512 KiB) / interval (2 s); retries on network, 429 and 5xx with doubling backoff (cap 30 s,
4 retries); 400/401/403/404 are permanent. `Close(ctx)` flushes within its deadline. TLS verify defaults on.
Stats expose sent/dropped/retries/failed for a platform alert.

## Suricata and Zeek (`internal/integrations/suricata`)

Offline readers for EVE JSON (alerts; dns/http as optional context) and Zeek conn.log/dns.log (JSON-lines or TSV).
Lines over 1 MiB and malformed lines are skipped and counted. `CommunityID` (v1, seed 0, verified against the
official vector) fills in missing IDs; `Join` groups events from all sources by Community ID.

## Needs the lab

Real Wazuh 4.14.9 bundle in the depot and its SHA-256s; indexer/API field names on the real build; Wazuh
RAM headroom measurement for manager placement; HEC token creation on the scored Splunk and confirmation the
`phylax` index is unscored; real EVE/Zeek samples from a pulled pcap; each missing action implemented and run
on ccdc27 without a failed Quotient round (Windows backends: registry, SCM, ADSI, wevtapi, auditpol/Defender through the allowlisted exec, COM firewall, all untested off-Windows); Windows service name `WazuhSvc` and `ossec.conf` path per version.
