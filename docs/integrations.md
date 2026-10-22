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

### Implemented Linux and application actions (`internal/actions`, files `linux_*.go`, `app_*.go`)

Backends are injected through `Env.Linux` (`LinuxEnv`): command runner (the `host.exec` escape hatch, with an
optional hash-pinned tool list), patch-window lookup, depot directory, firewall manager, database dialer, HTTP
client, Wazuh API factory, inode-flag backend. Every one has a fake for tests; nothing in the tests touches the
real host.

- `pkg.install`, `pkg.upgrade`, `pkg.remove`: apt/dnf via the runner only inside an open patch window, through
  the window's loopback proxy; versions pinned; `source: depot:<path>` installs a file from the local depot after a
  sha256 check (param or `SHA256SUMS`), re-verified right before use; dry-run shows the package manager's simulated
  transaction; refuses removing a package that provides a scored service. Not rolled back automatically.
- `firewall.allow`: adds or updates one tagged inbound rule in the declared host policy and installs it through the
  firewall manager (`NftFirewall` adapts `internal/firewall`); rollback restores kernel and declared state.
- `ini.set`, `conf.set`, `service.config`: comment- and order-preserving atomic key edits (stanza INI, `key = value`
  with brace blocks and Postfix continuation lines, sshd-style space separated), the service's own syntax check
  (`sshd -t`, `postfix check`, `doveconf -n`) with automatic restore of the old file on failure, and the
  scoring-safety lint below.
- `xml.set`: in-place element text edit at an xpath subset (`//a/b`, `[n]`, `[@a='v']`), multi-root documents,
  comments and layout untouched; creates a missing leaf under an existing parent.
- `agentopt.set`: Wazuh `local_internal_options.conf` keys (POSIX or Windows paths).
- `sysctl.set` (runtime plus `/etc/sysctl.d/99-phylax.conf`, rollback restores both), `kernel.module_block`
  (modprobe.d blacklist plus `install /bin/false`, unload via `delete_module`), `systemd.dropin` (allowlisted
  settings, daemon-reload), `cockpit.disable`, `cron.disable` / `at.disable` (quarantine, never delete),
  `file.attr` (chattr flags through ioctl; refuses `+i`/`+a` on cache, log, upload and database paths).
- `mysql.audit`, `mysql.lock`, `sql.query` (mysql/mariadb only): built-in client for the unix socket
  (native, caching_sha2 and socket auth; LOCAL INFILE refused). `sql.query` takes named statements
  (`version`, `audit_accounts`, `rotate_opencart_admin`) or one parameterised statement; writes need `write: true`.
  The rotated OpenCart password is returned in the output (`password`) for the vault.
- `web.remove_dir`, `web.rename_dir` (fixes `HTTP_SERVER`/`HTTPS_SERVER` and absolute paths in `config.php`),
  `web.opencart_audit` (install dir, default admin dir, writable config, PHP in upload dirs, vendor hash diff,
  extension list, admin users and installed extensions from the database).
- `net.tcp_probe`, `net.http_probe`, `command.check` (sudo, pkexec, ssh, kernel, user-namespace probes with the
  known vulnerable ranges), `wazuh.health`, `wazuh.capture`, `wazuh.test_alert`.

Scoring-safety lint (refusals wrap `ErrScoringUnsafe`, apply in dry-run too): sshd `PasswordAuthentication no`,
key-only `AuthenticationMethods`, `PermitTTY no`, `ForceCommand`/`ChrootDirectory`, `LoginGraceTime 0`, `UsePAM no`,
`AllowUsers` that omits a scored account, `AllowGroups`; Dovecot `disable_plaintext_auth yes`, `ssl required`;
Postfix TLS-only/`noplaintext`/postscreen/sender-domain rejects; Splunk SSL/mgmt port/`acceptFrom`/lockout/auth
changes; `bind-address` on loopback for a database; `icmp_echo_ignore_all`; drop-ins that restrict a scored
service. The rules are skipped only when the guard lists this host's scored services and the service is not one.

### Remaining stubs (Windows, AD, devices, Splunk)

These are declared as data in `plans/actions.yaml` so templates validate today
(`catalog.Missing()` lists them; a stub is rejected once the real action exists):
`registry.set`, `windows.smb1`, `ad.secure_channel`, `ad.zerologon_check`, `windows.hotfix`,
`palo.permitted_ips`, `palo.commit`, `splunk.rest`, `splunk.password`, `splunk.hec_setup`, `vyos.snapshot`.
`sql.query` with `engine: mssql` returns `ErrUnsupported` (MSSQL is not in this action set).

Also: `file.write` validates paths as POSIX on the controller, so Windows paths need a platform-aware validator
(worked around with `agentopt.set`). Palo steps must be their own commits (no commit-confirm on PAN-OS).

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
on ccdc27 without a failed Quotient round; Windows service name `WazuhSvc` and `ossec.conf` path per version.
