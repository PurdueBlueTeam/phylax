# Manifest format reference

The manifest is the only place infra facts live. Host firewall policy, Palo and
VyOS rules, egress allowlists, agent configs, checks and inject artifacts are
generated from it (design: "Manifest"). This page describes the files, the
loader, the lint and the renderers implemented in `internal/manifest` and
`internal/manifest/render`.

Examples: `manifest/2027/` (the 2027 reference, team 1) and
`manifest/two-segment/` (2026 style: a relay-served DMZ). JSON Schemas for
editors and CI are in `manifest/schema/*.schema.json`; they are generated from
the Go types (`go test ./internal/manifest -update-schema`) and a test fails if
they are stale. The Go loader is the authority: it rejects unknown keys.

## Loading

```go
m, err := manifest.LoadDir("manifest/2027", manifest.Options{})   // strict decode + validation
findings, err := render.LintAll(m)                                // manifest lint + firewall lint
```

- **Strict decoding.** Every file is decoded with unknown keys as errors.
  Files over 4 MiB and more than 4096 entries per file are refused.
- **Templates.** Any string value may contain `{{ expr }}` where expr is
  integers and `team` joined by `+` and `-` (`"172.25.{{ 20 + team }}.10"`).
  Quote templated values. `team` comes from `topology.yml`; `Options.Team`
  overrides it. Keys are never templated.
- **Validation** (errors, load fails): references (hosts, segments, devices,
  credlists, relay hosts, dependency targets), CIDR/address syntax, address
  uniqueness, addresses inside their segment, same-last-octet public NAT inside
  the pool, enum values, port clashes on a host, service dependency cycles,
  segments that cannot reach the controller, a loopback-only operator UI,
  exactly one controller.
- **Secrets never appear** in the manifest; it names them (`default_credentials:
  host.default`) and values live in the controller vault.

## Files

| File | Top-level key | Declares |
| --- | --- | --- |
| `topology.yml` (required) | (the file itself) | `team`, `controller`, `segments`, `devices`, `backups` |
| `hosts.yml` (required) | `hosts` | hosts |
| `services.yml` | `services` | services |
| `accounts.yml` | `accounts` | managed accounts |
| `scorer.yml` | `scorer` | the scorer (Quotient) and PCR credlists |
| `devices.yml` | `devices` | network devices (merged with `topology.yml` devices; a name in both is an error) |
| `decoys.yml` | `decoys` | per-host decoys |
| `integrations.yml` | `integrations` | optional sensors (`wazuh`, `suricata`, `zeek`, `splunk_hec`, `clamav`) |
| `policy.yml` | `policy` | firewall invariants, egress, patch windows, response, retention, limits |
| `overrides.yml` | `overrides` | competition-day changes: `adopted_drift`, `inject_changes`, `accepted_findings` |

### topology.yml

| Key | Meaning |
| --- | --- |
| `team` | Team number 0-255 (placeholder in examples) |
| `controller.host / agent_port / ui` | Controller host, agent/bootstrap port, loopback `host:port` operator UI |
| `segments.<name>.cidr` | Segment network |
| `.firewall`, `.uplink` | Device guarding the segment; device reached through its outside |
| `.nat.public_pool`, `.nat.mode` | Public pool; `static_1to1_same_octet` |
| `.relay`, `.relay_port`, `.parent` | Relay host in this segment (role `relay`), its port (default 7444), the segment whose relay/controller it dials (default: the controller's segment) |
| `.controller_path.{via,public,allow_from,port}` | The declared path from a segment outside the controller's LAN: static NAT to the controller's `public` address; the Palo rule allows only `allow_from`'s translated source on `port` |
| `devices.<name>` | See devices below |
| `backups` | `{name, host, path}` backup targets |

A segment other than the controller's must have a `controller_path` or a
relay chain that reaches one.

### hosts.yml

`segment`, `ip` (address or `dhcp`), `public` (same last octet as `ip`, inside
the segment's pool), `os.{family,distro,version}` (family: debian, rhel, suse,
arch, alpine, windows), `roles`, `class` (`server` default, or `workstation`),
`default_credentials` (secret name), `hardening` (declared scorer-sensitive
knobs: `lockout_policy`, `ntlm`, `lm_compat_level`, `protected_users`,
`icmp_echo`).

Roles: `controller`, `relay`, `device_proxy`, `check_runner`, `scanner`,
`canary`, `decoys`, `capture`; `vantage` is shorthand for
`check_runner + scanner + canary`.

### services.yml

`host`, `kind` (http, https, ssh, mail, smtp, imap, pop3, ftp, dns, icmp, smb,
winrm, rdp, mssql, mysql, splunk, ldap, tcp), `scored`, `state` (`running`
default, `stopped`, `disabled`), `listen[{proto,port,sources}]`, `process`,
`transport` (what the scorer does: `plaintext`, `tls_verify`, `starttls`
never/optional/required, `auth` password/ntlm/key/none, `pty`, `shell`,
`encryption` none/optional/required), `content`, `data`, `outbound` (`none` or
a host list), `depends_on[{egress,to,ports,proto,service}]`, `health`.
`depends_on.service` names the target service and feeds the cycle check.
`listen.sources` restricts who may connect; it is accepted for unscored
services and rejected by the lint for scored ones.

### accounts.yml

`scope` (local, domain, service, device), `hosts`, `scored` (`true`, `false`,
`unknown` = protected: treated as scored), `credlist` (key in `scorer.yml`),
`rotation` (`pcr_transaction`, `free`, `manual`), `learn_from`, `embedded_in`,
`ssh_auth` (password, both, key_only), `shell`, `username` (default: key up to
`@`).

### scorer.yml

`engine` (quotient), `portal`, `identifier`, `delay`/`jitter`/`timeout`
(durations; defaults 60s, 5s, Delay/2), `known` (false: estimates),
`sla_threshold`, `credlists.<name>.path` (PCR calls use the path, never the
display name), `poll_portal` (off, ask_organizers, operator_paste,
cookie_poll).

### devices

`vendor` (panos, vyos, ftd), `mgmt`, `segment`, `via` (device the management
path crosses), `external_ip` (address the device source-NATs to on its
outside; VyOS `172.31.(20+T).2`), `ports` (management ports; vendor default),
`adapter`, `proxy` (a `device_proxy` host).

### decoys.yml

Per host: `listeners[{kind,port}]` (ssh, mysql, redis, telnet, winrm, rdp,
http_admin), `honey_files`, `honeytokens[{kind,at}]`, `exposure`
(lan/public/both). Values and banners are generated at competition time.

### policy.yml

`firewall.{icmp,dhcp,ipv6}` (`allow`; `drop` is an error), `egress`
(`allow[{host,to,ports,proto,reason}]`, `sinkhole.{enabled,port}`,
`canary_ports`, `deny_log_group`), `patch_windows`, `response`,
`protected_processes`, `retention`, `limits`, `cache_tiers`.

## Lint

`manifest.Lint(m)` and `render.CheckAll(m)` produce `Finding{ID, Severity,
Subject, Message, Accepted}`, sorted errors first. `render.LintAll` merges
both. Errors fail CI and plan generation. Warnings and info can be accepted in
`overrides.yml` (`accepted_findings: [{id, subject, reason}]`); errors cannot.

| ID | Sev | Rule |
| --- | --- | --- |
| SS001 | error | Lockout machinery (`hardening.lockout_policy`) on a host with scored services or protected accounts |
| SS002 | error/warn | Scored SSH: `auth` key/none, `pty: false`, `shell: false` (error); no `transport` block (warn) |
| SS003 | error | Scored/protected account with `ssh_auth: key_only` or a nologin/rbash/false shell |
| SS004 | error/warn | Scored mail: STARTTLS required or plaintext refused; scored FTP/HTTP refusing plaintext |
| SS005 | error | A scored listener has `sources` (source filtering) |
| SS006 | error | ICMP echo dropped (`policy.firewall.icmp: drop`, `hardening.icmp_echo: drop`) |
| SS007 | error | NTLM denied, `lm_compat_level` < 3, Protected Users, required encryption (SMB, WinRM, FTPS, MSSQL), non-NTLM WinRM on scored paths |
| SS008 | error | A scored service is `stopped` or `disabled` (never SSH/WinRM/RDP) |
| SS009 | error | Scored/protected account not rotated by `pcr_transaction` |
| SS010 | error/warn | Scored account without a credlist (error); protected without one (warn) |
| SS011 | error | A response tier action kills or disables a service |
| DC001 | error/warn | A decoy on a scored port (error) or any service port (warn) |
| DC002 | error | Decoys on a host without the `decoys` role |
| FW002 | error | `policy.firewall.dhcp: drop` |
| FW003 | error | `policy.firewall.ipv6: drop` |
| EG001 | error | An egress allowance wider than a /16 |
| EG002 | warn | Patch window longer than 60 min or without an upstream allowlist |
| NET001 | warn | Controller (or relay) on DHCP while a static NAT or relay allowlist depends on it |
| NET002 | warn | Scored service on a host without a public address in a NATed segment |
| NET003 | warn | `depends_on` port that nothing on the target listens on |
| SC001 | info | Scorer timing values are estimates |
| SC002 | warn | Scorer timeout exceeds delay |
| FW101-FW108 | error/warn | Rendered host policy: a scored port not accepted from all sources; ICMP, ICMPv6, DHCP, DHCPv6 missing; a dependency or the agent link blocked; server not default-deny; a drop rule outside the canary group |
| FW101, FW102, FW109 | | Device intents: a scored rule restricted by source; no ICMP allow; (info) a NAT target needing a manual address |

## Renderers (`internal/manifest/render`)

`BuildHostPolicy(m, host)` derives a typed `HostPolicy` (rules in groups
`base`, `mgmt`, `service`, `dependency`, `decoy`, `egress`, `canary`); the
outputs below are renderings of it.

- **nftables** (`NFTables`): per Linux host, three tables loaded atomically by
  declare/delete/define: `phylax_mgmt` (agent link, relay, device access; marks
  flows with conntrack mark `0x7068`, never drops), `phylax` (default-deny in
  and out for servers; loopback, established, ICMP, ICMPv6, DHCP, DHCPv6,
  services from any source, decoy listeners, canary drop+log, dependencies,
  egress allowances, then a rate-limited NFLOG of denied egress) and
  `phylax_nat` (sinkhole redirect of denied outbound TCP in a `nat` chain,
  sparing everything allowed). Workstations (`class: workstation`) keep
  default-deny input but accept output. Validated with `nft -c -f` in tests.
- **Windows** (`WindowsRules`): `WinPolicy` of typed `WinRule`s in groups
  `Phylax Mgmt`, `Phylax Service`, ... with default inbound Block and default
  outbound Block (servers) or Allow (workstations). Not PowerShell.
- **Palo Alto** (`PaloIntents`): addresses, static NAT, security rules
  (outside-to-inside scored/decoy services from any source with the pre-NAT
  destination, ICMP, the Kali path allowing only the VyOS translated source on
  the agent port, device access, server egress deny), and a separate
  management lockdown commit (additive). Everything carries `phylax-managed`;
  rules carry a `commit` group and a `risk` class.
- **VyOS** (`VyOSIntents`): source NAT to the device's `external_ip`, forward
  rules (ICMP, the Kali path, scored services from any source) and the
  management-access restriction (lockout class, soft-revert protocol).

## Decisions where the design was silent

- `devices` are accepted in `topology.yml` (as in the design's reference) and in
  `devices.yml`; they are merged.
- The VyOS external address needed for the Kali's translated source is
  `devices.<vyos>.external_ip`; the design only gives it in prose.
- `class: workstation` marks hosts outside server egress rules (the design says
  workstations have PAT internet access but does not name the field).
- A DHCP host appears in rules as its segment CIDR (`approx`); static NAT
  targets that need an exact address are `unresolved` and printed for the
  Network role.
- The management table admits flows by conntrack mark so the service table
  need not duplicate management allows.
- Canary probes are *dropped and logged* on the way out (they are expected to
  fail) and the Kali listens on the canary ports to catch a leak.
