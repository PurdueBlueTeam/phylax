# Detection rules: format and field reference

Implementation: `internal/detect`. Corpus: `rules/` (active) and `rules/pending/` (producer missing). Design: `phylax_design.md`, "Detection and response".

## Files and loading

- A rule file is YAML with one or more documents (`---`). A document is a rule (has `id`) and/or carries `profiles:`.
- `detect.LoadDir(dir, opts)` loads `*.yml`/`*.yaml` directly in `dir`. Subdirectories (`pending/`) are not loaded by the agent.
- Loading is strict. These are load errors, never silent: unknown keys at any level; unknown operators; a condition with zero or more than one key; a regex that fails to compile or **matches the empty string**; an empty `all`/`any`/`in` list; an empty or null list item or value (a dangling `-`); an empty-string match value; a rule with no conditions; a missing event kind; bad severity/tier/duration/CIDR; an unknown profile; a profile tested on a field other than the one it learns; duplicate rule ids; revoked or malformed ATT&CK ids (`T1562.001` fails with "use T1685"); a rule without both a `should_match: true` and a `should_match: false` test (not required under `pending/`).
- Regexes are compiled once at load. Rules are indexed by event kind, so an event only visits rules for its kind.

## Rule document

```yaml
id: D6f.immutable-flag            # required; unique
title: ...                        # required
description: ...                  # optional
mode: act                         # act (default; may trigger tier-0/1 responses) | alert; Options.AlertOnly forces alert
scope: agent                      # agent (default) | controller (needs events from several agents)
severity: medium                  # info | low | medium | high | critical
tier: 1                           # 0 automatic | 1 one-click | 2 manual (response tier of the recipe)
attack: [T1222.002]               # ATT&CK v19 ids, required
collect: [process_tree]           # evidence collectors run when the rule fires
ir_template: web-app-compromise   # optional
exempt_tagged: true               # skip events carrying a Phylax tag (see Tags)
entities: [path, exe]             # fields copied into Alert.Entities (default: the count/sequence `by` keys)
message: "{exe} wrote {path}"     # alert text; {field} placeholders
needs: "..."                      # pending rules: the missing producer
source: {author: Phylax, license: repo}   # upstream attribution for imported rules
when:
  event: process_start            # kind or list of kinds (mandatory)
  all: [ ...conditions... ]       # AND
  any: [ ...conditions... ]       # OR, ANDed with all
  count: {window: 2m, gte: 12, by: [agent, source, account], distinct: host, cooldown: 2m}
  sequence: {by: [pid], within: 30s, then: {event: net.connection_opened, all: [...]}}
tests: [ ... ]
```

At least one of `all`/`any` must be non-empty. `count` and `sequence` are mutually exclusive.

## Conditions

A condition is a mapping with exactly one key:

| Form | Meaning |
| --- | --- |
| `all: [c...]`, `any: [c...]`, `not: c` | boolean combinators (lists non-empty) |
| `field: value` | equals (case-insensitive) |
| `field: [a, b]` | in |
| `field: {op: arg}` | operator, exactly one |

A condition on a missing field is false, so `not: {x: a}` is true when `x` is absent. Numbers compare as strings of their decimal form for `eq`/`in` (so `event_id: [4624]` matches int 4624 or "4624"); `gt/lt/gte/lte` parse numbers (decimal or `0x` hex strings). If the event value is a list, an operator matches when any element does.

Operators (string operators are case-insensitive, ASCII folding; suffix `_cs` makes `eq`, `in`, `contains`, `startswith`, `endswith` and their `_any` forms case-sensitive):

`eq` (`equals`), `in`, `contains`, `startswith` (`prefix`), `endswith` (`suffix`), `contains_any`, `startswith_any`, `endswith_any`, `re` (`regex`; RE2, case-sensitive unless `(?i)`; unanchored), `gt`, `lt`, `gte`, `lte`, `cidr` (one or a list; IPv4-mapped IPv6 unmapped), `present` (`exists`; true means non-empty), `in_profile`.

## Counts and sequences

`count`: per key (the `by` fields; a missing field contributes an empty component), fires when `gte` events (or `gte` distinct values of `distinct`) arrive within `window`. After firing the key is quiet for `cooldown` (default `window`). `by: [agent, source, account]` gives per-host, per-source, per-account windows; `agent` is a pseudo field (the event's agent). Evidence is the last three events. State per rule is bounded (`Options.MaxKeys`, default 4096; expired keys are pruned, then the least recently seen evicted). Windows use event time, so replays and tests with a fake clock are deterministic.

`sequence`: the rule's own `when` is stage A; `then` is stage B (own event kinds and conditions). When B matches and an A with the same `by` key arrived within `within`, the rule fires with both events as evidence; A is consumed. One pending A per key, bounded.

## Profiles (`in_profile`)

```yaml
profiles:
  - name: svc.children          # learned baseline
    event: process_start        # events that feed it
    key: [parent.comm]          # baseline per key (optional)
    value: image                # the field learned; the in_profile condition must test this field
    learn: 15m                  # window from the first event of each key
    where: [ ... ]              # optional conditions an event must meet to be learned
    max_keys: 4096              # defaults 4096 / 512
    max_values: 512
  - name: rotation.pending      # static list: no learn; filled with Engine.Seed
```

`{image: {in_profile: svc.children}}` is true while the key's learning window is open (including the very event that opens it) so rules stay quiet while learning, then true only for values learned in the window or seeded. Missing key fields make it false. Static lists: `Engine.Seed(name, key, values...)` (key `nil` for a list). Seeding a key of a learned profile marks it already learned (use for manifest baselines). `ExportProfiles`/`ImportProfiles` persist baselines across restarts. `rules/profiles.yml` holds the shared declarations; the agent seeds `scored.service_comms`, `rotation.pending`, `accounts.scored`, `service.dependencies`, `device.admins`, `reference.windows_tasks` from the manifest and plan engine.

## Tags and exemptions

`exempt_tagged: true` skips any event whose `tag` field is non-empty. The plan engine and patch windows set `tag` (e.g. `plan:harden-linux`, `patch-window`) on events caused by our own work, on every event kind: this is how `chattr +i`, `useradd`, `auditpol`, firewall restores and package installs stay silent. The net module also uses `tag: canary` for its probes; D12 therefore exempts them and V3 deliberately does not set `exempt_tagged`.

Scorer behaviour is exempted by behaviour, never by address (Divisor re-draws addresses): brute-force thresholds sit above Quotient's `badattempts` burst and are per (agent, source, account); fan-out rules exclude `accounts.scored`.

## Inline tests

```yaml
tests:
  - name: shell under a scored service
    should_match: true
    seed: {scored.service_comms: [apache2], svc.children: {apache2: [/usr/bin/convert]}}   # list, or key -> values ("a|b" for composite keys)
    event: {kind: process_start, fields: {image: /bin/sh, parent: {comm: apache2}}}
    # or events: [{kind: ..., at: 5s, agent: h1, fields: {...}}, ...]   (at = offset from a fixed base time)
```

Each test runs on a fresh engine holding only that rule plus all profiles; `should_match: true` passes if the rule fires at least once. `go test ./internal/detect` runs every test in `rules/` and validates `rules/pending/` without running its tests.

## Canonical field names

Field lookup order: the flat key, the nested path (`parent.comm` into `{parent: {comm: ...}}`), then the flat alias. Aliases: `image` falls back to `exe`; `parent.exe`, `parent.comm`, `parent.cmdline` fall back to `pexe`, `pcomm`, `pcmdline`. Pseudo fields: `agent`, `kind`.

**process_start** (Linux audit; Windows Sysmon 1 / 4688): `image` (executed file; `exe` on Windows), `comm`, `cmdline`, `argc` (Linux), `pid`, `ppid`, `uid`, `euid`, `auid`, `cgroup` (Linux unit scope), `cwd`, `parent.{pid,exe,comm,cmdline}` / `pexe`, `pcomm`, `pcmdline`, `user` (Windows), `sha256`/`md5`/`imphash` (Windows), `tag`.

**file_change** (Linux audit and sweep; Windows Sysmon 11/23/26): `path`, `op` (`create`, `modify`, `rename`, `delete`, `attr`; Windows only create/delete), `old_path` (rename source; `path` is the new name), writer identity `pid`, `ppid`, `exe`, `comm`, `uid`, `euid`, `auid`, `ses`, `tty`, `writer_cmdline` (Windows: `actor_exe`, `actor_pid`), `writer_known:false` and `source:sweep` for sweep-found changes, `self_tamper:true` for the agent's own paths, `sha256`/`old_sha256`, `tag`.

**net.listener_added / net.listener_removed**: `proto`, `addr`, `port`, `service` (manifest-declared), `baseline` (start-up snapshot), `pid`, `comm`, `exe`, `uid`, `exe_deleted`, `exe_sha256`, `sock_uid`.

**net.connection_opened / net.connection_closed**: `dir` (`inbound`|`outbound`), `proto`, `laddr`, `lport`, `raddr`, `rport`, `src`, `dst`, `service`, `state`, `community_id`, `bytes_in`/`bytes_out`, process fields as above, `baseline`.

**net.egress_denied**: `dir`, `proto`, `laddr`, `lport`, `raddr`, `rport`, `community_id`, `attributed`, `attempts`, process fields, `tag: canary` and `canary_tag` for canary targets. **net.canary_result**: `result` (`blocked`|`leak`|`error`), `expected`, `raddr`, `rport`, `tag`.

**net_connect** (audit connect/accept; Sysmon 3): audit `direction`, `addr`, `port`; Windows `dir` (`in`|`out`), `src_ip`, `dst_ip`, `src_port`, `dst_port`, `initiated`, `dst_host`.

**audit.rules_changed**, **telemetry_gap** (`source`, `reason`, `count`).

**auth_success / auth_fail** (logs module; winevt 4624/4625): `account`, `source` (source IP), `service` (`sshd`, `cockpit`, ..., `windows`), `method`, `logon_type`, `logon_type_name`, `machine_account`, `status`, `sub_status`.

**sec_event** (winevt): `channel`, `provider`, `event_id` (int), `category`, `record_id`, plus raw EventData keys in snake_case (`target_object`, `details`, `pipe_name`, `source_image`, `target_image`, `task_content`, `image_path`, `service_name`, `new_value`, ...). Categories used: `service_install`, `scheduled_task`, `account_change`, `group_change`, `computer_account_change`, `ad_access`, `ad_object_change`, `kerberos`, `ntlm_validation`, `log_cleared`, `netlogon_secure_channel`, `defender_tamper`, `registry`, `pipe`, `wmi`, `process_access`, `sysmon_state`, `sysmon_config`, `file_time_changed`. Computed: `zerologon_signal`, `replication_rights`, `target_lsass`, `defender_exclusion`, `tamper`, `rc4_ticket`, `subject_account`.

**log_line** (logs module, planned): `file`, `line`, `source` (parsed client address, where a parser extracts it).

## Corpus

`rules/linux_persistence.yml` (file_change), `linux_exec.yml` (process_start), `network.yml` (net.*), `auth.yml`, `windows.yml`, `logs.yml`, `profiles.yml`; `rules/pending/` names each missing producer in `needs:`. Mapping from the proposed rules P01-P81 to ids is in the rule ids (`D18.default-cred-logon` = P01 ...); additional catalog rules: D1, D3, D4, D5a/b, D5h, D7a, D6a, D2a, D10 (audit rules, telemetry gap), D12/D12b, V3.
