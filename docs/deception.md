# Deception: decoys and honeytokens

Design reference: `phylax_design.md`, "Deception" and detection D15. This page
documents what is implemented in `internal/decoys`, `internal/honeytokens`,
`pools/` and `rules/deception.yml`.

## Principles enforced in code

- Record only. `internal/decoys` imports no process-execution package (a test
  parses the sources and fails on `os/exec`, `syscall`, `plugin`, `unsafe`, file
  writes or removals). The fake shell is a function over an in-memory filesystem
  built from `pools/fs`; `touch`, `echo >`, `rm` change only that memory.
- Never on a scored port. `decoys.New` returns `ErrScoredPort` for a listener on
  any port in `Config.ScoredPorts`, and always refuses 445. The agent factory
  (`internal/agent/mods/deception.go`) passes the scored ports from
  `deception.json` plus every port in the net module's service map, so a decoy
  never shares a port with any declared service. The manifest lint (DC001) is the
  first line; this is the agent-side backstop.
- Bounded. Per-source concurrent sessions, total sessions, a hard session
  timeout, an idle timeout, a command cap, an auth-attempt cap, bounded line,
  bulk, HTTP and MySQL packet sizes, and a per-source token bucket on events.
  Honeytoken hits bypass the event rate limit; everything else is dropped and
  counted (`Stats.HitsDropped`).

## `decoy.hit` event

Kind `decoy.hit`, priority Critical (so it rides the spool's top class); the
`severity` field carries the depth.

| field | meaning |
| --- | --- |
| `stage` | `connect`, `login`, `command`, `request`, `rejected`, `end` |
| `severity` | `info` (connect, request), `high` (login, command), `critical` (honeytoken) |
| `protocol`, `source`, `source_port`, `dest_port`, `decoy_host` | who touched what |
| `account`, `secret`, `method` | a credential attempt (`secret` is what the attacker typed; MySQL records `$mysql$salt$response` for offline cracking) |
| `key_fingerprint` | SSH public key tried |
| `command` | one fake-shell line, or Redis command |
| `honeytoken`, `token_origin`, `token_kind` | set when a honeytoken was used: the host it was planted on |
| `credentials`, `commands`, `duration_ms`, `honeytokens`, `token_origins` | on the `end` summary |

Listener kinds: `ssh`, `mysql`, `redis`, `telnet`, `winrm`, `rdp`, `http_admin`
(the manifest kinds) and `smb` (banner only, never 445). SSH, Telnet, RDP and
MySQL speak enough protocol for real clients; SSH accepts after
`AcceptAfter` password attempts or immediately for a honey password or key.

## Deployment

The deploy plan writes `<state dir>/deception.json` (`decoys.LocalConfig`:
listeners, scored ports, tokens, watch paths). The role `decoys` switches on the
`decoys` module and, on Linux, `honeywatch` (fanotify on the planted files).

## Honeytokens

`honeytokens.Generator.ForHost` takes a `HostSpec` (from `decoys.yml`) and
returns a `HostPlan`: tokens (registered, unique across hosts), `ActionSpec`s the
planner can emit (`file.write`, guarded `OnlyIfAbsent`, secrets listed in
`SecretParams`; `ad.honey_account` for the DC), and the `Watch` list (fanotify
on Linux, SACL/4663 on Windows). Nothing is executed by this package.

Kinds: `ssh_key`, `db_cred`, `shell_history`, `passwords_file`, `browser_cred`,
`aws_key` (AKIA + 16 base32 characters, 40-character secret), `honey_file`, and
AD `ad_spn` (kerberoast bait), `ad_asrep` (pre-auth disabled), `ad_admin`.
`Registry` refuses a duplicate id, secret, account, fingerprint, SPN or
host+path. `Registry.Attribute` maps an alert's fields to the token and its
origin host; `Registry.Seeds` yields the static profiles for the rules.

## Rules (`rules/deception.yml`)

D15a decoy connect (low), D15b login or command (high), D15c honeytoken at a
decoy (critical), D15d logon for a honey account (critical), D15e Kerberos
4769/4768/4771/4776 for honey SPN or account (critical), D15f honey file read
(`honey.read` or 4663; critical), D15g canary AWS key id (critical). Seed the
profiles `honeytoken.accounts`, `honeytoken.spns`, `honeytoken.paths`,
`honeytoken.aws_keys` from `Registry.Seeds()`.
