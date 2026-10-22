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
  (`internal/agent/mods/deception.go`) passes the scored ports from the signed
  `deception` section plus every real service port in the net module's service
  map (the decoys' own `decoy-*` entries are skipped), so a decoy never shares a
  port with any declared service. The manifest lint (DC001) is the
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

Configuration travels in the signed `AgentConfig` (`modules.deception`,
`plan.DeceptionSettings`), built by the controller (`internal/controller/
deception_config.go`) from `decoys.yml` and the honeytoken registry: the
listeners, the scored ports of the host's scored services, every registered
token (decoys match a credential planted on host A tried at host B) and the
honey files planted on this host (fanotify watch). The agent restarts the decoys
when that section changes. The old unsigned `<state dir>/deception.json` is read
only when the signed config has no section (migration; the agent logs a
warning). Remove it once every controller sends the section.

The role `decoys` switches on the `decoys` module and, on Linux, `honeywatch`.
Shell history files are tokens but not watched: the shell itself opens them at
every login, which would alert on the legitimate owner.

`decoys.yml` accepts the `smb` listener kind (banner only, never 445), a
per-host `domain:` (needed for the AD token kinds on a domain controller) and
validates `honeytokens[].kind` against the generator's kinds.

### Deploy plan

`Controller.DeceptionPlan(ctx, id, hosts...)` generates the missing tokens and
returns the plan (shape: `plans/deception.deploy.yaml`): an approval gate, a
`deception.decoy_check` per decoy host (connects to the listeners on loopback),
and a `plant.<token>` node per planting step (`file.plant`, `ad.honey_account`).
Create it with `CreatePlan` like any plan.

### Secrets never travel in plans

Plan nodes of `file.plant` and `ad.honey_account` name their secret parameters
(`secret_params`) and a vault entry per parameter (`secret_refs`, only entries
under `honeytoken/`). The plan JSON, its hash, the stored plan body, the signed
step params, diffs and results hold only those names. When the controller
issues a step (dry-run, apply, verify) it resolves the entries from the vault
into the step's secrets blob (digest signed with the step) and the agent hands
it to the action through its context (`actions.WithSecrets`). `file.plant`
diffs say "content not shown"; the AD action scrubs the password out of backend
errors. There is no plaintext `password` parameter at all.

`file.plant` is `file.write` plus `only_if_absent` (an existing file is never
replaced: a real `.bash_history` or `.env` survives; verify then only checks
existence) and secret content. It is a separate action so the shared
`file.write` stays untouched; the generator emits it.

`ad.honey_account` creates the kerberoast SPN / AS-REP roastable / admin
lookalike accounts (no rights, long random password). It runs against the
`actions.HoneyADBackend` interface; **no backend is bound yet**: until the
win/ad agent's AD layer lands, call `actions.SetHoneyADBackend` from the
Windows agent start-up (TODO). Without one the action fails with
`ErrNoADBackend`. It does not roll back automatically.

### Registry persistence

`GenerateHoneytokens` runs the generator against a copy of the registry,
writes every secret (token password, each file body, each AD password) to the
vault as `honeytoken/<id>/<name>`, stores the metadata (no secrets) as one
record in the store's `meta` table, and only then swaps the live registry and
pushes the changed configs. Calling it again generates nothing for hosts that
already have tokens. Without a vault (`Options.Vault`) generation is refused.
If the vault is locked at start the registry loads without secrets, an
`honeytokens.secrets_unavailable` alert fires and decoys cannot recognise honey
passwords until `ReloadHoneytokenSecrets` (after unlock); seeds and attribution
do not need secrets.

### Detection feed

`Registry.Seeds()` becomes `Detect.Seeds` (`honeytoken.accounts`, `.spns`,
`.paths`, `.aws_keys`) in every host's signed config that has rules, so D15d-g
fire wherever the event shows up; a registry change bumps the config version
and the agents re-seed. `Registry.Attribute` is applied to incoming
`detect.alert` events (`alerts.go`): the alert gets `honeytoken`, `token_origin`
and `token_kind` entities, so a D15d/D15e alert on the DC names the host that
was looted. (The stored events themselves are hash-chained and not rewritten.)

### Hardening

- **Separate unprivileged process** (`internal/decoys/sandbox`). The agent binds
  the listening sockets, then re-executes its own binary as the decoy child with
  the sockets as inherited descriptors. On Linux, when the agent is root the
  child starts with the uid/gid of `nobody` (or `sandbox_user`) and no
  supplementary groups; it sets `no_new_privs` first thing and refuses to run
  if it is still root after a requested drop. Configuration (including tokens)
  arrives on stdin, never argv or environment; the child's environment is empty
  apart from the marker. Events return as JSON lines on stdout. The open stdin
  pipe is the lifeline: when the agent dies the child exits. A child crash is a
  module crash, restarted by the supervisor with backoff. The `internal/decoys`
  package itself stays free of `os/exec`/`syscall` (a test enforces it); the
  process handling is in the sandbox sub-package. The agent binary must be
  executable by the sandbox user.
- **Windows** runs the listeners in the agent process (`in_process`). A
  restricted-token child (CreateRestrictedToken, low integrity) is the plan;
  until it exists the Windows decoys are the weakest link and should not run on
  the DC.
- **Persistent SSH host key**: `decoy_ssh_host_ed25519` in the agent state dir
  (0600, atomic create). A damaged key is an error, never silently replaced.
- **Canary AWS key ids**: the `akiascan` module (hosts with rules) watches the
  agent's own `http_request`, `net.sinkhole_capture` and `dns_query` events for
  AKIA-pattern key ids (case-insensitive, so DNS labels match; bounded depth,
  size and count) and emits a copy of the event with `aws_access_key_id` and
  `derived_from` set, which D15g matches against `honeytoken.aws_keys`. It adds
  nothing for events that already carry the field and never rescans its own
  output. Nothing in the tree emits those event kinds yet; the scanner is the
  hook the sinkhole and proxy producers will feed.

## Honeytokens

`honeytokens.Generator.ForHost` takes a `HostSpec` (from `decoys.yml`) and
returns a `HostPlan`: tokens (registered, unique across hosts), `ActionSpec`s the
planner can emit (`file.plant`, guarded `OnlyIfAbsent`, secrets listed in
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

## Gaps

- `ad.honey_account` has no directory backend until the win/ad AD layer is
  bound (`actions.SetHoneyADBackend`); it is not rolled back automatically.
- The controller does not learn that `file.plant` skipped an existing file: that
  token stays registered (and its path watched) although nothing was planted.
- Windows decoys run in the agent process (no restricted token yet).
- No producer emits `http_request` / `net.sinkhole_capture` / `dns_query` yet;
  `akiascan` is ready for them. Honey SACLs for 4663 on Windows are not set by
  any action yet.
- The honeytoken secrets of every host are in each decoy host's signed config
  (needed for cross-host credential matching). They are fake, but a compromised
  decoy host reveals them.
- `GenerateHoneytokens` is an API; there is no CLI or UI button, and a changed
  `decoys.yml` for a host that already has tokens does not regenerate them.
- A vault unlock does not trigger `ReloadHoneytokenSecrets` by itself.
