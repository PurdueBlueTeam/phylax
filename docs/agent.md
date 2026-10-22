# `phylax agent`

Implementation notes for the agent runtime (`internal/agent`, `internal/svcinstall`,
`cmd/phylax/agent.go`). Design: `phylax_design.md` ("The agent", "Enrollment",
"Dead-man switch"); wire format: `docs/protocol.md`.

## Subcommands

| Command | Does |
| --- | --- |
| `agent run [--state-dir D] [--bootstrap F] [--service-name N]` | Run the agent. Under the Windows SCM it runs as a service (`svc.Run`). |
| `agent rollback [--state-dir D] <id>` | Fire dead-man entry `<id>` as `os-timer`. This is what the systemd transient timer / scheduled task invokes. Idempotent. |
| `agent install --bootstrap F [--secret HEX] [--name --binary-name --dir --state-dir]` | Copy the binary and bootstrap, register the service (privileged). |
| `agent uninstall --name N` | Remove the service. |
| `agent unit [same flags]` | Print the systemd unit `install` would write (no privileges). |

## Bootstrap bundle and state directory

`bootstrap.json`: `controllers` (host:port list, tried in rotation), `controller_pin`
(64 hex or `sha256//base64`), `host`, `token` (one-time, optional), `roles`.

```
<state-dir>/bootstrap.json   bundle; token removed after enrollment
<state-dir>/identity.pem     ECDSA P-256 key + cert, 0600, atomic, generated on first start
<state-dir>/state.json       {"enrolled": bool}, written only after `welcome`
<state-dir>/spool/           internal/spool
<state-dir>/deadman/         internal/deadman journal
<state-dir>/config.json      last good signed config (verbatim `config` message)
<state-dir>/configseq.json   (epoch, version) high-water mark of accepted configs
<state-dir>/ledger.plx       integrity ledger (hash pinned by the config)
```

## Run loop

1. Open spool, open the dead-man manager with the registered handlers, **Recover()** (expired
   entries roll back before anything else acts), start the supervisor, send `READY=1` to systemd.
2. Connect loop: jittered backoff 1 s to 30 s (reset after a connection that got welcome and an ack),
   round-robin over `controllers`.
3. Per connection: `hello` (token only while not enrolled, `last_seq` = spool head), wait for
   `welcome` (persist enrollment, scrub token) and the first `ack`, rewind the spool cursor, then
   `link.Uplink` streams the spool from the controller's ack. Acks are fed to `spool.Ack`.
   Heartbeats every 5 s (`TrySend`, never blocks) carry the clock, spool depth, congestion, module
   states, safe mode and shed count.
4. Sensors only ever write to the spool, so a down link cannot block them.

## Handlers

`Config.Handlers` plugs `Config`, `Step`, `Fetch`, `Control`. Defaults: config is verified and
applied (below); steps get a `step_result` with status `rejected`; fetch is
logged; controls are verified first (below), then `safe_mode`, `deadman_confirm` and `step_status` are implemented.

## Modules

`Module{Name, Start(ctx, emit)}`. The supervisor recovers panics, restarts with exponential
backoff (reset after a stable run), emits `agent.module_crash`, applies a per-module token bucket
(over-limit events are dropped and counted, never block), and polls a `Budget` hook (a non-nil error
stops the module; it restarts after backoff, state `over_budget`). The built-in `health` module emits
`agent.health` (spool stats, module states, link state) and `telemetry_gap` events (`rate_limit`,
`spool_refused`, `module_down`).

## Signed config and the module registry

`Factory{Name, Section, Build}` (`registry.go`) is how a module becomes configurable:
`Section` returns a fingerprint of the module's settings in the signed config and
whether it should run, `Build` returns its `ModuleSpec` (rate limits from the config) or an
error wrapping `ErrUnavailable` (wrong platform, no privilege). Factories register from `init`
into a process-wide registry (`RegisterFactory`; `Config.Factories` adds or overrides for
tests). The sensor packages import `internal/agent`, so the registrations live in
`internal/agent/mods` (blank-imported by `cmd/phylax`): `net` (Linux), `audit` (Linux, root),
`winevt` (Windows), `integrity`, `detect`; `health` registers in the agent package.

The Config handler is mandatory-verify (`plan.ConfigVerifier`, see protocol section 8a), persists the
config to `<state>/config.json` (atomic), and wakes a reconciler goroutine that, per factory:
removes a module whose section went away, leaves an unchanged fingerprint alone, builds and
replaces a changed one (`Supervisor.Remove` waits for the old module), and records
`running` / `disabled` / `unavailable: why` / `error: why` per module (`Agent.ConfigStatus`).
An unavailable module makes the state `degraded`, not a crash loop. A module supplied
statically in `Config.Modules` under the same name is never replaced. At start-up the persisted
config (signature re-verified) is applied before the link comes up.
`budgets.memory_limit_mb` lowers the Go memory limit.

`Env.Subscribe` is the agent's event stream: every event a module emits (after its rate limit,
before the spool, so shedding cannot blind a consumer) goes to bounded subscriber channels that
drop rather than block. The `detect` module subscribes, runs `detect.Engine` (AlertOnly unless the
signed config sets `act_enabled`, which the controller leaves off: tier-0 responses stay disabled) and
emits each alert as a `detect.alert` event at Critical priority (`rule`, `title`, `severity`, `tier`,
`mode`, `message`, `attack`, `collect`, `entities`, `evidence`). It ignores `detect.*` events (no
feedback) and hands its learned profiles to its replacement through `Env.Keep`, so a rules update does
not forget baselines. The `integrity` module judges exec events, pinned service processes (`/proc`
scan, Linux) and periodic sweeps against the signed ledger in `<state>/ledger.plx` whose sha256 the
config pins; until the file is present it emits `integrity.ledger_unavailable` and retries every 30 s.

## Service install

systemd unit: `Restart=always`, `RestartSec=1`, `StartLimitIntervalSec=0`, `Type=notify` +
`WatchdogSec`, `OOMScoreAdjust=-900`, optional `MemoryMax`/`CPUQuota`, `NoNewPrivileges`,
`LockPersonality`, `RestrictSUIDSGID`, `UMask=0077`. No filesystem or capability confinement
(the agent needs root). Windows: automatic LocalSystem service, recovery actions restart forever.
Names are configurable; `--secret` derives stable randomised service/binary/dir names (D-8).

## Not done yet

Fetch, the decoy process, delivery of the integrity ledger file (the config only pins its hash),
persisting learned detection baselines across agent restarts, tier-0 automatic responses,
Job Object hard caps, a protected service DACL.

## Plan steps (`internal/agent/exec.go`)

Enabled by `Config.Exec` (cmd: whenever the bootstrap has `plan_key`, 64 hex of
the controller's Ed25519 key; with `Exec` set and no key `New` fails). The step
handler runs on the receive path only to verify: the typed `link.Step` is turned
back into a `plan.Step` and `plan.Verifier` (key, host id,
`FileSeqStore` at `<state>/planseq.json`) checks signature, host, window and
epoch/seq (replay); a non-check step needs a real approval record (`dry-run` never counts). Execution
is off the receive path (bounded, 8 at once; excess is answered `failed`).

Phases: `check` = `Env.Execute` dry run; `apply` = `Env.Execute` with the dead-man
window from the step (the executor rolls back by itself on apply/verify failure;
after a successful armed apply the agent opens a fresh handshake to the
controller and rolls back at once if that fails); `verify` = the action's own
`Verify`; `rollback` = fire the node's dead-man entries (`NodeID` is
`<plan>:<node>`), idempotent, allowed in safe mode. `safe_mode` control switches
`Env.Safe` (persisted in `<state>/safe_mode`), so applies are refused while
checks and rollbacks still work. `deadman_confirm` takes `{id}` or
`{plan,node}`.

**Controls** are mandatory-signed: `plan.ControlVerifier` (plan key from the
bootstrap, host id, durable mark `<state>/controlseq.json`, separate from the
step mark) checks signature, host, window and sequence before any handler runs;
with no `plan_key` every control is refused. Refusals emit
`agent.control_refused`. `step_status` re-sends the signed result kept in
`<state>/results.json` (last 256) or answers unsigned `unknown`/`lost`/`running`.
`hello` carries `minor` and the dead-man entries of plan nodes (`deadman`). In-process dead-man fires are reported as critical
`agent.deadman_fired` events; refusals as `agent.step_refused`. Results that
cannot be sent are kept (64) and re-sent after the next reconnect. The scoring
guard comes from `<state>/guard.json` (`phylax guard <host>` prints it from the
manifest); `phylax agent rollback` loads the same environment so the OS timer
can undo action changes.
