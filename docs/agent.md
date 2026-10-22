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

`Config.Handlers` plugs `Config`, `Step`, `Fetch`, `Control`. Defaults: config is logged and an
`agent.config_rejected` event is emitted; steps get a `step_result` with status `rejected`; fetch is
logged; control implements `safe_mode` and `deadman_confirm` (`args.id`).

## Modules

`Module{Name, Start(ctx, emit)}`. The supervisor recovers panics, restarts with exponential
backoff (reset after a stable run), emits `agent.module_crash`, applies a per-module token bucket
(over-limit events are dropped and counted, never block), and polls a `Budget` hook (a non-nil error
stops the module; it restarts after backoff, state `over_budget`). The built-in `health` module emits
`agent.health` (spool stats, module states, link state) and `telemetry_gap` events (`rate_limit`,
`spool_refused`, `module_down`).

## Service install

systemd unit: `Restart=always`, `RestartSec=1`, `StartLimitIntervalSec=0`, `Type=notify` +
`WatchdogSec`, `OOMScoreAdjust=-900`, optional `MemoryMax`/`CPUQuota`, `NoNewPrivileges`,
`LockPersonality`, `RestrictSUIDSGID`, `UMask=0077`. No filesystem or capability confinement
(the agent needs root). Windows: automatic LocalSystem service, recovery actions restart forever.
Names are configurable; `--secret` derives stable randomised service/binary/dir names (D-8).

## Not done yet

Signed config verification, step execution, fetch, the real sensor modules, the decoy process,
Job Object hard caps, a protected service DACL.
