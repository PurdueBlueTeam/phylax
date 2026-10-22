# Controller core (`phylax serve`)

Package `internal/controller`, command `cmd/phylax/serve.go`.

## Config (JSON, unknown keys rejected)

`agent_listen` (default `0.0.0.0:7443`), `data_dir` (required), `identity_path`
(default `data_dir/identity.pem`, created on first run), `manifest_path`
(optional; when set, tokens can only be minted for manifest hosts),
`silence_threshold` (default `30s`), `hello_timeout` (10s), `read_idle` (20s),
`max_handshakes`, `max_conns`, `reorder_window` (65536), `max_buffered_events`
(16384), `max_live_tokens` (1024), `rules_path` (detection rules directory) and
`ledger_path` (signed integrity ledger; agents get its sha256), see "Agent config". Durations are strings. Run:
`phylax serve -config controller.json` (or `-data-dir DIR`). The controller key
pin is logged at start.

Files in `data_dir`: `phylax.db` (store), `tokens.json` (hashed tokens), identity.

## Agent config (`agentconfig.go`, `genconfig.go`)

With `manifest_path` set, `phylax serve` generates every host's `plan.AgentConfig`
from the manifest (`BuildAgentConfig`): roles (vantage expanded), and per OS the
modules and their settings.

| Module | Hosts | Settings from the manifest |
| --- | --- | --- |
| health | all | 60 s interval |
| audit | Linux | service content roots and upload dirs (web roots), declared service binaries |
| net | Linux | listeners as `proto/port` to service id (ranges up to 64 ports; decoy listeners as `decoy-<kind>`), NFLOG groups and canary targets from `render.BuildHostPolicy`, exe hashing |
| winevt | Windows | built-in default channels |
| integrity | Linux | pinned service binaries (`process.pin`), ledger reference (sha256 of `ledger_path`) |
| detect | all (when `rules_path` is set) | rule files as YAML text, manifest-seeded profiles (`accounts.scored`, `rotation.pending`, `scored.service_comms`, `service.dependencies`), `act_enabled: false` |

The scorer exemption is behavioural, as the design requires: accounts and service
processes, never addresses. `rotation.pending` seeds the accounts on hosts that have a
default credential and whose rotation is `pcr_transaction` or `free`.

Signing: Ed25519 with the plan key, canonical JSON, host-bound, epoch from the store,
`version` per host. Versions are kept in `data_dir/agentconfigs.json` and move only
when a host's content digest or the epoch changes, so a reconnect re-sends the
identical message (the signature is deterministic and `issued_at` is kept). The file
is a durable record: a corrupt one stops the controller starting (fail closed).

Delivery: in `welcome` on every connect; as a `config` message to connected agents
whenever the inputs change (`SetConfigInputs`); and again when a heartbeat reports an
older config than wanted (at most every 15 s). `phylax serve` loads the inputs at
start (an invalid manifest or rule set stops it) and polls the manifest, rules and
ledger files every 5 s (`WatchConfigInputs`); a change that does not load or does
not pass strict rule validation raises `config.inputs_invalid` and the previous
inputs stay in force. `AgentStatus` carries `ConfigState`, `ConfigEpoch`,
`ConfigVersion` from the heartbeat.

## Session flow (`phylax/agent`)

1. Handshake accepts any P-256 key (so unknown agents can enroll); `hello` must
   arrive within `hello_timeout`.
2. Known host: the pin must equal the stored key (`store.EnrollAgent` key =
   the 32-byte pin). A different key is refused and alerted
   (`enroll.key_mismatch`); a token never re-keys a host.
3. Unknown host: needs a token minted for that host, unexpired, unused (or
   used by the same pin: idempotent retry). A wrong-host claim does not burn it.
   A pin already enrolled as another host is refused. Then `EnrollAgent`.
4. `welcome{enrolled}` then `ack{stored seq}`. A newer session for a host
   supersedes the old one.
5. Event batches go into a per-agent reorder buffer; every run contiguous with
   the stored head (gap records bridge `from..seq-1`) is passed to
   `store.Ingest` (<= 1000 per call); the ack is sent only after the commit.
   Heartbeats record clock skew, spool state, and are answered with an ack.
6. A chain error commits the valid prefix, raises `store.chain_error`, and ends
   that session; the controller keeps running.

Alerts (`agent.silent`, `agent.resumed`, `enroll.*`, `store.chain_error`) are
logged, held in a 256-entry ring (`Controller.Alerts`) and passed to
`Options.OnAlert`. They become chained controller events once the controller has
its own event stream.

## Bounds

One live session per host; reorder buffer <= `max_buffered_events` and
sequences <= `reorder_window` above the ack (else session ends); live tokens
capped; handshake/connection caps from `internal/link`.

## Deviations / notes

- `link.Receiver` is not used: it tracks contiguity by sequence number, which a
  spool gap record (sequence jump) would stall forever. The reorder buffer
  (which understands gap records) replaces it.
- `welcome` has no epoch/hash fields and `ack` only a sequence, so neither is
  sent; the epoch will travel in the signed `config`.
- Events at or below the ack are dropped without comparison (the store still
  rejects a rewrite if such an event reaches `Ingest`).

## Plan execution (`internal/controller/plans.go`, `execkeys.go`)

**Keys and counters.** `data_dir/plan.key` is the Ed25519 plan-signing key
(PKCS#8 PEM, written atomically with mode 0600; a looser mode is refused at
start). Its public half is logged at start (`plan_key`) and goes into every
agent bootstrap as `plan_key`. Per-host step sequence numbers come from
`store.NextStepSeq` (a durable counter in `meta`, allocated before a step is
signed); the epoch is the store's current epoch, so a restore (which bumps the
epoch) makes agents accept the new controller's lower sequence numbers.

**API** (all on `*Controller`): `CreatePlan` (validated against
`Options.Registry` through `plan.Catalog`; a draft), `DryRun`, `ApprovePlan`,
`ApproveNode` (gates, lockout, destructive, `host.exec`), `Apply`, `Wait`,
`PlanStatus`, `StoredPlans`, `DropAgent`, `SendRaw`.

**Lifecycle.** draft -> `DryRun` -> dryrun -> `ApprovePlan` -> approved ->
`Apply` -> running -> succeeded | failed | rolled_back. A controller restart does not end a
plan: see "Restart and resume" below.

1. **Dry run.** The controller lints every node with `Options.Guard(host)`
   (the manifest-backed `actions.GuardFromManifest`), then sends a signed
   `check` step per node. Check steps carry the approver `dry-run`; the agent
   never executes a change for them. A failed check (including the agent's own
   guard refusing) marks the node `rejected`; an unanswered one is `missing`.
   `ApprovePlan` needs an approvable dry run.
2. **Apply.** `plan.Run.Next` yields ready nodes (4 per host); each gets a
   signed `apply` step. `applied` -> a `verify` step -> `verified` unlocks the
   dependents. After `verified` the controller sends
   a signed `control{deadman_confirm, args:{plan,node}}` for nodes with a dead-man
   window. A `verify` step re-runs the action's own post-condition on the agent.
3. **Failure.** `stop_dependents` / `continue` follow `plan.Run.Fail`; a node
   that fails verify is also rolled back individually. `rollback_plan` waits
   for in-flight nodes, then sends `rollback` steps one at a time in reverse
   topological order (`Run.RollbackOrder`). A node whose apply failed is not
   sent a rollback: the agent's executor already undid it. For `rollback_plan`
   plans nodes without a `deadman_sec` get `RollbackWindowSec` (600 s, part of
   the signed plan), confirmation is deferred until the whole plan has
   succeeded, and the agent keeps rollback data until then.
4. **Results.** A `step_result` is matched by `(host, epoch, seq)`, verified
   against the ECDSA key of the live TLS session (whose pin is the enrolled
   key) and against the step it answers, then applied. Unsigned `rejected`
   results fail the phase. No result within `Options.StepTimeout` (2 min)
   fails the phase; on reconnect lost verify/rollback steps are re-issued
   (fresh sequence number); a pending apply is never re-sent but queried
   (`step_status`), so a lost apply result is recovered: the agent re-sends the
   signed result, or says `unknown` (never accepted: the apply is issued afresh)
   or `lost` (accepted, no record: an armed dead-man entry means applied and
   verify decides, otherwise the node fails and the dead-man covers it).

Persistence: `plans` (state, epoch, body = plan + hash + approvals + dry run)
and `plan_steps` (state, per-phase result history with signed flag, digests,
failure reason) are written on every transition. No secret appears in either.

## Signed controls

`SendControl` / internal confirms are signed with the plan key (see
docs/protocol.md): per-host control sequence from `store.NextStepSeq("control/"+host)`,
current epoch, `Options.ControlValidity` (60 s). Agents refuse unsigned, forged,
replayed or expired controls. `SendRaw` remains for tests (replays, forgeries).

## Restart and resume

Every plan transition stores a runtime snapshot with the plan (node states,
wanted phase, the `(epoch, seq, step digest)` of the step in flight, confirm and
rollback progress). The in-flight record is written before the step is sent.
At start `loadPlans` reloads draft/dryrun/approved plans as they were and
running (or legacy `interrupted`) plans as running; a stored plan whose hash no
longer matches is refused with an alert.

When an agent reconnects (`resume`): in-flight verify/rollback steps are
re-issued (idempotent); an in-flight apply is queried; then the agent's
`hello.deadman` report is reconciled with each node on that host: an
applied/verified node whose dead-man entry fired is marked rolled back
(`plan.deadman_fired`, failure policy applies: dependents skipped, or
`rollback_plan` rolls the rest back); a verified node whose entry is still armed
gets its confirm sent again (unless `rollback_plan` defers it to plan end);
a confirmed entry sets `confirmed`. Nothing is dispatched to a session until
this reconciliation ran. After a restart, applies for hosts that have not
reconnected wait `Options.ResumeGrace` (default `StepTimeout`) before failing.
Sequence numbers are durable, so no number is signed twice and a change is
never applied twice (except the `unknown` answer, which proves it was not
accepted). `Controller.Close` stops timers; the plan stays as persisted.
Dead-man fires while connected are not yet reconciled until the next reconnect.
