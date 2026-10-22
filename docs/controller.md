# Controller core (`phylax serve`)

Package `internal/controller`, command `cmd/phylax/serve.go`.

## Config (JSON, unknown keys rejected)

`agent_listen` (default `0.0.0.0:7443`), `data_dir` (required), `identity_path`
(default `data_dir/identity.pem`, created on first run), `manifest_path`
(optional; when set, tokens can only be minted for manifest hosts),
`silence_threshold` (default `30s`), `hello_timeout` (10s), `read_idle` (20s),
`max_handshakes`, `max_conns`, `reorder_window` (65536), `max_buffered_events`
(16384), `max_live_tokens` (1024). Durations are strings. Run:
`phylax serve -config controller.json` (or `-data-dir DIR`). The controller key
pin is logged at start.

Files in `data_dir`: `phylax.db` (store), `tokens.json` (hashed tokens), identity.

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
`Apply` -> running -> succeeded | failed | rolled_back (interrupted after a
controller restart; plans are not resumed, the agents' dead-man switches cover
anything applied).

1. **Dry run.** The controller lints every node with `Options.Guard(host)`
   (the manifest-backed `actions.GuardFromManifest`), then sends a signed
   `check` step per node. Check steps carry the approver `dry-run`; the agent
   never executes a change for them. A failed check (including the agent's own
   guard refusing) marks the node `rejected`; an unanswered one is `missing`.
   `ApprovePlan` needs an approvable dry run.
2. **Apply.** `plan.Run.Next` yields ready nodes (4 per host); each gets a
   signed `apply` step. `applied` -> a `verify` step -> `verified` unlocks the
   dependents. After `verified` the controller sends
   `control{deadman_confirm, args:{plan,node}}` for nodes with a dead-man
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
   (fresh sequence number), lost applies are not.

Persistence: `plans` (state, epoch, body = plan + hash + approvals + dry run)
and `plan_steps` (state, per-phase result history with signed flag, digests,
failure reason) are written on every transition. No secret appears in either.
