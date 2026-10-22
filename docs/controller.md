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
