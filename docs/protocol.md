# Phylax wire protocol v3 (protocol version 1, minor 1)

Written protocol spec, M0 deliverable. It is the contract between
`phylax agent`, relays and `phylax serve`. `internal/link` implements it and
its tests pin it. The design context is in `phylax_design.md`
("Wire protocol and data flow", "Trust model", "How the relay works"). Where
this file and the design disagree, fix one of them in the same commit.

"MUST", "SHOULD" are used in the RFC 2119 sense.

## 1. Transport

- One long-lived TLS connection per logical stream. No multiplexing layer.
- **TLS 1.3 only** for every `phylax/*` connection. Bootstrap downloads (no
  `phylax/*` ALPN) also accept TLS 1.2, because Windows 10 / Server 2016 /
  2019 cannot do 1.3 and the console one-liner uses the host's TLS stack.
- Go standard library TLS. Certificates are self-signed **ECDSA P-256**
  (SChannel cannot negotiate Ed25519 server certificates). Certificates carry
  validity of ten years from one day ago for stock clients that check dates,
  but Phylax ignores dates, names and chains entirely.
- **Authentication is public-key pinning.** The *pin* of a key is the SHA-256
  of its DER `SubjectPublicKeyInfo` (the same value `curl --pinnedpubkey
  sha256//<base64>` uses). Written as 64 lowercase hex characters, or the
  curl form.
  - Clients pin the server: the handshake fails unless the server key's pin
    equals the configured pin.
  - Servers require a client certificate on `phylax/*` connections and call
    an authorisation callback with the client key's pin **inside the
    handshake**. A rejection aborts the handshake; the handler is never
    invoked and no application data is processed. (In TLS 1.3 the client can
    finish its own handshake and write before the server has judged its
    certificate; those bytes are discarded.)
  - A controller that admits unknown agent keys for enrollment does so in the
    callback and decides on the token in `hello`; it MUST NOT treat an
    unenrolled key as an authenticated host.
  - Session tickets/resumption are disabled so every connection re-verifies.
- Keys: each node holds one transport identity (key + self-signed cert),
  generated on first start and stored in a single PEM file (mode 0600,
  atomic write). The plan-signing key (Ed25519, controller memory only) is a
  different key and never used for transport.
- TCP keepalive (15 s) is enabled on every connection.

### 1.1 Connection types (ALPN)

The controller listens on **one port** (`agent_port`). The server config is
chosen from the ClientHello: a client offering any `phylax/*` protocol gets
the strict config (TLS 1.3, mandatory client certificate, pin check, ALPN
restricted to the four ids below); anything else gets the bootstrap config.

| ALPN | Opened by | Purpose |
| --- | --- | --- |
| `phylax/agent` | Agent (direct or spliced through a relay), including the Kali | All agent messaging (this spec, section 3 onward) |
| `phylax/relay` | Relay | The relay's control connection (`relay_request`) |
| `phylax/splice` | Relay | One device-proxy or bootstrap stream |
| `phylax/patch` | Agent | One proxied HTTP connection during a patch window |
| none, or `http/1.1` | A host being bootstrapped from the console | Download of the binary and a bootstrap config bound to a one-time token. Serves only these; mints nothing |

A server selecting an ALPN other than the one the client asked for is a
handshake failure on the client side. An ALPN with no registered handler is
closed after the handshake. Nothing on this listener is unauthenticated except
the token-gated bootstrap download; the operator UI is on another listener.

### 1.2 Server connection handling

- The accept loop does no TLS work. Each accepted TCP connection gets a
  goroutine that performs the handshake under a deadline (default **5 s**).
- At most **128** connections may be in the handshake phase at once and
  **4096** live connections overall (both configurable); beyond a cap the new
  TCP connection is closed immediately. Idle or half-open connections are cut
  when the handshake deadline expires and cannot delay other handshakes.
- After the handshake the handler runs with the negotiated ALPN and the peer
  pin; the connection is closed when it returns. Handler panics are recovered.

### 1.3 Relays

The relay is a dumb splicer and not in the trust path:

- Listens on its declared port, accepts only from source addresses in its
  segment's manifest entry, with deadlines and a connection cap.
- For each accepted `phylax/agent` connection it opens a fresh outbound
  connection to its parent and copies bytes both ways. TLS runs end to end;
  the relay never sees plaintext and holds no agent keys.
- It keeps one outbound `phylax/relay` connection to the controller (own
  identity, pinned), used only to receive `relay_request`.
- A `relay_request` names `host:port`; the relay checks its manifest
  allowlist, connects to the device, opens a fresh outbound `phylax/splice`
  connection to the controller and splices. The device's own TLS stays end
  to end. Splices record metadata only (source, destination, bytes, duration).

## 2. Framing

```
+----------------+-----------+--------------------+
| length u32 BE  | type u8   | body (JSON, UTF-8) |
+----------------+-----------+--------------------+
```

- `length` counts the type byte plus the body. It MUST be 1..**4 MiB**
  (4 194 304). A larger or zero length is a protocol error and closes the
  connection **before any body byte is buffered**. Receivers buffer only the
  bytes that actually arrive.
- Type bit `0x40` marks a **zstd-compressed** body (single zstd frame,
  pure-Go codec). The low six bits are the message type. Types are therefore
  `0x01..0x3F`.
- A compressed body MUST decompress to at most **4 MiB**. Receivers check the
  frame header's declared content size first, cap decoder window and memory
  at the same limit, and stop reading output at limit+1 bytes regardless of
  what the stream claims. Exceeding it, or any malformed stream, closes the
  connection.
- Senders compress bodies of at least 512 bytes when that makes them smaller;
  `chunk` bodies are never recompressed.
- Whole-frame read deadline: a frame must arrive completely within the read
  idle window (20 s default) of when its read began, so a trickling peer
  cannot hold a connection. Each frame write has a 10 s deadline.
- Bulk data larger than a frame moves as 256 KiB (`262144` byte) chunks (section 4).

## 3. Messages

Bodies are JSON objects. Receivers MUST validate every message against its
schema (types, required fields, length caps) and MUST treat the content as
evidence, never as instructions. **Unknown JSON fields are ignored** (additive
evolution within a protocol version). Trailing data after the JSON value, an
unknown type byte, or a type not valid for the receiver's role is a protocol
error and closes the connection.

| Code | Name | Direction | Fields |
| --- | --- | --- | --- |
| 0x01 | `hello` | agent to controller | `proto` (int, 1), `minor` (int, 1), `host`, `version`, `roles[]`, `caps{}`, `last_seq`, `token` (enrollment only), `binary_sha256` (sha256 hex of the running agent binary; absent when unreadable), `deadman[]` (`{id,node,state,deadline}` for journal entries belonging to a plan node, newest first, at most 256) |
| 0x18 | `welcome` | controller to agent | `proto`, `minor`, `enrolled` (bool), `config` (optional signed config) |
| 0x02 | `heartbeat` | agent to controller | `seq`, `host_clock` (RFC 3339), `spool_depth`, `congestion` (`ok`/`warning`/`full`/`flood`/`recovered`), `modules{name:status}`, `safe_mode`, `drops` |
| 0x03 | `events` | agent to controller | `events[]`: `internal/event` records (`agent`, `seq`, `time`, `kind`, `prio`, `fields`, `prev`, `hash`), 1..5000 per batch |
| 0x04 | `step_result` | agent to controller | `v`, `plan`, `node`, `host`, `epoch`, `seq`, `phase` (`check`/`apply`/`verify`/`rollback`), `status`, `error`, `step_digest`, `rollback_data_hash`, `before_digest`, `after_digest`, `started_ms`, `finished_ms`, `detail`, `sig` |
| 0x05 | `chunk` | both | `sha256` (object digest, hex), `offset`, `total`, `data` (base64, 1..262144 bytes) |
| 0x06 | `chunk_have` | both | `sha256`, `ranges[]` of `[offset,end)` the receiver already holds |
| 0x10 | `ack` | controller to agent | `seq`: highest contiguous event sequence stored |
| 0x11 | `step` | controller to agent | `v`, `plan`, `plan_hash`, `node`, `host`, `action`, `phase`, `params`, `risk`, `approval{by,at,note}`, `rollback_policy`, `rollback_digest`, `secrets_digest`, `epoch`, `seq`, `not_before`, `not_after`, `deadman`, `secrets` (base64), `sig` (base64) |
| 0x12 | `config` | controller to agent | `version`, `epoch`, `body`, `sig` |
| 0x13 | `fetch` | controller to agent | `id`, `kind` (`pcap`/`file`/`telemetry`), `args` |
| 0x15 | `control` | controller to agent | `v`, `host`, `kind` (`safe_mode`, `freeze_capture`, `patch_window`, `deadman_confirm`, `step_status`, ...), `on`, `args`, `epoch`, `seq`, `not_before`, `not_after`, `sig` |
| 0x16 | `relay_request` | controller to relay | `target` (`host:port`), `class` (`device-proxy`/`bootstrap`), `id` |
| 0x17 | `token_issue` | controller internal (bootstrap handler) | `host`, `token`, `ttl_s` (1..3600; 600 for enrollment) |

`0x14` is reserved (v2 controller-to-agent chunk; `chunk` is now one type used
in both directions).

`config` is carried opaquely by the link layer (`body` is arbitrary JSON); the
agent interprets it as the signed `AgentConfig` of `internal/plan/agentconfig.go`
(section "Agent config" below). A `config` rides `welcome` on every connect and is
sent as its own message when the manifest or rules change.
`step`, `step_result` and `control` have typed fields; since minor 1 nothing is
tunnelled through a generic field.

### Plan steps, results and controls on the wire

All three are the typed form of a signed body. The receiver rebuilds the body
from the message fields and verifies the signature over its RFC 8785 canonical
JSON, so there are no separate "copies" that could disagree with the signed
content: changing any field fails verification.

- **`step`**: the fields are `plan.StepBody` (`plan` = plan id, `node` = node
  id, `params` = the action's parameter object, `deadman` = `deadman_sec`, ...)
  plus `secrets` (this host's secrets only; covered by `secrets_digest`) and
  `sig` (Ed25519, plan key). Executor checks: signature, host binding, window,
  `(epoch, seq)` monotonic (durable mark), approval record for non-check phases.
- **`step_result`**: the fields are `plan.ResultBody`; `status` is the signed
  outcome (`checked|applied|verified|failed|rolled_back`), `sig` is the agent's
  ECDSA P-256 identity signature. `detail` is an optional object (diff, notes)
  whose SHA-256 is the signed `after_digest`. Four statuses are **unsigned**
  (no `sig`) and never accepted as an outcome: `rejected` (step refused before
  verification), and the answers to a `step_status` query: `unknown` (the
  agent never accepted `(epoch, seq)`: nothing was applied), `lost` (accepted
  but no result on record, e.g. the agent restarted mid-step) and `running`.
- **`control`**: signed with the same Ed25519 plan key (domain-separated from
  steps) over `v, host, kind, on, args, epoch, seq, not_before, not_after`.
  Mandatory: an agent without a plan key accepts no control. The agent checks
  signature, `host`, a validity window of at most 5 minutes (controller default
  60 s, clock skew 60 s), and a per-host **control sequence** that must be
  above the agent's durable control mark. The control sequence is a counter
  parallel to the step sequence (steps and controls travel on different queues
  and may overtake each other, so one shared mark would refuse legitimate
  messages); the controller signs and queues controls under one lock so they
  are ordered. A refused control raises `agent.control_refused`. Kinds:
  `safe_mode` (`on`), `deadman_confirm` (`args` `{"id"}` or `{"plan","node"}`),
  `step_status` (`args` `{"plan","node","phase","epoch","seq"}`): the agent
  re-sends the stored signed `step_result` for that step (the agent keeps the
  last 256 durably) or an unsigned `unknown`/`lost`/`running` one.

### Inbound types per role

- Controller receives: `hello`, `heartbeat`, `events`, `step_result`, `chunk`, `chunk_have`, `ack`.
- Agent receives: `welcome`, `ack`, `step`, `config`, `fetch`, `chunk`, `chunk_have`, `control`.
- Relay receives: `relay_request`.

### Examples

```json
// hello
{"proto":1,"host":"ubuntu-ecom","version":"0.3.0","roles":["capture","decoys"],
 "caps":{"netlink_proc":true,"af_packet_v3":true},"last_seq":18342}

// heartbeat
{"seq":18361,"host_clock":"2026-10-18T14:03:12.441Z","spool_depth":12,
 "congestion":"ok","modules":{"link":"ok","proc":"ok"},"safe_mode":false,"drops":0}

// ack
{"seq":18361}
```

### Session establishment (`phylax/agent`)

1. TLS handshake with pin checks both ways (section 1).
2. Agent sends `hello` (with `token` on first contact only).
3. Controller validates (enrollment: token bound to the host, single use,
   idempotent; see the design's "Enrollment"), replies `welcome` followed by
   an `ack` carrying its highest contiguous stored sequence for that host
   (0 on first contact). The first `ack` tells the agent where to resume.
4. Agent streams `events` from `ack+1`, sends `heartbeat` every 5 s.
5. Controller answers each `heartbeat` with an `ack` (the controller-to-agent
   keepalive too). Silence for the read-idle window (20 s) ends the session.

### Versioning

`proto` is the major version. The **minor** revision (`hello.minor`,
`welcome.minor`, absent = 0) marks additive changes that older peers can
ignore; a sender uses a feature only with peers announcing the minor that
introduced it. Minor 1 (2026-10-22) replaced the step/result envelopes tunnelled
in `step.params` / `step_result.after`, and the unsigned `control`, with the
typed signed forms above, and added `hello.deadman`. A controller sends steps
and controls only to agents announcing minor >= 1.

`hello.proto` and `welcome.proto` carry the major protocol version (now 1). A
controller that does not support the agent's `proto` MUST close the connection
without sending `welcome`. Fields may be
added within a version (ignored by older receivers); new message types or
changed semantics bump `proto`. Receivers reject unknown message types
rather than skipping them, so a type is only sent to peers whose `proto`
is known to support it.

## 4. Chunked transfers

Pcap slices, files, packages and binaries are content-addressed by the
SHA-256 of the whole object. The sender splits it into chunks of at most
256 KiB (`chunk{sha256, offset, total, data}`). The receiver validates
`offset + len(data) <= total`, stores by offset, and verifies the digest when
complete. To resume, a receiver sends `chunk_have` listing ranges it holds
and the sender skips them. Bulk chunks ride the lowest priority and are
rate-shaped (section 5).

## 5. Priority and queues

Each connection has six send queues drained in **strict priority** order:

| Prio | Contents |
| --- | --- |
| 0 `critical` | heartbeats, alerts (events with `prio` critical), acks, hello/welcome, control (dead-man confirmations), chunk_have |
| 1 `step` | plan steps, step results, config, fetch, relay requests |
| 2 `evidence` | evidence attached to alerts |
| 3 `flow` | transactions and flows (event `prio` high) |
| 4 `telemetry` | other telemetry (event `prio` normal) |
| 5 `bulk` | pcap slices, files, binaries; token-bucket shaped (default unlimited, configurable bytes/s) |

An `events` batch is sent at the best (lowest-numbered) priority of the events
in it. A queued bulk transfer never delays an alert; because a higher
priority batch may overtake lower ones, `events` can arrive out of sequence
order (section 6).

**Bounds.** Every queue is bounded in messages and bytes (defaults per
priority: critical 1024 msgs/4 MiB, step 256/8 MiB, evidence/flow/telemetry
64/8 MiB, bulk 8/4 MiB). A full queue gives **backpressure** to the producer:
a blocking send waits (cancellable) and a try-send returns "queue full". The
link never discards a queued message silently: events that cannot be queued
stay in the agent's spool, which is the only place shedding happens (see the
design's "The spool"), and unacknowledged alerts, evidence, heartbeats and
step results are never shed. The one exception is **heartbeat coalescing**: a
newer heartbeat replaces any heartbeat still queued.

**Receive side.** Inbound messages are validated on the read loop and handed
to handlers off it, on two bounded queues (control/heartbeat, and everything
else), so a slow handler cannot delay control messages or acks (`ack` is
consumed in the read loop itself). A handler queue overflow ends the session
(the agent reconnects and resends unacknowledged events).

## 6. Reliability

- Every event has a per-agent sequence number `seq` (1, 2, ...) assigned by
  the agent's spool, plus the hash chain (`prev`, `hash`) from `internal/event`.
- The agent streams events with a bounded in-flight window (default 5000
  unacknowledged events, 500 events per message). On every (re)connect it
  restarts from the controller's first `ack` and resends everything above it.
- The controller deduplicates by `(host, seq)` and acks the **highest
  contiguous** sequence stored. Events arriving out of order (priority
  overtaking, or resend of an already stored range) are remembered in a
  bounded set (default window 65 536 sequences above the ack); an event
  beyond the window ends the session. The controller stores events durably
  *before* sending the ack. A link drop or controller restart therefore
  neither loses nor duplicates data, and an ack lost with the connection only
  causes a harmless resend.
- The hash chain is verified by the store when events are ordered by `seq`;
  the link guarantees only delivery and de-duplication.
- **Gap records break plain contiguity tracking.** A spool `spool.gap` record
  (`kind: spool.gap`, `seq = to+1`) announces a run of sequence numbers that
  were never stored. The controller therefore does not use `link.Receiver`'s
  contiguous-sequence tracker for event ingest: its per-agent reorder buffer
  treats a gap record as covering `from..to`, passes each contiguous run to
  `store.Ingest`, and acks only after the commit (implementation:
  internal/controller, 2026-10-22).
- Reconnect with jittered exponential backoff, 1 s to 30 s (half to full of
  the step), reset after a healthy connection.
- Chunked transfers resume via `chunk_have` (section 4).
- Per-agent limits (message rate, bytes/minute, concurrent fetches) are
  enforced by the controller on top of the above; an agent over its limit is
  throttled and never starves others.

## 7. Limits summary

| Item | Limit |
| --- | --- |
| Frame (type + body) | 4 MiB |
| Decompressed body | 4 MiB, window 8 MiB max |
| Chunk payload | 256 KiB |
| Events per batch | 5000 |
| Handshake deadline | 5 s; 128 concurrent handshakes; 4096 connections |
| Frame read window / write deadline | 20 s / 10 s |
| Heartbeat interval | 5 s |
| Handler queues | 256 messages each |
| String fields | host <= 253 bytes, ids/plan/node <= 1024 bytes, token <= 256 bytes |

## 8. Bootstrap (console one-liner)

1. The operator generates a one-time token in the UI for host *H*
   (`token_issue`, 10-minute TTL, single use).
2. The generated console command downloads `/phylax` and `/bootstrap.json`
   over HTTPS from the controller (no custom ALPN), pinning the controller key
   (`curl --pinnedpubkey sha256//...`, or a validation callback in PowerShell
   that also enables TLS 1.2 on older builds).
3. It checks the binary's SHA-256 (printed in the command) and installs. A
   wrong pinned key aborts before the token is sent; a tampered binary is
   never run.

Bootstrap config: controller (or relay) `address:port`, the controller pin,
the host's manifest identity, the one-time token, initial roles. The agent
then generates its own P-256 identity and enrolls (section 3, `hello.token`).

## 8a. Agent config

`config.body` is the RFC 8785 (integer subset) canonical JSON of
`plan.AgentConfig`: `v` (1), `host`, `epoch`, `version`, `issued_at`, `roles[]`
(vantage expanded), `modules` (optional sections `health`, `audit`, `net`,
`winevt`, `integrity`, `detect`; a missing section means the module does not run
on that host), `budgets`. `config.sig` is the hex Ed25519 signature, with the
plan key, over `"phylax-config-v1\0" || body`. `config.epoch` and
`config.version` repeat the signed values and must match them.

Agent checks, in order, all mandatory: a plan key is configured; the signature
verifies; `v`, `host` (must be this agent) and the envelope match; then replay
protection against a durable `(epoch, version)` mark (`<state>/configseq.json`):
an older epoch is `epoch older than accepted`, a version not above the mark is
a replay. Exceptions: the exact config already in force is a silent no-op
(controllers resend it on every connect), and the config whose acceptance was
interrupted before it was applied may be presented again. A refusal never ends
the session; it is reported as an `agent.config_rejected` event. An accepted
config is persisted verbatim to `<state>/config.json` before modules change; at
start-up the agent re-verifies that file (signature only) and runs it, so a
restart without the controller still runs the modules.

The agent reports the config in force in every heartbeat under the reserved
module name `config`: `"<state>/<epoch>.<version>"` with state `none`, `pending`,
`ok` or `degraded` (a module is unavailable on this host or failed to build).
The controller re-sends the config if a heartbeat shows the agent behind.

## 9. Enrollment and epochs

- The agent connects with ALPN `phylax/agent` and presents its token in
  `hello`. The controller checks the token against the host identity it was
  issued for, records the agent's pin, marks the token used and replies
  `welcome{enrolled:true}` then `ack{0}` and `config`. Enrollment is
  idempotent: a retry of the same (token, pin) after a dropped connection
  succeeds again.
- Host identity is manifest name + enrolled pin, never an IP address. A new
  pin claiming an existing host identity is an alert until an operator
  approves a re-enrollment (revokes the old pin, issues a fresh token).
- `welcome` and `ack` carry no epoch or chain hash on the wire (ack is a
  sequence number only). The controller epoch reaches agents inside the signed
  `config` and in every signed step. (Noted 2026-10-22 when the controller was
  built.)
- Plan steps carry an epoch in addition to a sequence number; restoring the
  controller from a snapshot raises the epoch (needs the plan-signing key).
  After a restore the controller asks agents to resend everything their spools
  still hold and verifies the resent chain passes through the snapshot's
  `(seq, hash)`.
