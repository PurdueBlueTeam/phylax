# Phylax wire protocol v2

Written protocol spec, M0 deliverable. This is the contract between
`phylax agent`, relays and `phylax serve`; the Go code in `internal/link`
implements it and the protocol tests in `internal/link` and the integration
tests pin it.

## Transport

- One long-lived TLS connection per logical stream. No multiplexing layer.
- **TLS 1.3 only**, Go standard library, self-signed certificates. Certificate
  validation is *replaced* by public-key pinning: each side verifies the
  peer's certificate SPKI (SHA-256, base64) against a pinned value and
  **ignores certificate dates** (moving the clock cannot break
  authentication). Bootstrap connections (see ALPN table) also accept TLS 1.2
  because Windows 10 / Server 2016 / 2019 cannot do 1.3, and because stock
  console tools (curl, PowerShell) use the host's own TLS stack.
- Keys:
  - The controller generates a TLS ed25519 keypair at first start; the
    public-key pin travels in every agent/relay bootstrap bundle.
  - Each agent generates its own TLS ed25519 keypair at install and presents
    it at enrollment; the controller pins it against the host's manifest
    identity. A stolen agent key impersonates only that one host.
  - The **plan-signing key** (also ed25519, controller memory only) is a
    *different* key from the transport key. Plan steps are signed with it;
    agents verify signature + expected plan id + epoch + monotonic sequence.
- The controller listens on **one port** (`agent_port`) for every connection
  type; the ALPN value selects the handler.

| ALPN | Opened by | Purpose |
| --- | --- | --- |
| `phylax/agent` | Agent (direct or spliced through a relay) | All agent messaging |
| `phylax/relay` | Relay | The relay's control connection |
| `phylax/splice` | Relay | One device-proxy or bootstrap stream |
| `phylax/patch` | Agent | One proxied HTTP connection during a patch window |
| *(none / `http/1.1`)* | A host being bootstrapped from the console | Binary + bootstrap-config download with a one-time token |

### Relay behavior

The relay is a dumb splicer:

- Listens on its declared port; accepts connections only from source
  addresses in its segment's manifest entry.
- For each accepted `phylax/agent` connection it opens a fresh outbound
  `phylax/agent` connection to its parent (controller or parent relay) and
  copies bytes both ways. The agent's TLS session runs end to end; the relay
  never sees plaintext and holds no agent keys.
- It keeps one outbound `phylax/relay` control connection to the controller
  (its own identity, pinned) used only for device-proxy and bootstrap
  splice requests.
- A device-proxy request names a target address:port; the relay checks it
  against its manifest allowlist, opens a connection to the device and a
  fresh outbound `phylax/splice` connection to the controller, and splices.
  The device's own TLS stays end to end.
- Each splice records metadata only: source, destination, bytes, duration.

## Framing

- Every message: `u32be length` + `u8 type` + `JSON body`.
- `length` counts the type byte + body (max **4 MiB**).
- Types 0x40–0x7F mark a **zstd-compressed** body (pure Go). Compressed
  messages decompress to at most 4 MiB.
- Content-addressed bulk (pcap slices, files, binaries) does not ride inline:
  it moves as 256 KiB chunks addressed by SHA-256, zstd-compressed first
  where that helps.

### Message types

| Code | Name | Direction | Payload |
| --- | --- | --- | --- |
| 0x01 | `hello` | agent → controller | host id, agent version, roles, detected capabilities, last acknowledged sequence |
| 0x02 | `heartbeat` | agent → controller | sequence, host clock, spool depth, module status, safe mode, capture drop counts |
| 0x03 | `events` | agent → controller | batch of events (telemetry, alerts, transactions, flows), each with its sequence number |
| 0x04 | `step_result` | agent → controller | per-action check/apply/verify outcome with before and after state |
| 0x05 | `chunk` | agent → controller | bulk chunk (sha256, offset, payload) |
| 0x10 | `ack` | controller → agent | highest contiguous sequence stored |
| 0x11 | `step` | controller → agent | a signed plan step (signature, epoch, seq, action, params, secrets-for-this-host-only) |
| 0x12 | `config` | controller → agent | signed config and rules update |
| 0x13 | `fetch` | controller → agent | request for a pcap slice, file or telemetry window |
| 0x14 | `chunk` | controller → agent | step payloads: files, packages, the agent binary |
| 0x15 | `control` | controller → agent | safe mode on/off, freeze capture window, patch window open/close |
| 0x16 | `relay_request` | controller → relay | splice request: target address:port + stream class |
| 0x17 | `token_issue` | controller (bootstrap handler) | one-time enrollment token for a named host, 10-minute TTL |

### JSON shapes (core)

```json
// hello
{ "host": "ubuntu-ecom", "version": "0.3.0", "roles": ["capture","decoys"],
  "caps": ["netlink_proc","af_packet_v3","audit_mc"], "last_seq": 18342 }

// heartbeat
{ "seq": 18361, "host_clock": "2026-10-18T14:03:12.441Z", "spool_depth": 12,
  "modules": { "link": "ok", "proc": "ok", "fim": "ok" },
  "safe_mode": false, "drops": 0 }

// events (compressed)
{ "events": [ { "seq": 18362, "ts": "2026-10-18T14:03:12.501Z",
                "type": "process_start", "data": { "pid": 4321, ... } } ] }

// ack
{ "host": "ubuntu-ecom", "seq": 18361 }

// step
{ "plan": "harden-ecom", "node": "ssh_off", "epoch": 3, "seq": 7,
  "action": "service.state", "params": { "unit": "ssh.service", "state": "disabled" },
  "secrets": { "unit": "ssh.service" }, "deadman": 90,
  "sig": "<ed25519 base64 over plan|node|epoch|seq|action|params|secrets>" }

// control
{ "kind": "safe_mode", "on": true }
```

## Priority

The sender drains its queues in strict order:

1. Heartbeats, alerts and acknowledgments
2. Plan steps and step results
3. Evidence attached to alerts
4. Transactions and flows
5. Other telemetry
6. Bulk transfers (pcap slices, files, binaries)

A queued bulk transfer never delays an alert.

## Reliability

- **Spool and acknowledge.** Every event has a per-host sequence number.
  The agent stores events in a hash-chained spool (event *n* carries the
  SHA-256 of event *n-1*). After every reconnect the agent resends from the
  last acknowledged sequence; the controller discards duplicates by
  (host, seq) and verifies the chain. Neither a controller restart nor a
  link drop loses or duplicates data.
- **Reconnect** with jittered backoff, 1 s to 30 s.
- **Chunked transfers resume**: the receiver reports which chunks it already
  has.
- **Limits** per agent: message rate, bytes/minute, concurrent fetches. An
  agent over its limit is throttled, never allowed to starve the others.
- **Agent data is evidence, never instructions**: every message is validated
  against its schema; nothing an agent sends is ever executed or used to
  build a command or query.

## Volume and retention

- Shipped continuously: alerts, heartbeats, process starts, connection
  changes, file changes on watched paths, selected log lines, flows, protocol
  transactions on scored ports, denied-egress attempts, sinkhole captures,
  decoy sightings.
- Kept on the host until fetched: the packet ring, raw sampler output, full
  log files.
- Spool near its cap: drop acknowledged events oldest first; then shed
  unacknowledged data in order (raw log lines, connection churn, flows on
  unscored ports). Unacknowledged alerts, evidence, heartbeats and step
  results are **never** shed.

## Bootstrap (console one-liner)

1. The operator generates a one-time token in the UI for host *H*
   (`token_issue`); it expires in 10 minutes and is single-use.
2. The console command (generated per host by the UI) downloads
   `/phylax` (the binary) and `/bootstrap.json` (the bootstrap config) from
   the controller over plain HTTPS (no custom ALPN), with the controller's
   public key pinned (`curl --pinnedpubkey`, or a validation callback in
   PowerShell that also enables TLS 1.2 on older builds).
3. The command checks the binary's SHA-256 (printed in the command) and
   installs. A wrong pinned key aborts before the token is ever sent; a
   tampered binary is never run.

Bootstrap config contents: controller (or relay) address:port, the
controller's public-key pin, the host's manifest identity, the one-time
token, and the initial roles.

## Enrollment

1. The agent connects with ALPN `phylax/agent` and presents its token in
   `hello`.
2. The controller checks the token against the host identity it was issued
   for, records the agent's public key, marks the token used, and replies
   with `ack` (seq 0 on first contact) followed by `config`.
3. Host identity is manifest name + enrolled key, never an IP address.
4. A new key claiming an existing host identity after a re-enrollment is an
   **alert** until an operator approves it — re-enrollment is explicit
   (revokes the old key, issues a fresh token).

## Epochs (controller recovery)

- Plan steps carry an **epoch** in addition to their sequence number.
- Restoring the controller from a snapshot raises the epoch. Agents accept
  any sequence within a higher epoch, so steps the lost controller sent
  after the snapshot cannot block the restored one. Raising the epoch takes
  the plan-signing key, so a hostile relay or network still cannot replay
  old steps.
- After a restore, the controller asks each agent to resend everything its
  spool still holds; it verifies the resent chain passes through the
  snapshot's recorded (seq, hash). Anything no spool holds is marked on
  timelines as a gap ("controller restored").
