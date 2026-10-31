#### `capture`

**1. Purpose and evidence.**

Every host with the `capture` role records its own traffic into a bounded packet ring, ships a flow record for every connection and parsed protocol transactions for the declared service ports, and freezes the ring around an alert. It is passive: it never sits in the scored path and drops packets before it slows the host.

Capture feeds, by event only (no module imports another):

- scorer learning: the round clock, scorer fingerprints, check discovery and account learning read the transactions (`scorer`);
- traffic labels, trace-back and attack chains (`traceback`, `chains`);
- IR evidence: frozen pcap slices attached to alerts (`report`, `detect` collects `freeze_ring`);
- scan detection and the controller-scope network rules (`detect`).

Evidence that it matters for points:

- On the flat LAN it is the only east-west visibility, because LAN traffic never crosses the Palo (core: environment table; review D74, D231, D234, D236).
- Scorer learning depends on it. The parsers follow what Quotient actually sends [Q §6, Q §9.13, SP §A4]. Against a real Quotient run (2026-10-22 lab, 84 rounds) the recorded Go TLS ClientHello parses to the JA3 `006598cf32b8feecd39e4337bdba9c44` and JA4 `t13i131000_f57a46bbacb6_ab7e3b40a677`, the SSH HASSH values for the real login and for `BadAttempts` match, and SMTP, IMAP, POP3, FTP, SMB, WinRM, DNS and ICMP sessions decode with no parser panics or reassembly gaps (`docs/capture.md`, lab table).
- The ring exports real pcap, so Wireshark, Suricata and Zeek can read slices [OA §5.10].
- Credential-bearing traffic is the reason for field-level sealing: no plaintext password reaches the controller's disk.

**2. Status and code.**

Status: built; the controller side of freeze is not.

| Piece | State | Where |
| --- | --- | --- |
| Engine: decode (Ethernet, 802.1Q, IPv4/IPv6 with extension headers, TCP/UDP/ICMP, raw-IP), flow table, scan tracker, snap policy | built | `internal/capture/{engine,decode,flow,events}.go` |
| Ring with per-flow cutoff, freeze, pull, release | built | `internal/capture/{ring,freeze}.go` |
| AF_PACKET TPACKET_V3 source, classic BPF built with `x/net/bpf`, pcap replay source | built; run only on pcaps and a Docker loopback test | `source_linux.go`, `bpf.go`, `source.go` |
| TCP reassembly (reordering, overlap, wraparound, mid-stream, bounded) | built | `reasm.go` |
| Parsers: `http`, `tls`, `ssh`, `ftp`, `smtp`, `imap`, `pop3`, `dns`, `smb2`, `winrm`, `tds`, `icmp`, `tcp` (plus `ntlm`, `txn`, `parsertest` helpers) | built | `internal/parsers/*` |
| Agent module, credential sealing, evidence files, disk budget, rate limits, stats | built | `internal/capture/module.go`, `internal/agent/mods/capture.go` |
| Controller-scope rules over stored flows (P88 `D13e`, `D18b`) | built | `internal/controller/capture_ingest.go` |
| Org-network labels for `http_request` destinations | built | `orgnets.go`, `orgnets.json`, `cmd/orgnetgen` |
| Controller sends `freeze_capture` for controller-scope `freeze_ring` collects | missing (Known bug 7) | |
| Agent answers `fetch` for evidence pcaps | missing (core `fetch` handler is a no-op, Known bug 4) | |
| TFTP and NTP parsers | missing (review D240, N7.1) | |
| Signed `AgentConfig` section for capture (`capture.json` today) | missing | |
| Source-address check at drop flag | missing | |
| Windows raw-socket capture | cut (review D235) | `OpenInterface` returns `ErrUnsupported` on Windows |
| LDAP parser | not built; build only if an LDAP check is scored (review D241) | |
| Splunk REST parser, Kerberos metadata, file carving | cut (review D241, D242) | |

**3. Capability manifest.**

```go
module.Manifest{
	Name:      "capture",
	Sides:     []module.Side{module.SideAgent, module.SideController},
	OS:        []string{"linux"}, // Windows coverage comes from other sensors (below)
	Privilege: "root",            // CAP_NET_RAW
	Roles:     []string{"capture"},
	Consumes:  []string{"detect.alert", "devices.traffic"},
	Emits:     []event.Type{ /* part 5 */ },
	Budget: module.Budget{CPUMillisPerSec: 25, HeldMB: 512, EventsPerSec: 600, Burst: 1200,
		BytesOutPerMin: 31457280, DiskMB: 512},
	Default:  true, // on hosts with the capture role
	Tables:   []string{"capture_source_check"},
	Content:  []string{"rules/capture"},
	Actions:  nil,
	Pages:    nil, // folded into the Traffic page
	Evidence: []string{"2026-mw-regional-packet#e19"},
}
```

Budget notes: `EventsPerSec: 600` is the supervisor budget in the code (per-class buckets: transactions 300/s, flows 300/s, scans 20/s). `HeldMB: 512` is the default ring (256 MiB) plus the freeze hold (256 MiB); see part 12, where this conflicts with the agent memory cap. `CPUMillisPerSec` is a starting cap against the agent-wide 3% average; the module has not been run on a real NIC under load.

**4. Configuration.**

The block is `modules/capture.yml`. The signed `AgentConfig` decides whether the module runs (the host has the `capture` role, Linux) and which ports are scored; the rest is local tuning that today lives in `<state>/capture.json` and moves into the signed config as `modules.capture`.

```yaml
# manifest/modules/capture.yml
capture:
  interface: ""                 # "" = all interfaces
  exclude: []                   # addr:port endpoints never captured; the controller link is always added
  ring_mb: 256                  # packet ring
  hold_mb: 256                  # shared budget for freeze holds
  flow_bytes: 1048576           # per-flow full-length cutoff, then 128 bytes
  disk_budget_mb: 512           # pcaps under <state>/capture
  freeze: { before: 5m, after: 10m, max_windows: 8 }
  scan: { threshold: 20, window: 10s }
  scored_ports_extra: []        # on top of the net module's service map
  services_extra: {}            # port -> parser, e.g. { 69: tftp, 123: ntp }
  stats_every: 60s
  seal_key: capture.seal        # name of the vault secret distributed to the host (part 12)
```

```go
// package plan: new ModuleSettings.Capture, replacing capture.json
type CaptureSettings struct {
	ModuleLimits
	Interface      string            `json:"interface,omitempty"`
	Exclude        []string          `json:"exclude,omitempty"`
	LocalAddrs     []string          `json:"local_addrs,omitempty"`
	RingMB         int               `json:"ring_mb,omitempty"`
	HoldMB         int               `json:"hold_mb,omitempty"`
	FlowBytes      int               `json:"flow_bytes,omitempty"`
	DiskBudgetMB   int               `json:"disk_budget_mb,omitempty"`
	FreezeBeforeS  int               `json:"freeze_before_sec,omitempty"`
	FreezeAfterS   int               `json:"freeze_after_sec,omitempty"`
	ScanThreshold  int               `json:"scan_threshold,omitempty"`
	ScanWindowS    int               `json:"scan_window_sec,omitempty"`
	ScoredPorts    []uint16          `json:"scored_ports,omitempty"`
	Services       map[uint16]string `json:"services,omitempty"`
	SealKeyRef     string            `json:"seal_key_ref,omitempty"`
}
```

Defaults match the code: ring 256 MiB and 2 M packets, hold 256 MiB, flow cutoff 1 MiB, disk budget 512 MiB, scan threshold 20 within `ScanWindow`, at most 1 024 scan sources with 4 096 targets each, freeze 5 minutes before to 10 minutes after.

**5. Events.**

Consumed: `detect.alert` for this host (a rule that collects `freeze_ring` freezes the ring); `devices.traffic` (controller side only, for the source-address check).

Emitted. The code's names (`net.txn`, `net.flow`, `net.scan`, `http_request`) are renamed `capture.*` when the module is retrofitted; the controller accepts the old names for one release (core: kinds).

| Kind (code name) | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `capture.txn` (`net.txn`) | 1 | normal | `proto`, `type`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `community_id`, `ok`, `duration_ms`, `attr` and `list` (the scorer feature keys; values clipped to 512 bytes, 64 items), `cred {user, domain, mech}`, `sealed`, `secrets_dropped` |
| `capture.flow` (`net.flow`) | 1 | bulk | one per ended flow including SYN-only (`handshake: timeout`) and refused ones: `community_id`, `proto`, endpoints, `start`, `end`, packets and bytes each way, `handshake`, `end_reason`, `service`, `scan`, `truncated`; when the host's addresses are known `dir`, `raddr`, `laddr`, `lport`, `rport` |
| `capture.scan` (`net.scan`) | 1 | high | `src_ip`, `start`, `end`, `targets`, `hosts`, `final` |
| `capture.http_request` (`http_request`) | 1 | normal | `method`, `host`, `uri`, `ua`, `status`, endpoints, `community_id`, `dst_org`, `dst_cloud` |
| `capture.evidence` | 1 | high | `id`, `rule`, `alert_time`, `from`, `to`, `ips`, `path`, `bytes`, `packets`, `sha256`, `final`, `truncated`, `evicted`, `error` |
| `capture.stats` | 1 | normal | packets, kernel drops, ring occupancy, every drop counter (`ReasmGaps`, `ReasmCapped`, `ParserPanics`, `HoldDrops`, rate-limit sheds) |
| `capture.source_check` | 1 | high | controller side: `agree` (bool), `sample` (flows compared), `firewall_sources` (bool: every inbound source is the firewall), `recovered` (bool) |

**6. Behaviour.**

*Data flow.* A source (AF_PACKET TPACKET_V3 or a pcap) feeds `Engine.Process`: decode, then the ring (bounded, snap policy), the flow table (Community ID), TCP reassembly into a parser, and failed or empty connections into the scan tracker. The engine is one pipeline, one per capture thread; `Process`, `Expire` and `Flush` are serialised and callbacks run under the lock, so callbacks only convert and queue (4096 events); a full queue sheds and counts. Time is the packet clock, so offline replays are deterministic.

*Tiers.*

| Tier | Contents | Lives on | Shipped |
| --- | --- | --- | --- |
| Full packets | Every packet. Full length on scored ports, decoy ports (and sinkhole traffic if the sinkhole is kept), ICMP echo and flows announced by a parser (FTP data channels); the first 128 bytes elsewhere. A per-flow byte cutoff keeps bulk transfers from evicting evidence; the flow is marked `truncated`. | Host packet ring | On request as a filtered time slice; automatically around alerts |
| Flow records | One record per connection | Agent spool | Continuously |
| Transactions | Parsed exchanges on declared service ports | Agent spool | Continuously |

*Ring.* In the code the ring is an in-memory circular buffer bounded by bytes (`MaxBytes`, default 256 MiB) and packets (`MaxPackets`, default 2 M); oldest packets are evicted first, each packet is copied in so sources can reuse their buffers. v3 specified an on-disk ring of the smaller of 2 GB or 10% of free disk. The code's choice is reasonable for a first version and keeps the API stable if the ring moves to a file. The design follows the code and records the disk-ring sizing as open (part 12).

*Sources.* `OpenInterface` opens `AF_PACKET`/`SOCK_RAW`, sets TPACKET_V3, maps a block ring (8 x 1 MiB, 60 ms block timeout), attaches the classic BPF program before binding so nothing unfiltered is ever queued, then binds to the interface (or all). There is no promiscuous mode: a host records its own traffic. Kernel-stripped 802.1Q tags are re-inserted so pcap output shows the wire. Kernel drops are read from `PACKET_STATISTICS` (which resets on read, so the source accumulates). The filter returns full snap length on scored ports and ICMP, 128 bytes elsewhere (or nothing for unscored traffic when configured so), and drops excluded endpoints (the agent-to-controller link) in both directions, IPv4 and IPv6, tagged or untagged. Limits: at most 48 ports in the BPF program; IPv6 extension headers and non-first fragments are treated as "other".

*Windows.* Windows packet capture is cut (review D235). The module reports unavailable there. Windows coverage comes from the connection table, Sysmon 3, Security 5156/5157 and Palo logs; services on Windows get transactions from their own logs (IIS, DNS analytical log, `winevt` content) and flows from the `net` module. The reference manifest gives Windows hosts the `capture` role; it should not (part 12).

*Bounded and passive.* Under load the agent drops packets rather than slowing the host and reports drop counts in `capture.stats`. The agent's own link is excluded in the BPF program (no feedback loop). Scans are aggregated: a source that causes at least `scan.threshold` (20) refused, unanswered or payload-less connections to distinct address:port pairs within `scan.window` yields one `capture.scan` when the threshold is crossed and a final one when the window closes; those flows are flagged and no longer produce individual `tcp` transactions.

*Freeze on alert* (review D237). The module subscribes to the agent's bus. A `detect.alert` for this host whose rule collects `freeze_ring` freezes the ring from alert time minus 5 minutes to plus 10 minutes, for the remote addresses the alert involves (entities and evidence fields; loopback and the host's own addresses never filter, because every packet involves them; no remote address means all traffic). Packets already in the ring are pinned; packets arriving until the window's end keep being added to the hold, so freezing never drops post-alert packets and ring eviction cannot lose pinned ones. The hold id is a hash of the rule and addresses, so a repeat extends the same window; at most 8 windows are open (the rest are counted as skipped). Holds draw from one shared budget (`hold_mb`); when it is full `Frozen(id).Full` is set and `HoldDrops` counts the loss. Two `capture.evidence` events follow: one at once (what the ring held) and one when the window closes (`final: true`), same file replaced atomically. The pcap is a real pcap (microsecond timestamps, original lengths kept) at `<state>/capture/<id>.pcap`. The disk budget (`disk_budget_mb`, default 512) refuses a capture larger than the whole budget (the evidence event carries the error) and otherwise deletes the oldest other pcaps to make room. The controller pulls the slice by `fetch` at bulk priority, filtered to the IPs involved.

*Controller-scope freeze.* A controller-scope rule (for example `D13e`, `D18b`, which see flows across hosts) that collects `freeze_ring` must send a signed `control: freeze_capture` to the agents that saw the flows, carrying the rule id, the alert time and the addresses. The controller never does this today (review D237; Known bug 7); finishing it is part of this module. The agent handler reuses the module's freeze path, so the hold id and windows are the same as for a local alert.

*Source-address check at drop flag* (review D238; kept). Host capture can fingerprint the scorer by behaviour whatever the source, but labelling external sources needs real addresses. In the first minutes the controller compares the source addresses captured on inbound flows to scored services with the Palo's traffic logs (`devices.traffic`, pulled for this check and on demand) and emits `capture.source_check`. If every inbound connection appears to come from the firewall (the Palo rewrites source addresses on inbound NAT), it warns loudly and the `traceback` and `scorer` modules recover sources from the Palo traffic logs instead. It decides whether scorer learning by address-adjacent features works at all. In the 2026-10-22 lab the check passed (real client addresses, no NAT between runners and boxes); the Palo question stays open for the event.

*Reassembly.* Per direction: reordering, overlap, retransmission, sequence wraparound and mid-stream pickup. Bounds per direction: 64 parked segments, 128 KiB parked bytes, 4 MiB delivered. Exceeding the first two declares a gap and ends the parser (which flushes what it has), because parsing across a hole would mis-frame; exceeding the third caps the stream. A segment cut by the snap length on a service port is treated as a gap. Parsers see only in-order bytes. A parser panic is recovered per flow, counted in `ParserPanics`, and silences only that flow.

*Parsers.* All are Go-native and isolated, so a bug affects only its own protocol. They run on the ports in the service map (`DefaultServices`: 21 ftp, 22 ssh, 25/587 smtp, 53 dns, 80/8000/8080 http, 110 pop3, 143 imap, 443/465/993/995/8089/8443/5986 tls, 445 smb, 5985 winrm, 1433 tds); a scored port with no mapping is sniffed from the first bytes (HTTP, TLS, SSH, SMB, TDS from the client; SSH, POP3, IMAP, SMTP, FTP banners from the server). Every parser emits a `txn.Txn` (`Proto` is the `scorer` feature vocabulary, `Attr`/`List` the scorer's feature keys plus extras, an optional `Cred`, and `Secret` naming credential-derived fields).

| Phase | Parsers | State |
| --- | --- | --- |
| 1 | HTTP/1.x; DNS over UDP and TCP; ICMP echo; SSH (banner, KEXINIT, HASSH, dwell); SMTP; IMAP; POP3; FTP control with data-channel linkage; SMB2 with NTLM; WinRM over HTTP (`/wsman`, NTLM exchange); bare TCP connect-and-hold (RDP, tcp) | built |
| 1, added | **TFTP and NTP** (both scored at the 2026 regional [[2026-mw-regional-packet#e19]]; they may return in 2027) | missing |
| 2 | TDS (MSSQL pre-login, Login7, SQL batch); TLS handshake metadata (SNI, ALPN, JA3, JA4, certificate for TLS 1.2 and earlier) | built |
| 2, conditional | LDAP binds and searches | build only if an LDAP check is scored |
| 2, generic | First-bytes fingerprint for unknown protocols: the flow record carries a SHA-256 of the first 64 payload bytes each way, and the sniffer labels known ones, so a service added by an inject is fingerprinted before anyone writes a parser | built |

Cut: Splunk REST parsing (the check and logs cover it; review D241), Kerberos metadata and file carving from HTTP, FTP and SMB (no evidence they score or speed an IR; Sysmon and DC events cover Kerberos; review D242).

The features each parser emits (`http.*`, `tls.*`, `ssh.*`, `ftp.*`, `smtp.*`, `imap.*`, `pop3.*`, `dns.*`, `smb.*`, `winrm.*`, `tds.*`, `icmp.*`, `tcp.*`) are specified in `docs/capture.md` and are the input contract of the `scorer` fingerprint table (Appendix G). The Go TLS JA4 changes with the Go toolchain (Go 1.27 adds hybrid key groups, giving a different c-part than the recorded Go 1.25.3 value), so the table is re-learned per event, as `scorer` already assumes.

*TFTP and NTP parsers.* TFTP on UDP 69: request opcode (RRQ/WRQ), filename, mode, and the first data block's size and hash; transfer completion by the final short block. NTP on UDP 123: version, mode, stratum, poll, and the reference id. Both emit a `txn` with `Proto` `tftp` and `ntp`; both are added to `services_extra` only when the manifest lists the service as scored, so the lint rule that protects UDP 69/123 and the parser switch on together. `shortcut: TFTP follows a single transfer on port 69 only, upgrade if a packet shows a server that answers from a random port`.

*Credentials.* No password is stored. `Cred.PassHash` is the first 16 hex digits of SHA-256(`"phylax-cred-v1\0"` + password) so a learned credential can be recognised; the hash of a weak password can be guessed offline, hence `Secret` marks it for field-level encryption. NTLM carries user and domain only. SQL batch text is clipped to 256 bytes. SMTP bodies are stored only when at most 128 bytes (the scorer's is 64 hex digits). The module never puts a `Secret` field in an event in the clear: with a 32-byte hex key (`capture.seal`) the fields are sealed with AES-256-GCM (`enc1:` plus base64) under `sealed`; without it they are dropped and named in `secrets_dropped`. `Cred.PassHash` is always treated as secret, whether a parser listed it or not, and attribute keys that look like passwords are dropped. The controller stores credentials seen in traffic field by field encrypted and masked until revealed (core: Secrets).

*What passive capture cannot see* (carried from `docs/capture.md`).

- SSH after NEWKEYS: `ssh.auth`, `ssh.pty` and `ssh.fail_then_accept` come from sshd logs (`logs`); the parser supplies the banner, both KEXINITs, HASSH and dwell.
- TLS 1.3: certificates and the ALPN selection are encrypted; JA3/JA4, SNI, offered ALPN and the server's chosen version and cipher are visible.
- TDS with encryption negotiated: Login7 travels inside TLS; the session reports `tds.tls=true` and the pre-login fields only.
- SMB 3 encryption stops parsing; signing does not.
- SMTP, IMAP, POP3 and FTP after STARTTLS/STLS/AUTH TLS stop parsing and set `*.tls`.
- Compressed HTTP bodies are hashed as sent; HTTP/2 is not parsed; DNS responses are not paired with queries by the parser (correlate on `dns.id` and Community ID).

*HTTPS visibility* (review D243). For HTTPS services we get handshake metadata from packets, request details from the server's own access logs (custom formats set by hardening; the `logs` module), and response content from active checks (`checks`). The scorer's Go TLS ClientHello is distinctive.

*Org networks.* `internal/capture/orgnets.json` is embedded in the agent (offline) and labels `capture.http_request` destinations (`dst_org`, `dst_cloud`) for rule P82. It ships as a bootstrap seed of coarse prefixes. It is regenerated before the event on a connected machine with `go run ./internal/capture/cmd/orgnetgen` from the Azure service tags, Microsoft 365 endpoints, AWS ranges and any provider lists; a host can override it with `<state>/orgnets.json` (an invalid file fails the module build rather than silently using the seed; capped at 60 000 prefixes).

*Pulled pcaps and optional analysis.* Frozen slices are real pcap files. The controller can run Suricata and Zeek over a slice offline and join their output to Phylax flows by Community ID, attaching the result to the incident (the `suricata` module).

*Palo-side capture* is in `devices` (review D244 is kept there), as a complement for "is the scorer even getting through".

**7. Actions and content.**

No actions. Pulling a pcap is a `fetch`, not an action. Content: `rules/capture/` holds the controller-scope rules over stored flows (`D13e` and `D18b` are the first; they move here from `rules/network.yml` at retrofit) with inline tests, and `reference.scorer_sources` seeding (below).

*Controller wiring* (built, `capture_ingest.go`). Controller-scope rules run over the stored events of all agents. `capture.flow` events with a direction are translated to the common `conn` kind (`op: opened`, `dir`, `raddr`, `laddr`, `lport`); the agents' own `conn` events are fed as they are; alerts go to the operator queue with the flow events as evidence. Only events at or below the ingest ack are fed, so a re-sent batch is never counted twice. The engine is rebuilt and re-seeded when its config inputs change. `reference.scorer_sources` is seeded from the manifest: hosts with the `scanner` or `canary` role (the Kali), their public address and their segment's translated source (device `external_ip`), and the controller host. The scorer itself is recognised by behaviour, so its addresses are never guessed; `Controller.NoteScorerSource(addr)` adds an address that scorer discovery or the operator confirmed (bounded at 256, in memory). Agent-side detection configs do not carry this seed yet.

**8. UI.**

Capture folds into the Traffic page: per host capture state (interface, ring fill, kernel drops, sheds), flows and transactions by service, scans, the list of frozen windows with a download link (download only, never inline), and the source-address check result. No separate page. Host x step grid: none. Overview tile: capture hosts reporting versus expected, and the drop rate.

**9. Health.**

- `ok`: source open, ring filling, drops below threshold.
- `degraded`: kernel drops above a threshold (reported in `capture.stats`); ring or hold budget exhausted; parser panics; sheds from the queue; the seal key missing (credential fields dropped); on Windows, the module is unavailable and the host's config reports `degraded` until the role is removed.
- `unavailable`: not Linux, no `CAP_NET_RAW`, or no interface. A finite source (tests) ends without stopping the module, so freezes still work.
- Gaps: encrypted protocols not parsed (TLS 1.3, SMB3 encryption), unscored traffic captured at 128 bytes only, the Windows host classes above.

**10. Scoring safety.**

- Passive: an AF_PACKET read socket with a filter. It never injects, answers or redirects.
- Bounded: ring, hold, flows, scan sources, parked reassembly bytes and the event queue are all capped; it drops packets and events rather than slowing the host, and counts what it drops.
- It reads scorer traffic, so credential handling is the main risk: fields are sealed or dropped before an event exists, and tests prove the password and its hash appear in neither events nor spool files.
- The module has no alert-only stage because it takes no action.

**11. Tests.**

- Built: generated fixtures (`internal/capture/fixture` builds Ethernet/VLAN/raw-IP, IPv4/IPv6 TCP sessions with chosen segmentation, reordering, loss, keepalives, teardown, plus NTLM, SMB2, TDS, DNS and SSH wire builders) driven through the pcap source; every parser also runs byte by byte to prove segmentation independence; ring bounds, freeze semantics, reassembly orderings and the BPF program (in `bpf.VM`) have their own tests; the recorded values (Go 1.25.3 ClientHello to JA3/JA4; HASSH for the real login and for `BadAttempts`) are asserted; module tests cover lifecycle, secrets, freeze-on-alert, disk budget, rate limits; `internal/controller/capture_test.go` runs a rotating-source SYN scan through the module, the real link and controller ingest to a `P88` alert; `lab_test.go` replays the 2026-10-22 Quotient pcaps (skipped when absent).
- Fuzzing, 10 s each: `FuzzHTTP FuzzWinRM FuzzSSH FuzzTLS FuzzFTP FuzzSMTP FuzzIMAP FuzzPOP3 FuzzDNS FuzzDNSDatagram FuzzSMB2 FuzzTDS FuzzNTLM FuzzICMP`, and `FuzzReassembly` and `FuzzProcess` in capture.
- Real AF_PACKET: `TestAFPacketTPACKETV3OnContainerLoopback` runs only with `PHYLAX_CAPTURE_DOCKER=1` and `/.dockerenv`; nothing else touches a real interface.
- To add: TFTP and NTP parsers (fixtures and fuzz), `freeze_capture` end to end (controller rule, control message, agent freeze, `fetch`), the source-address check against a fixture Palo log, `go test -race` on the module, the conformance entries.
- Lab: a real capture run on a real NIC under load (drop counts, block sizing, VLAN and bonded interfaces, CPU against the budget), the T33 expectations that depend on stitched flows, and the Palo inbound NAT question. The Windows raw-socket test (v3 T26) is dropped with the cut.

**12. Limits and open items.**

- **Memory cap conflict with the core.** The core Footprint table puts agent RSS at 80 MB "excluding the packet ring and kernel-held memory". The code's ring and hold are in the Go heap (256 MiB each by default), so they count against `debug.SetMemoryLimit` and `MemoryMax`. Either the ring moves to a file (the API allows it; v3 specified an on-disk ring sized at the smaller of 2 GB or 10% of free disk, and `policy.yml` still has `packet_ring_max_bytes` and `packet_ring_free_pct`, which the code ignores) or the cap excludes it. Undecided; recommendation is the file-backed ring.
- **Reference manifest.** The core hosts example gives Windows hosts (`ad`, `mssql`, `win11-wkst`) the `capture` role. With Windows capture cut, those entries should drop the role so health does not read `degraded` forever.
- **Seal key distribution.** `capture.seal` is a file in the state directory with no distribution mechanism. A vault secret delivered in the signed config (`seal_key_ref`) is proposed; the key is then in each capture host's config.
- **Agent `fetch`** is a core task (Known bug 4); the evidence pcaps and the controller's pull depend on it.
- `shortcut: the freeze budget is one shared hold across windows, upgrade if two simultaneous large freezes starve each other`.
- Known parser issues from the 2026-10-22 lab (`docs/capture.md`): `icmp.iputils_pattern` is wrong for 64-bit iputils (the pattern starts at byte 16, not 8, for a 16-byte timeval, so 56-byte pings report false); failed logins (`USER PASS QUIT`, a lone IMAP `LOGIN`) and banner-only SSH sessions have no table rule and classify `unknown` (the `scorer` fingerprint table closes them); DNS and RDP-style connects do not reach `likely_scorer`; capture loss in `lab_svc2.pcap` came from the lab's own tcpdump, not the engine.
- The org-network seed is coarse; regenerate it before the repository freeze (part 6).
- Needs from `devices`: `devices.traffic` for the source-address check.
