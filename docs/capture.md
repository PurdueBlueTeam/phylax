# Packet capture and protocol parsers

Implements the design's "Service monitoring: capture tiers, capture mechanics,
protocol parsers, pulled pcaps" (`phylax_design.md`). Code: `internal/capture`
(ring, filter, flows, reassembly, sources) and `internal/parsers/*` (one package
per protocol, plus `txn`, the shared event type).

## Data flow

```
Source (AF_PACKET TPACKET_V3 | pcap) -> Engine.Process
    decode (Ethernet, 802.1Q, IPv4, IPv6 + extension headers, TCP/UDP/ICMP; raw-IP link types too)
    -> Ring (bounded, snap-length policy)         -> freeze / pull as pcap
    -> flow table (Community ID)                  -> OnFlow(Flow) when a flow ends
    -> TCP reassembly (bounded) -> parser         -> OnTxn(txn.Txn)
    -> failed/empty connections -> scan tracker   -> OnScan(Scan)
```

`Engine` is one capture pipeline. Run one per capture thread/source. `Process`,
`Expire` and `Flush` are serialised by a mutex and callbacks run under it, so
callbacks must hand off (queue to the spool) and never call back into the engine.
Time is the packet clock, so offline replays are deterministic.

## Ring, freeze, pull

`Ring` is an in-memory circular buffer bounded by bytes (`MaxBytes`, default
256 MiB) and packets (`MaxPackets`, default 2 M). Oldest packets are evicted
first; `Stats()` reports evictions. Each packet is copied in, so sources can
reuse their buffers. The design's "2 GB or 10% of free disk, on disk" sizing is
the caller's choice of `MaxBytes`; moving the ring to a file-backed store would
not change this API.

Snap policy, applied by the engine (and by the kernel filter on Linux):

* full length on scored, decoy and sinkhole ports (`Config.ScoredPorts`, plus
  every port in `Config.Services`), on ICMP echo and on flows announced by a
  parser (FTP data channels);
* the first 128 bytes everywhere else;
* a per-flow cutoff (`Config.FlowBytes`, default 1 MiB): once a flow has stored
  that much in full, its later packets are stored at 128 bytes, so a bulk
  transfer cannot evict evidence. The flow record is marked `truncated`.

**Freeze:** `Ring.Freeze(id, from, to, ips)` pins `[from, to]` (alert minus 5
minutes to plus 10 minutes) for the listed IPs (empty means all). Packets
already in the ring are pinned; packets arriving until `to` keep being added to
the hold, so freezing never drops post-alert packets, and ring eviction cannot
lose pinned ones. Holds draw from one shared budget (`HoldBytes`); when it is
full, `Frozen(id).Full` is set and `Stats().HoldDrops` counts the loss.
Re-freezing an id extends it. **Pull:** `WriteFrozen(w, id)` or
`WriteSlice(w, from, to, ips)` writes a real pcap (pcapgo; microsecond
timestamps, original lengths preserved), readable by Wireshark, Suricata and
Zeek. `Release(id)` frees the hold.

## Sources

* **Linux:** `OpenInterface` opens `AF_PACKET`/`SOCK_RAW`, sets `TPACKET_V3`,
  maps a block ring (default 8 x 1 MiB, 60 ms block timeout), attaches the
  classic BPF program **before binding** so nothing unfiltered is ever queued,
  then binds to the interface (or all interfaces if no name is given). There is
  no promiscuous option; a host agent records its own traffic. Needs
  `CAP_NET_RAW`. Kernel-stripped 802.1Q tags are re-inserted so pcap output shows
  the wire. `Source.Stats()` reports kernel drops (read from
  `PACKET_STATISTICS`, which resets on read, so the source accumulates).
* **Filter:** `Filter{Ports, SnapScored, SnapOther, OnlyScored, Exclude}` is built
  with `x/net/bpf` (no libpcap). It returns snap lengths (full on scored ports and
  ICMP, 128 elsewhere, or 0 for everything unscored with `OnlyScored`) and drops
  `Exclude` endpoints (the agent-to-controller link) in both directions, for IPv4
  and IPv6, tagged or untagged. Limits: at most 48 ports; IPv6 extension headers
  and non-first IP fragments are treated as "other". The program is tested by
  running it in `bpf.VM` against generated frames, and in the kernel (below).
* **pcap:** `NewPCAPSource` replays a pcap (fixtures, pulled slices).
* **Windows: documented gap.** `OpenInterface` returns `ErrUnsupported`. Raw
  capture on Windows needs a driver (Npcap, not shipped) or a `SIO_RCVALL` raw
  socket, which sees IP only, may miss outbound packets and interacts with
  Windows Firewall; the design already flags this for lab proof (T26). The engine
  accepts `LinkTypeRaw` input and `Ring`, flows and parsers are platform
  independent and compile on Windows, so a `SIO_RCVALL` source is only a new
  `Source`. Until T26 settles coverage, Windows agents report flows from the
  connection table and transactions from logs.

## Flow records

`Flow` (JSON-tagged) is emitted when a flow ends (FIN/RST plus a 3 s linger,
idle timeout, eviction, or shutdown): Community ID v1 (reusing
`internal/collect/net`), endpoints (client is the SYN sender), start and end,
packets, wire bytes and payload bytes each way, handshake result
(`established`, `refused`, `timeout`, `midstream`), resets and who sent them,
end reason, SHA-256 of the first 64 payload bytes each way (a fingerprint for
protocols without a parser), the service parser, `RelatedTo` (control flow that
announced this one), and flags `Scan`, `Truncated`. UDP and ICMP echo flows are
tracked too (ICMP Community IDs use the request type pairing).

Bounds: `MaxFlows` (default 65 536, least recently active evicted), idle
timeouts (TCP 60 s, UDP 30 s, ICMP 10 s), at most 256 pending data-channel
expectations, at most 1 024 scan sources with 4 096 targets each.

**Scans** are aggregated: a source that causes at least `ScanThreshold` (20)
refused, unanswered or payload-less connections to distinct address:port pairs
within `ScanWindow` yields one `Scan` event when the threshold is crossed and a
final one when the window closes. Those flows are flagged and no longer produce
individual `tcp` transactions.

## Reassembly

Per direction, in `reasm.go`: handles reordering, overlap, retransmission,
sequence wraparound and mid-stream pickup. Bounds per direction: 64 parked
segments, 128 KiB parked bytes, 4 MiB delivered. Exceeding the first two
declares a gap and ends the parser (which flushes what it has), because
parsing across a hole would mis-frame; exceeding the third caps the stream.
Both are counted (`ReasmGaps`, `ReasmCapped`). A segment cut by the snap length
on a service port is treated as a gap. Parsers only see in-order bytes.

Parsers run for ports in `Config.Services` (`DefaultServices`: 21 ftp, 22 ssh,
25/587 smtp, 53 dns, 80/8000/8080 http, 110 pop3, 143 imap, 443/465/993/995/
8089/8443/5986 tls, 445 smb, 5985 winrm, 1433 tds); a scored port with no
mapping is sniffed from the first bytes (HTTP, TLS, SSH, SMB, TDS from the
client; SSH, POP3, IMAP, SMTP, FTP banners from the server). A parser panic is
recovered per flow, counted in `ParserPanics`, and only silences that flow.

## Transactions and what the scorer classifier reads

Every parser emits `txn.Txn`: `Proto` (the `scorer.Features.Proto` vocabulary),
`Type`, endpoints, Community ID, times, `Attr`/`List` (the scorer's feature
keys plus extras), an optional `Cred`, and `Secret` naming credential-derived
fields. `Txn.Features()` yields a `scorer.Features`; the caller adds
`InBurst`, `OneShot`, `LearnedCred`, `AdvisoryRunner`.

**Credentials:** no password is ever stored. `Cred.PassHash` is the first 16
hex digits of SHA-256(`"phylax-cred-v1\0"` + password) so a learned credential
can be recognised; `Secret` marks it for field-level encryption. A hash of a
weak password can be guessed offline, hence the marker. NTLM carries user and
domain only (no response bytes are read). SQL batch text is clipped to 256
bytes. SMTP bodies are stored only when at most 128 bytes (the scorer's is 64
hex digits); longer ones keep length and hash.

| Package | Proto / Type | Features emitted |
| --- | --- | --- |
| `http` | `http` exchange (request + response) | `http.method http.path http.host http.ua http.version http.status http.content_type http.req/resp_body_len http.req/resp_body_sha256`; list `http.headers` (names, wire order) |
| `tls` | `tls` handshake | `tls.ja3 tls.ja3_string tls.ja4 tls.sni tls.hello_len tls.version tls.sh_version tls.sh_cipher tls.sh_alpn`; list `tls.alpn` (present even when empty); cert hash/subject/issuer for TLS 1.2 and earlier only |
| `ssh` | `ssh` session | `ssh.banner ssh.server_banner ssh.hassh ssh.hassh_server ssh.hassh_string ssh.dwell_ms ssh.encrypted` |
| `ftp` | `ftp` session | list `ftp.cmds ftp.files ftp.data_channels`; `ftp.auth_ok`; data channels announced to the engine via `Meta.Expect` |
| `smtp` | `smtp` session | list `smtp.cmds smtp.rcpts`; `smtp.ehlo_arg smtp.mail_ext smtp.subject smtp.body smtp.body_sha256 smtp.auth_ok smtp.delivered` |
| `imap` | `imap` session | list `imap.cmds`; `imap.tag imap.auth_ok imap.auth_mech` |
| `pop3` | `pop3` session | list `pop3.cmds`; `pop3.auth_ok pop3.retrieved` |
| `dns` | `dns` query / response (UDP, TCP) | `dns.id dns.qname dns.qtype dns.rd dns.edns dns.udp_size dns.rcode`; list `dns.answers` |
| `smb2` | `smb` session | `smb.dialect smb.ntlm_flags smb.user smb.domain smb.workstation smb.domain_is_server smb.tree smb.auth_ok smb.read_bytes`; lists `smb.dialects smb.trees smb.files` |
| `winrm` | `winrm` exchange | `winrm.method winrm.path winrm.ua winrm.first_no_auth winrm.ntlm_type winrm.ntlm_flags winrm.status`; `Cred` from NTLM type 3 |
| `tds` | `mssql` session | `tds.client/server_version tds.client/server_encryption tds.instance tds.tls tds.user tds.host tds.app tds.server tds.library tds.database tds.login_ok`; list `tds.queries` |
| `icmp` | `icmp` echo_request / echo_reply | `icmp.id icmp.seq icmp.payload_len icmp.payload_sha256 icmp.iputils_pattern` |
| `tcp` | `tcp` / `rdp` connect | `tcp.zero_payload tcp.hold_ms tcp.result tcp.keepalives tcp.reset_by`; emitted for empty connections, refusals and timeouts only |

Shared helpers: `ntlm` (NTLMSSP types 1-3 from SPNEGO blobs and HTTP headers),
`internal/httpwire` (bounded streaming HTTP/1.x reader), `internal/lines`
(bounded line splitter), `txn`, and `parsertest` (test driver).

### What passive capture cannot see

* **SSH:** everything after NEWKEYS. `ssh.auth`, `ssh.pty` and
  `ssh.fail_then_accept` (scorer rules `ssh.auth_none_password`, `ssh.pty`,
  `ssh.fail_then_accept`) must come from sshd logs; the parser supplies banner,
  both KEXINITs, HASSH and dwell. `ssh.dwell_ms` is first-to-last data time of
  the connection.
* **TLS 1.3:** certificates and ALPN selection are encrypted; JA3/JA4, SNI, offered
  ALPN and the server's chosen version and cipher are not.
* **TDS with encryption negotiated:** Login7 travels inside TLS, so the session
  reports `tds.tls=true` and the pre-login fields only.
* **SMB 3 encryption** (transform header) stops parsing; signing does not.
* **SMTP/IMAP/POP3/FTP after STARTTLS/STLS/AUTH TLS** stop parsing and set `*.tls`.
* Compressed HTTP bodies are hashed as sent. HTTP/2 is not parsed.
* DNS responses are not paired with queries by the parser; correlate on
  `dns.id` and Community ID.

## Tests

* `go test -race ./internal/capture/... ./internal/parsers/...`: generated
  fixtures (`internal/capture/fixture` builds Ethernet/VLAN/raw-IP, IPv4/IPv6
  TCP sessions with chosen segmentation, reordering, loss, keepalives, teardown;
  also NTLM, SMB2, TDS, DNS and SSH wire builders), driven through
  `NewPCAPSource` and `Run`. Parsers are also run byte-by-byte to prove
  segmentation independence. Ring bounds, freeze semantics, reassembly orderings
  and the BPF program (in `bpf.VM`) have their own tests.
* **Recorded values.** `tls`: the ClientHello of the real `crypto/tls` client of
  Go 1.25.3 (`internal/parsers/tls/testdata`, produced with that toolchain, empty
  ServerName, `InsecureSkipVerify`) parses to exactly `quotient.md` section 6's JA3
  `006598cf32b8feecd39e4337bdba9c44` and JA4
  `t13i131000_f57a46bbacb6_ab7e3b40a677`. The Go 1.27 toolchain building this repo
  produces the same JA4 a- and b-parts but a different c-part (it adds hybrid key
  groups), so the table must be re-learned per event, as the scorer already says.
  `ssh`: HASSH is `a7230c16ea72e6ff36f15892c8d4d569` for the recorded KEXINIT lists
  with `3des-cbc` appended to the ciphers (the real login) and
  `0a07365cc01fa9fc82608ba4019af499` without it (BadAttempts); both are rebuilt
  byte-exactly from the lists in `quotient.md` and asserted. The x/crypto version in
  `go.mod` is newer than Quotient's v0.33.0 and adds a leading `mlkem768x25519-sha256`
  kex, so its live HASSH differs; the test asserts that everything after that prefix
  equals the recorded lists. **Not reconstructable offline:** the exact bytes of the
  SMB, WinRM, SMTP, IMAP, POP3, FTP, DNS and ICMP exchanges (the fixtures follow
  the described command sequences and field values, and the scorer's table
  matches them, but only the lab pcaps in `/tmp/qlab/final/` prove them), and the
  HTTP User-Agent (random, deliberately not a rule).
* **Fuzzing, 10 s each:** `go test -run '^$' -fuzz '^FuzzHTTP$' -fuzztime 10s ./internal/parsers/http`
  (and `FuzzWinRM FuzzSSH FuzzTLS FuzzFTP FuzzSMTP FuzzIMAP FuzzPOP3 FuzzDNS
  FuzzDNSDatagram FuzzSMB2 FuzzTDS FuzzNTLM FuzzICMP`; capture has `FuzzReassembly`
  and `FuzzProcess`, which drives arbitrary frames through the whole engine). Seed
  corpora run in every plain `go test`.
* **Real AF_PACKET (Docker only).** `TestAFPacketTPACKETV3OnContainerLoopback`
  opens TPACKET_V3 on a container's own `lo`, with a test-owned HTTP server and UDP
  noise, and checks the transaction, the flow, the ring, the pcap export and that
  the kernel filter kept the unscored datagrams out. It skips unless
  `PHYLAX_CAPTURE_DOCKER=1` **and** `/.dockerenv` exists; nothing else in the suite
  touches a real interface.

  ```
  CGO_ENABLED=0 go test -c -o /tmp/capture.test ./internal/capture
  docker run --rm --cap-add NET_RAW -e PHYLAX_CAPTURE_DOCKER=1 \
    -v /tmp/capture.test:/capture.test:ro alpine:3 /capture.test -test.run AFPacket -test.v
  ```

## The agent module

`internal/capture/module.go` (registered by `internal/agent/mods/capture.go`) is the
agent's `capture` module. The signed `AgentConfig` decides **whether** it runs (the
host has the `capture` role; Linux only, Windows reports it unavailable) and **which
ports are scored** (every port in the net module's service map, decoys included).
Local knobs live in an optional `capture.json` in the agent state directory, because
`plan.AgentConfig` has no capture section yet (adding one is a `plan` change):

```
{"interface": "eth0",              // default: all interfaces
 "exclude": ["10.0.0.5:8443"],     // the controller link: never captured
 "local_addrs": ["10.0.0.10"],     // default: the interface's addresses
 "ring_mb": 256, "hold_mb": 256,   // ring and freeze budgets
 "disk_budget_mb": 512,            // pcaps under <state>/capture
 "freeze_before_sec": 300, "freeze_after_sec": 600,
 "scan_threshold": 20, "scan_window_sec": 10, "scored_ports": [8080]}
```

It opens AF_PACKET with the scored-port BPF (everything else at 128 bytes, so SYN
scans of unscored ports are still seen), runs the engine, and publishes through the
agent's emit (rate limited, then the spool). The engine callbacks run under its lock,
so they only convert and queue (4096 events); a full queue sheds and counts. Per-class
token buckets bound the rates (net.txn 300/s, net.flow 300/s, net.scan 20/s) on top of
the supervisor's 600/s budget; `capture.stats` (every 60 s) reports packets, kernel
drops, ring occupancy and every drop counter. A finite source (tests) ends without
stopping the module, so freezes still work.

| Event | Priority | Fields |
| --- | --- | --- |
| `http_request` | normal | as `HTTPEvents` (method, host, uri, ua, status, src/dst ip and port, community_id, dst_org, dst_cloud) |
| `net.txn` | normal | `proto type src_ip src_port dst_ip dst_port community_id ok duration_ms`, `attr` and `list` (the scorer feature keys, values clipped to 512 bytes, 64 items), `cred {user domain mech}`, `sealed`, `secrets_dropped` |
| `net.flow` | bulk | one per ended flow including SYN-only (`handshake: timeout`) and refused ones: `community_id proto src_* dst_* start end pkts/bytes/payload each way handshake end_reason service scan truncated`, and when the host's addresses are known `dir raddr laddr lport rport` (the names the network rules use) |
| `net.scan` | high | `src_ip start end targets hosts final` |
| `capture.evidence` | high | see below |
| `capture.stats` | normal | counters |

**Secrets.** Parsers list credential-derived fields in `Txn.Secret`; the module never
puts them in an event in the clear. With a 32-byte hex key in `<state>/capture.seal`
they are sealed with AES-256-GCM (`enc1:` + base64) under `sealed`; without it they are
dropped and named in `secrets_dropped`. `Cred.PassHash` is always treated as secret,
whether a parser listed it or not, and attribute keys that look like passwords are
dropped. Tests prove the password and its hash are in neither the events nor the spool
files.

## Freeze on alert

The module subscribes to the agent's event stream. A `detect.alert` for this host whose
rule collects `freeze_ring` freezes the ring for **alert minus 5 min to plus 10 min**
for the remote addresses the alert involves (entities and evidence fields; loopback and
the host's own addresses never filter, because every packet involves them; no remote
address means all traffic). The hold id is a hash of the rule and addresses, so a repeat
extends the same window rather than starting another; at most 8 windows are open at once
(the rest are counted as skipped). Two `capture.evidence` events follow: one at once
(what the ring held), one when the window closes (`final: true`), same file replaced
atomically. Fields: `id rule alert_time from to ips path bytes packets sha256 final`,
plus `truncated` (hold budget hit), `evicted` and `error`. The IR drafter attaches
`path` (on the agent, `<state>/capture/<id>.pcap`; a Wireshark-readable pcap) or fetches
it by id. **Disk budget:** pcaps under `<state>/capture` total at most `disk_budget_mb`
(default 512). A capture bigger than the whole budget is refused (evidence carries the
error); otherwise the oldest other pcaps are deleted to make room. The agent does not
yet serve the controller `fetch` message for these files (see gaps).

## Controller wiring

* **Controller-scope rules.** `internal/controller/capture_ingest.go` runs the rules whose
  `scope` is `controller` (P88 D13e, D18b) over the stored events of all agents.
  `net.flow` events with a direction are translated to `net.connection_opened`
  (`dir raddr laddr lport`), the agents' own `net.connection_opened` are fed as is, and
  alerts go to the operator queue with the flow events as evidence. Only events at or
  below the ingest ack are fed, so a re-sent batch is never counted twice. The engine
  is rebuilt, and re-seeded, when the config inputs change. Alerts are alert-only.
* **`reference.scorer_sources`** is seeded (`seed_sources.go`) from the manifest: hosts with the
  `scanner` or `canary` role (the Kali), their public address and their segment's
  translated source (device `external_ip`), and the controller host (team console). The
  scorer itself is recognised by behaviour, so its addresses are not guessed:
  `Controller.NoteScorerSource(addr)` adds an address that scorer discovery or the
  operator confirmed (bounded at 256, in memory, survives rule reloads, not a restart).
  Agents' own detection configs do not carry this seed yet (`genconfig.go` is another
  task's file; `ManifestScorerSources` is ready to be added to `detectSeeds`).
* The controller does not yet act on `collect: [freeze_ring]` of a controller-scope
  alert (sending `freeze_capture` controls to the agents that saw the flows).

## Updating the network lists (Microsoft and cloud CIDRs)

`internal/capture/orgnets.json` is embedded in the agent (offline) and labels `http_request`
destinations (`dst_org`, `dst_cloud`) for P82. It ships as a **bootstrap seed** of coarse
prefixes; regenerate it before the event on a connected machine and commit the result:

```
# download: Azure "Service Tags - Public" JSON (Microsoft Download Center, weekly),
#   https://endpoints.office.com/endpoints/worldwide?clientrequestid=<uuid>  (-m365),
#   https://ip-ranges.amazonaws.com/ip-ranges.json                          (-aws),
#   plus any provider lists you want as one CIDR per line
go run ./internal/capture/cmd/orgnetgen -azure ServiceTags_Public_*.json -m365 m365.json \
   -aws ip-ranges.json -list digitalocean=cloud:do.txt > internal/capture/orgnets.json
go test ./internal/capture/...
```

`microsoft` is `dst_org` only (not cloud); `cloud: true` orgs set `dst_cloud`. A host can
override the list with `<state>/orgnets.json` (same format; an invalid file fails the
module build rather than silently using the seed). The file is capped at 60 000 prefixes.

## Lab Quotient pcaps (run 2026-10-22)

`internal/capture/lab_test.go` runs `/tmp/qlab/final/lab_{svc1,svc2,web1b,db}.pcap`
(`PHYLAX_QLAB` overrides the directory; skipped when absent) through `NewPCAPSource`
and asserts each parser against the scorer's checks. The lab is two teams, 84 rounds
(delay 20 s) of a real Quotient, five runner source addresses (172.28.77.132-136), no
NAT between runners and boxes, so the **source-address check at drop passes in the lab**
(real client addresses, never a firewall's); the Palo question stays open for the event.

Result: no decode errors, parser panics, reassembly gaps or caps in any file.

| Check | Parser result | Scorer classifier (successful sessions) |
| --- | --- | --- |
| smtp | EHLO localhost, AUTH PLAIN, `BODY=8BITMIME`, 16-char subject, 64-hex body, delivered; 84 per team | scorer, 84/84 (svc2: 82 scorer, 2 likely) |
| imap | LOGIN LIST LOGOUT, 6-char tag | likely_scorer |
| pop3 | USER PASS NOOP STAT QUIT | likely_scorer |
| ftp | USER PASS FEAT TYPE OPTS EPSV RETR QUIT, `RETR readme.txt`, passive data channel followed (81 `ftp-data(passive)` flows) | likely_scorer |
| smb | dialects 0x0311..0x0202, NTLM flags `0xe2888215`, domain_is_server, tree `\\ip\shared`, file `important.txt` | scorer, 79-84 per team |
| winrm | POST `/wsman`, `Go-http-client/1.1`, first request without auth (401), two exchanges per round | likely_scorer |
| dns | A (and MX) queries, `rd` set, no EDNS, answers listed; responses unpaired as documented | unknown (no DNS rule scores above 0.28) |
| icmp | the scorer's ping: 24-byte payload, seq 0, one per round | likely_scorer (0.53) |
| ssh | both HASSHes (`0a07365c...` BadAttempts, `a7230c16...` the real login), encrypted, dwell | scorer (0.90 on HASSH) |
| tls (web1b) | JA4 `t13i131000_f57a46bbacb6_ab7e3b40a677`, JA3 `006598cf32b8feecd39e4337bdba9c44`, no SNI, empty ALPN list: **the recorded values reproduce on the real scorer's traffic** | scorer, 0.99 |
| http (web1b) | GET, HTTP/1.1, header order `Host User-Agent Accept-Encoding Connection`, Host carries `:80` | likely_scorer (0.74) |
| db (MySQL) | no parser; 168 established TCP flows and 13 unanswered SYN flows still become `net.flow` | n/a |

Credential hashes: every `PassHash` of a successful smtp/ftp/imap/pop3 login equals
`HashSecret("LabPass-<user>-<n>")` (322 of 325 in svc1; the other 3 are logins during
PCR windows with the new password).

**Findings from the real traffic (not fixed here, outside this task's files):**

1. **`icmp.iputils_pattern` is wrong for 64-bit iputils.** Real Linux ping sends a
   16-byte `struct timeval` and then `0x10 0x11 ...`; the parser (`internal/parsers/icmp`)
   starts the pattern at byte 8, so all 56-byte pings (168 per file, the lab harness's own
   pings) report `false`. Fix: accept the pattern at offset 16 (64-bit) as well as 8.
2. **Failed logins have no fingerprint.** After a wrong password the scorer sends
   `USER PASS QUIT` (ftp, pop3) or just `LOGIN` (imap); `ftp.cmds`/`pop3.cmds`/`imap.cmds`
   rules only know the success sequences, so those sessions classify `unknown` (2-4 per
   file, during PCR windows). A scorer table rule for the failed shape would close it.
3. **Banner-only SSH.** The `tcp22` check and the custom `pyprobe` each open port 22,
   read the banner and close: 2 per round, reported as `ssh/session` with no client banner,
   `ssh.encrypted=false`, and classify `unknown`. A rule on "no client banner, no KEXINIT"
   would label them.
4. **DNS, RDP-style connects and the custom checks** have no table rule that reaches
   `likely_scorer` (DNS 0.28, rdp 0.37); they are only separable by burst/port/account.
5. **Capture loss in the lab file.** In `lab_svc2.pcap` at +248.27 s a burst overran the
   lab's tcpdump: clients ACK server data that is not in the file, cutting 6 in-flight
   smtp/ftp/pop3 sessions short. The engine flushes them without error; the test tolerates
   up to 6. Real AF_PACKET reports kernel drops in `capture.stats`.

## Tests added with the module

* `module_test.go`: lifecycle over a PCAP source (http_request, net.txn with feature
  lists, SYN-only inbound flows, net.scan), secrets (dropped, sealed and opened with the
  key, absent from the spool's files), freeze-on-alert (valid pcap, within budget, the
  involved addresses only, hold released, alerts without `freeze_ring` or for another
  host ignored), disk budget (refusal, eviction of the oldest), rate limits.
* `internal/controller/capture_test.go`: a rotating-source SYN scan through the capture
  module, the agent spool, the real link and controller ingest raises P88 in the operator
  queue; the Kali's own address and a learned scorer source do not; unstored events and
  direction-less flows are not counted.
* `orgnets_test.go`, `cmd/orgnetgen`, `internal/agent/mods/capture_test.go`.

## Needs a real capture run

* AF_PACKET on a real NIC under load: drop counts, block sizing, VLAN-tagged and bonded
  interfaces, and CPU against the 3% budget (the module has only been run on pcaps and
  in the Docker loopback test); promiscuous mode is intentionally absent.
* Windows raw-socket coverage (T26) and a Windows `Source`; the manifest gives Windows
  hosts the `capture` role, so their config reports `degraded` until then.
* Ring sizing against free disk, and whether a file-backed ring is needed.
* `capture.json` should become a signed `AgentConfig` section; the agent should answer
  the controller's `fetch` (pcap) and `freeze_capture` control for these files; the
  controller should send `freeze_capture` for controller-scope alerts.
* The seal key has no distribution mechanism yet (a file in the state directory).
* The Palo's inbound NAT behaviour (does the scorer's source survive).
