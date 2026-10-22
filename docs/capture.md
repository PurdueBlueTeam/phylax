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

## Needs a real capture run

* The lab Quotient pcaps through `NewPCAPSource`: confirm each parser's features
  against the real scorer (SMB, WinRM, mail, FTP, DNS, ICMP shapes), and the
  source-address check at drop.
* AF_PACKET on a real NIC under load: drop counts, block sizing, VLAN-tagged
  and bonded interfaces, and CPU against the 3% budget; promiscuous mode is
  intentionally absent, so only traffic to and from the host is seen.
* Windows raw-socket coverage (T26) and a Windows `Source`.
* Ring sizing against free disk, and whether a file-backed ring is needed.
* Controller integration: wiring `OnTxn`/`OnFlow`/`OnScan` to the spool, the
  freeze-on-alert trigger, and field encryption of `Secret` fields.
