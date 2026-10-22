# Kali vantage point and probe library

Implements the design section "The Kali as an external vantage point" and the
active-check table in "Active checks". Two packages:

- `internal/checks`: the probe library, shared by the in-LAN `check_runner`
  and the Kali. It talks to exactly the host in the `Spec` and nothing else.
- `internal/vantage`: the Kali roles as agent `Module`s plus the
  controller-side interfaces.

## Probe library (`internal/checks`)

`Run(ctx, Spec, *Item, *Cred, Options) Result` runs one probe.
`Faithful` picks one uniformly random item and credential (the scorer's
round), `Sweep` probes every learned item in turn (the union sweep, with a
pause between probes), `AuthOnly` logs in with a given credential and asks for
no item (PCR verification). A probe's lifetime is bounded by `Options.Timeout`
(default 10 s) and every socket gets that deadline, so nothing leaks the way
the scorer's check goroutines do.

| Type | Behaviour reproduced (research/topics/quotient.md section 2) |
| --- | --- |
| http/https | `GET`, `Host: ip:port` always with the port, random browser User-Agent, `Accept-Encoding: gzip`, keep-alives off, fresh Transport, TLS verify off, no SNI for an IP, redirects followed. Status checked only if set, then regex; neither set passes on any response |
| dns | one UDP A/MX query, RD set, no EDNS, same query repeated after a deadline; only A answers are compared, so MX never passes (`ClassScorerLimit`) |
| ping | ICMP echo, 24-byte payload (8-byte timestamp + 16 tracker), seq 0, random id, 5 s; unprivileged datagram socket first, raw socket as fallback |
| tcp, rdp | bare connect (rdp has no RDP bytes) |
| ssh | banner from a 19-string OpenSSH/PuTTY/Windows list, `3des-cbc` appended to the ciphers, password auth (x/crypto sends `none` first), `pty-req xterm` 80 columns x 40 rows, ECHO off, `shell`, `<command>\n` typed, wait `Timeout/8`, read. Contains/regex on stdout; otherwise stderr must be empty (always true under a PTY). `BadAttempts` N extra full connections with a random password, own banner, default ciphers; **off by default** |
| ftp | `USER`, `PASS` (anonymous/anonymous without a credential), `FEAT`, `TYPE I`, `OPTS UTF8 ON`, `EPSV`, `RETR`, `QUIT`; regex xor SHA-256 |
| smb | own SMB2 client (dialects 2.0.2/2.1), NTLMv2 with flags `0xe2888215` (key exchange, no seal), empty domain replaced by the challenge's TargetName, tree `\\ip:445\share`, Create, Read 512 then the rest, Close, Tree Disconnect, Logoff; HMAC-SHA256 signing when the server requires it; guest/empty password without a credential |
| smtp | `EHLO localhost`, `AUTH PLAIN` over plaintext when a credential exists and AUTH is advertised (or `RequireAuth`), `MAIL FROM:<u> BODY=8BITMIME`, `RCPT TO:<another credlist user>`, `DATA` with a 16-hex subject and 64-hex body; no STARTTLS; verdict before the final `.` is acknowledged; `Encrypted` = implicit TLS |
| imap | `LOGIN`, `LIST "" "*"`, `LOGOUT`; no credential passes on connect; `Encrypted` verifies the certificate (as the scorer does) |
| pop3 | `USER`, `PASS`, `NOOP`, `STAT`, `QUIT`; fixed 3 s dial; `Encrypted` verifies the certificate |
| winrm | `POST /wsman`, unauthenticated first, then NTLM Negotiate on the same connection (empty body), then Authenticate with the body; shell create, `powershell.exe -EncodedCommand` (default `hostname`), receive, delete; bare user = empty NTLM domain; any stderr fails; stdout trimmed-equals or matches |
| ldap | hand-written BER simple bind as `user@domain` (389 cleartext, 636 TLS) |
| mssql | TDS 7.4 PRELOGIN, TLS inside TDS when the server answers ON/REQ or login-only, LOGIN7 (SQL auth), SQL batch, first column of any row equals/matches |
| splunk | Basic-auth `GET /services/server/info` on 8089; with a `Query`, REST login then `/services/search/jobs/export` compared with the expected output |

### Verdicts and strict mode

Every `Result` carries `ScorerOK` (what Quotient would conclude, blind spots
included) and, when `Options.Strict`, `StrictOK` with `StrictIssues`. `OK` is
the verdict for the mode used. `Class` separates "service unhealthy"
(`unreachable`, `timeout`, `auth`, `protocol`) from "scorer would fail on
content" (`content`) and "the scorer itself cannot pass this" (`scorer_limit`,
the MX case). Strict mode adds: web status 2xx when none is configured and
body SHA-256; DNS MX actually compared and all expected A addresses present;
FTP/SMB file regex and hash both when both are set, empty files flagged; SSH
output must contain the expected string and must not look like an error;
SMTP final `250` after DATA; IMAP `SELECT INBOX`; POP3 well-formed `STAT`;
WinRM exit code 0 and non-empty output; LDAP non-empty password; RDP an
X.224 confirm. Passwords never appear in `Err`/`Debug` (they are redacted via
`vault.RedactString`) or in events.

## Vantage modules (`internal/vantage`)

All modules satisfy `agent.Module`; wiring (roles, config, the Kali's
allowlist and credential delivery) belongs to the agent/controller config
work. **Every target must be inside the `Allowlist` of our own public
addresses; hostnames are refused and anything else is never contacted.**

| Module | Name | Events |
| --- | --- | --- |
| `CheckRunner` | `vantage.check_runner` | `vantage.check` (one per probe, fields: id, type, host, port, item, user, mode faithful/sweep, ok, scorer_ok, strict_ok, class, err, elapsed_ms, steps), `vantage.check_deferred`, `vantage.refused` |
| `VerifyService` | `vantage.verify` | `vantage.pcr_verify` (critical on failure = V4) |
| `Scanner` | `vantage.scanner` | `vantage.exposure_change` (V2: `newly_open`, `closed`, `declared_closed`), `vantage.scan` (summary + nmap-like `evidence` text) |
| `Canary` | `vantage.canary` | `vantage.canary_hit` (V3, an egress leak) |

**CheckRunner.** Gets `[]checks.Spec` (the learned item and credential
unions, in memory) from a `CheckSource`. Every `Interval` (45 s, +-10%) it
runs one faithful sample per check, and every `SweepEvery`-th pass of a check
(10) also the union sweep. Before each probe it asks the round clock
(`Gate`, satisfied by `scorer.WindowSource`) for a quiet window as long as the
probe timeout and waits for it up to `MaxDefer`; if none opens it skips the
check for that pass and emits `check_deferred`. Probe starts are `MinGap`
apart (250 ms) with at most `MaxConcurrent` (2) in flight. `Compare(external,
lan)` classifies a pair of results for V1: both green, `service_down`,
`path_broken` (external red and LAN green: Palo/NAT), `scorer_content`,
`internal_only`.

**PCR verification.** `scorer.Verifier` is implemented on the controller by
`RemoteVerifier{T: Transport}`; `Transport.Verify(VerifyRequest) -> VerifyResult`
is the signed-step carrier to the Kali (the request holds a `vault.Secret`,
which redacts itself in JSON, so the transport must serialise it explicitly).
On the Kali, `VerifyService.Handle` runs `AuthOnly` against every public
service of the account (`Targets(account)`) and succeeds only if all accept
the credential. No public service, or a non-allowlisted target, is a failure.
`LocalTransport` runs it in-process.

**Scanner.** TCP connect scan of `[TCPFrom, TCPTo]` (default 1-65535) in
random order per host, paced by a token bucket at `Rate` attempts/s (default
100) with `Concurrency` workers (32); UDP probes with protocol payloads for
DNS 53, NTP 123, SNMP 161, TFTP 69 and IKE 500 (a reply means open, ICMP
unreachable or silence does not). `DiffExposure(declared, observed, scanned)`
gives `NewlyOpen` (V2), `Missing`, `Unchanged`. An undeclared port alerts once
until it closes. A cancelled scan emits nothing, so it cannot look like closed
ports. `Report.Text()` is the evidence for the recurring perimeter-scan
injects. The scan waits for a 30 s quiet window when a `Gate` is set.

**Canary.** Listens on configured TCP and UDP ports. An agent's
`SendCanary(ctx, proto, kaliAddr, hostName, timeout)` sends
`PHYLAX-CANARY/1 host=<name> nonce=<hex>`; the listener replies `ACK <nonce>`
(so the agent knows it reached the Kali and reports leak versus blocked) and
emits `vantage.canary_hit` carrying the tagged host name (the Kali sees
translated source addresses, so the tag is the reliable identity; `Resolve` is
a fallback). Hits are deduplicated per (source, port, host) for 30 s with a
`suppressed` count, rate-limited globally (5/s, burst 20), and the connection
handlers and dedup table are bounded.

## Ambiguities resolved

- *"Item union" vs "random sample"*: `Spec.Items`/`Spec.Creds` are the learned
  unions; `Faithful` samples uniformly like `getCreds`; `Sweep` takes each
  item with a random credential (not the full item x credential product) to
  keep volume low. A credential-wide sweep is a loop over `AuthOnly`.
- *Web status "must equal the first response"*: compared with the final
  response after redirects, which is what `http.Client.Get` returns.
- *SMB dialects/signing*: only 2.0.2/2.1, no encryption or pre-auth integrity;
  signing is implemented because go-smb2 signs when required. NTLM MIC is not
  sent. A server that insists on SMB3 encryption or 3.1.1 is reported as a
  protocol failure (limitation; not what Quotient's lab runs exercised).
- *WinRM command*: the scorer's default is `hostname` run through
  `powershell.exe -EncodedCommand`; CLIXML noise on stderr would fail it as it
  would the scorer. WinRM message encryption (sealing) is not used (masterzen's
  NTLM transport does none), so a service with AllowUnencrypted=false fails here
  as it fails the scorer.
- *MSSQL*: the real scorer script is unknown; this follows go-mssqldb
  (SQL auth, optional TLS-in-TDS). Only common column types (nvarchar,
  varchar, int family, bit) are decoded; others return a protocol failure
  only when an output comparison needs them.
- *SMTP/LDAP/HTTPS TLS verification*: unspecified for the scorer, so
  verification is off; IMAP and POP3 verify, as documented.
- *Ping*: needs `net.ipv4.ping_group_range` or raw-socket privilege; without
  either the result is `ClassConfig` (not a false red).
- *Hostnames in targets*: refused, because an allowlist of public IPs cannot
  vouch for what a name resolves to.
