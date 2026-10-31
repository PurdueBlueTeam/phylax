#### `logs`

##### 1. Purpose and evidence

`logs` reads application and operating-system log files on Linux and turns them into events: authentication results (`auth_event`) from sshd, Cockpit, the mail and FTP servers and web admin logins, request detail from web access logs, and selected kernel log lines. It is the only source of authentication facts on Linux. On Windows the same facts come from `winevt` (Security 4624 and 4625), so rules and the controller see one `auth_event` kind on both.

Why it matters for points:

- Scorer-account learning needs to know which account logged in to which service, from what source, with which result. Quotient is not reachable from inside the environment, so observed logins are the primary source of the scored-account list (review D251, area 7 revision; `scorer`). `logs` supplies the Linux half.
- Chains build an `access` hop from each successful login with a source address (`chains`), and trace-back follows the inbound connection to the source.
- Brute-force (D9e), default-credential logon (D18), credential fan-out (D18b) and web-admin brute-force (D17e) are written against `auth_event` and access-log lines. The scorer's deliberate failed logins (`BadAttempts`) have to be told apart by behaviour, which needs the individual results with timestamps, not a count [Q §9.6].
- HTTPS cannot be read from packets. For HTTPS services request detail comes from the server's own access logs (custom formats set by hardening) and response content from active checks. The scorer's Go TLS ClientHello is distinctive but handshake metadata alone says nothing about the request.

Decision: review D73, kept (auth events feed scorer-account confirmation and chains). Evidence that it is needed now: the log-line rules in `rules/logs.yml` are inert until a producer exists, and `rules/pending/needs_producer.yml` parks D17e (needs `log_line.source` from an access-log parser).

Evidence against and the limit it implies: a log tailer is only as good as the log. Debian 12 installs without rsyslog and writes no `/var/log/auth.log`; applications such as OpenCart do not log logins at all. The module reports a coverage gap per missing log instead of pretending (Health). Wazuh (`wazuh`) also tails logs, but it is optional and not on the critical path.

##### 2. Status and code

Status: missing. The consumers exist.

- Consumers: `rules/auth.yml` (D18, D18b, D9e and others; keyed on `auth_success` and `auth_fail`), `rules/logs.yml` (D2e, D19, D23, keyed on `log_line` with `file`, `line`), `rules/pending/needs_producer.yml` (D17e, D14d, D14b), `internal/traceback/obs.go` (reads `account`, `source`, `source_port`, `method`, `service`), `internal/scorer` and `internal/chains`.
- No Linux tailer, no parser content, no `plan.LogsSettings`, no factory.
- The Windows channels (Security, System, PowerShell, Defender, Task Scheduler, WMI-Activity) are `winevt`'s. The Windows Firewall operational log, the DNS Server analytical log and the Netlogon log tail that v3 listed under `logs` are not covered by either module yet (see Limits).

##### 3. Capability manifest

```go
module.Manifest{
	Name:      "logs",
	Sides:     []module.Side{module.SideAgent},
	OS:        []string{"linux"},
	Privilege: "root", // log files are mode 0640 root:adm or root:root
	Roles:     nil,
	Consumes:  nil,
	Emits: []event.Type{ /* auth_event v1, logs.line v1, telemetry_gap v1 */ },
	Budget: module.Budget{
		CPUMillisPerSec: 30, HeldMB: 8, EventsPerSec: 300, Burst: 600,
		BytesOutPerMin: 4 << 20, DiskMB: 1,
	},
	Default:  true, // core-default
	Tables:   nil,
	Content:  []string{"logs/parsers"}, // regex parsers with inline tests
	Actions:  nil,
	Pages:    nil,
	Evidence: []string{"review D73", "review D251", "[Q §9.6]"},
}
```

Numbers are initial limits. Access logs are the volume risk; the rate limit and bulk priority bound it. `shortcut: budget numbers are estimates, replace with Invitational measurements (R7, O3 in docs/impl/invitational-data.md)`.

##### 4. Configuration

`modules/logs.yml` becomes `modules.logs`. The controller renders `files` per host from `services.yml` (each service kind knows its default log paths) and the host's OS family (`/var/log/auth.log` on Debian and Ubuntu, `/var/log/secure` on Rocky), so the manifest does not list paths by hand unless a path differs. A nil block disables the module.

```yaml
rate_per_sec: 300
burst: 600
files:
  - { path: /var/log/auth.log,           parser: sshd,    service: sshd }
  - { path: /var/log/secure,             parser: sshd,    service: sshd }
  - { path: /var/log/mail.log,           parser: dovecot, service: dovecot }
  - { path: /var/log/vsftpd.log,         parser: vsftpd,  service: vsftpd }
  - { path: /var/log/apache2/access.log, parser: access,  service: http, lines: true }
  - { path: /var/log/kern.log,           parser: raw,     lines: true }
```

```go
// package plan (new; ModuleSettings gains `Logs *LogsSettings`)
type LogFile struct {
	Path    string `json:"path"`
	Parser  string `json:"parser"`            // name of a parser in logs/parsers
	Service string `json:"service,omitempty"` // value of the auth_event service field
	Lines   bool   `json:"lines,omitempty"`   // also emit logs.line for every line
}
type LogsSettings struct {
	ModuleLimits
	Files []LogFile `json:"files"`
}
```

Parsers are content: `logs/parsers/*.yml`, one file per parser, each with an ordered list of RE2 patterns with named groups, the event they produce, the result and the field mapping, and inline tests (sample line to expected event), under the same CI as rules. A new log format is a new YAML file, not Go. RE2 matches in linear time, so a hostile log line cannot cost more than its length.

Fixed internals: poll every 1 s for new data, rotation and truncation; lines longer than 8 KiB are cut and flagged; offsets saved at most once a second; on the first start of a file the offset is the end of the file (history is not replayed).

##### 5. Events

Consumed: none.

Emitted:

| Kind | Priority | Key fields |
| --- | --- | --- |
| `auth_event` (common) | high | `result` (`success` or `fail`), `account`, `source` (client address; empty if the log has none), `source_port`, `method` (`password`, `publickey`, `keyboard-interactive`, `PLAIN`, `LOGIN`, and so on), `service` (`sshd`, `dovecot`, `vsftpd`, `proftpd`, `cockpit`, `postfix-sasl`, or the web admin service name), `invalid_user` (true when the log says the account does not exist), `file`, `parser`. No password and no password hash ever |
| `logs.line` | bulk | `file`, `line` (as read, newline removed), `source` (parsed client address where the parser extracts one), and for access logs parsed `method`, `uri`, `status`, `ua`, `host`, `bytes`. Alias `log_line` for one release |
| `telemetry_gap` (common) | high | `source: logs`, `reason` (`rate_limited`, `file_unreadable`, `file_missing`, `rotated_tail_lost`, `line_too_long`, `offsets_corrupt`), `file`, `count` |

`auth_event` replaces the code-side names `auth_success` and `auth_fail` that `winevt`, `rules/auth.yml` and `internal/traceback/obs.go` use today; the controller accepts the old names as aliases for one release, and rules match either with `result`. `service` is the key the `scorer` uses to map accounts to services, so the service names are those of `rules/auth.yml` (`sshd, dovecot, vsftpd, proftpd, cockpit, postfix-sasl, windows`).

##### 6. Behaviour

**Tailing.** Each configured file is opened read-only and read from the saved offset. Every second the module stats the path: new bytes are read to the end of the last complete line (a partial line waits for its newline); a changed inode (rotation) makes the module finish the old descriptor to EOF and then open the new file from offset 0; a size smaller than the offset (copytruncate) restarts from 0 and emits a `rotated_tail_lost` gap if unread bytes could have been lost. A missing file is retried every second and reported once as `file_missing`; it appears in Health until it exists. An unreadable file (permission, SELinux) is a `file_unreadable` gap and a Health gap. Polling is chosen over inotify because it needs no kernel feature, behaves the same on every filesystem and costs a stat per file per second.

**Offsets.** Saved in `StateDir/logs/offsets.json` as `{path, inode, offset}`, written atomically (`internal/atomicfile`), at most once a second and after each batch. After a restart reading resumes at the offset, so lines written while the agent was down are read. A corrupt offsets file is moved aside, every file restarts at its end, and an `offsets_corrupt` gap says that lines may have been missed.

**Parsing.** A line goes through its file's parser: patterns are tried in order, the first that matches produces the event (or none, for lines the parser deliberately ignores). Lines no pattern matches are counted per file as `unparsed`; the count is reported in Health. With `lines: true` the raw line is also emitted as `logs.line`. Defaults by parser (patterns are written from recorded lines of the lab images, with inline tests; the shapes below are the target):

- *sshd* (`auth.log`, `secure`): `Accepted <method> for <user> from <ip> port <p>` is success; `Failed <method> for [invalid user ]<user> from <ip> port <p>` and `Invalid user <user> from <ip>` are failures; pre-auth disconnects are ignored (they are not a result).
- *dovecot* (IMAP, POP3): the login line with `user=<…>`, `method=…`, `rip=<client>` is success; `auth failed` lines with the same fields are failures.
- *vsftpd* and *proftpd*: `OK LOGIN` and `FAIL LOGIN` lines with the client.
- *cockpit*: the web login and PAM result lines (Cockpit's own log format and its PAM messages vary by version; the pattern set is fixed from the lab image).
- *postfix* SASL: `sasl_username=` on accepted submissions and `authentication failed` lines.
- *web admin logins*: where the application logs a login, the parser reads it; where it does not (OpenCart logs none), the access log is used: a `POST` to the configured login URL regex with a configured success status (a redirect) or failure status (the form page again). The URL regex and the two status codes are part of the service kind's default in the parser file. `shortcut: web admin login result inferred from the HTTP status of the login POST, validate per application in the lab and replace with the application's own log if one exists`. The brute-force rule D17e needs the POST count per source only, which the access log gives without any inference.
- *access* (Apache, nginx; combined or the custom format set by hardening): parsed into `source`, `method`, `uri`, `status`, `ua`, `host`, `bytes`. The hardening pack sets a log format that includes the host and the real client address (behind no proxy on this LAN, the remote address).
- *raw*: no parsing; with `lines: true` it emits the line. Used for `kern.log`, `messages` and `syslog` (promiscuous mode D19, USB attach D23).

**Scorer logins.** The scorer sends failed logins on purpose (`BadAttempts`) and a successful one in the same round. `logs` makes no exemption: it reports every result with its timestamp and source. The exemption lives in `detect` rules (N failures then a success from one source within about 100 ms) and by behaviour in `scorer`, never by address, because Divisor re-draws the scorer's sources every round [Q §6, Q §9.6]. Timestamps matter for that: the parsers use the log line's own time with year and zone resolution (syslog lines carry no year; the module assumes the current year and corrects at year boundary and fails over to the host clock for an unparsable time) and set `Event.Time`; sub-second resolution exists only where the application logs it, so the rule's 100 ms window can be too tight on sshd logs with one-second stamps. The Invitational question S10 (does the scorer send bad credentials, how often, with which user) settles this; keep the window a rule parameter.

**Feedback loops.** The module never reads its own log or state directory. Lines produced by the agent itself (it logs to the journal, not to these files) are not excluded further.

**Plan tagging.** `auth_event`s from our own activity (the controller's WinRM or SSH logins for plans, our scorer-mimic probe logins) carry no tag because the log line cannot carry one. They are told apart in `detect` by the known controller and probe sources, and by the plan window tag at the controller (a login event inside a plan node's window from the controller's address is ours). Probe logins from the Kali look like scorer logins by design.

##### 7. Actions and content

Actions: none. The log format change on web servers is a `hardening` pack node (`service.config` with the `validate` hook).

Content: `logs/parsers/*.yml` (sshd, dovecot, vsftpd, proftpd, cockpit, postfix, access, raw) and the rules that consume the events in `rules/auth.yml` and `rules/logs.yml`. The Falco-style exceptions in those rules take their lists from the manifest.

##### 8. UI

No page of its own. The Platform page shows the module state, per-file state (read position lag, `unparsed` count) and gaps. The Credentials page (`creds`/`scorer`) shows learned scorer accounts built from these events; that is not this module's page.

##### 9. Health

Implements `agent.HealthReporter`. States:

- `ok`: every configured file is open and parsers are matching.
- `degraded`: any file missing or unreadable, a rotation lost lines, rate limiting is active, or an auth file has had lines but no parsed result for 10 minutes.
- `unavailable`: not Linux.

Gaps: `no auth log: sshd logs only to journald on this host (install rsyslog from the depot or add a journal reader)`, `<file> unreadable: <err>`, `<file> missing`, `<file> unparsed lines: N of M`, `rate limited: N lines dropped`. These are exactly the coverage losses the Platform page should show; the sshd-without-a-file case is likely on Debian 12.

##### 10. Scoring safety

Read-only: opens files for reading and writes only its own offsets file under `StateDir`. It adds no listener, no process and no change to a service. It does not touch scored state. The risk is indirect: the web-server log format change that gives it request detail is made by `hardening` through `service.config`, which carries the scoring lint, the `validate` hook (`apachectl -t`, `nginx -t`) and the dead-man; a bad `LogFormat` can stop a web server from starting, which is exactly what the hook prevents. Reading a log from a scored host adds negligible I/O. Alert-only: all telemetry.

##### 11. Tests

To build: fixture tests per parser (recorded lines from the lab images, success, failure, invalid user, ignored lines; the inline tests in the YAML), tail tests (append, partial line, rotation by rename, copytruncate, missing file appears later, unreadable file, offsets resume after restart, corrupt offsets file, line cap), rate-limit gap, year resolution for syslog timestamps, rule tests that run `rules/auth.yml` and `rules/logs.yml` over parser output (the existing inert tests then run against real parser output), and the alias test for `log_line`, `auth_success` and `auth_fail`.

Conformance: starts with no config (disabled), starts with a default config on a fixture host (fixture log files), stops within 5 s, emits only declared kinds, survives link loss (emit errors are counted, offsets still advance), survives reconfiguration (a new file list replaces the module; offsets live on disk, so `Keep` is not needed), `go test -race`.

Lab tests: T37 scorer failed logins do not trip D9e (v3 id, to be renumbered), the purple-team false-positive run T36, and the Invitational questions S5 (which accounts the scorer logs in as, per service), S6 (NTLM or Kerberos on Windows), S10, E9 (which logs exist on each host).

##### 12. Limits and open items

- `shortcut: log files only, no journald reader; hosts whose sshd logs only to the journal need rsyslog installed from the depot (pkg.install) or a Go journal reader, add the reader if the Invitational shows hosts with no file`.
- `shortcut: polling at 1 s, so a line can be up to a second late; fine for authentication events, which are not time-critical at that scale`.
- `shortcut: web admin result inferred from HTTP status where the application does not log logins, see Behaviour`.
- Open: exact line formats for Cockpit, ProFTPD, Postfix SASL and the web admin applications are taken from the lab images; none is verified yet. The parser files ship with tests that fail until real samples are added.
- Open: the Windows Firewall operational log, the DNS Server analytical log and the Netlogon log tail (v3 Windows `logs` row) belong to `winevt` (channels) or to a Windows build of this file tailer. The Go file tail is portable, so adding `windows` to `OS` and a `C:\Windows\debug\netlog*.log` entry is small; decide when a rule needs it.
- Open: an ESXi or Palo/FTD syslog receiver (rules D14b, D14d) needs a listener, which `logs` does not have and which the complexity register would need a line for. The `devices` module pulls device logs, which is the preferred route; no listener is planned.
- Open: `plan.ModuleSettings` needs a `Logs` field and the `Files` list needs schema generation, a core change that follows the retrofit order.
- Open: detection of `rules/logs.yml` regex cost on busy access logs; the on-host engine runs it per `logs.line`. The rate limit bounds it. If the Invitational shows access-log volume above the budget, add `lines: false` for the access log and emit only parsed fields for attacks.
