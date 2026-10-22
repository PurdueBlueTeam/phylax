# Trace-back and attack chains

Implements phylax_design.md "Traffic labeling, change detection and trace-back" and "Attack chains"
(owner decision D-2: lightweight, no general graph engine). Packages: `internal/traceback`,
`internal/chains`; accessors in `internal/store/chains.go`.

## traceback

`Tracer.Trace(ctx, Trigger)` walks one change back, inside a host and then across hosts:
change -> writer -> lineage -> inbound connection -> source -> everything else the source did.
The trigger is a stored event (file_change, process_start, a login or connection), an alert
(`FromAlert`), or agent + time for a red check (the latest untagged file change before it).

Result: a chronological `Timeline` (the chain plus the source's other activity on every host,
failed logins grouped), causal `Links` each with method and confidence, and for every missing link
a `BrokenBecause` string (`Result.Breaks()` renders "chain breaks at X because ..."). Evidence:
files to hash, packet-ring freeze windows per host, nearby agent gaps.

Link confidence: writer named by pid and start ticks 1.0, pid only 0.9, named by the event with no
process_start 0.7; socket owner = writer 0.95, ancestor 0.9, minus 0.1 without start ticks (pid
reuse is rejected when ticks differ); connection already closed before the process started halves
it; time-window fallback 0.5 (one candidate) or 0.3 (several); loopback peer (php-fpm, proxy) is
followed to the external client by time at 0.4/0.25. The overall confidence is the weakest link.

## chains

`Builder.Build(ctx, Seed)` loads events from every agent within +-Window (2 h) of the seed, applies
clock offsets, and builds hops with these rules:

1. Each successful login with a source address is an `access` candidate (coalesced per host,
   source, account within the account window); failed logins before it are evidence, and 5 or more
   mean T1110.
2. An inbound connection merges into the login on the same host and source (<= N s). Connections
   with no login become `access` hops only when something attaches to them.
3. Cross-host stitching: an inbound flow is matched to another host's outbound record by Community
   ID, else by swapped 5-tuple (skew 10 s): `move`, 0.95. A login from a known host with an
   outbound connection to this host just before: 0.75. Source address of a known host and nothing
   else: 0.6. An outbound connection to a lateral port or managed host with no partner: `move`,
   `unmatched`, 0.5. Other outbound destinations: `egress`.
4. Within a host a process, file change or Security event attaches to the session whose socket it
   or an ancestor owned (0.95/0.9, 0.85/0.8 without ticks), else to the login of the same account
   within N s (120 s; refreshed by activity), 0.6.
5. A seed no session explains is run through `traceback` and grafted with its confidence.

Hop kinds are access, exec, change, move, egress. DCSync (4662 replication rights) is a `change`
(T1003.006): Security 4662 carries no source address to stitch on. Own (tagged) activity,
scorer/us sources and sweep-only changes (no writer) are excluded. Short utility execs
(`NoisyExecs`) are dropped unless something follows from them.

Bounds: hops beyond +-Window are never loaded; expansion is breadth-first from the seed over cause
links and shared source address, account (not root/system/machine accounts) or binary hash, kept to
`MaxHops` (12) nearest, seed first; `Truncated` and a note say so. A hop whose cause fell outside is
marked, never silently re-parented.

Confidence: each hop carries the method and confidence of its weakest link; a recorded agent gap
within 10 min of a hop on its host multiplies by 0.6 and adds a note; the chain confidence is the
minimum hop. The timeline marks time-window and unmatched hops as guesses.

Campaigns: `Group` merges chains sharing an outside access source, an account, a binary SHA-256 or
a C2 destination (union-find). Internal pivot addresses are not keys. `SyncCampaigns` persists and
assigns them, keeping the oldest member's campaign id.

Remediation (`AddRemediation`, called by Build): access -> close entry, rotate the credential,
block the source (outside only); move -> close the path, rotate; change -> remove persistence
(path, created account, group membership, task) or remove artifact; DCSync -> rotate krbtgt;
egress -> block destination; exec only when the binary is in a temp/user path. A given action
appears once, on its earliest hop. `Builder.Verify` marks items verified from later telemetry:
password reset of the account (krbtgt needs two), delete of the path, group removal, task
deletion. close_entry and block_source cannot be proven from events and stay manual. States are
open, applied, verified.

Output: `Chain.Timeline(loc)` (one row per hop, Central and UTC) and `Chain.IRSection(loc)` for the
IR drafter (rows, remediation lines with verified state, techniques, sources, accounts, hosts,
caveats, `ProofClosed`).

## Storage

The existing tables are minimal, so structured detail lives in JSON: `hops.link` holds the hop
document (account, process, 5-tuple, technique, notes, evidence, cause ord; chain seed/notes on the
first hop), `remediation_items.action` the item. `hops.src/dst` hold host or address, `state` is the
item state (`todo` reads as open). A future migration can promote these to columns.

## Testing

`internal/traceback/tbtest` ingests sealed synthetic multi-host streams into a real store. Scenarios:
webshell write on ecom traced to the HTTP source; default-credential SSH, sudo, cron persistence and
WinRM to the DC with a hidden Domain Admin (one campaign, Community ID stitching, account link);
agent gap; bounds; time-window fallback; remediation and verification; persistence round trip.
