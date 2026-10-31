#### `net`

##### 1. Purpose and evidence

`net` is the host's network telemetry module. It reports which sockets exist and who owns them: listeners and connections with the owning process, its binary hash and a Community ID; it reports every outbound connection the host firewall denied, attributed to a process; and it sends the egress canary probes. In v3 the denied-egress collection was a module of its own (`egress`). In the code it is part of `net` (NFLOG joined to the same `sock_diag` and `/proc` walk), so v4 follows the code: `net` collects, and the controller-side `egress` module analyses (ranking, beacon periodicity, the per-executable allowlist).

Why it matters for points:

- Listeners and connections with owners are the input to drift detection (a listener that is in no service, decoy or profile: rule D3), service dependency discovery (`deps`), trace-back from a change to the inbound connection that caused it (`traceback`), and chains (review D71).
- The first denied connection from a server is the best C2 signal, because default-deny egress makes the callback fail loudly, and the join gives the process and its hash (review D75, D218, D332; [OA §5.3]).
- The Community ID in every record joins host data to Palo, Suricata and Zeek data by string [OA §5.3].
- Egress canaries show when the egress policy or the perimeter has drifted (a "leak" is a policy failure).

Decisions applied: decision 7 (kernel `sock_diag`, no proc connector). Review D96 and D97 are kept as built: `sock_diag` plus the fd-inode join, audit `connect` records on default-deny hosts (that is an `audit` rule, `net_rules`), Community ID, and the agent's own link excluded. Review D75 and D218 put the denied-egress collection here. The sinkhole (D76, D222: nft redirect of denied TCP to a loopback catcher) is not in `net`; its decision is deferred to the C2 fingerprinting lab (the sinkhole is not in this module's scope in v4).

##### 2. Status and code

Status: built on Linux (code and unit tests; real-kernel tests exist for NFLOG in a container; nothing lab-proven). Windows: not built in this module.

- `internal/collect/net`: `module.go` (module, config, main loop, canary loop), `sockdiag.go` and `sockdiag_linux.go` (`NETLINK_SOCK_DIAG` dump of TCP and UDP, v4 and v6; no privilege needed to dump), `proc_linux.go` (`ProcFS`: inode-to-process walk of `/proc/<pid>/fd` with a cache, negative cache of 10 s, executable sha256 cached by device, inode, ctime and size, size limit 256 MiB), `tracker.go` (snapshot diff to events, direction inference), `nflog.go` and `nflog_linux.go` (NFLOG reader over `NETLINK_NETFILTER`, copies 128 bytes per packet), `egress.go` (denied-packet attribution), `communityid.go` (Community ID v1), `canary.go` (probe sender), `module_other.go` (stub off Linux).
- `internal/agent/mods/net.go`: the factory (returns `ErrUnavailable` off Linux).
- Tests: `tracker_test.go`, `nflog_test.go` (recorded `testdata/nflog_syn.hex`), `communityid_test.go`, `procfs_linux_test.go`, `real_linux_test.go`, `docker_linux_test.go` (real NFLOG in a throwaway container with only `CAP_NET_ADMIN`).

Different from the design or missing:

- Windows: no socket tables (`GetExtendedTcpTable`, UDP table), no 5157 egress attribution. Sysmon 3 arrives as `conn` from `winevt`; 5156 and 5157 arrive there as `winevt.sec_event{category: wfp_connection}`. (D235, Windows raw-socket capture, is cut, so Windows network coverage is: socket tables here, Sysmon 3, 5156/5157, and Palo logs.)
- The agent's own link is not excluded from `conn` events and egress attribution (D96, D97; see Behaviour).
- An NFLOG `ENOBUFS` counter exists (`NFLogReader.Lost`) but is not reported as a gap.
- The module calls `internal/deps` directly and emits `deps.edge` and `deps.peer` from its tracker. Under the module contract that is a sibling import; see Limits.
- Kinds are `net.*` names and `net_connect`; they are mapped to declared kinds during the retrofit.

##### 3. Capability manifest

```go
module.Manifest{
	Name:      "net",
	Sides:     []module.Side{module.SideAgent},
	OS:        []string{"linux", "windows"}, // Windows half unbuilt
	Privilege: "root", // socket dump needs none; the inode-to-process join needs readable /proc/<pid>/fd; NFLOG needs CAP_NET_ADMIN
	Roles:     nil,
	Consumes:  []string{"winevt.sec_event"}, // Windows only: 5157 outbound blocks become net.egress_denied
	Emits: []event.Type{ /* conn v1, listener v1, net.egress_denied v1, net.canary_result v1, net.sensor_degraded v1, telemetry_gap v1 */ },
	Budget: module.Budget{
		CPUMillisPerSec: 80, HeldMB: 64, EventsPerSec: 200, Burst: 400,
		BytesOutPerMin: 8 << 20, DiskMB: 0,
	},
	Default:  true, // core-default
	Tables:   nil,
	Content:  nil,
	Actions:  nil,
	Pages:    nil,
	Evidence: []string{"[OA §5.2]", "[OA §5.3]", "review D75, D218, D332 (first denied connection)"},
}
```

Budget numbers are initial limits. Held memory is dominated by the tracked-connection map (65536 entries) and the process cache. `shortcut: budget numbers are estimates, replace with Invitational measurements (O3 in docs/impl/invitational-data.md)`.

##### 4. Configuration

`modules/net.yml`, rendered per host into `modules.net` (`plan.NetSettings`). A nil block disables the module.

```yaml
rate_per_sec: 200
burst: 400
services: {}              # "proto/port" or "port" -> service name, from services.yml; e.g. "tcp/22": ssh. Rendered per host
nflog_groups: []          # NFLOG groups of the firewall renderer's deny rules; none disables the egress reader. Filled by the controller from the rendered firewall policy
canaries: []              # egress canary targets: { addr, port, tag }. Filled from vantage/firewall config, per host
hash_exe: true            # sha256 of the owning executable on each new socket owner
interval_ms: 2000         # sock_diag poll interval; 0 means 2000
```

```go
// package plan (built)
type NetSettings struct {
	ModuleLimits
	Services    map[string]string `json:"services,omitempty"`
	NFLogGroups []uint16          `json:"nflog_groups,omitempty"`
	Canaries    []CanarySettings  `json:"canaries,omitempty"` // {Addr string, Port uint16, Tag string}
	HashExe     bool              `json:"hash_exe,omitempty"`
	IntervalMS  int               `json:"interval_ms,omitempty"`
}
```

Internals at the code's defaults, not in the signed config: tracked connections 65536; byte counters (`tcp_info`) off; egress dedup 30 s, attribution wait 3 s, pending 256, seen 8192; canary interval 5 min, timeout 2 s. `NoDeps` (see Limits) is false.

##### 5. Events

Consumed (Windows side only, once built): `winevt.sec_event` filtered to `category: wfp_connection`, `event_id: 5157`.

Emitted:

| Kind | Priority | Key fields |
| --- | --- | --- |
| `listener` (common) | high | `op` (`added` or `removed`), `proto`, `addr`, `port`, `inode`, `sock_uid`, `service`, `baseline` (true for the first snapshot), process fields: `pid`, `pid_start`, `comm`, `exe`, `uid`, `exe_sha256`, `exe_deleted`. Code kinds `net.listener_added` and `net.listener_removed` are aliases for one release |
| `conn` (common) | normal | `op` (`opened` or `closed`), `dir` (`inbound` or `outbound`), `proto`, `laddr`, `lport`, `raddr`, `rport`, `src`, `dst` (flow orientation), `community_id`, `service`, `state` (opened), `duration_ms` (closed), `bytes_out`, `bytes_in` (when counters are on), `baseline`, process fields. Aliases `net.connection_opened` and `net.connection_closed`. `source` is `net`; the `audit` module's `conn` events carry `source: audit` |
| `net.egress_denied` | high | `dir: outbound`, `proto`, `laddr`, `lport`, `raddr`, `rport`, `community_id`, `attributed` (bool), `attempts` (retries counted, including those suppressed in the previous window), `nflog_group`, `prefix`, `sock_uid`, `inode`, process fields, `tag: canary` and `canary_tag` when the destination is a canary target |
| `net.canary_result` | normal, critical on a leak | `raddr`, `rport`, `proto`, `tag: canary`, `result` (`leak`, `blocked`, `error`), `expected` (true when blocked), `detail` (`refused`, `unreachable`, `timeout`, error text), `elapsed_ms`, `canary_tag` |
| `net.sensor_degraded` | high | `module`, `sensor` (`nflog`), `error` |
| `telemetry_gap` (common) | high | `source: net`, `reason` (to add: `nflog_enobufs`, `connection_table_full`), `count` |

The first snapshot is reported with `baseline: true` so consumers can treat existing state as the starting point and not as new activity.

##### 6. Behaviour

**Socket telemetry.** Every `interval_ms` (default 2 s) the module dumps all TCP and UDP sockets (v4 and v6) from `sock_diag`, resolves the owning processes for unmapped inodes by walking `/proc/<pid>/fd` (the osquery algorithm: known inodes come from a cache, a walk happens only when a wanted inode is unmapped, and inodes that stay unmapped, such as kernel sockets or other users' sockets when unprivileged, are not retried for 10 s), and diffs against the previous snapshot. A new listener, a removed listener, a new connection and a closed connection each produce one event. A socket whose owner appears later is attributed without a second event. Connections beyond 65536 are counted (`Dropped`) and neither opened nor closed.

A process is identified by `(pid, pid_start)`; the start time (field 22 of `/proc/<pid>/stat`) makes a reused pid a different process. The executable is hashed with sha256 once per `(device, inode, ctime, size)`. A deleted executable (`exe_deleted`) is reported as such. This is the evidence the per-executable egress allowlist and the replaced-binary rules need.

**Direction and service.** A connection is inbound when its local endpoint matches one of this host's listeners (same protocol and port, and the listener's address is unspecified or equal). The service name comes from the `services` map: the local port for inbound connections (what we serve), the remote port for outbound ones (what we consume). Both orient `src` and `dst` as flow source and destination for the Community ID: the Community ID v1 (seed 0) is the same in both directions and joins to Palo, Suricata and Zeek records.

**Short connections.** Polling at 2 s misses connections shorter than that. Hosts with default-deny egress get audit `connect` records (`net_rules` in `audit`, filtered by uid where possible), and Windows gets Sysmon 3. Neither is complete by itself. The poller is the baseline; the audit records and the NFLOG feed fill the short-lived gap.

**Own link excluded (to build).** The agent's own TLS connection and its spool writes are excluded from every stream; otherwise events about the link produce more link traffic, the documented feedback loop [OA §5.2, §5.3]. Rule: sockets owned by the agent's own pid are not reported as `conn` events and are not attributed in `net.egress_denied` (the agent's own link is allowlisted in the firewall by its randomised path and hash, so a denial of it is a platform problem reported by the link, not a C2 signal).

**Denied egress (Linux).**

1. The firewall renderer's drop rule also sends the packet to an NFLOG group (`nflog_groups`). Rules drop rather than reject, so the blocked socket keeps retrying its SYNs and the module finds the owning socket.
2. The NFLOG reader (needs `CAP_NET_ADMIN` in the namespace that owns the rules) delivers the first 128 bytes of each packet, enough for IPv6 plus TCP options. Packets go through a bounded channel of 1024; when it is full they are dropped, which is acceptable because the blocked socket retries.
3. For each denied packet the module parses the IP header, checks whether this 5-tuple was already reported in the last 30 s (repeats are counted into `attempts` of the next report, never emitted), and looks for the sending socket in the current table (same protocol and local port, local address equal or unspecified, remote equal to the destination, or an unconnected UDP socket). If it finds an owner, it emits at once; otherwise the denial stays pending and is retried on a 250 ms tick for up to 3 s. After that it is emitted unattributed (`attributed: false`) so a denial is never silently lost. At most 256 pending denials are kept; past that, new ones are reported unattributed immediately and counted.
4. If the process died within about a second, the only evidence is the audit `connect` record (`audit` with `net_rules`).
5. Denials to a configured canary destination are tagged `tag: canary` so rules and beacon analysis skip them.

If the NFLOG reader cannot start (no `CAP_NET_ADMIN`, no `nfnetlink_log`), the module logs it, emits a high-priority `net.sensor_degraded` event and continues with socket telemetry.

**Denied egress (Windows, to build).** The module subscribes to `winevt.sec_event` with `category: wfp_connection` and `event_id: 5157` (Windows Filtering Platform blocked connection) for outbound traffic, and re-emits it as `net.egress_denied` with `attributed: true` (5157 carries the process id and application path), `sensor: "5157"`, and the agent's own link excluded by application path. Only `net` may emit `net.*` kinds, which is why `winevt` does not emit it directly. 5157 needs the Filtering Platform Connection audit subcategory on; `win.audit_policy.set` enables it in the hardening pack and `winevt` must add 5156/5157 to the Security include list on default-deny hosts. Windows socket tables (`GetExtendedTcpTable` with owner pid, `GetExtendedUdpTable`) are the missing `SockSource` for the same tracker (process image path from the pid), so listeners and connections would use the same code as Linux.

**Where else denied egress is seen.**

| Vantage point | Mechanism | Owner |
| --- | --- | --- |
| Linux host | NFLOG plus `sock_diag` join; audit `connect` if the process died | `net` (and `audit`) |
| Windows host | Security 5157, outbound only, agent link excluded | `net` (from `winevt`) |
| Palo | The adapter pulls deny entries for outbound sessions every 30 s; covers the case where an implant killed our agent or disabled the host firewall | `devices` |
| DNS | The DC's DNS analytical log and Sysmon 22 | `winevt` |

**Analysis is not here.** Ranking by binary hash and destination, the periodic-callback escalation (jitter below 20% over at least 10 intervals, rule D13c), the per-executable allowlist and the "block this?" suggestion belong to the controller-side `egress` module, which reads `net.egress_denied` and `conn` from the store.

**Canary sender.** For each configured target the module dials TCP on `canary_interval` (5 min) with a 2 s timeout. A completed connection is a `leak` (the egress policy failed to block it; critical); a timeout, refusal or unreachable error is `blocked` (the expected result); anything else is `error`. The canary listeners (the Kali side), verdicts and the perimeter checks belong to `vantage`; this module only sends.

**Containers (N7.6).** For `runtime: docker` services, the published-port listener is `docker-proxy` or the netfilter DNAT, not the service binary. The module reports the host-visible socket owner; the manifest's service-to-listener mapping (container name, published ports) is what lets the controller attribute it. Connections inside a container's network namespace are not visible from the host's `sock_diag` dump. `shortcut: sockets in other network namespaces are not dumped; add a per-container namespace dump only if the 2027 stack runs services in containers with their own network namespace`.

##### 7. Actions and content

Actions: none. Content: none. Rules over its events are `detect`'s (`rules/network.yml`, `rules/profiles.yml`); the baseline for D3 comes from the manifest, not from this module.

##### 8. UI

No page of its own. The Platform page shows the module state, its sensors (socket poll, NFLOG, canary results) and drops. The Traffic page, the egress view and the host grid are registered by `capture` and `egress`; the "firewall applied" column is `firewall`'s. A canary leak appears in the alert queue as a critical event.

##### 9. Health

Implements `agent.HealthReporter`. States:

- `ok`: poll succeeds, and the NFLOG reader is running if `nflog_groups` is set.
- `degraded`: the NFLOG reader failed or stopped (`net.sensor_degraded`), the connection table is full, NFLOG lost packets, or the process join is failing for many sockets (a `/proc` hidepid mount).
- `unavailable`: the OS has no `sock_diag` (non-Linux, until the Windows source exists).

Gaps: `NFLOG not available: <err>`, `connection table full (N dropped)`, `NFLOG buffer overflowed (N packets lost)`, `owning process unknown for N sockets (not root or /proc restricted)`, `sockets in other network namespaces not seen`.

##### 10. Scoring safety

Passive on the host: it reads the socket table and `/proc` and listens on an NFLOG group. The only packets it sends are the canary dials, which go to destinations policy should block, never to scored services. The NFLOG group itself is created by the firewall renderer's rules (module `firewall`), whose own lint applies (the drop rule must not touch scored inbound ports and never narrows sources on a scored port, decision 13); the reader only consumes. Cost: a 2 s poll of the socket table is cheap, and the `/proc` fd walk is limited to unmapped inodes. Alert-only stage: all of it is observation.

##### 11. Tests

Built: tracker diff (listener/connection add, remove, late attribution, baseline, direction inference, table cap), NFLOG parsing from a recorded SYN, Community ID against reference vectors, `ProcFS` against a fake `/proc` and against the real one, egress attribution (immediate, delayed, unattributed on timeout, dedup and attempt counting, pending cap), canary result classification, module under the supervisor, egress through the packet feed, and a real NFLOG test in a container with `CAP_NET_ADMIN` (`docker_linux_test.go`, skipped with a message when Docker is not available).

To add: own-link exclusion; the `HealthReporter` output; NFLOG overflow as a gap; Windows socket source and the 5157 re-emit once built; alias tests for old kind names.

Conformance: starts with no config (disabled), starts with a default config on a fixture host (a fake `Source` and `Feed` are injected), stops within 5 s, emits only declared kinds, survives link loss (emit errors are counted and ignored), survives reconfiguration (a changed service map replaces the module; the connection table is rebuilt from the next snapshot, so a `baseline` flag on the first snapshot after reconfiguration must not read as new activity: use `Env.Keep`), `go test -race`.

Lab tests (v3 ids): denied egress attributed to a process (lab implant test, id to be assigned in the Testing section), the canary leak, T02 firewall disabled (the canary and the Palo deny logs still see), the Invitational questions R4 and E16 (what C2 traffic and what legitimate idle egress look like).

##### 12. Limits and open items

- `shortcut: polling at 2 s misses connections shorter than the interval; close the gap with audit connect records and NFLOG, shorten the interval only if a lab run shows scored-path connections being missed`.
- `shortcut: sockets in other network namespaces are not dumped, see Behaviour (containers)`.
- `shortcut: unprivileged mode shows only own-user sockets' owners; the agent runs as root, so this only matters for lab runs`.
- Open: `net` calls `deps.Collector` directly in `Start` (`NoDeps`, `DNS` config). Under the contract the dependency collector should subscribe to `conn` and `listener` events through the on-host bus and emit `deps.edge` and `deps.peer` from the `deps` module. Change is in `deps` and `net` together; the `deps` section describes the target.
- Open: own-link exclusion is unbuilt.
- Open: Windows socket tables and the 5157 re-emit are unbuilt (decided here; the Windows `SockSource` is the main work).
- Open: the sinkhole (D76, D222) is deferred to the C2 fingerprinting lab. If first-bytes fingerprints discriminate between frameworks, a sinkhole catcher returns as a separate Linux module that consumes `net.egress_denied`; it does not belong in `net`.
- Open: the kind retrofit (`net.listener_*` to `listener`, `net.connection_*` to `conn`, `net_connect` to `conn`). `rules/profiles.yml`, `rules/mw-redteam.yml` and `internal/traceback/obs.go` use the old names until the controller's alias table or the rules are updated.
- Core change request: none beyond `Env.Keep` for the baseline flag (already planned).
