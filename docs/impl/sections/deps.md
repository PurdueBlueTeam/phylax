#### `deps`

**1. Purpose and evidence.**

The manifest says what a service should depend on. Traffic says what it does depend on. `deps` observes the second without anyone hand-writing the first. Both ends are observed: the agent of the calling host and the agent of the called host. The graph feeds three things: `depends_on` proposals for the manifest (which render the egress allowlists), the scoring-safety lint (a plan or rendered policy must not cut a dependency of a scored service), and the rules that alert on a new, public or vanished dependency.

Evidence that it matters for points:

- Default-deny egress breaks every scored check that uses a dependency it did not allow: domain auth for AD-backed mail and SMB, LDAP and Kerberos from the mail host to the DC (core, Manifest rules). The dependency graph is what keeps the egress policy from cutting a scored service.
- The 2026 regional red team ran custom Postfix and DNS binaries that forwarded to its own host (the case the rules `DEP2` and `DEP3` describe, from `rules/deps.yml`). A new or public dependency of a service is how that shows.
- A service that stops reaching its upstream is down for the scorer even if its process is up; the vanished-dependency rule and the doctor's dependency probes (`checks`) use the graph.
- No vault card cites dependency discovery directly; the evidence is the mechanism above and the built code. The module starts as core because the lint depends on it; the next review can cut it if the lint is not used in a lab run.

**2. Status and code.**

Built (Linux agent side and controller graph, with tests in `internal/deps/deps_test.go`): `collector.go` (per-service edge aggregation, strength, learning window), `dnscache.go`, `graph.go` (confidence score, host and service resolution), `propose.go` (`Propose`, `Diff`, `Apply`), `lint.go` (the lint rules), `covered.go` (what the egress policy already allows), `rules/deps.yml` (three rules). Not done (docs/deps.md):

- Controller wiring: nothing feeds stored `deps.*` events into a `Graph`, so there is no live graph, no `DepsGuard` for plan nodes (`Graph.Dependents` is the primitive: refuse stop, disable or mask of a service a scored service depends on), and no persisted learning state beyond the agent-side flag.
- The UI page and the proposal review page.
- Windows hosts: no collector. Sysmon 3 and Security 5156 events would feed the collector; the mapping from service name and `svchost` to a service needs work.
- DNS names need a producer: the `capture` DNS parser should feed the cache. In the module this becomes the common kind `dns_query` (answers consumed by `deps`) instead of `DNSCache.Note`.
- The rule ids `D14`, `D14b`, `D14c` collide with the device-tampering rule D14 (Known bugs 2). They are renamed `DEP1`, `DEP2`, `DEP3`. The rule-id registry check in CI covers the one detection namespace. The lint codes `DEP001`-`DEP003` and `DEP101` are a separate namespace (lint codes, not detection rules).

Retrofit for the contract: the agent collector is called from the `net` module's `sock_diag` poll (`internal/collect/net/tracker.go`, `module.go`), which is a sibling import. It becomes a separate agent module `deps` that consumes common kinds from the on-host bus (`conn`, `listener`, `process_start`, `process_exit`) and emits `deps.*`. This needs `net`'s `conn` events to carry the process fields, direction and the start and end of each connection, including connections that open and close between polls (part 12). The controller side becomes an analyser; the lint becomes a set of rules reading its output (part 12).

Files: `internal/deps/*.go`, `internal/agent/mods/deps.go` (new), `rules/deps.yml` (renamed ids), `docs/deps.md`.

**3. Capability manifest.**

| Field | Value |
| --- | --- |
| Name | `deps` |
| Sides | agent (collector, Linux first), controller (graph and proposals) |
| OS | linux (agent); windows later |
| Privilege | `root` (reads the process table through the event bus only; no extra privilege) |
| Roles | any host with a scored service (agent); `controller` |
| Default | core |
| Budget (agent) | 15 CPU ms/s, 8 MB held, 1 event/s, burst 10, 12 KB out/min, 1 MB disk |
| Budget (controller) | 40 CPU ms/s, 24 MB held, 1 event/s, 20 KB out/min, 5 MB disk |
| Tables | `deps_edge` (the persisted graph; rebuilt from events on loss) |
| Content | `rules/deps` (the three detection rules) |
| Actions | none |
| Pages | `/dependencies` |
| Evidence | part 1 |

**4. Configuration.**

```yaml
# modules/deps.yml
learn: 15m              # learning window after the agent starts
report: 5m              # periodic re-emission of changed aggregates
gone_after: 30m         # a learned edge idle this long is gone
gone_min: 3             # observations before an edge can be gone
max_services: 128
max_edges: 128          # per service
max_peers: 128          # inbound peers per service
cid_samples: 4
propose:
  min_level: medium     # lowest confidence proposed
  baseline_only: false  # true: never propose an edge first seen after the learning window
```

```go
// package deps; the agent block is DepsSettings in internal/plan (nil = disabled).
type Config struct {
	Learn, Report, GoneAfter time.Duration
	GoneMin, MaxServices, MaxEdges, MaxPeers, CIDSamples int
	Propose struct{ MinLevel string; BaselineOnly bool }
}
```

**5. Events.**

Consumes (agent): `conn`, `listener`, `process_start`, `process_exit`, `dns_query`. Consumes (controller): `deps.edge`, `deps.edge_gone`, `deps.peer`, `listener`, `inventory.snapshot` and `inventory.row` with `table: domain_join` (the Linux domain-join probe of `inventory`, which seeds `depends_on` proposals for the mail host's LDAP and Kerberos dependencies), the manifest addresses and services (config).

Emits:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `deps.edge` | 1 | normal | `service`, `svc_key` (proto/port), `svc_exe`, `svc_comm`, `edge`, `proto`, `dst_addr`, `dst_port`, `dst_name`, `public`, `count`, `request_count`, `background_count`, `strength` (`strong`, `weak`), `periodic`, `new`, `learning`, `first_seen_ms`, `last_seen_ms`, `src_addr`, `community_ids` |
| `deps.edge_gone` | 1 | normal | the same fields plus `idle_ms` |
| `deps.peer` | 1 | bulk | `peer_addr`, `port`, `count`, `community_ids`; an inbound client of a service |
| `deps.graph` | 1 | bulk | the resolved graph: edges (from host and service, to host and service, proto, port, confidence level and score, baseline flag, gone flag, evidence lines); emitted by the analyser when it changes |
| `deps.proposal` | 1 | normal | `host`, `service`, `add[]` (the `depends_on` entries), `evidence[]` |

**6. Behaviour.**

*Agent side.* Each listening socket's owner process is a service root; the service id is the manifest name of its port. An outbound connection belongs to the service whose root appears in the connecting process's ancestor chain (bounded depth), so workers, forked children and grandchildren count; an orphaned worker falls back to its binary, only if exactly one service runs it. Connections to the service's own listener over loopback are ignored. Per (service, protocol, destination address, port) the collector keeps counts, first and last seen, the DNS name (from `dns_query` answers when a producer fills it), the source address and a few Community IDs.

*Evidence strength.* **Strong** (request-driven): the connection opened while an inbound connection to that service was active, or one that opened and closed inside the same poll. **Weak**: no inbound request, so periodic or background; cron-like refreshes are flagged `periodic` when the gaps are even. A dependency is strong when at least half its connections are request-driven. Connections already open when the agent started count as background. Inbound clients are aggregated the same way per service (`deps.peer`), so a called host with an agent confirms the edge even if the caller has none.

Everything is bounded (services, edges and peers per service, Community ID samples) and aggregated. `deps.edge` is emitted at once for a new edge (`new: true`) and every `report` (5 minutes) for changed ones. `learning` marks edges first seen in the agent's 15-minute learning window; the rule profile `deps.seen` learns the same window per service. `deps.edge_gone` is emitted when a learned edge with at least `gone_min` (3) observations is idle for `gone_after` (30 minutes).

*Controller side (the graph).* Edges are resolved to hosts through the manifest addresses, the source addresses agents report and their listener events, and to a service through the listener inventory. **Confidence is a score, not a guess:** base 0.5 for request-driven and 0.25 for background; +0.2 when the destination is a known host; +0.2 when that host's `deps.peer` shows the same address pair (+0.1 more when a Community ID matches); +0.1 for five or more connections. High is 0.8 or more, medium 0.5. Each edge keeps readable evidence lines. An address no host owns stays an external edge with no service.

*Uses.*

1. **Proposals.** `Propose` turns resolved, cross-host, medium-or-better edges that the egress policy does not already allow into `depends_on` additions, grouped per destination host and protocol, rendered as a diff for the operator. Nothing is applied: a proposal is a `Host.Propose` of kind "manifest override", and `Apply` returns a copy only for validation and lint. With `baseline_only` an edge first seen after the learning window is never proposed for approval, so an intruder's dependency is not offered as a normal one.
2. **The lint** (`DEP001`-`DEP003`, `DEP101`): errors when a manifest or a rendered host policy would cut a high-confidence request-driven dependency of a scored service (`DEP001`, `DEP101`), or stop or disable a service a scored service depends on (`DEP003`); weaker evidence warns; external addresses only warn (`DEP002`). `Graph.Dependents` backs a plan guard that refuses `stop`, `disable` or `mask` of such a service.
3. **Rules** (`rules/deps.yml`):
   - `DEP1.new-dependency`: a new private dependency after the learning window (severity high, tier 1; ATT&CK T1071, T1090).
   - `DEP2.external-dependency`: a new public dependency of a service (critical, tier 1; T1048, T1071; collects the process tree and freezes the ring). This is the 2026 custom Postfix and DNS shape.
   - `DEP3.dependency-gone`: a learned dependency that vanished (medium, tier 2; the service may have been replaced or its upstream broken).
   - Declared dependencies are exempt through `service.dependencies`; plan-tagged events are exempt.
4. **A per-service table:** what it depends on and what depends on it, with confidence and evidence. The doctor (`checks`) probes high-confidence edges when a scored service fails.

**7. Actions and content.**

No actions. Content: `rules/deps.yml` with `DEP1`, `DEP2`, `DEP3`, each with inline tests (a mail service talks to an unlearned internal host; a learned dependency does not fire; a declared dependency does not fire; a periodic re-report is not new; a Postfix proxy to an outside host; a learned external DNS forwarder does not fire; a baseline dependency vanished; a late-appearing edge going away does not fire). The rule-id registry check treats these as detection rules.

**8. UI.**

`/dependencies`: per service, the table of what it depends on and what depends on it (confidence, evidence lines, baseline flag), and the proposal review (the diff of `depends_on` additions with Accept, which writes overrides). Overview tile: new dependencies since the learning window. No host-grid column.

**9. Health.**

States: `ok`; `degraded` when the agent is inside its learning window (gap: "learning, edges not yet baseline"), when a bound was hit (services, edges or peers truncated, with the count), or when `conn` events lack process fields or direction (gap: "net does not report the owning process"); `unavailable` on Windows hosts ("no collector on Windows"). Degraded means the graph may be incomplete, so a lint warning cannot be treated as an all-clear.

**10. Scoring safety.**

The collector only reads events; the controller only reads and proposes. The lint is the module's safety function: it refuses plans and rendered policy that would cut an observed dependency of a scored service, and its output is graded by confidence so weak evidence warns instead of blocking. A planted dependency inside the learning window is learned as normal; that is the known weakness, and the rules on public addresses (`DEP2`) still fire on a public destination if the address was not seen in the window. Alert-only stage: the rules start at tier 1 (one-click), and proposals are never applied by the module.

**11. Tests.**

- Unit (built): `deps_test.go` covers the collector (ancestor chain, orphan fallback, loopback ignored, strength, learning flag, gone), the graph (confidence arithmetic, resolution), `Propose` and `Diff`, and the lint.
- New: the agent module fed from a recorded bus stream (no `net` import); `dns_query` naming; the graph analyser from a fixture store (identical output twice); `DEP1`-`DEP3` fixtures renamed, and the registry test that one rule id has one definition (the `D14` collision is a regression test).
- Conformance: starts with no config, stops cleanly, emits only declared kinds, respects its budget, survives link loss and reconfiguration (the learning window state is kept through `Keep`).
- Lab: a mail service with an LDAP and Kerberos dependency survives default-deny egress rendered from accepted proposals; a planted forwarder to a public address fires `DEP2`; a stopped upstream fires `DEP3`. The lint rejects a plan that stops a service a scored service depends on.

**12. Limits and open items.**

- `shortcut: sampling at the net module's 2 s poll can miss a connection that opens and closes between polls; upgrade when audit connect events carry enough to replace the poll.`
- `shortcut: request-driven attribution is temporal, not causal; an unrelated background connection during traffic is called strong, which the half-of-connections rule and repeated observation dampen. Upgrade only if a lab run shows a wrong strong edge becoming a lint error.`
- `shortcut: a planted dependency inside the learning window is learned as normal; a baseline-only proposal mode and DEP2 limit the damage, no further control.`
- `shortcut: no Windows collector; upgrade when a scored service on a Windows host needs egress allowances rendered from observation (the AD host's allowances come from the declared domain membership, so the gap is small for 2027).`
- Open (`net` section): the `net` section's `conn` events carry `op`, `dir`, `service`, `duration_ms` and process fields; the collector needs the process fields to include pid and start ticks (for the ancestor chain with `process_start`) and `conn` closed events for connections that open and close within one poll. If `net` cannot provide that, the collector stays inside `net` as a documented exception to the no-sibling-import rule.
- Core change: modules cannot import each other, so the lint rules `DEP001`-`DEP003` and `DEP101` need a core registration point (or a query-based rule form) to read `deps.graph`. Until then they stay as pure functions the core lint package calls; that is the one place a core package depends on a module and needs a decision.
- Open: the lint codes versus detection rule ids look alike (`DEP001` against `DEP1`). If the registry check flags the confusion, rename the lint codes `LDEP1`-`LDEP4`.
- Cross-section: `inventory` emits the `domain_join` table rows; `capture` or `net` emits `dns_query`; `checks` consumes `deps.graph`; the manifest section's egress rendering reads accepted `depends_on`.
