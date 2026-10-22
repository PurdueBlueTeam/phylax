# Service dependency discovery

Design: phylax_design.md, "Service dependency discovery". Code: `internal/deps`
(collector, graph, proposals, lint), hooked into `internal/collect/net`
(Linux). Rules: `rules/deps.yml`.

## Events (agent)
| Kind | Fields |
| --- | --- |
| `deps.edge` | `service`, `svc_key` (proto/port), `svc_exe`, `svc_comm`, `edge`, `proto`, `dst_addr`, `dst_port`, `dst_name`, `public`, `count`, `request_count`, `background_count`, `strength` (strong/weak), `periodic`, `new`, `learning`, `first_seen_ms`, `last_seen_ms`, `src_addr`, `community_ids` |
| `deps.edge_gone` | as above, plus `idle_ms` |
| `deps.peer` | inbound client of a service: `peer_addr`, `port`, `count`, `community_ids` |

Enabled by default; `net.Config.NoDeps` turns it off. `net.Config.DNS`
(`deps.DNSCache`) names destinations; the capture module's DNS parser should
`Note` answers into it.

## Controller API (`internal/deps`)
- `Graph.Ingest(agent, event)` takes `deps.*` and `net.listener_*` events;
  `LoadManifest` adds addresses, listeners, scored flags, unit names.
- `Graph.Edges()`, `Services()`, `DependsOn`, `DependedOnBy`, `Dependents`.
- `Propose` / `Diff` / `Apply`: depends_on additions for operator approval.
- `CheckManifest`, `CheckHostPolicy`: lint rules DEP001 (observed dependency
  of a scored service would be cut; error when high confidence and
  request-driven), DEP002 (external address, warn), DEP003 (a depended-on
  service is stopped or disabled), DEP101 (rendered host policy cuts one).

## Gaps
- Controller wiring is not done: nothing yet feeds stored `deps.*` events into
  a `Graph` (needs a store poll or an ingest hook in `internal/controller`,
  which other work owns), so there is no live graph, no `DepsGuard` for plan
  nodes (`Graph.Dependents` is the primitive: refuse stop/disable/mask of a
  service a scored service depends on) and no learning-window state beyond the
  agent-side flag.
- UI page (table per service: depends on / depended on by, confidence,
  evidence) and the proposal review page are not built; `Graph.Services()` and
  `Diff` are the data sources.
- Windows hosts: no collector yet. Sysmon 3 / 5156 events would feed
  `deps.Collector.Observe` with `ConnEvent`s plus a listener table; the
  service-to-process mapping (service name, svchost) needs work.
- DNS names depend on a DNS producer calling `DNSCache.Note`; none exists yet.
- Sampling is per 2 s poll; short connections can be missed.
- Not persisted: the graph is rebuilt from stored events.
