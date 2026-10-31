#### `traceback`

**1. Purpose and evidence.**

Every connection to our services is labelled scorer, us or other. Any change to a service is detected within a minute. Each change our own plans did not make starts an automatic trace-back: from the changed thing, to the process that changed it, to the network request that drove that process, to the source and everything else it did. The result goes into an incident, which `chains` turns into hops. Three analysers do this: traffic labels, change detection and trace-back.

Evidence that it matters for points:

- Our own outages are blamed on red and cost the same uptime [[how-to-win-ccdc-scoring#e3]]. Change detection explains what we changed; trace-back explains what red changed.
- Half of the red-team lead's IR rubric is attack-path remediation: who or what placed the thing and how the account was compromised [TTP §0, PRO §3]. Trace-back is the data for that section.
- The scorer and our own hardening are the main sources of false positives, more than the red team [DR §3]. The label `scorer` and the plan tag keep them out of alerts. Red may imitate the scorer, so the working question is "is this neither the scorer nor us?"
- OpenCart backdoor admins were real (red-team report); app-level data changes (admin rows, database users, UDFs) need read-only pollers (review D286).
- At the 2026 regional the red team ran custom Postfix and DNS binaries that forwarded to its own host (rule `DEP2` in `deps` exists for this case); the change and its writer must be found quickly.
- Target metric: trace-back reaches the source IP for webshell-driven changes in 90% or more of lab campaigns (Success metrics).

**2. Status and code.**

Trace-back is built with tests (`internal/traceback/trace.go`, `obs.go`, scenario tests in `trace_test.go` and the synthetic multi-host stream harness `tbtest/tbtest.go`). It reads stored events only (`Source`: `Events`, `Gaps`, `Agents`), takes a `Label` callback and a clock-offset callback, and returns a `Result` (timeline, links with method and confidence, source, lineage, files, freeze windows, gaps, truncation notes). The two other analysers are missing:

- Traffic-label assignment (`scorer`, `us`, `other`, `attack_like`, red-learned) is not built; trace-back receives labels through a callback that nothing implements yet.
- Change detection (the baseline of served content, configuration, runtime behaviour, binary, identity, app data, and the untagged-change trigger) is not built. The semantic parsers for PHP ini and unit files are partly in `internal/collect/audit` and `internal/actions` and are reused as shared parsers.
- The controller wires the tracer only from the UI report path (`internal/controller/report_ir.go`); there is no analyser run, no trigger loop and no stored result.
- IIS request linking is dropped (review D289): IIS is not in the 2027 environment. The code has no IIS path; it stays out.

Retrofit: `Tracer.Trace` becomes the body of an analyser. The `Source` interface is satisfied by `store.Query`. The tracer keeps no state between runs.

Files: `internal/traceback/*.go`, `internal/traceback/tbtest`, `rules/traceback` (app-level queries), `internal/controller/report_ir.go` (consumer, to be folded away).

**3. Capability manifest.**

| Field | Value |
| --- | --- |
| Name | `traceback` |
| Sides | controller (analysers) |
| OS | n/a |
| Privilege | `none` |
| Roles | `controller` |
| Default | core |
| Budget | 120 CPU ms/s during a run, 64 MB held, 4 events/s, burst 30, 100 KB out/min, 20 MB disk |
| Tables | `source`, `traceback_baseline` |
| Content | `rules/traceback/app_queries` (read-only application data queries), `rules/traceback/change_classes.yml` (which paths and files a service treats as content or config) |
| Actions | none (read-only evidence requests ride on events) |
| Pages | `/changes`, `/sources` |
| Evidence | part 1 |

Analysers (each a pure function over store queries; `Every` and the trigger set shown): `traceback.labels` (Inputs: `capture.flow`, `scorer.round`, `decoys.hit`, `detect.alert`; every 30 s), `traceback.changes` (Inputs: `file_change`, `process_start`, `listener`, `inventory.row`, `integrity.verdict`, `checks.result`, `inventory.probe_result`; every 30 s so a change is detected within a minute), `traceback.trace` (Inputs: `traceback.change`, `checks.red`, `detect.alert`; on trigger).

**4. Configuration.**

```yaml
# modules/traceback.yml
window: 2h                  # look-back and forward for lineage and source activity
fallback_window: 30s        # time-window correlation reach
gap_slack: 10m              # a recorded agent gap this near counts against a link
max_depth: 16               # lineage depth
max_activity: 200           # source-activity entries kept per trace
labels:
  red_learned_ttl: event    # red sources learned from decoy hits and detections stay red for the event
  attack_like_from: [detect.alert, decoys.hit, honeytokens.use]
changes:
  poll_app_data: 60s        # read-only app-level queries per service
  baseline_accept_tagged: true   # a plan or work-window change quietly updates the baseline
```

```go
// package traceback
type Config struct {
	Window, FallbackWindow, GapSlack time.Duration
	MaxDepth, MaxActivity            int
	Offset func(agent string) time.Duration // measured clock offsets (from heartbeats)
	Label  func(addr string) string         // "us", "scorer", "other" or ""
	Labels struct{ RedLearnedTTL string; AttackLikeFrom []string }
	Changes struct{ PollAppData time.Duration; BaselineAcceptTagged bool }
}
```

**5. Events.**

Consumes: `file_change`, `process_start`, `process_exit`, `conn`, `listener`, `auth_event` (common kinds); `capture.flow`; `scorer.round` (its `sources` per burst); `detect.alert`; `decoys.hit`, `honeytokens.sighting` (red-learned sources); `integrity.verdict`; `inventory.row` and `inventory.probe_result` (accounts, units, app data); `checks.result` and `checks.red`; `telemetry_gap`, `spool.gap`.

Emits:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `traceback.source` | 1 | normal | `addr`, `label` (`us`, `scorer`, `other`), `attack_like`, `red_learned`, `fingerprints[]`, `first_seen`, `last_seen`, `reason`; emitted when a source's label set changes |
| `traceback.change` | 1 | high when untagged | `service`, `host`, `class` (`content`, `config`, `runtime`, `binary`, `identity`, `app_data`, `device`), `what`, `before`, `after` (hashes), `tag`, `writer` (pid, exe), `untagged` |
| `traceback.result` | 1 | high | `trigger`, `change`, `links[]` (name, method, confidence, `broken_because`), `timeline[]`, `source`, `lineage[]`, `files[]` (host, path, sha256), `freeze[]` (host, from, to), `gaps[]`, `confidence`, `truncated[]` |

Evidence requests ride on `traceback.result`: `capture` freezes the ring for each freeze window and the collect path hashes and pulls each file. Both are read-only.

**6. Behaviour.**

*Traffic labels.*

| Label | How it is assigned |
| --- | --- |
| `us` | Our active checker, the Kali and its scans, agents, relays and device adapters; known sources and connection types. A canary probe or plan step carries its tag. |
| `scorer` | A flow that falls inside a burst of a `scorer.round` and whose source is listed there with a fingerprint verdict. Never from address alone. |
| `other` | Everything else: traffic generators and the red team. Within it, `attack_like` is flagged by detections: scans, exploit payloads, webshell requests, decoy hits. |

Red-team sources learned from decoy hits and detections are tagged red, so later connections from them are labelled on sight. The labelling is stateless: the same store and `now` give the same labels. Sources whose label changes are emitted as `traceback.source`; flows are labelled on read from those and `scorer.round`, which keeps the event volume small.

*What counts as a change* (review D282-D286):

| Change | Detected by |
| --- | --- |
| Served content on disk (webroots, FTP root, zone data, mail store structure, the SMB SOP files) | `file_change` with hashes |
| What the service returns | `checks.result` (strict-mode hash and regex drift against the last response seen next to a scorer success) |
| Configuration (Apache or httpd, PHP, Postfix, Dovecot, DNS, `.htaccess`, `auto_prepend_file`, Splunk apps) | `file_change`, plus semantic parsers for PHP ini and unit files |
| Runtime behaviour: new child processes, listeners, outbound connections or loaded modules under the service | `process_start`, `listener`, `conn`, Sysmon 7, `integrity.verdict` |
| The service's own binary or libraries | `integrity.verdict` |
| Identity: accounts, groups or permissions the service depends on | `file_change` on account files; Security events on Windows; `inventory.row` |
| App-level data (OpenCart admin rows, database users, UDFs) | read-only SQL pollers |
| Network devices: rules, NAT, admins | `devices` config diff events |

Changes made by our own plans carry the plan's tag in the envelope and quietly update the baseline. Anything untagged emits `traceback.change` with `untagged: true`. The application queries are content (`rules/traceback/app_queries/*.yml`: service kind, driver, a read-only statement, the key columns); the controller runs them as `probe.run` on the service host every `poll_app_data` and diffs the rows against the baseline. Which paths are content and which are config comes from `services.yml` (`content.roots`, `process.binaries`) and the change-class content.

*The trace-back chain.* Triggered automatically by any untagged change, red health check, or high-severity detection on a service. For a red check the trigger is the agent and time: it finds the latest untagged file change before it.

1. **The change.** For example `index.php` modified at 14:03:12.
2. **The writer.** The file event carries the actor (audit watches on Linux, Sysmon 11 on Windows). Writer link confidence: named by pid and start ticks 1.0, pid only 0.9, named by the event with no `process_start` 0.7.
3. **Its lineage.** For example `sh` <- `httpd` worker <- `httpd` parent, from the agent's process records, to depth `max_depth`.
4. **The request.** The agent maps the worker to the client connection it was serving, and the transaction log gives the parsed request. By stack:
   - The worker owns the client socket (Apache prefork with mod_php, most simple daemons): the socket records give the connection directly. Confidence 0.95 when the socket owner is the writer, 0.9 for an ancestor, minus 0.1 without start ticks (pid reuse is rejected when ticks differ). A connection already closed before the process started halves it.
   - php-fpm behind Apache or nginx: the worker holds only the FastCGI socket. The loopback peer is followed to the external client by time at 0.4 (0.25 with several candidates). If the front-end serves one connection at a time the match is exact.
   - Fallback: time-window correlation, 0.5 with one candidate and 0.3 with several, marked lower confidence. The full-chain confidence is the weakest link.
5. **The source.** The connection's source address and its label.
6. **Everything else from that source:** earlier transactions, scans, login attempts and decoy hits across every host, failed logins grouped. This usually reveals first contact and the foothold.
7. **Evidence.** The packet ring around the window is frozen and pulled; files involved are hashed and collected.

*Breaks.* When the chain breaks, the timeline says which link is missing instead of guessing: `Result.Breaks()` renders "chain breaks at X because ...". The causes: encrypted traffic (HTTPS details only from server logs), in-memory changes with no writer, agent gaps within `gap_slack`, short-lived processes (the agent queries sockets at the moment of the exec or file event, not only on a timer, which is the `net` module's job), and bounded reads that may hide events (`Truncated`). **Complexity flag:** the request link (step 4) is the hardest part. It has a dedicated lab test with quick webshell requests. If it misses too often the fallback is the time-window correlation, which is already in and lower in confidence.

*Dedupe.* An analyser keeps no state, so before tracing a change it queries for an existing `traceback.result` with the same trigger key; the key is the change's agent, sequence and path.

**7. Actions and content.**

No actions. Content: `rules/traceback/app_queries/` (OpenCart admin users and group rows, MySQL users and the UDF table, Splunk deployment-server and app lists, SQL Server logins), `rules/traceback/change_classes.yml`. The semantic parsers are shared libraries under `internal/parsers`.

**8. UI.**

- `/changes`: the change feed per service (tagged and untagged), baseline accept, and a link from each untagged change to its trace-back.
- `/sources`: sources with labels, fingerprints, first and last seen, the red-learned flag. A **pivot** on a source address opens the full-text store on that address (shell Alerts page).
- The incident page (shell) shows `traceback.result` as the timeline with the broken link named.
- Overview tile: untagged changes in the last hour and traces with broken links.
- The `/services` page (registered by `checks`) links to the service's change feed.

**9. Health.**

States: `ok`; `degraded` when an input feed is missing for a scored host (gap: "no process_start from <host>", "no capture from <host>"), when a run exceeds its CPU budget, or when events at an unknown schema version were skipped (the count is shown); `unavailable` when the store cannot be queried. Degraded means labels or traces may be incomplete; the timeline marks guesses.

**10. Scoring safety.**

Read-only against scored services except the application pollers: those run read-only SQL as a database user the plan created for Phylax, at 60 s, against services whose database is also a scored dependency (OpenCart's MySQL). The statements are content, reviewed, `SELECT` only, with a row limit and a statement timeout; the poll user is not a scored account. A poll that exceeds its timeout is skipped. The module takes no action on a change: it reports and traces. The rule that `scorer`-labelled flows are exempt from attack-like flags is behavioural, never address-based. Alert-only stage: it is alert-only by nature.

**11. Tests.**

- Unit (built): `trace_test.go` with `tbtest` scenarios: webshell write on ecom traced to the HTTP source; default-credential SSH, sudo, cron persistence and WinRM to the DC with a hidden Domain Admin; agent gap; bounds; time-window fallback; link confidence values.
- New: label assignment from a fixture store (identical output twice); change classes per row of the table; tagged versus untagged baseline update; app-query diff; dedupe by trigger key; the analyser runs from fixture stores with a fixed `now`.
- Conformance, analyser rules: identical output twice from the same fixture store and `now`; switchable alone; budget respected on a large fixture.
- Lab (v3 ids): T03 (PHP webshell upload, command, file change: trace-back reaches the source IP and request), T31 (integrity changes appear as `class: binary`), the OpenCart admin-row case of T38. Quick webshell requests are the request-link stress test.

**12. Limits and open items.**

- `shortcut: request linking handles worker-owned sockets, php-fpm and time-window fallback only; other front-end stacks (Passenger, Node behind nginx) fall back to the time window, add a stack when the 2027 services require it.`
- `shortcut: encrypted traffic (HTTPS) gives only server-log request details; there is no TLS interception.`
- `shortcut: sampling at the net module's 2 s poll can miss a connection that opens and closes between polls; the audit connect and accept events are the primary source.`
- Open: where the application pollers run when the service is containerised (`runtime: docker`): a query through the container's published port or a `docker exec`-class action. Undecided until the 2027 stack is known.
- Core change: none for events. The `Label` callback becomes the `traceback.source` events described above; `chains`, `report` and the UI read those instead of calling the tracer.
- Cross-section: `scorer` provides `scorer.round.sources`; `capture` and `report` consume `traceback.result` evidence requests; the Services page belongs to `checks`.
