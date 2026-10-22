# Operator web UI

Packages `internal/ui` (server, pages, templates) and `internal/controller`
(`webui.go`, `webops.go`, `alerts.go`, `planops.go`, `plantemplates.go`); started
by `phylax serve`.

## Running

`phylax serve` starts the UI on `127.0.0.1:8443` (config `ui_listen`, flag
`-ui-listen`; `off` disables it; a non-loopback address is refused). Plan
templates come from `plans_path` / `-plans`. On the first start it creates the
`admin` operator and prints the generated password once on stderr; only the
argon2id hash is stored (store tables `ui_accounts`, `ui_audit`, migration 3).
Change the password on the Account page.

## Extension points

* `ui.Server.Handle(pattern, handler)`: authenticated, CSRF-checked (every
  non-GET), and audited (`request METHOD path` is written before the handler
  runs; the request is refused if the audit write fails). Handlers add a named
  entry with `Server.AuditAction`.
* `ui.Ops` is the backend interface behind the operator pages;
  `controller.WebOps` implements it (`Controller.NewUI` wires accounts, audit,
  agents and ops). `WebOps.SetScorer(estimator, slaTracker, services)` feeds the
  round clock and SLA streaks; until then the dashboard says "no scorer data".

## Pages

| Route | Shows / does |
| --- | --- |
| `/` | One screen: agents (connected/silent, config state, spool, safe mode), open alerts by severity, plans awaiting approval, round clock and SLA streaks, recent chains and campaigns, platform health. Refreshes every 5 s (htmx). |
| `/agents`, `/agents/{host}` | Table; per host: last heartbeat, clock skew, config state/version/epoch, spool and congestion, modules, telemetry gaps. |
| `/agents/{host}/safemode` | Confirmation page (type the host name). The POST sends a signed `safe_mode` control through `Controller.SendControl`. |
| `/alerts`, `/alerts/{id}` | Queue (open/acked/closed/all); evidence = the referenced stored events; Trace back builds the attack chain (once) and links to it; ack/close. |
| `/chains`, `/chains/{id}` | Campaigns and chains; the timeline is a table, one row per hop (Central time and UTC, confidence level, "guess" flag, evidence refs, remediation items). |
| `/reports`, `/reports/{id}` | IR and inject drafts: see docs/report.md ("Controller and UI integration"). "Draft IR" buttons are on the chain and campaign pages. |
| `/checks`, `/checks/{id}` | Probe-library results and `vantage.check` events per scored service and vantage: last result, recent up/down history, uptime, SLA streak and penalties; per-check history of the last 200 results (sweeps included). |
| `/health` | Platform self-health: problems first (silent or disconnected agents, clock skew over 2 s, module errors, dropped events, WAL size, alert backlog, missing team number), controller and store facts, a per-agent table (link, last seen, skew, spool depth, congestion, dropped events, gap records, module errors). |
| `/audit` | Audit log, newest first, 50 per page ("Older entries" cursor), filter by operator and action. |
| `/plans`, `/plans/{id}` | List; create from a template; dry-run diff table; Approve plan; Approve node (gates, `host.exec`, lockout, destructive; note field); Apply; Roll back. Node table polls `/plans/{id}/nodes` every 2 s until the plan is final. |

Alerts reach the queue from stored `detect.alert` events or `Controller.RecordAlert`. The queue row is written
inside the ingest transaction (`store.SetIngestHook`, `Controller.ingestHook`), so a crash can never leave a stored
alert event without its row, and a failing hook rolls the batch back for the agent to resend. Rows are idempotent
(one per agent, seq and rule), and the controller replays any stored `detect.alert` event without a row on start.

## Checks and the scorer feed

`controller.ChecksHub` (`Controller.Checks()`) collects results from the controller's own probes (`RunProbe`,
`RecordResult`, vantage "controller") and from `vantage.check` events (vantage = the agent). Results go to the
`check_results` table (newest 2000 per check). Faithful results move an `scorer.SLATracker` (one outcome per result,
using the scorer-would-conclude verdict) and the hub hands it to `WebOps.SetScorer` on every result, unless another
tracker was installed by an explicit `SetScorer` call. Check ids map to services by the part before the first `:` or
`/` (`SetServiceFunc` overrides). Streaks are rebuilt from the stored results on start.

## Plan templates

YAML files `plans/<name>.yml|yaml` with `id`, `name`, `on_failure`, and `nodes`
(same fields as `plan.Node`: `id`, `action`, `target`, `risk`, `needs`, `gate`,
`deadman_sec`, `note`, `params`). Unknown fields are an error; the file is capped
at 256 KiB; names are a file base name only. Creating a plan runs the normal
`CreatePlan` validation. The plan id is the operator's choice or
`<template id>-<UTC timestamp>`. A template that does not parse is listed as
"invalid: ..." instead of hiding.

## Rollback

`Controller.RollbackPlan` (the Roll back button) aborts a running plan: unstarted
nodes are skipped, in-flight steps finish, then signed `rollback` steps run in
reverse order. It is only available for `on_failure: rollback_plan` plans: only
those give their nodes the rollback window that makes the agent keep rollback
data (others get `ErrNoRollbackData`). A finished plan cannot be rolled back.

## Gaps

* The checks page shows what was recorded; nothing on the controller schedules probes yet (the Kali check runner or a
  caller of `RunProbe` does).
* Audit viewing is not itself audited (GETs are not); the audit log is append-only in the UI.
* Uploaded screenshot files are never deleted when a figure is removed (they stay hashed under the state directory).

## Deviations from the design

* Live updates use htmx polling (2 s plan nodes, 5 s dashboard), not SSE.
* The plan DAG and chain timeline are tables (the task asked for a table), not
  server-side SVG; `Needs` lists the edges.
