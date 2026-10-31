#### `splunk`

##### 1. Purpose and evidence

`splunk` forwards selected Phylax events to the environment's Splunk over the HTTP Event Collector (HEC) into a dedicated `phylax` index, and ships a small dashboards pack on top of the forwarded data. Splunk is the environment's SIEM and is also a scored service (query and management on 8089), so the module is built around two promises: it never touches an index or search the scored check reads, and it never waits on Splunk. It is optional, off the critical path, and off unless the manifest enables it.

Why it matters for points:

- Central-logging injects recur (SOCS30T, TOOL29T; 16 events in 9 seasons [IJ, PRO §10]) and ask for evidence that logs reach Splunk and that dashboards exist for logons, group changes, services and firewall events [[cyberuci-locs#e20]] to [[cyberuci-locs#e23]]. Forwarded Phylax events are that evidence, and the dashboards are the screenshots (review D440).
- Peer dashboards show what a small pack looks like: SEMO's `11_threat_hunting_triage.xml`, SigPwny's `service_health.xml`, CyberUCI's LOCS JSON dashboards.
- Splunk is a place judges and the team can look, which is independent of the Phylax UI.

Evidence against: Splunk must not be the only place for storage and alerts (the controller's store is), and the organizer's toolkit ships raw logs and no alerts. The module therefore forwards copies; Phylax decisions never read from Splunk. The Splunk REST parser (D241) was cut: checks and `logs` cover what it was for.

Decision (review D440): keep the forwarder; ship a small dashboards pack of three views (service health, lateral movement, process tree by ProcessGuid) on top of logons, group changes, services and firewall events. Decision 12 and the area 12 answer: no coexistence work for the MWCCDC Defender Toolkit. If the environment ships an organizer Splunk toolkit and audit rules, they are part of the image, not tamper (see Behaviour).

##### 2. Status and code

Status: built for the forwarder and the actions; not wired into the controller; the dashboards pack is missing.

- `internal/integrations/splunk/hec.go`: `Forwarder` (bounded queue, batching, retries, TLS verification on by default, statistics), `SendEvent` (a Phylax event as a HEC event).
- `internal/actions/splunk_actions.go`, `splunk_api.go`: `splunk.hec_setup` (creates the `phylax` index and an HEC token bound to it through the management API on 8089; never modifies existing indexes or tokens), plus `splunk.rest`, `splunk.password`, `splunk.sidecar_off` (see Actions for ownership).
- `plans/splunk.forwarding.yaml`: HEC setup, firewall for 8088, a TCP probe, and a syslog fallback input.

Missing: the controller module (subscribes to events, owns the forwarder, reads the token from the vault, reports statistics), the kind selection, the dashboards pack and the node that installs it, and the declaration of scored indexes that the setup action must refuse.

##### 3. Capability manifest

```go
module.Manifest{
	Name:      "splunk",
	Sides:     []module.Side{module.SideController},
	OS:        nil,
	Privilege: "none",
	Roles:     []string{"controller"},
	Consumes:  []string{"detect.alert", "auth_event", "winevt.sec_event", "process_start" /* opt-in */, "chains.*", "devices.*" /* see Configuration */},
	Emits: []event.Type{ /* splunk.forwarder_state v1 */ },
	Budget: module.Budget{
		CPUMillisPerSec: 30, HeldMB: 8, EventsPerSec: 1, Burst: 5,
		BytesOutPerMin: 24 << 20, DiskMB: 0, // BytesOutPerMin here counts HEC bytes sent
	},
	Default:  false, // opt-in
	Tables:   nil,
	Content:  []string{"plans/splunk.forwarding.yaml", "splunk/dashboards"},
	Actions:  []string{"splunk.hec_setup"},
	Pages:    nil,
	Evidence: []string{"[IJ]", "[PRO §10]", "[[cyberuci-locs#e20]]", "[[cyberuci-locs#e23]]"},
}
```

The queue holds 1024 events and drops on overflow, so held memory is small. `shortcut: budget numbers are estimates, replace with Invitational measurements`.

##### 4. Configuration

`integrations.yml` declares the sensor; `modules/splunk.yml` the forwarder.

```yaml
# integrations.yml (excerpt)
splunk:
  enabled: true
  host: debian-splunk          # the scored Splunk host; from hosts.yml
  hec_url: https://172.20.240.20:8088
  mgmt_url: https://172.20.240.20:8089
  index: phylax
  token_name: phylax-hec
```

```yaml
# modules/splunk.yml
secrets: { hec_token: splunk.hec, mgmt: splunk.mgmt }   # vault names; the HEC token is written by splunk.hec_setup
ca_secret: ""
insecure_tls: false                                    # true only for lab self-signed certificates
source: phylax
sourcetype: _json
forward:                                               # event kinds to forward; wildcard allowed at the end
  - detect.alert
  - auth_event
  - winevt.sec_event                                   # only the categories listed below
  - chains.*
  - devices.*                                          # Palo and VyOS deny and change logs (kind names as declared by `devices`)
  # - process_start                                    # off by default: volume; turn on for the process-tree view
sec_event_categories: [group_change, account_change, service_install, scheduled_task, wfp_connection, log_cleared]
queue: 1024
batch: 100
batch_bytes: 524288
flush_sec: 2
retries: 4
timeout_sec: 5
```

```go
// package splunk (controller side)
type Settings struct {
	Secrets            map[string]string `json:"secrets"` // hec_token, mgmt: vault names
	CASecret           string            `json:"ca_secret,omitempty"`
	InsecureTLS        bool              `json:"insecure_tls,omitempty"`
	Source, SourceType string            `json:"source,omitempty"`
	Forward            []string          `json:"forward"`
	SecEventCategories []string          `json:"sec_event_categories,omitempty"`
	Queue, Batch       int               `json:"queue,omitempty"`
	BatchBytes         int               `json:"batch_bytes,omitempty"`
	FlushSec, Retries  int               `json:"flush_sec,omitempty"`
	TimeoutSec         int               `json:"timeout_sec,omitempty"`
}
```

The defaults (queue 1024, batch 100 events or 512 KiB, flush every 2 s, 4 retries, request timeout 5 s, index `phylax`, source `phylax`, sourcetype `_json`) are the forwarder's built-in values.

##### 5. Events

Consumed: the kinds in `forward`. `process_start` is opt-in. `devices.*` and `chains.*` are patterns; the exact kind names are those the `devices` and `chains` sections declare (open item).

Emitted:

| Kind | Priority | Key fields |
| --- | --- | --- |
| `splunk.forwarder_state` | normal, high when failing | `sent`, `dropped`, `retries`, `failed` (cumulative), `last_error`, `queue_len`. One event per 60 s and on every change of state (`ok`, `failing`, `dropping`) |

##### 6. Behaviour

**Setup (plan `splunk.forwarding`).**

1. `splunk.hec_setup` creates the `phylax` index and a HEC token bound to it through the management API. It never modifies existing indexes or tokens: an existing token bound to a different index is refused ("refusing to rebind it"), an existing disabled token is a human decision, a built-in index name is refused. If the HEC input is globally disabled it is enabled, and the rollback disables it again if the action enabled it. The token value is returned as `secret.token` and goes to the vault; it is never logged.
2. `firewall.allow` for port 8088 from the LAN with a dead-man window.
3. `net.tcp_probe` to port 8088.
4. A syslog fallback input (UDP 514 into the `phylax` index) for firewall logs if HEC is unavailable. This opens a listener on the scored Splunk host, so it is a gated node with its own approval, not part of the default path.

The plan's index never matches the index the scored Splunk check searches [SH §11]; see Scoring safety.

**Forwarding.** The module subscribes to the kinds in `forward` through the controller's `Host.Subscribe`, converts each event with `SendEvent` (adds `phylax_kind`, `phylax_agent`, `phylax_seq`, `phylax_hash` and all event fields to the HEC event, using the event time), and hands it to the forwarder. `Send` never blocks: it appends to a bounded queue and returns; on overflow the event is dropped and counted. Batches go out by count (100), by size (512 KiB) or by interval (2 s). A network error, 429 or 5xx is retried with doubling backoff (500 ms start, 30 s cap, 4 retries); 400, 401, 403 and 404 are permanent for that batch and counted as `failed`. `Close` flushes within its deadline. TLS verification is on; it is turned off only for lab self-signed certificates, or a CA is given.

A dead Splunk therefore only increments counters. The statistics (`sent`, `dropped`, `retries`, `failed`) produce a platform alert when `failed` or `dropped` grows, and appear on the Platform page.

**Dashboards pack (review D440).** A small set of dashboards over the `phylax` index, kept in `splunk/dashboards/` as Simple XML views, with parameters for the index so the same files work if the index name is overridden. Views:

- *Logons:* `auth_event` by account, source, service and result (including the scored accounts and failures), from Linux logs and Windows 4624/4625.
- *Group changes:* Security group membership changes (4728, 4732, 4756 and removals) and Linux group edits.
- *Services:* service installs (7045, 4697) and unit changes.
- *Firewall events:* host firewall denies (NFLOG, 5157), Palo and VyOS deny and change logs.
- *Service health:* the checks' pass and fail by service over time (from `checks` results).
- *Lateral movement:* admin logons (type 3 and 10), admin-share access and remote service creation grouped by source.
- *Process tree by ProcessGuid:* `process_start` events by parent and child using the Sysmon ProcessGuid (requires `process_start` forwarding on).

The views are installed by a plan node that writes them under Phylax's own Splunk app directory (not into the `search` app or any organizer app), so they cannot change a scored search. Splunk loads views from an app's `data/ui/views`; whether a splunkd restart is needed is verified in the lab (a restart of the scored Splunk would be a scorer-visible touch and would need a quiet window). Keep the pack small: more views are cheap to write after the inject names them.

**Organizer toolkit and audit rules.** If the environment's Splunk host or the Windows hosts ship an organizer-installed toolkit (forwarders, `inputs.conf`, audit rules), it is part of the image. Its files are unknown at the first ledger sweep and go to the prebake hunt's triage queue (not alerts, review A5 answer D356/D392), and its audit rules are foreign rules to `audit` (the module manages only `phylax`-keyed rules; only foreign `never` rules are reported). No coexistence logic is built (decision 12). The dashboards read the `phylax` index and do not depend on the toolkit's sourcetypes.

##### 7. Actions and content

| Action | Where | Risk | Locks | Scorer-visible touches |
| --- | --- | --- | --- | --- |
| `splunk.hec_setup{index, token_name}` | controller, over the 8089 management API | service | none | creates one index and one token, enables HEC if it was disabled (opens 8088), restarts nothing; never touches an existing index, token, search or role |

The same files hold actions owned elsewhere: `splunk.rest` (GET only, search endpoints refused, used by hardening reads) and `splunk.sidecar_off` (disables the Splunk PostgreSQL sidecar, CVE-2026-20253 workaround; a `fh.splunk.sidecar_off` first-hour node) belong to `hardening`; `splunk.password` (rotates a Splunk user's password through a guarded action) belongs to `creds`. `splunk.hec_setup` is the only integration action of this module (review D168).

Content: `plans/splunk.forwarding.yaml`, `splunk/dashboards/*.xml`, and the node that installs the dashboards.

##### 8. UI

A Platform section "Splunk": forwarder state, counters, last error, queue length. No page of its own. The Splunk dashboards are viewed in Splunk. The inject evidence recipe (the dashboards screenshot) is a `report` evidence run.

##### 9. Health

States: `disabled`; `ok` (sent grows or nothing to send, no failures); `degraded` (retries, or events dropped since the last report, or the last batch failed); `unavailable` (no token in the vault, HEC refuses authentication). Gaps: `HEC token missing in the vault`, `HEC unreachable: <err>`, `N events dropped (queue full)`, `index phylax not found`. Phylax never waits on Splunk.

##### 10. Scoring safety

Splunk query and management on 8089 are scored. The module's scoring rules:

- It touches no index the scored query searches. The setup creates a new index and a token bound to it and refuses built-in index names (`main`, `summary`, `history`, `defaultdb`, `lastchanceindex`, `splunklogger`, `notable`, `risk`). The scored index names are not known to the action: the manifest must declare the indexes the scored Splunk check reads, and the action must refuse them (open item).
- It never rebinds an existing token or enables a disabled token.
- It reads no searches, saved searches, dashboards or roles. `splunk.rest` is separate, GET only, with search endpoints refused.
- HEC opens port 8088 on the scored host, the forwarding plan adds a firewall allow for it, and a syslog input would add UDP 514; none of these is a scored port, but both are listeners on a scored host and each has a complexity-register line and a lint check that the allow does not narrow a scored port (decision 13).
- Splunk resource use rises with ingestion; the forwarder's queue and batch limits bound the rate, and the 8089 query path is separate.
- Alert-only stage: forwarding is passive. Setup runs as a plan node with a dead-man window (the rollback deletes what the action created).

##### 11. Tests

Built: forwarder tests (batching by count, bytes and interval, retry on network error, 429 and 5xx with backoff, permanent on 400, 401, 403 and 404, overflow drops and counts, `Close` flushes within the deadline, TLS defaults); Splunk action tests with a fake API (index and token creation, refusal to rebind, refusal of a disabled token, built-in index refusal, HEC enable and rollback, verify).

To build: the controller module (subscribe, convert, state events), `sec_event_categories` filtering, the dashboards install node, the scored-index refusal, the platform alert, conformance (starts disabled with no config; starts with a default config against a fake HEC; stops within 5 s and flushes; emits only declared kinds; budget; reconfiguration changes the forward list without losing the queue; `go test -race`).

Lab tests: HEC token creation on the scored Splunk, and confirmation that the `phylax` index is unscored and that the views load without a restart. A real Quotient round must pass during the setup (the "needs the lab" list). Invitational question E19 (Splunk specifics: indexes, forwarders, inputs, HEC and REST enabled, local users, RAM and CPU use, management exposure, the scored search content).

##### 12. Limits and open items

- `shortcut: the forwarder queue is in memory, so events are lost on a controller restart; the controller's store is the record, add a replay from the store only if Splunk evidence must survive restarts`.
- `shortcut: no indexer acknowledgement; HEC acknowledgements are not used, delivery is best effort`.
- Open: the exact `devices.*` and `chains.*` kind names that carry Palo logs and the chain timeline (declared in those sections). The list in `forward` must use them.
- Open: the scored Splunk search's index (or indexes) must be declared in `services.yml` so `splunk.hec_setup` can refuse it. Today only built-in names are refused.
- Open: whether views need a splunkd restart; if they do, the install node is gated by a quiet window.
- Open: `process_start` forwarding volume. The process-tree view needs it; turn it on only when the inject names the view, and watch the drop counter.
- Core change request: `Host.Subscribe` already exists in the controller `Host`; no core change. The module relies on controller-origin events being stored under agent `controller`.
