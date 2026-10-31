#### `wazuh`

##### 1. Purpose and evidence

`wazuh` is the optional Wazuh integration: a deploy plan for a Wazuh manager and agents, read-only actions that check it and capture evidence from it, and a controller-side poller that imports Wazuh alerts as low-priority context and reports the health of the deployment. Phylax owns orchestration, integrity, chains and checks; Wazuh is an optional sensor whose health Phylax monitors. Nothing on the critical path depends on it (D-9, design principle 15). It is off unless the manifest enables it.

Why it matters for points:

- The injects recur. "Configure End-Point Protection Software" came as SVRA12T in the 2026 qualifier (where we deployed a Wazuh manager and agents) and as SOFT04A in the 2026 regional, and has appeared in 6 events across 4 seasons. Central logging (SOCS30T, TOOL29T) has appeared in 16 events across 9 seasons [IJ, PRO §10]. A deploy plan that is ready before the inject lands saves the team the hand work and gives detection the whole time (review D434).
- Wazuh adds FIM, rootcheck and configuration assessment (SCA) as a second opinion and a central dashboard for the screenshots those injects ask for.
- Placement is configuration, not an event profile (decision 4).

Evidence against, and what it implies:

- The Wazuh manager can push configuration and commands to every agent, so whoever owns the manager owns every agent. The manager's host is a tier-0 asset. Remote commands are therefore disabled on agents and Wazuh active response is disabled, because response is Phylax's and typed (review D353, OSS-EDR report: Wazuh active response and Velociraptor `execve` are lateral-movement paths).
- Wazuh `authd` password enrollment is a repeated CVE source (CVE-2025-24016 and the 2026 `authd` and API bugs). The plan pins a fixed version and stops `authd` after enrollment [SV R2.3.6].
- Peer: SigPwny's "slop" deployment runs a Wazuh 4.9 server on the Splunk host and uses ports 1514, 1515 and 55000. Wazuh's value here is the dashboard and the inject evidence, not Phylax's detection.

Wazuh rules are GPL-2.0: Phylax reads Wazuh alerts and never copies Wazuh rule text.

Decisions applied: review D434 to D437 kept (deploy plan 4.14.9 or newer with an offline bundle; placement; agent safety; `wazuh.deploy` and `wazuh.health`). D438 (the evidence pack) becomes one evidence-run recipe in `report` (N10.3). D168 lists the integration actions; `splunk.hec_setup` is in `splunk`, `suricata.analyze_pcap` in `suricata`, and `av.clamav` is cut. Decision 12: no Defender Toolkit coexistence work.

##### 2. Status and code

Status: partial.

Built:

- `internal/integrations/wazuh`: `client.go` (API client: JWT with re-auth on 401, manager info, agents, groups with config checksums, `Health` with active, disconnected and never-connected lists, indexer alert query), `poll.go` (`Poller`: imports alerts as events and de-duplicates the overlap at the time boundary), `version.go` (`MinVersion` 4.14.9, numeric comparison, `CheckManager` refuses a manager older than the minimum, `CheckAgents` refuses any agent newer than the manager). TLS verification is on unless `InsecureTLS` (lab self-signed certificates) or a CA is given.
- `internal/actions/app_wazuh.go`: `wazuh.health` (read-only: version pin, no agent newer than the manager, counts, optional `min_active`), `wazuh.capture` (writes `health.json`, `agents.json`, `agents.csv`, `groups.json`, `group_details.json` to a directory), `wazuh.test_alert` (appends a marker line to a log under `/var/log` so a test alert fires).
- `plans/wazuh.deploy.yaml` (the deploy plan) and `plans/wazuh.evidence.yaml` (the evidence recipe), validated by the plan package against the action catalogue.
- Supporting core actions the plan uses: `pkg.install` (depot source), `firewall.allow`, `xml.set`, `file.write`, `service.state`, `agentopt.set` (Windows `local_internal_options.conf`).

Missing:

- No controller module: nothing starts the `Poller`, schedules `wazuh.health`, converts results into `wazuh.health` events or reports to the Platform page.
- No uninstall plan (v3: "A plan removes it if it misbehaves").
- No memory cap node for the manager when it is placed on the Splunk host (v3: cgroup cap; `systemd.dropin` exists, the plan does not use it).
- The real 4.14.9 bundle is not in the depot yet; the indexer and API field names on the real build are unchecked; the RAM headroom for placement is unmeasured.
- `wazuh.deploy` is a plan template, not an action. The core catalogue row "Integrations: `wazuh.deploy`, `wazuh.health` …" means the plan and its actions.

##### 3. Capability manifest

```go
module.Manifest{
	Name:      "wazuh",
	Sides:     []module.Side{module.SideController},
	OS:        nil,
	Privilege: "none",
	Roles:     []string{"controller"},
	Consumes:  nil,
	Emits: []event.Type{ /* wazuh.alert v1, wazuh.health v1 */ },
	Budget: module.Budget{
		CPUMillisPerSec: 20, HeldMB: 16, EventsPerSec: 5, Burst: 50,
		BytesOutPerMin: 1 << 20, DiskMB: 0,
	},
	Default:  false, // opt-in
	Tables:   nil,
	Content:  []string{"plans/wazuh.deploy.yaml", "plans/wazuh.evidence.yaml"},
	Actions:  []string{"wazuh.health", "wazuh.capture", "wazuh.test_alert"},
	Pages:    nil, // a Platform section and alert context
	Evidence: []string{"[IJ]", "[PRO §10]", "[SV R2.3.6]"},
}
```

The numbers are initial limits for the poller. The manager and the agents are separate processes on other hosts and are not charged to this budget; their cost is measured as host load (the RAM headroom question E14 in `docs/impl/invitational-data.md`). `shortcut: budget numbers are estimates`.

##### 4. Configuration

`integrations.yml` declares the sensor (pinned versions and hosts, review D199); the module's block `modules/wazuh.yml` carries the poller settings.

```yaml
# integrations.yml (excerpt)
wazuh:
  enabled: true
  version: "4.14.9"            # manager and agents; agents never newer than the manager
  manager: ubuntu-wkst         # or the Splunk host, memory-capped; chosen by RAM headroom
  manager_addr: 172.20.240.10  # example; from hosts.yml
  allow_from: 172.20.240.0/24  # our hosts and the controller
  linux_agents: [debian-splunk, rocky-web, fedora-mail]
  win_agents: [win-dc, win-ad, win-wkst]
```

```yaml
# modules/wazuh.yml
api_url: https://172.20.240.10:55000
indexer_url: https://172.20.240.10:9200   # alerts are read from wazuh-alerts-* in the indexer
secrets: { api: wazuh.api, indexer: wazuh.indexer }   # vault names, never values
ca_secret: ""                              # vault name of a CA PEM; empty uses system roots
insecure_tls: false                        # true only for lab self-signed certificates
min_level: 7                               # import alerts at this Wazuh rule level or higher (initial value, tune at the Invitational)
poll_sec: 30
min_active: 0                              # health requires at least this many connected agents; the controller sets it to the agent count after enrollment
```

```go
// package wazuh (controller side)
type Settings struct {
	APIURL      string            `json:"api_url"`
	IndexerURL  string            `json:"indexer_url,omitempty"`
	Secrets     map[string]string `json:"secrets"` // api, indexer: vault names
	CASecret    string            `json:"ca_secret,omitempty"`
	InsecureTLS bool              `json:"insecure_tls,omitempty"`
	MinLevel    int               `json:"min_level"`
	PollSec     int               `json:"poll_sec,omitempty"`
	MinActive   int               `json:"min_active,omitempty"`
}
```

Values that vary by event are runtime facts: the manager address, the API and indexer credentials (generated by the deploy plan and stored in the vault, review A7.Q8 for the vault), and the number of agents.

Deploy-plan settings (fixed in `plans/wazuh.deploy.yaml`, overridable by plan `vars`):

| Decision | Setting |
| --- | --- |
| Version | Pinned: manager and agents 4.14.9 or newer, agent not newer than the manager. The 4.7 and 4.14.3 URLs in older playbooks are vulnerable. If no fixed version can be cached, skip Wazuh rather than run an older one |
| Packages | The offline bundle (manager, indexer, dashboard, agent MSI, deb and rpm) is in the cache before the event (`depot`, priority 1); nothing is downloaded at install time |
| Manager placement | A trusted Linux host that is not scored. Default: the Ubuntu workstation if the lab shows at least 8 GB RAM headroom; otherwise the Debian Splunk host under a memory cap (the scored Splunk Web must not starve). Measured in the lab. The first plan node is an approval gate for this |
| Exposure | Ports 1514, 1515, 55000 and 443 allowed only from our hosts. `authd` uses a password and is stopped after enrollment. The dashboard and API credentials are rotated and held in the vault |
| Agent groups | FIM (realtime on `/etc`, `/usr/bin`, `/usr/sbin`; scheduled on the web and Splunk configuration), rootcheck, SCA, and syscollector on, plus log collection for the services' logs |
| Agent safety | `wazuh_command.remote_commands`, `logcollector.remote_commands` and `sca.remote_commands` set to 0 on every agent; active response disabled on the manager |

##### 5. Events

Consumed: none (it reads the Wazuh indexer over HTTPS).

Emitted (controller-origin events are stored under agent `controller`; the code today sets `Agent: "wazuh"`, which the retrofit changes, with the Wazuh agent name kept in a field):

| Kind | Priority | Key fields |
| --- | --- | --- |
| `wazuh.alert` | normal | `alert_id`, `rule_id`, `level`, `description`, `wazuh_agent` (name), `wazuh_agent_id`, `agent_ip`, `location`, `full_log` (truncated). Imported as context: shown with the host's alerts, never a primary alert on its own |
| `wazuh.health` | normal on change, high when degraded | `manager_version`, `version_ok`, `agents_total`, `active`, `disconnected` (names), `never_connected` (names), `agent_newer_than_manager` (names), `error` |

##### 6. Behaviour

**Deploy (plan `wazuh.deploy`).** An ordered DAG with a gate, per-host expansion and health checks; `on_failure: stop_dependents`:

1. `approve-placement` (gate): confirm the manager host has the RAM headroom (at least 8 GB) and that the depot has the 4.14.9 or newer bundle; otherwise skip Wazuh.
2. Manager: `pkg.install` from the depot, `firewall.allow` for 1514, 1515, 55000 and 443 from our hosts (with a dead-man window), active response off, `authd` password on, three agent groups written (`phylax-fim`, `phylax-rootcheck`, `phylax-sca`), then `service.state` restart and `wazuh.health` (version pin).
3. Agents: `pkg.install` on each Linux host (deb or rpm) and each Windows host (the MSI), the manager address set in `ossec.conf`, remote commands off (`file.write` on Linux; `agentopt.set` on Windows because `file.write` path validation is POSIX-only on the controller), `service.state` (Linux unit `wazuh-agent`, Windows service `WazuhSvc`).
4. `wazuh.health` again (all agents connected, no agent newer than the manager), then `authd` disabled and the manager restarted so it accepts no more enrollment.

Order in the game: after credentials and firewalls are done, so it never competes with the work that matters first. A node that cannot run (no bundle, no RAM headroom) stops its dependents and leaves a visible "waiting" cell; the platform does not depend on it.

*Scoring-safe order.* Installs on scored hosts happen after the host's service stack has been backed up (`backup`) and run through the normal lint. FIM groups use scheduled scans except for system binaries and configuration; no realtime watch on a content root.

**Health.** `wazuh.health` and the poller call the API read-only: agent list, last keepalive and status, groups and their configuration checksums. The module runs the health check every poll and compares with the last result. A disconnected agent, a never-connected agent, a manager older than the pin, an agent newer than the manager or a dead API is a `wazuh.health` event at high priority and a Platform alert, because the red team may kill the manager or an agent. The client reads manager version and agent state; it does not read manager CPU and memory (those come from the agent on the manager host).

**Alert import.** The manager API has no alert query, so the `Poller` queries the indexer's `wazuh-alerts-*` indices for alerts since the last seen time at or above `min_level`. It keeps the alert ids seen at the last timestamp so a re-query never yields one alert twice. On an error nothing is consumed and the next poll retries from the same point. Each alert becomes a `wazuh.alert` event.

**Evidence.** The evidence recipe (`plans/wazuh.evidence.yaml`, now an evidence-run recipe in `report`, review N10.3 and D438) runs `wazuh.health`, `wazuh.capture` (the agent list export with id, name, IP, version, status and last keepalive), hashes the group configuration files, appends a marker with `wazuh.test_alert` so a test alert is generated, and ends at a gate where a human takes the dashboard screenshots (agents, FIM, SCA, the test alert). The files are saved into the inject kit. Whether graders accept a transcript for a screenshot is unknown (test at the first event).

**Uninstall (to build).** A plan removes the agent (stop the service, `pkg.remove`) and the manager; it exists for when Wazuh misbehaves on a scored host.

##### 7. Actions and content

| Action | Where | Risk | Locks | Scorer-visible touches |
| --- | --- | --- | --- | --- |
| `wazuh.health{api, min_version, min_active}` | controller (runs on the manager target in the plan) | none, read-only | none | none |
| `wazuh.capture{api, out, min_version}` | same | none, read-only | none | writes the output directory under the inject kit (a controller path) |
| `wazuh.test_alert{path, marker}` | agent on the manager host | none | none | appends one line to a log under `/var/log` (path must be a clean file under it) |

Content: `plans/wazuh.deploy.yaml`, `plans/wazuh.evidence.yaml`, the agent group files embedded in the plan. Package actions come from `depot`; firewall, file and service actions from the core.

##### 8. UI

A Platform section "Wazuh": manager version and pin state, agents connected out of total with the names of the disconnected, last import time and the count imported in the last hour. `wazuh.alert` events show as low-priority context under the host in the alert queue and in pivots. The plans appear on the Plans page. No page of its own.

##### 9. Health

States: `disabled` when not enabled; `ok` when the manager is at or above the pin, no agent is newer, and every enrolled agent is active; `degraded` when an agent is disconnected or never connected, or the indexer is unreachable (alerts are not imported but the manager may be fine); `unavailable` when the API cannot be reached or authentication fails. Gaps: `agents disconnected: <names>`, `manager below 4.14.9`, `alerts not imported: indexer unreachable`, `no fixed bundle in the cache; Wazuh skipped`. Health is shown on the Platform page. Nothing blocks on it.

##### 10. Scoring safety

- The manager host is not a scored service host. If it has to be the Splunk host, the manager runs under a memory cap and the plan's firewall rules never touch a scored port; Splunk Web (8000) and management (8089) are untouched. A source-restricted allow on 1514, 1515, 55000 or 443 is acceptable only because none of them is scored; the scoring lint (decision 13: never narrow a scored port to a source allowlist) refuses the node if the manifest says otherwise on that host.
- Agents add CPU, memory and file-scan load to scored hosts. FIM scans are scheduled (600 s), realtime only on system paths, SCA every 12 hours, and installs go through the usual approval, backup and probe.
- Agents run no remote commands and the manager has active response off, so Wazuh cannot be used to run code on scored hosts.
- Alert-only: the module only reads. Installing is a plan node with an approval. Deploy ordering keeps it behind credentials and firewalls.

##### 11. Tests

Built: client tests against a fake API and indexer (auth and re-auth, version parse and pin, agent newer than manager, health counts, groups, alert query, truncation), poller de-duplication at the boundary, the three actions with fakes (health pin and `min_active`, capture file set, test alert path and marker validation, append only), and plan validation of the two templates against the action catalogue.

To build: the controller module (poll loop, health event on change, backoff), `wazuh.alert` conversion with the retrofit agent name, the uninstall plan, the memory-cap node, the kind declarations, conformance (starts with no config and with the integration disabled; default config against a fake API; stops within 5 s; emits only declared kinds; budget; link loss does not apply on the controller side, store errors do; reconfiguration; `go test -race`).

Lab tests: T40 offline drill (the Wazuh deploy works from the cache with the internet blocked), the first real run on ccdc27 without a failed Quotient round (the "needs the lab" list: the real 4.14.9 bundle and its hashes in the depot, indexer and API field names on the real build, RAM headroom for manager placement, the Windows service name `WazuhSvc` and the `ossec.conf` path per version). Invitational question E14 (resource headroom, `ubuntu-wkst` first) decides placement.

##### 12. Limits and open items

- `shortcut: alerts are imported by polling the indexer every poll_sec, not pushed; fine for context, tighten only if the alert delay matters for an inject`.
- `shortcut: manager CPU and memory are not read through the API; use the manager host's agent health instead`.
- Open: the right `min_level` is unknown; it is an initial value to tune from the Invitational (R15: how many imported alerts are actionable).
- Open: controller-origin event naming. `wazuh.alert` currently has `Agent: "wazuh"`; under the envelope it should be `controller` with the Wazuh agent in `wazuh_agent`. Conformance would otherwise flag it.
- Open: whether the manager runs on the workstation or the Splunk host is a measurement (RAM) and a gate in the plan, not a design decision.
- Open: the evidence-run recipe lives in `report`; this module keeps the file `plans/wazuh.evidence.yaml` and the actions it uses until `report` takes ownership. Decide the owner in the `report` section.
- Peer evidence worth revisiting only if Wazuh is dropped from the reference manifest: a team that runs only Splunk plus the organizer toolkit gets the "central logging" inject without it.
