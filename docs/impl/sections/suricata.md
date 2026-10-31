#### `suricata`

##### 1. Purpose and evidence

`suricata` runs Suricata and Zeek offline over a pcap slice that `capture` has frozen and pulled, reads their output (EVE JSON and the Zeek `conn.log` and `dns.log`), turns it into Phylax events, and joins them to every other record about the same flow by Community ID. The results attach to the incident and to the trace-back. Neither tool runs live: the flat LAN has no tap, so there is nothing to run a live sensor on, and a live sensor would be one more daemon in the environment.

Why it matters for points:

- When an alert freezes the packet ring, the pulled pcap holds the exploit, the beacon or the exfiltration. A signature set (ET Open) and protocol logs turn that raw pcap into named detections, URLs, DNS names and connection summaries the IR report needs (IPs, timelines, impact). IR quality is half of the red-team lead's rubric [PKT Scoring 5, TTP §0].
- The join by Community ID lets one string connect the host's own `conn` record, the Palo log, the `capture` flow and the Suricata alert [OA §5.3].
- Zeek and Suricata give a second opinion on a flow that the Phylax protocol parsers might have mislabelled.

Evidence for the shape: CyberHawks run a Zeek sensor with a custom script (`ansible/roles/zeek_sensor/files/cyberhawks.zeek`). Evidence against running them live or as a default: they add a daemon, a rule set to maintain and CPU on the controller host; the Phylax parsers already cover the scored protocols. So the module is on demand, opt-in (D-9), and the controller never depends on it.

Decision (review D439): the readers are built; the runs happen only on demand; set Zeek `ignore_checksums` and Suricata `-k none` for pcaps taken on offloaded NICs (checksum offload leaves wrong checksums in captures on the sending host, and both tools drop such packets by default).

##### 2. Status and code

Status: built for the readers; the run and the action are missing.

- `internal/integrations/suricata`: `eve.go` (`ReadEVE`: alert events, optionally DNS and HTTP context; lines over 1 MiB and malformed lines are skipped and counted; events are sorted by time; `Join` groups events by Community ID), `zeek.go` (`ReadZeek`: `conn.log` and `dns.log` in JSON-lines or TSV form), `communityid.go` (Community ID v1, seed 0, verified against the official test vector; used when a record has none). Tests with `testdata/eve.json`, `conn.log`, `dns.jsonl`.
- Missing: the `suricata.analyze_pcap` action, the runner that invokes the tools on the controller, the shipped minimal configuration, the rules cache entry and the UI action. The controller does not call the readers anywhere yet.

##### 3. Capability manifest

```go
module.Manifest{
	Name:      "suricata",
	Sides:     []module.Side{module.SideController},
	OS:        []string{"linux"}, // the controller host
	Privilege: "none",           // runs the tools unprivileged on a copy of the pcap
	Roles:     []string{"controller"},
	Consumes:  nil,
	Emits: []event.Type{ /* suricata.alert v1, suricata.dns v1, suricata.http v1, suricata.zeek_conn v1, suricata.zeek_dns v1, suricata.run v1 */ },
	Budget: module.Budget{
		CPUMillisPerSec: 500, HeldMB: 256, EventsPerSec: 100, Burst: 2000, // only while a run is in progress
		BytesOutPerMin: 8 << 20, DiskMB: 1024,
	},
	Default:  false, // opt-in, on demand
	Tables:   nil,
	Content:  []string{"suricata/config", "suricata/zeek"},
	Actions:  []string{"suricata.analyze_pcap"},
	Pages:    nil, // an incident tab and a one-click action
	Evidence: []string{"[OA §5.3]", "review D439"},
}
```

CPU and memory apply only while a run is in progress (the controller host is the workstation that also serves the UI), and the run is cancelled when it exceeds them. `shortcut: budget numbers are estimates, replace with Invitational measurements (O3, E14)`.

##### 4. Configuration

`integrations.yml` declares the sensors with pinned versions; `modules/suricata.yml` the run settings.

```yaml
# integrations.yml (excerpt)
suricata:
  enabled: true
  suricata_version: "7.0"    # example; pinned to the cached package
  zeek_version: "6.2"        # example; pinned to the cached package
  rules: et-open             # cached ruleset id in the depot (priority 1)
```

```yaml
# modules/suricata.yml
tools: [suricata, zeek]     # which tools a run uses by default
max_pcap_mb: 256            # larger slices are refused (the ring's own bound)
timeout_sec: 300            # per tool; the process is killed and the run reported failed
include_context: true       # also read EVE dns and http records as bulk-priority context
offload_safe: true          # suricata -k none; zeek ignore_checksums
work_dir: /var/lib/phylax/suricata   # private per-run directory, removed after the run
```

```go
// package suricata (controller side)
type Settings struct {
	Tools          []string `json:"tools"`
	MaxPcapMB      int      `json:"max_pcap_mb,omitempty"`
	TimeoutSec     int      `json:"timeout_sec,omitempty"`
	IncludeContext bool     `json:"include_context,omitempty"`
	OffloadSafe    *bool    `json:"offload_safe,omitempty"` // default true
	WorkDir        string   `json:"work_dir,omitempty"`
}
```

`offload_safe` is on by default because the pcaps come from hosts and from the Palo, and checksum offload is common on virtual NICs; it is a setting only so a lab run on a clean capture can turn it off to test checksum handling.

##### 5. Events

Consumed: none (it is driven by the action).

Emitted (controller-origin events are stored under agent `controller`; the code sets `Agent: "suricata"` or `"zeek"`, changed by the retrofit; `Time` is the packet time in the pcap, not the run time):

| Kind | Priority | Key fields |
| --- | --- | --- |
| `suricata.alert` | high for severity 1, normal for 2, bulk for 3 | `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `community_id` (read, or computed from the 5-tuple), `flow_id`, `signature_id`, `signature`, `category`, `severity`, `action` |
| `suricata.dns` | bulk | the flow fields, `rrname`, `rrtype` (context only) |
| `suricata.http` | bulk | the flow fields, `hostname`, `url`, `method` (context only) |
| `suricata.zeek_conn` | bulk | `uid`, `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `community_id`, `service`, `conn_state`, `duration`, `orig_bytes`, `resp_bytes`. The code names this `zeek.conn`; alias for one release |
| `suricata.zeek_dns` | bulk | the flow fields, `query`, `qtype_name`, `rcode_name`, `answers`. Code name `zeek.dns`; alias for one release |
| `suricata.run` | normal | `pcap_sha256`, `source` (`capture` host, `palo`, `file`), `window`, `tools`, `rules_version`, `flags`, `alerts`, `events`, `skipped` (lines skipped by reason), `duration_ms`, `error` |

Zeek events are named under `suricata` because the contract allows only the named module's prefix (`<module>.<name>`); the module is the integration for both tools.

##### 6. Behaviour

**Input.** A pcap slice from `capture` (the frozen ring, written with `WriteSlice(from, to, ips)` and pulled to the controller as a content-addressed file; the pull needs the agent `fetch` handler, a core task), a slice from the Palo-side capture (`devices`, gated on the licence flag; Palo-side pcap kept per review D244), or a file placed by an operator. The module records the pcap's sha256 and refuses a file over `max_pcap_mb`. The evidence directory holds pcaps encrypted at rest; the module decrypts a copy into a private run directory (mode 0700), runs the tools there, and removes the directory after the run.

**Running the tools.** The controller runs Suricata and Zeek as host binaries; this is the escape hatch (`host.exec`) and is labeled "runs a host binary" in the UI. They are pre-approved, hash-pinned tools on the controller, started with no network and a read-only input:

- Suricata: `suricata -r <pcap> -l <run dir> -k none -c <shipped minimal config> -S <cached rules>`; `-k none` is the offload-safe flag. EVE is configured for alerts, DNS and HTTP only, with no payload logging. Output: `eve.json` in the run directory.
- Zeek: `zeek -C -r <pcap>` (`-C` is `ignore_checksums`); a small script sets JSON output so logs read as JSON lines (the reader also reads TSV). Output: `conn.log`, `dns.log`.

Each tool has `timeout_sec`; a tool that exceeds it is killed and the run is marked failed for that tool, the other still runs. Both run at low CPU priority.

**Reading.** `ReadEVE` and `ReadZeek` stream the files with a 1 MiB line cap; malformed lines and over-long lines are skipped and counted in `suricata.run.skipped`, never fatal. Records without a Community ID get one computed from the 5-tuple (Community ID v1, seed 0), so the join works for tools that do not write it. Events are stored with their packet time.

**Join.** `Join` groups events from all readers by Community ID. The store holds them with the `community_id` field, so the incident view, the trace-back and the chain builder pivot on it; events without a Community ID (some Zeek logs) are kept but not joined. Hosts' own `conn` events from `net` and `capture` flows carry the same ID, so one string connects host, wire and signature views.

**Rules.** ET Open, cached in the depot as a `ruleset` entry (priority 1) with a version recorded in `suricata.run`. The rules are not edited. They are not Phylax content; their license is the ruleset's.

**On demand only.** The module starts nothing at boot. A run starts from the incident page ("Analyse pcap") or from a plan node. A run for the same pcap hash and ruleset version returns the stored result.

**Not Wazuh and not live.** A live sensor on the LAN is not planned; if one is ever needed it is a separate module with its own complexity-register line.

##### 7. Actions and content

| Action | Where | Risk | Locks | Scorer-visible touches |
| --- | --- | --- | --- | --- |
| `suricata.analyze_pcap{pcap, tools, context}` | controller | none (read-only on the environment; runs host binaries on the controller) | none | none |

Content: `suricata/config/suricata.yaml` (the minimal configuration), `suricata/zeek/phylax.zeek` (JSON output and checksum setting), and the ruleset entry in `depot/index.d`.

##### 8. UI

On the incident page: an action "Analyse pcap with Suricata and Zeek" (registered with `ui.Registrar.Action`) and a tab with the alerts by severity, the DNS and HTTP context, the Zeek connection summary and the joined view by Community ID. On the Platform page: the module's state and the last run. No page of its own.

##### 9. Health

States: `disabled`; `ok` (tools present and hash-verified, ruleset cached); `degraded` (a tool or the ruleset is missing, so a run would be partial; the Gap names it, for example `ET Open rules not cached`); `unavailable` (neither tool installed). A failed run is reported in `suricata.run.error` and in the incident tab, not as a platform failure. Usage reports run CPU and bytes read.

##### 10. Scoring safety

Offline and on the controller only. It sends no packet, opens no listener, touches no scored host and reads a copy of a pcap. The tools run with no network access and cannot reach the LAN. Resource use on the controller host is bounded by `max_pcap_mb`, the timeouts and low priority, so a run cannot starve the UI or the cache sync. Pcaps may hold credentials; they stay in the encrypted evidence directory, the run copy lives in a private directory removed after the run, EVE payloads are not logged, and credential fields in stored events follow the controller's field-encryption rule. Alert-only: it produces events and nothing else.

##### 11. Tests

Built: the Community ID against the official vector, `ReadEVE` over a recorded `eve.json` (alerts, context, severity-to-priority, sorting), Zeek JSON-lines and TSV with `Join`, an over-size line skipped and counted.

To build: the runner (a fake tool script writing known output; timeout kills; exit codes; run directory removal), `suricata.analyze_pcap` argument validation (pcap path inside the evidence area, size cap, tool allowlist), the idempotence of a repeated run, the flags (a test that asserts `-k none` and `-C` are passed), the retrofit kind aliases, conformance (starts disabled with no config; starts with a default config against fake tools; stops within 5 s and kills a running tool; emits only declared kinds; budget under a fixture pcap; reconfiguration; `go test -race`).

Lab tests: real EVE and Zeek samples from a pulled pcap (the "needs the lab" list), the offloaded-NIC case (a capture with bad checksums must yield alerts and flows with the flags on and none with them off, to prove the flags matter), and the joined view for a purple-team campaign.

##### 12. Limits and open items

- `shortcut: the run is one pcap at a time on the controller; add a queue only if analysts start several in parallel`.
- `shortcut: the ruleset is a cached ET Open snapshot, not refreshed during the event; refresh only through the cache index delta`.
- `shortcut: Zeek events without a Community ID in the log are given one computed from the 5-tuple; flows with address translation between the capture point and the host will not join, because the 5-tuple differs on each side of the NAT`.
- Core task: the agent `fetch` handler, so a frozen slice can be pulled to the controller.
- Core change request: add Suricata and Zeek to the controller's pre-approved, hash-pinned `host.exec` tool list. The `host.exec` pre-approval list in the execution engine currently names the package managers, the Sysmon installer, YARA-X, the validators, the services' dump tools, and `nmap` and `xfreerdp` on the Kali.
- Open: the exact Suricata and Zeek versions, the controller packages for them (priority 2 in the depot cache plan, generated when the integration is enabled) and the install path on the controller host.
- Open: the Zeek script and the minimal Suricata configuration are not written; JSON output options differ by version.
- Open: pcaps taken on the Palo may need Palo-specific handling (VLAN tags, NAT); decide when the Palo-side capture is used.
