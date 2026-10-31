#### `report`

##### Purpose and evidence

`report` turns data Phylax already holds into the artifacts the team has to hand in or show: incident reports, and the recurring inject artifacts (inventories, service lists, port tables, diagrams, firewall and device exports, evidence captures, traffic reports, saved queries). It is the only module that renders documents. Everything it makes is a **generator**: a query over the manifest, the event store or a typed probe, plus a renderer. It ships no answer prose.

**The line between a generator and a prewritten response** (review decision 6, A10.Q1). A generator renders facts Phylax holds, or structure taken from a prompt a human enters: a memo shell (header, numbered headings, placeholders), a skeleton with one heading per deliverable, an evidence run, a table built from the manifest. A prewritten response is any text that answers an inject without a fact behind it: policy text, plan text, risk registers, framework mappings, canned summaries. Prewritten material lives in a separate set outside Phylax. Phylax does not track injects, does not reach the inject portal or the scoreboard (they sit behind Authentik and are unreachable from inside), keeps no inject board and exports no event archive (review decision 6, area 11 answer: "Phylax is not a Jira board of inject-related things").

**Screen first, file second** (review A10.Q4). The generators prioritise an on-screen view that a human can screenshot from the controller console and carry out. Files (PDF, CSV, raw config exports) are secondary. They leave the environment by hand: the operator downloads the file in the controller's browser and uploads it to the team Nextcloud, which is expected to be writable from inside and is unverified until the Invitational. There is no upload integration, and none is built unless it turns out to be trivial.

Evidence that the module matters for points:

- **IR scoring.** IR reports need IPs, timelines, cracked passwords, impact and remediation; half of the red-team lead's rubric is remediation of the attack path. A multi-topic IR scores only its best item, and duplicates and reports about stock OS behaviour score negative [PKT Scoring 5], [TTP §0], [[xixsaucexix-century-2026#e6]]. Hence one draft per attack narrative or persistence mechanism, a duplicate check and a stock-behaviour check.
- **Copy-forward mistakes repeat.** Stale templates showed up in seven events; 2021Inv D01 was labelled C06; an IR headed "FROM ANOTHER COMPETITION" scored 0 [[how-to-win-ccdc-scoring]]. Hence the pre-submit copy-forward checks.
- **Incomplete answers are the most common inject loss.** Five areas were marked incomplete [[2026-mw-regional-scorecard-t7#e2]]; SOFT07T answered 3 of 6 tasks [[soft07t]]; also [[netw07t]], [[soft08t]]. Hence the prompt-to-skeleton tool with one heading per deliverable.
- **Per-host proof.** About a third of the 2026 prompts want proof from each host (LEGP11T, LINX01A, WINS01A), and teams lose points on "screenshots that don't show fw logs" [[discord-2026q-lessons#e6]]. Hence evidence runs with captioned text figures and a list of screenshots still owed.
- **Mislabelled artifacts.** Our own EVAL11A response mislabelled ports 464, 593 and 636 and mixed TCP and UDP [[eval11a]]; a missing software-version and CVE table cost points in [[2023-mw-regional-eval15a-response#e1]]. Hence services named from observed fingerprints, ports written as `TCP/80`, and a version and CVE table.
- **Inject queries.** Login counts, installed software, sudo and wheel members, failed SSH per source, startup items per host [[bluescreenofwin-stanford-ccdc-25#e14]], [[bluescreenofwin-stanford-ccdc-25#e15]], [[cpp-cyber-blue#e17]]; injects SVRA07T and SVRA02T.
- **File-upload injects.** TOOL26T said "do not respond with a memo; upload the result files". Hence a file export mode with no memo wrapper.
- **Traffic analysis injects.** EVAL08T, NETW05A, NETW06A, NETW14T, SOCS06T, CRYP15A; the concept appears in 14 events.

##### Status and code

Status: **partial**.

| Part | State | Where |
| --- | --- | --- |
| Markdown subset to PDF with `go-pdf/fpdf` and embedded Go TrueType fonts, ToUnicode map so text extracts (decision 7) | built | `internal/report/pdf.go`, `extract.go` |
| IR drafter from a chain, trace-back, detection and evidence; self-score checklist; reviewer page | built; one draft per chain or campaign today | `internal/report/ir.go`, `irchecklist.go`, `rubric.go` |
| Evidence figures (screenshots, host log excerpts) with hashes and house captions | built | `internal/report/evidence.go` |
| Inject kit renderer: memo, config memo, policy, extension request | built | `internal/report/inject.go`, `inject-kit/*.md.tmpl` |
| Pre-submit validator on the final PDF | built, without the copy-forward checks | `internal/report/validate.go` |
| File names `incidentNN_teamTT.pdf` and `injectNN_teamTT.pdf`; Central time helpers | built | `internal/report/names.go` |
| Controller glue and UI: drafts table, review page, figure upload, download | built | `internal/controller/report_*.go`, `internal/ui/reports.go`, store table `report_drafts` (migration 4) |
| Wazuh evidence plan | built; becomes one evidence-run recipe | `plans/wazuh.evidence.yaml` |
| Generator engine, generated artifacts, on-screen views, prompt-to-skeleton, evidence-run recipes, saved queries, traffic report, device exports, copy-forward checks, duplicate and stock-behaviour checks, one draft per narrative, hunt-finding drafts | missing | |

**Code to delete** (git history is the archive): `inject-kit/policy.md.tmpl`, `inject-kit/extension-request.md.tmpl`, the `InjectPolicy` and `InjectExtension` kinds in `inject.go` with `Statement`, `DoneRow` and `RemainRow`, and their tests (review D490, decision 6). `memo.md.tmpl` and `config-memo.md.tmpl` merge into one memo shell: the host summary table appears when host rows are supplied. Every Typst reference in docs and comments goes (Known bug 3). `docs/report.md` must also be fixed where it reads `team`, `forbidden_words` and the NISE upload as the module's own behaviour (see Configuration).

##### Capability manifest

| Field | Value |
| --- | --- |
| Name | `report` |
| Sides | controller |
| OS | both (it runs on the controller and reads facts about both) |
| Privilege | none |
| Roles | `controller` |
| Consumes | `detect.alert`, `chains.chain`, `chains.remediation`, `hunt.finding`, `hunt.completed`, `integrity.verdict`, `capture.flow`, `capture.txn`, `capture.evidence`, `scorer.round`, `checks.result`, `vantage.scan`, `listener`, `net.egress_denied`, `net.canary_result`, `agent.step_result`, `backup.taken`, `devices.backup`, `devices.traffic`, `teamfeed.say`, `teamfeed.claim` |
| Emits | `report.draft`, `report.validated`, `report.figure`, `report.export` |
| Budget | CPU 200 ms/s (a PDF render is a burst of about a second), held 64 MB, 1 event/s, burst 10, bytes out 20 KB/min, disk 512 MB (figures, exports and rendered files under `<data_dir>/reports/`) |
| Default | core |
| Tables | `report_drafts` (exists; its migration moves from the controller's list into the package), `report_figures` (figure metadata, so a figure survives a draft deletion for audit) |
| Content | `reports/generators/*.yml`, `reports/queries/*.yml`, `reports/evidence/*.yml`, `reports/lint.yml`, `inject-kit/` (the memo shell only) |
| Actions | none on agents. Evidence runs are plans made of existing read-only actions (`probe.run` and others), proposed through `Host.Propose` |
| Pages | `/reports`, `/reports/{id}`, `/artifacts`, `/artifacts/{id}`, `/evidence`, `/queries` |
| Evidence | the citations in the first part |

The kinds named under Consumes are the kinds the owning modules declare. Where a sibling section has not fixed a name (`chains.*`, `hunt.*`, `backup.*`, `teamfeed.*`), the name above is binding on that section.

##### Configuration

```yaml
# manifest/modules/report.yml
enabled: true
next_incident: 1            # first number offered; later drafts continue after the highest used
next_inject: 1
forbidden_words: []         # words the validator must not find in a deliverable (names left over from earlier events)
figure_max_mb: 8            # screenshot upload cap
generators: []              # empty: every file under reports/generators/ is offered
lint:
  stale_template: true      # copy-forward checks
  duplicate_ir: true
  stock_behaviour: true
  past_tense: true          # the lint for sections marked forward-looking
```

The team number is not in the module's block. It is the manifest's `team` (topology.yml, overridden at runtime), the single source (principle 5); the module uses it in file names and for the other-team-number check. The event dates for the copy-forward check are a runtime fact: `overrides.yml` `event: {start, end}`, entered in the UI, because the repository is frozen before the access week. Without them the date check is skipped and reported as a gap.

```go
// package report (internal/report)
type Settings struct {
	NextIncident   int      `json:"next_incident"`
	NextInject     int      `json:"next_inject"`
	ForbiddenWords []string `json:"forbidden_words"`
	FigureMaxMB    int      `json:"figure_max_mb"`
	Generators     []string `json:"generators"`
	Lint           struct {
		StaleTemplate  bool `json:"stale_template"`
		DuplicateIR    bool `json:"duplicate_ir"`
		StockBehaviour bool `json:"stock_behaviour"`
		PastTense      bool `json:"past_tense"`
	} `json:"lint"`
}
```

A **generator file** is content. This is the port matrix, which is the shape every table generator takes:

```yaml
id: port_matrix
module: report
title: Port and protocol matrix
kind: table                    # table | diagram | text | file
views: [screen, pdf, csv]
source:
  manifest: services           # projection of services.yml and hosts.yml
  join:
    - { store: listener, by: [host, port, proto], take: [exe, service] }
columns:
  - { name: Host,        from: host }
  - { name: Port,        from: "{{upper proto}}/{{port}}" }       # always TCP/80, never "80" or "80/tcp"
  - { name: Service,     from: service, fallback: kind }          # observed fingerprint first, manifest second
  - { name: Process,     from: exe }
  - { name: Exposure,    from: exposure }                         # public, LAN only, localhost
  - { name: Expected,    from: declared }
  - { name: Unneeded,    from: undeclared }
  - { name: Remediation, from: remediation }
sort: [host, proto, port]
```

##### Events

Consumed: the list in the capability manifest. Emitted:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `report.draft` | 1 | normal | `id`, `type` (`ir_chain`, `ir_finding`, `inject`, `skeleton`, `evidence_run`, `export`), `refs` (chain id, finding id, inject number), `state` (`new`, `edited`, `validated`, `downloaded`) |
| `report.validated` | 1 | normal | `id`, `ok`, `failed` (check ids), `warned`, `pages`, `words` |
| `report.figure` | 1 | normal | `draft`, `n`, `kind` (`screenshot`, `host_log`, `probe`, `canary`), `host`, `taken` (UTC), `sha256` |
| `report.export` | 1 | bulk | `generator`, `artifact`, `format` (`pdf`, `csv`, `file`), `sha256`, `bytes` |

Every download is also audited by the UI shell before the handler runs, so a download is always on record.

##### Behaviour

###### The generator engine

One engine serves every artifact (cross-cutting idea 6). A generator names its data source, its columns or layout, and the views it supports. Sources are a manifest projection, a store aggregation (kind, filters, `group_by`, `count`, `distinct`; no SQL) or a typed probe. Renderers are Go: `table`, `diagram`, `text` and `file`. A new table generator is a YAML file. A new renderer or source type is Go and needs a reason.

**Views.** Every generator has a screen view at `/artifacts/{id}`, built to screenshot well from outside the environment:

- one table or one figure per screen, content width at most 1100 px, text at least 14 px, light background, no horizontal scroll, stable sort order, nothing that shows only on hover;
- a caption bar with the generator's title, the scope (hosts or label expression) and the generation time in Central time with UTC alongside;
- long tables split into pages of 40 rows with a visible page index, so each screenshot is a whole page;
- `?clean=1` hides the shell navigation and the session name, so a screenshot shows only the artifact.

The PDF view renders the same rows through the pure-Go PDF renderer. The CSV view is the raw table. The three views read one result set, so they cannot disagree.

###### Generated artifacts

| Artifact | From | Notes |
| --- | --- | --- |
| Asset inventory | manifest hosts, `inventory` snapshots | OS, version, role, addresses (internal and public), declared services |
| Service list | manifest services, observed listeners | scored flag, owner host, process, version |
| Port and protocol matrix | `listener` events, manifest | Services are **named from the observed fingerprint** (the protocol parser's verdict) and fall back to the manifest kind. Ports are written `TCP/80` and `UDP/53`, TCP and UDP never mixed in one cell. Our own EVAL11A answer called 464, 593 and 636 by the wrong names [[eval11a]]. An **expected / unneeded / remediation** column comes from the manifest: expected means declared, unneeded means listening but undeclared, remediation says what closes it. |
| User and group listing | `inventory` accounts, `ad` hunt output | local and domain, privileged flag from the allowlist |
| Firewall policy summary | rendered policy from the manifest, device snapshots | per host and per device; scored ports show as allow-any-source |
| Network and data-flow diagram | manifest topology and `depends_on`, observed flows | Layout is computed once (segments as columns, hosts as boxes, edges from dependencies and observed east-west flows) and drawn two ways from the same coordinates: SVG for the screen, `fpdf` line and rectangle calls for the PDF. No graph library. |
| Backup schedule with restore times | `backup.taken`, `backup.restored` | restore times are the measured ones |
| Logging coverage matrix | module health and gaps per host | which telemetry each host has and which it lacks, from the heartbeat's `Health` blocks |
| Software version and CVE table | `inventory` software rows joined with `vuln` findings | If `vuln` is off the CVE column reads "vuln module off", never empty (review D492, [[2023-mw-regional-eval15a-response#e1]]) |
| External scan report | `vantage.scan` events | kept from the old evidence packs (review D493) |

Printed per-role checklists are not here. They moved to the host x step grid in the UI shell (review D208, N11.4); a print view of the grid is the fallback.

###### Memo shell

The only document template that ships is the memo shell: the header (To, From, Date in Central time, Subject beginning with the inject number), numbered headings, an optional host summary table, a figure list and a contact line. Its inputs are `{{f "key" "hint"}}` fields. It contains no answer text. The inject number is the first text in the PDF. The team number reaches only the file name; the template cannot see it.

###### Prompt to skeleton

The operator enters the inject prompt, or just its list of tasks, in the UI (`/reports`, "New from prompt"). The portal is outside the environment and there is no clipboard from the machine that shows it (review A7.Q5), so the practical input is a list typed one deliverable per line. Pasted text works the same. The extractor is plain string handling, no model: numbered and lettered items, lines under "Deliverables" or "Requirements", and imperative sentences that begin with a verb from a list in `reports/lint.yml` (provide, submit, include, list, document, describe, identify, explain, create). It builds a **skeleton**: one numbered heading per deliverable in the prompt's order, each with a `[[FILL: deliverable N]]` placeholder and a "screenshots owed" counter.

Validation fails while any deliverable heading is unanswered (placeholder still present, or an empty body). Two lints warn: **blank headers**, and **past tense in sections the operator marked forward-looking** (a plan or policy section that says "we did"). The extraction rules are content, so a prompt style the extractor misses is fixed by editing `reports/lint.yml`. This is a generator built from the prompt, not a prewritten answer (review N10.2, A10.Q1).

###### Evidence run

An evidence run answers "show this on every relevant host" (review N10.3). A recipe in `reports/evidence/` lists steps, each naming a typed probe (`probe.run`, owned by `inventory` and `hunt`), a host selector (host names or a label expression) and a caption:

```yaml
id: sshd_hardening
module: report
steps:
  - { probe: sshd_effective_config, params: { keys: [PermitRootLogin, PasswordAuthentication, MaxAuthTries] },
      hosts: "linux && !workstation", caption: "sshd effective configuration" }
  - { probe: firewall_ruleset, hosts: "linux", caption: "host firewall rules in force", screenshot: true }
```

Running a recipe proposes one plan (`Host.Propose`) with one `probe.run` node per step and host. All nodes are read-only (risk class `none`), so approval is one click. When a node finishes, its output becomes a **text figure**: caption in the house format `Figure N: <what it proves> (<host>, taken <Central time>)`, the probe name and parameters, the output in a monospace block, and a SHA-256 of the output. The figure is shown on screen in a terminal-style block that screenshots well, and is attached to the draft.

- **Probes, not commands.** The module never runs a host command and has no free-form command field. If a recipe needs output no probe yields, the fix is a new probe in `inventory` content (content before code), not a command box here. This keeps `host.exec` out of evidence and keeps the scoring-safety lint able to read every node.
- **Firewall-deny proof** (the recurring "screenshots that don't show fw logs"). The recipe reads the host's latest `net.canary_result` with `result: blocked`, the matching `net.egress_denied` event (the NFLOG record on Linux, 5157 on Windows), and, for the network path, the Palo deny-log entry that `devices` pulled (`devices.traffic`). The figure shows the canary tag, the denial and the log line together. Canaries are sent by the `net` module on its own schedule to non-scored destinations; the recipe does not send traffic.
- **Screenshots owed.** A step marked `screenshot: true` is something a human should capture from the on-screen figure. The skeleton's counter lists, per deliverable, the screenshots expected and the ones attached.
- **Wazuh evidence pack** (review D438, D493). `plans/wazuh.evidence.yaml` (health, agent list, group config hash, test alert, a gate for the human dashboard screenshots) becomes the recipe `wazuh`, available only when the `wazuh` module is enabled. The ClamAV pack is gone (review D441). The Splunk dashboards come from the `splunk` module's dashboards pack; the external scan report comes from `vantage`.
- **Open question.** Whether graders accept a transcript where the prompt says "screenshot" is unknown. The text figure is built to be screenshotted, so the human can submit either. Test at the first event.

###### Inject queries

Saved queries answer the recurring "how many, which" injects (review N10.6, A10.Q3). They are content in `reports/queries/`, in two forms:

- **Probe queries** run on hosts through `probe.run` over `inventory` tables: installed software with versions, sudo and wheel members, startup items and services per host, local users and groups, scheduled tasks.
- **Store queries** are declarative aggregations over events already held: logins per account and host (`auth_event`), failed SSH logins per source address, new accounts, firewall denies per source. Fields are kind, filter, `group_by`, `count` and `distinct`.

Neither form is a query language on hosts. Results appear as a screen table first, with a CSV download.

###### Traffic report

From held captures: protocol hierarchy, top talkers, suspicious flows, a beacon chart and a payload decode (review N10.4). The data is in `capture.flow`, `capture.txn` events and pulled pcap slices, so this is a report section, not a new analyser.

- **Protocol hierarchy and top talkers** by bytes and flows over a chosen window.
- **Suspicious flows:** flows tied to a `detect.alert`, a decoy or honeytoken hit, or a denied-egress ranking entry.
- **Beacon chart:** for one flow key (source, destination, port), the histogram of inter-arrival times with the median interval and jitter ratio, drawn as a server-side SVG bar chart.
- **Payload decode:** the operator picks a stored payload slice. The generator tries single-byte XOR with every key (1 to 255) and ROT1 to ROT25, scores each candidate by the share of printable ASCII, and shows the top five. ASCII only; pure Go.

###### Device and firewall exports

Config exports as files (review N10.5) take their data from the `devices` module's config backups (`devices.backup`: the Palo running config as XML, VyOS `showConfig`) and its read-only `ftd.export` for a Cisco FTD (A6.Q1). The file name is a template the operator fills (`Team<NN>-PA` style names vary by inject). The **file export mode** writes the raw file with no memo wrapper, for prompts that say to upload result files. Before a config leaves the controller, a scrub removes password hashes, pre-shared keys, API keys, SNMP communities and private keys by pattern, replacing each with `[removed]`. The scrub is tested with fixtures from real exports.

###### IR drafter

**Unit of a draft** (review D487). One draft per attack narrative or per persistence mechanism, never per campaign [[xixsaucexix-century-2026#e6]]:

- **Attack narrative:** one chain from `chains`, with its entry hop, access path and impact. If two chains share the same entry vector (same service, same technique), the operator can attach the second to the first draft. A campaign-wide draft is not offered; the campaign page lists its chains, each with its own button (review D304: a campaign is a view).
- **Persistence mechanism:** every hunt finding of severity High gets its own draft: what, where, hash, how found, how removed, times. Persistence that is also a hop of a chain is cross-referenced from the chain's draft ("see IR N"), not re-described.

**Input:** a chain or a hunt finding, with everything the store holds about it: trace-back timeline, alerts, sources, accounts, files, hashes, ledger verdicts, evidence and the response audit trail. Team actions recorded by `teamfeed` (`say`, `claim`) inside the incident's window are listed as "team actions", so our own hand changes are not read as attacker activity.

**Chain draft sections** (carried from v3):

| Section | Filled from |
| --- | --- |
| Header: team number, incident id, times in Central time | Manifest, incident |
| Summary | Recipe sentence, edited by hand |
| Timeline | Chain hops with clock offsets applied, Central time with UTC alongside; guessed hops labelled "inferred, not confirmed" |
| Source and destination | Addresses, ports and protocols from flows and transactions; hostnames from the manifest |
| Accounts and credentials | Accounts used or created; credentials stolen or cracked (D8, honeytoken sightings); what was rotated after |
| Affected systems and services | Hosts and services, and whether scoring was affected (health and scorer history) |
| Technique | ATT&CK ids from the rules, in plain words |
| Evidence | Hashes, ledger verdicts, log excerpts, packet excerpts, quarantined files, figures |
| Attack path and remediation | The chain's remediation items with link method, confidence, stored-event pointers (`agent#seq`) and state (`OPEN`, `APPLIED`, `VERIFIED`), and the proof the hole is closed |
| Containment | The response audit trail and work windows |

**Finding draft sections:** what it is; where (host, path or location, owner, mtime); hash and ledger verdict; how found (hunt check id, rule source, ATT&CK id, time found); impact; how removed (plan id, action, quarantined hash, approver, time) and the clean re-hunt that verified it; what planted it (a cross-reference to a chain, or "entry unknown"); figures.

**The rubric.** The sections map onto the red-team lead's rubric: proof, time of compromise, how it was detected, what the attack was and its impact, how it was mitigated, and (half the marks) remediation of the attack path [TTP §0]. The self-score checklist in `irchecklist.go` carries the rubrics of WinterKnight (`WK-*`), UW-Stout (`ST-*`) and the playbook (`PB-*`). Only `met` earns weight. Operator-only items are never auto-passed: screenshot quality (cursor, cropping, annotation), whether the incident was caused by red rather than a preconfigured service or scorer traffic, and the second-person header re-read.

**Rendering.** The Markdown subset goes through the pure-Go renderer to PDF: one to two pages, exploitation and unsolicited access only, every claim traced to evidence. Facts the controller cannot know are `[[FILL: ...]]` placeholders (detection method if unknown, downtime, the data statement, remediation time, retest steps, figure captions, host and time of figures). `PDF(false)` refuses while any placeholder remains. Every view re-drafts from the stored chain or finding, applies the saved fills and runs the validator again, so the page, the validator and the download always agree; nothing is cached.

###### Pre-submit validator

`ValidateSubmission` keeps its checks: file name and its agreement with number and team; extractable text on every page; the inject number first (IR: `Incident Report N` in the header); team number only in the file name for injects (IR: the From line carries it); forbidden words; every attachment filename appears in the text; no `[[FILL`, angle-bracket placeholders or TODO; the "US Central" label (warning); length sanity (words, pages, file size).

**New: copy-forward checks** (review N10.1), each a `fail` unless noted:

| Check | Rule |
| --- | --- |
| `dates` | A date in the text outside the event window (`overrides.yml` `event`). Skipped, with a gap, when the window is not entered. |
| `reference` | The `Re:` line or the inject code does not match the draft's inject number and code. |
| `addresses` | An IP address or hostname that is not in the manifest, the observed sources of the incident, or an allowlist in `reports/lint.yml`. A warning when only a public address is unknown. |
| `other_team` | A team number other than ours, or the pattern "Team NN" with a different NN. |
| `stale_template` | Text that matches a template fingerprint from a past event kept in `reports/lint.yml` (company names, headings, dates from earlier events). |

**New: IR checks.** `duplicate_ir` fails when two drafts name the same artifact (the same host plus path and hash, unit, task or account, or the same entry source and vulnerability). `stock_behaviour` fails when the subject's hash has an `integrity.verdict` that matches the stock OS image, or the subject is a default scheduled task or service in the host's inventory baseline; both score negative [[xixsaucexix-century-2026#e6]]. Both can be turned off in config.

**Downloads.** A file downloads only when the validator has no failure and no stored figure file has changed since it was hashed; otherwise the response is 409 naming the failed checks. Warnings do not block.

###### File export path

Files leave by hand. The UI download gives the operator the file in the controller's browser; the operator uploads it to the team Nextcloud. Nothing uploads from the controller process. If Nextcloud is not writable from inside, the file stays on controller disk and is carried out later. The Platform page shows "export path: unverified" until someone has done one upload.

##### Actions and content

No agent actions. Controller-side plan content proposed by the module: evidence-run plans built from recipes. Content files:

- `reports/generators/*.yml`: port matrix, asset inventory, service list, user and group listing, firewall summary, diagram, backup schedule, logging coverage, software and CVE table, external scan report, traffic report sections, device export.
- `reports/queries/*.yml`: the saved inject queries.
- `reports/evidence/*.yml`: `sshd_hardening`, `firewall_deny`, `listening_ports`, `wazuh`.
- `reports/lint.yml`: the prompt extractor's verb list, past-tense phrases, template fingerprints and the address allowlist.
- `inject-kit/memo.md.tmpl`: the memo shell.

##### UI

| Route | Shows |
| --- | --- |
| `/reports` | Drafts list; "New from prompt" (skeleton); "New memo"; IR buttons |
| `/reports/{id}` | Review: validation, field form, placeholders, rubric checklist, figures, text preview, download |
| `/artifacts`, `/artifacts/{id}` | The generator list; each artifact's screen view with PDF and CSV links and `?clean=1` |
| `/evidence` | Recipes, run status, figures produced, screenshots owed per deliverable |
| `/queries` | The saved queries and results |

"Draft IR" buttons sit on chain pages and on hunt-finding rows, and each makes one draft. Overview tile: open drafts and validation failures. No host-grid column.

##### Health

- `ok`: store readable, fonts loaded, `<data_dir>/reports` writable.
- `degraded`, with a gap each: `event window not set` (date check off); `inventory disabled` (evidence runs and software tables unavailable); `vuln disabled` (CVE column reads "vuln module off"); `devices disabled` (no config exports); `capture disabled` (no traffic report); `export path unverified`; `team number missing` (no drafts).
- `unavailable`: the data directory is not writable.

##### Scoring safety

`report` reads and renders; it changes no host and no scored state. Evidence runs are read-only `probe.run` nodes, which the scoring-safety lint passes. The firewall-deny recipe sends no traffic of its own. Config exports are scrubbed before they leave. The validator is advisory about content, so a human decides what is submitted; the only hard gate is the download refusal above. Because a validator false positive blocks a download, an override is an open item.

##### Tests

- Unit (existing): `ir_test.go`, `inject_test.go`, `pdf_test.go`, `names_test.go`, `report_test.go`. New: generator-engine fixtures per generator over a fixture manifest and store; the port-name fixture built from the EVAL11A mistake (464, 593 and 636 must come out right); `TCP/80` formatting; XOR and ROT decode vectors; the config scrub over real PAN-OS and VyOS exports; the skeleton extractor over 2026 prompts (LEGP11T, LINX01A, WINS01A, and SOFT07T with six tasks) and a fixture where the prompt has more tasks than headings; copy-forward fixtures (a 2021 inject number on a 2026 draft, "FROM ANOTHER COMPETITION", an address outside the manifest); duplicate and stock-behaviour fixtures using ledger verdicts; one-draft-per-narrative selection from a two-chain campaign; a hunt-finding draft with its cross-reference.
- Screen views: render each artifact at 1100 px with a layout check and fail on horizontal overflow.
- Fuzz the prompt extractor and the Markdown subset parser.
- Conformance suite (the shared one): starts with no config, emits only declared kinds, stops cleanly, respects its budget under a 50-draft fixture load.
- Lab: T58 (generators, evidence runs, queries, exports) and T59 (IR drafter, skeleton and validator).

##### Limits and open items

- `shortcut: diagram layout is a fixed segments-as-columns grid, upgrade if a topology with more than two segments or 30 hosts overlaps edges in a lab render`.
- `shortcut: fonts are Latin only and PDF layout is plain (no syntax highlighting, inline bold and italic flattened), upgrade if an inject needs another script`.
- `shortcut: removing a figure renumbers later figures and retest lines that cite a number must be edited by hand, upgrade by storing figure references by id`.
- `shortcut: the prompt extractor is verb and list-pattern matching, upgrade by adding patterns to reports/lint.yml when a real prompt is missed`.
- `shortcut: no override for a validator false positive, upgrade to a typed-reason "download anyway" if a lab run shows false positives`.
- Open: the exact reading of the past-tense lint in review N10.2 (the row names it without its rule); the smallest reading above (forward-looking sections only) needs confirming.
- Open: whether a text-transcript figure satisfies a "screenshot" prompt (test at the first event); whether the Nextcloud path works from inside; whether the portal text can reach the controller without typing (an outside person could put it in a Nextcloud text file).
- Open: screenshot properties (cursor, cropping) are untested.
- Core changes needed: none beyond the retrofit. `Host.Propose` must accept a plan draft with several nodes (the contract already says "a plan draft").
- Naming dependency: the consumed kinds above must match what `chains`, `hunt`, `backup` and `teamfeed` declare.
- Complexity register line: `report` | one engine for every artifact, with PDF text that extracts | pure-Go renderer, no host binary, no new listener, generators are content.
