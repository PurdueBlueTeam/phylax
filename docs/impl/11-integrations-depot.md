# W11: Integrations and Depot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put `depot`, `wazuh`, `splunk` and `suricata` on the module contract and finish them: the one signed cache index with priority-ordered sync and package installs from staged closures, the Wazuh controller module, the Splunk forwarder module with its dashboards pack, the Suricata/Zeek runner and `suricata.analyze_pcap`, the agent `fetch` handler with chunked transfers (Known bug 4), the split of the Splunk half out of the controller's device `Directory`, and the fixes for Known bugs 4, 15 (depot part), 17 (wazuh part) and 21.

**Architecture:** Each module is one package (`internal/depot`, `internal/wazuh`, `internal/splunk`, `internal/suricata`). Chunked transfers are core: `internal/link/bulk.go` (sender and receiver with resume), `internal/agent/fetch.go` (serve `fetch`, stage pushed blobs), `internal/controller/fetch.go` (request an object, push a blob). The depot's controller side owns the store, the sync client and the cache plan; its agent side verifies and deploys the tool depot from a bounded staging area. Action families (`pkg.*`, `windows.hotfix`, `wazuh.*`, `splunk.*`, `suricata.analyze_pcap`) leave `internal/actions` and register with `actions.Register`; module backends reach actions through `Env.Ext`. The Splunk management client moves out of `controller.Directory` into `internal/splunk`.

**Tech Stack:** Go 1.27.2 (mise), standard library, existing deps only (`modernc.org/sqlite`, `gopkg.in/yaml.v3`, `github.com/klauspost/compress`, `golang.org/x/sys`). No new modules in `go.mod`.

**Spec:** `phylax_design.md` (v4): Integrations and depot (`depot`, `wazuh`, `splunk`, `suricata`, all 12 parts each), "The module contract", "Wire protocol and spool" (messages, chunked transfers, the `fetch` paragraph), "Execution engine" (action families Packages and Integrations, controller executor, approval classes, scoring-safety lint), "Manifest" (Files table: `packages`, `scored_indexes`), Known bugs 3, 4, 15, 17, 21, Testing and lab (T40, T41, T46, T63, T65, T76). Master plan: `docs/impl/README.md`. Contract names: `docs/impl/01-module-contract.md` (W1). Names consumed from W3 (`internal/sockets`), W5 (`internal/signing`, `internal/integrity/format`) and W6 (`actions.Register`, `RegisterUndo`, `Unsupported`, `Env.Ext`, `controller.Options.Backends`, `Host.Manifest()`).

## Deviations and additions (applied by Task 1 to `phylax_design.md` in the same commit, each with its reason)

1. **Action registration helper name.** One name, owned by W1 Task 2a: `actions.Register(f func() []Action)`, with `actions.RegisterUndo`, `actions.Unsupported`, `(*Env).Now()` and `Env.Ext map[string]any`. (Earlier drafts of this plan said `RegisterFamily`.) Nothing here defines them.
2. **`Fetch` stays controller to agent; blobs are pushed.** The design's wire table says `fetch` requests "a depot blob", but a `fetch` can only travel controller to agent, so an agent cannot request a blob. `Fetch.Kind` stays `pcap | file | telemetry` (agent uploads). A depot blob reaches an agent by the controller pushing chunks to it (`Controller.PushBlob`); the agent stages it only when its digest verifies. No new message type, so `link.ProtoMinor` does not change.
3. **A new core kind `agent.fetch_result`** (`{id, ok, sha256, size, error}`, priority high) is the completion signal of both directions. There is no error reply in the wire for `fetch`, and a push needs confirmation that the blob is staged and verified. The core kind table gains a row (30 rows); the same commit updates the table and the count sentence.
4. **The signed index is the trust root on the agent.** The controller pushes the signed index (`depot.json`) like any blob; the agent verifies it against `DepotSettings.ReleaseKey` (a hex Ed25519 public key carried in the signed config, which is how the design says the deployed manifest is checked), and `pkg.install{source: "depot:<name>/<version>"}` resolves the expected sha256 from that verified index. A blob without an index entry (cache-through, operator pin) is installable only when the plan names its `sha256`. This keeps plans readable and keeps the sha256 out of every template.
5. **A package closure is one blob.** The index entry of kind `package` is a tar archive (`.deb` or `.rpm` files plus `SHA256SUMS`); the agent extracts it with a bounded reader into `stage/closures/<sha256>/` after the archive digest verifies. `pkg.install` then runs the host package manager on every package file of that directory with all repositories disabled (`apt-get -o Dir::Etc::sourcelist=/dev/null -o Dir::Etc::sourceparts=/dev/null`, `dnf --disablerepo=*`). The existing "directory plus `SHA256SUMS`" resolution in `linux_pkg.go` is kept for the named package inside the closure.
6. **Package-to-service map.** `manifest.Service` gains `Packages []string` and `ScoredIndexes []string` (the design's Files table lists both; no workstream added them). The controller lint rule `PK001` reads them from the manifest; the agent reads the host's map from `DepotSettings.Packages` (service name per package name), rendered by `genconfig`. The hard-coded `pkgScoredAliases` is deleted.
7. **Pins are command events, not `overrides.yml` rows.** `Host` has no write path to manifest files (W6 found the same for `learned_listeners`). A cache-through blob and an operator-pinned vendor entry are each one core `operator.edit` (`module: depot`, `op: add`, `record` the full `Entry` with `provenance`, `source`, `by`, `at`; S4: no `depot.entry_added` kind), emitted through `Host.Emit`. `depot_entry` is the union of the signed index and those events, built by the module's one writer goroutine; the UI form and the cache plan read the table. `shortcut: operator pins are operator.edit events replayed into depot_entry, not overrides.yml; upgrade when Host gets an overrides write path`.
8. **`modules/depot.yml` gains `release_key`** (hex Ed25519 public key; default the compiled-in `depot.ReleaseKeyHex`, set with `-ldflags`). The design says the key is compiled in and printed on the driver's checklist but gives the config no field for tests and rebuilds.
9. **`modules/suricata.yml` gains `evidence_dir`** (default `/var/lib/phylax/evidence`): the design requires "pcap path inside the evidence area" and names no setting. `shortcut: pcaps are read in clear; evidence encryption at rest is not built in core, wire the decrypt hook when it is`.
10. **The `run` record of the one `suricata` kind** (W1 declares the single kind `suricata` with a `record` field, S4; it carried `pcap, alerts, records, error`) takes the design's fields; schema stays 1 because nothing has been deployed.
11. **The two non-HEC Splunk actions move with the client.** `splunk.rest` and `splunk.password` are owned by `hardening` in the action table (`creds` does not list `splunk.password`), but all three Splunk actions share one API client that leaves `internal/actions` in this workstream. `internal/splunk` registers `splunk.hec_setup`, `splunk.rest` and `splunk.password`; its manifest `Actions` lists only `splunk.hec_setup`. There is no `splunk.sidecar_off` action (S4): the Splunk PostgreSQL sidecar disable is a `service.state` step on the sidecar unit in the `fh.splunk.sidecar_off` first-hour node (W5). **Integrator:** the CI action-table owner check must accept these two until W5 takes them over.
12. **Splunk management TLS.** The module's management client verifies against `ca_secret` when given; with `insecure_tls: true` it pins the first certificate seen per host (the behaviour `controller.Directory` has today); otherwise it uses system roots. The forwarder uses the same policy.
13. **The plan templates move** to `plans/wazuh/{deploy,evidence,uninstall}.yaml`, `plans/splunk/{forwarding,dashboards}.yaml`, `plans/suricata/analyze.yaml`, each with `module:` (W5 Task 37 owns the loader change; Task 28 here waits for it). `suricata`'s manifest `Content` gains `plans/suricata`.
14. **The incident-page tab is a link.** The design's "tab on the incident page" needs a core hook that does not exist; `suricata` registers a page and an action and the incident page links to the page. `shortcut: no incident-page tab, link only; upgrade when the UI shell has an incident tab registrar`.
15. **`phylax init` is W12's** (first contact). W11 provides `depot.Refresh` and `phylax cache refresh|sync`; `init` calls them later.
16. **`splunk` wildcard patterns expand against `Consumes` only** (`Host.Subscribe` drops kinds outside the manifest), so `devices.*` reaches `devices.config`, `devices.change`, `devices.deny` and nothing else. `shortcut: forward list limited to the manifest Consumes kinds, upgrade when a sink may subscribe to a family`.

## Global Constraints

- Go 1.27.2 via mise; `CGO_ENABLED=0`; `make build build-windows vet test race` passes at every commit (linux/amd64 and windows/amd64 both build and vet; `-race` runs with `CGO_ENABLED=1`).
- Every package ships tests; tests exercise the real code (no mocking of the code under test, no tautological asserts). Fakes only at an edge the package does not own: an `httptest` mirror, a fake Wazuh API and indexer, a fake HEC and splunkd, fake `suricata` and `zeek` scripts, a fake package manager runner (`CommandRunner`). A test that needs privileges or containers calls `t.Skip` with a reason string.
- Commits are small, one logical change, message `area: summary` (for example `depot: priority-ordered sync`). No attribution lines.
- No shelling out in the default path (`suricata` and `zeek` are the declared `host.exec` escape hatch, labelled "runs a host binary"). Bounded everything: queues, buffers, decoded sizes, archive extraction, timeouts. Atomic writes through `internal/atomicfile`. Times stored in UTC. Secrets never appear in events, logs, config files or plans.
- No compatibility shims, aliases or dual formats; renamed things are renamed everywhere in the same commit (`zeek.conn` and `zeek.dns` become `suricata` records `zeek_conn` and `zeek_dns`; `Agent: "wazuh"` and `Agent: "suricata"` are deleted, not aliased).
- A module imports only the core packages (`internal/event`, `internal/module`, `internal/agent`, `internal/link`, `internal/plan`, `internal/actions`, `internal/store`, `internal/manifest`, `internal/manifest/render`, `internal/deadman`, `internal/ui`, `internal/vault`) and the shared libraries (`internal/atomicfile`, `internal/parsers/...`, `internal/checks/probe`, `internal/sockets`, `internal/signing`, `internal/integrity/format`, `internal/inventory/fold`). `depot` imports no `integrity`, `net` or `collect/...`; `internal/actions` imports no module (W6's guard, extended here with `internal/wazuh`, `internal/splunk`, `internal/depot`).
- The release key signs the index; the private key never enters the repo, the event or a test fixture that is committed (tests generate keys).
- Agents never fetch from the internet. Only the controller does, and only from hosts in the `mirrors` allowlist.
- Wazuh active response and remote commands stay off (the deploy template turns them off). None of the four modules has `act_enabled` or `autonomy` (S4: they take no automatic action; their blocks carry `enabled` only and reject the others as unknown fields), and per-module rate and burst default from each manifest. Splunk never touches an index the scored search reads.
- The design is authoritative; a forced design change edits `phylax_design.md` in the same commit with the reason.

## Review Focus

1. **A downgraded or substituted index.** A mirror or a man in the middle serves an older signed index, an index signed by another key, or an unsigned one. Expected: the refresh refuses all three, the current index stays, `depot.problem{index_unsigned}` is emitted, and health is `unavailable` only when the index in use fails its signature (Task 11 `TestRefreshRefusesOlderIndex`, `TestRefreshRefusesWrongKey`).
2. **A sync killed mid-blob, and a staging flood.** `kill -9` during a large blob must leave no partial visible in `blobs/`; a second run resumes. On the agent, a sender that pushes more than `stage_mb`, or opens more partial objects than allowed, must be refused without filling the disk (Task 7 `TestPartialNeverVisible`, Task 2 `TestReceiverCapAndMaxOpen`).
3. **A package change that restarts a scored service.** `pkg.install` of `httpd` on a host where `httpd` provides a scored service. Expected: refused in any plan class except `click` (lint `PK001`), declared in the plan note as a restart of the service, and `pkg.remove` of it refused on the agent too (Task 19).
4. **A scored Splunk index name.** `splunk.hec_setup{index: "main"}` or an index listed in `scored_indexes`. Expected: refused before any API call is made, and an existing token bound to another index is never rebound (Task 23 `TestHECSetupRefusesScoredIndex`).
5. **A hostile pcap or tool output.** `suricata.analyze_pcap` with a path outside the evidence area, a symlink out of it, a pcap over `max_pcap_mb`, or a tool that writes a huge `eve.json`. Expected: refused or truncated and counted, the run directory removed, nothing read outside the evidence area (Task 27 `TestAnalyzeRefusesPathOutsideEvidence`, Task 26 `TestEveOverCapIsTruncated`).

---

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `internal/link/bulk.go` | `Sender`, `Receiver`, resume, caps | 1, 2 |
| `internal/agent/fetch.go`, `stage.go` | `fetch` handler, providers, staging receiver, closure extraction | 3, 4 |
| `internal/controller/fetch.go`, `stage.go` | `Fetch`, `PushBlob`, `Options.Stage` hook | 5 |
| `internal/event/core.go` | `agent.fetch_result` | 1 |
| `internal/depot/index.go` | `Entry`, `Manifest` (the index), `Sign`, `Parse` | 6 |
| `internal/depot/store.go` | content-addressed store, partial blobs | 7 |
| `internal/depot/build.go`, `depot/index.d/`, `depot/tools.json` | `phylax cache build` input and output | 8 |
| `internal/depot/sync.go`, `cacheplan.go`, `refresh.go`, `throughcache.go` | sync, cache plan, refresh, cache-through | 9 to 12 |
| `cmd/phylax/cache.go`, `depot.go` | `phylax cache build|sync|refresh|status`, `phylax depot` | 13 |
| `internal/depot/{kinds,config,manifest_mod,module,tables}.go` | events, config, module manifest, controller module | 1, 14 |
| `internal/depot/agent.go`, `internal/agent/mods/depot.go`, `internal/controller/genconfig.go` | agent module, settings rendering | 15 |
| `internal/depot/ui.go` | Platform page, tile, actions | 16 |
| `internal/depot/pkg*.go`, `hotfix.go`, `lint.go` | package actions, `windows.hotfix`, `PK001` | 17 to 20 |
| `internal/wazuh/` | client, poller, kinds, module, actions | 21, 22 |
| `internal/splunk/`, `splunk/dashboards/` | forwarder, kinds, module, API client, directory, actions, dashboards | 23 to 25 |
| `internal/suricata/`, `suricata/{config,zeek}/` | readers (W1), runner, module, action | 26, 27 |
| `plans/{wazuh,splunk,suricata}/` | templates | 28 |
| `manifest/2027/modules/{depot,wazuh,splunk,suricata}.yml`, `internal/manifest/` | reference blocks, `integrations.yml` removal | 29 |
| `internal/depot/offline_test.go`, `bugs_test.go` | T40 in CI form, bug guards | 30 |
| `docs/impl/lab/w11-integrations-depot.md` | lab record | 31 |

---

### Task 1: Seams (Sonnet or Opus)

Done by a stronger model. Moves `wazuh` and `splunk`, declares every kind with its payload struct, writes the four module manifests, config structs and settings, the module skeletons, the transfer and fetch signatures, the manifest fields, the skipped tests of Tasks 2 to 30 and the design edits. Merges on its own as a pull request into `v4`. **Entry gate:** W5 Task 2 (`internal/signing`, `internal/integrity/format`) and W3 Task 1 (`internal/sockets`, the `gotools` import) are merged; if W6 Task 1 is not, add its `actions` hooks first (Deviation 1).

**Files:**
- Move (`git mv`, delete old paths, fix every importer in the same commit): `internal/integrations/wazuh/*` to `internal/wazuh/`; `internal/integrations/splunk/*` to `internal/splunk/`. Rename the client config types: `wazuh.Config` to `wazuh.ClientConfig`, `splunk.Config` to `splunk.ForwarderConfig`. `internal/integrations/` no longer exists (`suricata` was moved by W1 Task 39). `internal/actions/app_wazuh.go` keeps importing `internal/wazuh` until Task 22 moves it.
- Create: `internal/depot/{kinds,config,manifest_mod,module,agent}.go`, `internal/wazuh/{kinds,config,manifest_mod,module}.go`, `internal/splunk/{kinds,config,manifest_mod,module}.go`, `internal/suricata/{kinds_run,config}.go`, `internal/agent/mods/depot.go`, `internal/link/bulk.go`, `internal/agent/{fetch,stage}.go`, `internal/controller/{fetch,stage}.go`, every skipped test file named in Tasks 2 to 30.
- Modify: `internal/event/core.go` (`AgentFetchResult`), `internal/plan/agentconfig.go` (`ModuleSettings.Depot *DepotSettings`), `internal/manifest/types.go` (`Service.Packages`, `Service.ScoredIndexes`), `internal/agent/agent.go` and `handlers.go` (route `Chunk` and `ChunkHave`), `internal/controller/controller.go` (`Options.Stage`), `internal/module/all/all.go` (blank-import `depot`, `wazuh`, `splunk`; `suricata` already), `internal/module/conformance/allowed.go` (`ModulePackages` for the four; `PreContract` adds `depot`, `wazuh`, `splunk`, each removed by its module task), `phylax_design.md`.

**Interfaces:**
- Consumes: W1 `event.Declare`, `event.Type`, `module.Manifest`, `module.Common`, `module.ControllerModule`, `module.Host`, `module.Register`, `agent.Factory`, `plan.ModuleLimits`, `plan.BlockFor`; W1 `actions.Register`, `Env.Ext`, `Host.Manifest`; W5 `signing.Signer`, `signing.Verifier`.
- Produces (exact; every later task uses these):

```go
// ---- internal/event/core.go ----
const KindAgentFetchResult = "agent.fetch_result" // Declare: Schema 1, PriorityHigh, Alert false
type AgentFetchResult struct {
	ID     string `json:"id"` // the fetch id, or "stage:<sha256>" for a pushed blob
	OK     bool   `json:"ok"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Error  string `json:"error,omitempty"`
}

// ---- internal/plan/agentconfig.go ----
type DepotSettings struct { // json block "depot"
	ModuleLimits
	Dir               string              `json:"dir,omitempty"`
	StageMB           int                 `json:"stage_mb,omitempty"`            // default 512
	VerifyIntervalSec int                 `json:"verify_interval_sec,omitempty"` // default 600; 0 disables
	ReleaseKey        string              `json:"release_key,omitempty"`         // hex Ed25519 public key
	Packages          map[string][]string `json:"packages,omitempty"`            // package name -> scored or declared service names on this host
}

// ---- internal/manifest/types.go ---- Service gains:
//   Packages      []string `yaml:"packages,omitempty" json:"packages,omitempty"`
//   ScoredIndexes []string `yaml:"scored_indexes,omitempty" json:"scored_indexes,omitempty"`

// ---- internal/link/bulk.go ---- (stubs; Task 2)
type SendFunc func(ctx context.Context, p Priority, m Message) error
const MaxObjectBytes = 4 << 30
var ErrCap = errors.New("link: transfer cap exceeded")
type Sender struct{ /* unexported */ }
func NewSender(send SendFunc) *Sender
func (s *Sender) Send(ctx context.Context, sum string, r io.ReaderAt, size int64) error // PrioBulk chunks; skips ranges a ChunkHave reports
func (s *Sender) Have(h *ChunkHave)                                                      // route an incoming ChunkHave to the in-flight Send
type Result struct {
	Done bool
	Path string      // Dir/<sha256> when Done
	Have *ChunkHave  // non-nil: send it back so the sender skips what is held
}
type Receiver struct{ /* unexported */ }
func NewReceiver(dir string, capBytes int64, maxOpen int) (*Receiver, error)     // removes stale *.part files
func (r *Receiver) Accept(c *Chunk) (Result, error)                              // ErrCap when over capBytes or maxOpen
func (r *Receiver) Path(sum string) (string, bool)
func (r *Receiver) Used() int64                                                   // bytes of completed objects plus partials

// ---- internal/agent/fetch.go ----
type FetchObject struct {
	Path   string
	Delete bool // remove the file after it is sent (a temporary slice)
}
type FetchProvider func(ctx context.Context, args json.RawMessage) (FetchObject, error)
func RegisterFetch(kind string, p FetchProvider) // from init; panics on a duplicate kind
const MaxFetchBytes = 256 << 20
// agent.Config gains: FetchRoots []string (allowed roots of the built-in "file" provider), MaxFetches int (default 2)
// Handlers gains: Chunk func(ctx context.Context, c *link.Chunk, reply Reply) error; ChunkHave func(ctx context.Context, h *link.ChunkHave, reply Reply) error

// ---- internal/agent/stage.go ----
func (a *Agent) StageDir() string                  // StateDir/depot/stage ; blobs at StageDir()/blobs/<sha256>, closures at StageDir()/closures/<sha256>
func (a *Agent) SetStageCap(mb int)                // from modules.depot.stage_mb when a config is applied; default 512

// ---- internal/controller/fetch.go, stage.go ----
type FetchedObject struct {
	Path, SHA256 string
	Size         int64
}
func (c *Controller) Fetch(ctx context.Context, host, kind string, args any) (FetchedObject, error) // default timeout 5 min
func (c *Controller) PushBlob(ctx context.Context, host, sha256 string, r io.ReaderAt, size int64) error // returns when the agent reports it staged
// Options gains: Stage func(ctx context.Context, host string, n plan.Node) error // called before a step with a depot source is sent; blocks until staged
// Options gains: EvidenceDir string // where fetched objects land (default <data dir>/fetch)

// ---- internal/depot/kinds.go ---- (Declare in init; structs exact)
const (
	KindSyncState = "depot.sync_state" // normal
	KindDeploy    = "depot.deploy"     // normal
	KindProblem   = "depot.problem"    // high; critical per event for planted_file and verify_failed
)
type FailedEntry struct{ Name, Reason string } // json "name", "reason"
type SyncState struct {
	Priority     int           `json:"priority"`
	EntriesTotal int           `json:"entries_total"`
	EntriesDone  int           `json:"entries_done"`
	BytesTotal   int64         `json:"bytes_total"`
	BytesDone    int64         `json:"bytes_done"`
	State        string        `json:"state"` // idle | syncing | waiting | failed
	RateKbps     int           `json:"rate_kbps"`
	Failed       []FailedEntry `json:"failed,omitempty"`
	IndexVersion string        `json:"index_version"`
}
type DeployEvent struct {
	DirHash string   `json:"dir_hash"` // not the path
	Tools   []string `json:"tools"`    // "name version"
	Missing []string `json:"missing,omitempty"`
	OK      bool     `json:"ok"`
}
type ProblemEvent struct {
	What   string `json:"what"` // verify_failed | fetch_failed | index_unsigned | blob_corrupt | planted_file
	Entry  string `json:"entry,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// ---- internal/depot/config.go ----
type Config struct { // modules/depot.yml
	module.Common `yaml:",inline"`
	StoreDir   string   `yaml:"store_dir,omitempty"`
	Sync       SyncCfg  `yaml:"sync,omitempty"`
	Mirrors    []string `yaml:"mirrors,omitempty"`
	Priorities []int    `yaml:"priorities,omitempty"`
	CachePlan  struct {
		Closures     []string `yaml:"closures,omitempty"`
		Integrations []string `yaml:"integrations,omitempty"`
	} `yaml:"cache_plan,omitempty"`
	Tools      struct{ HiddenDirBase string `yaml:"hidden_dir_base,omitempty"` } `yaml:"tools,omitempty"`
	ReleaseKey string `yaml:"release_key,omitempty"`
}
type SyncCfg struct {
	BandwidthKbps int    `yaml:"bandwidth_kbps,omitempty"`
	Parallel      int    `yaml:"parallel,omitempty"`
	Start         string `yaml:"start,omitempty"` // "t0" (default)
}
var ReleaseKeyHex string // set with -ldflags "-X .../internal/depot.ReleaseKeyHex=..."

// ---- internal/wazuh/kinds.go ----
const (
	KindAlert  = "wazuh.alert"  // normal
)
type AlertEvent struct {
	AlertID       string `json:"alert_id"`
	RuleID        string `json:"rule_id"`
	Level         int    `json:"level"`
	Description   string `json:"description"`
	WazuhAgent    string `json:"wazuh_agent"`
	WazuhAgentID  string `json:"wazuh_agent_id"`
	AgentIP       string `json:"agent_ip,omitempty"`
	Location      string `json:"location,omitempty"`
	FullLog       string `json:"full_log,omitempty"` // truncated to 2048 bytes
}
type HealthDetail struct { // the module Health.Info block and the `detail` of telemetry_gap{source: wazuh, reason: wazuh_degraded} (S4: no wazuh.health kind)
	ManagerVersion        string   `json:"manager_version"`
	VersionOK             bool     `json:"version_ok"`
	AgentsTotal           int      `json:"agents_total"`
	Active                int      `json:"active"`
	Disconnected          []string `json:"disconnected,omitempty"`
	NeverConnected        []string `json:"never_connected,omitempty"`
	AgentNewerThanManager []string `json:"agent_newer_than_manager,omitempty"`
	Error                 string   `json:"error,omitempty"`
}

// ---- internal/wazuh/config.go ---- the module block (design part 4: sensor and the rest, one struct)
type SensorConfig struct {
	Version      string   `yaml:"version"`
	Manager      string   `yaml:"manager"`
	ManagerAddr  string   `yaml:"manager_addr"`
	AllowFrom    string   `yaml:"allow_from"`
	LinuxAgents  []string `yaml:"linux_agents"`
	WinAgents    []string `yaml:"win_agents"`
}
type Config struct {
	module.Common `yaml:",inline"`
	Sensor     SensorConfig      `yaml:"sensor"`
	APIURL     string            `yaml:"api_url"`
	IndexerURL string            `yaml:"indexer_url,omitempty"`
	Secrets    map[string]string `yaml:"secrets"` // api, indexer: vault names
	CASecret   string            `yaml:"ca_secret,omitempty"`
	InsecureTLS bool             `yaml:"insecure_tls,omitempty"`
	MinLevel   int               `yaml:"min_level"`
	PollSec    int               `yaml:"poll_sec,omitempty"`
	MinActive  int               `yaml:"min_active,omitempty"`
}

// ---- internal/splunk/kinds.go, config.go ----
// no splunk.forwarder_state kind (S4): the counters are module Health.Info and the `detail` of telemetry_gap{source: splunk, reason: forwarder_failing}
type ForwarderState struct {
	Sent      uint64 `json:"sent"`
	Dropped   uint64 `json:"dropped"`
	Retries   uint64 `json:"retries"`
	Failed    uint64 `json:"failed"`
	LastError string `json:"last_error,omitempty"`
	QueueLen  int    `json:"queue_len"`
	State     string `json:"state"` // ok | failing | dropping
}
type SensorConfig struct {
	Host      string `yaml:"host"`
	HECURL    string `yaml:"hec_url"`
	MgmtURL   string `yaml:"mgmt_url"`
	Index     string `yaml:"index"`
	TokenName string `yaml:"token_name"`
}
type Config struct {
	module.Common `yaml:",inline"`
	Sensor             SensorConfig      `yaml:"sensor"`
	Secrets            map[string]string `yaml:"secrets"` // hec_token, mgmt: vault names
	CASecret           string            `yaml:"ca_secret,omitempty"`
	InsecureTLS        bool              `yaml:"insecure_tls,omitempty"`
	Source             string            `yaml:"source,omitempty"`
	SourceType         string            `yaml:"sourcetype,omitempty"`
	Forward            []string          `yaml:"forward"`
	SecEventCategories []string          `yaml:"sec_event_categories,omitempty"`
	Queue, Batch       int               `yaml:"queue,omitempty"`
	BatchBytes         int               `yaml:"batch_bytes,omitempty"`
	FlushSec, Retries  int               `yaml:"flush_sec,omitempty"`
	TimeoutSec         int               `yaml:"timeout_sec,omitempty"`
}

// ---- internal/suricata (kinds_run.go, config.go) ---- W1 declares the one kind `suricata` with a `record` field (alert, dns, http, zeek_conn, zeek_dns, run); the `run` record's payload below replaces W1's
type RunEvent struct {
	PCAPSHA256   string         `json:"pcap_sha256"`
	Source       string         `json:"source"` // capture | palo | file
	Window       string         `json:"window,omitempty"`
	Tools        []string       `json:"tools"`
	RulesVersion string         `json:"rules_version,omitempty"`
	Flags        []string       `json:"flags"`
	Alerts       int            `json:"alerts"`
	Events       int            `json:"events"`
	Skipped      map[string]int `json:"skipped,omitempty"`
	DurationMS   int64          `json:"duration_ms"`
	Error        string         `json:"error,omitempty"`
}
type SensorConfig struct {
	SuricataVersion string `yaml:"suricata_version"`
	ZeekVersion     string `yaml:"zeek_version"`
	Rules           string `yaml:"rules"` // ruleset id in the depot index
	SuricataSHA256  string `yaml:"suricata_sha256,omitempty"` // pin of the host binary
	ZeekSHA256      string `yaml:"zeek_sha256,omitempty"`
}
type Config struct { // replaces W1's Config
	module.Common  `yaml:",inline"`
	Sensor         SensorConfig `yaml:"sensor"`
	Tools          []string     `yaml:"tools"`
	MaxPcapMB      int          `yaml:"max_pcap_mb,omitempty"`   // default 256
	TimeoutSec     int          `yaml:"timeout_sec,omitempty"`   // default 300
	IncludeContext bool         `yaml:"include_context,omitempty"`
	OffloadSafe    *bool        `yaml:"offload_safe,omitempty"`  // default true
	WorkDir        string       `yaml:"work_dir,omitempty"`      // default /var/lib/phylax/suricata
	EvidenceDir    string       `yaml:"evidence_dir,omitempty"`  // default /var/lib/phylax/evidence
}
```

Module manifests are the design's part 3 verbatim (Budget numbers, `Default`, `Tables`, `Content`, `Actions`, `Pages`, `Evidence`), with `Emits` the kinds above (`wazuh`: `wazuh.alert` and the common `telemetry_gap`; `splunk`: `telemetry_gap`; `depot`: its three kinds and `operator.edit`; `suricata`: `suricata`), `Consumes` as the design lists (`splunk`: the default `forward` kinds; `depot`: its own `depot.sync_state` and `operator.edit` for the table writer), and `suricata.Content` plus `plans/suricata`. `depot.Manifest.Sides` is both; the controller registration is `module.Register(&Module{})`, the agent one is `agent.Factory{Name: "depot", ...}` in `internal/agent/mods/depot.go`.

- [ ] **Step 1: Move the two packages and fix importers.** `grep -rn 'internal/integrations' --include='*.go' .` returns nothing afterwards; `internal/actions/app_wazuh.go` and `app_misc_test.go` import `internal/wazuh`; `cmd/phylax/serve.go` is unchanged.
- [ ] **Step 2: Write the stubs.** Types, constants and signatures exactly as above; stub bodies `panic("unimplemented: W11 Task N")` naming the implementing task. `module.go` skeletons register and report `StateUnavailable` with the gap `{"<module>", "not built (W11 Task N)"}` until their module task. Add the new fields to existing structs zero-value safe (`omitempty`).
- [ ] **Step 3: Write the skipped tests** of Tasks 2 to 30, each body as that task's Step 1 gives it, first statement `t.Skip("unimplemented: W11 Task N")`.
- [ ] **Step 4: Apply the deviations to `phylax_design.md`** (one bullet each with its reason under the `depot`, `wazuh`, `splunk`, `suricata` sections and the wire protocol `fetch` paragraph; the 30th core kind row and the count sentence; Appendix D gains nothing).
- [ ] **Step 5: Verify.** Run: `make build build-windows vet test race`. Expected: PASS. Then `go test -v ./internal/... 2>&1 | grep -c 'unimplemented: W11 Task'` equals the number of skipped tests written. `go list -deps ./internal/actions | grep -c 'internal/integrations'` prints `0`.
- [ ] **Step 6: Commit.**

```bash
git add internal docs phylax_design.md cmd
git commit -m "depot: W11 seams (module moves, kinds, config, transfer signatures, skipped tests)"
```

Open this as its own pull request into `v4`; merge after review.

---

### Task 2: Chunked transfer library (`internal/link/bulk.go`)

**Files:**
- Modify: `internal/link/bulk.go`
- Test: `internal/link/bulk_test.go`

**Interfaces:**
- Consumes: Task 1 signatures; built `link.Chunk`, `link.ChunkHave`, `link.ChunkSize`, `link.PrioBulk`.
- Produces: the working `Sender` and `Receiver` of Task 1.

Rules. `Sender.Send` rejects `size <= 0` or `> MaxObjectBytes`, hashes nothing (the caller supplies `sum`), sends chunk 0, waits at most 1 s for a `ChunkHave` on that sum, then sends every range not covered, in order, each as one `Chunk` through `send` at `PrioBulk` (the session's token bucket shapes it). `Receiver.Accept` validates the chunk range, writes into `Dir/<sum>.part` with `WriteAt` (preallocated length `Total`), merges ranges, and on the last missing byte hashes the file, renames it to `Dir/<sum>` and returns `Done`; a digest mismatch deletes the partial and returns an error. The first chunk of an object returns `Have` with the ranges already held (all of `[0,Total)` and `Done` when the object is already complete). Caps: `capBytes` bounds completed objects plus partials (`ErrCap` otherwise, nothing written), `maxOpen` bounds distinct partials, `Total` over `MaxObjectBytes` is refused. `NewReceiver` deletes stale `*.part` files. `shortcut: ranges are held in memory, so a partial survives a link drop but not a process restart; upgrade if multi-GB transfers must survive restarts`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestSendReceiveRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte("phylax"), 100000) // 600000 bytes: 3 chunks
	sum := sha256Hex(data)
	rcv, _ := NewReceiver(t.TempDir(), 1<<30, 4)
	var snd *Sender
	snd = NewSender(func(_ context.Context, p Priority, m Message) error {
		if p != PrioBulk { t.Errorf("priority %v", p) }
		res, err := rcv.Accept(m.(*Chunk))
		if res.Have != nil { snd.Have(res.Have) }
		_ = err
		return nil
	})
	if err := snd.Send(context.Background(), sum, bytes.NewReader(data), int64(len(data))); err != nil { t.Fatal(err) }
	p, ok := rcv.Path(sum)
	got, _ := os.ReadFile(p)
	if !ok || !bytes.Equal(got, data) { t.Fatal("object not assembled") }
}
func TestSendSkipsHeldRanges(t *testing.T) { /* receiver pre-holds chunk 1 of 3; count Chunk messages sent: want 2 (chunk 0 always, chunk 2); ends Done */ }
func TestReceiverRejectsDigestMismatch(t *testing.T) { /* chunks of a body whose sum names other bytes: last Accept returns error, no Dir/<sum>, no .part left */ }
func TestReceiverCapAndMaxOpen(t *testing.T) {
	// cap 1 MiB: a Chunk with Total 2 MiB -> errors.Is(err, ErrCap), directory empty
	// maxOpen 2: first chunks of three different objects -> third errors.Is(err, ErrCap)
}
func TestReceiverRemovesStalePartsOnStart(t *testing.T) { /* a pre-existing x.part is gone after NewReceiver */ }
func TestSendRejectsOversize(t *testing.T) { /* size > MaxObjectBytes -> error, nothing sent */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/link/ -run 'SendReceive|SendSkips|Receiver|SendRejects' -v`. Expected: FAIL (`unimplemented`).
- [ ] **Step 3: Implement** `Sender`, `Receiver` and `Result` as specified; a mutex per receiver, a map of in-flight sends per sum for `Have`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/link/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "link: chunked transfer sender and receiver with resume and caps"`

---

### Task 3: Agent `fetch` handler (Known bug 4)

**Files:**
- Modify: `internal/agent/fetch.go`, `internal/agent/handlers.go` (delete `placeholderFetch`), `internal/agent/agent.go` (route `*link.Fetch` to `a.fetchHandler`, `*link.ChunkHave` to the sender), `cmd/phylax/agent.go` (set `FetchRoots`)
- Test: `internal/agent/fetch_test.go`

**Interfaces:**
- Consumes: Task 1 `RegisterFetch`, `FetchObject`, `AgentFetchResult`; Task 2 `Sender`.
- Produces: `(*Agent).fetchHandler(ctx, f *link.Fetch, reply Reply) error`; the built-in `file` provider (`args: {"path": "<abs>"}`); on every fetch, one `agent.fetch_result` event (`ID` the fetch id; `OK`, `SHA256`, `Size` or `Error`).

Rules. The handler runs the transfer in its own goroutine (bounded by `MaxFetches`, default 2; the third concurrent fetch answers `agent.fetch_result{ok:false, error:"too many concurrent fetches"}`), because handlers must return promptly. An unknown kind answers `ok:false`. The `file` provider resolves symlinks, requires a regular file under one of `FetchRoots` (defaults: Linux `/var/log`, `/etc`, `/var/lib/phylax/evidence`; Windows `C:\Windows\System32\winevt\Logs`, `C:\ProgramData\phylax`) and a size of at most `MaxFetchBytes`. The result event is emitted before the first chunk so the controller can expect the object. `FetchObject.Delete` removes the file after sending.

- [ ] **Step 1: Write the failing tests** (use the agent test harness `newTestAgent` from `testutil_test.go`):

```go
func TestFetchFileStreamsChunks(t *testing.T) {
	// root := t.TempDir(); write 600000 bytes; agent FetchRoots = [root]
	// deliver &link.Fetch{ID: "f1", Kind: "file", Args: {"path": file}}; capture replies
	// want: >= 3 *link.Chunk replies at PrioBulk whose reassembly sha256 == file's; one agent.fetch_result{ID:"f1", OK:true, SHA256: sum, Size: 600000}
}
func TestFetchFileOutsideRootsRefused(t *testing.T) { /* path /etc/passwd with roots [tmp]: result ok:false, error mentions "outside"; no chunk */ }
func TestFetchFileSymlinkEscapeRefused(t *testing.T) { /* symlink inside root pointing outside: ok:false */ }
func TestFetchOverCapRefused(t *testing.T) { /* sparse file of MaxFetchBytes+1: ok:false, no chunk */ }
func TestFetchUnknownKind(t *testing.T) { /* Kind "telemetry" with no provider: ok:false "no provider" */ }
func TestFetchConcurrencyBounded(t *testing.T) { /* provider blocks; MaxFetches 2; third fetch -> ok:false immediately */ }
func TestRegisterFetchPanicsOnDuplicate(t *testing.T) {}
func TestPhylaxAgentHasNoPlaceholderFetch(t *testing.T) { /* Known bug 4: a default Agent with no Handlers.Fetch still answers a file fetch (does not log "not implemented") */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/agent/ -run 'Fetch' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `RegisterFetch`, the `file` provider, `fetchHandler`; delete `placeholderFetch`; set `FetchRoots` in `cmd/phylax/agent.go`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/agent/ ./cmd/phylax/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "agent: fetch handler streams files as chunks (Known bug 4)"`

---

### Task 4: Agent staging receiver and closure extraction

**Files:**
- Modify: `internal/agent/stage.go`, `internal/agent/agent.go` (route `*link.Chunk`; apply `SetStageCap` when a config with `Modules.Depot` is applied)
- Test: `internal/agent/stage_test.go`

**Interfaces:**
- Consumes: Task 2 `Receiver`; Task 1 `StageDir`, `SetStageCap`, `AgentFetchResult`.
- Produces: pushed chunks land in `StageDir()/blobs/<sha256>`; on each completed blob the agent emits `agent.fetch_result{ID:"stage:"+sum, OK:true, SHA256, Size}`; a failed chunk (cap, digest) emits `ok:false` with the error; a first chunk answers a `ChunkHave` (`reply(ctx, link.PrioCritical, res.Have)`). `Agent.OnStaged func(sum string)` (called after each staged blob; nil by default), and `func ExtractClosure(blob, dstDir string, maxFiles int, maxBytes int64) error` (exported for Task 17): extracts a tar (optionally gzip) into `dstDir`, rejecting absolute paths, `..`, links, device files, more than `maxFiles` entries or more than `maxBytes` expanded, and writes nothing outside `dstDir`.

Rules. The stage cap is `stage_mb` (default 512 MiB), open partials at most 8. `closures/<sha256>/` is created only for an object the depot index marks as a package; the agent does not know, so extraction is on demand by `pkg.install` (Task 17), not at receipt.

- [ ] **Step 1: Write the failing tests:**

```go
func TestPushedBlobIsStagedAndAnnounced(t *testing.T) { /* send chunks of 300000 bytes via the agent handler; blobs/<sum> exists, content equal; events contain agent.fetch_result{ID: "stage:<sum>", OK: true} */ }
func TestStageCapRefusesAndReports(t *testing.T) { /* SetStageCap(1); chunk with Total 2 MiB: fetch_result ok:false error contains "cap"; blobs dir empty */ }
func TestFirstChunkAnswersChunkHave(t *testing.T) { /* blob already staged: first chunk -> reply *link.ChunkHave covering [0,total) */ }
func TestExtractClosureRejectsTraversal(t *testing.T) { /* tar with "../x" and with an absolute name and with a symlink: each errors; nothing written outside dst */ }
func TestExtractClosureBounds(t *testing.T) { /* maxFiles 2 with 3 members -> error; maxBytes 10 with 11 bytes -> error */ }
func TestExtractClosureOK(t *testing.T) { /* a.deb, b.deb, SHA256SUMS extracted, mode 0600 */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/agent/ -run 'Stage|Pushed|Extract' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/agent/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "agent: bounded staging of pushed blobs; closure extraction"`

---

### Task 5: Controller `Fetch`, `PushBlob` and the `Stage` hook

**Files:**
- Modify: `internal/controller/fetch.go`, `internal/controller/stage.go`, `internal/controller/agent.go` (route `*link.Chunk`, `*link.ChunkHave`), `internal/controller/plans.go` (`sendStep` calls `Options.Stage`), `internal/controller/controller.go` (receiver and per-agent sender maps, `EvidenceDir`)
- Test: `internal/controller/fetch_test.go`, `stage_test.go`

**Interfaces:**
- Consumes: Task 2 `Sender`, `Receiver`; Task 3 and 4 agent behaviour; W1 `EmitController`, the ingest path for agent events.
- Produces: `Controller.Fetch`, `Controller.PushBlob`, `Options.Stage` as in Task 1.

Rules. `Fetch` sends `link.Fetch{ID: <random 16 hex>, Kind, Args}` at `PrioStep`, registers a waiter, and completes when the `agent.fetch_result{ID}` event with `OK` has arrived and the receiver holds the object (`Path(sha256)`); a result with `OK=false` returns its error; the context or the 5 min default ends the wait. Fetched objects land in `EvidenceDir/<sha256>`. `PushBlob` uses the per-agent `Sender`, then waits for `agent.fetch_result{ID:"stage:"+sha256}`; if the agent holds the blob the sender stops after the first chunk (ChunkHave) and the result arrives immediately. `sendStep`: for a node whose `Params["source"]` has the prefix `depot:`, call `Options.Stage(ctx, host, node)` before registering the pending step and fail the step with the returned error text `blob not staged: <err>`; a nil `Stage` leaves the step alone (the agent's `check` then fails with "blob not staged"). `sendStep` must not run on the agent's receive loop: if the plan engine calls it there, move the dispatch of such nodes to a goroutine (the test `TestStageDoesNotBlockIngest` pins this).

- [ ] **Step 1: Write the failing tests** (an in-process agent through the existing `e2e` helpers in `e2e_test.go`):

```go
func TestFetchFileEndToEnd(t *testing.T) { /* agent FetchRoots [dir]; c.Fetch(ctx, "h1", "file", map{"path": f}) -> Path under EvidenceDir, SHA256 == sha of f, bytes equal */ }
func TestFetchAgentRefusalReturnsError(t *testing.T) { /* path outside roots -> err contains "outside"; returns well before the 5 min timeout */ }
func TestPushBlobEndToEnd(t *testing.T) { /* c.PushBlob(ctx, "h1", sum, bytes.NewReader(b), n) returns nil; agent StageDir()/blobs/<sum> equals b */ }
func TestPushBlobAlreadyStagedSendsOneChunk(t *testing.T) { /* push twice; count Chunk messages on the second call == 1 */ }
func TestStageHookRunsBeforeDepotStep(t *testing.T) { /* plan node pkg.install source "depot:x/1"; Stage called once with host and node before the step reaches the agent; Stage error -> step failed "blob not staged: boom" */ }
func TestStageDoesNotBlockIngest(t *testing.T) { /* Stage blocks 2 s; heartbeats from the agent are still acknowledged within 500 ms */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run 'Fetch|PushBlob|Stage' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: fetch objects from agents, push blobs, stage hook before depot steps"`

---
### Task 6: The signed index (entries with kind, priority, needed-by)

**Files:**
- Move: `internal/depot/manifest.go` to `internal/depot/index.go` (`git mv`); modify `internal/depot/{deploy,run,pack,store}.go`, `internal/depot/depot_test.go` (rename `Manifest.Tools` to `Manifest.Entries` everywhere), `cmd/phylax/depot.go`
- Test: `internal/depot/index_test.go`, `internal/depot/imports_test.go`

**Interfaces:**
- Consumes: W5 `signing.Signer`, `signing.Verifier`, `signing.ErrBadSignature` (already swapped in by W5 Task 2).
- Produces:

```go
type Entry struct { // existing fields kept (Name, Version, OS, Arch, SHA256, Size, URL, License, Recipe, Source, Provides, FetchAtInit), plus:
	Kind     string   `json:"kind"`                // tool | package | installer | bundle | ledger_index | reference | feed | ruleset
	Priority int      `json:"priority"`            // 0 shipped in the release, 1 fetched first, 2 background; lower syncs first
	NeededBy []string `json:"needed_by,omitempty"` // module names
}
const (KindTool = "tool"; KindPackage = "package"; KindInstaller = "installer"; KindBundle = "bundle"
	KindLedgerIndex = "ledger_index"; KindReference = "reference"; KindFeed = "feed"; KindRuleset = "ruleset")
func (e Entry) Key() string // "kind/os/arch/name/version"
type Manifest struct {
	Format  int     `json:"format"` // stays 1
	Created string  `json:"created,omitempty"`
	Entries []Entry `json:"entries"`
}
func (m *Manifest) For(goos, goarch string) []Entry // KindTool entries of the platform, sorted by name (deploy, Lookup)
func (m *Manifest) ByPriority(p int) []Entry        // sorted by Size ascending, then Name
func (m *Manifest) Find(kind, name, version, os string) (Entry, bool)
func (m *Manifest) Blocked(st Store, module string) []Entry // entries NeededBy contains module and absent from st
const MaxBlobSize = 2 << 30
```

`Validate` adds: `Kind` in the set, `Priority` in 0..2, `Size` in `0..MaxBlobSize`, tools need `OS` and `Arch`, other kinds may carry a distro tag in `OS` (for example `rocky-9`, `windows-server-2022`), `NeededBy` entries non-empty, duplicate `Key()` rejected. `Parse` and `Sign` are unchanged apart from the signer types.

- [ ] **Step 1: Write the failing tests:**

```go
func TestValidateKindPriorityAndKey(t *testing.T) {
	good := Entry{Name: "busybox", Version: "1.36.1", OS: "linux", Arch: "amd64", License: "GPL-2.0-only", SHA256: strings.Repeat("a", 64), Kind: KindTool, Priority: 1}
	for name, mut := range map[string]func(*Entry){
		"no kind":       func(e *Entry) { e.Kind = "" },
		"bad kind":      func(e *Entry) { e.Kind = "zip" },
		"priority 3":    func(e *Entry) { e.Priority = 3 },
		"tool no arch":  func(e *Entry) { e.Arch = "" },
		"huge":          func(e *Entry) { e.Size = MaxBlobSize + 1 },
		"empty needed":  func(e *Entry) { e.NeededBy = []string{""} },
	} {
		e := good
		mut(&e)
		if err := (&Manifest{Format: 1, Entries: []Entry{e}}).Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := (&Manifest{Format: 1, Entries: []Entry{good, good}}).Validate(); err == nil {
		t.Error("duplicate key accepted")
	}
}
func TestByPriorityOrdersBySize(t *testing.T) { /* priorities 1 with sizes 9,3,5 -> 3,5,9; priority 0 entry excluded from ByPriority(1) */ }
func TestFindAndBlocked(t *testing.T) { /* Blocked(st, "wazuh") lists the wazuh entries not in the store, none once Put */ }
func TestSignParseWithSigningTypes(t *testing.T) { /* unsigned, tampered body, wrong key: errors.Is ErrNoSig / signing.ErrBadSignature; good key parses with Entries */ }
// internal/depot/imports_test.go (Known bug 15, depot part)
func TestDepotImportsNoSibling(t *testing.T) {
	out, _ := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "./...").Output()
	for _, p := range strings.Fields(string(out)) {
		for _, bad := range []string{"/internal/integrity", "/internal/collect", "/internal/net"} {
			if strings.HasSuffix(p, bad) || strings.Contains(p, bad+"/") {
				t.Errorf("internal/depot imports %s", p)
			}
		}
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ -run 'Validate|ByPriority|Find|SignParse|Imports' -v`. Expected: FAIL (compile errors, then assertions). The banned list is `integrity`, `collect` and `net`; `internal/actions` is a core package a module may import.
- [ ] **Step 3: Implement** the rename, fields, `Validate`, helpers; update `deploy.go`, `run.go`, `pack.go`, `cmd/phylax/depot.go` and the existing tests for `Entries`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/... ./cmd/phylax/ && GOOS=windows go vet ./internal/depot/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: one signed index with kind, priority and needed-by"`

---

### Task 7: Store: partial blobs, streaming verify, size bounds

**Files:**
- Modify: `internal/depot/store.go`
- Test: `internal/depot/store_test.go`

**Interfaces:**
- Consumes: Task 6 `MaxBlobSize`.
- Produces:

```go
func (s Store) OpenPart(sum string) (f *os.File, have int64, err error) // Dir/part/<sum>, opened for append; have = bytes already there
func (s Store) CommitPart(sum string, f *os.File, wantSize int64) error // hash the whole part; on match rename into blobs/<sum>; on mismatch or size error delete the part and return an error
func (s Store) Verify(sum string) error                                  // streaming re-hash of a blob (no memory proportional to size)
func (s Store) Delete(sum string) error
func (s Store) Used() (int64, error)                                     // bytes under blobs/
// Put's default bound becomes MaxBlobSize (was MaxToolSize); ReadVerified keeps MaxToolSize (tools are read into memory)
```

- [ ] **Step 1: Write the failing tests:**

```go
func TestPartialNeverVisible(t *testing.T) { // Review Focus 2
	st := Store{Dir: t.TempDir()}
	data := bytes.Repeat([]byte{7}, 1<<20)
	sum := hexSum(data)
	f, have, _ := st.OpenPart(sum)
	f.Write(data[:400000])
	if st.Has(sum) || have != 0 { t.Fatal("partial visible or pre-existing") }
	f.Close() // simulate kill -9
	f2, have2, _ := st.OpenPart(sum)
	if have2 != 400000 { t.Fatalf("resume at %d", have2) }
	f2.Write(data[400000:])
	if err := st.CommitPart(sum, f2, int64(len(data))); err != nil || !st.Has(sum) { t.Fatal(err) }
}
func TestCommitPartMismatchDeletes(t *testing.T) { /* wrong bytes: error, Has false, part file gone */ }
func TestCommitPartSizeMismatch(t *testing.T) { /* right hash, wantSize+1: error, not stored */ }
func TestVerifyDetectsCorruption(t *testing.T) { /* flip a byte in blobs/<sum>: Verify errors; ReadVerified errors; blob still present until Delete */ }
func TestUsedAndDelete(t *testing.T) {}
func TestPutBoundedByMaxBlobSize(t *testing.T) { /* reader that yields MaxBlobSize+1 bytes of a wrong hash stops early with an error and stores nothing */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ -run 'Partial|CommitPart|Verify|Used|PutBounded' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Use `atomicfile` semantics for the rename (fsync the part, then rename, then fsync the directory).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: resumable partial blobs, streaming verify, blob size bound"`

---

### Task 8: `Build`: spec plus `index.d` to store and signed index

**Files:**
- Modify: `internal/depot/pack.go` renamed to `internal/depot/build.go`; `depot/tools.json` (add `"kind": "tool"`, `"priority": 1` and `needed_by` to every tool: Sysinternals `["winevt","hardening"]`, `nmap` `["vantage"]`, others none)
- Create: `depot/index.d/suricata-ruleset.yml`, `depot/index.d/wazuh-4.14.9.yml`, `depot/index.d/splunk-10.0.10.yml`, `depot/index.d/kev-feed.yml` (skeleton entries; `fetch_at_init: true` with `sha256` empty and a `# lab: fill the pinned sha256` comment, `needed_by` the owning modules, priority 1)
- Test: `internal/depot/build_test.go`

**Interfaces:**
- Consumes: Task 6, 7; `signing.Signer`.
- Produces:

```go
type IndexEntry struct {
	Entry `yaml:",inline"`
	File  string `yaml:"file,omitempty"` // relative to SrcDir: hashed into the store; empty = pinned hash and URL only
}
func LoadIndexDir(dir string) ([]IndexEntry, error) // *.yml in name order; unknown fields are an error
type BuildInput struct {
	Spec     *Spec          // depot/tools.json
	SrcDir   string
	IndexDir string         // depot/index.d
	Store    Store
	Signer   signing.Signer
	BaseURL  string         // release channel base; an entry with a File and no URL gets BaseURL + "/" + sha256
	Now      time.Time
}
func Build(in BuildInput) (*Manifest, error) // Pack's behaviour plus index.d; writes Store.ManifestPath() (signed) and Dir/CHANGELOG.txt (added, removed, changed keys versus the previous index in the store)
```
`Pack` and `phylax depot pack` are deleted (no alias); Task 13 moves the command.

- [ ] **Step 1: Write the failing tests:**

```go
func TestBuildMergesSpecAndIndexDir(t *testing.T) { /* spec tool busybox (file) + index.d package entry with file: result has both; every blob with a file is in the store; signed index parses with the test key */ }
func TestBuildFillsReleaseURL(t *testing.T) { /* entry with file and empty URL gets BaseURL+"/"+sha256 */ }
func TestBuildKeepsFetchAtInitPins(t *testing.T) { /* entry fetch_at_init with sha256 empty is allowed and keeps empty */ }
func TestBuildRefusesMissingFile(t *testing.T) { /* tool without file and not fetch_at_init: error naming the tool */ }
func TestBuildWritesChangelog(t *testing.T) { /* second Build with one entry changed and one removed: CHANGELOG.txt lists "changed <key>", "removed <key>" */ }
func TestLoadIndexDirRejectsUnknownField(t *testing.T) {}
func TestRepoIndexDirAndToolsValidate(t *testing.T) { /* LoadIndexDir("../../depot/index.d") and LoadSpec("../../depot/tools.json") parse; the merged entries pass Manifest.Validate; no entry has kind "" ; no file in depot/ or internal/depot mentions "typst" (Known bug 3) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ -run 'Build|LoadIndexDir|RepoIndexDir' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `Build` (delete `Pack`); update `depot_test.go` and `cmd/phylax/depot_test.go` to use `Build`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: Build merges the tool spec and index.d into one signed index"`

---

### Task 9: Priority-ordered, resumable, bandwidth-capped sync

**Files:**
- Create: `internal/depot/sync.go`
- Modify: `internal/depot/store.go` (`Fetcher.Fetch(ctx, e Entry, off int64)`; `FetchMissing` passes 0), `cmd/phylax/depot.go` (`httpFetcher` sends `Range: bytes=<off>-`)
- Test: `internal/depot/sync_test.go`

**Interfaces:**
- Consumes: Task 6, 7, `SyncState` and `FailedEntry` (Task 1).
- Produces:

```go
type Fetcher interface {
	Fetch(ctx context.Context, e Entry, off int64) (io.ReadCloser, error) // bytes from off; a server that ignores the range returns the whole object and the caller discards off bytes
}
type SyncOptions struct {
	Store         Store
	Fetcher       Fetcher
	Mirrors       []string                  // allowed hosts; an entry whose URL host is not listed fails with "host not in mirrors"
	Priorities    []int                     // which priorities, in order; nil = 0,1,2
	BandwidthKbps int                       // 0 = uncapped
	Parallel      int                       // default 2
	Want          func(Entry) bool          // cache plan filter; nil = all
	OnState       func(SyncState)           // at most once per 30 s while running, and on every state change
	Now           func() time.Time
}
func Sync(ctx context.Context, m *Manifest, o SyncOptions) error // blocks until every wanted entry of the priorities is stored or failed; the error joins the failures; a failed entry never stops the others
```
Rules. Entries with `Has(sha256)` count done without a fetch. Order: priority ascending, then size ascending. Each download resumes from `OpenPart`, verifies with `CommitPart`; a hash mismatch deletes the part and records `blob_corrupt`-style reason, retrying once from zero. Entries without a URL and not in the store fail with `not in the store and no URL`. `FetchAtInit` with empty `SHA256` fails with `no pinned hash yet`. The limiter is a token bucket shared by all workers (`BandwidthKbps*1000/8` bytes per second). `State` is `syncing` while work remains, `waiting` when the only remaining entries are retrying after a network error (backoff 1 s doubling to 60 s, max 5 tries), `failed` when entries failed and nothing remains, `idle` when done.

- [ ] **Step 1: Write the failing tests** (an `httptest` mirror serving blobs and honouring `Range`, plus a counting `Fetcher`):

```go
func TestSyncOrdersByPriorityThenSize(t *testing.T) { /* entries p2 small, p1 big, p1 small, p0: fetch order p0, p1small, p1big, p2 (Parallel 1) */ }
func TestSyncResumesAfterKill(t *testing.T) { /* first run: cancel ctx after 400000 of 1 MiB bytes; second run sends Range from 400000 (assert server saw "bytes=400000-"); blob stored once, hash ok */ }
func TestSyncBandwidthCap(t *testing.T) { /* 64 kbps cap, 40 KiB blob with a fake clock: not completed before 5 s of fake time have passed */ }
func TestSyncMirrorAllowlist(t *testing.T) { /* URL on evil.example: entry failed "host not in mirrors"; fetcher never called for it; others proceed */ }
func TestSyncCorruptBlobRetriedOnceFromZero(t *testing.T) { /* first body has a flipped byte: after the retry the good body is stored; a permanently bad body ends failed with "hash mismatch" and no blob */ }
func TestSyncFailureDoesNotStopOthers(t *testing.T) { /* one 500 entry: others stored; Sync error mentions the failed name; last OnState.Failed has it */ }
func TestSyncStateReporting(t *testing.T) { /* OnState sequence ends "idle" with EntriesDone == EntriesTotal; with a failed entry ends "failed"; calls within 30 s of fake time are coalesced except on state change */ }
func TestSyncSkipsHeldBlobsOffline(t *testing.T) { /* all blobs present, Fetcher fails the test if called: returns nil (T40 building block) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ -run 'Sync' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `Sync` with a worker pool; the limiter is a small type in the same file.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/ ./cmd/phylax/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: priority-ordered resumable sync with bandwidth cap and mirror allowlist"`

---

### Task 10: Cache plan from the manifest and the enabled modules

**Files:**
- Create: `internal/depot/cacheplan.go`
- Test: `internal/depot/cacheplan_test.go`

**Interfaces:**
- Consumes: Task 6; `manifest.Manifest` (`Hosts`, `Services`, `OS`, the new `Service.Packages`).
- Produces:

```go
type Pin struct { // operator-pinned vendor entry (a depot_entry row with provenance operator)
	Name, Version, OS, Arch, Kind, URL, SHA256 string
	Size                                       int64
}
type CachePlan struct {
	Want    map[string]bool   // Entry.Key() -> wanted
	Reasons map[string]string // Key -> "closure for rocky-9 (web)" | "integration wazuh" | "priority 0" | "operator pin"
}
func OSTag(o manifest.OS) string // "rocky-9", "ubuntu-22.04", "windows-server-2022", "windows-11"
func BuildCachePlan(idx *Manifest, m *manifest.Manifest, enabled func(module string) bool, pins []Pin, drop []string) CachePlan
func (p CachePlan) Wants(e Entry) bool
func (p CachePlan) PendingFor(idx *Manifest, st Store, module string) []Entry // wanted entries NeededBy module and absent: the "waiting for cache" list
```
Rules. Priority 0 and 1 entries are wanted unless `NeededBy` is non-empty and none of those modules is enabled. A priority 2 entry of kind `package` is wanted when its `OS` equals `OSTag` of some host and (its `Name` or one of its `Provides` is in the `Packages` of a service on a host of that OS). Entries of kind `bundle`, `installer`, `ruleset` are wanted when a module in `NeededBy` is enabled. `drop` removes keys. Pins are added as wanted with reason `operator pin`. `shortcut: closures are matched by package name only, not by dependency resolution; the build job records the closure inside the archive, upgrade if hosts drift from the lab images`.

- [ ] **Step 1: Write the failing tests** (fixture manifest: `rocky-ecom` rhel/rocky/9 with service `web` packages `[httpd, php]`; `win11-wkst`; index entries for `closure-httpd` OS `rocky-9` p2 kind package provides `[httpd]`, `closure-nginx` OS `rocky-9` p2, `closure-httpd-u22` OS `ubuntu-22.04` p2, `wazuh-manager` bundle p1 needed_by `[wazuh]`, `sysmon` tool p1 needed_by `[winevt]`):

```go
func TestOSTag(t *testing.T) { /* rocky/9 -> rocky-9; ubuntu/22.04; windows server-2022 -> windows-server-2022; windows 11 -> windows-11 */ }
func TestPlanSelectsClosureByHostOSAndServicePackages(t *testing.T) { /* wanted: closure-httpd; not wanted: closure-nginx (no service lists it), closure-httpd-u22 (no ubuntu-22.04 host with that package) */ }
func TestPlanIntegrationFollowsEnabledModules(t *testing.T) { /* enabled(wazuh)=false: wazuh-manager unwanted; true: wanted with reason "integration wazuh" */ }
func TestPlanDropAndPins(t *testing.T) { /* drop removes; a Pin appears wanted, reason "operator pin" */ }
func TestPendingForListsMissingNeededBy(t *testing.T) { /* wazuh enabled, bundle absent from store: PendingFor(..., "wazuh") has it; after Put none */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ -run 'OSTag|Plan|PendingFor' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: cache plan from hosts, services and enabled modules"`

---

### Task 11: Index refresh and downgrade protection

**Files:**
- Create: `internal/depot/refresh.go`
- Test: `internal/depot/refresh_test.go`

**Interfaces:**
- Consumes: Task 6, 9 (`Fetcher`).
- Produces:

```go
var ErrOlder = errors.New("depot: index is older than the current one")
type Refresher struct {
	Store  Store
	Key    signing.Verifier
	Source func(ctx context.Context) ([]byte, error) // returns the signed index bytes from the first channel that answers (release asset, dist/ file, vendor mirror)
}
func (r Refresher) Refresh(ctx context.Context) (*Manifest, bool, error) // true when a newer index was installed
func LoadCurrent(st Store, v signing.Verifier) (*Manifest, []byte, error) // reads and verifies Store.ManifestPath()
```
Rules. A candidate is parsed with `Key`; unsigned or wrong key returns the parse error and installs nothing; an index whose `Created` is older than the current is `ErrOlder`; equal `Created` is a no-op (false). Installation is an atomic write of `depot.json`. Nothing is deleted from `blobs/`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestRefreshInstallsNewer(t *testing.T) {}
func TestRefreshRefusesOlderIndex(t *testing.T) { /* Review Focus 1: Created 2026-10-30 offered over 2026-10-31: ErrOlder, depot.json bytes unchanged */ }
func TestRefreshRefusesWrongKey(t *testing.T) { /* signed by another key: error, current index unchanged */ }
func TestRefreshRefusesUnsigned(t *testing.T) { /* errors.Is(err, ErrNoSig) */ }
func TestRefreshEqualIsNoop(t *testing.T) { /* installed == false, err nil */ }
func TestLoadCurrentRejectsTamperedFile(t *testing.T) { /* edit one byte of depot.json in the store: LoadCurrent errors */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ -run 'Refresh|LoadCurrent' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: signed index refresh refuses older, unsigned and wrong-key indexes"`

---

### Task 12: Cache-through and operator pins

**Files:**
- Create: `internal/depot/throughcache.go`
- Test: `internal/depot/throughcache_test.go`

**Interfaces:**
- Consumes: Task 7, 9 (`Fetcher`, mirror check).
- Produces:

```go
var ErrHostNotAllowed = errors.New("depot: host not in mirrors")
type Through struct {
	Name, Version, OS, Arch, Kind, URL string
	SHA256                             string // the observed hash
	Size                               int64
	Provenance                         string // "cache-through"
}
func CacheThrough(ctx context.Context, st Store, f Fetcher, mirrors []string, req Pin, log *slog.Logger) (Through, error) // req.SHA256 empty; stores under the observed hash; logs the request (url, host, hash)
func FetchPinned(ctx context.Context, st Store, f Fetcher, mirrors []string, p Pin, log *slog.Logger) (Through, error) // p.SHA256 required; Provenance "operator"; a mismatch stores nothing
```
Rules. The URL host must be in `mirrors` (`ErrHostNotAllowed` before any request). Blobs are bounded by `MaxBlobSize`. A cache-through blob is not in the signed index; it is installable only by a plan node naming its `sha256` (Task 17 enforces on the agent).

- [ ] **Step 1: Write the failing tests:**

```go
func TestCacheThroughStoresUnderObservedHash(t *testing.T) { /* mirror serves bytes; Through.SHA256 == sha256(bytes); st.Has; Provenance "cache-through"; log line contains the URL */ }
func TestCacheThroughRefusesUnlistedHost(t *testing.T) { /* errors.Is ErrHostNotAllowed; fetcher not called */ }
func TestFetchPinnedChecksEnteredHash(t *testing.T) { /* wrong hash: error, st empty; right hash: stored, Provenance "operator" */ }
func TestFetchPinnedRequiresHash(t *testing.T) {}
func TestCacheThroughBounded(t *testing.T) { /* body longer than MaxBlobSize aborts without storing (use a limit override var for the test) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ -run 'CacheThrough|FetchPinned' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: cache-through and operator-pinned fetches through the mirror allowlist"`

---

### Task 13: `phylax cache` commands and the adapted `phylax depot`

**Files:**
- Create: `cmd/phylax/cache.go`
- Modify: `cmd/phylax/depot.go` (delete `pack` and `fetch`; `httpFetcher.Fetch(ctx, e, off)`), `cmd/phylax/main.go` (`register(command{name: "cache", ...})`), `cmd/phylax/depot_test.go`
- Test: `cmd/phylax/cache_test.go`

**Interfaces:**
- Consumes: Tasks 8, 9, 11; the existing `register(command{...})` pattern in `main.go`.
- Produces: `phylax cache build --spec depot/tools.json --index-d depot/index.d --src out/ --store dist/depot --key release.key [--base-url URL]`; `phylax cache sync --store DIR --pub HEX [--source URL|DIR] [--priority 0,1,2] [--kbps N] [--mirror host]...` (runs `Sync` against the signed index in the store, printing one progress line per state change); `phylax cache refresh --store DIR --pub HEX --from URL|FILE`; `phylax cache status --store DIR --pub HEX` (per priority: entries and bytes done, failed). `--source DIR` reads blobs from a local directory laid out as `<dir>/blobs/<sha256>` (the signed-release fallback under `dist/`).

- [ ] **Step 1: Write the failing tests:**

```go
func TestCacheBuildSyncStatusRoundTrip(t *testing.T) { /* keygen via runDepot; build a 2-tool index into storeA; sync from DIR source into storeB; status prints "priority 1: 2/2" and exits 0; remove one blob from storeB; status exits non-zero and names it */ }
func TestCacheSyncRefusesUnsignedIndex(t *testing.T) { /* store with an index signed by another key: error mentions signature; no blob written */ }
func TestDepotPackAndFetchRemoved(t *testing.T) { /* runDepot("pack") and ("fetch") return the usage error: commands deleted, not aliased */ }
func TestHTTPFetcherSendsRange(t *testing.T) { /* off 100 -> request header "Range: bytes=100-" ; 200 response with full body is trimmed to start at 100 */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./cmd/phylax/ -run 'Cache|DepotPack|HTTPFetcher' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Update `docs/depot.md` (commands, the index, priorities) in this commit; delete its Typst remnants if any.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./cmd/phylax/ && ./bin/phylax cache 2>&1 | head -5`. Expected: PASS and the usage text.
- [ ] **Step 5: Commit.** `git commit -am "cmd: phylax cache build|sync|refresh|status; depot pack and fetch folded into it"`

---

### Task 14: `depot` controller module (config, health, sync scheduler, tables, events)

**Files:**
- Modify: `internal/depot/{config,manifest_mod,module}.go`, `internal/depot/tables.go` (new), `internal/module/conformance/allowed.go` (removed in Task 15, when the agent half also conforms), `cmd/phylax/serve.go` (`controller.Options.Stage = depot.Default.Stage`, `Options.Backends["depot"]`)
- Create: `internal/depot/conformance_ctl_test.go`
- Test: `internal/depot/module_test.go`, `internal/depot/tables_test.go`

**Interfaces:**
- Consumes: Tasks 6 to 12; W1 `module.Host` (`Config`, `Emit`, `Tables`, `Manifest`, `UI`, `Logger`), `Controller.PushBlob` (Task 5); W6 `Host.Manifest()`.
- Produces:

```go
var Default = &Module{}                       // registered; serve.go reads it
type Module struct{ /* store, index, plan, state behind a mutex */ }
func (m *Module) Manifest() module.Manifest
func (m *Module) Start(ctx context.Context, h module.Host) error // decodes Config; opens the store; LoadCurrent; builds the cache plan; starts Sync at once ("start: t0"); one writer goroutine for the tables
func (m *Module) Health() module.Health
func (m *Module) ConfigBlock() any            // Config{}
func (m *Module) Stage(ctx context.Context, host string, n plan.Node) error // resolve n.Params["source"] "depot:<name>[/<version>]" against the host's OS tag; push the signed index then the blob; no-op when n has a sha256 and it is a cache-through blob already staged
func (m *Module) Pending(module string) []string // names of wanted entries NeededBy module and absent: "waiting for cache"
```
Tables (migrations in order, names exact): `depot_entry(key TEXT PRIMARY KEY, name TEXT, version TEXT, os TEXT, arch TEXT, kind TEXT, priority INTEGER, sha256 TEXT, size INTEGER, state TEXT, reason TEXT, provenance TEXT, updated TEXT)` with `state` in `wanted | have | failed`, `provenance` in `release | vendor | cache-through | operator`; `depot_sync(id INTEGER PRIMARY KEY CHECK (id = 1), index_version TEXT, signature TEXT, priority INTEGER, entries_total INTEGER, entries_done INTEGER, bytes_total INTEGER, bytes_done INTEGER, state TEXT, updated TEXT)`.

Health. `disabled` when not enabled; `unavailable` when the index fails its signature or the store is not writable (Gap `index signature invalid` / `store not writable: <err>`); `degraded` when sync is waiting or any entry of an enabled priority failed (Gap per failed entry, for example `wazuh bundle 4.14.9 not cached: network`); else `ok`. `Info` has `index_version` and `signature` (`ok|invalid`). Events: `depot.sync_state` from the sync callback through `Host.Emit` (the Sync callback already coalesces to one per 30 s plus state changes); `depot.problem{index_unsigned}` once when the signature fails; `depot.problem{fetch_failed, entry}` once per newly failed entry; `blob_corrupt` when `Stage` finds a stored blob failing `Store.Verify` (it deletes the blob so the next sync refetches it). The module has no `act_enabled` (S4): nothing is pushed to hosts except through `Stage` (a plan node an operator approved). The writer goroutine also applies the module's `operator.edit` events (`op: add`: cache-through blobs and operator pins) to `depot_entry`.

- [ ] **Step 1: Write the failing tests** (a fixture store with a signed 3-entry index, an `httptest` mirror, the W1 controller conformance helpers):

```go
func TestControllerConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Module{}, Config: "enabled: true\nstore_dir: STORE\nrelease_key: PUB\n", Now: time.Unix(1e9, 0)}) // STORE and PUB substituted by a helper
}
func TestStartWithNoConfigIsUnavailable(t *testing.T) { /* ErrNoConfig path: Health state unavailable with a gap, Start returns nil after ctx ends */ }
func TestHealthDegradedNamesFailedEntry(t *testing.T) { /* mirror 500s one priority-1 entry: after sync Health().State == degraded and a Gap.What contains the entry name */ }
func TestHealthUnavailableOnBadSignature(t *testing.T) { /* index signed by another key: unavailable, depot.problem{index_unsigned} emitted exactly once across two checks */ }
func TestSyncStateEventsAreDeclaredAndRateLimited(t *testing.T) { /* every emitted event passes event.Validate; fewer than 5 sync_state events for a 10-entry sync */ }
func TestTablesTrackEntriesAndSyncRow(t *testing.T) { /* after sync depot_entry rows state "have" for stored entries, depot_sync.state "idle", entries_done == entries_total */ }
func TestStagePushesIndexThenBlob(t *testing.T) { /* fake PushBlob recorder: order index sha then blob sha; source "depot:wazuh-manager/4.14.9" for an ubuntu-22.04 host picks the OS-matching entry */ }
func TestStageUnknownSourceFails(t *testing.T) { /* error "not in the index: <source>" ; message used as "blob not staged: ..." */ }
func TestPendingListsWaitingEntries(t *testing.T) {}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ -run 'Controller|StartWith|Health|SyncState|Tables|Stage|Pending' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Stage` computes the OS tag from `Host.Manifest()` for the target host; a node target that is not a host (controller or device) is a no-op.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/ ./cmd/phylax/ && make build-windows`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: controller module with sync scheduler, tables, health and staging"`

---

### Task 15: `depot` agent module (verify loop, deploy from staging) and `genconfig`

**Files:**
- Modify: `internal/depot/agent.go`, `internal/agent/mods/depot.go`, `internal/controller/genconfig.go` (render `Modules.Depot` for every host where the module is effective), `internal/depot/deploy.go` (`Verify` returns the planted-file problem separately)
- Create: `internal/depot/conformance_agent_test.go`
- Test: `internal/depot/agent_test.go`, `internal/controller/genconfig_depot_test.go`

**Interfaces:**
- Consumes: Task 4 (`StageDir`, `agent.fetch_result`), Task 6 and existing `Deploy`, `OpenDeployed`, `Verify`; W1 `agent.Factory`, `agent.Env`, `module.Health`.
- Produces: `agent.Factory{Name: "depot", Manifest: Manifest(), Section: ..., Build: ...}` in `mods/depot.go`; an agent `Module` that, every 5 s while the staged index file `StageDir()/blobs/<index sha>` or the file `StageDir()/index.sha256` changes, verifies the staged signed index with `DepotSettings.ReleaseKey`, runs `Deploy` into `Dir` (empty = `HiddenDir(base, secret)`, mode 0700) for the staged tool blobs of its OS and arch, and emits `depot.deploy{dir_hash, tools, missing, ok}`; every `VerifyIntervalSec` it runs `Deployed.Verify()` and emits `depot.problem` (`verify_failed` for a hash mismatch, `planted_file` for an unexpected file, both critical) and re-emits `depot.deploy` with `ok:false`. Health: `ok` when the deployed depot verifies or nothing is deployed yet; `degraded` when staging is at more than 90 percent of `stage_mb` or a tool is missing. `genconfig` fills `Dir` (empty), `StageMB` (default 512), `VerifyIntervalSec` (default 600), `ReleaseKey` (module config or `ReleaseKeyHex`), and `Packages` (package name to service names from this host's services in `services.yml`, Task 19 relies on it).
- How the module learns which staged blob is the index: `agent/stage.go` calls `Agent.OnStaged func(sum string)` after every staged blob (Task 4 adds the field, nil by default); the depot module registers it, tries `Parse` with the release key on that blob, and when it parses writes `StageDir()/index.sha256` atomically. A blob that does not parse as an index is ignored by the callback.

- [ ] **Step 1: Write the failing tests:**

```go
func TestAgentConformance(t *testing.T) { /* conformance.Agent with Default {Enabled:true, StageMB:512, VerifyIntervalSec:1} and Reconfig {VerifyIntervalSec:2} */ }
func TestDeployFromStagedIndex(t *testing.T) { /* stage a signed index (2 tools for this GOOS/GOARCH) and the blobs; module deploys into a temp Dir: bin/<tool> mode 0500, depot.json present; depot.deploy ok:true with both tools; dir_hash is not the path */ }
func TestStagedIndexWithWrongKeyIsNotDeployed(t *testing.T) { /* depot.problem{index_unsigned}; no bin dir */ }
func TestVerifyLoopReportsTamperAndPlantedFile(t *testing.T) { /* modify a deployed tool: critical depot.problem{verify_failed, entry}; add bin/evil: critical planted_file */ }
func TestHealthDegradedWhenStageNearlyFull(t *testing.T) {}
func TestGenconfigRendersDepotSettings(t *testing.T) { /* host rocky-ecom with service web packages [httpd, php]: Packages {"httpd": ["web"], "php": ["web"]}; ReleaseKey from the module block; StageMB 512 */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ ./internal/controller/ -run 'AgentConformance|DeployFromStaged|WrongKey|VerifyLoop|StageNearlyFull|GenconfigRendersDepot' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Remove `depot` from `PreContract` here (both halves now conform). Run `go test ./internal/module/all/ -run Schema -update` for `manifest/schema/modules/depot.schema.json`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/ ./internal/controller/ ./internal/module/... && make build-windows`. Expected: PASS, including `TestNoSiblingImports` and `TestKindTable` with `depot` a contract module.
- [ ] **Step 5: Commit.** `git commit -am "depot: agent module deploys staged tools and verifies them; genconfig depot settings"`

---

### Task 16: `depot` UI (Platform section, overview tile, deploy and pin actions)

**Files:**
- Create: `internal/depot/ui.go`, `internal/depot/templates/depot_status.html` (or inline `html/template`)
- Test: `internal/depot/ui_test.go`

**Interfaces:**
- Consumes: Task 14 module state and tables; W1 `ui.Registrar` (`Page`, `Tile`, `Action`), `ui.Cell`.
- Produces: `GET /m/depot/status` (per priority: entries and bytes done, current rate, failed entries with reasons, index version, signature state; a "blocked features" list from `NeededBy`); tile `cache` (green when priorities 0 and 1 are complete, amber while syncing, red on a failed signature); `POST /m/depot/action/deploy` (`host`) which calls `Stage` for the index and that host's tool blobs; `POST /m/depot/action/pin` (`name, version, os, arch, kind, url, sha256`) which runs `FetchPinned` and writes a `depot_entry` row `provenance operator` (installable only after a plan names its `sha256`). Hostile strings (entry names, reasons from the network) are escaped by `html/template`; actions need the logged-in operator (the registrar's wrapper).

- [ ] **Step 1: Write the failing tests:**

```go
func TestStatusPageShowsPrioritiesAndEscapesReasons(t *testing.T) { /* a failed entry reason "<script>x</script>" renders as &lt;script&gt;; priority rows show "2/3" and byte counts */ }
func TestTileColours(t *testing.T) { /* p0+p1 complete -> "green"; syncing -> "amber"; signature invalid -> "red" (assert the tile HTML class) */ }
func TestDeployActionStagesToolsForHost(t *testing.T) { /* POST host=h1 -> recorder saw PushBlob for the index and each tool of h1's GOOS/arch from the manifest */ }
func TestPinActionRejectsBadHashAndUnlistedHost(t *testing.T) { /* sha mismatch -> 4xx, no row; URL host not in mirrors -> 4xx */ }
func TestPinActionRecordsOperatorRow(t *testing.T) {}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ -run 'StatusPage|Tile|DeployAction|PinAction' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** and register in `Start` through `h.UI()`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: Platform page, cache tile, deploy and pin actions"`

---
### Task 17: Package actions move to `depot` and install from staged closures (Known bug 21, part 1)

**Files:**
- Move (`git mv`): `internal/actions/linux_pkg.go` to `internal/depot/pkg.go`, `linux_pkg_test.go` to `internal/depot/pkg_test.go`; the `pkg.*` entries leave `linuxActions()` in `internal/actions/registry_linux.go`
- Modify: `internal/actions/linux_env.go` (delete `PatchWindow`, `requireWindow`, `DepotDir`, `pkgScoredAliases` users; add `StageDir string`, `DepotLookup func(name, version string) (sha256 string, err error)`, `PackageServices func(pkg string) []string`; export `(*LinuxEnv).Runner()` and the other helpers the moved file needs, using W5's already exported names where they exist), `internal/actions/imports_test.go` (W6's guard: add `internal/depot`)
- Test: `internal/depot/pkg_test.go`

**Interfaces:**
- Consumes: Task 4 `ExtractClosure`; W6 `actions.Register`; the `CommandRunner` fake in the moved tests.
- Produces: `pkg.install{name, version, source, sha256}` (one action for a first install, an upgrade, a reinstall and a downgrade, S4: there is no `pkg.upgrade`), `pkg.remove{name}` registered by `internal/depot` (`init` calls `actions.Register`), `Runs: RunsAgent`, `Risk: RiskService`, `Locks: [LockPackages]`.

Rules. Resolution of the package closure: (1) `sha256` given: the staged blob `StageDir/blobs/<sha256>` (a cache-through or operator-pinned closure); (2) else `source: "depot:<name>/<version>"` (or `depot:<name>` with the `version` param): `DepotLookup` returns the sha256 from the verified staged index. Either way the blob is re-hashed with `Store.Verify` semantics immediately before use, extracted with `ExtractClosure` (limits 4096 files, 2 GiB) into `StageDir/closures/<sha256>/` if absent, and every `*.deb` (apt) or `*.rpm` (dnf) in it is passed to one transaction: `apt-get -o Dir::Etc::sourcelist=/dev/null -o Dir::Etc::sourceparts=/dev/null install -y --no-install-recommends <files>` (dry run `-s`), `dnf --disablerepo=* install -y <files>` (dry run `--assumeno`). A `check` with nothing staged fails `blob not staged: <source>`. No patch window, no proxy, no network. A missing `version` and `source` and `sha256` is an error (`a package is never installed without a pinned version or a depot source`). `pkg.remove` is unchanged except it uses `PackageServices` (Task 19). The note "package changes are not rolled back automatically; reinstall the previous version" stays.

- [ ] **Step 1: Write the failing tests** (port the existing ones that still apply; fixture closures are tar files built in the test):

```go
func TestInstallFromStagedClosureIndexResolved(t *testing.T) { /* Env{Root: tmp, Linux: {StageDir, PackageManager:"apt", Exec: fake, DepotLookup: returns sum}}; staged blob = tar{a.deb,b.deb,SHA256SUMS}; Apply runs one command whose argv contains both files and the two -o Dir::Etc flags and no "Acquire::http::Proxy"; Output has no "window" key */ }
func TestInstallBySHA256NeedsNoIndex(t *testing.T) { /* DepotLookup nil, sha256 param names the staged blob: works */ }
func TestInstallNotStagedFailsInCheck(t *testing.T) { /* Plan returns error containing "blob not staged" */ }
func TestInstallRehashesBeforeUse(t *testing.T) { /* flip a byte of the staged blob between Plan and Apply: Apply errors with "sha256" and the runner was not called */ }
func TestInstallDryRunShowsSimulatedTransaction(t *testing.T) { /* fake runner returns apt -s output; Plan.Diff contains it */ }
func TestInstallWithoutPinNorSourceRefused(t *testing.T) {}
func TestDnfUsesDisablerepo(t *testing.T) { /* PackageManager "dnf": argv contains "--disablerepo=*" */ }
func TestNoPatchWindowRequired(t *testing.T) { /* Known bug 21: Env without PatchWindow (the field is gone) installs; grep-style: strings.Contains(source of pkg.go, "requireWindow") is false is not tested, the compile proves it */ }
func TestActionsImportsNoDepot(t *testing.T) { /* W6 guard list includes internal/depot */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ ./internal/actions/ -run 'Install|NoPatchWindow|ActionsImports' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the move and rewrite `Plan`, `Apply`, `argv` and `depotFile` (replace by `stagedClosure(env, p) (dir string, files []string, sum string, err error)`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/ ./internal/actions/ && make build-windows`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: pkg actions install from staged closures; patch window and proxy removed"`

---

### Task 18: `pkg.install` reinstall and downgrade form, and `pkg.repair`

**Files:**
- Modify: `internal/depot/pkg.go` (the reinstall and downgrade form of `pkg.install`), create `internal/depot/pkg_repair.go`
- Test: `internal/depot/pkg_reinstall_test.go`, `internal/depot/pkg_repair_test.go`

**Interfaces:**
- Consumes: Task 17 `stagedClosure`, `pkgMgr`.
- Produces: no `pkg.reinstall` action (S4): `pkg.install{name, version, source, sha256}` covers it with the same resolution, risk and lock as Task 17. When the installed version equals `version` it reinstalls; when `version` is lower it goes down (apt `install --reinstall --allow-downgrades`, dnf `downgrade` when the installed version differs, else `reinstall`). `pkg.repair{}` (`Risk: RiskService`, lock `packages`, no params) with these findings, each fixed in `Apply` and re-checked in `Verify`: stale lock files (`/var/lib/dpkg/lock-frontend`, `/var/lib/dpkg/lock`, `/var/lib/apt/lists/lock`, `/var/cache/apt/archives/lock`, `/var/lib/rpm/.rpm.lock`) removed only when no process holds them (`fcntl` probe through the runner is not needed: the check opens with `O_RDWR` and tries a non-blocking `flock`); an interrupted dpkg (`/var/lib/dpkg/updates/` has numeric files) fixed with `dpkg --configure -a`; a corrupt rpm database (`rpm -qa` exits non-zero) fixed with `rpm --rebuilddb`. A missing package-manager binary and empty or broken sources are reported in `Plan.Notes` and not changed. `shortcut: repair does not restore a missing package manager or rewrite sources; the installs here ignore configured repositories, so that is only needed if a node needs the host's own repositories, upgrade then`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestReinstallDowngradesToPreviousVersion(t *testing.T) { /* pkg.install with installed 2.4.58 and version param 2.4.57 staged: apt argv has --reinstall and --allow-downgrades; dnf path uses "downgrade"; Verify passes when query reports 2.4.57 */ }
func TestReinstallSameVersionOnDnfUsesReinstall(t *testing.T) { /* pkg.install with the installed version again, dnf: argv uses reinstall; the registry has no pkg.reinstall and no pkg.upgrade */ }
func TestRepairRemovesOnlyUnheldStaleLocks(t *testing.T) { /* two lock files in the Root tmp tree, one flock'ed by the test: the free one removed, the held one kept and mentioned in Notes */ }
func TestRepairRunsDpkgConfigureForInterruptedUpdates(t *testing.T) { /* updates/0001 present: fake runner saw "dpkg --configure -a" */ }
func TestRepairRebuildsCorruptRpmDB(t *testing.T) { /* rpm -qa exit 1: runner saw "rpm --rebuilddb" */ }
func TestRepairCleanHostIsDone(t *testing.T) { /* Plan.Done true, Apply not called by the framework */ }
func TestRepairNeverTouchesSources(t *testing.T) { /* /etc/apt/sources.list bytes identical after Apply with an empty file there; Notes mention it */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ -run 'Reinstall|Repair' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** and register both in `init`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: pkg.install reinstall form and pkg.repair"`

---

### Task 19: Package-to-service map, `PK001`, and no hard-coded aliases (Known bug 21, part 2)

**Files:**
- Create: `internal/depot/lint.go`
- Modify: `internal/depot/pkg.go` (`scoredRemoval` uses `PackageServices`; delete `pkgScoredAliases`), `internal/agent` exec wiring that builds `LinuxEnv` (set `PackageServices` from `DepotSettings.Packages`, `StageDir` from `Agent.StageDir()`, `DepotLookup` from the depot agent module), `manifest/2027/services.yml` (add `packages:` to the reference web, mail, database, DNS and Splunk services), `internal/manifest/validate.go` (a package name is a non-empty string without spaces)
- Test: `internal/depot/lint_test.go`, `internal/depot/pkg_services_test.go`

**Interfaces:**
- Consumes: Task 1 `Service.Packages`, `DepotSettings.Packages` (rendered in Task 15); W1 `lint.Register`, `lint.Rule`, `lint.Ctx`, `lint.Finding`, `plan.ClassClick`.
- Produces: lint rule `PK001` (registered in `init`): for a node whose action is `pkg.install` or `pkg.remove`, with `Params["name"]` listed in the `Packages` of a scored service on the node's target host (`c.Manifest.Services`), and `c.Class != plan.ClassClick`, one finding `PK001`: `package <name> provides scored service <svc>; package changes that restart a scored service are click-only`. `pkg.remove` of such a package stays refused on the agent. Doc string for `PK001` states that the quiet window, the post-change probe and the human approval come from the existing scoring-safety rules for the service touch. `Plan` on the agent adds the note `restarts scored service <svc>` when `PackageServices` returns a name.

- [ ] **Step 1: Write the failing tests:**

```go
func TestPK001RefusesNonClickClassForScoredPackage(t *testing.T) { // Review Focus 3
	m := fixtureManifest(t) // rocky-ecom service web (scored) packages [httpd, php]
	node := plan.Node{ID: "n", Action: "pkg.install", Target: "rocky-ecom", Params: map[string]any{"name": "httpd", "version": "2.4.57"}}
	for _, class := range []plan.ApprovalClass{plan.ClassAuto, plan.ClassStanding, plan.ClassAutoReadOnly} {
		if fs := ruleByID(t, "PK001").Check(node, lint.Ctx{Manifest: m, Class: class}); len(fs) != 1 { t.Errorf("%s: %v", class, fs) }
	}
	if fs := ruleByID(t, "PK001").Check(node, lint.Ctx{Manifest: m, Class: plan.ClassClick}); len(fs) != 0 { t.Error("click refused") }
}
func TestPK001IgnoresUnscoredAndUnrelatedPackages(t *testing.T) { /* package "htop"; and "httpd" on a host where the service is not scored: no finding */ }
func TestRemoveRefusedForScoredServicePackage(t *testing.T) { /* Env.Linux.PackageServices returns ["web"] and Guard StaticGuard{Services:["web"]}: Plan errors ErrScoringUnsafe; a package mapped to an unscored service is allowed */ }
func TestInstallPlanNotesRestartedService(t *testing.T) {}
func TestNoHardCodedAliasMap(t *testing.T) { /* os.ReadFile("pkg.go") does not contain "pkgScoredAliases" (Known bug 21) */ }
func TestReferenceServicesListPackages(t *testing.T) { /* manifest.Load("../../manifest/2027") web, mail, db, dns, splunk services have non-empty Packages and the manifest validates */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ -run 'PK001|RemoveRefused|RestartedService|NoHardCoded|ReferenceServices' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/ ./internal/manifest/ ./internal/agent/ && make build-windows`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: package-to-service map from services.yml, PK001, aliases deleted (Known bug 21)"`

---

### Task 20: `pkg.fetch_to_depot` and `windows.hotfix` on staged blobs

**Files:**
- Create: `internal/depot/pkg_fetch.go`
- Move (`git mv`): `internal/actions/win_hotfix.go` to `internal/depot/hotfix.go`; modify `internal/actions/win_env.go` (`WinEnv.DepotDir` replaced by `StageDir string` and `DepotLookup func(name, version string) (string, error)`), `registry_win.go`
- Test: `internal/depot/pkg_fetch_test.go`, `internal/depot/hotfix_test.go`

**Interfaces:**
- Consumes: Tasks 9, 12, 14; W6 `Env.Ext`, `Runs: RunsController`.
- Produces: `pkg.fetch_to_depot{name, version, os, url}` (`Runs: RunsController`, `Risk: RiskNone`, not `ReadOnly` because it writes the store; `Touches` none; the executor reaches the module through `Env.Ext["depot"]` which is `Default`): checks the URL host against `mirrors`, runs `CacheThrough`, returns `Output{"sha256": ..., "provenance": "cache-through"}` and emits one `operator.edit` (`module: depot`, `op: add`, the full `Entry`, `by` the approver) that the writer projects into `depot_entry`; `Module.Through(ctx, req Pin) (Through, error)` is the method it calls. `windows.hotfix{kb}` resolves `kb` through `DepotLookup(kb, "")` to `blobs/<sha256>`, copies it to a temp file named `<kb>.msu` in a 0700 directory and runs `wusa /quiet /norestart` exactly as before; `windows.hotfix` keeps `Risk: RiskService`, lock `packages`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestFetchToDepotCacheThrough(t *testing.T) { /* module with a mirror httptest host in mirrors; Apply returns sha256 of the served bytes; one operator.edit{module depot, op add} and a depot_entry row with provenance "cache-through" after the writer runs; a second Apply with the same params is idempotent (Plan.Done) */ }
func TestFetchToDepotRefusesUnlistedHost(t *testing.T) { /* Plan errors ErrHostNotAllowed text; no request made */ }
func TestFetchToDepotRunsOnController(t *testing.T) { /* Spec().OnController() is true */ }
func TestHotfixInstallsFromStagedMSU(t *testing.T) { /* fake Executor records "wusa" args with a path ending KB5001234.msu inside a 0700 dir; temp dir removed after */ }
func TestHotfixNotStaged(t *testing.T) { /* error "blob not staged" */ }
```
(Existing hotfix tests are ported, keeping their assertions.)

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/depot/ ./internal/actions/ -run 'FetchToDepot|Hotfix' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/depot/ ./internal/actions/ && make build-windows`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: pkg.fetch_to_depot; windows.hotfix installs staged MSUs"`

---

### Task 21: `wazuh`: client backend and actions leave `internal/actions` (Known bug 17, part 1)

**Files:**
- Move (`git mv`): `internal/actions/app_wazuh.go` to `internal/wazuh/actions.go`; the wazuh parts of `internal/actions/app_misc_test.go` to `internal/wazuh/actions_test.go`
- Modify: `internal/actions/{registry_linux.go,linux_env.go}` (delete `wazuhHealth{}, wazuhCapture{}, wazuhTestAlert{}`, `LinuxEnv.Wazuh`, `WazuhAPI`, `WazuhGroupsAPI`, `WazuhFactory`), `internal/actions/imports_test.go` (add `internal/wazuh`), `internal/wazuh/{client,poll}.go` (`ToEvent` removed: events are built in Task 22)
- Test: `internal/wazuh/actions_test.go`

**Interfaces:**
- Consumes: W1 `Register`, `Env.Ext`; Task 1 `Config`.
- Produces:

```go
const ExtKey = "wazuh"
type API interface { // *Client implements it
	Health(ctx context.Context) (*Health, error)
	Agents(ctx context.Context) ([]Agent, error)
	Groups(ctx context.Context) ([]Group, error)
}
type Backend interface { // *Module implements it
	API(ctx context.Context, apiURL, minVersion string) (API, error)
}
```
`wazuh.check` (the design's name for the read-only health action) and `wazuh.capture` become `Runs: RunsController` (the credentials are controller vault secrets, never agent config); `wazuh.test_alert` stays an agent action on the manager host. The actions read `env.Ext[ExtKey].(Backend)`; absent returns `actions.Unsupported("wazuh API")`. The old agent-side credential hook is deleted. Existing assertions are kept: health pin and `min_active`, capture file set (`health.json`, `agents.json`, `agents.csv`, `groups.json`, `group_details.json`) and CSV injection safety, test-alert path under `/var/log` and marker regexp, append-only.

- [ ] **Step 1: Write the failing tests:** port the existing action tests to `package wazuh` with a fake `Backend` returning a `*Client` aimed at an `httptest` fake API; add:

```go
func TestHealthWithoutBackendIsUnsupported(t *testing.T) { /* errors.Is(err, actions.ErrUnsupported) */ }
func TestHealthAndCaptureRunOnController(t *testing.T) { /* Spec().OnController() true for both, false for test_alert */ }
func TestActionsImportsNoWazuh(t *testing.T) { /* go list -deps ./internal/actions has no internal/wazuh */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/wazuh/ ./internal/actions/ -v -run 'Wazuh|Health|Capture|TestAlert|Backend|ActionsImports'`. Expected: FAIL.
- [ ] **Step 3: Move and rewire.** `init` in `internal/wazuh` calls `actions.Register`; the controller executor builds `Ext["wazuh"] = Default` through `Options.Backends` (wired in Task 22).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/wazuh/ ./internal/actions/ ./internal/controller/ && make build-windows`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "wazuh: own the wazuh actions; actions imports no module"`

---

### Task 22: `wazuh` controller module (poll loop, alert conversion, health, UI section)

**Files:**
- Modify: `internal/wazuh/{module,config,manifest_mod}.go`, `internal/wazuh/client.go` (`ClientConfig` use), `cmd/phylax/serve.go` (`Options.Backends["wazuh"] = wazuh.Default`), `internal/module/conformance/allowed.go` (remove `wazuh` from `PreContract`)
- Create: `internal/wazuh/events.go`, `internal/wazuh/ui.go`, `internal/wazuh/conformance_test.go`
- Test: `internal/wazuh/module_test.go`

**Interfaces:**
- Consumes: Task 1 kinds and `Config`; Task 21 `API`, `Backend`; W1 `Host.Secrets`, `Host.Emit`, `Host.UI`; the client's `Alerts`, `Health`.
- Produces: `var Default = &Module{}`; `(*Module).Start` decodes `Config`, reads the secrets named in `Config.Secrets` (`api`, `indexer`) through `Host.Secrets`, builds the client (`ca_secret` PEM or `InsecureTLS`), polls every `poll_sec` (default 30): alerts at or above `min_level` since the last seen time become `wazuh.alert` events (`AlertEvent`, `FullLog` truncated to 2048 bytes; the Wazuh agent name in `WazuhAgent`; no `Agent` override: the Host stores controller events under `controller`), then health: when the result changes to degraded or unavailable (or its disconnected set changes), one common `telemetry_gap` event (`source: wazuh`, `reason: wazuh_degraded`, the design's fields in `detail`, priority high; the core `detect` rule on `telemetry_gap` raises the Platform alert); the full state stays in `Health.Info`, and a return to healthy emits nothing (S4: no `wazuh.health` kind). On a poll error nothing is consumed and the next poll retries from the same point with doubling backoff (30 s to 5 min). `Module.API` (the `Backend`) returns a client for the given URL with the same credentials. `min_active` in the health check is `Config.MinActive`.

Health. `disabled`; `ok` (manager at or above the pin, no agent newer, every enrolled agent active); `degraded` (an agent disconnected or never connected, or the indexer unreachable: Gap `alerts not imported: indexer unreachable`; `agents disconnected: <names>`); `unavailable` (API unreachable or authentication fails, or `manager below 4.14.9`). Platform tile: manager version and pin state, agents connected out of total with the disconnected names, last import time, count imported in the last hour.

- [ ] **Step 1: Write the failing tests** (fake Wazuh API and indexer from the existing client tests):

```go
func TestWazuhConformance(t *testing.T) { conformance.Controller(t, conformance.ControllerCase{Module: &Module{}, Config: "enabled: true\napi_url: URL\nindexer_url: URL\nsecrets: {api: wazuh.api, indexer: wazuh.indexer}\nmin_level: 7\n", Now: time.Unix(1e9, 0)}) }
func TestAlertsBecomeDeclaredEvents(t *testing.T) { /* fake indexer with 2 alerts; emitted events validate, Kind "wazuh.alert", fields wazuh_agent set, event stored with agent "controller" (Known bug 17: assert via store.Latest(ctx, "controller", "wazuh.alert") and none under agent "wazuh") */ }
func TestFullLogTruncated(t *testing.T) { /* 5000-byte full_log -> 2048 */ }
func TestPollErrorConsumesNothing(t *testing.T) { /* indexer 500 then OK: the same alerts arrive once after recovery; backoff doubled */ }
func TestDegradedGapOnChange(t *testing.T) { /* healthy twice -> no event; one agent disconnects -> one telemetry_gap{source wazuh, reason wazuh_degraded} at priority high; unchanged degraded polls -> no repeat; a different disconnected set -> a new gap; back to healthy -> none; Health.Info carries the counts and names */ }
func TestHealthStates(t *testing.T) { /* table: manager 4.14.3 -> unavailable "manager below 4.14.9"; agent newer -> degraded; API 401 -> unavailable; indexer down only -> degraded with the exact gap text */ }
func TestStartWithoutSecretsIsUnavailable(t *testing.T) {}
func TestBackendAPIUsesModuleCredentials(t *testing.T) { /* Default.API(ctx, otherURL, "") issues requests with the vault password */ }
func TestPlatformTileShowsAgents(t *testing.T) {}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/wazuh/ -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Update `docs/integrations.md` Wazuh paragraph.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/wazuh/ ./internal/module/... && make build-windows`. Expected: PASS, with `wazuh` a contract module.
- [ ] **Step 5: Commit.** `git commit -am "wazuh: controller module (poller, health, UI); alerts stored under controller (Known bug 17)"`

---

### Task 23: `splunk`: split the Splunk half out of `controller.Directory`; actions move

**Files:**
- Move (`git mv`): `internal/actions/splunk_api.go`, `splunk_actions.go`, `splunk_actions_test.go` to `internal/splunk/{api,actions}.go`, `actions_test.go`
- Create: `internal/splunk/directory.go`
- Modify: `internal/controller/dir_devices.go` (delete `Client`, `SplunkAccount`, `SplunkBase`, `SplunkHTTP`, the `splunk:` client, the `actions.SplunkDirectory` assertion), `internal/controller/exec.go` (the controller executor: `devexec_run.go` before W1 Task 29; W6 Task 3 changed its Env; use the file as merged), `internal/actions/{win_env.go,registry_win.go}` (delete `WinEnv.Splunk`, `SplunkDirectory`, the four registrations), `internal/actions/imports_test.go` (add `internal/splunk`)
- Test: `internal/splunk/actions_test.go`, `internal/splunk/directory_test.go`, `internal/controller/exec_redact_test.go`

**Interfaces:**
- Consumes: W6 Task 3 (**gate: merged**; `Env.Ext` from W1 Task 2a, `Options.Backends`, the device `Directory` in its post-W6 shape), Task 1 `Config`.
- Produces:

```go
package splunk
const ExtKey = "splunk"
type API interface { // was actions.SplunkAPI, same methods
	Get(ctx context.Context, path string, q url.Values) ([]byte, error)
	Post(ctx context.Context, path string, form url.Values) ([]byte, error)
	Delete(ctx context.Context, path string) ([]byte, error)
	As(user, password string) API
}
type Directory interface {
	Client(ctx context.Context, host string) (API, error)
	ScoredIndexes(ctx context.Context, host string) []string // from services.yml scored_indexes of the splunk services on host
}
func directoryFor(env *actions.Env) (Directory, error) // env.Ext[ExtKey], else actions.Unsupported("splunk")
func (m *Module) Client(ctx context.Context, host string) (API, error)   // *Module implements Directory and Redact
func (m *Module) ScoredIndexes(ctx context.Context, host string) []string
func (m *Module) Redact(s string) string
// controller executor: redaction and locking become backend-neutral
//   x.redact(s string) string  // Directory.Redact, then every Options.Backends value that has Redact(string) string, then the tracked secrets
//   x.lock(ctx, name string) (func(), error) // the per-name channel lock moves from Directory.Lock into the executor
```
Rules. `Client` builds `HTTPSplunk{Base, User: "admin", Password}` with the password from the vault name `Config.Secrets["mgmt"]` through `Host.Secrets`, base `Config.Sensor.MgmtURL` for `Sensor.Host` else `https://<manifest address of host>:8089`; TLS per Deviation 12 (CA, or per-host first-seen pin when `insecure_tls`, else system roots). `splunk.hec_setup` (and only it) refuses an index in `ScoredIndexes` or in the built-in set before any API call. `splunk.rest` and `splunk.password` keep their behaviour. There is no `splunk.sidecar_off` action (S4: a `service.state` step on the sidecar unit); all three Splunk actions are `Runs: RunsController`. `Directory.Lock` for devices stays; the executor's `lock` is used for both.

- [ ] **Step 1: Write the failing tests:** port every existing Splunk action test (index and token creation, refusal to rebind, disabled token, built-in index refusal, HEC enable and rollback, verify) to a fake `Directory`; add:

```go
func TestHECSetupRefusesScoredIndex(t *testing.T) { // Review Focus 4
	d := fakeDir{scored: []string{"main_scored", "ecom_logs"}}
	for _, ix := range []string{"main", "ecom_logs", "ECOM_LOGS"} { // built-in and declared, case-insensitive
		out := runPlan(t, d, "splunk.hec_setup", map[string]any{"index": ix, "token_name": "phylax-hec"})
		if out.err == nil || d.calls() != 0 { t.Errorf("%s: err %v, API calls %d", ix, out.err, d.calls()) }
	}
}
func TestDirectoryClientUsesVaultMgmtSecret(t *testing.T) { /* Authorization header carries admin:<secret>; the secret never appears in the returned error text via Redact */ }
func TestDirectoryTLSModes(t *testing.T) { /* system roots against a self-signed httptest server fails; insecure_tls pins first cert then rejects a different cert on the same host; ca_secret PEM verifies */ }
func TestDeviceDirectoryHasNoSplunkLeft(t *testing.T) { /* reflect: controller.Directory has no method Client; go list -deps ./internal/actions has no internal/splunk */ }
func TestExecutorRedactsBackendSecrets(t *testing.T) { /* controller test: a splunk node whose error contains the mgmt password: stored result text has "<redacted>" or the password absent; a device node still redacts device creds */ }
func TestExecutorLockSerialisesSplunkHost(t *testing.T) { /* two nodes on debian-splunk run one after the other */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/splunk/ ./internal/controller/ -run 'Splunk|HEC|Directory|Redact|Lock' -v`. Expected: FAIL.
- [ ] **Step 3: Move and rewire.** `init` in `internal/splunk` calls `actions.Register` and `RegisterUndo` for the HEC rollback; `serve.go` sets `Options.Backends["splunk"] = splunk.Default`. Delete `SplunkDirectory` users and update `docs/integrations.md`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/splunk/ ./internal/actions/ ./internal/controller/ && make build-windows`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "splunk: own the Splunk client and actions; device directory is devices only"`

---

### Task 24: `splunk` controller module (forwarder wiring, telemetry_gap, UI section)

**Files:**
- Modify: `internal/splunk/{module,config,manifest_mod,hec}.go`, `internal/module/conformance/allowed.go` (remove `splunk` from `PreContract`)
- Create: `internal/splunk/forward.go`, `internal/splunk/ui.go`, `internal/splunk/conformance_test.go`
- Test: `internal/splunk/module_test.go`, `internal/splunk/forward_test.go`

**Interfaces:**
- Consumes: Task 1 `Config`, `ForwarderState`; Task 23; the built `Forwarder` (`New(ForwarderConfig)`, `SendEvent`, `Stats`, `Close`); W1 `Host.Subscribe`, `Host.Secrets`, `Host.Emit`.
- Produces: `(*Module).Start`: decodes `Config`; reads the HEC token (`Secrets["hec_token"]`; absent means `unavailable` with the gap `HEC token missing in the vault`, and the module re-reads it every 30 s so a token written by `splunk.hec_setup` is picked up); builds the forwarder with `ForwarderConfig` from the block (defaults queue 1024, batch 100 or 512 KiB, flush 2 s, 4 retries, timeout 5 s, index `phylax`, source `phylax`, sourcetype `_json`); subscribes to the expanded `forward` kinds (`func ExpandForward(patterns []string, consumes []string) ([]string, error)`: exact names must be in `consumes`; a trailing `*` matches `consumes` entries with that prefix and errors when it matches none); `winevt.sec_event` events are forwarded only when their `category` field is in `sec_event_categories`; every other event goes through `SendEvent`. The forwarder state (`ok`, `failing` when `failed` grew, `dropping` when `dropped` grew) and its counters are in `Health.Info`; one common `telemetry_gap` (`source: splunk`, `reason: forwarder_failing`, the counters and `queue_len` in `detail`, priority high) is emitted when the state turns `failing` or `dropping` and again when a counter grows after a report; recovery emits nothing (S4: no `splunk.forwarder_state` kind). A reconfiguration changes the forward list without losing the queue (the forwarder is kept; the subscription is replaced). `Close` flushes within a 5 s deadline.

Health. `disabled`; `ok`; `degraded` (retries, drops since the last report, last batch failed; Gap `N events dropped (queue full)`, `HEC unreachable: <err>`); `unavailable` (no token, HEC refuses authentication; Gap `HEC token missing in the vault`). Platform tile: forwarder state, counters, last error, queue length. Phylax never waits on Splunk: `Send` never blocks.

- [ ] **Step 1: Write the failing tests** (fake HEC `httptest` server, fake vault):

```go
func TestSplunkConformance(t *testing.T) { conformance.Controller(t, conformance.ControllerCase{Module: &Module{}, Config: "enabled: true\nsecrets: {hec_token: splunk.hec, mgmt: splunk.mgmt}\nforward: [detect.alert]\nsensor: {hec_url: URL, index: phylax}\n", Now: time.Unix(1e9, 0)}) }
func TestExpandForward(t *testing.T) {
	consumes := []string{"detect.alert", "devices.config", "devices.change", "devices.deny"}
	got, err := ExpandForward([]string{"detect.alert", "devices.*"}, consumes)
	// want [detect.alert devices.change devices.config devices.deny] sorted, err nil
	if _, err := ExpandForward([]string{"nope.*"}, consumes); err == nil { t.Error("pattern matching nothing accepted") }
	if _, err := ExpandForward([]string{"made.up"}, consumes); err == nil { t.Error("kind outside Consumes accepted") }
}
func TestForwardsOnlyListedKinds(t *testing.T) { /* emit detect.alert and auth_event with forward [detect.alert]: HEC received one event with phylax_kind, phylax_agent, phylax_seq, phylax_hash and the event time */ }
func TestSecEventCategoryFilter(t *testing.T) { /* winevt.sec_event category group_change forwarded; category logon not */ }
func TestDeadSplunkNeverBlocksAndCounts(t *testing.T) { /* HEC returns 503 forever, 5000 events through Subscribe in under 2 s; one telemetry_gap{reason forwarder_failing} at high priority, Health.Info failed or dropped > 0 */ }
func TestTokenPickedUpAfterSetup(t *testing.T) { /* start without the secret: unavailable; put it; within 31 s of fake time health ok and events flow */ }
func TestReconfigurationKeepsQueue(t *testing.T) { /* change forward list while 50 events queued against a slow HEC: all 50 still delivered */ }
func TestStopFlushesWithinDeadline(t *testing.T) {}
func TestForwarderGapOnlyOnFailureOrDrop(t *testing.T) { /* healthy HEC: no gap event over 5 minutes of fake time; failing: event.Validate passes on the telemetry_gap, one per change; recovery: none */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/splunk/ -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/splunk/ ./internal/module/... && make build-windows`. Expected: PASS, with `splunk` a contract module.
- [ ] **Step 5: Commit.** `git commit -am "splunk: controller module forwards selected kinds, reports forwarder state"`

---

### Task 25: `splunk` dashboards pack

**Files:**
- Create: `splunk/dashboards/{logons,group_changes,services,firewall_events,service_health,lateral_movement,process_tree}.xml`, `splunk/embed.go` (`//go:embed dashboards/*.xml`, `package splunkcontent`), `plans/splunk/dashboards.yaml` is written in Task 28 from these files
- Test: `splunk/dashboards_test.go`

**Interfaces:**
- Consumes: the field names of the forwarded kinds (`AuthEvent`, `winevt.sec_event`, `devices.*`, `process_start`, `checks` results).
- Produces: seven Simple XML views over the `phylax` index; each begins `<form version="1.1">` with an `index` text token defaulting to `phylax` and every search starting `index=$index$ phylax_kind=...`. `Views() map[string][]byte` returns the embedded files by name. The views: *Logons* (`phylax_kind=auth_event` by `account`, `source`, `service`, `result`), *Group changes* (`winevt.sec_event` categories 4728, 4732, 4756 and removals, plus Linux group edits), *Services* (7045, 4697, unit changes), *Firewall events* (host denies, 5157, Palo and VyOS deny and change logs), *Service health* (checks pass and fail by service over time), *Lateral movement* (logon types 3 and 10, admin-share access, remote service creation grouped by source), *Process tree by ProcessGuid* (`process_start` by parent and child; a banner that it needs `process_start` forwarding on). `shortcut: keep the pack small; more views are cheap after the inject names them`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestViewsAreWellFormedXML(t *testing.T) { /* each file parses with encoding/xml; root element "form" or "dashboard"; has <label> */ }
func TestEverySearchIsScopedToTheIndexToken(t *testing.T) { /* every <query> text starts with "index=$index$" or "| tstats" over $index$; none mentions "index=main", "_internal" or "| rest" (a dashboard must never read scored indexes or REST) */ }
func TestIndexTokenDefaultsToPhylax(t *testing.T) {}
func TestViewsCoverTheDesignList(t *testing.T) { /* the seven names are present; no extra file */ }
func TestProcessTreeNotesForwardingRequirement(t *testing.T) {}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./splunk/ -v`. Expected: FAIL.
- [ ] **Step 3: Write the seven views** (small, one panel group each).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./splunk/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "splunk: dashboards pack of seven views over the phylax index"`

---
### Task 26: `suricata` runner (flags, timeouts, work directory, output caps) and shipped configuration

**Files:**
- Create: `internal/suricata/runner.go`, `suricata/config/suricata.yaml`, `suricata/zeek/phylax.zeek`, `suricata/embed.go` (`package suricatacontent`, `//go:embed config/* zeek/*`)
- Modify: `internal/suricata/{eve,zeek}.go` (accept an `io.Reader` already capped by the runner; `ReadEVE` and `ReadZeek` unchanged otherwise), `depot/index.d/suricata-ruleset.yml` (already created in Task 8)
- Test: `internal/suricata/runner_test.go`

**Interfaces:**
- Consumes: Task 1 `Config`, `RunEvent`; the built readers.
- Produces:

```go
type ExecFunc func(ctx context.Context, argv []string, dir string, env []string) (exitCode int, err error)
type RunRequest struct {
	PcapPath string   // a private copy inside the run directory
	Tools    []string // subset of cfg.Tools
	Context  bool
}
type ToolResult struct {
	Tool       string
	Flags      []string
	ExitCode   int
	TimedOut   bool
	OutputPath []string // eve.json | conn.log, dns.log inside the run directory
}
type Runner struct {
	Cfg  Config
	Exec ExecFunc // production: os/exec, no network namespace needed (the tools open no sockets: see Rules), nice 10
}
func (r *Runner) Run(ctx context.Context, req RunRequest) ([]ToolResult, error)
const MaxOutputBytes = 256 << 20 // a tool's output file is read through io.LimitReader(MaxOutputBytes); the excess is counted in skipped["over_cap"]
```
Rules. Suricata argv: `suricata -r <pcap> -l <rundir> -k none -c <rundir>/suricata.yaml -S <rules file>` (`-k none` only when `offload_safe`); Zeek argv: `zeek -C -r <pcap> <rundir>/phylax.zeek` (`-C` only when `offload_safe`), working directory `<rundir>`. Binaries are resolved under `/usr/bin`, `/usr/local/bin`, `/opt/zeek/bin`, `/opt/suricata/bin`; when `Sensor.SuricataSHA256` (or `ZeekSHA256`) is set the binary is hashed first and a mismatch refuses the tool. Each tool has `timeout_sec`; the process group is killed on timeout or context end and `TimedOut` is set; the other tool still runs. The environment is `PATH=/usr/bin:/bin`, `HOME=<rundir>` and nothing inherited. The run directory is `<work_dir>/<random>` mode 0700, removed by the caller. The shipped `suricata.yaml` enables only `eve-log` with `alert`, `dns` and `http` and no payload, packet or stats output; `phylax.zeek` sets `redef LogAscii::use_json = T;`. `shortcut: Suricata and Zeek run as unprivileged host binaries with no network namespace; they only read a file, but a sandbox (unshare -n) is the upgrade if a tool version proves chatty on the network`.

- [ ] **Step 1: Write the failing tests** (a fake `Exec` records argv and writes known output files):

```go
func TestSuricataFlagsOffloadSafe(t *testing.T) { /* argv contains "-k" "none" and "-r"; with OffloadSafe false it does not */ }
func TestZeekFlagsChecksumIgnored(t *testing.T) { /* argv contains "-C" and "-r"; not with offload_safe false */ }
func TestToolTimeoutKillsAndOtherToolStillRuns(t *testing.T) { /* suricata Exec blocks past 50 ms timeout: TimedOut true; zeek result present with ExitCode 0 */ }
func TestBinaryHashPinRefusesMismatch(t *testing.T) { /* fake binary file with other bytes than Sensor.SuricataSHA256: tool refused, error names the pin */ }
func TestEnvironmentIsScrubbed(t *testing.T) { /* Exec env == [PATH=/usr/bin:/bin, HOME=<rundir>] exactly */ }
func TestEveOverCapIsTruncated(t *testing.T) { // Review Focus 5
	/* output file of MaxOutputBytes+1024 bytes of valid EVE lines: ReadEVE through the limited reader returns events, stats.Skipped["over_cap"] > 0, memory bounded (no more than MaxOutputBytes read) */
}
func TestRunDirIsPrivate(t *testing.T) { /* mode 0700 */ }
func TestShippedConfigHasNoPayloadLogging(t *testing.T) { /* embedded suricata.yaml parses as YAML; eve-log types are exactly alert, dns, http; payload and packet keys absent or no; phylax.zeek contains use_json */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/suricata/ -run 'Flags|Timeout|HashPin|Environment|OverCap|RunDir|ShippedConfig' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `Runner` and write the two content files.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/suricata/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "suricata: offline runner with pinned flags, timeouts, output caps; shipped config"`

---

### Task 27: `suricata.analyze_pcap`, the module, idempotence and the UI action

**Files:**
- Create: `internal/suricata/{action,analyze,ui}.go`
- Modify: `internal/suricata/module.go` (replace W1's placeholder `Start`), `internal/module/conformance` (already contract), `cmd/phylax/serve.go` (`Options.Backends["suricata"] = suricata.Default`, `Options.EvidenceDir`)
- Test: `internal/suricata/analyze_test.go`, `internal/suricata/module_test.go`, `internal/suricata/conformance_test.go` (extend W1's)

**Interfaces:**
- Consumes: Task 26 `Runner`; W1 `Host.Query` (`store.Reader`, `Query.Fields`), `Host.Emit`, `Host.RunReadOnly`, `Host.UI`; Task 5 `Controller.Fetch` objects in `EvidenceDir`.
- Produces:

```go
var Default = &Module{}
type AnalyzeRequest struct {
	Pcap    string   // path inside Config.EvidenceDir
	Source  string   // capture | palo | file
	Window  string   // free text, shown in the run event
	Tools   []string // nil = Config.Tools
	Context bool
}
func (m *Module) Analyze(ctx context.Context, req AnalyzeRequest) (RunEvent, error) // emits events, returns the run record
func (m *Module) Backend() // Default implements the interface the action reads from Env.Ext["suricata"]
const ExtKey = "suricata"
```
`suricata.analyze_pcap{pcap, tools, context}` is registered with `actions.Register`: `Runs: RunsController`, `Risk: RiskNone`, `ReadOnly: true`, no `Touches`, Doc says "runs a host binary on the controller". Rules. `pcap` is resolved with `filepath.EvalSymlinks` and must be a regular file under `EvidenceDir`; larger than `max_pcap_mb` is refused; the file is copied to the run directory (mode 0600, through `EvidenceOpen`, a package variable defaulting to `os.Open`), its sha256 recorded. A previous `run` record (kind `suricata`, `record: run`) with the same `pcap_sha256` and `rules_version` and no `error` makes `Analyze` return that record without running (look up with `Query().Events(Query{Kinds: ["suricata"], Fields: {"record": "run", "pcap_sha256": sum, "rules_version": v}})`). `rules_version` is the ruleset id from `Sensor.Rules` plus the file's sha256 prefix (8 hex). Events: alerts get priority high for severity 1, normal for 2, bulk for 3 (set per event; the kind itself is not alert-class), context and Zeek events bulk, each with `Time` the packet time and `community_id` (read, or computed by `sockets.CommunityID` through the W3 helper the readers already use); at most `MaxEventsPerRun = 20000` events are emitted, the rest counted in `skipped["over_cap"]` (`shortcut: per-run event cap protects the Host budget, raise with the measured budget`). Then the `run` record (kind `suricata`) is emitted with `flags`, `tools`, `alerts`, `events`, `skipped`, `duration_ms`, `error`. The run directory is removed in a `defer`. A tool failure sets `error` and still emits what the other tool produced. UI: `Registrar.Action("analyze", h)` (POST `pcap`, `source`) calls `Host.RunReadOnly("analyze", params)` with the template `plans/suricata/analyze.yaml` (Task 28) and redirects to the page `GET /m/suricata/run?pcap_sha256=...` showing alerts by severity, DNS and HTTP context, the Zeek connection summary and the `Join` view by community id; the Platform page lists the state and the last run.

Health. `disabled`; `ok` (tools present with matching pins, ruleset cached); `degraded` (a tool or ruleset missing: Gap `ET Open rules not cached`, `zeek not installed`); `unavailable` (neither tool installed). A failed run is reported in the `run` record's `error`, not as a platform failure. Ruleset presence is the file `<work_dir>/rules/<Sensor.Rules>.rules`. `shortcut: the ruleset file is placed in work_dir/rules by hand or by the lab step, because a module cannot read depot blobs; upgrade when Host gets a depot reader`.

- [ ] **Step 1: Write the failing tests** (fake `Exec` writing `testdata/eve.json`, `conn.log`, `dns.log`; a controller test host with a store):

```go
func TestAnalyzeRefusesPathOutsideEvidence(t *testing.T) { // Review Focus 5
	for _, p := range []string{"/etc/passwd", "../x.pcap", evidence + "/../outside.pcap", symlinkInEvidencePointingOut} {
		if _, err := mod.Analyze(ctx, AnalyzeRequest{Pcap: p}); err == nil { t.Errorf("accepted %s", p) }
	}
	// and no run directory is left under WorkDir
}
func TestAnalyzeRefusesOversizePcap(t *testing.T) {}
func TestAnalyzeEmitsDeclaredEventsWithPacketTime(t *testing.T) { /* every event passes event.Validate; the alert record (kind suricata) has Time == the packet time; severity 1 high, 2 normal, 3 bulk; the run record present with flags ["-k","none"] and ["-C"] ; stored under agent "controller" */ }
func TestRepeatedRunReturnsStoredResult(t *testing.T) { /* second Analyze: fake Exec call count unchanged; same RunEvent */ }
func TestFailedRunIsRerun(t *testing.T) { /* first run with error set: second Analyze executes again */ }
func TestOneToolFailsOtherStillStored(t *testing.T) {}
func TestEventCapCountsOverflow(t *testing.T) { /* 20500 eve alerts: 20000 emitted, skipped["over_cap"] == 500 */ }
func TestRunDirectoryRemoved(t *testing.T) {}
func TestSuricataConformanceWithFakeTools(t *testing.T) { /* W1's conformance case, now with a fake Exec: stops within 5 s and kills a running tool */ }
func TestAnalyzeActionIsReadOnlyController(t *testing.T) { /* Spec: Runs controller, ReadOnly, Risk none, Touches empty; SS000 accepts a plan with this node */ }
func TestUIActionStartsReadOnlyPlan(t *testing.T) { /* POST analyze -> Host.RunReadOnly called with template "analyze" and params pcap */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/suricata/ -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Update `docs/integrations.md` (Suricata paragraph).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/suricata/ ./internal/module/... && make build-windows`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "suricata: analyze_pcap action, run events, idempotent runs, UI action"`

---

### Task 28: Plan templates move under `plans/<module>/` and the new ones

**Files:**
- Move (`git mv`): `plans/wazuh.deploy.yaml` to `plans/wazuh/deploy.yaml`, `plans/wazuh.evidence.yaml` to `plans/wazuh/evidence.yaml`, `plans/splunk.forwarding.yaml` to `plans/splunk/forwarding.yaml`
- Create: `plans/wazuh/uninstall.yaml`, `plans/splunk/dashboards.yaml`, `plans/suricata/analyze.yaml`
- Modify: the three moved files (add `module: wazuh` or `splunk`; the deploy plan's `source` values become `depot:<name>/${version}`), `plans/plans_test.go`, `docs/integrations.md`, W5's `TestEveryTemplateHasModule` skip table (remove the wazuh and splunk rows)
- Test: `plans/integration_plans_test.go`

**Interfaces:**
- Consumes: **gate: W5 Task 37 merged** (`plans/plans.go` embeds `*.yaml */*.yaml`; `Template.Module` and `Parse` are W1 Task 22b's); Task 8 `depot/index.d`; Tasks 17, 21, 23, 25 action names.
- Produces: templates (each with `module:`, `scoring_note`, `probe` where it touches a scored host):
  - `wazuh/deploy.yaml`: the existing DAG (approve-placement gate; manager `pkg.install`, `fw.apply{op: allow}`, `xml.set` active response off and authd password, three agent groups, restart, `wazuh.check`; agents `pkg.install` per OS, manager address, remote commands off (`file.write` on Linux, `agentopt.set` on Windows), `service.state`; second `wazuh.check`; authd disabled and the manager restarted), `source` values `depot:<name>/${version}`, plus a node `mgr-memcap` (`systemd.dropin` on `${manager}`, `needs: [mgr-install]`, drop-in `MemoryMax=${manager_memory_max}` with the default `infinity`; the approval gate's note tells the operator to set `4G` when the manager is placed on the Splunk host).
  - `wazuh/uninstall.yaml`: on each agent host `service.state` stopped then `pkg.remove`; then the same two nodes on the manager (`needs` every agent node); `on_failure: continue`; the firewall allow of the deploy plan is left in place and the plan's note says so.
  - `splunk/dashboards.yaml`: for each of the seven views one `file.write` node on `${splunk}` to `/opt/splunk/etc/apps/phylax/default/data/ui/views/<name>.xml` (content inline, mode `0640`), plus `app.conf` and `metadata/default.meta` nodes; a final `net.http_probe` to the Splunk Web port is not included (that would touch a scored service); `scoring_note` says the app directory is Phylax's own and no existing app is touched; the open question of a splunkd restart is a gate node `restart-if-needed` (`gate: true`) that is skipped unless the lab shows it is required.
  - `suricata/analyze.yaml`: one node `suricata.analyze_pcap` on `${controller}` with params `pcap`, `tools`, `context` taken from template parameters.

- [ ] **Step 1: Write the failing tests:**

```go
func TestEveryIntegrationTemplateHasModuleAndValidates(t *testing.T) { /* Load each of the six; Module non-empty; validate against NewCatalog (every action exists: pkg.*, wazuh.*, splunk.*, suricata.*, systemd.dropin, file.write) */ }
func TestDeployPackageSourcesResolveInIndexDir(t *testing.T) { /* every pkg.install source "depot:<name>/<version>" in wazuh/deploy.yaml with version var 4.14.9 has an entry in depot/index.d with that name and version */ }
func TestDashboardsPlanEmbedsTheViewFiles(t *testing.T) { /* each file.write content equals splunkcontent.Views()[name] byte for byte (drift guard) and paths stay under /opt/splunk/etc/apps/phylax/ */ }
func TestNoTemplateTouchesSearchApp(t *testing.T) { /* no param path contains "/apps/search" or "/etc/system/" except the existing syslog fallback input which is gated */ }
func TestWazuhActiveResponseStaysOff(t *testing.T) { /* deploy.yaml still sets active-response disabled yes and remote_commands 0 for logcollector, sca, wazuh_command */ }
func TestUninstallRemovesAgentsBeforeManager(t *testing.T) { /* needs-order check */ }
func TestOldTemplatePathsGone(t *testing.T) { /* plans/wazuh.deploy.yaml etc. do not exist */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./plans/ -run 'IntegrationTemplate|DeployPackage|Dashboards|NoTemplateTouches|ActiveResponse|Uninstall|OldTemplate' -v`. Expected: FAIL.
- [ ] **Step 3: Move and write.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./plans/ ./internal/controller/ && make build build-windows vet`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "plans: wazuh, splunk and suricata templates under plans/<module>/; uninstall, dashboards, analyze"`

---

### Task 29: Sensor declarations move into module blocks; `integrations.yml` is deleted

**Files:**
- Create: `manifest/2027/modules/{depot,wazuh,splunk,suricata}.yml` (reference blocks: `depot` enabled with the design's defaults; `wazuh`, `splunk`, `suricata` `enabled: false` with the design's example `sensor:` parts as comments-free values), `manifest/schema/modules/{depot,wazuh,splunk,suricata}.schema.json` (generated)
- Delete: `manifest/2027/integrations.yml`, `manifest/schema/integrations.yml.schema.json`
- Modify: `internal/manifest/{types,load,schema,validate}.go` (delete `FileIntegrations`, `Manifest.Integrations`, `Integration`, the loader entry, the validation), `docs/manifest.md`, `internal/manifest/lint_test.go` and any test fixture that wrote `integrations.yml`
- Test: `internal/manifest/modules_w11_test.go`

**Interfaces:**
- Consumes: Task 1 configs; W1 `manifest.ModuleBlock`, `Manifest.Modules`. **Conflict hot spot:** `load.go` is also edited by W9 (`decoys.yml`) and W1; rebase before the pull request.
- Produces: each module's `Config.Check(m *manifest.Manifest) error` (exported) reporting hosts named in `sensor:` that are not in the manifest; the module calls it in `Start` and reports a Gap, so the old `integration X: host not a host` validation survives. `depot` `cache_plan.integrations` stays generated, never hand-written (Task 10 derives it).

- [ ] **Step 1: Write the failing tests:**

```go
func TestReferenceModuleBlocksDecodeStrictly(t *testing.T) { /* Load manifest/2027; for each of the four blocks: ModuleBlock.Decode into the module Config is strict (an extra key errors) and the reference values decode */ }
func TestNoIntegrationsYml(t *testing.T) { /* manifest dir has no integrations.yml; manifest.Manifest has no Integrations field (reflect) ; a leftover integrations.yml in a test dir is rejected as an unknown file */ }
func TestSensorHostMustExist(t *testing.T) { /* wazuh Config.Check with manager "nohost" errors; splunk sensor.host; suricata none */ }
func TestOptInModulesAreOffInReference(t *testing.T) { /* wazuh, splunk, suricata enabled:false; depot true */ }
func TestSchemaFilesCurrent(t *testing.T) { /* module.Schema(Config{}) equals the committed JSON for the four (the -update golden check W1 uses) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/manifest/ ./internal/module/all/ -run 'ReferenceModuleBlocks|NoIntegrations|SensorHost|OptIn|Schema' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Run `go test ./internal/module/all/ -run Schema -update`.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "manifest: sensor declarations live in module blocks; integrations.yml deleted"`

---

### Task 30: T40 offline drill in CI form and the bug guards

**Files:**
- Create: `internal/depot/offline_test.go`, `internal/depot/bugs_test.go`
- Test: the same

**Interfaces:**
- Consumes: Tasks 5, 6 to 15, 17, 28 (fixture release from `Build`, `Sync`, the controller module, an in-process agent from the `e2e` helpers, the fake package runner).
- Produces: `TestT40OfflineDrill` and `TestKnownBugsW11`; part of `make conformance` through the test name prefix `Test` plus a `// conformance:` build of nothing new.

- [ ] **Step 1: Write the tests:**

```go
func TestT40OfflineDrill(t *testing.T) {
	rel := buildFixtureRelease(t)            // Build: 2 tools (p1), a wazuh bundle closure tar (p1, needed_by wazuh), a distro closure (p2), signed with a test key
	storeB := Store{Dir: t.TempDir()}
	syncVia(t, rel, storeB, []int{0, 1})     // "a prior sync" through an httptest mirror for priorities 0 and 1 only
	rel.server.Close()                       // the internet is blocked from here on
	var calls atomic.Int32
	blocked := fetcherFunc(func(context.Context, Entry, int64) (io.ReadCloser, error) { calls.Add(1); return nil, errors.New("network blocked") })

	m := startControllerModule(t, storeB, blocked)           // cold start from the store alone
	h := waitHealth(t, m)
	if h.State != module.StateDegraded || !gapContains(h, "waiting") { t.Fatalf("priority 2 missing must read waiting: %+v", h) }
	if got := m.Pending("wazuh"); len(got) != 0 { t.Fatalf("wazuh bundle is cached, nothing pending: %v", got) }
	if _, err := LoadCurrent(storeB, rel.verifier); err != nil { t.Fatal(err) }

	// plans and restores read the same store with no network
	if _, err := storeB.ReadVerified(rel.toolSHA); err != nil { t.Fatal(err) }
	// the Wazuh deploy works from the cache: stage the bundle on an in-process agent and run the check phase of pkg.install
	ag := newInProcessAgent(t, rel.verifier, withPackageManager("apt"))
	if err := m.Stage(ctx, "h1", pkgNode("depot:wazuh-manager/4.14.9")); err != nil { t.Fatal(err) }
	out := ag.Check(t, "pkg.install", map[string]any{"name": "wazuh-manager", "version": "4.14.9", "source": "depot:wazuh-manager/4.14.9"})
	if out.Err != nil || !strings.Contains(out.Diff, "wazuh-manager") { t.Fatalf("%+v", out) }
	// a priority-2 package that was never synced fails in check with the visible "waiting" text, not a platform failure
	_, err := ag.CheckErr("pkg.install", map[string]any{"name": "nginx", "version": "1.24", "source": "depot:nginx/1.24"})
	if err == nil || !strings.Contains(err.Error(), "blob not staged") { t.Fatalf("%v", err) }
	if calls.Load() != 0 { t.Fatalf("an offline drill made %d fetches", calls.Load()) }
}

func TestKnownBugsW11(t *testing.T) {
	root := "../.."
	t.Run("bug3_no_typst", func(t *testing.T) { /* walk depot/, internal/depot, docs/depot.md: no "typst" (case-insensitive) */ })
	t.Run("bug4_no_placeholder_fetch", func(t *testing.T) { /* grep internal/agent for "placeholderFetch": none */ })
	t.Run("bug15_depot_imports", func(t *testing.T) { /* go list -deps ./internal/depot/... has no internal/integrity, internal/collect, internal/net */ })
	t.Run("bug17_controller_events", func(t *testing.T) { /* grep internal/wazuh internal/suricata *.go (non-test) for `Agent:` struct literals with "wazuh", "suricata" or "zeek": none */ })
	t.Run("bug21_no_aliases_no_window", func(t *testing.T) { /* internal/depot/pkg*.go contain neither "pkgScoredAliases" nor "requireWindow" nor "PatchWindow" */ })
}
```

- [ ] **Step 2: Run, expect FAIL or PASS.** Run: `go test ./internal/depot/ -run 'T40|KnownBugsW11' -v`. Expected: FAIL until the helpers (`buildFixtureRelease`, `startControllerModule`, `newInProcessAgent`) exist; write them in this task from the earlier tasks' test helpers (move shared helpers into `internal/depot/helpers_test.go`).
- [ ] **Step 3: Implement the helpers**; no production code changes are expected. A failure here is a defect in an earlier task: fix it there.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race conformance`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "depot: T40 offline drill in CI form; W11 known-bug guards"`

---

### Task 31: Lab (stronger agent or David)

**Files:**
- Create: `docs/impl/lab/w11-integrations-depot.md`

Run on the BTaP replica (`stacks/ccdc`: `ubuntu-wkst` as controller, `rocky-ecom`, `ubuntu-email`, `debian-splunk`, `ad`, `win11`), from a build of the merged branch.

- [ ] **Step 1: Depot build (T-depot).** In the lab, run `depot/recipes/build.sh out/`, fill the `fetch_at_init` and bundle hashes in `depot/index.d/*.yml` (Wazuh 4.14.9 bundle, Splunk 10.0.10, ET Open, KEV feed), run `phylax cache build` with a fresh release key, then `phylax depot verify` and `phylax depot run` on each target OS image. Run `sigcheck64 -a` on the pinned Sysinternals files on Windows once. Record sizes and the measured total per priority.
- [ ] **Step 2: Sync and T40.** `phylax cache sync` on the controller from the release channel and from `dist/` (the fallback); record time per priority against the bandwidth cap (Invitational questions E15, O11). Then the T40 drill: block the controller's internet (nft drop on its uplink), cold start `phylax serve`; confirm the Platform page shows priorities 0 and 1 complete and priority 2 "waiting", plans open, ledger lookups and `binary.restore_from_depot` restore a replaced service binary from the store, and the Wazuh deploy (Step 3) completes.
- [ ] **Step 3: Wazuh (T41).** Deploy to all hosts from the cache; kill the manager and an agent and confirm a `telemetry_gap{reason: wazuh_degraded}` at high priority and the Platform tile; run `plans/wazuh/evidence.yaml`; run `plans/wazuh/uninstall.yaml` on one agent. Record the real API and indexer field names, the Windows service name and `ossec.conf` path per version, the manager RAM headroom (E14) and that no Quotient round failed.
- [ ] **Step 4: Fetch handler and transfers.** Pull a 100 MB file from `rocky-ecom` (`Controller.Fetch`) with the link cut for 20 s mid-transfer; confirm it resumes and the sha256 matches. Push a package closure to `rocky-ecom` and `ubuntu-email`, `pkg.install` it with the internet blocked, `pkg.install` the previous version (the reinstall form), and `pkg.repair` after planting a stale lock. T63: on the Docker-hosted ecom variant, confirm the package-to-service map from `services.yml` produces the `PK001` refusal for an `auto` class plan and the restart note in a `click` plan.
- [ ] **Step 5: Splunk.** Create the HEC token on the scored Splunk through `splunk.hec_setup`, confirm the `phylax` index is not read by the Quotient check and that a Quotient round passes during setup; install the dashboards pack and record whether the views load without a splunkd restart; forward `detect.alert` and `auth_event` and screenshot the views; record E19 answers.
- [ ] **Step 6: Suricata and Zeek.** Freeze and pull a pcap slice from `capture` (needs W6's `pcap` fetch provider), run `suricata.analyze_pcap`; confirm alerts, Zeek `conn.log` and the joined view by community id. Offloaded-NIC case: a capture with bad checksums yields alerts and flows with the flags on and none with `offload_safe: false`. Record the exact Suricata and Zeek versions and the install path.
- [ ] **Step 7: Record and commit.** Write the date, commit, VMIDs, each step's result, measured values (sizes, times, headroom) and what was not run to `docs/impl/lab/w11-integrations-depot.md`; open an issue per failure. `git commit -m "lab: W11 integrations and depot results"`. Update the catalogue Status in `phylax_design.md` for `depot`, `wazuh`, `splunk`, `suricata` ("lab-proven" only for what the record shows).

---

## Self-review

**Spec coverage** (module sections `depot`, `wazuh`, `splunk`, `suricata`, parts 1 to 12, and the core pieces W11 owns):

| Design requirement | Task |
| --- | --- |
| One signed index with `Kind`, `Priority`, `NeededBy`; unsigned, tampered, wrong-key refused | 6, 11 |
| Content-addressed store: atomic, hash-checked on write and read, size bound, partial never visible | 7 |
| `phylax cache build` from the tool spec plus `index.d`, changelog | 8, 13 |
| Priority-ordered sync, resume, bandwidth cap, mirror allowlist, progress, failed entry degrades one tool | 9, 14 |
| Cache plan from hosts, services and enabled modules; "waiting for cache" | 10, 14, 16 |
| Cache-through and operator pins; installable only by a plan naming the sha256 | 12, 17, 20 |
| Index-delta refresh from the release channel, fallback `dist/` | 11, 13 |
| Delivery to hosts as chunks, `stage_mb` bound, digest before staging | 2, 4, 5 |
| Agent `fetch` handler (Known bug 4), per-agent concurrency, pcap/file/telemetry | 3 |
| Trusted tool depot kept: manifest, deploy, run, verify, gotools | 6, 15 |
| Agent-side periodic verify, `depot.problem` critical on planted file | 15 |
| `pkg.install` (install, upgrade, reinstall, downgrade) and `pkg.remove` without patch window or proxy; staged closure; dry-run; pinned | 17 |
| the reinstall form of `pkg.install`, `pkg.repair`, `pkg.fetch_to_depot`, `windows.hotfix` | 18, 20 |
| Package-to-service map from `services.yml`; scoring lint; Known bug 21 | 19 |
| Depot module events, tables, health, UI, conformance | 14, 15, 16 |
| `depot` imports no sibling (Known bug 15); `gotools` through `sockets` | 6, 30 (W3 and W5 seams do the edit) |
| `wazuh` actions leave `internal/actions`; controller module; alerts under `controller` (Known bug 17) | 21, 22 |
| Wazuh deploy, evidence, uninstall, memory cap; active response off | 28 |
| `splunk` client and Directory split; `hec_setup` refuses scored indexes | 23 |
| `splunk` forwarder module, forward list, `sec_event_categories`, `telemetry_gap` on failure | 24 |
| Dashboards pack of seven views, installed under Phylax's own app | 25, 28 |
| `suricata` flags, timeouts, work dir, caps, shipped config | 26 |
| `suricata.analyze_pcap`, idempotence, run event, UI action | 27 |
| Sensor declarations in module blocks; `integrations.yml` gone | 29 |
| T40 in CI form; T41, T63 and lab questions | 30, 31 |
| Known bugs 3, 4, 15 (depot), 17 (wazuh), 21 | 8, 3, 6, 22, 19 (guards in 30) |

Gaps: the design's "tab on the incident page" (Deviation 14), "forward kinds beyond Consumes" (Deviation 16), "evidence encrypted at rest" (Deviation 9), and the controller-side raw `telemetry` and `pcap` fetch providers (W6 `capture` and W3 register them with `agent.RegisterFetch`; this plan builds the mechanism and the `file` provider) are deliberate and carry `shortcut:` comments or are named in the integrator notes.

**Step scan.** Every step names a file, a signature or a test with its assertion. Tasks 14, 15, 22, 24 and 27 list behaviour rules in prose where the signature and the tests leave a choice open; each rule has a test. `mgr-memcap` uses a variable default instead of a conditional because the plan loader has none; the implementer does not add one.

**Type consistency.** `Manifest.Entries` (Task 6) is used by Tasks 8 to 15; `Fetcher.Fetch(ctx, e, off)` (Task 9) by Tasks 12 and 13; `Pin` (Task 10) by Tasks 12, 14, 16, 20; `CachePlan.PendingFor` by Task 14's `Pending`; `SyncState` (Task 1) by Tasks 9 and 14; `Receiver.Accept` and `Sender` (Task 2) by Tasks 3, 4, 5; `AgentFetchResult` (Task 1) by Tasks 3, 4, 5; `wazuh.Backend` and `API` (Task 21) by Task 22; `splunk.Directory` (Task 23) by Task 24; `Runner` (Task 26) by Task 27; event payload names (`DeployEvent`, `ProblemEvent`, `AlertEvent`, `HealthDetail`, `RunEvent`) avoid the clashes with the existing `Deploy`, `Problem`, `Alert`, `Health` identifiers in their packages.

**Review Focus.** Each line has its test: 1 in Task 11, 2 in Tasks 2 and 7, 3 in Task 19, 4 in Task 23, 5 in Tasks 26 and 27.

**Proportion.** About 32 tasks for four modules plus the core transfer; the design sections total about 900 lines and the plan is longer because every task carries tests; code bodies are not transcribed.

## Notes for the integrator (flags, not decisions made here)

1. **Action registration helper**: unified as `actions.Register` (W1 Task 2a); this plan uses it throughout.
2. **Design changes this plan makes** (Task 1 edits them in): `fetch` is controller to agent only and blobs are pushed; a new core kind `agent.fetch_result` (kind table 29 to 30 rows); `DepotSettings.ReleaseKey` and `Packages`; `modules/depot.yml` `release_key`; `modules/suricata.yml` `evidence_dir`; closure archives; pins and cache-through blobs as `operator.edit` events replayed into `depot_entry`; `splunk.rest` and `splunk.password` registered by `internal/splunk` (no `splunk.sidecar_off` action).
3. **Ordering dependencies beyond the README row**: Task 1 needs W3 Task 1 (`sockets`, the `gotools` import) and W5 Task 2; Task 23 needs W6 Task 3; Task 28 needs W5 Task 37; Task 29 touches `internal/manifest/load.go` with W1 and W9. Task 31 Step 6 needs W6's `pcap` fetch provider (`agent.RegisterFetch("pcap", ...)`), which W6 must add.
4. **Ownership**: `phylax init` calls `depot.Refresh` and `phylax cache sync` (W12); the first-hour `fh.splunk.sidecar_off` node (a `service.state` step, W5) and the `splunk.password` callers keep working through the action names.
