# W7: Scoring and Credentials Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put `checks`, `scorer`, `vantage` and `creds` on the module contract: extract the stateless probe library to `internal/checks/probe`, supply the executor's `Env.Probe`, build the scorer-quiet-window and typed-PCR machinery, and add TFTP and NTP probes, Orange flows, the service doctor, the typeable passphrase class and the PCR transaction with eviction, verification, failure handling and automatic revert re-apply.

**Architecture:** Four packages (`internal/checks`, `internal/scorer`, `internal/vantage`, `internal/creds` with `internal/creds/pcr`) each meet the module contract; the only shared code is `internal/checks/probe`, which has no scheduler, no globals and no goroutines of its own. Agent sides (`checks` runner, `vantage` Kali roles) get the round clock and the credential-transaction pause through signed `control: fact` messages and their scored passwords through a sealed config section; controller sides keep their tables as projections of their own events, written by one goroutine each. The PCR transaction is a state machine in `creds/pcr` driven by plans from `plans/creds/` that carry a transaction id, a `window: scorer_quiet` hold and a `gate: manual` reply; the quiet window comes from the latest `scorer.clock` event.

**Tech Stack:** Go 1.27.2 (mise), standard library (`crypto/ecdh`, `crypto/hkdf`, `net/http/cookiejar`), `golang.org/x/crypto/ssh`, `gopkg.in/yaml.v3`, `modernc.org/sqlite` (module tables), `filippo.io/age` (vault, already used). No new modules in `go.mod`.

**Spec:** `phylax_design.md` (v4): "The module contract" and "Event kinds"; module sections "Scoring and credentials" (`checks` 5331, `scorer` 5591, `vantage` 5805, `creds` 5987); core "Execution engine" (the scoring-safety lint and its three sanctioned exceptions, lint registration, the scorer-mimic probe, plan and node options `window`, `gate: manual`, `txn`, controller executor, session eviction), "Wire protocol" (fact subtypes `round_clock`, `scorer_probe_result`, `creds_txn`; sealed secrets), "Local accounts"; Appendix F (PCR list rules) and G (fingerprint table); Test matrix T14, T15, T30, T35, T37, T39, T49, T50, T51 (and T16, T48, T66 as consumers); Known bug 20 (probe half). Master plan: `docs/impl/README.md`. Contract names: `docs/impl/01-module-contract.md` (W1) Interfaces blocks; `docs/impl/03-telemetry.md` (W3) for `auth_event`, `net.canary_result`, `inventory.probe_result`, `actions.Register`; `docs/impl/05-integrity-hunting.md` (W5) for `hunt.finding`. The `conn` kind (with `source: capture`) and `capture.txn` come from W6's seams (`internal/capture/kinds.go`); this plan names them only through the README dependency row.

## Design gaps and decisions (Task 1 writes each into `phylax_design.md` in the same commit)

1. **Table names must start with the module name.** W1's `ModuleDB.Migrate` refuses a table that does not start with `<module>_`. Renames: `checks` to `checks_check`, `check_results` to `checks_result`; `credentials` to `creds_account`, `pcr_txn` to `creds_txn`, `pcr_row` to `creds_row`. There is no `cred_credlist` table (S4): the credlist label of a scored account is read from `scorer`'s account groups (`scorer.account` `group`, kept in step by `scorer`'s `operator.edit` group edits) and the per-credlist PCR state is the latest `creds.state` event per (account, host, credlist), held in memory (Task 39). `scorer_*` and `vantage_*` keep the design's names. The core migrations drop `checks`, `check_results` and `credentials` (Task 30); nothing is deployed, so there is no data migration.
2. **Plan node options `window: scorer_quiet`, `gate: manual` and `txn:` are specified in the core but built by nobody.** W1 builds approval classes, not these options; the agent never sets `actions.Request.PCR`, so the scoring guard's PCR exception is unreachable. W7 builds them (Tasks 3 and 4); W1 builds the two other core plan options (`expires_after` Task 22a, `gate: auto` Task 27a) and the template key translator `translateNodeKeys` in `internal/controller/plantemplates.go` that Tasks 3 and 4 extend (`max_hold: 120s` to `max_hold_sec`, `gate: manual` to a gate node whose `ask`/`reply`/`choices` this plan validates). `hardening` (W5) and `backup` (W10) also use `window:`; they depend on Tasks 2 to 7 here.
3. **A controller module cannot see an agent-run step's outcome or output.** W1's `agent.step_result` is emitted for controller-side actions only. The doctor needs collected output and `creds` needs to know a host change finished. Task 5 emits `agent.step_result` for every step result and adds optional `output` and `reply` fields to `event.AgentStepResult`.
4. **No secret write path for modules, and `stepSecrets` serves honeytokens only.** `creds` must store a pending password and ship it to `user.set_password` and to the `probe.run` step `pcr_verify`. Task 6 adds `vault.Writer` and widens `stepSecrets` to plans with `Module == "creds"` and a node `txn`, for the vault prefix `pcr/` only. `shortcut: write access is granted to the module named creds in moduleHost.Secrets, upgrade to a manifest field when a second module writes secrets.`
5. **"Sealed to the host's enrolled key" has no implementation.** Agents have a P-256 identity (`internal/link/identity.go`) and the controller stores it in `agents.pubkey`. Task 7 adds `link.SealSecret` and `(*link.Identity).OpenSecret` (ECIES: P-256 ECDH, HKDF-SHA256, AES-256-GCM, the agent id as associated data) and `agent.Env.OpenSealed`; the controller seals with the public key it stores in `agents.pubkey`.
6. **`internal/parsers/txn` imports `internal/scorer`** (`Txn.Features`), a shared library depending on a module. Task 1 deletes `Txn.Features` and adds `scorer.FeaturesFromTxn`; parser tests that classify fixtures keep importing `scorer` (test-only edge, `shortcut:` comment).
7. **Neither `pcr.generate` nor `pcr.verify` is a plan action.** Generation is a module step (a UI action of `creds`) and needs no plan node. Verification is the `probe.run` step named `pcr_verify` that `vantage` runs on the Kali (S4: no `pcr.verify` action, no verify sub-role); the `creds` manifest lists no action of its own and uses that step. The design's `creds` Actions row still names `pcr.generate`; Task 1 Step 7 corrects it as before (flagged for the integrator).
8. **`Env.Probe` runs on the controller.** The design says the controller process runs no scheduled probes; the executor's probe is on demand and uses the library from the controller host, the in-LAN reference vantage. Agent-side `Env.Probe` is not supplied (agents hold no vault credentials; W1 Task 27 probes controller-side).
9. **Scored-account eviction needs inputs the agent does not have** (the measured round delay, the scorer-labelled sources). `session.terminate_predating` (W2) gains the params `scored` (bool), `cutoff_ms` and `exempt_sources` (comma-separated); the module fills them from `scorer.clock` and `scorer.round`. The policy is a pure function (`actions.EvictionPolicy`, Task 40).
10. **Fact data shapes are not defined.** Task 1 adds `plan.RoundClock`, `plan.CredsTxnFact` and `plan.ProbeResultFact` and the extrapolation `RoundClock.Window`.
11. **Check and flow content has no loader path.** `checks/{checks,flows,doctor}/` are root-level content directories (Appendix D); the controller module reads them from `Config.ContentDir` (default `checks`), the way plans are read from `plans/`. Added to `modules/checks.yml`.
12. **Agent settings carry integers, not durations,** matching the built settings (`IntervalSec`, `MaxDeferSec`); the design's `time.Duration` sketch is corrected.
13. **Inputs from workstreams that have not merged** (`detect.alert` W4, `traceback.change` W8, `deps.graph` W8, `deception.sighting` W9, `chains.item` W8, `hunt.finding` W5) cannot be in a manifest's `Consumes` until declared (`Manifest.Validate` and conformance check 12). Every handler takes a plain Go struct; Task 47 adds the thin adapters and the `Consumes` entries once the kinds exist.
14. **Lint id namespace `CR###`** is added for the `creds` transaction rule (`CR001`), next to `SS`, `FW`, `DEP`.
15. **The design orders Kali verification two ways.** `vantage` says it runs before the human submits; `creds` (the A7.Q6 builder check, authoritative) says the window covers the host change and the submit and verification runs after the window. The plan follows `creds`; a failed verify then holds a revert to the next quiet window (Task 43). The `vantage` text is corrected.
16. **`max_accounts_per_txn` contradicts "one transaction covers one account".** Read as the size of one typed-list batch (`Engine.Prepare`); `max_open_txns` caps open transactions. The design text says so.
17. **The design's typeable example `Plum-river-tent-82` is 18 characters, below its own 20 to 25.** The generator redraws until the length fits; the word list is BIP-39 (2,048 words, 3 to 8 letters). The example is replaced (Task 38).

## Global Constraints

- Go 1.27.2 via mise; `CGO_ENABLED=0`; `make build build-windows vet test race` passes at every commit (linux/amd64 and windows/amd64 both build and vet). `-race` needs `CGO_ENABLED=1`.
- Every package ships tests; tests exercise the real code (no mock of the code under test; fakes only at the edge the package does not own: a fake SSH, SMB, TFTP, NTP, Netlogon or web server, a recorded capture fixture, a fake executor result). A test that needs privileges, Windows or containers calls `t.Skip` with a reason string.
- Commits are small, one logical change, message `area: summary` (for example `probe: tftp check type`). No attribution lines of any kind.
- No shelling out in the default path; the one exception here is the Kali-only `xfreerdp /auth-only` wrapper, a pre-approved host tool (Task 33). Bounded queues, buffers, decoded sizes, timeouts; every probe socket has a hard deadline. Atomic writes through `internal/atomicfile` for state files (`overrides.yml`, pending-credential records).
- No compatibility shims, aliases or dual formats: a renamed kind, table or path is renamed everywhere in the same commit. `vantage.check` becomes `checks.result`, `vantage.check_deferred` becomes `checks.deferred`; the check-runner's `vantage.refused` becomes `checks.refused`.
- A module imports only the core packages and the shared libraries (W1 Global Constraints). `checks`, `scorer`, `vantage` and `creds` import none of each other; `vantage` and `checks` import `internal/checks/probe` only; `internal/creds/pcr` imports nothing from the repo except `internal/vault`.
- Times stored in UTC. Passwords never appear in an event, a table, a log, a plan's JSON, an `Err` string or a config file in clear: they pass through `vault.RedactString`, travel as `vault.Secret`, in step secrets, or sealed.
- Scoring safety: probes touch only allowlisted IP literals of our own; `bad_attempts` stays 0; a scored account's password changes only inside a PCR transaction; nothing here connects to, scans or probes the scorer's addresses, and no code reads Quotient (`/api/credlists` is not an input).
- `act_enabled` and `autonomy` exist only on `creds` (it embeds `module.Actor`); `checks`, `scorer` and `vantage` carry `enabled` only and reject the others as unknown fields. Per-module rate and burst default from the manifest (`ModuleLimits` overrides are optional). How far a `creds` template goes is its engine `autonomy` setting and the attempt ledger, not a `creds` ladder.
- Observe mode: probes and flows without effects run, the doctor collects only, `scorer` learns and publishes, proposals appear, no transaction starts and no automatic re-apply runs.
- The design is authoritative; a forced design change edits `phylax_design.md` in the same commit with the reason.
- Code style ponytail: the smallest complete change; a known limit carries `// shortcut: <limit>, <when to upgrade>`.
- Branch `v4-scoring-creds`, cut from `v4` after W1 and W6's seams merge.

## Review Focus

1. **A stale or absent round clock read as "safe".** The fact's TTL passes, the controller link is down, or `scorer.clock` is provisional. Expected: a runner or a PCR gate treats it as unknown (probes follow the jittered fallback, a transaction is refused), never as an open window; a held node fails at `max_hold` rather than applying late (Task 2 `TestRoundClockExpiredIsUnknown`, Task 3 `TestHoldFailsAtMaxHold`, Task 13 `TestStaleFactFallsBack`).
2. **A scored password in a place it must not be.** Event fields, module tables, the plan's stored JSON, logs, error strings, UI HTML, the agent's persisted config. Expected: none; the agent holds it only in memory and the config carries it sealed (Task 14 `TestNoSecretInEventsOrConfigOnDisk`, Task 42 `TestNoSecretAnywhere`).
3. **Controller restart in the middle of a transaction.** Host changed, human not yet submitted. Expected: the transaction resumes from `creds_txn` at the same state, the host change is never re-run, the `creds_txn` fact is re-sent with a fresh TTL (Task 42 `TestRestartResumesAtHostChanged`).
4. **Target allowlist bypass forms.** A hostname, an IPv4-mapped IPv6 address, a decimal or octal IP, a trailing dot, `0.0.0.0`, an address one bit outside the prefix. Expected: refused with `checks.refused` or `vantage.refused`, nothing dialled (Task 12 `TestAllowlistBypassForms`).
5. **A user who lost their scored status on the list, or a reply that disagrees.** The portal reply `count` differs from the rows, or `skipped` is not empty. Expected: the transaction is treated as possibly applied, a rollback also enters the old value, skipped rows fail with no PCR rollback (Task 43 `TestReplyMismatchTreatedAsApplied`).

---

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `internal/checks/probe/` | the stateless probe library (moved from `internal/checks`): 18 check types, `Run`, `Faithful`, `Sweep`, `AuthOnly` | 1, 8-10 |
| `internal/checks/{kinds,module,config,tables,derive,compare,proposals,records,mimic,doctor,flow,ui}.go` | the `checks` module, controller side | 1, 11, 15-22 |
| `internal/checks/{runner,gate,creds}.go` | the `checks` agent module (moved from `internal/vantage/checkrunner.go`) | 12-14 |
| `checks/checks/*.yml`, `checks/flows/*.yml`, `checks/doctor/*.yml` | content | 11, 20, 21 |
| `internal/agent/mods/checks.go`, `vantage.go` | factories | 12, 31 |
| `internal/scorer/{kinds,module,config,feed,tables,accounts,groups,sla_feed,risk,facts,ui}.go` | the `scorer` module around the built estimator, classifier, discovery and tracker | 1, 23-29 |
| `rules/scorer/fingerprints.json` | the fingerprint table as data (Appendix G) | 23 |
| `internal/vantage/{kinds,module,controller,exposure,verify,zerologon,smbwinrm,rdpauth,ui}.go` | the `vantage` module | 1, 31-36 |
| `internal/creds/{kinds,module,config,tables,words,txn,proposal,lint,sheet,ui}.go` | the `creds` module around the built generator, records and break-glass | 1, 38-46 |
| `internal/creds/pcr/{engine,csv}.go` | the PCR engine (moved from `internal/scorer`) | 37 |
| `rules/creds/words.txt`, `plans/creds/{scored-change,resync,unscored-rotation}.yml` | content | 38, 41 |
| `internal/plan/{fact,plan,step}.go`, `internal/controller/{window,plans,facts_step,deception_plan,genconfig_checks}.go` | core additions (window hold, manual gate, txn, step results, genconfig) | 1-7, 18 |
| `internal/vault/writer.go`, `internal/link/seal.go` | `Writer`, sealing | 6, 7 |
| `internal/actions/{health_check,session_evict}.go` | `health.check`, the eviction policy | 19, 40 |
| `manifest/2027/modules/{checks,scorer,vantage,creds}.yml`, `manifest/schema/modules/*.schema.json` | reference blocks | with each module's conformance task |
| `docs/impl/lab/w7-scoring-creds.md` | lab record | 48 |

---

### Task 1: Seams (Sonnet or Opus)

Done by a stronger model. Extracts the probe library, moves the PCR engine, declares the kinds of the four modules, writes the stubs of their packages and the core hooks later tasks fill, and the skipped tests. **Open it as two pull requests into `v4`:** 1A is Steps 1 to 3 (probe extraction; W12 waits on it), merged first; 1B is the rest.

**Files:**
- Move (`git mv`, fix package clauses and every importer in the same commit): every non-test and test file of `internal/checks/*.go` to `internal/checks/probe/` (package `probe`; `checks.go` keeps its name); `internal/vantage/compare.go` to `internal/checks/compare.go` (package `checks`); `internal/vantage/checkrunner.go` and `checkrunner_test.go` to `internal/checks/runner.go` and `runner_test.go` (package `checks`); `internal/scorer/pcr.go`, `pcr_test.go`, `csv.go`, `csv_test.go` to `internal/creds/pcr/engine.go`, `engine_test.go`, `csv.go`, `csv_test.go` (package `pcr`).
- Create: `internal/checks/{kinds,module,config,tables}.go`, `internal/scorer/{kinds,module,config}.go`, `internal/vantage/{kinds,module,config}.go`, `internal/creds/{kinds,module,config,tables}.go`, `internal/link/seal.go`, `internal/vault/writer.go`, `internal/controller/window.go`, `internal/agent/mods/{checks,vantage}.go`
- Modify: `internal/plan/{agentconfig,fact,plan,step}.go`, `internal/event/core.go`, `internal/parsers/txn/txn.go` (delete `Features`), `internal/scorer/fingerprint.go` (`FeaturesFromTxn`), `internal/controller/{checks_hub,webops,dir_devices}.go`, `internal/vantage/{vantage,verify}.go`, `internal/manifest/types.go`, `internal/module/all/all.go`, `internal/module/conformance/allowed.go` (`PreContract` gains `checks`, `scorer`, `vantage`, `creds`; `ModulePackages` entries), `phylax_design.md` (the 17 gaps; table names; `pcr.generate`; Appendix D)
- Create: every test file named in Tasks 2 to 47 with each test body as given in its Step 1 and `t.Skip("unimplemented: W7 Task N")` as the first statement; helpers they share

**Interfaces:**
- Consumes: W1 Tasks 1 to 5 names (`event.Declare`, `event.New`, `event.Type`, `module.Manifest`, `module.Common`, `module.Health`, `module.ControllerModule`, `module.Host`, `agent.Factory`, `plan.ModuleLimits`, `conformance.PreContract`, `module.Actor`); W3 `actions.Register`; W6 seams' `conn` (`source: capture`) and `capture.txn` kind names.
- Produces (exact; later tasks and other workstreams use these):

```go
// ---- internal/checks/probe ---- (package probe; the built exports unchanged, plus)
const (TFTP Type = "tftp"; NTP Type = "ntp")                    // Types() lists 18
// Item gains: Skew time.Duration // ntp: largest accepted |reply time - local time|; 0 means 2s
// Options gains: RDPAuth func(ctx context.Context, host string, port int, user, pass string) error // Kali wrapper; nil: rdp AuthOnly reports class config

// ---- internal/checks/kinds.go ---- (all declared at schema 1 in init; priorities: result Normal (High when not OK, set after New), deferred Bulk, refused High+Alert, red High+Alert, latency Normal, compare High, flow Normal, diagnosis High)
const (KindResult = "checks.result"; KindDeferred = "checks.deferred"; KindRefused = "checks.refused"; KindRed = "checks.red"
	KindLatency = "checks.latency"; KindCompare = "checks.compare"; KindFlow = "checks.flow"; KindDiagnosis = "checks.diagnosis")
type ResultEvent struct {
	ID string `json:"id"`; Type string `json:"type"`; Service string `json:"service,omitempty"`; Host string `json:"host"`; Port int `json:"port,omitempty"`
	Item string `json:"item,omitempty"`; User string `json:"user,omitempty"`; Mode string `json:"mode"`; Vantage string `json:"vantage"`
	OK bool `json:"ok"`; ScorerOK bool `json:"scorer_ok"`; StrictOK bool `json:"strict_ok"`; Strict bool `json:"strict,omitempty"`
	Class string `json:"class,omitempty"`; Err string `json:"err,omitempty"`; StrictIssues []string `json:"strict_issues,omitempty"`
	ElapsedMS int64 `json:"elapsed_ms"`; Steps map[string]int64 `json:"steps,omitempty"`; Debug string `json:"debug,omitempty"`
}
type DeferredEvent struct{ ID, Vantage, Reason string }          // json id, vantage, reason
type RefusedEvent struct{ ID, Vantage, Target string }           // json id, vantage, target
type RedEvent struct {
	Service string `json:"service"`; Check string `json:"check"`; Vantage string `json:"vantage"`; Streak int `json:"streak"`
	Class string `json:"class,omitempty"`; Diff string `json:"diff,omitempty"`; Trace string `json:"trace,omitempty"`
}
type LatencyEvent struct{ Service, Check string; ElapsedMS, LimitMS int64 } // json service, check, elapsed_ms, limit_ms
type EventRefPair struct{ Agent string `json:"agent"`; Seq uint64 `json:"seq"` }
type CompareEvent struct {
	Service string `json:"service"`; Check string `json:"check"`
	Class string `json:"class"` // both_ok | service_down | path_broken | scorer_content | internal_only
	External EventRefPair `json:"external"`; LAN EventRefPair `json:"lan"`; Samples int `json:"samples"`
}
type FlowStep struct{ Name string `json:"name"`; OK bool `json:"ok"`; ElapsedMS int64 `json:"elapsed_ms"`; Class string `json:"class,omitempty"` }
type FlowEvent struct {
	Flow string `json:"flow"`; Vantage string `json:"vantage"`; OK bool `json:"ok"`; FailedStep string `json:"failed_step,omitempty"`
	Steps []FlowStep `json:"steps"`; Effects []string `json:"effects,omitempty"`
}
type Cause struct{ Rank int `json:"rank"`; Cause string `json:"cause"`; Evidence string `json:"evidence"`; Step string `json:"step"` }
type DiagnosisEvent struct{ Service, Host, StreakID string; Causes []Cause } // json service, host, streak_id, causes

// ---- internal/checks/config.go ---- (controller block, modules/checks.yml; unknown fields are an error)
type Config struct {
	module.Common `yaml:",inline"`
	Interval, MinGap, MaxDefer time.Duration; ProbeTimeout string // "auto" or a duration
	SweepEvery, MaxConcurrent, RedAfter, BadAttempts int
	Strict bool; LatencyWarn float64; Vantages []string; ContentDir string
	Doctor DoctorConfig; Flows FlowsConfig; Allowlist []string
}
type DoctorConfig struct{ Enabled bool; On string; Timeout time.Duration }
type FlowsConfig struct{ Enabled bool; Interval time.Duration }
type Module struct{ /* health behind a mutex */ }                 // controller side; Manifest() per the design table; init: module.Register
// ---- internal/plan/agentconfig.go ----
type ChecksSettings struct {
	ModuleLimits
	IntervalSec, SweepEvery, MinGapMS, MaxDeferSec, ProbeTimeoutSec, MaxConcurrent, BadAttempts int // 0 ProbeTimeoutSec = auto
	Strict bool; Vantage string // "lan" or "kali": the label on every result
	Allowlist []string
	Checks []CheckSpec
	Creds  []CheckCred
}
type CheckSpec struct { // a probe.Spec in JSON form; credentials by reference into Creds
	ID, Service, Type, Host string; Port int; Encrypted bool; Domain string; RequireAuth bool
	Items []map[string]any; CredRefs []string // "<account>@<credlist>"
}
type CheckCred struct {
	Service, Host, Account, Credlist string
	Version int
	Sealed []byte `json:"sealed"` // link.SealSecret output; opened in memory only
}
type VantageSettings struct {
	ModuleLimits
	Allowlist []string; ScanIntervalSec, ScanFirstDelaySec, QuietWaitSec int
	TCPRate, TCPConcurrency, TCPConnectTimeoutMS, UDPRate, UDPWaitMS int
	PreWindow []time.Time
	CanaryTCP, CanaryUDP []int; CanaryDedupSec, CanaryMaxEventsPerSec, CanaryMaxConns, CanaryReadTimeoutMS int
	VerifyTimeoutSec int; ProbeZerologon, ProbeSMB, ProbeWinRM bool
	ScoredServices []ScoredPort // the manifest's scored set on our public addresses, for DiffExposure
}
type ScoredPort struct{ Host, Proto, Label string; Port int }
// ModuleSettings gains: Checks *ChecksSettings `json:"checks,omitempty"`; Vantage *VantageSettings `json:"vantage,omitempty"`

// ---- internal/plan/fact.go ---- (data of the three fact subtypes; JSON in ControllerFact.Data)
type RoundClock struct {
	DelayMS, JitterMS int64; Confidence float64; Provisional bool
	WindowStart, WindowEnd, NextEarliest time.Time
}
// Window reports whether a quiet window of at least need is open at now, extrapolating whole delays when now is past WindowEnd.
func (r RoundClock) Window(now time.Time, need time.Duration) (safe bool, until time.Time)
type CredsTxnFact struct{ Txn, Account, Host, Credlist string; Open bool }
type ProbeResultFact struct{ Service, Host, Source string; OK bool; Round int } // source: lan | external

// ---- internal/link/seal.go ----
func SealSecret(to *ecdsa.PublicKey, aad string, plain []byte) ([]byte, error)
func (id *Identity) OpenSecret(aad string, sealed []byte) ([]byte, error)
// agent.Env gains: func (e Env) OpenSealed(aad string, sealed []byte) ([]byte, error)

// ---- internal/vault/writer.go ----
type Writer interface {
	Reader
	Put(name string, v Secret, note string) (version string, err error)
	Delete(name string) error
}

// ---- internal/plan/plan.go: Node gains (all omitempty) ----
// Window string `json:"window"`        // "scorer_quiet"
// MaxHoldSec int `json:"max_hold_sec"` // default 600
// WindowMinSec int `json:"window_min_sec"` // default 30
// Ask string `json:"ask"`; Reply string `json:"reply"` // count | text | choice
// Choices []string `json:"choices"`
// Txn string `json:"txn"`
// Approval gains: Reply string `json:"reply,omitempty"`; StepBody gains: Txn string `json:"txn,omitempty"` (signed)
// ---- internal/event/core.go: AgentStepResult gains Output map[string]any `json:"output,omitempty"` and Reply string `json:"reply,omitempty"`
// ---- internal/controller/window.go ----
func (c *Controller) quietWindow(ctx context.Context, need time.Duration) (open bool, until time.Time, why string)

// ---- internal/scorer/fingerprint.go ----
func FeaturesFromTxn(t txn.Txn) Features

// ---- internal/scorer/kinds.go ---- (priorities: round Normal, clock Normal, service Normal, item_set Bulk, login Normal, account Normal,
//   proposal Normal, blocked High+Alert, silent Normal, sla High+Alert, risk Normal; no scorer.note: the hand-entered verdict is operator.edit, S4)
const (KindRound = "scorer.round"; KindClock = "scorer.clock"; KindService = "scorer.service"; KindItemSet = "scorer.item_set"
	KindLogin = "scorer.login"; KindAccount = "scorer.account"; KindProposal = "scorer.proposal"; KindBlocked = "scorer.blocked"
	KindSilent = "scorer.silent"; KindSLA = "scorer.sla"; KindRisk = "scorer.risk")
type RoundSource struct{ Addr string `json:"addr"`; Score float64 `json:"score"` }
type RoundEvent struct {
	Round int `json:"round"`; Start time.Time `json:"start"`; End time.Time `json:"end"`; Conns int `json:"conns"`
	Services []string `json:"services,omitempty"`; Accounts []string `json:"accounts,omitempty"`; Sources []RoundSource `json:"sources,omitempty"`
	Dropped bool `json:"dropped,omitempty"`; Provisional bool `json:"provisional,omitempty"`
}
type ClockEvent struct {
	DelayMS, JitterMS, TimeoutEstMS int64; Confidence float64; Provisional bool; Bursts int
	LastBurstEnd, NextEarliest, NextLatest, WindowStart, WindowEnd time.Time
	MinWindowMS int64; EvictionCutoffMS int64 // 0 until the delay is measured
} // json tags: delay_ms, jitter_ms, timeout_est_ms, confidence, provisional, bursts, last_burst_end, next_earliest, next_latest, window_start, window_end, min_window_ms, eviction_cutoff_ms
type ServiceEvent struct{ Host string; Port int; Proto, TypeGuess string; Fingerprints []string; Rounds int; Learned, Custom bool }
type ItemSetEvent struct {
	Service string; Items int; Coverage, SizeEstimate, RoundsToAll, RoundsExpectedOne, RoundsExpectedAll float64; Users []string
} // json: service, items, coverage, size_estimate, rounds_to_all, rounds_expected (= One), rounds_expected_all, users
type LoginEvent struct{ Account, Service, Host string; OK bool; TS time.Time; Round int } // json: account, service, host, ok, ts, round
type AccountEvent struct {
	User, Service, Host, Proto, How string; OK, Fail int; FirstSeen, LastSeen time.Time; Group string
} // json: user, service, host, proto, how (capture|auth_event), ok, fail, first_seen, last_seen, group
type ProposalEvent struct{ Kind, Service string; Sample string; Prefilled map[string]any; RoundsSilent int } // json: kind (new|update|stale), service, sample, prefilled, rounds_silent
type BlockedEvent struct{ Service string; RoundsMissed int; Window string; DenyRefs []EventRefPair }
type SilentEvent struct{ Since time.Time }
type SLAEvent struct{ Service, Level string; Streak, Penalties int; Source string } // level: warn|critical|penalty; source: probe|capture|note
type NoteRecord struct{ Service, Verdict string; Round int; Text string }            // the `record` of operator.edit{module: scorer, op: note}; verdict: up|down; by and at are the event's
type RiskService struct {
	Service string `json:"service"`; Weight, LostPoints, PointsPerMinuteDown float64; DownSince *time.Time `json:"down_since,omitempty"`; Cause string `json:"cause"`
}
type RiskEvent struct{ Services []RiskService `json:"services"` }

// ---- internal/scorer/config.go ----
type Config struct { // modules/scorer.yml
	module.Common `yaml:",inline"`
	Clock ClockConfig; Discovery DiscoveryConfig; SLA SLAConfig; Classify struct{ ScorerMin, LikelyMin float64 }
	Fingerprints string; ReplayWindow time.Duration; Risk struct{ PointsPerService float64; EventMinutes int }
}

// ---- internal/vantage/kinds.go ---- (priorities: scan Normal, exposure_change High+Alert, canary_hit High+Alert, probe Normal (Critical+Alert for a failed pcr_verify or a positive zerologon, set after New), refused High+Alert; no correlation rules: these are alert-class kinds, S4)
const (KindScan = "vantage.scan"; KindExposureChange = "vantage.exposure_change"; KindCanaryHit = "vantage.canary_hit"
	KindProbe = "vantage.probe"; KindRefused = "vantage.refused")
type ScanEvent struct{ Hosts []string; TCPOpen, UDPOpen []string; DurationMS int64; Evidence string }
type ExposureChange struct{ Host string; Port int; Proto, Change string; Scored bool } // change: newly_open|closed|declared_closed
type CanaryHit struct{ Host, Source string; Port int; Proto string; Suppressed int }
type ProbeEvent struct{ Probe, Host, Result, Evidence, Account, Credlist, Service, Err string; OK bool } // probe: zerologon|smb_exposure|winrm_exposure|pcr_verify; the last five only for pcr_verify, credential-free (S4: pcr_verify is a probe.run step, not a kind)
type RefusedScan struct{ Target, Reason string }
// ---- internal/vantage/config.go ----
type Config struct { module.Common `yaml:",inline"`; Allowlist []string; Scan ScanYAML; Canary CanaryYAML; Verify struct{ Timeout time.Duration }; ExposureProbes struct{ Zerologon, SMB, WinRM bool } }

// ---- internal/creds/kinds.go ---- (priorities: state Normal, proposal High, txn High, reverted High+Alert, notice Normal, t0 Normal)
const (KindState = "creds.state"; KindProposal = "creds.proposal"; KindTxn = "creds.txn"; KindReverted = "creds.reverted"; KindNotice = "creds.notice"; KindT0 = "creds.t0")
type StateEvent struct{ Account, Host, Credlist, State, CurrentVersion, PreviousVersion, Txn string } // never a value
type ProposalEvent struct{ Account string; Credlists, Hosts []string; Reason string; Evidence []EventRefPair; ProposedBy string }
type TxnEvent struct {
	Txn, Account, Step string; Window string; Reply *TxnReply; By []string
} // step: prepared|staged|committing|host_changed|verify_ok|pcr_submitted|verified|failed|rolled_back|late|race
type TxnReply struct{ Count int `json:"count"`; Skipped []string `json:"skipped,omitempty"` }
type RevertedEvent struct{ Host string; Accounts, Credlists []string; Reason string }       // reason: reenroll|login_mismatch|operator
type NoticeEvent struct{ Txn, What string }
type T0Event struct{ Host, Account, Step, By string }
// ---- internal/creds/config.go ----
type Config struct { module.Common `yaml:",inline"`; module.Actor `yaml:",inline"` /* creds acts: act_enabled and autonomy; checks, scorer and vantage embed Common only and reject both */; Generation GenConfig; PCR PCRConfig; Revert struct{ OnReenroll bool }; BreakGlass struct{ Epoch int }; ProposalRules []string }
```

- [ ] **Step 1 (1A): Extract the probe library.** `git mv` the files, change the package clause to `probe`, fix every importer (`internal/controller/{checks_hub,report_test}.go`, `internal/vantage/*.go`, `internal/capture`, `internal/parsers/*` tests). The old `internal/checks/*.go` library files do not remain. Add the `TFTP`, `NTP` constants, `Item.Skew` and `Options.RDPAuth` as stubs (`Types()` returns 18; the dispatcher reports class `config` for the two new types until Tasks 8 and 9).
- [ ] **Step 2 (1A): Test that proves the library has no scheduler.** Write `internal/checks/probe/nosched_test.go` (not skipped):

```go
func TestProbeHasNoSchedulerOrGlobals(t *testing.T) {
	// go/parser over every non-test file of this package: no package-level var of type sync.Mutex, sync.Map,
	// time.Ticker, time.Timer or chan; no `go` statement anywhere (Sweep is sequential with a gap between probes)
}
func TestTypesListsEighteen(t *testing.T) { if n := len(Types()); n != 18 { t.Fatalf("%d", n) } }
```

- [ ] **Step 3 (1A): Verify and commit.** Run: `make build build-windows vet test race`. Expected: PASS (the moved tests pass unchanged). `git commit -am "probe: extract internal/checks/probe as the shared stateless library"`. Open pull request 1A, merge after review.
- [ ] **Step 4 (1B): Move the runner, `Compare` and the PCR engine** as listed, with only package clause and import fixes. Delete `Engine.PlanForRecord`, `SyncRecord`, `CredsState` and `Generate` from `pcr`; Task 37 and Task 39 re-home their logic in `creds`, and the tests that called them move into those tasks' skipped files.
- [ ] **Step 5 (1B): Write the stubs.** Types and constants exactly as above; `init` in each `kinds.go` with the `event.Declare` calls (`Fields` is the zero payload struct); module `Manifest()` per the design's capability tables (name, sides, OS, privilege, roles, budget, tables with the renamed names, content, actions, pages; `Consumes` only kinds declared today: `conn`, `capture.txn`, `operator.edit` (W1), `auth_event`, `inventory.probe_result`, `net.canary_result`, `devices.deny`, `devices.traffic`, `agent.enrolled`, `agent.reenrolled`, `agent.step_result`, plus the four modules' own kinds); `Start` returns `module.ErrNoConfig` when the block is absent and otherwise reports `unavailable` with the gap `unimplemented: W7`; agent factories in `internal/agent/mods/{checks,vantage}.go` whose `Section` returns `false` until their tasks. Function bodies `panic("unimplemented: W7 Task N")` except where a test of this task needs them. Add the new fields to existing structs (zero-value safe, `omitempty`), delete `parsers/txn.Txn.Features`, add `scorer.FeaturesFromTxn`, and change the parser tests that call `.Features()`.
- [ ] **Step 6 (1B): Write the skipped tests and shared helpers** (`internal/checks/helpers_test.go` fake-store builder `newChecksHost`, `internal/scorer/feed_helpers_test.go` capture-fixture builders `txnEvent(proto, port, user, ok)` and `burst(at, n)`, `internal/creds/txn_helpers_test.go` a fake plan runner `fakeRunner` that records started templates and lets a test deliver `agent.step_result` events, `internal/controller/modtest_w7_test.go`). Task 1's own tests, not skipped: `TestKindsDeclared` in each of the four packages (every constant is `event.Lookup`-able, schema 1, priority and alert flag as listed) and `TestManifestsValid` (`Manifest.Validate()` nil for the four).
- [ ] **Step 7 (1B): Apply the 17 gaps to `phylax_design.md`** (one bullet each under the module sections they touch, plus the corrected table names, the removal of `pcr.generate` from the `creds` Actions row, the `CR` lint namespace, the `ContentDir` key in `modules/checks.yml`, and Appendix D lines for `internal/checks/probe`, `internal/creds/pcr`, `rules/creds`, `plans/creds`, `rules/scorer`, `checks/`; `rules/vantage` is not created).
- [ ] **Step 8 (1B): Verify and commit.** Run: `make build build-windows vet test race`, then `go test -v ./internal/... 2>&1 | grep -c 'unimplemented: W7 Task'`. Expected: all pass; the count equals the number of skipped tests written. `git commit -am "scoring-creds: W7 seams (kinds, stubs, settings, core hooks, skipped tests, design gaps)"`. Open pull request 1B, merge after review.

---

### Task 2: `RoundClock.Window` (pure extrapolation)

**Files:**
- Modify: `internal/plan/fact.go`
- Test: `internal/plan/roundclock_test.go`

**Interfaces:**
- Consumes: `plan.RoundClock` (Task 1).
- Produces: `func (r RoundClock) Window(now time.Time, need time.Duration) (safe bool, until time.Time)`. Rule: the window repeats every `DelayMS`; for `k` whole delays after the sent window the start moves by `k*(Delay+Jitter)` and the end by `k*(Delay-Jitter)` (the burst can be as late as Delay+Jitter or as early as Delay-Jitter), so the window narrows by `2*k*Jitter`; `k` is at most 3 and a window narrower than `need` is unsafe. `Provisional` or a zero `WindowEnd` is never safe. `shortcut: jitter accumulates per delay, three delays then unknown; upgrade if the Kali runner needs longer without a refresh.`

- [ ] **Step 1: Write the failing test**

```go
func TestRoundClockWindow(t *testing.T) {
	t0 := time.Date(2027, 2, 1, 12, 0, 0, 0, time.UTC)
	rc := RoundClock{DelayMS: 60000, JitterMS: 5000, Confidence: 0.9,
		WindowStart: t0.Add(3 * time.Second), WindowEnd: t0.Add(52 * time.Second)}
	for _, c := range []struct {
		name string
		at   time.Duration
		need time.Duration
		safe bool
		end  time.Duration
	}{
		{"inside", 10 * time.Second, 30 * time.Second, true, 52 * time.Second},
		{"too little left", 30 * time.Second, 30 * time.Second, false, 0},
		{"before the window", time.Second, 5 * time.Second, false, 0},
		{"gap between windows", 55 * time.Second, 5 * time.Second, false, 0},
		{"one delay later, narrowed by 10 s", 70 * time.Second, 30 * time.Second, true, 107 * time.Second},
		{"three delays later", 3*60*time.Second + 20*time.Second, 5 * time.Second, true, 3*60*time.Second + 52*time.Second - 15*time.Second},
		{"four delays later is unknown", 4*60*time.Second + 10*time.Second, 5 * time.Second, false, 0},
	} {
		safe, until := rc.Window(t0.Add(c.at), c.need)
		if safe != c.safe || (safe && !until.Equal(t0.Add(c.end))) {
			t.Errorf("%s: safe=%v until=%v", c.name, safe, until.Sub(t0))
		}
	}
	rc.Provisional = true
	if safe, _ := rc.Window(t0.Add(10*time.Second), time.Second); safe {
		t.Error("provisional clock read as safe")
	}
}
func TestRoundClockExpiredIsUnknown(t *testing.T) {
	var zero RoundClock
	if safe, _ := zero.Window(time.Now(), time.Second); safe {
		t.Fatal("zero clock read as safe")
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/plan/ -run RoundClock -v`. Expected: FAIL (`unimplemented: W7 Task 2` or a wrong window).
- [ ] **Step 3: Implement** `Window` as specified (about 20 lines).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/plan/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "plan: RoundClock window with bounded extrapolation"`

---

### Task 3: Plan node `window: scorer_quiet` hold (Sonnet)

Core engine work: the design resolves the option; nothing builds it.

**Files:**
- Modify: `internal/plan/plan.go` (`Node.Window`, `MaxHoldSec`, `WindowMinSec` validation), `internal/controller/window.go`, `internal/controller/plans.go` (hold before dispatch)
- Test: `internal/plan/window_test.go`, `internal/controller/window_test.go`

**Interfaces:**
- Consumes: `Node` fields (Task 1), `RoundClock.Window` (Task 2), `Controller.EmitController`, `store.Reader.Latest`.
- Produces: `(*Controller).quietWindow(ctx, need) (open bool, until time.Time, why string)` reading the latest `scorer.clock` event of agent `controller`; `Options.WindowConfidence float64` (default 0.5). A node with `Window == "scorer_quiet"` is held after approval until `quietWindow(need)` is open (`need` = `WindowMinSec`, default 30 s), then dispatched; the node shows the note `waiting for a quiet window: <why>`; after `MaxHoldSec` (default 600) the node fails with reason `window: max hold exceeded` and nothing is applied. The dead-man and step expiry timers start at dispatch, not at approval. `shortcut: the hold polls the latest scorer.clock event once a second; upgrade to the bus subscription if the poll shows in a profile.`

- [ ] **Step 1: Write the failing tests**

```go
// internal/plan/window_test.go
func TestNodeWindowValidates(t *testing.T) {
	ok := Node{ID: "a", Action: "file.hash", Target: "h1", Window: "scorer_quiet", MaxHoldSec: 120, WindowMinSec: 30}
	bad := []Node{{ID: "a", Action: "file.hash", Target: "h1", Window: "other"},
		{ID: "a", Action: "file.hash", Target: "h1", Window: "scorer_quiet", MaxHoldSec: 4000},
		{ID: "a", Action: "file.hash", Target: "h1", Window: "scorer_quiet", WindowMinSec: 700}}
	if err := validateNode(ok); err != nil {
		t.Fatal(err)
	}
	for i, n := range bad {
		if validateNode(n) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	// a YAML template with `window: scorer_quiet` and `max_hold: 120` parses into Node (key names per the design)
}
// internal/controller/window_test.go  (blank-imports internal/scorer to get the scorer.clock kind declared; test-only edge)
func TestQuietWindowReadsLatestClock(t *testing.T) {
	c := newTestController(t)
	emitClock(t, c, clockAt{start: 3, end: 52, conf: 0.9}) // helper: EmitController of scorer.clock built with event.New, times relative to c.opt.Now()
	for _, tc := range []struct{ name string; at, need time.Duration; open bool; why string }{
		{"inside", 10 * time.Second, 30 * time.Second, true, ""},
		{"too short", 30 * time.Second, 30 * time.Second, false, "window"},
		{"no clock", 0, 0, false, "no round clock"},
	} { /* set the fake now; assert open and strings.Contains(why, tc.why) */ }
	// confidence 0.4 -> why contains "confidence"; provisional true -> why contains "provisional"
}
func TestHoldAppliesWhenWindowOpens(t *testing.T) {
	// e2e helpers (real agent h1); plan with one file.write node on a temp path, Window scorer_quiet; approve
	// no clock yet: after 200 ms OnStepSent has seen no apply step; the node note contains "waiting for a quiet window"
	// emitClock(open) -> within 2 s exactly one apply step is sent and the node verifies
}
func TestHoldFailsAtMaxHold(t *testing.T) {
	// MaxHoldSec 1, hold poll 10 ms (c.holdPoll), fake clock advanced 2 s with no window
	// want: node state failed, reason "window: max hold exceeded", OnStepSent saw no apply step, file untouched
}
func TestHoldIgnoresStaleOpenWindowAfterEnd(t *testing.T) {
	// clock window ended 10 s ago and no refresh: quietWindow extrapolates (Task 2); at k>3 delays it returns open=false
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/plan/ ./internal/controller/ -run 'NodeWindow|QuietWindow|Hold' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the fields (JSON keys `window`, `max_hold_sec`, `window_min_sec`; the YAML template loader accepts `max_hold: 120s` as seconds), `quietWindow` (decode the event with a local struct; return the confidence and provisional reasons before the width reason), and the hold in the dispatch path of `plans.go` for nodes of any approval class. A held node counts as running for `Wait` and for plan expiry.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/plan/ ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: window: scorer_quiet hold with max hold"`

---

### Task 4: `gate: manual`, `txn:` and the agent's PCR flag (Sonnet)

> **Carried from W1 (2026-11-06).** Until this task lands, W1's `SS010` reads the resync marker from a node's own `txn: resync` param (`lintParams` strips it for the lint only), so the template author asserts it. Replace it with a controller-set transaction field that only the `creds` resync path can set, make `SS010` read that, and delete the param fallback. Test: a template node that carries `txn: resync` itself is refused in an `auto` plan when it sets a protected account's password (`app_mysql`, `mssql_query` emit `OpSetPassword`).

**Files:**
- Modify: `internal/plan/plan.go` (`Node.Ask/Reply/Choices/Txn`, `Approval.Reply`), `internal/plan/step.go` (`StepBody.Txn`, copied by `Signer.Issue`), `internal/controller/plans.go` (`ApproveGateReply`, `ApproveNode` refuses a manual gate), `internal/agent/exec.go` (`req.PCR = s.Txn != ""`)
- Test: `internal/plan/manualgate_test.go`, `internal/controller/manualgate_test.go`, `internal/agent/pcr_flag_test.go`

**Interfaces:**
- Consumes: Task 1 fields; the built `ApproveNode`, `Signer.Issue`, `actions.Request.PCR`, the manifest guard (`guard_manifest.go`).
- Produces: `(*Controller).ApproveGateReply(ctx, planID, node, by, note, reply string) error`; `Approval.Reply`; the node's reply readable as `${<gate id>.reply}` in later nodes' string params (`ExpandReplies(p Plan, run Run) Plan` in `internal/controller/plans.go`, applied when a node is dispatched).

Rules: `Ask` and `Reply` only on a gate node; `Reply` is one of `count` (a non-negative integer), `text` (1 to 256 printable characters) or `choice` (must be one of `Choices`); `Ask` requires `Reply`; `Txn` matches `^[A-Za-z0-9_.-]{1,64}$`.

- [ ] **Step 1: Write the failing tests**

```go
func TestManualGateValidates(t *testing.T) {
	g := func(mut func(*Node)) Node { n := Node{ID: "g", Gate: true, Ask: "Portal count?", Reply: "count"}; mut(&n); return n }
	if validateNode(g(func(*Node) {})) != nil { t.Fatal("good gate refused") }
	for i, n := range []Node{
		{ID: "a", Action: "file.hash", Target: "h1", Ask: "q", Reply: "count"},          // Ask on a non-gate
		g(func(n *Node) { n.Reply = "" }),                                              // Ask without Reply
		g(func(n *Node) { n.Reply = "choice" }),                                        // choice without Choices
		g(func(n *Node) { n.Reply = "number" }),                                        // unknown kind
		{ID: "a", Action: "file.hash", Target: "h1", Txn: "bad id!"},
	} {
		if validateNode(n) == nil { t.Errorf("case %d accepted", i) }
	}
}
func TestApproveGateReplyStoresReply(t *testing.T) {
	// plan: gate g (Ask "Portal count?", Reply count) then a node needing g; create + approve plan
	// c.ApproveNode(..., "g", "alice", "") -> error containing "reply required"
	// c.ApproveGateReply(..., "g", "alice", "approved by bob", "abc") -> error (not a count)
	// c.ApproveGateReply(..., "g", "alice", "approved by bob", "3") -> nil; status node g Approval.By=="alice", Reply=="3", Note=="approved by bob"
	// the later node's string param "${g.reply}" is "3" in the step handed to the agent (OnStepSent)
}
func TestTxnCoveredBySignature(t *testing.T) {
	// issue a step for a node with Txn "t1": step.Txn == "t1" and the verifier accepts it; set step.Txn = "t2": Verify -> error
}
func TestAgentSetsPCRForTxnSteps(t *testing.T) {
	// agent exec test env with a manifest guard marking user "scored1" scored (guard_manifest_test.go helper);
	// step user.set_password{user: scored1} with Txn "t1" -> applied; the same step with Txn "" -> refused, error contains "scored passwords change only by PCR transaction"
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/plan/ ./internal/controller/ ./internal/agent/ -run 'ManualGate|ApproveGateReply|TxnCovered|SetsPCR' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified. `shortcut: the agent trusts StepBody.Txn because the signature covers it; the controller-side rule CR001 (Task 47) checks that the transaction is open.`
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/plan/ ./internal/controller/ ./internal/agent/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "plan: gate: manual replies, txn on steps, agent PCR flag"`

---

### Task 5: `agent.step_result` for every step result (Sonnet)

**Files:**
- Modify: `internal/controller/plans.go` (the step-result handler), `internal/controller/exec.go`, `internal/event/core.go` (`AgentStepResult.Output`, `Reply`)
- Test: `internal/controller/step_result_test.go`

**Interfaces:**
- Consumes: W1 Task 29's `agent.step_result` emission for controller-side actions; the agent's `StepResult` message (output map); `EmitController`.
- Produces: one `agent.step_result` event (agent `controller`) per verified step result of an agent-run node and per gate approval (`Phase: "gate"`, `Reply` set), with `Output` bounded at 32 KiB encoded (over the bound: `Output = {"truncated": true, "bytes": <n>}`) and any output key beginning `secret.` dropped.

- [ ] **Step 1: Write the failing tests**

```go
func TestAgentRunStepEmitsStepResult(t *testing.T) {
	// e2e helpers, real agent h1; plan with one read-only collect node (file.hash of a temp file); Wait
	// e := c.st.Latest(ctx, "controller", "agent.step_result") decoded with event.Decode[AgentStepResult]:
	// Host=="h1", Node==the node id, Outcome=="verified" (or the agent's outcome string), Output["sha256"] != nil
}
func TestStepResultDropsSecretOutputsAndBoundsSize(t *testing.T) {
	// a result output {"secret.token": "x", "big": 40 KiB string}: event has no "secret.token" key; Output["truncated"]==true; Output["bytes"] > 32768
}
func TestGateApprovalEmitsReply(t *testing.T) {
	// manual gate approved with reply "3": a step_result with Phase "gate", Node "g", Reply "3"
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run 'StepResult|GateApprovalEmits' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the emission beside the existing store write of the result; failures to emit are logged, never fail the plan.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/ ./internal/event/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: agent.step_result for agent-run steps, with bounded output"`

---

### Task 6: Vault writer and `stepSecrets` for credential transactions

**Files:**
- Create: `internal/vault/writer.go`
- Modify: `internal/controller/deception_plan.go` (`stepSecrets(p plan.Plan, n plan.Node)`), `internal/controller/host.go` (`Secrets` returns the writer for module `creds`)
- Test: `internal/vault/writer_test.go`, `internal/controller/stepsecrets_pcr_test.go`

**Interfaces:**
- Consumes: built `Vault.Put/Get/Delete`, `vault.Reader`, `vault.Scoped` (W1), W1 `moduleHost.Secrets`.
- Produces: `func ScopedWriter(v *Vault, patterns []string) Writer` (a pattern ending in `/*` matches any name with that prefix, any other pattern is exact; a name outside every pattern returns `ErrNotAllowed` from `Get`, `Put` and `Delete`); `stepSecrets` allows the vault prefix `pcr/` for the actions `user.set_password`, `ad.account.reset_password` and `probe.run` with name `pcr_verify` (param `password`) only when `p.Module == "creds"` and `n.Txn != ""`.

- [ ] **Step 1: Write the failing tests**

```go
func TestScopedWriter(t *testing.T) {
	v := newTestVault(t) // helper from vault_test.go, unlocked
	w := ScopedWriter(v, []string{"cred/*", "pcr/*", "exact/one"})
	if _, err := w.Put("pcr/t1/h1/alice", NewSecretString("x"), "pending"); err != nil { t.Fatal(err) }
	s, err := w.Get("pcr/t1/h1/alice")
	if err != nil || s.Reveal() != "x" { t.Fatal(err) }
	for _, name := range []string{"honeytoken/a", "exact/two"} {
		if _, err := w.Put(name, NewSecretString("y"), ""); !errors.Is(err, ErrNotAllowed) { t.Errorf("%s: %v", name, err) }
		if w.Delete(name) == nil { t.Errorf("delete %s allowed", name) }
	}
	if err := w.Delete("pcr/t1/h1/alice"); err != nil { t.Fatal(err) }
}
func TestStepSecretsPCRNeedsCredsPlanAndTxn(t *testing.T) {
	good := plan.Plan{Module: "creds", Nodes: []plan.Node{{ID: "n", Action: "user.set_password", Target: "h1", Txn: "t1",
		Params: map[string]any{"user": "alice", "secret_params": []any{"password"}, "secret_refs": map[string]any{"password": "pcr/t1/h1/alice"}}}}}
	// vault holds pcr/t1/h1/alice = "pw": stepSecrets(good, good.Nodes[0]) == {"password":"pw"}
	// Module "hardening" -> error; Txn "" -> error; ref "cred/h1/alice" -> error; ref "pcr/t1/../../cred/h1/alice" -> error;
	// action "file.plant" with a pcr/ ref -> error (the honeytoken rule is unchanged: honeytoken/ refs still work for file.plant)
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/vault/ ./internal/controller/ -run 'ScopedWriter|StepSecretsPCR' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `ScopedWriter`, change `stepSecrets` to take the plan and adjust both call sites in `plans.go`; `moduleHost.Secrets` returns `ScopedWriter` for the module named `creds` and `Scoped` for others.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/vault/ ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "vault: ScopedWriter; stepSecrets for credential transactions"`

---

### Task 7: Sealing a secret to an agent's identity

**Files:**
- Create: `internal/link/seal.go`
- Modify: `internal/agent/registry.go` (`Env.OpenSealed`), `internal/agent/agent.go` (wire the identity into `Env`)
- Test: `internal/link/seal_test.go`, `internal/agent/opensealed_test.go`

**Interfaces:**
- Consumes: built `link.Identity` (P-256 key), `agents.pubkey` (DER PKIX of the enrolled key).
- Produces: `func SealSecret(to *ecdsa.PublicKey, aad string, plain []byte) ([]byte, error)` (ephemeral P-256 key, `crypto/ecdh` shared secret, `crypto/hkdf` SHA-256 with info `phylax-seal-v1`, AES-256-GCM, output `epk(65) || nonce(12) || ciphertext`); `func (id *Identity) OpenSecret(aad string, sealed []byte) ([]byte, error)`; `agent.Env.OpenSealed(aad, sealed)`. Plaintext over 64 KiB is refused. Task 1 declares these names.

- [ ] **Step 1: Write the failing tests**

```go
func TestSealRoundTrip(t *testing.T) {
	id, _ := GenerateIdentity("h1")
	sealed, err := SealSecret(&id.key.PublicKey, "h1", []byte("Plum-river-tent-82"))
	if err != nil { t.Fatal(err) }
	if bytes.Contains(sealed, []byte("Plum")) { t.Fatal("plaintext visible") }
	got, err := id.OpenSecret("h1", sealed)
	if err != nil || string(got) != "Plum-river-tent-82" { t.Fatalf("%q %v", got, err) }
	other, _ := GenerateIdentity("h2")
	if _, err := other.OpenSecret("h1", sealed); err == nil { t.Error("wrong key opened it") }
	if _, err := id.OpenSecret("h2", sealed); err == nil { t.Error("wrong aad opened it") }
	sealed[len(sealed)-1] ^= 1
	if _, err := id.OpenSecret("h1", sealed); err == nil { t.Error("tampered ciphertext opened") }
	again, _ := SealSecret(&id.key.PublicKey, "h1", []byte("x"))
	again2, _ := SealSecret(&id.key.PublicKey, "h1", []byte("x"))
	if bytes.Equal(again, again2) { t.Error("two seals are identical") }
	if _, err := SealSecret(&id.key.PublicKey, "h1", make([]byte, 64<<10+1)); err == nil { t.Error("oversize accepted") }
}
// internal/agent/opensealed_test.go: a module factory built through the harness with a sealed value from the controller side
// opens it with env.OpenSealed(host, sealed); a value sealed for another host fails.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/link/ ./internal/agent/ -run 'Seal|OpenSealed' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified (about 60 lines of standard library).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/link/ ./internal/agent/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "link: seal a secret to an agent's identity key"`

---

### Task 8: probe: TFTP check type

**Files:**
- Create: `internal/checks/probe/tftp.go`, `internal/checks/probe/tftp_test.go`
- Modify: `internal/checks/probe/checks.go` (dispatcher, `DefaultPort`, `NeedsCreds`)

**Interfaces:**
- Consumes: the built `probe` struct helpers (`p.dial`, `p.step`, `fail`, `classify`) in `checks.go`; `Item.File`, `Item.SHA256`.
- Produces: `func probeTFTP(ctx context.Context, p *probe) error`; `TFTP` default port 69. Behaviour: UDP RRQ for `Item.File` in `octet` mode, read DATA blocks with ACKs (512-byte blocks, last block short), cap 8 MiB, compare SHA-256 when `Item.SHA256` is set; an ERROR packet is class `content` ("file not found") except access violation, class `auth`; no reply within the timeout is `timeout`; strict mode flags an empty file. The scorer's real logic is unknown; `shortcut: learned by burst, port and file; upgrade when the scripts are captured.`

- [ ] **Step 1: Write the failing tests**

```go
func TestTFTPReadsFileAndHash(t *testing.T) {
	srv := newFakeTFTP(t, map[string][]byte{"motd.txt": bytes.Repeat([]byte("a"), 1300)}) // fake server: serves RRQ over UDP with 512-byte blocks, requires ACKs
	spec := Spec{ID: "tftp", Type: TFTP, Host: srv.IP, Port: srv.Port, Items: []Item{{File: "motd.txt", SHA256: sha256Hex(bytes.Repeat([]byte("a"), 1300))}}}
	res := Faithful(ctx, spec, Options{Timeout: 2 * time.Second})
	if !res.ScorerOK || res.Mode != "faithful" { t.Fatalf("%+v", res) }
	if srv.Acks() != 3 { t.Fatalf("acks %d", srv.Acks()) }
}
func TestTFTPContentFailures(t *testing.T) {
	// missing file -> ScorerOK false, Class content; wrong hash -> content; server silent -> timeout within the Timeout;
	// ERROR 2 (access violation) -> Class auth; DATA with a wrong block number is ignored then times out (no panic)
}
func TestTFTPBoundedAndStrict(t *testing.T) {
	// a server that streams blocks forever stops at 8 MiB with class protocol; an empty file passes ScorerOK, StrictOK false with an issue "empty file"
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/probe/ -run TFTP -v`. Expected: FAIL (class `config`, type unsupported).
- [ ] **Step 3: Implement** `probeTFTP` and register it in the dispatcher.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/probe/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "probe: tftp check type"`

---

### Task 9: probe: NTP check type

**Files:**
- Create: `internal/checks/probe/ntp.go`, `internal/checks/probe/ntp_test.go`
- Modify: `internal/checks/probe/checks.go`

**Interfaces:**
- Consumes: probe helpers; `Item.Skew`.
- Produces: `func probeNTP(ctx context.Context, p *probe) error`; `NTP` default port 123. A 48-byte mode-3 (client) packet, version 4; pass when a 48-byte mode-4 (server) reply arrives, stratum 1 to 15, leap indicator not 3, and `|server transmit time - local time| <= Item.Skew` (default 2 s). Stratum 0 (kiss-of-death) is class `content`; no reply `timeout`; a reply that is not mode 4 `protocol`. Passwords n/a.

- [ ] **Step 1: Write the failing tests**

```go
func TestNTPPassesSaneReply(t *testing.T) {
	srv := newFakeNTP(t, ntpReply{mode: 4, stratum: 2, offset: 500 * time.Millisecond}) // answers one UDP datagram
	res := Faithful(ctx, Spec{ID: "ntp", Type: NTP, Host: srv.IP, Port: srv.Port, Items: []Item{{Skew: 2 * time.Second}}}, Options{Timeout: time.Second})
	if !res.ScorerOK { t.Fatalf("%+v", res) }
	if srv.LastRequestMode() != 3 || srv.LastRequestVersion() != 4 { t.Fatal("not a v4 client request") }
}
func TestNTPFailures(t *testing.T) {
	for name, c := range map[string]struct{ reply ntpReply; class Class }{
		"skew too large": {ntpReply{mode: 4, stratum: 2, offset: time.Hour}, ClassContent},
		"stratum 0":      {ntpReply{mode: 4, stratum: 0}, ClassContent},
		"stratum 16":     {ntpReply{mode: 4, stratum: 16}, ClassContent},
		"alarm leap":     {ntpReply{mode: 4, stratum: 2, leap: 3}, ClassContent},
		"wrong mode":     {ntpReply{mode: 5, stratum: 2}, ClassProtocol},
	} { /* ScorerOK false and res.Class == c.class */ }
	// a silent server -> ClassTimeout; a 10-byte reply -> ClassProtocol (no panic)
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/probe/ -run NTP -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `probeNTP` and register it.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/probe/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "probe: ntp check type"`

---

### Task 10: probe: RDP authentication hook

**Files:**
- Modify: `internal/checks/probe/simple.go` (the `rdp` probe), `internal/checks/probe/checks.go` (`AuthOnly` for `RDP`)
- Create: `internal/checks/probe/rdp_auth_test.go`

**Interfaces:**
- Consumes: `Options.RDPAuth` (Task 1).
- Produces: `AuthOnly` on an `RDP` spec calls `Options.RDPAuth(ctx, host, port, user, pass)`; nil hook gives class `config` ("rdp authentication probe unavailable"); a hook error gives class `auth` with the error text passed through `vault.RedactString`; the faithful `rdp` probe is unchanged (TCP hold, no RDP bytes, as upstream). The wrapper that runs `xfreerdp` is Task 38.

- [ ] **Step 1: Write the failing tests**

```go
func TestRDPAuthOnlyUsesHook(t *testing.T) {
	var got struct{ host, user, pass string; port int }
	opts := Options{Timeout: time.Second, RDPAuth: func(_ context.Context, h string, p int, u, pw string) error { got.host, got.port, got.user, got.pass = h, p, u, pw; return nil }}
	res := AuthOnly(ctx, Spec{ID: "rdp", Type: RDP, Host: "172.25.21.5"}, Cred{User: "alice", Pass: vault.NewSecretString("pw")}, opts)
	if !res.ScorerOK || got.user != "alice" || got.pass != "pw" || got.port != 3389 { t.Fatalf("%+v %+v", res, got) }
}
func TestRDPAuthFailureRedacted(t *testing.T) {
	opts := Options{RDPAuth: func(context.Context, string, int, string, string) error { return errors.New("login failed for pw-secret-1") }}
	res := AuthOnly(ctx, Spec{ID: "rdp", Type: RDP, Host: "172.25.21.5"}, Cred{User: "alice", Pass: vault.NewSecretString("pw-secret-1")}, opts)
	if res.ScorerOK || res.Class != ClassAuth || strings.Contains(res.Err, "pw-secret-1") { t.Fatalf("%+v", res) }
	if r := AuthOnly(ctx, Spec{ID: "rdp", Type: RDP, Host: "172.25.21.5"}, Cred{User: "a"}, Options{}); r.Class != ClassConfig { t.Fatalf("%+v", r) }
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/probe/ -run RDPAuth -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/probe/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "probe: rdp authentication through an injected hook"`

---

### Task 11: `checks`: templates and check records from the manifest

**Files:**
- Create: `internal/checks/templates.go`, `internal/checks/records.go`, `checks/checks/{http,https,dns,ping,tcp,rdp,ssh,ftp,smb,smtp,imap,pop3,winrm,ldap,mssql,splunk,tftp,ntp}.yml`
- Modify: `internal/manifest/types.go` (`validKinds` gains `tftp`, `ntp`)
- Test: `internal/checks/records_test.go`

**Interfaces:**
- Consumes: `probe.Types()`, `manifest.Manifest` services and hosts.
- Produces:

```go
type Template struct { // checks/checks/<kind>.yml, unknown fields are errors
	Kind string; Type probe.Type; Port int; Encrypted bool
	Items []map[string]any; Expect map[string]any; Interval string; Vantages []string
}
func LoadTemplates(fsys fs.FS) (map[string]Template, error)          // reads "checks/*.yml"; one per probe type
type Record struct {
	ID, Service, Host string; Type probe.Type; Params map[string]any
	Origin string // manifest | discovered | manual
	State  string // active | paused | retired | proposed
	Interval time.Duration; Vantages []string
}
func RenderRecords(m *manifest.Manifest, t map[string]Template) (recs []Record, gaps []string)
```

`RenderRecords` makes one record per scored service listener (mail services give smtp, imap, pop3 by their ports; `health:` blocks give records with origin `manifest`), probing the host's address, never its name (a host with no address is a gap string). **TFTP and NTP records exist only when the manifest has a scored service of kind `tftp` or `ntp`** (review N7.1).

- [ ] **Step 1: Write the failing tests**

```go
func TestTemplatesCoverEveryProbeType(t *testing.T) {
	ts, err := LoadTemplates(os.DirFS("../.."))
	if err != nil || len(ts) != len(probe.Types()) { t.Fatalf("%d %v", len(ts), err) }
	if _, err := LoadTemplates(fstest.MapFS{"checks/x.yml": {Data: []byte("kind: x\nbogus: 1\n")}}); err == nil { t.Fatal("unknown field accepted") }
}
func TestRenderReferenceManifest(t *testing.T) {
	recs, gaps := RenderRecords(loadReferenceManifest(t), loadTemplates(t))
	// a record for ecom-http (http, host rocky-ecom's address, port 80) and ecom-ssh; ids unique and stable across two renders; no gaps
	for _, r := range recs { if net.ParseIP(r.Host) == nil { t.Errorf("%s probes a name: %s", r.ID, r.Host) } }
}
func TestTFTPAndNTPOnlyWhenScored(t *testing.T) {
	m := manifestWithService(t, "tftp-svc", "tftp", true, 69, "udp")
	if n := countType(RenderRecordsOf(m), probe.TFTP); n != 1 { t.Fatalf("scored tftp: %d", n) }
	if n := countType(RenderRecordsOf(manifestWithService(t, "tftp-svc", "tftp", false, 69, "udp")), probe.TFTP); n != 0 { t.Fatal("unscored tftp rendered") }
	if n := countType(RenderRecordsOf(loadReferenceManifest(t)), probe.NTP); n != 0 { t.Fatal("ntp rendered with no scored ntp service") }
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/ -run 'Templates|Render|TFTPAndNTP' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the loader, the renderer and the 18 templates (default items and expectations per the design's check-type table).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/ ./internal/manifest/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "checks: templates and records rendered from the manifest"`

---

### Task 12: `checks` agent: the runner on the contract, allowlist in the library

**Files:**
- Modify: `internal/checks/runner.go` (moved in Task 1), `internal/checks/probe/allowlist.go` (new: `Allowlist`, `NewAllowlist`, `ParseAllowlist`, `Allows` moved from `internal/vantage/vantage.go`), `internal/agent/mods/checks.go`, `internal/vantage/vantage.go` (use `probe.Allowlist`)
- Test: `internal/checks/probe/allowlist_test.go`, `internal/checks/runner_test.go`, `internal/agent/mods/checks_test.go`

**Interfaces:**
- Consumes: `plan.ChecksSettings` and `CheckSpec` (Task 1), `event.New`, `agent.Factory`, `agent.Env.Subscribe`.
- Produces:

```go
func (a Allowlist) Allows(host string) bool                          // package probe; IP literals only
func ResultEventOf(res probe.Result, vantage string, now time.Time) event.Event  // package checks; checks.result, High when !OK, credential-free
type RunnerConfig struct {
	Vantage string; Allow probe.Allowlist; Source CheckSource
	Interval, MinGap, MaxDefer time.Duration; SweepEvery, MaxConcurrent int
	Probe probe.Options; Gate Gate; Rand *rand.Rand; Now func() time.Time
}
func NewRunner(cfg RunnerConfig) (*Runner, error)                    // agent.Module named "checks"; implements agent.HealthReporter
```

The runner emits `checks.result`, `checks.deferred`, `checks.refused` (renamed from `vantage.check`, `vantage.check_deferred`, the runner's `vantage.refused`) through `event.New`; the factory builds it from `Modules.Checks`, `Section` is enabled when the block is non-nil. The allowlist is a settings field, not Kali-specific.

- [ ] **Step 1: Write the failing tests**

```go
func TestAllowlistBypassForms(t *testing.T) {
	a, _ := probe.ParseAllowlist("172.25.21.0/24")
	for _, h := range []string{"172.25.21.5", "::ffff:172.25.21.5"} { if !a.Allows(h) { t.Errorf("%s refused", h) } }
	for _, h := range []string{"", "scoring.example.com", "172.25.21.5.", " 172.25.21.5", "2886865157", "0xac191505", "0.0.0.0", "172.25.22.1", "::ffff:8.8.8.8", "172.25.21.5%eth0", "172.25.21.5:22"} {
		if a.Allows(h) { t.Errorf("%q allowed", h) }
	}
}
func TestRunnerRefusesOutsideAllowlist(t *testing.T) {
	// runner with allowlist 127.0.0.0/8 and a spec for 203.0.113.9; Dial counter in probe.Options.Dial
	// RunOnce twice: dial count 0; exactly one checks.refused event (dedup per id+host), High priority, Validate ok
}
func TestRunnerEmitsDeclaredResultKinds(t *testing.T) {
	// fake http server on 127.0.0.1; one http spec; RunOnce; events: checks.result with Vantage "lan", ScorerOK true, no credential text;
	// every emitted event passes event.Validate and its kind is in Module.Manifest().Emits
}
func TestFactoryBuildsRunnerFromSettings(t *testing.T) {
	// harness (agent.NewHarness) with Modules.Checks{Common enabled, IntervalSec 1, Allowlist 127.0.0.0/8, Checks [http spec]}; within 10 s Health("checks").State == ok or unavailable
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/... ./internal/agent/mods/ -run 'Allowlist|Runner|Factory' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Delete `CheckEvent` and the vantage kind constants it used; `Gate` is the Task 13 interface (a `nil` gate means no alignment, as built).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/... ./internal/vantage/ ./internal/agent/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "checks: runner is the checks agent module; allowlist moves into probe"`

---

### Task 13: `checks` agent: round-clock gate, transaction pause, deferral health

**Files:**
- Create: `internal/checks/gate.go`
- Modify: `internal/checks/runner.go`, `internal/plan/fact.go` (`CredsTxnFactID`)
- Test: `internal/checks/gate_test.go`

**Interfaces:**
- Consumes: `agent.Env.Fact`, `plan.RoundClock.Window`, `plan.CredsTxnFact`, `agent.Harness.Fact`.
- Produces:

```go
type Window struct{ Safe bool; Until time.Time; Reason string }
type Gate interface{ SafeFor(now time.Time, need time.Duration) Window }
func NewFactGate(env agent.Env) Gate                                  // fact id "round_clock"; absent or expired: Safe false, Reason "no round clock"
func CredsTxnFactID(account string) string                            // package plan: "creds_txn:" + account
```

The runner asks for a window as long as the probe timeout and waits up to `MaxDefer`; if none opens it skips that pass and emits `checks.deferred` (reason `no quiet window in <max_defer>`). With no gate feed at all it follows the jittered interval and health is `unavailable` with the gap `{"no round clock", "probes are not aligned to the scorer's bursts"}`. Health is `degraded` when more than half of a runner's passes were deferred. A credential whose `creds_txn:<account>` fact is open (`Open: true`, not expired) is skipped; closing the fact or its TTL resumes it.

- [ ] **Step 1: Write the failing tests**

```go
func TestFactGateUsesRoundClock(t *testing.T) {
	h := newHarness(t, checksCase()) // helper from Task 1: harness with the checks factory and a settable agent clock
	h.Fact(roundClockFact(open, ttl: 30*time.Second))
	if w := NewFactGate(h.Env()).SafeFor(h.Now(), 5*time.Second); !w.Safe { t.Fatalf("%+v", w) }
	h.Advance(31 * time.Second) // beyond the fact TTL
	if w := NewFactGate(h.Env()).SafeFor(h.Now(), 5*time.Second); w.Safe || w.Reason != "no round clock" { t.Fatalf("%+v", w) }
}
func TestStaleFactFallsBack(t *testing.T) { /* no fact ever: passes run on the jittered interval, no checks.deferred, health unavailable with the gap above */ }
func TestRunnerDefersWithoutQuietWindow(t *testing.T) {
	// gate always closed, MaxDefer 50 ms: RunOnce skips the check, one checks.deferred (Bulk), dial count 0;
	// after 3 deferred passes of 4 health.State == degraded
}
func TestCredsTxnFactPausesAccount(t *testing.T) {
	// two creds alice and bob on an ssh spec; fact creds_txn:alice open -> 20 faithful passes never use alice (recorded by the fake ssh server)
	// close fact (Open false) -> alice used again; open with ttl 1 s then Advance(2 s) -> alice used again
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/ -run 'FactGate|StaleFact|Defers|CredsTxn' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `NewFactGate`, the pause filter in the credential selection, the deferral counters and health.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "checks: round-clock gate from facts, transaction pause, deferral health"`

---

### Task 14: `checks` agent: sealed credentials held in memory

**Files:**
- Create: `internal/checks/creds.go`
- Modify: `internal/checks/runner.go`, `internal/agent/mods/checks.go`
- Test: `internal/checks/creds_test.go`

**Interfaces:**
- Consumes: `plan.CheckCred`, `agent.Env.OpenSealed` (Task 7), `probe.Cred`, `vault.NewSecretString`.
- Produces: `func openCreds(env agent.Env, cs []plan.CheckCred) (map[string]probe.Cred, error)` keyed `"<account>@<credlist>"`; for the same key the highest `Version` wins. The runner builds each `probe.Spec.Creds` from `CheckSpec.CredRefs`. A spec that needs a credential and has none runs no probe and yields `checks.result` with class `config`, `err: "no credential"` (never a guess). Passwords exist only in memory; the module writes nothing credential-derived into `StateDir`, events or `Health.Info`.

- [ ] **Step 1: Write the failing tests**

```go
func TestOpensSealedCredsAndProbes(t *testing.T) {
	id := identityOf(h)                                           // the harness agent's link.Identity
	sealed, _ := link.SealSecret(id.PublicKey(), "h1", []byte("Plum-river-tent-82"))
	// settings: ssh spec with CredRefs ["alice@linux"], Creds [{Account alice, Credlist linux, Version 1, Sealed}]
	// fake ssh server records the password it was given: "Plum-river-tent-82"
}
func TestNoSecretInEventsOrConfigOnDisk(t *testing.T) {
	// after several passes: no emitted event JSON, no file under StateDir, no Health().Info value contains "Plum-river-tent-82"
}
func TestMissingCredIsConfigNotGuess(t *testing.T) {
	// ssh spec with CredRefs ["bob@linux"] but no CheckCred: res.Class == "config", Err "no credential", fake server saw 0 connections
}
func TestNewerVersionReplaces(t *testing.T) {
	// Apply config with Version 1 (old password) then Apply with Version 2 (new): the next probe sends the new password; an older Version in a later config is ignored
}
func TestUnopenableSealedValueDegrades(t *testing.T) { /* a value sealed for another host: health degraded, gap names the account, no panic */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/ -run 'Sealed|NoSecret|MissingCred|NewerVersion|Unopenable' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** AAD is the agent's own host name.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "checks: sealed credentials opened in memory"`

---

### Task 15: `checks` controller module: config, tables, one writer

**Files:**
- Modify: `internal/checks/module.go`, `internal/checks/config.go`, `internal/checks/tables.go`
- Create: `manifest/2027/modules/checks.yml`
- Test: `internal/checks/module_test.go`

**Interfaces:**
- Consumes: `module.Host` (`Config`, `Tables`, `Subscribe`, `Emit`, `Query`), `RenderRecords`.
- Produces: `(*Module).Start` decodes `Config` strictly, migrates `checks_check` and `checks_result` (the migrations below), seeds `checks_check` from `RenderRecords` (origin `manifest`; an existing row keeps its state), and runs one writer goroutine subscribed to `checks.result` that inserts into `checks_result` (`INSERT OR IGNORE`) and trims each check to 200 rows; if `checks_result` is empty at start it backfills from `Query().Events`.

```sql
CREATE TABLE checks_check(id TEXT PRIMARY KEY, service TEXT NOT NULL, kind TEXT NOT NULL, spec TEXT NOT NULL, origin TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'active', updated_ns INTEGER NOT NULL);
CREATE TABLE checks_result(check_id TEXT NOT NULL, time_ns INTEGER NOT NULL, vantage TEXT NOT NULL, mode TEXT NOT NULL, ok INTEGER NOT NULL, scorer_ok INTEGER NOT NULL, class TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', agent TEXT NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY(check_id, time_ns, vantage)) WITHOUT ROWID;
```

- [ ] **Step 1: Write the failing tests**

```go
func TestResultsProjected(t *testing.T) { /* module on the W1 controller test host; emit three checks.result events (two vantages) through EmitController; rows appear in checks_result with agent and seq of the event; a duplicate delivery adds no row */ }
func TestBackfillOnEmptyTable(t *testing.T) { /* events stored before the module starts; empty table; Start backfills 3 rows */ }
func TestHistoryTrimmedTo200(t *testing.T) { /* 250 results for one check: 200 rows remain, the newest */ }
func TestSeedKeepsOperatorState(t *testing.T) { /* a checks_check row set to 'paused' survives a restart seed; a new manifest service adds a row */ }
func TestConfigUnknownFieldFailsClosed(t *testing.T) { /* "x_unknown: 1" -> health unavailable or error, never ok */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/ -run 'Projected|Backfill|Trimmed|SeedKeeps|ConfigUnknown' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The reference block `manifest/2027/modules/checks.yml` is the design's, with `enabled: true`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "checks: controller module with tables and one writer"`

---

### Task 16: `checks` controller: red, latency and comparison

**Files:**
- Create: `internal/checks/derive.go`, `internal/checks/compare.go` (moved `Compare` renamed), `internal/checks/derive_test.go`
- Modify: `internal/checks/module.go`

**Interfaces:**
- Consumes: `ResultEvent`, `scorer.clock` (latest, for Delay) read through `Host.Query().Latest`.
- Produces:

```go
type Deriver struct{ /* per (check, vantage) streaks; bounded map of 4096 */ }
func NewDeriver(redAfter int, latencyWarn float64) *Deriver
func (d *Deriver) Observe(r ResultEvent, ref EventRefPair, delay time.Duration) []event.Event // checks.red and checks.latency
func ClassifyCompare(external, lan ResultEvent) string                                         // both_ok | service_down | path_broken | scorer_content | internal_only
type Pairer struct{ /* last lan and kali result per check with times */ }
func NewPairer() *Pairer
func (p *Pairer) Add(r ResultEvent, ref EventRefPair, at time.Time, delay time.Duration) *CompareEvent
```

Rules: only `mode == "faithful"` results count; a streak counts `scorer_ok == false` and ignores class `config` and `scorer_limit`; red fires once at `RedAfter` (2) and again only after a pass resets the streak; `strict_ok` never counts. Latency fires when `elapsed_ms` exceeds `LatencyWarn * Delay/2` (Delay 60 s until measured). A pair is one `lan` and one `kali` result of the same check produced within one delay of each other; `Add` returns a `CompareEvent` only after 3 pairs; classes follow the built `Compare` (renamed) with `scorer_ok` as the verdict.

- [ ] **Step 1: Write the failing tests**

```go
func TestRedAfterTwoFaithfulFailures(t *testing.T) {
	d := NewDeriver(2, 0.7)
	// fail, fail -> one checks.red with Streak 2; third fail -> none; pass then fail,fail -> a second red
	// a sweep-mode failure, a strict-only failure (ScorerOK true, StrictOK false) and a Class "config" failure never count
	// red at vantage kali does not combine with a failure at lan
}
func TestLatencyAgainstHalfDelay(t *testing.T) { /* delay 60 s, warn 0.7: 21 s -> no event; 22 s -> checks.latency with LimitMS 21000 */ }
func TestComparePairsNeedThreeSamples(t *testing.T) {
	// two (lan, kali) pairs with kali red: nil; third pair: CompareEvent Class path_broken, Samples 3, refs set
	// lan result 3 delays older than kali: not a pair
}
func TestClassifyCompare(t *testing.T) { /* table: ok/ok both_ok; red/red service_down; kali red lan ok path_broken; kali red with class content, lan ok scorer_content; kali ok lan red internal_only */ }
func TestDeriverBounded(t *testing.T) { /* 10000 distinct check ids: map length <= 4096 */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/ -run 'Red|Latency|Compare|Deriver' -v`. Expected: FAIL.
- [ ] **Step 3: Implement**, and wire `Observe`/`Add` into the writer goroutine's loop; emitted events go through `Host.Emit`. `checks.red` carries `diff` (the previous passing `err` vs the current one) and `trace` (empty until `traceback.change` exists; `shortcut: trace reference left empty until the traceback module exposes it, W8`).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "checks: red, latency and comparison events"`

---

### Task 17: `checks` controller: probe-result facts, proposals, lifecycle

**Files:**
- Create: `internal/checks/proposals.go`, `internal/checks/facts.go`
- Modify: `internal/checks/module.go`, `internal/checks/ui.go` (actions only)
- Test: `internal/checks/proposals_test.go`

**Interfaces:**
- Consumes: `Host.Control`, `plan.ProbeResultFact`, `scorer.proposal` (own-prefix neighbour kind, consumed by name), `scorer.item_set`, `Registrar.Action`.
- Produces:

```go
func (m *Module) sendProbeFact(h module.Host, r ResultEvent, round int) error  // after a lan faithful pass; also kali results with Source "external"; TTL 3*Delay (min 90s)
func (m *Module) applyProposal(ctx context.Context, p ProposalEvent) error     // stores a checks_check row in state proposed
func (m *Module) Accept(ctx context.Context, id, by string) error              // proposed -> active; manifest override written
func (m *Module) Pause(ctx context.Context, id, by string) error
func (m *Module) Retire(ctx context.Context, id, by string) error
func (m *Module) AcceptCurrent(ctx context.Context, id, by string) error       // rewrites the expected response from the latest passing result
```

Facts go to the service's host (`ControlMsg{Hosts: [host], Fact: "scorer_probe_result", ID: "probe:"+service, TTL}`); a failed `Control` is logged and skipped. Nothing is ever removed automatically: a `stale` proposal marks the row `stale: true` only. Every lifecycle change is written to the manifest overrides (`overrides.yml` through `atomicfile`), is emitted as one core `operator.edit` (`module: checks`; `op` `add`, `edit`, `pause`, `resume`, `accept_proposal`, `make_check`, `accept_current` or `retire`; `record` the whole check record; S4: no per-module edit kinds) through `Host.Emit`, and takes effect at once; `checks_check` is a replay of those events and the `health:` records.

- [ ] **Step 1: Write the failing tests**

```go
func TestProbeFactSentAfterLANFaithful(t *testing.T) { /* fake Host recording ControlMsg: lan faithful result -> one fact, Data decodes to ProbeResultFact{OK: scorer_ok, Source "lan"}, TTL >= 90 s; kali result -> Source "external"; sweep result -> none */ }
func TestProposalLifecycle(t *testing.T) {
	// scorer.proposal kind new -> row state proposed, origin discovered; Accept -> active and the override file has the check;
	// a stale proposal never deletes an active row; Retire -> retired; AcceptCurrent rewrites Items from the latest passing result;
	// every call emits one operator.edit{module: checks, op, subject: id, record: the whole check record, by, at} and rebuilding checks_check from those events plus the services.yml health: records gives the same rows
}
func TestOverridesWrittenAtomically(t *testing.T) { /* crash-injection: temp file left behind never corrupts overrides.yml (atomicfile) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/ -run 'ProbeFact|ProposalLifecycle|OverridesWritten' -v`. Expected: FAIL.
- [ ] **Step 3: Implement**; the UI actions (`accept`, `pause`, `retire`, `accept_current`, `make_check`) call these methods (Task 22 renders the buttons).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "checks: scorer_probe_result facts, proposals, lifecycle"`

---

### Task 18: `checks`: agent settings rendered per runner, credentials re-sent on rotation

**Files:**
- Create: `internal/controller/genconfig_checks.go`
- Modify: `internal/controller/genconfig.go`, `internal/controller/agentconfig.go` (`inputsFingerprint`)
- Test: `internal/controller/genconfig_checks_test.go`

**Interfaces:**
- Consumes: `RenderRecords` output through an exported `checks.RecordsFor(m *manifest.Manifest, contentDir string) ([]checks.Record, error)`; `link.SealSecret`; `agents.pubkey`; vault names `cred/<host>/<account>` and their version ids (`Vault.Names`, `Vault.Get`).
- Produces: for a host with the role `check_runner`, `AgentConfig.Modules.Checks` filled from `modules/checks.yml` (`Vantage: "lan"`, or `"kali"` when the host also has role `scanner`; `Allowlist` = the LAN addresses of the manifest for `lan`, the block's public allowlist for `kali`), `Checks` from the records assigned to the vantage, and `Creds` with one sealed `CheckCred` per scored account in the credlist the host probes, `Version` = a counter derived from the vault version id. `inputsFingerprint` includes the vault version ids of `cred/*` entries, so a rotation signs a new `(epoch, version)` config to the runners.

- [ ] **Step 1: Write the failing tests**

```go
func TestRunnerHostGetsChecksSettings(t *testing.T) { /* reference manifest, host ubuntu-wkst (check_runner): Modules.Checks non-nil, Vantage lan, Allowlist all inside the LAN prefixes, >= 1 CheckSpec per scored service; a host without the role: Modules.Checks nil */ }
func TestKaliGetsPublicAllowlistAndExternalVantage(t *testing.T) { /* host with roles check_runner+scanner: Vantage kali, Allowlist == block allowlist */ }
func TestCredsSealedToTheHostsKey(t *testing.T) {
	// vault cred/rocky-ecom/alice = "pw1"; runner config Creds[0].Sealed opens only with that runner's identity (link Identity.OpenSecret(host)); no plaintext "pw1" anywhere in the marshalled config
}
func TestRotationBumpsConfigVersion(t *testing.T) {
	// v1 := AgentConfigFor(host).Version; vault.Put(cred/..., "pw2"); v2 := AgentConfigFor(host).Version; v2 > v1 and Creds[0].Version increased
}
func TestNoCredentialInVaultMeansNoCheckCred(t *testing.T) { /* scored account with no vault entry: no CheckCred (runner reports config: no credential) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run 'RunnerHostGets|KaliGets|CredsSealed|RotationBumps|NoCredentialInVault' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** `shortcut: Version is a per-name counter held in the controller KV (store/kv.go); upgrade to the vault's own version number if the vault exposes one.`
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "checks: runner settings and sealed credentials in the signed agent config"`

---

### Task 19: `Env.Probe` supplier and the `health.check` action

**Files:**
- Create: `internal/checks/mimic.go`, `internal/actions/health_check.go`
- Modify: `cmd/phylax/controller.go` (set `controller.Options.Probe` from `checks.NewProbe`)
- Test: `internal/checks/mimic_test.go`, `internal/actions/health_check_test.go`

**Interfaces:**
- Consumes: `controller.Options.Probe` and `actions.Env.Probe` (W1), `probe.Faithful`, `RecordsFor`, `vault.Reader`, `Controller.quietWindow` is not used here (probes run immediately; they sit inside a node's own window).
- Produces:

```go
type ProbeDeps struct {
	Records func(service string) []Record   // active records of one service
	Creds   func(service string) []CredRef   // {Account, Credlist, Pass vault.Secret} from the vault
	Options probe.Options
}
type CredRef struct{ Account, Credlist string; Pass vault.Secret }
func PickUsers(refs []CredRef) []CredRef                        // up to two distinct accounts per credlist, stable order
func NewProbe(d ProbeDeps) func(ctx context.Context, service string) error // nil only if every probe's ScorerOK; error lists failing checks without credentials
// actions: health.check{service string, probe string = "scorer_mimic"} Runs: RunsController, Risk none, ReadOnly true, Touches none
```

The probe runs the library from the controller host (the in-LAN reference vantage), one faithful probe per record and picked user; the service with no scored credential runs itemless. Probes are bounded: the executor adds the retry (W1 Task 27); this function is a single pass with the library's timeout. `health.check` calls `env.Probe(ctx, service)`; with `env.Probe == nil` it fails the node with `probe cannot run`.

- [ ] **Step 1: Write the failing tests**

```go
func TestPickUsersTwoPerCredlist(t *testing.T) {
	refs := []CredRef{{"a", "linux", s}, {"b", "linux", s}, {"c", "linux", s}, {"d", "mail", s}}
	got := PickUsers(refs)
	// 3 entries: two from linux (a, b), d from mail; deterministic
}
func TestNewProbeGreenAndRed(t *testing.T) {
	// fake http server ok -> nil; server returns 500 with a spec that sets Status 200 -> error mentioning the check id and class, not any password
	// service with an ssh record and two users where the second password is wrong (fake ssh) -> error naming user b only
}
func TestHealthCheckAction(t *testing.T) {
	// env.Probe returns an error -> Apply error "health.check: web: ..."; env.Probe nil -> error "probe cannot run"; nil result -> ok; Spec().Runs == RunsController && ReadOnly
}
func TestControllerWiresProbe(t *testing.T) { /* cmd wiring: controller built by the command has Options.Probe != nil when the checks module is enabled */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/ ./internal/actions/ ./cmd/phylax/ -run 'PickUsers|NewProbe|HealthCheck|WiresProbe' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** This closes Known bug 20's probe half (W6 swaps the device hook to call it).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/ ./internal/actions/ ./cmd/phylax/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "checks: Env.Probe supplier and the health.check action"`

---

### Task 20: `checks`: the service doctor

**Files:**
- Create: `internal/checks/doctor.go`, `checks/doctor/{ssh,http,https,dns,smtp,imap,pop3,ftp,smb,winrm,mssql,splunk,ldap,rdp,tcp,ping,tftp,ntp}.yml`, `plans/checks/doctor.yml`
- Modify: `internal/checks/module.go`
- Test: `internal/checks/doctor_test.go`

**Interfaces:**
- Consumes: `Host.RunReadOnly`, `agent.step_result` (Task 5, `Output`), `Deriver` first-failure signal, `deps.graph` is not consumed yet (Task 47).
- Produces:

```go
type Rule struct{ When string; Cause string; Weight int } // checks/doctor/<kind>.yml `rules:`; When is a small expression over collected keys (equality, contains, <, >, and/or)
type Doctor struct{ /* content, runner */ }
func LoadDoctor(fsys fs.FS) (*Doctor, error)
func (d *Doctor) Rank(kind string, collected map[string]any) []Cause   // matched rules ordered by weight desc then cause; Rank/Evidence/Step set
func (m *Module) runDoctor(ctx context.Context, svc string, host string, streak string) error // RunReadOnly("doctor", params) then waits for step results (Doctor.Timeout), emits checks.diagnosis
```

Triggers: the first failed faithful probe of a failure streak at any vantage, class not `scorer_limit`, not `config`; once per streak id; "Run again" calls it directly. The read-only plan template `plans/checks/doctor.yml` has nodes `config_test` (the service's own validator in check mode: `sshd -t`, `apachectl -t` or `httpd -t`, `nginx -t`, `named-checkconf`, `postfix check`; pre-approved hash-pinned tools only), `listeners` (`probe.run` listeners table against the manifest), `journal` (`shortcut: reads the journal through host.exec journalctl until a native reader exists, replace when the logs module has one`), `avc` (SELinux denials on Rocky), `space` (statfs and inodes), `unit` (process state) and `deps` (TCP connect to each `depends_on` of the manifest). Each content file ranks causes (`stopped unit`, `config test failed`, `listener missing or wrong bind`, `selinux denial`, `disk full`, `dependency down`).

- [ ] **Step 1: Write the failing tests**

```go
func TestRankOrdersByWeight(t *testing.T) {
	d := loadDoctor(t) // the real checks/doctor content
	got := d.Rank("ssh", map[string]any{"config_test.exit": 1, "unit.active": "inactive", "space.free_pct": 40})
	// causes: ["config test failed" (weight 90), "stopped unit" (80)] in that order; Rank numbers 1..n; no cause for disk
}
func TestEveryKindHasContentAndCauses(t *testing.T) { /* 18 kinds loaded; each has >= 3 rules; a rule with a bad expression fails LoadDoctor */ }
func TestDoctorFixtures(t *testing.T) {
	// table over the five injected failures (stopped unit, broken config, full disk, SELinux denial, dependency down):
	// fixture collected output -> the expected top cause for http and ssh
}
func TestDoctorRunsOncePerStreak(t *testing.T) {
	// Deriver reports a first failure -> RunReadOnly called once with template "doctor" and params host/service; a second failure in the same streak -> not called;
	// pass then fail -> called again; class scorer_limit and config -> never; checks.diagnosis emitted with Causes when the fake step results arrive; timeout -> a diagnosis with one cause "doctor timed out" and no panic
}
func TestDoctorIsReadOnly(t *testing.T) { /* lint.Run with ClassAutoReadOnly over plans/checks/doctor.yml: no findings (SS000) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/ -run 'Rank|EveryKind|DoctorFixtures|DoctorRuns|DoctorIsReadOnly' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the expression evaluator (no `eval`; a tiny parser over `key op value` joined by `and`/`or`), the loader and the runner.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "checks: service doctor with ranked causes per service kind"`

---

### Task 21: `checks`: Orange flows

**Files:**
- Create: `internal/checks/flow.go`, `checks/flows/{ecom-purchase,webmail-roundtrip,ad-rdp-logon}.yml`
- Modify: `internal/manifest/types.go` (`Account.OrangeVisible *bool`), `manifest/2027/accounts.yml` (a `phylax-orange` test customer, `scored: false`, `orange_visible: false`), `internal/checks/module.go`
- Test: `internal/checks/flow_test.go`

**Interfaces:**
- Consumes: `probe.Run` and `probe.AuthOnly` for protocol steps, `net/http` with `cookiejar` and `probe.Options.Dial` for web steps, `FlowsConfig`.
- Produces:

```go
type Flow struct{ Module, ID string; Vantages, Effects []string; Steps []FlowStepDef }
type FlowStepDef struct { Name string; HTTP *HTTPStep; Probe *ProbeStep } // exactly one
type HTTPStep struct{ Get, Post string; Form map[string]string; ExpectStatus int; ExpectRegex string; Capture map[string]string }
type ProbeStep struct{ Type string; Item map[string]any; Auth bool }       // smtp send, imap read, rdp auth-only
func LoadFlows(fsys fs.FS) ([]Flow, error)
func RunFlow(ctx context.Context, f Flow, vars map[string]string, o probe.Options, allow probe.Allowlist) FlowEvent
```

Steps share a cookie jar and the captured variables (`{{ name }}` templating, no code). The first failed step stops the flow and names itself in `FailedStep`. A flow with `effects` is off until an operator enables that flow (`modules/checks.yml` `flows.enabled` plus a per-flow switch in the UI); a flow without effects runs once `flows.enabled`. The test customer is never a scored user (a flow whose account is scored fails to load). Targets pass the allowlist like any probe. The webmail flow sends mail by SMTP as the test user and reads the same 16-hex subject by IMAP; the AD flow is `ProbeStep{Type: rdp, Auth: true}` and needs `Options.RDPAuth`.

- [ ] **Step 1: Write the failing tests**

```go
func TestFlowCookiesCaptureAndForm(t *testing.T) {
	app := newFakeShop(t) // sets a session cookie on /, embeds name="csrf" value="tok123" on the product page, accepts POST cart.add only with the cookie, POST confirm only with csrf=tok123 and answers "order 42"
	ev := RunFlow(ctx, ecomFlow(app.URL), map[string]string{"product_id": "40"}, probe.Options{Timeout: 2 * time.Second}, allowLoopback)
	if !ev.OK || len(ev.Steps) != 4 { t.Fatalf("%+v", ev) }
}
func TestFlowNamesFirstFailedStep(t *testing.T) { /* the cart.add handler returns 500: ev.OK false, FailedStep "add", later steps absent */ }
func TestFlowEffectsGate(t *testing.T) {
	// FlowsConfig{Enabled: true}: webmail (no effects flag? it has effects [sends_mail]) does not run until enabled per flow; a read-only flow runs; disabled config runs none
}
func TestFlowRefusesNonAllowlistedTarget(t *testing.T) { /* http step to 203.0.113.9: step fails class config "target not allowed", nothing dialled */ }
func TestFlowAccountMustNotBeScored(t *testing.T) { /* LoadFlows with a manifest that marks the flow's account scored: error */ }
func TestWebmailRoundTrip(t *testing.T) { /* fake SMTP+IMAP (lineproto fakes) share a mailbox: send step stores subject, read step finds it; ev.OK; the subject is 16 hex characters */ }
func TestFlowEmitsCheckflowKind(t *testing.T) { /* event.New(KindFlow, ev) validates; steps carry elapsed and class */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/ -run 'Flow|Webmail' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The 2027 ecom product is unverified; the shipped URLs are the OpenCart shape and are replaced from the packet (`shortcut: flow URLs are the 2026 OpenCart shape, replace from the 2027 packet`). The lab reuses these files as the Orange traffic generator (D511).
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/ ./internal/manifest/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "checks: Orange flows with cookie jar, capture and effects gate"`

---

### Task 22: `checks`: pages, tile, conformance

**Files:**
- Create: `internal/checks/ui.go`, `internal/checks/ui/{services,checks,check,flows}.html`, `internal/checks/conformance_test.go`, `manifest/schema/modules/checks.schema.json` (via `-update`)
- Modify: `internal/checks/module.go` (`Registrar` pages `/services`, `/checks`, `/checks/{id}`, `/flows`, tile `red checks`), `internal/module/conformance/allowed.go` (remove `checks` from `PreContract`), `internal/module/all/all.go`
- Test: `internal/checks/ui_test.go`, `internal/checks/conformance_test.go`

**Interfaces:**
- Consumes: the tables, `Registrar.Page/Tile/Action`, `conformance.Agent`, `conformance.Controller`.
- Produces: `/services` (per service: our checks at each vantage with latest result, SLA streak from `scorer.sla`, ranked doctor causes, proposals, link to `/changes`), `/checks` and `/checks/{id}` (200-row history; buttons add, edit, pause, retire, Accept current response, Make this a check), `/flows` (steps, effects, enable switch); a tile with red checks, `path_broken` count and services with a diagnosis; no host-grid column. Old `internal/ui` checks page, `ChecksOps`, `ChecksView` and templates `checks.html`, `check.html` are deleted in Task 30.

- [ ] **Step 1: Write the failing tests**

```go
func TestChecksAgentConformance(t *testing.T) {
	conformance.Agent(t, conformance.AgentCase{Factory: factoryNamed(t, "checks"), Default: checksCfg(1), Reconfig: checksCfg(2), KeepKey: "checks.passes", Load: resultLoad(40)})
}
func TestChecksControllerConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Module{}, Config: "enabled: true\ncontent_dir: ../../checks\n", Seed: seedResults(), Now: time.Unix(1e9, 0)})
}
func TestServicesPageRenders(t *testing.T) { /* module on the controller test host with two services, one red with a diagnosis: GET /m/checks/services contains both service names, the cause text, and no password */ }
func TestAcceptCurrentResponseAction(t *testing.T) { /* POST /m/checks/action/accept_current with csrf: the override file changes; GET with no csrf is 403 (UI shell) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/ -run 'Conformance|Services|AcceptCurrent' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the pages (templates embedded), the tile, `KeepKey` state (`Keep("checks.passes", map[string]int)` so reconfiguration keeps pass counters), remove the `PreContract` entry, run `go test ./internal/module/all/ -run Schema -update`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/checks/... ./internal/module/...`. Expected: PASS, including `TestNoSiblingImports`, `TestKindTable` and `TestPreContractShrinks` with `checks` a contract module.
- [ ] **Step 5: Commit.** `git commit -am "checks: pages and conformance; checks leaves PreContract"`

---

### Task 23: `scorer`: module base, tables, overrides, replay, no `sysadmin` special case

**Files:**
- Modify: `internal/scorer/module.go`, `config.go`, `discovery.go` (delete the `sysadmin` branch of `isScoredLocked` and the `/api/credlists` comments), `internal/manifest/labels.go` (`Host.EffectiveLabels`)
- Create: `internal/scorer/tables.go`, `internal/scorer/overrides.go`, `rules/scorer/fingerprints.json`, `manifest/2027/modules/scorer.yml`
- Test: `internal/scorer/module_test.go`, `internal/scorer/overrides_test.go`

**Interfaces:**
- Consumes: `module.Host`, `ClockConfig`, `DiscoveryConfig`, `SLAConfig` (built), `DefaultTable().JSON()`, `atomicfile`.
- Produces:

```go
const migration1 = `CREATE TABLE scorer_round(round INTEGER PRIMARY KEY, start_ns INTEGER NOT NULL, end_ns INTEGER NOT NULL, conns INTEGER NOT NULL, dropped INTEGER NOT NULL DEFAULT 0, provisional INTEGER NOT NULL DEFAULT 0);
CREATE TABLE scorer_service(key TEXT PRIMARY KEY, host TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL, type_guess TEXT NOT NULL DEFAULT '', learned INTEGER NOT NULL DEFAULT 0, custom INTEGER NOT NULL DEFAULT 0, rounds INTEGER NOT NULL DEFAULT 0, last_seen_ns INTEGER NOT NULL DEFAULT 0);
CREATE TABLE scorer_item(service TEXT PRIMARY KEY, items INTEGER NOT NULL, coverage REAL NOT NULL, size_estimate REAL NOT NULL, users TEXT NOT NULL DEFAULT '[]');
CREATE TABLE scorer_account(user TEXT NOT NULL, service TEXT NOT NULL, host TEXT NOT NULL, proto TEXT NOT NULL, how TEXT NOT NULL, ok INTEGER NOT NULL DEFAULT 0, fail INTEGER NOT NULL DEFAULT 0, first_ns INTEGER NOT NULL, last_ns INTEGER NOT NULL, grp TEXT NOT NULL DEFAULT '', PRIMARY KEY(user, service));
CREATE TABLE scorer_note(id INTEGER PRIMARY KEY AUTOINCREMENT, ts_ns INTEGER NOT NULL, service TEXT NOT NULL, verdict TEXT NOT NULL, round INTEGER NOT NULL DEFAULT 0, by TEXT NOT NULL, text TEXT NOT NULL DEFAULT '');`
type Overrides struct{ /* scored map[string]bool, groups map[string][]string (user -> labels), names map[string]string (label -> Quotient name), measured timing */ }
func LoadOverrides(path string) (*Overrides, error)                          // absent file is empty
func (o *Overrides) MarkScored(user string, at time.Time) error              // atomic write
func (o *Overrides) MarkNotScored(user string) error
func (h Host) EffectiveLabels() []string                                     // package manifest: Labels plus "role_<r>" for every role
```

`Start` decodes `Config`, migrates, loads the fingerprint table from `Config.Fingerprints` (parse failure: health `degraded`, gap "no fingerprint table loaded"), and runs one writer goroutine that projects its own kinds and its `operator.edit` events into the tables (`op: note` into `scorer_note`; the group ops `rename_group`, `merge`, `split`, `mark_not_scored` into `scorer_account`). **Replay:** on start the module feeds the last `ReplayWindow` of stored `conn` (`source: capture`), `capture.txn`, `auth_event` and `checks.result` events through the same code the live path uses (Tasks 24 to 27) with emission suppressed, so the estimator, discovery and tracker are rebuilt; the tables hold the rest.

- [ ] **Step 1: Write the failing tests**

```go
func TestSysadminIsNotSpecial(t *testing.T) {
	d := NewDiscovery(DiscoveryConfig{})
	if d.IsScored("sysadmin") { t.Fatal("sysadmin scored by default") }
	d.Observe(Observation{Time: t0, Round: 1, Key: sshKey, User: "sysadmin", Auth: AuthOK})
	d.CloseRound(1)
	if !d.IsScored("sysadmin") { t.Fatal("not learned by observation like any other account") }
}
func TestOverridesRoundTrip(t *testing.T) { /* MarkScored writes overrides.yml atomically (kill between temp and rename leaves the old file); reload sees it; MarkNotScored removes the mark and Discovery.IsScored is false even when observed */ }
func TestFingerprintFileEqualsBuiltTable(t *testing.T) { /* ParseTable(rules/scorer/fingerprints.json) deep-equals DefaultTable(); a corrupt file degrades with the gap */ }
func TestScorerOpensNoConnections(t *testing.T) { /* go/parser over internal/scorer non-test files: no import of net/http, net (net/netip is fine), os/exec, crypto/tls; the module is passive toward the scorer */ }
func TestReplayRebuildEqualsLive(t *testing.T) { /* feed fixture events live into module A; store them; module B starts over the store: the estimate, learned services and accounts are equal (compare Estimate().Delay, Services() keys, ScoredAccounts() users) */ }
func TestEffectiveLabelsImplyRoles(t *testing.T) { /* host with roles [check_runner, scanner] -> labels include role_check_runner, role_scanner */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/scorer/ ./internal/manifest/ -run 'Sysadmin|Overrides|FingerprintFile|OpensNoConnections|Replay|EffectiveLabels' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Generate `fingerprints.json` with `DefaultTable().JSON()`. `MarkScored`/`MarkNotScored` stay operator overrides, written to `overrides.yml`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/scorer/ ./internal/manifest/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "scorer: module base, tables, overrides, replay; sysadmin is not special"`

---

### Task 24: `scorer`: bursts, rounds, the clock and the `round_clock` fact

**Files:**
- Create: `internal/scorer/feed.go`, `internal/scorer/facts.go`
- Modify: `internal/scorer/module.go`
- Test: `internal/scorer/feed_test.go`, `internal/scorer/facts_test.go`

**Interfaces:**
- Consumes: `Estimator.Observe/ObserveBurst/Tick/Estimate/SafeFor`, `Classifier.Classify`, `conn` events with `source: capture` (inbound connection starts; other sources are ignored) decoded into a local permissive struct `CaptureFlow{Time time.Time; Client, Server netip.AddrPort; Proto string; Dir string}` (field names confirmed against W6's `internal/capture/kinds.go` in Step 3; a decode failure drops the event and counts a gap), `plan.RoundClock`, `Host.Control`.
- Produces:

```go
type Feed struct{ /* estimator, classifier, discovery, sla; one goroutine owns it */ }
func NewFeed(cfg Config, table Table) (*Feed, error)
func (f *Feed) OnFlow(fl CaptureFlow) []event.Event                 // may emit scorer.round and scorer.clock
func (f *Feed) Tick(now time.Time) []event.Event                    // closes bursts, emits dropped rounds
func clockFact(e ClockEvent, ttlMin time.Duration) module.ControlMsg // Hosts ["role_check_runner || role_scanner"], Fact "round_clock", ID "round_clock"
```

An inbound new connection to a service of the manifest counts toward a burst unless its source is currently classified `not_scorer` (`shortcut: burst detection counts every non-excluded inbound connection, 15 within 100 ms is the signal; attribution is applied afterwards, upgrade if red scans of 15 connections in 100 ms fool the estimator`). `scorer.clock` is emitted when the estimate changes and at least every 5 s; `eviction_cutoff_ms` is the measured delay once the estimate is not provisional, else 0. The fact is sent when the clock changes and refreshed every `min(Delay/2, 30 s)`; TTL is `max(3*Delay, 60 s)`; a provisional clock is sent with `Provisional: true`.

- [ ] **Step 1: Write the failing tests**

```go
func TestClockFromFixture(t *testing.T) { // T30 CI form
	f := newTestFeed(t)
	// 20 bursts of 20 flows in 40 ms, interval 20 s +- 5 s uniform (fixed seed), burst 11 missing (interval 40 s)
	ev := feedBursts(t, f, fixtureBursts)
	last := lastClock(ev)
	if abs(last.DelayMS-20000) > 1000 || abs(last.JitterMS-5000) > 1000 || last.Provisional { t.Fatalf("%+v", last) }
	if d := droppedRounds(ev); len(d) != 1 { t.Fatalf("dropped %v", d) } // a team-wide missing burst is a round gap, not an outage
}
func TestRedScanIsNotABurst(t *testing.T) { /* 15 flows in 100 ms from a source whose last exchange classified not_scorer: no scorer.round */ }
func TestEvictionCutoffEmptyUntilMeasured(t *testing.T) { /* after 3 bursts: clock.Provisional, EvictionCutoffMS == 0; after 12 bursts: equals DelayMS */ }
func TestRoundClockFactCadence(t *testing.T) {
	// fake Host records ControlMsg: first non-provisional clock -> one fact (Data decodes to plan.RoundClock, TTL >= 60 s, ID "round_clock", Fact "round_clock");
	// unchanged clock inside the refresh interval -> none; after min(Delay/2, 30 s) -> one; provisional clock -> a fact with Provisional true
}
func TestClockRespectsMinConnsAndJoinGap(t *testing.T) { /* 14 flows in 100 ms: no burst; retries 1 s later join the burst */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/scorer/ -run 'ClockFromFixture|RedScan|EvictionCutoff|RoundClockFact|MinConns' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Step 0 of the implementer: open W6's capture kinds file and align `CaptureFlow`'s field tags; do not import `internal/capture`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/scorer/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "scorer: bursts, rounds, scorer.clock and the round_clock fact"`

---

### Task 25: `scorer`: services, item sets, proposals, blocked and silent

**Files:**
- Modify: `internal/scorer/feed.go`, `internal/scorer/discovery.go`
- Create: `internal/scorer/items.go`
- Test: `internal/scorer/items_test.go`, `internal/scorer/discovery_feed_test.go`

**Interfaces:**
- Consumes: `capture.txn` decoded into `CaptureTxn{Time; Client, Server netip.AddrPort; Proto, Type string; OK *bool; Attr map[string]string; List map[string][]string; Cred *struct{User, Domain, Mech string}}`, `FeaturesFromTxn`, `Classifier`, `Discovery.Observe/CloseRound/Compare`, `checks.result` (active-check inference), `devices.deny` and `devices.traffic` references.
- Produces: `func ItemOf(t CaptureTxn) (kind, item string)` (http path, dns `kind name`, smb `share\file`, ftp file, ssh/others none; variable parts such as UUIDs, hex runs of 16 or more and numbers of 10 or more digits replaced by `{x}`); `Feed.OnTxn(t CaptureTxn) []event.Event` emitting `scorer.service` (when learned), `scorer.item_set` (per changed service at round close, with `rounds_expected` = `ExpectedVerifyRounds(k)` one), `scorer.proposal`, `scorer.blocked` (with `DenyRefs` from the denies of the window), `scorer.silent`. Active checks for `Compare` are inferred from `checks.result` events of the last 10 minutes (id, host, port, type, distinct `item` values). Protocols with no native Quotient check (mssql, splunk, rdp-with-auth, tftp, ntp) are capped at 0.7 and `custom: true` with up to `MaxSamples` first-byte samples.

- [ ] **Step 1: Write the failing tests**

```go
func TestItemTemplating(t *testing.T) { /* "/index.php?id=7f3a9c2e41b85d60aa" -> "/index.php?id={x}"; "GET /a/1700000000000" -> "/a/{x}"; dns "A example.com" unchanged */ }
func TestServiceLearnedAfterTwoRounds(t *testing.T) { /* two rounds of http txns on ecom:80 -> one scorer.service learned; one round -> none; the second round more than 3 rounds later -> none */ }
func TestProposalsAgainstActiveChecks(t *testing.T) { // T15 CI form
	// scorer observes 6 services; checks.result covers 4 of them with the same items: proposals new x2, update x1 (an item the check lacks), none for matched;
	// a check with no scorer counterpart for 5 rounds -> stale proposal, never removed
}
func TestBlockedCarriesDenyRefs(t *testing.T) { /* round reaches 3 services, none reaches the 4th for 2 rounds, a devices.deny event in the window -> scorer.blocked with DenyRefs containing its ref */ }
func TestSilentIsNotHealthy(t *testing.T) { /* no scorer traffic for any service for 2 rounds while the clock says one was due -> scorer.silent */ }
func TestCustomServiceCappedAndSampled(t *testing.T) { /* mssql:1433 exchanges: custom true, score <= 0.7, 3 samples kept, the 4th dropped */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/scorer/ -run 'ItemTemplating|LearnedAfter|ProposalsAgainst|BlockedCarries|SilentIs|CustomService' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the pipeline: classify, build `Observation`, `Discovery.Observe`, close rounds at `scorer.round`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/scorer/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "scorer: services, item sets, proposals, blocked and silent from capture"`

---

### Task 26: `scorer`: account and login learning, credlist groups (T50 CI form)

**Files:**
- Create: `internal/scorer/accounts.go`, `internal/scorer/groups.go`
- Modify: `internal/parsers/{smtp,imap,pop3,ftp}/*.go` and `internal/parsers/txn/txn.go` (`AttrPasswordShape`), `internal/scorer/feed.go`
- Test: `internal/scorer/accounts_test.go`, `internal/scorer/groups_test.go`, parser tests

**Interfaces:**
- Consumes: `CaptureTxn.Cred`, `auth_event` (`event.AuthEvent`), `Estimator.InBurst`, the round's sources, `Overrides`.
- Produces:

```go
const AttrPasswordShape = "password_shape" // package txn; "uuid" when the plaintext password matches 8-4-4-4-12 hex, set by the plaintext parsers before the hash
func (f *Feed) OnAuth(a event.AuthEvent, at time.Time, source string) []event.Event // scorer.account, scorer.login
func Groups(accounts []Account) map[string]string                                   // user -> "L1", "L2" by the set of services the account is observed on
func ApplyGroupOverrides(g map[string]string, o *Overrides) map[string][]string     // operator rename/merge/split; a user may sit on two lists
```

Learning rules: a user is learned from an exchange classified `scorer` (SMTP `AUTH PLAIN`, IMAP `LOGIN`, FTP `USER`, SMB NTLM names, WinRM NTLM, TDS login7); a host `auth_event` counts only when `result == success`, its source is in the current round's scorer sources and its time is inside a burst; a failed login whose password shape is `uuid` is never learned from (`BadAttempts`); marking is automatic and writes `overrides.yml`; removing a mark is an operator action. Every observed login emits `scorer.login` (never a password or hash). `shortcut: SSH user names reach discovery only through host auth_event; a host without the logs module cannot contribute SSH accounts.`

- [ ] **Step 1: Write the failing tests**

```go
func TestLearnsOnlyScorerLabelledLogins(t *testing.T) {
	// fixture: scorer-labelled IMAP LOGIN alice, SMTP AUTH bob; a red-team IMAP LOGIN eve classified not_scorer -> accounts exactly {alice, bob}
}
func TestBadAttemptsNotLearned(t *testing.T) { // T37 CI half
	// IMAP LOGIN carol with password_shape uuid, failed: no account, no scorer.login; ssh auth_event fail,fail,success for dave inside a burst: dave learned from the success only, Fail counter 2
}
func TestAuthEventNeedsBurstAndSource(t *testing.T) { /* success from a non-scorer source outside any burst: not learned; same account from a scorer source inside a burst: learned (how "auth_event") */ }
func TestMarkingWritesOverridesAndEmitsOnce(t *testing.T) { /* first sighting: one scorer.account and overrides scored[alice]=true; the 50th sighting: no new scorer.account, counters grow in the table */ }
func TestCredlistGroupsByServiceSet(t *testing.T) { // T50 CI form, two credlists
	// linux users seen on ssh only -> L1; mail users on smtp+imap+pop3 -> L2; "alice" seen on ssh and imap -> her own set {ssh, imap} -> L3
	// ApplyGroupOverrides: merge L3 into L2 and put alice on both L1 and L2 -> Groups reports both for alice; the rename L1 -> "linux.credlist" is kept
}
func TestPlaintextParsersFlagUUIDPasswords(t *testing.T) { /* smtp, imap, pop3, ftp parsers: a UUID password sets Attr["password_shape"]="uuid"; a normal one does not; PassHash unchanged */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/scorer/ ./internal/parsers/... -run 'LearnsOnly|BadAttempts|AuthEventNeeds|MarkingWrites|CredlistGroups|UUIDPasswords' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/scorer/ ./internal/parsers/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "scorer: learn accounts and logins from scorer-labelled exchanges; credlist groups"`

---

### Task 27: `scorer`: SLA with source precedence, notes and per-round accrual

**Files:**
- Create: `internal/scorer/sla_feed.go`
- Modify: `internal/scorer/sla.go` (`SLAConfig.Accrual`, `Phases`, `Penalty`; `Points(svc)`), `internal/scorer/module.go`
- Test: `internal/scorer/sla_feed_test.go`, `internal/scorer/sla_test.go`

**Interfaces:**
- Consumes: `SLATracker.ObserveRound/Discard/Verdict/Calibration`, `checks.result` (faithful, `scorer_ok`, `vantage`), capture-inferred outcomes (a refused or reset connection, a failed login, a wrong content reply from the service in `CaptureTxn.OK`), `operator.edit` (`module: scorer`, `op: note`), `scorer.round.dropped`.
- Produces:

```go
type Phase struct{ Until time.Time; PerRound int }
// SLAConfig gains: Accrual string ("reset" default | "per_round"); Penalty int (5); Phases []Phase
func (t *SLATracker) Points(svc string) int                                  // sum of costs so far under the configured accrual
type SLAFeed struct{ /* pending[round][service] candidates with a source rank */ }
func NewSLAFeed(t *SLATracker, settle time.Duration) *SLAFeed
func (s *SLAFeed) Add(round int, svc string, src string, out Outcome)        // src: note | capture | kali | lan
func (s *SLAFeed) Close(round int, now time.Time) []event.Event             // applies the best source per (round, service) after settle; emits scorer.sla
func (s *SLAFeed) Note(n NoteRecord, round int) []event.Event                // Verdict(round, svc, pass) on history
```

Precedence per round and service: note, capture, kali probe, lan probe; a higher source overrides a lower for that round, a lower fills a round no higher source covers; `strict_ok` never counts; unknown neither advances nor resets; a dropped round is `Discard`ed. Alerts: `warn` at threshold-2, `critical` at threshold-1, `penalty` at the threshold; with `per_round` the first failed round already alerts (it costs).

- [ ] **Step 1: Write the failing tests**

```go
func TestPrecedenceTable(t *testing.T) {
	// same round and service, four conflicting candidates: lan fail + kali pass -> pass; + capture fail -> fail; + note pass -> pass (Source "note")
	// a round only the lan probe covers -> lan decides (Source "probe"); a round nobody covers -> unknown, streak unchanged
}
func TestResetAccrualFiveFailures(t *testing.T) { /* threshold 5: warn at 3, critical at 4, penalty at 5, counter resets; a pass resets earlier; Points == 5 after the first penalty */ }
func TestPerRoundAccrualPhases(t *testing.T) { // WR regional: 35 then 20
	// phases [{until T, 35}, {zero, 20}]: a failed round before T costs 35, after T costs 20; the first failed round emits scorer.sla level penalty
}
func TestNoteCorrectsHistory(t *testing.T) { /* streak of 3 fails; Note(up, round 2) -> streak recomputed 1+...; Calibration() agree/disagree counted */ }
func TestStrictOnlyFailureNeverCounts(t *testing.T) { /* checks.result scorer_ok true strict_ok false -> pass */ }
func TestReplayEqualsLive(t *testing.T) { /* rebuild the tracker from the round log: Streak, Points identical to the live tracker for 200 random rounds with discards and verdicts (fixed seed) */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/scorer/ -run 'Precedence|ResetAccrual|PerRound|NoteCorrects|StrictOnly|ReplayEquals' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Tracker state is recomputed by replaying the round log as built; extend the replay with the accrual.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/scorer/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "scorer: SLA from ranked sources, notes, per-round accrual"`

---

### Task 28: `scorer`: points at risk (analyser)

**Files:**
- Create: `internal/scorer/risk.go`
- Test: `internal/scorer/risk_test.go`

**Interfaces:**
- Consumes: `module.Analyzer`, `store.Reader`, kinds `scorer.sla`, `checks.red` (Task 47 adds `traceback.change`).
- Produces: `func (m *Module) Analyzers() []module.Analyzer` with one analyser `risk` (`Inputs: scorer.sla, checks.red`; `Every: 60 s`) emitting one `scorer.risk` event. Equal weight per service; `lost_points` from `Points(svc)` times `Risk.PointsPerService`'s unit when known, else relative; `points_per_minute_down` from the rate of penalty while down; `down_since` from the first red or `scorer.sla` event of the open streak; `cause` is `red` when a `checks.red` exists for the streak and nothing says otherwise, else `unknown` (`ours` and `platform` need `traceback.change`, Task 47). Services ranked by `lost_points` then `points_per_minute_down`. Pure: no state between runs.

- [ ] **Step 1: Write the failing tests**

```go
func TestRiskRanksServices(t *testing.T) { /* fixture store: ecom down 12 min with 2 penalties, mail down 2 min with 0: ecom first; weights equal 1/n */ }
func TestRiskDeterministic(t *testing.T) { /* run twice over the same store and now: byte-identical JSON */ }
func TestRiskAbsolutePointsOnlyWhenKnown(t *testing.T) { /* PointsPerService unknown: LostPoints are relative (0..1); known 6132: absolute and EventMinutes used for points_per_minute_down */ }
func TestRiskNothingDownEmitsEmptyRanking(t *testing.T) { /* no sla events: one scorer.risk with all services at zero, no panic */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/scorer/ -run Risk -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/scorer/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "scorer: points-at-risk analyser"`

---

### Task 29: `scorer`: pages, notes, health, conformance

**Files:**
- Create: `internal/scorer/ui.go`, `internal/scorer/ui/scorer.html`, `internal/scorer/conformance_test.go`, `manifest/schema/modules/scorer.schema.json`
- Modify: `internal/scorer/module.go`, `internal/module/conformance/allowed.go` (remove `scorer` from `PreContract`)
- Test: `internal/scorer/ui_test.go`

**Interfaces:**
- Consumes: `Registrar`, `Host.Emit`, tables.
- Produces: `/scorer` (round clock: Delay, Jitter, confidence, last burst, next window, dropped rounds; learned services with coverage; learned accounts and credlist groups with rename, merge, split and mark-not-scored; proposals and stale flags; recent fingerprint verdicts; the Up/Down note form), a strip on `/services` and the Overview (round clock, SLA streaks, risk ranking) as a tile; the note form POST action `note` emits one core `operator.edit` (`module: scorer`, `op: note`, `record` = service, verdict, round, text; `by` = the operator's login), and the group actions (`rename_group`, `merge`, `split`, `mark_not_scored`) emit the same kind with the full resulting groups and also write `overrides.yml` (S4: no `scorer.note` kind). Health: `ok`; `degraded` while the estimate is provisional or no capture feed arrives for a host that should have one; `unavailable` with no capture events; gaps "round clock provisional", "no fingerprint table loaded", "capture not feeding from <host>", "scorer silent".

- [ ] **Step 1: Write the failing tests**

```go
func TestScorerConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Module{}, Config: "enabled: true\nfingerprints: ../../rules/scorer/fingerprints.json\n", Seed: seedScorerEvents(), Now: time.Unix(1e9, 0)})
}
func TestNoteFormEmitsNote(t *testing.T) { /* POST action note {service ecom-http, verdict down, round 12, text "portal shows down"}: an operator.edit{module scorer, op note} with by == the session login and one scorer_note row; GET page shows it */ }
func TestHealthDegradedWhileProvisional(t *testing.T) { /* fewer than min_bursts: degraded with gap "round clock provisional"; no capture events at all: unavailable */ }
func TestMarkNotScoredAction(t *testing.T) { /* POST mark_not_scored {user}: overrides.yml updated, scorer.account no longer re-learns until seen again */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/scorer/ -run 'Conformance|NoteForm|HealthDegraded|MarkNotScored' -v`. Expected: FAIL.
- [ ] **Step 3: Implement**, remove the `PreContract` entry, run `go test ./internal/module/all/ -run Schema -update`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/scorer/... ./internal/module/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "scorer: pages, notes, health; scorer leaves PreContract"`

---

### Task 30: Delete the old checks and scorer wiring in the controller

**Files:**
- Delete: `internal/controller/checks_hub.go`, `internal/controller/checks_ops.go`, `internal/ui/templates/{checks,check}.html`
- Modify: `internal/controller/{webops,alerts,controller}.go`, `internal/ui/{reports,ui,pages}.go` (`ChecksOps`, `ChecksView`, `CheckHistoryView`, `getChecks`, `getCheck`, routes), `internal/store/{hook,migrations}.go` (`RecordCheck`, `CheckResult`, `CheckResults`, the `checks`, `check_results`, `credentials` tables), `internal/controller/dir_devices.go`
- Test: `internal/controller/nooldchecks_test.go`

**Interfaces:**
- Consumes: Tasks 15 to 29 (the module owns the pages, tables and SLA).
- Produces: `WebOps.SetScorer`, `ChecksHub`, `kindVantageCheck`, `store.RecordCheck` and the three core tables no longer exist; the dashboard's scorer tile comes from the module's registered tile. `internal/controller` and `internal/ui` import neither `internal/scorer` nor `internal/checks`.

- [ ] **Step 1: Write the failing test**

```go
func TestNoOldChecksPaths(t *testing.T) {
	// walk *.go (not _test.go, not docs) under the repo: none contains "vantage.check\"", "check_results", "kindVantageCheck", "SetScorer(", "ChecksHub", "RecordCheck"
	// go list -deps ./internal/controller ./internal/ui: neither contains internal/scorer, internal/checks, internal/vantage or internal/creds
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run NoOldChecksPaths -v`. Expected: FAIL (lists the leftovers).
- [ ] **Step 3: Implement** the deletions; `dir_devices.go` stops importing `creds` (it asks for a generated password through the vault interface W6 supplies; until W6 merges, replace the call by `vault` access with a `shortcut:` comment).
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: remove the checks hub and scorer wiring now owned by the modules"`

---

### Task 31: `vantage`: one agent module with two sub-roles, no `scorer` import

**Files:**
- Create: `internal/vantage/module.go`, `internal/vantage/gate.go`
- Modify: `internal/vantage/{vantage,scan,canary,verify}.go` (kinds through `event.New`, `scorer.Window` removed), `internal/agent/mods/vantage.go`
- Test: `internal/vantage/module_test.go`, `internal/vantage/{scan,canary,verify,core}_test.go` (updated)

**Interfaces:**
- Consumes: `plan.VantageSettings`, `AgentConfig.Roles`, `plan.RoundClock.Window`, `probe.Allowlist` (Task 12), `event.New`.
- Produces:

```go
type Module struct{ /* scanner and canary by role */ }
func New(cfg Config, env agent.Env) (*Module, error)       // agent.Module "vantage"; HealthReporter; roles scanner and canary switch the two sub-parts; verification is no sub-role, `VerifyService` backs the `pcr_verify` probe step (Task 33)
func Active() *Module                                       // the running instance, for the pcr_verify probe step (shortcut: one agent per process)
func (m *Module) refuse(target, reason string)             // emits vantage.refused (RefusedScan), High, deduplicated
```

The three old agent modules (`vantage.scanner`, `vantage.verify`, `vantage.canary`) become one module `vantage` with two sub-roles, `scanner` and `canary`; verification is not a sub-role but the `probe.run` step `pcr_verify` (Task 33); `Section` is enabled when `Modules.Vantage != nil`; the allowlist check is a hard check in the agent (scans, canary replies are inbound-only, verify targets). The gate is a local 12-line adapter over `Env.Fact("round_clock")` and `plan.RoundClock.Window` (`shortcut: duplicated in checks, hoist to agent.Env when a third module needs it`). The `scorer.Verifier` implementation `RemoteVerifier` is deleted (the controller starts verification with a plan, Task 33); `LocalTransport` stays for the lab.

- [ ] **Step 1: Write the failing tests**

```go
func TestVantageAgentConformance(t *testing.T) {
	conformance.Agent(t, conformance.AgentCase{Factory: factoryNamed(t, "vantage"), Default: kaliCfg(1), Reconfig: kaliCfg(2), KeepKey: "vantage.last_scan", Load: canaryLoad()})
}
func TestRolesSwitchSubparts(t *testing.T) { /* Roles [scanner]: scanner on, canary listener not bound; [canary]: reverse; [] with block non-nil: neither sub-part, the pcr_verify step still answers */ }
func TestRefusesNonAllowlistedScanTarget(t *testing.T) { /* settings Allowlist 127.0.0.0/8, a scan request for 203.0.113.9: nothing dialled, one vantage.refused, event validates */ }
func TestKindsAreDeclaredAndTagged(t *testing.T) { /* every emitted event validates; canary hits and scans carry no vantage.check names; grep guard: no "vantage.check" in the package */ }
func TestNoScorerImport(t *testing.T) { /* go list -deps ./internal/vantage excludes internal/scorer and internal/checks */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/vantage/ ./internal/agent/mods/ -run 'Conformance|RolesSwitch|RefusesNon|KindsAre|NoScorerImport' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/vantage/ ./internal/agent/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "vantage: one agent module with scanner and canary sub-roles"`

---

### Task 32: `vantage`: scored ports closed, pre-window scan

**Files:**
- Create: `internal/vantage/exposure.go`
- Modify: `internal/vantage/scan.go` (`Diff`, `DiffExposure`), `internal/vantage/module.go`
- Test: `internal/vantage/exposure_test.go`

**Interfaces:**
- Consumes: `plan.VantageSettings.ScoredServices`, `PreWindow`.
- Produces:

```go
// Diff gains: ScoredClosed []Finding
func DiffExposure(declared Exposure, observed Observed, scanned []netip.Addr) Diff   // no dangerous-port list (S4)
func NextScanAt(now time.Time, last time.Time, interval time.Duration, pre []time.Time) time.Time
```

The scan is diffed against the scored set only (no public decoys). `newly_open` fires for any open port that is not a scored service, whatever the port number (135, 445 and 3389 included), once until the port closes; a scored port that is closed fires `closed` with `scored: true`; a cancelled scan emits nothing; a full-range scan starts 10 minutes before each pre-window time; the scan waits `quiet_wait` for a quiet window when a clock feed exists and runs at its low rate otherwise. There is no `dangerous_ports.yml` and no `dangerous_open` change (S4).

- [ ] **Step 1: Write the failing tests**

```go
func TestAnyUndeclaredPortIsNewlyOpen(t *testing.T) { /* 135, 445, 3389 and 9200 open and not scored: four newly_open findings; 445 open with smb scored: none; no dangerous_open change exists */ }
func TestScoredPortClosedAlerts(t *testing.T) { /* declared 443 scored, observed closed: ExposureChange{change closed, scored true} */ }
func TestNewlyOpenOncePerOpening(t *testing.T) { /* open on scan 1 and 2: one event; closes then opens: a second */ }
func TestCancelledScanEmitsNothing(t *testing.T) { /* cancel mid-scan: no vantage.scan, no exposure_change (cannot look like closed ports) */ }
func TestNextScanAtPreWindow(t *testing.T) { /* pre [14:00]: at 13:40 with interval 15 m last 13:30 -> next 13:50 (pre-window start); at 13:55 -> 13:50 already past -> runs now once; no pre times -> last+interval */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/vantage/ -run 'UndeclaredPort|ScoredPortClosed|NewlyOpen|Cancelled|NextScanAt' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/vantage/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "vantage: scored ports closed, pre-window scan"`

---

### Task 33: `vantage`: the `pcr_verify` probe step per credlist and the RDP wrapper

**Files:**
- Create: `internal/vantage/rdpauth.go`
- Modify: `internal/vantage/verify.go`, `internal/vantage/module.go` (registers the `pcr_verify` name with the agent's `probe.run` dispatch)
- Test: `internal/vantage/verify_test.go`, `internal/vantage/rdpauth_test.go`

**Interfaces:**
- Consumes: the agent `probe.run` handler (W3 Task 35: `probe.run{name, params}` is a read-only core action; its dispatch looks a name up in signed table content. `pcr_verify` is code-backed, so Task 1 adds the one hook `actions.RegisterProbeStep(name string, fn func(ctx context.Context, params json.RawMessage, secrets map[string]vault.Secret) (json.RawMessage, error))`; `// shortcut: one code-backed probe name, upgrade to a registry when a second module needs one`), `actions.WithSecrets`, `Active()` (Task 31), `probe.AuthOnly`, `probe.Allowlist`.
- Produces:

```go
// probe.run{name: "pcr_verify", params: JSON{account, credlist, targets []Target}}  Risk none, Runs agent (the Kali), secret param password; no `pcr.verify` action and no verify sub-role (S4)
type Target struct{ Type string `json:"type"`; Host string `json:"host"`; Port int `json:"port"`; Encrypted bool `json:"encrypted,omitempty"`; Domain string `json:"domain,omitempty"`; Service string `json:"service"` }
func (m *Module) Verify(ctx context.Context, account, credlist string, targets []Target, pass vault.Secret) (ok bool, perService map[string]error)
func RDPAuth(ctx context.Context, host string, port int, user, pass string) error // runs `xfreerdp /v:host:port /u:user /from-stdin /auth-only /cert:ignore`; the password goes on stdin, never argv
var ErrToolMissing = errors.New("vantage: xfreerdp not installed")
```

Verification logs in with `AuthOnly` on the public services of that credlist group only (the controller sends the targets), succeeds only if every target accepts, and fails when there are no targets or any target is outside the allowlist (`vantage.refused`). The step result is the credential-free outcome, and the module emits one `vantage.probe` per service with `probe: pcr_verify`, `account`, `credlist`, `service`, `ok`, `err` (Critical and an alert on failure). The module sets `probe.Options.RDPAuth = RDPAuth`; a missing tool is the health gap "xfreerdp absent (RDP auth probe unavailable)". `shortcut: stdin password mode of xfreerdp assumed from the 3.x flags, verify in the lab.`

- [ ] **Step 1: Write the failing tests**

```go
func TestVerifyAllMustPass(t *testing.T) { /* two fake targets (imap ok, smtp wrong password): ok false, perService["smtp"] != nil, two vantage.probe{probe pcr_verify} events, the failing one Critical */ }
func TestVerifyOnlyTheCredlistsServices(t *testing.T) { /* targets list has imap only: the ssh fake server sees no connection */ }
func TestVerifyNoTargetsOrDisallowedFails(t *testing.T) { /* no targets: failure with ErrNoPublicPath text; a 203.0.113.9 target: failure and vantage.refused, nothing dialled */ }
func TestVerifyStepSecretNeverLeaks(t *testing.T) { /* run through probe.run{name pcr_verify} with Secrets {"password":"Plum-river-tent-82"}: step output, events and the returned error never contain it */ }
func TestPCRVerifyIsAProbeStepNotAnAction(t *testing.T) { /* actions registry has no "pcr.verify"; probe.run with name pcr_verify dispatches to Module.Verify; an unknown name is an error */ }
func TestRDPAuthPasswordOnStdin(t *testing.T) {
	// PATH=<tmp> containing a script "xfreerdp" that records argv and stdin and exits 0 / 1:
	// stdin == "Plum-river-tent-82\n" (or the mode's framing), argv does not contain it; exit 1 -> error without the password; no tool -> ErrToolMissing and the health gap
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/vantage/ -run 'VerifyAll|VerifyOnly|VerifyNoTargets|VerifyStepSecret|PCRVerifyIsA|RDPAuth' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/vantage/ ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "vantage: pcr_verify probe step per credlist; xfreerdp wrapper with stdin password"`

---

### Task 34: `vantage`: Zerologon check-only tester (Sonnet)

**Files:**
- Create: `internal/vantage/zerologon.go`, `internal/vantage/zerologon_test.go`, `internal/vantage/netlogon_fake_test.go`
- Modify: `internal/vantage/module.go` (action `probe.zerologon_check`)

**Interfaces:**
- Consumes: `actions.Register`, `probe.Allowlist`.
- Produces:

```go
type ZerologonResult string // "vulnerable" | "not_vulnerable" | "inconclusive"
func ZerologonCheck(ctx context.Context, dc netip.Addr, dcName, account string, o ZerologonOptions) (ZerologonResult, error)
type ZerologonOptions struct{ Attempts int /* 2000 */; Timeout time.Duration; Dial func(ctx context.Context, network, addr string) (net.Conn, error) }
// action probe.zerologon_check{host string} Risk none, ReadOnly, Touches none; emits vantage.probe{probe: zerologon}
```

The tester does the public check-only handshake: DCE/RPC bind over TCP (endpoint mapper on 135 to find the Netlogon port), `NetrServerReqChallenge` with an all-zero client challenge, then `NetrServerAuthenticate3` with an all-zero client credential and the unsealed-flags negotiate value, up to `Attempts` times (each attempt succeeds with probability 1/256 on a vulnerable DC); success means `vulnerable`, every attempt rejected means `not_vulnerable`, an unreachable or filtered endpoint mapper means `inconclusive`. **It never calls `NetrServerPasswordSet2` or any opnum other than ReqChallenge (4) and Authenticate3 (26)**; it targets only an allowlisted address. `shortcut: TCP RPC through the endpoint mapper only (no SMB named pipe); a DC that answers only on the pipe reports inconclusive.`

- [ ] **Step 1: Write the failing tests**

```go
func TestZerologonVulnerableFake(t *testing.T) { /* fake Netlogon (epmapper + one RPC port): mode vulnerable accepts a zero credential with p = 1/256 (seeded) -> result vulnerable within 2000 attempts */ }
func TestZerologonPatchedFake(t *testing.T) { /* mode patched answers STATUS_ACCESS_DENIED to every Authenticate3 -> not_vulnerable after Attempts; elapsed bounded by ctx */ }
func TestZerologonOnlyCheckOpnums(t *testing.T) { /* in both modes the fake recorded opnums are a subset of {4, 26}; never 30 (NetrServerPasswordSet2) */ }
func TestZerologonInconclusiveWhenFiltered(t *testing.T) { /* nothing listening on 135: inconclusive, no error, no hang past Timeout */ }
func TestZerologonActionRefusesOutsideAllowlistAndIsReadOnly(t *testing.T) { /* Spec().ReadOnly, Risk none; host 203.0.113.9 refused with vantage.refused */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/vantage/ -run Zerologon -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Hand-written NDR for the two calls (about 300 lines); no new module in `go.mod`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/vantage/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "vantage: zerologon check-only tester and action"`

---

### Task 35: `vantage`: SMB and WinRM exposure probes

**Files:**
- Create: `internal/vantage/smbwinrm.go`, `internal/vantage/smbwinrm_test.go`
- Modify: `internal/checks/probe/smb.go` (export `SMBNegotiate`)

**Interfaces:**
- Consumes: the probe library's SMB2 framing.
- Produces:

```go
type SMBInfo struct{ Dialect string; SigningRequired bool; Encrypts bool }
func SMBNegotiate(ctx context.Context, addr string, o Options) (SMBInfo, error)        // package probe: NEGOTIATE only, no session setup
func WinRMMethods(ctx context.Context, addr string, tls bool, o probe.Options) ([]string, error) // unauthenticated POST /wsman, the WWW-Authenticate schemes
// Module.exposureProbes(ctx) emits vantage.probe{probe: smb_exposure | winrm_exposure, host, result, evidence} per allowlisted address
```

These are fingerprint reads, not logins: the SMB probe stops after the NEGOTIATE response; the WinRM probe sends one unauthenticated request and reads the `WWW-Authenticate` header. They run only for hosts where the corresponding probe is enabled in settings and only on allowlisted addresses.

- [ ] **Step 1: Write the failing tests**

```go
func TestSMBNegotiateParses(t *testing.T) { /* fake SMB2 server answering dialect 0x0210 with signing-required: SMBInfo{"2.1", true, false}; a garbage reply -> error, no panic; no session setup bytes were received by the fake */ }
func TestWinRMMethodsFromHeader(t *testing.T) { /* fake wsman answering 401 with WWW-Authenticate: Negotiate, Kerberos -> [Negotiate Kerberos]; 200 -> [] ; TLS variant on 5986 with a self-signed cert works */ }
func TestExposureProbesEmitAndRespectSettings(t *testing.T) { /* settings SMB true WinRM false: only smb_exposure events; every event validates; a non-allowlisted host is skipped with vantage.refused */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/vantage/ ./internal/checks/probe/ -run 'SMBNegotiate|WinRMMethods|ExposureProbes' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/vantage/ ./internal/checks/probe/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "vantage: SMB and WinRM exposure probes"`

---

### Task 36: `vantage`: controller side, alert-class kinds, pages, conformance

**Files:**
- Create: `internal/vantage/controller.go`, `internal/vantage/ui.go`, `internal/vantage/ui/vantage.html`, `internal/controller/genconfig_vantage.go`, `plans/vantage/scan_now.yml`, `manifest/2027/modules/vantage.yml`, `manifest/schema/modules/vantage.schema.json`
- Modify: `internal/module/conformance/allowed.go` (remove `vantage` from `PreContract`), `internal/module/all/all.go`
- Test: `internal/vantage/controller_test.go`, `internal/vantage/conformance_test.go`, `internal/controller/genconfig_vantage_test.go`

**Interfaces:**
- Consumes: `Host.Tables`, `Host.Subscribe` (`vantage.scan`, `vantage.exposure_change`), the core alert pipeline (alert-class events become alert rows), `Host.RunReadOnly`.
- Produces: tables `vantage_scan(id INTEGER PRIMARY KEY AUTOINCREMENT, time_ns INTEGER NOT NULL, hosts TEXT NOT NULL, duration_ms INTEGER NOT NULL, tcp_open TEXT NOT NULL, udp_open TEXT NOT NULL)` and `vantage_exposure(host TEXT NOT NULL, port INTEGER NOT NULL, proto TEXT NOT NULL, state TEXT NOT NULL, scored INTEGER NOT NULL, first_ns INTEGER NOT NULL, last_ns INTEGER NOT NULL, PRIMARY KEY(host, port, proto))` written by one goroutine from the module's own events. There are no vantage correlation rules and no `rules/vantage/` (S4): `checks.compare` (class `path_broken`, `scorer_content` or `internal_only`), `vantage.exposure_change` (`newly_open`, or `closed` with `scored: true`), `vantage.canary_hit` and a Critical `vantage.probe` (a failed `pcr_verify`, a positive Zerologon) are alert-class kinds with the severity declared in Task 1, so the core alert pipeline makes the alert rows; `declared_closed` is not an alert. Pages: `/vantage` (per public address open ports against the scored set, last scan and diff, canary results by host, verification history from `vantage.probe` rows, the Kali's link and allowlist, a **Scan now** button that runs `plans/vantage/scan_now.yml` through `RunReadOnly`, the field for the organizers' scan times written to `overrides.yml`); `genconfig_vantage.go` renders `VantageSettings` for a host with role `scanner` or `canary` (allowlist, scored set from the manifest's public addresses, `PreWindow` from the overrides). `shortcut: the manifest's public address per host is the hosts.yml field public, add it to the reference manifest when absent.` Health: `degraded` when the scan is behind schedule, the clock feed is absent or `xfreerdp`/`nmap` is missing; `unavailable` when the Kali is down or its allowlist empty.

- [ ] **Step 1: Write the failing tests**

```go
func TestVantageControllerConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Module{}, Config: "enabled: true\nallowlist: [172.25.21.0/24]\n", Seed: nil, Now: time.Unix(1e9, 0)})
}
func TestAlertClassKindsBecomeAlertRows(t *testing.T) { /* through the core alert pipeline: exposure_change newly_open and closed{scored} -> High alert rows; declared_closed -> none; canary_hit -> High; vantage.probe pcr_verify ok false -> Critical, ok true -> none; no rules/vantage directory exists */ }
func TestExposureTableProjection(t *testing.T) { /* newly_open then closed events: one vantage_exposure row, state closed, first_ns kept */ }
func TestScanNowRunsReadOnlyPlan(t *testing.T) { /* POST action scan_now -> Host.RunReadOnly("scan_now", {host: kali}); the template passes lint SS000 */ }
func TestKaliSettingsRendered(t *testing.T) { /* reference manifest: kali host Modules.Vantage.Allowlist == the public /24, ScoredServices non-empty, PreWindow from overrides; a LAN host: nil */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/vantage/ ./internal/controller/ -run 'VantageControllerConformance|AlertClassKinds|ExposureTable|ScanNow|KaliSettings' -v`. Expected: FAIL.
- [ ] **Step 3: Implement**, remove the `PreContract` entry, run `go test ./internal/module/all/ -run Schema -update`.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/vantage/... ./internal/controller/ ./internal/module/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "vantage: controller side, alert-class kinds, page; vantage leaves PreContract"`

---

### Task 37: `creds/pcr`: the engine as a record keeper

**Files:**
- Modify: `internal/creds/pcr/engine.go`, `internal/creds/pcr/csv.go`, tests (moved in Task 1)
- Test: `internal/creds/pcr/engine_test.go`, `internal/creds/pcr/csv_test.go`

**Interfaces:**
- Consumes: the moved engine; `vault.Secret`.
- Produces: the engine keeps the transaction state machine, the caps and the CSV; hosts, the Kali and the portal are no longer its collaborators (plans do those steps).

```go
type Window struct{ Safe bool; Start, End time.Time; Confidence float64; Reason string }
type Config struct{ MinWindow time.Duration; MinConfidence float64; AllowLowConfidence bool; VerifyNotice time.Duration; MaxAccountsPerBatch, MaxOpenTxns int; Policy CSVPolicy }
func NewEngine(cfg Config) *Engine
func (e *Engine) Plan(req PlanRequest, now time.Time) (Txn, error)                    // caps: MaxOpenTxns, CanRotate; ErrBatchTooLarge is raised by Prepare
func (e *Engine) Gate(w Window) error                                                  // NotInWindowError / LowConfidenceError
func (e *Engine) HostChanged(id string, now time.Time, w Window, hazard bool) error   // planned -> host_changed; Deadline = w.End; Race when hazard or now > w.End
func (e *Engine) KaliResult(id string, ok bool, now time.Time) error
func (e *Engine) Prepare(ids []string) (Submission, error)                             // unchanged CSV blocks; len(ids) <= MaxAccountsPerBatch
func (e *Engine) ConfirmSubmission(subID string, reply PCRReply, at time.Time) error // unchanged
func (e *Engine) ObserveScorerLogin(account string, ok bool, burstSeq int, at time.Time) []string // unchanged
func (e *Engine) Rollback(id string, now time.Time) (*Submission, error)              // marks HostReverted/old-value Submission; no host call
func (e *Engine) Load(t Txn) error                                                     // rebuild after a restart from creds_txn
const StateReverted TxnState = "reverted"
```

Removed: `Scripted`, `PCRSubmitter`, `Submit`, `HostChanger`, `Verifier`, `WindowSource`, `ErrScriptedDisabled`, `ErrNoSubmitter`, `Generate`, `PlanForRecord`, `SyncRecord`, `CredsState`, and the imports of `creds` and `scorer`. The package imports only `internal/vault` and the standard library.

- [ ] **Step 1: Write the failing tests** (the built state-machine, window, CSV, race and rollback tests are adapted, not rewritten; these are the new ones)

```go
func TestPCRImportsOnlyVault(t *testing.T) { /* go list -deps ./internal/creds/pcr contains no internal/creds, internal/scorer, internal/vantage, internal/checks */ }
func TestCapsEnforced(t *testing.T) { /* MaxOpenTxns 6: the 7th Plan -> error; Prepare of 4 ids with MaxAccountsPerBatch 3 -> ErrBatchTooLarge; a second Plan for an account with an open txn -> CanRotate error */ }
func TestGateNeedsWindowAndConfidence(t *testing.T) { /* Window{Safe false} -> NotInWindowError; Confidence 0.35 -> LowConfidenceError unless AllowLowConfidence */ }
func TestHostChangedSetsDeadlineAndRace(t *testing.T) { /* inside the window: Deadline == w.End, Race false; hazard true or now after w.End: Race true; first failed login after a Race is forgiven once (Tolerated), the second is failed */ }
func TestLoadRebuildsOpenTxn(t *testing.T) { /* a Txn at host_changed round-trips through json (no secrets in the JSON: OldPass/NewPass tagged json:"-") and Load restores it; ApplyHost-equivalent is not repeatable (HostChanged again -> ErrBadState) */ }
func TestStateRevertedTransitions(t *testing.T) { /* verified -> reverted allowed; reverted -> planned (resync/back) allowed; failed -> reverted not allowed */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/creds/pcr/ -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the edits; Task 1's skipped tests for `Plan`, `HostChanged` and `Load` are unskipped here.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/creds/... ./internal/scorer/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "creds/pcr: the engine keeps transactions; plans do the host work"`

---

### Task 38: `creds`: the typeable passphrase class and the word list

**Files:**
- Create: `internal/creds/words.go`, `rules/creds/words.txt` (BIP-39 English list, 2,048 words, MIT licence text kept in `rules/creds/LICENSE-words`)
- Modify: `internal/creds/policy.go` (`Class`: `Typeable`, `Admin`, `Machine`; `Scored` and `Unscored` removed), `internal/creds/breakglass.go`, `internal/creds/record.go`, `internal/controller/dir_devices.go`, `internal/controller/devexec_test.go`
- Test: `internal/creds/words_test.go`, `internal/creds/creds_test.go`

**Interfaces:**
- Consumes: `vault.Secret`, `Generator.Reserve` (unique across everything generated).
- Produces:

```go
func LoadWords(fsys fs.FS) ([]string, error)                         // 2,048 unique lowercase words; sha256 pinned
// Class: Typeable (4 words, one capitalised, joined by '-', two digits, 20 to 25 characters), Admin (5 words, up to 32), Machine (24 to 32 from the conservative alphabet plus # % ^)
func (g *Generator) Generate(c Class, avoid ...string) (vault.Secret, error)   // Typeable and Admin need the loaded list: NewGenerator(words []string)
func DeriveBreakGlassTypeable(secret, host, user string, epoch uint32, words []string) (vault.Secret, error) // 5 words, HMAC-SHA256 expansion; DeriveBreakGlass stays for Machine
```

The generated password satisfies AD complexity (upper, lower, digit, `-`), stays inside `[A-Za-z0-9._+=-]`, never contains the account name (3 or more characters), and is rejected and redrawn when its length is outside 20 to 25 (the design's example `Plum-river-tent-82` is 18 characters; the design text is corrected in this commit: BIP-39 words run 3 to 8 letters). About 53 bits: `shortcut: typeable passphrases carry about 50 bits; upgrade to five words if dumped scored hashes are cracked.`

- [ ] **Step 1: Write the failing tests**

```go
func TestWordlistValid(t *testing.T) {
	w, err := LoadWords(os.DirFS("../.."))
	if err != nil || len(w) != 2048 { t.Fatalf("%d %v", len(w), err) }
	// all lowercase a-z, unique, no word a prefix of another within the first 4 letters (BIP-39 property), sha256 of the file == the pinned constant
}
func TestTypeableShape(t *testing.T) {
	g := NewGenerator(loadWords(t))
	re := regexp.MustCompile(`^[A-Za-z0-9-]{20,25}$`)
	for i := 0; i < 2000; i++ {
		s, _ := g.Generate(Typeable, "alice")
		pw := s.Reveal()
		if !re.MatchString(pw) || strings.Count(pw, "-") != 3 || !hasUpper(pw) || !hasLower(pw) || !endsWithTwoDigits(pw) || strings.Contains(strings.ToLower(pw), "alice") { t.Fatalf("%q", pw) }
		if exactlyOneCapitalisedWord(pw) == false { t.Fatalf("%q", pw) }
		if err := PCRSafe("alice", pw); err != nil { t.Fatalf("%q: %v", pw, err) }
	}
}
func TestTypeableUniqueAcrossGenerator(t *testing.T) { /* 5000 draws, no duplicates (case-insensitive SHA-256 reservation); a Reserved value is never returned */ }
func TestAdminAndMachineClasses(t *testing.T) { /* Admin: 5 words, <= 32 chars; Machine: 24..32 chars from the alphabet with # % ^ allowed and none of , " ' \ space @ : / $ ` ; & | < > ( ) ! * ~ { } [ ] */ }
func TestBreakGlassTypeableKnownAnswer(t *testing.T) { /* fixed secret, host, user, epoch 1 and the word list: equals the pinned vector; epoch 2 differs; the vector fails if the word-list hash changes */ }
func TestNoScoredOrUnscoredClassLeft(t *testing.T) { /* grep guard: no "creds.Scored" or "creds.Unscored" in the tree */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/creds/ -run 'Wordlist|Typeable|AdminAndMachine|BreakGlassTypeable|NoScored' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** Rejection sampling for the length window; uniform word choice with `crypto/rand`; the vector is computed once and pinned.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "creds: typeable passphrase class, admin and machine classes, word list"`

---

### Task 39: `creds`: module base, inventory per (account, credlist), tables, restart

**Files:**
- Modify: `internal/creds/module.go`, `config.go`, `record.go` (`Record.Credlists []CredlistRow`, `CredlistRow{Credlist, State, Txn}`; `PCRState` gains `reverted`), `internal/creds/tables.go`
- Create: `internal/creds/inventory.go`, `manifest/2027/modules/creds.yml`
- Test: `internal/creds/module_test.go`, `internal/creds/inventory_test.go`

**Interfaces:**
- Consumes: `module.Host` (`Config`, `Tables`, `Subscribe`, `Secrets`, `Emit`), `accounts.yml` through `Host.Config`-adjacent manifest access (`Config.Accounts` rendered by the controller into the module block as `accounts:`), `scorer.account`, `operator.edit` (`module: scorer`), `pcr.Engine.Load`.
- Produces: migrations

```sql
CREATE TABLE creds_account(account TEXT NOT NULL, host TEXT NOT NULL, role TEXT NOT NULL, domain INTEGER NOT NULL, scored INTEGER NOT NULL, current_version TEXT NOT NULL DEFAULT '', previous_version TEXT NOT NULL DEFAULT '', last_rotated_ns INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(account, host));
CREATE TABLE creds_txn(txn TEXT PRIMARY KEY, account TEXT NOT NULL, state TEXT NOT NULL, json TEXT NOT NULL, updated_ns INTEGER NOT NULL);
CREATE TABLE creds_row(txn TEXT NOT NULL, credlist TEXT NOT NULL, row INTEGER NOT NULL, user TEXT NOT NULL, state TEXT NOT NULL, PRIMARY KEY(txn, credlist, row));
```

One writer goroutine fills them from `creds.state` and `creds.txn`; `creds_txn.json` is a `pcr.Txn` snapshot without secrets (tables hold vault version ids only). There is no `creds_credlist` table (S4): `Record.Credlists` is rebuilt at `Start` from the latest `creds.state` event per (account, host, credlist), and a scored account's credlist label comes from `scorer.account` `group` and follows `scorer`'s `operator.edit` group edits (`rename_group`, `merge`, `split`). `// shortcut: per-credlist state lives in memory, rebuilt from events at Start; upgrade to a table if the replay gets slow.` `Start` rebuilds the engine from open `creds_txn` rows. The inventory is every account in `accounts.yml` plus the learned scored accounts (`scorer.account`: `scored`, credlist rows from the learned group); `scored: unknown` is treated as protected and is not rotatable. Health: `degraded` with the gap "vault locked, no rotation or verification", or "no quiet window" while the clock is provisional, or when the Kali is down; `unavailable` when the vault cannot be read. `Config` gains `Secrets []string` (default `[cred/*, pcr/*]`).

- [ ] **Step 1: Write the failing tests**

```go
func TestInventoryFromAccountsAndScorer(t *testing.T) { /* accounts.yml has mail-users scored with credlists [learned]; a scorer.account event for alice on imap group L2 -> record alice scored, one CredlistRow L2 stable; sysadmin@linux unscored with rotation t0_console */ }
func TestUnknownScoredIsProtectedNotRotatable(t *testing.T) { /* scored: unknown -> Record.Scored true for the guard, Prepare refuses with "scored status unknown" */ }
func TestTablesProjectedFromEventsOnly(t *testing.T) { /* creds.state events for (alice, L1) and (alice, L2): one creds_account row, and after a module restart Record.Credlists holds both rows with their states; a direct Exec to creds_account from the test succeeds only through ModuleDB; rows hold no value, only version ids */ }
func TestCredlistLabelFollowsScorerGroups(t *testing.T) { /* scorer.account alice group L1, then operator.edit{module: scorer, op: rename_group, L1 -> linux}: alice's CredlistRow label is linux; no creds table stores the label */ }
func TestRestartRebuildsOpenTxns(t *testing.T) { /* creds_txn row at host_changed -> after a module restart Engine.Get(id).State == host_changed and no plan is started */ }
func TestHealthStates(t *testing.T) { /* vault locked: degraded + gap; clock provisional: degraded "no quiet window"; vault read error: unavailable */ }
func TestNoSecretInTables(t *testing.T) { /* put "Plum-river-tent-82" in the vault under pcr/t1/..., run a full inventory + a txn row: dump every creds_* table and every stored creds.* event: the value is nowhere */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/creds/ -run 'Inventory|UnknownScored|TablesProjected|CredlistLabel|RestartRebuilds|HealthStates|NoSecretInTables' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/creds/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "creds: module base, per-credlist inventory, tables, restart"`

---

### Task 40: Scored-account session eviction policy (T49 CI form)

Precondition: W2 merged `session.terminate_predating{account | source, before}` (README row). If it is absent, stop and escalate.

**Files:**
- Create: `internal/actions/session_evict.go`
- Modify: the W2 action file for `session.terminate_predating` (params and wiring)
- Test: `internal/actions/session_evict_test.go`

**Interfaces:**
- Consumes: the W2 action and its session lister.
- Produces:

```go
type Session struct{ ID, User, Source string; Start time.Time; LogonType string; OwnsServiceProcess bool } // LogonType: rdp | ssh | network | console | service | batch | other; OwnsServiceProcess: the session owns a process of a manifest service (process.unit or binaries)
type EvictParams struct{ Before, Now time.Time; Scored bool; CutoffMS int64; ExemptSources []string }
func EvictionPolicy(ss []Session, p EvictParams) (kill, flag []Session)
// session.terminate_predating gains params: scored bool, cutoff_ms int (>= 0), exempt_sources string (comma-separated addresses)
```

Rules (design R5, 2026-11-06): only interactive logon types (`rdp`, `ssh`, `network`, `console`) are eligible for any account class; a session of another logon type, or with `OwnsServiceProcess`, is never killed and is flagged instead (a Windows service logon session or a long-lived database connection owned by the rotated account stays). A session that began at or after `Before` is untouched. Admin accounts (`Scored` false): kill every eligible session that began before `Before`. Scored accounts: kill only a session that began before `Before`, whose age at `Now` is at least `CutoffMS`, whose source parses as an address not in `ExemptSources`, and whose `Start` is non-zero; a session older than the cutoff from an exempt source is flagged; any session that cannot be classified (zero start, unparseable or empty source) is flagged, never killed; `CutoffMS == 0` (no delay measured yet) means flag-only: nothing is killed.

- [ ] **Step 1: Write the failing tests**

```go
func TestEvictionPolicyTable(t *testing.T) { // T49 CI half
	now := t0
	before := now.Add(-5 * time.Minute)
	ss := []Session{
		{"young-scorer", "alice", "198.51.100.7", now.Add(-10 * time.Second)},   // began after Before: untouched
		{"old-red", "alice", "203.0.113.5", before.Add(-2 * time.Hour)},          // old, non-scorer: killed
		{"old-from-scorer-src", "alice", "198.51.100.7", before.Add(-2 * time.Hour)}, // older than cutoff but scorer-labelled: flagged
		{"unclassifiable", "alice", "", before.Add(-2 * time.Hour)},              // no source: flagged
		{"zero-start", "alice", "203.0.113.6", time.Time{}},                      // flagged
		{"before-but-young", "alice", "203.0.113.8", before.Add(-30 * time.Second)}, // began before Before but younger than the cutoff: flagged
	}
	kill, flag := EvictionPolicy(ss, EvictParams{Before: before, Now: now, Scored: true, CutoffMS: 120000, ExemptSources: []string{"198.51.100.7"}})
	// kill == [old-red]; flag == [old-from-scorer-src, unclassifiable, zero-start, before-but-young]; young-scorer in neither
	k2, f2 := EvictionPolicy(ss, EvictParams{Before: before, Now: now, Scored: true, CutoffMS: 0, ExemptSources: nil})
	// flag-only: len(k2) == 0; every session older than Before is flagged
	k3, _ := EvictionPolicy(ss, EvictParams{Before: before, Now: now, Scored: false})
	// plain eviction: kills every eligible session with a non-zero Start before Before: old-red, old-from-scorer-src, unclassifiable, before-but-young
}
func TestEvictionNeverEndsServiceSessions(t *testing.T) {
	// sessions: {svc-logon, LogonType "service"}, {db-conn, LogonType "network", OwnsServiceProcess true}, {rdp-old, "rdp"}, all older than Before
	// plain and scored policies: kill == [rdp-old] only (scored additionally needs its cutoff rules); svc-logon and db-conn are flagged, never killed
}
func TestTerminateActionParams(t *testing.T) { /* negative cutoff_ms rejected; scored true without cutoff_ms defaults to flag-only; the action output lists killed and flagged ids */ }
```

(The implementer replaces the inline comments with `reflect.DeepEqual` on ids; the `before-but-young` row is flagged and a zero `Start` is flagged for scored and skipped for plain eviction.)

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ -run 'EvictionPolicy|TerminateActionParams' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the pure function and wire the action to it.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/actions/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: scored-account session eviction policy"`

---

### Task 41: `creds`: plan templates and the `CR001` transaction rule

**Files:**
- Create: `plans/creds/scored-change.yml`, `plans/creds/resync.yml`, `plans/creds/unscored-rotation.yml`, `internal/creds/lint.go`
- Test: `internal/creds/lint_test.go`, `internal/creds/templates_test.go`

**Interfaces:**
- Consumes: `lint.Register`, `lint.Ctx.Query`, `LoadModuleTemplate`, `ExpandTemplate`, node options (Tasks 3 and 4), `session.terminate_predating` (Task 40), the `probe.run` step `pcr_verify` (Task 33), `health.check` (Task 19).
- Produces: `CR001` registered from `init`: a node that sets a password (`user.set_password`, `ad.account.reset_password`, `splunk.password`) for an account the manifest marks scored or unknown passes only when it carries `txn: <id>`, the plan is `module: creds` and one of the three templates, and the latest `creds.txn` event for that id is not terminal (read through `Ctx.Query`). Templates (class `click` for `scored-change`, `auto` for `resync`, `click` for `unscored-rotation`):

```yaml
# scored-change.yml: params account, hosts (comma list), txn, pref (pcr/<txn>/new or pcr/<txn>/old), before, cutoff_ms, exempt_sources, kali, credlist, targets
id: creds.scored-change
module: creds
on_failure: stop_dependents
nodes:
  - {id: change, each: hosts, action: user.set_password, target: "${host}", txn: "${txn}", window: scorer_quiet, max_hold: 600s, window_min_sec: 30, deadman_sec: 120, params: {user: "${account}", secret_params: [password], secret_refs: {password: "${pref}/${host}/${account}"}}}
  - {id: evict,  each: hosts, action: session.terminate_predating, target: "${host}", needs: [change], params: {user: "${account}", before: "${before}", scored: true, cutoff_ms: "${cutoff_ms}", exempt_sources: "${exempt_sources}"}}
  - {id: reply,  gate: true, ask: "Portal reply: how many rows did Quotient accept?", reply: count, needs: [evict]}
  - {id: verify, action: probe.run, target: "${kali}", needs: [evict], txn: "${txn}", params: {name: pcr_verify, params: '{"account":"${account}","credlist":"${credlist}","targets":"${targets}"}', secret_params: [password], secret_refs: {password: "${pref}/verify/${account}"}}}
```

`resync.yml` is the same `change` node (value `pcr/<txn>/cur/...`, the vault's current value) followed by `verify`, no gate, no eviction; `unscored-rotation.yml` rotates an unscored account (`user.set_password`, the files that embed it, then `health.check` scorer_mimic) and has no `txn`.

- [ ] **Step 1: Write the failing tests**

```go
func TestCR001(t *testing.T) {
	ctx := lintCtx(t, scoredAccounts("alice"), openTxn("t1"), closedTxn("t0"))
	node := func(user, txn string) plan.Node { return plan.Node{ID: "n", Action: "user.set_password", Target: "h1", Txn: txn, Params: map[string]any{"user": user}} }
	cases := []struct{ name string; p plan.Plan; want bool }{
		{"no txn", planOf("creds", "scored-change", node("alice", "")), true},
		{"closed txn", planOf("creds", "scored-change", node("alice", "t0")), true},
		{"open txn", planOf("creds", "scored-change", node("alice", "t1")), false},
		{"open txn in a hardening plan", planOf("hardening", "x", node("alice", "t1")), true},
		{"unscored account", planOf("hardening", "x", node("svc-app", "")), false},
		{"unknown account is protected", planOf("hardening", "x", node("mystery", "")), true},
	}
	for _, c := range cases { /* lint.Run(c.p, ctx) has a CR001 finding == c.want */ }
}
func TestScoredChangeExpandsPerHost(t *testing.T) { /* template with hosts "rocky-ecom,ubuntu-email": two change nodes and two evict nodes, ids unique, every change node has Window scorer_quiet, MaxHoldSec 600, Txn set; the reply gate has Ask and Reply count; ExpandTemplate rejects a missing param */ }
func TestTemplatesLintClean(t *testing.T) { /* scored-change with txn open passes every registered rule except none; resync is ClassAuto and passes; unscored-rotation passes for an unscored account and fails CR001 if pointed at a scored one */ }
func TestResyncHasNoTypedStep(t *testing.T) { /* resync.yml contains no gate and no session.terminate_predating */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/creds/ -run 'CR001|ScoredChange|TemplatesLint|ResyncHas' -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the rule and the templates; extend the template loader's `each` to take a comma-separated parameter if it cannot (`each: hosts` with `${host}` per element) and say so in the commit.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/creds/ ./internal/plan/... ./internal/controller/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "creds: plan templates and the CR001 transaction rule"`

---

### Task 42: `creds`: transaction driver A: prepare, stage, release, commit, eviction (Sonnet)

**Files:**
- Create: `internal/creds/txn.go`, `internal/creds/txn_ui.go`
- Modify: `internal/creds/module.go`
- Test: `internal/creds/txn_test.go`

**Interfaces:**
- Consumes: `pcr.Engine` (Task 37), `Generator` (Task 38), `vault.Writer` via `Host.Secrets("cred/*", "pcr/*")`, `Host.Propose`, `Host.Control` (`creds_txn` fact), `scorer.clock` (latest, for `Window`, `eviction_cutoff_ms`, `rounds_expected`), `scorer.round` (current sources), `agent.step_result` (Task 5), the `fakeRunner` helper (Task 1), `vantage.probe` (latest Zerologon result for domain accounts).
- Produces:

```go
func (m *Module) Prepare(ctx context.Context, p PrepareRequest) (txn string, err error) // PrepareRequest{Accounts []AccountRef; By string; OverrideConfidence bool}
func (m *Module) ShowList(ctx context.Context, txn, by string) (pcr.Submission, error)  // reveal is a POST action, audited by the UI shell
func (m *Module) Stage(ctx context.Context, txn, by string) error                       // staged tick with the operator's name
func (m *Module) Release(ctx context.Context, txn string) (proposalID int64, err error) // Host.Propose of scored-change; the operator's Accept click starts it
```

`Prepare` refuses (error text names the reason, nothing is stored): a scored status of unknown, an account with an open txn, more open transactions than `max_open_txns`, a batch larger than `max_accounts_per_txn`, a host with a `reverted` row, a domain account while the latest Zerologon result is not `not_vulnerable`, a vault that is locked, and (at `Release`) a clock that is provisional or below `min_confidence` unless `OverrideConfidence`. It generates one `Typeable` password per (account), writes `pcr/<txn>/new/<host>/<account>`, `pcr/<txn>/old/<host>/<account>` (a copy of the current value), `pcr/<txn>/verify/<account>` and, for resync, `pcr/<txn>/cur/...`; emits `creds.txn{prepared}`; opens the `creds_txn` fact (`ID: plan.CredsTxnFactID(account)`, hosts = the check runners and the Kali, TTL 30 min, refreshed every 10 min until the transaction ends). `Release` fills the plan parameters (`before` = now, `cutoff_ms` and `exempt_sources` from the latest clock and round) and proposes `scored-change`; plan node results (`agent.step_result`, filtered to plans of module `creds` with a `txn`) drive `HostChanged` (emitting `host_changed`) and record eviction. The UI also generates a dummy list (made-up users, no host change) for the timing exercise.

- [ ] **Step 1: Write the failing tests**

```go
func TestPrepareRefusals(t *testing.T) {
	for name, setup := range map[string]func(*fixture){
		"scored unknown": func(f *fixture) { f.account("mystery", unknown) }, "open txn": func(f *fixture) { f.openTxn("alice") },
		"too many open": func(f *fixture) { f.openTxns(6) }, "batch too large": func(f *fixture) { f.batch = 4 },
		"reverted row on host": func(f *fixture) { f.reverted("rocky-ecom", "alice") },
		"domain without zerologon result": func(f *fixture) { f.account("dom-user", domain) }, "vault locked": func(f *fixture) { f.lockVault() },
	} { /* Prepare returns an error naming the reason; no vault write, no event, no fact */ }
}
func TestPrepareStoresPendingAndOpensFact(t *testing.T) {
	// Prepare(alice on rocky-ecom,ubuntu-email, credlists L1,L2): vault has pcr/<txn>/new/<host>/alice for both hosts (typeable, 20-25 chars), .../old/... equal to the current values;
	// one creds.txn{prepared}; fake Host.Control saw creds_txn:alice Open true with TTL 30 min, and a refresh after 10 min (fake clock)
	// ShowList returns two CSV blocks (L1, L2) with one "alice,<pw>" line each and the row count; Stage by "dana" adds creds.txn{staged, by [dana]}
}
func TestReleaseProposesWithClockParams(t *testing.T) {
	// clock confidence 0.9, window open, eviction_cutoff_ms 20000, scorer sources [198.51.100.7]: Release -> Host.Propose with Template "scored-change", Params hosts, txn, pref "pcr/<txn>/new", before (RFC 3339), cutoff_ms "20000", exempt_sources "198.51.100.7", Reason "tier 1"
	// confidence 0.35 -> error "round clock confidence 0.35 below 0.50"; with OverrideConfidence -> proposed; provisional -> refused even with override? (override allows confidence only)
}
func TestStepResultsDriveHostChanged(t *testing.T) {
	// fakeRunner delivers agent.step_result for change nodes (module creds, txn t1) verified inside the window: engine state host_changed, creds.txn{host_changed} emitted once after all hosts are done;
	// a failed change node: no host_changed; the txn ends rolled_back with creds.txn{rolled_back} and the fact is closed (Open false) (failure handling detail in Task 43)
}
func TestRestartResumesAtHostChanged(t *testing.T) { /* kill the module after host_changed; a new module over the same store: state host_changed, no new Propose, no second host change, creds_txn fact re-sent with a fresh TTL */ }
func TestNoSecretAnywhere(t *testing.T) { /* after prepare+release+host_changed: grep the store events, creds_* tables, the proposal row, the plan JSON stored by the controller and the module logger output for the generated password and for the old one: absent */ }
func TestDummyListMakesNoHostChange(t *testing.T) { /* dummy list: made-up users, no vault write, no proposal, no fact */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/creds/ -run 'PrepareRefusals|PrepareStores|ReleaseProposes|StepResultsDrive|RestartResumes|NoSecretAnywhere|DummyList' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.** The gate on the clock reads the same `scorer.clock` event the controller hold (Task 3) reads.
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/creds/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "creds: prepare, stage, release and commit of a scored change"`

---

### Task 43: `creds`: transaction driver B: verify, reply, scorer login, failure handling (Sonnet)

**Files:**
- Modify: `internal/creds/txn.go`
- Create: `internal/creds/txn_finish.go`
- Test: `internal/creds/txn_finish_test.go`

**Interfaces:**
- Consumes: Task 42, `vantage.probe` (`probe: pcr_verify`), `scorer.login`, `scorer.item_set` (`rounds_expected`), `pcr.Engine.KaliResult/ConfirmSubmission/ObserveScorerLogin/Rollback`.
- Produces:

```go
func (m *Module) Reply(ctx context.Context, txn, by string, r pcr.PCRReply) error // the portal reply, from the manual gate or the UI form
func (m *Module) FixForward(ctx context.Context, txn, row, by string) error        // the operator retyped a row after a failed scored login
func (m *Module) RollBack(ctx context.Context, txn, by string) error               // revert plan in the next quiet window + typed list with the old value
```

Behaviour: after the `reply` gate (count equal to the rows, `skipped` empty) the transaction waits for a passing `scorer.login` by that user on the credlist's service; the UI shows the expected rounds (`rounds_expected` for one user, `k ln k` for all); after `verify_notice` (15 min) without a pass a `creds.notice` is emitted, **silence never rolls back**. On `verified`: the new value becomes the current vault entry (`Put cred/<host>/<account>`, previous version recorded), the pending `pcr/<txn>/*` entries are deleted, the `creds_txn` fact is closed, `creds.state` is emitted per credlist row. Failures: (1) host change fails: the plan rolled the node back, nothing submitted, `rolled_back`, pending entries deleted; (2) the Kali verify fails (`vantage.probe` with `probe: pcr_verify`, `ok: false`): the transaction stays `host_changed`, the revert is proposed as `scored-change` with `pref=pcr/<txn>/old` held to the next quiet window, and the typed list with the old value is shown (the human re-submits the old value; Quotient already holds the new one); (3) window missed or human late (`HostChanged` race, or the reply arrives after the deadline): marked `late` or `race`, the first failed scorer login in the next burst is forgiven once; (4) reply mismatch: treated as possibly applied, a rollback also enters the old value, `skipped` rows fail with no PCR rollback; (5) a scored login fails after submit: default fix-forward (retype one row), alternative rollback; rollback never uses "Reset to Defaults".

- [ ] **Step 1: Write the failing tests**

```go
func TestHappyPathEndToEnd(t *testing.T) { // T35 normal
	// fixture clock open; Prepare, Stage, Release+Accept via fakeRunner, change/evict results, verify result ok, Reply(count 2, no skipped), scorer.login ok for alice@imap
	// -> creds.txn steps in order [prepared staged committing host_changed verify_ok pcr_submitted verified]; vault cred/<host>/alice == the new value, previous version kept; pcr/<txn>/* gone; fact closed; creds.state stable
}
func TestSilenceNeverRollsBack(t *testing.T) { /* after Reply, advance the fake clock 20 min with no scorer.login: one creds.notice "verification overdue", state still pcr_submitted, no plan started */ }
func TestKaliVerifyFailureStartsHeldRevert(t *testing.T) { /* verify result ok false: state stays host_changed, a Propose of scored-change with pref pcr/<txn>/old, the list shown carries the OLD value, a Critical vantage.probe{probe pcr_verify, ok false} present */ }
func TestReplyMismatchTreatedAsApplied(t *testing.T) {
	// Reply count 1 for 2 rows: error "reply does not match", PCRUnknown true; RollBack's list contains the old value; Reply skipped ["bob"]: that row failed, RollBack list excludes bob's old value
}
func TestLateAndRaceForgiveFirstFailedLogin(t *testing.T) { /* host change after the window end: step "late"; HostChanged inside a hazard: "race"; first failed scorer.login is forgiven (Tolerated), the second moves to failed; no more than one failed round per affected user is charged */ }
func TestFailedLoginFixForwardOrRollback(t *testing.T) { /* failed login -> state failed; FixForward(row) keeps the host, re-shows that row and returns to pcr_submitted; RollBack proposes the old-value change and never emits a "Reset to Defaults" CSV (the list has one line per affected row only) */ }
func TestOldValueWrittenBackOnRollback(t *testing.T) { /* after rolled_back the vault current value is the old one and pending entries are deleted */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/creds/ -run 'HappyPath|SilenceNever|KaliVerifyFailure|ReplyMismatch|LateAndRace|FailedLoginFixForward|OldValueWritten' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/creds/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "creds: verification, portal reply, scorer login and failure handling"`

---

### Task 44: `creds`: revert detection and automatic re-apply (T51 CI form)

**Files:**
- Create: `internal/creds/revert.go` (PCR back reuses the engine and the typed list; it has no plan template)
- Modify: `internal/creds/txn.go`, `internal/creds/module.go`
- Test: `internal/creds/revert_test.go`

**Interfaces:**
- Consumes: `agent.reenrolled` (core), `Host.RunAuto` and `module.ErrProposed`, `plans/creds/resync.yml`, `vantage.probe` (`probe: pcr_verify`), `scorer.login`, the operator action `mark_reverted`.
- Produces:

```go
func (m *Module) MarkReverted(ctx context.Context, host, reason string) error // reason: reenroll | operator | login_mismatch
func (m *Module) Resync(ctx context.Context, host, account string) error       // RunAuto("resync", params + trigger); ErrProposed leaves the row queued with a button
func (m *Module) PCRBack(ctx context.Context, host, account, by string) error  // typed list with the old value; no host change plan
```

`agent.reenrolled` (a reverted DC reverts every domain credential) or an operator mark turns every rotated credential of that host into `reverted` per (account, credlist) and emits `creds.reverted` (Alert). `login_mismatch` fires after three consecutive failed `scorer.login` for a `verified` row (`shortcut: no probe with the previous value; upgrade when the Kali can test the previous password`). While any row of a host is `reverted`, `Prepare` refuses scored changes on it. **Re-apply is automatic (A-AUTO):** `creds.reverted` starts `RunAuto("resync")` (`trigger` = the event ref; `act_enabled` for the host and `autonomy: {resync: auto}` in the block's `module.Actor`, S1; a repeated failure is stopped by the engine's attempt ledger for (host, object, kind), not by a `creds` guard); the plan is held to the next quiet window (`max_hold`), runs behind the scorer-mimic probe and the Kali verification and rolls back to `reverted` on a red probe; it sets no new value, so nothing is typed. If `RunAuto` returns `ErrProposed` (probe cannot run, quiet window never fits) the proposal is the button and the row stays queued. Re-apply is a transaction of type `resync` (it records that Quotient already holds the value, which is what lets CR001 pass); **PCR back** leaves the host at the old value and produces a typed list for the human.

- [ ] **Step 1: Write the failing tests**

```go
func TestReenrollMarksRowsReverted(t *testing.T) { /* two verified rows on rocky-ecom (alice L1, L2) and one on ubuntu-email: agent.reenrolled{rocky-ecom} -> both rocky rows reverted, one creds.reverted{reason reenroll, credlists [L1 L2]}, ubuntu row stable */ }
func TestRevertedBlocksScoredChangeOnHost(t *testing.T) { /* Prepare for bob on rocky-ecom refused while a reverted row exists there; allowed on ubuntu-email */ }
func TestAutoResyncSuccess(t *testing.T) { /* fake RunAuto records template "resync", params with trigger "controller:<seq>"; the fake runner reports change verified + Kali verify ok -> rows stable, a resync creds.txn with no list shown and no scored login required to unblock */ }
func TestResyncProposedWhenProbeCannotRun(t *testing.T) { /* RunAuto returns ErrProposed -> rows stay reverted, one open proposal with Reason, no host change */ }
func TestResyncRedProbeReturnsToReverted(t *testing.T) { /* node result outcome rolled_back "after-probe red: web" -> state reverted again, a creds.notice, the engine's attempt ledger (W1) counted the failed (host, resync) attempt */ }
func TestPCRBackListHasOldValueNoHostPlan(t *testing.T) { /* PCRBack -> CSV block with the previous value, no Propose, state planned->host_changed shortcut documented; reply + scorer.login -> stable */ }
func TestOperatorMarkAndDCRevertsAllDomainCreds(t *testing.T) { /* MarkReverted(host dc, operator): every domain account row reverted */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/creds/ -run 'ReenrollMarks|RevertedBlocks|AutoResync|ResyncProposed|ResyncRedProbe|PCRBack|OperatorMark' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/creds/...`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "creds: revert detection, automatic re-apply, PCR back"`

---

### Task 45: `creds`: proposals from evidence

**Files:**
- Create: `internal/creds/proposal.go`
- Test: `internal/creds/proposal_test.go`

**Interfaces:**
- Consumes: `Host.Emit` for `creds.proposal`; plain structs only (Task 47 adds the adapters from `detect.alert`, `deception.sighting`, `hunt.finding`, `chains.item`).
- Produces:

```go
type Evidence struct{ Kind string; Ref EventRefPair; Account string; Hosts []string; Source string; Rule string }
// Kind: pth_alert | dcsync | honeytoken_dump | credential_file | rotate_credential_item | interactive_login
func (m *Module) Propose(ctx context.Context, ev Evidence) (emitted bool, err error)
```

A proposal starts only from evidence of compromise or leak of a specific **scored** account (`creds.proposal`: account, credlists, hosts, reason, evidence refs, `proposed_by`); a scored account in a DCSync or `ntds.dit` chain; a scored user's interactive login from a non-scorer source (`auth_event` with `logon_type` 2, 10 or an ssh session from an address that is not in the current round's scorer sources); operators can add an account by hand. Nothing is rotated automatically; an unscored account yields no proposal; the same (account, kind) within 10 minutes is deduplicated. `Config.ProposalRules` lists the rule ids that count as `pth_alert` and `dcsync`.

- [ ] **Step 1: Write the failing tests**

```go
func TestProposalOnlyForScoredAccounts(t *testing.T) { /* evidence for an unscored svc account: no event; for alice (scored, credlists L1, L2, hosts rocky-ecom): one creds.proposal with both credlists and the evidence ref */ }
func TestInteractiveLoginFromNonScorerSource(t *testing.T) { /* auth_event success logon_type 10 for alice from 203.0.113.5 (not in round sources): proposal; same login from a scorer source: none */ }
func TestProposalDeduplicated(t *testing.T) { /* two pth_alert evidences within 10 minutes: one proposal; after 11 minutes: two */ }
func TestManualProposal(t *testing.T) { /* UI action add_proposal {account}: proposal with ProposedBy the operator and reason "operator"; unscored account refused */ }
func TestAcceptRecordsApprover(t *testing.T) { /* accepting (Prepare from the proposal) records "approved by <name>" in creds.txn.By */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/creds/ -run 'ProposalOnly|InteractiveLogin|ProposalDedup|ManualProposal|AcceptRecords' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `go test -race ./internal/creds/`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "creds: proposals from evidence of compromise"`

---

### Task 46: `creds`: T+0 sheet, unscored rotation, pages, conformance

**Files:**
- Create: `internal/creds/sheet.go`, `cmd/phylax/creds.go` (subcommand `creds sheet`), `internal/creds/ui.go`, `internal/creds/ui/{credentials,pcr}.html`, `internal/creds/conformance_test.go`, `manifest/schema/modules/creds.schema.json`
- Modify: `cmd/phylax/main.go`, `internal/module/conformance/allowed.go` (remove `creds` from `PreContract`)
- Test: `internal/creds/sheet_test.go`, `internal/creds/ui_test.go`, `cmd/phylax/creds_test.go`

**Interfaces:**
- Consumes: `DeriveBreakGlassTypeable`, the manifest accounts, `Registrar`, `creds.t0` events.
- Produces: `phylax creds sheet -manifest <dir> -secret-file <path> [-epoch N]` printing, offline, every host's `sysadmin`, root and local Administrator, the domain admins, the Palo `admin` and VyOS `vyos` accounts (the interactive admin identities; service and application accounts never appear, they rotate later by probed plan, design R4) with their derived values and an urgent-hardening step (Zerologon first on the DC) and a checkbox per step; scored users never appear; `(*Module).T0Enter(ctx, secret, by)` derives and stores the values in the vault once the controller is up (a POST action, audited); `(*Module).Tick(ctx, host, account, by)` emits `creds.t0` (an owner name is required). Unscored rotation after enrollment uses `plans/creds/unscored-rotation.yml` through `Host.Propose`; any successful admin authentication from a source other than the controller after rotation is left to `detect` rule D9. Pages: `/credentials` (inventory with masked secrets and reveal as an audited POST, open proposals, the PCR list screen with staged tick, countdown, window remaining and reply form, the transaction log, the `reverted` queue), a host-grid column "creds handled" (verified when the host's T+0 rotation is ticked and no row is `reverted` or open), a tile (open transactions, reverted rows). Controller conformance: starts locked (`degraded`, vault gap), stops cleanly, emits only declared kinds, respects its budget, survives link loss and reconfiguration.

- [ ] **Step 1: Write the failing tests**

```go
func TestSheetListsAdminsNotScoredUsers(t *testing.T) { /* reference manifest: sheet has sysadmin@linux on 3 hosts, windows Administrator, ad-admin, Palo admin, VyOS vyos; no mail-users (scored); same secret+epoch gives byte-identical output, epoch 2 differs */ }
func TestSheetValuesAreTypeable(t *testing.T) { /* every value matches ^[A-Za-z0-9-]{20,40}$ and words come from the list */ }
func TestT0EnterStoresDerivedValues(t *testing.T) { /* T0Enter with the printed secret: vault cred/<host>/<account> equals DeriveBreakGlassTypeable(...) for each; a wrong secret length is refused */ }
func TestTickNeedsOwnerName(t *testing.T) { /* Tick with by "" -> error; with name -> creds.t0 event */ }
func TestCredsControllerConformance(t *testing.T) {
	conformance.Controller(t, conformance.ControllerCase{Module: &Module{}, Config: "enabled: true\nact_enabled: false\n", Seed: nil, Now: time.Unix(1e9, 0)})
}
func TestCredentialsPageMasksSecrets(t *testing.T) { /* GET /m/creds/credentials never contains a password; reveal is POST only and audited */ }
func TestUnscoredRotationTemplate(t *testing.T) { /* Propose(unscored-rotation) for ecom-admin: embedded files updated in the same plan, health.check last; lint clean */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/creds/ ./cmd/phylax/ -run 'Sheet|T0Enter|TickNeeds|Conformance|PageMasks|UnscoredRotation' -v`. Expected: FAIL.
- [ ] **Step 3: Implement**, remove the `PreContract` entry, run `go test ./internal/module/all/ -run Schema -update`.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS, including `TestNoSiblingImports`, `TestKindTable`, `TestPreContractShrinks` with all four modules on the contract.
- [ ] **Step 5: Commit.** `git commit -am "creds: T+0 sheet, pages, conformance; creds leaves PreContract"`

---

### Task 47: Late-bound inputs (run when the W4, W5, W8 and W9 seams are merged)

**Files:**
- Create: `internal/creds/adapters.go`, `internal/scorer/adapters.go`, `internal/checks/adapters.go`
- Modify: the manifests of `creds`, `scorer` and `checks` (`Consumes`), `internal/scorer/risk.go`, `internal/checks/doctor.go`
- Test: `internal/creds/adapters_test.go`, `internal/scorer/adapters_test.go`, `internal/checks/adapters_test.go`

**Interfaces:**
- Consumes: the declared kinds `detect.alert` (W4), `deception.sighting` (W9), `hunt.finding` (W5), `chains.item` (W8), `traceback.change` (W8), `deps.graph` (W8), `inventory.probe_result` (W3, already declared); their payload structs from the producing packages' `kinds.go` read at this point (no import: decode with a local struct).
- Produces: `creds`: `evidenceFromAlert`, `evidenceFromSighting`, `evidenceFromFinding`, `evidenceFromChainItem` mapping to `Evidence` (Task 45); `scorer`: `traceback.change` joins the risk analyser (`ours` when an untagged change of ours or a failed plan node precedes the outage, `red` for an untagged change by red, `platform` for a Phylax fault); `checks`: `deps.graph` high-confidence edges join the doctor's dependency probes. Each manifest `Consumes` gains the kinds; `Manifest.Validate` and conformance check 12 pass.

- [ ] **Step 1: Write the failing tests**

```go
func TestEvidenceMapping(t *testing.T) { /* a detect.alert with rule id in ProposalRules and entities.account alice -> Evidence{pth_alert}; a deception.sighting that shows a dump -> honeytoken_dump; a hunt.finding of kind credential_file -> credential_file; chains.item kind rotate_credential -> rotate_credential_item; a chain event that is not an item is ignored */ }
func TestRiskCauseWithTraceback(t *testing.T) { /* untagged change by us before the red -> ours; untagged by red -> red; none -> unknown; identical output twice */ }
func TestDoctorUsesDepsGraph(t *testing.T) { /* a high-confidence edge web -> db in deps.graph adds a TCP probe node for db to the doctor plan; low confidence does not */ }
func TestManifestsConsumeDeclaredKinds(t *testing.T) { /* Validate nil for the three; every Consumes entry event.Lookup ok */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/creds/ ./internal/scorer/ ./internal/checks/ -run 'EvidenceMapping|RiskCauseWith|DoctorUsesDeps|ManifestsConsume' -v`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "scoring-creds: adapters for late-bound inputs"`

---

### Task 48: Lab (stronger agent or David)

Runs on the BTaP Proxmox replica (`stacks/ccdc` in btap-infra; the "ccdc27" lab) with real Quotient at commit `9000379` (admin API for ground truth), two credlists, a Kali on the VyOS side leg, one unpatched and one patched DC, and the Orange traffic generator built from `checks/flows/*.yml`. Does not block the merge.

**Files:**
- Create: `docs/impl/lab/w7-scoring-creds.md`

- [ ] **Step 1: Run the matrix tests and record each** (date, commit, VMIDs, test id, pass or fail, measured values, what was not run):
  - T14 a Quotient `event.conf` hot-adds an HTTP path, a DNS record and a custom check: a `scorer.proposal` within one round.
  - T15 two hours with Orange traffic: 100% of Quotient's checks proposed, 0 false proposals, dropped checks stale within 5 rounds.
  - T30 20 bursts with jitter, a discarded round, a team-wide missing burst: Delay and Jitter within 1 s, the dropped round is not an incident.
  - T35 PCR transaction: normal, a list entered mid-round, wrong order, a list typo, edge-character passwords, one user on two credlists: at most one failed round per affected user, verification via the Kali and the scorer's next login, rollback by a typed list of the old values.
  - T37 `BadAttempts` and scorer fingerprints with the runner address changed each round: no brute-force or lockout alert, scorer-labelled by behaviour.
  - T39 faithful checks against Quotient's results: agreement 98% or more after calibration; a Palo rule that blocks the public path but not the LAN gives `path_broken`; a newly opened port raises a `vantage.exposure_change` alert; an egress leak raises a `vantage.canary_hit` alert.
  - T49 eviction: a scorer session in flight, a session older than the measured delay, an unclassifiable session: only the old non-scorer session is evicted; before a delay is measured eviction is flag-only; 0 failed scorer rounds.
  - T50 account and credlist learning against two credlists: 100% of the accounts used in the window; service-to-credlist matches the admin API.
  - T51 revert a host and the AD after a PCR: rows `reverted`, scored changes blocked, automatic re-apply in a quiet window (button if the probe cannot run), PCR back offered.
  - New: TFTP and NTP against a Quotient configured with them; each Orange flow against the lab ecom and mail host; a doctor run for each injected failure (stopped unit, broken config, full disk, SELinux denial, dependency down); a closed scored port raises a `vantage.exposure_change` alert; the Zerologon tester against the unpatched and the patched DC; the pre-window scan; `xfreerdp /auth-only` stdin mode.
- [ ] **Step 2: Record the measurements the plan marks open:** agent and controller CPU and memory per module against the starting budgets, mailbox growth from the SMTP probe, `max_accounts_per_txn` and `max_open_txns` from the typing exercise, the verification wait against `rounds_expected`.
- [ ] **Step 3: Commit.** `git add docs/impl/lab/w7-scoring-creds.md && git commit -m "lab: W7 scoring and credentials record"`; open an issue for every failure.

---

## Self-review

**Spec coverage.** `checks`: probe library move and no scheduler (1), TFTP/NTP (8, 9, 11 only when scored), runner with allowlist and fact gate (12, 13), sealed credentials (7, 14, 18), tables and writer (15), red/latency/compare with pairing and 3 samples (16), probe-result facts, proposals, lifecycle and accept-current (17), `Env.Probe` with two users per credlist and `health.check` (19), doctor (20), Orange flows (21), pages and conformance (22). `scorer`: base, replay, no `sysadmin` (23), clock/rounds/fact/eviction cutoff (24), discovery/proposals/blocked/silent (25), account learning with BadAttempts and credlist groups (26), SLA precedence and per-round accrual (27), points at risk (28), pages/notes/health (29), old wiring removed (30). `vantage`: one module (31), scored port closed and pre-window scan (32), the `pcr_verify` probe step per credlist and RDP (33), Zerologon (34), SMB/WinRM (35), controller side with alert-class kinds (36). `creds`: engine (37), passphrase class (38), per-credlist inventory (39), eviction policy (40), templates and CR001 (41), process steps 1 to 4 (42), steps 5 and 6 (43), step 7 revert and A-AUTO (44), proposals (45), T+0, rotation, pages (46). Core gaps closed: window hold (3), manual gate, txn, PCR flag (4), step results (5), vault writer (6), sealing (7), fact data (2). Late inputs (47). Lab (48). Known bug 20 probe half: Task 19. Not built here, by design: agent-side `Env.Probe`; the `detect` pass-the-hash pack (W4); `session.terminate_predating` itself (W2).

**Step scan.** Each test step carries names and assertions with the design's values (window 30 s and confidence 0.5, `red_after` 2, 3 samples, 200 history rows, 20 to 25 characters, `verify_notice` 15 min, caps 3 and 6, BIP-39 2,048 words); code steps carry signatures and the file. Comment-bodied tests (marked `/* ... */`) are descriptions the implementer turns into the code they name, as in W1 and W3.

**Type consistency.** `RoundClock`, `CredsTxnFact`, `ProbeResultFact` (Task 1) are used by Tasks 2, 13, 17, 24, 31, 42; `EventRefPair` by Tasks 16, 25, 36, 45; `ResultEvent` by 12, 15, 16, 17; `pcr.Window`/`Engine` (37) by 42 to 44; `CredsTxnFactID` (13) by 42; `Allowlist` moves to `probe` in Task 12 and is used by 31 to 35; `vault.Writer` (6) by 42, 43; `link.SealSecret` replaces the Task 1 `plan.SealSecret` sketch (Task 7 states it; Task 1 declares it in `link`).

**Proportion.** About four modules, 48 tasks; the plan is about 1.6 times the module sections it implements, mostly tests and signatures. No function body is transcribed except the extrapolation rule (Task 2), the eviction rules (Task 40) and the lint cases (Task 41), which the signatures alone do not determine.
