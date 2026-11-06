# W12: Enrollment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move first contact and enrollment into the core package `internal/enroll` (SSH push, WinRM push, console one-liner, bootstrap handler, tokens, `set-controller`), keep W2's bundle, safe-mode and console-script behaviour, finish controller recovery (snapshot, restore, resend verification) and agent self-protection (Linux and Windows watchdog, Job Object, service DACL, stolen-key alert), and add the `agent.*` action family.

**Architecture:** `internal/enroll` owns tokens, the enrollment decision (`Authorize`), bundle writing, the bootstrap HTTP handler, the one-liner generators and the pushers; `internal/controller` constructs one `*enroll.Enroller` and calls it from `hello` and `Serve`, and passes it `EmitController` and `c.alert`. No module imports `internal/enroll` (W1's import check). The SSH client is `golang.org/x/crypto/ssh`; the NTLM and WinRM protocol code comes from the shared stateless library `internal/checks/probe`, which this plan's Task 1 extracts. Recovery adds a snapshot writer and a `serve -restore` path around the store's existing `Backup`, `Restore` and `ResumeAfterRestore`, and the controller and agent changes that make the resend actually pass through them. Self-protection is agent runtime code plus Windows-only files that CI builds and vets and the lab exercises.

**Tech Stack:** Go 1.27.2 (mise), standard library, `golang.org/x/crypto/ssh` and `golang.org/x/sys/windows` (already in `go.mod`), `filippo.io/age` (already used by `internal/vault`), real `sh` and `curl` in tests where available. No new modules in `go.mod`.

**Spec:** `phylax_design.md` (v4): "Enrollment, bootstrap and recovery" (all subsections), "Core components: Agent runtime" (self-protection and tamper detection, lifecycle), Execution engine "Actions" (the Agent family `agent.*`), Event kinds (`agent.enrolled`, `agent.reenrolled`, `enroll.*`), Known bugs (none owned), Testing and lab (T19 enrollment half, T21, T22, T23, T27, T28, T47, T48, T76 enroll half). Master plan: `docs/impl/README.md`. Code and tests it moves: `docs/impl/02-invitational.md` Tasks 2, 3 and 5. Contract names: `docs/impl/01-module-contract.md`.

## Scope and ordering (read first)

- **Built now, for 2026-11-07, together with W0, W1 and W2.** David scoped the Invitational build to W0, W1, W2 and W12; W3 to W11 come later. W12 therefore depends on nothing from W3 to W11 except what it does itself. The README row says "W7 seams (`internal/checks/probe` ntlm, winrm)"; this plan replaces that edge. **Task 1 performs exactly W7 Task 1 Steps 1 to 3 ("1A", the probe extraction)**, with W7's names, file moves, tests and commit message copied. When Task 1 merges, W7 starts at its Step 4 ("1B"); W7's plan needs one line saying 1A was done by W12 (not edited here). If W7 1A has already merged when this plan is built, skip Task 1 and run its verification step only.
- **Entry gate:** W0, W1 and W2 merged (W2 Tasks 2, 3 and 5 included: `Bundle.Safe`, `Controller.WriteBundles`, `phylax serve -bundles`, safe mode at first run, `e.sh` and `e.ps1`). Branch `v4-enrollment`, cut from `v4`.
- **Order inside the plan:** what the event needs first (Tasks 2 to 7: package, events, bootstrap handler and one-liner, SSH push, `set-controller`, CLI), then the WinRM push and the operator page (Tasks 8 to 11), then recovery (Tasks 12 and 13), then self-protection and the `agent.*` family (Tasks 14 to 18), then the lab (Task 19). Each task leaves `make build build-windows vet test race` green.
- **W2's code moves, it is not rewritten.** `Bundle.Safe`, `BundleOptions` and `WriteBundles` move from `internal/controller/bundles.go` into `internal/enroll` with their tests; the old files are deleted in the same commit. `writeBundles` in `cmd/phylax/serve.go`, `adoptBootstrap` and the `-bundles`, `-advertise`, `-bundle-ttl`, `-bundle-safe` flags keep their behaviour. `tools/invitational/e.sh` and `e.ps1` stay as W2 wrote them (they serve the Invitational kit and keep working); the signed one-liner of Task 4 is the production path. The console scripts' own text does not change, but the enrollment watch W2 Task 3a added (binary hash in `hello`, `enroll.hash_mismatch`, `enroll.no_show`, bundle removal once a host connects, alert-class `enroll.refused`) moves into `internal/enroll` with the rest of the bundle code and keeps its tests (R1, decided 2026-11-06).

## Design gaps found while writing this plan (accepted by David on 2026-11-06 as written; already written into `phylax_design.md` by the review pass, M19 to M29, so the named task checks the design text instead of writing it)

1. **Re-enrollment restarts the event chain at seq 1, and the store forbids that.** A new reservation gives a fresh VM, so its spool starts at 1 while the store holds `last_seq = N` for the host (`ReplaceAgentKey` keeps the chain). Chosen: `Store.ArchiveAgent` moves the old chain to the id `<host>~<n>` (tables `events`, `gaps`, `alerts`) and the host starts a new chain under its own name (Task 3). `shortcut: archived rows are not re-verified under their new id, upgrade when a chain-verify command exists`.
2. **The WinRM push cannot upload a 40 MB binary.** SOAP chunks are about 4 KB, so roughly 9,000 round trips. Chosen: the WinRM push runs the Windows one-liner (Task 4) through the shell, so the host downloads the binary from the bootstrap handler over the pinned connection; the host must reach the controller, which it must anyway (Task 9).
3. **Stolen-key detection has no event kind.** The design lists the check but the kind table has none for it. Chosen: `enroll.key_reuse` (alert-class, already in the table) with detail "second live session from <addr>" (Task 14). W1's table is unchanged.
4. **SFTP fallback** is moot (design S2): the SSH push no longer uploads a binary, it runs the pinned console one-liner, so there is no file transfer to fall back from (Task 5).
5. **A protected service DACL that denies the administrators group stop and delete would lock the operator out.** Chosen: deny stop, pause and delete to interactive, service and batch logons and to the `BA` group, but keep `WRITE_DAC` for `BA` so a console administrator can `sc sdset` it back (the break-glass path); the hardening and winevt content already alert on `sc sdset` (Task 16).
6. **`agent.config`, `agent.rename` and `agent.safe_mode` have a name and no behaviour in the design.** Chosen: `agent.config{memory_limit_mb}` writes `options.json` and applies it live; `agent.rename{secret}` reinstalls under the names `svcinstall.DeriveNames(secret)` through the swap helper of Task 18; `agent.safe_mode{on: true}` only (turning it off stays a signed control from the UI, because the executor refuses every action while safe mode is on).
7. **The first ack after a restore lowers the agent's ack, and the spool ignores lower acks** (`Spool.Ack` returns when `upTo <= s.ack`), so an agent never resends the events a restored controller lost. Chosen: `Spool.SetAck`, used for the first ack of a session only (Task 12).
8. **Items 3 and 5 of the self-protection list** (kernel-side watches on the agent's own files, cross-source tripwires) are `audit`, `winevt` and `hunt` content (W3, W5, later). W12 builds items 1, 2, 4 (already built), 6 and 7 (already built). Said here so the conformance check against the design does not report them missing.
9. **The snapshot triggers "after plan completion and vault change"**: plan completion has a hook in `internal/controller/plans.go`; the vault has no change hook. `shortcut: vault changes wait for the next 15-minute snapshot, upgrade when vault gets OnChange` (Task 13).

## Global Constraints

- Go 1.27.2 via mise; `CGO_ENABLED=0` for builds, `CGO_ENABLED=1` for `-race`; `make build build-windows vet test race` passes at every commit (linux/amd64 and windows/amd64 both build and vet).
- Every package ships tests; tests exercise the real code (no mock of the code under test). Fakes only at the edge the package does not own: a fake SSH server (the `x/crypto/ssh` test server pattern in `internal/checks/probe/ssh_test.go`), a fake WinRM server (the one in `probe/misc_test.go`), a recorded `curl` exit code. A test that needs privileges, Windows, `curl` or `sh` calls `t.Skip` with a reason string.
- Commits are small, one logical change, message `area: summary` (for example `enroll: move tokens and bundles from controller`). No attribution lines.
- No shelling out in the default path. Allowed: the generated one-liner is *text* the operator types; the SSH and WinRM pushers send commands to remote hosts; `agent.rename` and `agent.replace_binary` start `phylax agent swap` as a detached helper (Task 18).
- Bounded everything: pushes 30 s per host and at most 8 in parallel, bootstrap requests 8 KiB of headers and one request per connection, 20 failed token lookups per remote address per minute, uploaded binaries at most 64 MiB, snapshot files at most 64 MiB. Atomic writes through `internal/atomicfile` for state files (`tokens.json`, `revoked.json`, `known_hosts.json`, `options.json`, snapshots).
- No compatibility shims or aliases: `Controller.MintToken`, `internal/controller/tokens.go`, `bundles.go` and their tests are deleted in the commit that moves them. Renamed things are renamed everywhere in the same commit.
- `internal/enroll` imports core packages and `internal/checks/probe` only; the controller imports it; it never imports `internal/controller`. No module imports it (W1 `TestNoSiblingImports`, which Task 2 extends with a fixture).
- A token never appears in an event, a log line, an `Err` string or the UI after minting; it is stored hashed (already true) and shown once. Passwords travel as `vault.Secret` and are never logged.
- The Windows pins: the one-liner for Windows pins the controller certificate's SHA-1 thumbprint (`X509Certificate.GetCertHashString()` is the only hash .NET Framework 4.x exposes without extra code); `shortcut: SHA-1 thumbprint pin on Windows, upgrade when the minimum Windows build has GetCertHash(HashAlgorithmName)`. The Linux one-liner pins the SPKI hash (`--pinnedpubkey`).
- Times in UTC. The design is authoritative; a forced design change edits `phylax_design.md` in the same commit with the reason.
- Code style ponytail: the smallest complete change; a known limit carries `// shortcut: <limit>, <when to upgrade>`.

## Review Focus

1. **A wrong controller key must abort before any token leaves the host.** The token is part of the URL path, so a pin failure at the TLS handshake means the request line is never sent. Expected: with the real `curl` and a wrong pin, exit code 90 and zero requests logged by the handler (Task 4 `TestOneLinerWrongPinSendsNothing`).
2. **Token reuse and the wrong-host claim.** A token for host A presented by host B must not burn the token; the same (token, key) pair must succeed again after a dropped connection; a second key must be refused. These are already tested in `tokens_test.go`; they must survive the move unchanged (Task 2).
3. **A revoked key must stop working at once.** After `Revoke(host)` the old key's next hello is refused and its live session closed, while the new key with a fresh token enrolls and emits `agent.reenrolled` exactly once (Task 3 `TestRevokeThenReenroll`).
4. **Restore resend must verify, not trust.** After a restore, events at or below the snapshot's recorded sequence are accepted only if the run reaches that sequence with the recorded hash; a forged history is refused and nothing is stored (Task 12 `TestRestoreResendForgedHistoryRefused`, on top of the store's own test).
5. **Operator lockout.** A hardened service DACL, a Job Object memory cap that is too low, a `set-controller` to a wrong address and an `agent.replace_binary` of a binary that never connects must each have a recovery that does not need the agent: console `sc sdset`, a cap derived from the 80 MB base plus held budgets, the dead-man style rollback of the swap helper in 30 s, and `phylax set-controller` run again (Tasks 6, 16, 17, 18).
6. **Push failure classes.** Auth refused, no shell, no space, SELinux denial, timeout, hostname mismatch and Windows OpenSSH each produce a distinct class and a next step; a hostname mismatch must stop before a token is minted and before the one-liner runs (Task 5).

---

## File structure

| Path | Responsibility | Task |
| --- | --- | --- |
| `internal/checks/probe/` | the stateless probe library (moved from `internal/checks`); `winrmshell.go` is the exported WinRM command client | 1, 8 |
| `internal/enroll/tokens.go` | one-time tokens (moved from `internal/controller/tokens.go`), `Peek` | 2 |
| `internal/enroll/enroll.go` | `Enroller`, `Options`, `MintToken`, `Authorize`, `Announce`, `Revoke` | 2, 3 |
| `internal/enroll/bundles.go` | `BundleOptions`, `WriteBundles`, `bundleFor` (moved from `internal/controller/bundles.go`) | 2 |
| `internal/enroll/bootstrap.go` | the HTTP handler on the bootstrap ALPN, release files | 4 |
| `internal/enroll/oneliner.go` | `OneLiner`, the served install scripts | 4 |
| `internal/enroll/ssh.go`, `class.go`, `hostkeys.go`, `push.go` | SSH push, failure classes, host keys, fan-out | 5 |
| `internal/enroll/winrm.go` | WinRM push | 9 |
| `internal/enroll/reenroll.go` | `ReenrollAll` | 10 |
| `internal/store/archive.go` | `ArchiveAgent` | 3 |
| `internal/bootstrapfile/` | `Rewrite`; the agent reloads the file in `agent.go` | 6 |
| `cmd/phylax/{setcontroller,enroll}.go` | the commands | 6, 7 |
| `internal/ui/{enroll.go,templates/enroll.html}`, `internal/controller/enroll_ops.go` | the operator page and `Ops` methods | 11 |
| `internal/spool/spool.go` (`SetAck`), `internal/agent/agent.go`, `internal/controller/agent.go` | resend verification | 12 |
| `internal/controller/snapshot.go`, `cmd/phylax/serve.go` | snapshot and restore | 13 |
| `internal/agent/watchdog.go`, `internal/agent/job_windows.go`, `internal/svcinstall/dacl_windows.go` | self-protection | 15, 16 |
| `internal/actions/agent_*.go`, `cmd/phylax/swap.go`, `internal/svcinstall/restart*.go` | `agent.*` actions and the swap helper | 17, 18 |
| `docs/impl/lab/w12-enrollment.md` | lab record | 19 |

---

### Task 1: Probe extraction (W7 Task 1 Steps 1 to 3, "1A")

Do exactly what `docs/impl/07-scoring-creds.md` Task 1 Steps 1 to 3 specify. This task copies its names; if W7's text and this one differ, W7's wins and this one is corrected.

**Files:**
- Move (`git mv`, change the package clause to `probe`, fix every importer in the same commit): every non-test and test file of `internal/checks/*.go` to `internal/checks/probe/` (package `probe`; `checks.go` keeps its name). Importers to fix: `internal/controller/{checks_hub,report_test}.go`, `internal/vantage/*.go`, `internal/capture`, `internal/parsers/*` tests (find with `grep -rl '"github.com/PurdueBlueTeam/phylax/internal/checks"' --include='*.go' .`).
- Modify: `internal/checks/probe/checks.go` (constants `TFTP Type = "tftp"`, `NTP Type = "ntp"`; `Item.Skew time.Duration`; `Options.RDPAuth func(ctx context.Context, host string, port int, user, pass string) error`; `Types()` lists 18; the dispatcher reports class `config` for `tftp` and `ntp` until W7 Tasks 8 and 9)
- Create: `internal/checks/probe/nosched_test.go`

**Interfaces:**
- Consumes: the built probe library unchanged.
- Produces (exactly W7's; later tasks and W7 rely on them): package path `github.com/PurdueBlueTeam/phylax/internal/checks/probe`, package name `probe`, the 16 built exports unchanged, plus `TFTP`, `NTP`, `Item.Skew`, `Options.RDPAuth`; `Types()` returns 18.

- [ ] **Step 1: Extract the library.** `mkdir internal/checks/probe && git mv internal/checks/*.go internal/checks/probe/`, then `sed -i 's/^package checks$/package probe/' internal/checks/probe/*.go`. Fix the importers (`probe "github.com/.../internal/checks/probe"`, uses of `checks.` become `probe.`). Add the two constants, `Item.Skew`, `Options.RDPAuth`, and the `config`-class stub for the two new types. After this step `internal/checks/` holds only the `probe` directory.
- [ ] **Step 2: Test that proves the library has no scheduler.** Write `internal/checks/probe/nosched_test.go` (not skipped):

```go
func TestProbeHasNoSchedulerOrGlobals(t *testing.T) {
	// go/parser over every non-test file of this package: no package-level var of type sync.Mutex, sync.Map,
	// time.Ticker, time.Timer or chan; no `go` statement anywhere (Sweep is sequential with a gap between probes)
}
func TestTypesListsEighteen(t *testing.T) { if n := len(Types()); n != 18 { t.Fatalf("%d", n) } }
```

If the first test finds a `go` statement or a package-level mutex in today's code, that is a W7 finding: stop and report it instead of changing the library.
- [ ] **Step 3: Verify and commit.** Run: `make build build-windows vet test race`. Expected: PASS (the moved tests pass unchanged). Then `git commit -am "probe: extract internal/checks/probe as the shared stateless library"` (W7's exact message). Open the pull request for branch `v4-enrollment-probe`, merge before Task 2 starts, so W7 can rebase on it.

---

### Task 2: `internal/enroll`: tokens, bundles and the Enroller

**Files:**
- Create: `internal/enroll/{enroll.go,tokens.go,bundles.go}`, `internal/enroll/{enroll_test.go,tokens_test.go,bundles_test.go}`
- Move: `internal/controller/tokens.go` to `internal/enroll/tokens.go`, `tokens_test.go` to `internal/enroll/tokens_test.go`, `internal/controller/bundles.go` and `bundles_test.go` (W2 Task 2) to `internal/enroll/bundles.go` and `bundles_test.go`; delete the old files.
- Modify: `internal/controller/controller.go` (field `enr *enroll.Enroller`, constructed in `New`; `MintToken` deleted; `Enroller() *enroll.Enroller` added), `internal/controller/agent.go` (`authorize` stays until Task 3), `cmd/phylax/serve.go` (`writeBundles` calls `c.Enroller().WriteBundles`), `internal/module/conformance/testdata/enroll/a.go` (fixture), `internal/module/conformance/static_test.go` (one test added)
- Test: the moved tests plus `TestImportCheckRejectsEnroll`

**Interfaces:**
- Consumes: `link.Pin`, `link.Identity`, `agent.Bundle` (W2: with `Safe bool`), `agent.ParseBundle`, `atomicfile.WriteFile`, `store.Store`, W1's `(*Controller).EmitController(ctx, event.Event) (event.Event, error)` and `(*Controller).alert(host, kind, detail string)`, W1's `checkFileImports(module, path string) error` in `internal/module/conformance`.
- Produces:

```go
package enroll

var (
	ErrTokenInvalid  = errors.New("enroll: enrollment token invalid")
	ErrTokenExpired  = errors.New("enroll: enrollment token expired")
	ErrTokenUsed     = errors.New("enroll: enrollment token already used")
	ErrTokenHost     = errors.New("enroll: enrollment token is bound to a different host")
	ErrTooManyTokens = errors.New("enroll: too many live enrollment tokens")
	ErrUnknownHost   = errors.New("enroll: host is not in the manifest")
	ErrRevoked       = errors.New("enroll: key revoked")
)
const DefaultTokenTTL = 10 * time.Minute

type Tokens struct{ /* unexported, as in the moved controller.Tokens */ }
func OpenTokens(path string, maxLive int) (*Tokens, error)
func (t *Tokens) Mint(host string, ttl time.Duration) (string, error)
func (t *Tokens) Consume(tok, host string, pin link.Pin) error
// Peek returns the host a live, unconsumed token is bound to; ErrTokenInvalid, ErrTokenExpired or ErrTokenUsed otherwise.
func (t *Tokens) Peek(tok string) (host string, err error)

type Options struct {
	DataDir       string                       // tokens.json, revoked.json, known_hosts.json live here
	MaxLiveTokens int                          // 0 means 1024
	Store         *store.Store
	Identity      *link.Identity               // the controller's transport identity (pin, certificate)
	PlanKey       ed25519.PublicKey
	HostKnown     func(host string) bool       // nil allows any host
	Emit          func(ctx context.Context, e event.Event) (event.Event, error) // Controller.EmitController
	Alert         func(host, kind, detail string)                               // Controller.alert
	Connected     func(host string) bool       // true when the host's agent has a live session
	Now           func() time.Time             // nil means time.Now
}
type Enroller struct{ /* unexported */ }
func New(o Options) (*Enroller, error)
func (e *Enroller) MintToken(host string, ttl time.Duration) (string, error) // ErrUnknownHost when HostKnown says no
func (e *Enroller) Tokens() *Tokens

type BundleOptions struct {
	Controllers []string      // host:port the agent dials, required
	TTL         time.Duration // <= 0 means DefaultTokenTTL
	Safe        bool
}
// WriteBundles mints one token per host and writes <dir>/<host>.json (dir 0700, files 0600). All hosts are validated before any token is minted.
func (e *Enroller) WriteBundles(dir string, hosts []string, o BundleOptions) error
// Bundle returns the in-memory bootstrap bundle for host with a fresh token (used by the bootstrap handler and the pushers).
func (e *Enroller) Bundle(host string, o BundleOptions) (*agent.Bundle, error)
```

- [ ] **Step 1: Write the failing tests.** `git mv` the four test files and change their package clause to `enroll`; they must still pass unchanged apart from the constructor (`newCtl(t)` becomes `newEnroller(t)` in a new helper in `enroll_test.go`, which opens a real store in `t.TempDir()`, a real `link.GenerateIdentity("phylax-controller")` and an `ed25519` key). Add:

```go
func TestMintTokenUnknownHost(t *testing.T)
// Options.HostKnown = func(h string) bool { return h == "h1" }: MintToken("ghost", 0) -> errors.Is(err, ErrUnknownHost); MintToken("h1", 0) ok and Peek(tok) == "h1".
func TestPeekDoesNotConsume(t *testing.T)
// Peek twice returns "h1" both times; after Consume(tok, "h1", pin) Peek returns ErrTokenUsed; an expired token returns ErrTokenExpired (clock moved with Options.Now).
func TestBundleCarriesPinPlanKeyAndSafe(t *testing.T)
// Bundle("h1", BundleOptions{Controllers: []string{"10.0.0.5:7443"}, Safe: true}): Host "h1", Token != "", Safe true, ControllerPin == identity.Pin.String(), PlanKey == hex(PlanKey).
```

```go
// internal/module/conformance/static_test.go
func TestImportCheckRejectsEnroll(t *testing.T) {
	// testdata/enroll/a.go is "package x" importing "github.com/PurdueBlueTeam/phylax/internal/enroll"
	if err := checkFileImports("depot", "testdata/enroll/a.go"); err == nil || !strings.Contains(err.Error(), "internal/enroll") {
		t.Fatalf("a module importing internal/enroll must fail the import check: %v", err)
	}
}
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/enroll/ ./internal/module/conformance/ -run 'Mint|Peek|Bundle|TestTokens|TestWriteBundles|ImportCheckRejectsEnroll' -count=1`. Expected: FAIL to compile (`package internal/enroll is not in std`).
- [ ] **Step 3: Implement.** Move the code with package, error-prefix and receiver changes only; add `Peek` (same lookup as `Consume`, no mutation); `New` opens `tokens.json` under `DataDir`; `Bundle` assembles `agent.Bundle{Controllers, ControllerPin: o.Identity.Pin.String(), Host, Token, PlanKey, Safe}` and `WriteBundles` marshals it with `json.MarshalIndent` after validating all hosts and `Controllers` first (W2's `TestWriteBundles_UnknownHostWritesNothing` and `_RequiresController` stay). In the controller, build the Enroller in `New` after the identity and plan key exist, with `Emit: c.EmitController`, `Alert: c.alert`, `Connected: func(h string) bool { s, ok := c.AgentStatus(h); return ok && s.Connected }`; delete `tokens.go`, `bundles.go`, their tests and `Controller.MintToken`; fix every caller (`grep -rn 'MintToken\|WriteBundles\|OpenTokens' --include='*.go' .`). Write the `docs` change: `phylax_design.md` gets the "Design gaps" 1 to 3 bullets under "Enrollment" as they apply to this task (none yet) and Appendix D already lists `internal/enroll`.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS, including W2's `TestWriteBundlesForManifest` and `TestAdoptBootstrapSafe` in `cmd/phylax`.
- [ ] **Step 5: Commit.** `git commit -am "enroll: move tokens and bundles into internal/enroll"`

---

### Task 3: `Authorize`, the core events, `Revoke` and chain archiving

**Files:**
- Create: `internal/enroll/revoked.go`, `internal/store/archive.go`, `internal/store/archive_test.go`
- Modify: `internal/enroll/enroll.go`, `internal/controller/agent.go` (`hello` calls the Enroller; `authorize` deleted), `internal/controller/agent_test.go` or the existing enrollment tests (renamed callers)
- Test: `internal/enroll/authorize_test.go`

**Interfaces:**
- Consumes: Task 2's `Enroller`; `store.Store.Agent`, `Agents`, `EnrollAgent`, `ErrUnknownAgent`, `ErrKeyMismatch`; W1's `event.New[T any](kind string, v T) (Event, error)`, `event.AgentEnrolled`, `event.AgentReenrolled` (fields `Host`, `KeyHash`, `Manifest`, json `host`, `key_hash`, `manifest`), `event.EnrollRefused`, `event.EnrollKeyMismatch`, `event.EnrollKeyReuse` (fields `Host`, `Detail`); confirm the exact Go field names with `go doc ./internal/event AgentEnrolled` before writing the test.
- Produces:

```go
type Result struct{ Enrolled, Reenrolled bool } // Enrolled: first enrollment of a host; Reenrolled: a revoked host enrolled again
// Authorize decides whether pin may act as h.Host: the moved controller.authorize, plus revocation. Refusals call Options.Alert(host, kind, detail)
// with kinds "enroll.refused", "enroll.key_mismatch" and "enroll.key_reuse" (W1's alert path emits the events).
func (e *Enroller) Authorize(ctx context.Context, h *link.Hello, pin link.Pin) (Result, error)
// Announce emits agent.enrolled or agent.reenrolled through Options.Emit. Called after welcome is sent.
func (e *Enroller) Announce(ctx context.Context, host string, pin link.Pin, r Result) error
// Revoke makes host's current key unusable (persisted in revoked.json) so that the next valid token for host replaces the key; a live session is
// closed by the caller via Options.Connected/the controller's session table (Controller.RevokeAgent in this task).
func (e *Enroller) Revoke(ctx context.Context, host string) error
func (e *Enroller) Revoked(host string) bool

// internal/store/archive.go
// ArchiveAgent moves host's chain (rows of events, gaps and alerts) to the id "<host>~<n>" (n = 1 + the highest existing suffix), inserts
// that id into agents with the old key, chain head and epoch, then resets host to pubkey with last_seq 0 and an empty chain. One transaction.
func (s *Store) ArchiveAgent(ctx context.Context, host string, pubkey []byte) (archivedAs string, err error)

// internal/controller
func (c *Controller) RevokeAgent(ctx context.Context, host string) error // Enroller.Revoke, then closes the host's live session
```

- [ ] **Step 1: Write the failing tests.**

```go
func TestAuthorizeFirstEnrollment(t *testing.T) // Authorize with a valid token for "h1": Result{Enrolled: true}, store.Agent("h1") has the key; Announce emits agent.enrolled with key_hash == pin.String() and manifest "h1".
func TestAuthorizeRefusals(t *testing.T)
// table: unknown host without token -> Alert kind "enroll.refused"; wrong-host token -> ErrTokenHost and the token is still usable by the right host;
// known host with a different key -> store.ErrKeyMismatch and kind "enroll.key_mismatch"; a key enrolled as "h1" presenting a token for "h2" -> kind "enroll.key_reuse".
func TestRevokeThenReenroll(t *testing.T)
// enroll h1 with key A; ingest 5 events for h1; Revoke(h1); Authorize with key A -> errors.Is(err, ErrRevoked);
// mint a token; Authorize with key B -> Result{Reenrolled: true}; Announce emits agent.reenrolled once; Revoked("h1") is false;
// store.Agent("h1").PubKey == B and LastSeq == 0; store.Agent("h1~1").LastSeq == 5 and Count(ctx, "h1~1") == 5.
func TestArchiveAgentMovesChain(t *testing.T) // store level: events, gaps and alerts of the host appear under the new id; a fresh chain from seq 1 ingests under "h1" without ErrOutOfOrder; a second archive makes "h1~2".
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/enroll/ ./internal/store/ -run 'Authorize|Revoke|Archive' -count=1`. Expected: FAIL (`undefined: Authorize`).
- [ ] **Step 3: Implement.** Move the body of `controller.authorize` into `Authorize` (same mutex, same order of checks) with these changes: a host in `revoked.json` refuses its old key (`ErrRevoked`, kind `enroll.refused`); a revoked host with a valid token for it and a new key calls `Store.ArchiveAgent`, clears the revoked flag, and returns `Result{Reenrolled: true}`; `Result.Enrolled` for a first enrollment. `revoked.json` is a sorted JSON array written with `atomicfile`. `hello` calls `c.enr.Authorize`, sends welcome, then `c.enr.Announce(ctx, host, pin, res)`; `Welcome.Enrolled` is `res.Enrolled || res.Reenrolled`. `RevokeAgent` calls `Revoke` and closes `st.sess`. `ArchiveAgent` runs the inserts and updates in one `BeginTx` on the writer connection (the `agents` insert first, then `UPDATE events/gaps/alerts SET agent=? WHERE agent=?`, then the reset). Add the design edit to the "Re-enrollment after a reset" bullets (gap 1).
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS, including the existing `internal/e2e` enrollment tests and the `internal/controller` tests that exercised `authorize`.
- [ ] **Step 5: Commit.** `git commit -am "enroll: authorize, agent.enrolled and reenrolled events, revoke with chain archiving"`

---

### Task 4: Bootstrap handler and the console one-liner

**Files:**
- Create: `internal/enroll/{bootstrap.go,oneliner.go,bootstrap_test.go,oneliner_test.go}`
- Modify: `internal/controller/controller.go` (`Serve` sets `ServerOptions.Bootstrap`), `internal/controller/config.go` (`ReleaseDir string` json `release_dir`), `cmd/phylax/serve.go` (flag `-release-dir DIR`), `internal/enroll/enroll.go` (`Options.ReleaseDir`)
- Test: the two test files

**Interfaces:**
- Consumes: `link.Handler`, `link.Conn` (embeds `*tls.Conn`), `link.Pin.Curl()`, `Tokens.Peek`, `Enroller.Bundle`, `Options.Identity`.
- Produces:

```go
// OS names used by the generators and the handler routes.
const (OSLinux = "linux"; OSWindows = "windows")

// OneLiner returns the line to type on a console. ctl is host:port as the host sees the controller. Linux:
//   curl -sk --pinnedpubkey sha256//<b64> https://<ctl>/l/<token>|sh
// Windows (PowerShell 5.1 and later, also enables TLS 1.2 on older builds), pinning the certificate thumbprint:
//   powershell -c "[Net.ServicePointManager]::SecurityProtocol=3072;[Net.ServicePointManager]::ServerCertificateValidationCallback={param($s,$c)$c.GetCertHashString() -eq '<SHA1 hex>'};iex(iwr https://<ctl>/w/<token> -UseBasicParsing)"
func (e *Enroller) OneLiner(osName, ctl, token string) (string, error)

// Bootstrap returns the handler for connections that negotiated no phylax protocol. Routes (GET only; anything else 405 with no body):
//   /l/<token>        the Linux install script (sh)      /w/<token>        the Windows install script (PowerShell)
//   /b/<token>/linux  the Linux binary                    /b/<token>/windows the Windows binary
//   /b/<token>/boot   the host's bootstrap JSON (a fresh Bundle for the token's host, same token)
// An unknown, expired or used token is 404 with the same body for each case. The scripts embed the sha256 of the binary they download and
// refuse to install on a mismatch.
func (e *Enroller) Bootstrap() link.Handler
```

`Options.ReleaseDir` holds `phylax-linux-amd64` and `phylax-windows-amd64.exe` (the `make build` outputs, renamed by `phylax init`); their sha256 is computed once at `New` and recomputed when the file's size or mtime changes. A missing file makes its route 404 and `OneLiner` for that OS return an error naming the file.

- [ ] **Step 1: Write the failing tests.**

```go
func TestBootstrapRoutes(t *testing.T)
// real TLS: start link.NewServer with Bootstrap: e.Bootstrap() on 127.0.0.1:0; ReleaseDir has a 1 KiB fake linux binary; token for h1.
// GET /b/<tok>/linux -> 200, body equals the file, sha256 matches the one embedded in GET /l/<tok>; /b/<tok>/boot -> a JSON that agent.ParseBundle accepts with Host "h1" and Token == tok;
// unknown token and used token (Consume'd) -> 404 and identical bodies; POST /l/<tok> -> 405; a header block over 8 KiB -> connection closed with no 200.
func TestBootstrapRateLimitPerRemote(t *testing.T) // 21 unknown-token GETs from one address inside a minute: the 21st is 429 and a valid token from the same address is also refused until the minute passes (Options.Now moved).
func TestOneLinerShape(t *testing.T)
// Linux line: ASCII only, no newline, contains "--pinnedpubkey sha256//" + base64 of identity.Pin and "https://10.0.0.5:7443/l/"+tok, length == 136 (measured with a 14-character controller address and a 32-character token); Windows line: ASCII only, no newline, contains the SHA-1 thumbprint of identity.Cert.Certificate[0] in upper-case hex and "/w/"+tok, length == 294 (measured the same way). An unknown OS or empty ctl is an error.
func TestOneLinerWrongPinSendsNothing(t *testing.T) // Review Focus 1. Skips if curl is missing.
// run the real server above; hits := count of requests the handler sees (wrapped counter). Build the Linux line with the identity pin XOR-flipped in one byte.
// exec "sh","-c",line with PATH containing the real curl: exit status of curl is 90 (or the pipeline's sh gets empty input and curl's status is 90 via `set -o pipefail`-free check: run curl directly with the same args), hits == 0.
func TestOneLinerInstallsWithRealCurlAndSh(t *testing.T) // Skips if curl or sh is missing; right pin, token for h1, a fake "phylax" release file that is a shell script appending its args to $T/args;
// the served /l script is run with INSTALL_DIR=$T/inst (the script reads PHYLAX_DIR, default /opt/<derived>), final args contain "agent install --bootstrap" and the downloaded boot JSON file exists.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/enroll/ -run 'Bootstrap|OneLiner' -count=1`. Expected: FAIL (`undefined: OneLiner`).
- [ ] **Step 3: Implement.** The handler serves the single accepted connection with `net/http` through a one-shot listener (`Accept` returns the conn once, then blocks until `Close`), `http.Server{ReadHeaderTimeout: 5s, MaxHeaderBytes: 8 << 10, IdleTimeout: time.Second}` and `Connection: close` on every response, so one connection serves one request. The failed-lookup limiter is a map of remote IP to a ring of the last 20 failure times (`shortcut: in-memory, resets on restart, fine for an event`). Scripts are text/template strings in `oneliner.go`; the Linux script: `set -e`, fetch the binary and boot JSON with the same `curl -sk --pinnedpubkey` args into `${PHYLAX_DIR:-/opt/<names.Dir>}`, `sha256sum -c`, `chmod 700`, `"$d/phylax" agent install --bootstrap "$d/boot.json"`, remove `boot.json`. The Windows script does the same with `Invoke-WebRequest` under the same validation callback, `Get-FileHash`, and `& $exe agent install --bootstrap $boot`. Where install paths are randomised, the script uses `phylax agent install` defaults (W2 and `parseInstallFlags` already derive names from `--secret`; the script passes none). `Serve` passes `Bootstrap: c.enr.Bootstrap()`. Add `-release-dir` to `serve` and `release_dir` to the config.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS (the `curl` tests skip with a reason on a machine without curl).
- [ ] **Step 5: Commit.** `git commit -am "enroll: bootstrap handler and pinned console one-liners"`

---

### Task 5: SSH push

**Files:**
- Create: `internal/enroll/{class.go,hostkeys.go,ssh.go,push.go}`, `internal/enroll/{class_test.go,hostkeys_test.go,ssh_test.go,push_test.go}`
- Test: those, using an in-process SSH server built with `golang.org/x/crypto/ssh` that implements `exec` requests by running a scripted responder (a map from command prefix to stdout, stderr, exit status). This is the same fake-server pattern as `internal/checks/probe/ssh_test.go`; read it first and copy its server setup.

**Interfaces:**
- Consumes: `vault.Secret`, `svcinstall.DeriveNames`, `Enroller.MintToken`, `Enroller.OneLiner`, `Options.Connected`.
- Produces:

```go
type Class string
const (
	ClassAuth        Class = "auth_refused"
	ClassNoShell     Class = "no_shell"
	ClassNoSpace     Class = "no_space"
	ClassSELinux     Class = "selinux_denial"
	ClassTimeout     Class = "timeout"
	ClassHostname    Class = "hostname_mismatch"
	ClassWindowsSSH  Class = "windows_openssh"   // banner says Windows: use the console one-liner or WinRM
	ClassHostKey     Class = "hostkey_changed"
	ClassNoHeartbeat Class = "no_heartbeat"      // the one-liner ran and a fresh login worked, the agent never connected
	ClassInstall     Class = "install_failed"    // the one-liner (download or install) exited non-zero
)
func (c Class) Next() string // the next step the UI names for each class (one sentence each)
type PushError struct{ Host string; Class Class; Detail string }
func (e *PushError) Error() string

type Target struct {
	Host      string       // manifest name
	Addr      string       // host:port for ssh (default port 22)
	User      string
	Pass      vault.Secret
	Hostname  string       // expected `hostname -s`, normally Host
}
type SSHPusher struct {
	Controller string       // host:port as the host sees the controller; the one-liner fetches from it
	HostKeys   *HostKeys
	Timeout    time.Duration // per host, default 30s
	Dial       func(ctx context.Context, network, addr string) (net.Conn, error) // tests; nil means net.Dialer
}
func (p *SSHPusher) Push(ctx context.Context, e *Enroller, t Target) error // returns *PushError

type HostKeys struct{ /* known_hosts.json under Options.DataDir */ }
func OpenHostKeys(path string) (*HostKeys, error)
func (h *HostKeys) Callback(host string) ssh.HostKeyCallback // records on first contact, ErrHostKeyChanged on a different key later

// PushAll runs push for every target with at most `parallel` (default 8) at once and returns one result per target in input order.
type PushResult struct{ Target Target; Err error }
func PushAll(ctx context.Context, targets []Target, parallel int, push func(context.Context, Target) error) []PushResult
```

Push steps, in order: connect (password auth, `HostKeys.Callback`); class `windows_openssh` if the server version string contains `Windows`; open an exec channel; sentinel `echo PHYLAXOK` must come back (else `no_shell`); `hostname -s` equals `Target.Hostname` (else `hostname_mismatch`, **before** a token exists); at least 80 MiB free under `/opt` from `df -Pk /opt` (else `no_space`); mint the host's token with `e.MintToken(t.Host, DefaultTokenTTL)`; derive the install directory from that token (`/opt/` + `svcinstall.DeriveNames([]byte(token)).Dir`, the same derivation the bootstrap handler's served script uses); run `e.OneLiner(OSLinux, p.Controller, token)` — the pinned console line — through the shell channel; on failure with `Permission denied` and `getenforce` printing `Enforcing`, class `selinux_denial`, else `install_failed`, and in both cases remove the install directory the one-liner may have created (`rm -rf`, best effort, on its own 5 s deadline); a fresh second login must succeed (else `auth_refused`); finally wait up to the remaining timeout for `Options.Connected(host)` (else `no_heartbeat`). **The push uploads nothing (design S2):** the host downloads the binary and the bootstrap config from the bootstrap handler over the pinned connection and the one-liner checks the hash, so there is no base64 upload, no remote hash check over SSH and no name-secret file.

- [ ] **Step 1: Write the failing tests.**

```go
func TestSSHPushRunsOneLiner(t *testing.T)
// fake server accepts user "root"/"pw", answers `echo PHYLAXOK`, `hostname -s` -> "h1", `df -Pk` -> plenty, records every exec command. Push succeeds;
// exactly one command contains "|sh" and it equals e.OneLiner(OSLinux, ctl, token) for the live h1 token in it (Peek). No command contains base64,
// "agent install", "--bootstrap", sha256sum, rm -rf or the password. Connected(h1) is made true by the fake when it runs the one-liner.
func TestSSHPushFailedInstallRemovesDir(t *testing.T) // the one-liner exits 1 ("boom"): class install_failed; the last command is `rm -rf '/opt/<DeriveNames(token).Dir>'`; detail says removed, or NOT removed when rm exits 1.
func TestSSHPushHostnameMismatchMintsNothing(t *testing.T) // `hostname -s` -> "other": *PushError Class hostname_mismatch; no one-liner command recorded; no token minted (Tokens live count unchanged).
func TestSSHPushClasses(t *testing.T) // table: wrong password -> auth_refused; server never answers the sentinel (Timeout 300ms) -> timeout; sentinel missing -> no_shell; df reports 1 MiB -> no_space;
// the one-liner exits 1 with "Permission denied" and getenforce -> "Enforcing" -> selinux_denial; version string "SSH-2.0-OpenSSH_for_Windows_8.1" -> windows_openssh; Connected stays false -> no_heartbeat. Every class has a non-empty Next().
func TestHostKeysRecordThenCheck(t *testing.T) // first contact records; same key later passes; a different key later -> ErrHostKeyChanged and PushError Class hostkey_changed; the file is mode 0600 and survives reopen.
func TestSSHPushHostKeyChanged(t *testing.T) // a key recorded at an earlier contact and a different one now: PushError Class hostkey_changed and one Alert("h1", "enroll.hostkey_changed", ...).
func TestPushAllBounded(t *testing.T) // 20 targets, parallel 4, a push func that tracks max concurrency: max <= 4, results in input order, one failure does not stop the others.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/enroll/ -run 'SSHPush|HostKeys|PushAll' -count=1`. Expected: FAIL (`undefined: SSHPusher`).
- [ ] **Step 3: Implement** in the order of the push steps; one `ssh.Session` per command; every read of command output is capped at 64 KiB; the per-host deadline is `context.WithTimeout`. The token is minted only after the hostname and free-space checks pass, and its value names the install directory the cleanup removes. `runSSH` has no stdin: nothing is uploaded.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "enroll: ssh push runs the pinned console one-liner"`

---

### Task 6: `phylax set-controller` and an agent that follows the bootstrap file

**Files:**
- Create: `internal/bootstrapfile/bootstrapfile.go`, `internal/bootstrapfile/bootstrapfile_test.go`, `cmd/phylax/setcontroller.go`, `cmd/phylax/setcontroller_test.go`, `internal/e2e/setcontroller_test.go`
- Modify: `internal/agent/agent.go` (`session` reloads the bundle before each dial)

**Interfaces:**
- Consumes: `agent.Layout`, `Layout.LoadBundle`, `Layout.SaveBundle`, `agent.Bundle`, `link.ParsePin`.
- Produces:

```go
// package bootstrapfile is a leaf (standard library and internal/atomicfile and internal/link only), so internal/actions can use it without importing internal/agent.
// Rewrite replaces the controller addresses (and the pin when pin != "") in the bootstrap JSON file at path, keeping every other field byte-for-byte
// (it edits the raw JSON object, so fields it does not know survive). Atomic. Addresses are validated like Bundle.Validate. It never changes anything else.
func Rewrite(path string, controllers []string, pin string) error
// the agent re-reads bootstrap.json before every dial when its size or mtime changed (unexported reloadBundle on *Agent).
```

CLI: `phylax set-controller [-state-dir DIR] [-pin HEX] ADDRESS[,ADDRESS...]` (default state dir `defaultStateDir()`); prints `controllers: <list>` and the line `the agent follows the new address on its next reconnect (within seconds)`. The Palo NAT stays manual (design: "Nothing is automatic").

- [ ] **Step 1: Write the failing tests.**

```go
func TestRewriteKeepsEverythingElse(t *testing.T) // save a bundle with token, roles, plan key, safe plus an unknown field: Rewrite(l.Bootstrap(), []string{"10.1.1.1:7443","10.1.1.2:7443"}, "") -> LoadBundle: Controllers replaced, every other field byte-equal to before; pin unchanged.
func TestRewriteRejectsBadInput(t *testing.T) // "nonsense", "10.0.0.1" (no port), empty list, a pin that is not 64 hex: error and the file is unchanged (compare bytes).
func TestSetControllerCommand(t *testing.T) // cmd/phylax: commands["set-controller"].run(ctx, []string{"-state-dir", dir, "10.9.9.9:7443"}) rewrites the file; missing address -> error mentioning "usage".
func TestAgentFollowsSetController(t *testing.T) // e2e (read internal/e2e/e2e_test.go harness first): controller A on port P1 and one agent enrolled; start a second controller B on the same data dir copy
// (stop A, start B on another port with the same identity, which is how an address change looks); run bootstrapfile.Rewrite(layout.Bootstrap(), []string{B addr}, ""); eventually (10 s) AgentStatus(host).Connected on B with no re-enrollment (token not re-used: the bundle has Token "").
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/bootstrapfile/ ./internal/agent/ ./cmd/phylax/ ./internal/e2e/ -run 'Rewrite|SetController' -count=1`. Expected: FAIL (`undefined: Rewrite`).
- [ ] **Step 3: Implement.** `reloadBundle`: `os.Stat(l.Bootstrap())`, compare size and mtime with the last loaded; if different, `LoadBundle` and swap `a.bundle` under `a.mu`, reset `a.attempt`. A bundle that fails to parse keeps the old one and logs once. Register the command in `cmd/phylax/setcontroller.go` with `register(command{name: "set-controller", ...})`. The design line "run on each affected host's console" is unchanged.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "agent: set-controller rewrites the bootstrap controllers; the agent follows the file"`

---

### Task 7: `phylax enroll` for the operator at the event

**Files:**
- Create: `cmd/phylax/enroll.go`, `cmd/phylax/enroll_test.go`
- Modify: `internal/controller/controller.go` (none beyond Task 2) and `cmd/phylax/serve.go` (an optional `-ssh-binary PATH` is not needed: the pusher reads the release dir)

**Interfaces:**
- Consumes: `Enroller.OneLiner`, `SSHPusher.Push`, `PushAll`, the controller's data dir and vault (`openVault`), `manifest.LoadDir`.
- Produces `phylax enroll <subcommand>` run against the controller's data dir (the same flags `-config` or `-data-dir` as `serve`, read only for identity, tokens and store; it works while `serve` runs because tokens are read and written through the same file with `atomicfile`; `shortcut: two processes share tokens.json, last writer wins on a race, upgrade when enroll talks to the running controller over the UI port`):
  - `enroll line -os linux|windows -ctl HOST:PORT HOST` prints the one-liner for a manifest host (mints a token).
  - `enroll push -ctl HOST:PORT [-parallel N] HOST...` SSH-pushes the named hosts (Linux), credentials from the vault secret named by the manifest host's `default_credentials` field read as `user:password`; prints one line per host `HOST ok` or `HOST FAIL <class>: <next step>` and exits non-zero if any failed.
  - `enroll status` prints each manifest host with `enrolled`, `connected`, `revoked`.

- [ ] **Step 1: Write the failing tests.**

```go
func TestEnrollLinePrintsPinnedLine(t *testing.T) // temp data dir with a real controller identity (controller.New), run `enroll line -os linux -ctl 10.0.0.5:7443 h1` capturing stdout: one line starting "curl -sk --pinnedpubkey sha256//", ending with "|sh", token not stored in clear (tokens.json does not contain it).
func TestEnrollPushAgainstFakeSSH(t *testing.T) // reuse the fake SSH server helper from the enroll package tests (exported in enroll/enrolltest via a _test-only file is not allowed across packages: copy the 40-line helper into cmd/phylax/sshfake_test.go);
// one host succeeds, one has a wrong password: stdout has "h1 ok" and "h2 FAIL auth_refused:", exit error non-nil.
func TestEnrollStatus(t *testing.T) // two hosts in a manifest, one enrolled in the store: the table shows enrolled true/false.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./cmd/phylax/ -run 'Enroll' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** the three subcommands as thin wrappers over Tasks 4 and 5. Print nothing secret: the one-liner contains a token by design and is the one thing the command prints; the pusher output never prints a password.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "enroll: phylax enroll line, push and status"`

---

### Task 8: probe: an exported WinRM command client

**Files:**
- Create: `internal/checks/probe/winrmshell.go`, `internal/checks/probe/winrmshell_test.go`
- Test: the fake WinRM server in `internal/checks/probe/misc_test.go` (`TestWinRM`; read it and reuse its handler; extend it to answer the `Delete` action and a second command)

**Interfaces:**
- Consumes: the unexported `winrmClient`, `ntlmClient`, `soapEnvelope`, the regexes and `utf16le` in the same package.
- Produces:

```go
var ErrWinRMAuth = errors.New("probe: winrm authentication refused")

type WinRMConfig struct {
	Host string
	Port int       // 5985 (http) or 5986 (https)
	TLS  bool
	User string    // "user" or "DOMAIN\user"
	Pass string
	Dial func(ctx context.Context, network, addr string) (net.Conn, error) // nil means a net.Dialer
}
type WinRMShell struct{ /* unexported: client, shell id, url */ }
// OpenWinRM connects with NTLM (message-level encryption is not used: Basic and AllowUnencrypted are never used; TLS is the transport guarantee on 5986,
// and on 5985 NTLM signing is requested as in the scorer-mimic probe). It creates a shell. ErrWinRMAuth on a 401 without a challenge or a refused AUTHENTICATE.
func OpenWinRM(ctx context.Context, c WinRMConfig) (*WinRMShell, error)
// Run executes a PowerShell script (powershell.exe -EncodedCommand) and returns its output; err is non-nil only for transport or protocol failure,
// a non-zero exit is reported in exit. Output is capped at 1 MiB per stream.
func (s *WinRMShell) Run(ctx context.Context, script string) (stdout, stderr string, exit int, err error)
func (s *WinRMShell) Close(ctx context.Context) error
```

`shortcut: NTLM without message-level encryption on 5985 (the probe's behaviour), upgrade when a target requires AllowUnencrypted=false enforcement of sealing`. Design says "NTLM and message encryption": the existing client has signing key support (`signingKey`) but no sealing; if the lab (Task 19) finds a Server 2019 default config refusing unencrypted SOAP over 5985, sealing becomes a follow-up in this file. State this in the lab record.

- [ ] **Step 1: Write the failing tests.**

```go
func TestOpenWinRMRunsScript(t *testing.T) // fake server accepts user "admin"/"pw"; Run(ctx, "hostname") returns stdout "WIN-TEST\r\n", exit 0; the server saw the script as powershell.exe -EncodedCommand whose UTF-16LE base64 decodes to "hostname".
func TestOpenWinRMBadPassword(t *testing.T) // errors.Is(err, ErrWinRMAuth).
func TestWinRMRunNonZeroExit(t *testing.T)  // server answers ExitCode 3 with stderr "boom": exit 3, stderr "boom", err nil.
func TestWinRMOutputCapped(t *testing.T)    // server streams 3 MiB: stdout length == 1 MiB.
func TestWinRMCloseDeletesShell(t *testing.T) // the server saw a Delete for the shell id.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/checks/probe/ -run 'OpenWinRM|WinRMRun|WinRMOutput|WinRMClose' -count=1`. Expected: FAIL (`undefined: OpenWinRM`).
- [ ] **Step 3: Implement** by building a `winrmClient` literal as `probeWinRM` does and reusing its create, command, receive and delete envelopes; do not change `probeWinRM`. Receive loop: at most 200 iterations (an install can take minutes; each Receive long-polls up to the `OperationTimeout` PT60S). Add the `TestProbeHasNoSchedulerOrGlobals` rules still hold (no goroutine, no global).
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "probe: exported WinRM command client for the enrollment push"`

---

### Task 9: WinRM push

**Files:**
- Create: `internal/enroll/winrm.go`, `internal/enroll/winrm_test.go`
- Modify: `internal/enroll/class.go` (adds classes), `cmd/phylax/enroll.go` (`push` picks the pusher by the host's OS family)

**Interfaces:**
- Consumes: `probe.OpenWinRM`, `Enroller.OneLiner(OSWindows, ...)`, `Enroller.Bundle`, `Options.Connected`, `PushError`, `Class`.
- Produces:

```go
const ClassWinRMUnreachable Class = "winrm_unreachable" // connect refused or no route: console one-liner
type WinRMTarget struct{ Target; Port int; TLS bool; Domain string }
type WinRMPusher struct {
	Controller string        // host:port the host dials for the bootstrap download and the link
	Timeout    time.Duration // per host, default 120s (the download is a few seconds, the install a few more)
	Dial       func(ctx context.Context, network, addr string) (net.Conn, error)
}
// Push opens WinRM, checks `$env:COMPUTERNAME` against Hostname (stops before running the install on a mismatch), runs the Windows one-liner's script
// (the line without the leading `powershell -c`), and waits for Options.Connected(host).
func (p *WinRMPusher) Push(ctx context.Context, e *Enroller, t WinRMTarget) error
```

The token for the script is minted after the hostname check, as in Task 5.

- [ ] **Step 1: Write the failing tests.**

```go
func TestWinRMPushRunsInstallScript(t *testing.T) // fake WinRM server (the Task 8 helper, copied into this package's test file): COMPUTERNAME -> "h1"; the second script it receives contains "https://10.0.0.5:7443/w/" + a live token and the controller certificate thumbprint; Connected flips true; Push returns nil.
func TestWinRMPushHostnameMismatch(t *testing.T) // COMPUTERNAME "OTHER": Class hostname_mismatch; the server received exactly one script; no live token.
func TestWinRMPushClasses(t *testing.T) // bad password -> auth_refused; closed port -> winrm_unreachable with Next() naming the console one-liner; no heartbeat within Timeout (200ms) -> no_heartbeat.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/enroll/ -run WinRMPush -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement.** The script text is the Windows one-liner with the `powershell -c "..."` wrapper stripped by a shared helper `windowsScript(ctl, token)` in `oneliner.go` that Task 4's generator also calls (refactor in this task, with Task 4's tests proving the line is unchanged). `phylax enroll push` chooses the pusher by `manifest.Host.OS.Family == "windows"` and reads the credential from the vault the same way.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "enroll: winrm push runs the pinned install script"`

---

### Task 10: Re-enroll all, in dependency order

**Files:**
- Create: `internal/enroll/reenroll.go`, `internal/enroll/reenroll_test.go`
- Modify: `cmd/phylax/enroll.go` (`reenroll-all`)

**Interfaces:**
- Consumes: `Enroller.Revoke`, `Revoked`, `PushAll`, `SSHPusher`, `WinRMPusher`, `manifest.Manifest.Hosts`, `manifest.Host.Roles`, `manifest.Host.DomainMember`.
- Produces:

```go
// ReenrollOrder returns the manifest hosts in dependency order: every host with the domain_controller role first, then the hosts that are not
// domain members, then domain members, each group sorted by name. A pure function.
func ReenrollOrder(m *manifest.Manifest) []string
type Step struct{ Host, Method string } // Method: "ssh", "winrm" or "console"
// ReenrollAll revokes every listed host's key (in order) and pushes each one with its method, group by group (a group starts only when the previous
// group's pushes returned). Hosts whose push fails are returned with their PushError; they stay revoked, so the console one-liner can finish them.
func (e *Enroller) ReenrollAll(ctx context.Context, order []string, method func(host string) string, push func(ctx context.Context, host string) error) []PushResult
```

`phylax enroll reenroll-all -ctl HOST:PORT [-yes]` prints the order and the method per host and runs it only with `-yes`, because it is destructive to the running agents' keys. The command prints the reminder "repeat the T+0 console phase first (design: Re-enrollment after a reset)".

- [ ] **Step 1: Write the failing tests.**

```go
func TestReenrollOrder(t *testing.T) // the reference manifest (manifest.LoadDir("../../manifest/2027")): "ad" (domain_controller) is first; every host with DomainMember "ad" comes after every host without one; the order is stable across two calls.
func TestReenrollAllRevokesInOrderAndReportsFailures(t *testing.T) // three enrolled hosts, push func records the call order and fails for "h2": result has one error for h2; all three Revoked; h1 and h3 pushed after their revoke; a later successful Authorize for h2 with a fresh token still works.
func TestReenrollAllGroupBarrier(t *testing.T) // a slow DC push (50 ms) finishes before any member push starts (timestamps).
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/enroll/ -run Reenroll -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Revoke` of an agent whose session is live closes it through `Options.Connected`'s sibling `Options.Disconnect func(host string)` (add the field here; the controller supplies a closure over `RevokeAgent`'s session close). Add the field to `Options` and the constructor in the controller.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "enroll: re-enroll all in dependency order"`

---

### Task 11: Operator page: tokens, one-liners, pushes (T28 CI half)

**Files:**
- Create: `internal/controller/enroll_ops.go`, `internal/ui/enroll.go`, `internal/ui/templates/enroll.html`, `internal/ui/enroll_test.go`
- Modify: `internal/ui/ops.go` (`Ops` interface), `internal/ui/ui.go` (routes), `internal/ui/ops_test.go` (the fake backend and `opsPosts`), `internal/controller/webops.go`

**Interfaces:**
- Consumes: the `Ops` pattern in `internal/ui/ops.go` (read `opsEnv`, `loggedIn`, the CSRF and Origin checks, and `TestOpsRoutesRequireAuthAndCSRF`), `Enroller.OneLiner`, `Enroller.ReenrollAll`.
- Produces:

```go
// internal/ui/ops.go
type EnrollRow struct{ Host, State string } // State: not_enrolled | enrolled | revoked; Connected bool
type Ops interface { /* existing */
	EnrollHosts(ctx context.Context) ([]EnrollRow, error)
	// EnrollLine mints a token for host and returns the one-liner (shown once). osName is "linux" or "windows".
	EnrollLine(ctx context.Context, host, osName, by string) (string, error)
	// EnrollPush pushes host with the method that matches its OS (SSH or WinRM), using the manifest credential. Returns the push class on failure.
	EnrollPush(ctx context.Context, host, by string) error
	ReenrollAll(ctx context.Context, by string) error
}
```

Routes (all behind the existing session, CSRF and Origin checks): `GET /enroll`, `POST /enroll/<host>/line`, `POST /enroll/<host>/push`, `POST /enroll/reenroll-all` (requires `confirm=REENROLL`). Token minting is reachable **only** from these POST routes (T28: "token minting only from the UI").

- [ ] **Step 1: Write the failing tests.**

```go
func TestEnrollRoutesRequireAuthAndCSRF(t *testing.T) // add "/enroll/h1/line", "/enroll/h1/push", "/enroll/reenroll-all" to opsPosts and "/enroll" to the anonymous GET list of TestOpsRoutesRequireAuthAndCSRF; the fake backend must record no call.
func TestEnrollLineShownOnceAndAudited(t *testing.T) // logged in: POST /enroll/h1/line returns 200 with the line in the body; ui_audit has a row with the operator name, action "enroll.line", host "h1", and NOT the token; a second GET /enroll does not contain the token.
func TestReenrollAllNeedsConfirmation(t *testing.T) // POST without confirm=REENROLL -> 400 and the fake backend not called; with it -> called once.
func TestAgentPortServesOnlyAgentsAndBootstrap(t *testing.T) // T28 agent-port half, controller level (internal/controller): a TLS client with no certificate and ALPN "phylax/agent" is refused in the handshake; with no ALPN, GET / -> 404, GET /e -> 404, a path under /b/ with a bad token -> 404, POST anything -> 405; nothing on this port mints a token (tokens.json byte-identical before and after).
func TestEveryUIPostRouteRequiresSession(t *testing.T) // walks the registered routes of the UI mux (httptest) and asserts that each one answers 303/401 to an anonymous request; fails when a new route is added without the guard.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/ui/ ./internal/controller/ -run 'Enroll|EveryUIPost|AgentPortServes' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement.** `WebOps` methods in `enroll_ops.go` build the pushers from the controller's configured release dir, advertised address (`Config.Advertise`, new field `advertise`, the address agents use; `serve -advertise` already exists from W2 for bundles and now also fills this) and the vault. The template lists the hosts, shows the line in a `<pre>`, and states the push class and next step on failure. Add the design line under "First contact": token minting is only reachable from the UI and the CLI run by someone with the controller's data directory.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "ui: enrollment page; tests for T28 routes"`

---

### Task 12: Restore resend verification

**Files:**
- Modify: `internal/spool/spool.go` (`SetAck`), `internal/agent/agent.go` (first ack of a session), `internal/controller/agent.go` (`events` verification path), `internal/store/store.go` (`Agent` already exposes `RestoredSeq`, `RestoredHash`)
- Create: `internal/spool/setack_test.go`, `internal/e2e/restore_test.go`
- Test: also extends `internal/store/store_test.go` only if a missing case appears

**Interfaces:**
- Consumes: `store.Restore`, `store.Store.Backup(ctx, dest, BackupOptions{StateOnly: true})`, `store.Store.ResumeAfterRestore`, `store.ErrRestoreMismatch`, `link.Session.WaitFirstAck`.
- Produces:

```go
// internal/spool: SetAck sets the acknowledged sequence to upTo (clamped to the head) even when it is lower than the current one, and rewinds
// the send cursor to it. Called only for the first ack of a session: a restored controller really has less than the agent believes.
func (s *Spool) SetAck(upTo uint64) error
```

Agent: in `session()`, `WaitFirstAck` returns the ack sequence; replace `a.sp.Rewind()` by `a.sp.SetAck(firstAck)` (then `Rewind`). The later `ackPump` keeps using `Ack` (monotonic).

Controller `events()`, per session state `st.verify` (true when the agent row has `RestoredSeq > 0` and `st.acked == RestoredSeq`, read in `hello`): (a) events with `Seq <= st.acked` are passed in order to `Store.Ingest` (which backfills them only if the run reaches `RestoredSeq` with `RestoredHash`) instead of being skipped; (b) when the lowest event of the first batch has `Seq > st.acked+1` and it is not a gap record, call `Store.ResumeAfterRestore(ctx, host, lowest)` and set `st.acked = lowest.Seq-1` before buffering, so the missing range is recorded as a gap with reason "controller restored". On `ErrRestoreMismatch` the existing drain error path ends the session after `c.alert(host, "store.chain_error", err.Error())`.

- [ ] **Step 1: Write the failing tests.**

```go
// spool
func TestSetAckLowersAndResends(t *testing.T) // append 20 events, Ack(20); SetAck(12): Stats().AckSeq == 12 and ReadBatch(100, 1<<20) returns seq 13..20; SetAck(99) clamps to 20.
// internal/e2e/restore_test.go (T23 CI half; harness from e2e_test.go and restart_test.go)
func TestRestoreResendBackfillsAndExtends(t *testing.T)
// controller C1, one agent h1 emitting 30 numbered events; snapshot after seq 12 (StateOnly) ; let it reach 30; stop C1; store.Restore into a new data dir (copy identity, plan.key, tokens);
// start C2 on it, same agent state dir. Eventually: Count(h1) == 30 (backfilled 1..12 verified, 13..30 accepted), no gap rows, store.Epochs has a second epoch with the restore reason, agent.start is not duplicated.
func TestRestoreResendSpoolTrimmedRecordsGap(t *testing.T)
// same, but the agent's spool is cut so it retains only seq 21..30 (agent test option: spool MaxBytes small enough, or delete the first segments before start — read internal/spool/options): after reconnect Gaps(h1) has exactly {From 13, To 20, Reason "controller restored"} and Count includes 21..30.
func TestRestoreResendForgedHistoryRefused(t *testing.T)
// C2 restored from the snapshot at seq 12; a second client connects with the real h1 identity but its spool holds a different history (written by a second agent state dir seeded with other events, same key):
// Count(h1) stays 0 (state-only snapshot), the controller raised store.chain_error, the session is closed, and the honest agent (same key, real spool) then still succeeds.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/spool/ ./internal/e2e/ -run 'SetAck|RestoreResend' -count=1`. Expected: FAIL (`undefined: SetAck`, then the e2e cases fail because the agent never resends below its old ack).
- [ ] **Step 3: Implement** the three changes above. Keep `events()`'s existing duplicate skip for the normal (not `st.verify`) path. After the first successful ingest that moves past `RestoredSeq`, clear `st.verify`.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS. Update the design's last sentence of "Controller recovery" ("The resend verification is not finished") to say it is built, with the tests named.
- [ ] **Step 5: Commit.** `git commit -am "recovery: restore resend verification end to end"`

---

### Task 12a: The restore epoch is `max(snapshot, reported)+1` (R7)

`store.Restore` raises the epoch by one from the snapshot's epoch E, so a second restore from the same or an older snapshot produces E+1 again, and agents that accepted `(E+1, s)` from the first restored controller reject everything from the second. The design (Controller recovery): `hello` carries the agent's highest accepted epoch, the restored controller uses `max(snapshot epoch, all reported)+1`, and until every enrolled agent has reported the controller signs nothing and shows "restored: waiting for N agents".

**Files:**
- Modify: `internal/link/message.go` (`Hello.Epoch`), `internal/agent/agent.go` (send `plan.FileSeqStore.Load().Epoch`), `internal/store/backup.go` (`RaiseEpoch`), `internal/controller/agent.go` (record a report in `hello`), `internal/controller/restorewait.go` (new), `docs/protocol.md`
- Test: `internal/store/epoch_test.go`, `internal/controller/restorewait_test.go`, `internal/e2e/restore_test.go` (extends Task 12)

**Interfaces:**
- Consumes: `store.Restore`, `Store.Epoch`, `Store.Epochs`, agent rows with `RestoredSeq > 0`, the signing path (`Controller.sign*`, `PlanSigner`).
- Produces:

```go
// link.Hello gains:
Epoch uint64 `json:"epoch,omitempty"` // highest epoch of a signed config or step this agent has accepted (its sequence mark)

// package store
// RaiseEpoch sets the epoch to max(current, atLeast), appending an epochs row with reason when it rose. It returns the epoch in force.
func (s *Store) RaiseEpoch(ctx context.Context, atLeast uint64, reason string) (uint64, error)

// package controller
// SigningReady is false after a restore until every agent enrolled in the snapshot has sent a hello (reporting its epoch) or an operator
// released the wait. Plan signing, facts and deadman_confirm check it; a refused call says "restored: waiting for N agents".
func (c *Controller) SigningReady() (ready bool, waiting []string)
// ReleaseRestoreWait ends the wait for the named agents (or all when none are named), recording the epoch in force and the operator in the audit trail.
func (c *Controller) ReleaseRestoreWait(ctx context.Context, by string, hosts ...string) error
```

Rules: on a `hello` with `Epoch >= current`, the controller calls `RaiseEpoch(ctx, h.Epoch+1, "agent reported epoch N")`; the wait set is the agents with `RestoredSeq > 0` at start; a hello removes its host from the set. The wait is held in memory plus the `restore_wait` kv key, so a controller restart during the wait keeps waiting. A normal start (no restore) has an empty set and `SigningReady` is true. `shortcut: a controller restored twice at once is not detected, upgrade if two controllers could ever hold one snapshot`.

- [ ] **Step 1: Write the failing tests:**

```go
func TestRaiseEpoch(t *testing.T) {
	// st at epoch 3: RaiseEpoch(2) returns 3 and adds no row; RaiseEpoch(7, "r") returns 7, Epoch() == 7, Epochs() ends with {7, "r"}
}
func TestHelloCarriesEpoch(t *testing.T) {
	// the in-package test agent with a sequence mark (epoch 5, seq 9): its hello has Epoch == 5
}
func TestRestoreTwiceFromSameSnapshot(t *testing.T) {
	// e2e: snapshot at epoch 1; restore #1 -> epoch 2; agent h1 accepts a step signed at (2, 1); stop; restore #2 from the same snapshot -> store epoch 2 again;
	// h1 reconnects with hello Epoch 2 -> controller epoch raised to 3; a step signed after SigningReady is (3, n) and h1 accepts it;
	// without the raise the agent refuses it (pin the failure first)
}
func TestSigningWaitsForAgents(t *testing.T) {
	// restored controller with agents h1 and h2 in the snapshot; before any hello SigningReady() is false with waiting [h1 h2]; a plan approve is refused
	// with "restored: waiting for 2 agents"; after both hellos it is true; ReleaseRestoreWait(ctx, "driver", "h2") releases only h2 and writes an audit entry
}
func TestRestoreWaitSurvivesRestart(t *testing.T) { /* stop and start the controller on the same data dir mid-wait: still waiting for the same hosts */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/store/ ./internal/controller/ ./internal/e2e/ -run 'RaiseEpoch|HelloCarriesEpoch|RestoreTwice|SigningWaits|RestoreWait' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "recovery: restore epoch from agent reports, signing waits for agents"`

---

### Task 13: Controller snapshot and `serve -restore`

**Files:**
- Create: `internal/controller/snapshot.go`, `internal/controller/snapshot_test.go`
- Modify: `internal/controller/config.go` (`SnapshotDirs []string` json `snapshot_dirs`, `SnapshotInterval Duration` json `snapshot_interval` default `15m`), `internal/controller/plans.go` (call `c.snapshotSoon()` when a plan reaches a terminal state), `internal/enroll/enroll.go` (`Options.OnEnrolled func()`, called by `Announce`), `cmd/phylax/serve.go` (`-restore FILE`, `-restore-reason`, passphrase from `PHYLAX_VAULT_PASSPHRASE` before it is cleared)

**Interfaces:**
- Consumes: `store.Store.Backup`, `store.Restore`, `filippo.io/age` scrypt recipient and identity (`age.NewScryptRecipient`, `age.NewScryptIdentity`), `atomicfile.Write`.
- Produces:

```go
// WriteSnapshot writes <dir>/phylax-snapshot-<UTC yyyymmddThhmmssZ>.age: an age (scrypt) encrypted tar holding phylax.db (StateOnly backup),
// identity.pem, plan.key, tokens.json, revoked.json, known_hosts.json and the vault file when Config has one. Keeps the newest 8 files in dir.
func (c *Controller) WriteSnapshot(ctx context.Context, dir string, pass []byte) (path string, err error)
// RunSnapshots writes to every SnapshotDirs entry every SnapshotInterval and again (debounced to one per 30 s) after enrollment and plan completion.
// It does nothing while pass is empty ("locked": snapshots need the operator passphrase).
func (c *Controller) RunSnapshots(ctx context.Context, pass func() []byte)
// RestoreSnapshot decrypts file with pass, refuses a data dir that already has phylax.db unless force, unpacks the files, and installs phylax.db with
// store.Restore(ctx, snapshotDB, dbPath, reason) (new epoch). Max snapshot size 64 MiB; tar entry names are checked (no path separators).
func RestoreSnapshot(ctx context.Context, file string, pass []byte, dataDir, reason string, force bool) error
```

`shortcut: snapshot targets are local directories (a mounted share or the backup box path), upgrade to copying over ssh when W10's backup transport exists`; `shortcut: vault changes wait for the next scheduled snapshot, upgrade when vault gets OnChange` (gap 9).

- [ ] **Step 1: Write the failing tests.**

```go
func TestSnapshotRoundTrip(t *testing.T) // controller with 2 enrolled agents and 10 events each; WriteSnapshot -> file name pattern, mode 0600; wrong passphrase to RestoreSnapshot errors; right one into a new dir: phylax.db has the agents with their last_seq and last_hash and ZERO events, identity.pem and plan.key bytes equal the originals, tokens.json present; a new controller.New on that dir has the same Pin() and PlanPublicKey().
func TestSnapshotKeepsNewestEight(t *testing.T) // 10 writes with the clock moved: 8 files remain, the newest 8.
func TestSnapshotRefusesExistingDataDir(t *testing.T) // RestoreSnapshot without force into a dir with phylax.db -> error naming the file; with force proceeds.
func TestSnapshotRejectsPathTraversal(t *testing.T) // a hand-built tar with entry "../x" or "/etc/x", encrypted with the right passphrase: error and nothing written outside dataDir.
func TestRunSnapshotsDebouncesAndWaitsForPassphrase(t *testing.T) // with pass returning nil nothing is written; once it returns bytes, an Announce and a plan completion inside 30 s produce ONE extra file; a tick produces one.
func TestServeRestoreFlag(t *testing.T) // cmd/phylax: write a snapshot from a live controller, run serve with -restore (and -data-dir new, PHYLAX_VAULT_PASSPHRASE set, no listener: ui-listen off, listen 127.0.0.1:0, context cancelled after 1 s): data dir has phylax.db with epoch 2 in epochs.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ ./cmd/phylax/ -run 'Snapshot|ServeRestore' -count=1`. Expected: FAIL (`undefined: WriteSnapshot`).
- [ ] **Step 3: Implement.** `Backup(StateOnly)` into a temp dir, tar the files (regular files only, fixed list), `age.Encrypt(w, scryptRecipient)` with `SetWorkFactor(15)` (`shortcut: scrypt work factor 15 (about 100 ms), raise when snapshots are rare`), write through `atomicfile.Write`. Decrypt with a 64 MiB `io.LimitReader`. The design edit lists the files in the snapshot.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "recovery: encrypted controller snapshots and serve -restore"`

---

### Task 13a: A locked controller says so (R8)

After a crash or reboot with nobody at the console, plan signing and secret access stay locked until the passphrase is entered: auto plans, facts, `deadman_confirm` and safe-mode toggles stop, and in-flight dead-man timers fire and roll back applied changes. Nothing surfaced that state. The design (Controller recovery: restart safety): a critical `controller.locked` alarm and a LOCKED banner; the dead-man is unchanged (fail-safe). One flag drives the banner, the alarm and the snapshot writer's "skipped" state (Task 13).

**Files:**
- Create: `internal/controller/locked.go`
- Modify: `internal/controller/controller.go` (set the flag at start when a vault exists and no passphrase is held; clear it in the unlock handler), `internal/controller/snapshot.go` (`RunSnapshots` reports `skipped: locked` from the flag), `internal/ui/` (header banner and Overview tile), `internal/controller/webops.go` (`Overview.Locked`)
- Test: `internal/controller/locked_test.go`, `internal/ui/locked_test.go`

**Interfaces:**
- Consumes: `EmitController`, `event.ControllerLocked` (W1 Task 5a), the notify path for alert-class events, Task 13's `RunSnapshots(pass func() []byte)`.
- Produces:

```go
// Locked reports whether plan signing is locked (a vault exists and no passphrase has been entered since start), and since when.
func (c *Controller) Locked() (locked bool, since time.Time)
// Unlock is the existing passphrase entry; on success it clears the flag and emits controller.locked is not repeated.
// At start with Locked() true the controller emits one event.ControllerLocked at PriorityCritical (Stopped: auto plans, facts,
// deadman_confirm, safe_mode, snapshots) and re-emits it every 5 minutes until unlocked, so notify keeps ringing.
// webops: Overview gains Locked bool, LockedSince time.Time. ui: a red LOCKED banner in the page header on every page and a tile on the Overview
// naming what is stopped; the banner links to the unlock form.
```

- [ ] **Step 1: Write the failing tests:**

```go
func TestStartLockedEmitsCritical(t *testing.T) {
	// controller on a data dir with a vault file, no passphrase: Locked() true; Latest(controller, controller.locked) is Critical with Stopped containing "deadman_confirm";
	// an alert row exists (alert-class) for it
}
func TestLockedReemitsUntilUnlock(t *testing.T) {
	// clock moved by 5 minutes twice: three events; after Unlock none more, Locked() false
}
func TestNoVaultIsNotLocked(t *testing.T) { /* no vault file: Locked() false, no event */ }
func TestSnapshotWriterSkipsWhileLocked(t *testing.T) { /* RunSnapshots with the flag set writes nothing and reports "skipped: locked" in its status; after unlock the next tick writes */ }
func TestDeadmanStillFiresWhileLocked(t *testing.T) { /* a plan node with deadman in flight at restart: no confirm is sent while locked and the agent's timer rolls back (unchanged behaviour, pinned) */ }
// ui
func TestLockedBannerOnEveryPage(t *testing.T) { /* GET / and /agents with Overview.Locked: body contains "LOCKED" and the stopped list; unlocked: absent */ }
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ ./internal/ui/ -run 'Locked|SkipsWhileLocked|DeadmanStillFires' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** as specified.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: LOCKED banner and critical alarm while plan signing is locked"`

---

### Task 14: Stolen-key alert

**Files:**
- Modify: `internal/controller/agent.go` (`hello`, the session table `agentState`), `internal/controller/agent_test.go` or a new `internal/controller/stolenkey_test.go`
- Create: `internal/controller/stolenkey_test.go`

**Interfaces:**
- Consumes: `link.Conn.RemoteAddr()`, `c.alert(host, "enroll.key_reuse", detail)`.
- Produces: no new exported names. Behaviour: when `hello` finds `st.sess != nil` (a live session) for the same host and the new connection's remote IP differs from the old one's, the controller raises `enroll.key_reuse` with detail `second live session from <ip>, first from <ip>` (once per pair per minute), and the newer session supersedes the old one as today.

- [ ] **Step 1: Write the failing tests.**

```go
func TestSameKeyFromTwoPlacesAlerts(t *testing.T) // real listener; one agent identity dials from 127.0.0.1 and then from 127.0.0.2 (Linux loopback range; skip with a reason on other OSes) while the first session is live: exactly one Alert{Kind: "enroll.key_reuse"} whose Detail names both addresses; a reconnect from the SAME address after a drop raises none.
func TestKeyReuseAlertRateLimited(t *testing.T) // flapping between two addresses 5 times inside a minute: one alert.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/controller/ -run 'SameKeyFromTwo|KeyReuseAlertRate' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement.** `agentState` gains `sessAddr string` and `lastReuseAlert time.Time`, set under `st.mu` in `hello` where `st.sess` is replaced. Note in the design (self-protection item 6) that the kind is `enroll.key_reuse` (gap 3).
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "controller: alert when one agent key is used from two places"`

---

### Task 15: Linux watchdog tied to progress

**Files:**
- Create: `internal/agent/watchdog.go`, `internal/agent/watchdog_test.go`
- Modify: `internal/agent/agent.go` (`watchdog` goroutine and the `Run` wiring), `internal/agent/sdnotify.go` (injectable notifier)

**Interfaces:**
- Consumes: the existing `a.watchdog`, `sdNotify`, `Agent.heartbeat`.
- Produces:

```go
// Pulse is the agent's liveness record: the main loops call Beat() whenever they make progress (a heartbeat tick, a supervisor tick, a config loop tick).
type Pulse struct{ /* atomic last-beat times per source */ }
func NewPulse(now func() time.Time, sources ...string) *Pulse
func (p *Pulse) Beat(source string)
// Stalled returns the sources whose last beat is older than limit, sorted. Empty means healthy.
func (p *Pulse) Stalled(limit time.Duration) []string
```

The watchdog goroutine sends `WATCHDOG=1` only while `Pulse.Stalled(3*HeartbeatInterval)` is empty and the supervisor has not reported all modules dead; a wedged agent stops notifying, so systemd (`WatchdogSec=30`, `Restart=always`) restarts it. The same `Pulse` is what the Windows service handler checks in Task 16. Today's watchdog notifies unconditionally, which detects only a crashed process.

- [ ] **Step 1: Write the failing tests.**

```go
func TestPulseStalled(t *testing.T) // sources "heartbeat","supervisor"; Beat both at t0; at t0+40s with limit 30s: Stalled == ["heartbeat","supervisor"]; Beat("heartbeat") at t0+40s: Stalled == ["supervisor"]; unknown source Beat is ignored.
func TestWatchdogStopsNotifyingWhenStalled(t *testing.T) // inject the notifier as a func(string) recorder and a fake clock: while beats continue, "WATCHDOG=1" is recorded each tick; stop beating the heartbeat source, advance past the limit: no further notifications; resume beating: notifications resume.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/agent/ -run 'Pulse|WatchdogStops' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement.** `Agent` gets `pulse *Pulse` created in `New`; `heartbeat()` beats `heartbeat`; the supervisor's tick (read `internal/agent/module.go` for its loop) beats `supervisor`; `configLoop` beats `config`. `watchdog` takes `notify func(string)` (default `sdNotify`) and a clock for the test. The default `HeartbeatInterval` is 5 s, so the stall limit is 15 s, inside `WatchdogSec=30`.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS. Also run `go test -race ./internal/agent/ -count=3` once (the new goroutine and atomics).
- [ ] **Step 5: Commit.** `git commit -am "agent: watchdog notifies only while the agent makes progress"`

---

### Task 16: Windows self-protection: watchdog, Job Object, service DACL

**Files:**
- Create: `internal/agent/job_windows.go`, `internal/agent/job_other.go`, `internal/agent/job_test.go` (pure part), `internal/agent/job_windows_test.go`, `internal/svcinstall/dacl_windows.go`, `internal/svcinstall/dacl_windows_test.go`, `internal/svcinstall/dacl.go` (the SDDL constant, not Windows-only, so Linux CI can test its shape)
- Modify: `internal/svcinstall/windows.go` (`Install` applies the DACL; `winHandler` takes a `Stalled func() []string` and exits non-zero when stalled), `cmd/phylax/agent.go` (`agent run` calls `agent.ApplyJobLimits`; `agent install` passes the limits), `internal/svcinstall/svcinstall.go` (`Spec` gains `JobLimits`? no: limits are applied by the agent process itself, see below)

**Interfaces:**
- Consumes: `golang.org/x/sys/windows` (`CreateJobObject`, `SetInformationJobObject`, `AssignProcessToJobObject`, `SecurityDescriptorFromString`), `golang.org/x/sys/windows/svc/mgr`, Task 15's `Pulse`.
- Produces:

```go
// internal/agent
type JobLimits struct{ MemoryBytes uint64; CPUPercent int } // CPUPercent 0 = no CPU cap; 1..100 is a hard cap of that share of ONE core
// ApplyJobLimits puts the current process in a new Job Object with a per-process memory limit and an optional CPU hard cap. Windows only;
// other platforms return nil. Idempotent: a process already in a job whose limits cannot be changed returns the OS error and the agent logs it and continues.
func ApplyJobLimits(l JobLimits) error
// DefaultJobLimits is 80 MB base plus the capture module's configured held budget plus 64 MB headroom, and a 50% CPU cap (matches --cpu-quota 50%).
func DefaultJobLimits(heldMB int64) JobLimits

// internal/svcinstall
// ServiceSDDL is the protected service DACL. SYSTEM full control; BA, IU, SU, BU and AU may query and start but not stop, pause, delete or reconfigure;
// BA keeps WRITE_DAC (break-glass: `sc sdset`). Audit ACE (SACL) for failed and successful access by everyone (picked up by the winevt module).
const ServiceSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BU)(A;;CCLCSWLOCRRCWD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
```

(Verify the SDDL string with `windows.SecurityDescriptorFromString` in the Windows test, and adjust the access masks until the assertions below hold; the structure above is the intent: SY allow-all-service-rights, a deny of `DCLCWPDTSD` (change config, stop... ) to interactive, service and users, BA allow query, start, write-DAC.) The service handler exits with a non-zero status when `Pulse.Stalled` is non-empty for 3 consecutive 10-second checks, so SCM's recovery action (restart forever, already installed) restarts a wedged agent: this is the Windows half of the watchdog.

- [ ] **Step 1: Write the failing tests.**

```go
// Linux CI (internal/svcinstall/dacl_test.go, no build tag)
func TestServiceSDDLShape(t *testing.T) // starts with "D:", contains "(A;;" ...";;;SY)", contains a deny ACE for "IU", contains "WD" only in the BA allow ACE, ends with a SACL "S:(AU;FA;"; length < 400.
func TestDefaultJobLimits(t *testing.T) // DefaultJobLimits(0).MemoryBytes == (80+64)<<20; DefaultJobLimits(256).MemoryBytes == (80+256+64)<<20; CPUPercent == 50.
func TestWatchdogStallExitsAfterThreeChecks(t *testing.T) // winHandler's pure decision function stallCounter(stalled []string, n int) (exit bool, n2 int): two stalled checks -> no exit; third -> exit; a healthy check resets.
// Windows only (build tag windows; t.Skip with a reason when not running as administrator)
func TestApplyJobLimitsSetsMemoryLimit(t *testing.T) // spawn the test binary as a child with a helper env var that calls ApplyJobLimits(JobLimits{MemoryBytes: 64<<20}) then allocates 200 MB: the child is terminated (non-zero exit), the parent survives.
func TestServiceSDDLParsesAndDeniesStop(t *testing.T) // windows.SecurityDescriptorFromString(ServiceSDDL) succeeds; installing a throw-away service with it (Install then query), a non-SYSTEM token cannot open it with SERVICE_STOP but can with SERVICE_START|SERVICE_QUERY_STATUS and WRITE_DAC; uninstall via the break-glass `sc sdset` path in the test cleanup.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/svcinstall/ ./internal/agent/ -run 'ServiceSDDL|DefaultJobLimits|StallExits' -count=1` and `GOOS=windows go vet ./internal/...`. Expected: FAIL (`undefined`).
- [ ] **Step 3: Implement.** `job_windows.go`: `windows.CreateJobObject(nil, nil)`, `SetInformationJobObject` with `JOBOBJECT_EXTENDED_LIMIT_INFORMATION{BasicLimitInformation.LimitFlags: JOB_OBJECT_LIMIT_PROCESS_MEMORY, ProcessMemoryLimit: MemoryBytes}` and, when `CPUPercent > 0`, `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION{ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, CpuRate: percent*100/numCPU}`, then `AssignProcessToJobObject(job, windows.CurrentProcess())`. `shortcut: Windows behaviour is verified in the lab only (CI vets and builds for windows, it does not run Windows tests), upgrade when a Windows runner exists`. `Install` applies `ServiceSDDL` with `windows.SetNamedSecurityInfo(name, windows.SE_SERVICE, DACL|SACL, ...)` after `CreateService`; `Uninstall` first resets the DACL to the default (SYSTEM and BA full) when running as SYSTEM or BA, so `phylax agent uninstall` works from an elevated console. The design text of self-protection item 2 changes "(to build)" to built, with gap 5's reasoning.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS on Linux; the Windows-tagged tests compile under `GOOS=windows go vet`.
- [ ] **Step 5: Commit.** `git commit -am "agent: windows job object cap, protected service DACL and progress watchdog"`

---

### Task 17: The `agent.*` family, part 1: `set_controller`, `safe_mode`, `config`

**Files:**
- Create: `internal/actions/agent_actions.go`, `internal/actions/agent_actions_test.go`
- Modify: `internal/actions/env.go` (`Env.AgentRoot string`, the agent state directory; set from `agent.Config.Layout.Root` where the executor's `Env` is built — find it with `grep -rn 'actions.Env{' --include='*.go' internal cmd`), `internal/agent/agent.go` (apply `options.json` at start and on change), `internal/actions/registry.go` (the family registers through W1/W3/W5's `actions.RegisterFamily`; use the name that exists in `internal/actions` when this task starts, see the note below), `docs` (the actions table row of the design is already present)

**Interfaces:**
- Consumes: `bootstrapfile.Rewrite` (Task 6; `internal/actions` must not import `internal/agent`, which imports actions), `actions.NewSafeMode`, `atomicfile`, the `Action` interface (`Spec`, `Locks`, `Touches`, `Plan`, `Capture`, `Apply`, `Verify`) and `Rollback{Kind, Data}`.
- Produces three registered actions (all `RunsAgent`):
  - `agent.set_controller{controllers: string (comma list), pin: string (optional)}` Risk `lockout`: Plan shows old and new list; Capture stores the old bootstrap bytes; Apply rewrites via the shared function; Verify re-reads the file; rollback kind `agent.restore_bootstrap` writes the old bytes back. The dead-man default for `lockout` applies (a wrong address is undone if the agent cannot confirm).
  - `agent.safe_mode{on: bool}` Risk `none`: `on: true` sets safe mode; `on: false` is refused with `safe mode is turned off from the operator UI` (gap 6).
  - `agent.config{memory_limit_mb: int}` Risk `service`: writes `<AgentRoot>/options.json` (`{"memory_limit_mb":N}`, 0600, atomic), the agent applies it with `debug.SetMemoryLimit` on change (poll at the heartbeat tick); rollback restores the old file; range 32..1024.

**Note on the registration name:** W3 calls it `actions.RegisterExtra`, W5 `actions.Register`, W6 `actions.RegisterFamily`; the README says one name is chosen in W1's fix pass. Use whatever exists in `internal/actions/registry.go` after W1 merges (`grep -n 'func Register' internal/actions/registry.go`); if none does, use the existing `registerExtra` init pattern (`extraActions`).

- [ ] **Step 1: Write the failing tests.**

```go
func TestSetControllerAction(t *testing.T) // Env.AgentRoot = t.TempDir() with a saved bundle: Plan reports the diff; Apply -> LoadBundle controllers equal; Verify nil; Rollback(old bytes) restores byte-equal; params "nonsense" -> Plan errors.
func TestSafeModeAction(t *testing.T) // on:true sets the marker file; on:false -> error containing "operator UI" and the marker unchanged; Plan Done=true when already on.
func TestAgentConfigAction(t *testing.T) // memory_limit_mb 128 writes options.json {"memory_limit_mb":128}; 16 and 4096 refused; Rollback restores the previous content (and removes the file if there was none).
func TestAgentOptionsApplied(t *testing.T) // internal/agent: write options.json, run the agent's options check once: debug.SetMemoryLimit was called with 128<<20 (read back with debug.SetMemoryLimit(-1)); restore the previous limit in cleanup.
func TestAgentFamilyRegistered(t *testing.T) // actions.Core().Lookup for each of the five names (the last two are registered by Task 18; this test lists three here and Task 18 extends it).
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./internal/actions/ ./internal/agent/ -run 'SetControllerAction|SafeModeAction|AgentConfigAction|AgentOptionsApplied|AgentFamily' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement.** The action calls `bootstrapfile.Rewrite` on `<AgentRoot>/bootstrap.json`; `Env.AgentRoot` is the new field.
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: agent.set_controller, agent.safe_mode, agent.config"`

---

### Task 18: The `agent.*` family, part 2: the swap helper, `replace_binary`, `rename`

**Files:**
- Create: `cmd/phylax/swap.go`, `cmd/phylax/swap_test.go`, `internal/actions/agent_swap.go`, `internal/actions/agent_swap_test.go`, `internal/svcinstall/restart.go` (interface method) and `restart_systemd.go`, `restart_windows.go`
- Modify: `internal/svcinstall/svcinstall.go` (`Installer` gains `Restart(ctx, name string) error`), `internal/svcinstall/systemd.go`, `internal/svcinstall/windows.go`, `internal/svcinstall/default_other.go`, `internal/agent/agent.go` (writes `<state>/started.json` `{pid, time}` after the first controller ack of each start), `cmd/phylax/agent.go` (`agent swap` subcommand)

**Interfaces:**
- Consumes: `signing` is W5's and not available: `agent.replace_binary` verifies the new binary with the **plan-signing key** the agent already holds (`Bundle.PlanKey`): the step carries `sha256` and `sig` (Ed25519 over `"phylax-binary\x00" + sha256`, domain-separated like the existing plan signing) and the binary is fetched by a `file.content`-style param `path` that an earlier plan node placed (the `fetch` handler is W11's; until then, the operator places the file with a `file.write` node). `shortcut: binary delivered by an earlier plan node and signed with the plan key, upgrade to sshsig release signatures and depot fetch when W5 and W11 land`.
- Produces:

```go
// svcinstall.Installer gains:
Restart(ctx context.Context, name string) error

// cmd/phylax: `phylax agent swap -state-dir DIR -plan FILE` (detached helper, started by the actions). FILE is JSON:
type SwapPlan struct {
	Kind        string   // "replace_binary" | "rename"
	Service     string
	OldBinary   string
	NewBinary   string   // replace_binary: the verified new file; rename: a copy of the running binary at the new path
	NewService  string   // rename only
	StateDir    string
	WaitSec     int      // default 30
	Args        []string // rename: the install args for the new service
}
// Behaviour: wait for the agent process to exit or stop the service; replace_binary: rename OldBinary to OldBinary+".old", move NewBinary in, Restart the service,
// poll <state>/started.json for a start newer than the swap (the first ack after restart) for WaitSec; if none, move .old back, Restart, exit 1. rename: Install the new
// service (not the old), Uninstall the old one after the new one reports started.json newer than the swap; if none within WaitSec, Uninstall the new one, Restart the old, exit 1.
```

Actions: `agent.replace_binary{path, sha256, sig}` Risk `lockout`; `agent.rename{secret}` Risk `lockout` (names from `svcinstall.DeriveNames(hex secret)`). Both: Plan verifies hash and signature (replace_binary) or computes the names (rename); Apply writes the `SwapPlan`, starts the helper detached (`exec.Command(os.Executable(), "agent", "swap", ...)` with `SysProcAttr` creating a new session on Linux and `DETACHED_PROCESS` on Windows), and returns; Verify is the agent coming back (the controller's heartbeat check for the node, the existing plan engine mechanics); rollback is the helper's own 30 s revert, so the action's `Rollback` kind is `agent.noop` (documented: the helper owns the revert, because the agent is dead during the swap).

- [ ] **Step 1: Write the failing tests.**

```go
func TestSwapReplaceBinarySuccess(t *testing.T) // cmd/phylax: a fake Installer (records Restart calls; its Restart writes <state>/started.json with a later time, like the real agent would); files: old "A", new "B": after run, OldBinary has content "B", ".old" removed after success; exit nil.
func TestSwapReplaceBinaryRollsBackWithoutHeartbeat(t *testing.T) // fake Installer whose Restart does not write started.json, WaitSec 1: OldBinary content is "A" again, Restart called twice, error returned.
func TestSwapRenameInstallsNewThenRemovesOld(t *testing.T) // success: Install(new) then Uninstall(old) in that order; failure (no started.json): Uninstall(new) and Restart(old), old never uninstalled.
func TestReplaceBinaryRejectsBadSignature(t *testing.T) // actions: wrong sig, or sha256 not matching the file, or the signer not the bundle plan key: Plan errors, Apply never starts the helper (the helper start func is injected in Env and not called).
func TestReplaceBinaryStartsDetachedHelper(t *testing.T) // good sig: the injected helper starter receives a SwapPlan JSON file path whose content has Kind "replace_binary", NewBinary equal to params.path, WaitSec 30.
func TestRenameUsesDerivedNames(t *testing.T) // secret hex "00112233445566778899": SwapPlan.NewService == svcinstall.DeriveNames(secret).Service.
func TestAgentFamilyRegistered(t *testing.T) // extends Task 17's test: all five names resolve.
func TestAgentWritesStartedAfterFirstAck(t *testing.T) // internal/agent harness: after the first controller ack, <state>/started.json exists with pid == os.Getpid() and a time >= the test's start.
```

- [ ] **Step 2: Run, expect FAIL.** Run: `go test ./cmd/phylax/ ./internal/actions/ ./internal/agent/ ./internal/svcinstall/ -run 'Swap|ReplaceBinary|Rename|AgentFamily|StartedAfterFirstAck' -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement.** The helper is small (about 80 lines) and runs the same code on both platforms through `svcinstall.New()` (injected in tests). `Restart` on systemd is `systemctl restart <name>`; on Windows `svc.Control(Stop)`, wait for stopped, `Start`. Add the design line to the Lifecycle table: "replace_binary: the swap helper restarts the service and reverts after 30 s without a controller ack".
- [ ] **Step 4: Run, expect PASS.** Run: `make build build-windows vet test race`. Expected: PASS.
- [ ] **Step 5: Commit.** `git commit -am "actions: agent.replace_binary and agent.rename through a detached swap helper"`

---

### Task 19: Lab (stronger agent or David)

Done by a stronger agent or David on the BTaP replica (`docs/impl/lab/w12-enrollment.md` is the record). Not a Haiku task. Everything below needs real hosts or the replica; none of it blocks merging Tasks 1 to 18, but T27 and T21 on Windows are the exit evidence for the Windows halves of Tasks 4, 9 and 16.

**Files:**
- Create: `docs/impl/lab/w12-enrollment.md`

- [ ] **Step 1: T27, console bootstrap.** On Windows 10 or 11, Server 2019 and Linux (each a fresh VM): type the generated one-liner from the UI. Expected: the agent enrolls; with one pin byte changed the command aborts before the token is sent (check the controller's bootstrap log shows no request); a tampered binary in the release dir fails the embedded sha256 and is never run. Record the typed length of each line and whether the console's keyboard mapping accepted every character (data doc O2); if the Windows line fails to type, record which characters failed.
- [ ] **Step 2: SSH push on the replica.** Push every Linux host with the rotated credentials; record the failure classes seen. Expected: one class per failure, none unclassified; hostname mismatch tested by pointing a manifest name at the wrong IP.
- [ ] **Step 3: WinRM push.** Push a Server 2019 and a Server 2022 host with default WinRM settings (port 5985, NTLM). If either refuses unencrypted SOAP, record it: message-level sealing becomes a follow-up in `internal/checks/probe/winrmshell.go` (Task 8's shortcut).
- [ ] **Step 4: T21 first contact, then kill.** Linux and Windows: record time from enrollment to first heartbeat, then kill and disable the agent (`systemctl kill -s SIGKILL`; `sc stop` must be refused by the DACL and `Stop-Process` / `taskkill` followed by SCM recovery must bring it back; `systemctl stop` is the Linux comparison) and record silence-detection latency (`agent.silent`).
- [ ] **Step 5: T22, relay host killed; T47, relay end to end.** Multi-segment variant: an agent through a relay; a bootstrap download through the relay; the relay holds no keys and sees no plaintext; the connection cap holds. Record whether the bootstrap handler works through the relay; if the relay forwards only phylax ALPNs, a follow-up is needed (this plan does not build relay changes).
- [ ] **Step 6: T23, controller lost mid-plan.** Run a plan, kill the controller, restore from a snapshot older than the plan on another machine (`phylax serve -restore`), run `phylax set-controller` on the hosts. Expected: agents reconnect without re-enrollment; the new epoch is accepted; spools are resent and chain-checked; gaps are marked "controller restored". Record how long the resend took with 100,000 events in the spool.
- [ ] **Step 7: T48 enrollment half, and T19 enrollment half.** T+0 rehearsal: after the console rotation, enroll with the new values (first contact uses them). Then a new reservation: run `reenroll-all` and record time to every host back, that `agent.reenrolled` fired once per host, and that the old keys are refused. (`hunt` and `creds` consumption of the events is W5 and W7's lab.)
- [ ] **Step 8: Self-protection on Windows.** Job Object: record the agent's working set against the cap and whether `capture` hosts need a larger one. DACL: confirm `sc stop`, `Stop-Service` and `net stop` are refused for an administrator, `sc sdset` restores access (break-glass), and the winevt/Sysmon record shows the attempt. Watchdog: suspend the agent process (`pssuspend`) and record how long until SCM restarts it.
- [ ] **Step 9: Write the record and commit.** The record lists each test, host, commands, measurements and anything unverified. `git add docs/impl/lab/w12-enrollment.md && git commit -m "enroll: lab record for T19, T21, T22, T23, T27, T47, T48"`.

---

## Self-review

**1. Spec coverage** (design "Enrollment, bootstrap and recovery" and the rows W12 owns):

| Requirement | Task |
| --- | --- |
| `internal/enroll` core package, no module imports it (T76 enroll half) | 2 (move, fixture test), 3, W1's `TestNoSiblingImports` |
| SSH push: sentinel, base64 stdin, banner routing, hostname check, failure classes, 30 s fan-out, fresh login and heartbeat verify, host keys recorded | 5 (SFTP fallback: gap 4) |
| WinRM push with NTLM from `internal/checks/probe`, no Basic, no AllowUnencrypted, no SMB drop | 1, 8, 9 (sealing: lab step 3) |
| Console one-liner with two pins (controller key hash, download hash), ASCII, short (T27) | 4, 19 |
| Bootstrap handler on the `http/1.1` ALPN; the agent port serves only agent streams and bootstrap downloads (T28) | 4, 11 |
| Token minting and atomic consumption, 10 minute expiry, wrong-host claim not burning, idempotent retry, minting only from the UI | 2, 11 |
| Bootstrap config contents (addresses, pin, identity, plan key, token, roles) and W2's `Safe` | 2 |
| `welcome`, `agent.enrolled`, `agent.reenrolled`, `enroll.refused`, `enroll.key_mismatch`, `enroll.key_reuse` through `EmitController` | 3 |
| A new key claiming an existing host is always an alert; re-enrollment revokes old keys, fresh tokens, dependency order (T19 half) | 3, 10 |
| `phylax set-controller` | 6 |
| Controller recovery: snapshot every 15 min and after enrollment and plan completion, age encryption, restore with new epoch, resend verification, gaps "controller restored" (T23) | 12, 13 (vault trigger: gap 9) |
| Restart safety (accept traffic before unlock) | already built; Task 13's snapshot loop waits for the passphrase |
| Self-protection: sensor-health heartbeat (built), service hardening incl. Windows protected DACL and Job Object, watchdog, stolen-key alert | 14, 15, 16 (items 3 and 5: gap 8) |
| Agent family `agent.replace_binary`, `agent.config`, `agent.set_controller`, `agent.safe_mode`, `agent.rename` | 17, 18 (gap 6) |
| W2 code moves with behaviour and tests kept | 2, 4, 7 |

**2. Placeholder scan:** no "TBD" or "similar to Task N". Items the implementer must read first are named (the fake SSH and WinRM servers in `probe`, the e2e harness, the registration function name in `internal/actions`); each is a read instruction with a file path, not a missing design.

**3. Type consistency:** `Enroller`, `Options` (fields added in Tasks 2, 4, 10, 13: `Connected`, `ReleaseDir`, `Disconnect`, `OnEnrolled`), `Result{Enrolled, Reenrolled}`, `Class` constants, `PushError`, `Target`, `WinRMTarget{Target; Port; TLS; Domain}`, `PushResult{Target, Err}` (Task 5's `PushResult.Target` is a `Target`; Task 10's `ReenrollAll` returns `[]PushResult` and its `push` func takes a host name, so the caller adapts), `Pulse` (Task 15, used by Task 16), `bootstrapfile.Rewrite` (Task 6, used by the CLI and Task 17), `SwapPlan` (Task 18), `JobLimits` and `ServiceSDDL` (Task 16). `OneLiner(osName, ctl, token)` is a method on `*Enroller` everywhere it is used (Tasks 4, 7, 9, 11).
