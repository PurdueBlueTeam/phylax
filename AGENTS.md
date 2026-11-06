# phylax: repo notes for contributors (human and AI)

Branch `v4` builds the v4 design in [phylax_design.md](phylax_design.md)
(version 4, which supersedes v3) by moving the v3 code onto the module contract,
workstream by workstream (`docs/impl/README.md`). Don't copy code from `main` or
from the older `qwen-wip` work (its branch was deleted on 2026-11-06);
their review is in ccdc-private `strategy/phylax-code-review.md`,
and its findings are design requirements.

## The design and the module contract
- phylax_design.md is authoritative for the target. Where a module section says it
  "follows the code", that choice is already the design. Existing paths (for example
  `internal/collect/*`, `internal/integrations`) are where today's code lives; each
  package moves to `internal/<module>` in that module's retrofit task and the old path
  is deleted. Nothing has ever been deployed, so there are no compatibility shims,
  aliases or dual formats: rename kinds, fields and paths in one go (the rename map is
  in the design, for the migration only).
- **Small core, everything else a module.** The core is the link, spool, execution
  engine, event store, manifest and UI shell (plus `internal/enroll`). Every other
  capability is a module that meets the contract in the design ("The module
  contract"):
  - one Go package `internal/<name>` (agent side, controller side, or both), with its
    agent registration in `internal/agent/mods/<name>*.go`;
  - one config block (`modules/<name>.yml`, a typed struct, unknown fields are an
    error) that carries the generic `enabled` and `act_enabled` fields; the YAML maps
    1:1 onto the struct; new capabilities are off unless the manifest enables them;
  - a capability manifest (sides, OS, privilege, roles, `Consumes`, `Emits`,
    tables, content, actions, pages), typed events declared with `event.Declare` and
    listed in the event-kind table, and a health report;
  - **no sibling imports**: a module imports only core packages and the closed list
    of shared stateless libraries (`internal/checks/probe`, `internal/sockets`,
    `internal/signing`, `internal/atomicfile`, `internal/parsers/*`,
    `internal/integrity/format`, `internal/inventory/fold`). Modules talk through
    typed events, `Host.Propose`, `Host.RunReadOnly`, `Host.RunStanding` and
    `Host.Control` (a signed `control: fact` to agents), never through each other;
  - analysers are pure functions over store queries; a module with tables has one
    writer goroutine that fills them from its own events;
  - rules, plans and checks are YAML content under `rules/<module>/`,
    `plans/<module>/`, `checks/`; write content, not Go, where content can do it;
  - common kinds (`conn`, `process_start`, `process_exit`, `file_change`,
    `auth_event`, `listener`) use only the canonical field names in the design
    (`dir: inbound|outbound`, `laddr`, `raddr`, `lport`, `rport`, `exe`, `user` ...);
    producers translate to them and rules read only them;
  - it passes the shared conformance suite (`internal/module/conformance`).
- Keep the design's tables in step with the code: the event-kind table (emitters,
  consumers, alert flag), the action table and the test list (T01 to T76) are single
  sources, and CI compares them with the registries.
- A package is done when CI is green (build for both OSes, vet, test, `-race`) and it
  has unit, fixture and conformance tests. Lab tests are a separate gate run by a
  stronger agent or by David.

## Rules
- **Simple over complete.** Reducing complexity is the owner's first priority, and
  the tool is tested extensively in the lab and at events, so real problems show
  up there. Build what the plan names, in its smallest form. A review finding gets
  the smallest fix that closes a real risk; a hypothetical case gets a `shortcut:`
  comment, not a new mechanism (no extra locks, caches, retries, registries or
  config knobs "just in case"). Reviewers flag over-engineering as a finding.
- Go 1.27.2 (mise). `CGO_ENABLED=0`, except the race job, which needs
  `CGO_ENABLED=1` and gcc (`make race` sets both); linux/amd64 and windows/amd64
  must both build (`make build build-windows`) and vet (`make vet`) at every
  commit.
- Every package ships tests; `go test ./...` and `go test -race ./...` pass.
  Tests must exercise the real thing (no mocking away the code under test, no
  tautological asserts). Tests needing privileges or containers are skipped with a
  clear message when unavailable, never silently passing.
- No shelling out in the default path (design principle "Go-native"); `host.exec`
  is the only explicit escape hatch.
- Bounded everything: queues, buffers, decompression, timeouts and deadlines.
- Crash-safety: writes to critical files are atomic (temp file + fsync + rename),
  preserving owner, mode and SELinux label.
- Keep the design doc authoritative: if implementation forces a design change,
  update phylax_design.md in the same commit and say why.

## Gotchas
- Go's `tls.NewListener` defers the handshake: call `HandshakeContext` before
  reading `ConnectionState().NegotiatedProtocol` (ALPN), and do it off the accept
  loop with a deadline.
- This dev VM and most containers mount `/proc` with `noexec`, so a memfd
  cannot be executed through `/proc/self/fd`; the depot falls back to a private
  0500 copy of the verified bytes. Keep that fallback (`internal/depot/exec_*.go`).
- The controller's own events are a hash chain under store agent `controller`
  (`internal/controller/chain.go`, keyed by the controller identity). It is not
  a host: `controller.New` skips it when it loads known agents into the live
  agent states, or the silence watcher would report the controller silent and
  the agents page would list it. Emit through `EmitController`, never by
  building an `event.Event` and calling `Ingest` (the head read and the ingest
  are one critical section).
- A module's tables go through `store.ModuleDB(name)`: migrations are numbered
  per module and statements may only touch `<name>_*` tables. The ownership
  check is a regexp over the statement text (a shortcut for a SQLite
  authorizer), so quoted table names are refused and `ON CONFLICT ... DO UPDATE`
  is skipped rather than mistaken for an `UPDATE` on `SET`.
- A `destructive` or `lockout` node gets a default 90 s dead-man
  (`plan.EffectiveDeadmanSec`), so an action with no undo data must use risk
  `service` (or the run fails with `actions.ErrNotReversible`). `host.exec` is
  `service` for that reason; it is gated by its own node approval and by
  `SS010`, not by the risk class. The envelope plan tag is
  `actions.Tag.PlanTag()` (`plan:<id>`).
- The bench recorder is on by default, so every controller started with a data
  dir (including `newCtl` in the tests) writes `<data_dir>/bench.jsonl` every
  `bench_interval` (10 s) for as long as `Serve` runs; `bench_off: true` stops
  it. The e2e test helper `newAgent` heartbeats every 50 ms unless the test
  sets `hbEvery` to 0 before `run`, which is how a test keeps one heartbeat's
  `RTTUs`/`Health` in the sample (a later heartbeat overwrites them with the
  measured round trip).
