# W0 results

Baseline for the W0 proving plan (`docs/impl/00-proving.md`). Updated by the
later tasks in the same plan.

## Baseline

Recorded 2026-11-06 on the dev VM (uid 1000, 16 CPUs, Go 1.27.2 via mise,
`/usr/bin/gcc` present, `/proc` mounted `noexec`) at `git rev-parse --short
HEAD` = `a7fe8a4`.

| command | exit | failing packages/tests | note |
|---|---|---|---|
| `make build build-windows` | 0 | none | both OSes build |
| `make vet` | 0 | none | vet runs linux and `GOOS=windows`, so Windows `_test.go` files type-check |
| `CGO_ENABLED=0 go test -count=1 ./...` | 1 | `internal/depot`: `TestRunVerifiedAndCleanEnv`, `TestRunExecsVerifiedBytesNotDisk` | first error, verbatim: `    depot_test.go:226: run: 126 fork/exec /proc/self/fd/3: permission denied `; the second test fails with `    depot_test.go:287: fork/exec /proc/self/fd/3: permission denied`. Deterministic; `/proc` is mounted `noexec` here and the depot execs its sealed memfd through `/proc/self/fd/3` |
| `CGO_ENABLED=1 go test -race -count=1 ./...` | 1 | `internal/depot`: the same two tests; once also `internal/agent/mods`: `TestSandboxedDecoysFromSignedConfig` (`deception_test.go:148: decoy never listened`) | same depot error under `-race`; the mods failure was seen in one run out of three and is chased in the Task 3 sweep |
| `CGO_ENABLED=0 go test -race ./internal/event` | 2 | n/a (the tool refuses) | verbatim: `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1` |

So the v3 code under test is in good shape; two real defects: the depot's
memfd exec assumes an executable `/proc`, and the `race` target inherits the
caller's `CGO_ENABLED` (Task 2).

## Sweep

Run 2026-11-06 at `b4c0833` (the depot fix) with `make race` fixed, as the
plan's Task 3 Step 1 asks.

| command | exit | failing packages/tests | note |
|---|---|---|---|
| `CGO_ENABLED=1 go test -race -count=3 -cpu 1,4 ./internal/controller/... ./internal/e2e/... ./internal/capture/... ./internal/agent/... ./internal/link/... ./internal/spool/... ./internal/store/...` | 1 | `internal/controller`: `TestEndToEnd`, three times | first error, verbatim: `    e2e_test.go:408: only 4632 events streamed`; the same test failed in all three counts (`4632`, `4789`, `4630`), so it is not a timing flake |
| `GOOS=windows go vet ./...` | 0 | none | Windows `_test.go` files type-check |
| `PATH=$(go env GOROOT)/bin CGO_ENABLED=0 go test -count=1 ./internal/collect/... ./internal/firewall/... ./internal/actions/... ./internal/deadman/...` | 0 | none | with tcpdump, nft, docker and systemctl off `PATH`; 20 tests SKIP with a message (re-run with `-v` to count them), none fail |

### Fix: `TestEndToEnd` depends on a drained spool

`internal/controller/e2e_test.go:408` asserts that at least 5000 of the phase 2
events streamed, but phase 1 leaves a 2 MB bulk flood unacked and the spool
admits bulk events only up to half its cap (`admitPercent`), so phase 2's bulk
events are shed while that backlog is in flight. With `GOMAXPROCS=1` the agent
drains slowly enough that the backlog is still there when phase 2 runs
(6000 - 4632 = 1368 shed, about the 1500 bulk events in the phase 2 mix); with
16 CPUs the drain wins the race, which is why the full run never showed it.

Fix `c252fb6` (controller: wait for the flood to drain before the phase 2
stream): phase 1b waits for the deterministic condition "the controller accepted
everything the spool holds" (the same predicate the final wait uses) before
phase 2 starts. No assertion changed. Verified:

- `CGO_ENABLED=1 go test -race -count=20 -cpu 1 -run '^TestEndToEnd$' ./internal/controller` = `ok` (182 s)
- `CGO_ENABLED=1 go test -race -count=3 -cpu 1,4 -run '^TestEndToEnd$' ./internal/controller` = `ok`

### The one-off in `internal/agent/mods`

`TestSandboxedDecoysFromSignedConfig` failed once during the baseline
(`deception_test.go:148: decoy never listened`) and did not reproduce in 40
further runs (`-race -count=5 -cpu 1,4`, eight at a time), nor in the sweep
above. The failure was undiagnosable because the test discarded the module's
error, so commit `0482952` (mods: report why the decoy child stopped in the
sandbox test) makes it say why the child stopped.

Cause (seen again later as `decoys: listen ssh on 46884: bind: address already
in use`): the test picked a port by listening on `127.0.0.1:0`, closing it and
then using that number (and the next one) for the decoy child, so any parallel
test could take either port in between; the sandbox parent's bind then failed.
The fix runs the whole start again on a fresh pair of probed ports when the
module reports `EADDRINUSE` (at most five attempts, no sleeps), and waits for
the module's `Ready` instead of polling the port. The bind failure is now
explained by the module's error, which the test surfaces.

### After the fixes

The sweep above, run again at `0482952`:

| command | exit | failing packages/tests | note |
|---|---|---|---|
| `CGO_ENABLED=1 go test -race -count=3 -cpu 1,4 ./internal/controller/... ./internal/e2e/... ./internal/capture/... ./internal/agent/... ./internal/link/... ./internal/spool/... ./internal/store/...` | 0 | none | six runs per package (3 counts x cpu 1 and 4) |
| `CGO_ENABLED=0 make build build-windows vet test race` | 0 | none | full gate |
