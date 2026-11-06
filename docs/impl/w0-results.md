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
