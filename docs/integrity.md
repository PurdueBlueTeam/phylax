# internal/integrity

Binary integrity ledger (design: "Binary integrity ledger", D-1). **Alert only:**
nothing here writes, quarantines or restores a file. Hashing is native Go
(`os` + `crypto/sha256`), never host tools.

## Pieces

| File | Role |
| --- | --- |
| `ledger.go`, `verdict.go` | `Entry` (path, sha256, size, mode, package, version, signer, OS, source), `Ledger` (lookup by path and by hash, known-bad list), `Judge` producing a `Result` with evidence |
| `format.go` | On-disk format: magic, meta JSON, signature, zstd body (string table, path front-coding, sorted). `Signer`/`Verifier` interfaces, ed25519 implementations |
| `deb.go`, `rpm.go`, `decompress.go` | Pure-Go `.deb` (ar + tar, gzip/xz/zstd/none) and `.rpm` (header + cpio newc, gzip/xz/zstd/bzip2/none) readers. Hashes come from the payload, not the package's own digests. Bounded by `ReadLimits` |
| `hostdb.go` | dpkg `status` + `md5sums`, rpm `rpmdb.sqlite` (read-only, immutable). Hints only |
| `winbindex.go` | Importer for Winbindex per-file JSON (plain or gzip) |
| `signature*.go` | `SignatureVerifier` interface; Windows implementation via `WinVerifyTrustEx` (embedded, then catalog via CryptCATAdmin) with signer name extraction. Compiled and vetted only on Linux CI; untested on a real Windows host |
| `checker.go`, `pin.go`, `maps.go`, `sweep.go`, `cache.go` | Agent-side checks |
| `yara.go`, `procmem_*.go` | Scanner interface, pure-Go matcher, schedule, `/proc/<pid>/mem` reader |

## Verdicts

Names follow the design; the shorthand in the task maps as: known-good = `match`
(`match_other_version` is informational), known-bad = `known_bad` (hash on the
ledger's bad list), modified = `mismatch`, unsigned = `sig_invalid`, plus
`unknown`. A host-hint entry (`SourceHostHint`) never yields `match`; the result is
`unknown` with `hint_only`. `match_other_version` is returned when the host's
claimed package version (from dpkg/rpm hints) differs from the matching entry's.
A validly signed file from an allowlisted signer that the ledger does not know is
accepted (`match`, note records the signer).

Paths are normalised: usr-merge folded (`/bin` -> `/usr/bin`, `/sbin`, `/lib*`),
`" (deleted)"` stripped, Windows paths lower-cased without drive letter.

## Events

`integrity.verdict` (agent-side, unsealed; the spool seals). Fields: `path`,
`sha256`, `size`, `verdict`, `trigger` (`exec|library|pin|sweep`), `root`,
`escalate` (unknown/mismatch/known_bad/sig_invalid under root, a service or a
pin: raise D5d), `pid`, `ppid`, `uid`, `process` (tree pointer), `service`,
`flags`, `matched`, `expected` (all entries at the path) plus flat
`expected_sha256`/`source`/`package`/`version`, `signer`, `bad_label`,
`hint_only`, `hash_known_at`, `note`. Pin events add `running_sha256`,
`disk_sha256`, verdicts and `running_target`; library events add `library`.
Identical findings are suppressed for `Suppress` (default 15 min). Good verdicts
are not emitted unless `EmitMatches`. YARA: `integrity.yara`.

Pin flags: `image_deleted`, `inode_replaced`, `disk_differs_from_running`,
`memfd_image`, `disk_missing`, `stale_after_update` (both images ledger-good: a
package update awaiting restart, informational), `running_<verdict>`,
`disk_<verdict>`.

## Wiring (for the agent/controller integrators)

- Build a `Checker` with `integrity.New(Config{Agent, Judge: ledger, Hints, Emit, Verifier})`.
  `Judge` is an interface so the agent can pass a controller-backed lookup.
- Exec: `HandleProcessStart(ctx, ev)` reads `pid`, `exe`|`path`, `uid`, `ppid`,
  `process`, `service` from a process_start event, or call `CheckExec`. With a
  live pid it hashes `/proc/<pid>/exe`, i.e. the image actually running.
- Pins every 60 s: `CheckPin`; maps at start and every 60 s: `CheckMaps`;
  system sweeps every 15 min: `Sweep` (cache-skips unchanged files; run with
  `FullRehash` on a slower cadence; `BytesPerSec` throttles).
- Cache key: dev + inode + ctime + size (ctime cannot be forged by userland the
  way mtime can). Not-linux builds key on path + mtime.
- Callers of `CheckMaps` must set `Context.UID` to -1 when unknown (0 means root).

## YARA

The design leaves YARA-X vs Go-native open. This package defines `Scanner`
(`ScanFile`, `ScanReader`, `ScanProcess`) and ships `GoScanner`, a minimal matcher:
text strings (`ascii`, `wide`, `nocase`), hex strings with `??`, conditions with
`$id`, `any|all|N of them`, `and/or/not`, parentheses, `filesize`,
`uint8/16/32(offset)` in the first 4 KiB. Regexes, jumps, modules, `fullword`,
`xor`, `base64` are unsupported: such rules are listed in `Matcher.Skipped`, never
silently ignored. `ExternalScanner` is the stub for the pinned YARA-X binary and
`BundledC2Corpus` is the stubbed corpus loader (`ErrCorpusNotBundled`; rule
licences must be checked first). `LoadCorpusDir` loads `*.yar` from disk.
`YaraSchedule` runs files (deduplicated by inode identity) and processes every
5 minutes with a pause between items.

## Not done / follow-ups

Local depot and one-click restore (a tier-1 action, outside this package);
building ledgers from ISOs (lab tooling; the `Builder` is the API); network
fetching of packages and Winbindex (callers supply readers; tests are offline);
Windows YARA process memory; behavioural corroboration is the event consumer's
job (the controller joins `integrity.verdict` with net/proc events by pid).
