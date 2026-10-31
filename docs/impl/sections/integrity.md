#### `integrity`

D-1: detect red-team-modified or replaced binaries continuously, and **alert only**. Nothing in this module writes, quarantines or restores a file by itself; restoring is a one-click proposal that goes through a plan (the `binary.restore_from_depot` action). The module also runs YARA over files and process memory, the rootkit cross-checks the hunt defines, and the PAM content checks.

**1. Purpose and evidence**

- **What it does.** The agent hashes executables at exec, hashes pinned scored-service binaries every minute, checks loaded libraries, sweeps system paths, and judges every hash against a signed reference ledger. It emits a verdict event for anything that is not known-good. The controller builds the ledgers, adds vendor-package truth and holds the accepted-hash overrides.
- **Evidence.** At the 2026 regional the red team replaced the Postfix binary with a proxy to their Kali and replaced `dns.exe` with a build that had a remote kill switch. In 2020 teams saw trojaned `nologin` and `dash`. These are prebaked, so they are not "changes" and file-change monitoring stays silent. The old design checked binaries once, in the first-15-minutes hunt [PRO §2, COV L-8/S-1/S-2]. Prebaked persistence was most of red's 2026 access (redteam report). Pinning scored service binaries is where the ledger earns its cost.
- **Evidence against, and limits.** A root attacker can lie to the agent (a hooked `readdir`, a rootkit). A root red can also rewrite the host package database, so it stays a hint (UCF RedBaron2's `integrity/mod.rs:11` trusts the on-host dpkg/rpm DB; Spike v1 auto-reinstalls on a mismatch; both are the pattern D-1 and the off-host ledger exist to avoid). Real competition images do not exist for us, so the ledger is only as complete as the stock images behind it and an image's extra files are `unknown` at the first sweep. They go to the hunt's triage queue, not to alerts (review area 5).
- **Decisions applied.** D-1 stands. Review D14, D23, D79 (emit the verdict so D5d fires), D83 and D368 (YARA, A5.Q1), D165, D324, D356 to D367, D369, D398, D399, N5.9.

**2. Status and code**

Status: **partial**. The checks and the ledger are built; the producer for D5d, the YARA engine wiring and the controller side are not.

| Piece | Where | State |
| --- | --- | --- |
| Ledger: entries, lookup by path and hash, known-bad list, merge, builder | `internal/integrity/ledger.go`, `verdict.go` | built |
| Signed on-disk format (magic, meta, ed25519 signature, zstd body with string table and front-coded paths) | `format.go` | built |
| Pure-Go `.deb` and `.rpm` readers (hashes from the payload, not the package's own digests), bounded | `deb.go`, `rpm.go`, `decompress.go` | built |
| Host package DB hints: dpkg `status` and `md5sums`, rpm `rpmdb.sqlite` read-only | `hostdb.go` | built |
| Winbindex importer | `winbindex.go` | built |
| Windows Authenticode and catalog verification with signer extraction | `signature_windows.go` | built; compiled and vetted on Linux CI, untested on a real Windows host |
| Exec, pin, library maps and sweep checks, identity cache, suppression | `checker.go`, `pin.go`, `maps.go`, `sweep.go`, `cache.go` | built |
| Agent module wiring: ledger load and hash check, exec feed, pin loop, sweep loop with a full re-hash every tenth sweep | `internal/agent/mods/integrity.go` | built; no signer allowlist and no host hints passed yet |
| YARA: `Scanner` interface, `GoScanner` (a minimal pure-Go matcher), `LoadCorpusDir`, `YaraSchedule` for files and `/proc/<pid>/mem` | `yara.go`, `procmem_linux.go` | partial; the schedule is not wired into the module; `ExternalScanner` (pinned YARA-X) and the corpus loader are stubs; Windows process memory is a stub |
| D5d producer | `integrity.verdict` exists and has the `escalate` field | the rule still waits on a different kind (`binary_integrity`); see part 5 |
| Actions `ledger.sweep`, `ledger.verify_pin`, `binary.restore_from_depot`, `yara.scan` | none registered | missing |
| `phylax ledger build` and `lookup` | the `Builder` API only; no command in `cmd/phylax` | missing |
| Controller side: per-host ledger composition, vendor-package fetch, accepted-hash overrides, ledger delivery | none (and the agent `fetch` handler is a no-op, Known bug 4) | missing |
| Rootkit cross-checks, PAM content checks, SUID sweep | none | missing |

**3. Capability manifest**

| Field | Value |
| --- | --- |
| Name | `integrity` |
| Sides | agent, controller |
| OS | both |
| Privilege | root |
| Roles | any host; controller side on the controller |
| Consumes | `process_start`, `sec_event` (Sysmon 6 driver load and Sysmon 7 image load hashes on Windows), `file_change` (sweep triggers), `telemetry_gap` |
| Emits | `integrity.verdict` (schema 1, critical/high/normal), `integrity.yara` (schema 1, critical), `integrity.crosscheck` (schema 1, high), `integrity.claims` (schema 1, normal), `integrity.ledger_unavailable` (schema 1, high) |
| Budget | CPU 8 ms/s average (sweeps and scans run at low priority and are throttled separately by `bytes_per_sec`), held 24 MB (identity cache and the loaded ledger), 2 events/s, burst 20, 100 KB/min out, disk 100 MB (ledger file and YARA corpus). Starting values; the Invitational collector measures the ledger size |
| Default | core |
| Tables | `ledger_entry` (controller working set built from vendor packages and imports), `ledger_accept` (accepted hashes, with reason, owner, time) |
| Content | `ledger/` (signed indexes shipped in the release), `rules/yara/` (the corpus), the D5d and D11 rules |
| Actions | `ledger.sweep` (none risk), `ledger.verify_pin` (none), `binary.restore_from_depot` (service risk; locks `packages`/service lock; touches the binary path), `yara.scan` (none; read-only, takes a path) |
| Pages | Integrity (the verdict queue) |
| Evidence | [[redefiningreality-cobalt-strike#e6]], [[ccdc-the-great-the-good-and-the-ok#e10]], [[dannygaev-ccdc2025#e11]], [[cert-cc-vulnerability-note-vu-260001#e2]], [[discord-2026q-lessons#e1]] |

The core "Action families" table lists `yara.scan` under Collection (core). The scanner is this module's, so it is registered here; the core table needs the owner changed (part 12).

**4. Configuration**

```yaml
# manifest/modules/integrity.yml
integrity:
  sweep_interval_sec: 900        # all system paths; hash only files whose identity changed
  full_rehash_every: 10          # every Nth sweep ignores the identity cache
  pin_interval_sec: 60           # pinned service binaries, running image against disk against ledger
  maps_interval_sec: 60          # loaded libraries of service processes
  suid_interval_sec: 300         # SUID and SGID set hash sweep (Copy Fail control); starting value
  bytes_per_sec: 33554432        # sweep hashing throttle
  suppress_sec: 900              # identical findings are not re-emitted for 15 minutes
  sweep_roots: []                # default roots (/usr, /bin, /sbin, /lib*, /etc, /opt on Linux; System32, SysWOW64, drivers, Program Files on Windows)
  signers: []                    # third-party signer allowlist from the manifest (Splunk, SQL Server, Sysinternals)
  crosscheck_interval_sec: 300   # rootkit cross-checks (hunt content)
  yara:
    files: { enabled: true, interval_sec: 300, roots: [webroots, new binaries, temp dirs] }
    memory: { enabled: true, interval_sec: 300, cpu_budget_ms_per_sec: 4 }   # scheduled, low priority, inside the module budget
    engine: go                   # go (built) | yarax (pinned binary from the depot, for rules the Go matcher skips)
# Rendered per host from services.yml, not configured here: pins (process.binaries with pin: true) and the ledger reference.
```

```go
// package plan (built, extended)
type IntegritySettings struct {
	ModuleLimits
	Pins             []PinSettings `json:"pins,omitempty"`
	SweepRoots       []string      `json:"sweep_roots,omitempty"`
	SweepIntervalSec int           `json:"sweep_interval_sec,omitempty"`
	PinIntervalSec   int           `json:"pin_interval_sec,omitempty"`
	Ledger           LedgerRef     `json:"ledger"`                    // file name in StateDir and its sha256, in the signed config
	// NEW
	MapsIntervalSec      int          `json:"maps_interval_sec,omitempty"`
	SuidIntervalSec      int          `json:"suid_interval_sec,omitempty"`
	FullRehashEvery      int          `json:"full_rehash_every,omitempty"`
	BytesPerSec          int64        `json:"bytes_per_sec,omitempty"`
	SuppressSec          int          `json:"suppress_sec,omitempty"`
	Signers              []string     `json:"signers,omitempty"`
	CrosscheckIntervalSec int         `json:"crosscheck_interval_sec,omitempty"`
	Yara                 YaraSettings `json:"yara"`
}
```

The ledger file travels separately because it is large; the signed config pins its hash and the agent refuses a file that does not match, then reports itself degraded and retries every 30 s.

**5. Events**

Consumed: `process_start` (the exec feed), Sysmon 6 and 7 hash fields on Windows, `telemetry_gap`.

Emitted:

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `integrity.verdict` | 1 | critical for `known_bad`, `mismatch` and any escalated verdict; high for other alerting verdicts; normal for good verdicts when `EmitMatches` | `path`, `sha256`, `size`, `verdict` (`match`, `match_other_version`, `unknown`, `mismatch`, `known_bad`, `sig_invalid`), `trigger` (`exec`, `library`, `pin`, `sweep`), `root`, `escalate`, `pid`, `ppid`, `uid`, `process` (tree pointer), `service`, `flags`, `matched`, `expected` (all entries at the path) plus flat `expected_sha256`, `source`, `package`, `version`, `expected_signer`, `signer`, `bad_label`, `hint_only`, `hash_known_at`, `note`. Pin events add `running_sha256`, `disk_sha256`, `running_target`; library events add `library` |
| `integrity.yara` | 1 | critical | `rule`, `tags`, `target`, `pid`, `strings` (id, count, offset), `meta` |
| `integrity.crosscheck` | 1 | high | `check` (name from the hunt catalogue), `finding`, `detail`, `pid`/`module`/`path` as the check yields |
| `integrity.claims` | 1 | normal | `packages`: package name and version pairs read from the host package database (hints for the controller to fetch the matching vendor packages) |
| `integrity.ledger_unavailable` | 1 | high | `module`, `path`, `error` |

**D5d is wired to `integrity.verdict`, not to a new `binary_integrity` kind** (review D79, D324; Known bug 6). The verdict event already carries every field the pending rule asked for (path, package, expected and actual hash, signer, service) and an `escalate` flag that is true for `unknown`, `mismatch`, `known_bad` and `sig_invalid` under root, a service or a pin. The rule changes from `event: binary_integrity` to `event: integrity.verdict` with `escalate: true`, exempt-tagged, and moves out of `rules/pending/`. The code's choice is followed; a second kind would duplicate the first.

**6. Behaviour**

*Truth sources, never the host alone,* in order of trust:

| Rank | Source | What it gives | Where it comes from |
| --- | --- | --- | --- |
| 1 | **Lab reference ledgers** | Path to sha256, size, mode, owner package, signer, for each OS and role we have images for | Built in the lab from **stock images of the announced OS versions** (Rocky 9, Ubuntu 22.04, Debian 12, Server 2019 and 2022, Windows 11), signed, shipped in the release as compressed indexes. There are no real competition images, so the packet host's extra files show as `unknown` at the first sweep (review D356, D392, area 5) |
| 2 | **Windows signatures plus Winbindex** | Authenticode and catalog verification natively (`WinVerifyTrust`); exact sha256 for every Microsoft binary version of the builds in play | Winbindex data fetched and trimmed in CI for the three builds; cached (D-5) (review D357) |
| 3 | **Vendor packages** | For the exact package versions found on the host, the real file hashes | The controller downloads the `.deb` or `.rpm` from the distro mirror (prefetched for announced OS versions, cached), extracts and hashes the contents. This survives an attacker who edited the host's `dpkg` md5sums or RPM database |
| 4 | **Host package metadata** | `dpkg` md5sums, RPM SQLite digests | Hint only; used to guess which package version to fetch, never as proof. A hint-only match yields `unknown` with `hint_only`, never `match` |

The controller fetches the version the host *claims* (from `integrity.claims`) and the distro's current version. A binary that matches neither is a mismatch. Third-party signed software (Splunk, SQL Server, Sysinternals) is accepted against a signer allowlist from the manifest. A validly signed file from an allowlisted signer that the ledger does not know is accepted as `match`, with the signer in the note. The controller composes one ledger file per host (reference for its OS and role, plus the vendor entries for its claimed packages), signs it, and the signed config pins its hash.

*Verdicts.*

| Verdict | Meaning |
| --- | --- |
| `match` | Hash equals a trusted entry for this path and version |
| `match_other_version` | Hash is a known-good for a different version of the package (patch-level drift; informational, never alerts) |
| `unknown` | Path or hash appears in no trusted source (an unpackaged binary in a system directory) |
| `mismatch` | The path is known and the hash equals no known version |
| `known_bad` | The hash is on the ledger's bad list (a label says what it is) |
| `sig_invalid` | Authenticode or catalog failed, or the signer is not on the allowlist (Windows) |

Paths are normalised before lookup: usr-merge folded (`/bin` to `/usr/bin`, `/sbin`, `/lib*`), `" (deleted)"` stripped, Windows paths lower-cased without a drive letter. `HashKnownAt` lists other trusted paths where the same hash is known-good, which catches `/usr/bin/nologin` replaced by a copy of `/bin/bash`.

*When it checks.*

- **At enrollment:** a full sweep of system binaries, libraries, service binaries, drivers, and scheduled-task and autostart targets against the ledger. This replaces the one-time T+15 hunt for binaries, and the hunt re-runs it. The first sweep marks `unknown` findings outside executables running as root or a service with `first_sweep`, and the controller routes them to the hunt's triage queue instead of the alert queue. A `mismatch` or `known_bad` at the first sweep is still an alert, because a replaced packaged binary is exactly the prebake.
- **At every exec:** the agent hashes the executable (the image actually running, `/proc/<pid>/exe`; cached by device, inode, ctime and size) and looks it up. An `unknown` or `mismatch` hash running as root, as a service account, or as a scored service's process raises D5d. On Windows the hash comes from Sysmon 1 (and 6 for drivers, 7 for image loads).
- **Loaded libraries:** for service processes, file-backed mappings in `/proc/<pid>/maps` are checked against the ledger at start and every 60 s. This catches `LD_PRELOAD`, a replaced `.so`, and a PHP or Apache module that is not package-owned. Windows: Sysmon 7.
- **Periodic:** pinned service binaries every 60 s; all system paths every 15 minutes, hashing only files whose device, inode, size, mtime or ctime changed, with a full re-hash on every tenth sweep so a rootkit that forges the identity fields is eventually caught. The cache key is device, inode, ctime and size (ctime cannot be forged by userland the way mtime can); non-Linux builds key on path and mtime. The sweeps are low priority and throttled by `bytes_per_sec`.
- **SUID and SGID set:** hashed on a short cadence (`suid_interval_sec`), because FIM cannot see the page-cache write of Copy Fail [[cert-cc-vulnerability-note-vu-260001#e2]] and the hash sweep is the only catch (review N4.3). A new SUID file or a changed SUID hash is a verdict with `trigger: sweep`.
- **After every restore, re-enrollment or reset,** a full sweep runs before the host may be tagged golden. The tag is withheld until the sweep and the hunt are clean [COV X-2].
- **Around plan-tagged package installs,** the controller pre-resolves the hashes of the packages the node will install, so expected changes are `match` and others stay alerts. (v3's patch windows are replaced by `pkg.install` from the depot; the tag comes from the plan.)

*Service binary pinning.* The manifest ties each scored service to its process and its binaries (`process.binaries` with `pin: true`). The agent checks the running image (`/proc/<pid>/exe`, opened through the magic link so it is the real inode even when "(deleted)"; also memfd and a replaced inode) against the on-disk file **and** the ledger. That catches "swapped but not yet restarted" and "restarted on the trojan". Pin flags: `image_deleted`, `inode_replaced`, `disk_differs_from_running`, `memfd_image`, `disk_missing`, `stale_after_update` (both images ledger-good: a package update awaiting restart, informational), `running_<verdict>`, `disk_<verdict>`. Identical findings are suppressed for 15 minutes so a 60-second loop does not repeat forever. For a containerized service (`runtime: docker` or `podman`) the pin resolves the binary inside the container's mount namespace (core manifest, N7.6).

*Behavioural corroboration.* Severity rises when the same binary shows service-inappropriate behaviour, because a ledger can be incomplete and a rootkit can lie to hashing. The controller joins `integrity.verdict` with network and process events by pid; the detection rules express it (D4b, D1, D3):

| Signal | Example |
| --- | --- |
| Outbound from a service that has none | Postfix to a non-relay host; `dns.exe` to an unexpected peer (D4b) |
| Near-symmetric bytes in and out on a service socket | The proxy signature |
| A new listener, child shell or unusual module load | D1, D3, Sysmon 7 |
| Running image differs from the file on disk | The pinning check |

These would have caught the regional's Postfix proxy even without a ledger entry.

*YARA.* The scheduled scan runs every 5 minutes over files and over process memory, deduplicated by inode identity, at low priority with a pause between items so CPU stays inside the module budget, and raises D5-class alerts at tier 1 with a quarantine proposal.

- **Corpus.** The C2 set: Sliver, Mythic (Apollo and Poseidon), Realm, Sentinel, chisel, ligolo, pamspy, sshsnake, watershell, Cobalt Strike and Metasploit stagers [WT §2.3, §9.3]. It includes the **17 MIT-licensed UCF CCDC rules** (`nmagill123/compiled-yara-rules-rb2@c2b9d3f custom/`: Realm imix, Sentinel, chisel, ligolo, pamspy, sshsnake, watershell, jstap, headshot, powerlurk and others), imported as content with attribution, which removes the licence reason for that subset. Elastic protections-artifacts stay out. Other public sets are used only after their licence is checked.
- **Memory is kept** (review A5.Q1; David's call on a mixed record). Evidence against: sleep-masked beacons are encrypted while sleeping [[redefiningreality-cobalt-strike#e6]], and UCF ran memory polling, found red adapted its beacons, and paid real CPU [[ccdc-the-great-the-good-and-the-ok#e10]]. Reasons to keep it: implants that do not sleep-mask (chisel, ligolo, pamspy, sshsnake, watershell, stagers) are in memory in clear, and the scan is scheduled, low priority and capped by `cpu_budget_ms_per_sec`; if the cap is hit the scheduler slows down, never the host. `/proc/<pid>/mem` is read on Linux; `ReadProcessMemory` on Windows is not built.
- **Scan on write** (review N5.9): a write into a content root triggers `yara.scan` on that file as a `respond` recipe, which is faster than the schedule for webshells and needs no new Go because the action takes a path.
- **Engine.** The `Scanner` interface has the built `GoScanner` (text and hex strings with wildcards, `any/all/N of them`, boolean conditions, `filesize`, `uint8/16/32(offset)` in the first 4 KiB; regexes, jumps, modules, `fullword`, `xor` and `base64` are not supported, and such rules are listed in `Matcher.Skipped`, never silently ignored) and a stub for the pinned YARA-X binary. v3 specified YARA-X as the engine and flagged it as the one host binary in a default path. The code's pure-Go matcher needs no host binary, so the default is `engine: go`; YARA-X is the fallback for rules the Go matcher skips. Which engine ships is decided by how many of the 17 UCF rules appear in `Skipped` (part 12).

*Rootkit cross-checks* (review D80, D103, D331; David: yes, run by this module, defined as hunt content, no separate module). The loop runs the catalogue in the `hunt` section on a timer and emits `integrity.crosscheck` events. They need only native calls (`/proc`, `/sys`, getdents, the BPF syscall, netlink), never host tools. They are not a defence against a kernel rootkit that lies consistently to every view; they raise the cost.

*PAM and package content checks* (review D398, D399, built plus additions). Package verification without host tools: on Debian and Ubuntu the agent reads the per-package checksum lists under `/var/lib/dpkg/info/` and hashes files itself, which is a hint; on Rocky it reads the RPM SQLite database with its own library. Package holds (`apt-mark hold`, `versionlock`) on PAM, ssh, sudo and libc are flagged (D6c). New PAM content checks, from UCI `linux-toolbox/pam_audit.sh@f2af5a1`: any `pam_exec.so` line, `nullok` in an auth stack, and tamper with `pam_deny` (removed, reordered or commented). Findings are `integrity.crosscheck` events with check names `pam_exec`, `pam_nullok`, `pam_deny_tamper`, and D6i (PAM module or config changed) corroborates.

*The alert and the response.* The alert carries the hash, the ledger verdict, the signer, the owning package, the expected file and its source, the process tree and the network behaviour. **There is no automatic restore.** The one-click tier-1 response is: quarantine the file as evidence (hash, mtime, copy; `file.quarantine`), restore the known-good file from the **local depot** (`binary.restore_from_depot`, service binaries; command tools are in the trusted tool depot), restart the service, and verify with the scorer-mimic probe. Behavioural corroboration raises severity; a ledger entry accepted by an operator goes into `ledger_accept` and into overrides, so the queue stays quiet after review (an `integrity.verdict` for an accepted hash is suppressed).

*The local depot.* Known-good copies of service binaries and their packages for the announced OS versions, plus the vendor packages the ledger fetched. It is a signed release asset (small tier) and a controller cache (large tier), so a restore never depends on the internet (D-5). DePaul's "offline depot" is the model [PRO §2]. The `depot` module owns it.

*Limits (carried over).*

- A root attacker can lie to the agent. The cross-checks and behavioural corroboration are the mitigation. Hypervisor-level verification is not available.
- The first-contact trust gap: the ledger's own code runs on a possibly backdoored host. Hashing uses only native Go calls, never host tools.
- A ledger is only as complete as the images behind it. `unknown` is a prompt to look, not proof, and `match_other_version` keeps patch drift from flooding the queue.
- Expected false positives: package updates outside a tagged plan, self-built binaries, and files modified by the organizers' images. The queue lets an operator accept a hash into the overrides.

**7. Actions and content**

| Action | Risk | Locks | Scorer-visible touches | What it does |
| --- | --- | --- | --- | --- |
| `ledger.sweep` | none | none | none | Runs a sweep now (options: roots, full re-hash) and returns the stats; read-only |
| `ledger.verify_pin` | none | none | none | Checks one pin now, returns the flags and verdicts; read-only |
| `binary.restore_from_depot` | service | `packages`, the service lock | modifies the binary path of a scored service (declared pin) | Verifies the depot copy against the ledger, takes the replaced file as rollback data, writes atomically with owner, mode and label, restarts the service; verifies with the scorer-mimic probe |
| `yara.scan` | none | none | none | Scans a path with the corpus and returns the matches; used by the scan-on-write recipe |

Content: the ledger indexes in the release (`ledger/*.plx`), `rules/yara/` (corpus with a `LICENSE` and an attribution file for the UCF subset), the D5d rule, and the SUID sweep and PAM checks above. `phylax ledger build` takes package directories, Winbindex JSON and signer lists and writes a signed ledger; `phylax ledger lookup <path|sha256>` answers a lookup. Both use the built `Builder` and readers.

**8. UI**

The Integrity page is the verdict queue. Each row shows the path, hash, ledger verdict, signer, owning package, expected file and source, process tree and network behaviour, with buttons: accept this hash (writes `ledger_accept` and overrides), quarantine as evidence, restore from the depot (creates the plan), and hunt this hash everywhere (a hunt proposal). First-sweep `unknown` items appear in the Hunts triage queue, not here. Overview tile: hosts with an open mismatch. Host-grid column: "ledger sweep clean" (verified when the last full sweep has no open mismatch; amber when a first sweep is pending; failed on a `mismatch` or `known_bad`).

**9. Health**

`ok` with the ledger loaded and its hash matching. `degraded` while the ledger file is absent, mismatching or unsigned (the module retries every 30 s and has emitted `integrity.ledger_unavailable`); degraded also when the YARA engine skipped rules, or a sweep root could not be read. Gaps: `Matcher.Skipped` rule names, "Windows signature check not run" on a host where `WinVerifyTrust` failed, "memory scan unavailable" on Windows until `ReadProcessMemory` is built, filesystems the sweep could not read. Detail: ledger entry count and OS, last sweep stats (files, hashed, cache hits, bytes, verdict counts, errors), pins checked.

**10. Scoring safety**

- The module is read-only. It hashes files, reads `/proc` and judges, so it cannot fail a scored check; its cost is CPU and disk reads, bounded by the throttle and the budget.
- Hashing uses native Go calls and opens files read-only. Large files are skipped above a cap (2 GiB).
- The one write path is `binary.restore_from_depot`, a tier-1 plan node: it declares a touch on a scored service's binary, takes the service lock, runs the scorer-mimic probe before and after, rolls back on a failed probe and needs an approval record. Alert-only is the default stage and the only automatic behaviour (D-1).
- The sweep never reads content roots as binaries; scored content is the `content_guard` module's concern.

**11. Tests**

- Unit (built, extend): verdict logic including usr-merge folding, hint-only handling and `match_other_version`; the on-disk format round trip and signature rejection; deb and rpm readers; Winbindex import; pin flags (swapped not restarted, restarted on a trojan, memfd, deleted, stale after update); library maps; cache key; suppression window; sweep throttling; GoScanner conditions and `Skipped`; schedule deduplication by inode.
- Fixture: a fake `/proc` tree (`ProcRoot`) and recorded `process_start` streams; the 17 UCF rules loaded and the `Skipped` list asserted; the D5d rule's inline tests with a `integrity.verdict` event.
- Conformance: ledger absent at start is `degraded` not a crash; a changed ledger hash replaces it without losing the identity cache (`Keep`); `go test -race`.
- Lab: T01 (the prebaked set: ledger sweep finds every replaced binary), T31 (replaced Postfix `smtpd` proxy, trojaned `nologin`, an `LD_PRELOAD` library, a replaced `dns.exe` stand-in, an unknown hash executed; D4b fires for the proxy), T32 (a package update inside a plan tag yields no alert; an untagged update yields `match_other_version` or an alert with clear provenance), T12 (cross-checks catch an `LD_PRELOAD` rootkit hiding a process), T19 (after bulk re-enrollment the sweep runs automatically and the golden tag is withheld until clean). Latencies (exec to alert, swap to pin alert) are measured and reported, not targeted.

**12. Limits and open items**

- `shortcut: the agent integrity module passes no signer allowlist and no host-hint reader yet, so hint-only entries and allowlisted signers are not exercised end to end; wire both from the signed config before the first lab sweep.`
- `shortcut: the Windows Authenticode path is compiled and vetted on Linux CI only; upgrade at the first real Windows lab run.`
- `shortcut: Windows process-memory YARA is a stub; upgrade by implementing ReadProcessMemory only if the lab shows Windows implants in clear memory.`
- `shortcut: per-host ledgers are composed on the controller from claimed packages, which needs the agent fetch handler (Known bug 4); until it works the ledger ships with the release only.`
- Open: GoScanner or YARA-X as the default engine. Recommendation: Go by default (no host binary in a default path), and enable YARA-X for the rule files that appear in `Matcher.Skipped` after the UCF corpus loads. The lab run that settles it is the first load of the 17 rules.
- Open: cadence of the cross-checks (5 minutes here) and the SUID sweep (5 minutes). Recommendation: keep the starting values until the Invitational collector reports their CPU cost.
- Core changes: `yara.scan` ownership in the core action table; `Modules.Integrity` settings grow the fields above; the rule engine needs `first_sweep` routing in the controller (to the hunt queue) and the agent `fetch` handler.
