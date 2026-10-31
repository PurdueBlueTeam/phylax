#### `depot`

##### 1. Purpose and evidence

`depot` makes the platform work from the cache alone (D-5). It holds one content-addressed store of everything the event might need (static tools, distro and vendor packages, installers, reference data, rule sets, feeds), one signed index that says what each blob is and how important it is, the sync that fills the store on the controller from T+0, the trusted tool depot that operators use during a response, the package actions that install from the store, and the Go-native fallback tools for hosts where even a static binary cannot be run. The internet is available from every host and slow; it is an optimisation, never a dependency.

Why it matters for points:

- The red team replaces host binaries (a custom Postfix, `dns.exe`, trojaned `nologin` and `dash`). During a response neither operators nor Phylax may trust `ps`, `ss`, `ls` or even the dynamic linker of the host. DePaul's offline depot of known-good static tools is the model [PRO §2, patterns idea 4] (review D25, D451, D453, D452).
- Restoring a replaced service binary or reinstalling a package must not depend on a download that may be slow or blocked by default-deny egress (review D164). The integrity ledger's restore (`binary.restore_from_depot`) and the service restores read from the same store.
- The cache is the offline prerequisite of other modules: Sysmon and Sysinternals (`winevt`, `hardening`), YARA-X and the Winbindex extract (`integrity`), the Wazuh bundle (`wazuh`), Suricata rules (`suricata`), the nmap and xfreerdp pins for the Kali (`vantage`), the CISA KEV feed and vendor advisories (`vuln`).
- Vendor products need fixed builds that the hosts do not have: Splunk 10.0.10 [[security-hardening-in-splunk-enterprise#e3]], a fixed Roundcube, the fixed OpenCart, the VyOS image (review D442 to D445).

Decisions applied: D-5 (offline-first caches); review D13, D21 and D207 kept (content-addressed store, `phylax cache` build and sync, a cache plan generated from host OS and integrations); D442 to D445 changed (one signed index with a priority field instead of four tiers; vendor fixed builds and the KEV feed added); D446 to D450 kept (build in CI, publish channels, sync from T+0, cache-through for misses, index-delta refresh), without reasoning tied to repository or proxy rules (decision 3); D164 changed (package installs come from the depot over `fetch`); D26 kept (`phylax tools` Go-native fallbacks are not a duplicate of the depot: they are what runs when not even a static binary can be copied in). Decision 7: PDFs are generated in pure Go, so no PDF toolchain is cached.

Evidence against: a content-addressed cache with a signed index, a CI build job and a sync client is real complexity (the v3 complexity flag). It is bounded by one index format, the release signing path (`integrity.Signer`) and the rule that no feature requires a live fetch.

##### 2. Status and code

Status: partial. The tool depot is built; the cache pipeline is missing.

Built:

- `internal/depot`: `manifest.go` (signed manifest, `Entry`, `Lookup` by tool or applet), `store.go` (content-addressed blobs, atomic writes, hash-checked on write and read, size bounds, `FetchMissing` for fetch-at-init entries), `pack.go` (spec to store plus signed manifest), `deploy.go` (copy to a hidden per-event directory, applet symlinks, `Verify`), `run.go` (clean environment, hashed bytes executed from a sealed memfd on Linux), `exec_linux.go`, `exec_other.go`.
- `internal/depot/gotools`: Go-native `ps`, `ss`, `ls`, `hash`, `lsof` (Linux for `ps`, `ss`, `lsof`).
- `cmd/phylax/depot.go`: `phylax depot keygen|pack|fetch|deploy|list|verify|run|shell` and `phylax tools ps|ss|ls|hash|lsof`.
- `depot/recipes` and `depot/tools.json`: reproducible static builds (Alpine/musl container), 28 of 28 outputs bit-for-bit identical on one machine on 2026-10-22, about 77 MB in total; `windows.md` for the Sysinternals pins.
- `internal/actions/linux_pkg.go`: `pkg.install`, `pkg.upgrade`, `pkg.remove` with `source: depot:<path>` and sha256 checks (see Actions for what must change).

Missing:

- The cache pipeline: `phylax cache build` and `phylax cache sync`, the index with priorities, the cache plan, cache-through, index-delta refresh, progress reporting, bandwidth cap.
- The agent `fetch` handler is a no-op (`internal/agent/handlers.go:41`; Known bugs). Without it nothing reaches an agent from the store. Core task (review D117).
- `pkg.reinstall`, `pkg.repair`, `pkg.fetch_to_depot`.
- Agent-side periodic `Verify` of the deployed tools.
- The module registration, manifest and conformance wiring.

##### 3. Capability manifest

```go
module.Manifest{
	Name:      "depot",
	Sides:     []module.Side{module.SideController, module.SideAgent},
	OS:        nil, // Linux static tools; Windows gets Go tools and Sysinternals
	Privilege: "root",
	Roles:     []string{"controller"}, // the controller side; the agent side is eligible everywhere
	Consumes:  nil,
	Emits: []event.Type{ /* depot.sync_state v1, depot.deploy v1, depot.problem v1 */ },
	Budget: module.Budget{
		CPUMillisPerSec: 40, HeldMB: 32, EventsPerSec: 2, Burst: 20,
		BytesOutPerMin: 1 << 20, DiskMB: 8192, // controller cap; agents 512 for staging and the deployed tools
	},
	Default:  true, // core-default
	Tables:   []string{"depot_entry", "depot_sync"},
	Content:  []string{"depot/recipes", "depot/tools.json", "depot/index.d"},
	Actions:  []string{"pkg.install", "pkg.upgrade", "pkg.remove", "pkg.reinstall", "pkg.repair", "pkg.fetch_to_depot"},
	Pages:    nil, // a Platform section and an overview tile
	Evidence: []string{"[PRO §2]", "[[security-hardening-in-splunk-enterprise#e3]]", "[[known-exploited-vulnerabilities#e1]]"},
}
```

The disk cap is a ceiling, not a measurement: the free disk on the controller host is question E14 in `docs/impl/invitational-data.md`. `shortcut: budget numbers are estimates, replace with Invitational measurements`.

##### 4. Configuration

`modules/depot.yml` (controller) and the agent block `modules.depot` (agent side).

```yaml
# modules/depot.yml
store_dir: /var/lib/phylax/cache          # content-addressed blobs and the signed index
sync:
  bandwidth_kbps: 2048                    # cap so first-contact traffic is not starved; 0 = uncapped
  parallel: 2
  start: t0                               # begin at controller start, in priority order
mirrors:                                  # hosts the controller may fetch from (cache-through and sync)
  - archive.ubuntu.com
  - deb.debian.org
  - dl.rockylinux.org
  - download.sysinternals.com
  - live.sysinternals.com
  - github.com
  - objects.githubusercontent.com
priorities:                               # which index priorities to sync, in order
  - 0
  - 1
  - 2
cache_plan:                               # derived from hosts.yml and integrations.yml; edits are overrides
  closures: []                            # generated: per host OS and version, the service stacks' package closure
  integrations: []                        # generated: wazuh, suricata, zeek, splunk bundles when enabled
tools:
  hidden_dir_base: /var/tmp               # deployed depot is <base>/.<10 hex of HMAC(event secret)>
```

```yaml
# agent block (modules.depot)
dir: ""                                   # deployed tool depot; empty = derived from the event secret
stage_mb: 512                             # staging area for blobs pushed by the controller
verify_interval_sec: 600                  # re-hash deployed tools; 0 disables
```

```go
// package plan (new; ModuleSettings gains `Depot *DepotSettings`)
type DepotSettings struct {
	Dir               string `json:"dir,omitempty"`
	StageMB           int    `json:"stage_mb,omitempty"`
	VerifyIntervalSec int    `json:"verify_interval_sec,omitempty"`
}
```

**The index (review D442 to D445).** One signed index replaces the four tiers. It is the existing signed manifest (`depot.json`: the body bytes and an Ed25519 signature with the release key, domain-separated, through `integrity.Signer` and `Verifier`), extended with three fields per entry:

```go
type Entry struct {
	Name, Version, OS, Arch string
	SHA256 string; Size int64
	URL, License, Recipe, Source string
	Provides []string
	FetchAtInit bool
	Kind      string   // NEW: tool, package, installer, bundle, ledger_index, reference, feed, ruleset
	Priority  int      // NEW: 0 in the release, 1 fetched first, 2 background; lower syncs first
	NeededBy  []string // NEW: module names, so the Platform page says what an incomplete priority blocks
}
```

Priority replaces the tiers: 0 is shipped in the release (the binaries, rules, the YARA corpus, the Sysmon config, decoy pools, the ledger indexes for the announced OS versions, the index itself; tens of MB); 1 is fetched first and small (the tool depot and Sysinternals, Sysmon, YARA-X binaries, the Winbindex extract for Server 2019, 2022 and Windows 11, the Wazuh offline bundle and agent installers, Suricata rules, the Kali pins, the KEV feed and the vendor-advisory extract, the vendor fixed builds; hundreds of MB); 2 is large and runs in the background (distro packages for the service stacks with their dependency closure per OS, the exact vendor package versions for ledger proofs, security-relevant OS updates, optionally Windows cumulative updates; GB). The ordering inside a priority is by size, smallest first. Sizes are estimates until measured.

A blob is stored once, named by its sha256. An entry with `FetchAtInit` (Sysmon, Sysinternals) carries a pinned hash and URL only: the controller fetches it from the vendor, checks the pinned hash and stores it; the file is never redistributed. Microsoft updates Sysinternals files in place, so a fetch that no longer matches the pin fails closed, and the pin is refreshed deliberately.

##### 5. Events

Consumed: none.

Emitted:

| Kind | Priority | Key fields |
| --- | --- | --- |
| `depot.sync_state` | normal | Controller: `priority`, `entries_total`, `entries_done`, `bytes_total`, `bytes_done`, `state` (`idle`, `syncing`, `waiting`, `failed`), `rate_kbps`, `failed` (entry names with reasons), `index_version`. At most one event per 30 s, plus one on every state change |
| `depot.deploy` | normal | Agent: `dir_hash` (not the path), `tools` (names and versions deployed), `missing`, `ok` |
| `depot.problem` | high (critical for a planted file) | `what` (`verify_failed`, `fetch_failed`, `index_unsigned`, `blob_corrupt`, `planted_file`), `tool` or `entry`, `detail`. A deployed-tool verify failure is critical: a file in the hidden directory that is not in the manifest, or a hash mismatch |

##### 6. Behaviour

**The store.** `<store>/blobs/<sha256>`: content addressed, written atomically (temp file, fsync, rename), hash-checked on write and again on every read, bounded in size (`MaxToolSize`). A blob that fails its hash on read is deleted and refetched, and a `depot.problem{blob_corrupt}` is emitted. The store is the cache directory of the controller (Event store: "cache directory"). On a host the same store layout is used for the staging area.

**Build (CI, weekly and on release; a final rebuild before the event).** `phylax cache build` produces the set of blobs (sha256, size, source URL, licence, priority) and the signed index, plus a changelog. Ledger indexes are rebuilt from the lab images, Winbindex and the distro mirrors. The static Linux tools are built in the lab from `depot/recipes` (not in CI): `depot/recipes/build.sh out/` in an Alpine/musl container with pinned versions and source hashes (`versions.env`; the script refuses an empty or mismatching hash), then `phylax depot keygen`, then `phylax depot pack --spec depot/tools.json --src out/ --store dist/depot --key release.key`. The private key never enters the event; the public key is compiled in and printed on the platform driver's checklist.

**Publish.** Signed release assets (primary), the same signed artifacts under `dist/` in the repository (fallback; Enrollment lists the order), vendor mirrors directly (last). `phylax init` reports which channel worked.

**The cache plan (review D207).** Generated from the manifest: for each host, its OS family and version (from `hosts.yml`) selects the service stacks' package closures to cache; each enabled integration (`integrations.yml`) selects its bundle. Operators edit the plan through overrides, never by hand in the store. The plan is the answer to "what must be complete before feature X starts".

**Sync (review D446 to D450).** `phylax cache sync` runs on the controller from T+0: resumable and chunked, bandwidth-capped, in priority order, verifying every hash. The Platform page shows progress per priority (from `depot.sync_state`). A feature that needs an incomplete priority shows "waiting for cache" and starts when the entries it needs (`NeededBy`) are complete; it does not fail. A failed entry degrades one tool or package, never the platform.

**Cache-through.** An in-event fetch for something the index does not have (an unknown package version) goes through the controller only: a `pkg.fetch_to_depot` step fetches it from a host in the `mirrors` allowlist, logs the request and stores the blob with its observed sha256 and provenance `cache-through` (not signed by the release key). It can be installed only by a plan node that names that sha256, which an operator approves. Agents never fetch from the internet.

**Refresh at the event.** Only the index delta is fetched: new blobs since the last build, in priority order. If the internet is too slow, the previous complete set is already enough. After the repository freeze (the access week) nothing in the repository changes, so a refreshed index has to come from the release channel, not from a commit; see Limits for the case where it cannot.

**Delivery to hosts.** The controller moves a blob to an agent over the existing link as content-addressed 256 KiB chunks at bulk priority, resumable with `chunk_have` (Wire protocol: chunked transfers). The exact message flow (the controller pushing a staged blob before a step, or the agent requesting it with `fetch`) is the core wire's; this module needs two things from it: a blob lands in `StateDir/depot/stage/<sha256>` only after its digest verifies, and the staging area is bounded by `stage_mb`. Until the handler exists a step with a depot source fails in `check` with "blob not staged".

**Trusted tool depot (review D25, D451, D452, D453).**

- *Signed manifest:* name, version, OS and arch, sha256, size, source URL, licence (SPDX), build recipe, source reference, multi-call applet names. An unsigned, tampered or wrong-key manifest is refused everywhere.
- *Linux tools:* static musl builds from reproducible recipes: busybox, coreutils, procps-ng (`ps`, `top`), iproute2 (`ip`, `ss`), lsof, net-tools (`netstat`), tcpdump, strace, curl, socat, the OpenSSH client (`ssh`, `ssh-keygen`, `scp`), file (with `magic.mgc`), findutils, grep, tar, gzip, xz; toybox and nmap (with a data tarball) optional. GPL and LGPL tools ship as unmodified upstream builds with the pinned source tarball URL and the recipe as the source reference; the release also carries those tarballs or a written offer when binaries are redistributed.
- *Windows tools:* our own Go tools (`phylax tools` equivalents compiled into `phylax.exe`) plus Sysinternals fetched from Microsoft at `phylax init` with pinned hashes (procmon, autoruns, tcpview, handle, listdlls, sigcheck, pslist, sysmon). Never redistributed. The Authenticode chain of the pinned files has not been validated yet: run `sigcheck64 -a` on Windows once before the event.
- *Deployed depot:* `<dir>/depot.json` and `<dir>/bin/<tool>` with the directory mode 0700 and tools 0500, applet symlinks for multi-call binaries. The directory is hidden and per event (D-8): `/var/tmp/.<10 hex>` from an HMAC of the event secret, overridable with `--dir` or `$PHYLAX_DEPOT`. Obscurity is not a boundary.
- *Use:* every `phylax depot run` re-hashes the tool, requires a regular file that is not group or world writable, and executes the hashed bytes from a sealed memfd (`/proc/self/fd/3`), so swapping the file between check and exec changes nothing. The environment is rebuilt from scratch: `PATH` is the depot's `bin` only, no `LD_*`, no shell start-up hooks, nothing inherited except `TERM` and `TZ`. Static binaries need no host loader. `phylax depot shell` verifies the whole depot at start and re-hashes the shell; `phylax depot verify` exits 1 on any mismatch or planted file.
- *Network:* only the controller fetches. Agents get tools from the controller.

**Go-native fallbacks (review D26).** `phylax tools ps|ss|ls|hash|lsof` read `/proc` and netlink `sock_diag` directly and run when not even a static binary can be copied in. `ps` flags deleted executables, `lsof` flags deleted open files, `ls` shows hidden files, inodes and symlink targets. They are Linux-only for `ps`, `ss`, `lsof`.

**Limits of the depot.** It defeats replaced binaries, a poisoned `PATH` and `LD_PRELOAD`, and a backdoored loader. It does not defeat a kernel rootkit that lies to any user-space tool; the hunt's rootkit cross-checks are the mitigation.

**Agent-side verification.** Every `verify_interval_sec` the agent re-hashes the deployed tools against the signed manifest; a mismatch or an unexpected file in the directory is a critical `depot.problem`. The manifest in the deployed directory is checked against the release public key held in the signed config.

##### 7. Actions and content

Actions (core Packages row; the module owns them):

| Action | Where | Risk class | Locks | Scorer-visible touches | State |
| --- | --- | --- | --- | --- | --- |
| `pkg.install{name, version, source, sha256}` | agent | service | `packages` | restart of any service the package provides, declared from the package-to-service map; none for a package that provides no service | built; must change: remove the patch-window requirement and proxy, accept a staged closure, declare touches |
| `pkg.upgrade{name, version, source, sha256}` | agent | service | `packages` | same | built; same change |
| `pkg.remove{name}` | agent | service | `packages` | refuses a package that provides a scored service | built; keep (not in the v3 catalogue row; the code has it) |
| `pkg.reinstall{name}` | agent | service | `packages` | same as install | missing |
| `pkg.repair{}` | agent | service | `packages` | none | missing |
| `pkg.fetch_to_depot{name, version, os}` | controller | none | none | none | missing |
| `windows.hotfix{kb}` | agent (Windows) | service | `packages` | possible reboot, so the reboot-survival gate applies | built (cached MSU only, `wusa`); Windows Update Agent COM is deferred |

*Install from the depot (review D164).* A step installs a pinned version from a depot path after checking the file's sha256 (the `sha256` parameter or the directory's `SHA256SUMS`), re-verified right before use. The transaction uses the host package manager on the staged closure with all repositories disabled (apt with the sources empty for the call, dnf with `--disablerepo=*`), so nothing is fetched by the host. `dry-run` shows the package manager's own simulated transaction. A package is never installed without a pinned version or a depot source. The dependency closure is cached, so an offline install is complete or it fails in `check`.

*Preflight and repair.* `pkg.repair` is a preflight that fixes a broken package manager before an install: the apt or dnf binary missing, empty or broken sources, stale lock files, an interrupted `dpkg` (`--configure -a`), a corrupt rpm database, and it sources replacement files from the depot. Peer references: UA `repairPackageManagers.yaml@b227937` and `distroRepair.sh`. The repair never changes the configured repositories of a host in a way the scorer sees.

*Reboot-survival gate.* Any package change that can need a reboot (kernel, glibc, systemd, `windows.hotfix`) is gated by the hardening module's reboot-survival preflight (review N3.2): the host must prove it comes back (services enabled, boot files present) before the node applies. The gate is a lint rule on the node, not a step this module runs.

*No automatic rollback.* Package changes are not rolled back by the dead-man; the way back is `pkg.reinstall` of the previous version, which is why the depot keeps the previous version's blob for every service package it installs.

Content: `depot/recipes/*` (build scripts and pinned versions), `depot/tools.json` (the spec with licences and pins), `depot/index.d/*.yml` (entries for vendor builds, feeds and bundles, with priority and `needed_by`).

##### 8. UI

A section on the Platform page: per priority, entries and bytes done, current rate, failed entries with reasons, the index version and signature state. An overview tile "cache" (green when priorities 0 and 1 are complete, amber while syncing, red on a failed signature). The tool depot has no page: it is the `phylax depot` command line on the controller and on any host, used during a response. The package nodes appear in the Plans page like any other plan nodes. The host grid gets no column from this module.

##### 9. Health

Controller side: `ok` when the index is signed and loaded and no entry of an enabled priority has failed; `degraded` when sync is waiting or an entry failed (the Gap names the entry, for example `wazuh bundle 4.14.9 not cached: network`); `unavailable` when the index signature fails or the store is not writable. Agent side: `ok` when the deployed depot verifies; `degraded` when staging is full (`stage_mb`) or a tool is missing; any verify failure is critical via `depot.problem`. Usage reports store size, held bytes and bytes out.

##### 10. Scoring safety

Cache operations never touch a scored host. The dangerous parts are the package actions:

- Installing or upgrading a package that provides a scored service restarts it. The node declares the service touch from a package-to-service map (the code's `pkgScoredAliases` today; to be generated from `services.yml` bindings, since the code returns no touches), so the scoring lint requires a quiet window, a scorer-mimic probe afterwards and a human approval.
- `pkg.remove` refuses a package that provides a scored service (built).
- The host fetches nothing, so a package change never needs an outbound allowance and never changes egress policy.
- Dependency changes can replace a library a scored service uses; the dry-run transaction is shown in the diff for approval.
- Alert-only stage: the cache sync and the verify loop only observe and fetch on the controller. Installing is always a plan node with an approval.

##### 11. Tests

Built: manifest validation, signing and verification (unsigned, tampered, wrong key), store (put, hash mismatch on write and on read, size bound, atomic write), pack and deploy (permissions, applet symlinks, missing blobs), run (clean environment, memfd execution, swap between check and exec), `FetchMissing` with fetch-at-init pins, gotools (`ps`, `ss`, `ls`, `lsof` against a fake `/proc`), package action tests with a fake runner (versions, dry-run, scored-removal refusal, depot-file hash checks, patch-window requirement).

To build: index with `Kind`, `Priority`, `NeededBy` and priority-ordered sync (resume after kill, bandwidth cap, partial blob never visible), cache plan generation from a fixture manifest, cache-through record and the approval requirement, agent staging and verify loop, `pkg.reinstall`, `pkg.repair` against fixture broken states, install without a patch window, touches declaration from a package-to-service map, conformance (starts with no config; starts with default config on a fixture store; stops within 5 s; emits only declared kinds; budget; link-loss and reconfiguration; `go test -race`).

Lab tests (v3 ids): T40 offline drill (cold start with the internet blocked, cache from a prior sync: plans, ledger lookups, restores and the Wazuh deploy work, and missing priorities show "waiting"), T-depot (build the tools, fill source hashes, pack and sign, run `depot verify` and `run` on each target OS image), and the Invitational questions E15 (internet from each host class: bandwidth, latency, TLS interception), O11 (does the offline state work in the real environment, how long does a sync take).

##### 12. Limits and open items

- `shortcut: static tools are built in the lab, not in CI, and the Alpine package set inside the build image is not pinned, so a rebuild months later may differ; pin the apk set if reproducibility across dates matters`.
- `shortcut: toybox, lsof and procps-ng sources are trust-on-first-use over TLS, not independently verifiable; net-tools has no upstream signature (sha512 cross-checked against Alpine aports); confirm key fingerprints out of band before the event`.
- `shortcut: Sysinternals Authenticode chain not validated at pin time; run sigcheck64 once on Windows before the event`.
- `shortcut: phylax tools ps, ss and lsof are Linux-only; add Windows versions only if a response needs them (Sysinternals covers it)`.
- `shortcut: Windows package updates are cached MSU files installed with wusa, not Windows Update Agent COM; add WUA only if hotfix injects need it`.
- Core task: the agent `fetch` handler and the blob push (D117). Nothing reaches an agent until it exists.
- Core change request: `internal/depot` imports `internal/integrity` for `Signer` and `Verifier`, and `internal/depot/gotools` imports `internal/collect/net`. Both are sibling imports under the module contract. Move the release-key signing types to a small core or shared package, and take the socket reading from the shared stateless socket library proposed in the `inventory` section.
- Open: after the repository freeze nothing in the repository can change, so a refreshed signed index must come from the release channel. If the release pipeline also counts as frozen, runtime additions (a vendor version found in the environment) need a different path: an operator-pinned entry (URL and sha256 typed in the UI, written to `overrides.yml`, verified by the entered hash, installable only after approval). Decide before the freeze.
- Open: package-to-service map. `pkgScoredAliases` is a hard-coded list; it should come from `services.yml` (the service's package names). Needed by the scoring lint.
- Open: exact fixed versions for Roundcube, OpenCart and VyOS depend on the 2027 products (Roundcube is confirmed as the webmail; Splunk 10.0.10 is known).
- Open: the previous-version blob policy for `pkg.reinstall` (how many versions to keep per package) and the disk cost of the dependency closures, to be measured at the Invitational (E14, E17).
