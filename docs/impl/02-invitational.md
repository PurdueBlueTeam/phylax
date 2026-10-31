# W2 Invitational Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Have, by 2026-11-07, an observe-mode Phylax configuration, the few code changes it needs on today's v3 code, a read-only collector kit (C1 to C7), and a runbook, all rehearsed once on the BTaP replica.

**Architecture:** Observe mode is configuration, not code: a generator script derives an observe manifest from `manifest/2027` (no decoys, no canary probes); every module's act switch is already off in code. Three small Go changes close real gaps (no way to mint enrollment bundles, no way to start in safe mode, safe mode blocks read-only actions). The collectors are standalone `sh` and PowerShell 5.1 scripts under `tools/invitational/` that share one small library and each write one directory plus one archive; exports are uploaded to the team Nextcloud by hand.

**Tech Stack:** Go 1.27.2 (mise), POSIX `sh`, Windows PowerShell 5.1, `tcpdump`, `pktmon`, `curl`, Python 3 `http.server` (to serve the kit from the controller host).

**Spec:** `phylax_design.md` (v4), section "Operations" > "The Invitational: observe mode and battle-test tiers" (I1, I2) and "Testing and lab"; module sections for `detect`, `capture`/`net`, `audit`, `winevt`, `integrity`, `deception`, `creds`; and `docs/impl/invitational-data.md` (questions S, E, R, O; collectors C0 to C9). Tests T70 (observe mode leaves host state unchanged) and T27 (console bootstrap) apply.

## Global Constraints

- Go 1.27.2 via mise; `CGO_ENABLED=0` for builds (the race job needs `CGO_ENABLED=1`, see `docs/impl/00-proving.md` Task 2). `make build build-windows vet test race` passes at every commit.
- Small commits, one logical change each, message `area: summary` (for example `invitational: c1 packet capture scripts`). **No attribution lines** in commits.
- Real tests, no mocks of the code under test. A stub external program (a fake `phylax` binary for `e.sh`) is a fixture, not a mock of the code under test.
- ponytail: smallest complete change; a known limit gets a `shortcut: <limit>, <when to upgrade>` comment.
- **Collectors observe only** (data doc, "Ground rules"): no config edits, restarts, reboots, firewall changes, extra accounts, or reads of password stores. Allowed: packet capture, log reads, `ss`/`systemctl show`/`Get-*` queries, file hashing, HTTP GETs. A collector writes only under `$INV_ROOT` (Linux default `/var/tmp/phylax-inv`, Windows `C:\ProgramData\phylax-inv`).
- Every record is UTC with second precision; each collector notes the host's NTP offset (question O5).
- No clipboard between consoles and outside: every command a person types is short; scripts are fetched from the controller by URL; results leave over the network (Nextcloud, by hand), never typed.
- Windows scripts target PowerShell 5.1 (Server 2019/2022, Windows 11): no `?:`, no `-Parallel`, no `ForEach-Object -Parallel`, no `&&`.
- Size limits: pcap rings 100 MB x 20 per capture process; internet probe downloads capped at 100 MB per host class; log archives skip files over 1 GB each (record the skip).
- The Invitational tiers are unchanged by A-AUTO (design, Operations): Tier A everywhere with every `act_enabled` false; Tier B on non-scored accounts and one canary host; Tier C only in the second half.

## Review Focus

- **Re-running a collector** (a person types the line twice, or after a console hiccup): expected to refuse a second `c1-capture.sh start` while the first runs, and any other collector to make a new timestamped directory rather than overwrite. Tests in Tasks 6 and 1.
- **Disk fill by captures and archives** on a 20 GB VM: expected `c1-capture.sh start` to refuse when free space is below `INV_MIN_FREE_MB` (default 6000) and to stay inside two rings of 20 x 100 MB. Task 6.
- **Missing tools or privileges** (no `ss`, no `curl`, not root, `pktmon` absent on an older image): expected the script to record the exit code in `_index.tsv` and continue, never abort half way. Tasks 1 and 7.
- **Secrets in collected data** (sudoers, AD user descriptions, `.env` files): expected no collector to read `/etc/shadow` or password hashes, and the AD archive to carry `SENSITIVE` in its name so it goes to the private Nextcloud folder only. Tasks 1 (lint) and 10.
- **Controller restart mid-event**: expected the bundle files not to be regenerated unless `-bundles` is passed again, and a consumed token to stay consumed. Tasks 2 and 3.
- **Console typing**: the longest line a person types is under 70 characters and uses only `a-z 0-9 . : / | -` and space (data doc O2: special keys such as `| ~ \ ' "` may not map). Task 14 measures the length; the pipe is the one punctuation exception; the rehearsal (Task 15) checks both and tries to shorten the line.

---

## What exists today (verified in the code on branch `v3-redesign`, 2026-10-31)

| Item (design I1, I2, data doc) | Status | Evidence and consequence |
|---|---|---|
| Every module act off | **Usable** | `BuildAgentConfig` (`internal/controller/genconfig.go`) never sets `Detect.ActEnabled`; `internal/agent/mods/detect.go` passes `AlertOnly: !ActEnabled`; `TestBuildAgentConfigRealManifest` asserts it. No other module has an act switch yet (W1 adds them). |
| Agents run `net`, `audit`, `integrity`, `detect` (Linux), `winevt` (Windows), `capture` (role `capture`, Linux) | **Usable** | factories in `internal/agent/mods/*.go`; config comes from the manifest roles. Windows has no raw capture (`capture.go` returns unavailable): C1 `pktmon` covers it. |
| Safe mode on at start | **Needs code** | state is only the file `<state>/safe_mode`, created by the UI after connect (`WebOps.SetSafeMode`) or by hand. Tasks 2 and 3 add `Bundle.Safe`. |
| Enrollment of a host | **Needs code** | `Controller.MintToken` is called only from tests; no command writes a bootstrap bundle. Tasks 2, 3 and 5. |
| Safe mode keeps checks working (design: "checks and rollbacks still work") | **Needs code** | `internal/actions/env.go` returns `ErrSafeMode` for every non-dry-run action including `ReadOnly` ones, and `executor_test.go` pins that for `file.hash`. Task 13. |
| Decoys and honeytokens (Tier A) | **Usable, on** | role `decoys` plus `decoys.yml`, LAN only. They open listeners and plant files; David decided they run in observe mode (Open questions 1). The generator keeps them; `--no-decoys` drops them. |
| Canary probes from every Linux host | **Usable, left off** | `genconfig.go` turns `policy.egress.canary_ports` into outbound dials; the generator empties the list. |
| External checks, scorer-mimic (C9, Tier A) | **Library exists, start path unverified** | `internal/checks`, `internal/vantage`, `controller/checks_hub.go`; whether the UI starts rounds is checked in the rehearsal (Task 15). |
| Hunts, ledger, YARA (Tier A) | **Linux only, ledger unverified** | `integrity` module is registered for non-Windows hosts; a ledger comes from `phylax depot`. Checked in the rehearsal. |
| Firewall shadow mode | **Not wired** | `internal/firewall` has `ModeShadow` but no module or action installs it. Offline only: `phylax manifest render <host> --format nft`. No W2 code (belongs to the firewall retrofit). |
| Alert-only content guard, service doctor, flag-only session eviction, live scorer learning | **Not present** | no package exists. The Invitational answers the scorer questions offline from C1 pcaps through `internal/scorer`; no W2 code. |
| Tier B (`respond`, `firewall`, eviction `act_enabled`) | **Not present as modules** | what exists: the plan engine with dead-man, `user.*`, `firewall.allow`, `ad.account.*` actions and `plans/first-hour/*.yaml`. Tier B at the event is operator-approved plans on the canary host with safe mode switched off for that host in the UI; nothing automatic. |
| Device read-out (C8), check rounds (C9) | **Not in this plan** | runbook gives the by-hand read paths for C8; C9 is the rehearsal item above. |

## Open questions (placeholders, not decisions)

1. Decided (David, 2026-10-31): decoys (LAN-only) and honeytokens run in observe mode. The generator keeps them by default; `--no-decoys` drops them.
2. Decided (David, 2026-10-31): the canary host for Tier B is `win11-wkst`.
3. Where the kit lands on the controller host: this plan assumes Nextcloud, reachable from `ubuntu-wkst`'s browser (design: expected writable from inside). If not, the kit travels by whatever the packet allows.

---

### Task 1: Seams: collector library, test harness and lint

**Files:**
- Create: `tools/invitational/lib.sh`, `tools/invitational/lib.ps1`
- Create: `tools/invitational/testlib.sh`, `tools/invitational/test.sh`, `tools/invitational/test_lib.sh`
- Create: `tools/invitational/doc.go`, `tools/invitational/invitational_test.go`

**Interfaces:**
- Produces (shell API used by every later collector; names are fixed here):
  - `inv_utc` prints `2026-11-07T14:03:22Z`.
  - `inv_init CID` sets and exports `INV_ROOT` (default `/var/tmp/phylax-inv`), `INV_HOST` (`hostname -s`), `INV_CID`, `INV_STAMP` (`20261107T140322Z`), `INV_OUT` (`$INV_ROOT/$INV_HOST/$CID-$INV_STAMP`), creates `$INV_OUT` (if it already exists, appends `-2`, `-3`, ... so a second run in the same second never overwrites), writes `$INV_OUT/_meta.txt` (UTC time, host, `uname -a`, one NTP-offset line from `chronyc tracking`, else `timedatectl show-timesync`, else `ntpq -pn`, else the text `ntp: unavailable`).
  - `inv_run NAME CMD [ARG...]` runs the command, stdout and stderr into `$INV_OUT/NAME.txt`, appends the line `NAME<TAB>EXIT<TAB>SECONDS` to `$INV_OUT/_index.tsv`, always returns 0; a missing command records exit 127.
  - `inv_pack` creates `$INV_ROOT/$INV_HOST-$INV_CID-$INV_STAMP.tar.gz` from `$INV_OUT` and prints `PATH BYTES SHA256`.
- PowerShell: `Inv-Utc`, `Inv-Init -Cid <string>` (sets `$script:InvRoot` default `C:\ProgramData\phylax-inv`, `$script:InvHost` = `$env:COMPUTERNAME`, `$script:InvOut`), `Inv-Run -Name <string> -Script <scriptblock>` (output to `$InvOut\<Name>.txt`, same `_index.tsv` format, errors recorded not thrown), `Inv-Pack` (zip via `Compress-Archive`; `# shortcut: Compress-Archive caps at 2 GB, switch to tar.exe if an evtx set exceeds it`).
- Test harness: `testlib.sh` defines `t_pass NAME`, `t_fail NAME MSG`, `assert_eq NAME EXPECT ACTUAL`, `assert_file NAME PATH` (exists and non-empty), `assert_grep NAME PATTERN PATH`. `test.sh` runs `sh -n` on every `*.sh`, the lint, then every `test_*.sh`, prints `PASS name`/`FAIL name: msg`, exits 1 on any FAIL. Each later task adds one `test_<topic>.sh` and nothing else to the harness.
- Lint rule (in `test.sh`): a `.sh` or `.ps1` line containing a forbidden token must carry the comment marker `inv:ro` (the author asserts the use is read-only). Tokens, sh: `rm mv cp chmod chown useradd usermod userdel passwd chpasswd reboot shutdown halt kill pkill killall iptables ip6tables nft ufw systemctl service sed -i crontab visudo mount umount sysctl -w setenforce auditctl apt apt-get dnf yum pip shadow`; ps1: `Set- New-ItemProperty Remove- Restart- Stop- Disable- Enable- Add- Clear- Reset- net user net localgroup reg add reg delete sc config shutdown /etc/shadow`. Exceptions without a marker: `Set-StrictMode`, `Set-Content` and `Add-Content` to a path containing `InvOut` or `InvRoot`, `Remove-` is never exempt.

- [ ] **Step 1: Write the failing tests**

`tools/invitational/test_lib.sh` (sourced by `test.sh` after `testlib.sh`):

```sh
# test_lib.sh
T=$(mktemp -d); export INV_ROOT=$T/root
. "$(dirname "$0")/lib.sh"
inv_init demo
assert_file lib_meta "$INV_OUT/_meta.txt"
assert_grep lib_meta_host "$(hostname -s)" "$INV_OUT/_meta.txt"
inv_run echo1 echo hello
inv_run missing_cmd no-such-command-xyz
assert_grep lib_run_out hello "$INV_OUT/echo1.txt"
assert_grep lib_index_ok "^echo1	0	" "$INV_OUT/_index.tsv"
assert_grep lib_index_127 "^missing_cmd	127	" "$INV_OUT/_index.tsv"
set -- $(inv_pack); assert_file lib_pack "$1"
tar tzf "$1" | grep -q "echo1.txt" && t_pass lib_pack_has_file || t_fail lib_pack_has_file "echo1.txt not in archive"
case $(inv_utc) in 20??-??-??T??:??:??Z) t_pass lib_utc ;; *) t_fail lib_utc "$(inv_utc)" ;; esac
inv_init demo; assert_eq lib_dirs_distinct 2 "$(ls "$INV_ROOT/$INV_HOST" | wc -l)"   # same CID, same second: second dir gets a suffix
```

`tools/invitational/invitational_test.go` (package `invitational`):

```go
func TestScripts(t *testing.T)  // skips on windows or when sh is missing; runs `sh test.sh` in this dir with INV_TEST=1; fails with the script output if it exits non-zero
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./tools/invitational/ -run TestScripts -count=1`
Expected: FAIL (`lib.sh: No such file` in the output).

- [ ] **Step 3: Implement the files listed in Files**

`lib.sh` and `test.sh` per the Interfaces block (no `set -e`; scripts must keep going). `lib.ps1` per its signatures (it cannot be run on this machine: no `pwsh`; `test.sh` runs a PowerShell syntax check only when `pwsh` exists, via `pwsh -NoProfile -Command "[void][System.Management.Automation.Language.Parser]::ParseFile('$f',[ref]$null,[ref]$e); if($e){exit 1}"`, otherwise prints `SKIP ps1-syntax (no pwsh)`). `doc.go` is `package invitational` with a one-line comment.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./tools/invitational/ -count=1 -v && sh tools/invitational/test.sh | tail -3`
Expected: PASS; the last lines are `PASS` rows, no `FAIL`.

- [ ] **Step 5: Commit**

```bash
git add tools/invitational
git commit -m "invitational: collector library, test harness and read-only lint"
```

---

### Task 2: Bundle.Safe and Controller.WriteBundles

**Files:**
- Modify: `internal/agent/bootstrap.go` (type `Bundle`, add one field)
- Create: `internal/controller/bundles.go`
- Test: `internal/controller/bundles_test.go`

**Interfaces:**
- Consumes: `Controller.MintToken(host string, ttl time.Duration) (string, error)`, `Controller.Pin() link.Pin`, `Controller.PlanPublicKey() ed25519.PublicKey`, `agent.ParseBundle`, `atomicfile.WriteFile(path, data, perm)`, test helper `newCtl(t)` (any host except `"ghost"` is known).
- Produces:
  - `agent.Bundle.Safe bool` with tag `json:"safe,omitempty"`: start the agent in safe mode (acted on by Task 3).
  - ```go
    type BundleOptions struct {
        Controllers []string      // host:port the agent dials, required
        TTL         time.Duration // token lifetime; <= 0 means DefaultTokenTTL
        Safe        bool
    }
    // WriteBundles mints one token per host and writes <dir>/<host>.json (dir mode 0700, files 0600).
    // All hosts are validated before any token is minted.
    func (c *Controller) WriteBundles(dir string, hosts []string, o BundleOptions) error
    ```

- [ ] **Step 1: Write the failing tests** in `internal/controller/bundles_test.go`

```go
func TestWriteBundles_ParseAndEnroll(t *testing.T)
// newCtl(t); WriteBundles(dir, []string{"h1","h2"}, BundleOptions{Controllers: []string{"10.0.0.5:7443"}, TTL: time.Hour, Safe: true}).
// For each host: file mode is 0600; agent.ParseBundle(contents) succeeds; b.Host == host; b.Token != "";
// b.Safe is true; b.Controllers == ["10.0.0.5:7443"]; b.ControllerPin parses to x.c.Pin();
// b.PlanKey == hex.EncodeToString(x.c.PlanPublicKey()); the two tokens differ.
func TestWriteBundles_UnknownHostWritesNothing(t *testing.T)
// hosts {"h1","ghost"}: errors.Is(err, ErrUnknownHost); dir has no files; a following MintToken("h1",0) still works.
func TestWriteBundles_RequiresController(t *testing.T)
// empty Controllers: non-nil error, no files.
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/controller/ -run TestWriteBundles -count=1`
Expected: FAIL to compile (`undefined: BundleOptions`).

- [ ] **Step 3: Implement** `WriteBundles` in `bundles.go` and the `Safe` field in `bootstrap.go`

Validate first (`c.opt.HostKnown`, controllers non-empty, host names non-empty), then mint and write each file with `atomicfile.WriteFile`. Use `agent.Bundle` and `json.MarshalIndent`. Import direction: `internal/controller` already imports `internal/agent`? If it does not, define the JSON shape with `agent.Bundle` anyway only if the import creates no cycle; otherwise marshal a local struct with identical tags and let the test (which parses with `agent.ParseBundle`) prove they match.

- [ ] **Step 4: Run to verify it passes**

Run: `go test -race ./internal/controller/ -run TestWriteBundles -count=1` (needs `CGO_ENABLED=1`)
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/bootstrap.go internal/controller/bundles.go internal/controller/bundles_test.go
git commit -m "controller: write enrollment bootstrap bundles"
```

---

### Task 3: `phylax serve -bundles` and safe mode at first run

**Files:**
- Modify: `cmd/phylax/serve.go` (flags and call), `cmd/phylax/agent.go` (`adoptBootstrap`)
- Test: `cmd/phylax/bundles_test.go`

**Interfaces:**
- Consumes: Task 2's `Controller.WriteBundles`, `agent.Bundle.Safe`, `actions.NewSafeMode(path).Set(true)`, `agent.Layout.SafeModeFile()`, `controller.New`, `manifest.LoadDir`.
- Produces:
  - serve flags `-bundles DIR`, `-advertise HOST:PORT`, `-bundle-ttl DURATION` (default `8h`), `-bundle-safe` (bool). With `-bundles` set, serve writes one bundle per manifest host before accepting agents; `-advertise` is required with `-bundles`; a manifest is required.
  - `func writeBundles(c *controller.Controller, m *manifest.Manifest, dir, advertise string, ttl time.Duration, safe bool) error` (sorted host names from `m.Hosts`).
  - `adoptBootstrap(l agent.Layout, path string) error` additionally switches safe mode on (persisted marker) when the bundle has `Safe: true`. It runs only when the state directory has no bootstrap yet (`agent run`) or on `agent install`, so a later "safe mode off" in the UI is not undone by a restart.

- [ ] **Step 1: Write the failing tests**

```go
func TestAdoptBootstrapSafe(t *testing.T)
// bundle JSON with "safe": true -> adoptBootstrap -> os.Stat(l.SafeModeFile()) exists and actions.NewSafeMode(l.SafeModeFile()).On() is true.
// Same bundle with safe false/absent -> no marker file.
func TestWriteBundlesForManifest(t *testing.T)
// m := manifest.LoadDir("../../manifest/2027", manifest.Options{}); controller.New with Config{DataDir: t.TempDir()} (after Validate) and Options{HostKnown: manifest host check};
// writeBundles(c, m, dir, "172.20.240.5:7443", time.Hour, true): one <host>.json per m.Hosts key (8 files), each parses with agent.ParseBundle with Safe true.
func TestServeBundlesNeedsAdvertise(t *testing.T)
// commands["serve"].run(ctx, []string{"-data-dir", tmp, "-bundles", tmp2}) returns an error whose text contains "-advertise".
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/phylax/ -run 'TestAdoptBootstrapSafe|TestWriteBundlesForManifest|TestServeBundlesNeedsAdvertise' -count=1`
Expected: FAIL to compile (`undefined: writeBundles`).

- [ ] **Step 3: Implement** the flags, `writeBundles` and the `adoptBootstrap` change

The `-advertise` check runs before the controller is created so the third test never opens a listener. `ErrNoManifest` wording: `-bundles needs a manifest (manifest_path)`.

- [ ] **Step 4: Run to verify it passes**

Run: `CGO_ENABLED=1 go test -race ./cmd/phylax/ -count=1`
Expected: PASS (existing tests too).

- [ ] **Step 5: Commit**

```bash
git add cmd/phylax
git commit -m "serve: write enrollment bundles; agent starts in safe mode from the bundle"
```

---

### Task 4: Observe manifest generator

**Files:**
- Create: `tools/invitational/make-observe-manifest.sh`
- Test: `internal/controller/observe_test.go`

**Interfaces:**
- Consumes: `manifest.LoadDir`, `LoadConfigInputs(Config{ManifestPath, RulesPath})`, `BuildAgentConfig(ConfigInputs, host)`, `manifest.RoleDecoys`, `Host.HasRole`, fields `cfg.Modules.Detect.ActEnabled`, `cfg.Modules.Deception`, `cfg.Modules.Net.Canaries`.
- Produces: `sh make-observe-manifest.sh SRC DST [--no-decoys]` copies the manifest directory `SRC` to `DST` and sets `canary_ports: []` in `policy.yml`; decoys stay by default; with `--no-decoys` it deletes `decoys.yml` and removes `decoys` from every host's `roles` in `hosts.yml`. Refuses a non-empty `DST`. Prints `observe manifest: DST`. `phylax manifest load --dir DST` and `lint` report 0 errors (verified by hand on 2026-10-31 with the sed rules `s/, decoys\]/]/`, `s/\[decoys, /[/`, `s/roles: \[decoys\]/roles: []/`, `s/canary_ports: \[[^]]*\]/canary_ports: []/`).

- [ ] **Step 1: Write the failing test**

```go
func TestObserveManifest(t *testing.T) // skips on windows or without sh
// Run `sh ../../tools/invitational/make-observe-manifest.sh ../../manifest/2027 <tmp>/obs`, then:
// m := manifest.LoadDir(obs); rules via LoadConfigInputs(Config{ManifestPath: obs, RulesPath: "../../rules"}).
// For every host: BuildAgentConfig succeeds; Detect != nil && !Detect.ActEnabled; hosts with RoleDecoys in the source still have it and Deception != nil (decoys stay by default);
// Linux hosts: Net != nil && len(Net.Canaries) == 0; Windows hosts: Winevt != nil.
// Compared with the source manifest's rocky-ecom config, Net.Canaries is non-empty there (proves the generator changed something).
func TestObserveManifestNoDecoys(t *testing.T)
// With "--no-decoys": no host HasRole(manifest.RoleDecoys); every Deception == nil; Net.Canaries still empty; Detect.ActEnabled still false.
func TestObserveManifestRefusesNonEmptyDest(t *testing.T)
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/controller/ -run TestObserveManifest -count=1`
Expected: FAIL (`make-observe-manifest.sh: No such file`).

- [ ] **Step 3: Implement the script** with `cp -r`, the canary `sed` rule (always) and the three decoy `sed` rules (only with `--no-decoys`), and the guards. It edits only the copy in `DST` (mark those lines `# inv:ro: edits the copy`).

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/controller/ -run TestObserveManifest -count=1 -v`
Expected: PASS for all three.

- [ ] **Step 5: Commit**

```bash
git add tools/invitational/make-observe-manifest.sh internal/controller/observe_test.go
git commit -m "invitational: observe manifest generator (no decoys, no canary probes)"
```

---

### Task 5: Console enrollment scripts `e.sh` and `e.ps1`

**Files:**
- Create: `tools/invitational/e.sh`, `tools/invitational/e.ps1`, `tools/invitational/test_enroll.sh`

**Interfaces:**
- Consumes: the controller host serves a directory over HTTP containing `kit.tgz` (a tarball of `tools/invitational/`, top directory `invitational/`), `phylax` (linux/amd64), `phylax.exe`, and `<host>.json` bundles.
- Produces: `sh e.sh CTL HOST [agent]` (typed as `curl -s CTL/e|sh -s CTL HOST agent`, where the short URL `CTL/e` is the controller's file `e`, a copy of `e.sh`; the test copes with both names). Behaviour: downloads `kit.tgz` and extracts to `${INV_KIT:-/var/tmp/phylax-kit}`; with `agent` it also downloads `phylax` and `HOST.json` to `${INV_BIN:-/var/tmp/phylax-bin}`, `chmod 700`, and runs `"$INV_BIN/phylax" agent install --bootstrap "$INV_BIN/HOST.json"`. Prints each step with `inv_utc` for the timeline. `e.ps1 -Ctl CTL -HostName HOST [-Agent]` does the same with `Invoke-WebRequest`, `tar.exe -xzf`, kit in `C:\ProgramData\phylax-kit`, binary in `C:\ProgramData\phylax-bin`.

- [ ] **Step 1: Write the failing test** `test_enroll.sh`

Build a temp web root with `tar czf kit.tgz -C ../ invitational`, a stub `phylax` (a shell script that appends its arguments to `$T/args`), and `h1.json` (`{}`); start `python3 -m http.server $PORT --bind 127.0.0.1 --directory $WEB &` (PORT from a free-port probe), then:

```sh
INV_KIT=$T/kit INV_BIN=$T/bin sh "$HERE/e.sh" 127.0.0.1:$PORT h1 agent >$T/out 2>&1
assert_file enroll_kit "$T/kit/invitational/lib.sh"
assert_grep enroll_args "agent install --bootstrap $T/bin/h1.json" "$T/args"
assert_grep enroll_utc "^20..-..-..T..:..:..Z" "$T/out"
INV_KIT=$T/kit2 INV_BIN=$T/bin2 sh "$HERE/e.sh" 127.0.0.1:$PORT h1 >/dev/null 2>&1   # no 'agent': kit only
[ -e "$T/bin2/phylax" ] && t_fail enroll_kit_only "binary fetched" || t_pass enroll_kit_only
```

Stop the server in a trap. Also assert `e.sh` fails (non-zero, message contains `usage`) with no arguments.

- [ ] **Step 2: Run to verify it fails**

Run: `sh tools/invitational/test.sh 2>&1 | grep -E 'FAIL|enroll'`
Expected: FAIL rows for `enroll_*`.

- [ ] **Step 3: Implement `e.sh` and `e.ps1`**

`e.sh` is self-contained (it cannot source `lib.sh` before the kit is fetched): define a local `utc()` at the top. Known limit: the typed line `curl -s 172.20.240.5:8000/e|sh -s 172.20.240.5:8000 ubuntu-email agent` is 71 characters, over the 70 goal; leave it, put it in a `shortcut:` comment in `e.sh`, and let Task 15 measure whether it types acceptably.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./tools/invitational/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/invitational/e.sh tools/invitational/e.ps1 tools/invitational/test_enroll.sh
git commit -m "invitational: console enrollment scripts"
```

---

### Task 6: C1 packet capture scripts

**Files:**
- Create: `tools/invitational/c1-capture.sh`, `tools/invitational/c1-capture.ps1`, `tools/invitational/test_c1.sh`

**Interfaces:**
- Consumes: Task 1's `inv_init`, `inv_utc`.
- Produces: `c1-capture.sh start|stop|status`. Environment: `SCORED_PORTS` (default `21 22 25 53 80 110 143 389 443 445 465 587 993 995 1433 3306 5985 8089`, a comment says to replace it from the team packet), `IFACE` (default `any`), `INV_MIN_FREE_MB` (default 6000), `INV_DRY=1` (print the two command lines, run nothing, need no root and no tcpdump).
  - `start` runs two `tcpdump` processes in the background: scored ports `-i $IFACE -nn -s 1500 -C 100 -W 20 -w $INV_ROOT/pcap/$HOST-scored.pcap 'port 21 or port 22 ...'` and the rest `-s 256 -C 100 -W 20 -w $INV_ROOT/pcap/$HOST-other.pcap 'not (port 21 or ...)'`; their pids go to `$INV_ROOT/pcap/c1.pids`, stderr to `tcpdump-scored.log` and `tcpdump-other.log`. Refuses (exit 1, message) if `c1.pids` lists a live pid, if free space under `$INV_ROOT` is below `INV_MIN_FREE_MB`, or if not root (unless `INV_DRY`).
  - `stop` sends SIGINT to the pids, waits up to 10 s, and copies every `packets dropped by kernel` line from the logs into `$INV_ROOT/pcap/drops.txt` (answers O12).
  - `status` prints each pid's liveness, file sizes in `$INV_ROOT/pcap`, and `drops.txt` if present.
  - `c1-capture.ps1 -Action start|stop|status` uses `pktmon start --capture --pkt-size 256 --file-name "$InvRoot\pcap\$env:COMPUTERNAME.etl" --file-size 100 --log-mode multi-file`; `stop` runs `pktmon counters` into `drops.txt` before `pktmon stop`; absent `pktmon` prints a message and exits 1 (`# shortcut: etl is converted to pcap offline (pktmon etl2pcap needs build 2004+), upgrade if the Server 2019 image lacks it`).

- [ ] **Step 1: Write the failing tests** `test_c1.sh`

```sh
out=$(INV_DRY=1 INV_ROOT=$T/r sh "$HERE/c1-capture.sh" start 2>&1); 
assert_eq c1_dry_exit 0 $?
echo "$out" | grep -q -- '-s 1500' && echo "$out" | grep -q -- '-s 256' && echo "$out" | grep -q -- '-C 100 -W 20' && t_pass c1_cmdlines || t_fail c1_cmdlines "$out"
echo "$out" | grep -q 'not (port 21 or port 22' && t_pass c1_other_filter || t_fail c1_other_filter "$out"
SCORED_PORTS="8080 9090" INV_DRY=1 INV_ROOT=$T/r sh "$HERE/c1-capture.sh" start 2>&1 | grep -q 'port 8080 or port 9090' && t_pass c1_ports_override || t_fail c1_ports_override ""
INV_MIN_FREE_MB=99999999 INV_DRY=1 INV_ROOT=$T/r sh "$HERE/c1-capture.sh" start >/dev/null 2>&1; assert_eq c1_refuses_low_disk 1 $?
mkdir -p $T/r2/pcap; echo $$ > $T/r2/pcap/c1.pids
INV_DRY=1 INV_ROOT=$T/r2 sh "$HERE/c1-capture.sh" start >/dev/null 2>&1; assert_eq c1_refuses_second_start 1 $?
```

(`$$` is the test shell's own live pid, so the second-start refusal is exercised for real.)

- [ ] **Step 2: Run to verify it fails**

Run: `sh tools/invitational/test.sh 2>&1 | grep -E 'FAIL.*c1'`
Expected: FAIL rows.

- [ ] **Step 3: Implement both scripts** as specified. Lines with `kill`, `pkill` need `# inv:ro: stops only our own tcpdump pids`.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./tools/invitational/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/invitational/c1-capture.* tools/invitational/test_c1.sh
git commit -m "invitational: c1 packet capture scripts"
```

---

### Task 7: C2 host facts, Linux, plus resource sampler

**Files:**
- Create: `tools/invitational/c2-facts.sh`, `tools/invitational/c2-sampler.sh`, `tools/invitational/test_c2.sh`

**Interfaces:**
- Consumes: `inv_init`, `inv_run`, `inv_pack`.
- Produces: `sh c2-facts.sh` runs `inv_init c2` and then `inv_run NAME CMD...` for each of these names (the test checks every one is present in `_index.tsv`, whatever its exit code): `kernel` (`uname -a`), `procversion`, `btf` (`ls -l /sys/kernel/btf/vmlinux`), `kconfig` (`grep -E 'FANOTIFY|NETLINK_DIAG|INET_DIAG|AUDIT|BPF|NF_TABLES' /boot/config-$(uname -r)` else `/proc/config.gz`), `osrelease`, `packages` (`dpkg -l`, else `rpm -qa`), `versions` (`sshd -V`, `apachectl -v`, `nginx -v`, `php -v`, `postconf mail_version`, `dovecot --version`, `mysql --version`, `named -v`, each tried, `sh -c` with `2>&1`), `containers` (`docker ps -a`, `podman ps -a`), `listeners` (`ss -tulnpe`), `unixsockets` (`ss -xlp`), `passwd` (`getent passwd`), `group` (`getent group`), `sudoers` (`cat /etc/sudoers /etc/sudoers.d/*`), `lastlog` (`last -n 50`), `authkeys` (`find / -xdev -name authorized_keys` with `ls -l`, not contents), `cron` (`ls -l /etc/cron*` and `crontab -l -u root`), `timers` (`systemctl list-timers --all`), `units` (`systemctl list-units --all --type=service`), `auditstate` (`auditctl -s`, `auditctl -l`), `auditd` (`systemctl show auditd -p ActiveState -p MainPID`), `logconf` (`cat /etc/rsyslog.conf /etc/systemd/journald.conf`), `journal` (`journalctl --disk-usage`), `firewall` (`nft list ruleset`, `iptables -S`, read only), `network` (`ip -br a; ip r; cat /etc/resolv.conf`), `disk` (`df -hT; df -i; lsblk`), `memory` (`free -m`), `cpu` (`nproc; cat /proc/loadavg`), `boot` (`uptime -s; systemd-analyze`), `ntp` (`chronyc tracking`, `timedatectl`), `sshd` (`sshd -T`), `mail` (`postconf -n; doveconf -n`), `web` (`apachectl -S; apachectl -M; nginx -T`), `splunk` (`ls /opt/splunk/etc/apps`, `/opt/splunk/bin/splunk version` if present), `datasizes` (`du -sx` on `/var/www /var/lib/mysql /var/lib/pgsql /var/lib/splunk /opt/splunk/var /var/spool/mail /var/mail /home`). Never reads `/etc/shadow`. Ends with `inv_pack`.
  - `sh c2-sampler.sh start|stop` appends one CSV row per `INTERVAL` seconds (default 60) to `$INV_ROOT/sampler.csv`: header `utc,load1,mem_avail_kb,root_used_pct,cpu_busy_pct` (cpu from two `/proc/stat` readings 1 s apart); pid file `$INV_ROOT/sampler.pid`; `INV_SAMPLE_ONCE=1` writes one row and exits; refuses a second `start`.

- [ ] **Step 1: Write the failing tests** `test_c2.sh`

```sh
INV_ROOT=$T/r sh "$HERE/c2-facts.sh" >$T/c2.out 2>&1; assert_eq c2_exit 0 $?
idx=$(ls -d $T/r/*/c2-*/ | head -1)_index.tsv
for n in kernel osrelease packages listeners passwd group sudoers auditstate firewall network disk memory boot ntp datasizes; do
  grep -q "^$n	" "$idx" && t_pass c2_has_$n || t_fail c2_has_$n "missing from _index.tsv"; done
assert_file c2_osrelease "$(dirname $idx)/osrelease.txt"
ls $T/r/*.tar.gz >/dev/null 2>&1 && t_pass c2_archive || t_fail c2_archive "no tar.gz"
grep -rq 'root:[^:]*:[0-9]' $T/r --include='*.txt' -l 2>/dev/null; # passwd lines have x, never a hash:
grep -rE '^[a-z_-]+:\$[0-9a-z]+\$' $T/r >/dev/null 2>&1 && t_fail c2_no_hashes "hash-like line collected" || t_pass c2_no_hashes
# runs with a minimal PATH: records 127 and still finishes
PATH=/usr/bin:/bin INV_ROOT=$T/r3 sh "$HERE/c2-facts.sh" >/dev/null 2>&1; assert_eq c2_minimal_path_exit 0 $?
INV_SAMPLE_ONCE=1 INV_ROOT=$T/r4 sh "$HERE/c2-sampler.sh" start; assert_eq c2_sampler_rows 2 "$(wc -l < $T/r4/sampler.csv)"
assert_grep c2_sampler_header '^utc,load1,mem_avail_kb,root_used_pct,cpu_busy_pct$' $T/r4/sampler.csv
```

- [ ] **Step 2: Run to verify it fails**

Run: `sh tools/invitational/test.sh 2>&1 | grep -E 'FAIL.*c2'`
Expected: FAIL rows.

- [ ] **Step 3: Implement both scripts.** Commands that need a marker (`systemctl`, `auditctl`, `nft`, `service`) get `# inv:ro: list/show only`.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./tools/invitational/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/invitational/c2-facts.sh tools/invitational/c2-sampler.sh tools/invitational/test_c2.sh
git commit -m "invitational: c2 Linux host facts and resource sampler"
```

---

### Task 8: C2 host facts, Windows

**Files:**
- Create: `tools/invitational/c2-facts.ps1`, `tools/invitational/c2-sampler.ps1`
- Modify: `tools/invitational/test.sh` is not touched; the syntax check from Task 1 covers these files where `pwsh` exists.

**Interfaces:**
- Consumes: `Inv-Init`, `Inv-Run`, `Inv-Pack` (Task 1).
- Produces: `c2-facts.ps1` calls `Inv-Init -Cid c2` and then `Inv-Run -Name <n> -Script { ... }` for these names: `computerinfo` (`Get-ComputerInfo`), `systeminfo`, `hotfix` (`Get-HotFix`), `build` (`(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion') | select ProductName,CurrentBuild,UBR`), `software` (the two `Uninstall` registry keys), `features` (`Get-WindowsFeature` when present), `services` (`Get-Service | select Name,Status,StartType`), `listeners` (`Get-NetTCPConnection -State Listen` with `OwningProcess` name), `firewallprofile` (`Get-NetFirewallProfile`), `localusers` (`Get-LocalUser`), `localadmins` (`Get-LocalGroupMember Administrators`), `tasks` (`Get-ScheduledTask`), `auditpol` (`auditpol /get /category:*`), `defender` (`Get-MpComputerStatus`, `Get-MpPreference`, `Get-MpThreatDetection`), `applocker` (`Get-AppLockerPolicy -Effective`), `sysmon` (service `Sysmon*` and `Sysmon64`), `psloging` (the three `PowerShell` policy registry keys), `smb` (`Get-SmbServerConfiguration`, `Get-SmbShare`), `rdp` (`reg query` of `Terminal Server` and `WinStations\RDP-Tcp` `UserAuthentication`), `eventlogs` (`Get-WinEvent -ListLog Security,System,Application,'Microsoft-Windows-Sysmon/Operational'` with size and record count), `ntp` (`w32tm /query /status`, `w32tm /query /configuration`), `network` (`Get-NetIPConfiguration`, `ipconfig /all`, `Get-DnsClientServerAddress`), `disk` (`Get-Volume`), `memory`/`boot` (`Win32_OperatingSystem`: `TotalVisibleMemorySize`, `LastBootUpTime`), `mssql` (services `MSSQL*`, and `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'`), `iis` (`Get-WebBinding` when the module exists), `datasizes` (`Get-ChildItem` size of `C:\inetpub`, `D:\`, SQL data dirs; sizes only). Marker `inv:ro` is needed on `reg query` lines. `c2-sampler.ps1 -Action start|stop` appends `utc,cpu_pct,mem_avail_mb,disk_free_pct` rows from `Get-Counter` every 60 s to `$InvRoot\sampler.csv` in a background `Start-Job`-free loop run with `Start-Process powershell -WindowStyle Hidden` (`# shortcut: pid file only, no service`, upgrade if the sampler must survive logoff).

- [ ] **Step 1: Write the failing check**

Run: `ls tools/invitational/c2-facts.ps1 tools/invitational/c2-sampler.ps1`
Expected: `No such file or directory`. There is no `pwsh` on the dev machine, so this task's automated test is the lint (forbidden tokens) plus the syntax check where `pwsh` exists; the real run is Task 15. Say so in the commit body.

- [ ] **Step 2: Run the lint on the new files and verify it fails when a forbidden token is added**

Temporarily add `Restart-Service foo` to `c2-facts.ps1`, run `sh tools/invitational/test.sh`, expect `FAIL lint c2-facts.ps1`; remove the line.

- [ ] **Step 3: Implement both scripts as specified.**

- [ ] **Step 4: Run to verify**

Run: `go test ./tools/invitational/ -count=1` (lint passes, syntax check runs if `pwsh` exists, otherwise prints `SKIP ps1-syntax (no pwsh)`).
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tools/invitational/c2-facts.ps1 tools/invitational/c2-sampler.ps1
git commit -m "invitational: c2 Windows host facts and sampler (untested on Windows until the rehearsal)"
```

---

### Task 9: C3 log copy

**Files:**
- Create: `tools/invitational/c3-logs.sh`, `tools/invitational/c3-logs.ps1`, `tools/invitational/test_c3.sh`

**Interfaces:**
- Consumes: Task 1 library.
- Produces: `sh c3-logs.sh [LABEL]` (LABEL defaults to `mid`; the runbook uses `mid` and `end`) with `LOGROOT` (default `/var/log`) and `SPLUNK_LOGS` (default `/opt/splunk/var/log/splunk`) overrides. It makes `$INV_OUT/files.txt` (one `ls -l` line per candidate), skips and records files over 1 GB, and tars (gzip) the existing files from this set under `LOGROOT`: `auth.log* secure* syslog* messages* mail.log* maillog* kern.log* apache2/ httpd/ nginx/ vsftpd.log* dovecot* proftpd/ audit/audit.log* mysql/ mariadb/ cron* dpkg.log* yum.log* dnf.log*` plus `splunkd*.log*` from `SPLUNK_LOGS`; archive `$INV_ROOT/$HOST-c3-$LABEL-$STAMP.tar.gz`. `c3-logs.ps1 -Label mid|end -SinceHours 5` runs `wevtutil epl <channel> <file> /q:"*[System[TimeCreated[timediff(@SystemTime) <= <ms>]]]" /ow:true` into `$InvOut` for `Security System Application Microsoft-Windows-Sysmon/Operational Microsoft-Windows-PowerShell/Operational Microsoft-Windows-WinRM/Operational` and `Directory Service` when the channel exists, copies `C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG*`, `C:\inetpub\logs\LogFiles\*`, `C:\Windows\System32\dns\*.log` when present, then `Inv-Pack` (`# shortcut: zip caps at 2 GB`).

- [ ] **Step 1: Write the failing test** `test_c3.sh`

```sh
mkdir -p $T/log/apache2 $T/log/audit $T/splunk
echo a > $T/log/auth.log; echo b > $T/log/apache2/access.log; echo c > $T/log/audit/audit.log; echo d > $T/splunk/splunkd.log; echo e > $T/log/unrelated.bin
LOGROOT=$T/log SPLUNK_LOGS=$T/splunk INV_ROOT=$T/r sh "$HERE/c3-logs.sh" mid >/dev/null 2>&1; assert_eq c3_exit 0 $?
a=$(ls $T/r/*c3-mid*.tar.gz | head -1); assert_file c3_archive "$a"
for f in auth.log apache2/access.log audit/audit.log splunkd.log; do tar tzf "$a" | grep -q "$f" && t_pass "c3_has_$(basename $f)" || t_fail "c3_has_$(basename $f)" "not archived"; done
tar tzf "$a" | grep -q unrelated.bin && t_fail c3_only_listed "unrelated file archived" || t_pass c3_only_listed
LOGROOT=$T/nothing INV_ROOT=$T/r5 sh "$HERE/c3-logs.sh" end >/dev/null 2>&1; assert_eq c3_empty_logroot_exit 0 $?
INV_MAX_FILE_MB=0 LOGROOT=$T/log INV_ROOT=$T/r6 sh "$HERE/c3-logs.sh" mid >/dev/null 2>&1; grep -q 'skipped' $T/r6/*/c3-*/files.txt && t_pass c3_size_skip || t_fail c3_size_skip "no skipped line"
```

`INV_MAX_FILE_MB` defaults to 1024.

- [ ] **Step 2: Run to verify it fails.** `sh tools/invitational/test.sh 2>&1 | grep -E 'FAIL.*c3'` Expected: FAIL rows.
- [ ] **Step 3: Implement both scripts.**
- [ ] **Step 4: Run to verify it passes.** `go test ./tools/invitational/ -count=1` Expected: PASS.
- [ ] **Step 5: Commit**

```bash
git add tools/invitational/c3-logs.* tools/invitational/test_c3.sh
git commit -m "invitational: c3 log copy scripts"
```

---

### Task 10: C4 AD dump

**Files:**
- Create: `tools/invitational/c4-ad.ps1`

**Interfaces:**
- Consumes: `Inv-Init`, `Inv-Run`, `Inv-Pack`; the ActiveDirectory and GroupPolicy PowerShell modules on the DC.
- Produces: `c4-ad.ps1` (run on the DC) writes under `$InvOut` and archives as `<host>-c4-<stamp>-SENSITIVE.zip`. Items (names are the file stems): `users.csv` (`Get-ADUser -Filter * -Properties *` selecting `SamAccountName,Enabled,Description,ServicePrincipalName,PasswordLastSet,PasswordNeverExpires,LastLogonDate,adminCount,MemberOf,UserAccountControl,whenCreated`), `groups.csv`, `computers.csv`, `ou.csv`, `privileged.csv` (members, recursive, of `Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Backup Operators, DnsAdmins, Server Operators, Print Operators, Group Policy Creator Owners`), `duplicates.csv` (group names that occur more than once, answering the ~500 duplicate groups report), `krbtgt.txt` (`PasswordLastSet`), `domain.txt` (`Get-ADDomain`, `Get-ADForest`, functional levels, Recycle Bin via `Get-ADOptionalFeature`), `pwpolicy.txt` (`Get-ADDefaultDomainPasswordPolicy`, `Get-ADFineGrainedPasswordPolicy -Filter *`), `gpo.xml` (`Get-GPOReport -All -ReportType Xml`), `acl.txt` (`dsacls` on the domain DN), `hardening.txt` (`reg query` for `LmCompatibilityLevel`, `LDAPServerIntegrity`, `RequireSignOrSeal`, `FullSecureChannelProtection`, `RequireSecuritySignature`, `RestrictAnonymous`), `repl.txt` (`repadmin /replsummary`, `nltest /dclist:`), and a `SENSITIVE.txt` stating why. It exits with a message, writing nothing, when the ActiveDirectory module is absent.

- [ ] **Step 1: Write the failing check**

Run: `test -f tools/invitational/c4-ad.ps1 && echo present || echo missing`
Expected: `missing`.

- [ ] **Step 2: Add the lint check**

`tools/invitational/test.sh` lint already covers `.ps1`; run it after Step 3.

- [ ] **Step 3: Implement the script** (per-item failures are recorded by `Inv-Run`; a failure of `Get-ADUser` must not stop the later items).

- [ ] **Step 4: Run to verify**

Run: `go test ./tools/invitational/ -count=1`
Expected: PASS (lint clean; syntax check where `pwsh` exists). Real execution is Task 15.

- [ ] **Step 5: Commit**

```bash
git add tools/invitational/c4-ad.ps1
git commit -m "invitational: c4 AD dump script"
```

---

### Task 11: C5 reachability and internet probe

**Files:**
- Create: `tools/invitational/c5-probe.sh`, `tools/invitational/c5-probe.ps1`, `tools/invitational/test_c5.sh`

**Interfaces:**
- Consumes: Task 1 library.
- Produces: `sh c5-probe.sh [-t TARGETS_FILE] [-m MIRRORS_FILE]`. `TARGETS_FILE` lines are `host port [label]`; default targets are written from the 2027 manifest addresses (172.20.240.10/15/20/100/120 on the scored ports) and a comment says to regenerate from `phylax manifest load`. `MIRRORS_FILE` lines are hostnames; default `deb.debian.org archive.ubuntu.com security.ubuntu.com mirror.rockylinux.org download.windowsupdate.com github.com`. Outputs into `$INV_OUT`: `ports.csv` (`host,port,result,ms` where result is `open`, `closed` or `timeout`, using `nc -z -w 3` else `timeout 3 sh -c ': </dev/tcp/H/P'` under `bash`), `winrm.txt` (`curl -s -m 5 -i -X OPTIONS http://H:5985/wsman` for every host in targets with port 5985 or 5986), `http.csv` (`url,code,dns_s,connect_s,tls_s,total_s,bytes` from `curl -o /dev/null -s -w ... --max-filesize 104857600 https://MIRROR/` for each mirror), `tls.txt` (issuer, subject, dates of `https://github.com` and each mirror, via `openssl s_client`), `dns.csv` (`name,ms` timed `getent hosts`), `trace.txt` (`traceroute -n -w 2 -m 15` to the first mirror, else `tracepath -n`). `c5-probe.ps1 -TargetsFile -MirrorsFile` produces the same files with `Test-NetConnection`/`System.Net.Sockets.TcpClient` with a 3 s timeout, `Invoke-WebRequest -Method Options`, `Measure-Command`, `Resolve-DnsName`, `tracert -d -h 15 -w 2000`. Connect-only: no payload is sent to scored ports.

- [ ] **Step 1: Write the failing tests** `test_c5.sh`

Start `python3 -m http.server $PORT --bind 127.0.0.1` in a temp dir with an `index.html` of 1000 bytes; pick a second port with nothing listening.

```sh
printf '127.0.0.1 %s web\n127.0.0.1 %s dead\n' $PORT $DEAD > $T/targets
printf '127.0.0.1\n' > $T/mirrors
INV_ROOT=$T/r sh "$HERE/c5-probe.sh" -t $T/targets -m $T/mirrors -s http >/dev/null 2>&1; assert_eq c5_exit 0 $?
d=$(ls -d $T/r/*/c5-*/ | head -1)
assert_grep c5_open "^127.0.0.1,$PORT,open," $d/ports.csv
assert_grep c5_closed "^127.0.0.1,$DEAD,closed," $d/ports.csv
assert_grep c5_http_row "^http://127.0.0.1:$PORT/,200," $d/http.csv
```

`-s http` makes the mirror probe use `http://MIRROR:PORT/` with `-p PORT`: add `-p PORT` to the interface (test calls `-p $PORT -s http`); the default is `-s https` and port 443. Add the assertion `c5_bytes_1000` that the `bytes` column equals 1000.

- [ ] **Step 2: Run to verify it fails.** `sh tools/invitational/test.sh 2>&1 | grep -E 'FAIL.*c5'` Expected: FAIL rows.
- [ ] **Step 3: Implement both scripts.**
- [ ] **Step 4: Run to verify it passes.** `go test ./tools/invitational/ -count=1` Expected: PASS.
- [ ] **Step 5: Commit**

```bash
git add tools/invitational/c5-probe.* tools/invitational/test_c5.sh
git commit -m "invitational: c5 reachability and internet probe"
```

---

### Task 12: C6 timeline marker, C7 scribe sheet, O2 checklist

**Files:**
- Create: `tools/invitational/m.sh`, `tools/invitational/m.ps1`, `tools/invitational/scribe.sh`, `tools/invitational/o2-checklist.txt`, `tools/invitational/test_c6.sh`

**Interfaces:**
- Consumes: `inv_utc`.
- Produces:
  - `sh m.sh TEXT...` appends `UTC<TAB>HOST<TAB>TEXT` to `${INV_TIMELINE:-$INV_ROOT/timeline.txt}` (typeable as `sh m.sh drop flag`); `m.ps1` the same to `C:\ProgramData\phylax-inv\timeline.txt`. With no arguments it prints the last 5 lines.
  - `sh scribe.sh` (runs on the outside scribe's machine, any POSIX shell or Git Bash): `scribe.sh init` writes `scribe.csv` with header `utc,round_note,service,status,score,source` once; `scribe.sh row SERVICE STATUS SCORE [NOTE]` appends a row with the current UTC and source `board`; `scribe.sh pcr SECONDS` and `scribe.sh credlists FILE` record the S13 submit time and copy `GET /api/credlists` output the scribe saved to FILE into `credlists-<utc>.json`.
  - `o2-checklist.txt` is the console checklist, one line per item of question O2: `console latency (keypress to echo)`, `session timeout seen (minutes)`, `simultaneous consoles per VM`, `several viewers on one VM (y/n)`, `resolution`, `keys that do not map: | ~ \ ' "`, `paste inside a VM works (y/n)`, `file transfer to a VM (y/n)`, `login time (seconds)`, and one more line `typed line length that worked`.

- [ ] **Step 1: Write the failing tests** `test_c6.sh`

```sh
INV_ROOT=$T/r sh "$HERE/m.sh" drop flag; INV_ROOT=$T/r sh "$HERE/m.sh" console open rocky
assert_eq c6_two_lines 2 "$(wc -l < $T/r/timeline.txt)"
assert_grep c6_format "^20..-..-..T..:..:..Z	$(hostname -s)	drop flag$" $T/r/timeline.txt
assert_grep c6_second_line "console open rocky" $T/r/timeline.txt
(cd $T && sh "$HERE/scribe.sh" init && sh "$HERE/scribe.sh" init && sh "$HERE/scribe.sh" row http up 120 "round 1")
assert_eq c6_scribe_header_once 1 "$(grep -c '^utc,' $T/scribe.csv)"
assert_grep c6_scribe_row ",round 1,http,up,120," $T/scribe.csv
assert_grep c6_o2_items "keys that do not map" "$HERE/o2-checklist.txt"
```

(The CSV column order is `utc,round_note,service,status,score,source`, the row above matches it.)

- [ ] **Step 2: Run to verify it fails.** Expected: FAIL rows `c6_*`.
- [ ] **Step 3: Implement** the three scripts and the checklist.
- [ ] **Step 4: Run to verify it passes.** `go test ./tools/invitational/ -count=1` Expected: PASS.
- [ ] **Step 5: Commit**

```bash
git add tools/invitational/m.* tools/invitational/scribe.sh tools/invitational/o2-checklist.txt tools/invitational/test_c6.sh
git commit -m "invitational: c6 timeline marker, c7 scribe sheet and O2 checklist"
```

---

### Task 13: Safe mode lets read-only actions run

**Files:**
- Modify: `internal/actions/env.go` (the two `e.Safe.On()` checks in `Execute`, around lines 176 and 183)
- Modify: `internal/actions/executor_test.go` (the safe-mode test near line 205)

**Interfaces:**
- Consumes: `Spec.ReadOnly` (already on every action spec), `ErrSafeMode`.
- Produces: `Env.Execute` refuses with `ErrSafeMode` only when the action is not `ReadOnly`. This follows the design (Execution engine > Safe mode: "checks and rollbacks still work") and lets observe mode run read-only plan nodes with safe mode on.

- [ ] **Step 1: Change the existing test first**

In the safe-mode test, remove `{"file.hash", ...}` from the refused list and add after the loop:

```go
if _, err := f.run(t, "file.hash", map[string]any{"path": "/etc/passwd"}); err != nil {
    t.Fatalf("read-only action in safe mode: %v", err)
}
```

Keep `user.lock`, `file.write` and `service.start` refused.

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/actions/ -run TestSafeMode -count=1` (find the exact name with `grep -n 'func Test.*Safe' internal/actions/executor_test.go`)
Expected: FAIL with `read-only action in safe mode: actions: agent is in safe mode; only rollback is permitted`.

- [ ] **Step 3: Change both checks to `if e.Safe.On() && !spec.ReadOnly`** and update the `ErrSafeMode` message in `action.go` to `agent is in safe mode; only rollback and read-only actions are permitted`.

- [ ] **Step 4: Run the package**

Run: `go test -race ./internal/actions/ -count=1 && grep -rn 'only rollback is permitted' --include='*.go' .`
Expected: `ok`, and no remaining occurrence of the old message.

- [ ] **Step 5: Commit**

```bash
git add internal/actions
git commit -m "actions: safe mode permits read-only actions"
```

---

### Task 14: Runbook

**Files:**
- Create: `docs/impl/invitational-runbook.md`

**Interfaces:**
- Consumes: everything above. Roles are the design's names (Platform driver, Captain, Linux lead, Windows and AD lead, Network, SOC, Credentials role) plus the outside scribe.
- Produces: the document below. It contains exact commands, not prose descriptions of them.

- [ ] **Step 1: Write the runbook with these sections, in this order**

1. **Before the event (by 2026-11-06), on the dev machine:** `make build build-windows`; `sh tools/invitational/make-observe-manifest.sh manifest/2027 /tmp/obs` (decoys on by default); edit `topology.yml` team number and any packet differences; `./bin/phylax manifest lint --dir /tmp/obs` (0 errors); the kit tree `kit/` = `bin/phylax`, `bin/phylax-windows-amd64.exe` (as `phylax.exe`), `rules/`, `plans/`, the observe manifest, `tools/invitational/`, a controller config JSON (`data_dir`, `manifest_path`, `rules_path`, `plans_path`, `ui_listen` `127.0.0.1:8080`, `agent_listen` `0.0.0.0:7443`, `team`); `tar czf kit.tgz -C tools invitational`; upload `kit/` and `kit.tgz` to Nextcloud; print the O2 checklist and this runbook.
2. **Roles and who types what** (table: step, role, machine, command, mark text).
3. **Order of operations**, each step with its command and the `m.sh` mark (the Platform driver or Captain keeps the timeline on the controller host):
   1. Drop flag: scribe starts `scribe.sh init`, reads the scoreboard every round for 20 minutes then every 5 minutes (C7); Captain runs `sh m.sh drop flag`.
   2. Controller host (`ubuntu-wkst`): download the kit from Nextcloud in the browser (the time and speed are the first upload/download measurement, mark it), extract to `/srv/phylax`; `cd /srv/phylax && python3 -m http.server 8000 --directory web &` where `web/` holds `kit.tgz`, `phylax`, `phylax.exe`, a copy of `e.sh` named `e`, and later the bundles; start `./phylax serve -config cfg.json -bundles web -advertise <controller ip>:7443 -bundle-safe` (the bundle directory is `web/`, so the files are served; tokens live 8 h and are single use; `shortcut: bundles are served over plain HTTP on the LAN, stop the http server once every host is enrolled`).
   3. First 15 minutes: `sh c5-probe.sh` on the controller; test an upload to Nextcloud from one host of each OS and mark the throughput; fill the O2 checklist.
   4. Each host, by its lead, **in this order** (C1 first because pcaps are the most valuable data and cannot be recovered later): `curl -s CTL/e|sh -s CTL HOST` (kit only), then `sh /var/tmp/phylax-kit/invitational/c1-capture.sh start` (Linux, VyOS) or `powershell -File C:\ProgramData\phylax-kit\invitational\c1-capture.ps1 -Action start` (Windows); then `c2-facts` once and `c2-sampler start`; then the agent: `curl -s CTL/e|sh -s CTL HOST agent` (Windows: the `e.ps1` line); mark each as `m.sh HOST c1 started`, `... c2 done`, `... enrolled`. Safe mode is on from the bundle; the Platform driver confirms on the Platform page that every host shows safe mode and the module list.
   5. DC (Windows and AD lead): `c4-ad.ps1` once, early; mark.
   6. Network: C8 by hand, read-only: Palo `Device > Setup > Operations > Export named configuration snapshot`, `Monitor` log exports (traffic, system, config), licence page screenshot; VyOS `show configuration commands`, `show interfaces`, `show nat source rules`; save to the controller host under `/var/tmp/phylax-inv/network/`. Never enter configuration mode.
   7. +1 h and +3 h: the O12 checklist: `c1-capture.sh status` on every capture host (drop counters), Platform page (gaps, last event per module), `sh m.sh o12 ok|problem`.
   8. +2 h: `c3-logs.sh mid` on every host; the second half starts only if the Captain approves.
   9. Tier B (Captain's call, second half or earlier, only on the canary host `win11-wkst`): the Platform driver turns safe mode off for that host in the UI after a verbal callout, then approves plans from `plans/first-hour` one at a time (dead-man on); mark each. Tier C: one scored-password change on the one scored user's host and one hardening pack on one scored server, per design Operations; time the PCR typing (O8) and have the scribe record S13.
   10. Last 15 minutes: `c1-capture.sh stop` on every capture host; `c3-logs.sh end`; `c2-facts` again (for the T70 before/after diff); stop `phylax serve`; `tar czf` the controller data dir.
4. **Exports** (table): per collector, the file pattern, where it is, size order, and the Nextcloud folder (`C4` and `c3` Windows Security logs in the private folder; scribe files upload from the outside machine): `*-c1-*` is `$INV_ROOT/pcap/*.pcap*` (upload scored-port files first), `<host>-c2-<stamp>.tar.gz`, `<host>-c3-<label>-<stamp>.tar.gz`, `<host>-c4-<stamp>-SENSITIVE.zip`, `<host>-c5-<stamp>.tar.gz`, `timeline.txt`, `scribe.csv` plus screenshots, `sampler.csv`, controller data dir tarball, network exports. Upload by hand in quiet moments; fallback: leave on the controller disk.
5. **Fallbacks:** the agent fails to enroll on a host: continue with C1, C2, C3 only (they need nothing from Phylax); Defender blocks a script: record the time and message (O4), no exclusion unless the Captain approves; no Nextcloud: keep everything on the controller host.
6. **Not done at the event** (so nobody improvises): no firewall change, decoys stay as configured (LAN only), no hardening except Tier B/C, no reboot.

- [ ] **Step 2: Check every command in the runbook against the scripts**

Run: `for f in $(grep -oE '[a-z0-9-]+\.(sh|ps1)' docs/impl/invitational-runbook.md | sort -u); do test -f tools/invitational/$f || echo "MISSING $f"; done; grep -o -- '-bundles\|-advertise\|-bundle-safe\|-bundle-ttl' docs/impl/invitational-runbook.md | sort -u`
Expected: no `MISSING` lines; the four flag names present.

- [ ] **Step 3: Check the longest typed line**

Run: `grep -oE '^ *`?curl -s [^`]*' docs/impl/invitational-runbook.md | awk '{ print length($0) }' | sort -n | tail -1`
Expected: a number; write it into the runbook as "longest typed line: N characters" (the rehearsal tries to shorten it).

- [ ] **Step 4: Commit**

```bash
git add docs/impl/invitational-runbook.md
git commit -m "docs: Invitational runbook"
```

---

### Task 15: Lab task (stronger agent or David): rehearsal on the BTaP replica

**Files:**
- Create: `docs/impl/w2-rehearsal.md` (results)
- Modify: any script or Go file for a real failure, same rules as the other tasks

**Interfaces:**
- Consumes: the BTaP replica (Linux hosts, Windows Server 2019 and 2022, a DC, a Windows 11, Kali), the kit, the runbook.
- Produces: `w2-rehearsal.md`: one line per runbook step with the elapsed time, plus pass/fail for each check below.

- [ ] **Step 1: Run the runbook end to end, once, with a stopwatch**

Follow `docs/impl/invitational-runbook.md` exactly as written. Record: time to type each console line and its length (O1, T27), characters that did not map, whether `|` worked on each console type, time from `curl` to enrollment seen on the controller.

- [ ] **Step 2: Windows scripts, first real run**

On Server 2019, Server 2022, Windows 11 and the DC: `e.ps1`, `c1-capture.ps1` (does `pktmon` exist on Server 2019; how many multi-file parts are kept), `c2-facts.ps1`, `c2-sampler.ps1`, `c3-logs.ps1`, `c4-ad.ps1`, `c5-probe.ps1`. For each, record which `_index.tsv` rows have a non-zero exit and fix the script when the cause is the script.

- [ ] **Step 3: T70, observe mode changes nothing**

Run `c2-facts` before enrolling the agent and after one hour of observe mode; `diff -r` the two output directories ignoring the agent's own files (`/var/lib/phylax`, `/opt/phylax`, the `phylax` unit, the audit rules the audit module adds: this is the one documented host setting, data doc C0). Expected: no other difference in listeners, accounts, firewall, services. Record it.

- [ ] **Step 4: Unverified claims from "What exists today"**

Check on the replica and write the answer in the results file: does the UI start check rounds (C9)? does `integrity` report anything without a ledger, and does `phylax depot` build one? does the safe-mode UI toggle for one host work (Tier B)? does a plan from `plans/first-hour` run on the canary host through the UI with the dead-man? is `pcr.generate` reachable from the UI for the typed PCR list?

- [ ] **Step 5: Resource cost (O3)**

Read `c2-sampler.csv` and the Platform page budgets for one hour; record agent CPU/RSS per host. Fix or tighten module budgets in `internal/controller/genconfig.go` (`moduleBudgets`) only if a budget is exceeded, as one commit with the numbers in the message.

- [ ] **Step 6: Commit**

```bash
git add docs/impl/w2-rehearsal.md
git commit -m "docs: Invitational rehearsal results"
```

---

## Self-review

1. **Spec coverage.** (a) observe-mode configuration: Task 4 (generator) plus the "already usable" row for act-off and Task 2/3 for safe mode on at start; per-host module set is the manifest roles (Linux: net, audit, integrity, detect, capture; Windows: winevt, detect) as `BuildAgentConfig` derives it. (b) Tier A/B items: verified one by one in "What exists today"; the three gaps that block the Invitational got Tasks 2, 3, 5, 13; the items with no code (firewall shadow, content guard, doctor, eviction, live scorer learning, `respond`) are listed as not present and deliberately not built in W2. (c) collectors C1 to C7: Tasks 6 to 12, with C0 covered by Tasks 2 to 5 and C8, C9 by the runbook and the rehearsal. (d) runbook: Task 14. (e) rehearsal: Task 15, which also runs T70 and T27. Tasks are ordered by value: seams, enrollment of agents (C0, the most `must` answers), observe manifest, console scripts, then pcaps and facts, logs, AD, probes, timeline, then the safe-mode fix, the runbook and the rehearsal.
2. **Step scan.** Collector tasks give the exact file names and columns a test checks and leave the shell bodies to the implementer; Tasks 8 and 10 cannot be tested here (no `pwsh`), and say so: their tests are lint plus the Task 15 run. Task 5 has a known gap (a 71-character line) that is stated as a number to beat, not hidden.
3. **Type consistency.** `inv_init/inv_run/inv_pack/inv_utc` and `Inv-Init/Inv-Run/Inv-Pack/Inv-Utc` are named once in Task 1 and used unchanged. `WriteBundles(dir, hosts, BundleOptions)` (Task 2) is called by `writeBundles` (Task 3) with the same field names. Flag names `-bundles -advertise -bundle-ttl -bundle-safe` match in Task 3 and the runbook (Task 14 Step 2 greps them). The kit directory name `invitational` is the same in Tasks 5 and 14.
4. **Review Focus.** Re-run refusal and disk guard: Task 6 tests; missing tools: Tasks 1 (127 rows) and 7 (minimal PATH); secrets: Task 1 lint token `shadow` and Task 7 hash test, Task 10 `SENSITIVE`; controller restart: Task 3 (bundles only with the flag); typing length: Task 5/14/15.
5. **Proportion.** The plan is about the size of the data document it serves and carries test code only where an assertion needs exact values; script bodies are left to the implementer.
