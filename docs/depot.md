# Trusted tool depot

Red team replaces host binaries (custom Postfix, `dns.exe`, trojaned `nologin`/`dash`). During a
response, neither operators nor Phylax may trust `ps`, `ss`, `ls` or even the dynamic linker on a
host. The depot carries our own known-good tools. Code: `internal/depot`, `internal/depot/gotools`,
`cmd/phylax/depot.go`. Build recipes and spec: `depot/`.

## Pieces

- **Signed manifest** (`depot.json`): per tool name, version, OS/arch, sha256, size, source URL,
  licence (SPDX), build recipe, source reference, multi-call applet names (`provides`). The body is
  signed with the release key through `integrity.Signer` / `integrity.Verifier` (ed25519, domain
  separated). An unsigned, tampered or wrong-key manifest is refused everywhere.
- **Store** (`<store>/blobs/<sha256>`): content addressed, written atomically, hash-checked on write
  and on read, size bounded. Controller cache tier; also a signed release asset.
- **Deployed depot** (`<dir>/depot.json`, `<dir>/bin/<tool>`): dir 0700, tools 0500, applet symlinks.
  The directory is hidden and per event (D-8): `HiddenDir(base, secret)` gives `/var/tmp/.<10 hex>`
  from an HMAC of the event secret; override with `--dir` or `$PHYLAX_DEPOT`. Obscurity is not a boundary.
- **Execution**: every run re-hashes the tool, requires a regular file that is not group/world
  writable, then executes the *hashed bytes* from a sealed memfd (`/proc/self/fd/3`), so swapping the
  file between check and exec changes nothing. Environment is built from scratch: `PATH` = depot bin
  only, no `LD_*`, no shell startup hooks, nothing inherited except `TERM`/`TZ`. Static binaries need
  no host loader.
- **Go-native tools** (`phylax tools ps|ss|ls|hash|lsof`): read `/proc` and netlink `sock_diag`
  directly (same code as the network collector). Use when even a static binary cannot be copied in.
  `ps` flags deleted executables; `lsof` flags deleted open files; `ls` shows hidden files, inodes and
  symlink targets.

## Operator, game day

```
export PHYLAX_RELEASE_PUB=<hex from the driver checklist>
export PHYLAX_DEPOT_SECRET=<event secret>        # or PHYLAX_DEPOT=/path
phylax depot verify            # exit 1 on any mismatch or planted file
phylax depot list
phylax depot run ps -ef
phylax depot run ss -tlnp
phylax depot shell             # verified sh, PATH = depot only, prompt "[depot]"
phylax tools ps | phylax tools ss | phylax tools lsof 1234
```

Deploying to a host (controller side, a library call today; agent push wiring comes with the first-contact
code): `phylax depot deploy --store <store> --dir <dir> --pub <key>`.

`shell` verifies the whole depot at start and re-hashes the shell itself; programs the shell launches
are the files in `bin/`, so re-run `phylax depot verify` if anything looks wrong. `run` is the
strictest path.

## Release build (lab, needs internet once)

1. `depot/recipes/build.sh out/` builds static linux/amd64 tools in an Alpine/musl container
   (`versions.env` pins versions; fill each `*_SHA256` on first build, the script refuses empty).
2. `phylax depot keygen --out release` (once; the private key never enters the event).
3. `phylax depot pack --spec depot/tools.json --src out/ --store dist/depot --key release.key`.
4. Ship `dist/depot` as a signed release asset. The `.pub` is compiled in / printed on the checklist.
5. Controller, with internet: `phylax depot fetch --store ...` pulls the fetch-at-init Windows
   Sysinternals tools (not redistributable; same pattern as Sysmon) and verifies the pinned hash.

Windows: our own Go tools plus Sysinternals only (`depot/recipes/windows.md`). `phylax tools ps|ss|lsof`
are Linux only for now.

## Licences

Recorded per tool in the manifest and `depot/tools.json`. GPL/LGPL tools (busybox, coreutils, procps,
iproute2, net-tools, socat, grep, tar, gzip, findutils, strace) are shipped as unmodified upstream
builds; the pinned source tarball URL in `versions.env` plus the recipe is the source reference, and
the release must also carry those tarballs (or a written offer) when binaries are redistributed.
Sysinternals is never redistributed.

## Limits

A root attacker can still lie to any user-space tool via kernel hooks; the depot defeats replaced
binaries, poisoned PATH/LD_PRELOAD and a backdoored loader, not a rootkit. Crossview remains the
mitigation. The static binaries themselves have not been built in CI; see the lab checklist in the
design section.
