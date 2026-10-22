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
   (`versions.env` pins versions and source hashes; the script refuses an empty or mismatching hash).
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
mitigation. The static binaries are built in the lab, not in CI; see the build log below.

## Build log (2026-10-22, lab build)

Build image: `alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc`
(Alpine/musl, gcc 13.2.1; the apk package set inside it is not pinned, so a rebuild months later may differ).
`SOURCE_DATE_EPOCH=1700000000`, `-ffile-prefix-map`, builds run in `/work`. Built twice on one machine from the
same image and sources (`SRC_CACHE=<dir of pre-downloaded tarballs> depot/recipes/build.sh out1`, then `out2`):
**every output was bit-for-bit identical (28/28 files)**. This shows determinism of recipe and toolchain on one
host, not independence across machines.

Every binary is a static linux/amd64 ELF (`file`: "statically linked") and was started with `--version`/`--help`
in a container with an empty root filesystem (no libraries, no loader). `ssh`/`ssh-keygen` additionally need a
`/etc/passwd` entry for the running uid (they refuse otherwise); every real host has one. Sizes are the stripped
binaries.

| tool | version | size (bytes) | reproducible | licence |
|---|---|---|---|---|
| busybox | 1.36.1 | 1,181,592 | yes | GPL-2.0-only |
| coreutils | 9.5 | 5,009,208 | yes | GPL-3.0-or-later |
| ps | 4.0.4 | 248,704 | yes | GPL-2.0-or-later |
| top | 4.0.4 | 336,512 | yes | GPL-2.0-or-later |
| ip | 6.9.0 | 1,360,600 | yes | GPL-2.0-or-later |
| ss | 6.9.0 | 273,296 | yes | GPL-2.0-or-later |
| lsof | 4.99.3 | 278,128 | yes | LicenseRef-lsof |
| netstat | 2.10 | 182,432 | yes | GPL-2.0-or-later |
| tcpdump | 4.99.4 | 4,889,656 | yes | BSD-3-Clause |
| strace | 6.9 | 1,243,184 | yes | LGPL-2.1-or-later |
| curl | 8.8.0 | 5,330,424 | yes | curl |
| socat | 1.8.0.0 | 4,830,424 | yes | GPL-2.0-only |
| ssh | 9.7p1 | 4,621,912 | yes | BSD-2-Clause |
| ssh-keygen | 9.7p1 | 4,240,536 | yes | BSD-2-Clause |
| scp | 9.7p1 | 284,752 | yes | BSD-2-Clause |
| file | 5.45 | 535,408 | yes | BSD-2-Clause |
| find | 4.10.0 | 314,640 | yes | GPL-3.0-or-later |
| xargs | 4.10.0 | 108,672 | yes | GPL-3.0-or-later |
| grep | 3.11 | 231,648 | yes | GPL-3.0-or-later |
| tar | 1.35 | 628,368 | yes | GPL-3.0-or-later |
| gzip | 1.13 | 113,648 | yes | GPL-3.0-or-later |
| xz | 5.6.2 | 248,384 | yes | 0BSD |
| magic.mgc | 5.45 | 8,513,392 | yes | BSD-2-Clause |
| toybox | 0.8.11 | 797,224 | yes | 0BSD |
| nmap | 7.95 | 8,955,888 | yes | LicenseRef-Nmap |
| nmap-data.tar | 7.95 | 22,169,600 | yes | LicenseRef-Nmap |

Notes:
- `coreutils` is one multi-call binary (`coreutils --help` lists applets); it carries no `provides`, so applet names
  resolve to busybox (`provides` is the real `busybox --list`, 401 applets). Run coreutils explicitly with
  `phylax depot run coreutils --coreutils-prog=ls`.
- `toybox` (optional) is built but has no applet links, same reason.
- `magic.mgc` is a data file for `file`: `phylax depot run file -m <depot>/bin/magic.mgc <path>`.
- `nmap-data.tar` is a deterministic tar of the nmap data files, `nse_main.lua`, `scripts/` and `nselib/`; unpack it
  with the depot `tar` into a private directory and run `nmap --datadir <dir>`.
- `lsof` and `xz` initially linked dynamically (libtool swallows `-static`); the recipe now passes `-all-static`.
- Fixes needed on Alpine 3.20: zstd static libs for iproute2 (libelf) and curl, `--disable-nls` for tar, `make lsof`
  only (man page needs `soelim`), `-lnet-tools` search path for net-tools, `_FORTIFY_SOURCE=0` for toybox, and
  recipe lines now fail the build (earlier `&&` chains hid failures).

### Source integrity (versions.env)

Verified against upstream-published GPG signatures (keys fetched from keyserver.ubuntu.com, fingerprints recorded
in `depot/recipes/versions.env`): busybox, coreutils, iproute2 (also kernel.org `sha256sums.asc`), tcpdump,
libpcap, strace, curl, openssh, file (valid signature, signing key since expired), findutils, grep, tar, gzip, xz,
nmap (also nmap.org digest file). socat: upstream `download.sha256sum` (no signature for 1.8.0.0).
**Not independently verifiable (trust on first use over TLS): toybox, lsof, procps-ng.** net-tools: sourceforge
tarball, sha512 cross-checked against the Alpine aports checksum, no upstream signature. Key trust is TOFU from the
keyserver; confirm fingerprints out of band before the event if that matters.
procps and net-tools now use the sourceforge release tarballs (generated `configure`, no autogen) instead of git
archive tarballs.

### Windows Sysinternals pins

Downloaded once from `https://live.sysinternals.com/<name>.exe` on 2026-10-22, not stored in git, not redistributed.
`version` is `lm-` plus the HTTP Last-Modified date. Each file is a PE32+ x86-64 with an embedded Authenticode blob
naming Microsoft; the chain was **not** validated (no Windows or osslsigncode on the build host), so run
`sigcheck64 -a` once on Windows before the event.

| file | version | size | sha256 (prefix) |
|---|---|---|---|
| procmon64.exe | lm-20261015 | 2,237,720 | `28495e642b2a4654...` |
| autoruns64.exe | lm-20260617 | 1,931,616 | `d8deb836731fdf76...` |
| tcpview64.exe | lm-20230411 | 1,087,368 | `0cbcb7ec4a042622...` |
| handle64.exe | lm-20221026 | 416,144 | `24bafcc570cc9bbb...` |
| listdlls64.exe | lm-20261015 | 293,152 | `641405893f7966a0...` |
| sigcheck64.exe | lm-20261015 | 528,184 | `f3d671b4bab47147...` |
| pslist64.exe | lm-20230330 | 267,136 | `d3247f03dcd7b933...` |
| sysmon64.exe | lm-20260924 | 3,203,368 | `83d31f2478dc6716...` |
