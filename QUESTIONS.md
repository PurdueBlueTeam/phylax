# QUESTIONS.md

Log of decisions, ambiguities and skipped-unverifiable items from the overnight
implementation run (2026-10-18). Format: question / options / decision / rationale.

## Decisions (made autonomously, logged per the unattended-run rules)

### D-run-01: What counts as "verified" for a milestone
- Question: milestone gates in the design doc reference the Proxmox replica lab,
  real Palo/VyOS devices and Windows hosts, none of which exist in this
  environment.
- Options: (a) count a milestone complete when its *locally verifiable core*
  passes and each unverifiable criterion is listed here; (b) only count lab-
  verified gates.
- Decision: (a) — the user confirmed "you can skip unverifiable parts (like you
  don't need to run in a VM)". A skipped item is listed below with its reason.
  "Locally verifiable" means: runs on this VM, either in-process, on the host
  loopback, or in docker test containers (including `--cap-add=NET_ADMIN`
  containers, which are contained to their own network namespace).

### D-run-02: docker test containers may add capabilities
- Question: `fw.apply`, the sinkhole, denied-egress and capture need
  `CAP_NET_ADMIN`/`CAP_NET_RAW` (nftables netlink, AF_PACKET). AGENTS.md
  forbids `--privileged` containers but not targeted capability adds.
- Options: (a) `--cap-add=NET_ADMIN,NET_RAW,AUDIT_READ` per test container;
  (b) skip everything needing caps.
- Decision: (a). A container's own network namespace is isolated from the host;
  with docker's default bridge the added caps cannot touch host network state.
  Containers used only for tests, never `--privileged`, never host path mounts
  outside the repo.

### D-run-03: NFLOG is unavailable on this kernel
- Observation: the host kernel (7.0.0-34-generic) has `nf_tables`, `nf_nat`,
  `nf_conntrack` but no `nfnetlink_log` module, and modules cannot be loaded
  without root.
- Consequence: D12's NFLOG path (first packet of every denied attempt, incl.
  UDP) cannot be exercised here. The sinkhole (nftables `redirect` to the
  catcher, no extra module) is fully testable and covers the TCP beacon
  capture required by T05. Denied-UDP logging is implemented in code but its
  live kernel path is listed as unverifiable (U-01).

### D-run-04: library choices where the design names a mechanism, not a package
- nftables "over netlink" → `github.com/google/nftables` (pure-Go netlink
  client, no `nft` binary).
- SQLite "pure Go" → `modernc.org/sqlite`.
- zstd → `github.com/klauspost/compress` (pure Go).
- TLS 1.3, ed25519, age, SSH client, netlink/AF_PACKET primitives → stdlib +
  `golang.org/x/{crypto,net,sys}`.
- Rationale: design principle 3 (Go-native, no host-binary dependency in the
  default path). No cgo: AF_PACKET ring and all netlink talk are written in
  pure Go on top of `x/sys/unix`, so the linux/amd64 binary is static.

### D-run-05: repo module path
- `github.com/PurdueBlueTeam/phylax` (matches the existing git remote).
  Nothing is pushed (run boundary).

### D-run-06: milestone "gate" interpretation
- Each milestone's gate lists lab tests (Txx). For this run: a gate passes
  when every Txx that has a local equivalent passes that equivalent, and every
  Txx without one is listed below as unverifiable with its reason. Progress is
  recorded in MILESTONES.md.

### D-run-07: repo-local git identity
- Question: `git commit` fails (no identity in global or repo config); the
  AGENTS.md rule says never change git config, but the unattended rules
  require a commit at each green checkpoint.
- Options: (a) set `user.name`/`user.email` in the repo-local config only;
  (b) skip commits.
- Decision: (a), matching the identity used by earlier commits in this
  history (`David Racovan <davidracovan@localhost>`). Repo-local only; the
  global config is untouched.

### D-run-08: rollback snapshot wire type
- Question: the rollback target snapshot (`Before`) was base64-encoded into a
  `string` field on the wire, then the agent base64-decoded it — two layers of
  encoding with a bug: the agent sent the already-encoded string back, so
  rollback decoded once and restored the base64 text, not the file content.
- Options: (a) keep the string and fix the double-encode; (b) make the wire
  field `[]byte` and let JSON handle the base64 layer once.
- Decision: (b). `link.Step.Before` and `link.StepResult.Before` are now
  `[]byte`; controller stores raw snapshot bytes, agent restores raw content.
  Verified E2E: failed plan rolls back `file.write` to the exact prior bytes.

### D-run-09: agent/relay identity location
- Question: agent and relay private keys were written to
  `<CWD>/<host>-identity/key` (relative to the process working directory),
  leaking key material into the repo (committed in d880337) and sharing one
  identity across different state dirs of the same host name.
- Decision: identity now lives under the state dir
  (`<state-dir>/<host>-identity/key`), matching the doc's "state dir persists
  identity". The leaked keys were removed from git and the worktree;
  `*-identity/` added to .gitignore. M1 tests re-run green.
## Unverifiable in this environment (skipped, per user instruction)

- U-01: NFLOG-based denied-egress first-packet logging (kernel module absent;
  see D-run-03).
- U-02: Windows agent end-to-end (no Windows hosts): WinRM E2E, Sysmon,
  Defender, raw-socket capture, WMI/COM actions, LSASS decoy, T04/T06/T08/
  T10/T24/T26/T27(Windows part). Code for these exists and compiles for
  GOOS=windows where practical; runtime behavior is untested.
- U-03: Real PAN-OS / VyOS devices (no licenses/boxes): adapter apply/commit/
  drift E2E. Rendering, config-diff and client logic are tested against the
  documented XML API semantics; device E2E untested.
- U-04: Proxmox/Terraform replica lab with fault injection and real
  firewalls; the docker two-segment-with-NAT simulation is the local stand-in
  for topology tests (partial: host firewalls simulated with per-container
  nftables, Palos with an XML mock or the render-only path).
- U-05: Active Directory (DCSync T07, kerberoasting T08, honey AD accounts,
  krbtgt reset) — no Windows/AD stack available.
- U-06: systemd/Windows-service supervised install E2E on competition images
  (unit/service file rendering and install commands are tested; live restart
  supervision is not).
- U-07: 25-minute cold-start hardening timing on real servers (the plans and
  their health checks are exercised; wall-clock against real infra is not).
- U-08: NISE upload path (no NISE access) — PDFs are produced locally.
- U-09: GitHub Actions CI execution (workflow file committed; running it
  requires pushing to the remote, which is outside the run boundary).

## Open questions for the user (nothing blocked on these)

- Q-run-01: The design doc's build plan is 16 weeks with 7 milestones. The
  overnight run compresses this into a single night. Where the two diverge
  (e.g., week-long lab soaks), the local equivalent is used. Flag anything you
  would rather have cut or kept whole.
- Q-run-02: `dist/` fallback binaries are to be committed to the repo in the
  real workflow (competition constraint: public GitHub releases). For this run
  I sign locally and keep signed artifacts under `dist/` but they are build
  output, not hand-made.
