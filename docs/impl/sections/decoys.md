#### `decoys`

**1. Purpose and evidence.**

The `decoys` module runs fake network services and a fake shell on hosts that opt in. Nothing legitimate ever connects to them, so a connection is a signal, a login attempt or a command is a stronger one, and a honey credential typed into a decoy names the host that was looted. The module turns red-team curiosity into precise, low-noise alerts.

Everything runs in an unprivileged child process of the agent. The decoys parse hostile input all day, and they are the agent code most exposed to attackers, so a bug in one must not land in the root process that holds the agent's keys.

Decoys are LAN-only (review D388, D389, area 9 answer). A decoy on a public address is found by the organizers' perimeter assessment, which scores extraneous or missing services [[2026-mw-regional-scorecard-t7#e3]]; v3 allowed public exposure, v4 does not.

Evidence that it matters for points:

- On a flat LAN nothing else watches east-west traffic. A connection from one of our own servers to a decoy means that server is compromised, which is the main value of decoys (review D388). Honeytokens plus the SSH decoy catch lateral movement (review D383).
- A honey credential used anywhere is near-certain compromise; the decoy recognises the credential and names its origin (review D335 `D15`, "highest-confidence alerts we have").
- Red teams loot credentials and scan from inside the LAN after the first foothold [[how-to-win-ccdc-dealing-with-red-team]].
- Peer evidence: none for a decoy shell in an open CCDC defence platform; the module is built from the v3 design. This is a point against, and the reason for opt-in per host and the cut of public exposure.
- Isolation is what makes decoys safe (review D64, D82).

**2. Status and code.**

Status: built. The process split is done on Linux; Windows runs in the agent process.

| Piece | State | Where |
| --- | --- | --- |
| Decoy module: listeners, per-source and global limits, session timeouts, event rate limit | built | `internal/decoys/module.go` |
| Fake shell over an in-memory filesystem from `pools/fs`; no process-execution import (a test parses the sources and fails on `os/exec`, `syscall`, `plugin`, `unsafe`, file writes) | built | `internal/decoys/{shell,shellio}.go` |
| Decoy services: `ssh`, `telnet`, `mysql`, `redis`, `rdp` (X.224 negotiate, `mstshash` cookie), `winrm` and `http_admin` (HTTP login page), `smb` (banner only, never 445) | built | `internal/decoys/{ssh,telnet,mysql,redis,rdp,httpadmin}.go` |
| Sandbox: the agent binds the sockets, re-executes its own binary as an unprivileged child with the sockets as inherited descriptors | built, Linux; Windows runs in-process | `internal/decoys/sandbox` |
| Persistent SSH host key `decoy_ssh_host_ed25519` (0600, atomic create; a damaged key is an error) | built | `sandbox/hostkey.go` |
| Agent factory, signed `deception` section | built; one `deception` section serves both modules | `internal/agent/mods/deception.go`, `internal/plan/agentconfig.go` |
| Controller config build from `decoys.yml` and the registry | built | `internal/controller/deception_config.go` |
| Manifest lint `DC001` (decoy on a scored port), `DC002` (decoy without the role) | built | `internal/manifest/lint.go` |
| Decoy rules `D15a`-`D15c` | built | `rules/deception.yml` |
| Windows restricted-token child | missing | |
| Public exposure | cut (the code defaults `exposure` to `both`; the field goes away) | `HostDecoys.Exposure` in `internal/manifest/types.go` |

**3. Capability manifest.**

```go
module.Manifest{
	Name:      "decoys",
	Sides:     []module.Side{module.SideAgent},
	OS:        nil,                      // Linux (sandboxed) and Windows (in-process, weaker)
	Privilege: "root",                    // binds low ports, then drops to the sandbox user
	Roles:     []string{"decoys"},
	Consumes:  nil,
	Emits:     []event.Type{ /* decoys.hit */ },
	Budget: module.Budget{CPUMillisPerSec: 10, HeldMB: 16, EventsPerSec: 20, Burst: 100,
		BytesOutPerMin: 131072, DiskMB: 1},
	Default:  false,                      // opt-in per host in decoys.yml
	Tables:   nil,
	Content:  []string{"rules/decoys", "pools"},
	Actions:  []string{"deception.decoy_check"},
	Pages:    []string{"/deception"},     // shared with honeytokens
	Evidence: []string{"2026-mw-regional-scorecard-t7#e3", "how-to-win-ccdc-dealing-with-red-team"},
}
```

The sandbox child is part of the module, not a second module. Budgets are starting caps; the child's memory counts toward the agent's cap.

**4. Configuration.**

Which decoys run on which host is `decoys.yml` (a per-host declaration, the same file `honeytokens` reads for its half). Behaviour knobs are in `modules/decoys.yml`.

```yaml
# manifest/decoys.yml (per host; the exposure field is removed)
decoys:
  rocky-ecom:
    listeners: [{ kind: winrm, port: 5985 }, { kind: rdp, port: 3389 }, { kind: redis, port: 6379 }, { kind: http_admin, port: 8081 }]
  mssql:
    listeners: [{ kind: ssh, port: 22 }, { kind: telnet, port: 23 }]
```

```yaml
# manifest/modules/decoys.yml
decoys:
  sandbox_user: nobody          # Linux; "-" runs with the agent's identity (tests only)
  bind: ""                      # "" = all interfaces of the host
  limits:
    max_sessions: 64            # concurrent, all sources
    max_per_source: 4
    session_timeout: 2m
    idle_timeout: 30s
    max_commands: 100           # per session
    max_auth_attempts: 6        # per session before the connection is dropped
    accept_after: 3             # password attempts before the SSH/telnet decoy lets the client in
    hit_rate: 2                 # sustained hit events/s per source
    hit_burst: 20
  lan_only: true                # host firewall rule restricted to the host's segment prefixes; not a setting that can be false
```

Listener kinds in the manifest: `ssh`, `mysql`, `redis`, `telnet`, `winrm`, `rdp`, `http_admin`, `smb` (banner only, never 445). `lan_only` is shown for explanation; it is not a field.

```go
// package plan, as built
type DeceptionSettings struct {
	Bind        string                  `json:"bind,omitempty"`
	Listeners   []DecoyListenerSettings `json:"listeners,omitempty"`
	ScoredPorts []uint16                `json:"scored_ports,omitempty"`  // the host's scored services; a decoy is refused on any of them
	Tokens      []HoneyToken            `json:"tokens,omitempty"`        // every registered honeytoken (cross-host matching)
	WatchPaths  []string                `json:"watch_paths,omitempty"`   // honeytokens' fanotify/SACL paths
	SandboxUser string                  `json:"sandbox_user,omitempty"`
	InProcess   bool                    `json:"in_process,omitempty"`
}
```

At retrofit the single `deception` section splits into `modules.decoys` (listeners, scored ports, limits, sandbox) and `modules.honeytokens` (tokens, watch paths). The old unsigned `<state>/deception.json` is read only when the signed config has no section (migration, with a warning); remove it once every controller sends the section.

**5. Events.**

Consumed: none (the decoys act on network input). They need the honey token registry only as configuration.

Emitted:

| Kind (code name) | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `decoys.hit` (`decoy.hit`) | 1 | critical for the bus (so it rides the spool's top class); the `severity` field carries the depth | see below |

`decoys.hit` fields:

| Field | Meaning |
| --- | --- |
| `stage` | `connect`, `login`, `command`, `request`, `rejected`, `end` |
| `severity` | `info` (connect, request), `high` (login, command), `critical` (honeytoken) |
| `protocol`, `source`, `source_port`, `dest_port`, `decoy_host` | who touched what |
| `account`, `secret`, `method` | a credential attempt (`secret` is what the attacker typed; MySQL records `$mysql$salt$response` for offline cracking) |
| `key_fingerprint` | SSH public key tried |
| `command` | one fake-shell line, or one Redis command |
| `honeytoken`, `token_origin`, `token_kind` | set when a honeytoken was used: the host it was planted on |
| `credentials`, `commands`, `duration_ms`, `honeytokens`, `token_origins` | on the `end` summary |

Priority is critical for every hit so the spool's top class carries it; the `severity` field, not the event priority, drives the rule. Honeytoken hits bypass the per-source event rate limit; everything else over the limit is dropped and counted (`Stats.HitsDropped`).

**6. Behaviour.**

*Principles.*

- **Declared like services.** Decoys are listed in `decoys.yml`; the host-firewall rule is generated from them.
- **Isolated.** All decoy listeners and the fake shell run in the unprivileged decoy process (review D64, D82).
- **Record only.** Nothing received is ever executed. Decoys never connect back and never touch red-team infrastructure (review D385). `internal/decoys` imports no process-execution package; a test parses the sources and fails on `os/exec`, `syscall`, `plugin`, `unsafe`, file writes or removals. The fake shell is a function over an in-memory filesystem built from `pools/fs`: `touch`, `echo >`, `rm` change only that memory (at most 128 files, 4096 bytes each).
- **Never on a scored port** (review D386). In 2027, SSH, WinRM and RDP are scored on specific hosts, so decoys of those kinds go only on hosts where the service is not scored: SSH on the Windows hosts, WinRM and RDP on the Linux hosts. Three layers: the manifest lint (`DC001`, error on a scored port), `decoys.New` returns `ErrScoredPort` for a listener on any port in `ScoredPorts` and always refuses 445, and the agent factory passes the scored ports from the signed section plus every real service port in the `net` module's service map (the decoys' own `decoy-*` entries are skipped), so a decoy never shares a port with any declared service.
- **Generated at competition time.** Banners, decoy ports, hostnames and fake data are randomised per event from `pools/` (D-8). The pools are in the public repo, so a careful attacker may recognise some decoys; per-host values are what the repo cannot reveal.
- **Severity follows depth** (review D390): connecting is info, logging in or running commands is high, a honey credential or key anywhere is critical. Bare decoy connections stay info because traffic generators and scans produce them; blocking stays one click.
- **Bounded.** Per-source concurrent sessions (4), total sessions (64), a hard session timeout (2 minutes), an idle timeout (30 s), a command cap (100), an auth-attempt cap (6), bounded line, bulk, HTTP and MySQL packet sizes, and a per-source token bucket on events (2/s, burst 20).

*Decoy services.*

| Decoy | Behaviour |
| --- | --- |
| SSH (22 where real SSH is absent or not scored; also non-standard ports) | A full fake shell: accepts a login after `accept_after` password attempts (or at once for a honey password or key), presents a believable filesystem and command set, records every keystroke, never executes anything. Banner randomised per host. Persistent host key so the decoy keeps its identity across restarts. SSH public keys tried are recorded by fingerprint. |
| Telnet on hosts that do not run it | Protocol-correct login prompts; credentials recorded; same shell. |
| MySQL, Redis | Protocol-correct handshake and login prompts; credentials recorded (MySQL as `$mysql$salt$response` for offline cracking; Redis commands recorded). |
| WinRM (5985) and RDP (3389) on hosts where those are not scored | RDP: reads the X.224 connection request, records the `mstshash` cookie as the account name, answers a standard-RDP connection confirm and discards the rest. WinRM: an HTTP exchange that records credentials where the protocol offers them. Both negotiate only. |
| Fake admin web panel (`http_admin`) on an unused port | A login page that records every credential tried; panel titles come from `pools/http_panels.txt`. At most 20 requests per session. |
| SMB | Banner only, never 445: Windows holds 445 on every host. |

These extra decoys (MySQL, Redis, Telnet, WinRM/RDP, the panel) were proposed for deletion as low-depth signals; David kept them (area 9 answer, review D383): LAN-only, opt-in per host in `decoys.yml`. **Complexity flag:** the fake shell is the largest decoy by far. It is isolated in the unprivileged process, has no real filesystem or command execution behind it, and has its own fuzz tests in CI.

*LAN-only exposure* (review D388, D389). A decoy's host-firewall accept rule is in the `decoy` group and is limited to the host's own segment prefixes, not to any source. This is allowed: decoy ports are never scored, and decision 13 applies only to scored ports. The Palo and VyOS get no rule, object or NAT entry for a decoy port, so no decoy is reachable from outside. The manifest drops the `exposure` field (the code defaulted it to `both`); a manifest that still sets it fails validation. Public addresses are never decoy addresses. A connection from one of our servers to a decoy means that server is compromised; the alert names the source host from the manifest.

*Our own scanners.* The Kali's subnet sweep (`scanner` role; unmanaged-host sweep) and the egress canaries must not alert. Both come from the Kali's translated source, which is in `reference.scorer_sources` (seeded by the controller from the manifest), and `D15a` gains that exemption (it has none today). A bare connection is a low-severity alert in any case.

*Hardening of the process.* The agent (privileged, able to bind low ports) binds every listening socket, then starts a copy of its own binary as the decoy child with the sockets as inherited file descriptors. On Linux, when the agent is root, the child starts with the uid and gid of `nobody` (or `sandbox_user`) and no supplementary groups, sets `no_new_privs` first thing, and refuses to run if it is still root after a requested drop. Configuration, including tokens, arrives on stdin, never in argv or the environment; the child's environment is empty apart from a marker. Events return as JSON lines on stdout. The open stdin pipe is the lifeline: when the agent dies the child exits. A child crash is a module crash, restarted by the supervisor with backoff. The agent binary must be executable by the sandbox user. The `internal/decoys` package itself stays free of `os/exec` and `syscall`; the process handling is in the `sandbox` subpackage.

*Windows.* The listeners run in the agent process (`in_process`). A restricted-token, low-integrity child (CreateRestrictedToken) is the plan; until it exists Windows decoys are the weakest link and should not run on the domain controller. The manifest lint warns on a decoy declared on a host with the `domain_controller` role. The reference manifest has decoys on `mssql` only.

*Windows Defender.* An unsigned binary that runs fake services can look like malware. Lab test T24 runs the agent, decoys and the LSASS decoy session against current definitions; if flagged, the one exclusion is the agent's randomised install directory (core: Windows Defender).

*Deploy plan.* `plans/deception.deploy.yaml` verifies the listeners and plants the bait. `Controller.DeceptionPlan(ctx, id, hosts...)` generates the missing tokens and returns the plan: an approval gate, a `deception.decoy_check` per decoy host (connects to the listeners on loopback), and the `plant.<token>` nodes from `honeytokens`. The decoy listeners themselves need no step: the `decoys` role plus `decoys.yml` put the section in the host's signed config, and the agent starts the listeners when it applies it.

**7. Actions and content.**

| Action | Risk | Locks | Scorer-visible touches | Notes |
| --- | --- | --- | --- | --- |
| `deception.decoy_check` | none | none | none | Connects to the decoy listeners on loopback and waits up to `wait_sec` (30 s in the plan); read-only. |

Content: `rules/decoys/` holds `D15a.decoy-touch` (low; a bare connection, exempting our own scanners), `D15b.decoy-login-or-command` (high; stage `login` or `command`, collects a 10-minute auth window) and `D15c.honeytoken-at-decoy` (critical; a honey credential or key used against a decoy, naming `token_origin`), each with inline tests. The decoy pools live in `pools/` (SSH banners, MySQL and Redis versions, Telnet banners, panel titles, shell hostnames, usernames, service names, filenames, `fs/` for the fake filesystem and `commands.txt` for the shell). Rules `D15d`-`D15g` belong to `honeytokens`.

**8. UI.**

The Deception page (shared with `honeytokens`) lists, per host, the declared decoys with their ports and state, the last hits by source with the depth, and the credentials and commands recorded (masked until revealed; `secret` is attacker-typed and hostile, escaped like any agent string). Decoy sources are linked to the traffic labels. Host x step grid: none. Overview tile: decoy hits in the last hour by severity.

**9. Health.**

- `ok`: all declared listeners bound and the child alive.
- `degraded`: a listener could not bind (port in use, which is itself reported); the hit rate limit is shedding events; the host runs the Windows in-process fallback; the SSH host key could not be created.
- `unavailable`: the sandbox user does not exist or the agent binary is not executable by it.
- Gaps: Windows decoys not isolated (restricted token missing); decoys refused on a scored port (reported with the port and service, so the operator can see why a declared decoy is missing).

**10. Scoring safety.**

- It adds listeners, so each is a risk on the scored path. The three layers above keep decoys off every scored port and off 445. The firewall lint (`FW101`) still requires every scored port open to any source; the decoy rule is additive.
- Decoys never run on a scored port, never change content the scorer fetches, and never open an outbound connection (record only).
- The listeners are bounded and run in an unprivileged process, so a flood from the LAN cannot exhaust the agent: the supervisor restarts the child.
- LAN-only means the organizers' perimeter assessment cannot see a decoy.
- The module has no alert-only stage because it takes no action on the host.

**11. Tests.**

- Built: shell and service tests; the source-level import test for the record-only rule; limits (sessions, per-source, timeouts, command and auth caps); the sandbox tests (child serves decoys and relays events, `no_new_privs` and stops with the parent, root drop); `ErrScoredPort` and the refusal of 445; pool tests (`pools_test.go`); the lint tests (`DC001`, `DC002`); controller tests for config and plan (`deception_test.go`); decoy rule inline tests; `FuzzShell`.
- To add: host-firewall decoy rules restricted to the segment prefixes (render test) and the absence of any decoy rule in Palo and VyOS intents; a manifest with `exposure` fails validation; the lint warning for a decoy on a domain controller; `D15a` exemption for the Kali source; conformance entries (no config, link loss, budget).
- Lab: T09 (a honey SSH key used against the SSH decoy: critical alert naming the origin host), T24 (Defender), T25 (crafted strings in decoy-shell input never execute or render as markup in the UI). Review D514 keeps the decoy tests in the renumbered matrix.

**12. Limits and open items.**

- `shortcut: Windows decoys run in the agent process; upgrade to a restricted-token child before decoys run on a domain controller or any host with sensitive keys in memory`.
- The honeytoken secrets of every host sit in each decoy host's signed config, so a decoy can recognise a credential planted on another host. A compromised decoy host reveals them. They are fake, but a recommendation is to send the decoys a salted hash of each secret and compare hashes (the SSH and Telnet decoys compare plain passwords; MySQL's `$mysql$salt$response` cannot be verified against a hash). Undecided.
- The `deception` agent section is shared with `honeytokens`; the split at retrofit needs a `plan.ModuleSettings.Decoys` and `.Honeytokens` and a config migration.
- The core action table does not list `deception.decoy_check`; it belongs here. `file.plant` and `ad.honey_account` belong to `honeytokens`.
- LAN-only host-firewall restriction for the decoy rule group is new (the code accepts any source); it needs the renderer to restrict `GroupDecoy` peers to the host's segment prefixes. The Palo and VyOS renderers must not emit decoy-port rules. The `HostDecoys.Exposure` field and its `both` default go away with it.
- No decoy for SMB (Windows holds 445 on every host).
- Hit severity maps to rule severity with `D15a` at `low`, not `info`, so it appears in the alert queue; whether bare connections should be alerts at all is the noise question the Invitational answers (observe mode, collector data).
