# W2 rehearsal results (Task 15), 2026-11-06

Branch `lab-rehearsal`, base `v4` at `2e8c9a3`. Replica ccdc26 on prox2, guests rolled back to their clean
snapshots; credentials are the packet defaults (not recorded here). Controller on the test box (26001,
172.20.240.240, `serve -advertise 172.20.240.240:7443 -bundle-safe -enroll-window 30m`), kit served on
`:8000`. The manifest is the observe manifest with hosts renamed to the replica (ubuntu-ecom, fedora-webmail,
splunk, ad, web, ftp, win11-wkst). The owner asked to expedite: Step 5 is one reading per host, parts of
Step 4 are "not checked". Step 3 ran longer than asked (about 55 to 80 minutes of observe mode) because the
hour was already under way.

Hosts: ubuntu-ecom 172.20.242.30 (26010), fedora-webmail .40 (26011), splunk .20 (26012), ad 172.20.240.102
(26014), web .101 (26015), ftp .104 (26016), win11-wkst .100 (26017). ubuntu-wkst (26013) was not used. The
Cisco FTD stayed off.

## Step 1: runbook end to end

Typed through the Proxmox console (`qm monitor sendkey`) on ubuntu-ecom (Linux tty) and the AD (Windows
cmd). Other hosts were driven over SSH and WinRM with the same lines. The injector types about 66 characters
per second (1.5 to 1.9 s per line), so these are lengths and key mapping, not human typing time.

| Line | Chars |
| --- | --- |
| `curl -s 172.20.240.240:8000/e\|sh -s 172.20.240.240:8000 ubuntu-ecom` | 67 |
| `c1-capture.sh start` | 60 |
| `c2-facts.sh` | 47 |
| `c2-sampler.sh start` | 55 |
| `curl ... ubuntu-ecom agent` (Linux enrollment) | 73 (over the 70 goal with these longer values) |
| Windows `md`, `curl.exe`, `tar.exe` lines | 28, 83, 75 |
| `c1-capture.ps1 -Action start`, `c2-facts.ps1`, `c2-sampler.ps1 -Action start` | 84, 68, 84 |
| `e.ps1 -Ctl ... -HostName ad -Agent` | 106 |

Characters that did not map: none (`| \ : ! ~ ' " _` all typed on the Linux tty and the Windows cmd; this tests
QEMU's keymap, not NETLAB's). `|` worked on both console types. Curl to "enrolled seen on the controller":
ubuntu-ecom about 10 s; AD about 45 s, almost all of it the 28 MB `phylax.exe` download from the
single-threaded `http.server`. Every Linux kit line prints `tar: ... time stamp in the future` because the
clean images' clocks are months off (ecom and fedora Feb 14, splunk Mar 10; AD, web and ftp also February):
harmless noise, but the controller timestamps events with the host clock, so a skewed host's timeline is wrong
until its clock is set. Worth adding "set the clock" to the host checklist.

Enrolled and connected: all 7 hosts, safe mode on from the bundle.

## Step 2: Windows scripts, first real run

All seven scripts ran on AD, web, ftp and win11 after the fixes below. pktmon exists on 2019, 2022 and
Windows 11; it writes its file only when the 64 MB buffer flushes or on stop, so a quiet host shows a 0-byte
`.etl` for a long time (not a failure). Sampler processes started over WinRM die with the session (a job
object, a driving artifact); started from a console they run. The win11 sampler was not restarted.

Failures found and fixed (verified on the replica):

| Failure | Cause | Fix |
| --- | --- | --- |
| `c2-facts.ps1`, `c4-ad.ps1` stop at once | StrictMode and `$script:InvRoot` unset | set `InvRoot` first (`ff97cfc`) |
| Every `powershell -File` line fails on Windows 11 | execution policy Restricted | runbook sets `PSExecutionPolicyPreference=Bypass` first (`b641535`) |
| c2 `datasizes` exit 1 | StrictMode on `Measure-Object -Sum` of an empty folder | sum in a loop (`b641535`) |
| c4 `krbtgt`, `domain`, `pwpolicy` exit 1 | wrote the file `Inv-Run` holds open | emit to the pipeline (`f6b50ae`) |
| c4 `hardening` exit 1 | missing registry value is an error under `Stop` | `Continue` for that block (`f6b50ae`) |
| c5 `Inv-AppendLine` throws | empty string rejected | `AllowEmptyString` (`f6b50ae`) |
| `agent install`: "A required privilege is not held" | SACL write needs SeSecurityPrivilege | enable it first (`f2ccc7f`) |
| ...retry: "service already exists" | failed install left the service | delete the service on failure (`f2ccc7f`) |
| winevt: every channel `subscription_error` on every Windows host | `EvtNext` returns 4317 for an empty future-events queue | treat 4317 as no more items (`83f4793`; events then arrived from win11, AD, ftp) |

Remaining non-zero `_index.tsv` rows are host facts: the Sysmon channel (no Sysmon installed), win11 `ntp`
(time service stopped), AD `computerinfo`/`trace` on several runs. No Go test runner exists for Windows, so
the Windows paths were verified on the replica only.

Linux kit failures found by the same run:

| Failure | Fix |
| --- | --- |
| **No pcap on any Linux host**: tcpdump drops to its own user and could not write the root-owned pcap dir, yet `c1 start` printed "started" | pcap dir 0777; `start` fails if tcpdump exits within a second (`e1f29db`). `-Z root` segfaults tcpdump on Fedora. Verified: pcaps grow on all three hosts. |
| `c3-logs.sh` fails on `tar` exit 1 ("file changed as we read it") | keep the archive on exit 1 (`e1f29db`; not rerun) |
| `c5-probe.sh` `trace` exit 64 on ubuntu-ecom | inetutils traceroute has no `-n`: prefer `tracepath` (`0c8de04`; verified by hand) |

Other Linux non-zero rows (`web`, `mail`, `datasizes`, `cron`, `sudoers`, `logconf`) are absent paths or
commands on these hosts, not faults.

## Step 3: T70, observe mode changes nothing

c2-facts before enrolling and again after the observation period. Linux: the only listener differences are
the decoys (ecom 3389, 5985, 6379, 8081; fedora 23, 3389, 5985; splunk 3306, 3389, 5985), exactly the
manifest's decoys, plus the `phylax.service` unit. Accounts, firewall and authorized_keys are unchanged
(ecom shows apt and OpenSSH upgrades from the image's own unattended updates; splunk's `dnf-makecache`
failed for lack of a repo), none of it Phylax.

Windows (ad and win11 compared; web and ftp not): listeners, local admins, firewall profile and scheduled
tasks unchanged; services differ by `phylax` plus ordinary state changes (gpsvc, seclogon, sppsvc, wuauserv).
On the AD, `localusers` shows `LastLogon` and `PasswordLastSet` changes for several accounts (22:36 to 23:22,
the rehearsal window). Phylax in observe mode sets no passwords, but I did not find the cause (my own WinRM
logons and test credentials are a likely source). Needs a look.

Result: pass for Linux; pass for Windows listeners, admins, firewall; AD account times unexplained.

## Step 4: claims from "What exists today"

- **C9 check rounds from the UI: no.** `/checks` is read-only; nothing outside tests calls
  `ChecksHub.RunProbe`. Not fixed.
- **integrity without a ledger:** each Linux agent emits one `integrity.ledger_unavailable` (`ledger.plx`
  missing) and nothing else. `phylax depot` does not build a ledger (it is the tool depot); nothing writes
  `ledger.plx`. Windows has no integrity module.
- **Safe-mode toggle per host: works.** `POST /agents/win11-wkst/safemode` with the host name as confirmation
  turned it off, the agents page showed it within 3 s; turned back on afterwards.
- **First-hour plan on the canary through the UI: no.** The Plans page lists only top-level files of the plans
  path and shows `actions`, `deception.deploy`, `splunk.forwarding`, `wazuh.*` as "invalid: unknown field"
  (`vars`, `each`): the UI template loader (`internal/controller/plantemplates.go`) is the old format and does
  not use `plans.Template.Expand`; `first-hour/` is not listed. Not fixed. A hand-written old-format template
  (file.write on win11-wkst, dead-man 60 s) went draft, dry run, approve, apply, verified in the UI; the file
  appeared and stayed (the dead-man did not roll it back). A later rollback via UI returned 404 after a
  controller restart (run state is not kept across restarts); I removed the file by hand.
- **`pcr.generate` from the UI: no.** No UI route, action or plan references it.
- Decoys crash-looped on all Linux hosts ("fork/exec /opt/phylax/phylax: permission denied" every ~45 s):
  `agent install` made `/opt/phylax` 0700 and the decoys child runs as nobody. Fixed (`b3db4ce`: install dir
  0755 first); on the replica `chmod 755 /opt/phylax` by hand stopped it.
- ubuntu-ecom raised 94 `D10.telemetry-gap` alerts with a count of 4294967295 (a wrapped uint32). Fixed to one
  inexact lost record (`5d8eaf3`, unit test); the rebuilt Linux agent was not deployed to the replica. It also
  shows 72 `D6i.pam-change` alerts, not investigated.
- The Health page shows `config: degraded` on the Windows hosts: my manifest gives them the `capture` role but
  there is no Windows capture module. Give Windows hosts winevt and detect only.
- `enroll.hash_mismatch` fired for each Windows host whenever I rebuilt `phylax.exe` and restarted `serve`:
  an artifact of this run, and it shows the alert works.

Not checked: the dead-man actually firing, other enrollment alerts, the remaining Operator pages.

## Step 5: resource cost (one reading, about 75 to 90 minutes after enrollment)

| Host | Agent CPU | Agent RSS | Note |
| --- | --- | --- | --- |
| ubuntu-ecom | 27% (mean since start) | 131 MB | decoys child 17 MB; load average 4.3 |
| fedora-webmail | 0.7% | 73 MB | decoys child 29 MB |
| splunk | 12% | 137 MB | decoys child 36 MB |
| ad | 34 CPU-s in about 80 min | 95 MB | |
| win11-wkst | 17 CPU-s in about 50 min | 71 MB | |

The unit's caps are 256 MB and 50% CPU: all within. ecom's mean 27% is high for a host doing little (audit exec
stream, many gap events); not investigated. `moduleBudgets` no longer exists in `genconfig.go`, so no budget was
changed. web and ftp were not read; the sampler CSV was not analysed.

## What was changed on each host

All hosts: snapshot `pre-phylax-rehearsal` (26010 to 26018, 26021); Phylax agent installed and enrolled
(service `phylax`; Linux `/opt/phylax`, `/var/tmp/phylax-kit`, `/var/tmp/phylax-bin`, `/var/tmp/phylax-inv`;
Windows `C:\ProgramData\phylax-kit`, `phylax-bin`, `phylax-inv`); C1 capture and C2 sampler started
(tcpdump or pktmon; samplers on the WinRM-driven Windows hosts died with their session); audit rules and
decoy listeners on Linux. Hosts stay enrolled, safe mode on.
- ubuntu-ecom, fedora-webmail, splunk: `chmod 755 /opt/phylax` by hand; pcap dir mode 0777.
- win11-wkst: a probe event in the Application log (`eventcreate`, source `phylaxprobe`); temporary files
  and the plan's rehearsal file removed; safe mode toggled off and back on.
- AD: `sc delete phylax` once after the failed first install, then reinstalled; c4 output zip under
  `C:\ProgramData\phylax-inv`.
- Windows hosts: agent reinstalled once after the winevt fix.
- Test box: `/srv/phylax`, tmux sessions `serve` and `web`, `/var/lib/phylax`, helper scripts in `/root`. The
  operator UI admin password is in `/var/tmp/phylax-serve.log` there.

## Push and bench (short run), 2026-11-06 late

Built from `v4` at `4f7e608`, plus one fix (`9945ddf`). Controller restarted with `-vault` (lab vault, packet
default credentials, one secret per OS because the Linux and Windows users differ) and `-release-dir`.
Pushes were run from the operator UI (`POST /enroll/{host}/push`); `phylax enroll push` refuses while `serve`
runs. Hosts that were not enrolled: the agents on fedora-webmail and ftp were uninstalled first; web (26015)
was found stopped on prox2 and left alone.

### Push enrollment

- **Fix first (`9945ddf`): UI push could never work from `serve -vault`.** `serve` opened the vault but never
  put it in `controller.Options`, so every UI push failed with "conflict: the vault is not open". Now passed
  through. No test: `serve` is not unit-testable here (it runs until cancelled); verified live.
- **Linux (fedora-webmail, SSH, user from the vault): FAIL, two findings.**
  1. `hostname_mismatch: host reports "goomonsu", manifest says "fedora-webmail"`: the replica's guest
     hostnames differ from the manifest names (lab artifact; the real event's hostnames must equal the
     manifest keys). I renamed the host in the lab manifest to `goomonsu` and pushed again.
  2. `selinux_denial: mkdir: cannot create directory '/opt/cron-pkgd-c1546f': Permission denied; install dir
     removed`. The cause is not SELinux: the packet's default user (`sysadmin`) is not root, and the SSH push
     runs the one-liner with no `sudo`. The class and its advice ("allow the install path under SELinux") are
     misleading for a non-root login. Needs a decision: push as root (is root SSH login allowed in the
     packet?) or make the push `sudo` the one-liner. Not fixed. The host was then enrolled with the console
     one-liner (as root, after clearing the old agent state; connected, `enrolled_now=true`).
- **Windows (ftp, WinRM 5985, NTLM): FAIL, as expected.** `auth_refused: probe: winrm authentication refused`
  with correct packet credentials (the same credentials work with pywinrm, which encrypts). On the wire the
  server answers the NTLM type-3 with `401 WWW-Authenticate: Negotiate, Kerberos`. Same result on ad and
  win11-wkst. `winrm get winrm/config/service` on ftp: `AllowUnencrypted = false`. Phylax's client sends NTLM
  without message sealing (documented shortcut in `internal/checks/probe/winrmshell.go`). The WinRM settings
  were not touched. The UI message also misleads ("check the vault's default credentials and the SSH
  password policy"). ftp was then enrolled through the console `e.ps1` line.
- Net: neither push path works with the stock packet hosts. The console one-liner works on both.

### Comms bench

`bench.jsonl` runs by default. Window 04:44 to 04:55 UTC (about 10 minutes, 7 to 8 agents after the controller
restart), `phylax bench report -check`. Output is appended below.

Result (650 s, 66 samples, 8 agents, includes my two re-enrollments):

| Measure | Value |
| --- | --- |
| Agent RTT | p50 1.8 ms, p95 3.8 ms, p99 88 ms, max 1.2 s |
| Event throughput (all agents) | critical 0.2, high 3.5, normal 3.3, bulk 2.2 events/s (about 15 KB/s) |
| Reconnects | `connects` 2 (ftp reinstall, goomonsu enrollment); no unplanned reconnects |
| Gaps | 0 records, 0 events; `down ms` all 0 |
| Spool depth / lag | max 164 / max 3 events; no shed, no non-ok samples |
| Controller | CPU p50 2.1%, max 2.9%; RSS max 559 MB; store 116 to 131 MB |
| Queries | events p99 27 ms, health p99 5 ms, overview p99 50 ms |

`-check` FAILED on one item: "partition_marks: none a partition_start mark" (no partition was run, so this
only means the partition test was not done). The latency columns show `+Inf` for p95 and p99 in every class:
every host's clock is months off the controller's (`skew abs max` about 2.3e10 ms), so event-to-controller
latency is meaningless here until the guest clocks are set; this is the same clock problem as in Step 1 and
it will make the real latency criterion unreadable on any host whose clock is wrong. Not a transport
problem: RTT and gaps are clean.

Lab state: controller restarted three times (vault wiring, manifest rename, bundle regeneration), serve now
runs with `-vault /srv/phylax/lab.vault -release-dir /srv/phylax/rel`; lab manifest has `fedora-webmail`
renamed to `goomonsu` (the guest's real hostname) and the old fedora-webmail enrollment is orphaned; web is
off. ftp and goomonsu are enrolled (console line), the rest as before.
