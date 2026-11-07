# Invitational runbook (observe mode)

Event: 2026-11-07. One controller on `ubuntu-wkst`, read-only collectors, every
module's act switch off. Nothing here changes a host's configuration, restarts
a service, reboots a host or reads a password store.

Conventions used below:

- `CTL` is the controller's web root as a `host:port`: `172.20.240.5:8000`.
- `HOST` is a name from the observe manifest: `rocky-ecom`, `ubuntu-email`,
  `debian-splunk`, `ad`, `mssql`, `ubuntu-wkst`, `win11-wkst`, `kali`.
- Every mark is typed on the **controller** console:
  `sh /srv/phylax/invitational/m.sh TEXT...`. The one timeline file is
  `/var/tmp/phylax-inv/timeline.txt` on the controller.
- The longest typed line: 70 characters (`curl -s CTL/e|sh -s CTL HOST agent`
  with the concrete values below). The rehearsal tries to shorten it.
- From `serve` starting until it stops, `phylax enroll line|push|status`
  refuse (they share the data-dir lock with `serve`). Use the Operator page
  (`http://127.0.0.1:8080` on the controller console) for enrollment status,
  safe mode, re-enrollment and plan approvals.

## 1. Before the event (by 2026-11-06), on the dev machine

```sh
cd ~/src/phylax
make build build-windows
sh tools/invitational/make-observe-manifest.sh manifest/2027 /tmp/obs
vi /tmp/obs/topology.yml          # set the team number and any packet differences
./bin/phylax manifest lint --dir /tmp/obs   # expect 0 errors
```

Decoys stay on by default (they are LAN only and run in observe mode); add
`--no-decoys` to the generator only if David says so.

Build the kit. It holds the binaries, content, the observe manifest, the
collector scripts and the controller config:

```sh
rm -rf /tmp/kit /tmp/kit.tgz
mkdir -p /tmp/kit/tools
cp bin/phylax /tmp/kit/phylax
cp bin/phylax-windows-amd64.exe /tmp/kit/phylax.exe
cp -r rules plans /tmp/kit/
cp -r /tmp/obs /tmp/kit/obs
cp -r tools/invitational /tmp/kit/tools/invitational
cat > /tmp/kit/cfg.json <<'EOF'
{
  "data_dir": "/var/lib/phylax",
  "manifest_path": "/srv/phylax/obs",
  "rules_path": "/srv/phylax/rules",
  "plans_path": "/srv/phylax/plans",
  "ui_listen": "127.0.0.1:8080",
  "agent_listen": "0.0.0.0:7443",
  "team": 1
}
EOF
tar czf /tmp/kit.tgz -C tools invitational
ls -l /tmp/kit.tgz /tmp/kit
```

Set `"team"` to the team number in the same `cfg.json`; it must be 1..99.
Upload the folder `/tmp/kit/` and the file `/tmp/kit.tgz` to the team
Nextcloud ("2027-invitational"). Print the O2 checklist and this runbook:

```sh
cat tools/invitational/o2-checklist.txt docs/impl/invitational-runbook.md
```

## 2. Roles and who types what

| Step | Role | Machine | Command | Mark text |
| --- | --- | --- | --- | --- |
| 1. Drop flag | Captain | controller console | `sh /srv/phylax/invitational/m.sh drop flag` | `drop flag` |
| 2. Scoreboard | outside scribe | outside machine | `sh scribe.sh init`, then `sh scribe.sh row SERVICE STATUS SCORE [NOTE]` | none (scribe.csv) |
| 3. Controller, web root, serve | Platform driver | `ubuntu-wkst` | section 3.2 | `controller up` |
| 4. C5 probe, upload test, O2 | Platform driver | `ubuntu-wkst` | `sh /srv/phylax/invitational/c5-probe.sh` | `c5 done`, `o2 ...` |
| 5. Linux hosts: kit, C1, C2, agent | Linux lead | `rocky-ecom`, `ubuntu-email`, `debian-splunk`, `kali` | section 3.4 | `HOST c1 started`, `HOST c2 done`, `HOST enrolled` |
| 5. Windows hosts: kit, C1, C2, agent | Windows and AD lead | `ad`, `mssql`, `win11-wkst` | section 3.4 | same |
| 5. VyOS capture | Network | VyOS console | `sudo sh /var/tmp/phylax-kit/invitational/c1-capture.sh start` | `vyos1 c1 started` |
| 6. AD dump | Windows and AD lead | `ad` | `powershell -File C:\ProgramData\phylax-kit\invitational\c4-ad.ps1` | `ad c4 done` |
| 7. Device read-out (C8) | Network | Palo and VyOS consoles, controller disk | section 3.6 | `network c8 done` |
| 8. O12 checks | Platform driver, SOC | controller and capture hosts | section 3.7 | `o12 ok` or `o12 problem` |
| 9. Log copy | each host lead | every host | section 3.8 | `HOST c3 mid`, `HOST c3 end` |
| 10. Tier B plans on the canary | Captain, Platform driver | Operator page | section 3.9 | `win11-wkst plan NAME approved` |
| 11. Tier C PCR and hardening | Captain, Credentials, Platform driver | host and Quotient machine | section 3.9 | `pcr SECONDS` |
| 12. Stop and archive | Platform driver, each host lead | all hosts and controller | section 3.10 | `event end` |
| 13. Uploads | Platform driver | controller to Nextcloud | section 4 | `upload NAME` |

## 3. Order of operations

### 3.1 Drop flag

The outside scribe starts the scoreboard sheet and reads it every round for the
first 20 minutes, then every 5 minutes (C7). The Captain marks the drop on the
controller:

```sh
# outside machine, in an empty directory
sh scribe.sh init
sh scribe.sh row web up 120 "round 1"

# controller console
sh /srv/phylax/invitational/m.sh drop flag
```

### 3.2 Controller host: `ubuntu-wkst`

Download `kit.tgz` and the `kit/` folder from Nextcloud in the controller's
browser, then install them. The download time and speed are the first
upload/download measurement (O1/throughput); mark it.

```sh
# Nextcloud saves the folder as ~/Downloads/kit.zip (top directory kit/)
mkdir -p /srv/phylax
unzip -o ~/Downloads/kit.zip -d /tmp
cp -r /tmp/kit/. /srv/phylax/
cp ~/Downloads/kit.tgz /srv/phylax/
cd /srv/phylax
tar xzf kit.tgz -C /srv/phylax
sh invitational/m.sh controller download 45s 8MB/s   # measured values

mkdir -p web
cp phylax phylax.exe kit.tgz web/
cp invitational/e.sh web/e
python3 -m http.server 8000 --directory web &
./phylax serve -config cfg.json -bundles web -advertise 172.20.240.5:7443 \
    -bundle-safe -bundle-ttl 8h \
    -served-dir /srv/phylax/web -enroll-window 30m
```

`web/` is served by the plain HTTP server and is also the `-bundles`
directory, so the bundles are downloadable at `http://CTL/<host>.json`. Tokens
live 8 h (`-bundle-ttl`) and are single use.

`shortcut: bundles are served over plain HTTP on the LAN; stop the http server once every host is enrolled.`

`-served-dir /srv/phylax/web -enroll-window 30m` starts the enrollment watch.
Until the 30-minute window ends it hashes the served `phylax` and `phylax.exe`,
checks the binary hash each `hello` reports, removes `<host>.json` after that
host connects, and at the end removes every bundle that is left. Watch the
**controller console** while this runs: the serve log prints
`level=WARN msg=alert kind=enroll.hash_mismatch|enroll.no_show|enroll.refused`,
and the same rows appear in the Operator page's alert queue. Any of those three
means **stop and look** before enrolling anything else. When the window ends,
stop the web server:

```sh
jobs -l                    # find the http.server job, then:
kill PID                   # the pid in the jobs listing
```

If the segment is shared with red, read the served binary hash from the
controller console (`sha256sum /srv/phylax/web/phylax`), not from the script
output on a host: the script's own output is not trustworthy in that case.

### 3.3 First 15 minutes

```sh
cd /srv/phylax
sh invitational/c5-probe.sh
sh invitational/m.sh c5 done

# upload test from one host of each OS (through that host's browser), e.g.
sh invitational/m.sh ubuntu-email upload 6s 1.2MB/s
sh invitational/m.sh win11-wkst upload 9s 0.8MB/s

# O2 checklist: read it out, answer every line, mark every answer
cat invitational/o2-checklist.txt
sh invitational/m.sh o2 'session timeout 10m'
sh invitational/m.sh o2 'keys that do not map: | ~'
```

### 3.4 Each host, by its lead, in this order

C1 first: pcaps are the most valuable data and cannot be recovered later.
Linux (also VyOS, run by Network):

```sh
curl -s 172.20.240.5:8000/e|sh -s 172.20.240.5:8000 ubuntu-email
sudo sh /var/tmp/phylax-kit/invitational/c1-capture.sh start
sh /var/tmp/phylax-kit/invitational/c2-facts.sh
sh /var/tmp/phylax-kit/invitational/c2-sampler.sh start
curl -s 172.20.240.5:8000/e|sh -s 172.20.240.5:8000 ubuntu-email agent
```

Windows. The first four lines are the policy line and the kit fetch (the Windows twin of the
`curl .../e` line); the last five are C1, C2, the sampler and the agent. If the
console cannot type these lines, copy `invitational/` from the injected media
to `C:\ProgramData\phylax-kit\invitational` and continue with the
`powershell` lines only.

Windows 11 refuses unsigned scripts (policy Undefined means Restricted); the first line
below lets this console session's `powershell` calls run them and changes no host setting.

```sh
set PSExecutionPolicyPreference=Bypass
md C:\ProgramData\phylax-kit
curl.exe -s -o C:\ProgramData\phylax-kit\kit.tgz http://172.20.240.5:8000/kit.tgz
tar.exe -xzf C:\ProgramData\phylax-kit\kit.tgz -C C:\ProgramData\phylax-kit
powershell -File C:\ProgramData\phylax-kit\invitational\c1-capture.ps1 -Action start
powershell -File C:\ProgramData\phylax-kit\invitational\c2-facts.ps1
powershell -File C:\ProgramData\phylax-kit\invitational\c2-sampler.ps1 -Action start
powershell -File C:\ProgramData\phylax-kit\invitational\e.ps1 -Ctl 172.20.240.5:8000 -HostName ad -Agent
```

Mark each host as it finishes, on the controller console:

```sh
sh /srv/phylax/invitational/m.sh ubuntu-email c1 started
sh /srv/phylax/invitational/m.sh ubuntu-email c2 done
sh /srv/phylax/invitational/m.sh ubuntu-email enrolled
```

Safe mode is on from the bundle (`-bundle-safe`). The Platform driver confirms
on the Platform page that every host shows safe mode and its module list.

### 3.5 Domain controller: `ad`

Early, once (the Windows and AD lead):

```sh
powershell -File C:\ProgramData\phylax-kit\invitational\c4-ad.ps1
sh /srv/phylax/invitational/m.sh ad c4 done      # controller console
```

The archive name carries `SENSITIVE`: it goes to the private Nextcloud folder
only (section 4).

### 3.6 Network: C8, read-only

```sh
mkdir -p /var/tmp/phylax-inv/network
# Palo Alto, browser on the controller console (https://172.20.240.200):
#   Device > Setup > Operations > Export named configuration snapshot
#   Monitor > Logs > Traffic, System and Config: download CSV
#   Dashboard: licence page screenshot
# VyOS, from the controller console (read paths only; never `configure`):
ssh vyos@172.16.0.254 'show configuration commands' > /var/tmp/phylax-inv/network/vyos-config.txt
ssh vyos@172.16.0.254 'show interfaces' > /var/tmp/phylax-inv/network/vyos-interfaces.txt
ssh vyos@172.16.0.254 'show nat source rules' > /var/tmp/phylax-inv/network/vyos-nat.txt
sh /srv/phylax/invitational/m.sh network c8 done
```

Never enter configuration mode on either device.

### 3.7 +1 h and +3 h: the O12 checklist

```sh
# on every capture host
sh /var/tmp/phylax-kit/invitational/c1-capture.sh status
powershell -File C:\ProgramData\phylax-kit\invitational\c1-capture.ps1 -Action status

# controller: Platform page (gaps, last event per module), then mark
sh /srv/phylax/invitational/m.sh o12 ok
# or, when something is wrong:
sh /srv/phylax/invitational/m.sh o12 problem
```

### 3.8 +2 h: log copy

```sh
# on every host
sh /var/tmp/phylax-kit/invitational/c3-logs.sh mid
powershell -File C:\ProgramData\phylax-kit\invitational\c3-logs.ps1 -Label mid

# controller
sh /srv/phylax/invitational/m.sh ubuntu-email c3 mid
```

The second half starts only if the Captain approves:

```sh
sh /srv/phylax/invitational/m.sh second-half approved CAPTAIN
```

### 3.9 Tier B and Tier C (Captain's call)

Tier B, on the canary host `win11-wkst` only. The Platform driver turns safe
mode off for that host in the Operator page after the Captain's verbal callout,
then approves the first-hour plans that name the canary one at a time (the
dead-man stays on):

```text
Operator page > Platform > win11-wkst > safe mode OFF
Operator page > Plans > plans/first-hour > open the plan > Approve
```

```sh
sh /srv/phylax/invitational/m.sh win11-wkst plan NAME approved
```

Tier C: one scored-password change on the one scored user's host and one
hardening pack on one scored server, per design Operations. The host change is
done inside a scorer quiet window; Phylax prints the typed list; the
Credentials role carries it to the Quotient machine and types it there (no
clipboard); the driver verifies with a Kali login and the next scorer round.
Time the PCR typing (O8); the scribe records S13:

```sh
sh scribe.sh pcr 140
sh /srv/phylax/invitational/m.sh pcr typed 140
```

### 3.10 Last 15 minutes

```sh
# on every capture host
sh /var/tmp/phylax-kit/invitational/c1-capture.sh stop
powershell -File C:\ProgramData\phylax-kit\invitational\c1-capture.ps1 -Action stop

# on every host: the end log copy and the second C2 facts run (T70 before/after)
sh /var/tmp/phylax-kit/invitational/c3-logs.sh end
powershell -File C:\ProgramData\phylax-kit\invitational\c3-logs.ps1 -Label end
sh /var/tmp/phylax-kit/invitational/c2-facts.sh
powershell -File C:\ProgramData\phylax-kit\invitational\c2-facts.ps1

# controller: stop serve with Ctrl-C, stop the web server, archive the data dir
jobs -l                    # find the http.server job
kill PID
tar czf /var/tmp/phylax-inv/controller-data-$(date -u +%Y%m%dT%H%M%SZ).tar.gz -C /var/lib phylax
sh /srv/phylax/invitational/m.sh event end
```

## 4. Exports

Collector output lives under `$INV_ROOT` (`/var/tmp/phylax-inv` on Linux,
`C:\ProgramData\phylax-inv` on Windows), except the outside scribe's files.
Upload by hand in quiet moments, from the controller's browser where possible.
Scored-port pcaps go first.

| Collector | File pattern | Where | Size order | Nextcloud folder |
| --- | --- | --- | --- | --- |
| C1 | `pcap/<host>-scored.pcap*`, then `pcap/<host>-other.pcap*` | `$INV_ROOT/pcap/` on each capture host and VyOS | 2-10 GB; scored first | `C1-pcap` |
| C2 | `<host>-c2-<stamp>.tar.gz` (Linux), `<host>-c2-<stamp>.zip` (Windows) | `$INV_ROOT/` on the host | 5-50 MB | `C2-facts` |
| C2 sampler | `sampler.csv` | `$INV_ROOT/` on the host | under 1 MB | `C2-facts` |
| C3 | `<host>-c3-mid-<stamp>.tar.gz`, `<host>-c3-end-<stamp>.tar.gz` (Windows: `.zip`) | `$INV_ROOT/` on the host | 20-200 MB Linux, 50-500 MB Windows | `C3-logs`; Windows Security exports in `C3-private` |
| C4 | `<host>-c4-<stamp>-SENSITIVE.zip` | `$INV_ROOT/` on `ad` | 5-50 MB | `C4-private` only |
| C5 | `<host>-c5-<stamp>.tar.gz` (Windows: `.zip`) | `$INV_ROOT/` on the host | under 5 MB | `C5-probe` |
| C6 | `timeline.txt` | `/var/tmp/phylax-inv/` on the controller | under 1 MB | `C6-timeline` |
| C7 | `scribe.csv`, `pcr.txt`, `credlists-*.json`, screenshots | outside machine | 20-100 MB | upload from the outside machine into `C7-scribe` |
| C8 | `network/*` | `/var/tmp/phylax-inv/network/` on the controller | 5-100 MB | `C8-network` |
| C0 | `controller-data-<stamp>.tar.gz` | `/var/tmp/phylax-inv/` on the controller | 0.2-2 GB | `C0-store` |

The `SENSITIVE` archive (C4) and the Windows Security event logs (C3 on `ad`,
`mssql` and `win11-wkst`) go to the private folder only. Scribe files upload
from the outside machine.

## 5. Fallbacks

- **The agent fails to enroll on a host:** continue with C1, C2 and C3 only;
  they need nothing from Phylax. Keep the console transcript and mark
  `HOST agent failed`.
- **An enrollment alert fires** (`enroll.hash_mismatch`, `enroll.no_show`,
  `enroll.refused`): stop enrolling, read the detail on the controller console
  and on the Operator page's alert queue, then decide.
- **Defender or an AV blocks a script:** record the time and the exact message
  (O4) with `sh /srv/phylax/invitational/m.sh o4 blocked HOST MESSAGE`. Do not
  add an exclusion unless the Captain approves it.
- **No Nextcloud:** keep everything on the controller disk under
  `/var/tmp/phylax-inv/`; pull it out later.
- **A Windows console cannot type the kit lines:** copy `invitational/` from
  the injected media to `C:\ProgramData\phylax-kit\invitational` and run the
  `powershell` lines.

## 6. Not done at the event

So nobody improvises:

- no firewall change on a host or a device;
- decoys stay as configured (LAN only);
- no hardening except the Tier B/Tier C items above;
- no reboot, no service restart, no config edit, no extra account, no read of
  a password store.
