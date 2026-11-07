# Phylax at the Invitational: user guide

A short guide for the 2026-11-07 Invitational. The full step-by-step, with every
collector and who types what, is [impl/invitational-runbook.md](impl/invitational-runbook.md);
the lab results behind this guide are in [impl/w2-rehearsal.md](impl/w2-rehearsal.md).

## What Phylax does tomorrow

- One controller (`phylax serve`) on `ubuntu-wkst`. Every other host runs the agent,
  which streams events (processes, logins, connections, file changes, Windows event
  logs) to the controller over TLS on port 7443.
- **Observe only.** Hosts enroll with safe mode on, and every module's act switch is
  off, so Phylax changes nothing on a host. The one exception is the decoy listeners on
  the hosts with the `decoys` role (fake RDP, WinRM, Redis and similar ports, LAN only).
- The controller writes a comms sample every 10 s to `/var/lib/phylax/bench.jsonl`.
  That file is the comms benchmark; nothing has to be started for it.
- The kit scripts (C1 pcaps, C2 host facts, C3 log copies, C4 AD dump, C5 probe) run
  without Phylax. If the agent fails somewhere, keep collecting with them.

## The kit

Built from `v4` (commit in `BUILT_FROM`) in `~/src/ccdc/invitational-kit/` on the dev VM:

| File | What |
| --- | --- |
| `kit.zip` | the `kit/` folder: `phylax`, `phylax.exe`, `rules/`, `plans/`, `obs/` (the observe manifest), `tools/invitational/`, `cfg.json` |
| `kit.tgz` | only the scripts (`invitational/`), which each host fetches |

Before uploading to Nextcloud, check against the packet:
1. `kit/cfg.json`: set `"team"` to the team number (1 to 99).
2. `kit/obs/hosts.yml`: host names and IPs must match the packet. The controller
   address used below (`172.20.240.5`) is `ubuntu-wkst`'s; change it everywhere if the
   packet differs. Lint after any edit: `./phylax manifest lint -dir obs` (expect 0 errors).

## 1. Start the controller (ubuntu-wkst, as root)

```sh
mkdir -p /srv/phylax && unzip -o ~/Downloads/kit.zip -d /tmp
cp -r /tmp/kit/. /srv/phylax/ && cp ~/Downloads/kit.tgz /srv/phylax/
cd /srv/phylax && tar xzf kit.tgz
mkdir -p web && cp phylax phylax.exe kit.tgz web/ && cp invitational/e.sh web/e
python3 -m http.server 8000 --directory web &
./phylax serve -config cfg.json -bundles web -advertise 172.20.240.5:7443 \
    -bundle-safe -bundle-ttl 8h -served-dir /srv/phylax/web -enroll-window 30m
```

- The first start prints `user: admin` and a password **once**. Write it down. The UI
  is `http://127.0.0.1:8080` in the controller's browser.
- Leave the serve console visible. `level=WARN msg=alert kind=enroll.hash_mismatch`,
  `enroll.no_show` or `enroll.refused` means stop enrolling and look.
- Kill the `http.server` job (`jobs -l`, `kill PID`) once every host is enrolled.

## 2. Enroll each host (console, one host at a time)

Enroll from each host's console with the one-liner. Don't use the Enroll page's
**Push** button: in the lab it failed on both OSes with the packet's stock settings
(Linux logins aren't root; Windows WinRM refuses unencrypted sessions).

**Linux.** Become root first (`sudo -i`); the install fails as a normal user.

```sh
curl -s 172.20.240.5:8000/e|sh -s 172.20.240.5:8000 HOST          # kit only
sh /var/tmp/phylax-kit/invitational/c1-capture.sh start
sh /var/tmp/phylax-kit/invitational/c2-facts.sh
sh /var/tmp/phylax-kit/invitational/c2-sampler.sh start
curl -s 172.20.240.5:8000/e|sh -s 172.20.240.5:8000 HOST agent    # enroll
```

**Windows.** An Administrator `cmd`, not PowerShell:

```bat
set PSExecutionPolicyPreference=Bypass
md C:\ProgramData\phylax-kit
curl.exe -s -o C:\ProgramData\phylax-kit\kit.tgz http://172.20.240.5:8000/kit.tgz
tar.exe -xzf C:\ProgramData\phylax-kit\kit.tgz -C C:\ProgramData\phylax-kit
powershell -File C:\ProgramData\phylax-kit\invitational\c1-capture.ps1 -Action start
powershell -File C:\ProgramData\phylax-kit\invitational\c2-facts.ps1
powershell -File C:\ProgramData\phylax-kit\invitational\c2-sampler.ps1 -Action start
powershell -File C:\ProgramData\phylax-kit\invitational\e.ps1 -Ctl 172.20.240.5:8000 -HostName HOST -Agent
```

`HOST` is the host's name in `obs/hosts.yml` (`rocky-ecom`, `ubuntu-email`,
`debian-splunk`, `ad`, `mssql`, `win11-wkst`, `kali`). Enrollment takes about 10 s
on Linux and about 45 s on Windows (most of it is downloading the 28 MB `phylax.exe`).
Start the Windows sampler from the console: started over a remote session, it dies
when the session closes.

**Check the clock** on each host (`date -u`, `w32tm /query /status`). The controller
stamps events with the host's clock, so a host that is minutes off has a wrong timeline
and makes the comms latency numbers unreadable. If you won't fix it, record the offset:
`sh /srv/phylax/invitational/m.sh HOST clock +90s`.

## 3. Using the UI

| Page | Use it for |
| --- | --- |
| **Agents** | Every host should be listed as connected with safe mode on. A host's own page shows its modules and the per-host safe-mode switch. |
| **Alerts** | What the rules fired. Open one for the events behind it; **Acknowledge** when someone owns it, **Close** when done. |
| **Health** | Module health per host; check it after enrolling and at +1 h and +3 h. |
| **Dashboard** | Live overview: event rates and recent alerts. |
| **Audit** | Every operator action. |
| **Checks** | Read-only check results (rounds can't be started from here yet). |

Plans, Proposals, Chains and Reports have nothing to do in observe mode.

Marks go on the controller console and land in `/var/tmp/phylax-inv/timeline.txt`:
`sh /srv/phylax/invitational/m.sh TEXT...` (no arguments prints the last five).
Mark anything you'll want to line up with the data later: enrollments, red-team
activity you notice, service outages.

## 4. Known noise and limits

Expected, not a problem:
- `tar: ... time stamp in the future` on every Linux kit line (host clock behind).
- One `integrity.ledger_unavailable` per Linux agent (no ledger is built yet).
- A Windows pcap (`.etl`) stays 0 bytes for a long time: pktmon writes when its buffer
  fills or on stop.
- `enroll.hash_mismatch` for Windows hosts if `phylax.exe` is replaced and `serve`
  restarted mid-event.
- Non-zero rows in a C2 `_index.tsv` for paths or tools a host doesn't have (Sysmon,
  web roots and so on).

Seen in the lab, not yet explained:
- The ecom host raised 72 `D6i.pam-change` alerts and its agent ran at about 27% CPU.
  Watch that host's agent CPU (`top -p $(pgrep -d, phylax)`); the unit caps it at
  50% CPU and 256 MB.
- On the DC, some accounts' `LastLogon` and `PasswordLastSet` changed during the
  rehearsal. Phylax doesn't set passwords, and the lab's own WinRM logons are the
  likely cause, but compare the two C4/C2 runs on `ad` afterwards.

Not working yet (don't plan on them):
- Push enrollment from the Enroll page.
- The Plans page: it doesn't list `plans/first-hour`, so the runbook's Tier B steps
  can't run as written.
- `pcr.generate` (the runbook's Tier C typed list).
- Starting check rounds from the Checks page.

## 5. If something goes wrong

- **Agent won't enroll:** keep that host on C1, C2 and C3 only, and mark
  `HOST agent failed` with the error.
- **An agent misbehaves** (CPU, a service problem you suspect it caused): stop it.
  Linux `systemctl stop phylax`; Windows `sc stop phylax`. Mark it. `phylax agent
  uninstall` (run from `/opt/phylax` or `C:\ProgramData\phylax-bin`) removes the service.
- **Controller dies:** start the same `serve` line again. Agents spool events and resend
  them when it comes back; the gap shows in the bench report.
- **Defender blocks a script:** mark `o4 blocked HOST MESSAGE`; no exclusions unless
  the Captain says so.

## 6. End of the event

1. Stop C1 on every host and run the second C2 facts (runbook section 3.10).
2. Stop `serve` with Ctrl-C.
3. Read the comms result on the controller:

   ```sh
   ./phylax bench report /var/lib/phylax/bench.jsonl
   ```

   It prints agent round-trip time, event throughput by priority, reconnects, gaps,
   spool depth and controller CPU and memory. `-check` also grades it against the
   transport criteria; it reports a failed `partition_marks` item because no partition
   test is run at the event, so read the other rows.
4. Archive the data dir and the timeline:

   ```sh
   tar czf /var/tmp/phylax-inv/controller-data-$(date -u +%Y%m%dT%H%M%SZ).tar.gz -C /var/lib phylax
   sh /srv/phylax/invitational/m.sh event end
   ```

5. Upload per runbook section 4. C4's `SENSITIVE` archive and the Windows Security
   logs go to the private folder only.
