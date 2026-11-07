# W2 rehearsal results (Task 15), 2026-11-06

Status: **blocked at Step 1, no guest login.** Steps 1 to 5 were not run.

## What was checked

- `make build build-windows` in the worktree: OK. `tools/invitational/test.sh`: all PASS.
  `make-observe-manifest.sh manifest/2027` then `phylax manifest lint`: 0 errors, 0 warnings.
- ccdc26 on prox2: VMs 26010 to 26018 and 26021 running, 26019 off. Test box (26001) up with
  172.20.240.240 and 172.20.242.240; `ip_forward` is 0 there.
- Addresses (nmap from the test box, same as the 2026 packet): ubuntu-ecom 172.20.242.30,
  fedora-webmail .40, splunk .20, palo 242.150 (ubuntu-wkst 26013 did not answer, DHCP);
  AD 172.20.240.102, web .101, ftp .104, win11 .100, Palo2 .200. Cisco side routes: yes, those
  hosts answer ping from the test box (it is on that segment; routing through Palo2 was not tested).
- The QEMU guest agent is not running in any guest (`qm guest cmd` fails), so no IPs from prox2.
- The Proxmox console path works: `qm monitor <id>` `sendkey` and `screendump` from prox2. Typing
  a login (a 8-char word) took about 1.3 s through `sendkey`. The console login prompt takes 5 to
  10 s to show the Password prompt after the user name, so typed text must wait for it.

## Blocker

The packet default `sysadmin` / `changeme` is rejected on the console of ubuntu-ecom (26010) and
fedora-webmail (26011), with correct timing (screenshots confirm the prompts). Other 242.x SSH
ports (.30, .40, .20) accept any password from the test box and run no real commands (every
command returns "command not found" or is echoed back; the banner says Ubuntu 22.04 while the
consoles show Ubuntu 24.04 and Fedora 42): something other than the guests' sshd answers there, so
SSH is no way in. No credentials for the ccdc26 images exist in ccdc-private or btap-infra. I did
not guess further or reset passwords through grub or the Windows recovery path.

## Needed from David

The ccdc26 guest credentials (or approval to reset them from the console after the
`pre-phylax-rehearsal` snapshot), then rerun Task 15.

## Not run

Steps 1 to 5 (typing times, Windows scripts, T70, the Step 4 checks, resource numbers).
No guest was changed and no snapshot was taken.
