#### The order step by step

Each step names who does it, what Phylax shows, and what must be true before the next step. The order is the point; there are no minute targets (decision 9). Latencies are measured and reported in dry runs, not promised. Role names are those in the Roles section. At the Invitational the same order runs under observe mode, with the tiers listed in the next section; this table is the full-run version. The whole order uses the host x step grid as its checklist: steps the platform can read tick themselves, manual steps need a named owner tick, and a step the platform sees as not done stays amber even if someone ticked it (review N11.4, N11.6).

| Step | Who | What happens | Done when |
| --- | --- | --- | --- |
| 0. Before drop flag | Platform driver, Captain | The controller host is ready; the T+0 sheet (rendered from the manifest and printed) is in hand with the new admin and service credentials, the release signing key to verify against, and the Palo rule text. The team number is entered in overrides. Runtime facts from the pre-qualifier access week are in overrides (see that section below). | Sheet printed; manifest loads |
| 1. T+0 console phase | Linux lead, Windows and AD lead, Network, all at consoles | Admin and service credentials rotated by hand on every host: `sysadmin`, root and local Administrator, domain admins and service accounts, the Palo `admin` and VyOS `vyos` accounts. **Zerologon first on the DC** if the build is unpatched (build check, secure channel enforcement, Spooler off, SMBv1 off), before any domain rotation. Palo management lockdown (additive), the Kali-to-controller rule and static NAT. VyOS snapshot first, then admin rotation. Scored users are not touched. Quotient is not reachable from inside, so nothing is read from it. | Each host's T+0 cells on the grid ticked by the person who did them, with their name |
| 2. Start Phylax | Platform driver | `phylax init` fetches and verifies the release, sets the passphrase, starts the UI and the cache sync. The rotated values are entered in the vault. | UI up; vault unlocked |
| 3. First contact | Platform driver; Windows lead for console one-liners | SSH push on Linux hosts, WinRM on the AD and MSSQL hosts, the console one-liner on Windows 11 and the Kali. | Every host enrolled; the grid's `enrolled` column green |
| 4. Session eviction | Automatic, driver approves | For each account rotated at T+0, sessions that began before the rotation are evicted. Admin and service accounts: plain eviction. Scored accounts: flag-only until a round delay is measured, then only sessions older than the measured delay and not scorer-labelled. | Eviction cells green |
| 5. Automatic starts | Automatic | As-found backups; `capture`, round-clock estimation, check discovery and scorer-account learning; source-address check against the Palo; ledger sweep and prebake hunt; the `inventory` baseline. | Each module's tile shows data |
| 6. Review queues | SOC, Linux lead, Windows lead | Hunt and ledger queues triaged; findings go to remediation plans or accepted records. DC checks confirmed: Zerologon patched, DCSync rule active. | Queues empty or each item has an owner |
| 7. Firewall plans | Platform driver, Network | Host firewalls in shadow mode, review of would-be drops, enforce, with scorer-mimic checks. Palo policy with the Kali verifying. Scored ports stay allow-any-source. | `firewall applied` green on every host |
| 8. Hardening packs | Platform driver | The first-hour library and the baseline packs with probes. A golden backup is taken as each service passes. | `hardened` and `backed up` green |
| 9. Deception | Floater | Decoys and honeytokens deployed, including honey AD accounts. | Deception tile shows all planned |
| 10. Integrations | Driver, inject writer | If enabled: Wazuh deploy; review of discovered checks (accept, edit, reject). | Health green |
| 11. Steady state | All | Incidents and chains; IR drafts (one per narrative or persistence mechanism); inject artifacts from the generators; patch windows; periodic backups; drift adoption; work windows and the feed; scored-password changes only on evidence (procedure below). | Ongoing |

**Scored-password changes** happen only on evidence of compromise or leak (decision 5). The Credentials role and the driver do it together, one service at a time: verbal callout; the host change inside a scorer quiet window; Phylax prints a short typed list of (credlist, user, new password); the Credentials role carries it to the Quotient machine outside the environment and types it in (there is no clipboard); the driver verifies by a login from the Kali and the scorer's next round; on failure the old value goes back by a second typed list. Phylax never submits a PCR. After any revert, the `creds` module marks each affected (account, credlist) as needing a re-sync and blocks further scored changes on that host until it is resolved.

#### Before lunch and day 2

Red razes boxes in the lunch window and on day 2 [[how-to-win-ccdc-dealing-with-red-team#e3]] (for example by deleting `fstab` and rebooting). Before lunch and again before day 2:

- take fresh golden backups of every scored service and a fresh **boot** set for every host, off the host and on the controller (the `backup` module; review D502);
- confirm the controller's state snapshot is fresh and copied to the backup targets;
- confirm the Linux and Windows leads know where the typed boot-file listing for their hosts is.

Day 2 start also includes: the Platform page for every agent's link, gaps and modules; overnight changes and chains; a device drift check; health checks re-run; the grid re-read for amber cells that were green yesterday.

#### Human factors

- **Live checklists, not paper.** The host x step grid replaces the printed per-role checklists; a print view of it is the fallback if the screen is unavailable (review D503).
- **Verbal callouts.** Before any tier-2 action, before turning safe mode on or off, and before each scored-password change (the host change and the typed list that follows). The approver's name is recorded with the approval whoever clicks, including a captain who is off the keyboard (core: Plan, approve, apply; review D504).
- **The Captain** keeps the list of open incidents and the injects due soon. Injects are not tracked in Phylax; that list lives outside it.
- **SOC seat rotation** every 90 minutes (review D505). The outgoing person presses "Hand over" on the Overview, which records the time and their name in the audit log and opens a free-text box for what the next person must know (injects due, anything pending that Phylax cannot see). The incoming person opens the **"since you left" digest**: everything since the last hand-over, listed newest first: plan completions and failures, drift adoptions, open work windows and feed entries, new and changed incidents, approvals waiting, safe-mode changes, modules or agents that degraded, and the outgoing person's notes. It is a read-only page built from the store; it adds nothing to the data model. `shortcut: one shared login, so hand-over is a button and a typed name, upgrade to per-person accounts only if the audit log is not enough`.
- **Role gaps are visible.** An unstaffed role shows on the Overview, with its pending manual steps (Roles section).

#### The order in one paragraph
