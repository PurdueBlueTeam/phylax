#### One controller screen

The UI is bound to localhost on the controller host and has one login. Whoever can see that VM's console can drive the platform; everyone else works on other consoles by hand. If NETLAB lets several people view one VM console, the whole team can watch one screen; if not, one person (the platform driver) owns the UI. Whether several people can view one console is unknown until the Invitational (observe item O2). There is no SSH tunnel, no remote access and no second viewer (review A11.Q1, D494); the cost is human bandwidth, and the answers to it are the pre-built plans, the role-merge map below, `phylax say` and `claim`, the `notify` alarm and webhook, and the "since you left" digest. If dry runs show the driver becoming the bottleneck, the response is a role change, not new access.

#### Nine roles

| Role | Owns |
| --- | --- |
| Captain | Inject triage (outside Phylax), White Team communication, tier-2 approvals (the approver's name is recorded) |
| Platform driver | The UI on the controller: plans, approvals, safe mode, re-enrollment, evidence runs |
| Network | Palo and VyOS consoles during the T+0 phase, the Kali path rules, then device plans and drift |
| Linux lead | Linux console work and break-glass; reviews Linux hunt findings |
| Windows and AD lead | Windows console work and break-glass (including the Windows 11 and Kali one-liners); reviews Windows, AD and ledger findings |
| Credentials | The scored-password procedure: reads the typed list Phylax prints, carries it to the Quotient machine outside the environment and types it in (no clipboard), reports back; works with the driver on quiet windows. Does not rotate admin credentials; that is the T+0 console phase |
| SOC | Alert queue, chains and incidents with the driver; IR drafts; takes the SOC seat in rotation |
| Inject writer | Generated artifacts, evidence runs, the memo shell, validation, and carrying files to the team Nextcloud by hand |
| Floater | Health checks, backups and restores, decoy hits, work windows, whatever is red |

Each role's steps on the host x step grid carry the role name. A manual step needs a tick by a named person; a step whose role is unstaffed shows with the role marked "unstaffed" until someone takes it.

#### Role-merge map

Teams field four to eight players, and 2026 regional had eight. Merges pair a role that is busy early with one that is busy late, and never put two roles that need the controller screen at the same moment on one person.

| Players | Assignment |
| --- | --- |
| 8 | Captain; Platform driver; Network and Floater; Linux lead; Windows and AD lead; Credentials; SOC; Inject writer |
| 6 | Captain and Credentials; Platform driver and Floater; Network and SOC; Linux lead; Windows and AD lead; Inject writer |
| 4 | Captain, Inject writer and Credentials; Platform driver, SOC and Floater; Linux lead and Network; Windows and AD lead |

Reasons for the pairs:

- **Network and Floater, Network and SOC:** Network is busy in the T+0 phase and at the device plans, and mostly idle after; the floater and SOC roles are steady and start when the early rush is over.
- **Captain and Credentials:** scored passwords change only on evidence, so Credentials is the lightest role, and the Captain already makes the verbal callout and holds the approval.
- **Platform driver and Floater or SOC:** the driver is already at the controller screen, where backups, restores and alerts are shown.
- **Linux lead and Network (four players):** VyOS is a Linux-style CLI and the Palo work is a few rules after T+0; the Windows and AD lead keeps the DC, which cannot be shared.
- **Windows and AD lead is never merged** with anything: the DC, Zerologon, the Windows consoles and the hardest hunt queue are one person's full load.

The map is a default. The team can enter its actual assignment in Settings (`overrides.yml` `roles: {captain: [name], ...}`), which is a runtime fact, because the people are known only at the event.

#### Unstaffed roles on the Overview

The Overview shows each role with its assigned names. A role with no name shows as **unstaffed**, with the manual steps and queues it would own that are still open: for example "Credentials: unstaffed, 0 pending", "Windows and AD lead: unstaffed, 3 T+0 steps open", "SOC: unstaffed, 4 alerts unacknowledged for more than 10 minutes". This is how a team that arrives short sees, in one glance, which duties nobody holds (review D495; [[discord-2026q-lessons#e2]], [[discord-2026q-lessons#e8]]). A merged person shows under each role they hold.
