#### `notify`

##### Purpose and evidence

`notify` makes sure an alert is noticed when nobody is looking at the controller screen. The web UI is bound to localhost on the controller's console, so only the people who can see that console see alerts (review A11.Q1: one controller screen, no tunnels). `notify` pushes the important ones out: a **local audible alarm** first, and an optional **webhook** to a chat channel. It sends nothing else and holds no state that matters.

Evidence that it matters for points:

- Teams that ran a chat notifier cite it: the EKU Slack notifier [[malfindor-eku-ccdc]] (`scripts/linux/slack/send.sh`), the CyberHawks Discord alerts [[cyberhawks-iit-wazuh#e1]] (`defense-tooling/docs/discord-alerting.md`), BigDaddySkySky `common_notify`. The pattern is cheap and it helps with the one-screen problem (review N11.3, competitors #5).
- The webhook payload follows the peers: one row per alert with the rule title, a severity colour and the host.
- No peer team uses an audible alarm. The local alarm is our own idea and is built first; it is the part that does not depend on any outside service. Whether sound reaches people at all depends on the console (see Limits).

It is opt-in and the reference manifest enables it.

##### Status and code

Status: **missing**. There is no code. It consumes `detect.alert` from the existing alert queue and registers a control on the Settings page.

##### Capability manifest

| Field | Value |
| --- | --- |
| Name | `notify` |
| Sides | controller |
| OS | both (controller side) |
| Privilege | none |
| Roles | `controller` |
| Consumes | `detect.alert`, `agent.silent`, `agent.deadman_fired` |
| Emits | `notify.sent`, `notify.failed` |
| Budget | CPU 1 ms/s, held 2 MB (the bounded send queue), 0.2 events/s, burst 10, bytes out 2 KB/min, disk 0 |
| Default | opt-in (the reference manifest enables it) |
| Tables | none |
| Content | none |
| Actions | none |
| Pages | `/notify` (test buttons and status) |
| Evidence | the first part |

##### Configuration

```yaml
# manifest/modules/notify.yml
enabled: true
alarm:
  min_severity: high            # high and critical alerts ring; below that, silent
  repeat_critical: 10s          # a critical alert repeats until acknowledged
  snooze_max: 5m                # the longest a person can mute the sound
webhook:
  enabled: false
  kind: generic                 # generic | slack | discord (payload shape only)
  secret: notify.webhook        # vault secret holding the URL; never in this file
  min_severity: high
  dedupe: 60s                   # same rule and host inside this window sends once
  timeout: 5s
  attempts: 3                   # then dropped, counted in health
  queue: 100                    # a full queue drops the oldest
# The controller's own egress must allow the webhook host. Declare it in hosts.yml for the controller host:
#   outbound: [{ to: hooks.example.org, ports: [443] }]
```

```go
// package notify (internal/notify)
type Settings struct {
	Alarm struct {
		MinSeverity    string        `json:"min_severity"`
		RepeatCritical time.Duration `json:"repeat_critical"`
		SnoozeMax      time.Duration `json:"snooze_max"`
	} `json:"alarm"`
	Webhook struct {
		Enabled     bool          `json:"enabled"`
		Kind        string        `json:"kind"`
		Secret      string        `json:"secret"`
		MinSeverity string        `json:"min_severity"`
		Dedupe      time.Duration `json:"dedupe"`
		Timeout     time.Duration `json:"timeout"`
		Attempts    int           `json:"attempts"`
		Queue       int           `json:"queue"`
	} `json:"webhook"`
}
```

The webhook URL is read through `Host.Secrets("notify.webhook")`, the only secret the module may read. The egress allowance is a manifest entry that renders into the controller host's firewall and a Palo rule if one is needed; the module cannot add it itself.

##### Events

Consumed: `detect.alert` (severity from the alert), `agent.silent` (a host stopped sending heartbeats), `agent.deadman_fired` (a dead-man rolled something back).

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `notify.sent` | 1 | bulk | `channel` (`alarm`, `webhook`), `alert` (event reference), `severity`, `ok` |
| `notify.failed` | 1 | normal | `channel`, `alert`, `reason`, `attempts` |

##### Behaviour

###### The local alarm

The controller's UI is a web page on the controller's own browser, so the alarm runs there:

- **Sound.** The page plays a short embedded tone when a qualifying alert arrives in the queue, using the htmx poll that already refreshes the dashboard. Browsers block sound until a person interacts with the page, so the Overview carries an "Arm sound" button; one click per browser session arms it. Until armed, the Overview shows "alarm not armed".
- **Critical alerts repeat** every `repeat_critical` until someone acknowledges the alert in the queue. High alerts sound once.
- **Visual part, always on.** A qualifying alert also sets a coloured banner across the top of every page and puts the count in the page title. This works with no sound and no armed button.
- **Snooze.** A person can mute the sound for up to `snooze_max` from the Overview. Snoozing is written to the audit log with the person's name, and the banner stays.
- **Rate cap.** At most 6 chimes a minute; beyond that the sound is one continuous low alarm until the queue is acknowledged. A flood of alerts must not make the screen unusable.

Which alerts: `detect.alert` at or above `alarm.min_severity` (critical for honeytoken and decoy hits and for DCSync, high for most tier-1 rules), plus `agent.silent` and `agent.deadman_fired`, which are always alarm-worthy because they mean a host stopped reporting or a change was undone.

###### The webhook

When enabled, a qualifying alert makes one HTTPS POST. The payload carries only **the rule title, the severity (as a colour) and the host name**. It never contains commands, paths, IP addresses, usernames, hashes or evidence, because the receiving service is outside the environment and its channel may be read by more people than the team. Titles come from our rules and host names from the manifest, so no attacker-controlled string reaches the chat service.

- `generic`: `{"title": "...", "severity": "high", "host": "rocky-ecom"}`.
- `slack`: one attachment with the colour and one line of text.
- `discord`: one embed with the colour and one line.
- Duplicates (same rule and host) inside `dedupe` send once, with "x N" in the title for the repeats.
- A send times out after `timeout`, is retried up to `attempts` times 2 s apart, and is then dropped and counted. The queue is bounded; a full queue drops the oldest. A failing webhook never blocks the alarm or anything else.
- The URL is a vault secret and is never logged, shown in the UI after it is saved, or put in an event.

###### Interaction with other modules

`notify` only reads the alert stream. It does not acknowledge, close or create alerts; acknowledging an alert in the queue is what stops a repeating alarm. In Invitational observe mode it behaves the same (alerts are alert-only there, which is the case it is built for).

##### Actions and content

None.

##### UI

`/notify`: status (alarm armed or not, webhook last result, queue depth, drops), "Test alarm" and "Test webhook" buttons (CSRF, audited), and the snooze control. Overview tile: alarm armed, webhook ok. No host-grid column.

##### Health

- `ok`: alarm armed in at least one session (or the banner alone is accepted) and the webhook, if enabled, succeeded recently.
- `degraded` with gaps: `no session has armed the sound` (a quiet console shows only the banner); `webhook failing: <reason>` after three consecutive failures; `webhook queue dropped N`; `webhook enabled but no egress allowance` (the first send fails to connect).
- `disabled` when `enabled: false`.

##### Scoring safety

`notify` touches no scored state and sends nothing from a host. The webhook is the controller's only outbound connection of its own, and the egress entry it needs is for a non-scored destination on port 443; the manifest lint treats it like any other declared dependency and it never touches a scored port. The payload is three fields, so the worst leak is a rule title and a host name.

##### Tests

- Unit: severity filter; dedupe window; payload contains exactly the three fields for each `kind` (a test fails if a field is added); retry bound and drop behaviour against a local test server; queue overflow drops the oldest; the URL never appears in logs or events; hostile strings in a host name are escaped in the Slack and Discord shapes.
- UI tests: the Arm button state, the banner for a critical alert, the repeat until acknowledged, the snooze cap and its audit entry.
- Conformance: the shared suite.
- Lab: T57. A critical alert sounds and repeats until acknowledged; a webhook to a lab receiver gets one payload; the receiver is blocked and the module degrades without delaying the alarm. At the Invitational, check whether the NETLAB console carries audio at all (observe item O2 in `docs/impl/invitational-data.md`).

##### Limits and open items

- `shortcut: the alarm plays in the controller's own browser, so it needs the page open and armed, upgrade to a host-level beep from the controller process if the console proves to carry audio and the page cannot be kept open`.
- `shortcut: the webhook sends only title, severity and host, upgrade to include a link or an alert id only if the channel is private and the team asks`.
- Open: whether sound from the controller VM reaches anyone. NETLAB consoles may not carry audio. If not, the banner and page title are the alarm, and the webhook is the only way to reach a person away from the screen.
- Open: which chat service the team uses at the event, and whether the controller can reach it (the internet is slow and never a dependency).
- Complexity register line: `notify` | alerts reach people who are not at the one screen | one outbound HTTPS call to a declared host, three-field payload; the sound is a page feature, no new listener.
