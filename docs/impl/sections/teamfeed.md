#### `teamfeed`

##### Purpose and evidence

`teamfeed` gives the team two commands that any person at any enrolled host's console can run: `phylax say "<text>"` posts a short note to a shared feed, and `phylax claim <host>` opens a tagged work window for hand changes. Both ride the agent's existing link. That is all it does (review N11.1; A11.Q3: "build `claim` and `say` only; they're thin wrappers over the existing control channel").

Evidence that it matters for points:

- **Hand changes cause outages and nobody knows why.** "Red team took our services down" when a teammate had rebooted the box [[how-to-win-ccdc-scoring#e3]]; at 2022WC the ecom was down and the cause was never recorded. Strategy §6.4 requires a manual change log.
- **Hand changes are certain.** Business tasks add or change services during injects [PKT Business tasks]; drift detection will see them. A claim turns an unexplained hand change into a tagged, explained one.
- **Our own tier-0 responses would fight a person.** A teammate rebuilding the firewall by hand is what a firewall-restoring response is built to undo. A work window tells the host not to.
- **No new network exposure.** The commands use the link the agent already has.

There is no peer evidence for this module; it comes from our own loss records. It starts off, and the reference manifest enables it. It is a cut candidate at the next review if the Invitational and the dry runs show nobody uses it.

##### Status and code

Status: **missing**. Existing pieces it relies on: the signed `control` channel (`internal/agent/handlers.go`, `internal/controller`), the envelope `Tag` field (core, described under Tagging and adoption), `detect`'s `exempt_tagged`, and `content_guard`'s `ignored_tag`.

To build: the `phylax say` and `phylax claim` subcommands in `cmd/phylax`; the agent module with a local endpoint; the controller module with window state; the feed page and Overview tile.

##### Capability manifest

| Field | Value |
| --- | --- |
| Name | `teamfeed` |
| Sides | agent (CLI endpoint, window tagging) and controller (feed, window state) |
| OS | both |
| Privilege | root (agent): the local endpoint is reachable by root or Administrators only |
| Roles | any host; the controller host too |
| Consumes | agent: none from the bus. Controller: `teamfeed.say`, `teamfeed.claim`, `agent.silent` (to close windows on a host that went away) |
| Emits | `teamfeed.say`, `teamfeed.claim`, `teamfeed.window` |
| Budget (agent) | CPU 1 ms/s, held 2 MB, 0.1 events/s, burst 5, bytes out 1 KB/min, disk 1 MB |
| Budget (controller) | CPU 1 ms/s, held 4 MB, disk 5 MB |
| Default | opt-in (the reference manifest enables it) |
| Tables | `teamfeed_windows` (id, host, opened by, opened at, until, ended at, note) |
| Content | none |
| Actions | none. Windows are opened by a signed control message, not by a plan step |
| Pages | `/feed` |
| Evidence | the first part |

##### Configuration

```yaml
# manifest/modules/teamfeed.yml
enabled: true
default_window: 15m        # a claim without --for
max_window: 60m            # the longest a window can be; a longer job re-claims
say_max_chars: 200         # typeable at a console
rate: { say: 6, claim: 3, per: 1m }   # per host
feed_keep: 500             # entries kept on the Feed page; all remain in the event store
```

```go
// package teamfeed (internal/teamfeed)
type Settings struct {
	DefaultWindow time.Duration `json:"default_window"`
	MaxWindow     time.Duration `json:"max_window"`
	SayMaxChars   int           `json:"say_max_chars"`
	Rate          struct {
		Say, Claim int
		Per        time.Duration
	} `json:"rate"`
	FeedKeep int `json:"feed_keep"`
}
```

##### Events

| Kind | Schema | Priority | Key fields |
| --- | --- | --- | --- |
| `teamfeed.say` | 1 | high | `host` (where it was typed), `user` (the local OS account that ran the command), `text` (at most `say_max_chars`) |
| `teamfeed.claim` | 1 | high | `host` (where it was typed), `target` (the host claimed), `user`, `action` (`open` or `end`), `id`, `until`, `note` |
| `teamfeed.window` | 1 | normal | controller-origin: `id`, `target`, `state` (`opened`, `extended`, `ended`, `expired`, `closed_silent`), `by`, `until` |

Priority is high so a note reaches the controller ahead of bulk traffic. `text` and `note` are agent-supplied strings: hostile input, escaped everywhere they are shown, never used to build a command or a query.

##### Behaviour

###### Commands

```text
phylax say "rebooting ecom, 2 min"
phylax claim rocky-ecom                 # default_window
phylax claim rocky-ecom --for 30m "rebuilding php config"
phylax claim --end rocky-ecom
```

The CLI is a thin client. It sends one JSON line to the agent on the same host and prints the result. The endpoint is a Unix domain socket under the agent's state directory on Linux (mode 0600, root) and a named pipe with an Administrators-only DACL on Windows. Only root or Administrators can use it; there is no password and no network listener. `phylax say` and `phylax claim` also work on the controller host, through that host's own agent.

`claim <host>` accepts the name of any manifest host, not only the one the command was typed on, because the person may be working on another machine from this console, or on a device. The named host must exist in the manifest.

###### The feed

Every `say` and every claim open or end becomes an event on the sender's own link and is stored like any other. The Feed page and the Overview tile show them newest first with the sender's host, the OS account, the Central time and the text. Nothing is posted anywhere else. If `notify` is enabled, a `say` is not pushed (the alarm is for alerts); the feed is read on the controller screen.

The feed is the manual change log that strategy §6.4 asks for. The IR drafter lists feed entries inside an incident's time window as "team actions", so a legitimate hand change is not read as attacker activity, and so the containment section can say what the team did.

###### Work windows

A claim opens a **window** on the target host:

1. The controller module records the window (id, target, who, until) and sends a signed `control: work_window{id, until}` to the target host's agent. The agent persists the window until it ends, so a restart does not drop it.
2. While a window is open, the agent stamps `Tag: "win:<id>"` on every event it emits (core: Tagging and adoption). Rules that exempt tagged events, and `content_guard`, then ignore the host's change events for the duration. Tier-0 responses on changes that carry the tag do not fire.
3. The window ends when `claim --end` is typed, when `until` passes, or when the host goes silent (`closed_silent`). It never runs longer than `max_window`. A claim on a host that already has an open window extends it only up to `max_window` from the first opening, and the extension is recorded.
4. An expired window does not retroactively untag anything. Events after expiry carry no tag and are judged normally.

The window covers the whole host, not one session: the agent cannot reliably attribute a process to a person. A claim should therefore be as short as the job.

Drift detection still sees changes made during a window. They are marked "during window <id> by <user>" and offer adopt or revert as usual.

###### A claim from a compromised host

An attacker with root on a host can run `phylax claim` on it, and `phylax claim <other host>` to open windows elsewhere. The module is built so this is bounded and visible, not impossible:

- Every window appears on the Feed page, the Overview tile and the audit log at once, with the typing host and OS account. A window nobody on the team asked for is the signal.
- Windows are short (`default_window`, `max_window`) and rate-limited per host.
- A window opened for a host by an agent other than that host's own needs no approval, but the Overview tile lists "windows opened by another host" separately, and the Platform page shows the count.
- A window exempts what the rules and `content_guard` exempt for any tagged event. It does not stop the integrity ledger from alerting on an unknown binary executed, decoy and honeytoken hits, or telemetry gaps, because those do not depend on the tag. Detection that does ignore tagged events (change classes) is the exposure.

`shortcut: a window tags every event on the host and every rule that exempts tags honours it, upgrade to a window tag that only the change-class rules exempt (detect gains a tag-prefix operator) if a lab run shows the exposure matters`.

###### Edge cases

- Two people claim the same host: the second sees the open window, its owner and time left, and may extend it or wait.
- The target agent is down or disconnected: the claim is recorded and shown as `pending` until the agent connects, then the window opens with its original `until`. If `until` has already passed it is marked expired and never opens.
- Clock differences: the window's `until` is relative to the controller; the agent receives the remaining duration, so a host clock that is wrong does not stretch it.
- `say` text beyond `say_max_chars` is refused with the limit stated.

##### Actions and content

No actions and no content files. Two core touches are required (see Limits): the signed `control: work_window` message, and the agent stamping the active window's tag on emitted events.

##### UI

`/feed`: the entries, open windows with time left, owner and a "who is working where" view; an "end window" button for the platform driver. Overview tile: the last five entries and the open windows. No host-grid column; a small "window open" marker appears on the host's row in the Agents table.

##### Health

- Agent: `ok` when the local endpoint is listening. `degraded` with a gap `endpoint unavailable: <why>` (socket path not creatable, pipe denied).
- Controller: `ok`. `degraded` with `windows opened by another host: N` when that count is above zero for more than one window, as information.

##### Scoring safety

`teamfeed` touches no scored state. A work window only affects what our own detection and responses do; it does not stop or start any service. The local endpoint exposes no action beyond the two commands. The one exposure is the attacker-claim case above.

##### Tests

- Unit: CLI to endpoint round trip on Linux and Windows (the pipe test skips with a clear message off Windows); rate limits; the `say_max_chars` refusal; window lifecycle with a fake clock (open, extend to the cap, end, expire, host silent); persistence across an agent restart; hostile strings (a `text` containing markup and a template action is stored and displayed escaped).
- Event tests: events emitted during a window carry the tag, events after expiry do not.
- Conformance: the shared suite; the endpoint is closed on stop and no goroutine leaks.
- Lab: T56. A claim on a lab host followed by a firewall edit raises no untagged alert and no tier-0 restore; the same edit without a claim does; an expired window re-enables both; a claim from a lab host that holds a planted implant is visible on the Overview tile within one refresh.

##### Limits and open items

- `shortcut: the local endpoint accepts any caller that can open it (root or Administrators), upgrade if a non-root shift user needs to post, by a signed token minted per user`.
- `shortcut: windows are host-wide, not per session, upgrade if the lab shows the exposure matters (see above)`.
- Core changes needed: (1) a signed `control: work_window{id, until}` message beside `safe_mode`, with the protocol minor version bumped; (2) the agent supervisor stamps the active window tag on events (an `Env` hook or a stamp in the emit path). Both are small and generic.
- Open: whether windows should need a second person's confirmation on the controller screen for hosts holding scored services. Not built: it would make `claim` no longer a thin wrapper.
- Complexity register line: `teamfeed` | explains hand changes and keeps our own responses off them | one local socket or pipe, root only, no network listener; windows capped at an hour.
