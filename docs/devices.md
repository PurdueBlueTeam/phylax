# Network device adapters

Package `internal/devices`. The adapter exposes primitives; the controller-side
runner `devices.SafeChange` owns the protocol, so one runner serves every device:

    preflight -> lock -> snapshot -> stage -> pending check -> validate
              -> commit (dead-man where the device has one) -> health callback
              -> confirm | rollback

Specs: ccdc-private `research/topics/device-apis.md`; design section "Network
devices and credentials". Typed change sources: `render.PaloIntent` and
`render.VyOSIntent` (`Adapter.Translate`).

## Interface notes
- `Adapter`: Kind, Caps, Info, Probe (fresh connection), Snapshot, Diff, Drift
  (emits `ConfigEvent`s for D14), Begin, Admins, Events, Close. `RotateAdmin`,
  `Capture` and `Facts` from the research proposal are not built yet.
- `Tx`: Preflight, Lock, Stage, Pending, Validate, Commit, Confirm, Rollback, Close.
  A Tx may also implement `Tainted` (foreign change seen during its window).
- A `lockout` risk change is refused unless the adapter has `SoftDeadman` or
  `NativeConfirm`, or the Network role set `ConsoleAck`. PAN-OS has neither.
- The runner always undoes on a context that ignores cancellation, falls back from
  granular rollback to restoring the snapshot, and bounds the health check to 3/4 of
  the dead-man.

## PAN-OS (`palo`, `palo/xmlapi`)
Own XML API client (form POST, `X-PAN-KEY`, bounded responses, job polls with
deadlines). Never issues a plain commit: only `commit partial admin`. Every object,
service, NAT and rule is tagged `phylax-managed`; Stage refuses to edit or delete an
untagged item. Foreign pending changes (journal entries by another admin, or any
entry when the device names no admin and the path is not ours) refuse the change.
Management lockdown is its own commit, additive (`Translate().Mgmt`), then a
fresh-connection probe; `MgmtRemovals` produces the second, removing commit.
Granular revert replays the prior XML recorded at Stage; the whole-config fallback
loads the `phylax-pre-<id>.xml` saved at Lock. Drift = canonical running-config
hash + config log after the stored `cfgseq` + foreign locks + foreign pending.

## VyOS (`vyos`)
HTTP API for reads (`/show`, `/retrieve`); SSH (x/crypto/ssh, pinned host key, one
new connection per call) for changes. Never `commit-confirm`, `rollback N`, reboot.
Commit: save `pre-<id>.boot` under `/config/archive/phylax`, arm
`systemd-run --on-active=T --unit=phylax-revert sg vyattacfg -c 'vbash ... load pre; commit'`,
plain commit, (lockout class: fresh SSH+HTTPS probe), health, then stop the timer
and `save`. Close deliberately leaves an armed timer so a dead controller is
covered. Commands are restricted to `set|delete` plain words with balanced quotes.
Drift = sorted `show configuration commands` hash, commit-log signatures newer than
the stored one, `/config/config.boot` hash, `compare saved`.

## Tests
`palotest` and `vyostest` are stateful fakes (PAN-OS candidate/running/journal/
lock/jobs/config log/permitted-IP on new connections; VyOS SSH server with a vbash
interpreter, real firing timers, HTTP API). No test contacts a real device.
