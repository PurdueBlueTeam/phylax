# phylax

Implementation of the Phylax blue-team platform per `phylax_design.md`: one Go
binary in two modes — `phylax serve` (controller) and `phylax agent` (every
host, including relay / device-proxy / check-runner / decoy / capture roles).

Build status is tracked in `MILESTONES.md`; implementation decisions and
skipped-unverifiable items are logged in `QUESTIONS.md`.

## Build

Go 1.27 (managed by mise; see `mise.toml`). No cgo; the linux/amd64 binary is
static.

```sh
make build            # -> bin/phylax
make test             # unit + integration (docker containers where needed)
make gate M=M1        # run one milestone's gate tests
make size             # binary size gate (40 MB, 15 MB compressed)
```

## Commands

- `phylax serve` — controller: event store (SQLite), plans, checks, UI on
  `127.0.0.1`, one inbound agent port (all connection types, ALPN-selected).
- `phylax agent` — host agent from a bootstrap bundle.
- `phylax init` — verify and lay down the release bundle on the controller.
- `phylax set-controller <addr:port>` — repoint an agent (relay hosts first).
- `phylax version`
