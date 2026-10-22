# phylax

Purdue's CCDC blue-team platform: one Go binary that runs as the controller
(`phylax serve`) or as the host agent (`phylax agent`) on Linux and Windows.

The design is [phylax_design.md](phylax_design.md) (v3, a from-scratch rewrite;
v2 is kept at [docs/phylax_design.v2-2026-10-17.md](docs/phylax_design.v2-2026-10-17.md)).
The earlier implementation is preserved on the `main` and `qwen-wip` branches and is
not used.

## Build

Go 1.27 (via mise). No cgo; the binaries are static.

```sh
make build            # bin/phylax (linux/amd64)
make build-windows    # bin/phylax-windows-amd64.exe
make test             # go test ./...
make race             # go test -race ./...
make vet              # go vet for linux and windows
```
