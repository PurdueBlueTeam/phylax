# phylax: repo notes for contributors (human and AI)

This branch (`v3`) is a **from-scratch rewrite** to the v3 design in
[phylax_design.md](phylax_design.md). Don't copy code from the `main` or
`qwen-wip` branches; their review is in ccdc-private `strategy/phylax-code-review.md`,
and its findings are design requirements.

## Rules
- Go 1.27.2 (mise). `CGO_ENABLED=0`; linux/amd64 and windows/amd64 must both build
  (`make build build-windows`) and vet (`make vet`) at every commit.
- Every package ships tests; `go test ./...` and `go test -race ./...` pass.
  Tests must exercise the real thing (no mocking away the code under test, no
  tautological asserts). Tests needing privileges or containers are skipped with a
  clear message when unavailable, never silently passing.
- No shelling out in the default path (design principle "Go-native"); `host.exec`
  is the only explicit escape hatch.
- Bounded everything: queues, buffers, decompression, timeouts and deadlines.
- Crash-safety: writes to critical files are atomic (temp file + fsync + rename),
  preserving owner, mode and SELinux label.
- Keep the design doc authoritative: if implementation forces a design change,
  update phylax_design.md in the same commit and say why.

## Gotchas
- Go's `tls.NewListener` defers the handshake: call `HandshakeContext` before
  reading `ConnectionState().NegotiatedProtocol` (ALPN), and do it off the accept
  loop with a deadline.
