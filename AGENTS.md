# phylax — repo notes

Go 1.27.2 via mise (see mise.toml). Tests: `go test ./...` (integration tests
live in internal/controller and run real multi-process TLS scenarios on
loopback).

## Gotchas

- **Go 1.27 `tls.NewListener` defers the handshake.** `Accept()` returns as
  soon as the TCP connection is established; `ConnectionState().NegotiatedProtocol`
  is empty until you call `Handshake()`/`HandshakeContext()` (or do I/O).
  `controller.Run` completes the handshake explicitly before ALPN dispatch —
  keep it that way.
- **`net/http.Server.Serve` returns once its listener is exhausted** (our
  bootstrap uses a one-connection listener): the connection stays owned by the
  server's goroutine. Never `defer conn.Close()` around it; use IdleTimeout to
  bound keep-alive.
- The controller listener is a single TLS listener with ALPN dispatch:
  `phylax/agent`, `phylax/relay`, `phylax/splice`, `phylax/patch`, and
  no-ALPN = plain HTTPS bootstrap/console.
