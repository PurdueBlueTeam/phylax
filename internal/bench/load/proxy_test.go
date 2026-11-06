package load

import "testing"

// Task 13's proxy tests; the proxy is implemented in Task 13.

func TestProxyForwards(t *testing.T) {
	t.Skip("unimplemented: W14 Task 13")
	// echo server; dial proxy; write "ping"; read "ping"
}

func TestProxyCutClosesAndRefuses(t *testing.T) {
	t.Skip("unimplemented: W14 Task 13")
	// two open conns through the proxy; p.Cut(); both reads return an error/EOF within 1 s;
	// a new dial succeeds at TCP level but its read returns EOF within 1 s (refused after accept);
	// p.Restore(); a new dial echoes again.
}

func TestProxyMaxConns(t *testing.T) {
	t.Skip("unimplemented: W14 Task 13")
	// maxConns 2: the third connection reads EOF; after closing one, a new one works
}

func TestProxyCloseWaits(t *testing.T) {
	t.Skip("unimplemented: W14 Task 13")
	// Close returns, no goroutine left: connection count 0, a dial now fails
}
