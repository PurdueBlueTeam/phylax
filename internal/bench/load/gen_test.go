package load

import "testing"

// Task 14's synthetic module and agent-runner tests; both are implemented in
// Task 14.

func TestGenEmitsRates(t *testing.T) {
	t.Skip("unimplemented: W14 Task 14")
	// Gen{Rates: {1, 5, 20, 0}, Size: 50} for 2 s: 1 critical (1..3), 5/s high (8..12),
	// 20/s normal (35..45), no bulk; every event is kind "bench.load" with a 50-byte "pad";
	// Gen.Emitted equals the emitted total.
}

func TestGenStop(t *testing.T) {
	t.Skip("unimplemented: W14 Task 14")
	// Start in a goroutine, Stop(), Start returns nil within 500 ms while ctx is live
}

func TestStartAgentsRealEnrollment(t *testing.T) {
	t.Skip("unimplemented: W14 Task 14")
	// package load_test: a real controller, WriteBundles for bench-001 and bench-002, the proxy in front of it,
	// StartAgents with 50..500 ms backoff; within 20 s both agents are connected, bench-001 has acked 20 events
	// and connects once; StopGen drains the spool to depth 0; the bundle token cannot be used twice.
}

func TestStartAgentsNotEnoughBundles(t *testing.T) {
	t.Skip("unimplemented: W14 Task 14")
	// dir with 1 bundle, n = 2 -> error mentions "need 2, found 1"
}
