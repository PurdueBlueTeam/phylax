package conformance

import "testing"

func TestSkipsCarryReason(t *testing.T) {
	t.Skip("unimplemented: W1 Task 41")
	// bad := findBareSkips(t, "../../..") walks internal/ and cmd/, parses *_test.go,
	// and returns "file:line" for t.Skip() with no or empty argument.
}
