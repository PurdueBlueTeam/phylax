package load_test

import "testing"

// Task 15's scenario tests; the runner is implemented in Task 15.

func TestRunEndToEndPartition(t *testing.T) {
	t.Skip("unimplemented: W14 Task 15")
	// package load_test. Real controller in-process (BenchInterval 500 ms); bundles for bench-001..bench-003;
	// Run with a 12 s duration, 3 s in and 3 s for the partition, MaxReconnectS 5.
	// want: no error, res.Pass, the three reconnects (none missing) each within 5 s, one reconnect per agent,
	//   GapEvents == 0, Class[2].EventsPerS > 20, a contiguous store sequence per agent,
	//   and the output contains "reconnect after partition" and "PASS no_loss".
}

func TestRunFailsWhenSpoolTooSmall(t *testing.T) {
	t.Skip("unimplemented: W14 Task 15")
	// same run but SpoolMax 200 KB and Rates {0, 0, 200, 200} Size 500 over a 4 s partition:
	// res.Pass is false, the "no_loss" check failed, err is nil.
}

func TestRunValidatesConfig(t *testing.T) {
	t.Skip("unimplemented: W14 Task 15")
	// PartitionAt+PartitionFor >= Duration -> error; N 0 -> error; missing bundles -> error naming the dir
}
