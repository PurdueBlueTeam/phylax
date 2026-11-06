//go:build !linux

package bench

// ProcStats returns 0, 0: process figures are Linux-only.
func ProcStats() (cpuMs, rssBytes uint64) {
	panic("unimplemented: W14 Task 7")
}
