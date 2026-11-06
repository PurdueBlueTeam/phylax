//go:build !linux

package bench

// ProcStats returns 0, 0: process figures are Linux-only.
//
// shortcut: the controller runs on Linux, upgrade when it does not.
func ProcStats() (cpuMs, rssBytes uint64) {
	return 0, 0
}
