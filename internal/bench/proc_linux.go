//go:build linux

package bench

// ProcStats returns the controller process CPU time (utime plus stime) and
// resident set size from /proc/self.
func ProcStats() (cpuMs, rssBytes uint64) {
	panic("unimplemented: W14 Task 7")
}

// parseStatCPUTicks returns fields 14 and 15 (utime and stime, in clock ticks)
// of one line of /proc/self/stat, skipping past the last ')' because the
// command name may contain spaces and parentheses.
func parseStatCPUTicks(line string) uint64 {
	panic("unimplemented: W14 Task 7")
}
