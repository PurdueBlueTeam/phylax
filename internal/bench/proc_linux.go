//go:build linux

package bench

import (
	"os"
	"strconv"
	"strings"
)

// ProcStats returns the controller process CPU time (utime plus stime) and
// resident set size from /proc/self.
func ProcStats() (cpuMs, rssBytes uint64) {
	if b, err := os.ReadFile("/proc/self/stat"); err == nil {
		// shortcut: USER_HZ assumed 100, upgrade if a kernel reports otherwise.
		cpuMs = parseStatCPUTicks(string(b)) * 10
	}
	if b, err := os.ReadFile("/proc/self/statm"); err == nil {
		if f := strings.Fields(string(b)); len(f) >= 2 {
			if pages, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				rssBytes = pages * uint64(os.Getpagesize())
			}
		}
	}
	return cpuMs, rssBytes
}

// parseStatCPUTicks returns fields 14 and 15 (utime and stime, in clock ticks)
// of one line of /proc/self/stat, skipping past the last ')' because the
// command name may contain spaces and parentheses.
func parseStatCPUTicks(line string) uint64 {
	// /proc/self/stat is "pid (comm) state ..."; comm is field 2 and may hold
	// ')' itself, so the field list resumes after the last ')'.
	i := strings.LastIndexByte(line, ')')
	if i < 0 {
		return 0
	}
	// f[0] is field 3 (state), so fields 14 and 15 are f[11] and f[12].
	f := strings.Fields(line[i+1:])
	if len(f) < 13 {
		return 0
	}
	u, _ := strconv.ParseUint(f[11], 10, 64)
	s, _ := strconv.ParseUint(f[12], 10, 64)
	return u + s
}
