package conformance

import (
	"runtime"
	"strings"
)

// goroutineKeys counts the running goroutines by their top function: the
// innermost frame that is not part of the runtime. A blocked goroutine's top
// frame is usually runtime.gopark, so the first user-space frame is what
// identifies it (for example conformance.leakyFactory.func1).
func goroutineKeys() map[string]int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	keys := map[string]int{}
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		lines := strings.Split(g, "\n")
		if len(lines) < 2 {
			continue
		}
		fn := ""
		for _, line := range lines[1:] {
			if strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "created by ") {
				continue
			}
			name := line
			if i := strings.IndexByte(name, '('); i >= 0 {
				name = name[:i]
			}
			if fn == "" {
				fn = name // fall back to the runtime frame (gopark) when there is no user frame
			}
			if !strings.HasPrefix(name, "runtime.") && !strings.HasPrefix(name, "internal/") && !strings.HasPrefix(name, "sync.") {
				fn = name
				break
			}
		}
		if fn != "" {
			keys[fn]++
		}
	}
	return keys
}

// extraGoroutines returns the top functions still running after a module
// stopped that were not running before it started.
func extraGoroutines(before, after map[string]int) map[string]int {
	extra := map[string]int{}
	for fn, n := range after {
		if d := n - before[fn]; d > 0 {
			extra[fn] = d
		}
	}
	return extra
}
