package agent

import (
	"encoding/json"
	"os"
	"runtime/debug"
)

// The memory limits options.json may carry (agent.config's range).
const (
	optMinMemoryMB = 32
	optMaxMemoryMB = 1024
)

// applyOptions applies <root>/options.json, written by the agent.config
// action: its memory limit is set live. It runs at start and on every
// heartbeat tick (the link loop is its only caller), so a change takes effect
// within one heartbeat without a restart. A missing or malformed file changes
// nothing; a malformed one is logged once.
func (a *Agent) applyOptions() {
	path := a.cfg.Layout.Options()
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var o struct {
		MemoryLimitMB int `json:"memory_limit_mb"`
	}
	if json.Unmarshal(raw, &o) != nil || o.MemoryLimitMB < optMinMemoryMB || o.MemoryLimitMB > optMaxMemoryMB {
		if a.optErr == "" {
			a.optErr = path
			a.log.Warn("ignoring options.json (not a memory limit in range)", "path", path)
		}
		return
	}
	a.optErr = ""
	limit := int64(o.MemoryLimitMB) << 20
	if limit == a.memLimit {
		return
	}
	a.memLimit = limit
	debug.SetMemoryLimit(limit)
}
