package agent

import (
	"encoding/json"
	"sync"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// TagScope answers which plan tag, if any, an event may carry. A plan tag
// covers only our own activity: the step's own child process and everything it
// starts (design: Tagging and adoption, "What may be tagged"; R6). An event
// from any other process on the host is untagged even while a step runs.
//
// shortcut: descent is followed through the process_start events the agent
// sees; a child started before the sensor attaches is untagged, upgrade when
// the executor can read /proc/<pid>/task children.
type TagScope struct {
	mu    sync.Mutex
	procs map[int]taggedProc // pid -> start time and plan tag
}

type taggedProc struct {
	start uint64
	tag   string
}

func NewTagScope() *TagScope { return &TagScope{procs: map[int]taggedProc{}} }

// Register adds the step's own child process (pid and start time) under the
// plan tag.
func (s *TagScope) Register(planTag string, pid int, startTime uint64) {
	if planTag == "" || pid <= 0 {
		return
	}
	s.mu.Lock()
	s.procs[pid] = taggedProc{start: startTime, tag: planTag}
	s.mu.Unlock()
}

// Release removes every process registered under planTag (called when the
// step ends).
func (s *TagScope) Release(planTag string) {
	if planTag == "" {
		return
	}
	s.mu.Lock()
	for pid, p := range s.procs {
		if p.tag == planTag {
			delete(s.procs, pid)
		}
	}
	s.mu.Unlock()
}

// Tag returns the plan tag for an event, or "" when the event is not our own
// activity. A process_start whose parent is registered is registered too (the
// descent) and tagged; any other event is tagged when its own pid is
// registered.
func (s *TagScope) Tag(kind string, fields map[string]any) string {
	pid := intField(fields, "pid")
	start := startField(fields)
	s.mu.Lock()
	defer s.mu.Unlock()
	if kind == event.KindProcessStart {
		ppid, pstart := parentOf(fields)
		if p, ok := s.procs[ppid]; ok && sameProc(p, pstart) {
			if pid > 0 {
				s.procs[pid] = taggedProc{start: start, tag: p.tag}
			}
			return p.tag
		}
	}
	if p, ok := s.procs[pid]; ok && sameProc(p, start) {
		return p.tag
	}
	return ""
}

// sameProc matches a pid's registration against an event's start time. An
// event or registration without a start time matches on the pid alone.
//
// shortcut: a reused pid whose start time the event does not carry is still
// tagged, upgrade when every sensor emits start_ticks (audit and winevt do).
func sameProc(p taggedProc, start uint64) bool {
	return start == 0 || p.start == 0 || start == p.start
}

// parentOf returns the parent pid and its start time when the event carries
// them: the process_start parent object's start_ticks, or the flat ppid_start.
func parentOf(fields map[string]any) (int, uint64) {
	if parent, ok := fields["parent"].(map[string]any); ok {
		pid := intField(parent, "pid")
		if pid == 0 {
			pid = intField(fields, "ppid")
		}
		return pid, uintField(parent, "start_ticks")
	}
	return intField(fields, "ppid"), uintField(fields, "ppid_start")
}

// startField is an event's own start time: conn and listener call it pid_start,
// process_start calls it start_ticks.
func startField(fields map[string]any) uint64 {
	if v := uintField(fields, "pid_start"); v != 0 {
		return v
	}
	return uintField(fields, "start_ticks")
}

func intField(fields map[string]any, name string) int {
	switch v := fields[name].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

func uintField(fields map[string]any, name string) uint64 {
	switch v := fields[name].(type) {
	case uint64:
		return v
	case uint32:
		return uint64(v)
	case int:
		if v > 0 {
			return uint64(v)
		}
	case int64:
		if v > 0 {
			return uint64(v)
		}
	case float64:
		if v > 0 {
			return uint64(v)
		}
	case json.Number:
		n, _ := v.Int64()
		if n > 0 {
			return uint64(n)
		}
	}
	return 0
}
