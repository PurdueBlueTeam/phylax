//go:build linux

package audit

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const clkTck = 100 // USER_HZ is 100 on every Linux ABI we run on

// ProcInfo is what we know about one process, identified by (PID, Start).
// Start is the /proc/<pid>/stat starttime in clock ticks since boot, so a
// reused pid is a different process.
type ProcInfo struct {
	PID     int
	PPID    int
	Start   uint64
	Exe     string
	Comm    string
	Cmdline string
	Cgroup  string
	Live    bool // read from /proc just now (false: from the cache)
	seen    time.Time
}

type procKey struct {
	pid   int
	start uint64
}

// procTable reads /proc and caches by (pid, starttime). Entries recorded from
// audit exec events outlive the process for ttl so that late children still
// resolve their parents (design: "exited entries live in a short-TTL table").
type procTable struct {
	root string
	ttl  time.Duration
	max  int
	now  func() time.Time

	mu     sync.Mutex
	byPID  map[int]*ProcInfo
	byKey  map[procKey]*ProcInfo
	btime  time.Time
	btRead bool
}

func newProcTable(root string, ttl time.Duration, max int) *procTable {
	return &procTable{root: root, ttl: ttl, max: max, now: time.Now,
		byPID: map[int]*ProcInfo{}, byKey: map[procKey]*ProcInfo{}}
}

// statFields returns ppid and starttime from /proc/<pid>/stat. The comm field
// may contain spaces and parentheses, so split after the last ')'.
func parseStat(b []byte) (ppid int, start uint64, ok bool) {
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, 0, false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 { // state=f[0] ... starttime=f[19]
		return 0, 0, false
	}
	pp, err1 := strconv.Atoi(f[1])
	st, err2 := strconv.ParseUint(f[19], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return pp, st, true
}

func (t *procTable) boot() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.btRead {
		return t.btime
	}
	t.btRead = true
	b, err := os.ReadFile(filepath.Join(t.root, "stat"))
	if err != nil {
		return t.btime
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "btime "); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				t.btime = time.Unix(n, 0)
			}
		}
	}
	return t.btime
}

func readSmall(path string, max int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, max)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

// readLive reads /proc/<pid>. ok is false if the process is gone.
func (t *procTable) readLive(pid int) (ProcInfo, bool) {
	dir := filepath.Join(t.root, strconv.Itoa(pid))
	sb, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return ProcInfo{}, false
	}
	ppid, start, ok := parseStat(sb)
	if !ok {
		return ProcInfo{}, false
	}
	pi := ProcInfo{PID: pid, PPID: ppid, Start: start, Live: true}
	pi.Exe, _ = os.Readlink(filepath.Join(dir, "exe"))
	pi.Comm = strings.TrimSpace(readSmall(filepath.Join(dir, "comm"), 64))
	pi.Cmdline = strings.TrimRight(strings.ReplaceAll(readSmall(filepath.Join(dir, "cmdline"), 4096), "\x00", " "), " ")
	if cg := readSmall(filepath.Join(dir, "cgroup"), 1024); cg != "" {
		pi.Cgroup = strings.TrimSpace(strings.SplitN(cg, "\n", 2)[0])
	}
	return pi, true
}

// Resolve returns what is known about pid at event time at. A live /proc read
// is used only if the process started no later than the event (otherwise the
// pid was reused); otherwise the cache.
func (t *procTable) Resolve(pid int, at time.Time) (ProcInfo, bool) {
	if pid <= 0 {
		return ProcInfo{}, false
	}
	if pi, ok := t.readLive(pid); ok {
		bt := t.boot()
		if bt.IsZero() || !bt.Add(time.Duration(pi.Start)*time.Second/clkTck).After(at.Add(2*time.Second)) {
			t.store(pi)
			return pi, true
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.byPID[pid]; c != nil && t.now().Sub(c.seen) <= t.ttl {
		cp := *c
		cp.Live = false
		return cp, true
	}
	return ProcInfo{}, false
}

func (t *procTable) store(pi ProcInfo) {
	pi.seen = t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.byPID) >= t.max {
		t.pruneLocked()
	}
	if len(t.byPID) >= t.max { // still full of live entries: drop an arbitrary one
		for k, v := range t.byPID {
			delete(t.byPID, k)
			delete(t.byKey, procKey{v.PID, v.Start})
			break
		}
	}
	if old := t.byPID[pi.PID]; old != nil && old.Start != pi.Start {
		delete(t.byKey, procKey{old.PID, old.Start})
	}
	cp := pi
	t.byPID[pi.PID] = &cp
	t.byKey[procKey{pi.PID, pi.Start}] = &cp
}

// Remember records a process seen in an audit exec event (works after exit).
func (t *procTable) Remember(pi ProcInfo) { t.store(pi) }

func (t *procTable) pruneLocked() {
	now := t.now()
	for pid, v := range t.byPID {
		if now.Sub(v.seen) > t.ttl {
			delete(t.byPID, pid)
			delete(t.byKey, procKey{v.PID, v.Start})
		}
	}
}

// Len is for tests and health.
func (t *procTable) Len() int { t.mu.Lock(); defer t.mu.Unlock(); return len(t.byPID) }
