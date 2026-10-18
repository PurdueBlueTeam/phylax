// Package procmod is the agent's `proc` module (docs: Modules): process
// start and exit events with lineage, user, command line and service
// attribution. It polls /proc (works without privileges, which is how the
// tests run it) and reads /proc/<pid> immediately on each new PID to beat
// processes that exit quickly.
package procmod

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcEvent is one process event.
type ProcEvent struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Comm    string `json:"comm"`
	Cmdline string `json:"cmdline,omitempty"`
	UID           int    `json:"uid"`
	Exe           string `json:"exe,omitempty"`
	Unit          string `json:"unit,omitempty"`      // systemd unit from the cgroup, when present
	Service       string `json:"service,omitempty"`   // declared service, if the proc belongs to one
	ParentService string `json:"pservice,omitempty"`  // declared service of the parent
}

// Sink receives events.
type Sink interface {
	ProcStart(ProcEvent)
	ProcExit(pid int)
}

// Services maps running processes to declared services for attribution.
// A service matches a process when the process's unit equals the service's
// unit, or its executable name equals the service's exe.
type Services struct {
	mu     sync.RWMutex
	byUnit map[string]string
	byExe  map[string]string
}

// NewServices builds an empty service table.
func NewServices() *Services {
	return &Services{byUnit: map[string]string{}, byExe: map[string]string{}}
}

// Declare adds a service.
func (s *Services) Declare(name, unit, exe string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if unit != "" {
		s.byUnit[unit] = name
	}
	if exe != "" {
		s.byExe[filepath.Base(exe)] = name
	}
}

// Undeclare removes a service.
func (s *Services) Undeclare(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.byUnit {
		if v == name {
			delete(s.byUnit, k)
		}
	}
	for k, v := range s.byExe {
		if v == name {
			delete(s.byExe, k)
		}
	}
}

// Lookup returns the service name owning a process, or "".
func (s *Services) Lookup(unit, exe string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if unit != "" {
		if n, ok := s.byUnit[unit]; ok {
			return n
		}
	}
	if exe != "" {
		if n, ok := s.byExe[filepath.Base(exe)]; ok {
			return n
		}
	}
	return ""
}

// Module watches the process table.
type Module struct {
	sink     Sink
	services *Services
	interval time.Duration
	procRoot string // /proc in production; t.TempDir in tests

	mu     sync.Mutex
	known  map[int]int // pid -> ppid at first sighting
	exited map[int]bool
}

// New builds the module. procRoot empty means /proc.
func New(sink Sink, services *Services, procRoot string) *Module {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &Module{
		sink: sink, services: services,
		interval: 250 * time.Millisecond,
		procRoot: procRoot,
		known:    map[int]int{}, exited: map[int]bool{},
	}
}

// Run scans until ctx is done.
func (m *Module) Run(ctx context.Context) error {
	if err := m.scan(true); err != nil {
		return err
	}
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			m.scan(false)
		}
	}
}

// scan walks the pid table once.
func (m *Module) scan(baseline bool) error {
	now, err := m.snapshot()
	if err != nil {
		return err
	}

	m.mu.Lock()
	var starts, exits []int
	for pid := range now {
		if _, ok := m.known[pid]; !ok {
			starts = append(starts, pid)
		}
	}
	for pid := range m.known {
		if _, ok := now[pid]; !ok {
			exits = append(exits, pid)
		}
	}
	sort.Ints(starts)
	sort.Ints(exits)
	m.mu.Unlock()

	if baseline {
		for _, pid := range starts {
			m.record(pid, now[pid])
		}
		return nil
	}

	for _, pid := range starts {
		ev := now[pid]
		m.record(pid, ev)
		ev.Service = m.services.Lookup(ev.Unit, ev.Exe)
		if p, ok := now[ev.PPID]; ok {
			ev.ParentService = m.services.Lookup(p.Unit, p.Exe)
		} else if pp, ok := readProc(m.procRoot, ev.PPID); ok {
			ev.ParentService = m.services.Lookup(pp.Unit, pp.Exe)
		}
		m.sink.ProcStart(ev)
	}
	for _, pid := range exits {
		m.mu.Lock()
		delete(m.known, pid)
		m.exited[pid] = true
		m.mu.Unlock()
		m.sink.ProcExit(pid)
	}
	return nil
}

// snapshot reads every pid once; gone pids are skipped.
func (m *Module) snapshot() (map[int]ProcEvent, error) {
	pids, err := listPIDs(m.procRoot)
	if err != nil {
		return nil, err
	}
	out := make(map[int]ProcEvent, len(pids))
	for _, pid := range pids {
		if ev, ok := readProc(m.procRoot, pid); ok {
			out[pid] = ev
		}
	}
	return out, nil
}

func (m *Module) record(pid int, ev ProcEvent) {
	m.mu.Lock()
	if _, ok := m.known[pid]; !ok && !m.exited[pid] {
		m.known[pid] = ev.PPID
	}
	m.mu.Unlock()
}

// listPIDs returns numeric directory entries of root, ascending.
func listPIDs(root string) ([]int, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []int
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out, nil
}

// readProc snapshots one process. ok=false when the pid vanished or the
// stat line is unreadable.
func readProc(root string, pid int) (ProcEvent, bool) {
	var ev ProcEvent
	ev.PID = pid
	dir := filepath.Join(root, strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return ev, false
	}
	// stat: pid (comm) state ppid ... — comm may contain spaces and
	// parens, so split on the last ')'.
	s := string(stat)
	li, ri := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if li < 0 || ri < 0 || ri < li {
		return ev, false
	}
	ev.Comm = s[li+1 : ri]
	rest := strings.Fields(s[ri+1:])
	// rest[0]=state, rest[1]=ppid. The uid is not in stat; it comes from
	// /proc/<pid>/status.
	if len(rest) < 2 {
		return ev, false
	}
	ev.PPID, _ = strconv.Atoi(rest[1])
	if b, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		ev.UID = uidFromStatus(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		c := strings.ReplaceAll(string(b), "\x00", " ")
		ev.Cmdline = strings.TrimRight(c, " ")
	}
	if t, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		ev.Exe = t
	}
	if b, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		ev.Unit = unitFromCgroup(string(b))
	}
	return ev, true
}
// uidFromStatus parses the Uid line of /proc/<pid>/status
// ("Uid:\treal\treal\teffective\tsaved").
func uidFromStatus(s string) int {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				n, _ := strconv.Atoi(f[1])
				return n
			}
		}
	}
	return -1
}

// unitFromCgroup extracts a systemd unit name from cgroup file content
// (v2 line "0::/system/sshd.service" or a v1 line ending in a unit).
func unitFromCgroup(s string) string {
	for _, line := range strings.Split(s, "\n") {
		// v1 "0:memory:/path", v2 "0::/system/sshd.service": the path is
		// everything after the last colon.
		i := strings.LastIndex(line, ":")
		if i < 0 || i == len(line)-1 {
			continue
		}
		path := strings.TrimSpace(line[i+1:])
		j := strings.LastIndex(path, "/")
		if j < 0 {
			continue
		}
		base := path[j+1:]
		if strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".scope") ||
			strings.HasSuffix(base, ".slice") || strings.HasSuffix(base, ".timer") {
			return base
		}
	}
	return ""
}

// Tree returns the ancestor chain of pid (pid first, then parents),
// resolved through the module's lineage map. Used by evidence collection.
func (m *Module) Tree(pid int) []ProcEvent {
	var out []ProcEvent
	seen := map[int]bool{}
	cur := pid
	for cur > 0 && !seen[cur] {
		seen[cur] = true
		ev, ok := readProc(m.procRoot, cur)
		if !ok {
			ev = ProcEvent{PID: cur}
		}
		out = append(out, ev)
		m.mu.Lock()
		ppid := m.known[cur]
		m.mu.Unlock()
		if ppid == 0 {
			ppid = ev.PPID
		}
		if ppid <= 1 || ppid == cur {
			break
		}
		cur = ppid
	}
	return out
}
