// Package crossview is the agent's `crossview` module (docs: Modules):
// hidden PIDs, sockets and modules; memfd or deleted executables;
// LD_PRELOAD; BPF programs. The core trick: enumerate the pid table two
// ways — readdir(/proc) (what a hooked libc shows) and a liveness probe
// over the pid range (kill(pid, 0), which a readdir hook cannot see) —
// and diff them.
package crossview

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// kill0 is signal-0 liveness: nil when the pid exists and we may signal it.
func kill0(pid int) error {
	return unix.Kill(pid, 0)
}

// Event is one crossview finding.
type Event struct {
	Kind    string `json:"kind"` // hidden_pid | hidden_exec | ld_preload | kernel_taint
	PID     int    `json:"pid,omitempty"`
	Comm    string `json:"comm,omitempty"`
	Exe     string `json:"exe,omitempty"`
	Preload string `json:"preload,omitempty"`
	Old     string `json:"old,omitempty"`   // kernel taint
	New     string `json:"new,omitempty"`   // kernel taint
}

// Sink receives findings.
type Sink interface {
	Crossview(Event)
}

// Module runs the periodic cross-checks.
type Module struct {
	sink     Sink
	interval time.Duration
	procRoot string
	sysPath  string // /proc/sys/kernel/taint in production

	// probe answers "is pid alive?" — kill(pid,0) in production,
	// a stub in tests.
	probe func(pid int) bool

	mu       sync.Mutex
	taint    string
	probeCap int // probe every pid up to this
	reported map[string]bool // per-finding dedupe until state changes
}

// New builds the module. probe nil means kill(pid,0).
func New(sink Sink, procRoot, sysPath string, probe func(int) bool) *Module {
	if procRoot == "" {
		procRoot = "/proc"
	}
	if sysPath == "" {
		sysPath = "/proc/sys/kernel/taint"
	}
	if probe == nil {
		probe = func(pid int) bool {
			// signal 0: no signal sent; ESRCH means dead
			err := kill0(pid)
			return err == nil
		}
	}
	return &Module{
		sink: sink, interval: 30 * time.Second,
		procRoot: procRoot, sysPath: sysPath, probe: probe, probeCap: 32768,
		reported: map[string]bool{},
	}
}

// Run checks until ctx is done.
func (m *Module) Run(ctx context.Context) error {
	m.check(true)
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			m.check(false)
		}
	}
}

func (m *Module) check(baseline bool) {
	visible, _ := readdirPIDs(m.procRoot)
	if baseline {
		m.taint = readTaint(m.sysPath)
		return
	}

	// 1. hidden pids: alive (probe) but not in the readdir listing.
	lo, hi := 1, m.probeCap
	if maxPID(visible) > hi {
		hi = maxPID(visible)
	}
	for pid := lo; pid <= hi; pid++ {
		if visible[pid] {
			continue
		}
		if !m.probe(pid) {
			continue
		}
		ev := Event{Kind: "hidden_pid", PID: pid}
		ev.Comm = commOf(m.procRoot, pid)
		m.report(ev)
	}

	// 2. deleted / memfd executables, 3. LD_PRELOAD
	for pid := range visible {
		d := filepath.Join(m.procRoot, strconv.Itoa(pid))
		if t, err := os.Readlink(filepath.Join(d, "exe")); err == nil {
			if strings.HasSuffix(t, " (deleted)") || strings.Contains(t, "memfd:") {
				m.report(Event{Kind: "hidden_exec", PID: pid, Exe: t})
			}
		}
		if b, err := os.ReadFile(filepath.Join(d, "environ")); err == nil {
			if p := preloadFrom(string(b)); p != "" {
				m.report(Event{Kind: "ld_preload", PID: pid, Preload: p})
			}
		}
	}
	// 4. kernel taint change (only after a real baseline was read)
	if t := readTaint(m.sysPath); t != "" {
		if m.taint != "" && t != m.taint {
			m.report(Event{Kind: "kernel_taint", Old: m.taint, New: t})
		}
		m.taint = t
	}
}

// report emits a finding once per state change (deduped).
func (m *Module) report(ev Event) {
	key := fmt.Sprint(ev)
	m.mu.Lock()
	if m.reported[key] {
		m.mu.Unlock()
		return
	}
	m.reported[key] = true
	// forget it once the pid is gone, so a re-appearance alerts again
	m.mu.Unlock()
	m.sink.Crossview(ev)
}

func readdirPIDs(root string) (map[int]bool, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := map[int]bool{}
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			out[n] = true
		}
	}
	return out, nil
}

func maxPID(p map[int]bool) int {
	m := 0
	for pid := range p {
		if pid > m {
			m = pid
		}
	}
	return m
}

func readTaint(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func commOf(root string, pid int) string {
	b, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// preloadFrom extracts LD_PRELOAD from an environ blob (NUL separated).
func preloadFrom(b string) string {
	for _, kv := range strings.Split(b, "\x00") {
		if strings.HasPrefix(kv, "LD_PRELOAD=") {
			return strings.TrimPrefix(kv, "LD_PRELOAD=")
		}
	}
	return ""
}
