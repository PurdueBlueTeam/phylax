package crossview

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type xrec struct {
	evs []Event
}

func (r *xrec) Crossview(e Event) { r.evs = append(r.evs, e) }

// fakeProcPid writes a minimal proc entry (stat/comm/exe/environ/cgroup).
func fakeProcPid(t *testing.T, root string, pid int, comm, exe, environ string) {
	t.Helper()
	d := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o644)
	if exe != "" {
		os.Symlink(exe, filepath.Join(d, "exe"))
	}
	if environ != "" {
		os.WriteFile(filepath.Join(d, "environ"), []byte(environ), 0o644)
	}
}

func TestHiddenPID(t *testing.T) {
	root := t.TempDir()
	alive := map[int]bool{1: true, 100: true, 999: true}
	// pid 1 and 100 visible; 999 alive but hidden from readdir
	fakeProcPid(t, root, 1, "init", "/sbin/init", "")
	fakeProcPid(t, root, 100, "svc", "/usr/sbin/svc", "")

	r := &xrec{}
	m := New(r, root, t.TempDir()+"/taint", func(pid int) bool { return alive[pid] })
	m.probeCap = 1000
	m.interval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(r.evs) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	found := false
	for _, e := range r.evs {
		if e.Kind == "hidden_pid" && e.PID == 999 {
			found = true
		}
	}
	if !found {
		t.Fatalf("hidden pid 999 not detected: %v", r.evs)
	}
	// dedupe: only one report per state
	time.Sleep(80 * time.Millisecond)
	n := 0
	for _, e := range r.evs {
		if e.Kind == "hidden_pid" && e.PID == 999 {
			n++
		}
	}
	if n != 1 {
		t.Errorf("hidden pid reported %d times", n)
	}
}

func TestDeletedExeAndPreload(t *testing.T) {
	root := t.TempDir()
	alive := map[int]bool{1: true, 200: true, 201: true}
	fakeProcPid(t, root, 1, "init", "/sbin/init", "")
	fakeProcPid(t, root, 200, "miner", "/tmp/.x (deleted)", "")
	fakeProcPid(t, root, 201, "svc", "/usr/sbin/svc", "PATH=/bin\x00LD_PRELOAD=/lib/rootkit.so\x00")

	r := &xrec{}
	m := New(r, root, t.TempDir()+"/taint", func(pid int) bool { return alive[pid] })
	m.probeCap = 1000
	m.interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ok := false
		for _, e := range r.evs {
			if e.Kind == "hidden_exec" && e.PID == 200 {
				ok = true
			}
			if e.Kind == "ld_preload" && e.PID == 201 && e.Preload == "/lib/rootkit.so" {
				ok = true
			}
		}
		if ok && len(r.evs) >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	kind := map[string]bool{}
	for _, e := range r.evs {
		kind[e.Kind] = true
	}
	if !kind["hidden_exec"] || !kind["ld_preload"] {
		t.Fatalf("want hidden_exec and ld_preload, got %v", r.evs)
	}
}

func TestTaintChange(t *testing.T) {
	root := t.TempDir()
	taintFile := filepath.Join(t.TempDir(), "taint")
	os.WriteFile(taintFile, []byte("0\n"), 0o644)
	alive := map[int]bool{1: true}
	fakeProcPid(t, root, 1, "init", "/sbin/init", "")

	r := &xrec{}
	m := New(r, root, taintFile, func(pid int) bool { return alive[pid] })
	m.probeCap = 10
	m.interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	time.Sleep(60 * time.Millisecond) // baseline reads 0

	os.WriteFile(taintFile, []byte("2\n"), 0o644) // GPU taint
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range r.evs {
			if e.Kind == "kernel_taint" && e.Old == "0" && e.New == "2" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("taint change not detected: %v", r.evs)
}
