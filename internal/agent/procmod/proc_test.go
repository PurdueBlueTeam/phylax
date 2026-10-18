package procmod

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeProc builds a minimal proc-like tree under root for one pid.
func fakeProc(t *testing.T, root string, pid, ppid, uid int, comm, cmdline, exe, cgroup string) {
	t.Helper()
	d := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := fmt.Sprintf("%d (%s) S %d 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0", pid, comm, ppid, uid)
	if err := os.WriteFile(filepath.Join(d, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "status"), []byte(fmt.Sprintf("Name:\t%s\nUid:\t%d\t%d\t%d\t%d\n", comm, uid, uid, uid, uid)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "cmdline"), []byte(cmdline+"\x00arg\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if exe != "" {
		if err := os.Symlink(exe, filepath.Join(d, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	if cgroup != "" {
		if err := os.WriteFile(filepath.Join(d, "cgroup"), []byte(cgroup), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

type recorder struct {
	starts []ProcEvent
	exits  []int
}

func (r *recorder) ProcStart(e ProcEvent) { r.starts = append(r.starts, e) }
func (r *recorder) ProcExit(pid int)      { r.exits = append(r.exits, pid) }

func newTestModule(t *testing.T) (*Module, *recorder, string) {
	t.Helper()
	root := t.TempDir()
	r := &recorder{}
	m := New(r, NewServices(), root)
	m.interval = 20 * time.Millisecond
	return m, r, root
}

func TestProcStartAndExit(t *testing.T) {
	m, r, root := newTestModule(t)
	fakeProc(t, root, 100, 1, 0, "init", "", "/sbin/init", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	time.Sleep(60 * time.Millisecond) // baseline: pid 100 is not a start
	if len(r.starts) != 0 {
		t.Fatalf("baseline emitted starts: %v", r.starts)
	}

	fakeProc(t, root, 101, 100, 1000, "sshd", "/usr/sbin/sshd -D", "/usr/sbin/sshd", "0::/system/sshd.service")
	fakeProc(t, root, 102, 101, 1000, "bash", "/bin/bash -i", "/bin/bash", "")

	time.Sleep(80 * time.Millisecond)
	if len(r.starts) != 2 {
		t.Fatalf("want 2 starts, got %v", r.starts)
	}
	got := map[int]ProcEvent{}
	for _, e := range r.starts {
		got[e.PID] = e
	}
	if e := got[101]; e.PPID != 100 || e.UID != 1000 || e.Unit != "sshd.service" || e.Exe != "/usr/sbin/sshd" {
		t.Errorf("101 wrong: %+v", e)
	}
	if e := got[102]; e.Cmdline != "/bin/bash -i arg" {
		t.Errorf("102 cmdline wrong: %q", e.Cmdline)
	}

	// kill 102
	os.RemoveAll(filepath.Join(root, "102"))
	time.Sleep(80 * time.Millisecond)
	if len(r.exits) != 1 || r.exits[0] != 102 {
		t.Fatalf("want exit [102], got %v", r.exits)
	}
}

func TestServiceAttribution(t *testing.T) {
	m, r, root := newTestModule(t)
	m.services.Declare("web", "nginx.service", "nginx")

	fakeProc(t, root, 200, 1, 0, "nginx", "", "/usr/sbin/nginx", "0::/system/nginx.service")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	time.Sleep(60 * time.Millisecond) // baseline: 200 only

	fakeProc(t, root, 201, 200, 33, "bash", "bash -c whoami", "/bin/bash", "")
	fakeProc(t, root, 202, 200, 33, "nginx", "nginx: worker", "/usr/sbin/nginx", "")
	time.Sleep(80 * time.Millisecond)

	var worker *ProcEvent
	for i := range r.starts {
		if r.starts[i].PID == 202 {
			worker = &r.starts[i]
		}
	}
	if worker == nil {
		t.Fatalf("202 not started: %v", r.starts)
	}
	if worker.Service != "web" {
		t.Errorf("want service web, got %q", worker.Service)
	}
	if got := r.starts; len(got) != 2 {
		t.Errorf("want starts 201,202 got %v", got)
	}
}

func TestTree(t *testing.T) {
	m, _, root := newTestModule(t)
	fakeProc(t, root, 300, 1, 0, "init", "", "/sbin/init", "")
	fakeProc(t, root, 301, 300, 0, "svc", "", "/usr/sbin/svc", "")
	fakeProc(t, root, 302, 301, 0, "sh", "", "/bin/sh", "")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go m.Run(ctx)
	<-ctx.Done()

	tree := m.Tree(302)
	if len(tree) != 3 || tree[0].PID != 302 || tree[1].PID != 301 || tree[2].PID != 300 {
		t.Fatalf("bad tree: %v", tree)
	}
}
