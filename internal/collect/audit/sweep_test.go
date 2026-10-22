//go:build linux

package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func snap(t *testing.T, roots ...string) Snapshot {
	t.Helper()
	s, err := TakeSnapshot(context.Background(), roots, SweepOptions{Depth: 8, MaxEntries: 1000, HashMaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func write(t *testing.T, p, s string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func kinds(cs []Change) map[string]ChangeKind {
	m := map[string]ChangeKind{}
	for _, c := range cs {
		m[filepath.Base(c.Path)] = c.Kind
	}
	return m
}

func TestSweepDiff(t *testing.T) {
	dir := t.TempDir()
	write(t, dir+"/keep", "same")
	write(t, dir+"/edit", "v1")
	write(t, dir+"/gone", "x")
	write(t, dir+"/sub/deep/old", "o")
	write(t, dir+"/perm", "p")
	os.Symlink("/etc/passwd", dir+"/link")
	s1 := snap(t, dir)

	write(t, dir+"/edit", "v2")
	os.Remove(dir + "/gone")
	write(t, dir+"/sub/deep/new", "n") // creation deep in the tree, no audit event needed
	os.Chmod(dir+"/perm", 0o777)
	os.Remove(dir + "/link")
	os.Symlink("/etc/shadow", dir+"/link")
	// Same-size, same-mtime content swap is still caught by the hash.
	st, _ := os.Stat(dir + "/keep")
	write(t, dir+"/keep", "SAME")
	os.Chtimes(dir+"/keep", st.ModTime(), st.ModTime())

	got := kinds(Diff(s1, snap(t, dir)))
	want := map[string]ChangeKind{"edit": Modified, "gone": Deleted, "new": Created, "perm": AttrOnly, "link": Modified, "keep": Modified}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q (all: %v)", k, got[k], v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected extra changes: %v", got)
	}
}

func TestSweepNoChangeIsEmptyDespiteDirMtime(t *testing.T) {
	dir := t.TempDir()
	write(t, dir+"/a", "1")
	s1 := snap(t, dir)
	os.Chtimes(dir, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	if d := Diff(s1, snap(t, dir)); len(d) != 0 {
		t.Fatalf("%v", d)
	}
}

func TestSweepBoundsAndExclusion(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 20; i++ {
		write(t, filepath.Join(dir, "f", string(rune('a'+i))), "x")
	}
	write(t, dir+"/own/spool.dat", "x")
	write(t, dir+"/d1/d2/d3/deep", "x")
	s, _ := TakeSnapshot(context.Background(), []string{dir}, SweepOptions{Depth: 2, MaxEntries: 8, HashMaxBytes: 1 << 20, Exclude: []string{dir + "/own"}})
	if len(s) > 8 {
		t.Fatalf("max entries ignored: %d", len(s))
	}
	for p := range s {
		if hasPrefixPath(p, dir+"/own") {
			t.Fatalf("excluded path in snapshot: %s", p)
		}
	}
	s, _ = TakeSnapshot(context.Background(), []string{dir}, SweepOptions{Depth: 2, MaxEntries: 1000, HashMaxBytes: 1 << 20})
	if _, ok := s[dir+"/d1/d2/d3/deep"]; ok {
		t.Fatal("depth limit ignored")
	}
}

func TestSweepOversizedFilesComparedByStat(t *testing.T) {
	dir := t.TempDir()
	write(t, dir+"/big", "0123456789")
	s1, _ := TakeSnapshot(context.Background(), []string{dir}, SweepOptions{Depth: 4, HashMaxBytes: 4})
	if s1[dir+"/big"].Hash != "" {
		t.Fatal("hashed oversized file")
	}
	write(t, dir+"/big", "0123456789abc")
	s2, _ := TakeSnapshot(context.Background(), []string{dir}, SweepOptions{Depth: 4, HashMaxBytes: 4})
	if d := Diff(s1, s2); len(d) != 1 || d[0].Kind != Modified {
		t.Fatalf("%v", d)
	}
}

func TestSweepThrottleAndCancel(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 30; i++ {
		write(t, filepath.Join(dir, string(rune('a'+i%26))+string(rune('a'+i/26))), "x")
	}
	start := time.Now()
	TakeSnapshot(context.Background(), []string{dir}, SweepOptions{Depth: 2, HashMaxBytes: 1 << 20, FilesPerSec: 100})
	if el := time.Since(start); el < 250*time.Millisecond {
		t.Fatalf("30 files at 100/s took %v: not throttled", el)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start = time.Now()
	_, err := TakeSnapshot(ctx, []string{dir}, SweepOptions{Depth: 2, HashMaxBytes: 1 << 20, FilesPerSec: 10})
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("cancel not honoured: %v after %v", err, time.Since(start))
	}
}

func TestSweepLoopEmitsMissedChangesButNotAuditReported(t *testing.T) {
	dir := t.TempDir()
	write(t, dir+"/a", "1")
	m, c := testModule(t, func(cfg *Config) { cfg.SweepFilesPerSec = 100000; cfg.SweepInterval = 40 * time.Millisecond })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.runSweeps(ctx, func() []string { return []string{dir} }, 40*time.Millisecond, 10*time.Millisecond)
		close(done)
	}()
	time.Sleep(60 * time.Millisecond) // baseline taken
	write(t, dir+"/missed", "evil")
	write(t, dir+"/seen", "evil")
	m.recent.Store(dir+"/seen", time.Now()) // audit already reported this one
	deadline := time.Now().Add(30 * time.Second)
	for len(c.kind(KindFileChange)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
	evs := c.kind(KindFileChange)
	if len(evs) != 1 {
		t.Fatalf("events: %v", c.all())
	}
	f := evs[0].Fields
	if f["path"] != dir+"/missed" || f["op"] != "create" || f["source"] != "sweep" || f["writer_known"] != false || f["sha256"] == "" {
		t.Fatalf("%v", f)
	}
}
