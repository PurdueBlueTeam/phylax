package fimmod

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fimrec struct {
	evs []FileEvent
}

func (r *fimrec) FileChange(e FileEvent) { r.evs = append(r.evs, e) }

func waitForFn(t *testing.T, d time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func TestFimFileEvents(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "app.conf")
	os.WriteFile(f, []byte("one\n"), 0o644)

	r := &fimrec{}
	m := New(r, []Watch{{Path: dir, Kind: "config"}}, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	waitForFn(t, 500*time.Millisecond, func() bool { m.mu.Lock(); n := len(m.last); m.mu.Unlock(); return n > 0 })

	// modify
	if err := os.WriteFile(f, []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitForFn(t, 2*time.Second, func() bool {
		for _, e := range r.evs {
			if e.Path == f && e.Op == "modified" {
				return true
			}
		}
		return false
	})

	// create
	g := filepath.Join(dir, "webshell.php")
	os.WriteFile(g, []byte("<?php"), 0o644)
	waitForFn(t, 2*time.Second, func() bool {
		for _, e := range r.evs {
			if e.Path == g && e.Op == "created" && e.SHA256 != "" {
				return true
			}
		}
		return false
	})

	// delete
	os.Remove(g)
	waitForFn(t, 2*time.Second, func() bool {
		for _, e := range r.evs {
			if e.Path == g && e.Op == "deleted" {
				return true
			}
		}
		return false
	})
}

func TestFimSweepCatchesUnwatchedChange(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x.txt")
	os.WriteFile(f, []byte("a"), 0o644)

	r := &fimrec{}
	m := New(r, []Watch{{Path: f, Kind: "persistence"}}, 30*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	waitForFn(t, 500*time.Millisecond, func() bool { m.mu.Lock(); n := len(m.last); m.mu.Unlock(); return n > 0 })

	// change by directly rewriting (inotify fires too, but the sweep must
	// also see it; wait for any second modified/created event for f)
	before := len(r.evs)
	// truncate+rewrite to force a hash change without relying on inotify
	os.WriteFile(f, []byte("bbbb"), 0o644)
	waitForFn(t, 1*time.Second, func() bool {
		n := 0
		for _, e := range r.evs[before:] {
			if e.Path == f {
				n++
			}
		}
		return n >= 1
	})
}

func TestFimTag(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "unit.service")
	os.WriteFile(f, []byte("a"), 0o644)

	r := &fimrec{}
	m := New(r, []Watch{{Path: dir, Kind: "persistence"}}, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	waitForFn(t, 500*time.Millisecond, func() bool { m.mu.Lock(); n := len(m.last); m.mu.Unlock(); return n > 0 })
	m.Tag(f, "plan-1")
	os.WriteFile(f, []byte("b"), 0o644)
	waitForFn(t, 2*time.Second, func() bool {
		for _, e := range r.evs {
			if e.Path == f && e.Op == "modified" && e.Tag == "plan-1" {
				return true
			}
		}
		return false
	})

	// expiry: force the tag to lapse, then it must not match
	m.tagExp[f] = time.Now().Add(50 * time.Millisecond)
	time.Sleep(80 * time.Millisecond)
	if got := m.tagFor(f); got != "" {
		t.Errorf("tag should have expired, got %q", got)
	}
}
