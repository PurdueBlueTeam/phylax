package logsmod

import (
	"context"
	"os"
	"regexp"
	"testing"
	"time"
)

type logrec struct {
	lines   []LogEvent
	cleared []ClearedEvent
}

func (r *logrec) LogLine(e LogEvent)       { r.lines = append(r.lines, e) }
func (r *logrec) LogCleared(e ClearedEvent) { r.cleared = append(r.cleared, e) }

func TestLogTailAndClear(t *testing.T) {
	f := t.TempDir() + "/auth.log"
	os.WriteFile(f, []byte("old line\n"), 0o644)

	r := &logrec{}
	m := New(r, []Watch{{File: f, Pattern: regexp.MustCompile("accepted|failed")}})
	m.interval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	time.Sleep(60 * time.Millisecond) // baseline: existing line not emitted

	// append matching and non-matching lines
	fh, _ := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0o644)
	fh.WriteString("Jan 1 00:00:00 sshd: accepted publickey for alice\nnoise line\n")
	fh.WriteString("Jan 1 00:00:01 sshd: failed password for bob\n")
	fh.Close()

	deadline := time.Now().Add(2 * time.Second)
	for len(r.lines) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(r.lines) != 2 {
		t.Fatalf("want 2 lines, got %v", r.lines)
	}
	if r.lines[0].Line != "Jan 1 00:00:00 sshd: accepted publickey for alice" {
		t.Errorf("line 0: %q", r.lines[0].Line)
	}

	// truncate: log clear
	os.WriteFile(f, []byte(""), 0o644)
	deadline = time.Now().Add(2 * time.Second)
	for len(r.cleared) < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(r.cleared) < 1 || r.cleared[0].Op != "truncated" {
		t.Fatalf("want 1 truncated, got %v", r.cleared)
	}

	// after the clear, new lines are read from zero
	fh, _ = os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0o644)
	fh.WriteString("Jan 1 00:00:02 sshd: accepted password for carol\n")
	fh.Close()
	deadline = time.Now().Add(2 * time.Second)
	for len(r.lines) < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(r.lines) < 3 || r.lines[2].Line != "Jan 1 00:00:02 sshd: accepted password for carol" {
		t.Fatalf("post-clear line missing: %v", r.lines)
	}
}

func TestPartialLineHeld(t *testing.T) {
	f := t.TempDir() + "/syslog"
	os.WriteFile(f, []byte(""), 0o644)

	r := &logrec{}
	m := New(r, []Watch{{File: f}})
	m.interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	time.Sleep(50 * time.Millisecond)

	// write without a trailing newline: must not be emitted yet
	fh, _ := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0o644)
	fh.WriteString("partial")
	fh.Close()
	time.Sleep(80 * time.Millisecond)
	if len(r.lines) != 0 {
		t.Fatalf("partial line emitted early: %v", r.lines)
	}
	// finish the line
	fh, _ = os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0o644)
	fh.WriteString(" done\n")
	fh.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(r.lines) < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(r.lines) != 1 || r.lines[0].Line != "partial done" {
		t.Fatalf("want 'partial done', got %v", r.lines)
	}
}
