package manifest

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendOverridesAtomicAndValidated(t *testing.T) {
	t.Skip("unimplemented: W1 Task 11a")
	dir := t.TempDir()
	ll := LearnedListener{Host: "h1", Proto: "tcp", Port: 8081, Reason: "scorer traffic seen", Observed: "2027-02-06T15:04:05Z"}
	if err := AppendOverrides(dir, func(o *Overrides) error { o.LearnedListeners = append(o.LearnedListeners, ll); return nil }); err != nil {
		t.Fatal(err)
	}
	m, err := LoadDir(dir, Options{})
	if err != nil || len(m.Overrides.LearnedListeners) != 1 || m.Overrides.LearnedListeners[0] != ll {
		t.Fatalf("%+v %v", m.Overrides, err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "overrides.yml"))
	bad := ll
	bad.Reason = ""
	if err := AppendOverrides(dir, func(o *Overrides) error { o.LearnedListeners = append(o.LearnedListeners, bad); return nil }); err == nil {
		t.Fatal("entry without a reason accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "overrides.yml"))
	if !bytes.Equal(before, after) {
		t.Fatal("a rejected write changed the file")
	}
}

func TestAppendOverridesFnErrorLeavesFile(t *testing.T) {
	t.Skip("unimplemented: W1 Task 11a")
	dir := t.TempDir()
	want := errors.New("no")
	if err := AppendOverrides(dir, func(*Overrides) error { return want }); !errors.Is(err, want) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "overrides.yml")); !os.IsNotExist(err) {
		t.Fatal("file created after a failed fn")
	}
}

func TestAppendOverridesKeepsMode(t *testing.T) {
	t.Skip("unimplemented: W1 Task 11a")
	// existing overrides.yml mode 0600 stays 0600; a new file is 0600
}

func TestAppendOverridesConcurrent(t *testing.T) {
	t.Skip("unimplemented: W1 Task 11a")
	// 20 goroutines each append one distinct LearnedListener port; afterwards the file holds 20 entries (race-clean)
}
