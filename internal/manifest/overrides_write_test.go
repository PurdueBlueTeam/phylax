package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAppendOverridesAtomicAndValidated(t *testing.T) {
	dir := t.TempDir()
	ll := LearnedListener{Host: "h1", Proto: "tcp", Port: 8081, Reason: "scorer traffic seen", Observed: "2027-02-06T15:04:05Z"}
	if err := AppendOverrides(dir, func(o *Overrides) error { o.LearnedListeners = append(o.LearnedListeners, ll); return nil }); err != nil {
		t.Fatal(err)
	}
	// The overrides-only reader of the loader: LoadDir needs topology.yml and
	// hosts.yml, which this directory does not have.
	ov, err := readOverrides(os.DirFS(dir))
	if err != nil || len(ov.LearnedListeners) != 1 || ov.LearnedListeners[0] != ll {
		t.Fatalf("%+v %v", ov, err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, FileOverrides))
	bad := ll
	bad.Reason = ""
	if err := AppendOverrides(dir, func(o *Overrides) error { o.LearnedListeners = append(o.LearnedListeners, bad); return nil }); err == nil {
		t.Fatal("entry without a reason accepted")
	}
	after, _ := os.ReadFile(filepath.Join(dir, FileOverrides))
	if !bytes.Equal(before, after) {
		t.Fatal("a rejected write changed the file")
	}
}

func TestAppendOverridesFnErrorLeavesFile(t *testing.T) {
	dir := t.TempDir()
	want := errors.New("no")
	if err := AppendOverrides(dir, func(*Overrides) error { return want }); !errors.Is(err, want) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileOverrides)); !os.IsNotExist(err) {
		t.Fatal("file created after a failed fn")
	}
}

func TestAppendOverridesKeepsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileOverrides)
	if err := os.WriteFile(path, []byte("overrides: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil { // umask-independent
		t.Fatal(err)
	}
	if err := AppendOverrides(dir, func(o *Overrides) error {
		o.AdoptedDrift = append(o.AdoptedDrift, OverrideEntry{Subject: "h1"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("existing file mode %o", st.Mode().Perm())
	}

	fresh := t.TempDir()
	if err := AppendOverrides(fresh, func(*Overrides) error { return nil }); err != nil {
		t.Fatal(err)
	}
	st, err = os.Stat(filepath.Join(fresh, FileOverrides))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode %o", st.Mode().Perm())
	}
}

func TestAppendOverridesConcurrent(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			ll := LearnedListener{Host: "h1", Proto: "tcp", Port: port, Reason: "learned", Observed: "2027-02-06T15:04:05Z"}
			if err := AppendOverrides(dir, func(o *Overrides) error {
				o.LearnedListeners = append(o.LearnedListeners, ll)
				return nil
			}); err != nil {
				t.Error(err)
			}
		}(uint16(8000 + i))
	}
	wg.Wait()
	ov, err := readOverrides(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(ov.LearnedListeners) != 20 {
		t.Fatalf("%d entries, want 20: %s", len(ov.LearnedListeners), fmt.Sprint(ov.LearnedListeners))
	}
}
