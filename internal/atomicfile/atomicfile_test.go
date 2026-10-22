package atomicfile

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func noTemps(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}

func TestWriteNewAndReplace(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := WriteFile(p, []byte("one"), 0640); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0640 {
		t.Fatalf("new file mode %v", st.Mode())
	}
	if err := os.Chmod(p, 0604); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p) != "two" {
		t.Fatal("content not replaced")
	}
	st, _ = os.Stat(p)
	if st.Mode().Perm() != 0604 {
		t.Fatalf("existing mode must be preserved, got %v", st.Mode())
	}
	noTemps(t, dir)
}

func TestWriteFailureLeavesOriginal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	os.WriteFile(p, []byte("orig"), 0600)
	boom := errors.New("boom")
	err := Write(p, 0600, func(w io.Writer) error {
		w.Write([]byte("partial"))
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if readFile(t, p) != "orig" {
		t.Fatal("original damaged by failed write")
	}
	noTemps(t, dir)
}

func TestSymlinkTargetReplaced(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	link := filepath.Join(dir, "link")
	os.WriteFile(real, []byte("a"), 0600)
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unsupported:", err)
	}
	if err := WriteFile(link, []byte("b"), 0600); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}
	if readFile(t, real) != "b" {
		t.Fatal("target not updated")
	}
}

func TestDirectoryRejected(t *testing.T) {
	if err := WriteFile(t.TempDir(), []byte("x"), 0600); err == nil {
		t.Fatal("expected error writing over a directory")
	}
}

func TestModify(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	add := func(s string) error {
		return Modify(p, 0600, func(old []byte, exists bool) ([]byte, error) {
			return append(old, s...), nil
		})
	}
	if err := add("a"); err != nil {
		t.Fatal(err)
	}
	if err := add("b"); err != nil {
		t.Fatal(err)
	}
	if readFile(t, p) != "ab" {
		t.Fatalf("got %q", readFile(t, p))
	}
	st1, _ := os.Stat(p)
	err := Modify(p, 0600, func(old []byte, exists bool) ([]byte, error) {
		if !exists || !bytes.Equal(old, []byte("ab")) {
			t.Error("callback saw wrong state")
		}
		return nil, ErrNoChange
	})
	if err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(p)
	if !os.SameFile(st1, st2) {
		t.Fatal("ErrNoChange must not replace the file")
	}
	boom := errors.New("boom")
	if err := Modify(p, 0600, func([]byte, bool) ([]byte, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if readFile(t, p) != "ab" {
		t.Fatal("changed on callback error")
	}
}

func TestModifyConcurrentNoLostUpdates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	var wg sync.WaitGroup
	const n = 40
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := Modify(p, 0600, func(old []byte, _ bool) ([]byte, error) {
				return append(old, 'x'), nil
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := len(readFile(t, p)); got != n {
		t.Fatalf("lost updates: %d of %d", got, n)
	}
}
