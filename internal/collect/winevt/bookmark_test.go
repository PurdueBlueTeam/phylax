package winevt

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBookmarkPersistRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "bm.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := OpenBookmarks(p, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.Set("Security", "<BookmarkList>sec</BookmarkList>")
	s.Set("System", "<BookmarkList>sys</BookmarkList>")
	if err := s.SaveIfDue(); err != nil { // lastSave is zero so the first save is due
		t.Fatal(err)
	}
	s.Set("System", "<BookmarkList>sys2</BookmarkList>")
	if err := s.SaveIfDue(); err != nil { // within the interval: no write
		t.Fatal(err)
	}
	r, _ := OpenBookmarks(p, time.Hour)
	if r.Get("System") != "<BookmarkList>sys</BookmarkList>" {
		t.Fatalf("SaveIfDue wrote inside the interval: %q", r.Get("System"))
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenBookmarks(p, time.Hour)
	if err != nil || r.Get("Security") != "<BookmarkList>sec</BookmarkList>" || r.Get("System") != "<BookmarkList>sys2</BookmarkList>" {
		t.Fatalf("%v %q %q", err, r.Get("Security"), r.Get("System"))
	}
	s.Clear("Security")
	_ = s.Flush()
	r, _ = OpenBookmarks(p, time.Hour)
	if r.Get("Security") != "" || r.Get("System") == "" {
		t.Fatal("Clear not persisted")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Fatalf("bookmark file mode %v", fi.Mode())
	}
}

func TestBookmarkCorruptFileMovedAside(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bm.json")
	_ = os.WriteFile(p, []byte("{not json"), 0o600)
	s, err := OpenBookmarks(p, 0)
	if err == nil {
		t.Fatal("expected error for corrupt file")
	}
	if s == nil || s.Get("Security") != "" {
		t.Fatal("store must still be usable")
	}
	if _, err := os.Stat(p + ".corrupt"); err != nil {
		t.Fatal("corrupt file not preserved:", err)
	}
	s.Set("Security", "x")
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestBookmarkMissingFileIsEmpty(t *testing.T) {
	s, err := OpenBookmarks(filepath.Join(t.TempDir(), "none.json"), 0)
	if err != nil || s.Get("x") != "" {
		t.Fatal(err)
	}
}

func TestBookmarkUnknownVersionRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bm.json")
	_ = os.WriteFile(p, []byte(`{"version":9,"bookmarks":{"Security":"x"}}`), 0o600)
	s, err := OpenBookmarks(p, 0)
	if err == nil || s.Get("Security") != "" {
		t.Fatal("future-version file must not be trusted")
	}
}
