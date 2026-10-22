package winevt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
)

// BookmarkStore persists one opaque bookmark (EvtRender bookmark XML) per
// channel in a JSON file, written atomically. A bookmark is stored only after
// the events it covers were handed to the agent's spool, so a restart can
// repeat the last in-flight events after a crash (at-least-once) but never
// skips any; after a clean stop it neither repeats nor loses events.
type BookmarkStore struct {
	path     string
	interval time.Duration

	mu       sync.Mutex
	m        map[string]string
	dirty    bool
	lastSave time.Time
	now      func() time.Time
}

type bookmarkFile struct {
	Version   int               `json:"version"`
	Bookmarks map[string]string `json:"bookmarks"`
}

// OpenBookmarks loads path (missing is fine). A corrupt file is moved aside to
// path+".corrupt" and an empty store is returned with the error so the caller
// can record a telemetry gap; the store is still usable.
func OpenBookmarks(path string, saveInterval time.Duration) (*BookmarkStore, error) {
	s := &BookmarkStore{path: path, interval: saveInterval, m: map[string]string{}, now: time.Now}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("winevt: read bookmarks: %w", err)
	}
	var f bookmarkFile
	if err := json.Unmarshal(b, &f); err != nil || f.Version != 1 {
		_ = os.Rename(path, path+".corrupt")
		return s, fmt.Errorf("winevt: bookmark file %s unreadable (moved aside): %v", path, err)
	}
	for k, v := range f.Bookmarks {
		s.m[k] = v
	}
	return s, nil
}

// Get returns the bookmark for a channel ("" if none).
func (s *BookmarkStore) Get(channel string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[channel]
}

// Set records a bookmark; it is written to disk when SaveIfDue/Flush runs.
func (s *BookmarkStore) Set(channel, bookmark string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[channel] != bookmark {
		s.m[channel] = bookmark
		s.dirty = true
	}
}

// Clear drops a channel's bookmark (stale after a log clear).
func (s *BookmarkStore) Clear(channel string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[channel]; ok {
		delete(s.m, channel)
		s.dirty = true
	}
}

// SaveIfDue writes the file when dirty and the save interval has passed.
func (s *BookmarkStore) SaveIfDue() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty || s.now().Sub(s.lastSave) < s.interval {
		return nil
	}
	return s.saveLocked()
}

// Flush writes the file if dirty, regardless of the interval.
func (s *BookmarkStore) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	return s.saveLocked()
}

func (s *BookmarkStore) saveLocked() error {
	b, err := json.Marshal(bookmarkFile{Version: 1, Bookmarks: s.m})
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(s.path, b, 0o600); err != nil {
		return fmt.Errorf("winevt: save bookmarks: %w", err)
	}
	s.dirty, s.lastSave = false, s.now()
	return nil
}
