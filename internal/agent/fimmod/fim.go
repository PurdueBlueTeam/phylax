// Package fimmod is the agent's `fim` module (docs: Modules): file
// changes on persistence paths, content roots and configs. It uses
// inotify for the live watch plus a periodic hash sweep (catches changes
// inotify missed and files that reappeared). It also answers "is this
// change ours?": the exec module tags paths a plan just wrote, so
// detections can separate our changes from anyone else's.
package fimmod

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// FileEvent is one file event.
type FileEvent struct {
	Path   string `json:"path"`
	Op     string `json:"op"` // created | modified | deleted | moved_from | moved_to
	Kind   string `json:"kind,omitempty"`  // persistence | content | config | log
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Tag    string `json:"tag,omitempty"` // plan id if the agent itself made the change
}

// Sink receives file events.
type Sink interface {
	FileChange(FileEvent)
}

// Watch is one watched path (file or directory).
type Watch struct {
	Path string
	Kind string // persistence | content | config | log
}

// Module watches a set of paths.
type Module struct {
	sink    Sink
	watches []Watch
	sweep   time.Duration // hash sweep period; 0 disables

	mu      sync.Mutex
	wd2dir  map[int]string   // inotify wd -> watched directory
	dirKind map[string]string
	byName  map[string]string // basename -> watched directory (for single-file watches)
	last    map[string]string // path -> sha256 at last sweep
	tagExp  map[string]time.Time
	tagVal  map[string]string
}

// New builds the module.
func New(sink Sink, watches []Watch, sweep time.Duration) *Module {
	return &Module{
		sink: sink, watches: watches, sweep: sweep,
		wd2dir: map[int]string{}, dirKind: map[string]string{}, byName: map[string]string{},
		last: map[string]string{}, tagExp: map[string]time.Time{}, tagVal: map[string]string{},
	}
}

// Tag marks a path as recently changed by our own plan (for the given
// plan id). The tag expires quickly: a red team overwriting our file
// moments later is not ours.
func (m *Module) Tag(path, planID string) {
	c := filepath.Clean(path)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tagExp[c] = time.Now().Add(30 * time.Second)
	m.tagVal[c] = planID
}

func (m *Module) tagFor(path string) string {
	c := filepath.Clean(path)
	m.mu.Lock()
	defer m.mu.Unlock()
	if exp, ok := m.tagExp[c]; ok {
		if time.Now().Before(exp) {
			return m.tagVal[c]
		}
		delete(m.tagExp, c)
		delete(m.tagVal, c)
	}
	return ""
}

// Run starts the inotify loop and the hash sweep until ctx is done.
func (m *Module) Run(ctx context.Context) error {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return fmt.Errorf("inotify: %w", err)
	}
	defer unix.Close(fd)

	mask := uint32(unix.IN_CREATE | unix.IN_MODIFY | unix.IN_DELETE |
		unix.IN_MOVED_FROM | unix.IN_MOVED_TO)
	for _, w := range m.watches {
		dir, base := w.Path, ""
		if fi, err := os.Stat(w.Path); err == nil && !fi.IsDir() {
			dir, base = filepath.Dir(w.Path), filepath.Base(w.Path)
		}
		if wd, err := unix.InotifyAddWatch(fd, dir, mask); err == nil {
			m.wd2dir[wd] = dir
			m.dirKind[dir] = w.Kind
			if base != "" {
				m.byName[dir+"\x00"+base] = w.Path
			}
		}
	}

	m.sweepHashes()
	errCh := make(chan error, 1)
	go func() { errCh <- m.eventLoop(ctx, fd) }()
	if m.sweep > 0 {
		go func() { errCh <- m.sweepLoop(ctx) }()
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

// eventLoop reads inotify events.
func (m *Module) eventLoop(ctx context.Context, fd int) error {
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, unix.EINTR) {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return err
		}
		off := 0
		for n >= 4 {
			if n < 16 {
				break
			}
			wd := int(uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24)
			mask := uint32(buf[4]) | uint32(buf[5])<<8 | uint32(buf[6])<<16 | uint32(buf[7])<<24
			cookie := uint32(buf[8]) | uint32(buf[9])<<8 | uint32(buf[10])<<16 | uint32(buf[11])<<24
			_ = cookie
			l := int(uint32(buf[12]) | uint32(buf[13])<<8 | uint32(buf[14])<<16 | uint32(buf[15])<<24)
			if l == 0 || 16+l > n {
				break
			}
			name := trimNUL(string(buf[16 : 16+l]))
			off += 16 + l
			n -= 16 + l
			m.handle(wd, mask, name)
		}
	}
}


func trimNUL(s string) string {
	for len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return s
}

// handle converts one inotify event into a FileEvent.
func (m *Module) handle(wd int, mask uint32, name string) {
	dir, ok := m.wd2dir[wd]
	if !ok {
		return
	}
	full := filepath.Join(dir, name)
	if p, ok := m.byName[dir+"\x00"+name]; ok {
		full = p
	}
	var op string
	switch {
	case mask&unix.IN_CREATE != 0:
		op = "created"
	case mask&unix.IN_MODIFY != 0:
		op = "modified"
	case mask&unix.IN_DELETE != 0 || mask&unix.IN_DELETE_SELF != 0:
		op = "deleted"
	case mask&unix.IN_MOVED_FROM != 0:
		op = "moved_from"
	case mask&unix.IN_MOVED_TO != 0:
		op = "moved_to"
	default:
		return
	}
	ev := FileEvent{Path: full, Op: op, Kind: m.dirKind[dir], Tag: m.tagFor(full)}
	if op == "created" || op == "modified" || op == "moved_to" {
		if fi, err := os.Stat(full); err == nil {
			ev.Size = fi.Size()
		}
		if h, err := hashFile(full); err == nil {
			ev.SHA256 = h
		}
	}
	m.sink.FileChange(ev)
}

// sweepLoop re-hashes everything on the watch list periodically.
func (m *Module) sweepLoop(ctx context.Context) error {
	t := time.NewTicker(m.sweep)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			m.sweepHashes()
		}
	}
}

// sweepHashes hashes every watched file and emits modified events for
// anything whose digest changed since the last sweep.
func (m *Module) sweepHashes() {
	paths := m.watchedFiles()
	now := map[string]string{}
	for _, p := range paths {
		h, err := hashFile(p)
		if err != nil {
			continue
		}
		now[p] = h
		if old, ok := m.last[p]; ok && old != h {
			kind := ""
			for dir, k := range m.dirKind {
				if strings.HasPrefix(p, dir) {
					kind = k
					break
				}
			}
			ev := FileEvent{Path: p, Op: "modified", Kind: kind, Tag: m.tagFor(p)}
			if fi, err := os.Stat(p); err == nil {
				ev.Size = fi.Size()
			}
			ev.SHA256 = h
			m.sink.FileChange(ev)
		}
	}
	m.last = now
}

func (m *Module) watchedFiles() []string {
	var out []string
	seen := map[string]bool{}
	for _, w := range m.watches {
		fi, err := os.Stat(w.Path)
		if err != nil {
			continue
		}
		if !fi.IsDir() {
			if !seen[w.Path] {
				out = append(out, w.Path)
				seen[w.Path] = true
			}
			continue
		}
		_ = filepath.Walk(w.Path, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !seen[p] {
				out = append(out, p)
				seen[p] = true
			}
			return nil
		})
	}
	return out
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
