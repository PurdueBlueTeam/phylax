// Package atomicfile replaces files crash-safely: the new content is written to
// a temp file in the same directory, fsynced, given the old file's mode, owner,
// group and security label, renamed over the target, and the directory is
// fsynced. A reader (or a crash) sees either the complete old file or the
// complete new one, never a partial write.
package atomicfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// ErrNoChange can be returned from a Modify callback to leave the file untouched.
var ErrNoChange = errors.New("atomicfile: no change")

// DefaultMaxRead bounds how much Modify reads from the existing file.
const DefaultMaxRead = 64 << 20

// ErrTooLarge is returned by Modify when the existing file exceeds the read bound.
var ErrTooLarge = errors.New("atomicfile: existing file too large")

// Write atomically replaces path with whatever fn writes. If path exists its
// permissions, owner/group and security label are preserved; otherwise the new
// file gets perm. If path is a symlink the link's target is replaced and the
// link is kept. On any error the original file is left untouched and the temp
// file is removed.
func Write(path string, perm fs.FileMode, fn func(w io.Writer) error) (err error) {
	target := path
	if r, rerr := filepath.EvalSymlinks(path); rerr == nil {
		target = r
	}
	dir, base := filepath.Split(target)
	if dir == "" {
		dir = "."
	}

	old, statErr := os.Stat(target)
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return fmt.Errorf("atomicfile: stat %s: %w", target, statErr)
	}
	if statErr == nil && old.IsDir() {
		return fmt.Errorf("atomicfile: %s is a directory", target)
	}

	tmp, err := os.CreateTemp(dir, "."+base+".tmp*")
	if err != nil {
		return fmt.Errorf("atomicfile: create temp: %w", err)
	}
	tmpName := tmp.Name()
	closed := false
	defer func() {
		if err != nil {
			if !closed {
				tmp.Close()
			}
			os.Remove(tmpName)
		}
	}()

	if err = fn(tmp); err != nil {
		return err
	}
	if statErr == nil {
		if err = copyMetadata(target, old, tmp, tmpName); err != nil {
			return fmt.Errorf("atomicfile: preserve metadata of %s: %w", target, err)
		}
	} else {
		if err = tmp.Chmod(perm); err != nil {
			return fmt.Errorf("atomicfile: chmod: %w", err)
		}
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("atomicfile: fsync: %w", err)
	}
	closed = true
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("atomicfile: close: %w", err)
	}
	if err = replace(tmpName, target); err != nil {
		return fmt.Errorf("atomicfile: rename: %w", err)
	}
	if err = syncDir(dir); err != nil {
		// The rename happened; the data is in place but its durability is unknown.
		return fmt.Errorf("atomicfile: fsync dir: %w", err)
	}
	return nil
}

// WriteFile is Write for a byte slice.
func WriteFile(path string, data []byte, perm fs.FileMode) error {
	return Write(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

var (
	locksMu sync.Mutex
	locks   = map[string]*sync.Mutex{}
)

func pathLock(p string) *sync.Mutex {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	locksMu.Lock()
	defer locksMu.Unlock()
	m := locks[p]
	if m == nil {
		m = &sync.Mutex{}
		locks[p] = m
	}
	return m
}

// Modify reads path (exists=false and empty old if it does not exist), passes
// the content to fn, and atomically writes the result. Concurrent Modify calls
// on the same path within this process are serialized; there is no
// cross-process lock, so callers that share a file between processes must
// coordinate (the deadman package does so with its own file lock).
// fn may return ErrNoChange to skip the write; Modify then returns nil.
func Modify(path string, perm fs.FileMode, fn func(old []byte, exists bool) ([]byte, error)) error {
	m := pathLock(path)
	m.Lock()
	defer m.Unlock()

	var old []byte
	exists := true
	f, err := os.Open(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		exists = false
	case err != nil:
		return fmt.Errorf("atomicfile: open %s: %w", path, err)
	default:
		old, err = io.ReadAll(io.LimitReader(f, DefaultMaxRead+1))
		f.Close()
		if err != nil {
			return fmt.Errorf("atomicfile: read %s: %w", path, err)
		}
		if len(old) > DefaultMaxRead {
			return ErrTooLarge
		}
	}
	nw, err := fn(old, exists)
	if errors.Is(err, ErrNoChange) {
		return nil
	}
	if err != nil {
		return err
	}
	return WriteFile(path, nw, perm)
}
