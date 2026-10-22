//go:build linux

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// FileState is one snapshot entry.
type FileState struct {
	Size   int64
	Mtime  int64 // unix nanoseconds
	Mode   uint32
	UID    uint32
	GID    uint32
	Hash   string // sha256 hex; empty for dirs, symlinks, unreadable or oversized files
	Target string // symlink target
	IsDir  bool
}

// Snapshot maps absolute path to state.
type Snapshot map[string]FileState

// SweepOptions bound one snapshot.
type SweepOptions struct {
	Depth        int
	MaxEntries   int
	HashMaxBytes int64
	FilesPerSec  int
	Exclude      []string // path prefixes skipped
}

// ChangeKind classifies a sweep diff.
type ChangeKind string

const (
	Created  ChangeKind = "create"
	Deleted  ChangeKind = "delete"
	Modified ChangeKind = "modify"
	AttrOnly ChangeKind = "attr"
)

// Change is one difference between two snapshots.
type Change struct {
	Path    string
	Kind    ChangeKind
	Old     *FileState
	New     *FileState
	Content bool // content differs (hash, or size/mtime when unhashed)
}

type throttle struct {
	perSec int
	n      int
	last   time.Time
}

// wait spends one unit; every perSec/10 units it sleeps 100 ms so that the
// long-run rate is perSec, without a timer per file.
func (t *throttle) wait(ctx context.Context) error {
	if t.perSec <= 0 {
		return ctx.Err()
	}
	t.n++
	batch := t.perSec / 10
	if batch < 1 {
		batch = 1
	}
	if t.n >= batch {
		t.n = 0
		d := time.Second * time.Duration(batch) / time.Duration(t.perSec)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	return ctx.Err()
}

func hasPrefixPath(p, prefix string) bool {
	prefix = strings.TrimRight(prefix, "/")
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// TakeSnapshot walks roots (files or directories) and records state. It never
// follows symlinks, reads at most HashMaxBytes per file and is throttled.
func TakeSnapshot(ctx context.Context, roots []string, o SweepOptions) (Snapshot, error) {
	snap := Snapshot{}
	th := &throttle{perSec: o.FilesPerSec}
	for _, root := range roots {
		root = filepath.Clean(root)
		rootDepth := strings.Count(root, string(filepath.Separator))
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil // vanished or unreadable: the next sweep sees it
			}
			for _, ex := range o.Exclude {
				if hasPrefixPath(p, ex) {
					if d.IsDir() {
						return fs.SkipDir
					}
					return nil
				}
			}
			if d.IsDir() && o.Depth > 0 && strings.Count(p, string(filepath.Separator))-rootDepth >= o.Depth {
				return fs.SkipDir
			}
			if len(snap) >= o.MaxEntries && o.MaxEntries > 0 {
				return fs.SkipAll
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			fsx := FileState{Size: info.Size(), Mtime: info.ModTime().UnixNano(),
				Mode: uint32(info.Mode()), IsDir: info.IsDir()}
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				fsx.UID, fsx.GID = st.Uid, st.Gid
			}
			switch {
			case info.Mode()&fs.ModeSymlink != 0:
				fsx.Target, _ = os.Readlink(p)
			case info.Mode().IsRegular():
				if err := th.wait(ctx); err != nil {
					return err
				}
				if info.Size() <= o.HashMaxBytes {
					fsx.Hash = hashFile(p, o.HashMaxBytes)
				}
			}
			snap[p] = fsx
			return nil
		})
		if err != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return snap, nil
}

func hashFile(p string, max int64) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, max)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Diff lists the differences from old to cur, sorted by path. Directory mtime
// churn is ignored (a changed child shows as its own entry).
func Diff(old, cur Snapshot) []Change {
	var out []Change
	for p, n := range cur {
		o, ok := old[p]
		if !ok {
			nn := n
			out = append(out, Change{Path: p, Kind: Created, New: &nn, Content: true})
			continue
		}
		if o == n {
			continue
		}
		oo, nn := o, n
		var content bool
		switch {
		case o.IsDir != n.IsDir || o.Target != n.Target:
			content = true
		case o.IsDir:
			content = false
		case o.Hash != "" && n.Hash != "":
			content = o.Hash != n.Hash
		default:
			content = o.Size != n.Size || o.Mtime != n.Mtime
		}
		perm := o.Mode != n.Mode || o.UID != n.UID || o.GID != n.GID
		switch {
		case content:
			out = append(out, Change{Path: p, Kind: Modified, Old: &oo, New: &nn, Content: true})
		case perm:
			out = append(out, Change{Path: p, Kind: AttrOnly, Old: &oo, New: &nn})
		}
	}
	for p, o := range old {
		if _, ok := cur[p]; !ok {
			oo := o
			out = append(out, Change{Path: p, Kind: Deleted, Old: &oo, Content: true})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
