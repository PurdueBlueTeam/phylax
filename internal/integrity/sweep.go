package integrity

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultSweepRoots are the Linux system paths swept every 15 minutes.
var DefaultSweepRoots = []string{
	"/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/lib", "/usr/lib64",
	"/usr/local/bin", "/usr/local/sbin", "/usr/local/lib",
	"/bin", "/sbin", "/lib", "/lib64", // symlinks on merged-usr hosts; skipped there
}

// SweepOptions control a sweep.
type SweepOptions struct {
	Roots []string // default DefaultSweepRoots
	// BytesPerSec throttles hashing (0 = unthrottled). Sweeps are low
	// priority and rate-limited.
	BytesPerSec int64
	// FullRehash bypasses the identity cache and re-hashes everything (the
	// slower cadence, so a rootkit that forges dev/inode/ctime/size is
	// eventually caught).
	FullRehash bool
	// AllFiles also judges non-executable, non-library files.
	AllFiles bool
	MaxFiles int // 0 = unlimited
}

// SweepStats summarises a sweep.
type SweepStats struct {
	Files, Hashed, CacheHits int
	Bytes                    int64
	Verdicts                 map[Verdict]int
	Errors                   int
}

func sweepWanted(path string, fi fs.FileInfo, all bool) bool {
	if !fi.Mode().IsRegular() {
		return false
	}
	if all || fi.Mode()&0o111 != 0 || fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return true
	}
	n := filepath.Base(path)
	return strings.Contains(n, ".so") || strings.HasSuffix(n, ".ko") || strings.HasSuffix(n, ".ko.xz") || strings.HasSuffix(n, ".ko.zst")
}

// Sweep walks the roots, hashing only files whose identity changed (unless
// FullRehash) and judging every wanted file; alerting verdicts are emitted. It
// does not follow symlinks and never modifies anything.
func (c *Checker) Sweep(ctx context.Context, opt SweepOptions) (SweepStats, error) {
	st := SweepStats{Verdicts: map[Verdict]int{}}
	roots := opt.Roots
	if len(roots) == 0 {
		roots = DefaultSweepRoots
	}
	var debt time.Duration
	last := time.Now()
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err2 := ctx.Err(); err2 != nil {
				return err2
			}
			if err != nil {
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				st.Errors++
				return nil
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			fi, err := d.Info()
			if err != nil || !sweepWanted(path, fi, opt.AllFiles) {
				return nil
			}
			if opt.MaxFiles > 0 && st.Files >= opt.MaxFiles {
				return filepath.SkipAll
			}
			f, err := os.Open(path)
			if err != nil {
				st.Errors++
				return nil
			}
			h, err := c.hashOpen(ctx, f, path, opt.FullRehash)
			f.Close()
			if err != nil {
				st.Errors++
				return nil
			}
			st.Files++
			if h.Cached {
				st.CacheHits++
			} else {
				st.Hashed++
				st.Bytes += h.Size
				if opt.BytesPerSec > 0 {
					debt += time.Duration(float64(h.Size) / float64(opt.BytesPerSec) * float64(time.Second))
					debt -= time.Since(last)
					last = time.Now()
					if debt > 20*time.Millisecond {
						t := time.NewTimer(debt)
						select {
						case <-ctx.Done():
							t.Stop()
							return ctx.Err()
						case <-t.C:
						}
						debt = 0
						last = time.Now()
					} else if debt < 0 {
						debt = 0
					}
				}
			}
			r := c.judge(ctx, path, h)
			st.Verdicts[r.Verdict]++
			c.emit(r, Context{Trigger: TriggerSweep, UID: -1}, nil, nil)
			return nil
		})
		if err != nil && ctx.Err() != nil {
			return st, ctx.Err()
		}
	}
	return st, nil
}
