// Package gotools holds Go-native mini versions of the most critical
// inspection tools (ps, ss, ls, hash, lsof). They read /proc and netlink
// directly and never execute or link against host tools, for when even a
// static depot binary cannot be copied onto a host.
package gotools

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FileInfo is one directory entry with the fields that matter in a response.
type FileInfo struct {
	Name   string
	Mode   fs.FileMode
	Size   int64
	UID    uint32
	GID    uint32
	Inode  uint64
	MTime  time.Time
	Target string // symlink target
}

// List lists a directory (or stats a single non-directory path), sorted by
// name, using lstat so symlinks are shown rather than followed. Hidden files
// are always included: hiding is what the attacker does.
func List(path string) ([]FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return []FileInfo{info(filepath.Dir(path), fi)}, nil
	}
	ents, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := make([]FileInfo, 0, len(ents))
	for _, de := range ents {
		fi, err := os.Lstat(filepath.Join(path, de.Name()))
		if err != nil {
			continue
		}
		out = append(out, info(path, fi))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func info(dir string, fi fs.FileInfo) FileInfo {
	f := FileInfo{Name: fi.Name(), Mode: fi.Mode(), Size: fi.Size(), MTime: fi.ModTime()}
	f.UID, f.GID, f.Inode = owner(fi)
	if fi.Mode()&fs.ModeSymlink != 0 {
		f.Target, _ = os.Readlink(filepath.Join(dir, fi.Name()))
	}
	return f
}

// FormatLS renders entries like ls -lai.
func FormatLS(w io.Writer, fs []FileInfo) {
	for _, f := range fs {
		name := f.Name
		if f.Target != "" {
			name += " -> " + f.Target
		}
		fmt.Fprintf(w, "%8d %s %5d %5d %10d %s %s\n", f.Inode, f.Mode, f.UID, f.GID, f.Size, f.MTime.Format("2006-01-02 15:04:05"), name)
	}
}

// HashFile returns the hex sha256 of a file.
func HashFile(path string) (string, error) {
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

// Hash writes "sha256  path" lines (sha256sum format); it returns the first error
// but keeps going.
func Hash(w io.Writer, paths []string) error {
	var first error
	for _, p := range paths {
		s, err := HashFile(p)
		if err != nil {
			if first == nil {
				first = err
			}
			fmt.Fprintf(w, "%s  %s: %v\n", strings.Repeat("?", 64), p, err)
			continue
		}
		fmt.Fprintf(w, "%s  %s\n", s, p)
	}
	return first
}
