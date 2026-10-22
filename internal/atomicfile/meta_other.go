//go:build !linux && !windows

package atomicfile

import (
	"io/fs"
	"os"
	"syscall"
)

func copyMetadata(target string, old fs.FileInfo, tmp *os.File, tmpName string) error {
	if st, ok := old.Sys().(*syscall.Stat_t); ok {
		_ = tmp.Chown(int(st.Uid), int(st.Gid)) // best effort
	}
	return tmp.Chmod(old.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky))
}

func replace(from, to string) error { return os.Rename(from, to) }

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
