//go:build linux

package atomicfile

import (
	"errors"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// labelXattr is the SELinux label attribute. A variable so tests can exercise
// the copy path with an attribute any user may set.
var labelXattr = "security.selinux"

func copyMetadata(target string, old fs.FileInfo, tmp *os.File, tmpName string) error {
	if st, ok := old.Sys().(*syscall.Stat_t); ok {
		if err := tmp.Chown(int(st.Uid), int(st.Gid)); err != nil && !errors.Is(err, fs.ErrPermission) {
			return err
		} else if err != nil {
			// Unprivileged: we can only keep ownership if it already matches.
			if int(st.Uid) != os.Getuid() {
				return err
			}
			if gerr := tmp.Chown(-1, int(st.Gid)); gerr != nil && int(st.Gid) != os.Getgid() {
				return gerr
			}
		}
	}
	// Chmod after Chown: chown clears setuid/setgid bits.
	if err := tmp.Chmod(old.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)); err != nil {
		return err
	}
	return copyLabel(target, tmpName)
}

func copyLabel(from, to string) error {
	buf := make([]byte, 512)
	for {
		n, err := unix.Lgetxattr(from, labelXattr, buf)
		if errors.Is(err, unix.ERANGE) {
			buf = make([]byte, len(buf)*4)
			continue
		}
		if err != nil {
			if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
				return nil // no label, or no xattr support on this filesystem
			}
			return err
		}
		if err := unix.Lsetxattr(to, labelXattr, buf[:n], 0); err != nil && !errors.Is(err, unix.ENOTSUP) {
			return err
		}
		return nil
	}
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
