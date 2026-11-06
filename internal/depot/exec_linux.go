//go:build linux

package depot

import (
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// prepareExec points cmd at a copy of the verified bytes. The preferred copy
// is a sealed memfd, which the child sees as fd 3 and execs through
// /proc/self/fd/3: nothing on disk can be swapped in between the hash check and
// the exec. Execve through /proc is refused when procfs is mounted noexec (the
// default in containers and on hardened hosts), and memfd may be unavailable,
// so in those cases the bytes are copied to a private file in the depot
// directory (0700 dir, 0500 file); that copy is as immutable to the caller as
// the memfd, only slower.
func prepareExec(cmd *exec.Cmd, path, execDir string, content []byte) (func(), error) {
	if procIsExecutable() {
		if cleanup, err := prepareExecMemfd(cmd, content); err == nil {
			return cleanup, nil
		}
	}
	return prepareExecCopy(cmd, execDir, content)
}

// prepareExecMemfd runs content from a sealed in-memory file. The caller's
// cleanup closes the parent's copy; the child holds its own until it execs.
func prepareExecMemfd(cmd *exec.Cmd, content []byte) (func(), error) {
	fd, err := unix.MemfdCreate("t", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "memfd")
	if _, err := f.Write(content); err != nil {
		f.Close()
		return nil, err
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		f.Close()
		return nil, err
	}
	cmd.Path = "/proc/self/fd/3"
	cmd.ExtraFiles = []*os.File{f}
	return func() { f.Close() }, nil
}

// procIsExecutable reports whether a memfd can be executed through
// /proc/self/fd, that is, whether the procfs mount is not noexec.
func procIsExecutable() bool {
	var st unix.Statfs_t
	if err := unix.Statfs("/proc/self/fd", &st); err != nil {
		return false
	}
	return st.Flags&unix.MS_NOEXEC == 0
}
