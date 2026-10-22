//go:build linux

package depot

import (
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// prepareExec points cmd at a sealed in-memory copy of the verified bytes. The
// child sees it as fd 3 and execs /proc/self/fd/3; if memfd is unavailable it
// falls back to the on-disk path.
func prepareExec(cmd *exec.Cmd, path string, content []byte) (func(), error) {
	fd, err := unix.MemfdCreate("t", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		cmd.Path = path
		return func() {}, nil
	}
	f := os.NewFile(uintptr(fd), "memfd")
	if _, err := f.Write(content); err != nil {
		f.Close()
		cmd.Path = path
		return func() {}, nil
	}
	_, _ = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL)
	cmd.Path = "/proc/self/fd/3"
	cmd.ExtraFiles = []*os.File{f}
	return func() { f.Close() }, nil
}
