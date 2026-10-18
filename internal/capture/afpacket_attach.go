//go:build linux

package capture

import (
	"golang.org/x/sys/unix"
)

// setsockoptAttachFilter installs a compiled BPF program as the
// socket's RX filter (kernel-side, before userspace).
func setsockoptAttachFilter(fd int, prog []unix.SockFilter) error {
	if len(prog) == 0 {
		return nil
	}
	fprog := &unix.SockFprog{Len: uint16(len(prog))}
	// SockFprog.Filter is *SockFilter; point it at the program array.
	fprog.Filter = &prog[0]
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, fprog)
}
