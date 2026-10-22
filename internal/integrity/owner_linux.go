//go:build linux

package integrity

import (
	"os"
	"syscall"
)

func fileOwner(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}
