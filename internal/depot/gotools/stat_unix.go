//go:build !windows

package gotools

import (
	"io/fs"
	"syscall"
)

func owner(fi fs.FileInfo) (uid, gid uint32, ino uint64) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid, st.Gid, uint64(st.Ino)
	}
	return
}
