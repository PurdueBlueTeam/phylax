//go:build unix

package actions

import (
	"io/fs"
	"syscall"
)

func ownerOf(st fs.FileInfo) (uid, gid int, ok bool) {
	if s, isStat := st.Sys().(*syscall.Stat_t); isStat {
		return int(s.Uid), int(s.Gid), true
	}
	return 0, 0, false
}
