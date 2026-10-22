//go:build linux

package integrity

import (
	"os"
	"syscall"
)

// idOf returns the identity used to key the hash cache: device, inode, ctime
// and size. ctime cannot be set by userland, unlike mtime, so a swapped file
// invalidates its entry even if the attacker restores mtime.
func idOf(fi os.FileInfo, _ string) fileID {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{Size: fi.Size(), CtimeNs: fi.ModTime().UnixNano(), Path: "?"}
	}
	return fileID{Dev: uint64(st.Dev), Ino: st.Ino, CtimeNs: st.Ctim.Nano(), Size: fi.Size()}
}
