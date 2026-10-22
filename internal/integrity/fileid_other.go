//go:build !linux

package integrity

import "os"

// idOf has no inode/ctime source here; the path and mtime stand in. Windows
// hashing is driven by Sysmon events, not this cache.
func idOf(fi os.FileInfo, path string) fileID {
	return fileID{Size: fi.Size(), CtimeNs: fi.ModTime().UnixNano(), Path: path}
}
