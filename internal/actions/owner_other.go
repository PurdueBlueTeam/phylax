//go:build !unix

package actions

import "io/fs"

func ownerOf(fs.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
