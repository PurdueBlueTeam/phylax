//go:build windows

package gotools

import "io/fs"

func owner(fs.FileInfo) (uid, gid uint32, ino uint64) { return }
