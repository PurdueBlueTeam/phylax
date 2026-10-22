//go:build !linux

package integrity

import "os"

func fileOwner(os.FileInfo) int { return -1 }
