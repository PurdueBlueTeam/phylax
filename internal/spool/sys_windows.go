//go:build windows

package spool

import (
	"fmt"
	"syscall"
)

type dirLock struct{ h syscall.Handle }

// lockDir opens the lock file with a zero share mode, which makes the open
// exclusive for as long as the handle lives (and is released if we crash).
func lockDir(path string) (*dirLock, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("spool: directory in use by another process: %w", err)
	}
	return &dirLock{h}, nil
}

func (l *dirLock) unlock() error { return syscall.CloseHandle(l.h) }

// syncDir is a no-op: NTFS journals directory metadata and Windows cannot
// fsync a directory handle through the os package.
func syncDir(string) error { return nil }
