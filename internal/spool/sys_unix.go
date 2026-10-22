//go:build !windows

package spool

import (
	"fmt"
	"os"
	"syscall"
)

type dirLock struct{ f *os.File }

func lockDir(path string) (*dirLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("spool: directory in use by another process: %w", err)
	}
	return &dirLock{f}, nil
}

func (l *dirLock) unlock() error { return l.f.Close() }

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
