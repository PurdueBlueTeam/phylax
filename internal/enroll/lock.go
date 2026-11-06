package enroll

import (
	"fmt"
	"os"
	"path/filepath"
)

// dataLock is the exclusive advisory lock on <DataDir>/enroll.lock. Every
// read-modify-write of a shared enrollment file takes it, so `phylax enroll`
// and `phylax serve` can share one data dir.
type dataLock struct{ f *os.File }

func lockDataDir(dir string) (*dataLock, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("enroll: lock: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "enroll.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("enroll: lock: %w", err)
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("enroll: lock: %w", err)
	}
	return &dataLock{f: f}, nil
}

func (l *dataLock) Unlock() {
	if l == nil || l.f == nil {
		return
	}
	unlockFile(l.f)
	l.f.Close()
	l.f = nil
}
