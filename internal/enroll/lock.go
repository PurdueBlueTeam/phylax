package enroll

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrServeRunning reports a data dir whose single-writer lock is held.
var ErrServeRunning = errors.New("serve is running; use the Operator page")

// LockDataDir takes the single-writer lock on <dir>/data.lock without
// waiting. serve holds it for its lifetime and the enroll commands for their
// run, so only one process ever writes the enrollment files. The kernel drops
// the lock if the holder dies. A held lock is ErrServeRunning.
func LockDataDir(dir string) (release func(), err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("enroll: lock: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "data.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("enroll: lock: %w", err)
	}
	ok, err := tryLockFile(f)
	if err != nil || !ok {
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("enroll: lock: %w", err)
		}
		return nil, ErrServeRunning
	}
	return func() { unlockFile(f); f.Close() }, nil
}
