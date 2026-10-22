//go:build unix

package deadman

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// tryLockFile takes a non-blocking exclusive advisory lock. flock locks belong
// to the open file description, so they exclude other processes and also other
// descriptors opened in this process. The kernel drops the lock if we die.
func tryLockFile(f *os.File) (bool, error) {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}

func unlockFile(f *os.File) { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }
