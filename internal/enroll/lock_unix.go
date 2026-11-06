//go:build !windows

package enroll

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes a blocking exclusive advisory lock. flock locks belong to the
// open file description, so they exclude other processes and other descriptors
// opened in this process; the kernel drops the lock if the process dies.
func lockFile(f *os.File) error {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

func unlockFile(f *os.File) { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }
