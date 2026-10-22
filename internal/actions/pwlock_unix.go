//go:build unix

package actions

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// lockFileCross takes the shadow-utils lock (an fcntl write lock on the lock
// file, as lckpwdf does) so we exclude passwd/useradd/chpasswd and friends.
func lockFileCross(ctx context.Context, path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0}
		err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lk)
		if err == nil {
			return func() {
				lk := unix.Flock_t{Type: unix.F_UNLCK}
				_ = unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lk)
				f.Close()
			}, nil
		}
		if err != unix.EAGAIN && err != unix.EACCES {
			f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}
