//go:build linux

package honeytokens

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Fanotify is the Linux Watcher: a notification-class fanotify group marking
// individual files for open/access. It needs CAP_SYS_ADMIN (root).
type Fanotify struct {
	fd     int
	events chan ReadEvent
	once   sync.Once
	done   chan struct{}
}

// NewFanotify opens a fanotify group.
func NewFanotify() (Watcher, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_CLASS_NOTIF|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWatchUnavailable, err)
	}
	f := &Fanotify{fd: fd, events: make(chan ReadEvent, 256), done: make(chan struct{})}
	go f.loop()
	return f, nil
}

// Watch implements Watcher.
func (f *Fanotify) Watch(path string) error {
	return unix.FanotifyMark(f.fd, unix.FAN_MARK_ADD, unix.FAN_OPEN|unix.FAN_ACCESS, unix.AT_FDCWD, path)
}

// Events implements Watcher.
func (f *Fanotify) Events() <-chan ReadEvent { return f.events }

// Close implements Watcher.
func (f *Fanotify) Close() error {
	f.once.Do(func() { close(f.done) })
	return nil
}

func (f *Fanotify) loop() {
	defer func() { _ = unix.Close(f.fd); close(f.events) }()
	buf := make([]byte, 8192)
	for {
		select {
		case <-f.done:
			return
		default:
		}
		pfd := []unix.PollFd{{Fd: int32(f.fd), Events: unix.POLLIN}}
		if n, _ := unix.Poll(pfd, 200); n <= 0 {
			continue
		}
		n, err := unix.Read(f.fd, buf)
		if err != nil || n <= 0 {
			continue
		}
		for off := 0; off+24 <= n; {
			evLen := int(binary.NativeEndian.Uint32(buf[off:]))
			if evLen < 24 || off+evLen > n {
				break
			}
			// fanotify_event_metadata: len u32, vers u8, res u8, mdlen u16, mask u64, fd s32, pid s32
			fd := int32(binary.NativeEndian.Uint32(buf[off+16:]))
			pid := int32(binary.NativeEndian.Uint32(buf[off+20:]))
			off += evLen
			if fd < 0 {
				continue
			}
			p, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(fd)))
			_ = unix.Close(int(fd))
			exe, _ := os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/exe")
			select {
			case f.events <- ReadEvent{Path: p, PID: int(pid), Exe: exe, Time: time.Now()}:
			default: // bounded: drop under a flood
			}
		}
	}
}
