//go:build linux

package audit

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	libaudit "github.com/elastic/go-libaudit/v2"
	"golang.org/x/sys/unix"
)

// errInterrupted is returned by rawNetlink.Receive after Interrupt.
var errInterrupted = errors.New("audit: receive interrupted")

// rawNetlink is a netlink socket for the reader side. go-libaudit's own client
// blocks in recvfrom, which closing the socket does not wake, and gives no
// control over the receive buffer. This one polls with a short timeout so the
// reader can be stopped, and requests a large SO_RCVBUF (design: "a large
// socket receive buffer", to avoid ENOBUFS). It plugs into
// libaudit.AuditClient through the exported Netlink field.
type rawNetlink struct {
	fd      int
	pid     uint32
	seq     uint32
	readBuf []byte

	rcvbuf    int // effective size, for health
	interrupt atomic.Bool
	closed    atomic.Bool
	rmu       sync.RWMutex // held (R) while a Receive is in flight
	closeOnce sync.Once
	closeErr  error
}

const pollInterval = 250 // ms

func newRawNetlink(groups uint32, rcvbuf int) (*rawNetlink, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_AUDIT)
	if err != nil {
		return nil, err
	}
	if rcvbuf > 0 {
		// FORCE bypasses rmem_max but needs CAP_NET_ADMIN.
		if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, rcvbuf) != nil {
			_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvbuf)
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind failed: %w", err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	nl, ok := sa.(*unix.SockaddrNetlink)
	if !ok {
		unix.Close(fd)
		return nil, errors.New("unexpected socket address type")
	}
	n := &rawNetlink{fd: fd, pid: nl.Pid, readBuf: make([]byte, syscall.NLMSG_HDRLEN+libaudit.AuditMessageMaxLength)}
	n.rcvbuf, _ = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	return n, nil
}

func (c *rawNetlink) Send(msg syscall.NetlinkMessage) (uint32, error) { return c.send(msg, 0) }
func (c *rawNetlink) SendNoWait(msg syscall.NetlinkMessage) (uint32, error) {
	return c.send(msg, syscall.MSG_DONTWAIT)
}

func (c *rawNetlink) send(msg syscall.NetlinkMessage, flags int) (uint32, error) {
	if c.closed.Load() {
		return 0, errors.New("audit: socket closed")
	}
	if msg.Header.Pid == 0 {
		msg.Header.Pid = c.pid
	}
	msg.Header.Seq = atomic.AddUint32(&c.seq, 1)
	msg.Header.Len = uint32(syscall.SizeofNlMsghdr + len(msg.Data))
	b := make([]byte, msg.Header.Len)
	*(*syscall.NlMsghdr)(unsafe.Pointer(&b[0])) = msg.Header
	copy(b[syscall.SizeofNlMsghdr:], msg.Data)
	return msg.Header.Seq, unix.Sendto(c.fd, b, flags, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

// Receive implements libaudit.NetlinkReceiver. A blocking receive polls every
// pollInterval ms so Interrupt and Close take effect.
func (c *rawNetlink) Receive(nonBlocking bool, p libaudit.NetlinkParser) ([]syscall.NetlinkMessage, error) {
	c.rmu.RLock()
	defer c.rmu.RUnlock()
	for {
		if c.closed.Load() {
			return nil, errors.New("audit: socket closed")
		}
		if !nonBlocking {
			if c.interrupt.Load() {
				return nil, errInterrupted
			}
			fds := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN}}
			n, err := unix.Poll(fds, pollInterval)
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				return nil, err
			}
			if n == 0 {
				continue
			}
		}
		nr, from, err := unix.Recvfrom(c.fd, c.readBuf, unix.MSG_DONTWAIT)
		if err != nil {
			if !nonBlocking && (errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR)) {
				continue
			}
			return nil, err
		}
		if nr < syscall.NLMSG_HDRLEN {
			return nil, fmt.Errorf("not enough bytes (%v) received to form a netlink header", nr)
		}
		if f, ok := from.(*unix.SockaddrNetlink); !ok || f.Pid != 0 {
			return nil, errors.New("message received was not from the kernel")
		}
		msgs, err := p(c.readBuf[:nr])
		if err != nil {
			return nil, fmt.Errorf("failed to parse netlink messages (bytes_received=%v): %w", nr, err)
		}
		return msgs, nil
	}
}

// Interrupt makes in-flight and future blocking Receives return errInterrupted
// until Resume.
func (c *rawNetlink) Interrupt() { c.interrupt.Store(true) }
func (c *rawNetlink) Resume()    { c.interrupt.Store(false) }

// Close waits for an in-flight Receive (at most one poll interval) then closes.
func (c *rawNetlink) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.rmu.Lock()
		c.closeErr = unix.Close(c.fd)
		c.rmu.Unlock()
	})
	return c.closeErr
}

// newReader returns an audit client reading through a rawNetlink.
func newReader(multicast bool, rcvbuf int) (*libaudit.AuditClient, *rawNetlink, error) {
	var groups uint32
	if multicast {
		groups = libaudit.NetlinkGroupReadLog
	}
	nl, err := newRawNetlink(groups, rcvbuf)
	if err != nil {
		return nil, nil, fmt.Errorf("open audit netlink socket: %w", err)
	}
	return &libaudit.AuditClient{Netlink: nl}, nl, nil
}
