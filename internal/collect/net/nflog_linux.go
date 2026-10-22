//go:build linux

package netmod

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// NFLogReader reads packets from NFLOG groups over NETLINK_NETFILTER.
// Binding needs CAP_NET_ADMIN in the network namespace that owns the rules.
type NFLogReader struct {
	fd   int
	Lost atomic.Uint64 // ENOBUFS events (kernel dropped packets for us)
	// Raw, if set, sees every received netlink buffer (recording fixtures).
	Raw func([]byte)
}

// OpenNFLog binds the groups, copying at most copyRange bytes of each packet
// (enough for headers; 128 covers IPv6 + TCP options).
func OpenNFLog(groups []uint16, copyRange uint32) (*NFLogReader, error) {
	if len(groups) == 0 {
		return nil, errors.New("nflog: no groups")
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nflog socket: %w", err)
	}
	r := &NFLogReader{fd: fd}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		r.Close()
		return nil, fmt.Errorf("nflog bind: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	tv := unix.NsecToTimeval(int64(2e9))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	for _, g := range groups {
		for _, m := range nflogBindMsgs(g, copyRange) {
			if err := unix.Sendto(fd, m, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
				r.Close()
				return nil, fmt.Errorf("nflog config send: %w", err)
			}
			if err := r.waitAck(); err != nil {
				r.Close()
				return nil, fmt.Errorf("nflog group %d: %w", g, err)
			}
		}
	}
	tv = unix.NsecToTimeval(int64(500e6))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	return r, nil
}

func (r *NFLogReader) waitAck() error {
	buf := make([]byte, 4096)
	for {
		n, _, err := unix.Recvfrom(r.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return err
		}
		ne := binary.NativeEndian
		b := buf[:n]
		for len(b) >= 16 {
			l := int(ne.Uint32(b))
			if l < 16 || l > len(b) {
				return errors.New("malformed ack")
			}
			if ne.Uint16(b[4:]) == unix.NLMSG_ERROR && l >= 20 {
				if e := int32(ne.Uint32(b[16:])); e != 0 {
					return syscall.Errno(-e)
				}
				return nil
			}
			b = b[min(len(b), (l+3)&^3):]
		}
	}
}

// Close releases the socket. Safe to call once.
func (r *NFLogReader) Close() error { return unix.Close(r.fd) }

// Run delivers packets to fn until ctx is cancelled. fn must not block long.
func (r *NFLogReader) Run(ctx context.Context, fn func(NFLogPacket)) error {
	buf := make([]byte, 1<<17)
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(r.fd, buf, 0)
		if err != nil {
			switch {
			case errors.Is(err, syscall.EINTR), errors.Is(err, syscall.EAGAIN):
				continue
			case errors.Is(err, syscall.ENOBUFS):
				r.Lost.Add(1)
				continue
			}
			return fmt.Errorf("nflog recv: %w", err)
		}
		if r.Raw != nil {
			r.Raw(buf[:n])
		}
		pkts, _ := ParseNFLog(buf[:n])
		for _, p := range pkts {
			fn(p)
		}
	}
	return ctx.Err()
}
