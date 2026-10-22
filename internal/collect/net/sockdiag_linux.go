//go:build linux

package netmod

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// SockDiag dumps TCP and UDP sockets (v4 and v6) over NETLINK_SOCK_DIAG.
// Dumping needs no privileges; every socket in the network namespace is
// visible, though the inode-to-process join only works for readable /proc/pid/fd.
type SockDiag struct {
	// WantBytes requests tcp_info (byte counters) for TCP sockets.
	WantBytes bool
}

const (
	sockDiagByFamily = 20
	allStates        = 0xfff
)

// Sockets implements SockSource.
func (d SockDiag) Sockets() ([]Sock, error) {
	var out []Sock
	var firstErr error
	ok := false
	for _, proto := range []string{"tcp", "udp"} {
		for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
			ss, err := d.dump(proto, fam)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			ok = true
			out = append(out, ss...)
		}
	}
	if !ok {
		return nil, firstErr
	}
	return out, nil
}

func (d SockDiag) dump(proto string, fam uint8) ([]Sock, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("sock_diag socket: %w", err)
	}
	defer unix.Close(fd)
	tv := unix.NsecToTimeval(int64(5e9))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	ipproto := uint8(unix.IPPROTO_TCP)
	var ext uint8
	if proto == "udp" {
		ipproto = unix.IPPROTO_UDP
	} else if d.WantBytes {
		ext = 1 << (attrInetInfo - 1)
	}
	req := make([]byte, 16+56)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], sockDiagByFamily)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	ne.PutUint32(req[8:], 1)
	req[16], req[17], req[18] = fam, ipproto, ext
	ne.PutUint32(req[20:], allStates)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sock_diag send: %w", err)
	}

	var out []Sock
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return nil, fmt.Errorf("sock_diag recv: %w", err)
		}
		msgs := buf[:n]
		for len(msgs) >= 16 {
			l := int(ne.Uint32(msgs))
			typ := ne.Uint16(msgs[4:])
			if l < 16 || l > len(msgs) {
				return nil, errors.New("sock_diag: malformed netlink message")
			}
			body := msgs[16:l]
			switch typ {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				if len(body) >= 4 {
					if e := int32(ne.Uint32(body)); e != 0 {
						return nil, fmt.Errorf("sock_diag: %w", syscall.Errno(-e))
					}
				}
			case sockDiagByFamily:
				s, err := parseDiagMsg(body, proto)
				if err == nil {
					out = append(out, s)
				}
			}
			msgs = msgs[min(len(msgs), (l+3)&^3):]
		}
	}
}
