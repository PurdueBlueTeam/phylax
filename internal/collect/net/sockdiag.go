package netmod

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// TCP state numbers as reported by sock_diag.
const (
	StateEstablished = 1
	StateSynSent     = 2
	StateSynRecv     = 3
	StateTimeWait    = 6
	StateClose       = 7 // for UDP: bound, unconnected
	StateListen      = 10
)

// Sock is one kernel socket from a sock_diag dump.
type Sock struct {
	Proto  string // "tcp" or "udp"
	Local  netip.AddrPort
	Remote netip.AddrPort
	State  uint8
	Inode  uint64
	UID    uint32
	// BytesOut/BytesIn are bytes acked to / received from the peer (tcp_info),
	// valid when HasBytes.
	BytesOut, BytesIn uint64
	HasBytes          bool
}

// IsListener reports whether the socket is a listening TCP socket or a bound,
// unconnected UDP socket.
func (s Sock) IsListener() bool {
	switch s.Proto {
	case "tcp":
		return s.State == StateListen
	case "udp":
		return s.Remote.Port() == 0 && s.Local.Port() != 0 && s.State != StateEstablished
	}
	return false
}

// IsConnection reports whether the socket represents a live connection.
func (s Sock) IsConnection() bool {
	switch s.Proto {
	case "tcp":
		return s.State != StateListen && s.State != StateClose && s.State != StateTimeWait && s.Remote.Port() != 0
	case "udp":
		return s.Remote.Port() != 0
	}
	return false
}

const (
	diagMsgLen    = 72
	attrInetInfo  = 2
	tcpInfoBytes  = 120 // offset of bytes_acked, then bytes_received at +8
	tcpInfoMinLen = tcpInfoBytes + 16
)

var errShortDiag = errors.New("netmod: short inet_diag message")

// parseDiagMsg decodes one inet_diag_msg (with trailing attributes) from a
// SOCK_DIAG_BY_FAMILY response. Addresses and ports are network byte order;
// uid, inode and attribute headers are host order.
func parseDiagMsg(b []byte, proto string) (Sock, error) {
	if len(b) < diagMsgLen {
		return Sock{}, errShortDiag
	}
	ne := binary.NativeEndian
	fam := b[0]
	s := Sock{Proto: proto, State: b[1]}
	sport := binary.BigEndian.Uint16(b[4:])
	dport := binary.BigEndian.Uint16(b[6:])
	var src, dst netip.Addr
	switch fam {
	case 2:
		src = netip.AddrFrom4([4]byte(b[8:12]))
		dst = netip.AddrFrom4([4]byte(b[24:28]))
	case 10:
		src = netip.AddrFrom16([16]byte(b[8:24])).Unmap()
		dst = netip.AddrFrom16([16]byte(b[24:40])).Unmap()
	default:
		return Sock{}, errors.New("netmod: unsupported family")
	}
	s.Local = netip.AddrPortFrom(src, sport)
	s.Remote = netip.AddrPortFrom(dst, dport)
	s.UID = ne.Uint32(b[64:])
	s.Inode = uint64(ne.Uint32(b[68:]))
	rest := b[diagMsgLen:]
	for len(rest) >= 4 {
		l := int(ne.Uint16(rest))
		typ := ne.Uint16(rest[2:])
		if l < 4 || l > len(rest) {
			break
		}
		if typ == attrInetInfo && proto == "tcp" && l-4 >= tcpInfoMinLen {
			p := rest[4:l]
			// bytes_acked counts the SYN's sequence number once the handshake
			// is acked; subtract it so the value is application bytes.
			s.BytesOut = ne.Uint64(p[tcpInfoBytes:])
			if s.BytesOut > 0 && s.State != StateSynSent && s.State != StateSynRecv {
				s.BytesOut--
			}
			s.BytesIn = ne.Uint64(p[tcpInfoBytes+8:])
			s.HasBytes = true
		}
		adv := (l + 3) &^ 3
		if adv >= len(rest) {
			break
		}
		rest = rest[adv:]
	}
	return s, nil
}
