package netmod

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// NFLOG netlink constants (linux/netfilter/nfnetlink_log.h).
const (
	nfnlSubsysULOG   = 4
	nfulnlMsgPacket  = 0
	nfulnlMsgConfig  = 1
	nfulaPacketHdr   = 1
	nfulaMark        = 2
	nfulaIfIndexIn   = 4
	nfulaIfIndexOut  = 5
	nfulaPayload     = 9
	nfulaPrefix      = 10
	nfulaUID         = 11
	nfulaGID         = 13
	nfulaCfgCmd      = 1
	nfulaCfgMode     = 2
	nfulnlCfgCmdBind = 1
	nfulnlCopyPacket = 2
)

// NFLogPacket is one packet delivered to an NFLOG group.
type NFLogPacket struct {
	Group    uint16
	Family   uint8
	Hook     uint8
	Prefix   string
	UID, GID int64 // -1 when absent
	Mark     uint32
	InIface  uint32
	OutIface uint32
	Payload  []byte
}

// ParseNFLog decodes a buffer of netlink messages read from an NFLOG socket
// and returns the packets in it. Non-packet messages (acks) are skipped.
func ParseNFLog(b []byte) ([]NFLogPacket, error) {
	var out []NFLogPacket
	ne := binary.NativeEndian
	for len(b) >= 16 {
		l := int(ne.Uint32(b))
		typ := ne.Uint16(b[4:])
		if l < 16 || l > len(b) {
			return out, errors.New("nflog: malformed netlink message")
		}
		body := b[16:l]
		adv := min(len(b), (l+3)&^3)
		b = b[adv:]
		if typ>>8 != nfnlSubsysULOG || typ&0xff != nfulnlMsgPacket || len(body) < 4 {
			continue
		}
		p := NFLogPacket{Family: body[0], Group: binary.BigEndian.Uint16(body[2:]), UID: -1, GID: -1}
		attrs := body[4:]
		for len(attrs) >= 4 {
			al := int(ne.Uint16(attrs))
			at := ne.Uint16(attrs[2:]) & 0x3fff // strip NLA_F_NESTED / byte-order flags
			if al < 4 || al > len(attrs) {
				break
			}
			d := attrs[4:al]
			switch at {
			case nfulaPacketHdr:
				if len(d) >= 3 {
					p.Hook = d[2]
				}
			case nfulaMark:
				if len(d) >= 4 {
					p.Mark = binary.BigEndian.Uint32(d)
				}
			case nfulaIfIndexIn:
				if len(d) >= 4 {
					p.InIface = binary.BigEndian.Uint32(d)
				}
			case nfulaIfIndexOut:
				if len(d) >= 4 {
					p.OutIface = binary.BigEndian.Uint32(d)
				}
			case nfulaPayload:
				p.Payload = append([]byte(nil), d...)
			case nfulaPrefix:
				p.Prefix = cstr(d)
			case nfulaUID:
				if len(d) >= 4 {
					p.UID = int64(binary.BigEndian.Uint32(d))
				}
			case nfulaGID:
				if len(d) >= 4 {
					p.GID = int64(binary.BigEndian.Uint32(d))
				}
			}
			adv := min(len(attrs), (al+3)&^3)
			attrs = attrs[adv:]
		}
		out = append(out, p)
	}
	return out, nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// Flow is the 5-tuple decoded from a logged packet's IP header.
type Flow struct {
	Proto      uint8 // IP protocol number
	Src, Dst   netip.AddrPort
	TCPFlags   uint8
	ICMPType   uint8
	ICMPCode   uint8
	SrcA, DstA netip.Addr
}

// ProtoName returns "tcp", "udp", "icmp", "icmp6" or the number.
func (f Flow) ProtoName() string {
	switch f.Proto {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	case ProtoICMPv6:
		return "icmp6"
	}
	return "ip" + itoa(int(f.Proto))
}

// CommunityID returns the flow's Community ID (seed 0).
func (f Flow) CommunityID() string {
	switch f.Proto {
	case ProtoTCP, ProtoUDP, ProtoSCTP:
		return CommunityID(0, f.Proto, f.Src, f.Dst)
	case ProtoICMP, ProtoICMPv6:
		return CommunityIDICMP(0, f.Proto, f.SrcA, f.DstA, f.ICMPType, f.ICMPCode)
	}
	return CommunityIDNoPorts(0, f.Proto, f.SrcA, f.DstA)
}

// ParseIPPacket decodes an IPv4 or IPv6 packet header (as delivered by NFLOG,
// starting at the network header). Truncated transport headers yield zero ports.
func ParseIPPacket(b []byte) (Flow, error) {
	if len(b) < 1 {
		return Flow{}, errors.New("nflog: empty payload")
	}
	var f Flow
	var l4 []byte
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return f, errors.New("nflog: short ipv4 header")
		}
		ihl := int(b[0]&0xf) * 4
		if ihl < 20 || len(b) < ihl {
			return f, errors.New("nflog: bad ipv4 ihl")
		}
		f.Proto = b[9]
		f.SrcA = netip.AddrFrom4([4]byte(b[12:16]))
		f.DstA = netip.AddrFrom4([4]byte(b[16:20]))
		// Non-first fragments carry no transport header.
		if binary.BigEndian.Uint16(b[6:])&0x1fff == 0 {
			l4 = b[ihl:]
		}
	case 6:
		if len(b) < 40 {
			return f, errors.New("nflog: short ipv6 header")
		}
		f.Proto = b[6]
		f.SrcA = netip.AddrFrom16([16]byte(b[8:24]))
		f.DstA = netip.AddrFrom16([16]byte(b[24:40]))
		l4 = b[40:]
		// Skip common extension headers.
		for i := 0; i < 8 && (f.Proto == 0 || f.Proto == 43 || f.Proto == 60) && len(l4) >= 8; i++ {
			f.Proto = l4[0]
			n := (int(l4[1]) + 1) * 8
			if len(l4) < n {
				l4 = nil
				break
			}
			l4 = l4[n:]
		}
	default:
		return f, errors.New("nflog: not an IP packet")
	}
	var sp, dp uint16
	switch f.Proto {
	case ProtoTCP, ProtoUDP, ProtoSCTP:
		if len(l4) >= 4 {
			sp, dp = binary.BigEndian.Uint16(l4), binary.BigEndian.Uint16(l4[2:])
		}
		if f.Proto == ProtoTCP && len(l4) >= 14 {
			f.TCPFlags = l4[13]
		}
	case ProtoICMP, ProtoICMPv6:
		if len(l4) >= 2 {
			f.ICMPType, f.ICMPCode = l4[0], l4[1]
		}
	}
	f.Src = netip.AddrPortFrom(f.SrcA.Unmap(), sp)
	f.Dst = netip.AddrPortFrom(f.DstA.Unmap(), dp)
	return f, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// nflogConfigMsg builds a NFULNL_MSG_CONFIG request for a group with one
// attribute (cmd: u8 bind, or mode: copy range + copy mode).
func nflogConfigMsg(group uint16, seq uint32, attrType uint16, data []byte) []byte {
	ne := binary.NativeEndian
	alen := 4 + len(data)
	total := 16 + 4 + ((alen + 3) &^ 3)
	b := make([]byte, total)
	ne.PutUint32(b[0:], uint32(total))
	ne.PutUint16(b[4:], nfnlSubsysULOG<<8|nfulnlMsgConfig)
	ne.PutUint16(b[6:], 0x1|0x4) // NLM_F_REQUEST | NLM_F_ACK
	ne.PutUint32(b[8:], seq)
	binary.BigEndian.PutUint16(b[18:], group) // nfgenmsg: family 0, version 0, res_id
	ne.PutUint16(b[20:], uint16(alen))
	ne.PutUint16(b[22:], attrType)
	copy(b[24:], data)
	return b
}

func nflogBindMsgs(group uint16, copyRange uint32) [][]byte {
	mode := make([]byte, 6)
	binary.BigEndian.PutUint32(mode, copyRange)
	mode[4] = nfulnlCopyPacket
	return [][]byte{
		nflogConfigMsg(group, 1, nfulaCfgCmd, []byte{nfulnlCfgCmdBind}),
		nflogConfigMsg(group, 2, nfulaCfgMode, mode),
	}
}
