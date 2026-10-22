// Package netmod is the Linux network telemetry module: socket listeners and
// connections from sock_diag joined to processes, plus denied-egress
// attribution from NFLOG. The pure parts (Community ID, diffing, parsers)
// build everywhere; the netlink and /proc parts are linux-only.
package netmod

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"net/netip"
)

// IP protocol numbers used by Community ID.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
	ProtoSCTP   = 132
)

var icmp4Pair = map[uint8]uint8{8: 0, 0: 8, 13: 14, 14: 13, 15: 16, 16: 15, 17: 18, 18: 17}
var icmp6Pair = map[uint8]uint8{128: 129, 129: 128, 130: 131, 131: 130, 133: 134, 134: 133, 135: 136, 136: 135, 139: 140, 140: 139}

// CommunityID returns the Community ID v1 string (seed 0 is the default) for
// a TCP, UDP or SCTP flow. The result is the same for either direction.
func CommunityID(seed uint16, proto uint8, src, dst netip.AddrPort) string {
	return communityID(seed, proto, src.Addr(), dst.Addr(), src.Port(), dst.Port(), false, true)
}

// CommunityIDICMP computes the ID for an ICMP (proto 1) or ICMPv6 (proto 58)
// message with the given type and code. Request/reply type pairs map to the
// same ID; unpaired types are "one way" and keep their direction.
func CommunityIDICMP(seed uint16, proto uint8, src, dst netip.Addr, typ, code uint8) string {
	pairs := icmp4Pair
	if proto == ProtoICMPv6 {
		pairs = icmp6Pair
	}
	if rt, ok := pairs[typ]; ok {
		return communityID(seed, proto, src, dst, uint16(typ), uint16(rt), false, true)
	}
	return communityID(seed, proto, src, dst, uint16(typ), uint16(code), true, true)
}

// CommunityIDNoPorts is for IP protocols without ports.
func CommunityIDNoPorts(seed uint16, proto uint8, src, dst netip.Addr) string {
	return communityID(seed, proto, src, dst, 0, 0, false, false)
}

func communityID(seed uint16, proto uint8, src, dst netip.Addr, sp, dp uint16, oneWay, ports bool) string {
	src, dst = src.Unmap(), dst.Unmap()
	if !src.IsValid() || !dst.IsValid() || src.Is4() != dst.Is4() {
		return ""
	}
	s, d := src.AsSlice(), dst.AsSlice()
	if !oneWay {
		c := bytes.Compare(s, d)
		if c > 0 || (c == 0 && sp > dp) {
			s, d, sp, dp = d, s, dp, sp
		}
	}
	buf := make([]byte, 0, 2+32+4+4)
	buf = binary.BigEndian.AppendUint16(buf, seed)
	buf = append(buf, s...)
	buf = append(buf, d...)
	buf = append(buf, proto, 0)
	if ports {
		buf = binary.BigEndian.AppendUint16(buf, sp)
		buf = binary.BigEndian.AppendUint16(buf, dp)
	}
	sum := sha1.Sum(buf)
	return "1:" + base64.StdEncoding.EncodeToString(sum[:])
}
