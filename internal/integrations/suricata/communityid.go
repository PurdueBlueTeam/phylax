package suricata

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"net/netip"
)

// CommunityID computes the Community ID v1 flow hash (seed 0) so Zeek logs
// without it, and pcap-derived flows, join Suricata's. Returns "" for
// unsupported input.
func CommunityID(src, dst string, sport, dport uint16, proto string) string {
	a, err1 := netip.ParseAddr(src)
	b, err2 := netip.ParseAddr(dst)
	if err1 != nil || err2 != nil || a.Is4() != b.Is4() {
		return ""
	}
	var pn byte
	hasPorts := true
	switch proto {
	case "tcp", "TCP":
		pn = 6
	case "udp", "UDP":
		pn = 17
	case "sctp", "SCTP":
		pn = 132
	case "icmp", "ICMP":
		pn, hasPorts = 1, true
	case "ipv6-icmp", "icmp6", "ICMP6", "IPV6-ICMP":
		pn, hasPorts = 58, true
	default:
		return ""
	}
	if pn == 1 || pn == 58 { // type/code, order by the standard's rule is symmetrical for echo; keep as given
		hasPorts = true
	}
	ab, bb := a.AsSlice(), b.AsSlice()
	if c := bytes.Compare(ab, bb); c > 0 || (c == 0 && sport > dport) {
		ab, bb = bb, ab
		sport, dport = dport, sport
	}
	h := sha1.New()
	h.Write([]byte{0, 0}) // seed
	h.Write(ab)
	h.Write(bb)
	h.Write([]byte{pn, 0})
	if hasPorts {
		var p [4]byte
		binary.BigEndian.PutUint16(p[0:], sport)
		binary.BigEndian.PutUint16(p[2:], dport)
		h.Write(p[:])
	}
	return "1:" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}
