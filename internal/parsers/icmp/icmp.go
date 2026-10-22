// Package icmp turns ICMP and ICMPv6 echo messages into transactions carrying
// the id, sequence number and payload shape (length, hash, and whether the
// payload is the incrementing 0x10.. pattern of iputils ping).
package icmp

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// Echo message types.
const (
	V4Reply   = 0
	V4Request = 8
	V6Request = 128
	V6Reply   = 129
)

// Echo parses an ICMP message body (the bytes after the IP header, starting at
// the ICMP type) from src to dst. ok is false for non-echo messages and for
// messages shorter than the 8-byte echo header.
func Echo(cid string, src, dst netip.Addr, v6 bool, msg []byte, ts time.Time) (t txn.Txn, ok bool) {
	if len(msg) < 8 {
		return t, false
	}
	typ := msg[0]
	var reply bool
	switch {
	case !v6 && typ == V4Request, v6 && typ == V6Request:
	case !v6 && typ == V4Reply, v6 && typ == V6Reply:
		reply = true
	default:
		return t, false
	}
	payload := msg[8:]
	client, server := src, dst
	kind := "request"
	if reply {
		client, server = dst, src
		kind = "reply"
	}
	m := txn.Meta{Client: netip.AddrPortFrom(client, 0), Server: netip.AddrPortFrom(server, 0), CommunityID: cid}
	t = txn.New(m, "icmp", "echo_"+kind, ts)
	t.SetInt("icmp.id", int64(binary.BigEndian.Uint16(msg[4:])))
	t.SetInt("icmp.seq", int64(binary.BigEndian.Uint16(msg[6:])))
	t.SetInt("icmp.payload_len", int64(len(payload)))
	t.Set("icmp.payload_sha256", txn.SHA256Hex(payload))
	head := payload
	if len(head) > 16 {
		head = head[:16]
	}
	t.Set("icmp.payload_head", hex.EncodeToString(head))
	t.SetBool("icmp.iputils_pattern", iputilsPattern(payload))
	t.SetBool("icmp.v6", v6)
	return t, true
}

// iputilsPattern reports whether the payload ends with the bytes 0x10, 0x11, ...
// that iputils ping writes after its 8-byte timestamp.
func iputilsPattern(p []byte) bool {
	if len(p) <= 8 {
		return false
	}
	for i, b := range p[8:] {
		if b != byte(0x10+i) {
			return false
		}
	}
	return true
}
