// Package tcp describes bare TCP connections: a handshake with no payload in
// either direction (RDP and tcp checks that connect and hold), refused
// connections and handshake timeouts. It works from a flow summary rather than
// a byte stream, so the capture engine calls Transaction when a flow ends.
package tcp

import (
	"net/netip"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

// Handshake outcomes.
const (
	Established = "established"
	Refused     = "refused" // SYN answered by RST
	Timeout     = "timeout" // SYN never answered
	MidStream   = "midstream"
)

// Summary is what the flow tracker knows about a finished connection.
type Summary struct {
	Client, Server netip.AddrPort
	CommunityID    string
	Start, End     time.Time
	Result         string // one of the constants above
	BytesC2S       int64  // payload bytes, not wire bytes
	BytesS2C       int64
	ResetBy        string // "client", "server" or ""
	Keepalives     int    // zero-length ACKs seen after the handshake
}

// Transaction returns an event for bare connections, refusals and timeouts.
// Connections that carried payload are left to the protocol parsers.
func Transaction(s Summary) (txn.Txn, bool) {
	zero := s.Result == Established && s.BytesC2S == 0 && s.BytesS2C == 0
	if !zero && s.Result != Refused && s.Result != Timeout {
		return txn.Txn{}, false
	}
	proto := "tcp"
	if s.Server.Port() == 3389 {
		proto = "rdp"
	}
	t := txn.New(txn.Meta{Client: s.Client, Server: s.Server, CommunityID: s.CommunityID}, proto, "connect", s.Start)
	t.End = s.End
	t.Set("tcp.result", s.Result)
	t.SetBool("tcp.zero_payload", zero)
	t.SetInt("tcp.hold_ms", s.End.Sub(s.Start).Milliseconds())
	t.SetInt("tcp.keepalives", int64(s.Keepalives))
	if s.ResetBy != "" {
		t.Set("tcp.reset_by", s.ResetBy)
	}
	t.Succeeded(s.Result == Established)
	return t, true
}
