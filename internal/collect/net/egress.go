package netmod

import (
	"net/netip"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// EgressConfig configures denied-egress attribution.
type EgressConfig struct {
	// Dedup suppresses repeat reports of the same 5-tuple (the blocked socket
	// retries SYNs); repeats are counted in the next report's "attempts".
	// Default 30s.
	Dedup time.Duration
	// AttributeWithin is how long to keep looking for the owning socket while
	// it retries (default 3s).
	AttributeWithin time.Duration
	// MaxPending and MaxSeen bound memory (defaults 256 and 8192).
	MaxPending, MaxSeen int
	// CanaryTargets are destinations probed on purpose; denials to them are
	// tagged "canary" so rules and beacon analysis skip them.
	CanaryTargets []CanaryTarget
}

// Egress turns denied packets into attributed egress_denied events. It is
// driven by Packet (from the NFLOG reader) and Tick (periodic); not safe for
// concurrent use.
type Egress struct {
	cfg     EgressConfig
	src     SockSource
	proc    ProcResolver
	pending []*pendingDeny
	seen    map[flowKey]*seenDeny
	Dropped uint64
}

type flowKey struct {
	proto    uint8
	src, dst netip.AddrPort
}
type seenDeny struct {
	last     time.Time
	attempts int
}
type pendingDeny struct {
	pkt      NFLogPacket
	flow     Flow
	first    time.Time
	attempts int
}

// NewEgress returns an attributor.
func NewEgress(cfg EgressConfig, src SockSource, proc ProcResolver) *Egress {
	if cfg.Dedup == 0 {
		cfg.Dedup = 30 * time.Second
	}
	if cfg.AttributeWithin == 0 {
		cfg.AttributeWithin = 3 * time.Second
	}
	if cfg.MaxPending == 0 {
		cfg.MaxPending = 256
	}
	if cfg.MaxSeen == 0 {
		cfg.MaxSeen = 8192
	}
	return &Egress{cfg: cfg, src: src, proc: proc, seen: map[flowKey]*seenDeny{}}
}

// Packet records a denied packet. It returns events that can be emitted
// immediately (attribution succeeded on the first look).
func (e *Egress) Packet(now time.Time, p NFLogPacket) []event.Event {
	f, err := ParseIPPacket(p.Payload)
	if err != nil {
		return nil
	}
	k := flowKey{f.Proto, f.Src, f.Dst}
	carried := 0
	if s, ok := e.seen[k]; ok {
		if now.Sub(s.last) < e.cfg.Dedup {
			s.attempts++
			return nil
		}
		carried = s.attempts // retries suppressed in the previous window
		delete(e.seen, k)
	}
	for _, pd := range e.pending {
		if pd.flow.Proto == f.Proto && pd.flow.Src == f.Src && pd.flow.Dst == f.Dst {
			pd.attempts++
			return nil
		}
	}
	if len(e.seen) >= e.cfg.MaxSeen {
		for kk, s := range e.seen { // evict expired; if none, drop the report
			if now.Sub(s.last) >= e.cfg.Dedup {
				delete(e.seen, kk)
			}
		}
		if len(e.seen) >= e.cfg.MaxSeen {
			e.Dropped++
			return nil
		}
	}
	pd := &pendingDeny{pkt: p, flow: f, first: now, attempts: 1 + carried}
	if ev, ok := e.try(now, pd, false); ok {
		return []event.Event{ev}
	}
	if len(e.pending) >= e.cfg.MaxPending {
		// No room to keep retrying: report unattributed now.
		e.Dropped++
		ev, _ := e.try(now, pd, true)
		return []event.Event{ev}
	}
	e.pending = append(e.pending, pd)
	return nil
}

// Tick retries pending attributions and reports those that succeeded or ran
// out of time.
func (e *Egress) Tick(now time.Time) []event.Event {
	var out []event.Event
	keep := e.pending[:0]
	for _, pd := range e.pending {
		expired := now.Sub(pd.first) >= e.cfg.AttributeWithin
		if ev, ok := e.try(now, pd, expired); ok {
			out = append(out, ev)
		} else {
			keep = append(keep, pd)
		}
	}
	for i := len(keep); i < len(e.pending); i++ {
		e.pending[i] = nil
	}
	e.pending = keep
	for k, s := range e.seen {
		if now.Sub(s.last) >= 2*e.cfg.Dedup {
			delete(e.seen, k)
		}
	}
	return out
}

// Pending reports unresolved attributions.
func (e *Egress) Pending() int { return len(e.pending) }

// try looks for the owning socket. With final set it always yields an event.
func (e *Egress) try(now time.Time, pd *pendingDeny, final bool) (event.Event, bool) {
	var owner *Proc
	var sock *Sock
	if socks, err := e.src.Sockets(); err == nil {
		for i := range socks {
			if matchesDenied(socks[i], pd.flow) {
				sock = &socks[i]
				break
			}
		}
	}
	if sock != nil && sock.Inode != 0 {
		if p, ok := e.proc.Resolve([]uint64{sock.Inode})[sock.Inode]; ok {
			owner = &p
		}
	}
	if owner == nil && !final {
		return event.Event{}, false
	}
	f := pd.flow
	fields := map[string]any{
		"dir": "outbound", "proto": f.ProtoName(),
		"laddr": f.Src.Addr().String(), "lport": int(f.Src.Port()),
		"raddr": f.Dst.Addr().String(), "rport": int(f.Dst.Port()),
		"community_id": f.CommunityID(), "attributed": owner != nil,
		"attempts": pd.attempts, "nflog_group": int(pd.pkt.Group),
	}
	if pd.pkt.Prefix != "" {
		fields["prefix"] = pd.pkt.Prefix
	}
	if pd.pkt.UID >= 0 {
		fields["sock_uid"] = pd.pkt.UID
	}
	if sock != nil {
		fields["inode"] = sock.Inode
	}
	for _, c := range e.cfg.CanaryTargets {
		if c.matches(f.Dst) {
			fields["tag"] = "canary"
			if c.Tag != "" {
				fields["canary_tag"] = c.Tag
			}
		}
	}
	procFields(fields, owner)
	e.seen[flowKey{f.Proto, f.Src, f.Dst}] = &seenDeny{last: now}
	return event.Event{Time: now, Kind: KindEgressDenied, Priority: event.PriorityHigh, Fields: fields}, true
}

// matchesDenied reports whether a kernel socket is the sender of the denied
// packet: same protocol and local endpoint, and either the same remote or an
// unconnected UDP socket.
func matchesDenied(s Sock, f Flow) bool {
	var proto string
	switch f.Proto {
	case ProtoTCP:
		proto = "tcp"
	case ProtoUDP:
		proto = "udp"
	default:
		return false
	}
	if s.Proto != proto || s.Local.Port() != f.Src.Port() {
		return false
	}
	if la := s.Local.Addr(); !la.IsUnspecified() && la != f.Src.Addr() {
		return false
	}
	if s.Remote == f.Dst {
		return true
	}
	return proto == "udp" && s.Remote.Port() == 0
}
