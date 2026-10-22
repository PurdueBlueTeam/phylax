package netmod

import (
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Event kinds emitted by this package.
const (
	KindListenerAdded    = "net.listener_added"
	KindListenerRemoved  = "net.listener_removed"
	KindConnectionOpened = "net.connection_opened"
	KindConnectionClosed = "net.connection_closed"
	KindEgressDenied     = "net.egress_denied"
	KindCanaryResult     = "net.canary_result"
	KindSensorDegraded   = "net.sensor_degraded"
)

// Proc identifies the process owning a socket. (PID, StartTicks) is the
// identity: pids are reused, start time is not.
type Proc struct {
	PID        int
	StartTicks uint64 // stat field 22, clock ticks since boot
	Comm       string
	Exe        string
	ExeDeleted bool
	ExeSHA256  string
	UID        uint32
}

// SockSource lists the machine's sockets.
type SockSource interface{ Sockets() ([]Sock, error) }

// ProcResolver maps socket inodes to owning processes.
type ProcResolver interface {
	Resolve(inodes []uint64) map[uint64]Proc
}

// TrackerConfig configures diffing.
type TrackerConfig struct {
	// Services maps "proto/port" or "port" to a service name.
	Services map[string]string
	// MaxConns bounds tracked connections (default 65536). Connections beyond
	// it are counted in Dropped and neither opened nor closed.
	MaxConns int
}

// Tracker diffs successive socket snapshots into events.
type Tracker struct {
	cfg  TrackerConfig
	src  SockSource
	proc ProcResolver

	listeners map[lkey]*lrec
	conns     map[ckey]*crec
	first     bool
	Dropped   uint64 // connections not tracked because of MaxConns
}

type lkey struct {
	proto string
	ap    netip.AddrPort
	inode uint64
}
type ckey struct {
	proto         string
	local, remote netip.AddrPort
	inode         uint64
}
type lrec struct {
	s Sock
	p *Proc
}
type crec struct {
	s     Sock
	p     *Proc
	dir   string
	since time.Time
	seen  bool
}

// NewTracker returns a tracker; the first Poll reports existing state with
// baseline=true.
func NewTracker(cfg TrackerConfig, src SockSource, proc ProcResolver) *Tracker {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 65536
	}
	return &Tracker{cfg: cfg, src: src, proc: proc, listeners: map[lkey]*lrec{}, conns: map[ckey]*crec{}, first: true}
}

// Service returns the configured service name for a protocol and port.
func (c TrackerConfig) Service(proto string, port uint16) string {
	if port == 0 {
		return ""
	}
	p := strconv.Itoa(int(port))
	if s, ok := c.Services[proto+"/"+p]; ok {
		return s
	}
	return c.Services[p]
}

// Poll takes one snapshot and returns the events since the previous one.
func (t *Tracker) Poll(now time.Time) ([]event.Event, error) {
	socks, err := t.src.Sockets()
	if err != nil {
		return nil, err
	}
	baseline := t.first
	t.first = false

	inodes := make([]uint64, 0, len(socks))
	for _, s := range socks {
		if s.Inode != 0 {
			inodes = append(inodes, s.Inode)
		}
	}
	procs := t.proc.Resolve(inodes)
	lookup := func(in uint64) *Proc {
		if p, ok := procs[in]; ok {
			return &p
		}
		return nil
	}

	var evs []event.Event
	// Listeners.
	curL := map[lkey]Sock{}
	for _, s := range socks {
		if s.IsListener() {
			curL[lkey{s.Proto, s.Local, s.Inode}] = s
		}
	}
	for k, r := range t.listeners {
		if _, ok := curL[k]; !ok {
			evs = append(evs, t.listenerEvent(KindListenerRemoved, now, r.s, r.p, false))
			delete(t.listeners, k)
		}
	}
	for k, s := range curL {
		r, ok := t.listeners[k]
		if !ok {
			r = &lrec{s: s}
			t.listeners[k] = r
			r.p = lookup(s.Inode)
			evs = append(evs, t.listenerEvent(KindListenerAdded, now, s, r.p, baseline))
		} else if r.p == nil {
			r.p = lookup(s.Inode) // late attribution; no new event
		}
	}
	listenAt := make(map[string][]netip.Addr)
	for _, r := range t.listeners {
		key := r.s.Proto + "/" + strconv.Itoa(int(r.s.Local.Port()))
		listenAt[key] = append(listenAt[key], r.s.Local.Addr())
	}

	// Connections.
	curC := map[ckey]Sock{}
	for _, s := range socks {
		if s.IsConnection() {
			curC[ckey{s.Proto, s.Local, s.Remote, s.Inode}] = s
		}
	}
	for k, r := range t.conns {
		if _, ok := curC[k]; !ok {
			evs = append(evs, t.connEvent(KindConnectionClosed, now, r, false))
			delete(t.conns, k)
		}
	}
	for k, s := range curC {
		r, ok := t.conns[k]
		if !ok {
			if len(t.conns) >= t.cfg.MaxConns {
				t.Dropped++
				continue
			}
			r = &crec{s: s, since: now, dir: inferDirection(s, listenAt)}
			r.p = lookup(s.Inode)
			t.conns[k] = r
			evs = append(evs, t.connEvent(KindConnectionOpened, now, r, baseline))
			continue
		}
		if r.p == nil {
			r.p = lookup(s.Inode)
		}
		r.s = s // refresh counters/state
	}
	return evs, nil
}

// Listeners and Conns report tracked counts (health and tests).
func (t *Tracker) Listeners() int { return len(t.listeners) }
func (t *Tracker) Conns() int     { return len(t.conns) }

// inferDirection classifies a connection as inbound when its local endpoint is
// one of this host's listening sockets (same protocol and port, and the
// listener's address is unspecified or equal to the local address), else
// outbound.
func inferDirection(s Sock, listenAt map[string][]netip.Addr) string {
	for _, a := range listenAt[s.Proto+"/"+strconv.Itoa(int(s.Local.Port()))] {
		if a.IsUnspecified() || a == s.Local.Addr() {
			return "inbound"
		}
	}
	return "outbound"
}

func procFields(f map[string]any, p *Proc) {
	if p == nil {
		return
	}
	f["pid"] = p.PID
	f["pid_start"] = p.StartTicks
	f["comm"] = p.Comm
	f["exe"] = p.Exe
	f["uid"] = p.UID
	if p.ExeSHA256 != "" {
		f["exe_sha256"] = p.ExeSHA256
	}
	if p.ExeDeleted {
		f["exe_deleted"] = true
	}
}

func (t *Tracker) listenerEvent(kind string, now time.Time, s Sock, p *Proc, baseline bool) event.Event {
	f := map[string]any{
		"proto": s.Proto, "addr": s.Local.Addr().String(), "port": int(s.Local.Port()),
		"inode": s.Inode, "sock_uid": s.UID,
	}
	if svc := t.cfg.Service(s.Proto, s.Local.Port()); svc != "" {
		f["service"] = svc
	}
	if baseline {
		f["baseline"] = true
	}
	procFields(f, p)
	return event.Event{Time: now, Kind: kind, Priority: event.PriorityHigh, Fields: f}
}

func (t *Tracker) connEvent(kind string, now time.Time, r *crec, baseline bool) event.Event {
	s := r.s
	f := map[string]any{
		"dir": r.dir, "proto": s.Proto,
		"laddr": s.Local.Addr().String(), "lport": int(s.Local.Port()),
		"raddr": s.Remote.Addr().String(), "rport": int(s.Remote.Port()),
		"inode": s.Inode, "sock_uid": s.UID,
	}
	// Service: the local port for inbound (what we serve), the remote port for
	// outbound (what we consume).
	port := s.Remote.Port()
	if r.dir == "inbound" {
		port = s.Local.Port()
	}
	if svc := t.cfg.Service(s.Proto, port); svc != "" {
		f["service"] = svc
	}
	var proto uint8 = ProtoTCP
	if s.Proto == "udp" {
		proto = ProtoUDP
	}
	src, dst := s.Local, s.Remote
	if r.dir == "inbound" {
		src, dst = dst, src
	}
	f["src"], f["dst"] = src.String(), dst.String()
	f["community_id"] = CommunityID(0, proto, src, dst)
	if s.HasBytes {
		f["bytes_out"], f["bytes_in"] = s.BytesOut, s.BytesIn
	}
	if kind == KindConnectionOpened {
		f["state"] = stateName(s.State)
		if baseline {
			f["baseline"] = true
		}
	} else {
		f["duration_ms"] = now.Sub(r.since).Milliseconds()
	}
	procFields(f, r.p)
	return event.Event{Time: now, Kind: kind, Priority: event.PriorityNormal, Fields: f}
}

var stateNames = map[uint8]string{1: "established", 2: "syn_sent", 3: "syn_recv", 4: "fin_wait1", 5: "fin_wait2",
	6: "time_wait", 7: "close", 8: "close_wait", 9: "last_ack", 10: "listen", 11: "closing"}

func stateName(s uint8) string {
	if n, ok := stateNames[s]; ok {
		return n
	}
	return fmt.Sprintf("state_%d", s)
}
