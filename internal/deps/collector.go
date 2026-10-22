package deps

import (
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Op is what happened to a connection in this observation.
type Op uint8

// Connection operations.
const (
	Opened Op = iota + 1
	Closed
)

// Listener is a listening socket and its owner, as the net module sees it.
type Listener struct {
	Proto   string
	Addr    netip.Addr
	Port    uint16
	PID     int
	Comm    string
	Exe     string
	SHA256  string
	Service string // manifest service id when known
}

// ConnEvent is a connection that opened or closed since the last observation.
type ConnEvent struct {
	Op          Op
	Dir         string // inbound | outbound
	Proto       string
	Local       netip.AddrPort
	Remote      netip.AddrPort
	PID         int
	Exe         string // used only when the process tree cannot be walked
	CommunityID string
	Baseline    bool   // existed when the agent started: open time unknown
	DstService  string // configured name of the consumed port, if any
}

// Config tunes a Collector. Zero values are safe defaults.
type Config struct {
	Learn       time.Duration // learning window after start (default 15m)
	Report      time.Duration // periodic re-emission of changed aggregates (default 5m)
	GoneAfter   time.Duration // a learned edge unseen this long is gone (default 30m)
	GoneMin     int           // minimum observations before an edge can be "gone" (default 3)
	MaxServices int           // default 128
	MaxEdges    int           // per service (default 128)
	MaxPeers    int           // inbound peers per service (default 128)
	CIDSamples  int           // community ids kept per aggregate (default 4)
	DNS         *DNSCache
	Now         func() time.Time
}

func (c *Config) defaults() {
	if c.Learn <= 0 {
		c.Learn = 15 * time.Minute
	}
	if c.Report <= 0 {
		c.Report = 5 * time.Minute
	}
	if c.GoneAfter <= 0 {
		c.GoneAfter = 30 * time.Minute
	}
	if c.GoneMin <= 0 {
		c.GoneMin = 3
	}
	if c.MaxServices <= 0 {
		c.MaxServices = 128
	}
	if c.MaxEdges <= 0 {
		c.MaxEdges = 128
	}
	if c.MaxPeers <= 0 {
		c.MaxPeers = 128
	}
	if c.CIDSamples <= 0 {
		c.CIDSamples = 4
	}
}

// maxTreeDepth bounds the ancestor walk from a connection's process to a
// listener owner.
const maxTreeDepth = 16

// Collector attributes outbound connections to listening services and
// aggregates them. Not safe for concurrent use: the net module's poll loop
// owns it.
type Collector struct {
	cfg        Config
	start      time.Time
	started    bool
	lastReport time.Time
	svcs       map[string]*svc
	dropped    uint64
}

type svc struct {
	key     string // "proto/port" of the primary listener
	name    string // configured service name, "" if none
	proto   string
	port    uint16
	ports   []uint16
	pid     int
	comm    string
	exe     string
	sha     string
	live    bool
	inbound map[string]struct{} // active inbound connections
	edges   map[edgeKey]*edge
	peers   map[peerKey]*peer
}

type edgeKey struct {
	proto string
	addr  netip.Addr
	port  uint16
}

type edge struct {
	count, req, bg   int
	first, last      time.Time
	lastBg           time.Time
	gapSum           time.Duration
	gapMin, gapMax   time.Duration
	gaps             int
	name             string
	srcAddr          netip.Addr
	dstSvc           string
	cids             []string
	learned          bool
	dirty, gone, bl  bool
	emittedStrength  string
	baselineObserved bool
}

type peerKey struct {
	proto string
	addr  netip.Addr
	port  uint16
}

type peer struct {
	count       int
	first, last time.Time
	cids        []string
	dirty       bool
}

// NewCollector returns a collector.
func NewCollector(cfg Config) *Collector {
	cfg.defaults()
	return &Collector{cfg: cfg, svcs: map[string]*svc{}}
}

// Dropped counts aggregates not tracked because of the bounds.
func (c *Collector) Dropped() uint64 { return c.dropped }

// Observe folds one poll's worth of state into the aggregates and returns the
// events to emit. listeners is the full current listener set; evs the
// connections opened or closed since the previous call; parent maps a pid to
// its parent pid (0 when unknown).
func (c *Collector) Observe(now time.Time, listeners []Listener, evs []ConnEvent, parent func(pid int) int) []event.Event {
	if !c.started {
		c.started, c.start, c.lastReport = true, now, now
	}
	roots, portSvc := c.update(listeners)

	// Inbound activity first: a request that opened and closed inside this
	// poll still counts as "active" for outbound connections of the same poll.
	closedNow := map[*svc]bool{}
	var closedKeys []struct {
		s *svc
		k string
	}
	for _, e := range evs {
		if e.Dir != "inbound" {
			continue
		}
		s := portSvc[e.Proto+"/"+strconv.Itoa(int(e.Local.Port()))]
		if s == nil {
			continue
		}
		k := e.Proto + "|" + e.Local.String() + "|" + e.Remote.String()
		switch e.Op {
		case Opened:
			s.inbound[k] = struct{}{}
			c.notePeer(s, e, now)
		case Closed:
			closedNow[s] = true
			closedKeys = append(closedKeys, struct {
				s *svc
				k string
			}{s, k})
		}
	}

	var out []event.Event
	for _, e := range evs {
		if e.Dir != "outbound" || e.Op != Opened || !e.Remote.IsValid() || e.Remote.Addr().IsUnspecified() {
			continue
		}
		s := c.attribute(e, roots, parent)
		if s == nil {
			continue
		}
		if ev, ok := c.noteEdge(now, s, e, len(s.inbound) > 0 || closedNow[s]); ok {
			out = append(out, ev)
		}
	}
	for _, ck := range closedKeys {
		delete(ck.s.inbound, ck.k)
	}

	out = append(out, c.periodic(now)...)
	return out
}

// update refreshes services from the listener set and returns the root-pid and
// port indexes.
func (c *Collector) update(ls []Listener) (map[int]*svc, map[string]*svc) {
	for _, s := range c.svcs {
		s.live = false
	}
	// Group listeners by owning process; the primary listener names the service.
	byPID := map[int][]Listener{}
	for _, l := range ls {
		if l.PID <= 0 {
			continue
		}
		byPID[l.PID] = append(byPID[l.PID], l)
	}
	roots := map[int]*svc{}
	portSvc := map[string]*svc{}
	pids := make([]int, 0, len(byPID))
	for p := range byPID {
		pids = append(pids, p)
	}
	sort.Ints(pids)
	for _, pid := range pids {
		g := byPID[pid]
		sort.Slice(g, func(i, j int) bool {
			if (g[i].Service != "") != (g[j].Service != "") {
				return g[i].Service != ""
			}
			if g[i].Port != g[j].Port {
				return g[i].Port < g[j].Port
			}
			return g[i].Proto < g[j].Proto
		})
		p := g[0]
		key := p.Proto + "/" + strconv.Itoa(int(p.Port))
		s := c.svcs[key]
		if s == nil {
			if len(c.svcs) >= c.cfg.MaxServices {
				c.dropped++
				continue
			}
			s = &svc{key: key, proto: p.Proto, port: p.Port, inbound: map[string]struct{}{},
				edges: map[edgeKey]*edge{}, peers: map[peerKey]*peer{}}
			c.svcs[key] = s
		}
		s.live, s.pid, s.comm, s.exe, s.sha, s.name = true, pid, p.Comm, p.Exe, p.SHA256, p.Service
		s.ports = s.ports[:0]
		for _, l := range g {
			s.ports = append(s.ports, l.Port)
			portSvc[l.Proto+"/"+strconv.Itoa(int(l.Port))] = s
		}
		roots[pid] = s
	}
	return roots, portSvc
}

// attribute finds the service whose process tree made the connection.
func (c *Collector) attribute(e ConnEvent, roots map[int]*svc, parent func(int) int) *svc {
	pid := e.PID
	for i := 0; pid > 1 && i < maxTreeDepth; i++ {
		if s := roots[pid]; s != nil {
			return s
		}
		if parent == nil {
			break
		}
		pid = parent(pid)
	}
	// Orphaned worker (parent exited, reparented to init): fall back to the
	// binary, but only when exactly one service runs it.
	if e.Exe == "" {
		return nil
	}
	var found *svc
	for _, s := range roots {
		if s.exe == e.Exe {
			if found != nil {
				return nil
			}
			found = s
		}
	}
	return found
}

func (c *Collector) noteEdge(now time.Time, s *svc, e ConnEvent, request bool) (event.Event, bool) {
	// A service talking to itself (loopback to its own listener) is not a dependency.
	if e.Remote.Addr().IsLoopback() {
		for _, p := range s.ports {
			if p == e.Remote.Port() {
				return event.Event{}, false
			}
		}
	}
	k := edgeKey{e.Proto, e.Remote.Addr().Unmap(), e.Remote.Port()}
	ed := s.edges[k]
	isNew := ed == nil
	if isNew {
		if len(s.edges) >= c.cfg.MaxEdges {
			c.dropped++
			return event.Event{}, false
		}
		ed = &edge{first: now, learned: now.Sub(c.start) < c.cfg.Learn, dstSvc: e.DstService, dirty: true}
		ed.name = c.cfg.DNS.Lookup(k.addr, now)
		s.edges[k] = ed
	}
	ed.count++
	ed.last = now
	ed.gone = false
	ed.dirty = true
	ed.srcAddr = e.Local.Addr().Unmap()
	if ed.name == "" {
		ed.name = c.cfg.DNS.Lookup(k.addr, now)
	}
	ed.cids = addSample(ed.cids, e.CommunityID, c.cfg.CIDSamples)
	switch {
	case e.Baseline:
		ed.bl = true // open since before the agent started: counts as background
		ed.bg++
	case request:
		ed.req++
	default:
		ed.bg++
		if !ed.lastBg.IsZero() {
			g := now.Sub(ed.lastBg)
			ed.gapSum += g
			if ed.gaps == 0 || g < ed.gapMin {
				ed.gapMin = g
			}
			if g > ed.gapMax {
				ed.gapMax = g
			}
			ed.gaps++
		}
		ed.lastBg = now
	}
	if isNew {
		return c.edgeEvent(now, s, k, ed, true), true
	}
	return event.Event{}, false
}

func addSample(l []string, v string, max int) []string {
	if v == "" {
		return l
	}
	for _, x := range l {
		if x == v {
			return l
		}
	}
	if len(l) >= max {
		l = l[1:]
	}
	return append(l, v)
}

func (c *Collector) notePeer(s *svc, e ConnEvent, now time.Time) {
	k := peerKey{e.Proto, e.Remote.Addr().Unmap(), e.Local.Port()}
	p := s.peers[k]
	if p == nil {
		if len(s.peers) >= c.cfg.MaxPeers {
			c.dropped++
			return
		}
		p = &peer{first: now}
		s.peers[k] = p
	}
	p.count++
	p.last = now
	p.dirty = true
	p.cids = addSample(p.cids, e.CommunityID, c.cfg.CIDSamples)
}

// periodic re-emits changed aggregates and reports vanished dependencies.
func (c *Collector) periodic(now time.Time) []event.Event {
	var out []event.Event
	report := now.Sub(c.lastReport) >= c.cfg.Report
	if report {
		c.lastReport = now
	}
	keys := make([]string, 0, len(c.svcs))
	for k := range c.svcs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, sk := range keys {
		s := c.svcs[sk]
		ekeys := make([]edgeKey, 0, len(s.edges))
		for k := range s.edges {
			ekeys = append(ekeys, k)
		}
		sort.Slice(ekeys, func(i, j int) bool {
			a, b := ekeys[i], ekeys[j]
			if a.addr != b.addr {
				return a.addr.Less(b.addr)
			}
			if a.port != b.port {
				return a.port < b.port
			}
			return a.proto < b.proto
		})
		for _, k := range ekeys {
			ed := s.edges[k]
			if s.live && !ed.gone && ed.count >= c.cfg.GoneMin && now.Sub(ed.last) >= c.cfg.GoneAfter {
				ed.gone = true
				out = append(out, c.goneEvent(now, s, k, ed))
				continue
			}
			if report && ed.dirty && !ed.gone {
				ed.dirty = false
				out = append(out, c.edgeEvent(now, s, k, ed, false))
			}
		}
		if report {
			pkeys := make([]peerKey, 0, len(s.peers))
			for k, p := range s.peers {
				if p.dirty {
					pkeys = append(pkeys, k)
				}
			}
			sort.Slice(pkeys, func(i, j int) bool {
				a, b := pkeys[i], pkeys[j]
				if a.addr != b.addr {
					return a.addr.Less(b.addr)
				}
				return a.port < b.port
			})
			for _, k := range pkeys {
				p := s.peers[k]
				p.dirty = false
				out = append(out, c.peerEvent(now, s, k, p))
			}
		}
	}
	return out
}

func strength(ed *edge) string {
	if ed.req >= 1 && ed.req*2 >= ed.count {
		return StrengthStrong
	}
	return StrengthWeak
}

// periodicBg reports whether the background opens are evenly spaced (cron or
// a keep-alive/refresh timer rather than traffic).
func periodicBg(ed *edge) (bool, time.Duration) {
	if ed.gaps < 3 {
		return false, 0
	}
	mean := ed.gapSum / time.Duration(ed.gaps)
	return mean > 0 && ed.gapMax-ed.gapMin <= mean/4, mean
}

func isPublic(a netip.Addr) bool {
	return !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || cgnat.Contains(a))
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// IsPublic reports whether a is a publicly routable address.
func IsPublic(a netip.Addr) bool { return isPublic(a.Unmap()) }

func (c *Collector) svcFields(s *svc) map[string]any {
	f := map[string]any{"svc_key": s.key, "svc_proto": s.proto, "svc_port": int(s.port),
		"svc_pid": s.pid, "svc_comm": s.comm}
	if s.name != "" {
		f["service"] = s.name
	}
	if s.exe != "" {
		f["svc_exe"] = s.exe
	}
	if s.sha != "" {
		f["svc_exe_sha256"] = s.sha
	}
	if len(s.ports) > 1 {
		ps := append([]uint16(nil), s.ports...)
		sort.Slice(ps, func(i, j int) bool { return ps[i] < ps[j] })
		l := make([]any, len(ps))
		for i, p := range ps {
			l[i] = int(p)
		}
		f["svc_ports"] = l
	}
	return f
}

func cidList(l []string) []any {
	out := make([]any, len(l))
	for i, v := range l {
		out[i] = v
	}
	return out
}

func (c *Collector) edgeEvent(now time.Time, s *svc, k edgeKey, ed *edge, isNew bool) event.Event {
	f := c.svcFields(s)
	f["edge"] = k.proto + "/" + k.addr.String() + "/" + strconv.Itoa(int(k.port))
	f["proto"] = k.proto
	f["dst_addr"] = k.addr.String()
	f["dst_port"] = int(k.port)
	f["public"] = isPublic(k.addr)
	f["count"] = ed.count
	f["request_count"] = ed.req
	f["background_count"] = ed.bg
	f["strength"] = strength(ed)
	f["first_seen_ms"] = ed.first.UnixMilli()
	f["last_seen_ms"] = ed.last.UnixMilli()
	f["new"] = isNew
	f["learning"] = ed.learned
	if per, mean := periodicBg(ed); per {
		f["periodic"] = true
		f["period_ms"] = mean.Milliseconds()
	}
	if ed.srcAddr.IsValid() {
		f["src_addr"] = ed.srcAddr.String()
	}
	if ed.name != "" {
		f["dst_name"] = ed.name
	}
	if ed.dstSvc != "" {
		f["dst_service"] = ed.dstSvc
	}
	if ed.bl {
		f["baseline"] = true
	}
	if len(ed.cids) > 0 {
		f["community_ids"] = cidList(ed.cids)
	}
	prio := event.PriorityNormal
	if isNew {
		prio = event.PriorityHigh
	}
	return event.Event{Time: now, Kind: KindEdge, Priority: prio, Fields: f}
}

func (c *Collector) goneEvent(now time.Time, s *svc, k edgeKey, ed *edge) event.Event {
	f := c.svcFields(s)
	f["edge"] = k.proto + "/" + k.addr.String() + "/" + strconv.Itoa(int(k.port))
	f["proto"] = k.proto
	f["dst_addr"] = k.addr.String()
	f["dst_port"] = int(k.port)
	f["public"] = isPublic(k.addr)
	f["count"] = ed.count
	f["strength"] = strength(ed)
	f["learning"] = ed.learned
	f["first_seen_ms"] = ed.first.UnixMilli()
	f["last_seen_ms"] = ed.last.UnixMilli()
	f["idle_ms"] = now.Sub(ed.last).Milliseconds()
	if ed.name != "" {
		f["dst_name"] = ed.name
	}
	return event.Event{Time: now, Kind: KindEdgeGone, Priority: event.PriorityHigh, Fields: f}
}

func (c *Collector) peerEvent(now time.Time, s *svc, k peerKey, p *peer) event.Event {
	f := c.svcFields(s)
	f["proto"] = k.proto
	f["peer_addr"] = k.addr.String()
	f["port"] = int(k.port)
	f["count"] = p.count
	f["first_seen_ms"] = p.first.UnixMilli()
	f["last_seen_ms"] = p.last.UnixMilli()
	if len(p.cids) > 0 {
		f["community_ids"] = cidList(p.cids)
	}
	return event.Event{Time: now, Kind: KindPeer, Priority: event.PriorityBulk, Fields: f}
}
