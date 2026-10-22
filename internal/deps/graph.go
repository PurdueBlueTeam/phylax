package deps

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

// Confidence levels.
const (
	ConfHigh   = "high"
	ConfMedium = "medium"
	ConfLow    = "low"
)

// ServiceRef names a service on a host. Host is empty and Addr set when the
// address does not belong to any known host (external or unknown).
type ServiceRef struct {
	Host    string `json:"host,omitempty"`
	Service string `json:"service,omitempty"` // manifest id, or "proto/port" when unnamed
	Proto   string `json:"proto,omitempty"`
	Port    uint16 `json:"port"`
	Addr    string `json:"addr,omitempty"`
}

func (r ServiceRef) String() string {
	if r.Host == "" {
		return fmt.Sprintf("%s:%d (%s)", r.Addr, r.Port, r.Proto)
	}
	return r.Host + "/" + r.Service
}

// Edge is one service dependency: From depends on To.
type Edge struct {
	From       ServiceRef `json:"from"`
	To         ServiceRef `json:"to"`
	DstName    string     `json:"dst_name,omitempty"`
	Count      int        `json:"count"`
	Requests   int        `json:"request_count"`
	Background int        `json:"background_count"`
	Strength   string     `json:"strength"`
	Periodic   bool       `json:"periodic,omitempty"`
	First      time.Time  `json:"first"`
	Last       time.Time  `json:"last"`
	Baseline   bool       `json:"baseline"` // seen in the learning window
	Gone       bool       `json:"gone,omitempty"`
	Public     bool       `json:"public,omitempty"`
	Confirmed  bool       `json:"confirmed"` // the destination host reported the matching inbound peer
	Confidence float64    `json:"confidence"`
	Level      string     `json:"level"`
	Evidence   []string   `json:"evidence"`
	Declared   bool       `json:"declared,omitempty"` // set by manifest comparison
}

type edgeID struct {
	fromHost, fromSvc, proto string
	dst                      netip.Addr
	port                     uint16
}

type gEdge struct {
	e       Edge
	srcAddr netip.Addr
	cids    []string
}

type hostSvc struct{ host, key string }

type listenRec struct {
	svc   string // service name or key
	proto string
	port  uint16
	addr  netip.Addr
}

type peerRec struct {
	host     string
	svc      string
	count    int
	cids     []string
	first    time.Time
	last     time.Time
	lport    uint16
	peerAddr netip.Addr
	proto    string
}

// Graph is the controller's join of the agents' deps.* events and listener
// inventory into a service dependency graph. Safe for concurrent use.
type Graph struct {
	mu        sync.Mutex
	edges     map[edgeID]*gEdge
	hostAddr  map[netip.Addr]string
	addrOf    map[string]netip.Addr
	listeners map[string]map[string]listenRec // host -> proto/port -> rec
	peers     map[string]*peerRec             // host|proto|peer|port
	scored    map[hostSvc]bool                // (host, service id) scored by the manifest
	unitSvc   map[hostSvc]string              // (host, unit or binary name) -> service id
	maxEdges  int
}

// NewGraph returns an empty graph.
func NewGraph() *Graph {
	return &Graph{
		edges: map[edgeID]*gEdge{}, hostAddr: map[netip.Addr]string{}, addrOf: map[string]netip.Addr{},
		listeners: map[string]map[string]listenRec{}, peers: map[string]*peerRec{},
		scored: map[hostSvc]bool{}, unitSvc: map[hostSvc]string{}, maxEdges: 16384,
	}
}

// LoadManifest registers host addresses, declared listeners, scored flags and
// unit names from the manifest.
func (g *Graph) LoadManifest(m *manifest.Manifest) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for name := range m.Hosts {
		if a, ok := m.HostAddr(name); ok {
			g.setAddr(name, a)
		}
	}
	for id, s := range m.Services {
		g.scored[hostSvc{s.Host, id}] = s.Scored
		if s.Process != nil {
			for _, u := range append([]string{s.Process.Unit}, s.Process.Units...) {
				if u != "" {
					g.unitSvc[hostSvc{s.Host, normUnit(u)}] = id
				}
			}
		}
		g.unitSvc[hostSvc{s.Host, normUnit(id)}] = id
		for _, l := range s.Listen {
			ps := l.PortSet()
			for _, p := range ps.Ports {
				g.addListener(s.Host, listenRec{svc: id, proto: l.Proto, port: p})
			}
		}
	}
}

func normUnit(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".service")) }

func (g *Graph) setAddr(host string, a netip.Addr) {
	a = a.Unmap()
	if a.IsUnspecified() || a.IsLoopback() || !a.IsValid() {
		return
	}
	if old, ok := g.addrOf[host]; ok && old != a {
		if g.hostAddr[old] == host {
			delete(g.hostAddr, old)
		}
	}
	g.addrOf[host] = a
	g.hostAddr[a] = host
}

func (g *Graph) addListener(host string, r listenRec) {
	m := g.listeners[host]
	if m == nil {
		m = map[string]listenRec{}
		g.listeners[host] = m
	}
	k := r.proto + "/" + strconv.Itoa(int(r.port))
	if old, ok := m[k]; ok && r.svc == k && old.svc != k {
		return // keep a name over an anonymous key
	}
	m[k] = r
}

// Ingest folds one stored event of the given agent (host) into the graph.
// Other event kinds are ignored.
func (g *Graph) Ingest(host string, e event.Event) {
	switch e.Kind {
	case KindEdge, KindEdgeGone, KindPeer, "net.listener_added", "net.listener_removed":
	default:
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	f := e.Fields
	switch e.Kind {
	case "net.listener_added", "net.listener_removed":
		proto, port := str(f, "proto"), uint16(num(f, "port"))
		if proto == "" || port == 0 {
			return
		}
		if e.Kind == "net.listener_removed" {
			// Declared listeners are kept; observed ones go away.
			if r, ok := g.listeners[host][proto+"/"+strconv.Itoa(int(port))]; ok && r.svc == proto+"/"+strconv.Itoa(int(port)) {
				delete(g.listeners[host], proto+"/"+strconv.Itoa(int(port)))
			}
			return
		}
		svc := str(f, "service")
		if svc == "" {
			svc = proto + "/" + strconv.Itoa(int(port))
		}
		a, _ := netip.ParseAddr(str(f, "addr"))
		g.addListener(host, listenRec{svc: svc, proto: proto, port: port, addr: a})
		if a.IsValid() && !a.IsUnspecified() {
			g.setAddr(host, a)
		}
	case KindPeer:
		g.ingestPeer(host, e)
	case KindEdge, KindEdgeGone:
		g.ingestEdge(host, e)
	}
}

func (g *Graph) ingestPeer(host string, e event.Event) {
	f := e.Fields
	pa, err := netip.ParseAddr(str(f, "peer_addr"))
	if err != nil {
		return
	}
	pa = pa.Unmap()
	k := host + "|" + str(f, "proto") + "|" + pa.String() + "|" + strconv.Itoa(num(f, "port"))
	r := g.peers[k]
	if r == nil {
		if len(g.peers) >= 65536 {
			return
		}
		r = &peerRec{host: host, proto: str(f, "proto"), peerAddr: pa, lport: uint16(num(f, "port"))}
		g.peers[k] = r
	}
	r.svc = svcName(f)
	if n := num(f, "count"); n > r.count {
		r.count = n
	}
	r.first, r.last = minT(r.first, ms(f, "first_seen_ms")), maxT(r.last, ms(f, "last_seen_ms"))
	r.cids = mergeStr(r.cids, strList(f, "community_ids"), 8)
}

func svcName(f map[string]any) string {
	if s := str(f, "service"); s != "" {
		return s
	}
	return str(f, "svc_key")
}

func (g *Graph) ingestEdge(host string, e event.Event) {
	f := e.Fields
	dst, err := netip.ParseAddr(str(f, "dst_addr"))
	if err != nil {
		return
	}
	dst = dst.Unmap()
	id := edgeID{fromHost: host, fromSvc: str(f, "svc_key"), proto: str(f, "proto"), dst: dst, port: uint16(num(f, "dst_port"))}
	if id.fromSvc == "" || id.port == 0 {
		return
	}
	ge := g.edges[id]
	if ge == nil {
		if len(g.edges) >= g.maxEdges {
			return
		}
		ge = &gEdge{}
		ge.e.From = ServiceRef{Host: host, Service: svcName(f), Proto: str(f, "svc_proto"), Port: uint16(num(f, "svc_port"))}
		ge.e.First = ms(f, "first_seen_ms")
		ge.e.Baseline = boolean(f, "learning")
		g.edges[id] = ge
	}
	ed := &ge.e
	if n := num(f, "count"); n > ed.Count {
		ed.Count = n
	}
	if n := num(f, "request_count"); n > ed.Requests {
		ed.Requests = n
	}
	if n := num(f, "background_count"); n > ed.Background {
		ed.Background = n
	}
	if s := svcName(f); s != "" && ed.From.Service != s {
		ed.From.Service = s
	}
	ed.First, ed.Last = minT(ed.First, ms(f, "first_seen_ms")), maxT(ed.Last, ms(f, "last_seen_ms"))
	ed.Public = boolean(f, "public")
	if n := str(f, "dst_name"); n != "" {
		ed.DstName = n
	}
	if boolean(f, "periodic") {
		ed.Periodic = true
	}
	if a, err := netip.ParseAddr(str(f, "src_addr")); err == nil {
		ge.srcAddr = a.Unmap()
		g.setAddr(host, a) // a service's outbound source address is the host's address
	}
	ge.cids = mergeStr(ge.cids, strList(f, "community_ids"), 8)
	ed.To = ServiceRef{Proto: id.proto, Port: id.port, Addr: dst.String()}
	// An edge event after a gone event means the dependency came back.
	ed.Gone = e.Kind == KindEdgeGone
}

// resolve fills To, strength, confirmation and confidence. Caller holds mu.
func (g *Graph) resolve(ge *gEdge) {
	ed := &ge.e
	dst, _ := netip.ParseAddr(ed.To.Addr)
	ed.To.Host, ed.To.Service = "", ""
	h, ok := g.hostAddr[dst]
	if dst.IsLoopback() {
		h, ok = ed.From.Host, true // a service on this host
	}
	if ok {
		ed.To.Host = h
		key := ed.To.Proto + "/" + strconv.Itoa(int(ed.To.Port))
		if l, ok := g.listeners[h][key]; ok {
			ed.To.Service = l.svc
		} else {
			ed.To.Service = key
		}
	}
	if ed.Requests >= 1 && ed.Requests*2 >= ed.Count {
		ed.Strength = StrengthStrong
	} else {
		ed.Strength = StrengthWeak
	}
	ed.Evidence = ed.Evidence[:0]
	score := 0.25
	if ed.Strength == StrengthStrong {
		score = 0.5
		ed.Evidence = append(ed.Evidence, fmt.Sprintf("request-driven: %d of %d connections opened while an inbound request was active", ed.Requests, ed.Count))
	} else if ed.Periodic {
		ed.Evidence = append(ed.Evidence, fmt.Sprintf("periodic background: %d connections", ed.Background))
	} else {
		ed.Evidence = append(ed.Evidence, fmt.Sprintf("background: %d connections", ed.Count))
	}
	if ed.To.Host != "" {
		score += 0.2
		ed.Evidence = append(ed.Evidence, "destination address belongs to host "+ed.To.Host)
	}
	// Join with the destination's own view of the inbound peer.
	ed.Confirmed = false
	if ed.To.Host != "" && ge.srcAddr.IsValid() {
		k := ed.To.Host + "|" + ed.To.Proto + "|" + ge.srcAddr.String() + "|" + strconv.Itoa(int(ed.To.Port))
		if p := g.peers[k]; p != nil {
			ed.Confirmed = true
			score += 0.2
			how := "peer address pair"
			if overlap(ge.cids, p.cids) {
				how = "Community ID"
				score += 0.1
			}
			ed.Evidence = append(ed.Evidence, fmt.Sprintf("%s reports %d inbound connections from %s (matched by %s)", p.host, p.count, ge.srcAddr, how))
		}
	}
	if ed.Count >= 5 {
		score += 0.1
	}
	if ed.DstName != "" {
		ed.Evidence = append(ed.Evidence, "resolved name "+ed.DstName)
	}
	if ed.Public {
		ed.Evidence = append(ed.Evidence, "destination is a public address")
	}
	if score > 1 {
		score = 1
	}
	ed.Confidence = score
	switch {
	case score >= 0.8:
		ed.Level = ConfHigh
	case score >= 0.5:
		ed.Level = ConfMedium
	default:
		ed.Level = ConfLow
	}
}

// Edges returns every dependency edge, resolved, sorted by source then target.
func (g *Graph) Edges() []Edge {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Edge, 0, len(g.edges))
	for _, ge := range g.edges {
		g.resolve(ge)
		e := ge.e
		e.Evidence = append([]string(nil), e.Evidence...)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.From != b.From {
			return a.From.String() < b.From.String()
		}
		if a.To.String() != b.To.String() {
			return a.To.String() < b.To.String()
		}
		return a.To.Proto < b.To.Proto
	})
	return out
}

// ServiceView is the dependency view of one service.
type ServiceView struct {
	Host        string `json:"host"`
	Service     string `json:"service"`
	Scored      bool   `json:"scored"`
	DependsOn   []Edge `json:"depends_on"`
	DependedBy  []Edge `json:"depended_on_by"`
	InboundOnly []Peer `json:"inbound_peers,omitempty"` // peers with no agent-side edge
}

// Peer is an inbound client of a service seen by the service's own host.
type Peer struct {
	Addr  string `json:"addr"`
	Host  string `json:"host,omitempty"`
	Count int    `json:"count"`
}

// Services groups the graph per service (both directions).
func (g *Graph) Services() []ServiceView {
	edges := g.Edges()
	g.mu.Lock()
	scored := func(h, s string) bool { return g.scored[hostSvc{h, s}] }
	g.mu.Unlock()
	by := map[hostSvc]*ServiceView{}
	get := func(h, s string) *ServiceView {
		k := hostSvc{h, s}
		v := by[k]
		if v == nil {
			v = &ServiceView{Host: h, Service: s, Scored: scored(h, s)}
			by[k] = v
		}
		return v
	}
	for _, e := range edges {
		get(e.From.Host, e.From.Service).DependsOn = append(get(e.From.Host, e.From.Service).DependsOn, e)
		if e.To.Host != "" {
			v := get(e.To.Host, e.To.Service)
			v.DependedBy = append(v.DependedBy, e)
		}
	}
	// Inbound peers that no edge explains (the other side has no agent).
	g.mu.Lock()
	explained := map[string]bool{}
	for _, ge := range g.edges {
		if ge.srcAddr.IsValid() {
			explained[ge.e.To.Host+"|"+ge.e.To.Proto+"|"+ge.srcAddr.String()+"|"+strconv.Itoa(int(ge.e.To.Port))] = true
		}
	}
	for k, p := range g.peers {
		if explained[k] {
			continue
		}
		v := get(p.host, p.svc)
		v.InboundOnly = append(v.InboundOnly, Peer{Addr: p.peerAddr.String(), Host: g.hostAddr[p.peerAddr], Count: p.count})
	}
	g.mu.Unlock()
	out := make([]ServiceView, 0, len(by))
	for _, v := range by {
		sort.Slice(v.InboundOnly, func(i, j int) bool { return v.InboundOnly[i].Addr < v.InboundOnly[j].Addr })
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Service < out[j].Service
	})
	return out
}

// DependsOn returns the edges out of (host, service).
func (g *Graph) DependsOn(host, service string) []Edge {
	var out []Edge
	for _, e := range g.Edges() {
		if e.From.Host == host && e.From.Service == service {
			out = append(out, e)
		}
	}
	return out
}

// DependedOnBy returns the edges into (host, service).
func (g *Graph) DependedOnBy(host, service string) []Edge {
	var out []Edge
	for _, e := range g.Edges() {
		if e.To.Host == host && e.To.Service == service {
			out = append(out, e)
		}
	}
	return out
}

// Scored reports whether the manifest marks (host, service) as scored.
func (g *Graph) Scored(host, service string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.scored[hostSvc{host, service}]
}

// ServiceByName maps a unit, binary or service name on a host to the service
// id the graph knows it by ("" if unknown).
func (g *Graph) ServiceByName(host, name string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.unitSvc[hostSvc{host, normUnit(name)}]
}

// ---- field helpers ----

func str(f map[string]any, k string) string { s, _ := f[k].(string); return s }

func num(f map[string]any, k string) int {
	switch v := f[k].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case uint64:
		return int(v)
	case float64:
		return int(v)
	case interface{ Int64() (int64, error) }: // json.Number
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

func boolean(f map[string]any, k string) bool { b, _ := f[k].(bool); return b }

func ms(f map[string]any, k string) time.Time {
	n := num(f, k)
	if n == 0 {
		return time.Time{}
	}
	return time.UnixMilli(int64(n)).UTC()
}

func strList(f map[string]any, k string) []string {
	switch v := f[k].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func mergeStr(a, b []string, max int) []string {
	for _, v := range b {
		a = addSample(a, v, max)
	}
	return a
}

func overlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func minT(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

func maxT(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
