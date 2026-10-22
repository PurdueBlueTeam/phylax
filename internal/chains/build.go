package chains

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/traceback"
)

// Config tunes chain building. Zero values take the defaults noted.
type Config struct {
	Window        time.Duration // expansion bound either side of the seed (2h)
	MaxHops       int           // hop limit (12)
	AccountWindow time.Duration // "same account within N seconds" (120s)
	StitchSkew    time.Duration // clock skew allowed when matching a connection across hosts (10s)
	GapSlack      time.Duration // an agent gap this near a hop lowers its confidence (10m)
	// Offset returns an agent's clock minus the controller's (default none).
	Offset func(agent string) time.Duration
	// Hosts maps an address to the agent that owns it. Addresses are also
	// learned from the hosts' own connection records.
	Hosts map[string]string
	// Label classifies an address: "us", "scorer", "other" or "". Sources
	// labeled us or scorer never start or join a chain.
	Label func(addr string) string
	// IgnoreAccounts never link hops by shared account (default root, system,
	// service accounts).
	IgnoreAccounts []string
	// NoisyExecs are short utility processes dropped from a chain unless they
	// matter (the seed, or something follows from them).
	NoisyExecs []string
}

var defaultIgnore = []string{"root", "system", "local service", "network service", "anonymous logon", "nobody", "-"}
var defaultNoisy = []string{"ls", "cat", "pwd", "clear", "sleep", "true", "false", "echo", "date", "tty", "dircolors", "locale"}

func (c Config) withDefaults() Config {
	if c.Window <= 0 {
		c.Window = 2 * time.Hour
	}
	if c.MaxHops <= 0 {
		c.MaxHops = 12
	}
	if c.AccountWindow <= 0 {
		c.AccountWindow = 120 * time.Second
	}
	if c.StitchSkew <= 0 {
		c.StitchSkew = 10 * time.Second
	}
	if c.GapSlack <= 0 {
		c.GapSlack = 10 * time.Minute
	}
	if c.IgnoreAccounts == nil {
		c.IgnoreAccounts = defaultIgnore
	}
	if c.NoisyExecs == nil {
		c.NoisyExecs = defaultNoisy
	}
	return c
}

func (c Config) off(a string) time.Duration {
	if c.Offset == nil {
		return 0
	}
	return c.Offset(a)
}

func (c Config) ignored(acct string) bool {
	if acct == "" || strings.HasSuffix(acct, "$") {
		return true
	}
	for _, a := range c.IgnoreAccounts {
		if a == acct {
			return true
		}
	}
	return false
}

func (c Config) ours(addr string) bool {
	if c.Label == nil || addr == "" {
		return false
	}
	l := c.Label(addr)
	return l == "us" || l == "scorer"
}

// Builder builds chains from the store.
type Builder struct {
	Src traceback.Source
	Cfg Config
}

// Seed is what starts a chain: a high-severity alert, an untagged service
// change, a red check, a decoy hit, a honeytoken use or a ledger alert.
type Seed struct {
	Kind  SeedKind
	Agent string
	Time  time.Time
	Path  string
	Event *event.Event
	Alert *detect.Alert
}

// SeedFromAlert turns an alert into a seed when it qualifies: severity high or
// critical, or a decoy, honeytoken or ledger detection of any severity.
func SeedFromAlert(a detect.Alert) (Seed, bool) {
	id := strings.ToLower(a.RuleID + " " + a.Title)
	s := Seed{Kind: SeedAlert, Agent: a.Agent, Time: a.Time, Alert: &a}
	if n := len(a.Evidence); n > 0 {
		e := a.Evidence[n-1]
		s.Event = &e
		if s.Agent == "" {
			s.Agent = e.Agent
		}
	}
	switch {
	case strings.Contains(id, "honeytoken"):
		s.Kind = SeedHoneytoken
	case strings.Contains(id, "decoy"):
		s.Kind = SeedDecoy
	case strings.Contains(id, "ledger") || strings.Contains(id, "integrity"):
		s.Kind = SeedLedger
	case a.Severity == "high" || a.Severity == "critical":
	default:
		return s, false
	}
	return s, true
}

// ErrNoSeedEvent is returned when no event could be found for the seed.
var ErrNoSeedEvent = errors.New("chains: no event found for the seed")

// ---- run state ----

type node struct {
	Hop
	cause       *node
	ing         *ingress
	dist        int
	prio        int
	isSeed      bool
	causeConf   float64
	causeMethod string
	order       int
	hosts       []string
	forced      bool
	noisy       bool
	dead        bool
	failures    int
	stitchOut   int // outbound observation index + 1; 0 when none
}

type ingress struct {
	n       *node
	host    string
	remote  string
	account string
	service string
	start   time.Time
	last    time.Time
	hasAuth bool
}

type session struct {
	i      int
	host   string
	remote string
	ing    *ingress
}

type attachment struct {
	ing    *ingress
	method string
	conf   float64
	note   string
	depth  int
}

type hostPID struct {
	host string
	pid  int64
}

type run struct {
	b    *Builder
	cfg  Config
	ctx  context.Context
	obs  []traceback.Obs
	idx  map[traceback.Ref]int
	t0   time.Time
	note []string

	procsByHost map[string][]int
	sessByPID   map[hostPID][]*session
	sessions    []*session
	outsByHost  map[string][]int
	outByCID    map[string][]int
	outByTuple  map[string][]int
	closeAt     map[string]time.Time
	hostAddr    map[string]string
	addrsOf     map[string][]string
	ingresses   []*ingress
	nodes       []*node
	procNodes   map[int]*node
	procBusy    map[int]bool
	chgNodes    map[int]*node
	outNodes    map[int]*node
	consumed    map[int]bool
	egressKey   map[string]*node
	failsBy     map[string][]int
	procByPID   map[hostPID][]int
	inByCID     map[string][]*session
	inByTuple   map[string][]*session
	procMemo    map[int]*node
	authDone    map[int]*ingress
}

func tupleKey(laddr string, lport int, raddr string, rport int) string {
	return fmt.Sprintf("%s:%d>%s:%d", laddr, lport, raddr, rport)
}

// Build builds the chain for seed.
func (b *Builder) Build(ctx context.Context, seed Seed) (*Chain, error) {
	cfg := b.Cfg.withDefaults()
	r := &run{b: b, cfg: cfg, ctx: ctx, idx: map[traceback.Ref]int{},
		procsByHost: map[string][]int{}, sessByPID: map[hostPID][]*session{}, outsByHost: map[string][]int{},
		outByCID: map[string][]int{}, outByTuple: map[string][]int{}, closeAt: map[string]time.Time{},
		hostAddr: map[string]string{}, addrsOf: map[string][]string{}, procNodes: map[int]*node{}, procBusy: map[int]bool{},
		chgNodes: map[int]*node{}, outNodes: map[int]*node{}, consumed: map[int]bool{}, egressKey: map[string]*node{},
		failsBy: map[string][]int{}, procByPID: map[hostPID][]int{}, inByCID: map[string][]*session{}, inByTuple: map[string][]*session{}, procMemo: map[int]*node{}, authDone: map[int]*ingress{}}
	for a, h := range cfg.Hosts {
		r.hostAddr[a] = h
		r.addrsOf[h] = append(r.addrsOf[h], a)
	}
	seedT := seed.Time
	if seed.Event != nil {
		seedT = seed.Event.Time.Add(-cfg.off(seed.Event.Agent))
	}
	if seedT.IsZero() {
		return nil, errors.New("chains: seed has no time")
	}
	r.t0 = seedT
	if err := r.load(ctx, seed); err != nil {
		return nil, err
	}
	si, err := r.seedObs(seed)
	if err != nil {
		return nil, err
	}
	r.index()
	r.buildIngresses()
	// One pass in time order creates every hop that ties into a session.
	for i := range r.obs {
		o := &r.obs[i]
		switch o.Class {
		case traceback.ClassProc:
			r.procNode(i)
		case traceback.ClassFile, traceback.ClassSec:
			r.changeNode(i)
		case traceback.ClassConnOpen, traceback.ClassEgressDenied:
			if o.Dir == "out" {
				r.outNode(i)
			}
		}
	}
	sn := r.seedNode(si, seed)
	r.resolveMoveCauses()
	r.prune(sn)
	return r.finish(ctx, sn, seed)
}

// ---- loading ----

func (r *run) load(ctx context.Context, seed Seed) error {
	agents, err := r.b.Src.Agents(ctx)
	if err != nil {
		return err
	}
	lo, hi := r.t0.Add(-r.cfg.Window), r.t0.Add(r.cfg.Window)
	for _, a := range agents {
		off := r.cfg.off(a.ID)
		// Stored times are the agent's clock: widen the query by the offset.
		evs, err := r.b.Src.Events(ctx, store.Query{Agent: a.ID, From: lo.Add(off), To: hi.Add(off), Limit: store.MaxQueryLimit})
		if err != nil {
			return err
		}
		if len(evs) >= store.MaxQueryLimit {
			r.note = append(r.note, fmt.Sprintf("%s: more than %d events in the window; the oldest or newest may be missing", a.ID, store.MaxQueryLimit))
		}
		for _, e := range evs {
			r.obs = append(r.obs, traceback.Normalize(e, off))
		}
	}
	sort.SliceStable(r.obs, func(i, j int) bool { return r.obs[i].T.Before(r.obs[j].T) })
	return nil
}

func (r *run) seedObs(seed Seed) (int, error) {
	r.reindex()
	if seed.Event != nil {
		o := traceback.Normalize(*seed.Event, r.cfg.off(seed.Event.Agent))
		if i, ok := r.idx[o.Ref()]; ok {
			return i, nil
		}
		r.obs = append(r.obs, o)
		sort.SliceStable(r.obs, func(i, j int) bool { return r.obs[i].T.Before(r.obs[j].T) })
		r.reindex()
		return r.idx[o.Ref()], nil
	}
	best := -1
	for i, o := range r.obs {
		if o.Host != seed.Agent || o.Tag != "" || o.T.After(seed.Time.Add(30*time.Second)) {
			continue
		}
		if o.Class != traceback.ClassFile || (seed.Path != "" && o.Path != seed.Path) {
			continue
		}
		best = i // sorted by time: the latest wins
	}
	if best < 0 {
		return 0, ErrNoSeedEvent
	}
	return best, nil
}

func (r *run) reindex() {
	r.idx = make(map[traceback.Ref]int, len(r.obs))
	for i := range r.obs {
		r.idx[r.obs[i].Ref()] = i
	}
}

func (r *run) index() {
	for i := range r.obs {
		o := &r.obs[i]
		switch o.Class {
		case traceback.ClassProc:
			r.procsByHost[o.Host] = append(r.procsByHost[o.Host], i)
			r.procByPID[hostPID{o.Host, o.PID}] = append(r.procByPID[hostPID{o.Host, o.PID}], i)
		case traceback.ClassConnOpen, traceback.ClassEgressDenied:
			if o.LAddr != "" && !traceback.IsLoopback(o.LAddr) {
				if _, ok := r.hostAddr[o.LAddr]; !ok && o.Class == traceback.ClassConnOpen {
					r.hostAddr[o.LAddr] = o.Host
					r.addrsOf[o.Host] = append(r.addrsOf[o.Host], o.LAddr)
				}
			}
			if o.Dir == "out" {
				r.outsByHost[o.Host] = append(r.outsByHost[o.Host], i)
				if o.CID != "" {
					r.outByCID[o.CID] = append(r.outByCID[o.CID], i)
				}
				if o.LAddr != "" {
					k := tupleKey(o.LAddr, o.LPort, o.RAddr, o.RPort)
					r.outByTuple[k] = append(r.outByTuple[k], i)
				}
			}
		case traceback.ClassConnClose:
			if o.CID != "" {
				r.closeAt[o.Host+"|"+o.CID] = o.T
			}
		case traceback.ClassAuthFail:
			k := o.Host + "|" + o.Source
			r.failsBy[k] = append(r.failsBy[k], i)
		}
	}
	for i := range r.obs {
		o := &r.obs[i]
		if o.Class != traceback.ClassConnOpen || o.Dir != "in" || o.RAddr == "" || traceback.IsLoopback(o.RAddr) || r.cfg.ours(o.RAddr) {
			continue
		}
		s := &session{i: i, host: o.Host, remote: o.RAddr}
		r.sessions = append(r.sessions, s)
		if o.CID != "" {
			r.inByCID[o.CID] = append(r.inByCID[o.CID], s)
		}
		if o.LAddr != "" {
			k := tupleKey(o.RAddr, o.RPort, o.LAddr, o.LPort)
			r.inByTuple[k] = append(r.inByTuple[k], s)
		}
		if o.PID > 4 { // PID 4 is http.sys on Windows: it owns every socket
			k := hostPID{o.Host, o.PID}
			r.sessByPID[k] = append(r.sessByPID[k], s)
		}
	}
}

// ---- process lookup and attachment ----

func (r *run) findProc(host string, pid int64, ticks uint64, at time.Time) int {
	best := -1
	for _, i := range r.procByPID[hostPID{host, pid}] {
		p := &r.obs[i]
		if p.T.After(at.Add(time.Second)) {
			continue
		}
		if ticks != 0 && p.StartTicks != 0 && p.StartTicks != ticks {
			continue
		}
		if best < 0 || p.T.After(r.obs[best].T) {
			best = i
		}
	}
	return best
}

func (r *run) sessionOwned(host string, pid int64, ticks uint64, at time.Time) (*session, bool) {
	var best *session
	exact := false
	for _, s := range r.sessByPID[hostPID{host, pid}] {
		c := &r.obs[s.i]
		if c.T.After(at.Add(time.Second)) {
			continue
		}
		ex := false
		if c.StartTicks != 0 && ticks != 0 {
			if c.StartTicks != ticks {
				continue // pid reused
			}
			ex = true
		}
		if best == nil || c.T.After(r.obs[best.i].T) {
			best, exact = s, ex
		}
	}
	return best, exact
}

func (r *run) ingressByAccount(host, acct string, at time.Time) *ingress {
	var best *ingress
	for _, g := range r.ingresses {
		if g.host != host || g.account != acct || at.Before(g.start.Add(-5*time.Second)) || at.Sub(g.last) > r.cfg.AccountWindow {
			continue
		}
		if best == nil || g.last.After(best.last) {
			best = g
		}
	}
	return best
}

// attach ties an observation to the access that made it possible: a process
// (or an ancestor) owning an inbound socket, else the same account within N
// seconds on the same host.
func (r *run) attach(o *traceback.Obs) *attachment {
	pid, ticks, ppid := o.PID, o.StartTicks, o.PPID
	user := o.User
	if user == "" {
		user = o.Actor
	}
	t := o.T
	if o.Class != traceback.ClassProc && pid != 0 {
		if pi := r.findProc(o.Host, pid, ticks, o.T); pi >= 0 {
			p := &r.obs[pi]
			ppid, t = p.PPID, p.T
			if user == "" {
				user = p.User
			}
		}
	}
	for depth := 0; depth < 16; depth++ {
		if pid != 0 {
			if s, exact := r.sessionOwned(o.Host, pid, ticks, o.T); s != nil {
				conf, note := 0.95, "process owned the client socket"
				m := MethodSocket
				if depth > 0 {
					conf, m, note = 0.9, MethodLineage, "an ancestor process owned the client socket"
				}
				if !exact {
					conf -= 0.1
					note += " (pid match only)"
				}
				return &attachment{ing: r.ingressOfSession(s), method: m, conf: conf, note: note, depth: depth}
			}
		}
		if user != "" && !r.cfg.ignored(user) {
			if g := r.ingressByAccount(o.Host, user, t); g != nil {
				return &attachment{ing: g, method: MethodSameAccount, conf: 0.6,
					note: fmt.Sprintf("account %s logged in on this host within %s", user, r.cfg.AccountWindow), depth: depth}
			}
		}
		if ppid == 0 {
			break
		}
		if pi := r.findProc(o.Host, ppid, 0, t); pi >= 0 {
			p := &r.obs[pi]
			pid, ticks, ppid, t = p.PID, p.StartTicks, p.PPID, p.T
			if p.User != "" {
				user = p.User
			}
		} else {
			pid, ticks, ppid = ppid, 0, 0 // forked parent with no process_start: its sockets only
		}
	}
	return nil
}

func (r *run) touch(g *ingress, t time.Time) {
	if t.After(g.last) {
		g.last = t
	}
	if t.After(g.n.End) {
		g.n.End = t
	}
}

// ---- ingress (access / move) ----

func (r *run) newIngress(host, remote, account, service string, t time.Time) *ingress {
	g := &ingress{host: host, remote: remote, account: account, service: service, start: t, last: t}
	n := &node{Hop: Hop{Kind: Access, Cause: -1, DstHost: host, DstAddr: "", SrcAddr: remote, Account: account, Service: service,
		Start: t, End: t, Method: MethodAuth, Confidence: 1}, prio: 0}
	n.ing = g
	g.n = n
	r.nodes = append(r.nodes, n)
	r.ingresses = append(r.ingresses, g)
	return g
}

func (r *run) buildIngresses() {
	// Every successful login with a source address is an access candidate.
	for i := range r.obs {
		o := &r.obs[i]
		if o.Class != traceback.ClassAuthOK || o.Source == "" || traceback.IsLoopback(o.Source) || r.cfg.ours(o.Source) {
			continue
		}
		if r.cfg.ignored(o.Account) && o.Account != "root" {
			continue // machine and anonymous logons are noise
		}
		var g *ingress
		for _, c := range r.ingresses {
			if c.host == o.Host && c.remote == o.Source && c.account == o.Account && o.T.Sub(c.last) <= r.cfg.AccountWindow && c.hasAuth {
				g = c
				break
			}
		}
		if g != nil {
			r.touch(g, o.T)
			r.addEvidence(g.n, o)
			continue
		}
		g = r.newIngress(o.Host, o.Source, o.Account, o.Service, o.T)
		g.hasAuth = true
		r.addEvidence(g.n, o)
		g.n.Method = MethodAuth
		g.n.Confidence = 0.9
		g.n.Notes = append(g.n.Notes, "login event carries the source address")
		// Merge with the nearest session from the same remote.
		var best *session
		for _, s := range r.sessions {
			c := &r.obs[s.i]
			if s.host != o.Host || s.remote != o.Source || s.ing != nil || c.T.Sub(o.T).Abs() > r.cfg.AccountWindow {
				continue
			}
			if best == nil || c.T.Sub(o.T).Abs() < r.obs[best.i].T.Sub(o.T).Abs() {
				best = s
			}
		}
		if best != nil {
			best.ing = g
			r.mergeSession(g, best)
			g.n.Confidence = 1
			g.n.Notes = g.n.Notes[:0]
		} else {
			r.stitchAuthOnly(g, o)
		}
		// Failed attempts shortly before the success.
		fails := 0
		for _, fi := range r.failsBy[o.Host+"|"+o.Source] {
			f := &r.obs[fi]
			if f.T.Before(o.T) && o.T.Sub(f.T) <= 30*time.Minute {
				fails++
				if len(g.n.Evidence) < 12 {
					g.n.Evidence = append(g.n.Evidence, f.Ref())
				}
			}
		}
		if fails > 0 {
			g.n.Notes = append(g.n.Notes, fmt.Sprintf("%d failed logins from this source before the success", fails))
			g.n.failures = fails
		}
		if g.n.Hop.Kind == Access {
			g.n.Technique = techniqueAccess(g.service, g.account != "", fails)
		}
	}
}

func (r *run) addEvidence(n *node, o *traceback.Obs) {
	ref := o.Ref()
	for _, e := range n.Evidence {
		if e == ref {
			return
		}
	}
	if len(n.Evidence) < 24 {
		n.Evidence = append(n.Evidence, ref)
	}
	if o.T.Before(n.Start) {
		n.Start = o.T
	}
	if o.T.After(n.End) {
		n.End = o.T
	}
}

// ingressOfSession returns the ingress for an inbound connection, creating an
// access/move hop when no login event covers it.
func (r *run) ingressOfSession(s *session) *ingress {
	if s.ing != nil {
		return s.ing
	}
	c := &r.obs[s.i]
	for _, g := range r.ingresses {
		if g.host == s.host && g.remote == s.remote && c.T.After(g.start.Add(-r.cfg.Window)) && c.T.Sub(g.last) <= r.cfg.Window && !g.hasAuth {
			s.ing = g
			r.mergeSession(g, s)
			return g
		}
	}
	g := r.newIngress(s.host, s.remote, "", c.Service, c.T)
	s.ing = g
	r.mergeSession(g, s)
	g.n.Hop.Technique = techniqueAccess(g.service, false, 0)
	return g
}

// mergeSession folds an inbound connection into an ingress hop and stitches it
// to the connecting host's outbound record.
func (r *run) mergeSession(g *ingress, s *session) {
	c := &r.obs[s.i]
	n := g.n
	r.addEvidence(n, c)
	r.touch(g, c.T)
	if n.Proto == "" {
		n.Proto, n.SrcPort, n.DstPort, n.DstAddr = c.Proto, c.RPort, c.LPort, c.LAddr
		n.CommunityID = c.CID
	}
	if n.Service == "" {
		n.Service, g.service = c.Service, c.Service
	}
	if n.Kind != Access || n.cause != nil {
		return
	}
	// Cross-host stitching: the other host's outbound record for this flow.
	var out = -1
	method, conf := "", 0.0
	if c.CID != "" {
		for _, oi := range r.outByCID[c.CID] {
			o := &r.obs[oi]
			if o.Host != c.Host && o.T.Sub(c.T).Abs() <= r.cfg.StitchSkew {
				out, method, conf = oi, MethodCommunityID, 0.95
				break
			}
		}
	}
	if out < 0 && c.LAddr != "" {
		for _, oi := range r.outByTuple[tupleKey(c.RAddr, c.RPort, c.LAddr, c.LPort)] {
			o := &r.obs[oi]
			if o.Host != c.Host && o.T.Sub(c.T).Abs() <= r.cfg.StitchSkew {
				out, method, conf = oi, MethodTuple, 0.95
				break
			}
		}
	}
	if out >= 0 {
		o := &r.obs[out]
		r.consumed[out] = true
		r.addEvidence(n, o)
		r.makeMove(n, o.Host, o.LAddr, method, conf, "outbound connection on "+o.Host+" matches this inbound flow")
		n.stitchOut = out + 1
		return
	}
	if h := r.hostAddr[c.RAddr]; h != "" && h != c.Host {
		r.makeMove(n, h, c.RAddr, MethodSourceAddr, 0.6, "no matching outbound record on "+h+" (agent gap or sensor miss)")
	}
}

func (r *run) makeMove(n *node, srcHost, srcAddr, method string, conf float64, note string) {
	n.Hop.Kind = Move
	n.SrcHost, n.SrcAddr = srcHost, srcAddr
	n.Method, n.Confidence = method, conf
	n.Notes = append(n.Notes, note)
	n.Technique = techniqueMove(n.Service, n.DstPort)
}

// stitchAuthOnly handles a login with no connection record (Windows without
// Sysmon network events): when the source is a known host, find its outbound
// connection to this host shortly before.
func (r *run) stitchAuthOnly(g *ingress, o *traceback.Obs) {
	src := r.hostAddr[o.Source]
	if src == "" || src == o.Host {
		return
	}
	best := -1
	for _, oi := range r.outsByHost[src] {
		c := &r.obs[oi]
		if c.Class != traceback.ClassConnOpen || r.consumed[oi] || c.T.After(o.T.Add(r.cfg.StitchSkew)) || o.T.Sub(c.T) > r.cfg.AccountWindow {
			continue
		}
		ok := false
		for _, a := range r.addrsOf[o.Host] {
			if a == c.RAddr {
				ok = true
			}
		}
		if ok && (best < 0 || c.T.After(r.obs[best].T)) {
			best = oi
		}
	}
	n := g.n
	if best >= 0 {
		c := &r.obs[best]
		r.consumed[best] = true
		r.addEvidence(n, c)
		n.DstPort, n.Proto, n.SrcPort = c.RPort, c.Proto, c.LPort
		r.makeMove(n, src, o.Source, MethodSourceAddr, 0.75,
			fmt.Sprintf("outbound connection on %s to this host %s before the login (no tuple on this side)", src, o.T.Sub(c.T).Round(time.Second)))
		n.stitchOut = best + 1
		return
	}
	r.makeMove(n, src, o.Source, MethodSourceAddr, 0.6, "login from a known host with no connection record on either side")
}
