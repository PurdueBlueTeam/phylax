package chains

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/traceback"
)

// ---- exec ----

func (r *run) procNode(i int) *node {
	if n, ok := r.procMemo[i]; ok {
		return n
	}
	if r.procBusy[i] {
		return nil
	}
	r.procBusy[i] = true
	defer delete(r.procBusy, i)
	o := &r.obs[i]
	var n *node
	if att := r.attach(o); att != nil {
		n = r.makeProcNode(i, att)
	}
	r.procMemo[i] = n
	return n
}

func (r *run) makeProcNode(i int, att *attachment) *node {
	o := &r.obs[i]
	n := &node{Hop: Hop{Kind: Exec, Cause: -1, DstHost: o.Host, Account: o.User, Start: o.T, End: o.T,
		Proc:      &ProcRef{Host: o.Host, PID: o.PID, Exe: o.Exe, Cmdline: o.Cmdline, SHA256: o.SHA256},
		Technique: techniqueExec(*o), Method: att.method, Confidence: att.conf, Evidence: []traceback.Ref{o.Ref()}}, prio: 2}
	if att.note != "" {
		n.Notes = append(n.Notes, att.note)
	}
	for _, b := range r.cfg.NoisyExecs {
		if base(o.Exe) == b {
			n.noisy = true
		}
	}
	n.cause, n.causeMethod, n.causeConf = nil, att.method, att.conf
	if att.ing != nil {
		n.ing = att.ing
		n.cause = att.ing.n
		if n.Account == "" {
			n.Account = att.ing.account
		}
		r.touch(att.ing, o.T)
	}
	if pi := r.findProc(o.Host, o.PPID, 0, o.T); pi >= 0 {
		if pn := r.procNode(pi); pn != nil && pn != n {
			n.cause = pn
			n.causeMethod = MethodLineage
		}
	}
	r.procMemo[i] = n
	r.nodes = append(r.nodes, n)
	return n
}

// ---- change ----

func (r *run) changeNode(i int) *node {
	if n := r.chgNodes[i]; n != nil {
		return n
	}
	o := &r.obs[i]
	if o.Class == traceback.ClassFile && o.Sweep {
		return nil
	}
	if o.Class == traceback.ClassSec {
		if _, _, ok := techniqueSec(*o); !ok {
			return nil
		}
	}
	att := r.attach(o)
	if att == nil {
		return nil
	}
	return r.makeChangeNode(i, att)
}

func (r *run) makeChangeNode(i int, att *attachment) *node {
	o := &r.obs[i]
	n := &node{Hop: Hop{Kind: Change, Cause: -1, DstHost: o.Host, Start: o.T, End: o.T, Method: att.method, Confidence: att.conf,
		Evidence: []traceback.Ref{o.Ref()}}, prio: 1}
	if o.Class == traceback.ClassFile {
		n.Path = o.Path
		n.Technique, n.Persistence = techniqueChangePath(o.Path)
		n.Account = o.User
		if o.PID != 0 {
			n.Proc = &ProcRef{Host: o.Host, PID: o.PID, Exe: o.Exe, Cmdline: o.Cmdline}
		}
		n.Notes = append(n.Notes, "op: "+orStr(o.Op, "change"))
	} else {
		n.Technique, n.Persistence, _ = techniqueSec(*o)
		n.Path = secTarget(*o)
		n.Account = o.Actor
		n.Notes = append(n.Notes, "security event: "+o.Category+" "+o.Op)
	}
	if att.note != "" {
		n.Notes = append(n.Notes, att.note)
	}
	n.causeMethod, n.causeConf = att.method, att.conf
	if att.ing != nil {
		n.ing = att.ing
		n.cause = att.ing.n
		if n.Account == "" {
			n.Account = att.ing.account
		}
		r.touch(att.ing, o.T)
	}
	if o.Class == traceback.ClassFile && o.PID != 0 {
		if pi := r.findProc(o.Host, o.PID, o.StartTicks, o.T); pi >= 0 {
			if pn := r.procNode(pi); pn != nil {
				n.cause = pn
				n.causeMethod = MethodLineage
				if n.Proc.SHA256 == "" {
					n.Proc.SHA256 = r.obs[pi].SHA256
				}
			}
		}
	}
	r.chgNodes[i] = n
	r.nodes = append(r.nodes, n)
	return n
}

func secTarget(o traceback.Obs) string {
	f := o.Ev.Fields
	s := func(k string) string { v, _ := f[k].(string); return v }
	switch o.Category {
	case "account_change":
		return "account:" + o.Account
	case "group_change":
		return "group:" + s("group_name") + "+" + s("member_name")
	case "service_install":
		return "service:" + s("service_name")
	case "scheduled_task":
		n := s("task_name")
		if n == "" {
			n = s("name")
		}
		return "task:" + n
	case "ad_access":
		return "dcsync"
	case "wmi_subscription":
		return "wmi-subscription"
	case "ad_object_change":
		return "ad:" + s("object_dn")
	}
	return o.Category
}

// ---- outbound ----

var lateralPorts = map[int]bool{22: true, 23: true, 135: true, 139: true, 445: true, 3389: true, 5900: true, 5985: true, 5986: true}

func (r *run) outNode(i int) *node {
	if n := r.outNodes[i]; n != nil {
		return n
	}
	o := &r.obs[i]
	if o.RAddr == "" || traceback.IsLoopback(o.RAddr) || r.cfg.ours(o.RAddr) || r.consumed[i] {
		return nil
	}
	att := r.attach(o)
	if att == nil {
		return nil
	}
	// A partner inbound record on another host makes this a stitched move.
	var partner *session
	for _, s := range r.inByCID[o.CID] {
		if o.CID != "" && s.host != o.Host && r.obs[s.i].T.Sub(o.T).Abs() <= r.cfg.StitchSkew {
			partner = s
			break
		}
	}
	if partner == nil {
		for _, s := range r.inByTuple[tupleKey(o.LAddr, o.LPort, o.RAddr, o.RPort)] {
			if s.host != o.Host && r.obs[s.i].T.Sub(o.T).Abs() <= r.cfg.StitchSkew {
				partner = s
				break
			}
		}
	}
	if partner != nil {
		g := r.ingressOfSession(partner)
		r.outNodes[i] = g.n
		return g.n
	}
	cause, cm, cc := att.ing.n, att.method, att.conf
	if pi := r.findProc(o.Host, o.PID, o.StartTicks, o.T); pi >= 0 {
		if pn := r.procNode(pi); pn != nil {
			cause, cm = pn, MethodLineage
		}
	}
	dstHost := r.hostAddr[o.RAddr]
	internal := dstHost != "" || traceback.IsPrivate(o.RAddr)
	key := fmt.Sprintf("%s|%s|%d", o.Host, o.RAddr, o.RPort)
	if internal && !(dstHost != "" || lateralPorts[o.RPort]) {
		return nil // ordinary internal traffic (DNS, NTP, proxies)
	}
	if n := r.egressKey[key]; n != nil && o.T.Sub(n.End) <= r.cfg.AccountWindow {
		n.End = o.T
		r.addEvidence(n, o)
		r.outNodes[i] = n
		return n
	}
	n := &node{Hop: Hop{Cause: -1, SrcHost: o.Host, SrcAddr: o.LAddr, DstAddr: o.RAddr, DstHost: dstHost, DstPort: o.RPort, SrcPort: o.LPort,
		Proto: o.Proto, Service: o.Service, CommunityID: o.CID, Start: o.T, End: o.T, Evidence: []traceback.Ref{o.Ref()},
		Method: cm, Confidence: cc}, cause: cause, causeMethod: cm, causeConf: cc, ing: att.ing, prio: 1}
	n.Account = att.ing.account
	if n.Account == "" {
		n.Account = o.User
	}
	if internal {
		n.Kind = Move
		n.Method, n.Confidence = MethodUnmatched, minf(cc, 0.5)
		n.Technique = techniqueMove(o.Service, o.RPort)
		n.Notes = append(n.Notes, "no inbound record on the far side: its agent may be dead, gapped or lying")
		if dstHost == "" {
			n.Notes = append(n.Notes, "destination is not a host with an agent")
		}
	} else {
		n.Kind = Egress
		n.Technique = techniqueEgress(o.RPort)
		if o.Class == traceback.ClassEgressDenied {
			n.Notes = append(n.Notes, "denied by the egress policy")
		}
	}
	if o.PID != 0 {
		n.Proc = &ProcRef{Host: o.Host, PID: o.PID, Exe: o.Exe, SHA256: o.SHA256}
	}
	r.egressKey[key] = n
	r.outNodes[i] = n
	r.nodes = append(r.nodes, n)
	return n
}

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// resolveMoveCauses ties each stitched move to the process that made the
// outbound connection on the other host, and a move whose source host is only
// known by address to the latest earlier hop on that host.
func (r *run) resolveMoveCauses() {
	for k := 0; k < len(r.nodes); k++ {
		n := r.nodes[k]
		if n.Kind != Move || n.cause != nil {
			continue
		}
		if n.stitchOut > 0 {
			o := &r.obs[n.stitchOut-1]
			cc, cm := 0.0, ""
			if pi := r.findProc(o.Host, o.PID, o.StartTicks, o.T); pi >= 0 {
				if pn := r.procNode(pi); pn != nil && pn != n {
					n.cause, cc, cm = pn, 0.95, MethodLineage
				}
			}
			if n.cause == nil {
				if att := r.attach(o); att != nil && att.ing.n != n {
					n.cause, cc, cm = att.ing.n, att.conf, att.method
				}
			}
			if n.cause != nil {
				n.causeMethod, n.causeConf = cm, cc
				if cc < n.Confidence {
					n.Confidence = cc
					n.Notes = append(n.Notes, "weakest link: the process on "+o.Host+" was tied to its session by "+cm)
				}
				continue
			}
		}
		if n.SrcHost != "" {
			var best *node
			for _, c := range r.nodes {
				if c != n && c.DstHost == n.SrcHost && !c.Start.After(n.Start) && c.Kind != Egress && (best == nil || c.Start.After(best.Start)) {
					best = c
				}
			}
			if best != nil {
				n.cause, n.causeMethod, n.causeConf = best, MethodSourceAddr, 0.5
				n.Confidence = minf(n.Confidence, 0.5)
				n.Notes = append(n.Notes, "cause is the latest earlier hop on "+n.SrcHost+" (address match, no process record)")
			}
		}
	}
}

// ---- seed ----

func (r *run) seedNode(si int, seed Seed) *node {
	o := &r.obs[si]
	var n *node
	switch o.Class {
	case traceback.ClassProc:
		n = r.procNode(si)
		if n == nil {
			n = r.makeProcNode(si, &attachment{method: MethodSeed, conf: 0.3, note: "seed process; no inbound session could be tied to its lineage"})
			n.forced = true
		}
	case traceback.ClassFile, traceback.ClassSec:
		n = r.changeNode(si)
		if n == nil {
			n = r.makeChangeNode(si, &attachment{method: MethodSeed, conf: 0.3, note: "seed change; no inbound session could be tied to its writer"})
			n.forced = true
		}
	case traceback.ClassAuthOK, traceback.ClassAuthFail, traceback.ClassConnOpen:
		for _, c := range r.nodes {
			for _, e := range c.Evidence {
				if e == o.Ref() {
					n = c
				}
			}
		}
		if n == nil {
			n = r.forcedAccess(o)
		}
	default:
		n = r.forcedAccess(o)
	}
	n.isSeed, n.Seed = true, true
	n.Method = orStr(n.Method, MethodSeed)
	if seed.Alert != nil {
		a := seed.Alert
		if len(a.Attack) > 0 {
			n.Technique = a.Attack[0]
			if len(a.Attack) > 1 {
				n.Notes = append(n.Notes, "also: "+strings.Join(a.Attack[1:], ", "))
			}
		}
		n.Notes = append(n.Notes, "seeded by alert "+a.RuleID+": "+a.Message)
	}
	if n.forced && n.cause == nil {
		r.graft(n, o)
	}
	return n
}

func (r *run) forcedAccess(o *traceback.Obs) *node {
	remote := o.Peer()
	g := r.newIngress(o.Host, remote, o.Account, o.Service, o.T)
	r.addEvidence(g.n, o)
	g.n.Technique = techniqueAccess(o.Service, o.Account != "", 0)
	g.n.forced = true
	return g.n
}

// graft runs the within-host trace-back for a seed that no session explained
// and, when it finds a source, adds the access hop with the trace-back's own
// (possibly time-window) confidence.
func (r *run) graft(n *node, o *traceback.Obs) {
	tr := &traceback.Tracer{Src: r.b.Src, Cfg: traceback.Config{Window: r.cfg.Window, Offset: r.cfg.Offset, Label: r.cfg.Label}}
	ev := o.Ev
	res, err := tr.Trace(r.ctx, traceback.Trigger{Event: &ev})
	if err != nil {
		n.Notes = append(n.Notes, "trace-back failed: "+err.Error())
		return
	}
	if res.Source == nil {
		for _, b := range res.Breaks() {
			n.Notes = append(n.Notes, b)
		}
		return
	}
	var reqT time.Time
	var reqRef traceback.Ref
	for _, e := range res.Timeline {
		if e.Role == "request" && len(e.Refs) > 0 {
			reqT, reqRef = e.Time, e.Refs[0]
		}
	}
	if reqT.IsZero() {
		reqT = o.T
	}
	g := r.newIngress(o.Host, res.Source.Addr, "", res.Source.Service, reqT)
	g.n.Technique = techniqueAccess(res.Source.Service, false, 0)
	g.n.SrcPort, g.n.CommunityID = res.Source.Port, res.Source.CID
	g.n.Evidence = append(g.n.Evidence, reqRef)
	g.n.Method, g.n.Confidence = MethodSocket, 1
	for _, l := range res.Links {
		if l.Name == "lineage<-request" || l.Name == "request<-frontend" {
			n.causeMethod = l.Method
			if l.Method == traceback.MethodTimeWindow {
				n.causeMethod = MethodTimeWindow
				g.n.Method, g.n.Confidence = MethodTimeWindow, l.Confidence
			}
			if l.Note != "" {
				n.Notes = append(n.Notes, "request link: "+l.Note)
			}
		}
	}
	n.cause, n.causeConf = g.n, res.Confidence
	n.Method, n.Confidence = n.causeMethod, res.Confidence
	n.ing = g
}

// ---- pruning ----

func (r *run) prune(seed *node) {
	for changed := true; changed; {
		changed = false
		children := map[*node]int{}
		for _, n := range r.nodes {
			if !n.dead && n.cause != nil {
				children[n.cause]++
			}
		}
		for _, n := range r.nodes {
			if n.dead || !n.noisy || n.isSeed || children[n] > 0 {
				continue
			}
			n.dead = true
			changed = true
		}
	}
}

// ---- finish ----

func (r *run) finish(ctx context.Context, sn *node, seed Seed) (*Chain, error) {
	cfg := r.cfg
	// Neighbours for bounded expansion: cause links, and shared source,
	// account or binary hash.
	children := map[*node][]*node{}
	bySrc := map[string][]*node{}
	byAcct := map[string][]*node{}
	byHash := map[string][]*node{}
	var alive []*node
	for _, n := range r.nodes {
		if n.dead || n.Start.Sub(r.t0).Abs() > cfg.Window {
			continue
		}
		alive = append(alive, n)
		if n.cause != nil {
			children[n.cause] = append(children[n.cause], n)
		}
		if n.SrcAddr != "" && !traceback.IsLoopback(n.SrcAddr) && !cfg.ours(n.SrcAddr) {
			bySrc[n.SrcAddr] = append(bySrc[n.SrcAddr], n)
		}
		if !cfg.ignored(n.Account) {
			byAcct[n.Account] = append(byAcct[n.Account], n)
		}
		if n.Proc != nil && n.Proc.SHA256 != "" {
			byHash[n.Proc.SHA256] = append(byHash[n.Proc.SHA256], n)
		}
	}
	for _, n := range alive {
		n.dist = -1
	}
	sn.dist = 0
	queue := []*node{sn}
	var reached []*node
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		reached = append(reached, n)
		var nb []*node
		if n.cause != nil {
			nb = append(nb, n.cause)
		}
		nb = append(nb, children[n]...)
		if n.SrcAddr != "" {
			nb = append(nb, bySrc[n.SrcAddr]...)
		}
		if !cfg.ignored(n.Account) {
			nb = append(nb, byAcct[n.Account]...)
		}
		if n.Proc != nil && n.Proc.SHA256 != "" {
			nb = append(nb, byHash[n.Proc.SHA256]...)
		}
		for _, m := range nb {
			if m.dead || m.dist >= 0 || m.Start.Sub(r.t0).Abs() > cfg.Window {
				continue
			}
			m.dist = n.dist + 1
			queue = append(queue, m)
		}
	}
	sort.SliceStable(reached, func(i, j int) bool {
		a, b := reached[i], reached[j]
		if a.isSeed != b.isSeed {
			return a.isSeed
		}
		if a.dist != b.dist {
			return a.dist < b.dist
		}
		if a.prio != b.prio {
			return a.prio < b.prio
		}
		return a.Start.Before(b.Start)
	})
	c := &Chain{Seed: seed.Kind, Created: time.Now().UTC(), Notes: append([]string(nil), r.note...)}
	if len(reached) > cfg.MaxHops {
		reached = reached[:cfg.MaxHops]
		c.Truncated = true
		c.Notes = append(c.Notes, fmt.Sprintf("hop limit %d reached: the chain continues beyond what is shown", cfg.MaxHops))
	}
	in := map[*node]bool{}
	for _, n := range reached {
		in[n] = true
	}
	sort.SliceStable(reached, func(i, j int) bool {
		a, b := reached[i], reached[j]
		if !a.Start.Equal(b.Start) {
			return a.Start.Before(b.Start)
		}
		return a.prio < b.prio
	})
	for i, n := range reached {
		n.order = i
	}
	for _, n := range reached {
		h := n.Hop
		h.Ord = n.order
		h.Cause = -1
		if n.cause != nil {
			if in[n.cause] {
				h.Cause = n.cause.order
			} else {
				h.Notes = append(h.Notes, "caused by a hop beyond the limit or the window")
			}
		}
		if h.Cause < 0 && !n.isSeed && n.Kind != Access && n.Kind != Move {
			h.Notes = append(h.Notes, "no access hop in the window explains this")
		}
		h.Evidence = append([]traceback.Ref(nil), h.Evidence...)
		h.Notes = append([]string(nil), h.Notes...)
		describe(&h)
		c.Hops = append(c.Hops, h)
	}
	if err := r.applyGaps(ctx, c); err != nil {
		return nil, err
	}
	AddRemediation(c)
	c.Confidence = 1
	for _, h := range c.Hops {
		if h.Confidence < c.Confidence {
			c.Confidence = h.Confidence
		}
	}
	return c, nil
}

// applyGaps lowers the confidence of hops on hosts whose agent recorded a
// telemetry gap near the hop: something may be missing there.
func (r *run) applyGaps(ctx context.Context, c *Chain) error {
	cache := map[string][]store.Gap{}
	get := func(host string) ([]store.Gap, error) {
		if g, ok := cache[host]; ok {
			return g, nil
		}
		g, err := r.b.Src.Gaps(ctx, host)
		if err != nil {
			return nil, err
		}
		for i := range g { // gap times are agent clock
			g[i].Time = g[i].Time.Add(-r.cfg.off(host))
		}
		cache[host] = g
		return g, nil
	}
	noted := map[string]bool{}
	for i := range c.Hops {
		h := &c.Hops[i]
		for _, host := range []string{h.DstHost, h.SrcHost} {
			if host == "" {
				continue
			}
			gs, err := get(host)
			if err != nil {
				return err
			}
			near := traceback.GapsNear(gs, h.Start, r.cfg.GapSlack)
			if len(near) == 0 {
				near = traceback.GapsNear(gs, h.End, r.cfg.GapSlack)
			}
			if len(near) == 0 {
				continue
			}
			g := near[0]
			h.Confidence *= 0.6
			h.Notes = append(h.Notes, fmt.Sprintf("agent gap on %s near this hop (%s, %d events lost): evidence may be missing", host, orStr(g.Reason, "unknown"), g.Count))
			if !noted[host] {
				noted[host] = true
				c.Notes = append(c.Notes, "agent gap on "+host+": the chain may be incomplete there")
			}
		}
	}
	return nil
}
