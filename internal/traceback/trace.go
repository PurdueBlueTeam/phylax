package traceback

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// Source is the read side of the store the tracer needs. *store.Store
// satisfies it.
type Source interface {
	Events(ctx context.Context, q store.Query) ([]event.Event, error)
	Gaps(ctx context.Context, agent string) ([]store.Gap, error)
	Agents(ctx context.Context) ([]store.Agent, error)
}

// Link methods, strongest first.
const (
	MethodExact      = "exact"       // the event itself names the thing (pid, tuple)
	MethodSocket     = "socket"      // the process owned the connection's socket
	MethodLineage    = "lineage"     // an ancestor owned the socket / parent pointers
	MethodTimeWindow = "time_window" // closest inbound connection in time
	MethodSource     = "source_addr" // same source address
	MethodNone       = "none"
)

// Config tunes the tracer. Zero values take the defaults noted.
type Config struct {
	Window         time.Duration // look-back/forward for lineage and source activity (2h)
	FallbackWindow time.Duration // time-window correlation reach (30s)
	GapSlack       time.Duration // a recorded agent gap this near counts (10m)
	MaxDepth       int           // lineage depth (16)
	MaxActivity    int           // source-activity entries kept (200)
	// Offset returns an agent's clock minus the controller's (default none).
	Offset func(agent string) time.Duration
	// Label classifies an address: "us", "scorer", "other" or "" (unknown).
	Label func(addr string) string
}

func (c Config) withDefaults() Config {
	if c.Window <= 0 {
		c.Window = 2 * time.Hour
	}
	if c.FallbackWindow <= 0 {
		c.FallbackWindow = 30 * time.Second
	}
	if c.GapSlack <= 0 {
		c.GapSlack = 10 * time.Minute
	}
	if c.MaxDepth <= 0 {
		c.MaxDepth = 16
	}
	if c.MaxActivity <= 0 {
		c.MaxActivity = 200
	}
	return c
}

func (c Config) off(agent string) time.Duration {
	if c.Offset == nil {
		return 0
	}
	return c.Offset(agent)
}

// Tracer runs trace-backs.
type Tracer struct {
	Src Source
	Cfg Config
}

// Trigger says what to trace. Give an Event (a file_change, process_start,
// connection or login), or Agent+Time (a red check or an alert without a
// stored event) plus an optional Path to find the change.
type Trigger struct {
	Reason string // "file_change", "alert:<rule>", "red_check:<id>"
	Agent  string
	Time   time.Time
	Path   string
	Event  *event.Event
}

// FromAlert builds a trigger from a detection alert: its last evidence event
// when it has one, else the agent and time.
func FromAlert(a detect.Alert) Trigger {
	t := Trigger{Reason: "alert:" + a.RuleID, Agent: a.Agent, Time: a.Time}
	if n := len(a.Evidence); n > 0 {
		e := a.Evidence[n-1]
		t.Event = &e
		if t.Agent == "" {
			t.Agent = e.Agent
		}
	}
	return t
}

// Entry is one row of the incident timeline.
type Entry struct {
	Time       time.Time
	Host       string
	Role       string // change, writer, lineage, request, source, activity
	Summary    string
	Confidence float64
	Method     string
	Refs       []Ref
}

// Link is one causal link, from the effect back to its cause.
type Link struct {
	Name       string // "change<-writer", "writer<-lineage", "lineage<-request", "request<-source", "source<-activity"
	Method     string
	Confidence float64
	Note       string
	// BrokenBecause is set when the chain breaks at this link: what is missing.
	BrokenBecause string
}

// Source description.
type SourceInfo struct {
	Addr    string
	Port    int
	Label   string
	Service string
	CID     string
	Conn    Ref
}

// FileEvidence is a file to hash and collect.
type FileEvidence struct {
	Host, Path, SHA256 string
}

// FreezeWindow is a packet-ring window to freeze on a host.
type FreezeWindow struct {
	Host     string
	From, To time.Time
}

// Result is the outcome of a trace-back.
type Result struct {
	Trigger    Trigger
	Timeline   []Entry // chronological: the chain plus everything else the source did
	Links      []Link  // causal order
	Source     *SourceInfo
	Lineage    []Obs // writer first, then its ancestors
	Files      []FileEvidence
	Freeze     []FreezeWindow
	Gaps       []store.Gap // agent gaps near the trigger on its host
	Confidence float64     // weakest link reached; 0 when the chain broke before any
	// Truncated notes bounded reads that may hide events.
	Truncated []string
}

// Breaks lists the "chain breaks here because ..." statements.
func (r *Result) Breaks() []string {
	var out []string
	for _, l := range r.Links {
		if l.BrokenBecause != "" {
			out = append(out, fmt.Sprintf("chain breaks at %s because %s", l.Name, l.BrokenBecause))
		}
	}
	return out
}

func (t *Tracer) fetch(ctx context.Context, agent, kind string, from, to time.Time, res *Result) ([]Obs, error) {
	evs, err := t.Src.Events(ctx, store.Query{Agent: agent, Kind: kind, From: from, To: to, Limit: store.MaxQueryLimit})
	if err != nil {
		return nil, err
	}
	if len(evs) >= store.MaxQueryLimit && res != nil {
		res.Truncated = append(res.Truncated, fmt.Sprintf("%s %s events truncated at %d", agent, kind, store.MaxQueryLimit))
	}
	out := make([]Obs, len(evs))
	for i, e := range evs {
		out[i] = Normalize(e, t.Cfg.off(e.Agent))
	}
	return out, nil
}

func (t *Tracer) fetchAll(ctx context.Context, agent string, from, to time.Time, res *Result) ([]Obs, error) {
	return t.fetch(ctx, agent, "", from, to, res)
}

// Trace runs a trace-back for trig.
func (t *Tracer) Trace(ctx context.Context, trig Trigger) (*Result, error) {
	cfg := t.Cfg.withDefaults()
	t = &Tracer{Src: t.Src, Cfg: cfg}
	res := &Result{Trigger: trig}

	// 1. The change.
	change, err := t.findChange(ctx, trig, res)
	if err != nil {
		return nil, err
	}
	if change == nil {
		res.Links = append(res.Links, Link{Name: "change<-writer", Method: MethodNone,
			BrokenBecause: "no change event was found on " + trig.Agent + " near the trigger (the change was not recorded, or happened in memory with no file event)"})
		return res, nil
	}
	host := change.Host
	res.addGaps(ctx, t, host, change.T)
	res.Timeline = append(res.Timeline, Entry{Time: change.T, Host: host, Role: "change",
		Summary: changeSummary(*change), Confidence: 1, Method: MethodExact, Refs: []Ref{change.Ref()}})
	if change.Path != "" {
		res.Files = append(res.Files, FileEvidence{Host: host, Path: change.Path})
	}

	// 2. The writer.
	var procs []Obs
	from := change.T.Add(-cfg.Window)
	procs, err = t.fetch(ctx, host, KindProcessStart, from, change.T.Add(time.Second), res)
	if err != nil {
		return nil, err
	}
	var writer *Obs
	wlink := Link{Name: "change<-writer", Method: MethodExact, Confidence: 1}
	switch {
	case change.Class == ClassProc:
		writer = change // the trigger is itself a process (a detection on an exec)
		wlink.Note = "the trigger is the process"
	case change.Class == ClassFile && change.PID != 0:
		writer = findProc(procs, change.PID, change.StartTicks, change.T)
		if writer == nil {
			// The audit record names the writer even without a process_start.
			w := *change
			w.Class = ClassProc
			writer = &w
			wlink.Confidence = 0.7
			wlink.Note = "writer named by the file event; no process_start for it in the window"
		} else if change.StartTicks != 0 && writer.StartTicks == change.StartTicks {
			wlink.Note = "pid and start time match"
		} else {
			wlink.Confidence = 0.9
			wlink.Note = "matched by pid (no start time to rule out pid reuse)"
		}
	case change.Class == ClassConnOpen || change.Class == ClassAuthOK || change.Class == ClassAuthFail || change.Class == ClassSec:
		// Network-side trigger: no writer; go straight to the source.
		return t.fromSource(ctx, res, change, nil, procs)
	default:
		reason := "the file event carries no writer (found by the hash sweep, or the audit watch missed it)"
		if !change.Sweep && change.Class == ClassFile {
			reason = "the file event names no writing process (in-memory change, or the writer was unattributed)"
		}
		if g := res.gapText(); g != "" {
			reason += "; " + g
		}
		wlink.Method, wlink.Confidence, wlink.BrokenBecause = MethodNone, 0, reason
		res.Links = append(res.Links, wlink)
		return res, nil
	}
	res.Links = append(res.Links, wlink)
	if writer.Class == ClassProc && change.Class == ClassFile {
		res.Timeline = append(res.Timeline, Entry{Time: writer.T, Host: host, Role: "writer",
			Summary: procSummary(*writer), Confidence: wlink.Confidence, Method: wlink.Method, Refs: []Ref{writer.Ref()}})
	}

	// 3. Lineage.
	return t.fromSource(ctx, res, change, writer, procs)
}

func (t *Tracer) findChange(ctx context.Context, trig Trigger, res *Result) (*Obs, error) {
	if trig.Event != nil {
		o := Normalize(*trig.Event, t.Cfg.off(trig.Event.Agent))
		return &o, nil
	}
	if trig.Agent == "" || trig.Time.IsZero() {
		return nil, fmt.Errorf("traceback: trigger needs an event or an agent and time")
	}
	// Latest untagged file change (optionally on Path) at or before the trigger.
	lo := trig.Time.Add(-t.Cfg.Window)
	files, err := t.fetch(ctx, trig.Agent, KindFileChange, lo, trig.Time.Add(t.Cfg.FallbackWindow), res)
	if err != nil {
		return nil, err
	}
	var best *Obs
	for i := range files {
		f := &files[i]
		if f.Tag != "" || (trig.Path != "" && f.Path != trig.Path) {
			continue
		}
		if best == nil || f.T.After(best.T) {
			best = f
		}
	}
	return best, nil
}

func (t *Tracer) fromSource(ctx context.Context, res *Result, change, writer *Obs, procs []Obs) (*Result, error) {
	cfg := t.Cfg
	host := change.Host
	var chain []Obs
	if writer != nil {
		chain = lineage(procs, *writer, cfg.MaxDepth)
		res.Lineage = chain
		llink := Link{Name: "writer<-lineage", Method: MethodLineage, Confidence: 0.95}
		if len(chain) == 1 {
			llink.Confidence = 0.5
			llink.Note = "no parent recorded"
			if writer.PExe != "" {
				llink.Note = "parent " + writer.PExe + " has no process_start in the window; lineage ends there"
				llink.Confidence = 0.8
			}
		}
		for i, p := range chain {
			if i == 0 {
				continue
			}
			res.Timeline = append(res.Timeline, Entry{Time: p.T, Host: host, Role: "lineage",
				Summary: "ancestor: " + procSummary(p), Confidence: llink.Confidence, Method: MethodLineage, Refs: []Ref{p.Ref()}})
		}
		res.Links = append(res.Links, llink)
	}

	// 4. The request: the inbound connection the process (or an ancestor) was serving.
	tref := change.T
	if writer != nil {
		tref = writer.T
	}
	conns, err := t.connections(ctx, host, change.T, res)
	if err != nil {
		return nil, err
	}
	var req *Obs
	rlink := Link{Name: "lineage<-request"}
	if change.Class == ClassConnOpen {
		req = change
		rlink.Method, rlink.Confidence = MethodExact, 1
	} else if change.Class == ClassAuthOK || change.Class == ClassAuthFail || change.Class == ClassSec {
		// The trigger names its source directly.
		rlink.Method, rlink.Confidence = MethodExact, 1
		rlink.Note = "the event carries the source address"
		res.Links = append(res.Links, rlink)
		return t.finishSource(ctx, res, change, change.Peer(), 0, "", "", Ref{}, 1)
	} else {
		var conf float64
		req, conf, rlink.Note = findOwner(conns, chain, tref, change.T)
		if req != nil {
			rlink.Method, rlink.Confidence = MethodSocket, conf
			if conf < 0.85 {
				rlink.Method = MethodLineage
			}
		} else {
			cand, k := closestInbound(conns, tref, cfg.FallbackWindow)
			if cand != nil {
				req = cand
				rlink.Method = MethodTimeWindow
				rlink.Confidence = 0.5
				rlink.Note = "no socket ownership recorded; closest inbound connection by time"
				if k > 1 {
					rlink.Confidence = 0.3
					rlink.Note = fmt.Sprintf("no socket ownership recorded; closest of %d inbound connections within %s", k, cfg.FallbackWindow)
				}
			}
		}
	}
	if req == nil {
		rlink.Method, rlink.Confidence = MethodNone, 0
		rlink.BrokenBecause = "no inbound connection could be tied to the process: none owned by it or its ancestors and none within " +
			cfg.FallbackWindow.String() + " (encrypted or proxied traffic, a local or console session, or the connection predates the window)"
		if g := res.gapText(); g != "" {
			rlink.BrokenBecause += "; " + g
		}
		res.Links = append(res.Links, rlink)
		return res, nil
	}
	// A loopback peer is a front end (php-fpm behind nginx, a reverse proxy):
	// follow to the connection it was serving, by time, marked lower confidence.
	if IsLoopback(req.RAddr) {
		res.Timeline = append(res.Timeline, Entry{Time: req.T, Host: host, Role: "request",
			Summary: "loopback connection (front end -> worker)", Confidence: rlink.Confidence, Method: rlink.Method, Refs: []Ref{req.Ref()}})
		res.Links = append(res.Links, rlink)
		var ext []Obs
		for _, c := range conns {
			if c.Dir == "in" && !IsLoopback(c.RAddr) && c.Class == ClassConnOpen {
				ext = append(ext, c)
			}
		}
		cand, k := closestInbound(ext, req.T, cfg.FallbackWindow)
		pl := Link{Name: "request<-frontend", Method: MethodTimeWindow, Confidence: 0.4,
			Note: "worker held only a loopback socket; matched the front end's client by time"}
		if cand == nil {
			pl.Method, pl.Confidence = MethodNone, 0
			pl.BrokenBecause = "the worker's connection is loopback and no external connection arrived within " + cfg.FallbackWindow.String()
			res.Links = append(res.Links, pl)
			return res, nil
		}
		if k > 1 {
			pl.Confidence = 0.25
			pl.Note += fmt.Sprintf(" (closest of %d)", k)
		}
		res.Links = append(res.Links, pl)
		req = cand
		rlink = pl
	} else {
		res.Links = append(res.Links, rlink)
	}
	svc := req.Service
	res.Timeline = append(res.Timeline, Entry{Time: req.T, Host: host, Role: "request",
		Summary:    fmt.Sprintf("inbound %s connection from %s:%d", orStr(svc, "network"), req.RAddr, req.RPort),
		Confidence: rlink.Confidence, Method: rlink.Method, Refs: []Ref{req.Ref()}})
	return t.finishSource(ctx, res, change, req.RAddr, req.RPort, svc, req.CID, req.Ref(), rlink.Confidence)
}

func (t *Tracer) finishSource(ctx context.Context, res *Result, change *Obs, addr string, port int, svc, cid string, conn Ref, conf float64) (*Result, error) {
	cfg := t.Cfg
	if addr == "" {
		res.Links = append(res.Links, Link{Name: "request<-source", Method: MethodNone,
			BrokenBecause: "the request record has no remote address"})
		return res, nil
	}
	label := ""
	if cfg.Label != nil {
		label = cfg.Label(addr)
	}
	res.Source = &SourceInfo{Addr: addr, Port: port, Label: label, Service: svc, CID: cid, Conn: conn}
	res.Links = append(res.Links, Link{Name: "request<-source", Method: MethodExact, Confidence: 1})
	res.Timeline = append(res.Timeline, Entry{Time: change.T, Host: change.Host, Role: "source",
		Summary: "source " + addr + labelSuffix(label), Confidence: 1, Method: MethodExact})

	// 6. Everything else from that source, on every host.
	agents, err := t.agents(ctx)
	if err != nil {
		return nil, err
	}
	lo, hi := change.T.Add(-cfg.Window), change.T.Add(cfg.Window)
	type key struct {
		host, summary string
	}
	grouped := map[key]int{} // index into acts
	counts := map[key]int{}
	var acts []Entry
	for _, a := range agents {
		obs, err := t.fetchAll(ctx, a, lo, hi, res)
		if err != nil {
			return nil, err
		}
		for _, o := range obs {
			if o.Peer() != addr || (o.Ev.Seq == conn.Seq && o.Host == conn.Agent) {
				continue
			}
			e := Entry{Time: o.T, Host: o.Host, Role: "activity", Summary: activityName(o), Confidence: 1, Method: MethodSource, Refs: []Ref{o.Ref()}}
			if o.Class == ClassAuthFail || o.Class == ClassEgressDenied {
				k := key{o.Host, e.Summary}
				if i, ok := grouped[k]; ok {
					counts[k]++
					if len(acts[i].Refs) < 20 {
						acts[i].Refs = append(acts[i].Refs, o.Ref())
					}
					acts[i].Summary = fmt.Sprintf("%s (x%d)", k.summary, counts[k])
					continue
				}
				counts[k] = 1
				grouped[k] = len(acts)
			}
			acts = append(acts, e)
		}
	}
	sort.SliceStable(acts, func(i, j int) bool { return acts[i].Time.Before(acts[j].Time) })
	if len(acts) > cfg.MaxActivity {
		res.Truncated = append(res.Truncated, fmt.Sprintf("source activity truncated at %d entries", cfg.MaxActivity))
		acts = acts[:cfg.MaxActivity]
	}
	res.Timeline = append(res.Timeline, acts...)
	res.Links = append(res.Links, Link{Name: "source<-activity", Method: MethodSource, Confidence: 0.9,
		Note: fmt.Sprintf("%d other events from %s within %s", len(acts), addr, cfg.Window)})

	// 7. Evidence: freeze the packet ring around the window; collect the writer binary.
	res.finish(change, conf)
	return res, nil
}

func (r *Result) finish(change *Obs, _ float64) {
	sort.SliceStable(r.Timeline, func(i, j int) bool { return r.Timeline[i].Time.Before(r.Timeline[j].Time) })
	hosts := map[string]*FreezeWindow{}
	for _, e := range r.Timeline {
		if e.Role == "activity" && e.Time.Sub(change.T).Abs() > 10*time.Minute {
			continue
		}
		w := hosts[e.Host]
		if w == nil {
			hosts[e.Host] = &FreezeWindow{Host: e.Host, From: e.Time, To: e.Time}
			continue
		}
		if e.Time.Before(w.From) {
			w.From = e.Time
		}
		if e.Time.After(w.To) {
			w.To = e.Time
		}
	}
	for _, w := range hosts {
		w.From, w.To = w.From.Add(-5*time.Minute), w.To.Add(5*time.Minute)
		r.Freeze = append(r.Freeze, *w)
	}
	sort.Slice(r.Freeze, func(i, j int) bool { return r.Freeze[i].Host < r.Freeze[j].Host })
	for _, p := range r.Lineage {
		if p.Exe != "" {
			r.Files = append(r.Files, FileEvidence{Host: p.Host, Path: p.Exe, SHA256: p.SHA256})
		}
	}
	// Confidence: the weakest link up to the source.
	min := 1.0
	for _, l := range r.Links {
		if l.Name == "source<-activity" {
			continue
		}
		if l.Confidence < min {
			min = l.Confidence
		}
	}
	r.Confidence = min
}

// agents lists agents that have events (all hosts).
func (t *Tracer) agents(ctx context.Context) ([]string, error) {
	as, err := t.Src.Agents(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.ID
	}
	return out, nil
}

// connections returns connection events (open and close) for host around at.
func (t *Tracer) connections(ctx context.Context, host string, at time.Time, res *Result) ([]Obs, error) {
	lo, hi := at.Add(-t.Cfg.Window), at.Add(time.Second)
	var all []Obs
	for _, k := range []string{KindConnOpened, KindConnClosed, KindNetConnect} {
		o, err := t.fetch(ctx, host, k, lo, hi, res)
		if err != nil {
			return nil, err
		}
		all = append(all, o...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].T.Before(all[j].T) })
	return all, nil
}

// addGaps records agent gaps near t on host.
func (r *Result) addGaps(ctx context.Context, tr *Tracer, host string, at time.Time) {
	gs, err := tr.Src.Gaps(ctx, host)
	if err != nil {
		return
	}
	r.Gaps = GapsNear(gs, at, tr.Cfg.GapSlack)
}

// GapsNear returns the gaps recorded within slack of at.
func GapsNear(gs []store.Gap, at time.Time, slack time.Duration) []store.Gap {
	var out []store.Gap
	for _, g := range gs {
		if g.Time.Sub(at).Abs() <= slack {
			out = append(out, g)
		}
	}
	return out
}

func (r *Result) gapText() string {
	if len(r.Gaps) == 0 {
		return ""
	}
	g := r.Gaps[0]
	return fmt.Sprintf("the agent recorded a telemetry gap near this time (%s, %d events lost)", orStr(g.Reason, "unknown reason"), g.Count)
}

// ---- matching helpers ----

// findProc returns the process_start for pid that began at or before at, the
// latest such (pids are reused); with ticks it must also match them.
func findProc(procs []Obs, pid int64, ticks uint64, at time.Time) *Obs {
	var best *Obs
	for i := range procs {
		p := &procs[i]
		if p.PID != pid || p.T.After(at.Add(time.Second)) {
			continue
		}
		if ticks != 0 && p.StartTicks != 0 && p.StartTicks != ticks {
			continue
		}
		if best == nil || p.T.After(best.T) {
			best = p
		}
	}
	return best
}

// lineage returns w and its ancestors as far as process_start events and
// parent pointers go.
func lineage(procs []Obs, w Obs, depth int) []Obs {
	out := []Obs{w}
	cur := w
	seen := map[int64]bool{w.PID: true}
	for len(out) < depth && cur.PPID != 0 && !seen[cur.PPID] {
		p := findProc(procs, cur.PPID, 0, cur.T)
		if p == nil {
			// Forked workers never exec, so they have no process_start; the
			// child's parent record still names them.
			if cur.PExe == "" {
				break
			}
			p = &Obs{Ev: cur.Ev, Host: cur.Host, T: cur.T, Class: ClassProc, PID: cur.PPID, Exe: cur.PExe,
				Comm: baseName(cur.PExe), Cmdline: ""}
			out = append(out, *p)
			break
		}
		seen[p.PID] = true
		out = append(out, *p)
		cur = *p
	}
	return out
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// findOwner finds the latest inbound connection opened at or before the
// change that is owned by a lineage process. Confidence falls when the owner
// is an ancestor, when start times cannot rule out pid reuse, and when the
// connection was already closed before the process started.
func findOwner(conns []Obs, chain []Obs, procT, changeT time.Time) (*Obs, float64, string) {
	closed := map[string]time.Time{}
	for _, c := range conns {
		if c.Class == ClassConnClose && c.CID != "" {
			closed[c.CID] = c.T
		}
	}
	var best *Obs
	var bestConf float64
	var bestNote string
	for depth, p := range chain {
		if p.PID == 0 {
			continue
		}
		for i := range conns {
			c := &conns[i]
			if c.Class != ClassConnOpen || c.Dir != "in" || c.PID != p.PID || c.T.After(changeT.Add(time.Second)) {
				continue
			}
			conf, note := 0.95, "writer process owned the client socket"
			if depth > 0 {
				conf, note = 0.9, fmt.Sprintf("ancestor %s (pid %d) owned the client socket", orStr(p.Comm, baseName(p.Exe)), p.PID)
			}
			if c.StartTicks != 0 && p.StartTicks != 0 {
				if c.StartTicks != p.StartTicks {
					continue // pid reused by another process
				}
			} else {
				conf -= 0.1
				note += " (pid match only)"
			}
			if ct, ok := closed[c.CID]; ok && ct.Before(procT.Add(-time.Second)) {
				conf *= 0.5
				note += "; the connection had already closed when the process started"
			}
			if best == nil || conf > bestConf || (conf == bestConf && c.T.After(best.T)) {
				best, bestConf, bestNote = c, conf, note
			}
		}
		if best != nil {
			break // the nearest owner in the lineage wins
		}
	}
	return best, bestConf, bestNote
}

// closestInbound returns the inbound connection nearest to at within reach
// (preferring ones opened before it) and the number of candidates.
func closestInbound(conns []Obs, at time.Time, reach time.Duration) (*Obs, int) {
	var best *Obs
	n := 0
	for i := range conns {
		c := &conns[i]
		if c.Class != ClassConnOpen || c.Dir != "in" || c.RAddr == "" {
			continue
		}
		d := at.Sub(c.T)
		if d < -2*time.Second || d > reach {
			continue
		}
		n++
		if best == nil || d.Abs() < at.Sub(best.T).Abs() {
			best = c
		}
	}
	return best, n
}

// ---- text ----

func orStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func labelSuffix(l string) string {
	if l == "" {
		return ""
	}
	return " (" + l + ")"
}

func changeSummary(o Obs) string {
	switch o.Class {
	case ClassFile:
		return fmt.Sprintf("%s %s", orStr(o.Op, "change"), o.Path)
	case ClassProc:
		return "process " + procSummary(o)
	case ClassSec:
		return "security event " + o.Category + " " + o.Op
	case ClassAuthOK, ClassAuthFail:
		return "login " + o.Account + " from " + o.Source
	}
	return o.Ev.Kind
}

func procSummary(p Obs) string {
	s := fmt.Sprintf("%s (pid %d)", orStr(p.Exe, p.Comm), p.PID)
	if p.Cmdline != "" {
		s += " " + trunc(p.Cmdline, 120)
	}
	return s
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// activityName describes a non-chain event from the source.
func activityName(o Obs) string {
	switch o.Class {
	case ClassAuthOK:
		return fmt.Sprintf("login ok %s %s", orStr(o.Service, "?"), o.Account)
	case ClassAuthFail:
		return fmt.Sprintf("login failed %s %s", orStr(o.Service, "?"), o.Account)
	case ClassConnOpen:
		return fmt.Sprintf("connection %s %s:%d", orStr(o.Dir, "?"), o.RAddr, o.RPort)
	case ClassEgressDenied:
		return fmt.Sprintf("denied egress to %s:%d", o.RAddr, o.RPort)
	case ClassSec:
		return "security event " + o.Category
	}
	return o.Ev.Kind
}
