package detect

import (
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Alert is a rule firing.
type Alert struct {
	RuleID     string
	Title      string
	Severity   string
	Tier       int
	Mode       string // act or alert (forced to alert by Options.AlertOnly)
	Attack     []string
	Collect    []string
	IRTemplate string
	Agent      string
	Time       time.Time
	Entities   map[string]string
	Message    string
	Evidence   []event.Event
	Source     map[string]string
}

// Options configure an Engine.
type Options struct {
	// Clock supplies the time for events that carry none. Default time.Now.
	Clock func() time.Time
	// AlertOnly forces every alert to mode alert (global override_mode).
	AlertOnly bool
	// MaxKeys bounds per-rule window and sequence state (default 4096).
	MaxKeys int
}

const maxEvidence = 3

// Engine evaluates a RuleSet. It is safe for concurrent use; evaluation is
// serialised.
type Engine struct {
	mu       sync.Mutex
	opts     Options
	byKind   map[string][]*ruleRT
	profiles map[string]*profileState
	byProf   map[string][]*profileState
	events   uint64
}

type ruleRT struct {
	r       *Rule
	buckets map[string]*bucket
	pend    map[string]*pending
}

type bucket struct {
	times    []time.Time
	distinct map[string]time.Time
	evid     []event.Event
	until    time.Time // cooldown end
	seen     time.Time
}

type pending struct {
	t  time.Time
	ev event.Event
}

// NewEngine builds an engine over a rule set.
func NewEngine(rs *RuleSet, o Options) *Engine {
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.MaxKeys <= 0 {
		o.MaxKeys = 4096
	}
	e := &Engine{opts: o, byKind: map[string][]*ruleRT{}, profiles: map[string]*profileState{}, byProf: map[string][]*profileState{}}
	for n, pd := range rs.profiles {
		ps := &profileState{def: pd, keys: map[string]*pkey{}}
		e.profiles[n] = ps
		for _, k := range pd.Kinds {
			e.byProf[k] = append(e.byProf[k], ps)
		}
	}
	for _, r := range rs.Rules {
		rt := &ruleRT{r: r}
		if r.count != nil {
			rt.buckets = map[string]*bucket{}
		}
		if r.seq != nil {
			rt.pend = map[string]*pending{}
		}
		kinds := append([]string(nil), r.Kinds...)
		if r.seq != nil {
			kinds = append(kinds, r.seq.thenKinds...)
		}
		seen := map[string]bool{}
		for _, k := range kinds {
			if !seen[k] {
				seen[k] = true
				e.byKind[k] = append(e.byKind[k], rt)
			}
		}
	}
	return e
}

func hasKind(ks []string, k string) bool {
	for _, x := range ks {
		if x == k {
			return true
		}
	}
	return false
}

func tagged(ev *event.Event) bool {
	switch t := ev.Fields["tag"].(type) {
	case string:
		return t != ""
	case []string:
		return len(t) > 0
	case []any:
		return len(t) > 0
	case nil:
		return false
	}
	return true
}

// Process evaluates one event and returns the alerts it triggers.
func (e *Engine) Process(ev event.Event) []Alert {
	rules := e.byKind[ev.Kind]
	profs := e.byProf[ev.Kind]
	if len(rules) == 0 && len(profs) == 0 {
		return nil
	}
	if ev.Time.IsZero() {
		ev.Time = e.opts.Clock()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events++
	c := &evalCtx{ev: &ev, eng: e}
	var out []Alert
	isTagged := tagged(&ev)
	for _, rt := range rules {
		r := rt.r
		if r.exemptTagged && isTagged {
			continue
		}
		switch {
		case r.seq != nil:
			out = e.stepSeq(out, rt, c)
		case !hasKind(r.Kinds, ev.Kind):
		case !r.cond.eval(c):
		case r.count != nil:
			out = e.stepCount(out, rt, c)
		default:
			out = append(out, e.alert(r, c, []event.Event{ev}))
		}
	}
	for _, ps := range profs {
		e.observe(ps, c)
	}
	return out
}

func (e *Engine) alert(r *Rule, c *evalCtx, evid []event.Event) Alert {
	a := Alert{RuleID: r.ID, Title: r.Title, Severity: r.Severity, Tier: r.Tier, Mode: r.Mode,
		Attack: r.Attack, Collect: r.Collect, IRTemplate: r.IRTemplate, Agent: c.ev.Agent,
		Time: c.ev.Time, Evidence: evid, Source: r.Source}
	if e.opts.AlertOnly {
		a.Mode = "alert"
	}
	if len(r.entities) > 0 {
		a.Entities = map[string]string{}
		for _, f := range r.entities {
			if v, ok := f.get(c); ok {
				a.Entities[f.name], _ = toStr(v)
			}
		}
	}
	if r.msg != nil && len(r.msg.fields) > 0 || r.msg != nil && r.msg.lits[0] != "" {
		a.Message = r.msg.render(c)
	}
	return a
}

func keyOf(by []fieldRef, c *evalCtx) string {
	if len(by) == 0 {
		return ""
	}
	var b strings.Builder
	for i, f := range by {
		if i > 0 {
			b.WriteByte(0)
		}
		if v, ok := f.get(c); ok {
			s, _ := toStr(v)
			b.WriteString(s)
		}
	}
	return b.String()
}

func (e *Engine) stepCount(out []Alert, rt *ruleRT, c *evalCtx) []Alert {
	cs := rt.r.count
	now := c.ev.Time
	key := keyOf(cs.by, c)
	b := rt.buckets[key]
	if b == nil {
		if len(rt.buckets) >= e.opts.MaxKeys {
			e.pruneBuckets(rt, now)
		}
		b = &bucket{}
		if cs.distinct != nil {
			b.distinct = map[string]time.Time{}
		}
		rt.buckets[key] = b
	}
	b.seen = now
	if now.Before(b.until) {
		return out
	}
	b.evid = append(b.evid, *c.ev)
	if len(b.evid) > maxEvidence {
		b.evid = b.evid[1:]
	}
	cut := now.Add(-cs.window)
	var n int
	if cs.distinct != nil {
		b.distinct[keyOf(cs.distinct, c)] = now
		for k, t := range b.distinct {
			if t.Before(cut) {
				delete(b.distinct, k)
			}
		}
		for len(b.distinct) > cs.gte*4 { // bounded: drop the oldest
			var ok string
			var ot time.Time
			f := true
			for k, t := range b.distinct {
				if f || t.Before(ot) {
					ok, ot, f = k, t, false
				}
			}
			delete(b.distinct, ok)
		}
		n = len(b.distinct)
	} else {
		b.times = append(b.times, now)
		if len(b.times) > cs.gte {
			b.times = b.times[len(b.times)-cs.gte:]
		}
		for len(b.times) > 0 && b.times[0].Before(cut) {
			b.times = b.times[1:]
		}
		n = len(b.times)
	}
	if n < cs.gte {
		return out
	}
	evid := append([]event.Event(nil), b.evid...)
	b.times, b.evid, b.until = nil, nil, now.Add(cs.cooldown)
	if b.distinct != nil {
		b.distinct = map[string]time.Time{}
	}
	a := e.alert(rt.r, c, evid)
	return append(out, a)
}

// pruneBuckets drops expired buckets, then the least recently seen if the map
// is still full.
func (e *Engine) pruneBuckets(rt *ruleRT, now time.Time) {
	ttl := rt.r.count.window
	if rt.r.count.cooldown > ttl {
		ttl = rt.r.count.cooldown
	}
	for k, b := range rt.buckets {
		if now.Sub(b.seen) > ttl {
			delete(rt.buckets, k)
		}
	}
	for len(rt.buckets) >= e.opts.MaxKeys {
		var ok string
		var ot time.Time
		f := true
		for k, b := range rt.buckets {
			if f || b.seen.Before(ot) {
				ok, ot, f = k, b.seen, false
			}
		}
		delete(rt.buckets, ok)
	}
}

func (e *Engine) stepSeq(out []Alert, rt *ruleRT, c *evalCtx) []Alert {
	r, ss := rt.r, rt.r.seq
	now := c.ev.Time
	if hasKind(ss.thenKinds, c.ev.Kind) && ss.thenCond.eval(c) {
		key := keyOf(ss.by, c)
		if p := rt.pend[key]; p != nil {
			delete(rt.pend, key)
			if !now.Before(p.t) && now.Sub(p.t) <= ss.within {
				out = append(out, e.alert(r, c, []event.Event{p.ev, *c.ev}))
			}
		}
	}
	if hasKind(r.Kinds, c.ev.Kind) && r.cond.eval(c) {
		key := keyOf(ss.by, c)
		if _, ok := rt.pend[key]; !ok && len(rt.pend) >= e.opts.MaxKeys {
			for k, p := range rt.pend {
				if now.Sub(p.t) > ss.within {
					delete(rt.pend, k)
				}
			}
			for len(rt.pend) >= e.opts.MaxKeys {
				for k := range rt.pend {
					delete(rt.pend, k)
					break
				}
			}
		}
		rt.pend[key] = &pending{t: now, ev: *c.ev}
	}
	return out
}

// StateSize reports bounded-state occupancy (buckets, pending, profile keys)
// for health reporting and tests.
func (e *Engine) StateSize() (buckets, pending, profileKeys int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rts := range e.byKind {
		_ = rts
	}
	seen := map[*ruleRT]bool{}
	for _, rts := range e.byKind {
		for _, rt := range rts {
			if !seen[rt] {
				seen[rt] = true
				buckets += len(rt.buckets)
				pending += len(rt.pend)
			}
		}
	}
	for _, ps := range e.profiles {
		profileKeys += len(ps.keys)
	}
	return
}
