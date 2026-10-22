package controller

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/checks"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// kindVantageCheck is the event the Kali check runner emits per probe result
// (vantage.KindCheck; the string is repeated here to keep the controller free
// of the vantage package).
const kindVantageCheck = "vantage.check"

// ChecksHub collects probe results from every vantage: the probe library run
// on the controller (RecordResult, RunProbe) and vantage.check events stored
// from agents. Results are kept in the store (check_results, with history);
// faithful results also advance the SLA streaks the dashboard shows, through
// WebOps.SetScorer.
type ChecksHub struct {
	c *Controller

	mu        sync.Mutex
	sla       *scorer.SLATracker
	round     int
	svcs      map[string]bool
	serviceOf func(id string) string
	ops       *WebOps
}

func newChecksHub(c *Controller) *ChecksHub {
	return &ChecksHub{c: c, sla: scorer.NewSLATracker(scorer.SLAConfig{Threshold: 5}), svcs: map[string]bool{}}
}

// Checks is the controller's hub.
func (c *Controller) Checks() *ChecksHub { return c.checks }

// SetServiceFunc maps a check id to its scored service (default: the part of
// the id before the first ':' or '/', else the whole id).
func (h *ChecksHub) SetServiceFunc(f func(id string) string) {
	h.mu.Lock()
	h.serviceOf = f
	h.mu.Unlock()
}

// SLA is the tracker fed by faithful results.
func (h *ChecksHub) SLA() *scorer.SLATracker { return h.sla }

func (h *ChecksHub) service(id string) string {
	h.mu.Lock()
	f := h.serviceOf
	h.mu.Unlock()
	if f != nil {
		if s := f(id); s != "" {
			return s
		}
	}
	if i := strings.IndexAny(id, ":/"); i > 0 {
		return id[:i]
	}
	return id
}

// Services lists the services seen so far, sorted.
func (h *ChecksHub) Services() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.svcs))
	for s := range h.svcs {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// attach connects the hub to the UI backend and publishes the SLA state.
func (h *ChecksHub) attach(o *WebOps) {
	h.mu.Lock()
	h.ops = o
	h.mu.Unlock()
	h.feed()
}

// feed hands the hub's SLA tracker to the dashboard (WebOps.SetScorer) unless
// someone else installed a different tracker.
func (h *ChecksHub) feed() {
	h.mu.Lock()
	o := h.ops
	h.mu.Unlock()
	if o == nil {
		return
	}
	o.smu.Lock()
	est, cur := o.est, o.sla
	o.smu.Unlock()
	if cur == nil || cur == h.sla {
		o.SetScorer(est, h.sla, h.Services)
	}
}

// RecordResult stores a probe-library result from the given vantage ("controller"
// for probes run here) and, for faithful runs, advances the service's SLA streak.
func (h *ChecksHub) RecordResult(ctx context.Context, vantage string, res checks.Result) error {
	at := res.Start
	if at.IsZero() {
		at = h.c.now()
	}
	detail, _ := json.Marshal(map[string]any{
		"class": string(res.Class), "err": res.Err, "mode": res.Mode, "item": res.Item, "user": res.User,
		"host": res.Host, "port": res.Port, "elapsed_ms": res.Elapsed.Milliseconds(), "scorer_ok": res.ScorerOK, "strict": res.Strict,
	})
	svc := h.service(res.ID)
	if err := h.c.st.RecordCheck(ctx, store.CheckResult{CheckID: res.ID, Service: svc, Kind: string(res.Type),
		Vantage: vantage, Time: at, OK: res.OK, Detail: string(detail)}); err != nil {
		return err
	}
	if res.Mode == "faithful" || res.Mode == "" {
		h.observe(svc, res.ScorerOK)
	}
	return nil
}

// RunProbe runs one faithful probe with the probe library and records it.
func (h *ChecksHub) RunProbe(ctx context.Context, spec checks.Spec, opts checks.Options) (checks.Result, error) {
	res := checks.Faithful(ctx, spec, opts)
	return res, h.RecordResult(ctx, "controller", res)
}

func (h *ChecksHub) observe(service string, ok bool) {
	h.mu.Lock()
	h.round++
	h.svcs[service] = true
	o := scorer.OutcomeFail
	if ok {
		o = scorer.OutcomePass
	}
	alerts := h.sla.ObserveRound(h.round, map[string]scorer.Outcome{service: o})
	h.mu.Unlock()
	for _, a := range alerts {
		h.c.alert(service, "sla."+string(a.Level), a.Detail)
	}
	h.feed()
}

// resultFromEvent decodes a vantage.check event (it carries no credentials).
func (h *ChecksHub) resultFromEvent(e event.Event) (store.CheckResult, bool) {
	id := fstr(e.Fields, "id")
	if id == "" {
		return store.CheckResult{}, false
	}
	ok, _ := e.Fields["ok"].(bool)
	keep := map[string]any{}
	for _, k := range []string{"class", "err", "mode", "item", "user", "host", "port", "elapsed_ms", "scorer_ok", "strict", "strict_issues"} {
		if v, present := e.Fields[k]; present {
			keep[k] = v
		}
	}
	detail, _ := json.Marshal(keep)
	return store.CheckResult{CheckID: id, Service: h.service(id), Kind: fstr(e.Fields, "type"), Vantage: e.Agent,
		Time: e.Time, OK: ok, Detail: string(detail)}, true
}

// observeEvent advances the SLA for a committed vantage.check event.
func (h *ChecksHub) observeEvent(e event.Event) {
	cr, ok := h.resultFromEvent(e)
	if !ok {
		return
	}
	if mode := fstr(e.Fields, "mode"); mode != "faithful" && mode != "" {
		return
	}
	sok, has := e.Fields["scorer_ok"].(bool)
	if !has {
		sok = cr.OK
	}
	h.observe(cr.Service, sok)
}

// rebuild restores the SLA state from the stored faithful results (oldest
// first) so streaks survive a controller restart.
func (h *ChecksHub) rebuild(ctx context.Context) {
	rows, err := h.c.st.Checks(ctx)
	if err != nil {
		return
	}
	type obs struct {
		t   time.Time
		svc string
		ok  bool
	}
	var all []obs
	for _, ck := range rows {
		hist, err := h.c.st.CheckHistory(ctx, ck.ID, 300)
		if err != nil {
			continue
		}
		for _, r := range hist {
			var d struct {
				Mode     string `json:"mode"`
				ScorerOK *bool  `json:"scorer_ok"`
			}
			_ = json.Unmarshal([]byte(r.Detail), &d)
			if d.Mode != "faithful" && d.Mode != "" {
				continue
			}
			ok := r.OK
			if d.ScorerOK != nil {
				ok = *d.ScorerOK
			}
			all = append(all, obs{r.Time, ck.Service, ok})
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, o := range all {
		h.round++
		h.svcs[o.svc] = true
		out := scorer.OutcomeFail
		if o.ok {
			out = scorer.OutcomePass
		}
		h.sla.ObserveRound(h.round, map[string]scorer.Outcome{o.svc: out})
	}
}
