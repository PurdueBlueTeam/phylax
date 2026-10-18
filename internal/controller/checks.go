package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/discovery"
	"github.com/PurdueBlueTeam/phylax/internal/labels"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/traceback"
	checks "github.com/PurdueBlueTeam/phylax/internal/checks"
)

// ServiceInfo names a scored service for change detection and trace-back:
// its listening port and the content roots a change under it is a
// service change (docs: What counts as a change).
type ServiceInfo struct {
	Name         string   `json:"name"`
	Scored       bool     `json:"scored"`
	Port         int      `json:"port"`
	ContentRoots []string `json:"content_roots,omitempty"`
	Kind         string   `json:"kind,omitempty"` // manifest service kind (web, mail, dns, ...)
}

// SetServices declares the scored services for change detection, the
// trace-back request link and the discovery service map.
func (c *Controller) SetServices(s []ServiceInfo) {
	c.svcMu.Lock()
	c.services = map[string]ServiceInfo{}
	for _, si := range s {
		c.services[si.Name] = si
	}
	c.svcMu.Unlock()
	if c.disc != nil {
		svcs := make([]discovery.Service, 0, len(s))
		for _, si := range s {
			svcs = append(svcs, discovery.Service{Name: si.Name, Port: si.Port, Scored: si.Scored})
		}
		c.disc.SetServices(svcs)
	}
}

// NewDiscovery wires the check-discovery module (docs: Check discovery)
// over the controller's event stream. us is the platform's own addresses
// (controller, agents, relays): never scorer, never trace-back sources.
func (c *Controller) NewDiscovery(us []string, round time.Duration) *discovery.Module {
	c.labs = labels.New(us)
	m := discovery.New(c, discovery.Config{
		US:            us,
		RoundDuration: round,
		Now:           time.Now,
	})
	c.disc = m
	c.trace = traceback.New()
	for _, ip := range us {
		c.trace.AddUSSource(ip)
	}
	c.trace.SetLabeler(c.labs.Classify)
	c.syncDiscovery()
	return m
}

// RunCorrelation starts the discovery module's periodic work (stale and
// blocked checks, rhythm learning) until ctx is done.
func (c *Controller) RunCorrelation(ctx context.Context) {
	if c.disc != nil {
		go c.disc.Run(ctx)
		// feed the learned scorer sources into the traffic labels
		// (docs: scorer learned by check discovery)
		go func() {
			t := time.NewTicker(c.disc.RoundDuration())
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					c.SetScorerSources(c.disc.ScorerSources())
				}
			}
		}()
	}
}

// ---- event observation ---------------------------------------------------------
//
// observeEvent feeds one mirrored agent event to the controller-side
// correlation modules: check discovery, traffic labels, trace-back and
// change detection (D17). It runs inline on the connection goroutine;
// the modules are bounded and non-blocking.

func (c *Controller) observeEvent(host string, ev store.Event) {
	data := map[string]any{}
	if err := json.Unmarshal(ev.Data, &data); err != nil {
		return
	}
	ts := parseTS(ev.TS)

	// trace-back: index everything
	if c.trace != nil {
		c.trace.AddEvent(traceback.Event{Host: host, TS: ts, Type: ev.Type, Data: data})
	}

	// check discovery: transactions and flows
	if c.disc != nil {
		c.disc.HandleEvent(ev.Type, data)
	}

	switch ev.Type {
	case "check_result", "check_red":
		c.observeCheck("agent:"+host, ev.Type, ts, data)
	case "file_change":
		c.observeFileChange(host, ts, data)
	case "alert":
		rule, _ := data["rule"].(string)
		// agent-side detection of a content change (D2) on a scored
		// service: the trace-back is triggered by any high-severity
		// detection on a service (docs: The trace-back chain). The
		// trigger event rides in the alert's "event" field.
		if rule == "D2.content-tamper" {
			if inner, ok := data["event"].(map[string]any); ok {
				c.observeFileChange(host, ts, inner)
			}
		}
		// traffic labels: detections tag their source as attack-like,
		// so later connections from it are labeled on sight (docs:
		// Traffic labels — "scans, exploit payloads, webshell
		// requests, decoy hits").
		if isAttackLike(rule) {
			if inner, ok := data["event"].(map[string]any); ok {
				if src := eventSrc(inner); src != "" {
					c.markRed(src)
				}
			}
		}
	}
}

// isAttackLike reports whether a detection rule tags its source
// attack-like (docs: Traffic labels). Decoy hits are D15.*.
func isAttackLike(rule string) bool {
	switch rule {
	case "D1.service-spawns-shell", // webshell request
		"D2.content-tamper", // webshell or defacement drop
		"D8.credential-theft",
		"D9.lateral-movement":
		return true
	}
	return strings.HasPrefix(rule, "D15.")
}

// eventSrc finds the remote address in a detection's trigger event:
// connection events carry raddr (the net module's field), decoy and
// capture events carry src.
func eventSrc(ev map[string]any) string {
	for _, k := range []string{"src", "raddr", "source", "src_ip"} {
		if s, ok := ev[k].(string); ok && s != "" {
			if net.ParseIP(s) != nil {
				return s
			}
		}
	}
	return ""
}

func (c *Controller) markRed(src string) {
	if c.labs != nil {
		c.labs.MarkRed(src)
	}
}

// RedSources lists the attack-like-tagged sources (the UI's traffic
// view).
func (c *Controller) RedSources() []string {
	if c.labs == nil {
		return nil
	}
	return c.labs.RedSources()
}

func parseTS(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ---- active checks (controller vantage) ----------------------------------------

// checker is the controller-side active checker (docs: the checker module
// in the controller, per-check timeouts and its own panic recovery).
// Thread-safe: the checker's own methods guard their state.
func (c *Controller) checker() *checks.Checker {
	c.chkMu.Lock()
	defer c.chkMu.Unlock()
	if c.chk == nil {
		c.chk = checks.NewChecker("controller")
		c.chk.SetSink(c)
		for _, ck := range c.loadChecks() {
			c.chk.Upsert(ck)
		}
	}
	return c.chk
}

// RunChecks runs the controller vantage's scheduler until ctx is done.
func (c *Controller) RunChecks(ctx context.Context) {
	c.checker().Run(ctx)
}

// checksPath is the controller's active-check list (every change is
// written to it and takes effect immediately, docs: Active checks).
func (c *Controller) checksPath() string {
	return filepath.Join(c.st.Dir(), "checks.json")
}

func (c *Controller) loadChecks() []checks.Check {
	b, err := os.ReadFile(c.checksPath())
	if err != nil {
		return nil
	}
	var out []checks.Check
	_ = json.Unmarshal(b, &out)
	return out
}

func (c *Controller) saveChecks(list []checks.Check) {
	b, _ := json.MarshalIndent(list, "", "  ")
	_ = os.WriteFile(c.checksPath(), b, 0o600)
}

// UpsertCheck adds or replaces an active check (operator action).
func (c *Controller) UpsertCheck(ck checks.Check) error {
	if ck.ID == "" || ck.Type == "" {
		return fmt.Errorf("checks: id and type required")
	}
	if ck.Origin == "" {
		ck.Origin = "manual"
	}
	if ck.State == "" {
		ck.State = "active"
	}
	c.checker().Upsert(ck)
	c.saveChecks(c.checker().List())
	c.syncDiscovery()
	return nil
}

// AcceptCurrentCheck resets a check's expected result to its last
// successful actual (docs: Accept current response, after a legitimate
// change such as an inject that edits a page).
func (c *Controller) AcceptCurrentCheck(id string) error {
	if err := c.checker().AcceptCurrent(id); err != nil {
		return err
	}
	c.saveChecks(c.checker().List())
	c.syncDiscovery()
	return nil
}

func (c *Controller) setStateCheck(id, state string) error {
	var err error
	switch state {
	case "active":
		err = c.checker().Activate(id)
	case "paused":
		err = c.checker().Pause(id)
	case "retired":
		err = c.checker().Retire(id)
	default:
		return fmt.Errorf("checks: bad state %q", state)
	}
	if err != nil {
		return err
	}
	c.saveChecks(c.checker().List())
	c.syncDiscovery()
	return nil
}

// syncDiscovery keeps the discovery module's comparison against the
// current active list (docs: compare against the active list).
func (c *Controller) syncDiscovery() {
	if c.disc != nil {
		c.disc.SetActive(c.checker().List())
	}
}

// checks.Sink for the controller vantage: results arrive from the
// checker's own scheduler.
func (c *Controller) Result(r checks.Result) {
	c.observeCheck("controller", "check_result", r.TS, resultMap(r))
}

func (c *Controller) Red(r checks.Result) {
	c.observeCheck("controller", "check_red", r.TS, resultMap(r))
}

func resultMap(r checks.Result) map[string]any {
	m := map[string]any{"check": r.CheckID, "vantage": r.Vantage, "ok": r.OK, "detail": r.Detail}
	if r.Actual != nil {
		m["actual"] = r.Actual
	}
	return m
}

// observeCheck records one vantage result and, on a red transition,
// opens the alert with the response diff and the latest trace-back for
// the check's service attached (docs: Active checks — Results).
func (c *Controller) observeCheck(vantage, typ string, ts time.Time, data map[string]any) {
	id, _ := data["check"].(string)
	if id == "" {
		return
	}
	service := ""
	for _, k := range c.checker().List() {
		if k.ID == id {
			service = k.Service
			break
		}
	}
	c.resMu.Lock()
	c.results[id+"|"+vantage] = map[string]any{
		"ts": ts.UTC().Format(time.RFC3339Nano), "ok": data["ok"], "detail": data["detail"],
	}
	c.resMu.Unlock()
	if typ != "check_red" {
		return
	}
	ev := map[string]any{
		"rule": "check.red", "severity": "high", "tier": 1,
		"check": id, "service": service, "vantage": vantage,
		"detail": data["detail"],
	}
	if tl := c.latestTimelineFor(service); tl != nil {
		ev["trace_back"] = tl
	}
	c.emitAlert(ev, "check-"+id+"-"+vantage)
}

// ---- change detection (D17) and trace-back -------------------------------------

// observeFileChange implements change detection: an untagged change to a
// scored service's content or config is D17, with the trace-back attached
// (docs: D17, The trace-back chain).
func (c *Controller) observeFileChange(host string, ts time.Time, data map[string]any) {
	path, _ := data["path"].(string)
	op, _ := data["op"].(string)
	tag, _ := data["tag"].(string)
	if tag != "" || path == "" {
		return
	}
	c.svcMu.Lock()
	var svc *ServiceInfo
	for _, si := range c.services {
		if si.Scored && inRoots(path, si.ContentRoots) {
			c2 := si
			svc = &c2
			break
		}
	}
	c.svcMu.Unlock()
	if svc == nil {
		return
	}
	tl := c.trace.Build(traceback.Change{
		Host: host, Path: path, Op: op, TS: ts,
		SHA256: strOf(data["sha256"]), Service: svc.Name, Port: svc.Port,
	})
	c.resMu.Lock()
	c.timelines[svc.Name] = tl
	c.resMu.Unlock()
	c.emitAlert(map[string]any{
		"rule": "D17.service-change", "severity": "high", "tier": 1,
		"attack":  []string{"T1505.003"},
		"service": svc.Name, "path": path, "op": op, "host": host,
		"trace_back": tl,
	}, "d17-"+svc.Name+"-"+path)
}

// latestTimelineFor returns the most recent trace-back built for the
// service (a red check's alert attaches it, docs: Active checks).
func (c *Controller) latestTimelineFor(service string) *traceback.Timeline {
	c.resMu.Lock()
	defer c.resMu.Unlock()
	return c.timelines[service]
}

// emitAlert stores one controller-side alert as an event under the
// controller's virtual host so the /alerts view shows it alongside the
// agent-side alerts.
func (c *Controller) emitAlert(data map[string]any, key string) {
	c.alertMu.Lock()
	c.alertSeq++
	seq := c.alertSeq
	c.alertMu.Unlock()
	b, _ := json.Marshal(data)
	if _, err := c.st.RecordEvent("controller", store.Event{
		Seq: seq, TS: time.Now().UTC().Format(time.RFC3339Nano),
		Type: "alert", Data: b, Hash: "controller:" + key,
	}); err != nil {
		return
	}
}

func inRoots(path string, roots []string) bool {
	if len(roots) == 0 {
		return false
	}
	for _, r := range roots {
		if path == r || strings.HasPrefix(path, r+"/") {
			return true
		}
	}
	return false
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

// ---- HTTP: the checks view ------------------------------------------------------
//
//	GET  /checks   active checks + latest results per vantage, observed
//	               scorer checks, proposals, stale flags, scored accounts
//	POST /checks   {"op": "upsert"|"pause"|"retire"|"activate"|"accept", ...}

func (c *Controller) handleChecks(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r.RemoteAddr) {
		http.Error(w, "localhost only", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		list := c.checker().List()
		c.resMu.Lock()
		results := map[string]any{}
		for k, v := range c.results {
			results[k] = v
		}
		c.resMu.Unlock()
		out := map[string]any{"checks": list, "results": results, "scored_accounts": c.ScoredAccounts()}
		if c.disc != nil {
			out["observed"] = c.disc.Observed()
			out["proposals"] = c.disc.Proposals()
		}
		json.NewEncoder(w).Encode(out)
	case http.MethodPost:
		var req struct {
			Op    string       `json:"op"`
			Check checks.Check `json:"check,omitempty"`
			ID    string       `json:"id,omitempty"`
			// Proposal resolves a discovery proposal:
			// {"op":"resolve","proposal":id,"accept":true|false}
			Proposal string `json:"proposal,omitempty"`
			Accept   bool   `json:"accept,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var err error
		switch req.Op {
		case "upsert":
			err = c.UpsertCheck(req.Check)
		case "accept":
			err = c.AcceptCurrentCheck(req.ID)
		case "pause", "retire", "activate":
			err = c.setStateCheck(req.ID, req.Op)
		case "resolve":
			if c.disc == nil {
				err = fmt.Errorf("discovery not configured")
			} else {
				c.disc.Resolve(req.Proposal, req.Accept)
				if req.Accept {
					// find the proposal's check and activate it
					var ck *checks.Check
					for _, p := range c.disc.Proposals() {
						if p.ID == req.Proposal {
							k := p.Check
							ck = &k
							break
						}
					}
					if ck == nil {
						// already resolved; nothing to do
						break
					}
					_ = c.UpsertCheck(*ck)
				}
			}
		default:
			err = fmt.Errorf("checks: bad op %q", req.Op)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- HTTP: the traffic view -----------------------------------------------------
//
//	GET /traffic  recent flow records across all agents, each source
//	               labeled us | scorer | other, attack-like tagged
//
// Docs: Traffic labels — "label every connection to a scored service
// as scorer, us or other, and flag attack-like traffic within other".

func (c *Controller) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r.RemoteAddr) {
		http.Error(w, "localhost only", http.StatusForbidden)
		return
	}
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = n
	}
	if limit > 500 {
		limit = 500
	}
	svcPorts := map[int]bool{}
	c.svcMu.Lock()
	for _, si := range c.services {
		if si.Scored {
			svcPorts[si.Port] = true
		}
	}
	c.svcMu.Unlock()

	evs, err := c.st.QueryEventsAnyHost("flow", limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	flows := make([]map[string]any, 0, len(evs))
	for _, ev := range evs {
		data := map[string]any{}
		if err := json.Unmarshal(ev.Data, &data); err != nil {
			continue
		}
		src := flowIP(data["src"])
		dst := flowIP(data["dst"])
		dport := intOf(data["dport"])
		label := "other"
		if c.labs != nil {
			label = c.labs.Classify(src)
		}
		red := false
		if c.labs != nil {
			red = c.labs.IsRed(src)
		}
		f := map[string]any{
			"ts": ev.TS, "src": src, "dst": dst,
			"sport": data["sport"], "dport": dport, "proto": data["proto"],
			"result": data["result"], "scan": data["scan"],
			"label": label, "red": red, "scored": svcPorts[dport],
		}
		if pid, ok := data["pid"]; ok {
			f["pid"] = pid
		}
		flows = append(flows, f)
	}
	out := map[string]any{"flows": flows}
	if c.labs != nil {
		out["red_sources"] = c.labs.RedSources()
		out["scorer_sources"] = c.labs.ScorerSources()
	}
	json.NewEncoder(w).Encode(out)
}

// flowIP decodes a flow endpoint: a base64 byte string (the agent's
// [16]byte through JSON, v4 in the last four bytes) or a plain dotted
// quad.
func flowIP(v any) string {
	s, ok := v.(string)
	if !ok || s == "" {
		return ""
	}
	if net.ParseIP(s) != nil {
		return s
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil && len(b) >= 4 {
		return net.IP(b[len(b)-4:]).String()
	}
	return ""
}

func intOf(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return 0
}

// ---- discovery.Sink -------------------------------------------------------------
//
// The controller is discovery's sink: proposals are stored for the checks
// view, scored accounts are marked, D16 alerts are emitted.

func (c *Controller) Proposal(p discovery.Proposal) {
	// D16: scorer check change — new or changed (docs: D16)
	c.emitAlert(map[string]any{
		"rule": "D16.scorer-check-change", "severity": "info", "tier": 2,
		"kind": p.Kind, "service": p.Observed.Service, "reason": p.Reason,
		"proposal": p.ID,
	}, "d16-"+p.ID)
}

func (c *Controller) Stale(p discovery.Proposal) {
	c.emitAlert(map[string]any{
		"rule": "D16.scorer-check-change", "severity": "info", "tier": 2,
		"kind": "stale", "service": p.Check.Service, "reason": p.Reason,
		"proposal": p.ID,
	}, "d16-stale-"+p.ID)
}

func (c *Controller) Account(a discovery.AccountMark) {
	c.MarkAccount(a.Account, a.Source, a.TS)
}

func (c *Controller) Blocked(b discovery.Blocked) {
	// D16: scorer traffic missing for a service (docs: D16). The Palo's
	// deny logs for the window are attached here in the lab; they are
	// unavailable in this environment (U-03).
	c.emitAlert(map[string]any{
		"rule": "D16.scorer-check-change", "severity": "info", "tier": 2,
		"kind": "blocked", "service": b.Service,
		"window": [2]string{b.WindowStart.UTC().Format(time.RFC3339), b.WindowEnd.UTC().Format(time.RFC3339)},
	}, "d16-blocked-"+b.Service)
}

func (c *Controller) Alert(rule string, event map[string]any, key string) {
	c.emitAlert(event, key)
	_ = rule
}

// SetScorerSources wires the learned scorer sources into the traffic
// labels (docs: Traffic labeling — scorer learned by check discovery).
func (c *Controller) SetScorerSources(srcs []string) {
	if c.labs != nil {
		c.labs.SetScorerSources(srcs)
	}
}

// MarkAccount marks a scored account: any account the scorer
// authenticates with (docs: Mark scored accounts). Rotation for it goes
// through the support-ticket workflow.
func (c *Controller) MarkAccount(account, source string, ts time.Time) {
	c.resMu.Lock()
	defer c.resMu.Unlock()
	if account == "" || c.scoredAccounts[account+"|"+source] {
		return
	}
	c.scoredAccounts[account+"|"+source] = true
	c.scoredList = append(c.scoredList, map[string]any{
		"account": account, "source": source, "ts": ts.UTC().Format(time.RFC3339Nano),
	})
	sort.Slice(c.scoredList, func(i, j int) bool {
		a, _ := c.scoredList[i]["ts"].(string)
		b, _ := c.scoredList[j]["ts"].(string)
		return a > b
	})
	if len(c.scoredList) > 100 {
		c.scoredList = c.scoredList[:100]
	}
}

// ScoredAccounts returns the marked accounts, newest first.
func (c *Controller) ScoredAccounts() []map[string]any {
	c.resMu.Lock()
	defer c.resMu.Unlock()
	out := make([]map[string]any, len(c.scoredList))
	copy(out, c.scoredList)
	return out
}

// Classify is the traffic label for an address (us/scorer/other); the
// trace-back source link and the UI use it.
func (c *Controller) Classify(ip string) string {
	if c.labs == nil {
		return "other"
	}
	return c.labs.Classify(ip)
}
