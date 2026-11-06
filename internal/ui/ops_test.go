package ui

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOps records calls and returns canned read models.
type fakeOps struct {
	mu          sync.Mutex
	calls       []string
	modules     []ModuleRow
	locked      bool
	lockedSince time.Time
}

func (f *fakeOps) rec(s string) error {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
	return nil
}
func (f *fakeOps) called() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, ";")
}

func (f *fakeOps) Overview(context.Context) (OpsDashboard, error) {
	return OpsDashboard{Agents: AgentSummary{Total: 1, Connected: 1, Rows: []AgentRow{{Host: "h<1>", State: "connected", Config: "applied"}}},
		OpenAlerts: 2, AlertsBySev: []SevCount{{"high", 2}}, Locked: f.locked, LockedSince: f.lockedSince}, nil
}
func (f *fakeOps) Modules(context.Context) []ModuleRow { return f.modules }
func (f *fakeOps) AgentDetail(_ context.Context, h string) (AgentDetail, error) {
	if h == "nope" {
		return AgentDetail{}, ErrNotFound
	}
	return AgentDetail{Host: h, Known: true, State: "connected", Modules: []KV{{"audit", "running"}}}, nil
}
func (f *fakeOps) SetSafeMode(_ context.Context, h string, on bool, by string) error {
	return f.rec("safe:" + h + ":" + by + ":" + map[bool]string{true: "on", false: "off"}[on])
}
func (f *fakeOps) ReenableAuto(_ context.Context, host, object, kind, by string) error {
	return f.rec("reenable:" + host + ":" + object + ":" + kind + ":" + by)
}
func (f *fakeOps) Alerts(context.Context, string) ([]AlertRow, error) {
	return []AlertRow{{ID: 7, Severity: "high", Title: "<b>x</b>", Host: "h1", State: "open", Time: time.Unix(0, 0)}}, nil
}
func (f *fakeOps) Alert(_ context.Context, id int64) (AlertDetail, error) {
	return AlertDetail{AlertRow: AlertRow{ID: id, Title: "t", Severity: "high"}, Evidence: []EvidenceRow{{Agent: "h1", Seq: 3, Kind: "proc.exec", Body: `{"a":1}`}}}, nil
}
func (f *fakeOps) TraceAlert(_ context.Context, id int64, by string) (int64, error) {
	return 42, f.rec("trace:" + by)
}
func (f *fakeOps) SetAlertState(_ context.Context, id int64, st, by string) error {
	return f.rec("alertstate:" + st)
}
func (f *fakeOps) Chains(context.Context) ([]CampaignView, error) {
	return []CampaignView{{ID: 1, Name: "camp", Chains: []ChainBrief{{ID: 42, Hops: 2}}}}, nil
}
func (f *fakeOps) Chain(_ context.Context, id int64) (ChainView, error) {
	return ChainView{ID: id, Rows: []TimelineRow{{Ord: 0, Cause: -1, What: "ssh login", Host: "h1", Evidence: []string{"h1#3"}}}}, nil
}
func (f *fakeOps) Templates(context.Context) ([]TemplateInfo, error) {
	return []TemplateInfo{{Name: "t1", Title: "T", Nodes: 2}}, nil
}
func (f *fakeOps) CreatePlan(_ context.Context, tpl, id, by string) (string, error) {
	if tpl == "bad" {
		return "", ErrInvalid
	}
	return "p-1", f.rec("create:" + tpl + ":" + by)
}
func (f *fakeOps) Proposals(context.Context) ([]ProposalRow, error) {
	return []ProposalRow{{ID: 1, Module: "ctltest", Title: "<script>x</script>", Template: "fix", Reason: "tier 1",
		Evidence: []string{"h1:7"}, Created: time.Unix(0, 0), State: "open"}}, nil
}
func (f *fakeOps) AcceptProposal(_ context.Context, id int64, by string) (string, error) {
	return "p-1", f.rec("acceptproposal:" + strconv.FormatInt(id, 10) + ":" + by)
}
func (f *fakeOps) DismissProposal(_ context.Context, id int64, by string) error {
	return f.rec("dismissproposal:" + strconv.FormatInt(id, 10) + ":" + by)
}
func (f *fakeOps) Plans(context.Context) ([]PlanBrief, error) {
	return []PlanBrief{{ID: "p-1", State: "dryrun", Waiting: "plan approval"}}, nil
}
func (f *fakeOps) Plan(_ context.Context, id string) (PlanView, error) {
	return PlanView{PlanBrief: PlanBrief{ID: id, State: "dryrun"}, HasDryRun: true, Approvable: true, CanApprove: true,
		Nodes: []PlanNodeView{{ID: "n1", DryStatus: "will_change", Diff: "+x", NeedsOwnApproval: true, CanApprove: true}}}, nil
}
func (f *fakeOps) DryRun(_ context.Context, id string) error { return f.rec("dry:" + id) }
func (f *fakeOps) ApprovePlan(_ context.Context, id, by string) error {
	return f.rec("approve:" + id + ":" + by)
}
func (f *fakeOps) ApproveNode(_ context.Context, id, n, by, note string) error {
	return f.rec("approvenode:" + id + "/" + n + ":" + by + ":" + note)
}
func (f *fakeOps) Apply(_ context.Context, id, by string) error    { return f.rec("apply:" + id) }
func (f *fakeOps) Rollback(_ context.Context, id, by string) error { return f.rec("rollback:" + id) }
func (f *fakeOps) EnrollHosts(context.Context) ([]EnrollRow, error) {
	return []EnrollRow{{Host: "h1", State: "enrolled", Connected: true}, {Host: "h2", State: "not_enrolled"}}, nil
}
func (f *fakeOps) EnrollLine(_ context.Context, h, osName, by string) (string, error) {
	return "curl -sk --pinnedpubkey sha256//PIN https://ctl:7443/l/" + testToken + "|sh", f.rec("line:" + h + ":" + osName + ":" + by)
}
func (f *fakeOps) EnrollPush(_ context.Context, h, by string) error {
	return f.rec("push:" + h + ":" + by)
}
func (f *fakeOps) ReenrollAll(_ context.Context, by string) error { return f.rec("reenroll:" + by) }

func opsEnv(t *testing.T) (*env, *fakeOps) {
	f := &fakeOps{}
	return newEnv(t, func(c *Config) { c.Ops = f }), f
}

func TestOpsPagesRender(t *testing.T) {
	e, _ := opsEnv(t)
	c, _ := e.loggedIn()
	for path, want := range map[string]string{
		"/":                   "1 of 1 connected",
		"/dashboard/live":     "no scorer data",
		"/agents/h1":          "audit",
		"/agents/h1/safemode": "Type the host name",
		"/alerts":             "&lt;b&gt;x&lt;/b&gt;",
		"/alerts/7":           "proc.exec",
		"/chains":             "camp",
		"/chains/42":          "ssh login",
		"/plans":              "t1",
		"/plans/p-1":          "Approve plan",
		"/plans/p-1/nodes":    "will_change",
	} {
		w := c.do("GET", path, nil, nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), want) {
			t.Errorf("GET %s: %d, missing %q:\n%s", path, w.Code, want, w.Body)
		}
	}
	if w := c.do("GET", "/", nil, nil); strings.Contains(w.Body.String(), "<b>x</b>") || !strings.Contains(w.Body.String(), "h&lt;1&gt;") {
		t.Error("dashboard host not escaped")
	}
	if w := c.do("GET", "/agents/nope", nil, nil); w.Code != 404 {
		t.Errorf("unknown agent: %d", w.Code)
	}
}

var opsPosts = []string{
	"/agents/h1/safemode", "/auto/reenable", "/alerts/7/trace", "/alerts/7/state", "/plans",
	"/plans/p-1/dryrun", "/plans/p-1/approve", "/plans/p-1/nodes/n1/approve", "/plans/p-1/apply", "/plans/p-1/rollback",
	"/proposals/1/accept", "/proposals/1/dismiss",
	"/enroll/h1/line", "/enroll/h1/push", "/enroll/reenroll-all",
}

func TestOpsRoutesRequireAuthAndCSRF(t *testing.T) {
	e, f := opsEnv(t)
	anon := &client{e: e}
	for _, p := range opsPosts {
		if w := anon.do("POST", p, url.Values{"template": {"t1"}}, nil); w.Code != 303 && w.Code != 401 {
			t.Errorf("anonymous POST %s: %d", p, w.Code)
		}
	}
	for _, p := range []string{"/agents/h1", "/alerts", "/alerts/7", "/chains", "/chains/1", "/plans", "/plans/p-1", "/plans/p-1/nodes", "/proposals", "/dashboard/live", "/enroll"} {
		if w := anon.do("GET", p, nil, nil); w.Code != 303 {
			t.Errorf("anonymous GET %s: %d", p, w.Code)
		}
	}
	c, tok := e.loggedIn()
	for _, p := range opsPosts {
		form := url.Values{"template": {"t1"}, "confirm": {"h1"}, "on": {"1"}, "state": {"acked"}}
		if w := c.do("POST", p, form, nil); w.Code != 403 {
			t.Errorf("POST %s without token: %d", p, w.Code)
		}
		form.Set("csrf_token", "wrong")
		if w := c.do("POST", p, form, nil); w.Code != 403 {
			t.Errorf("POST %s with wrong token: %d", p, w.Code)
		}
		form.Set("csrf_token", tok)
		if w := c.do("POST", p, form, map[string]string{"Origin": "http://evil.example"}); w.Code != 403 {
			t.Errorf("POST %s cross-origin: %d", p, w.Code)
		}
	}
	if got := f.called(); got != "" {
		t.Fatalf("backend reached without a valid CSRF token: %q", got)
	}
}

func TestOpsActionsAuditedAndAttributed(t *testing.T) {
	e, f := opsEnv(t)
	c, tok := e.loggedIn()
	post := func(path string, extra url.Values) int {
		form := url.Values{"csrf_token": {tok}}
		for k, v := range extra {
			form[k] = v
		}
		return c.do("POST", path, form, nil).Code
	}
	if code := post("/agents/h1/safemode", url.Values{"on": {"1"}, "confirm": {"other"}}); code != 400 {
		t.Errorf("safe mode with wrong confirmation: %d", code)
	}
	if f.called() != "" {
		t.Fatal("safe mode sent without confirmation")
	}
	for path, extra := range map[string]url.Values{
		"/agents/h1/safemode":         {"on": {"1"}, "confirm": {"h1"}},
		"/auto/reenable":              {"host": {"h1"}, "object": {"/etc/hosts"}, "kind": {"t1"}},
		"/alerts/7/trace":             nil,
		"/alerts/7/state":             {"state": {"closed"}},
		"/plans":                      {"template": {"t1"}},
		"/plans/p-1/dryrun":           nil,
		"/plans/p-1/approve":          nil,
		"/plans/p-1/nodes/n1/approve": {"note": {"checked"}},
		"/plans/p-1/apply":            nil,
		"/plans/p-1/rollback":         nil,
	} {
		if code := post(path, extra); code != 303 {
			t.Errorf("POST %s: %d", path, code)
		}
	}
	want := []string{"safe:h1:admin:on", "reenable:h1:/etc/hosts:t1:admin", "trace:admin", "alertstate:closed", "create:t1:admin", "dry:p-1",
		"approve:p-1:admin", "approvenode:p-1/n1:admin:checked", "apply:p-1", "rollback:p-1"}
	got := f.called()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("backend call %q missing in %q", w, got)
		}
	}
	acts := strings.Join(e.audit.actions(), ",")
	for _, a := range []string{"safe_mode", "alert_trace", "alert_state", "plan_create", "plan_dryrun", "plan_approve", "plan_approve_node", "plan_apply", "plan_rollback"} {
		if !strings.Contains(acts, a) {
			t.Errorf("audit action %q missing in %q", a, acts)
		}
	}
	if code := post("/plans", url.Values{"template": {"bad"}}); code != 400 {
		t.Errorf("invalid backend input: %d", code)
	}
}

func TestOpsRefusedWhenAuditDown(t *testing.T) {
	e, f := opsEnv(t)
	c, tok := e.loggedIn()
	e.audit.mu.Lock()
	e.audit.fail = true
	e.audit.mu.Unlock()
	w := c.do("POST", "/plans/p-1/approve", url.Values{"csrf_token": {tok}}, nil)
	if w.Code != 500 || f.called() != "" {
		t.Fatalf("approval ran with the audit log down: %d %q", w.Code, f.called())
	}
}

func TestNoOpsNoPages(t *testing.T) {
	e := newEnv(t, nil)
	c, _ := e.loggedIn()
	if w := c.do("GET", "/plans", nil, nil); w.Code != 404 {
		t.Errorf("plans without a backend: %d", w.Code)
	}
}
