package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

type webClient struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
	tok    string
}

var tokRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func (w *webClient) do(method, path string, form url.Values) *httptest.ResponseRecorder {
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Host, r.RemoteAddr = "127.0.0.1:8443", "127.0.0.1:4000"
	if w.cookie != nil {
		r.AddCookie(w.cookie)
	}
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "phylax_session" {
			w.cookie = c
		}
	}
	return rec
}

func (w *webClient) post(path string, form url.Values) *httptest.ResponseRecorder {
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", w.tok)
	return w.do("POST", path, form)
}

func newWebClient(t *testing.T, h *harness, plansDir string) *webClient {
	t.Helper()
	srv, _, err := h.c.NewUI(controller.UIOptions{Addr: "127.0.0.1:8443", PlansDir: plansDir})
	if err != nil {
		t.Fatal(err)
	}
	pw, _, err := srv.EnsureAdmin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	w := &webClient{t: t, h: srv.Handler()}
	m := tokRE.FindStringSubmatch(w.do("GET", "/login", nil).Body.String())
	if m == nil {
		t.Fatal("no login token")
	}
	if r := w.do("POST", "/login", url.Values{"username": {"admin"}, "password": {pw}, "csrf_token": {m[1]}}); r.Code != 303 {
		t.Fatalf("login %d", r.Code)
	}
	d := w.do("GET", "/", nil)
	if m = tokRE.FindStringSubmatch(d.Body.String()); m == nil {
		t.Fatalf("no session token: %d", d.Code)
	}
	w.tok = m[1]
	return w
}

const uiTemplate = `id: ui-demo
name: UI demo (write a file, set a password, gate)
on_failure: stop_dependents
nodes:
  - id: motd
    action: file.write
    target: h2
    risk: service
    params: {path: /etc/motd, content: "managed from the UI\n"}
  - id: pw
    action: user.set_password
    target: h1
    risk: lockout
    deadman_sec: 60
    params: {user: bob, password: "Ui-Pass-1234"}
  - id: go
    gate: true
    needs: [motd, pw]
`

// Operator walk-through against real agents: create a plan from a YAML
// template, dry run, approve (plan and the lockout node and the gate, each
// CSRF-protected and audited), apply with live node states, then safe mode.
func TestUIPlanFlowEndToEnd(t *testing.T) {
	h := newHarness(t)
	h1, h2 := h.addHost("h1"), h.addHost("h2")
	ctx := context.Background()
	plans := t.TempDir()
	if err := os.WriteFile(filepath.Join(plans, "ui-demo.yml"), []byte(uiTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	w := newWebClient(t, h, plans)

	// Agents page and dashboard show the real agents.
	eventually(t, "heartbeats", 5*time.Second, func() bool {
		st, _ := h.c.AgentStatus("h1")
		return !st.LastSeen.IsZero()
	})
	d := w.do("GET", "/", nil).Body.String()
	if !strings.Contains(d, "2 of 2 connected") || !strings.Contains(d, ">h1<") {
		t.Errorf("dashboard: %s", d)
	}
	if a := w.do("GET", "/agents/h1", nil); a.Code != 200 || !strings.Contains(a.Body.String(), "Clock skew") || !strings.Contains(a.Body.String(), "Telemetry gaps") {
		t.Errorf("agent page: %d %s", a.Code, a.Body)
	}
	if w.do("GET", "/agents/ghost", nil).Code != 404 {
		t.Error("unknown agent not 404")
	}
	if !strings.Contains(w.do("GET", "/plans", nil).Body.String(), "ui-demo") {
		t.Error("template not listed")
	}

	// Create. Without the CSRF token nothing happens.
	if r := w.do("POST", "/plans", url.Values{"template": {"ui-demo"}, "plan_id": {"ui1"}}); r.Code != 403 {
		t.Fatalf("create without csrf: %d", r.Code)
	}
	if _, err := h.c.PlanStatus("ui1"); err == nil {
		t.Fatal("plan created without a CSRF token")
	}
	if r := w.post("/plans", url.Values{"template": {"../etc/passwd"}, "plan_id": {"x"}}); r.Code != 400 {
		t.Errorf("path-traversing template name: %d", r.Code)
	}
	if r := w.post("/plans", url.Values{"template": {"ui-demo"}, "plan_id": {"ui1"}}); r.Code != 303 || r.Header().Get("Location") != "/plans/ui1" {
		t.Fatalf("create: %d %q %s", r.Code, r.Header().Get("Location"), r.Body)
	}
	if r := w.post("/plans", url.Values{"template": {"ui-demo"}, "plan_id": {"ui1"}}); r.Code != 409 {
		t.Errorf("duplicate plan id: %d", r.Code)
	}

	// Approval before a dry run is refused.
	if r := w.post("/plans/ui1/approve", nil); r.Code != 409 {
		t.Fatalf("approve without dry run: %d", r.Code)
	}
	if r := w.post("/plans/ui1/dryrun", nil); r.Code != 303 {
		t.Fatalf("dry run: %d %s", r.Code, r.Body)
	}
	page := w.do("GET", "/plans/ui1", nil).Body.String()
	for _, want := range []string{"will_change", "managed from the UI", "approvable", "Approve plan", "Approve node"} {
		if !strings.Contains(page, want) {
			t.Errorf("plan page after dry run lacks %q:\n%s", want, page)
		}
	}
	if !strings.Contains(w.do("GET", "/", nil).Body.String(), "plan approval") {
		t.Error("dashboard does not list the plan awaiting approval")
	}

	// Approve the plan, then the lockout node and the gate, each by its own POST.
	if r := w.do("POST", "/plans/ui1/approve", url.Values{}); r.Code != 403 {
		t.Fatalf("approve without csrf: %d", r.Code)
	}
	if ps, _ := h.c.PlanStatus("ui1"); ps.State != controller.PlanDryRun {
		t.Fatalf("state after refused approve: %s", ps.State)
	}
	if r := w.post("/plans/ui1/approve", nil); r.Code != 303 {
		t.Fatalf("approve: %d %s", r.Code, r.Body)
	}
	if r := w.post("/plans/ui1/apply", nil); r.Code != 303 {
		t.Fatalf("apply: %d %s", r.Code, r.Body)
	}
	for _, n := range []string{"pw", "go"} {
		if r := w.post("/plans/ui1/nodes/"+n+"/approve", url.Values{"note": {"reviewed in the UI"}}); r.Code != 303 {
			t.Fatalf("approve node %s: %d %s", n, r.Code, r.Body)
		}
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	st, err := h.c.Wait(wctx, "ui1")
	if err != nil || st.State != controller.PlanSucceeded {
		t.Fatalf("plan: %+v %v", st, err)
	}
	if got := h2.read(t, "etc/motd"); got != "managed from the UI\n" {
		t.Errorf("motd: %q", got)
	}
	live := w.do("GET", "/plans/ui1/nodes", nil).Body.String()
	if !strings.Contains(live, "succeeded") || !strings.Contains(live, "verified") || strings.Contains(live, "hx-get") ||
		!strings.Contains(live, "approved by admin") {
		t.Errorf("live node table:\n%s", live)
	}
	// The approval record the agent verified names the UI operator.
	if s := h.firstStep("ui1", "pw", "apply"); s == nil || s.Approval == nil || s.Approval.By != "admin" {
		t.Errorf("signed step approval: %+v", s)
	}
	_ = h1

	// Audit: who did what, in the store.
	rows, err := h.c.Store().Audit(ctx, 500)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, r := range rows {
		if r.Actor == "admin" {
			seen[r.Action] += r.Detail + ";"
		}
	}
	for action, detail := range map[string]string{"plan_create": "ui1", "plan_dryrun": "ui1", "plan_approve": "ui1", "plan_apply": "ui1", "plan_approve_node": "ui1/pw"} {
		if !strings.Contains(seen[action], detail) {
			t.Errorf("audit %s %q missing (have %q)", action, detail, seen[action])
		}
	}
	if !strings.Contains(seen["plan_approve_node"], "ui1/go") {
		t.Errorf("gate approval not audited: %q", seen["plan_approve_node"])
	}
}

// Safe mode is a signed control delivered through the controller, behind a
// confirmation.
func TestUISafeModeSignedControl(t *testing.T) {
	h := newHarness(t)
	h.addHost("h1")
	w := newWebClient(t, h, "")
	if r := w.do("GET", "/agents/h1/safemode", nil); r.Code != 200 || !strings.Contains(r.Body.String(), "Type the host name") {
		t.Fatalf("confirmation page: %d", r.Code)
	}
	nctl := func() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.ctls) }
	before := nctl()
	if r := w.do("POST", "/agents/h1/safemode", url.Values{"on": {"1"}, "confirm": {"h1"}}); r.Code != 403 || nctl() != before {
		t.Fatalf("no csrf: %d", r.Code)
	}
	if r := w.post("/agents/h1/safemode", url.Values{"on": {"1"}, "confirm": {"h2"}}); r.Code != 400 || nctl() != before {
		t.Fatalf("wrong confirmation: %d", r.Code)
	}
	if r := w.post("/agents/ghost/safemode", url.Values{"on": {"1"}, "confirm": {"ghost"}}); r.Code != 404 {
		t.Fatalf("unknown host: %d", r.Code)
	}
	if r := w.post("/agents/h1/safemode", url.Values{"on": {"1"}, "confirm": {"h1"}}); r.Code != 303 {
		t.Fatalf("enable: %d %s", r.Code, r.Body)
	}
	h.mu.Lock()
	var ctl *link.Control
	for _, c := range h.ctls[before:] {
		if c.Kind == plan.ControlSafeMode {
			ctl = c
		}
	}
	h.mu.Unlock()
	if ctl == nil || !ctl.On || len(ctl.Sig) == 0 || ctl.Host != "h1" {
		t.Fatalf("control sent: %+v", ctl)
	}
	eventually(t, "agent to report safe mode", 5*time.Second, func() bool {
		st, _ := h.c.AgentStatus("h1")
		return st.SafeMode
	})
	if p := w.do("GET", "/agents/h1", nil).Body.String(); !strings.Contains(p, "<strong>ON</strong>") {
		t.Errorf("agent page does not show safe mode: %s", p)
	}
	if d := w.do("GET", "/", nil).Body.String(); !strings.Contains(d, "1 in safe mode") {
		t.Errorf("dashboard does not show safe mode: %s", d)
	}
	if r := w.post("/agents/h1/safemode", url.Values{"on": {"0"}, "confirm": {"h1"}}); r.Code != 303 {
		t.Fatalf("disable: %d", r.Code)
	}
	eventually(t, "safe mode off", 5*time.Second, func() bool {
		st, _ := h.c.AgentStatus("h1")
		return !st.SafeMode
	})
	rows, _ := h.c.Store().Audit(context.Background(), 100)
	n := 0
	for _, r := range rows {
		if r.Action == "safe_mode" && strings.HasPrefix(r.Detail, "h1 ") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("safe_mode audit entries: %d", n)
	}
}

const rbTemplate = `id: ui-rb
name: waits at a gate
on_failure: rollback_plan
nodes:
  - id: motd
    action: file.write
    target: h2
    risk: service
    params: {path: /etc/motd, content: "half applied\n"}
  - id: hold
    gate: true
    needs: [motd]
`

// A plan paused at an approval gate can be rolled back from the UI: the
// applied node is undone by a signed rollback step.
func TestUIRollbackRunningPlan(t *testing.T) {
	h := newHarness(t)
	h.addHost("h1")
	h2 := h.addHost("h2")
	plans := t.TempDir()
	if err := os.WriteFile(filepath.Join(plans, "ui-rb.yml"), []byte(rbTemplate), 0o600); err != nil {
		t.Fatal(err)
	}
	w := newWebClient(t, h, plans)
	if h2.exists("etc/motd") {
		t.Fatal("fixture has a motd")
	}
	for _, p := range []string{"/plans", "/plans/ui-rb-x/dryrun", "/plans/ui-rb-x/approve", "/plans/ui-rb-x/apply"} {
		form := url.Values{"template": {"ui-rb"}, "plan_id": {"ui-rb-x"}}
		if r := w.post(p, form); r.Code != 303 {
			t.Fatalf("POST %s: %d %s", p, r.Code, r.Body)
		}
	}
	eventually(t, "node applied and gate waiting", 10*time.Second, func() bool {
		return h2.exists("etc/motd") &&
			strings.Contains(w.do("GET", "/plans/ui-rb-x/nodes", nil).Body.String(), "verified")
	})
	if !strings.Contains(w.do("GET", "/plans/ui-rb-x", nil).Body.String(), "Roll back") {
		t.Fatal("no roll back button on a running plan")
	}
	if r := w.do("POST", "/plans/ui-rb-x/rollback", url.Values{}); r.Code != 403 {
		t.Fatalf("rollback without csrf: %d", r.Code)
	}
	if r := w.post("/plans/ui-rb-x/rollback", nil); r.Code != 303 {
		t.Fatalf("rollback: %d %s", r.Code, r.Body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := h.c.Wait(ctx, "ui-rb-x")
	if err != nil || st.State != controller.PlanRolledBack {
		t.Fatalf("plan: %+v %v", st, err)
	}
	if h2.exists("etc/motd") {
		t.Errorf("motd not removed by the rollback: %q", h2.read(t, "etc/motd"))
	}
	if r := w.post("/plans/ui-rb-x/rollback", nil); r.Code != 409 {
		t.Errorf("second rollback: %d", r.Code)
	}
}
