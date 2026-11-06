package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

type uiClient struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
}

func (u *uiClient) do(method, path string, form url.Values) *httptest.ResponseRecorder {
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Host, r.RemoteAddr = "127.0.0.1:8443", "127.0.0.1:5000"
	if u.cookie != nil {
		r.AddCookie(u.cookie)
	}
	w := httptest.NewRecorder()
	u.h.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.Name == "phylax_session" {
			u.cookie = c
		}
	}
	return w
}

var csrfRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func (u *uiClient) token(body string) string {
	m := csrfRE.FindStringSubmatch(body)
	if m == nil {
		u.t.Fatalf("no csrf token in:\n%s", body)
	}
	return m[1]
}

// newUITest builds a controller with the real UI handler and logs in.
func newUITest(t *testing.T, plansDir string) (*Controller, *WebOps, *uiClient, string) {
	t.Helper()
	c := newBareController(t, filepath.Join(t.TempDir(), "data"))
	t.Cleanup(func() { c.Close() })
	srv, ops, err := c.NewUI(UIOptions{Addr: "127.0.0.1:8443", PlansDir: plansDir})
	if err != nil {
		t.Fatal(err)
	}
	pw, created, err := srv.EnsureAdmin(context.Background())
	if err != nil || !created {
		t.Fatalf("EnsureAdmin: %v %v", created, err)
	}
	u := &uiClient{t: t, h: srv.Handler()}
	tok := u.token(u.do("GET", "/login", nil).Body.String())
	if w := u.do("POST", "/login", url.Values{"username": {"admin"}, "password": {pw}, "csrf_token": {tok}}); w.Code != 303 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	d := u.do("GET", "/", nil)
	if d.Code != 200 {
		t.Fatalf("dashboard: %d %s", d.Code, d.Body)
	}
	return c, ops, u, u.token(d.Body.String())
}

type evFeeder struct {
	t    *testing.T
	c    *Controller
	seq  map[string]uint64
	prev map[string]string
}

func (f *evFeeder) add(agent string, at time.Time, kind string, fields map[string]any) event.Event {
	f.t.Helper()
	ctx := context.Background()
	if _, ok := f.seq[agent]; !ok {
		if err := f.c.Store().EnrollAgent(ctx, agent, []byte("key-"+agent)); err != nil {
			f.t.Fatal(err)
		}
	}
	ev := event.Event{Agent: agent, Time: at, Kind: kind, Priority: event.PriorityHigh, Fields: fields}
	if err := ev.Seal(f.seq[agent], f.prev[agent]); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.c.Store().Ingest(ctx, agent, []event.Event{ev}); err != nil {
		f.t.Fatal(err)
	}
	f.seq[agent], f.prev[agent] = ev.Seq, ev.Hash
	return ev
}

// An alert in the queue shows its evidence, traces back to a chain whose
// timeline renders, and the dashboard summarises all of it; the scorer feed is
// shown when present. Everything is backed by the real store.
func TestUIAlertTraceAndDashboard(t *testing.T) {
	c, ops, u, tok := newUITest(t, "")
	ctx := context.Background()
	f := &evFeeder{t: t, c: c, seq: map[string]uint64{}, prev: map[string]string{}}
	t0 := time.Date(2027, 3, 6, 15, 0, 0, 0, time.UTC)
	f.add("ecom", t0, "net.connection_opened", map[string]any{"dir": "inbound", "proto": "tcp", "laddr": "10.0.1.10", "lport": 80,
		"raddr": "198.51.100.7", "rport": 51000, "service": "http", "community_id": "1:abc", "pid": 800, "pid_start": 5000, "comm": "apache2", "exe": "/usr/sbin/apache2"})
	f.add("ecom", t0.Add(200*time.Millisecond), "process_start", map[string]any{"pid": 901, "ppid": 800, "exe": "/bin/sh",
		"cmdline": "sh -c echo pwn > uploads/x.php", "start_ticks": 5100, "parent": map[string]any{"pid": 800, "exe": "/usr/sbin/apache2"}, "pexe": "/usr/sbin/apache2"})
	ev := f.add("ecom", t0.Add(400*time.Millisecond), "file_change", map[string]any{"op": "create", "path": "/var/www/html/uploads/x.php",
		"pid": 901, "exe": "/bin/sh", "writer_start_ticks": 5100, "source": "audit"})

	// No scorer, no chains yet.
	d := u.do("GET", "/", nil).Body.String()
	for _, want := range []string{"no scorer data", "No chains yet", "Nothing waiting", "No agents enrolled"} {
		if !strings.Contains(d, want) {
			t.Errorf("empty dashboard lacks %q", want)
		}
	}

	id, err := c.RecordAlert(ctx, detect.Alert{RuleID: "W1.webshell", Title: "Web shell <written>", Severity: "high", Agent: "ecom",
		Time: ev.Time, Message: "uploads/x.php created by sh", Entities: map[string]string{"path": "/var/www/html/uploads/x.php"}, Evidence: []event.Event{ev}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.RecordAlert(ctx, detect.Alert{RuleID: "L2.noise", Title: "low", Severity: "low", Agent: "ecom", Time: ev.Time}); err != nil {
		t.Fatal(err)
	}
	list := u.do("GET", "/alerts", nil).Body.String()
	if !strings.Contains(list, "Web shell &lt;written&gt;") || strings.Contains(list, "<written>") {
		t.Errorf("alert list: %s", list)
	}
	page := u.do("GET", "/alerts/"+itoa(id), nil)
	body := page.Body.String()
	if page.Code != 200 || !strings.Contains(body, "file_change") || !strings.Contains(body, "x.php") || !strings.Contains(body, "Trace back") {
		t.Fatalf("alert page: %d\n%s", page.Code, body)
	}
	d = u.do("GET", "/", nil).Body.String()
	if !strings.Contains(d, "Open alerts (2)") || !strings.Contains(d, "high: 1") || !strings.Contains(d, "low: 1") {
		t.Errorf("dashboard alerts: %s", d)
	}

	// Trace needs CSRF.
	if w := u.do("POST", "/alerts/"+itoa(id)+"/trace", url.Values{}); w.Code != 403 {
		t.Fatalf("trace without csrf: %d", w.Code)
	}
	w := u.do("POST", "/alerts/"+itoa(id)+"/trace", url.Values{"csrf_token": {tok}})
	if w.Code != 303 || w.Header().Get("Location") != "/chains/1" {
		t.Fatalf("trace: %d %q %s", w.Code, w.Header().Get("Location"), w.Body)
	}
	ch := u.do("GET", "/chains/1", nil)
	if ch.Code != 200 || !strings.Contains(ch.Body.String(), "198.51.100.7") || !strings.Contains(ch.Body.String(), "x.php") ||
		!strings.Contains(ch.Body.String(), "<th>#</th>") {
		t.Fatalf("chain page: %d\n%s", ch.Code, ch.Body)
	}
	if !strings.Contains(u.do("GET", "/alerts/"+itoa(id), nil).Body.String(), "Chain timeline for this alert") {
		t.Error("alert does not link to its chain")
	}
	if again := u.do("POST", "/alerts/"+itoa(id)+"/trace", url.Values{"csrf_token": {tok}}); again.Header().Get("Location") != "/chains/1" {
		t.Errorf("second trace made a new chain: %q", again.Header().Get("Location"))
	}
	if cl := u.do("GET", "/chains", nil).Body.String(); !strings.Contains(cl, "/chains/1") {
		t.Errorf("chains page: %s", cl)
	}
	d = u.do("GET", "/", nil).Body.String()
	if !strings.Contains(d, "Chain 1") || !strings.Contains(d, "Campaign") {
		t.Errorf("dashboard chains: %s", d)
	}

	// Closing an alert takes it out of the open count.
	if w := u.do("POST", "/alerts/"+itoa(id)+"/state", url.Values{"csrf_token": {tok}, "state": {"closed"}}); w.Code != 303 {
		t.Fatalf("close: %d", w.Code)
	}
	if d = u.do("GET", "/", nil).Body.String(); !strings.Contains(d, "Open alerts (1)") {
		t.Errorf("closed alert still open: %s", d)
	}
	if w := u.do("POST", "/alerts/"+itoa(id)+"/state", url.Values{"csrf_token": {tok}, "state": {"bogus"}}); w.Code != 400 {
		t.Errorf("bogus state: %d", w.Code)
	}

	// Scorer feed.
	est := scorer.NewEstimator(scorer.ClockConfig{})
	now := time.Now()
	for i := 5; i >= 1; i-- {
		est.ObserveBurst(now.Add(-time.Duration(i)*time.Minute), now.Add(-time.Duration(i)*time.Minute+500*time.Millisecond), 40)
	}
	sla := scorer.NewSLATracker(scorer.SLAConfig{Threshold: 5})
	for r := 1; r <= 4; r++ {
		sla.ObserveRound(r, map[string]scorer.Outcome{"web": scorer.OutcomeFail, "dns": scorer.OutcomePass})
	}
	ops.SetScorer(est, sla, func() []string { return []string{"web", "dns"} })
	d = u.do("GET", "/", nil).Body.String()
	if strings.Contains(d, "no scorer data") || !strings.Contains(d, "sla-critical") || !strings.Contains(d, ">web<") {
		t.Errorf("scorer pane: %s", d)
	}

	// Audit trail in the store, attributed to the operator.
	rows, err := c.Store().Audit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, r := range rows {
		if r.Actor == "admin" {
			have[r.Action] = true
		}
	}
	for _, a := range []string{"login", "alert_trace", "alert_state", "request"} {
		if !have[a] {
			t.Errorf("audit action %q missing: %+v", a, rows)
		}
	}
}

func TestUIAccountsPersistInStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	c := newBareController(t, dir)
	srv, _, err := c.NewUI(UIOptions{Addr: "127.0.0.1:8443"})
	if err != nil {
		t.Fatal(err)
	}
	pw, created, err := srv.EnsureAdmin(context.Background())
	if err != nil || !created || pw == "" {
		t.Fatal(err, created)
	}
	c.Close()
	c2 := newBareController(t, dir)
	defer c2.Close()
	srv2, _, _ := c2.NewUI(UIOptions{Addr: "127.0.0.1:8443"})
	if _, created, _ := srv2.EnsureAdmin(context.Background()); created {
		t.Fatal("a second admin was created on restart")
	}
	acct, err := storeAccounts{c2.Store()}.Get(context.Background(), "admin")
	if err != nil || !strings.HasPrefix(acct.Hash, "$argon2id$") || strings.Contains(acct.Hash, pw) {
		t.Fatalf("stored account: %+v %v", acct, err)
	}
}

func TestUIRefusesNonLoopback(t *testing.T) {
	c := newBareController(t, filepath.Join(t.TempDir(), "data"))
	defer c.Close()
	if _, _, err := c.NewUI(UIOptions{Addr: "0.0.0.0:8443"}); err == nil {
		t.Fatal("UI accepted a non-loopback address")
	}
}

func TestPlanTemplates(t *testing.T) {
	dir := t.TempDir()
	good := "id: harden\nname: Harden\nnodes:\n  - id: a\n    action: file.write\n    target: h1\n    risk: service\n    params: {path: /etc/x, content: hi}\n  - id: g\n    gate: true\n    needs: [a]\n"
	for name, body := range map[string]string{"harden.yml": good, "broken.yml": "id: x\nnodes: [\n", "extra.yaml": "id: x\nbogus: 1\nnodes: []\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ts, err := ListTemplates(dir)
	if err != nil || len(ts) != 3 {
		t.Fatalf("%v %+v", err, ts)
	}
	byName := map[string]TemplateInfo{}
	for _, x := range ts {
		byName[x.Name] = x
	}
	if byName["harden"].Nodes != 2 || !strings.HasPrefix(byName["broken"].Title, "invalid") || !strings.HasPrefix(byName["extra"].Title, "invalid") {
		t.Fatalf("%+v", byName)
	}
	for _, bad := range []string{"../harden", "a/b", "", ".hidden", "harden.yml"} {
		if _, err := LoadTemplate(dir, bad); err == nil {
			t.Errorf("template name %q accepted", bad)
		}
	}
	p, err := LoadTemplate(dir, "harden")
	if err != nil || p.Nodes[0].Params["path"] != "/etc/x" || !p.Nodes[1].Gate {
		t.Fatalf("%+v %v", p, err)
	}
	if id := PlanIDFor(p, "harden", "", time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)); id != "harden-20270102-030405" {
		t.Errorf("plan id %q", id)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// A detect.alert event stored from an agent lands in the operator queue with
// its matched events resolved to stored evidence, so it can be traced.
func TestUIAgentDetectAlertQueued(t *testing.T) {
	c, _, u, tok := newUITest(t, "")
	f := &evFeeder{t: t, c: c, seq: map[string]uint64{}, prev: map[string]string{}}
	t0 := time.Date(2027, 3, 6, 15, 0, 0, 0, time.UTC)
	f.add("ecom", t0, "net.connection_opened", map[string]any{"dir": "inbound", "proto": "tcp", "laddr": "10.0.1.10", "lport": 80,
		"raddr": "198.51.100.7", "rport": 51000, "service": "http", "community_id": "1:abc", "pid": 800, "pid_start": 5000, "comm": "apache2", "exe": "/usr/sbin/apache2"})
	mt := t0.Add(300 * time.Millisecond)
	f.add("ecom", mt, "file_change", map[string]any{"op": "create", "path": "/var/www/html/uploads/y.php", "pid": 800, "exe": "/usr/sbin/apache2",
		"writer_start_ticks": 5000, "source": "audit"})
	al := f.add("ecom", mt.Add(time.Second), "detect.alert", map[string]any{"rule": "W1.webshell", "title": "Web shell", "severity": "critical", "tier": 1,
		"message": "php written under uploads", "attack": []any{"T1505.003"}, "entities": map[string]any{"path": "/var/www/html/uploads/y.php"},
		"evidence": []any{map[string]any{"kind": "file_change", "time": mt.UTC().Format(time.RFC3339Nano), "fields": map[string]any{}}}})
	c.recordAgentAlerts(context.Background(), []event.Event{al}, al.Seq)
	c.recordAgentAlerts(context.Background(), []event.Event{al}, al.Seq-1) // not stored yet: ignored
	rows, err := c.Store().Alerts(context.Background(), "open", 10)
	if err != nil || len(rows) != 1 || rows[0].Severity != 4 {
		t.Fatalf("%+v %v", rows, err)
	}
	page := u.do("GET", "/alerts/1", nil).Body.String()
	for _, want := range []string{"Web shell", "critical", "file_change", "y.php", "php written under uploads", "ecom#"} {
		if !strings.Contains(page, want) {
			t.Errorf("alert page lacks %q:\n%s", want, page)
		}
	}
	w := u.do("POST", "/alerts/1/trace", url.Values{"csrf_token": {tok}})
	if w.Code != 303 {
		t.Fatalf("trace: %d %s", w.Code, w.Body)
	}
	if ch := u.do("GET", w.Header().Get("Location"), nil); ch.Code != 200 || !strings.Contains(ch.Body.String(), "y.php") {
		t.Fatalf("chain: %d %s", ch.Code, ch.Body)
	}
}

// The operator reset route clears the attempt ledger's breaker for one key and
// records who did it.
func TestUIReenableAutoRoute(t *testing.T) {
	c, _, u, tok := newUITest(t, "")
	now := time.Now()
	for i := 0; i < 2; i++ {
		if _, _, err := c.noteAutoAttempt(ctx, "h1", "/etc/hosts", "t1", now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if open, err := ledgerOpen(c, "h1", "/etc/hosts", "t1"); err != nil || !open {
		t.Fatalf("ledger open=%v, %v; want true", open, err)
	}
	if w := u.do("POST", "/auto/reenable", url.Values{"csrf_token": {tok}}); w.Code != http.StatusBadRequest {
		t.Fatalf("missing key: %d %s", w.Code, w.Body)
	}
	if open, err := ledgerOpen(c, "h1", "/etc/hosts", "t1"); err != nil || !open {
		t.Fatalf("a refused reset changed the ledger: open=%v, %v", open, err)
	}
	w := u.do("POST", "/auto/reenable", url.Values{"csrf_token": {tok},
		"host": {"h1"}, "object": {"/etc/hosts"}, "kind": {"t1"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/plans" {
		t.Fatalf("reenable: %d %q %s", w.Code, w.Header().Get("Location"), w.Body)
	}
	if open, err := ledgerOpen(c, "h1", "/etc/hosts", "t1"); err != nil || open {
		t.Fatalf("after reset open=%v, %v; want false", open, err)
	}
	rows, err := c.st.Audit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Action == "auto_reenable" && r.Actor == "admin" && strings.Contains(r.Detail, "t1 on h1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no auto_reenable audit row: %+v", rows)
	}
}
