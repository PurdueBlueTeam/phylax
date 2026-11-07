package ui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var fastArgon = Argon2Params{Time: 1, Memory: 8, Threads: 1}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeAgents struct{ list []AgentInfo }

func (f fakeAgents) ListAgents(context.Context) ([]AgentInfo, error) { return f.list, nil }

type memAudit struct {
	mu sync.Mutex
	e  []AuditEntry
	// fail makes Record error.
	fail bool
}

func (a *memAudit) Record(_ context.Context, e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("audit down")
	}
	a.e = append(a.e, e)
	return nil
}
func (a *memAudit) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var s []string
	for _, e := range a.e {
		s = append(s, e.Action)
	}
	return s
}

type env struct {
	t     *testing.T
	s     *Server
	clock *fakeClock
	audit *memAudit
	pw    string
}

func newEnv(t *testing.T, mod func(*Config)) *env {
	t.Helper()
	clk := &fakeClock{t: time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)}
	au := &memAudit{}
	cfg := Config{
		Audit: au, Now: clk.Now, Argon2: fastArgon,
		Agents: fakeAgents{[]AgentInfo{{Name: "<script>alert(1)</script>", OS: "linux", LinkState: "up"}}},
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pw, created, err := s.EnsureAdmin(context.Background())
	if err != nil || !created {
		t.Fatalf("EnsureAdmin: %v %v", created, err)
	}
	return &env{t: t, s: s, clock: clk, audit: au, pw: pw}
}

// client is a minimal cookie-carrying client against the handler.
type client struct {
	e      *env
	cookie *http.Cookie
}

func (c *client) do(method, path string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, path, body)
	r.Host = "127.0.0.1:8443"
	r.RemoteAddr = "127.0.0.1:5555"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	w := httptest.NewRecorder()
	c.e.s.Handler().ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if strings.HasSuffix(ck.Name, cookieBase) {
			if ck.MaxAge < 0 {
				c.cookie = nil
			} else {
				c.cookie = ck
			}
		}
	}
	return w
}

var tokRe = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func tokenFrom(t *testing.T, body string) string {
	m := tokRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf token in body:\n%s", body)
	}
	return m[1]
}

func (c *client) login(user, pw string) *httptest.ResponseRecorder {
	g := c.do("GET", "/login", nil, nil)
	tok := tokenFrom(c.e.t, g.Body.String())
	return c.do("POST", "/login", url.Values{"username": {user}, "password": {pw}, "csrf_token": {tok}}, nil)
}

func (e *env) loggedIn() (*client, string) {
	c := &client{e: e}
	w := c.login("admin", e.pw)
	if w.Code != http.StatusSeeOther {
		e.t.Fatalf("login status %d: %s", w.Code, w.Body)
	}
	d := c.do("GET", "/", nil, nil)
	if d.Code != 200 {
		e.t.Fatalf("dashboard %d", d.Code)
	}
	return c, tokenFrom(e.t, d.Body.String())
}

func TestUnauthenticatedRoutesRejected(t *testing.T) {
	e := newEnv(t, nil)
	c := &client{e: e}
	cases := []struct{ m, p string }{
		{"GET", "/"}, {"GET", "/agents"}, {"GET", "/agents/table"}, {"GET", "/account"},
		{"POST", "/account/password"}, {"POST", "/logout"}, {"GET", "/nonexistent"},
		{"POST", "/"}, {"DELETE", "/agents"}, {"GET", "/static"}, {"GET", "/static/"},
	}
	for _, tc := range cases {
		w := c.do(tc.m, tc.p, nil, nil)
		if w.Code != 401 && w.Code != 303 && w.Code != 404 && w.Code != 405 {
			t.Errorf("%s %s: %d", tc.m, tc.p, w.Code)
		}
		if tc.p == "/static" || tc.p == "/static/" {
			continue
		}
		if w.Code == 303 && w.Header().Get("Location") != "/login" {
			t.Errorf("%s %s redirect to %q", tc.m, tc.p, w.Header().Get("Location"))
		}
		if w.Code == 404 || w.Code == 405 {
			t.Errorf("%s %s leaked routing info: %d", tc.m, tc.p, w.Code)
		}
	}
	// htmx requests get 401 rather than a redirect.
	if w := c.do("GET", "/agents/table", nil, map[string]string{"HX-Request": "true"}); w.Code != 401 {
		t.Errorf("htmx unauth: %d", w.Code)
	}
}

func TestStaticAndLoginPublic(t *testing.T) {
	e := newEnv(t, nil)
	c := &client{e: e}
	for _, p := range []string{"/static/htmx.min.js", "/static/app.css", "/static/htmx.LICENSE", "/login"} {
		if w := c.do("GET", p, nil, nil); w.Code != 200 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if w := c.do("GET", "/static/", nil, nil); w.Code == 200 {
		t.Error("static directory listing served")
	}
}

func TestLoginLogoutFlow(t *testing.T) {
	e := newEnv(t, nil)
	c, _ := e.loggedIn()
	if !c.cookie.HttpOnly || c.cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie flags: %+v", c.cookie)
	}
	ag := c.do("GET", "/agents", nil, nil)
	if ag.Code != 200 || strings.Contains(ag.Body.String(), "<script>alert") || !strings.Contains(ag.Body.String(), "&lt;script&gt;") {
		t.Errorf("agents page not escaped/rendered: %d\n%s", ag.Code, ag.Body)
	}
	old := c.cookie
	_, tok := c, tokenFrom(t, c.do("GET", "/account", nil, nil).Body.String())
	if w := c.do("POST", "/logout", url.Values{"csrf_token": {tok}}, nil); w.Code != 303 {
		t.Fatalf("logout %d", w.Code)
	}
	c.cookie = old
	if w := c.do("GET", "/", nil, nil); w.Code != 303 {
		t.Errorf("session survived logout: %d", w.Code)
	}
	got := strings.Join(e.audit.actions(), ",")
	if !strings.Contains(got, "login") || !strings.Contains(got, "logout") {
		t.Errorf("audit actions %q", got)
	}
}

func TestSessionFixationRotated(t *testing.T) {
	e := newEnv(t, nil)
	c := &client{e: e}
	c.do("GET", "/login", nil, nil)
	pre := c.cookie.Value
	c.login("admin", e.pw)
	if c.cookie.Value == pre {
		t.Error("session id not rotated on login")
	}
}

func TestBadLoginGeneric(t *testing.T) {
	e := newEnv(t, nil)
	c := &client{e: e}
	w1 := c.login("admin", "wrong")
	w2 := (&client{e: e}).login("nobody", "wrong")
	if w1.Code != 401 || w2.Code != 401 {
		t.Fatalf("codes %d %d", w1.Code, w2.Code)
	}
	if !strings.Contains(w1.Body.String(), "Invalid username or password.") || !strings.Contains(w2.Body.String(), "Invalid username or password.") {
		t.Error("error message differs or missing")
	}
	if !strings.Contains(strings.Join(e.audit.actions(), ","), "login_failed") {
		t.Error("failed login not audited")
	}
}

func TestCSRF(t *testing.T) {
	e := newEnv(t, nil)
	c, tok := e.loggedIn()
	// login form CSRF
	anon := &client{e: e}
	anon.do("GET", "/login", nil, nil)
	if w := anon.do("POST", "/login", url.Values{"username": {"admin"}, "password": {e.pw}}, nil); w.Code != 403 {
		t.Errorf("login without token: %d", w.Code)
	}
	if w := anon.do("POST", "/login", url.Values{"username": {"admin"}, "password": {e.pw}, "csrf_token": {"bogus"}}, nil); w.Code != 403 {
		t.Errorf("login bad token: %d", w.Code)
	}
	if w := (&client{e: e}).do("POST", "/login", url.Values{"username": {"admin"}, "password": {e.pw}, "csrf_token": {tok}}, nil); w.Code != 403 {
		t.Errorf("login without session cookie: %d", w.Code)
	}
	for _, p := range []string{"/logout", "/account/password"} {
		if w := c.do("POST", p, url.Values{}, nil); w.Code != 403 {
			t.Errorf("%s missing token: %d", p, w.Code)
		}
		if w := c.do("POST", p, url.Values{"csrf_token": {"bad"}}, nil); w.Code != 403 {
			t.Errorf("%s invalid token: %d", p, w.Code)
		}
		if w := c.do("POST", p, nil, map[string]string{"X-CSRF-Token": "bad"}); w.Code != 403 {
			t.Errorf("%s invalid header token: %d", p, w.Code)
		}
		if w := c.do("POST", p, url.Values{"csrf_token": {tok}}, map[string]string{"Origin": "http://evil.example"}); w.Code != 403 {
			t.Errorf("%s cross-origin: %d", p, w.Code)
		}
	}
	// A valid header token works (htmx path).
	w := c.do("POST", "/account/password", url.Values{"current": {"x"}, "new": {"y"}}, map[string]string{"X-CSRF-Token": tok})
	if w.Code != 401 { // passes CSRF, fails wrong current password
		t.Errorf("header token: %d", w.Code)
	}
}

func TestPasswordChange(t *testing.T) {
	e := newEnv(t, nil)
	c, tok := e.loggedIn()
	other := &client{e: e}
	other.login("admin", e.pw)
	w := c.do("POST", "/account/password", url.Values{"csrf_token": {tok}, "current": {e.pw}, "new": {"a-new-long-password"}}, nil)
	if w.Code != 200 {
		t.Fatalf("change: %d %s", w.Code, w.Body)
	}
	if r := other.do("GET", "/", nil, nil); r.Code != 303 {
		t.Errorf("other session survived: %d", r.Code)
	}
	if r := (&client{e: e}).login("admin", e.pw); r.Code != 401 {
		t.Errorf("old password still works: %d", r.Code)
	}
	if r := (&client{e: e}).login("admin", "a-new-long-password"); r.Code != 303 {
		t.Errorf("new password rejected: %d", r.Code)
	}
}

func TestSessionExpiry(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.IdleTimeout = 10 * time.Minute; c.AbsoluteTimeout = time.Hour })
	c, _ := e.loggedIn()
	e.clock.Add(9 * time.Minute)
	if w := c.do("GET", "/", nil, nil); w.Code != 200 {
		t.Fatalf("within idle: %d", w.Code)
	}
	e.clock.Add(11 * time.Minute)
	if w := c.do("GET", "/", nil, nil); w.Code != 303 {
		t.Errorf("idle timeout not enforced: %d", w.Code)
	}
	// absolute: keep active every 9 minutes
	c, _ = e.loggedIn()
	for i := 0; i < 6; i++ {
		e.clock.Add(9 * time.Minute)
		if w := c.do("GET", "/", nil, nil); w.Code != 200 {
			t.Fatalf("active session dropped early at %d: %d", i, w.Code)
		}
	}
	e.clock.Add(9 * time.Minute) // total 63m > 1h
	if w := c.do("GET", "/", nil, nil); w.Code != 303 {
		t.Errorf("absolute timeout not enforced: %d", w.Code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.LoginMaxFails = 3; c.LoginLockout = time.Minute })
	for i := 0; i < 3; i++ {
		if w := (&client{e: e}).login("admin", "bad"); w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := (&client{e: e}).login("admin", e.pw) // correct password, still locked
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("expected 429 with Retry-After, got %d", w.Code)
	}
	e.clock.Add(2 * time.Minute)
	if w := (&client{e: e}).login("admin", e.pw); w.Code != 303 {
		t.Errorf("lockout did not expire: %d", w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t, nil)
	c, _ := e.loggedIn()
	for _, p := range []string{"/login", "/", "/agents", "/static/app.css", "/missing"} {
		h := c.do("GET", p, nil, nil).Header()
		csp := h.Get("Content-Security-Policy")
		for _, want := range []string{"frame-ancestors 'none'", "script-src 'self'", "default-src 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s CSP missing %q: %s", p, want, csp)
			}
		}
		if strings.Contains(csp, "unsafe") {
			t.Errorf("%s CSP unsafe: %s", p, csp)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "same-origin" || h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s headers: %v", p, h)
		}
	}
	if cc := c.do("GET", "/", nil, nil).Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("dashboard Cache-Control %q", cc)
	}
}

func TestNoInlineScriptInTemplates(t *testing.T) {
	e := newEnv(t, nil)
	c, _ := e.loggedIn()
	for _, p := range []string{"/", "/agents", "/account", "/login"} {
		body := c.do("GET", p, nil, nil).Body.String()
		if p == "/login" {
			body = (&client{e: e}).do("GET", p, nil, nil).Body.String()
		}
		if regexp.MustCompile(`(?i)<script(\s[^>]*)?>\s*[^<\s]|\son[a-z]+=`).MatchString(body) {
			t.Errorf("%s has inline script/handler", p)
		}
	}
}

func TestHostHeaderRejected(t *testing.T) {
	e := newEnv(t, nil)
	r := httptest.NewRequest("GET", "/login", nil)
	r.Host = "evil.example"
	w := httptest.NewRecorder()
	e.s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("rebinding host accepted: %d", w.Code)
	}
}

func TestTemplatesRender(t *testing.T) {
	e := newEnv(t, nil)
	c, _ := e.loggedIn()
	d := c.do("GET", "/", nil, nil).Body.String()
	for _, id := range []string{"pane-overview", "pane-alerts", "pane-plans", "pane-approvals", "pane-roundclock", "pane-health"} {
		if !strings.Contains(d, `id="`+id+`"`) {
			t.Errorf("dashboard missing %s", id)
		}
	}
	tbl := c.do("GET", "/agents/table", nil, map[string]string{"HX-Request": "true"}).Body.String()
	if strings.Contains(tbl, "<html") || !strings.Contains(tbl, "agents-table") {
		t.Errorf("table partial wrong: %s", tbl)
	}
	if !strings.Contains(c.do("GET", "/account", nil, nil).Body.String(), "Change password") {
		t.Error("account page")
	}
}

func TestAuditFailureBlocksMutation(t *testing.T) {
	e := newEnv(t, nil)
	c, tok := e.loggedIn()
	e.audit.fail = true
	if w := c.do("POST", "/logout", url.Values{"csrf_token": {tok}}, nil); w.Code != 500 {
		t.Errorf("mutation allowed without audit: %d", w.Code)
	}
}

func TestHandleExtensionRoute(t *testing.T) {
	e := newEnv(t, nil)
	e.s.Handle("POST /x", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hi " + Principal(r.Context())))
	}))
	if w := (&client{e: e}).do("POST", "/x", nil, nil); w.Code != 401 {
		t.Errorf("unauth extension route: %d", w.Code)
	}
	c, tok := e.loggedIn()
	if w := c.do("POST", "/x", nil, nil); w.Code != 403 {
		t.Errorf("no csrf: %d", w.Code)
	}
	if w := c.do("POST", "/x", nil, map[string]string{"X-CSRF-Token": tok}); w.Code != 200 || w.Body.String() != "hi admin" {
		t.Errorf("ok path: %d %s", w.Code, w.Body)
	}
}

func TestRefuseNonLoopback(t *testing.T) {
	if _, err := New(Config{Addr: "0.0.0.0:8443", Argon2: fastArgon}); err == nil {
		t.Error("non-loopback accepted")
	}
	if _, err := New(Config{Addr: "[::1]:8443", Argon2: fastArgon}); err != nil {
		t.Error(err)
	}
}

func TestEnsureAdminOnce(t *testing.T) {
	e := newEnv(t, nil)
	if _, created, _ := e.s.EnsureAdmin(context.Background()); created {
		t.Error("second EnsureAdmin created account")
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse", fastArgon)
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatal(h, err)
	}
	if !VerifyPassword("correct horse", h) || VerifyPassword("wrong", h) {
		t.Error("verify")
	}
	for _, bad := range []string{"", "garbage", "$argon2id$v=19$m=99999999,t=1,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA"} {
		if VerifyPassword("x", bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}
