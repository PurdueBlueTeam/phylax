package ui

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

const testToken = "SECRETTOKEN-0123456789"

func TestEnrollLineShownOnceAndAudited(t *testing.T) {
	e, f := opsEnv(t)
	c, tok := e.loggedIn()
	w := c.do("POST", "/enroll/h1/line", url.Values{"csrf_token": {tok}, "os": {"linux"}}, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), testToken) {
		t.Fatalf("POST /enroll/h1/line: %d, token missing:\n%s", w.Code, w.Body)
	}
	if got := f.called(); !strings.Contains(got, "line:h1:linux:admin") {
		t.Fatalf("backend calls %q", got)
	}
	e.audit.mu.Lock()
	var action, actor, detail string
	leak := false
	for _, a := range e.audit.e {
		if a.Action == "enroll.line" {
			action, actor, detail = a.Action, a.Actor, a.Detail
		}
		if strings.Contains(a.Detail, testToken) || strings.Contains(a.Action, testToken) {
			leak = true
		}
	}
	e.audit.mu.Unlock()
	if action != "enroll.line" || actor != "admin" || detail != "h1" {
		t.Fatalf("audit row = %q %q %q, want enroll.line admin h1", action, actor, detail)
	}
	if leak {
		t.Fatal("the one-time token is in the audit log")
	}
	// The line is shown once: a later page load has neither it nor the token.
	g := c.do("GET", "/enroll", nil, nil)
	if g.Code != http.StatusOK || strings.Contains(g.Body.String(), testToken) {
		t.Fatalf("GET /enroll: %d, token shown again:\n%s", g.Code, g.Body)
	}
	if !strings.Contains(g.Body.String(), "h1") {
		t.Fatalf("GET /enroll does not list the hosts:\n%s", g.Body)
	}
}

func TestReenrollAllNeedsConfirmation(t *testing.T) {
	e, f := opsEnv(t)
	c, tok := e.loggedIn()
	if w := c.do("POST", "/enroll/reenroll-all", url.Values{"csrf_token": {tok}}, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("without confirmation: %d", w.Code)
	}
	if got := f.called(); got != "" {
		t.Fatalf("re-enroll ran without confirmation: %q", got)
	}
	if w := c.do("POST", "/enroll/reenroll-all", url.Values{"csrf_token": {tok}, "confirm": {"REENROLL"}}, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("with confirmation: %d %s", w.Code, w.Body)
	}
	if got := f.called(); !strings.Contains(got, "reenroll:admin") {
		t.Fatalf("backend calls %q", got)
	}
}

// wildcardRe substitutes route wildcards so a registered pattern can be
// requested as a concrete path.
var wildcardRe = regexp.MustCompile(`\{[^}]*\}`)

// TestEveryUIPostRouteRequiresSession walks every route the server registered
// and fails when one of them answers an anonymous request without the session
// guard. Login and the static files are the only public routes.
func TestEveryUIPostRouteRequiresSession(t *testing.T) {
	e := newEnv(t, nil)
	e.s.routeMu.Lock()
	routes := append([]string(nil), e.s.allRoutes...)
	public := map[string]bool{}
	for p := range e.s.publicRoutes {
		public[p] = true
	}
	e.s.routeMu.Unlock()
	if len(routes) < 20 {
		t.Fatalf("only %d routes recorded", len(routes))
	}
	for _, want := range []string{"GET /login", "POST /login", "GET /static/{file}"} {
		if !public[want] {
			t.Errorf("route %q is not registered as public", want)
		}
	}
	if len(public) != 3 {
		t.Errorf("public routes = %v; a new public route needs a test that says why", public)
	}
	anon := &client{e: e}
	for _, pattern := range routes {
		if public[pattern] {
			continue
		}
		method, path := http.MethodGet, pattern
		if i := strings.IndexByte(pattern, ' '); i >= 0 {
			method, path = pattern[:i], strings.TrimSpace(pattern[i+1:])
		}
		path = wildcardRe.ReplaceAllString(path, "x")
		w := anon.do(method, path, nil, nil)
		if w.Code != http.StatusSeeOther && w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d without a session", method, path, w.Code)
		}
	}
}
