package ui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestAuditExemptRouteSurvivesAuditFailure(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.AuditExempt = []string{"POST /agents/{host}/safe-mode"}
	})
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	e.s.Handle("POST /agents/{host}/safe-mode", ok)
	e.s.Handle("POST /other", ok)

	c, tok := e.loggedIn()
	e.audit.mu.Lock()
	e.audit.fail = true
	e.audit.e = nil
	e.audit.mu.Unlock()

	if w := c.do("POST", "/agents/h1/safe-mode", url.Values{"csrf_token": {tok}}, nil); w.Code != http.StatusNoContent {
		t.Fatalf("exempt safe mode route: %d %s", w.Code, w.Body)
	}
	if w := c.do("POST", "/other", url.Values{"csrf_token": {tok}}, nil); w.Code != http.StatusInternalServerError ||
		!strings.Contains(w.Body.String(), "audit unavailable") {
		t.Fatalf("non-exempt route: %d %s", w.Code, w.Body)
	}

	e.audit.mu.Lock()
	e.audit.fail = false
	e.audit.e = nil
	e.audit.mu.Unlock()
	if w := c.do("POST", "/other", url.Values{"csrf_token": {tok}}, nil); w.Code != http.StatusNoContent {
		t.Fatalf("recovered audit route: %d %s", w.Code, w.Body)
	}
	e.audit.mu.Lock()
	defer e.audit.mu.Unlock()
	if len(e.audit.e) != 2 {
		t.Fatalf("audit entries %+v", e.audit.e)
	}
	if !strings.Contains(e.audit.e[0].Detail, "/agents/h1/safe-mode") || !strings.Contains(e.audit.e[1].Detail, "/other") {
		t.Fatalf("queued entry not replayed first: %+v", e.audit.e)
	}
}
