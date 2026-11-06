package controller

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/ui"
)

// switchAudit fails on demand so a test can exercise the audit-write refusal.
type switchAudit struct {
	mu      sync.Mutex
	fail    bool
	entries []ui.AuditEntry
}

func (a *switchAudit) Record(_ context.Context, e ui.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("audit down")
	}
	a.entries = append(a.entries, e)
	return nil
}

// The controller's UI exempts the safe-mode control from the audit-write
// refusal: with the audit log failing the route still runs, while another
// audited POST is refused.
func TestUIAuditExemptControlRoutes(t *testing.T) {
	c := newBareController(t, filepath.Join(t.TempDir(), "data"))
	t.Cleanup(func() { c.Close() })
	au := &switchAudit{}
	srv, _, err := c.NewUI(UIOptions{Addr: "127.0.0.1:8443", Audit: au})
	if err != nil {
		t.Fatal(err)
	}
	// The fleet safe-mode and kill-switch handlers land with their features;
	// register stand-ins so the exemption list is tested end to end.
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	srv.Handle("POST /safe-mode", ok)
	srv.Handle("POST /settings/kill-switch", ok)
	pw, created, err := srv.EnsureAdmin(context.Background())
	if err != nil || !created {
		t.Fatalf("EnsureAdmin: %v %v", created, err)
	}
	u := &uiClient{t: t, h: srv.Handler()}
	tok := u.token(u.do("GET", "/login", nil).Body.String())
	if w := u.do("POST", "/login", url.Values{"username": {"admin"}, "password": {pw}, "csrf_token": {tok}}); w.Code != http.StatusSeeOther {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	dash := u.do("GET", "/", nil)
	if dash.Code != http.StatusOK {
		t.Fatalf("dashboard: %d %s", dash.Code, dash.Body)
	}
	tok = u.token(dash.Body.String())

	// The audit write now fails; every audited mutation is refused unless its
	// route is exempt.
	au.mu.Lock()
	au.fail = true
	au.entries = nil
	au.mu.Unlock()

	w := u.do("POST", "/agents/h1/safemode", url.Values{"csrf_token": {tok}, "on": {"1"}, "confirm": {"h1"}})
	if strings.Contains(w.Body.String(), "audit unavailable") {
		t.Fatalf("safe-mode route refused by the failing audit log: %d %s", w.Code, w.Body)
	}
	if w.Code != http.StatusNotFound { // no such connected agent; the handler ran
		t.Fatalf("safe-mode route: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/safe-mode", "/settings/kill-switch"} {
		if w := u.do("POST", path, url.Values{"csrf_token": {tok}}); w.Code != http.StatusNoContent {
			t.Fatalf("%s refused by the failing audit log: %d %s", path, w.Code, w.Body)
		}
	}

	w = u.do("POST", "/plans", url.Values{"csrf_token": {tok}})
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "audit unavailable") {
		t.Fatalf("non-exempt route: %d %s", w.Code, w.Body)
	}
}
