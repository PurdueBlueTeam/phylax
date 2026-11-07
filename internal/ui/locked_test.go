package ui

import (
	"strings"
	"testing"
	"time"
)

func TestLockedBannerOnEveryPage(t *testing.T) {
	e := newEnv(t, func(cfg *Config) {
		cfg.Ops = &fakeOps{locked: true, lockedSince: time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC),
			stopped: []string{"auto plans", "deadman_confirm"}}
	})
	c, _ := e.loggedIn()
	for _, path := range []string{"/", "/agents"} {
		w := c.do("GET", path, nil, nil)
		if w.Code != 200 {
			t.Fatalf("GET %s: %d", path, w.Code)
		}
		body := w.Body.String()
		for _, want := range []string{"LOCKED", "deadman_confirm", "/unlock"} {
			if !strings.Contains(body, want) {
				t.Fatalf("GET %s: banner does not name %q:\n%s", path, want, body)
			}
		}
	}

	u := newEnv(t, func(cfg *Config) { cfg.Ops = &fakeOps{} })
	uc, _ := u.loggedIn()
	for _, path := range []string{"/", "/agents"} {
		body := uc.do("GET", path, nil, nil).Body.String()
		if strings.Contains(body, "LOCKED") {
			t.Fatalf("GET %s: unlocked controller shows a LOCKED banner", path)
		}
	}
}

func TestLockedStoppedComesFromOverview(t *testing.T) {
	const unique = "only-from-overview"
	e := newEnv(t, func(cfg *Config) {
		cfg.Ops = &fakeOps{locked: true, lockedSince: time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC), stopped: []string{unique}}
	})
	c, _ := e.loggedIn()
	for _, path := range []string{"/", "/agents", "/unlock"} {
		body := c.do("GET", path, nil, nil).Body.String()
		if !strings.Contains(body, unique) {
			t.Fatalf("GET %s does not use the Overview's stopped list:\n%s", path, body)
		}
		if strings.Contains(body, "auto plans") {
			t.Fatalf("GET %s still shows the UI's own stopped list", path)
		}
	}
}
