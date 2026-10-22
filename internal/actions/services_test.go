package actions

import (
	"strings"
	"testing"
	"time"
)

func TestServiceOps(t *testing.T) {
	f := newFixture(t)
	fs := f.env.Services.(*fakeServices)
	f.ok(t, "service.start", map[string]any{"unit": "cups"})
	if !fs.units["cups.service"].Active {
		t.Fatal("not started")
	}
	if o := f.ok(t, "service.start", map[string]any{"unit": "cups"}); !o.Plan.Done || o.Changed {
		t.Fatal("start not idempotent")
	}
	f.ok(t, "service.enable", map[string]any{"unit": "cups"})
	f.ok(t, "service.stop", map[string]any{"unit": "cups"})
	f.ok(t, "service.mask", map[string]any{"unit": "cups"})
	if fs.units["cups.service"].Enabled != "masked" {
		t.Fatal("mask")
	}
	f.ok(t, "service.unmask", map[string]any{"unit": "cups"})
	f.ok(t, "service.restart", map[string]any{"unit": "httpd"})
	if got := fs.calls[len(fs.calls)-1]; got != "restart httpd" {
		t.Fatalf("calls %v", fs.calls)
	}
	// restart is never "already done"
	if o := f.ok(t, "service.restart", map[string]any{"unit": "httpd"}); !o.Changed {
		t.Fatal("restart skipped")
	}
	if _, err := f.run(t, "service.start", map[string]any{"unit": "no such;unit"}); err == nil {
		t.Fatal("bad unit name accepted")
	}
	if _, err := f.run(t, "service.start", map[string]any{"unit": "ghost"}); err == nil {
		t.Fatal("missing unit accepted")
	}
	if _, err := f.run(t, "service.state", map[string]any{"unit": "cups"}); err == nil {
		t.Fatal("empty service.state accepted")
	}
}

func TestServiceStateComposite(t *testing.T) {
	f := newFixture(t)
	fs := f.env.Services.(*fakeServices)
	fs.units["cups.service"].Enabled = "masked"
	f.ok(t, "service.state", map[string]any{"unit": "cups", "state": "running", "enable": "enabled"})
	u := fs.units["cups.service"]
	if !u.Active || u.Enabled != "enabled" {
		t.Fatalf("%+v calls=%v", u, fs.calls)
	}
	// unmask came before start
	if len(fs.calls) < 2 || !strings.HasPrefix(fs.calls[0], "unmask") {
		t.Fatalf("order: %v", fs.calls)
	}
	f.ok(t, "service.state", map[string]any{"unit": "cups", "state": "stopped", "enable": "disabled"})
	if u.Active || u.Enabled != "disabled" {
		t.Fatalf("%+v", u)
	}
}

func TestServiceDeadmanRestoresPriorState(t *testing.T) {
	f := newFixture(t)
	fs := f.env.Services.(*fakeServices)
	f.ok(t, "service.state", map[string]any{"unit": "httpd", "state": "stopped", "enable": "masked"}, func(r *Request) { r.Deadman = 120 * time.Millisecond })
	if u := fs.units["httpd.service"]; u.Active || u.Enabled != "masked" {
		t.Fatalf("apply: %+v", u)
	}
	waitFor(t, "service restore", func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		u := fs.units["httpd.service"]
		return u.Active && u.Enabled == "enabled"
	})
}

func TestServiceUnsupportedPlatformBackend(t *testing.T) {
	f := newFixture(t)
	f.env.Services = nil
	if _, err := f.run(t, "service.start", map[string]any{"unit": "x"}); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("%v", err)
	}
}
