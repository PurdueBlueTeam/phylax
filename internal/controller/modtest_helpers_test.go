package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
)

var ctx = context.Background()

type ctlMod struct{ m module.Manifest }

func (c ctlMod) Manifest() module.Manifest                    { return c.m }
func (ctlMod) Start(ctx context.Context, _ module.Host) error { <-ctx.Done(); return nil }
func (ctlMod) Health() module.Health                          { return module.Health{State: module.StateOK} }

func testMod() ctlMod {
	return ctlMod{module.Manifest{Name: "ctltest", Sides: []module.Side{module.SideController}, Privilege: "none",
		Emits: []event.Type{{Kind: "ctltest.found", Schema: 1}}, Consumes: []string{"agent.resumed"}}}
}

func mustNew(t *testing.T, kind string, v any) event.Event {
	t.Helper()
	e, err := event.New(kind, v)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func newTestControllerAt(t *testing.T, dir string) *Controller {
	t.Helper()
	return newBareController(t, dir)
}

func newTestController(t *testing.T) *Controller {
	t.Helper()
	return newTestControllerAt(t, t.TempDir())
}

func writeManifest(t *testing.T, files map[string]string) string {
	t.Helper()
	if files == nil {
		files = map[string]string{}
	}
	dir := t.TempDir()
	base := map[string]string{
		"topology.yml": `team: 3
controller: { host: ctl, agent_port: 7443, ui: "127.0.0.1:8443" }
segments:
  lan: { cidr: 10.0.0.0/24, nat: { public_pool: "172.25.23.0/24", mode: static_1to1_same_octet } }
`,
		"hosts.yml": `hosts:
  ctl: { segment: lan, ip: 10.0.0.2, public: "172.25.23.2", os: { family: debian, version: "12" }, roles: [controller] }
  h1: { segment: lan, ip: 10.0.0.10, public: "172.25.23.10", os: { family: debian, version: "12" }, labels: [linux, server] }
  db1: { segment: lan, ip: 10.0.0.11, public: "172.25.23.11", os: { family: debian, version: "12" }, labels: [linux, server] }
`,
		"services.yml": `services:
  web: { host: h1, kind: http, scored: true, listen: [{ proto: tcp, port: 80 }] }
`,
	}
	for name, body := range base {
		files[name] = body
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func newTestControllerWithManifest(t *testing.T, files map[string]string) *Controller {
	t.Helper()
	dir := writeManifest(t, files)
	return newBareController(t, filepath.Join(t.TempDir(), "data")).
		withManifest(t, dir)
}

func newTestControllerWithPlans(t *testing.T, plans map[string]string) *Controller {
	t.Helper()
	dir := t.TempDir()
	for name, body := range plans {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c := newTestControllerWithManifest(t, nil)
	c.cfg.PlansPath = dir
	return c
}

func newTestControllerWithRegistry(t *testing.T, reg *actions.Registry, probe func(context.Context, string) error) *Controller {
	t.Helper()
	c := newTestControllerWithManifest(t, nil)
	c.reg = reg
	c.opt.Registry = reg
	c.opt.Probe = probe
	return c
}

func newStandingController(t *testing.T) *Controller {
	t.Helper()
	return newTestControllerWithPlans(t, map[string]string{
		"ctltest/dump.yml": "id: dump\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: a, action: file.hash, target: '${host}', params: {path: /etc/hosts}}\n",
	})
}

func newAutoController(t *testing.T, block string, extra ...map[string]string) *Controller {
	t.Helper()
	files := map[string]string{"modules/ctltest.yml": block}
	for _, m := range extra {
		for k, v := range m {
			files[k] = v
		}
	}
	c := newTestControllerWithManifest(t, files)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"ctltest/t1.yml":  "id: t1\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: a, action: file.hash, target: '${host}', params: {path: /etc/hosts}}\n",
		"ctltest/t2.yml":  "id: t2\nmodule: ctltest\nnodes:\n  - {id: a, action: file.write, target: '${host}', risk: service, params: {path: /tmp/phylax-t2, content: x}}\n",
		"ctltest/bad.yml": "id: bad\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: a, action: host.exec, target: '${host}', params: {argv: [/bin/true]}}\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c.cfg.PlansPath = dir
	return c
}

func setHeartbeat(c *Controller, host string, safeMode bool, at time.Time) {
	s := c.state(host)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastSeen = at
	s.hb.SafeMode = safeMode
	s.hb.Host = host
}

// withManifest points the controller's config at a manifest directory.
func (c *Controller) withManifest(t *testing.T, dir string) *Controller {
	t.Helper()
	c.cfg.ManifestPath = dir
	return c
}
