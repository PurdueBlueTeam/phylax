package controller

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/module/conformance"
)

const labelsHostsYAML = `hosts:
  ctl: { segment: lan, ip: 10.0.0.2, public: "172.25.23.2", os: { family: debian, version: "12" }, roles: [controller] }
  h1: { segment: lan, ip: 10.0.0.10, public: "172.25.23.10", os: { family: debian, version: "12" }, labels: [linux, server] }
  db1: { segment: lan, ip: 10.0.0.11, public: "172.25.23.11", os: { family: debian, version: "12" }, labels: [linux] }
`

// labelsController is the test controller with h1 (labels linux, server) and
// db1 (linux only): the helper's base hosts would give both `server`.
func labelsController(t *testing.T) *Controller {
	t.Helper()
	c := newTestControllerWithManifest(t, nil)
	if err := os.WriteFile(filepath.Join(c.cfg.ManifestPath, "hosts.yml"), []byte(labelsHostsYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	return c
}

func writePlanFile(t *testing.T, root, mod, name, body string) {
	t.Helper()
	dir := filepath.Join(root, mod)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadModuleTemplateForResolvesLabels(t *testing.T) {
	c := labelsController(t)
	root := t.TempDir()
	writePlanFile(t, root, "demo", "pack", `id: pack
module: demo
vars:
  servers: {labels: server}
nodes:
  - {id: a, each: servers, action: file.hash, target: '${host}', params: {path: /etc/hosts}}
`)
	p, err := LoadModuleTemplateFor(root, "demo", "pack", c.hostsMatching)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 1 || p.Nodes[0].Target != "h1" || p.Module != "demo" {
		t.Fatalf("%+v", p)
	}
	// Without a resolver a label variable is an error, never "no hosts".
	if _, err := LoadModuleTemplate(root, "demo", "pack"); err == nil {
		t.Fatal("a pack with a label var loaded without a resolver")
	}
	// A pack may not be loaded through another module's directory.
	writePlanFile(t, root, "demo", "foreign", `id: foreign
module: other
vars:
  servers: {labels: server}
nodes:
  - {id: a, each: servers, action: file.hash, target: '${host}', params: {path: /etc/hosts}}
`)
	if _, err := LoadModuleTemplateFor(root, "demo", "foreign", c.hostsMatching); err == nil {
		t.Fatal("foreign module accepted")
	}
}

func TestLoadModuleTemplateForPlainFile(t *testing.T) {
	root := t.TempDir()
	writePlanFile(t, root, "demo", "ok", "id: ok\nmodule: demo\non_failure: stop_dependents\nnodes: []\n")
	p, err := LoadModuleTemplateFor(root, "demo", "ok", nil)
	if err != nil || p.Module != "demo" || p.ID != "ok" || p.Template != "ok" {
		t.Fatalf("%+v %v", p, err)
	}
	c := labelsController(t)
	if _, err := LoadModuleTemplateFor(root, "demo", "ok", c.hostsMatching); err != nil {
		t.Fatalf("a plain file must not need a resolver: %v", err)
	}
}

func TestCoreImportsHasPlans(t *testing.T) {
	found := false
	for _, p := range conformance.CoreImports {
		if p == "github.com/PurdueBlueTeam/phylax/plans" {
			found = true
		}
	}
	if !found {
		t.Fatal("plans package missing from CoreImports")
	}
}
