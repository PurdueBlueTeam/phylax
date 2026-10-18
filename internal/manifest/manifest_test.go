package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTemplateEval(t *testing.T) {
	vars := TeamVars(12)
	cases := []struct {
		in   string
		want string
		err  bool
	}{
		{in: `"172.25.{{ 20 + team }}.144"`, want: `"172.25.32.144"`},
		{in: `seg: {{ 20 + team }}`, want: "seg: 32"},
		{in: `a {{ 2 * (10 + team) }} b`, want: "a 44 b"},
		{in: `x: {{ team }}`, want: "x: 12"},
		{`bad {{ unclosed`, "", true},
		{`unknown var {{ nothere }}`, "", true},
		{`div by zero {{ 1 / 0 }}`, "", true},
	}
	for _, c := range cases {
		got, err := vars.Render(c.in)
		if c.err {
			if err == nil {
				t.Errorf("Render(%q): expected error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Render(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Render(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLoadReferenceManifest(t *testing.T) {
	m, err := LoadReference(refDir)
	if err != nil {
		t.Fatalf("LoadReference: %v", err)
	}
	if m.Hosts.Team != 12 {
		t.Errorf("team = %d, want 12", m.Hosts.Team)
	}
	// Templated NAT addresses must have resolved.
	seg := m.Topology.Segments["windows"]
	if seg.NAT.RelayPublic != "172.25.32.144" || seg.NAT.ControllerPublic != "172.25.32.200" {
		t.Errorf("NAT not templated: %+v", seg.NAT)
	}
	// Agent destinations: controller segment dials controller, windows dials relay.
	if got, err := m.AgentDestination("ubuntu-ecom"); err != nil || got != "172.20.242.10:7443" {
		t.Errorf("AgentDestination(ubuntu-ecom) = %q, %v; want 172.20.242.10:7443", got, err)
	}
	if got, err := m.AgentDestination("server-ad-dns"); err != nil || got != "172.20.240.100:7444" {
		t.Errorf("AgentDestination(server-ad-dns) = %q, %v; want 172.20.240.100:7444", got, err)
	}
}

func TestLintCatchesBadManifests(t *testing.T) {
	// Dependency cycle.
	dir := copyRef(t)
	if err := rewriteFile(t, dir, "services.yml", func(s string) string {
		return "services:\n  a:\n    host: ubuntu-ecom\n    kind: other\n    depends_on: [{service: b}]\n  b:\n    host: ubuntu-ecom\n    kind: other\n    depends_on: [{service: a}]\n"
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, TeamVars(12)); err == nil {
		t.Error("expected cycle error")
	}

	// Decoy on a scored service port.
	dir = copyRef(t)
	if err := rewriteFile(t, dir, "decoys.yml", func(s string) string {
		return "decoys:\n  ubuntu-ecom:\n    listeners:\n      - { kind: telnet, port: 80, exposure: inside }\n"
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, TeamVars(12)); err == nil {
		t.Error("expected decoy/port collision error")
	}

	// Scored service declared disabled.
	dir = copyRef(t)
	if err := rewriteFile(t, dir, "services.yml", func(s string) string {
		return "services:\n  ecom-http:\n    host: ubuntu-ecom\n    kind: http\n    scored: true\n    state: disabled\n    listen: [{proto: tcp, port: 80}]\n"
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, TeamVars(12)); err == nil {
		t.Error("expected disabled-scored error")
	}

	// Non-controller segment without relay.
	dir = copyRef(t)
	if err := rewriteFile(t, dir, "topology.yml", func(s string) string {
		return "controller:\n  host: ubuntu-wkst\n  agent_port: 7443\n  ui: 127.0.0.1:8443\nsegments:\n  linux:\n    cidr: 172.20.242.0/24\n    firewall: palo1\n  windows:\n    cidr: 172.20.240.0/24\n    firewall: palo2\n"
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, TeamVars(12)); err == nil {
		t.Error("expected missing-relay error")
	}

	// Controller UI not on loopback.
	dir = copyRef(t)
	if err := rewriteFile(t, dir, "topology.yml", func(s string) string {
		return "controller:\n  host: ubuntu-wkst\n  agent_port: 7443\n  ui: 0.0.0.0:8443\nsegments:\n  linux:\n    cidr: 172.20.242.0/24\n    firewall: palo1\n  windows:\n    cidr: 172.20.240.0/24\n    firewall: palo2\n    relay: { host: win11-wkst, port: 7444 }\n"
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, TeamVars(12)); err == nil {
		t.Error("expected ui-binding error")
	}

	// Schema violation: bad role.
	dir = copyRef(t)
	if err := rewriteFile(t, dir, "hosts.yml", func(s string) string {
		return "team: 12\nhosts:\n  ubuntu-wkst:\n    segment: linux\n    ip: 172.20.242.10\n    os: {family: debian}\n    roles: [bogus_role]\n"
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, TeamVars(12)); err == nil {
		t.Error("expected schema error for bogus role")
	}
}

// copyRef copies the repo reference manifest into a fresh temp dir.
func copyRef(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(refDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		data := readRef(t, e.Name())
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// rewriteFile replaces one manifest file in dir with f(current contents).
func rewriteFile(t *testing.T, dir, name string, f func(string) string) error {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), []byte(f(string(data))), 0o644)
}
