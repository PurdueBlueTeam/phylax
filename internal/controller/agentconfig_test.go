package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func realManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	m, err := manifest.LoadDir("../../manifest/2027", manifest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func realRules(t *testing.T) []plan.RuleFile {
	t.Helper()
	in, err := LoadConfigInputs(Config{ManifestPath: "../../manifest/2027", RulesPath: "../../rules"})
	if err != nil {
		t.Fatal(err)
	}
	return in.Rules
}

// Every host of the real example manifest gets a config whose modules match
// its OS and roles.
func TestBuildAgentConfigRealManifest(t *testing.T) {
	m := realManifest(t)
	rules := realRules(t)
	if len(rules) < 5 {
		t.Fatalf("rules: %d files", len(rules))
	}
	for name, h := range m.Hosts {
		cfg, _, err := BuildAgentConfig(ConfigInputs{Manifest: m, Rules: rules, Ledger: plan.LedgerRef{File: "ledger.plx", SHA256: "ab"}}, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ms := cfg.Modules
		if ms.Health == nil || ms.Detect == nil || len(ms.Detect.Rules) != len(rules) {
			t.Fatalf("%s: health/detect missing: %+v", name, ms)
		}
		if ms.Detect.ActEnabled {
			t.Fatalf("%s: tier-0 responses must stay disabled", name)
		}
		if h.IsWindows() {
			if ms.Winevt == nil || ms.Audit != nil || ms.Net != nil || ms.Integrity != nil {
				t.Fatalf("%s (windows): %+v", name, ms)
			}
			continue
		}
		if ms.Audit == nil || ms.Net == nil || ms.Integrity == nil || ms.Winevt != nil {
			t.Fatalf("%s (linux): %+v", name, ms)
		}
		if ms.Integrity.Ledger.SHA256 != "ab" {
			t.Fatalf("%s: ledger ref not carried", name)
		}
		if !h.IsWorkstation() && len(ms.Net.NFLogGroups) == 0 {
			t.Fatalf("%s: a server's denied-egress NFLOG group is missing", name)
		}
	}
	// A vantage host expands to its three roles.
	for name, h := range m.Hosts {
		if h.HasRole(manifest.RoleVantage) {
			cfg, _, _ := BuildAgentConfig(ConfigInputs{Manifest: m}, name)
			for _, r := range []string{"check_runner", "scanner", "canary", "vantage"} {
				if !cfg.HasRole(r) {
					t.Fatalf("%s lacks role %s: %v", name, r, cfg.Roles)
				}
			}
		}
	}
	// Web roots, service binaries and pins come from the services on the host.
	found := false
	for id, s := range m.Services {
		if s.Content == nil || len(s.Content.Roots) == 0 || m.Hosts[s.Host].IsWindows() {
			continue
		}
		cfg, _, _ := BuildAgentConfig(ConfigInputs{Manifest: m}, s.Host)
		for _, r := range s.Content.Roots {
			if !contains(cfg.Modules.Audit.WebRoots, r) {
				t.Fatalf("service %s: root %s missing from audit web roots %v", id, r, cfg.Modules.Audit.WebRoots)
			}
		}
		found = true
	}
	if !found {
		t.Fatal("manifest has no linux service with content roots; the test checks nothing")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestDetectSeedsFromManifest(t *testing.T) {
	m := &manifest.Manifest{
		Hosts: map[string]manifest.Host{"h1": {Segment: "s", IP: "10.0.0.5", OS: manifest.OS{Family: "debian"}, DefaultCredential: "cred"},
			"h2": {Segment: "s", IP: "10.0.0.6", OS: manifest.OS{Family: "debian"}}},
		Accounts: map[string]manifest.Account{
			"alice@h1": {Scope: "local", Hosts: []string{"h1"}, Scored: manifest.ScoredYes, Rotation: "pcr_transaction"},
			"bob":      {Scope: "local", Hosts: []string{"h1"}, Scored: manifest.ScoredNo, Rotation: "free"},
			"carol":    {Scope: "local", Hosts: []string{"h2"}, Scored: manifest.ScoredYes, Rotation: "manual"},
		},
		Services: map[string]manifest.Service{
			"web": {Host: "h1", Kind: "http", Scored: true, Process: &manifest.Process{Unit: "apache2.service", Binaries: []string{"/usr/sbin/apache2"}, Pin: true},
				Listen: []manifest.Listener{{Proto: "tcp", Port: 80}}, DependsOn: []manifest.Dependency{{Egress: "db", To: "h2"}}},
		},
	}
	cfg, _, err := BuildAgentConfig(ConfigInputs{Manifest: m, Rules: []plan.RuleFile{{Name: "x", YAML: "id: x"}}}, "h1")
	if err != nil {
		t.Fatal(err)
	}
	seeds := map[string][]string{}
	for _, s := range cfg.Modules.Detect.Seeds {
		seeds[s.Profile] = s.Values
	}
	for prof, want := range map[string]string{"accounts.scored": "alice", "rotation.pending": "alice,bob", "scored.service_comms": "apache2", "service.dependencies": "10.0.0.6"} {
		if strings.Join(seeds[prof], ",") != want {
			t.Errorf("seed %s = %v, want [%s]", prof, seeds[prof], want)
		}
	}
	if len(seeds["accounts.scored"]) != 1 {
		t.Error("carol is on another host and must not be seeded here")
	}
	in := cfg.Modules.Integrity
	if len(in.Pins) != 1 || in.Pins[0].Path != "/usr/sbin/apache2" || in.Pins[0].Unit != "apache2.service" || in.Pins[0].Service != "web" {
		t.Errorf("pins: %+v", in.Pins)
	}
	if cfg.Modules.Net.Services["tcp/80"] != "web" {
		t.Errorf("net services: %v", cfg.Modules.Net.Services)
	}
	if _, _, err := BuildAgentConfig(ConfigInputs{Manifest: m}, "nope"); err == nil {
		t.Error("unknown host must fail")
	}
}

func newBareController(t *testing.T, dir string) *Controller {
	t.Helper()
	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: dir}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := New(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Versions move only when the content does; identical content re-signs to the
// identical message, also across a controller restart; the epoch is in it.
func TestAgentConfigVersions(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	m := realManifest(t)
	host := "rocky-ecom"
	c := newBareController(t, dir)
	if w, err := c.AgentConfigFor(ctx, host); err != nil || w != nil {
		t.Fatalf("no inputs: %v %v", w, err)
	}
	if err := c.SetConfigInputs(ctx, ConfigInputs{Manifest: m, Rules: realRules(t)}); err != nil {
		t.Fatalf("the shipped rules must pass strict validation: %v", err)
	}
	w1, err := c.AgentConfigFor(ctx, host)
	if err != nil || w1 == nil || w1.Version != 1 || w1.Epoch == 0 {
		t.Fatalf("first config: %+v %v", w1, err)
	}
	ver := func() *plan.ConfigVerifier {
		return &plan.ConfigVerifier{Key: c.PlanPublicKey(), HostID: host, Store: plan.FileSeqStore{Path: filepath.Join(t.TempDir(), "s")}}
	}
	got, err := ver().Verify(w1)
	if err != nil || got.Epoch != w1.Epoch || got.Host != host {
		t.Fatalf("agent-side verify: %+v %v", got, err)
	}
	// Same inputs again: same message.
	if err := c.SetConfigInputs(ctx, ConfigInputs{Manifest: realManifest(t), Rules: realRules(t)}); err != nil {
		t.Fatal(err)
	}
	w1b, _ := c.AgentConfigFor(ctx, host)
	if w1b.Version != 1 || w1b.Sig != w1.Sig {
		t.Fatalf("unchanged content changed the message: v%d", w1b.Version)
	}
	// A different host's config is unaffected by a change that is not about it.
	other := "ad"
	o1, _ := c.AgentConfigFor(ctx, other)
	m2 := realManifest(t)
	s := m2.Services["ecom-http"]
	for id, sv := range m2.Services {
		if sv.Host == host && len(sv.Listen) > 0 {
			s = sv
			s.Listen = append(append([]manifest.Listener(nil), s.Listen...), manifest.Listener{Proto: "tcp", Port: 8089})
			m2.Services[id] = s
			break
		}
	}
	if err := c.SetConfigInputs(ctx, ConfigInputs{Manifest: m2, Rules: realRules(t)}); err != nil {
		t.Fatal(err)
	}
	w2, _ := c.AgentConfigFor(ctx, host)
	o2, _ := c.AgentConfigFor(ctx, other)
	if w2.Version != 2 {
		t.Fatalf("manifest change: version %d", w2.Version)
	}
	if o2.Version != o1.Version {
		t.Fatalf("an unrelated host's version moved: %d -> %d", o1.Version, o2.Version)
	}
	// Restart: the version record is durable.
	c.Close()
	c = newBareController(t, dir)
	defer c.Close()
	if err := c.SetConfigInputs(ctx, ConfigInputs{Manifest: m2, Rules: realRules(t)}); err != nil {
		t.Fatal(err)
	}
	w2b, _ := c.AgentConfigFor(ctx, host)
	if w2b.Version != 2 || w2b.Sig != w2.Sig {
		t.Fatalf("restart re-issued the config: v%d", w2b.Version)
	}
	// An unknown host has no config.
	if w, err := c.AgentConfigFor(ctx, "ghost"); w != nil || err != nil {
		t.Fatalf("ghost: %v %v", w, err)
	}
}

func TestSetConfigInputsRejectsBadRules(t *testing.T) {
	ctx := context.Background()
	c := newBareController(t, t.TempDir())
	defer c.Close()
	m := realManifest(t)
	if err := c.SetConfigInputs(ctx, ConfigInputs{Manifest: m, Rules: []plan.RuleFile{{Name: "bad.yml", YAML: "id: x\ntitle: t\nbogus: 1\n"}}}); err == nil {
		t.Fatal("invalid rules accepted")
	}
	if c.HasConfigInputs() {
		t.Fatal("rejected inputs were installed")
	}
	if err := c.SetConfigInputs(ctx, ConfigInputs{}); err == nil {
		t.Fatal("no manifest accepted")
	}
}

func TestParseConfigStatus(t *testing.T) {
	st, e, v := parseConfigStatus("degraded/3.12")
	if st != "degraded" || e != 3 || v != 12 {
		t.Fatalf("%s %d %d", st, e, v)
	}
	if st, e, v := parseConfigStatus("none/0.0"); st != "none" || e != 0 || v != 0 {
		t.Fatal(st, e, v)
	}
}

// The watcher reloads on file change, keeps the old inputs on a bad change and
// recovers on the next good one.
func TestWatchConfigInputs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tmp := t.TempDir()
	mdir := filepath.Join(tmp, "m")
	copyDir(t, "../../manifest/2027", mdir)
	rdir := filepath.Join(tmp, "rules")
	copyDir(t, "../../rules", rdir)
	os.RemoveAll(filepath.Join(rdir, "pending"))
	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: filepath.Join(tmp, "data"), ManifestPath: mdir, RulesPath: rdir}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	alerts := make(chan Alert, 8)
	c, err := New(ctx, cfg, Options{OnAlert: func(a Alert) { alerts <- a }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.LoadAndSetConfigInputs(ctx); err != nil {
		t.Fatal(err)
	}
	go c.WatchConfigInputs(ctx, 20*time.Millisecond)
	host := "rocky-ecom"
	w1, _ := c.AgentConfigFor(ctx, host)

	// Break a rule file: alert, old config stays.
	good, _ := os.ReadFile(filepath.Join(rdir, "auth.yml"))
	if err := os.WriteFile(filepath.Join(rdir, "auth.yml"), append(good, []byte("\nid: broken\nbogus: yes\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-alerts:
		if a.Kind != "config.inputs_invalid" {
			t.Fatalf("alert %+v", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no alert for invalid inputs")
	}
	if w, _ := c.AgentConfigFor(ctx, host); w.Version != w1.Version {
		t.Fatal("invalid inputs changed the config")
	}
	// Fix it and add a rule: new version.
	extra := "\n---\nid: Z1.extra\ntitle: extra\nseverity: low\ntier: 2\nattack: [T1059]\nwhen:\n  event: zz.extra\n  all:\n    - a: b\ntests:\n  - {name: y, should_match: true, event: {kind: zz.extra, fields: {a: b}}}\n  - {name: n, should_match: false, event: {kind: zz.extra, fields: {a: c}}}\n"
	if err := os.WriteFile(filepath.Join(rdir, "auth.yml"), append(good, []byte(extra)...), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if w, _ := c.AgentConfigFor(ctx, host); w.Version > w1.Version {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rule change did not produce a new config version")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = strings.TrimSpace
}
