package manifest

import (
	"slices"
	"testing"
	"testing/fstest"
)

// actFixture has two hosts with labels and the two module blocks the act
// cases name.
func actFixture(t *testing.T) *Manifest {
	t.Helper()
	fsys := fstest.MapFS{
		FileTopology: {Data: []byte(`
team: 3
controller: { host: ctl, agent_port: 7443, ui: "127.0.0.1:8443" }
segments:
  lan: { cidr: 10.0.0.0/24, nat: { public_pool: "172.25.23.0/24", mode: static_1to1_same_octet } }
`)},
		FileHosts: {Data: []byte(`
hosts:
  ctl: { segment: lan, ip: 10.0.0.2, public: "172.25.23.2", os: { family: debian, version: "12" }, roles: [controller] }
  web1: { segment: lan, ip: 10.0.0.10, public: "172.25.23.10", os: { family: debian, version: "12" }, labels: [linux, web] }
  db1: { segment: lan, ip: 10.0.0.11, public: "172.25.23.11", os: { family: debian, version: "12" }, labels: [linux, db] }
`)},
		"modules/respond.yml":  {Data: []byte("act_enabled: false\n")},
		"modules/firewall.yml": {Data: []byte("act_enabled: true\n")},
	}
	m, err := Load(fsys, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestActEnabledPerHost(t *testing.T) {
	m := actFixture(t)
	m.Overrides.Act = map[string][]string{"respond": {"web1"}, "hardening": {"linux && !db"}}
	cases := []struct {
		host, module string
		want         bool
	}{{"web1", "respond", true}, {"db1", "respond", false}, {"web1", "hardening", true}, {"db1", "hardening", false},
		{"db1", "firewall", true}, {"web1", "absent", false}}
	for _, c := range cases {
		if got := m.ActEnabled(c.host, c.module); got != c.want {
			t.Errorf("%s/%s: got %v", c.host, c.module, got)
		}
	}
}

func TestSafeModeHostSet(t *testing.T) {
	m := actFixture(t)
	m.Overrides.SafeModeHosts = []string{"db", "web1"}
	if got := m.SafeModeHostSet(); !slices.Equal(got, []string{"db1", "web1"}) {
		t.Fatalf("%v", got)
	}
}

func TestOverridesActValidated(t *testing.T) {
	dir := t.TempDir()
	bad := []func(*Overrides){
		func(o *Overrides) { o.Act = map[string][]string{"Respond": {"web1"}} },
		func(o *Overrides) { o.Act = map[string][]string{"respond": {"a &&"}} },
		func(o *Overrides) { o.SafeModeHosts = []string{"a b"} },
		func(o *Overrides) { o.Act = map[string][]string{"respond": make([]string, 65)} },
	}
	for i, f := range bad {
		if err := AppendOverrides(dir, func(o *Overrides) error { f(o); return nil }); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	ok := func(o *Overrides) error {
		o.Act = map[string][]string{"respond": {"web1"}}
		o.SafeModeHosts = []string{"web1"}
		return nil
	}
	if err := AppendOverrides(dir, ok); err != nil {
		t.Fatal(err)
	}
}

func TestOverridesActNoHostIsLintWarning(t *testing.T) {
	m := actFixture(t)
	m.Overrides.Act = map[string][]string{"respond": {"nosuchlabel"}}
	found := false
	for _, f := range Lint(m) {
		if f.ID == RuleOverridesNoHost && f.Severity == SevWarn && f.Subject == "overrides: act respond" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no %s warning for respond: %+v", RuleOverridesNoHost, Lint(m))
	}
}
