package manifest

import (
	"slices"
	"testing"
	"testing/fstest"
)

func minimalManifestFS() fstest.MapFS {
	return fstest.MapFS{
		FileTopology: {Data: []byte(`
team: 3
controller: { host: ctl, agent_port: 7443, ui: "127.0.0.1:8443" }
segments:
  lan: { cidr: 10.0.0.0/24, nat: { public_pool: "172.25.23.0/24", mode: static_1to1_same_octet } }
`)},
		FileHosts: {Data: []byte(`
hosts:
  ctl: { segment: lan, ip: 10.0.0.2, public: "172.25.23.2", os: { family: debian, version: "12" }, roles: [controller] }
  web1: { segment: lan, ip: 10.0.0.10, public: "172.25.23.10", os: { family: debian, version: "12" }, labels: [linux, web], modules: { demo: true } }
  db1: { segment: lan, ip: 10.0.0.11, public: "172.25.23.11", os: { family: debian, version: "12" }, labels: [linux, server] }
`)},
	}
}

func TestLoadModuleBlocks(t *testing.T) {
	t.Skip("unimplemented: W1 Task 11")
	fsys := minimalManifestFS()
	fsys["modules/demo.yml"] = &fstest.MapFile{Data: []byte("enabled: false\nact_enabled: true\nauto: [harden]\nlevel: 3\n")}
	fsys["modules/other.yml"] = &fstest.MapFile{Data: []byte("level: 1\n")}
	m, err := Load(fsys, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b := m.Modules["demo"]
	if b.Enabled == nil || *b.Enabled || !b.ActEnabled || !slices.Equal(b.Auto, []string{"harden"}) {
		t.Fatalf("block %+v", b)
	}
	if m.Modules["other"].Enabled != nil {
		t.Fatal("absent enabled must be nil")
	}
	var cfg struct {
		Level int `yaml:"level"`
	}
	if err := b.Decode(&cfg); err != nil || cfg.Level != 3 {
		t.Fatalf("decode %+v %v", cfg, err)
	}
	var strict struct {
		Level int `yaml:"level"`
	}
	if b.Decode(&strict) == nil {
		t.Fatal("unknown keys accepted")
	}
}

func TestModuleBlockBadFileName(t *testing.T) {
	t.Skip("unimplemented: W1 Task 11")
	fsys := minimalManifestFS()
	fsys["modules/Demo.yaml"] = &fstest.MapFile{Data: []byte("{}")}
	if _, err := Load(fsys, Options{}); err == nil {
		t.Fatal("bad file name accepted")
	}
}

func TestModuleEnabledPrecedence(t *testing.T) {
	t.Skip("unimplemented: W1 Task 11")
	fsys := minimalManifestFS()
	fsys["modules/demo.yml"] = &fstest.MapFile{Data: []byte("enabled: false\n")}
	m, _ := Load(fsys, Options{})
	if !m.ModuleEnabled("web1", "demo", false) {
		t.Fatal("host entry must win")
	}
	if m.ModuleEnabled("db1", "demo", true) {
		t.Fatal("block false must beat default true")
	}
	if !m.ModuleEnabled("db1", "absent", true) {
		t.Fatal("default applies without a block")
	}
}
