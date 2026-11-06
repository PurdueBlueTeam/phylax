package controller

import (
	"errors"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/vault"
)

func init() {
	event.Declare(event.Type{Kind: "ctltest.found", Schema: 1, Priority: event.PriorityNormal, Fields: struct {
		X string `json:"x"`
	}{}})
}

func TestHostConfigStrict(t *testing.T) {
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\nlevel: 2\ndb: ecom.db\n"})
	h := c.hostFor(testMod())
	var cfg struct {
		module.Common `yaml:",inline"`
		Level         int    `yaml:"level"`
		DB            string `yaml:"db"`
	}
	if err := h.Config(&cfg); err != nil || cfg.Level != 2 {
		t.Fatalf("%+v %v", cfg, err)
	}
	var strict struct {
		Level int `yaml:"level"`
	}
	if h.Config(&strict) == nil {
		t.Fatal("unknown keys accepted")
	}
	other := testMod()
	other.m.Name = "nocfg"
	if err := c.hostFor(other).Config(&strict); !errors.Is(err, module.ErrNoConfig) {
		t.Fatalf("got %v", err)
	}
}

func TestHostEmitOnlyManifestKinds(t *testing.T) {
	c := newTestControllerWithManifest(t, nil)
	h := c.hostFor(testMod())
	e, _ := event.New("ctltest.found", struct {
		X string `json:"x"`
	}{"y"})
	e.Agent = "spoofed"
	if err := h.Emit(e); err != nil {
		t.Fatal(err)
	}
	got, _ := c.st.Latest(ctx, "controller", "ctltest.found")
	if got.Agent != "controller" {
		t.Fatal("agent not forced")
	}
	r, _ := event.New("agent.resumed", event.AgentResumed{Host: "h"})
	if err := h.Emit(r); !errors.Is(err, module.ErrNotInScope) {
		t.Fatalf("got %v", err)
	}
}

func TestHostSecretsScoped(t *testing.T) {
	v := newVault(t)
	for _, name := range []string{"ecom.db", "other"} {
		if _, err := v.Put(name, vault.NewSecretString("value"), "test"); err != nil {
			t.Fatal(err)
		}
	}
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\nlevel: 2\ndb: ecom.db\n"})
	c.opt.Vault = v
	h := c.hostFor(testMod())
	r, err := h.Secrets("ecom.db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get("ecom.db"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Secrets("other"); !errors.Is(err, vault.ErrNotAllowed) {
		t.Fatalf("got %v", err)
	}
}

func TestHostTablesNeedDeclaration(t *testing.T) {
	c := newTestControllerWithManifest(t, nil)
	if _, err := c.hostFor(testMod()).Tables(); err == nil {
		t.Fatal("tables without declaration")
	}
	m := testMod()
	m.m.Tables = []string{"ctltest_rows"}
	if _, err := c.hostFor(m).Tables(); err != nil {
		t.Fatal(err)
	}
}
