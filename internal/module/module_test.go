package module

import (
	"context"
	"slices"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

func good() Manifest {
	return Manifest{Name: "demo", Sides: []Side{SideController}, Privilege: "none",
		Emits: []event.Type{{Kind: "demo.found", Schema: 1}}, Consumes: []string{"conn"}}
}

func TestManifestValidate(t *testing.T) {
	if err := good().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []func(*Manifest){
		func(m *Manifest) { m.Name = "Demo" },
		func(m *Manifest) { m.Sides = nil },
		func(m *Manifest) { m.OS = []string{"darwin"} },
		func(m *Manifest) { m.Privilege = "admin" },
		func(m *Manifest) { m.Sides = []Side{SideAgent}; m.Privilege = "none" },
		func(m *Manifest) { m.Emits = []event.Type{{Kind: "other.found", Schema: 1}} },
		func(m *Manifest) { m.Emits = []event.Type{{Kind: "agent.health", Schema: 1}} },
		func(m *Manifest) { m.Consumes = []string{"capture.*"} },
	}
	for i, f := range bad {
		m := good()
		f(&m)
		if m.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	h := Manifest{Name: "health", Sides: []Side{SideAgent}, Privilege: "root", Emits: []event.Type{{Kind: "agent.health", Schema: 1}, {Kind: "telemetry_gap", Schema: 1}}}
	if err := h.Validate(); err != nil {
		t.Fatalf("core module: %v", err)
	}
}

type regMod struct{ m Manifest }

func (r regMod) Manifest() Manifest                    { return r.m }
func (regMod) Start(ctx context.Context, _ Host) error { <-ctx.Done(); return nil }
func (regMod) Health() Health                          { return Health{State: StateOK} }

func TestRegistry(t *testing.T) {
	m := good()
	m.Name = "regtest"
	m.Emits = []event.Type{{Kind: "regtest.x", Schema: 1}}
	Register(regMod{m})
	if got, ok := Lookup("regtest"); !ok || got.Manifest().Name != "regtest" {
		t.Fatal("lookup")
	}
	names := []string{}
	for _, r := range Registered() {
		names = append(names, r.Manifest().Name)
	}
	if !slices.IsSorted(names) || !slices.Contains(names, "regtest") {
		t.Fatalf("registered %v", names)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate accepted")
		}
	}()
	Register(regMod{m})
}

func TestEffective(t *testing.T) {
	tr, fa := true, false
	cases := []struct {
		host, block *bool
		def, want   bool
	}{{nil, nil, true, true}, {nil, nil, false, false}, {nil, &fa, true, false}, {nil, &tr, false, true}, {&fa, &tr, true, false}, {&tr, &fa, false, true}}
	for i, c := range cases {
		if Effective(c.host, c.block, c.def) != c.want {
			t.Errorf("case %d", i)
		}
	}
}

// TestModuleEnabledAgreesWithEffective pins the two copies of the enablement
// rule (manifest cannot import module, deviation 17).
func TestModuleEnabledAgreesWithEffective(t *testing.T) {
	tr, fa := true, false
	ptrs := []*bool{nil, &tr, &fa}
	for _, host := range ptrs {
		for _, block := range ptrs {
			m := &manifest.Manifest{
				Hosts:   map[string]manifest.Host{"h1": {}},
				Modules: map[string]manifest.ModuleBlock{"demo": {Enabled: block}},
			}
			if host != nil {
				m.Hosts["h1"] = manifest.Host{Modules: map[string]bool{"demo": *host}}
			}
			for _, def := range []bool{true, false} {
				if got, want := m.ModuleEnabled("h1", "demo", def), Effective(host, block, def); got != want {
					t.Errorf("host %v block %v def %v: ModuleEnabled %v, Effective %v", host, block, def, got, want)
				}
			}
		}
	}
}
