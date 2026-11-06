package module

import (
	"context"
	"slices"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func good() Manifest {
	return Manifest{Name: "demo", Sides: []Side{SideController}, Privilege: "none",
		Emits: []event.Type{{Kind: "demo.found", Schema: 1}}, Consumes: []string{"conn"}}
}

func TestManifestValidate(t *testing.T) {
	t.Skip("unimplemented: W1 Task 7")
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
		func(m *Manifest) { m.Budget.HeldMB = -1 },
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
	t.Skip("unimplemented: W1 Task 7")
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
