package lint

import (
	"slices"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func node(id, action string, params map[string]any) plan.Node {
	return plan.Node{ID: id, Action: action, Target: "h1", Params: params}
}

func TestRegisterRejectsBadAndDuplicate(t *testing.T) {
	t.Skip("unimplemented: W1 Task 21")
	for _, id := range []string{"X1", "ss001", "SS0001", "SS000"} { // SS000 is already registered
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s accepted", id)
				}
			}()
			Register(Rule{ID: id, Check: func(plan.Node, Ctx) []Finding { return nil }})
		}()
	}
}

func TestSS000ReadOnly(t *testing.T) {
	t.Skip("unimplemented: W1 Task 21")
	reg := actions.Core()
	ro := plan.Plan{Nodes: []plan.Node{node("p", "net.tcp_probe", map[string]any{"host": "127.0.0.1", "port": 22})}}
	if f := Run(ro, Ctx{Class: plan.ClassAutoReadOnly, Actions: reg}); len(f) != 0 {
		t.Fatalf("read-only plan refused: %v", f)
	}
	w := plan.Plan{Nodes: []plan.Node{node("w", "file.write", map[string]any{"path": "/tmp/x", "content": "y"})}}
	f := Run(w, Ctx{Class: plan.ClassAutoReadOnly, Actions: reg})
	if len(f) != 1 || f[0].Rule != "SS000" || f[0].Node != "w" {
		t.Fatalf("write not refused: %v", f)
	}
	if len(Run(w, Ctx{Class: plan.ClassClick, Actions: reg})) != 0 {
		t.Fatal("SS000 must not apply to click plans")
	}
}

func TestSS000AutoRefusesClickOnly(t *testing.T) {
	t.Skip("unimplemented: W1 Task 21")
	reg := actions.Core()
	p := plan.Plan{Nodes: []plan.Node{node("x", "host.exec", map[string]any{"argv": []any{"/bin/true"}})}}
	if f := Run(p, Ctx{Class: plan.ClassAuto, Actions: reg}); len(f) == 0 {
		t.Fatal("host.exec allowed in an auto plan")
	}
}

func TestRulesSorted(t *testing.T) {
	t.Skip("unimplemented: W1 Task 21")
	ids := []string{}
	for _, r := range Rules() {
		ids = append(ids, r.ID)
	}
	if !slices.IsSorted(ids) || !slices.Contains(ids, "SS000") {
		t.Fatal(ids)
	}
}
