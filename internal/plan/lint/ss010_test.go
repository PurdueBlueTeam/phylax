package lint

import (
	"context"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

type passwordAction struct{ risk actions.Risk }

func (a passwordAction) Spec() actions.Spec {
	risk := a.risk
	if risk == "" {
		risk = actions.RiskLockout
	}
	return actions.Spec{Name: "test.password", Risk: risk}
}
func (passwordAction) Locks(actions.Params) []string { return nil }
func (passwordAction) Touches(actions.Params) []actions.Touch {
	return []actions.Touch{{Kind: actions.TouchAccount, Name: "admin", Op: actions.OpSetPassword}}
}
func (passwordAction) Plan(context.Context, *actions.Env, actions.Params) (actions.Plan, error) {
	return actions.Plan{}, nil
}
func (passwordAction) Capture(context.Context, *actions.Env, actions.Params) (actions.Rollback, error) {
	return actions.Rollback{}, nil
}
func (passwordAction) Apply(context.Context, *actions.Env, actions.Params) (actions.Output, error) {
	return nil, nil
}
func (passwordAction) Verify(context.Context, *actions.Env, actions.Params) error { return nil }

func TestSS010RefusesClickOnlySet(t *testing.T) {
	reg := actions.Core()
	for name := range ClickOnly {
		p := plan.Plan{Nodes: []plan.Node{node("x", name, nil)}}
		f := Run(p, Ctx{Class: plan.ClassAuto, Actions: reg})
		if len(f) == 0 || f[0].Rule != "SS010" {
			t.Errorf("%s: findings %+v", name, f)
		}
	}
}

func TestSS010RefusesScoredPasswordSet(t *testing.T) {
	reg := actions.NewRegistry()
	reg.Register(passwordAction{})
	m := &manifest.Manifest{Accounts: map[string]manifest.Account{
		"admin@lab": {Username: "admin", Scored: manifest.ScoredYes},
	}}
	p := plan.Plan{Nodes: []plan.Node{node("x", "test.password", map[string]any{})}}
	f := Run(p, Ctx{Class: plan.ClassAuto, Actions: reg, Manifest: m})
	if len(f) != 1 || f[0].Rule != "SS010" || !strings.Contains(f[0].Message, "password") {
		t.Fatalf("findings %+v", f)
	}
	resync := plan.Plan{Nodes: []plan.Node{node("x", "test.password", map[string]any{"txn": "resync"})}}
	if f := Run(resync, Ctx{Class: plan.ClassAuto, Actions: reg, Manifest: m}); len(f) != 0 {
		t.Fatalf("resync refused: %+v", f)
	}
}

func TestSS010RefusesIrreversibleNode(t *testing.T) {
	reg := actions.NewRegistry()
	reg.Register(passwordAction{risk: actions.Risk("unknown")})
	p := plan.Plan{Nodes: []plan.Node{node("x", "test.password", map[string]any{})}}
	f := Run(p, Ctx{Class: plan.ClassAuto, Actions: reg, Manifest: &manifest.Manifest{}})
	if len(f) != 1 || f[0].Rule != "SS010" || !strings.Contains(f[0].Message, "not reversible") {
		t.Fatalf("findings %+v", f)
	}
}
