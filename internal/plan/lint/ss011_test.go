package lint

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func scoredManifest() *manifest.Manifest {
	return &manifest.Manifest{Services: map[string]manifest.Service{
		"web": {Host: "h1", Scored: true, Content: &manifest.Content{Roots: []string{"/var/www"}}},
	}}
}

func scoredPlan(policy plan.FailurePolicy) plan.Plan {
	return plan.Plan{ID: "p", OnFailure: policy, Nodes: []plan.Node{{
		ID: "a", Action: "file.write", Target: "h1", Risk: plan.RiskService,
		Params: map[string]any{"path": "/var/www/index.html", "content": "x"},
	}}}
}

func TestSS011RejectsOtherPolicy(t *testing.T) {
	reg := actions.Core()
	for _, policy := range []plan.FailurePolicy{plan.StopDependents, plan.Continue} {
		f := Run(scoredPlan(policy), Ctx{Manifest: scoredManifest(), Actions: reg, Class: plan.ClassClick})
		if len(f) != 1 || f[0].Rule != "SS011" || f[0].Node != "a" {
			t.Fatalf("%s: findings %+v", policy, f)
		}
	}
	if f := Run(scoredPlan(plan.RollbackPlan), Ctx{Manifest: scoredManifest(), Actions: reg, Class: plan.ClassClick}); len(f) != 0 {
		t.Fatalf("rollback_plan refused: %+v", f)
	}
	if f := Run(scoredPlan(""), Ctx{Manifest: scoredManifest(), Actions: reg, Class: plan.ClassClick}); len(f) != 0 {
		t.Fatalf("an omitted on_failure is a finding: %+v", f)
	}
}
