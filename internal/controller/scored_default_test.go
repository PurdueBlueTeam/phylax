package controller

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func TestDefaultRollbackPlanForScoredTouch(t *testing.T) {
	c := newTestControllerWithPlans(t, map[string]string{
		"ctltest/write.yml": "id: write\nmodule: ctltest\nnodes:\n  - {id: a, action: file.write, target: '${host}', risk: service, params: {path: /tmp/x, content: y}}\n",
		"ctltest/hash.yml":  "id: hash\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: a, action: file.hash, target: '${host}', params: {path: /etc/hosts}}\n",
	})
	p, err := c.moduleTemplate("ctltest", "write", map[string]string{"host": "h1"})
	if err != nil {
		t.Fatal(err)
	}
	if p.OnFailure != plan.RollbackPlan {
		t.Fatalf("scored touch: on_failure %q, want rollback_plan", p.OnFailure)
	}
	p, err = c.moduleTemplate("ctltest", "hash", map[string]string{"host": "h1"})
	if err != nil {
		t.Fatal(err)
	}
	if p.OnFailure != plan.StopDependents {
		t.Fatalf("unscored plan: on_failure %q, want stop_dependents", p.OnFailure)
	}
}
