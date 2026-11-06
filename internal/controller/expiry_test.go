package controller

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func TestTemplateExpiresAfterDuration(t *testing.T) {
	p, err := ParseTemplate([]byte("id: t\nnodes:\n- {id: a, action: file.write, target: h1, params: {path: /tmp/x, content: y}, expires_after: 30m}\n"))
	if err != nil || p.Nodes[0].ExpiresAfterSec != 1800 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := ParseTemplate([]byte("id: t\nnodes:\n- {id: a, action: file.write, target: h1, params: {}, expires_after: soon}\n")); err == nil {
		t.Fatal("bad duration accepted")
	}
}

func TestExpiresAfterRefusedOnControllerAction(t *testing.T) {
	reg := actions.Core()
	reg.Register(ctlAction{new(atomic.Int32)})
	c := newTestControllerWithRegistry(t, reg, nil)
	p := plan.Plan{ID: "exp-ctl", OnFailure: plan.StopDependents, Nodes: []plan.Node{
		{ID: "dev", Action: "ctltest.local", Target: "ctl", ExpiresAfterSec: 600}}}
	err := c.CreatePlan(ctx, p, "tester")
	if err == nil || !strings.Contains(err.Error(), "controller-side action") {
		t.Fatalf("got %v", err)
	}
}
