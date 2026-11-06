package controller

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// txn is a node option, not an action parameter: a resync node must pass plan
// validation and reach the agent without it.
func TestResyncNodeRuns(t *testing.T) {
	var sawTxn atomic.Bool
	x := newPlanCtl(t, nil, nil, Options{Probe: func(context.Context, string) error { return nil }, OnStepSent: func(_ string, s *link.Step) {
		var params map[string]any
		if err := json.Unmarshal(s.Params, &params); err != nil {
			t.Errorf("step params: %v", err)
			return
		}
		if _, ok := params["txn"]; ok {
			sawTxn.Store(true)
		}
	}})
	_, root := newPlanAgent(t, x, "h1")
	p := plan.Plan{ID: "resync-node", OnFailure: plan.StopDependents, Class: plan.ClassClick, Nodes: []plan.Node{{
		ID: "a", Action: "file.write", Target: "h1", Risk: plan.RiskService,
		Params: map[string]any{"path": "/tmp/phylax-resync", "content": "changed", "txn": "resync"},
	}}}
	if err := x.c.CreatePlan(ctx, p, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.approveNow(ctx, p.ID, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.Apply(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := x.c.Wait(wctx, p.ID); err != nil {
		t.Fatal(err)
	}
	d, err := x.c.PlanDetail(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.State != PlanSucceeded || d.Nodes["a"].State != plan.StateVerified {
		t.Fatalf("plan %s node %+v", d.State, d.Nodes["a"])
	}
	if sawTxn.Load() {
		t.Fatal("txn reached the agent as an action parameter")
	}
	if got, _ := readFileString(root + "/tmp/phylax-resync"); got != "changed" {
		t.Fatalf("file content %q, want changed", got)
	}
}
