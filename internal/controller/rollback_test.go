package controller

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	phyagent "github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func rollbackOneNodePlan(id string) plan.Plan {
	return plan.Plan{ID: id, OnFailure: plan.RollbackPlan, Class: plan.ClassClick, Nodes: []plan.Node{{
		ID: "a", Action: "file.write", Target: "h1", Risk: plan.RiskService,
		Params: map[string]any{"path": "/tmp/" + id, "content": "x"},
	}}}
}

func runRollbackPlan(t *testing.T, x *ctl, p plan.Plan) PlanDetail {
	t.Helper()
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
	return d
}

// A failed apply is already undone by the agent's executor. The controller
// marks it rolled back and sends no second rollback step.
func TestFailedApplyUsesAgentRollback(t *testing.T) {
	var rollbacks atomic.Int32
	x := newPlanCtl(t, nil, nil, Options{Probe: func(context.Context, string) error { return nil }})
	newFakeStepAgent(t, x, "h1", false, func(w *link.Step) (string, bool) {
		switch w.Phase {
		case plan.PhaseApply:
			return plan.OutcomeFailed, true
		case plan.PhaseRollback:
			rollbacks.Add(1)
			return plan.OutcomeRolledBack, true
		}
		return plan.OutcomeFailed, true
	})
	d := runRollbackPlan(t, x, rollbackOneNodePlan("failed-apply-rollback"))
	if got := rollbacks.Load(); got != 0 {
		t.Fatalf("controller sent %d rollback steps after the agent already rolled back", got)
	}
	if d.State != PlanRolledBack || d.Nodes["a"].State != plan.StateRolledBack {
		t.Fatalf("plan %s node %+v", d.State, d.Nodes["a"])
	}
}

// When the agent's own undo of a failed apply failed, its typed outcome makes
// the controller report rollback_failed instead of assuming the change is gone.
func TestFailedApplyRollbackFailureIsReported(t *testing.T) {
	var rollbacks atomic.Int32
	x := newPlanCtl(t, nil, nil, Options{Probe: func(context.Context, string) error { return nil }})
	newFakeStepAgent(t, x, "h1", false, func(w *link.Step) (string, bool) {
		switch w.Phase {
		case plan.PhaseApply:
			return plan.OutcomeRollbackFailed, true
		case plan.PhaseRollback:
			rollbacks.Add(1)
			return plan.OutcomeRolledBack, true
		}
		return plan.OutcomeFailed, true
	})
	d := runRollbackPlan(t, x, rollbackOneNodePlan("failed-apply-rollback-report"))
	if got := rollbacks.Load(); got != 0 {
		t.Fatalf("controller sent %d rollback steps after the agent reported its undo failed", got)
	}
	if d.State != PlanFailed || d.Nodes["a"].State != plan.StateFailed {
		t.Fatalf("plan %s node %+v", d.State, d.Nodes["a"])
	}
	if !strings.Contains(d.Nodes["a"].Reason, "rollback failed") {
		t.Fatalf("reason %q does not report the failed rollback", d.Nodes["a"].Reason)
	}
}

// A verify failure leaves a live change: the controller sends exactly one
// rollback step and records the result.
func TestVerifyFailureIsRolledBackOnce(t *testing.T) {
	var rollbacks atomic.Int32
	x := newPlanCtl(t, nil, nil, Options{Probe: func(context.Context, string) error { return nil }})
	newFakeStepAgent(t, x, "h1", false, func(w *link.Step) (string, bool) {
		switch w.Phase {
		case plan.PhaseApply:
			return plan.OutcomeApplied, true
		case plan.PhaseVerify:
			return plan.OutcomeFailed, true
		case plan.PhaseRollback:
			rollbacks.Add(1)
			return plan.OutcomeRolledBack, true
		}
		return plan.OutcomeFailed, true
	})
	d := runRollbackPlan(t, x, rollbackOneNodePlan("failed-verify-rollback"))
	if got := rollbacks.Load(); got != 1 {
		t.Fatalf("rollback steps %d, want 1", got)
	}
	if d.State != PlanRolledBack || d.Nodes["a"].State != plan.StateRolledBack {
		t.Fatalf("plan %s node %+v", d.State, d.Nodes["a"])
	}
}

// A rollback that fails is reported and is not retried silently.
func TestFailedRollbackIsReported(t *testing.T) {
	var rollbacks atomic.Int32
	x := newPlanCtl(t, nil, nil, Options{Probe: func(context.Context, string) error { return nil }})
	newFakeStepAgent(t, x, "h1", false, func(w *link.Step) (string, bool) {
		switch w.Phase {
		case plan.PhaseApply:
			return plan.OutcomeApplied, true
		case plan.PhaseVerify:
			return plan.OutcomeFailed, true
		case plan.PhaseRollback:
			rollbacks.Add(1)
			return plan.OutcomeFailed, true
		}
		return plan.OutcomeFailed, true
	})
	d := runRollbackPlan(t, x, rollbackOneNodePlan("failed-rollback-report"))
	if got := rollbacks.Load(); got != 1 {
		t.Fatalf("rollback steps %d, want 1", got)
	}
	if d.State != PlanFailed || d.Nodes["a"].State != plan.StateFailed {
		t.Fatalf("plan %s node %+v", d.State, d.Nodes["a"])
	}
	if !strings.Contains(d.Nodes["a"].Reason, "rollback failed") {
		t.Fatalf("reason %q does not report the failed rollback", d.Nodes["a"].Reason)
	}
	time.Sleep(100 * time.Millisecond)
	if got := rollbacks.Load(); got != 1 {
		t.Fatalf("failed rollback was retried: %d steps", got)
	}
}

// A refused step never ran; the typed `rejected` status keeps it out of the
// rollback queue.
func TestRefusedStepIsNotRolledBack(t *testing.T) {
	var rollbacks atomic.Int32
	x := newPlanCtl(t, nil, nil, Options{Probe: func(context.Context, string) error { return nil }})
	newFakeStepAgent(t, x, "h1", false, func(w *link.Step) (string, bool) {
		switch w.Phase {
		case plan.PhaseApply:
			return phyagent.StatusRejected, true
		case plan.PhaseRollback:
			rollbacks.Add(1)
			return plan.OutcomeRolledBack, true
		}
		return plan.OutcomeFailed, true
	})
	d := runRollbackPlan(t, x, rollbackOneNodePlan("refused-step"))
	if got := rollbacks.Load(); got != 0 {
		t.Fatalf("refused step got %d rollback steps", got)
	}
	if d.Nodes["a"].State != plan.StateFailed {
		t.Fatalf("refused node %+v", d.Nodes["a"])
	}
}

// The skip set is exactly "never applied": a verify failure is rolled back,
// while a node failed before apply is left alone.
func TestRollbackSkipsOnlyNodesThatNeverApplied(t *testing.T) {
	c := newTestController(t)
	p := plan.Plan{ID: "skip-never-applied", OnFailure: plan.RollbackPlan, Nodes: []plan.Node{
		{ID: "applied", Action: "file.write", Target: "h1", Risk: plan.RiskService,
			Params: map[string]any{"path": "/tmp/phylax-applied", "content": "x"}},
		{ID: "never", Action: "file.write", Target: "h1", Risk: plan.RiskService,
			Params: map[string]any{"path": "/tmp/phylax-never", "content": "x"}},
	}}
	run, err := plan.NewRun(&p, c.catalog())
	if err != nil {
		t.Fatal(err)
	}
	rt := &planRT{c: c, p: &p, run: run, state: PlanRunning, draining: true, nodes: map[string]*nodeRT{
		"applied": {failedIn: plan.PhaseVerify, results: []phaseRec{{Phase: plan.PhaseApply, Outcome: plan.OutcomeApplied}}},
		"never":   {failedIn: "before"},
	}}
	if err := run.Restore(map[string]plan.State{"applied": plan.StateFailed, "never": plan.StateFailed}, nil, nil); err != nil {
		t.Fatal(err)
	}
	rt.rollbackStepLocked()
	if got := rt.nodes["applied"].want; got != plan.PhaseRollback {
		t.Fatalf("applied node wants %q, want %q", got, plan.PhaseRollback)
	}
	if got := rt.nodes["never"].want; got != "" {
		t.Fatalf("never-applied node wants %q, want no rollback", got)
	}
}
