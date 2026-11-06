package controller

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

type ctlAction struct{ probed *atomic.Int32 }

func (ctlAction) Spec() actions.Spec {
	return actions.Spec{Name: "ctltest.local", Risk: actions.RiskNone, ReadOnly: true, Runs: actions.RunsController}
}
func (ctlAction) Locks(actions.Params) []string          { return nil }
func (ctlAction) Touches(actions.Params) []actions.Touch { return nil }
func (ctlAction) Plan(context.Context, *actions.Env, actions.Params) (actions.Plan, error) {
	return actions.Plan{}, nil
}
func (ctlAction) Capture(context.Context, *actions.Env, actions.Params) (actions.Rollback, error) {
	return actions.Rollback{}, nil
}
func (a ctlAction) Apply(ctx context.Context, env *actions.Env, _ actions.Params) (actions.Output, error) {
	if env.Probe != nil {
		_ = env.Probe(ctx, "web")
		a.probed.Add(1)
	}
	return actions.Output{}, nil
}
func (ctlAction) Verify(context.Context, *actions.Env, actions.Params) error { return nil }

func TestLocalActionWithoutDevices(t *testing.T) {
	reg := actions.Core()
	a := ctlAction{new(atomic.Int32)}
	reg.Register(a)
	c := newTestControllerWithRegistry(t, reg, func(context.Context, string) error { return nil })
	p := plan.Plan{ID: "local-action", OnFailure: plan.StopDependents, Nodes: []plan.Node{
		{ID: "n1", Action: "ctltest.local", Target: "ctl", Params: map[string]any{}},
	}}
	if err := c.CreatePlan(ctx, p, "tester"); err != nil {
		t.Fatal(err)
	}
	dr, err := c.DryRun(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !dr.Approvable {
		t.Fatalf("dry run not approvable: %+v", dr)
	}
	if err := c.ApprovePlan(ctx, p.ID, "tester"); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	st, err := c.Wait(wctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Nodes["n1"].State; got != plan.StateVerified {
		t.Fatalf("node state %q (%+v)", got, st.Nodes["n1"])
	}
	if n := a.probed.Load(); n != 1 {
		t.Fatalf("probe called %d times, want 1", n)
	}
	e, err := c.st.Latest(ctx, "controller", "agent.step_result")
	if err != nil {
		t.Fatal(err)
	}
	got, err := event.Decode[event.AgentStepResult](e, "agent.step_result")
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome == "" || got.Node != "n1" {
		t.Fatalf("step result %+v", got)
	}
}

// A device action runs in the same executor; without EnableDeviceExec it has
// no directory and the dry run rejects the node instead of panicking.
func TestDeviceActionWithoutDirectory(t *testing.T) {
	c := newTestController(t)
	p := plan.Plan{ID: "dev", OnFailure: plan.StopDependents, Nodes: []plan.Node{
		{ID: "acl", Action: "palo.permitted_ips", Target: "palo1", Params: map[string]any{"add": "127.0.0.1"}, Risk: plan.RiskLockout}}}
	if err := c.CreatePlan(ctx, p, "tester"); err != nil {
		t.Fatal(err)
	}
	dr, err := c.DryRun(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(dr.Nodes) != 1 || !strings.Contains(dr.Nodes[0].Reason, "no device directory") {
		t.Fatalf("dry run %+v", dr)
	}
}
