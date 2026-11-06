package controller

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/event"
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
	t.Skip("unimplemented: W1 Task 29")
	reg := actions.Core()
	a := ctlAction{new(atomic.Int32)}
	reg.Register(a)
	c := newTestControllerWithRegistry(t, reg, func(context.Context, string) error { return nil })
	// create, approve, apply a click plan with one node {action: ctltest.local, target: <controller host>}; Wait
	// want: node verified; a.probed.Load() == 1;
	// c.st.Latest(ctx, "controller", "agent.step_result") decodes to event.AgentStepResult with Outcome set and Node == the node id
	_ = event.AgentStepResult{}
	_ = c
}
