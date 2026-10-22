package controller

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// ErrNoRollbackData is returned by RollbackPlan for a plan whose failure
// policy is not rollback_plan.
var ErrNoRollbackData = errors.New("controller: only plans with on_failure: rollback_plan keep rollback data")

// RollbackPlan is the operator's "roll back" for a plan that is running: it
// stops starting nodes, waits for in-flight steps, then sends signed rollback
// steps in reverse topological order. The plan ends rolled_back (or failed if a
// rollback fails). Other states are refused with ErrPlanState.
func (c *Controller) RollbackPlan(ctx context.Context, planID string) error {
	rt, err := c.plan(planID)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.state != PlanRunning {
		return ErrPlanState
	}
	if rt.policy() != plan.RollbackPlan {
		// Only rollback_plan plans give their nodes a rollback window, so only
		// they keep the data a rollback needs.
		return ErrNoRollbackData
	}
	rt.run.Abort()
	rt.draining = true
	if err := rt.persistLocked(ctx); err != nil {
		return err
	}
	rt.advanceLocked()
	return nil
}

// PlanDetail is a consistent snapshot of one in-memory plan for display.
type PlanDetail struct {
	Plan      plan.Plan
	State     string
	By        string
	Hash      string
	Created   time.Time
	DryRun    *plan.DryRun
	Nodes     map[string]PlanNodeDetail
	Draining  bool
	NodeOrder []string
}

// PlanNodeDetail is one node of a PlanDetail.
type PlanNodeDetail struct {
	State    plan.State
	Reason   string
	Phases   []phaseRec
	Risk     plan.Risk
	Approval *plan.Approval
}

// PlanDetail snapshots a plan held in memory (every unfinished plan, and every
// plan created or touched since the controller started).
func (c *Controller) PlanDetail(planID string) (PlanDetail, error) {
	rt, err := c.plan(planID)
	if err != nil {
		return PlanDetail{}, err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	d := PlanDetail{Plan: *rt.p, State: rt.state, By: rt.by, Hash: rt.hash, Created: rt.created,
		Nodes: map[string]PlanNodeDetail{}, Draining: rt.draining}
	if rt.dry != nil {
		cp := *rt.dry
		cp.Nodes = append([]plan.DryRunNode(nil), rt.dry.Nodes...)
		d.DryRun = &cp
	}
	for _, n := range rt.p.Nodes {
		nr := rt.nodes[n.ID]
		nd := PlanNodeDetail{State: rt.run.State(n.ID), Reason: nr.reason, Phases: append([]phaseRec(nil), nr.results...), Risk: rt.run.Risk(n.ID)}
		if nd.Reason == "" {
			nd.Reason = rt.run.FailureReason(n.ID)
		}
		if a, ok := rt.run.Approval(n.ID); ok {
			nd.Approval = &a
		}
		d.Nodes[n.ID] = nd
		d.NodeOrder = append(d.NodeOrder, n.ID)
	}
	return d, nil
}

// LivePlanIDs lists the plans held in memory, sorted.
func (c *Controller) LivePlanIDs() []string {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	ids := make([]string, 0, len(c.plans))
	for id := range c.plans {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// AgentHosts lists every host the controller knows (enrolled or connected).
func (c *Controller) AgentHosts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	hs := make([]string, 0, len(c.agents))
	for h := range c.agents {
		hs = append(hs, h)
	}
	sort.Strings(hs)
	return hs
}
