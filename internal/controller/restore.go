package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// loadPlans reloads unfinished plans from the store at start. A plan that was
// running (or marked interrupted by an older controller) is resumed: its
// executor state, including the step each node was waiting on, comes back from
// the snapshot stored with the plan, and every apply that was in flight is
// registered as pending so that, as soon as the host's agent reconnects, the
// controller asks it for the outcome of (epoch, seq) instead of guessing. Step
// sequence numbers are durable (store.NextStepSeq), so nothing is ever signed
// twice and nothing is applied twice. Dead-man reconciliation happens on the
// agent's hello (see planRT.reconcileLocked).
func (c *Controller) loadPlans(ctx context.Context) error {
	rows, err := c.st.Plans(ctx)
	if err != nil {
		return err
	}
	grace := c.opt.ResumeGrace
	for _, row := range rows {
		switch row.State {
		case PlanSucceeded, PlanFailed, PlanRolledBack:
			continue
		}
		rt, err := c.restorePlan(row, grace)
		if err != nil {
			c.log.Error("plan not restored", "plan", row.ID, "state", row.State, "err", err)
			c.planFailed("", event.PlanFailed{Reason: event.ReasonRestoreFailed, Plan: row.ID}, fmt.Sprintf("%s: %v", row.ID, err))
			if row.State == PlanRunning {
				_ = c.st.UpsertPlan(ctx, store.PlanRow{ID: row.ID, Name: row.Name, State: PlanInterrupted, Epoch: row.Epoch,
					Body: row.Body, Created: row.Created})
			}
			continue
		}
		c.plans[row.ID] = rt
		if rt.state == PlanRunning {
			c.log.Warn("plan resumed after controller restart", "plan", row.ID)
			rt.mu.Lock()
			_ = rt.persistLocked(ctx)
			rt.mu.Unlock()
			time.AfterFunc(grace, func() {
				rt.mu.Lock()
				defer rt.mu.Unlock()
				rt.advanceLocked()
			})
		}
	}
	return nil
}

func (c *Controller) restorePlan(row store.PlanRow, grace time.Duration) (*planRT, error) {
	var body planBody
	if err := json.Unmarshal([]byte(row.Body), &body); err != nil {
		return nil, fmt.Errorf("body: %w", err)
	}
	if body.Plan == nil {
		return nil, fmt.Errorf("no plan in the stored body")
	}
	p := body.Plan
	hash, err := p.Hash()
	if err != nil {
		return nil, err
	}
	if hash != body.Hash {
		return nil, fmt.Errorf("stored plan does not match its hash (stored %s, computed %s): tampered store?", body.Hash, hash)
	}
	run, err := plan.NewRun(p, c.catalog())
	if err != nil {
		return nil, err
	}
	state := row.State
	if state == PlanInterrupted {
		if body.Runtime == nil {
			return nil, fmt.Errorf("interrupted by an older controller without a runtime snapshot")
		}
		state = PlanRunning
	}
	rt := &planRT{c: c, p: p, run: run, state: state, by: body.By, dry: body.DryRun, nodes: map[string]*nodeRT{}, hash: hash,
		created: row.Created, done: make(chan struct{})}
	for _, n := range p.Nodes {
		rt.nodes[n.ID] = &nodeRT{}
	}
	states := map[string]plan.State{}
	reasons := map[string]string{}
	if snap := body.Runtime; snap != nil {
		rt.failed, rt.draining, rt.rbQueue, rt.rbBuilt, rt.rbBusy, rt.rbFailed = snap.Failed, snap.Draining, snap.RbQueue, snap.RbBuilt, snap.RbBusy, snap.RbFailed
		for id, ns := range snap.Nodes {
			nr := rt.nodes[id]
			if nr == nil {
				return nil, fmt.Errorf("snapshot names unknown node %q", id)
			}
			states[id], reasons[id] = ns.State, ns.Reason
			nr.want, nr.failedIn, nr.confirmed, nr.reason, nr.results = ns.Want, ns.FailedIn, ns.Confirmed, ns.Reason, ns.Results
			nr.cur = ns.Cur
		}
	} else {
		if state == PlanRunning {
			return nil, fmt.Errorf("running without a runtime snapshot")
		}
		for _, n := range p.Nodes {
			states[n.ID] = plan.StatePending
			if _, ok := body.Approvals[n.ID]; ok {
				states[n.ID] = plan.StateApproved
			}
		}
	}
	if err := run.Restore(states, reasons, body.Approvals); err != nil {
		return nil, err
	}
	if state != PlanRunning {
		return rt, nil
	}
	rt.holdUntil = c.now().Add(grace)
	for _, n := range p.Nodes {
		nr := rt.nodes[n.ID]
		if nr.cur != nil {
			cur := nr.cur
			if cur.Phase == plan.PhaseApply && run.State(n.ID) == plan.StateRunning {
				// Possibly applied, possibly not: ask the agent when it is back.
				exp := plan.Expect{Host: n.Target, PlanID: p.ID, NodeID: n.ID, Phase: cur.Phase, Epoch: cur.Epoch, Seq: cur.Seq, Digest: cur.Digest}
				key := stepKey{n.Target, cur.Epoch, cur.Seq}
				pd := &pending{exp: exp, rt: rt, node: n.ID, phase: cur.Phase}
				pd.timer = time.AfterFunc(grace+c.opt.StepTimeout, func() { c.stepTimedOut(key) })
				c.pend[key] = pd
				nr.inflight = true
			} else {
				// Verify and rollback are idempotent: issue them again.
				nr.cur, nr.want = nil, cur.Phase
			}
		}
		if nr.cur == nil && nr.want == "" && run.State(n.ID) == plan.StateRunning {
			nr.want = plan.PhaseApply // chosen to run but never sent
		}
	}
	return rt, nil
}
