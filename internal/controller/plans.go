package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	phyagent "github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// Plan lifecycle states (store plans.state).
const (
	PlanDraft       = "draft"
	PlanDryRun      = "dryrun"
	PlanApproved    = "approved"
	PlanRunning     = "running"
	PlanSucceeded   = "succeeded"
	PlanFailed      = "failed"
	PlanRolledBack  = "rolled_back"
	PlanInterrupted = "interrupted"
)

// RollbackWindowSec is the dead-man window given to nodes of a rollback_plan
// plan that do not set one: the agent must keep rollback data until the whole
// plan has succeeded, so confirmation is deferred to plan completion.
const RollbackWindowSec = 600

var (
	ErrPlanExists    = errors.New("controller: plan already exists")
	ErrNoSuchPlan    = errors.New("controller: no such plan")
	ErrNotApprovable = errors.New("controller: plan has no clean dry run to approve")
	ErrPlanState     = errors.New("controller: plan is in the wrong state for that")
)

// StepEvent describes a verified step result as it arrives.
type StepEvent struct {
	Host, Plan, Node, Phase, Outcome, Error string
}

type nodeRT struct {
	want      string // phase to dispatch next ("" = none)
	inflight  bool
	failedIn  string
	confirmed bool
	reason    string
	results   []phaseRec
}

type phaseRec struct {
	Phase   string `json:"phase"`
	Outcome string `json:"outcome"`
	Error   string `json:"error,omitempty"`
	Epoch   uint64 `json:"epoch"`
	Seq     uint64 `json:"seq"`
	Digest  string `json:"step_digest,omitempty"`
	Detail  string `json:"detail,omitempty"`
	AtMS    int64  `json:"at_ms"`
	Signed  bool   `json:"signed"`
}

type planRT struct {
	c  *Controller
	mu sync.Mutex

	p      *plan.Plan
	run    *plan.Run
	state  string
	by     string
	dry    *plan.DryRun
	nodes  map[string]*nodeRT
	hash   string
	failed bool // some node failed

	draining bool
	rbQueue  []string
	rbBuilt  bool
	rbBusy   bool
	rbFailed bool

	created time.Time
	done    chan struct{}
}

type stepKey struct {
	host       string
	epoch, seq uint64
}

type pending struct {
	step  *plan.Step
	rt    *planRT
	node  string
	phase string
	timer *time.Timer
	check chan checkResult // check phase only
}

type checkResult struct {
	outcome, err string
	detail       []byte
}

func (c *Controller) catalog() registryCatalog { return registryCatalog{c.reg} }

// PlanPublicKey is the Ed25519 key agents must be bootstrapped with.
func (c *Controller) PlanPublicKey() ed25519.PublicKey {
	return c.planKey.Public().(ed25519.PublicKey)
}

func (c *Controller) signer(ctx context.Context) (*plan.Signer, error) {
	ep, err := c.st.Epoch(ctx)
	if err != nil {
		return nil, err
	}
	return &plan.Signer{Key: c.planKey, Epoch: ep, Seqs: storeSeq{c.st}, Now: c.now}, nil
}

// CreatePlan validates a typed plan against the action catalog and stores it
// as a draft. For rollback_plan plans, nodes without a dead-man window get
// RollbackWindowSec so the agent keeps their rollback data.
func (c *Controller) CreatePlan(ctx context.Context, def plan.Plan, by string) error {
	p := def
	p.Nodes = append([]plan.Node(nil), def.Nodes...)
	if p.OnFailure == plan.RollbackPlan {
		for i, n := range p.Nodes {
			if n.Gate || n.DeadmanSec != 0 {
				continue
			}
			if a, err := c.reg.Get(n.Action); err == nil && !a.Spec().ReadOnly {
				p.Nodes[i].DeadmanSec = RollbackWindowSec
			}
		}
	}
	run, err := plan.NewRun(&p, c.catalog())
	if err != nil {
		return err
	}
	hash, err := p.Hash()
	if err != nil {
		return err
	}
	c.pmu.Lock()
	if _, ok := c.plans[p.ID]; ok {
		c.pmu.Unlock()
		return ErrPlanExists
	}
	if _, err := c.st.Plan(ctx, p.ID); err == nil {
		c.pmu.Unlock()
		return ErrPlanExists
	}
	rt := &planRT{c: c, p: &p, run: run, state: PlanDraft, by: by, nodes: map[string]*nodeRT{}, hash: hash,
		created: c.now(), done: make(chan struct{})}
	for _, n := range p.Nodes {
		rt.nodes[n.ID] = &nodeRT{}
	}
	c.plans[p.ID] = rt
	c.pmu.Unlock()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.persistLocked(ctx)
}

func (c *Controller) plan(id string) (*planRT, error) {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	rt, ok := c.plans[id]
	if !ok {
		return nil, ErrNoSuchPlan
	}
	return rt, nil
}

// lint runs the controller-side scoring guard over a node's touches.
func (c *Controller) lint(ctx context.Context, n plan.Node) string {
	if n.Gate || c.opt.Guard == nil {
		return ""
	}
	a, err := c.reg.Get(n.Action)
	if err != nil {
		return err.Error()
	}
	p, err := a.Spec().Validate(n.Params)
	if err != nil {
		return err.Error()
	}
	g := c.opt.Guard(n.Target)
	for _, t := range a.Touches(p) {
		if err := g.Allow(ctx, t); err != nil {
			return err.Error()
		}
	}
	return ""
}

// DryRun sends check-phase steps for every node to its agent, runs the
// scoring-safety lint, and aggregates the result. Nodes whose agent does not
// answer in time are "missing" and block approval.
func (c *Controller) DryRun(ctx context.Context, planID string) (plan.DryRun, error) {
	rt, err := c.plan(planID)
	if err != nil {
		return plan.DryRun{}, err
	}
	rt.mu.Lock()
	if rt.state != PlanDraft && rt.state != PlanDryRun {
		rt.mu.Unlock()
		return plan.DryRun{}, ErrPlanState
	}
	p := rt.p
	rt.mu.Unlock()

	// Check steps are read-only and the agent enforces that, but the signer
	// wants an approval record: use a throwaway run approved as "dry-run".
	tmp, err := plan.NewRun(p, c.catalog())
	if err != nil {
		return plan.DryRun{}, err
	}
	now := c.now()
	tmp.ApprovePlan(phyagent.DryRunApprover, now)
	for _, n := range p.Nodes {
		if tmp.State(n.ID) == plan.StatePending {
			_ = tmp.ApproveNode(n.ID, plan.Approval{By: phyagent.DryRunApprover, At: now.Unix()})
		}
	}
	sg, err := c.signer(ctx)
	if err != nil {
		return plan.DryRun{}, err
	}
	var checks []plan.NodeCheck
	type wait struct {
		node string
		ch   chan checkResult
	}
	var waits []wait
	for _, n := range p.Nodes {
		if n.Gate {
			continue
		}
		if why := c.lint(ctx, n); why != "" {
			checks = append(checks, plan.NodeCheck{NodeID: n.ID, LintReject: why})
			continue
		}
		ag := c.sessionFor(n.Target)
		if ag == nil {
			continue // missing
		}
		st, err := sg.Issue(p, tmp, n.ID, plan.IssueOpts{Phase: plan.PhaseCheck, Validity: c.opt.StepValidity})
		if err != nil {
			return plan.DryRun{}, err
		}
		pd := &pending{step: st, rt: rt, node: n.ID, phase: plan.PhaseCheck, check: make(chan checkResult, 1)}
		if err := c.sendStep(ctx, ag, n.Target, pd); err != nil {
			continue
		}
		waits = append(waits, wait{n.ID, pd.check})
	}
	tctx, cancel := context.WithTimeout(ctx, c.opt.StepTimeout)
	defer cancel()
	for _, w := range waits {
		select {
		case r := <-w.ch:
			nc := plan.NodeCheck{NodeID: w.node}
			switch r.outcome {
			case plan.OutcomeChecked:
				var d struct {
					Done bool   `json:"done"`
					Diff string `json:"diff"`
				}
				_ = json.Unmarshal(r.detail, &d)
				nc.WillChange, nc.Diff = !d.Done, d.Diff
			default:
				nc.LintReject = r.err
			}
			checks = append(checks, nc)
		case <-tctx.Done():
		}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	dr := rt.run.AggregateDryRun(checks, plan.Limits{})
	rt.dry = &dr
	rt.state = PlanDryRun
	return dr, rt.persistLocked(ctx)
}

// ApprovePlan is the one-click approval. It needs a dry run with no rejected,
// blocked or missing node. Nodes that need their own approval stay pending.
func (c *Controller) ApprovePlan(ctx context.Context, planID, by string) error {
	rt, err := c.plan(planID)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.state != PlanDryRun || rt.dry == nil || !rt.dry.Approvable {
		return ErrNotApprovable
	}
	rt.run.ApprovePlan(by, c.now())
	rt.state = PlanApproved
	return rt.persistLocked(ctx)
}

// ApproveNode records the separate approval of a gate, host.exec, lockout or
// destructive node (the signature of its steps covers the record).
func (c *Controller) ApproveNode(ctx context.Context, planID, node, by, note string) error {
	rt, err := c.plan(planID)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.dry == nil || !rt.dry.Approvable {
		return ErrNotApprovable
	}
	if rt.state == PlanSucceeded || rt.state == PlanFailed || rt.state == PlanRolledBack {
		return ErrPlanState
	}
	if err := rt.run.ApproveNode(node, plan.Approval{By: by, At: c.now().Unix(), Note: note}); err != nil {
		return err
	}
	if err := rt.persistLocked(ctx); err != nil {
		return err
	}
	rt.advanceLocked()
	return nil
}

// Apply starts execution of an approved plan.
func (c *Controller) Apply(ctx context.Context, planID string) error {
	rt, err := c.plan(planID)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.state != PlanApproved {
		return ErrPlanState
	}
	rt.state = PlanRunning
	if err := rt.persistLocked(ctx); err != nil {
		return err
	}
	rt.advanceLocked()
	return nil
}

// Wait blocks until the plan reaches a final state.
func (c *Controller) Wait(ctx context.Context, planID string) (PlanStatus, error) {
	rt, err := c.plan(planID)
	if err != nil {
		return PlanStatus{}, err
	}
	select {
	case <-rt.done:
	case <-ctx.Done():
		return PlanStatus{}, ctx.Err()
	}
	return c.PlanStatus(planID)
}

// NodeStatus is one node's live status.
type NodeStatus struct {
	State  plan.State
	Reason string
	Phases []phaseRec
}

// PlanStatus is a snapshot of a plan.
type PlanStatus struct {
	ID    string
	State string
	Nodes map[string]NodeStatus
}

// PlanStatus snapshots a plan held in memory.
func (c *Controller) PlanStatus(planID string) (PlanStatus, error) {
	rt, err := c.plan(planID)
	if err != nil {
		return PlanStatus{}, err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	ps := PlanStatus{ID: planID, State: rt.state, Nodes: map[string]NodeStatus{}}
	for id, nr := range rt.nodes {
		ps.Nodes[id] = NodeStatus{State: rt.run.State(id), Reason: nr.reason, Phases: append([]phaseRec(nil), nr.results...)}
	}
	return ps, nil
}

// StoredPlans lists persisted plans (including those of earlier runs).
func (c *Controller) StoredPlans(ctx context.Context) ([]store.PlanRow, error) {
	return c.st.Plans(ctx)
}

// DropAgent closes an agent's session (operator action, fault injection).
func (c *Controller) DropAgent(host string) {
	if ag := c.sessionFor(host); ag != nil {
		ag.sess.Close()
	}
}

func (c *Controller) sessionFor(host string) *agentConn {
	c.mu.Lock()
	s, ok := c.agents[host]
	c.mu.Unlock()
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sess
}

// ---- dispatch ----

// sendStep registers the pending step, then sends it. Registering first means
// a fast result can never beat the bookkeeping.
func (c *Controller) sendStep(ctx context.Context, ag *agentConn, host string, pd *pending) error {
	w, err := phyagent.StepToWire(pd.step)
	if err != nil {
		return err
	}
	key := stepKey{host, pd.step.Epoch, pd.step.Seq}
	c.pmu.Lock()
	c.pend[key] = pd
	pd.timer = time.AfterFunc(c.opt.StepTimeout, func() { c.stepTimedOut(key) })
	c.pmu.Unlock()
	sctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ag.sess.Send(sctx, link.PrioStep, w); err != nil {
		c.takePending(key)
		return err
	}
	if c.opt.OnStepSent != nil {
		c.opt.OnStepSent(host, w)
	}
	return nil
}

// SendRaw sends a message to a connected agent as is. It is the low-level
// operator/test hook (for example to deliver a control message); steps sent
// this way are still verified by the agent like any other.
func (c *Controller) SendRaw(ctx context.Context, host string, m link.Message) error {
	ag := c.sessionFor(host)
	if ag == nil {
		return fmt.Errorf("controller: agent %q is not connected", host)
	}
	return ag.sess.Send(ctx, link.PrioStep, m)
}

func (c *Controller) takePending(key stepKey) *pending {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	pd := c.pend[key]
	if pd != nil {
		delete(c.pend, key)
		pd.timer.Stop()
	}
	return pd
}

func (c *Controller) stepTimedOut(key stepKey) {
	pd := c.takePending(key)
	if pd == nil {
		return
	}
	c.log.Warn("step timed out", "host", key.host, "node", pd.node, "phase", pd.phase)
	c.alert(key.host, "plan.step_timeout", fmt.Sprintf("%s %s/%s: no result", pd.rt.p.ID, pd.node, pd.phase))
	c.deliver(pd, checkResult{outcome: plan.OutcomeFailed, err: "no result from the agent (timeout or link loss)"}, nil)
}

// onStepResult handles a step_result from agent session ag.
func (c *Controller) onStepResult(ag *agentConn, host string, m *link.StepResult) {
	key := stepKey{host, m.Epoch, m.Seq}
	c.pmu.Lock()
	pd := c.pend[key]
	c.pmu.Unlock()
	if pd == nil || pd.rt.p.ID != m.Plan || pd.node != m.Node {
		c.log.Debug("unmatched step result", "host", host, "plan", m.Plan, "node", m.Node, "seq", m.Seq)
		return
	}
	var out checkResult
	var rec *plan.StepResult
	if m.Status == "rejected" {
		out = checkResult{outcome: plan.OutcomeFailed, err: "agent refused the step: " + m.Error}
	} else {
		res, err := c.verifyResult(ag, pd, m)
		if err != nil {
			c.alert(host, "plan.bad_result", fmt.Sprintf("%s/%s: %v", m.Plan, m.Node, err))
			out = checkResult{outcome: plan.OutcomeFailed, err: "unverifiable result: " + err.Error()}
		} else {
			rec = res
			out = checkResult{outcome: res.Outcome, err: res.Error}
			if len(m.Before) > 0 {
				if h := sha256.Sum256(m.Before); hex.EncodeToString(h[:]) == res.AfterDigest {
					out.detail = m.Before
				}
			}
		}
	}
	if c.opt.OnStepResult != nil && c.opt.OnStepResult(StepEvent{host, m.Plan, m.Node, pd.phase, out.outcome, out.err}) {
		// Fault injection: lose this result and the link. The pending step
		// stays registered and will time out.
		ag.sess.Close()
		return
	}
	if c.takePending(key) == nil {
		return
	}
	c.deliver(pd, out, rec)
}

func (c *Controller) verifyResult(ag *agentConn, pd *pending, m *link.StepResult) (*plan.StepResult, error) {
	if ag.pub == nil {
		return nil, errors.New("no agent key")
	}
	var res plan.StepResult
	if err := json.Unmarshal(m.After, &res); err != nil {
		return nil, fmt.Errorf("result not decodable: %w", err)
	}
	if err := res.Verify(ag.pub, pd.step); err != nil {
		return nil, err
	}
	if m.Status != res.Outcome {
		return nil, errors.New("status does not match the signed outcome")
	}
	return &res, nil
}

func (c *Controller) deliver(pd *pending, out checkResult, rec *plan.StepResult) {
	if pd.phase == plan.PhaseCheck {
		pd.check <- out
		return
	}
	rt := pd.rt
	rt.mu.Lock()
	defer rt.mu.Unlock()
	pr := phaseRec{Phase: pd.phase, Outcome: out.outcome, Error: out.err, Epoch: pd.step.Epoch, Seq: pd.step.Seq,
		AtMS: c.now().UnixMilli(), Detail: string(out.detail)}
	if rec != nil {
		pr.Digest, pr.Signed = rec.StepDigest, true
	}
	rt.onResultLocked(pd.node, pr)
}

// resume re-sends steps that were in flight when a host's link dropped and
// lets nodes waiting for a connection proceed. Apply steps are not re-sent: a
// lost apply is failed by its timeout (the agent's dead-man covers it).
func (c *Controller) resume(host string) {
	c.pmu.Lock()
	var stale []*pending
	for k, pd := range c.pend {
		if k.host == host && pd.phase != plan.PhaseApply && pd.phase != plan.PhaseCheck {
			delete(c.pend, k)
			pd.timer.Stop()
			stale = append(stale, pd)
		}
	}
	rts := make([]*planRT, 0, len(c.plans))
	for _, rt := range c.plans {
		rts = append(rts, rt)
	}
	c.pmu.Unlock()
	for _, pd := range stale {
		pd.rt.mu.Lock()
		if nr := pd.rt.nodes[pd.node]; nr != nil && nr.inflight {
			nr.inflight, nr.want = false, pd.phase
		}
		pd.rt.mu.Unlock()
	}
	for _, rt := range rts {
		rt.mu.Lock()
		rt.advanceLocked()
		rt.mu.Unlock()
	}
}

// ---- the run loop (all *Locked methods hold rt.mu) ----

func (rt *planRT) policy() plan.FailurePolicy {
	if rt.p.OnFailure == "" {
		return plan.StopDependents
	}
	return rt.p.OnFailure
}

func (rt *planRT) node(id string) plan.Node {
	for _, n := range rt.p.Nodes {
		if n.ID == id {
			return n
		}
	}
	return plan.Node{}
}

func (rt *planRT) advanceLocked() {
	if rt.state != PlanRunning {
		return
	}
	if !rt.draining {
		for _, id := range rt.run.Next(plan.Limits{PerHost: 4}) {
			rt.nodes[id].want = plan.PhaseApply
		}
	}
	rt.rollbackStepLocked()
	ids := make([]string, 0, len(rt.nodes))
	for id := range rt.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if nr := rt.nodes[id]; nr.want != "" && !nr.inflight {
			rt.dispatchLocked(id, nr)
		}
	}
	rt.maybeFinishLocked()
}

func (rt *planRT) quiescentLocked() bool {
	for id, nr := range rt.nodes {
		if nr.inflight || nr.want != "" && nr.want != plan.PhaseRollback || rt.run.State(id) == plan.StateRunning {
			return false
		}
	}
	return true
}

// rollbackStepLocked drives the reverse-order rollback of a rollback_plan
// plan, one node at a time, once nothing else is in flight.
func (rt *planRT) rollbackStepLocked() {
	if !rt.draining || !rt.quiescentLocked() {
		return
	}
	if !rt.rbBuilt {
		rt.rbQueue, rt.rbBuilt = rt.run.RollbackOrder(), true
	}
	for !rt.rbBusy && len(rt.rbQueue) > 0 {
		id := rt.rbQueue[0]
		rt.rbQueue = rt.rbQueue[1:]
		nr := rt.nodes[id]
		if rt.run.State(id) == plan.StateFailed && nr.failedIn == plan.PhaseApply {
			// The agent's executor already rolled back a failed apply.
			_ = rt.run.MarkRolledBack(id)
			continue
		}
		nr.want, rt.rbBusy = plan.PhaseRollback, true
	}
}

func (rt *planRT) dispatchLocked(id string, nr *nodeRT) {
	c := rt.c
	n := rt.node(id)
	phase := nr.want
	ag := c.sessionFor(n.Target)
	if ag == nil {
		if phase == plan.PhaseApply {
			rt.failLocked(id, "agent "+n.Target+" is not connected", plan.PhaseApply)
		}
		return // verify and rollback wait for the reconnect
	}
	ctx := context.Background()
	sg, err := c.signer(ctx)
	var st *plan.Step
	if err == nil {
		st, err = sg.Issue(rt.p, rt.run, id, plan.IssueOpts{Phase: phase, Validity: c.opt.StepValidity})
	}
	if err != nil {
		rt.failLocked(id, "cannot issue step: "+err.Error(), phase)
		return
	}
	pd := &pending{step: st, rt: rt, node: id, phase: phase}
	nr.inflight, nr.want = true, ""
	if err := c.sendStep(ctx, ag, n.Target, pd); err != nil {
		nr.inflight = false
		if phase == plan.PhaseApply {
			rt.failLocked(id, "cannot send step: "+err.Error(), phase)
		} else {
			nr.want = phase // retry after reconnect
		}
	}
}

func (rt *planRT) onResultLocked(id string, pr phaseRec) {
	nr := rt.nodes[id]
	nr.inflight = false
	nr.results = append(nr.results, pr)
	ok := pr.Outcome
	switch pr.Phase {
	case plan.PhaseApply:
		if ok == plan.OutcomeApplied {
			_ = rt.run.MarkApplied(id)
			nr.want = plan.PhaseVerify
		} else {
			rt.failLocked(id, pr.Error, plan.PhaseApply)
		}
	case plan.PhaseVerify:
		if ok == plan.OutcomeVerified {
			_ = rt.run.MarkVerified(id)
			// Confirm now, unless the whole plan must succeed first.
			if rt.policy() != plan.RollbackPlan {
				rt.confirmLocked(id)
			}
		} else {
			rt.failLocked(id, pr.Error, plan.PhaseVerify)
		}
	case plan.PhaseRollback:
		rt.rbBusy = false
		if ok == plan.OutcomeRolledBack {
			_ = rt.run.MarkRolledBack(id)
		} else {
			rt.rbFailed = true
			nr.reason += " rollback failed: " + pr.Error
			rt.c.alert(rt.node(id).Target, "plan.rollback_failed", fmt.Sprintf("%s/%s: %s", rt.p.ID, id, pr.Error))
		}
	}
	_ = rt.persistLocked(context.Background())
	rt.advanceLocked()
}

func (rt *planRT) failLocked(id, reason, phase string) {
	nr := rt.nodes[id]
	nr.inflight, nr.want = false, ""
	if err := rt.run.Fail(id, reason); err != nil {
		rt.c.log.Error("plan: cannot fail node", "plan", rt.p.ID, "node", id, "err", err)
		return
	}
	nr.failedIn, nr.reason = phase, reason
	rt.failed = true
	if rt.policy() == plan.RollbackPlan {
		rt.draining = true
	} else if phase == plan.PhaseVerify {
		nr.want = plan.PhaseRollback // the change is live and wrong: undo it
	}
	_ = rt.persistLocked(context.Background())
}

// confirmLocked tells the agent to disarm the node's dead-man switch.
func (rt *planRT) confirmLocked(id string) {
	n := rt.node(id)
	nr := rt.nodes[id]
	if plan.EffectiveDeadmanSec(n, rt.run.Risk(id)) <= 0 {
		return
	}
	args, _ := json.Marshal(map[string]string{"plan": rt.p.ID, "node": id})
	ag := rt.c.sessionFor(n.Target)
	if ag == nil || ag.sess.TrySend(link.PrioCritical, &link.Control{Kind: "deadman_confirm", On: true, Args: args}) != nil {
		rt.c.alert(n.Target, "plan.confirm_failed", fmt.Sprintf("%s/%s: could not send dead-man confirm; the agent will roll back", rt.p.ID, id))
		return
	}
	nr.confirmed = true
}

func (rt *planRT) maybeFinishLocked() {
	if rt.state != PlanRunning || !rt.run.Done() {
		return
	}
	for _, nr := range rt.nodes {
		if nr.inflight || nr.want != "" {
			return
		}
	}
	if rt.draining && (!rt.rbBuilt || len(rt.rbQueue) > 0 || rt.rbBusy) {
		return
	}
	switch {
	case rt.draining && !rt.rbFailed:
		rt.state = PlanRolledBack
	case rt.failed || rt.draining:
		rt.state = PlanFailed
	default:
		rt.state = PlanSucceeded
		if rt.policy() == plan.RollbackPlan {
			for _, n := range rt.p.Nodes {
				if !n.Gate && !rt.nodes[n.ID].confirmed {
					rt.confirmLocked(n.ID)
				}
			}
		}
	}
	_ = rt.persistLocked(context.Background())
	close(rt.done)
}

// ---- persistence ----

type planBody struct {
	Plan      *plan.Plan               `json:"plan"`
	Hash      string                   `json:"hash"`
	By        string                   `json:"by"`
	Approvals map[string]plan.Approval `json:"approvals,omitempty"`
	DryRun    *plan.DryRun             `json:"dry_run,omitempty"`
	Failed    map[string]string        `json:"failed,omitempty"`
}

func (rt *planRT) persistLocked(ctx context.Context) error {
	c := rt.c
	body := planBody{Plan: rt.p, Hash: rt.hash, By: rt.by, DryRun: rt.dry, Approvals: map[string]plan.Approval{}}
	for _, n := range rt.p.Nodes {
		if a, ok := rt.run.Approval(n.ID); ok {
			body.Approvals[n.ID] = a
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	ep, _ := c.st.Epoch(ctx)
	if err := c.st.UpsertPlan(ctx, store.PlanRow{ID: rt.p.ID, Name: rt.p.Name, State: rt.state, Epoch: ep,
		Body: string(raw), Created: rt.created}); err != nil {
		return err
	}
	for _, n := range rt.p.Nodes {
		nr := rt.nodes[n.ID]
		res, _ := json.Marshal(map[string]any{"phases": nr.results, "reason": nr.reason, "failed_in": nr.failedIn})
		if err := c.st.UpsertPlanStep(ctx, store.PlanStepRow{PlanID: rt.p.ID, Step: n.ID, Host: n.Target,
			Action: n.Action, State: string(rt.run.State(n.ID)), Result: string(res)}); err != nil {
			return err
		}
	}
	return nil
}
