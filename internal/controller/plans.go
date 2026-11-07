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
	"github.com/PurdueBlueTeam/phylax/internal/event"
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

// defaultMaxHostInflight keeps the controller below the agent's 8-step cap.
const defaultMaxHostInflight = 6

// defaultBusyRetry is the wait before a step answered busy is sent again.
const defaultBusyRetry = 2 * time.Second

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

// inflightRec identifies the step a node is waiting on. It is persisted before
// the step is sent so a restarted controller can ask the agent what became of it.
type inflightRec struct {
	Phase  string `json:"phase"`
	Epoch  uint64 `json:"epoch"`
	Seq    uint64 `json:"seq"`
	Digest string `json:"step_digest"`
}

type nodeRT struct {
	want      string // phase to dispatch next ("" = none)
	inflight  bool
	cur       *inflightRec // the step in flight (set with inflight)
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
	Refused bool   `json:"refused,omitempty"` // the agent's typed `rejected` status: the step never ran
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

	// holdUntil: after a controller restart, apply steps for hosts that have
	// not reconnected yet wait (instead of failing) until this time.
	holdUntil time.Time

	// probes is the plan's scorer-mimic probe grouping (Task 27); gates is the
	// gate: auto state; busyRetries counts consecutive busy answers per node.
	probes *probePlan
	// probeSrc is the plan before CreatePlan adds the plan-wide rollback
	// window; it keeps that window from splitting probe groups. Nil after a
	// restart, where the extra probes are safe.
	probeSrc    *plan.Plan
	gates       map[string]*gateRT
	busyRetries map[string]int
}

// probePlan is the probe grouping of one plan and its per-group progress.
type probePlan struct {
	groups []plan.ProbeGroup
	of     map[string]int
	st     []probeGroupRT
}

type probeGroupRT struct {
	before, after         bool
	beforeBusy, afterBusy bool
	failed                bool
}

// gateRT is the evaluation state of one gate: auto node.
type gateRT struct {
	start   time.Time
	timer   *time.Timer
	waiting bool
	probing bool
	probeOK bool
	checked bool
	failed  bool
}

type stepKey struct {
	host       string
	epoch, seq uint64
}

type pending struct {
	step    *plan.Step  // nil for a step recovered from the store after a restart
	exp     plan.Expect // what a result must answer
	queried bool        // a step_status query is outstanding
	rt      *planRT
	node    string
	phase   string
	timer   *time.Timer
	check   chan checkResult // check phase only
}

type checkResult struct {
	outcome, err string
	detail       []byte
	refused      bool // the agent's typed `rejected` status: the step never ran
}

func (c *Controller) catalog() registryCatalog { return registryCatalog{c.reg} }

// PlanPublicKey is the Ed25519 key agents must be bootstrapped with.
func (c *Controller) PlanPublicKey() ed25519.PublicKey {
	return c.planKey.Public().(ed25519.PublicKey)
}

func (c *Controller) signer(ctx context.Context) (*plan.Signer, error) {
	if err := c.requireUnlocked(); err != nil {
		return nil, err
	}
	if err := c.signingWaitErr(); err != nil {
		return nil, err
	}
	ep, err := c.st.Epoch(ctx)
	if err != nil {
		return nil, err
	}
	return &plan.Signer{Key: c.planKey, Epoch: ep, Seqs: seqAlloc{st: c.st}, Now: c.now}, nil
}

// CreatePlan validates a typed plan against the action catalog and stores it
// as a draft. For rollback_plan plans, nodes without a dead-man window get
// RollbackWindowSec so the agent keeps their rollback data.
func (c *Controller) CreatePlan(ctx context.Context, def plan.Plan, by string) error {
	p := def
	p.Nodes = append([]plan.Node(nil), def.Nodes...)
	for _, n := range p.Nodes {
		if n.ExpiresAfterSec <= 0 || n.Gate {
			continue
		}
		if a, err := c.reg.Get(n.Action); err == nil && a.Spec().OnController() {
			return fmt.Errorf("plan %s node %s: expires_after: controller-side action", p.ID, n.ID)
		}
	}
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
	probeSrc := def
	probeSrc.Nodes = append([]plan.Node(nil), def.Nodes...)
	rt := &planRT{c: c, p: &p, probeSrc: &probeSrc, run: run, state: PlanDraft, by: by, nodes: map[string]*nodeRT{}, hash: hash,
		created: c.now(), done: make(chan struct{}), gates: map[string]*gateRT{}, busyRetries: map[string]int{}}
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
	p, err := a.Spec().Validate(n.ActionParams())
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
		if nc, ok := c.localCheck(ctx, p.ID, p.Class, n); ok { // device / Splunk node: checked on the controller (devexec_run.go)
			checks = append(checks, nc)
			continue
		}
		ag := c.sessionFor(n.Target)
		if ag == nil {
			continue // missing
		}
		secrets, err := c.stepSecrets(n) // deception_plan.go: vault refs -> step secrets
		if err != nil {
			return plan.DryRun{}, err
		}
		st, err := sg.Issue(p, tmp, n.ID, plan.IssueOpts{Phase: plan.PhaseCheck, Validity: c.opt.StepValidity, Secrets: secrets})
		if err != nil {
			return plan.DryRun{}, err
		}
		exp, err := st.Expect()
		if err != nil {
			return plan.DryRun{}, err
		}
		pd := &pending{step: st, exp: exp, rt: rt, node: n.ID, phase: plan.PhaseCheck, check: make(chan checkResult, 1)}
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
	if err := c.requireUnlocked(); err != nil {
		return err
	}
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
	if ag.minor < link.MinSignedMinor {
		return fmt.Errorf("controller: agent %q speaks protocol minor %d; typed signed steps need %d", host, ag.minor, link.MinSignedMinor)
	}
	w := plan.StepToWire(pd.step)
	key := stepKey{host, pd.exp.Epoch, pd.exp.Seq}
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

// SendControl signs a control with the plan key (per-host control sequence,
// current epoch, short validity window) and sends it to a connected agent.
// Unsigned controls are refused by agents, so this is the only way to deliver one.
func (c *Controller) SendControl(ctx context.Context, host, kind string, on bool, args []byte) error {
	ag := c.sessionFor(host)
	if ag == nil {
		return fmt.Errorf("controller: agent %q is not connected", host)
	}
	return c.sendControl(ctx, ag, host, kind, on, args, false)
}

// sendControl signs and queues a control. Signing and queueing happen under one
// lock so controls reach the (FIFO) critical queue in sequence order; the agent
// refuses a control whose sequence number is not above the last it accepted.
func (c *Controller) sendControl(ctx context.Context, ag *agentConn, host, kind string, on bool, args []byte, try bool) error {
	if kind == plan.ControlDeadmanConfirm {
		if err := c.signingWaitErr(); err != nil {
			return err
		}
	}
	if ag.minor < link.MinSignedMinor {
		return fmt.Errorf("controller: agent %q speaks protocol minor %d; signed controls need %d", host, ag.minor, link.MinSignedMinor)
	}
	c.ctlMu.Lock()
	defer c.ctlMu.Unlock()
	ep, err := c.st.Epoch(ctx)
	if err != nil {
		return err
	}
	sg := &plan.ControlSigner{Key: c.planKey, Epoch: ep, Seqs: seqAlloc{st: c.st, prefix: "control/"}, Now: c.now, Validity: c.opt.ControlValidity}
	ctl, err := sg.Issue(host, kind, on, args)
	if err != nil {
		return err
	}
	w := plan.ControlToWire(ctl)
	if try {
		err = ag.sess.TrySend(link.PrioCritical, w)
	} else {
		err = ag.sess.Send(ctx, link.PrioCritical, w)
	}
	if err == nil && c.opt.OnControlSent != nil {
		c.opt.OnControlSent(host, w)
	}
	return err
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
		if pd.timer != nil {
			pd.timer.Stop()
		}
	}
	return pd
}

func (c *Controller) stepTimedOut(key stepKey) {
	if c.closed.Load() {
		return
	}
	pd := c.takePending(key)
	if pd == nil {
		return
	}
	c.log.Warn("step timed out", "host", key.host, "node", pd.node, "phase", pd.phase)
	c.planFailed(key.host, event.PlanFailed{Reason: event.ReasonStepTimeout, Plan: pd.rt.p.ID, Node: pd.node},
		fmt.Sprintf("%s %s/%s: no result", pd.rt.p.ID, pd.node, pd.phase))
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
	switch m.Status {
	case phyagent.StatusRejected:
		out = checkResult{outcome: plan.OutcomeFailed, err: "agent refused the step: " + m.Error, refused: true}
	case phyagent.StatusRunning, phyagent.StatusUnknown, phyagent.StatusLost:
		c.onStatusAnswer(ag, host, key, pd, m.Status)
		return
	default:
		res, err := c.verifyResult(ag, pd, m)
		if err != nil {
			c.planFailed(host, event.PlanFailed{Reason: event.ReasonBadResult, Plan: m.Plan, Node: m.Node},
				fmt.Sprintf("%s/%s: %v", m.Plan, m.Node, err))
			out = checkResult{outcome: plan.OutcomeFailed, err: "unverifiable result: " + err.Error()}
		} else {
			rec = res
			out = checkResult{outcome: res.Outcome, err: res.Error}
			if len(m.Detail) > 0 {
				if h := sha256.Sum256(m.Detail); hex.EncodeToString(h[:]) == res.AfterDigest {
					out.detail = m.Detail
				}
			}
		}
	}
	if c.opt.OnStepResult != nil && c.opt.OnStepResult(StepEvent{host, m.Plan, m.Node, pd.phase, out.outcome, out.err}) {
		// Fault injection: lose this result and the link. The pending step
		// stays registered and will be recovered by a query or time out.
		ag.sess.Close()
		return
	}
	if c.takePending(key) == nil {
		return
	}
	if out.outcome == plan.OutcomeBusy {
		if pd.phase == plan.PhaseCheck {
			out = checkResult{outcome: plan.OutcomeFailed, err: "agent busy"}
		} else {
			c.onBusy(pd)
			return
		}
	}
	c.deliver(pd, out, rec)
}

// maxBusyRetries bounds the re-sends of a node the agent answers busy.
const maxBusyRetries = 30

// onBusy re-queues a step the agent answered busy. It is a retry, never a
// failure: no on_failure policy, audit failure or auto breaker sees it.
func (c *Controller) onBusy(pd *pending) {
	rt := pd.rt
	rt.mu.Lock()
	defer rt.mu.Unlock()
	nr := rt.nodes[pd.node]
	if nr == nil || !nr.inflight {
		return
	}
	nr.inflight, nr.cur, nr.want = false, nil, pd.phase
	rt.busyRetries[pd.node]++
	if rt.busyRetries[pd.node] > maxBusyRetries {
		rt.failLocked(pd.node, "agent busy for 60 s", pd.phase)
		rt.advanceLocked()
		return
	}
	_ = rt.persistLocked(context.Background())
	time.AfterFunc(c.opt.BusyRetry, func() {
		rt.mu.Lock()
		rt.advanceLocked()
		rt.mu.Unlock()
	})
}

// onStatusAnswer handles the unsigned answers to a step_status query.
func (c *Controller) onStatusAnswer(ag *agentConn, host string, key stepKey, pd *pending, status string) {
	c.pmu.Lock()
	queried := pd.queried
	c.pmu.Unlock()
	if !queried || pd.phase != plan.PhaseApply {
		c.log.Debug("unsolicited step status", "host", host, "node", pd.node, "status", status)
		return
	}
	switch status {
	case phyagent.StatusRunning:
		// Still executing: look again shortly (the step timeout still bounds this).
		time.AfterFunc(500*time.Millisecond, func() { c.queryPending(key) })
	case phyagent.StatusUnknown:
		// The agent never accepted (epoch, seq): nothing was applied, so the
		// apply can be issued afresh with a new sequence number.
		if c.takePending(key) == nil {
			return
		}
		rt := pd.rt
		rt.mu.Lock()
		defer rt.mu.Unlock()
		if nr := rt.nodes[pd.node]; nr != nil && nr.inflight {
			nr.inflight, nr.cur, nr.want = false, nil, plan.PhaseApply
		}
		_ = rt.persistLocked(context.Background())
		rt.advanceLocked()
	case phyagent.StatusLost:
		// The agent accepted the step but has no result (it restarted mid-step).
		// Its dead-man journal says whether the change happened.
		if c.takePending(key) == nil {
			return
		}
		st := deadmanState(ag.dm, nodeKey(pd.rt.p.ID, pd.node))
		out := checkResult{outcome: plan.OutcomeFailed, err: "apply outcome lost: the agent restarted mid-step and has no record; its dead-man switch covers the change"}
		if st == dmArmed {
			out = checkResult{outcome: plan.OutcomeApplied, detail: []byte(`{"recovered":"result lost; dead-man entry armed; verify decides"}`)}
		}
		c.deliver(pd, out, nil)
	}
}

// queryPending asks the agent for the outcome of a step still pending.
func (c *Controller) queryPending(key stepKey) {
	if c.closed.Load() {
		return
	}
	c.pmu.Lock()
	pd := c.pend[key]
	c.pmu.Unlock()
	if pd == nil {
		return
	}
	ag := c.sessionFor(key.host)
	if ag == nil {
		return // asked again when the agent reconnects
	}
	args, _ := json.Marshal(map[string]any{"plan": pd.rt.p.ID, "node": pd.node, "phase": pd.phase, "epoch": key.epoch, "seq": key.seq})
	c.pmu.Lock()
	pd.queried = true
	c.pmu.Unlock()
	if err := c.sendControl(context.Background(), ag, key.host, plan.ControlStepStatus, false, args, true); err != nil {
		c.log.Warn("step status query failed", "host", key.host, "node", pd.node, "err", err)
	}
}

func nodeKey(planID, node string) string { return planID + ":" + node }

const (
	dmNone  = ""
	dmArmed = "armed"
	dmDone  = "confirmed"
	dmFired = "rolled_back"
)

// deadmanState summarises the agent's dead-man entries for one plan node: fired
// if any rolled back (or failed to), armed if any is still pending, else confirmed.
func deadmanState(entries []link.DeadmanEntry, key string) string {
	st := dmNone
	for _, e := range entries {
		if e.Node != key {
			continue
		}
		switch e.State {
		case "rolled_back", "rollback_failed":
			return dmFired
		case "armed":
			st = dmArmed
		case "confirmed":
			if st == dmNone {
				st = dmDone
			}
		}
	}
	return st
}

func (c *Controller) verifyResult(ag *agentConn, pd *pending, m *link.StepResult) (*plan.StepResult, error) {
	if ag.pub == nil {
		return nil, errors.New("no agent key")
	}
	res, err := plan.ResultFromWire(m)
	if err != nil {
		return nil, err
	}
	if err := res.VerifyExpect(ag.pub, pd.exp); err != nil {
		return nil, err
	}
	return res, nil
}

func (c *Controller) deliver(pd *pending, out checkResult, rec *plan.StepResult) {
	if pd.phase == plan.PhaseCheck {
		pd.check <- out
		return
	}
	rt := pd.rt
	rt.mu.Lock()
	defer rt.mu.Unlock()
	pr := phaseRec{Phase: pd.phase, Outcome: out.outcome, Error: out.err, Epoch: pd.exp.Epoch, Seq: pd.exp.Seq,
		AtMS: c.now().UnixMilli(), Detail: string(out.detail), Refused: out.refused}
	if rec != nil {
		pr.Digest, pr.Signed = rec.StepDigest, true
	}
	rt.onResultLocked(pd.node, pr)
}

// resume runs when a host's agent (re)connects. It re-queues steps that were
// in flight when the link dropped (verify, rollback: idempotent; apply: asks the
// agent for the outcome instead of re-sending, so a change is never applied
// twice), reconciles plan nodes with the agent's dead-man state reported in
// hello, and lets nodes waiting for a connection proceed.
func (c *Controller) resume(host string) {
	ag := c.sessionFor(host)
	c.pmu.Lock()
	var stale []*pending
	var asks []stepKey
	for k, pd := range c.pend {
		if k.host != host || pd.phase == plan.PhaseCheck {
			continue
		}
		if pd.phase == plan.PhaseApply {
			if pd.step == nil && !pd.queried && pd.timer != nil {
				// Recovered after a restart: the clock starts now that the agent is back.
				pd.timer.Reset(c.opt.StepTimeout)
			}
			asks = append(asks, k)
			continue
		}
		delete(c.pend, k)
		if pd.timer != nil {
			pd.timer.Stop()
		}
		stale = append(stale, pd)
	}
	rts := make([]*planRT, 0, len(c.plans))
	for _, rt := range c.plans {
		rts = append(rts, rt)
	}
	c.pmu.Unlock()
	for _, pd := range stale {
		pd.rt.mu.Lock()
		if nr := pd.rt.nodes[pd.node]; nr != nil && nr.inflight {
			nr.inflight, nr.cur, nr.want = false, nil, pd.phase
		}
		pd.rt.mu.Unlock()
	}
	for _, k := range asks {
		c.queryPending(k)
	}
	var dm []link.DeadmanEntry
	if ag != nil {
		dm = ag.dm
	}
	if ag != nil {
		for _, rt := range rts {
			rt.mu.Lock()
			rt.reconcileLocked(host, dm)
			rt.mu.Unlock()
		}
		ag.reconciled.Store(true)
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
	if rt.state != PlanRunning || rt.c.closed.Load() {
		return
	}
	rt.initProbesLocked()
	rt.evalAutoGatesLocked()
	if !rt.draining {
		for _, id := range rt.run.Next(plan.Limits{PerHost: rt.c.opt.MaxHostInflight}) {
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
		nr := rt.nodes[id]
		if nr.want == "" || nr.inflight {
			continue
		}
		if nr.want == plan.PhaseApply {
			if idx, ok := rt.probes.of[id]; ok && !rt.probes.st[idx].before {
				rt.startProbeLocked(idx, "before")
				continue
			}
		}
		rt.dispatchLocked(id, nr)
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
		if nr.failedIn == plan.PhaseRollback {
			continue // its rollback already failed and was reported; do not retry silently
		}
		if rt.run.State(id) == plan.StateFailed {
			if !nr.applyRan() {
				continue // a node that never applied has nothing to undo
			}
			if nr.failedIn == plan.PhaseApply {
				// The agent's executor already undid a failed apply, unless its
				// own rollback failed; then the failure is reported, not hidden.
				if nr.applyRollbackFailed() {
					rt.noteRollbackFailedLocked(id, "the agent's own undo of the failed apply failed")
				} else {
					_ = rt.run.MarkRolledBack(id)
				}
				continue
			}
		}
		nr.want, rt.rbBusy = plan.PhaseRollback, true
	}
}

// applyRan reports whether the node's apply step ran. A node failed before its
// apply left the controller has nothing to undo; a typed `rejected` result
// proves the agent refused the step without running it.
func (nr *nodeRT) applyRan() bool {
	if nr.failedIn == plan.PhaseVerify {
		return true
	}
	for _, pr := range nr.results {
		if pr.Phase == plan.PhaseApply && !pr.Refused {
			return true
		}
	}
	return false
}

// applyRollbackFailed reports whether the agent's typed result says that its
// own undo of a failed apply failed.
func (nr *nodeRT) applyRollbackFailed() bool {
	for _, pr := range nr.results {
		if pr.Phase == plan.PhaseApply && pr.Outcome == plan.OutcomeRollbackFailed {
			return true
		}
	}
	return false
}

// noteRollbackFailedLocked records and alerts a rollback that failed. The node
// stays failed; the plan is reported failed rather than silently rolled back.
func (rt *planRT) noteRollbackFailedLocked(id, why string) {
	rt.rbFailed = true
	nr := rt.nodes[id]
	nr.failedIn = plan.PhaseRollback
	nr.reason += " rollback failed: " + why
	rt.c.planFailed(rt.node(id).Target, event.PlanFailed{Reason: event.ReasonRollbackFailed, Plan: rt.p.ID, Node: id},
		fmt.Sprintf("%s/%s: %s", rt.p.ID, id, why))
}

func (rt *planRT) dispatchLocked(id string, nr *nodeRT) {
	c := rt.c
	n := rt.node(id)
	phase := nr.want
	if c.isLocalNode(n) { // device / Splunk node: runs on the controller (devexec_run.go)
		rt.dispatchLocalLocked(id, nr, n)
		return
	}
	if c.inflightSteps(n.Target) >= c.opt.MaxHostInflight {
		return // the slot frees on a result; onResultLocked advances again
	}
	ag := c.sessionFor(n.Target)
	if ag != nil && !ag.reconciled.Load() {
		return // resume reconciles the new session, then advances every plan
	}
	if ag == nil {
		if phase == plan.PhaseApply && !c.now().Before(rt.holdUntil) {
			rt.failLocked(id, "agent "+n.Target+" is not connected", plan.PhaseApply)
		}
		return // verify and rollback (and, just after a restart, apply) wait for the reconnect
	}
	ctx := context.Background()
	sg, err := c.signer(ctx)
	var st *plan.Step
	if err == nil {
		var secrets []byte
		if secrets, err = c.stepSecrets(n); err == nil { // deception_plan.go
			st, err = sg.Issue(rt.p, rt.run, id, plan.IssueOpts{Phase: phase, Validity: c.opt.StepValidity, Secrets: secrets})
		}
	}
	if err != nil {
		rt.failLocked(id, "cannot issue step: "+err.Error(), phase)
		return
	}
	exp, err := st.Expect()
	if err != nil {
		rt.failLocked(id, "cannot describe step: "+err.Error(), phase)
		return
	}
	pd := &pending{step: st, exp: exp, rt: rt, node: id, phase: phase}
	nr.inflight, nr.want = true, ""
	nr.cur = &inflightRec{Phase: phase, Epoch: exp.Epoch, Seq: exp.Seq, Digest: exp.Digest}
	// Durable before the step leaves: a crash after this point is recovered by
	// asking the agent about (epoch, seq).
	if err := rt.persistLocked(ctx); err != nil {
		nr.inflight, nr.cur = false, nil
		rt.failLocked(id, "cannot persist the plan: "+err.Error(), phase)
		return
	}
	if err := c.sendStep(ctx, ag, n.Target, pd); err != nil {
		nr.inflight, nr.cur = false, nil
		if phase == plan.PhaseApply {
			rt.failLocked(id, "cannot send step: "+err.Error(), phase)
		} else {
			nr.want = phase // retry after reconnect
		}
	}
}

func (rt *planRT) onResultLocked(id string, pr phaseRec) {
	delete(rt.busyRetries, id)
	nr := rt.nodes[id]
	nr.inflight, nr.cur = false, nil
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
			if idx, ok := rt.probes.of[id]; ok {
				if !rt.probes.st[idx].failed && rt.groupVerifiedLocked(idx) {
					if !rt.probes.st[idx].after {
						rt.startProbeLocked(idx, "after")
					} else {
						rt.confirmProbeGroupLocked(idx)
					}
				}
			} else if rt.policy() != plan.RollbackPlan {
				// Confirm now, unless the whole plan must succeed first.
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
			rt.noteRollbackFailedLocked(id, pr.Error)
		}
	}
	_ = rt.persistLocked(context.Background())
	rt.advanceLocked()
}

func (rt *planRT) failLocked(id, reason, phase string) {
	nr := rt.nodes[id]
	nr.inflight, nr.cur, nr.want = false, nil, ""
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

// confirmLocked tells the agent to disarm the node's dead-man switch (a signed
// control).
func (rt *planRT) confirmLocked(id string) {
	n := rt.node(id)
	nr := rt.nodes[id]
	if rt.c.isLocalNode(n) {
		return // no dead-man on controller-side nodes
	}
	if locked, _ := rt.c.Locked(); locked {
		return // no signing while locked: the agent's timer rolls the change back
	}
	if idx, ok := rt.probes.of[id]; ok && !rt.probes.st[idx].after {
		return // the confirm waits for the node's after-probe
	}
	if plan.EffectiveDeadmanSec(n, rt.run.Risk(id)) <= 0 {
		return
	}
	if n.ExpiresAfterSec > 0 {
		return // the expiry itself is the undo: the controller never confirms it
	}
	args, _ := json.Marshal(map[string]string{"plan": rt.p.ID, "node": id})
	ag := rt.c.sessionFor(n.Target)
	if ag == nil || rt.c.sendControl(context.Background(), ag, n.Target, plan.ControlDeadmanConfirm, true, args, true) != nil {
		rt.c.planFailed(n.Target, event.PlanFailed{Reason: event.ReasonConfirmFailed, Plan: rt.p.ID, Node: id},
			fmt.Sprintf("%s/%s: could not send dead-man confirm; the agent will roll back", rt.p.ID, id))
		return
	}
	nr.confirmed = true
}

// reconcileLocked compares this plan's nodes on host with the dead-man entries
// the agent reported in hello. A change whose dead-man switch fired while the
// controller was away is lost (rolled back) and the failure policy applies; an
// entry still armed for a verified node gets its confirm (again).
func (rt *planRT) reconcileLocked(host string, entries []link.DeadmanEntry) {
	if rt.state != PlanRunning {
		return
	}
	for _, n := range rt.p.Nodes {
		if n.Gate || n.Target != host {
			continue
		}
		id := n.ID
		nr := rt.nodes[id]
		st := deadmanState(entries, nodeKey(rt.p.ID, id))
		switch rt.run.State(id) {
		case plan.StateApplied, plan.StateVerified:
			switch {
			case st == dmFired:
				rt.lostLocked(id, "dead-man switch fired while the controller was not looking: the change was rolled back by the agent")
			case st == dmDone:
				nr.confirmed = true
			case st == dmArmed && rt.run.State(id) == plan.StateVerified && rt.policy() != plan.RollbackPlan:
				rt.confirmLocked(id)
			}
		}
	}
}

// lostLocked records that a node's change was undone behind the controller's
// back (its dead-man fired) and applies the plan's failure policy.
func (rt *planRT) lostLocked(id, reason string) {
	nr := rt.nodes[id]
	if nr.cur != nil {
		rt.c.dropPending(rt.p.ID, id)
	}
	nr.inflight, nr.cur, nr.want = false, nil, ""
	if err := rt.run.Lost(id, reason); err != nil {
		rt.c.log.Error("plan: cannot mark node lost", "plan", rt.p.ID, "node", id, "err", err)
		return
	}
	nr.failedIn, nr.reason = "deadman", reason
	rt.failed = true
	if rt.policy() == plan.RollbackPlan {
		rt.draining = true
	}
	rt.c.planFailed(rt.node(id).Target, event.PlanFailed{Reason: event.ReasonDeadmanFired, Plan: rt.p.ID, Node: id},
		fmt.Sprintf("%s/%s: %s", rt.p.ID, id, reason))
	_ = rt.persistLocked(context.Background())
}

// dropPending forgets any pending step of a node.
func (c *Controller) dropPending(planID, node string) {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	for k, pd := range c.pend {
		if pd.rt.p.ID == planID && pd.node == node {
			delete(c.pend, k)
			if pd.timer != nil {
				pd.timer.Stop()
			}
		}
	}
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
	if rt.probes != nil {
		for i := range rt.probes.groups {
			st := &rt.probes.st[i]
			if st.failed {
				continue
			}
			if st.beforeBusy || st.afterBusy {
				return
			}
			if rt.groupVerifiedLocked(i) && !st.after {
				rt.startProbeLocked(i, "after")
				return
			}
		}
	}
	switch {
	case rt.draining && !rt.rbFailed:
		rt.state = PlanRolledBack
	case rt.failed || rt.draining:
		rt.state = PlanFailed
	default:
		// Confirm before the final state is stored: a crash in between leaves
		// the plan running, and the restart sends the confirms again.
		if rt.policy() == plan.RollbackPlan {
			for _, n := range rt.p.Nodes {
				if !n.Gate && !rt.nodes[n.ID].confirmed {
					rt.confirmLocked(n.ID)
				}
			}
		}
		rt.state = PlanSucceeded
	}
	_ = rt.persistLocked(context.Background())
	close(rt.done)
	rt.c.snapshotSoon()
}

// ---- scorer-mimic probes (Task 27) ----

// initProbesLocked groups the plan's nodes that touch a manifest-scored
// service. It is lazy because the manifest may be loaded after the plan.
func (rt *planRT) initProbesLocked() {
	if rt.probes != nil {
		return
	}
	rt.probes = &probePlan{of: map[string]int{}}
	man, err := rt.c.currentManifest()
	if err != nil || man == nil {
		why := "no manifest"
		if err != nil {
			why = err.Error()
		}
		rt.probeGroupingFailedLocked("probe grouping: " + why)
		return
	}
	scored := map[string][]string{}
	locks := map[string][]string{}
	for _, n := range rt.p.Nodes {
		if n.Gate {
			continue
		}
		a, err := rt.c.reg.Get(n.Action)
		if err != nil {
			rt.probeGroupingFailedLocked("probe grouping: node " + n.ID + ": " + err.Error())
			if rt.p.Class == plan.ClassAuto {
				return
			}
			continue
		}
		params, err := a.Spec().Validate(n.ActionParams())
		if err != nil {
			rt.probeGroupingFailedLocked("probe grouping: node " + n.ID + ": " + err.Error())
			if rt.p.Class == plan.ClassAuto {
				return
			}
			continue
		}
		if svc := plan.ScoredTouch(man, n, a.Touches(params)); len(svc) > 0 {
			scored[n.ID] = svc
		}
		locks[n.ID] = a.Locks(params)
	}
	src := rt.p
	if rt.probeSrc != nil {
		src = rt.probeSrc
	}
	rt.probes.groups = plan.ProbeGroups(*src, scored, locks)
	rt.probes.st = make([]probeGroupRT, len(rt.probes.groups))
	for i, g := range rt.probes.groups {
		for _, id := range g.Nodes {
			rt.probes.of[id] = i
		}
	}
}

// probeGroupingFailedLocked fails an auto plan closed when its probe groups
// cannot be built. Other classes keep the old behaviour (no probes) and log.
func (rt *planRT) probeGroupingFailedLocked(reason string) {
	if rt.p.Class != plan.ClassAuto {
		rt.c.log.Warn("probe grouping: running without probes", "plan", rt.p.ID, "reason", reason)
		return
	}
	rt.c.log.Error("probe grouping: failing the auto plan closed", "plan", rt.p.ID, "reason", reason)
	applied := rt.anyAppliedLocked()
	for _, n := range rt.p.Nodes {
		switch rt.run.State(n.ID) {
		case plan.StatePending, plan.StateApproved:
			// A running node is still the agent's to finish (or to time out
			// through the normal step path); failing it here would roll back a
			// change that is still in flight.
			if err := rt.run.FailUnstarted(n.ID, reason); err != nil {
				rt.c.log.Error("probe grouping: cannot fail node", "plan", rt.p.ID, "node", n.ID, "err", err)
				continue
			}
			rt.nodes[n.ID].reason = reason
			break
		}
	}
	rt.failed = true
	if rt.policy() == plan.RollbackPlan && applied {
		rt.draining = true
	}
	_ = rt.persistLocked(context.Background())
}

// anyAppliedLocked reports whether any node has a change that needs undoing.
func (rt *planRT) anyAppliedLocked() bool {
	for _, n := range rt.p.Nodes {
		switch rt.run.State(n.ID) {
		case plan.StateApplied, plan.StateVerified, plan.StateFailed:
			return true
		}
	}
	return false
}

// startProbeLocked runs one group's before or after probe off the plan lock.
// One probe per group and phase: a second call while it is running is a no-op.
func (rt *planRT) startProbeLocked(idx int, phase string) {
	st := &rt.probes.st[idx]
	switch phase {
	case "before":
		if st.before || st.beforeBusy {
			return
		}
		st.beforeBusy = true
	case "after":
		if st.after || st.afterBusy {
			return
		}
		st.afterBusy = true
	default:
		return
	}
	services := append([]string(nil), rt.probes.groups[idx].Services...)
	c := rt.c
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err, svc := c.probeServices(ctx, services)
		rt.mu.Lock()
		defer rt.mu.Unlock()
		if phase == "before" {
			st.beforeBusy = false
		} else {
			st.afterBusy = false
		}
		if err != nil {
			rt.failProbeGroupLocked(idx, phase, svc, err)
		} else if phase == "before" {
			st.before = true
		} else {
			st.after = true
			rt.confirmProbeGroupLocked(idx)
		}
		rt.advanceLocked()
	}()
}

// probeServices runs the probe for every service, one retry after c.probeRetry.
// It returns the failing service (empty when green).
func (c *Controller) probeServices(ctx context.Context, services []string) (error, string) {
	if len(services) == 0 {
		return nil, ""
	}
	if c.opt.Probe == nil {
		return errors.New("probe cannot run"), services[0]
	}
	for _, s := range services {
		err := c.opt.Probe(ctx, s)
		if err != nil && c.probeRetry > 0 {
			select {
			case <-time.After(c.probeRetry):
			case <-ctx.Done():
				return ctx.Err(), s
			}
			err = c.opt.Probe(ctx, s)
		}
		if err != nil {
			return err, s
		}
	}
	return nil, ""
}

// failProbeGroupLocked fails the node that owns a red probe. A red after-probe
// rolls the group back through the plan's failure policy; a dead-man node
// without rollback_plan keeps its own timer as the undo.
func (rt *planRT) failProbeGroupLocked(idx int, phase, service string, err error) {
	reason := phase + "-probe red: " + service
	g := rt.probes.groups[idx]
	st := &rt.probes.st[idx]
	st.failed = true
	if phase == "before" {
		// The node is running but nothing was applied: fail it and leave the
		// rest to the failure policy.
		id := ""
		for _, nid := range g.Nodes {
			if s := rt.run.State(nid); s == plan.StateRunning || s == plan.StatePending || s == plan.StateApproved {
				id = nid
				break
			}
		}
		if id == "" {
			id = g.Nodes[0]
		}
		applied := rt.anyAppliedLocked()
		rt.failLocked(id, reason, phase)
		if !applied {
			// Nothing was applied: there is no rollback to run.
			rt.draining = false
		}
		_ = rt.persistLocked(context.Background())
		_ = err
		return
	}
	// A verified node cannot move to failed; the group's undo is the rollback,
	// and the reason stays on the node that was last verified.
	id := ""
	for i := len(g.Nodes) - 1; i >= 0; i-- {
		if rt.run.State(g.Nodes[i]) == plan.StateVerified {
			id = g.Nodes[i]
			break
		}
	}
	if id == "" {
		id = g.Nodes[0]
	}
	rt.nodes[id].reason = reason
	rt.failed = true
	if rt.policy() == plan.RollbackPlan {
		rt.draining = true
	} else {
		for _, nid := range g.Nodes {
			switch rt.run.State(nid) {
			case plan.StateApplied, plan.StateVerified:
				n := rt.node(nid)
				if plan.EffectiveDeadmanSec(n, rt.run.Risk(nid)) == 0 {
					rt.nodes[nid].want = plan.PhaseRollback
				}
			}
		}
	}
	_ = rt.persistLocked(context.Background())
	_ = err
}

// groupVerifiedLocked reports whether every node of the group has verified.
func (rt *planRT) groupVerifiedLocked(idx int) bool {
	for _, id := range rt.probes.groups[idx].Nodes {
		if rt.run.State(id) != plan.StateVerified {
			return false
		}
	}
	return true
}

// confirmProbeGroupLocked confirms the dead-man entries of a group whose
// after-probe passed. rollback_plan confirms at plan completion instead.
func (rt *planRT) confirmProbeGroupLocked(idx int) {
	if rt.policy() == plan.RollbackPlan {
		return
	}
	for _, id := range rt.probes.groups[idx].Nodes {
		if rt.run.State(id) == plan.StateVerified {
			rt.confirmLocked(id)
		}
	}
}

// inflightSteps counts the steps in flight to a host.
func (c *Controller) inflightSteps(host string) int {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	n := 0
	for k := range c.pend {
		if k.host == host {
			n++
		}
	}
	return n
}

// ---- persistence ----

type planBody struct {
	Plan      *plan.Plan               `json:"plan"`
	Hash      string                   `json:"hash"`
	By        string                   `json:"by"`
	Approvals map[string]plan.Approval `json:"approvals,omitempty"`
	DryRun    *plan.DryRun             `json:"dry_run,omitempty"`
	Failed    map[string]string        `json:"failed,omitempty"`
	Runtime   *runtimeSnap             `json:"runtime,omitempty"`
}

// runtimeSnap is the executor state persisted with the plan so a restarted
// controller can pick the run up where it was.
type runtimeSnap struct {
	Failed   bool                `json:"failed,omitempty"`
	Draining bool                `json:"draining,omitempty"`
	RbQueue  []string            `json:"rb_queue,omitempty"`
	RbBuilt  bool                `json:"rb_built,omitempty"`
	RbBusy   bool                `json:"rb_busy,omitempty"`
	RbFailed bool                `json:"rb_failed,omitempty"`
	Nodes    map[string]nodeSnap `json:"nodes"`
}

type nodeSnap struct {
	State     plan.State   `json:"state"`
	Want      string       `json:"want,omitempty"`
	Cur       *inflightRec `json:"in_flight,omitempty"`
	FailedIn  string       `json:"failed_in,omitempty"`
	Confirmed bool         `json:"confirmed,omitempty"`
	Reason    string       `json:"reason,omitempty"`
	Results   []phaseRec   `json:"results,omitempty"`
}

func (rt *planRT) persistLocked(ctx context.Context) error {
	c := rt.c
	if c.closed.Load() {
		return errors.New("controller: closed")
	}
	body := planBody{Plan: rt.p, Hash: rt.hash, By: rt.by, DryRun: rt.dry, Approvals: map[string]plan.Approval{}}
	for _, n := range rt.p.Nodes {
		if a, ok := rt.run.Approval(n.ID); ok {
			body.Approvals[n.ID] = a
		}
	}
	snap := &runtimeSnap{Failed: rt.failed, Draining: rt.draining, RbQueue: rt.rbQueue, RbBuilt: rt.rbBuilt,
		RbBusy: rt.rbBusy, RbFailed: rt.rbFailed, Nodes: map[string]nodeSnap{}}
	for _, n := range rt.p.Nodes {
		nr := rt.nodes[n.ID]
		snap.Nodes[n.ID] = nodeSnap{State: rt.run.State(n.ID), Want: nr.want, Cur: nr.cur, FailedIn: nr.failedIn,
			Confirmed: nr.confirmed, Reason: nr.reason, Results: nr.results}
	}
	body.Runtime = snap
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
