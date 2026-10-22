package plan

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// State is a node's lifecycle state.
type State string

const (
	StatePending    State = "pending"
	StateApproved   State = "approved"
	StateRunning    State = "running"
	StateApplied    State = "applied"
	StateVerified   State = "verified"
	StateFailed     State = "failed"
	StateRolledBack State = "rolled_back"
	StateSkipped    State = "skipped" // never ran because a dependency failed or the plan stopped
)

func (s State) terminal() bool {
	switch s {
	case StateVerified, StateFailed, StateRolledBack, StateSkipped:
		return true
	}
	return false
}

var allowed = map[State][]State{
	StatePending:  {StateApproved, StateSkipped},
	StateApproved: {StateRunning, StateVerified /* gates */, StateSkipped},
	StateRunning:  {StateApplied, StateFailed},
	StateApplied:  {StateVerified, StateFailed, StateRolledBack},
	StateVerified: {StateRolledBack},
	StateFailed:   {StateRolledBack},
}

// ErrTransition is returned for an illegal state change.
var ErrTransition = errors.New("plan: illegal state transition")

// Limits bounds scheduling.
type Limits struct {
	PerHost int // max concurrently running nodes per host; <=0 means 1
	// HeldExternally reports a lock held outside this run (e.g. a tier-0
	// response); nodes needing it wait.
	HeldExternally func(host, lock string) bool
}

// Run is the mutable execution state of one validated Plan. Safe for concurrent use.
type Run struct {
	mu        sync.Mutex
	plan      *Plan
	res       *resolved
	state     map[string]State
	approvals map[string]Approval
	reason    map[string]string
}

// NewRun validates the plan and returns a Run with all nodes pending.
func NewRun(p *Plan, cat Catalog) (*Run, error) {
	res, err := p.resolve(cat)
	if err != nil {
		return nil, err
	}
	r := &Run{plan: p, res: res, state: map[string]State{}, approvals: map[string]Approval{}, reason: map[string]string{}}
	for _, n := range p.Nodes {
		r.state[n.ID] = StatePending
	}
	return r, nil
}

func (r *Run) node(id string) (Node, bool) {
	i, ok := r.res.byID[id]
	if !ok {
		return Node{}, false
	}
	return r.plan.Nodes[i], true
}

// ApprovePlan is the one-click approval: it approves every pending node that
// does not need its own record, and records the approval on each.
func (r *Run) ApprovePlan(by string, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.plan.Nodes {
		if r.state[n.ID] == StatePending && !RequiresOwnApproval(n, r.res.risk[n.ID]) {
			r.state[n.ID] = StateApproved
			r.approvals[n.ID] = Approval{By: by, At: at.Unix()}
		}
	}
}

// ApproveNode approves one node (required for gates, host.exec, lockout and
// destructive nodes).
func (r *Run) ApproveNode(id string, a Approval) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.node(id); !ok {
		return fmt.Errorf("plan: unknown node %q", id)
	}
	if a.By == "" {
		return errors.New("plan: approval needs an approver")
	}
	if err := r.move(id, StateApproved); err != nil {
		return err
	}
	r.approvals[id] = a
	return nil
}

// Approval returns the approval record for a node.
func (r *Run) Approval(id string) (Approval, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.approvals[id]
	return a, ok
}

// State returns a node's state.
func (r *Run) State(id string) State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state[id]
}

// Snapshot copies all node states.
func (r *Run) Snapshot() map[string]State {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := make(map[string]State, len(r.state))
	for k, v := range r.state {
		m[k] = v
	}
	return m
}

func (r *Run) move(id string, to State) error {
	from := r.state[id]
	for _, ok := range allowed[from] {
		if ok == to {
			r.state[id] = to
			return nil
		}
	}
	return fmt.Errorf("%w: %s %s -> %s", ErrTransition, id, from, to)
}

func (r *Run) depsDone(n Node) bool {
	for _, d := range n.Needs {
		s := r.state[d]
		if s == StateVerified {
			continue
		}
		if s == StateFailed && r.plan.policy() == Continue {
			continue
		}
		return false
	}
	return true
}

// Next returns, and marks running, every node that can start now: approved,
// dependencies done, within the per-host limit, and with its locks free. Gate
// nodes whose dependencies are done and which are approved complete at once.
// The order is deterministic (topological, then ID).
func (r *Run) Next(lim Limits) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	per := lim.PerHost
	if per <= 0 {
		per = 1
	}
	running := map[string]int{}
	held := map[string]map[string]bool{}
	for _, n := range r.plan.Nodes {
		if r.state[n.ID] == StateRunning {
			running[n.Target]++
			for _, l := range r.res.spec[n.ID].Locks {
				if held[n.Target] == nil {
					held[n.Target] = map[string]bool{}
				}
				held[n.Target][l] = true
			}
		}
	}
	var out []string
	for changed := true; changed; { // gates can unblock more gates
		changed = false
		for _, id := range r.res.order {
			n, _ := r.node(id)
			if r.state[id] != StateApproved || !r.depsDone(n) {
				continue
			}
			if n.Gate {
				r.state[id] = StateVerified
				changed = true
				continue
			}
			if running[n.Target] >= per {
				continue
			}
			blocked := false
			for _, l := range r.res.spec[id].Locks {
				if held[n.Target][l] || (lim.HeldExternally != nil && lim.HeldExternally(n.Target, l)) {
					blocked = true
					break
				}
			}
			if blocked {
				continue
			}
			r.state[id] = StateRunning
			running[n.Target]++
			for _, l := range r.res.spec[id].Locks {
				if held[n.Target] == nil {
					held[n.Target] = map[string]bool{}
				}
				held[n.Target][l] = true
			}
			out = append(out, id)
		}
	}
	return out
}

// MarkApplied records that the apply phase succeeded.
func (r *Run) MarkApplied(id string) error { return r.set(id, StateApplied) }

// MarkVerified records that verify succeeded; dependents may now run.
func (r *Run) MarkVerified(id string) error { return r.set(id, StateVerified) }

// MarkRolledBack records a completed rollback.
func (r *Run) MarkRolledBack(id string) error { return r.set(id, StateRolledBack) }

func (r *Run) set(id string, s State) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.node(id); !ok {
		return fmt.Errorf("plan: unknown node %q", id)
	}
	return r.move(id, s)
}

// Restore replaces the run's node states, reasons and approvals with persisted
// ones (controller restart). Every node must be known; states are taken as is.
func (r *Run) Restore(states map[string]State, reasons map[string]string, approvals map[string]Approval) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, st := range states {
		if _, ok := r.node(id); !ok {
			return fmt.Errorf("plan: restore: unknown node %q", id)
		}
		switch st {
		case StatePending, StateApproved, StateRunning, StateApplied, StateVerified, StateFailed, StateRolledBack, StateSkipped:
		default:
			return fmt.Errorf("plan: restore: node %q has unknown state %q", id, st)
		}
		r.state[id] = st
	}
	for id, why := range reasons {
		r.reason[id] = why
	}
	for id, a := range approvals {
		r.approvals[id] = a
	}
	return nil
}

// Lost records that an applied or verified node's change was undone outside
// the run (its dead-man switch fired while the controller was away): the node
// becomes rolled back and the failure policy applies to nodes not yet started.
func (r *Run) Lost(id, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.node(id); !ok {
		return fmt.Errorf("plan: unknown node %q", id)
	}
	if err := r.move(id, StateRolledBack); err != nil {
		return err
	}
	r.reason[id] = reason
	r.applyPolicy(id)
	return nil
}

// Fail marks a node failed and applies the plan's failure policy to the
// nodes that have not started.
func (r *Run) Fail(id, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.node(id); !ok {
		return fmt.Errorf("plan: unknown node %q", id)
	}
	if err := r.move(id, StateFailed); err != nil {
		return err
	}
	r.reason[id] = reason
	r.applyPolicy(id)
	return nil
}

func (r *Run) applyPolicy(id string) {
	switch r.plan.policy() {
	case StopDependents:
		dep := r.dependentsOf(id)
		for _, n := range r.plan.Nodes {
			if dep[n.ID] && (r.state[n.ID] == StatePending || r.state[n.ID] == StateApproved) {
				r.state[n.ID] = StateSkipped
			}
		}
	case RollbackPlan:
		for _, n := range r.plan.Nodes {
			if r.state[n.ID] == StatePending || r.state[n.ID] == StateApproved {
				r.state[n.ID] = StateSkipped
			}
		}
	}
}

func (r *Run) dependentsOf(id string) map[string]bool {
	out := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, n := range r.plan.Nodes {
			if out[n.ID] {
				continue
			}
			for _, d := range n.Needs {
				if d == id || out[d] {
					out[n.ID] = true
					changed = true
					break
				}
			}
		}
	}
	return out
}

// RollbackOrder lists nodes that changed state on hosts (applied, verified or
// failed after a partial apply) in reverse topological order, for the
// rollback_plan policy or a manual rollback.
func (r *Run) RollbackOrder() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for i := len(r.res.order) - 1; i >= 0; i-- {
		id := r.res.order[i]
		n, _ := r.node(id)
		if n.Gate {
			continue
		}
		switch r.state[id] {
		case StateApplied, StateVerified, StateFailed:
			out = append(out, id)
		}
	}
	return out
}

// Done reports whether every node is terminal.
func (r *Run) Done() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.state {
		if !s.terminal() {
			return false
		}
	}
	return true
}

// FailureReason returns the recorded reason for a failed node.
func (r *Run) FailureReason(id string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reason[id]
}

// Risk returns a node's effective risk.
func (r *Run) Risk(id string) Risk { return r.res.risk[id] }

// NodeCheck is one agent's dry-run report for a node.
type NodeCheck struct {
	NodeID     string
	WillChange bool
	Diff       string // readable diff
	LintReject string // non-empty: the scoring-safety lint rejects the node
}

// DryRunNode is a node's row in the aggregated dry run.
type DryRunNode struct {
	NodeID     string
	Host       string
	Action     string
	Status     string // unchanged | will_change | blocked | rejected | missing
	Diff       string
	Reason     string
	NeedsOwnOK bool
}

// DryRun is the aggregated plan diff the UI shows before approval.
type DryRun struct {
	Nodes      []DryRunNode // topological order
	Counts     map[string]int
	Approvable bool // no rejected, blocked or missing nodes
}

// AggregateDryRun combines per-node checks. A node whose lock is held
// externally is "blocked"; a node with no check is "missing" and stops approval.
func (r *Run) AggregateDryRun(checks []NodeCheck, lim Limits) DryRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	by := map[string]NodeCheck{}
	for _, c := range checks {
		by[c.NodeID] = c
	}
	dr := DryRun{Counts: map[string]int{}, Approvable: true}
	for _, id := range r.res.order {
		n, _ := r.node(id)
		row := DryRunNode{NodeID: id, Host: n.Target, Action: n.Action, NeedsOwnOK: RequiresOwnApproval(n, r.res.risk[id])}
		switch c, ok := by[id]; {
		case n.Gate:
			row.Status = "unchanged"
		case !ok:
			row.Status, row.Reason = "missing", "no check result"
		case c.LintReject != "":
			row.Status, row.Reason = "rejected", c.LintReject
		case r.lockHeld(n, lim):
			row.Status, row.Reason = "blocked", "resource lock held"
		case c.WillChange:
			row.Status, row.Diff = "will_change", c.Diff
		default:
			row.Status = "unchanged"
		}
		if row.Status == "rejected" || row.Status == "blocked" || row.Status == "missing" {
			dr.Approvable = false
		}
		dr.Counts[row.Status]++
		dr.Nodes = append(dr.Nodes, row)
	}
	return dr
}

func (r *Run) lockHeld(n Node, lim Limits) bool {
	if lim.HeldExternally == nil {
		return false
	}
	for _, l := range r.res.spec[n.ID].Locks {
		if lim.HeldExternally(n.Target, l) {
			return true
		}
	}
	return false
}

// Hosts lists the distinct target hosts, sorted.
func (p *Plan) Hosts() []string {
	m := map[string]bool{}
	for _, n := range p.Nodes {
		if !n.Gate {
			m[n.Target] = true
		}
	}
	out := make([]string, 0, len(m))
	for h := range m {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
