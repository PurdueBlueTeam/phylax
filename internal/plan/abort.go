package plan

// Abort stops the run for an operator-requested rollback: every node that has
// not started (pending or approved) is skipped, so the run can finish once the
// started nodes have been rolled back (RollbackOrder).
func (r *Run) Abort() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.plan.Nodes {
		if s := r.state[n.ID]; s == StatePending || s == StateApproved {
			r.state[n.ID] = StateSkipped
		}
	}
}
