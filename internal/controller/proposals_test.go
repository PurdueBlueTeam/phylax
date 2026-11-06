package controller

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/module"
)

func TestProposeAndAccept(t *testing.T) {
	t.Skip("unimplemented: W1 Task 25")
	c := newTestControllerWithPlans(t, map[string]string{"ctltest/fix.yml": "id: fix\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: a, action: file.hash, target: '${host}', params: {path: /etc/hosts}}\n"})
	id, err := c.Propose(ctx, module.Proposal{Module: "ctltest", Title: "hash hosts", Template: "fix", Params: map[string]string{"host": "h1"}, Reason: "tier 1",
		Evidence: []module.EventRef{{Agent: "h1", Seq: 7}}})
	if err != nil {
		t.Fatal(err)
	}
	planID, err := c.AcceptProposal(ctx, id, "driver")
	if err != nil || planID == "" {
		t.Fatalf("%q %v", planID, err)
	}
	// want: the plan's Class is click and Approver "driver"; the row is accepted with plan_id; OpenProposals is empty
	if _, err := c.AcceptProposal(ctx, id, "driver"); err == nil {
		t.Fatal("accepted twice")
	}
}

func TestProposeRejectsBrokenTemplate(t *testing.T) {
	t.Skip("unimplemented: W1 Task 25")
	c := newTestControllerWithPlans(t, nil)
	if _, err := c.Propose(ctx, module.Proposal{Module: "ctltest", Title: "x", Template: "missing"}); err == nil {
		t.Fatal("missing template accepted")
	}
}

func TestRunStandingFallbackRecordsProposal(t *testing.T) {
	t.Skip("unimplemented: W1 Task 25")
	// as TestRunStandingOutOfScopeProposes; then OpenProposals has one row with Module "ctltest" and a Reason naming "targets"
}
