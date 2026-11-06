package controller

import (
	"errors"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func TestProposeAndAccept(t *testing.T) {
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
	d, err := c.PlanDetail(planID)
	if err != nil || d.Plan.Class != plan.ClassClick || d.Plan.Approver != "driver" {
		t.Fatalf("plan %+v %v", d, err)
	}
	row, err := c.st.Proposal(ctx, id)
	if err != nil || row.State != "accepted" || row.PlanID != planID {
		t.Fatalf("row %+v %v", row, err)
	}
	open, err := c.OpenProposals(ctx)
	if err != nil || len(open) != 0 {
		t.Fatalf("open %+v %v", open, err)
	}
	if _, err := c.AcceptProposal(ctx, id, "driver"); err == nil {
		t.Fatal("accepted twice")
	}
}

func TestProposeRejectsBrokenTemplate(t *testing.T) {
	c := newTestControllerWithPlans(t, nil)
	if _, err := c.Propose(ctx, module.Proposal{Module: "ctltest", Title: "x", Template: "missing"}); err == nil {
		t.Fatal("missing template accepted")
	}
}

func TestRunStandingFallbackRecordsProposal(t *testing.T) {
	c := newStandingController(t)
	s := sa()
	s.Targets = "windows"
	if err := c.CreateStanding(ctx, s); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RunStanding(ctx, "ctltest", "s1", "dump", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("got %v", err)
	}
	open, err := c.OpenProposals(ctx)
	if err != nil || len(open) != 1 {
		t.Fatalf("open %+v %v", open, err)
	}
	if open[0].Module != "ctltest" || !strings.Contains(open[0].Reason, "targets") {
		t.Fatalf("row %+v", open[0])
	}
}
