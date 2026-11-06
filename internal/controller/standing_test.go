package controller

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func sa() plan.StandingApproval {
	return plan.StandingApproval{ID: "s1", Module: "ctltest", Template: "dump", Targets: "linux", Actions: []string{"file.hash"},
		Expires: time.Now().Add(time.Hour), Approver: "Captain", Created: "admin"}
}

func TestCreateStandingValidates(t *testing.T) {
	c := newStandingController(t)
	for i, f := range []func(*plan.StandingApproval){
		func(s *plan.StandingApproval) { s.Expires = time.Time{} },
		func(s *plan.StandingApproval) { s.Expires = time.Now().Add(73 * time.Hour) },
		func(s *plan.StandingApproval) { s.Actions = []string{"host.exec"} },
		func(s *plan.StandingApproval) { s.Approver = "" },
		func(s *plan.StandingApproval) { s.Targets = "linux &&" },
	} {
		s := sa()
		f(&s)
		if c.CreateStanding(ctx, s) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if err := c.CreateStanding(ctx, sa()); err != nil {
		t.Fatal(err)
	}
}

func TestRunStandingInScope(t *testing.T) {
	c := newStandingController(t)
	_ = c.CreateStanding(ctx, sa())
	id, err := c.RunStanding(ctx, "ctltest", "s1", "dump", map[string]string{"host": "h1"})
	if err != nil || id == "" {
		t.Fatalf("%q %v", id, err)
	}
	d, err := c.PlanDetail(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Plan.Class != plan.ClassStanding || d.Plan.Approver != "Captain (standing s1)" {
		t.Fatalf("plan %+v", d)
	}
	if n := d.Nodes["a"]; n.Approval == nil {
		t.Fatalf("node was not approved: %+v", n)
	}
}

func TestRunStandingOutOfScopeProposes(t *testing.T) {
	c := newStandingController(t)
	s := sa()
	s.Targets = "windows"
	_ = c.CreateStanding(ctx, s)
	if _, err := c.RunStanding(ctx, "ctltest", "s1", "dump", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("got %v", err)
	}
	_ = c.RevokeStanding(ctx, "s1", "admin")
	if _, err := c.RunStanding(ctx, "ctltest", "s1", "dump", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("revoked: %v", err)
	}
}

func TestRunStandingRevokedProposes(t *testing.T) {
	c := newStandingController(t)
	if err := c.CreateStanding(ctx, sa()); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeStanding(ctx, "s1", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RunStanding(ctx, "ctltest", "s1", "dump", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("got %v", err)
	}
	open, err := c.OpenProposals(ctx)
	if err != nil || len(open) != 1 {
		t.Fatalf("open %+v %v", open, err)
	}
	if !strings.Contains(open[0].Reason, "revoked") {
		t.Fatalf("reason %q does not name the revocation", open[0].Reason)
	}
}

func TestRevokeStandingAuditsOperator(t *testing.T) {
	c := newStandingController(t)
	if err := c.CreateStanding(ctx, sa()); err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeStanding(ctx, "s1", "  "); err == nil {
		t.Fatal("revocation without an operator accepted")
	}
	if got, err := c.st.Standing(ctx, "s1"); err != nil || got.Revoked {
		t.Fatalf("a refused revocation changed the approval: %+v %v", got, err)
	}
	if err := c.RevokeStanding(ctx, "s1", "net-op"); err != nil {
		t.Fatal(err)
	}
	if got, err := c.st.Standing(ctx, "s1"); err != nil || !got.Revoked {
		t.Fatalf("standing approval not revoked: %+v %v", got, err)
	}
	rows, err := c.st.Audit(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Action == "standing_revoke" && r.Actor == "net-op" && strings.Contains(r.Detail, "s1") {
			return
		}
	}
	t.Fatalf("no audit row for the revoking operator: %+v", rows)
}

func TestRunStandingExpired(t *testing.T) {
	c := newStandingController(t)
	s := sa()
	s.Expires = time.Now().Add(time.Second)
	if err := c.CreateStanding(ctx, s); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := c.RunStanding(ctx, "ctltest", "s1", "dump", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("got %v", err)
	}
	open, err := c.OpenProposals(ctx)
	if err != nil || len(open) != 1 || !strings.Contains(open[0].Reason, "expired") {
		t.Fatalf("open %+v %v", open, err)
	}
}
