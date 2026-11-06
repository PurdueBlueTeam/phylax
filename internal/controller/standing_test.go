package controller

import (
	"errors"
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
	t.Skip("unimplemented: W1 Task 24")
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
	t.Skip("unimplemented: W1 Task 24")
	c := newStandingController(t)
	_ = c.CreateStanding(ctx, sa())
	id, err := c.RunStanding(ctx, "ctltest", "s1", "dump", map[string]string{"host": "h1"})
	if err != nil || id == "" {
		t.Fatalf("%q %v", id, err)
	}
	// want: stored plan Class standing, Approver "Captain (standing s1)"
}

func TestRunStandingOutOfScopeProposes(t *testing.T) {
	t.Skip("unimplemented: W1 Task 24")
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

func TestRunStandingExpired(t *testing.T) {
	t.Skip("unimplemented: W1 Task 24")
	// insert s with Expires one second ahead via CreateStanding, wait until past, RunStanding -> ErrProposed
}
