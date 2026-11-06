package main

import (
	"context"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

func saveTestBundle(t *testing.T, dir string) agent.Layout {
	t.Helper()
	l := agent.Layout{Root: dir}
	if err := l.Ensure(); err != nil {
		t.Fatal(err)
	}
	b := &agent.Bundle{
		Controllers:   []string{"10.0.0.1:7443"},
		ControllerPin: link.Pin{1}.String(),
		Host:          "h1",
		PlanKey:       strings.Repeat("ab", 32),
	}
	if err := l.SaveBundle(b); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestSetControllerCommand(t *testing.T) {
	dir := t.TempDir()
	l := saveTestBundle(t, dir)
	if err := commands["set-controller"].run(context.Background(), []string{"-state-dir", dir, "10.9.9.9:7443"}); err != nil {
		t.Fatal(err)
	}
	b, err := l.LoadBundle()
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Controllers) != 1 || b.Controllers[0] != "10.9.9.9:7443" {
		t.Fatalf("Controllers = %v", b.Controllers)
	}
	if b.Host != "h1" || b.PlanKey != strings.Repeat("ab", 32) {
		t.Fatalf("the command changed other fields: %+v", b)
	}

	// A comma list and an explicit pin.
	pin := link.Pin{9}.String()
	if err := commands["set-controller"].run(context.Background(),
		[]string{"-state-dir", dir, "-pin", pin, "10.9.9.9:7443,10.9.9.10:7443"}); err != nil {
		t.Fatal(err)
	}
	b, err = l.LoadBundle()
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Controllers) != 2 || b.ControllerPin != pin {
		t.Fatalf("Controllers = %v pin = %q", b.Controllers, b.ControllerPin)
	}

	if err := commands["set-controller"].run(context.Background(), []string{"-state-dir", dir}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("missing address err = %v, want a usage error", err)
	}
}
