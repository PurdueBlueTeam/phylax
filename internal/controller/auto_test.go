package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/module"
)

func TestRunAutoNeedsActEnabled(t *testing.T) {
	t.Skip("unimplemented: W1 Task 26")
	c := newAutoController(t, "enabled: true\nact_enabled: false\nauto: [t1]\n")
	setHeartbeat(c, "h1", false, time.Now())
	_, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"})
	if !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "act_enabled") {
		t.Fatalf("got %v", err)
	}
}

func TestRunAutoNotOnAllowlist(t *testing.T) {
	t.Skip("unimplemented: W1 Task 26")
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [other]\n")
	setHeartbeat(c, "h1", false, time.Now())
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("got %v", err)
	}
}

func TestRunAutoUnknownSafeModeProposes(t *testing.T) {
	t.Skip("unimplemented: W1 Task 26")
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n")
	c.opt.Probe = func(context.Context, string) error { return nil }
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("no heartbeat: %v", err)
	}
	setHeartbeat(c, "h1", true, time.Now())
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("safe mode on: %v", err)
	}
	setHeartbeat(c, "h1", false, time.Now().Add(-time.Minute))
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("stale heartbeat: %v", err)
	}
}

func TestRunAutoLintAndProbe(t *testing.T) {
	t.Skip("unimplemented: W1 Task 26")
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t2, bad]\n")
	setHeartbeat(c, "h1", false, time.Now())
	if _, err := c.RunAuto(ctx, "ctltest", "bad", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("host.exec: %v", err)
	}
	_, err := c.RunAuto(ctx, "ctltest", "t2", map[string]string{"host": "h1"})
	if !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "probe cannot run") {
		t.Fatalf("no probe: %v", err)
	}
}

func TestRunAutoStarts(t *testing.T) {
	t.Skip("unimplemented: W1 Task 26")
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n")
	c.opt.Probe = func(context.Context, string) error { return nil }
	setHeartbeat(c, "h1", false, time.Now())
	id, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1", "trigger": "h1:7"})
	if err != nil || id == "" {
		t.Fatalf("%q %v", id, err)
	}
	// want: stored plan Class auto, OnFailure rollback_plan, Approver "auto:ctltest/t1 trigger h1:7"
}
