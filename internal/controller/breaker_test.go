package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
)

func TestBreakerHaltsAfterTwoRollbacks(t *testing.T) {
	t.Skip("unimplemented: W1 Task 28")
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n")
	c.opt.Probe = func(context.Context, string) error { return nil }
	setHeartbeat(c, "h1", false, time.Now())
	now := time.Now()
	c.noteAutoRollback("ctltest", "t1", "h1", now)
	c.noteAutoRollback("ctltest", "t1", "h1", now.Add(9*time.Minute))
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "halted") {
		t.Fatalf("got %v", err)
	}
	e, err := c.st.Latest(ctx, "controller", "plan.auto_halted")
	if err != nil || e.Priority != event.PriorityCritical {
		t.Fatalf("%+v %v", e, err)
	}
	_ = c.ReenableAuto(ctx, "ctltest", "t1", "h1", "driver")
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); err != nil {
		t.Fatalf("after re-enable: %v", err)
	}
}

func TestBreakerWindow(t *testing.T) {
	t.Skip("unimplemented: W1 Task 28")
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n")
	now := time.Now()
	c.noteAutoRollback("ctltest", "t1", "h1", now)
	c.noteAutoRollback("ctltest", "t1", "h1", now.Add(11*time.Minute))
	// want: not halted (kv key absent)
}
