package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func TestBreakerHaltsAfterTwoRollbacks(t *testing.T) {
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
	rows, err := c.st.Audit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Action == "auto_reenable" && r.Actor == "driver" && strings.Contains(r.Detail, "ctltest/t1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit row for the re-enabling operator: %+v", rows)
	}
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); err != nil {
		t.Fatalf("after re-enable: %v", err)
	}
}

func TestBreakerWindow(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n")
	now := time.Now()
	c.noteAutoRollback("ctltest", "t1", "h1", now)
	c.noteAutoRollback("ctltest", "t1", "h1", now.Add(11*time.Minute))
	if _, err := c.st.MetaGet(ctx, autoHaltedKey("ctltest", "t1", "h1")); !errors.Is(err, store.ErrNoMeta) {
		t.Fatalf("the breaker halted outside its window: %v", err)
	}
	if c.autoHalted(ctx, "ctltest", "t1", "h1") {
		t.Fatal("autoHalted reports a halt outside the window")
	}
}
