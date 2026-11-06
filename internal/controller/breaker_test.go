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

func TestLedgerHaltsAfterTwoAttempts(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nautonomy: {t1: auto}\n")
	c.opt.Probe = func(context.Context, string) error { return nil }
	setHeartbeat(c, "h1", false, time.Now())
	now := time.Now()
	c.now = func() time.Time { return now }
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); err != nil {
		t.Fatalf("first attempt: %v", err)
	}
	now = now.Add(9 * time.Minute)
	setHeartbeat(c, "h1", false, now)
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); err != nil {
		t.Fatalf("second attempt: %v", err)
	}
	if halted, err := c.autoHalted(ctx, "h1", "/etc/hosts", "t1"); !halted || err != nil {
		t.Fatalf("the ledger did not trip: %v %v", halted, err)
	}
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "halted") {
		t.Fatalf("got %v", err)
	}
	e, err := c.st.Latest(ctx, "controller", event.KindPlanFailed)
	if err != nil || e.Priority != event.PriorityCritical || e.Fields["reason"] != event.ReasonAutoHalted ||
		e.Fields["object"] != "/etc/hosts" || e.Fields["kind"] != "t1" || e.Fields["trigger"] != "repeat" {
		t.Fatalf("%+v %v", e, err)
	}
	if err := c.ReenableAuto(ctx, "h1", "/etc/hosts", "t1", "driver"); err != nil {
		t.Fatal(err)
	}
	rows, err := c.st.Audit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Action == "auto_reenable" && r.Actor == "driver" && strings.Contains(r.Detail, "t1 on h1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit row for the re-enabling operator: %+v", rows)
	}
	now = now.Add(time.Second)
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); err != nil {
		t.Fatalf("after re-enable: %v", err)
	}
}

func TestLedgerWindow(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nautonomy: {t1: auto}\n")
	now := time.Now()
	if _, opened, err := c.noteAutoAttempt(ctx, "h1", "/etc/hosts", "t1", now); err != nil || opened {
		t.Fatalf("first attempt: %v %v", opened, err)
	}
	if _, opened, err := c.noteAutoAttempt(ctx, "h1", "/etc/hosts", "t1", now.Add(11*time.Minute)); err != nil || opened {
		t.Fatalf("attempt outside the window opened the breaker: %v %v", opened, err)
	}
	halted, err := c.autoHalted(ctx, "h1", "/etc/hosts", "t1")
	if err != nil || halted {
		t.Fatalf("autoHalted = %v, %v; want false, nil", halted, err)
	}
	if _, err := c.st.MetaGet(ctx, autoLedgerKey("h1", "/etc/hosts", "t1")); err != nil {
		t.Fatalf("the attempt was not persisted: %v", err)
	}
}
