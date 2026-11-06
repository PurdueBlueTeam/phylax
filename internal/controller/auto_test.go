package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func TestRunAutoNeedsActEnabled(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: false\nautonomy: {t1: auto}\n")
	setHeartbeat(c, "h1", false, time.Now())
	_, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"})
	if !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "act_enabled") {
		t.Fatalf("got %v", err)
	}
	open, err := c.OpenProposals(ctx)
	if err != nil || len(open) != 1 || open[0].Module != "ctltest" || !strings.Contains(open[0].Reason, "act_enabled") {
		t.Fatalf("proposals %+v %v", open, err)
	}
}

func TestRunAutoProposesByDefault(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nautonomy: {other: auto}\n")
	setHeartbeat(c, "h1", false, time.Now())
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "propose") {
		t.Fatalf("got %v", err)
	}
	open, err := c.OpenProposals(ctx)
	if err != nil || len(open) != 1 || open[0].Module != "ctltest" {
		t.Fatalf("proposals %+v %v", open, err)
	}
}

func TestRunAutoShadowRecordsWithoutApplying(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nautonomy: {t1: shadow}\n")
	setHeartbeat(c, "h1", false, time.Now())
	id, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"})
	if err != nil || id == "" {
		t.Fatalf("%q %v", id, err)
	}
	d, err := c.PlanDetail(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.State != PlanDryRun || d.Plan.Class != plan.ClassAuto || d.Plan.Approver != "shadow:ctltest/t1" || d.DryRun == nil {
		t.Fatalf("shadow plan %+v", d)
	}
	if halted, err := ledgerOpen(c, "h1", "/etc/hosts", "t1"); halted || err != nil {
		t.Fatalf("shadow opened the ledger: %v %v", halted, err)
	}
	if _, err := c.st.MetaGet(ctx, autoLedgerKey("h1", "/etc/hosts", "t1")); !errors.Is(err, store.ErrNoMeta) {
		t.Fatalf("shadow touched the ledger: %v", err)
	}
	rows, err := c.st.Audit(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Action == "auto_shadow" && strings.Contains(r.Detail, "ctltest/t1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no shadow audit row: %+v", rows)
	}
}

func TestRunAutoUnknownSafeModeProposes(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nautonomy: {t1: auto}\n")
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
	c := newAutoController(t, "enabled: true\nact_enabled: true\nautonomy: {t2: auto, bad: auto}\n")
	setHeartbeat(c, "h1", false, time.Now())
	if _, err := c.RunAuto(ctx, "ctltest", "bad", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("host.exec: %v", err)
	}
	_, err := c.RunAuto(ctx, "ctltest", "t2", map[string]string{"host": "h1"})
	if !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "probe cannot run") {
		t.Fatalf("no probe: %v", err)
	}
}

func TestRunAutoFailsClosedOnStoreError(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nautonomy: {t1: auto}\n")
	setHeartbeat(c, "h1", false, time.Now())
	dead, cancel := context.WithCancel(ctx)
	cancel()
	_, err := c.RunAuto(dead, "ctltest", "t1", map[string]string{"host": "h1"})
	if err == nil || errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "auto ledger") {
		t.Fatalf("a breaker store error must fail the call, got %v", err)
	}
}

func TestRunAutoRefusesManifestSafeMode(t *testing.T) {
	for name, overrides := range map[string]string{
		"host":  "overrides:\n  safe_mode_hosts: [linux]\n",
		"fleet": "overrides:\n  safe_mode_hosts: [linux || windows]\n",
	} {
		t.Run(name, func(t *testing.T) {
			c := newAutoController(t, "enabled: true\nact_enabled: true\nautonomy: {t1: auto}\n",
				map[string]string{"overrides.yml": overrides})
			setHeartbeat(c, "h1", false, time.Now())
			_, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"})
			if !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "safe mode") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestRunAutoStarts(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nautonomy: {t1: auto}\n")
	c.opt.Probe = func(context.Context, string) error { return nil }
	setHeartbeat(c, "h1", false, time.Now())
	id, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1", "trigger": "h1:7"})
	if err != nil || id == "" {
		t.Fatalf("%q %v", id, err)
	}
	d, err := c.PlanDetail(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Plan.Class != plan.ClassAuto || d.Plan.OnFailure != plan.RollbackPlan ||
		d.Plan.Approver != "auto:ctltest/t1 trigger h1:7" {
		t.Fatalf("plan %+v", d.Plan)
	}
}
