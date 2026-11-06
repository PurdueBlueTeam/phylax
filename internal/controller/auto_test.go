package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func TestRunAutoNeedsActEnabled(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: false\nauto: [t1]\n")
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

func TestRunAutoNotOnAllowlist(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [other]\n")
	setHeartbeat(c, "h1", false, time.Now())
	if _, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"}); !errors.Is(err, module.ErrProposed) {
		t.Fatalf("got %v", err)
	}
}

func TestRunAutoUnknownSafeModeProposes(t *testing.T) {
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

func TestRunAutoFailsClosedOnStoreError(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n")
	setHeartbeat(c, "h1", false, time.Now())
	dead, cancel := context.WithCancel(ctx)
	cancel()
	_, err := c.RunAuto(dead, "ctltest", "t1", map[string]string{"host": "h1"})
	if err == nil || errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "auto breaker") {
		t.Fatalf("a breaker store error must fail the call, got %v", err)
	}
}

func TestRunAutoRefusesManifestSafeMode(t *testing.T) {
	for name, overrides := range map[string]string{
		"host":  "overrides:\n  safe_mode_hosts: [linux]\n",
		"fleet": "overrides:\n  safe_mode_hosts: [linux || windows]\n",
	} {
		t.Run(name, func(t *testing.T) {
			c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n",
				map[string]string{"overrides.yml": overrides})
			setHeartbeat(c, "h1", false, time.Now())
			_, err := c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"})
			if !errors.Is(err, module.ErrProposed) || !strings.Contains(err.Error(), "safe mode") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestRunAutoStartIsAtomicPerTemplate(t *testing.T) {
	plans := map[string]string{
		"ctltest/t1.yml": "id: t1\nmodule: ctltest\nnodes:\n  - {id: a, action: file.hash, target: '${host}', params: {path: /etc/hostname}}\n  - {id: g, gate: auto, needs: [a], until: {after: 60m}}\n",
	}
	x := newPlanCtl(t, autoProbeFiles(), plans, Options{GatePoll: 10 * time.Millisecond})
	stepClock(x.c)
	_, root := newPlanAgent(t, x, "h1")
	writeAgentFile(t, root, "/etc/hostname", "h1\n")
	setHeartbeat(x.c, "h1", false, time.Now().Add(time.Hour))
	type res struct {
		id  string
		err error
	}
	start := make(chan struct{})
	out := make(chan res, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			id, err := x.c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"})
			out <- res{id, err}
		}()
	}
	close(start)
	var ok, proposed int
	for i := 0; i < 2; i++ {
		r := <-out
		switch {
		case r.err == nil && r.id != "":
			ok++
		case errors.Is(r.err, module.ErrProposed) && strings.Contains(r.err.Error(), "already running"):
			proposed++
		default:
			t.Fatalf("unexpected result %q %v", r.id, r.err)
		}
	}
	if ok != 1 || proposed != 1 {
		t.Fatalf("started %d, proposed %d; want 1 and 1", ok, proposed)
	}
}

func TestRunAutoStarts(t *testing.T) {
	c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n")
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
