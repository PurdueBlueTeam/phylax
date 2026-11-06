package controller

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func autoProbeFiles() map[string]string {
	return map[string]string{
		"modules/ctltest.yml": "enabled: true\nact_enabled: true\nauto: [t1]\n",
	}
}

func autoWritePlan(path, content string) map[string]string {
	return map[string]string{
		"ctltest/t1.yml": "id: t1\nmodule: ctltest\nnodes:\n  - {id: a, action: file.write, target: '${host}', risk: service, params: {path: " + path + ", content: " + content + "}}\n",
	}
}

func TestAutoAfterProbeRollsBack(t *testing.T) {
	var calls atomic.Int32
	x := newPlanCtl(t, autoProbeFiles(), autoWritePlan("/tmp/phylax-after-probe", "changed"), Options{
		Probe: func(context.Context, string) error {
			if calls.Add(1) == 1 {
				return nil // the before-probe is green
			}
			return errors.New("scorer-mimic red")
		},
	})
	x.c.probeRetry = 10 * time.Millisecond
	_, root := newPlanAgent(t, x, "h1")
	file := writeAgentFile(t, root, "/tmp/phylax-after-probe", "original")
	setHeartbeat(x.c, "h1", false, time.Now())

	id, err := x.c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"})
	if err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := x.c.Wait(wctx, id); err != nil {
		d, _ := x.c.PlanDetail(id)
		t.Fatalf("%v %+v", err, d)
	}
	d, err := x.c.PlanDetail(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Nodes["a"].State != plan.StateRolledBack {
		t.Fatalf("plan %s node %+v", d.State, d.Nodes["a"])
	}
	if !strings.Contains(d.Nodes["a"].Reason, "after-probe red: web") {
		t.Fatalf("reason %q", d.Nodes["a"].Reason)
	}
	if got, _ := readFileString(file); got != "original" {
		t.Fatalf("file content %q, want the original", got)
	}
	if _, err := x.c.st.MetaGet(ctx, autoRollbacksKey("ctltest", "t1", "h1")); err != nil {
		t.Fatalf("the automatic rollback did not feed the breaker: %v", err)
	}
}

func TestAutoBeforeProbeStops(t *testing.T) {
	var steps atomic.Int32
	x := newPlanCtl(t, autoProbeFiles(), autoWritePlan("/tmp/phylax-before-probe", "changed"), Options{
		Probe: func(context.Context, string) error { return errors.New("scorer-mimic red") },
		OnStepSent: func(string, *link.Step) {
			steps.Add(1)
		},
	})
	x.c.probeRetry = 10 * time.Millisecond
	_, _ = newPlanAgent(t, x, "h1")
	setHeartbeat(x.c, "h1", false, time.Now())

	id, err := x.c.RunAuto(ctx, "ctltest", "t1", map[string]string{"host": "h1"})
	if err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := x.c.Wait(wctx, id); err != nil {
		t.Fatal(err)
	}
	d, err := x.c.PlanDetail(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Nodes["a"].State != plan.StateFailed || !strings.Contains(d.Nodes["a"].Reason, "before-probe red: web") {
		t.Fatalf("node %+v", d.Nodes["a"])
	}
	if n := steps.Load(); n != 0 {
		t.Fatalf("the agent received %d steps; a red before-probe must apply nothing", n)
	}
}

// groupPlan builds five chained writes to the same path, optionally giving one
// of them its own dead-man window.
func groupPlan(policy plan.FailurePolicy, deadman bool) plan.Plan {
	path := "/etc/ssh/phylax-probe-group"
	nodes := make([]plan.Node, 0, 5)
	for i := 0; i < 5; i++ {
		n := plan.Node{ID: string(rune('a' + i)), Action: "file.write", Target: "h1", Risk: plan.RiskService,
			Params: map[string]any{"path": path, "content": "x"}}
		if i > 0 {
			n.Needs = []string{string(rune('a' + i - 1))}
		}
		if deadman && i == 2 {
			n.DeadmanSec = 2
		}
		nodes = append(nodes, n)
	}
	return plan.Plan{ID: "probe-groups", OnFailure: policy, Class: plan.ClassClick, Nodes: nodes}
}

func probeGroupCalls(t *testing.T, policy plan.FailurePolicy, deadman bool) int32 {
	t.Helper()
	var calls atomic.Int32
	x := newPlanCtl(t, nil, nil, Options{Probe: func(context.Context, string) error {
		calls.Add(1)
		return nil
	}})
	_, _ = newPlanAgent(t, x, "h1")
	p := groupPlan(policy, deadman)
	if err := x.c.CreatePlan(ctx, p, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.approveNow(ctx, p.ID, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.Apply(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := x.c.Wait(wctx, p.ID); err != nil {
		t.Fatal(err)
	}
	return calls.Load()
}

func TestAutoProbeGroupingFailsClosed(t *testing.T) {
	for name, breakIt := range map[string]func(*Controller){
		"manifest": func(c *Controller) { c.cfg.ManifestPath = filepath.Join(t.TempDir(), "missing") },
		"action":   func(c *Controller) { c.reg = actions.NewRegistry() },
	} {
		t.Run(name, func(t *testing.T) {
			var steps atomic.Int32
			c := newAutoController(t, "enabled: true\nact_enabled: true\nauto: [t1]\n")
			c.opt.OnStepSent = func(string, *link.Step) { steps.Add(1) }
			p := plan.Plan{ID: "auto-probe-" + name, OnFailure: plan.RollbackPlan, Class: plan.ClassAuto,
				Module: "ctltest", Template: "t1", Nodes: []plan.Node{{
					ID: "a", Action: "file.write", Target: "h1", Risk: plan.RiskService,
					Params: map[string]any{"path": "/tmp/phylax-probe-fail", "content": "x"},
				}}}
			if err := c.CreatePlan(ctx, p, "driver"); err != nil {
				t.Fatal(err)
			}
			if err := c.approveNow(ctx, p.ID, "driver"); err != nil {
				t.Fatal(err)
			}
			breakIt(c)
			if err := c.Apply(ctx, p.ID); err != nil {
				t.Fatal(err)
			}
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			if _, err := c.Wait(wctx, p.ID); err != nil {
				d, _ := c.PlanDetail(p.ID)
				t.Fatalf("%v %+v", err, d)
			}
			d, err := c.PlanDetail(p.ID)
			if err != nil {
				t.Fatal(err)
			}
			if d.State != PlanFailed || d.Nodes["a"].State != plan.StateFailed {
				t.Fatalf("plan %s node %+v", d.State, d.Nodes["a"])
			}
			if n := steps.Load(); n != 0 {
				t.Fatalf("%d steps ran after probe grouping failed", n)
			}
		})
	}
}

func TestBeforeProbeFailureRollsBackAppliedGroup(t *testing.T) {
	files := map[string]string{"services.yml": `services:
  web: { host: h1, kind: http, scored: true, listen: [{ proto: tcp, port: 80 }], content: { roots: [/etc/ssh] } }
  db: { host: h1, kind: tcp, scored: true, listen: [{ proto: tcp, port: 5432 }], content: { roots: [/etc/audit] } }
`}
	x := newPlanCtl(t, files, nil, Options{Probe: func(_ context.Context, service string) error {
		if service == "db" {
			return errors.New("db is red")
		}
		return nil
	}})
	x.c.probeRetry = 10 * time.Millisecond
	_, root := newPlanAgent(t, x, "h1")
	writeAgentFile(t, root, "/etc/ssh/x", "original-ssh")
	writeAgentFile(t, root, "/etc/audit/x", "original-audit")
	p := plan.Plan{ID: "before-rollback", OnFailure: plan.RollbackPlan, Class: plan.ClassClick, Nodes: []plan.Node{
		{ID: "a", Action: "file.write", Target: "h1", Risk: plan.RiskService,
			Params: map[string]any{"path": "/etc/ssh/x", "content": "changed-ssh"}},
		{ID: "b", Action: "file.write", Target: "h1", Risk: plan.RiskService, Needs: []string{"a"},
			Params: map[string]any{"path": "/etc/audit/x", "content": "changed-audit"}},
	}}
	if err := x.c.CreatePlan(ctx, p, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.approveNow(ctx, p.ID, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.Apply(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := x.c.Wait(wctx, p.ID); err != nil {
		t.Fatal(err)
	}
	d, err := x.c.PlanDetail(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Nodes["a"].State != plan.StateRolledBack {
		t.Fatalf("plan %s a %+v b %+v", d.State, d.Nodes["a"], d.Nodes["b"])
	}
	if got, _ := readFileString(filepath.Join(root, "etc/ssh/x")); got != "original-ssh" {
		t.Fatalf("a's file is %q", got)
	}
	if d.Nodes["b"].State != plan.StateFailed {
		t.Fatalf("b %+v", d.Nodes["b"])
	}
}

func TestOneProbePerGroupAndPhase(t *testing.T) {
	if n := probeGroupCalls(t, plan.StopDependents, false); n != 2 {
		t.Fatalf("probes %d, want 2 (one before, one after)", n)
	}
	if n := probeGroupCalls(t, plan.StopDependents, true); n != 4 {
		t.Fatalf("probes %d, want 4 (the dead-man node is its own group)", n)
	}
	// rollback_plan adds the plan-wide rollback window to every node; that is
	// not a node's own dead-man window, so the group still shares one probe.
	if n := probeGroupCalls(t, plan.RollbackPlan, false); n != 2 {
		t.Fatalf("rollback_plan probes %d, want 2", n)
	}
}

func TestDeadmanConfirmWaitsForAfterProbe(t *testing.T) {
	t.Run("red", func(t *testing.T) {
		var calls atomic.Int32
		var confirms atomic.Int32
		var afterAt atomic.Int64
		x := newPlanCtl(t, nil, nil, Options{
			Probe: func(context.Context, string) error {
				n := calls.Add(1)
				if n == 1 {
					return nil
				}
				afterAt.Store(time.Now().UnixNano())
				return errors.New("red")
			},
			OnControlSent: func(_ string, c *link.Control) {
				if c.Kind == plan.ControlDeadmanConfirm {
					confirms.Add(1)
				}
			},
		})
		x.c.probeRetry = 10 * time.Millisecond
		_, root := newPlanAgent(t, x, "h1")
		file := writeAgentFile(t, root, "/tmp/phylax-deadman-red", "original")
		p := plan.Plan{ID: "deadman-red", OnFailure: plan.StopDependents, Class: plan.ClassClick, Nodes: []plan.Node{
			{ID: "a", Action: "file.write", Target: "h1", Risk: plan.RiskService, DeadmanSec: 2,
				Params: map[string]any{"path": "/tmp/phylax-deadman-red", "content": "changed"}},
		}}
		if err := x.c.CreatePlan(ctx, p, "driver"); err != nil {
			t.Fatal(err)
		}
		if err := x.c.approveNow(ctx, p.ID, "driver"); err != nil {
			t.Fatal(err)
		}
		if err := x.c.Apply(ctx, p.ID); err != nil {
			t.Fatal(err)
		}
		wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if _, err := x.c.Wait(wctx, p.ID); err != nil {
			d, _ := x.c.PlanDetail(p.ID)
			t.Fatalf("%v %+v", err, d)
		}
		if confirms.Load() != 0 {
			t.Fatal("deadman_confirm was sent after a red after-probe")
		}
		waitFor(t, 10*time.Second, "the agent timer to roll the file back", func() bool {
			b, err := readFileString(file)
			return err == nil && b == "original"
		})
		if afterAt.Load() == 0 {
			t.Fatal("the after-probe never ran")
		}
	})

	t.Run("green", func(t *testing.T) {
		var calls atomic.Int32
		var confirms atomic.Int32
		var afterAt, confirmAt atomic.Int64
		x := newPlanCtl(t, nil, nil, Options{
			Probe: func(context.Context, string) error {
				if calls.Add(1) == 2 {
					afterAt.Store(time.Now().UnixNano())
				}
				return nil
			},
			OnControlSent: func(_ string, c *link.Control) {
				if c.Kind == plan.ControlDeadmanConfirm {
					confirmAt.Store(time.Now().UnixNano())
					confirms.Add(1)
				}
			},
		})
		_, root := newPlanAgent(t, x, "h1")
		file := writeAgentFile(t, root, "/tmp/phylax-deadman-green", "original")
		p := plan.Plan{ID: "deadman-green", OnFailure: plan.StopDependents, Class: plan.ClassClick, Nodes: []plan.Node{
			{ID: "a", Action: "file.write", Target: "h1", Risk: plan.RiskService, DeadmanSec: 2,
				Params: map[string]any{"path": "/tmp/phylax-deadman-green", "content": "changed"}},
		}}
		if err := x.c.CreatePlan(ctx, p, "driver"); err != nil {
			t.Fatal(err)
		}
		if err := x.c.approveNow(ctx, p.ID, "driver"); err != nil {
			t.Fatal(err)
		}
		if err := x.c.Apply(ctx, p.ID); err != nil {
			t.Fatal(err)
		}
		wctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if _, err := x.c.Wait(wctx, p.ID); err != nil {
			t.Fatal(err)
		}
		if confirms.Load() != 1 {
			t.Fatalf("deadman_confirm sent %d times, want 1", confirms.Load())
		}
		if confirmAt.Load() < afterAt.Load() {
			t.Fatal("deadman_confirm was sent before the after-probe")
		}
		if got, _ := readFileString(file); got != "changed" {
			t.Fatalf("file content %q, want changed (the confirm kept it)", got)
		}
	})
}

// A restarted controller rebuilds the probe grouping lazily. A node whose
// apply was in flight is still the agent's to finish (or to time out); failing
// it as unstarted would roll back a change that is still being made.
func TestProbeGroupingFailureLeavesRunningNodeAlone(t *testing.T) {
	var applied atomic.Int32
	x := newPlanCtl(t, nil, nil, Options{
		ResumeGrace: 100 * time.Millisecond, StepTimeout: 30 * time.Second,
		Probe: func(context.Context, string) error { return nil },
		OnStepSent: func(_ string, s *link.Step) {
			if s.Phase == plan.PhaseApply {
				applied.Add(1)
			}
		},
	})
	newFakeStepAgent(t, x, "h1", true, nil) // hold the apply: the node stays running
	p := plan.Plan{ID: "probe-running-resume", OnFailure: plan.RollbackPlan, Class: plan.ClassAuto,
		Module: "ctltest", Template: "t1", Nodes: []plan.Node{
			{ID: "a", Action: "file.write", Target: "h1", Risk: plan.RiskService,
				Params: map[string]any{"path": "/tmp/phylax-resume-a", "content": "a"}},
			{ID: "b", Action: "file.write", Target: "h1", Risk: plan.RiskService, Needs: []string{"a"},
				Params: map[string]any{"path": "/tmp/phylax-resume-b", "content": "b"}},
		}}
	if err := x.c.CreatePlan(ctx, p, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.approveNow(ctx, p.ID, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.Apply(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "a's apply to be in flight", func() bool {
		d, err := x.c.PlanDetail(p.ID)
		return applied.Load() > 0 && err == nil && d.Nodes["a"].State == plan.StateRunning
	})

	x.shutdown()
	x.cfg.ManifestPath = filepath.Join(t.TempDir(), "missing") // grouping cannot be built
	x.start()

	waitFor(t, 10*time.Second, "b to be settled after the restart", func() bool {
		d, err := x.c.PlanDetail(p.ID)
		return err == nil && (d.Nodes["b"].State == plan.StateFailed || d.Nodes["b"].State == plan.StateSkipped)
	})
	d, err := x.c.PlanDetail(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Nodes["a"].State != plan.StateRunning {
		t.Fatalf("a was failed while its apply was still in flight: %+v", d.Nodes["a"])
	}
}
