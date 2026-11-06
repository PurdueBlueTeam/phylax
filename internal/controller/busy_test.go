package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func busyPlan(id string, n int) plan.Plan {
	nodes := make([]plan.Node, 0, n)
	for i := 0; i < n; i++ {
		nodes = append(nodes, plan.Node{ID: fmt.Sprintf("n%d", i), Action: "file.hash", Target: "h1",
			Params: map[string]any{"path": "/etc/hosts"}})
	}
	return plan.Plan{ID: id, OnFailure: plan.StopDependents, Class: plan.ClassClick, Nodes: nodes}
}

func TestControllerKeepsInflightBelowCap(t *testing.T) {
	var sent, maxSent atomic.Int32
	x := newPlanCtl(t, nil, nil, Options{OnStepSent: func(string, *link.Step) {
		n := sent.Add(1)
		for {
			m := maxSent.Load()
			if n <= m || maxSent.CompareAndSwap(m, n) {
				break
			}
		}
	}})
	newFakeStepAgent(t, x, "h1", true, nil)
	p := busyPlan("cap", 12)
	if err := x.c.CreatePlan(ctx, p, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.approveNow(ctx, p.ID, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.Apply(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the in-flight cap to fill", func() bool { return sent.Load() >= defaultMaxHostInflight })
	time.Sleep(200 * time.Millisecond)
	if got := maxSent.Load(); got > defaultMaxHostInflight {
		t.Fatalf("%d steps in flight, cap %d", got, defaultMaxHostInflight)
	}
	if got := sent.Load(); got != defaultMaxHostInflight {
		t.Fatalf("%d steps sent, want %d (results are held)", got, defaultMaxHostInflight)
	}
}

func TestControllerRetriesBusy(t *testing.T) {
	var f *fakeStepAgent
	x := newPlanCtl(t, nil, nil, Options{BusyRetry: 20 * time.Millisecond})
	f = newFakeStepAgent(t, x, "h1", false, func(w *link.Step) (string, bool) {
		switch w.Phase {
		case plan.PhaseApply:
			if f.takeBusy(w.Node) {
				return plan.OutcomeBusy, true
			}
			return plan.OutcomeApplied, true
		case plan.PhaseVerify:
			return plan.OutcomeVerified, true
		case plan.PhaseRollback:
			return plan.OutcomeRolledBack, true
		}
		return plan.OutcomeFailed, true
	})
	f.busyTimes("a", 1)
	p := plan.Plan{ID: "retry", OnFailure: plan.StopDependents, Class: plan.ClassClick, Nodes: []plan.Node{
		{ID: "a", Action: "file.hash", Target: "h1",
			Params: map[string]any{"path": "/etc/hosts"}},
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
	if d.State != PlanSucceeded || d.Nodes["a"].State != plan.StateVerified {
		t.Fatalf("plan %s node %+v", d.State, d.Nodes["a"])
	}
	for _, ph := range d.Nodes["a"].Phases {
		if ph.Outcome == plan.OutcomeFailed {
			t.Fatalf("busy was recorded as a failure: %+v", d.Nodes["a"].Phases)
		}
	}
}

func TestControllerFailsAfterBusyLimit(t *testing.T) {
	x := newPlanCtl(t, nil, nil, Options{BusyRetry: time.Millisecond})
	newFakeStepAgent(t, x, "h1", false, func(w *link.Step) (string, bool) {
		if w.Phase == plan.PhaseApply {
			return plan.OutcomeBusy, true
		}
		return plan.OutcomeVerified, true
	})
	p := plan.Plan{ID: "busy-limit", OnFailure: plan.StopDependents, Class: plan.ClassClick, Nodes: []plan.Node{
		{ID: "a", Action: "file.hash", Target: "h1",
			Params: map[string]any{"path": "/etc/hosts"}},
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
	if d.Nodes["a"].State != plan.StateFailed || !strings.Contains(d.Nodes["a"].Reason, "agent busy") {
		t.Fatalf("node %+v", d.Nodes["a"])
	}
}

func TestBusyOnAutoPlanDoesNotRollBack(t *testing.T) {
	var f *fakeStepAgent
	x := newPlanCtl(t, autoProbeFiles(), autoWritePlan("/tmp/phylax-busy-auto", "x"), Options{
		Probe:     func(context.Context, string) error { return nil },
		BusyRetry: 20 * time.Millisecond,
	})
	f = newFakeStepAgent(t, x, "h1", false, func(w *link.Step) (string, bool) {
		switch w.Phase {
		case plan.PhaseApply:
			if f.takeBusy(w.Node) {
				return plan.OutcomeBusy, true
			}
			return plan.OutcomeApplied, true
		case plan.PhaseVerify:
			return plan.OutcomeVerified, true
		case plan.PhaseRollback:
			return plan.OutcomeRolledBack, true
		}
		return plan.OutcomeFailed, true
	})
	f.busyTimes("a", 2)
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
	if d.State != PlanSucceeded || d.Nodes["a"].State != plan.StateVerified {
		t.Fatalf("plan %s node %+v", d.State, d.Nodes["a"])
	}
	if _, err := x.c.st.MetaGet(ctx, "auto_halted/ctltest/t1/h1"); !errors.Is(err, store.ErrNoMeta) {
		t.Fatalf("a busy answer opened the auto breaker: %v", err)
	}
}
