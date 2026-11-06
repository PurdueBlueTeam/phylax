package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func TestTemplateGateStrings(t *testing.T) {
	p, err := ParseTemplate([]byte("id: t\nnodes:\n- {id: a, action: file.hash, target: h1, params: {path: /etc/hostname}}\n- {id: g, gate: auto, needs: [a], until: {after: 10m, probe: '*', no_event: {kind: agent.resumed}}}\n- {id: p, gate: approval, needs: [g]}\n"))
	if err != nil || p.Nodes[1].Until == nil || p.Nodes[1].Until.AfterSec != 600 || p.Nodes[2].Until != nil || !p.Nodes[2].Gate {
		t.Fatalf("%+v %v", p, err)
	}
	for _, bad := range []string{"gate: auto", "gate: sometimes"} {
		if _, err := ParseTemplate([]byte("id: t\nnodes:\n- {id: g, " + bad + "}\n")); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// gatePlan builds a -> g (gate: auto) -> b with read-only nodes.
func gatePlan(id string, gate plan.Node) plan.Plan {
	return plan.Plan{ID: id, OnFailure: plan.StopDependents, Class: plan.ClassAuto, Nodes: []plan.Node{
		{ID: "a", Action: "file.hash", Target: "h1", Params: map[string]any{"path": "/etc/hostname"}},
		gate,
		{ID: "b", Action: "file.hash", Target: "h1", Needs: []string{"g"}, Params: map[string]any{"path": "/etc/hostname"}},
	}}
}

func autoGateNode(until plan.GateUntil) plan.Node {
	return plan.Node{ID: "g", Gate: true, Needs: []string{"a"}, Until: &until}
}

func startGatePlan(t *testing.T, x *ctl, p plan.Plan) string {
	t.Helper()
	if err := x.c.CreatePlan(ctx, p, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.approveNow(ctx, p.ID, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.Apply(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	return p.ID
}

func TestAutoGatePassesWhenConditionsHold(t *testing.T) {
	x := newPlanCtl(t, nil, nil, Options{GatePoll: 10 * time.Millisecond,
		Probe: func(context.Context, string) error { return nil }})
	_, root := newPlanAgent(t, x, "h1")
	writeAgentFile(t, root, "/etc/hostname", "h1\n")
	id := startGatePlan(t, x, gatePlan("gate-auto", autoGateNode(plan.GateUntil{AfterSec: 1, Probe: "web"})))
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := x.c.Wait(wctx, id); err != nil {
		t.Fatal(err)
	}
	d, err := x.c.PlanDetail(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Nodes["g"].State != plan.StateVerified || d.Nodes["b"].State != plan.StateVerified {
		t.Fatalf("gate %+v b %+v", d.Nodes["g"], d.Nodes["b"])
	}
	if d.Nodes["g"].Approval == nil || d.Nodes["g"].Approval.By != "auto" {
		t.Fatalf("approval %+v", d.Nodes["g"].Approval)
	}
}

func TestAutoGateWaitsForShadowTime(t *testing.T) {
	x := newPlanCtl(t, nil, nil, Options{GatePoll: 10 * time.Millisecond,
		Probe: func(context.Context, string) error { return nil }})
	_, root := newPlanAgent(t, x, "h1")
	writeAgentFile(t, root, "/etc/hostname", "h1\n")
	id := startGatePlan(t, x, gatePlan("gate-wait", autoGateNode(plan.GateUntil{AfterSec: 2, Probe: "web"})))
	time.Sleep(500 * time.Millisecond)
	d, err := x.c.PlanDetail(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Nodes["g"].State == plan.StateVerified || !strings.Contains(d.Nodes["g"].Reason, "left") {
		t.Fatalf("gate %+v", d.Nodes["g"])
	}
	if d.Nodes["b"].State == plan.StateVerified {
		t.Fatal("b ran before the shadow time elapsed")
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := x.c.Wait(wctx, id); err != nil {
		t.Fatal(err)
	}
}

func TestAutoGateFailsOnRedProbe(t *testing.T) {
	x := newPlanCtl(t, nil, nil, Options{GatePoll: 10 * time.Millisecond,
		Probe: func(context.Context, string) error { return errProbe }})
	x.c.probeRetry = 10 * time.Millisecond
	_, root := newPlanAgent(t, x, "h1")
	writeAgentFile(t, root, "/etc/hostname", "h1\n")
	id := startGatePlan(t, x, gatePlan("gate-red", autoGateNode(plan.GateUntil{Probe: "web"})))
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := x.c.Wait(wctx, id); err != nil {
		t.Fatal(err)
	}
	d, err := x.c.PlanDetail(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Nodes["g"].State != plan.StateFailed || !strings.Contains(d.Nodes["g"].Reason, "gate: auto failed") {
		t.Fatalf("gate %+v", d.Nodes["g"])
	}
	if d.Nodes["b"].State == plan.StateVerified {
		t.Fatal("b ran after a red gate probe")
	}
}

func TestAutoGateFailsOnEvent(t *testing.T) {
	t.Run("before", func(t *testing.T) {
		x := newPlanCtl(t, nil, nil, Options{GatePoll: 10 * time.Millisecond})
		_, root := newPlanAgent(t, x, "h1")
		writeAgentFile(t, root, "/etc/hostname", "h1\n")
		old, err := event.New("agent.resumed", event.AgentResumed{Host: "h1"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x.c.EmitController(ctx, old); err != nil {
			t.Fatal(err)
		}
		id := startGatePlan(t, x, gatePlan("gate-event-old", autoGateNode(plan.GateUntil{AfterSec: 1,
			NoEvent: &plan.NoEvent{Kind: "agent.resumed"}})))
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if _, err := x.c.Wait(wctx, id); err != nil {
			t.Fatal(err)
		}
		d, _ := x.c.PlanDetail(id)
		if d.Nodes["g"].State != plan.StateVerified {
			t.Fatalf("an event before the dependency finished failed the gate: %+v", d.Nodes["g"])
		}
	})

	t.Run("after", func(t *testing.T) {
		x := newPlanCtl(t, nil, nil, Options{GatePoll: 10 * time.Millisecond})
		_, root := newPlanAgent(t, x, "h1")
		writeAgentFile(t, root, "/etc/hostname", "h1\n")
		id := startGatePlan(t, x, gatePlan("gate-event-new", autoGateNode(plan.GateUntil{AfterSec: 1,
			NoEvent: &plan.NoEvent{Kind: "agent.resumed"}})))
		waitFor(t, 10*time.Second, "a to verify", func() bool {
			d, err := x.c.PlanDetail(id)
			return err == nil && d.Nodes["a"].State == plan.StateVerified
		})
		ev, err := event.New("agent.resumed", event.AgentResumed{Host: "h1"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x.c.EmitController(ctx, ev); err != nil {
			t.Fatal(err)
		}
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if _, err := x.c.Wait(wctx, id); err != nil {
			t.Fatal(err)
		}
		d, _ := x.c.PlanDetail(id)
		if d.Nodes["g"].State != plan.StateFailed || !strings.Contains(d.Nodes["g"].Reason, "agent.resumed") {
			t.Fatalf("gate %+v", d.Nodes["g"])
		}
	})
}

func TestAutoGateNoProbeConfiguredFails(t *testing.T) {
	x := newPlanCtl(t, nil, nil, Options{GatePoll: 10 * time.Millisecond})
	_, root := newPlanAgent(t, x, "h1")
	writeAgentFile(t, root, "/etc/hostname", "h1\n")
	id := startGatePlan(t, x, gatePlan("gate-noprobe", autoGateNode(plan.GateUntil{Probe: "web"})))
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := x.c.Wait(wctx, id); err != nil {
		t.Fatal(err)
	}
	d, _ := x.c.PlanDetail(id)
	if d.Nodes["g"].State != plan.StateFailed || !strings.Contains(d.Nodes["g"].Reason, "no probe configured") {
		t.Fatalf("gate %+v", d.Nodes["g"])
	}
}

func TestPlainGateStillWaitsForClick(t *testing.T) {
	x := newPlanCtl(t, nil, nil, Options{})
	_, root := newPlanAgent(t, x, "h1")
	writeAgentFile(t, root, "/etc/hostname", "h1\n")
	p := plan.Plan{ID: "plain-gate", OnFailure: plan.StopDependents, Class: plan.ClassAuto, Nodes: []plan.Node{
		{ID: "a", Action: "file.hash", Target: "h1", Params: map[string]any{"path": "/etc/hostname"}},
		{ID: "g", Gate: true, Needs: []string{"a"}},
		{ID: "b", Action: "file.hash", Target: "h1", Needs: []string{"g"}, Params: map[string]any{"path": "/etc/hostname"}},
	}}
	if err := x.c.CreatePlan(ctx, p, "driver"); err != nil {
		t.Fatal(err)
	}
	if _, err := x.c.DryRun(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if err := x.c.ApprovePlan(ctx, p.ID, "driver"); err != nil {
		t.Fatal(err)
	}
	if err := x.c.Apply(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "a to verify", func() bool {
		d, err := x.c.PlanDetail(p.ID)
		return err == nil && d.Nodes["a"].State == plan.StateVerified
	})
	time.Sleep(100 * time.Millisecond)
	d, err := x.c.PlanDetail(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Nodes["g"].State != plan.StatePending || d.Nodes["b"].State == plan.StateVerified {
		t.Fatalf("plain gate %+v b %+v", d.Nodes["g"], d.Nodes["b"])
	}
	if err := x.c.ApproveNode(ctx, p.ID, "g", "driver", "released"); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := x.c.Wait(wctx, p.ID); err != nil {
		t.Fatal(err)
	}
	d, _ = x.c.PlanDetail(p.ID)
	if d.Nodes["b"].State != plan.StateVerified {
		t.Fatalf("b %+v", d.Nodes["b"])
	}
}

var errProbe = probeError("probe red")

type probeError string

func (e probeError) Error() string { return string(e) }
