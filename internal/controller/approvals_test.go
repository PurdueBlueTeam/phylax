package controller

import (
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func TestRunReadOnlyStartsPlan(t *testing.T) {
	c := newTestControllerWithPlans(t, map[string]string{"ctltest/probe.yml": "id: probe\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: p, action: net.tcp_probe, target: '${host}', params: {host: 127.0.0.1, port: 22}}\n"})
	id, err := c.RunReadOnly(ctx, "ctltest", "probe", map[string]string{"host": "h1"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.PlanDetail(id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Plan.Class != plan.ClassAutoReadOnly || d.Plan.Approver != "auto_readonly:ctltest" {
		t.Fatalf("stored plan %+v", d)
	}
	// Apply starts at once; with no agent connected the node fails, but the
	// plan was approved and dispatched rather than left as a draft.
	if n := d.Nodes["p"]; n.Approval == nil {
		t.Fatalf("node was not approved: %+v", n)
	}
	switch d.State {
	case PlanApproved, PlanRunning, PlanFailed:
	default:
		t.Fatalf("state %q after Apply", d.State)
	}
}

func TestRunReadOnlyRefusesServiceRisk(t *testing.T) {
	c := newTestControllerWithPlans(t, map[string]string{"ctltest/perms.yml": "id: perms\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: p, action: file.perms, target: h1, params: {path: /etc/hosts, mode: '0644'}}\n"})
	_, err := c.RunReadOnly(ctx, "ctltest", "perms", nil)
	if err == nil || !strings.Contains(err.Error(), "SS000") || !strings.Contains(err.Error(), "file.perms") {
		t.Fatalf("got %v", err)
	}
	plans, err := c.StoredPlans(ctx)
	if err != nil || len(plans) != 0 {
		t.Fatalf("refused plan was stored: %+v %v", plans, err)
	}
}

func TestRunReadOnlyRefusesWrite(t *testing.T) {
	c := newTestControllerWithPlans(t, map[string]string{"ctltest/w.yml": "id: w\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: w, action: file.write, target: h1, params: {path: /tmp/x, content: y}}\n"})
	_, err := c.RunReadOnly(ctx, "ctltest", "w", nil)
	if err == nil || !strings.Contains(err.Error(), "SS000") {
		t.Fatalf("got %v", err)
	}
	plans, err := c.StoredPlans(ctx)
	if err != nil || len(plans) != 0 {
		t.Fatalf("refused plan was stored: %+v %v", plans, err)
	}
}
