package controller

import (
	"strings"
	"testing"
)

func TestRunReadOnlyStartsPlan(t *testing.T) {
	t.Skip("unimplemented: W1 Task 23")
	c := newTestControllerWithPlans(t, map[string]string{"ctltest/probe.yml": "id: probe\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: p, action: net.tcp_probe, target: '${host}', params: {host: 127.0.0.1, port: 22}}\n"})
	id, err := c.RunReadOnly(ctx, "ctltest", "probe", map[string]string{"host": "h1"})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := c.PlanStatus(id)
	// want: the stored plan has Class auto_readonly, Approver "auto_readonly:ctltest", and is approved (st shows it)
	_ = st
}

func TestRunReadOnlyRefusesWrite(t *testing.T) {
	t.Skip("unimplemented: W1 Task 23")
	c := newTestControllerWithPlans(t, map[string]string{"ctltest/w.yml": "id: w\nmodule: ctltest\non_failure: stop_dependents\nnodes:\n  - {id: w, action: file.write, target: h1, params: {path: /tmp/x, content: y}}\n"})
	_, err := c.RunReadOnly(ctx, "ctltest", "w", nil)
	if err == nil || !strings.Contains(err.Error(), "SS000") {
		t.Fatalf("got %v", err)
	}
	// want: no plan stored (c.StoredPlans(ctx) is empty)
}
