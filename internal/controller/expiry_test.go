package controller

import "testing"

func TestTemplateExpiresAfterDuration(t *testing.T) {
	t.Skip("unimplemented: W1 Task 22a")
	p, err := ParseTemplate([]byte("id: t\nnodes:\n- {id: a, action: file.write, target: h1, params: {path: /tmp/x, content: y}, expires_after: 30m}\n"))
	if err != nil || p.Nodes[0].ExpiresAfterSec != 1800 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := ParseTemplate([]byte("id: t\nnodes:\n- {id: a, action: file.write, target: h1, params: {}, expires_after: soon}\n")); err == nil {
		t.Fatal("bad duration accepted")
	}
}

func TestExpiresAfterRefusedOnControllerAction(t *testing.T) {
	t.Skip("unimplemented: W1 Task 22a")
	// plan with node {action: ctltest.local (Runs: RunsController), ExpiresAfterSec: 600}: Create -> error containing "controller-side action"
}
