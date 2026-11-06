package controller

import "testing"

func TestTemplateGateStrings(t *testing.T) {
	t.Skip("unimplemented: W1 Task 27a")
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

func TestAutoGatePassesWhenConditionsHold(t *testing.T) {
	t.Skip("unimplemented: W1 Task 27a")
	// e2e helpers; plan: a (file.hash on h1) -> g (gate auto, AfterSec 1, Probe "web") -> b (file.hash); GatePoll 10ms; Probe nil-error
	// approve the plan (no gate approval call); within 3 s b is verified and g's approval is By "auto"
}

func TestAutoGateWaitsForShadowTime(t *testing.T) {
	t.Skip("unimplemented: W1 Task 27a")
	// AfterSec 2: after 500 ms the gate is pending with a note containing "left"; b not dispatched
}

func TestAutoGateFailsOnRedProbe(t *testing.T) {
	t.Skip("unimplemented: W1 Task 27a")
	// Probe returns an error: the gate state is failed, reason contains "gate: auto failed", b is never dispatched
}

func TestAutoGateFailsOnEvent(t *testing.T) {
	t.Skip("unimplemented: W1 Task 27a")
	// NoEvent{Kind: "agent.resumed"}: emit one agent.resumed through EmitController after a verifies; the gate fails with the kind in the reason;
	// an event committed before a finished does not fail it
}

func TestAutoGateNoProbeConfiguredFails(t *testing.T) {
	t.Skip("unimplemented: W1 Task 27a")
	// Options.Probe nil and Probe "web": failed, reason contains "no probe configured"
}

func TestPlainGateStillWaitsForClick(t *testing.T) {
	t.Skip("unimplemented: W1 Task 27a")
	// gate: approval in an auto-class plan stays pending until ApproveNode
}
