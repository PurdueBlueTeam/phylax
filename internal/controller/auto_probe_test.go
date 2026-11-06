package controller

import "testing"

func TestAutoAfterProbeRollsBack(t *testing.T) {
	t.Skip("unimplemented: W1 Task 27")
	// e2e helpers (newCtl + a real agent "h1" with a scored service "web" in the manifest); module block act_enabled with auto [t1];
	// t1: one file.write node to a temp path on h1
	// Options.Probe returns nil before and an error after (count calls)
	// RunAuto(... "t1" ...) then Wait(planID)
	// want: node state rolled_back, reason contains "after-probe red: web"; the temp file content is the original
}

func TestAutoBeforeProbeStops(t *testing.T) {
	t.Skip("unimplemented: W1 Task 27")
	// same setup; Probe always errors
	// want: node failed with "before-probe red: web"; the agent received no apply step (OnStepSent saw none)
}
