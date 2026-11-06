package agent

import "testing"

func TestAgentCoreEventsValidate(t *testing.T) {
	t.Skip("unimplemented: W1 Task 6")
	// Use the in-package test agent and controller of testutil_test.go: start the agent,
	// apply a config, send one control the agent refuses (unsigned), make a test module
	// crash once, wait for one health report.
	// Then read every event the agent spooled and every event its bus published.
	// want: for each event e of a declared kind, event.Validate(e) == nil;
	// and at least one each of agent.start, agent.config_applied, agent.control_refused,
	// agent.module_crash, agent.health was seen.
}
