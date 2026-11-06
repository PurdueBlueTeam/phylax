package controller

import "testing"

func TestAgentHealthFromHeartbeat(t *testing.T) {
	t.Skip("unimplemented: W1 Task 14")
	// with the e2e helpers (newCtl and a real agent): register a factory whose module implements
	// HealthReporter with Info {"rules_hash": "abc"}; enable it in the config; wait for two heartbeats
	// want: c.AgentHealth(host)[name].Info["rules_hash"] == "abc"
	// and an unavailable module (Build returns ErrUnavailable) shows State unavailable with one Gap
}
