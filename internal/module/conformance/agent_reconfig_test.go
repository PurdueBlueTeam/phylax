package conformance

import "testing"

func TestAgentCheck8CatchesLostKeep(t *testing.T) {
	t.Skip("unimplemented: W1 Task 36")
	c := AgentCase{Factory: forgetfulFactory(), Default: cfgWith("forget"), Reconfig: cfgWith2("forget"), KeepKey: "baseline"}
	if errs := runAgentChecks(c); errs["reconfig"] == nil {
		t.Fatal("lost Keep state not detected")
	}
}

func TestAgentCheck9CatchesLooseBlock(t *testing.T) {
	t.Skip("unimplemented: W1 Task 36")
	if errs := runAgentChecks(AgentCase{Factory: goodFactory(), Default: cfgWith("good"), Block: &looseSettings{}}); errs["config_decode"] == nil {
		t.Fatal("unknown field accepted")
	}
}
