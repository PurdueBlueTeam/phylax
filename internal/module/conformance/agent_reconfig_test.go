package conformance

import "testing"

func TestAgentCheck7CatchesLostKeep(t *testing.T) {
	c := AgentCase{Factory: forgetfulFactory(), Default: cfgWith("forget"), Reconfig: cfgWith2("forget"), KeepKey: "baseline"}
	if errs := runAgentChecks(c); errs["reconfig"] == nil {
		t.Fatal("lost Keep state not detected")
	}
}

func TestAgentCheck8CatchesLooseBlock(t *testing.T) {
	// Block is a test settings struct whose UnmarshalJSON ignores unknown keys
	if errs := runAgentChecks(AgentCase{Factory: goodFactory(), Default: cfgWith("good"), Block: &looseSettings{}}); errs["config_decode"] == nil {
		t.Fatal("unknown field accepted")
	}
}
