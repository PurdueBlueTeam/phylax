package conformance

import "testing"

func TestAgentChecks1to3Pass(t *testing.T) {
	t.Skip("unimplemented: W1 Task 34")
	Agent(t, AgentCase{Factory: goodFactory(), Default: cfgWith("good")})
}

func TestAgentCheck3CatchesLeak(t *testing.T) {
	t.Skip("unimplemented: W1 Task 34")
	if errs := runAgentChecks(AgentCase{Factory: leakyFactory(), Default: cfgWith("leaky")}); errs["stops_cleanly"] == nil {
		t.Fatal("goroutine leak not detected")
	}
}

func TestAgentCheck2CatchesHang(t *testing.T) {
	t.Skip("unimplemented: W1 Task 34")
	if errs := runAgentChecks(AgentCase{Factory: neverOKFactory(), Default: cfgWith("neverok")}); errs["default_config"] == nil {
		t.Fatal("module stuck in starting not detected")
	}
}

func TestAgentCheck1CatchesPanic(t *testing.T) {
	t.Skip("unimplemented: W1 Task 34")
	if errs := runAgentChecks(AgentCase{Factory: panicsWithoutConfigFactory(), Default: cfgWith("p")}); errs["no_config"] == nil {
		t.Fatal("panic on empty config not detected")
	}
}
