package conformance

import "testing"

func TestAgentCheck5CatchesUndeclared(t *testing.T) {
	t.Skip("unimplemented: W1 Task 35")
	if errs := runAgentChecks(AgentCase{Factory: emitsUndeclaredFactory(), Default: cfgWith("undecl")}); errs["declared_kinds"] == nil {
		t.Fatal("undeclared kind not detected")
	}
}

func TestAgentCheck12CatchesLegacyField(t *testing.T) {
	t.Skip("unimplemented: W1 Task 35")
	if errs := runAgentChecks(AgentCase{Factory: emitsConnWithSrcIPFactory(), Default: cfgWith("legacy")}); errs["declared_kinds"] == nil {
		t.Fatal("non-canonical conn field not detected")
	}
}

func TestAgentCheck7CatchesCrashOnEmitError(t *testing.T) {
	t.Skip("unimplemented: W1 Task 35")
	if errs := runAgentChecks(AgentCase{Factory: crashOnEmitErrFactory(), Default: cfgWith("fragile"), Load: someLoad()}); errs["link_loss"] == nil {
		t.Fatal("crash under link loss not detected")
	}
}

func TestAgentCheck4CatchesMissingGap(t *testing.T) {
	t.Skip("unimplemented: W1 Task 35")
	if errs := runAgentChecks(AgentCase{Factory: wrongOSNoGapFactory(), Default: cfgWith("os")}); errs["health"] == nil {
		t.Fatal("missing OS gap not detected")
	}
}

func TestAgentChecks4to7Pass(t *testing.T) {
	t.Skip("unimplemented: W1 Task 35")
	Agent(t, AgentCase{Factory: goodFactory(), Default: cfgWith("good"), Load: someLoad()})
}
