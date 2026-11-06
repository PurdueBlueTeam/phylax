package conformance

import "testing"

func TestAgentCheck5CatchesUndeclared(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: emitsUndeclaredFactory(), Default: cfgWith("undecl")}); errs["declared_kinds"] == nil {
		t.Fatal("undeclared kind not detected")
	}
}

func TestAgentCheck11CatchesLegacyField(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: emitsConnWithSrcIPFactory(), Default: cfgWith("legacy")}); errs["declared_kinds"] == nil {
		t.Fatal("non-canonical conn field not detected")
	}
}

func TestAgentCheck6CatchesCrashOnEmitError(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: crashOnEmitErrFactory(), Default: cfgWith("fragile"), Load: someLoad()}); errs["link_loss"] == nil {
		t.Fatal("crash under link loss not detected")
	}
}

func TestAgentCheck4CatchesMissingGap(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: wrongOSNoGapFactory(), Default: cfgWith("os")}); errs["health"] == nil {
		t.Fatal("missing OS gap not detected")
	}
}

func TestAgentChecks4to6Pass(t *testing.T) {
	Agent(t, AgentCase{Factory: goodFactory(), Default: cfgWith("good"), Load: someLoad()})
}
