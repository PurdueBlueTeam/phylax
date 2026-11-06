package conformance

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func TestAgentChecks1to3Pass(t *testing.T) {
	Agent(t, AgentCase{Factory: goodFactory(), Default: cfgWith("good")})
}

func TestAgentCheck3CatchesLeak(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: leakyFactory(), Default: cfgWith("leaky")}); errs["stops_cleanly"] == nil {
		t.Fatal("goroutine leak not detected")
	}
}

func TestAgentCheck2CatchesHang(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: neverOKFactory(), Default: cfgWith("neverok")}); errs["default_config"] == nil {
		t.Fatal("module stuck in starting not detected")
	}
}

func TestAgentCheck1CatchesPanic(t *testing.T) {
	if errs := runAgentChecks(AgentCase{Factory: panicsWithoutConfigFactory(), Default: cfgWith("p")}); errs["no_config"] == nil {
		t.Fatal("panic on empty config not detected")
	}
}

// TestAgentCheck1ExemptsDefaultModule: a core-default module runs without its
// block, so check 1 does not require it to report unavailable.
func TestAgentCheck1ExemptsDefaultModule(t *testing.T) {
	f := defaultOnFactory()
	if _, on := f.Section(&plan.AgentConfig{}); !on {
		t.Fatal("fixture must run without a block")
	}
	if err := runAgentChecks(AgentCase{Factory: f, Default: cfgWith("on")})["no_config"]; err != nil {
		t.Fatalf("a core-default module must pass check 1: %v", err)
	}
}

// TestAgentChecksAcceptAPrivilegeGap: a module that reports a gap this host
// cannot close stays running through checks 2 and 6, and a module that
// reports no such gap must still be ok there.
func TestAgentChecksAcceptAPrivilegeGap(t *testing.T) {
	gap := func() module.Health {
		return module.Health{State: module.StateDegraded,
			Gaps: []module.Gap{{What: "privilege", Why: "needs root"}}}
	}
	c := AgentCase{Factory: gapFactory("gapped", gap), Default: cfgWith("gapped"), Load: someLoad()}
	for _, name := range []string{"default_config", "link_loss"} {
		if err := runAgentChecks(c)[name]; err != nil {
			t.Fatalf("%s: a reported privilege gap must pass: %v", name, err)
		}
	}
	// The same factory reporting error is still caught.
	bad := AgentCase{Factory: gapFactory("broken", func() module.Health {
		return module.Health{State: module.StateError}
	}), Default: cfgWith("broken"), Load: someLoad()}
	for _, name := range []string{"default_config", "link_loss"} {
		if err := runAgentChecks(bad)[name]; err == nil {
			t.Fatalf("%s: an error state under link loss must fail", name)
		}
	}
}
