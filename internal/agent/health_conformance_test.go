package agent_test

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/module/conformance"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// factoryNamed returns the registered agent factory with this name; the
// conformance suite runs the module the real registry holds.
func factoryNamed(t *testing.T, name string) agent.Factory {
	t.Helper()
	for _, f := range agent.Registered() {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no agent factory %q is registered", name)
	return agent.Factory{}
}

func TestHealthConformance(t *testing.T) {
	f := factoryNamed(t, "health")
	conformance.Agent(t, conformance.AgentCase{
		Factory:  f,
		Default:  &plan.AgentConfig{Host: "h1", Modules: plan.ModuleSettings{Health: &plan.HealthSettings{ModuleLimits: plan.ModuleLimits{Common: module.Common{Enabled: true}}, IntervalSec: 1}}},
		Reconfig: &plan.AgentConfig{Host: "h1", Modules: plan.ModuleSettings{Health: &plan.HealthSettings{ModuleLimits: plan.ModuleLimits{Common: module.Common{Enabled: true}}, IntervalSec: 2}}},
	})
}
