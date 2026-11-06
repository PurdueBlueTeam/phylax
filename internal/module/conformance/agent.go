package conformance

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// AgentCase is one agent module under test.
type AgentCase struct {
	Factory  agent.Factory
	Default  *plan.AgentConfig // the module's default block on a fixture host
	Reconfig *plan.AgentConfig // a changed block (check 8)
	KeepKey  string            // key the module stores with Env.Keep; "" when it keeps nothing
	Load     []event.Event     // consumed events fed on the bus (checks 6 and 7)
	Block    any               // pointer to a zero settings struct (check 9); nil: plan.BlockFor(Default, Factory.Name)
}

// Agent runs the agent-side conformance checks.
func Agent(t *testing.T, c AgentCase) { panic("unimplemented: W1 Task 34") }

// runAgentChecks returns one error per named check.
func runAgentChecks(c AgentCase) map[string]error { panic("unimplemented: W1 Task 34") }
