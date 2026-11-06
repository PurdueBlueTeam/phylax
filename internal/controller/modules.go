package controller

import (
	"context"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// EmitController stores an event on the controller-origin chain.
func (c *Controller) EmitController(ctx context.Context, e event.Event) (event.Event, error) {
	panic("unimplemented: W1 Task 16")
}

// RunModules runs every enabled controller module until ctx ends.
func (c *Controller) RunModules(ctx context.Context, mods []module.ControllerModule) error {
	panic("unimplemented: W1 Task 19")
}

// ModuleHealth returns controller-module health by name.
func (c *Controller) ModuleHealth() map[string]module.Health {
	panic("unimplemented: W1 Task 19")
}

// AgentHealth returns per-module health reported by an agent.
func (c *Controller) AgentHealth(host string) map[string]module.Health {
	panic("unimplemented: W1 Task 14")
}

func (c *Controller) RunReadOnly(ctx context.Context, mod, template string, params map[string]string) (string, error) {
	panic("unimplemented: W1 Task 23")
}

func (c *Controller) CreateStanding(ctx context.Context, sa plan.StandingApproval) error {
	panic("unimplemented: W1 Task 24")
}

func (c *Controller) RevokeStanding(ctx context.Context, id, by string) error {
	panic("unimplemented: W1 Task 24")
}

func (c *Controller) RunStanding(ctx context.Context, mod, approvalID, template string, params map[string]string) (string, error) {
	panic("unimplemented: W1 Task 24")
}

func (c *Controller) Propose(ctx context.Context, p module.Proposal) (int64, error) {
	panic("unimplemented: W1 Task 25")
}

func (c *Controller) AcceptProposal(ctx context.Context, id int64, by string) (string, error) {
	panic("unimplemented: W1 Task 25")
}

func (c *Controller) DismissProposal(ctx context.Context, id int64, by string) error {
	panic("unimplemented: W1 Task 25")
}

func (c *Controller) RunAuto(ctx context.Context, mod, template string, params map[string]string) (string, error) {
	panic("unimplemented: W1 Task 26")
}

func (c *Controller) ReenableAuto(ctx context.Context, mod, template, host, by string) error {
	panic("unimplemented: W1 Task 28")
}

func (c *Controller) SendFact(ctx context.Context, mod string, m module.ControlMsg) error {
	panic("unimplemented: W1 Task 30")
}

// noteAutoRollback feeds the auto circuit breaker.
func (c *Controller) noteAutoRollback(mod, template, host string, at time.Time) {
	panic("unimplemented: W1 Task 28")
}
