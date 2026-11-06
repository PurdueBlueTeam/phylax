package agent

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// HarnessOptions configure a test harness: a real agent without link, spool or
// identity.
type HarnessOptions struct {
	Host      string
	StateDir  string
	Factories []Factory
	PlanKey   ed25519.PublicKey
	EmitErr   func() error // nil: every emit succeeds
}

// Harness runs real modules over the real reconciler and supervisor.
type Harness struct{}

func NewHarness(o HarnessOptions) (*Harness, error)         { panic("unimplemented: W1 Task 15") }
func (h *Harness) Apply(cfg *plan.AgentConfig)              { panic("unimplemented: W1 Task 15") }
func (h *Harness) Run(ctx context.Context)                  { panic("unimplemented: W1 Task 15") }
func (h *Harness) Publish(e event.Event)                    { panic("unimplemented: W1 Task 15") }
func (h *Harness) Emitted() []event.Event                   { panic("unimplemented: W1 Task 15") }
func (h *Harness) Health(name string) (module.Health, bool) { panic("unimplemented: W1 Task 15") }
func (h *Harness) Kept(key string) any                      { panic("unimplemented: W1 Task 15") }
func (h *Harness) Fact(f event.ControllerFact)              { panic("unimplemented: W1 Task 31") }
func (h *Harness) setNow(f func() time.Time)                { panic("unimplemented: W1 Task 31") }
func (h *Harness) env() Env                                 { panic("unimplemented: W1 Task 31") }
