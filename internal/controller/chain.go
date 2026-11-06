package controller

import (
	"context"
	"fmt"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// ControllerAgent is the store agent id of the controller-origin event chain.
// The row exists so the chain has a key and a head, like any agent's.
const ControllerAgent = "controller"

// EmitController appends e to the controller's own event chain. The event is
// validated against its declared kind, addressed to agent "controller" and
// stamped with the controller clock when it carries no time; the chain
// continues from the stored head, so a restart never restarts at seq 1 (which
// the store refuses as a replay). chainMu serialises the head read and the
// ingest, and is deliberately separate from ctlMu: a control send may block in
// the session while controller-origin alerts keep being emitted.
func (c *Controller) EmitController(ctx context.Context, e event.Event) (event.Event, error) {
	if err := event.Validate(e); err != nil {
		return event.Event{}, err
	}
	e.Agent = ControllerAgent
	if e.Time.IsZero() {
		e.Time = c.now().UTC()
	}
	c.chainMu.Lock()
	defer c.chainMu.Unlock()
	head, err := c.st.Agent(ctx, ControllerAgent)
	if err != nil {
		return event.Event{}, fmt.Errorf("controller chain: %w", err)
	}
	if err := e.Seal(head.LastSeq, head.LastHash); err != nil {
		return event.Event{}, err
	}
	if _, err := c.st.Ingest(ctx, ControllerAgent, []event.Event{e}); err != nil {
		return event.Event{}, fmt.Errorf("controller chain: %w", err)
	}
	return e, nil
}
