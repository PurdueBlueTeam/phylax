package agent

import (
	"context"
	"encoding/json"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// Reply sends a message back on the current session.
type Reply func(ctx context.Context, p link.Priority, m link.Message) error

// Handlers are the pluggable handlers for controller messages. A nil field
// uses the placeholder, which logs and rejects. A handler error ends the
// session, so handlers return nil for ordinary refusals. They run on the
// session's handler goroutine and must return promptly (the executor runs
// long work off this path).
type Handlers struct {
	Config  func(ctx context.Context, c *link.Config) error
	Step    func(ctx context.Context, s *link.Step, reply Reply) error
	Fetch   func(ctx context.Context, f *link.Fetch, reply Reply) error
	Control func(ctx context.Context, c *link.Control) error
}

func (a *Agent) placeholderConfig(_ context.Context, c *link.Config) error {
	a.log.Warn("config received but config handling is not implemented; rejected", "version", c.Version, "epoch", c.Epoch)
	a.emit(event.Event{Kind: "agent.config_rejected", Priority: event.PriorityHigh,
		Fields: map[string]any{"version": c.Version, "epoch": c.Epoch, "reason": "not implemented"}})
	return nil
}

func (a *Agent) placeholderStep(ctx context.Context, s *link.Step, reply Reply) error {
	a.log.Warn("step received but execution is not implemented; rejected", "plan", s.Plan, "node", s.Node, "action", s.Action)
	phase := s.Phase
	if phase == "" {
		phase = "check"
	}
	return reply(ctx, link.PrioStep, &link.StepResult{Plan: s.Plan, Node: s.Node, Epoch: s.Epoch, Seq: s.Seq,
		Phase: phase, Status: "rejected", Error: "step execution not implemented on this agent"})
}

func (a *Agent) placeholderFetch(_ context.Context, f *link.Fetch, _ Reply) error {
	a.log.Warn("fetch received but not implemented; ignored", "id", f.ID, "kind", f.Kind)
	return nil
}

// defaultControl implements the controls the agent core owns: safe_mode and
// deadman_confirm (args {"id": "<entry id>"} or {"plan": ..., "node": ...}).
// Others are logged. Control messages ride the pinned mutual-TLS stream; they
// are not separately signed (a forged confirm could only disarm a rollback).
func (a *Agent) defaultControl(ctx context.Context, c *link.Control) error {
	switch c.Kind {
	case "safe_mode":
		a.safeMode.Store(c.On)
		if a.exec != nil {
			if err := a.exec.env.Safe.Set(c.On); err != nil {
				a.log.Error("persist safe mode", "err", err)
			}
		}
	case "deadman_confirm":
		var args struct {
			ID   string `json:"id"`
			Plan string `json:"plan"`
			Node string `json:"node"`
		}
		if err := json.Unmarshal(c.Args, &args); err != nil || (args.ID == "" && (args.Plan == "" || args.Node == "")) {
			a.log.Warn("deadman_confirm without id or plan/node", "err", err)
			return nil
		}
		a.confirmDeadman(ctx, args.Plan, args.Node, args.ID)
	default:
		a.log.Warn("unhandled control", "kind", c.Kind, "on", c.On)
	}
	return nil
}

// onDeadmanResult reports every in-process dead-man timer fire to the controller.
func (a *Agent) onDeadmanResult(e deadman.Entry, err error) {
	f := map[string]any{"id": e.ID, "node": e.NodeID, "state": string(e.State)}
	if err != nil {
		f["error"] = err.Error()
	}
	a.emit(event.Event{Kind: "agent.deadman_fired", Priority: event.PriorityCritical, Fields: f})
}
