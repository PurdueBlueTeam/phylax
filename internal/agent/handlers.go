package agent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// Reply sends a message back on the current session.
type Reply func(ctx context.Context, p link.Priority, m link.Message) error

// Handlers are the pluggable handlers for controller messages. A nil field
// uses the placeholder, which logs and rejects. A handler error ends the
// session, so handlers return nil for ordinary refusals. They run on the
// session's handler goroutine and must return promptly (the executor runs
// long work off this path).
type Handlers struct {
	Config func(ctx context.Context, c *link.Config) error
	Step   func(ctx context.Context, s *link.Step, reply Reply) error
	Fetch  func(ctx context.Context, f *link.Fetch, reply Reply) error
	// Control receives only controls that already passed signature, host,
	// window and replay verification (the agent verifies before any handler).
	Control func(ctx context.Context, c *link.Control, reply Reply) error
}

func (a *Agent) placeholderStep(ctx context.Context, s *link.Step, reply Reply) error {
	a.log.Warn("step received but execution is not implemented; rejected", "plan", s.Plan, "node", s.Node, "action", s.Action)
	phase := s.Phase
	if phase == "" {
		phase = "check"
	}
	return reply(ctx, link.PrioStep, &link.StepResult{Plan: s.Plan, Node: s.Node, Host: s.Host, Epoch: s.Epoch, Seq: s.Seq,
		Phase: phase, Status: StatusRejected, Error: "step execution not implemented on this agent"})
}

func (a *Agent) placeholderFetch(_ context.Context, f *link.Fetch, _ Reply) error {
	a.log.Warn("fetch received but not implemented; ignored", "id", f.ID, "kind", f.Kind)
	return nil
}

// handleControl verifies a control (mandatory: signed by the plan key, for
// this host, inside its validity window, with a sequence number above the
// durable control mark) and only then dispatches it. Anything else is refused
// and reported as an agent.control_refused event.
func (a *Agent) handleControl(ctx context.Context, w *link.Control, reply Reply) error {
	refuse := func(why string) error {
		a.log.Warn("control refused", "kind", w.Kind, "why", why)
		a.emit(core("agent.control_refused", event.AgentControlRefused{Kind: w.Kind, Reason: why, Epoch: w.Epoch, Seq: w.Seq}))
		return nil
	}
	if a.ctlVer == nil {
		return refuse("no plan-signing key configured: controls are never accepted unsigned")
	}
	c := plan.ControlFromWire(w)
	if err := a.ctlVer.Verify(c); err != nil {
		return refuse(err.Error())
	}
	if f := a.cfg.Handlers.Control; f != nil {
		return f(ctx, w, reply)
	}
	return a.defaultControl(ctx, c, reply)
}

// defaultControl implements the controls the agent core owns: safe_mode,
// deadman_confirm (args {"id": "<entry id>"} or {"plan": ..., "node": ...}) and
// step_status (args {"plan","node","phase","epoch","seq"}: re-send the signed
// result of that step, or say why there is none). Others are logged.
func (a *Agent) defaultControl(ctx context.Context, c *plan.Control, reply Reply) error {
	switch c.Kind {
	case plan.ControlSafeMode:
		a.safeMode.Store(c.On)
		if a.exec != nil {
			if err := a.exec.env.Safe.Set(c.On); err != nil {
				a.log.Error("persist safe mode", "err", err)
			}
		}
	case plan.ControlDeadmanConfirm:
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
	case plan.ControlStepStatus:
		return a.stepStatus(ctx, c, reply)
	default:
		a.log.Warn("unhandled control", "kind", c.Kind, "on", c.On)
	}
	return nil
}

// stepStatus answers a step_status query.
func (a *Agent) stepStatus(ctx context.Context, c *plan.Control, reply Reply) error {
	var q struct {
		Plan  string `json:"plan"`
		Node  string `json:"node"`
		Phase string `json:"phase"`
		Epoch uint64 `json:"epoch"`
		Seq   uint64 `json:"seq"`
	}
	if err := json.Unmarshal(c.Args, &q); err != nil || q.Plan == "" || q.Node == "" || q.Phase == "" || q.Seq == 0 {
		a.log.Warn("step_status with bad args", "err", err)
		return nil
	}
	x := a.exec
	if x == nil {
		return nil
	}
	k := resultKey{q.Epoch, q.Seq}
	if m, ok := x.log.get(k); ok && m.Plan == q.Plan && m.Node == q.Node {
		return reply(ctx, link.PrioStep, m) // the very same signed result as the first time
	}
	status := StatusUnknown
	x.mu.Lock()
	run := x.running[k]
	x.mu.Unlock()
	if run {
		status = StatusRunning
	} else if mark, err := x.ver.Store.Load(); err == nil && !mark.Less(plan.Mark{Epoch: q.Epoch, Seq: q.Seq}) {
		status = StatusLost
	}
	return reply(ctx, link.PrioStep, &link.StepResult{Plan: q.Plan, Node: q.Node, Host: a.bundle.Host, Epoch: q.Epoch,
		Seq: q.Seq, Phase: q.Phase, Status: status})
}

// onDeadmanResult reports every in-process dead-man timer fire to the
// controller. An entry that was armed by an expires_after node is reported as
// its expiry (design: Expiry): an agent.step_result with phase expire and the
// node and plan ids from the entry.
func (a *Agent) onDeadmanResult(e deadman.Entry, err error) {
	f := event.AgentDeadmanFired{ID: e.ID, Node: e.NodeID, State: string(e.State)}
	if err != nil {
		f.Error = err.Error()
	}
	a.emit(core("agent.deadman_fired", f))
	planID, node, ok := splitNodeKey(e.NodeID)
	if !ok {
		return
	}
	outcome := plan.OutcomeRolledBack
	if err != nil {
		outcome = plan.OutcomeFailed
	}
	ef := event.AgentStepResult{Plan: planID, Node: node, Phase: plan.PhaseExpire, Outcome: outcome}
	if err != nil {
		ef.Error = err.Error()
	}
	a.emit(core("agent.step_result", ef))
}

// splitNodeKey splits the dead-man entry's "<plan>:<node>" key. Plan ids may
// contain ':', node ids may not, so the last colon separates them.
func splitNodeKey(key string) (planID, node string, ok bool) {
	i := strings.LastIndex(key, ":")
	if i <= 0 || i == len(key)-1 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}
