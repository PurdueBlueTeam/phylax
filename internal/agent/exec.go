package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// ExecConfig turns on plan-step execution. Without it the agent answers every
// step with the "not implemented" rejection.
type ExecConfig struct {
	// Env is the action environment (host, root, backends, guard, tags). The
	// agent sets its Deadman manager and safe-mode switch.
	Env *actions.Env
	// PlanKey overrides the bootstrap's plan_key. One of the two is mandatory.
	PlanKey ed25519.PublicKey
	// FreshCheck makes the agent open a fresh handshake to its controller
	// after applying a dead-man-armed step and roll back at once if that
	// fails (design: Dead-man switch, step 2).
	FreshCheck bool
	// MaxConcurrent bounds steps executing at once (default 8).
	MaxConcurrent int
}

// DryRunApprover is the approver name the controller puts on check-phase
// steps; such a record never authorises a change.
const DryRunApprover = "dry-run"

const maxUnsent = 64

type execState struct {
	env   *actions.Env
	ver   *plan.Verifier
	fresh bool
	sem   chan struct{}

	mu      sync.Mutex
	unsent  []*link.StepResult
	running map[resultKey]bool
	log     *resultLog
}

// setRunning marks a verified step as executing (or done) for status queries.
func (x *execState) setRunning(s *plan.Step, on bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	k := resultKey{s.Epoch, s.Seq}
	if on {
		x.running[k] = true
	} else {
		delete(x.running, k)
	}
}

func (a *Agent) initExec() error {
	c := a.cfg.Exec
	if c == nil {
		return nil
	}
	if c.Env == nil {
		return errors.New("agent: exec enabled without an action environment")
	}
	key := c.PlanKey
	if len(key) == 0 {
		var err error
		if key, err = a.bundle.PlanPublicKey(); err != nil {
			return err
		}
	}
	if len(key) != ed25519.PublicKeySize {
		return errors.New("agent: no plan-signing key (set plan_key in the bootstrap): refusing to execute unsigned steps")
	}
	if _, ok := a.id.Cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
		return errors.New("agent: identity key is not ECDSA")
	}
	sm, err := actions.NewSafeMode(a.cfg.Layout.SafeModeFile())
	if err != nil {
		return fmt.Errorf("agent: safe mode state: %w", err)
	}
	env := c.Env
	if env.Host == "" {
		env.Host = a.bundle.Host
	}
	env.Safe = sm
	a.safeMode.Store(sm.On())
	n := c.MaxConcurrent
	if n <= 0 {
		n = 8
	}
	rl, err := openResultLog(a.cfg.Layout.Results())
	if err != nil {
		return fmt.Errorf("agent: result log: %w", err)
	}
	x := &execState{env: env, fresh: c.FreshCheck, sem: make(chan struct{}, n), running: map[resultKey]bool{}, log: rl,
		ver: &plan.Verifier{Key: key, HostID: a.bundle.Host, Store: plan.FileSeqStore{Path: a.cfg.Layout.PlanSeq()}}}
	a.exec = x
	return nil
}

func (a *Agent) stepHandler() func(context.Context, *link.Step, Reply) error {
	if f := a.cfg.Handlers.Step; f != nil {
		return f
	}
	if a.exec != nil {
		return a.handleStep
	}
	return a.placeholderStep
}

// handleStep verifies a step on the receive path (so (epoch, seq) is consumed
// in arrival order) and runs it off that path.
func (a *Agent) handleStep(ctx context.Context, w *link.Step, reply Reply) error {
	x := a.exec
	refuse := func(msg string) error {
		a.log.Warn("step refused", "plan", w.Plan, "node", w.Node, "why", msg)
		a.emit(core("agent.step_refused", event.AgentStepRefused{Plan: w.Plan, Node: w.Node, Phase: w.Phase, Reason: msg}))
		phase := w.Phase
		if phase == "" {
			phase = plan.PhaseCheck
		}
		return reply(ctx, link.PrioStep, &link.StepResult{Plan: w.Plan, Node: w.Node, Host: w.Host, Epoch: w.Epoch, Seq: w.Seq,
			Phase: phase, Status: StatusRejected, Error: msg})
	}
	// The wire message is the typed form of the signed body: the body is
	// rebuilt from its fields, so any tampered field fails the signature.
	s := plan.StepFromWire(w)
	if err := x.ver.Verify(s); err != nil {
		return refuse(err.Error())
	}
	x.setRunning(s, true)
	if s.Phase != plan.PhaseCheck && (s.Approval == nil || s.Approval.By == "" || s.Approval.By == DryRunApprover) {
		return a.finishStep(ctx, reply, s, plan.OutcomeFailed, "step has no approval record", nil)
	}
	select {
	case x.sem <- struct{}{}:
	default:
		return a.finishStep(ctx, reply, s, plan.OutcomeFailed, "agent busy: too many steps executing", nil)
	}
	a.execWG.Add(1)
	go func() {
		defer a.execWG.Done()
		defer func() { <-x.sem }()
		defer func() {
			if r := recover(); r != nil {
				a.log.Error("step panicked", "plan", s.PlanID, "node", s.NodeID, "panic", r)
				a.finishStep(a.runCtx, reply, s, plan.OutcomeFailed, fmt.Sprintf("agent panic: %v", r), nil)
			}
		}()
		a.runStep(a.runCtx, s, reply)
	}()
	return nil
}

func nodeKey(planID, node string) string { return planID + ":" + node }

func (a *Agent) runStep(ctx context.Context, s *plan.Step, reply Reply) {
	x := a.exec
	var params map[string]any
	if len(s.Params) > 0 {
		if err := json.Unmarshal(s.Params, &params); err != nil {
			a.finishStep(ctx, reply, s, plan.OutcomeFailed, "bad params: "+err.Error(), nil)
			return
		}
	}
	ctx = actions.WithTag(ctx, actions.Tag{Plan: s.PlanID, Node: s.NodeID})
	// The step's secrets (digest signed with the step) reach the action only
	// through its context, never through params, logs or results.
	var serr error
	if ctx, serr = actions.WithSecrets(ctx, s.Secrets); serr != nil {
		a.finishStep(ctx, reply, s, plan.OutcomeFailed, serr.Error(), nil)
		return
	}
	req := actions.Request{Action: s.Action, Params: params, NodeID: nodeKey(s.PlanID, s.NodeID)}
	a.emit(core("agent.step", event.AgentStep{Plan: s.PlanID, Node: s.NodeID, Phase: s.Phase, Action: s.Action, Epoch: s.Epoch, Seq: s.Seq}))

	switch s.Phase {
	case plan.PhaseCheck:
		req.DryRun = true
		out, err := x.env.Execute(ctx, req)
		if err != nil {
			a.finishStep(ctx, reply, s, plan.OutcomeFailed, err.Error(), nil)
			return
		}
		a.finishStep(ctx, reply, s, plan.OutcomeChecked, "", planDetail(out))
	case plan.PhaseApply:
		switch {
		case s.DeadmanSec > 0:
			req.Deadman = time.Duration(s.DeadmanSec) * time.Second
		case s.RollbackPolicy == plan.RollbackNone:
			req.Deadman = actions.NoDeadman
		}
		out, err := x.env.Execute(ctx, req)
		if err != nil {
			// Execute already fired any armed rollback before returning.
			a.finishStep(ctx, reply, s, plan.OutcomeFailed, err.Error(), planDetail(out))
			return
		}
		if out.DeadmanID != "" && x.fresh {
			if ferr := a.freshConn(ctx); ferr != nil {
				msg := "fresh connection to the controller failed: " + ferr.Error()
				if rerr := x.env.Rollback(context.WithoutCancel(ctx), out.DeadmanID); rerr != nil {
					msg += "; rollback: " + rerr.Error()
				} else {
					msg += "; rolled back"
				}
				a.finishStep(ctx, reply, s, plan.OutcomeFailed, msg, nil)
				return
			}
		}
		a.finishStep(ctx, reply, s, plan.OutcomeApplied, "", planDetail(out))
	case plan.PhaseVerify:
		// The action's own post-condition check (read-only by contract),
		// run again now: it catches drift between apply and this verify.
		act, err := x.registry().Get(s.Action)
		if err != nil {
			a.finishStep(ctx, reply, s, plan.OutcomeFailed, err.Error(), nil)
			return
		}
		p, err := act.Spec().Validate(params)
		if err == nil {
			err = act.Verify(ctx, x.env, p)
		}
		if err != nil {
			a.finishStep(ctx, reply, s, plan.OutcomeFailed, "verify: "+err.Error(), nil)
			return
		}
		a.finishStep(ctx, reply, s, plan.OutcomeVerified, "", nil)
	case plan.PhaseRollback:
		msg, err := a.rollbackNode(ctx, s)
		if err != nil {
			a.finishStep(ctx, reply, s, plan.OutcomeFailed, err.Error(), nil)
			return
		}
		a.finishStep(ctx, reply, s, plan.OutcomeRolledBack, "", []byte(fmt.Sprintf(`{"note":%q}`, msg)))
	default:
		a.finishStep(ctx, reply, s, plan.OutcomeFailed, "unknown phase "+s.Phase, nil)
	}
}

func (x *execState) registry() *actions.Registry {
	if x.env.Registry == nil {
		x.env.Registry = actions.Core()
	}
	return x.env.Registry
}

// rollbackNode fires the node's pending dead-man entries now. A node whose
// entry already rolled back (the timer got there first) is a success; one with
// nothing recoverable is an error.
func (a *Agent) rollbackNode(ctx context.Context, s *plan.Step) (string, error) {
	entries, err := a.dm.List()
	if err != nil {
		return "", err
	}
	key := nodeKey(s.PlanID, s.NodeID)
	var fired, already, confirmed int
	for _, e := range entries {
		if e.NodeID != key {
			continue
		}
		switch e.State {
		case deadman.StateArmed, deadman.StateRollbackFailed:
			if err := a.exec.env.Rollback(ctx, e.ID); err != nil {
				return "", fmt.Errorf("rollback %s: %w", e.ID, err)
			}
			fired++
		case deadman.StateRolledBack:
			already++
		case deadman.StateConfirmed:
			confirmed++
		}
	}
	switch {
	case fired > 0:
		return fmt.Sprintf("rolled back %d change(s)", fired), nil
	case already > 0:
		return "already rolled back", nil
	case confirmed > 0:
		return "", errors.New("change was confirmed; its rollback data is released")
	}
	return "", errors.New("nothing to roll back: no dead-man entry for this node")
}

// freshConn proves the controller is reachable over a new connection.
func (a *Agent) freshConn(ctx context.Context) error {
	var last error
	for _, addr := range a.bundle.Controllers {
		c, err := link.Dial(ctx, addr, link.DialOptions{Identity: a.id, ServerPin: a.pin, ALPN: link.ALPNAgent, Timeout: a.cfg.DialTimeout})
		if err == nil {
			c.Close()
			return nil
		}
		last = err
	}
	return last
}

func planDetail(o *actions.Outcome) []byte {
	if o == nil {
		return nil
	}
	b, _ := json.Marshal(map[string]any{"done": o.Plan.Done, "changed": o.Changed, "diff": o.Plan.Diff,
		"notes": o.Plan.Notes, "blocked": o.Plan.Blocked, "risk": o.Risk, "deadman": o.DeadmanID})
	return b
}

// finishStep signs and sends the result; if the link is down the result is
// kept (bounded) and flushed after the next reconnect. Every result is also
// recorded durably so the controller can ask for it again (step_status).
func (a *Agent) finishStep(ctx context.Context, reply Reply, s *plan.Step, outcome, errMsg string, detail []byte) error {
	started := time.Now()
	x := a.exec
	defer x.setRunning(s, false)
	res, err := plan.NewResult(s, outcome)
	if err != nil {
		return err
	}
	res.Error = errMsg
	if len(res.Error) > 4000 {
		res.Error = res.Error[:4000]
	}
	res.StartedMS, res.FinishedMS = started.UnixMilli(), started.UnixMilli()
	if len(detail) > 0 {
		h := sha256.Sum256(detail)
		res.AfterDigest = hex.EncodeToString(h[:])
	}
	key := a.id.Cert.PrivateKey.(*ecdsa.PrivateKey)
	if err := res.Sign(key); err != nil {
		return err
	}
	m := plan.ResultToWire(res, detail)
	if err := x.log.add(m); err != nil {
		a.log.Warn("could not persist step result", "err", err)
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := reply(sctx, link.PrioStep, m); err != nil {
		x.mu.Lock()
		if len(x.unsent) < maxUnsent {
			x.unsent = append(x.unsent, m)
		}
		x.mu.Unlock()
		return err
	}
	return nil
}

// flushResults re-sends results that could not be delivered earlier.
func (a *Agent) flushResults(ctx context.Context, sess *link.Session) {
	x := a.exec
	if x == nil {
		return
	}
	x.mu.Lock()
	pend := x.unsent
	x.unsent = nil
	x.mu.Unlock()
	for i, m := range pend {
		if err := sess.Send(ctx, link.PrioStep, m); err != nil {
			x.mu.Lock()
			x.unsent = append(pend[i:], x.unsent...)
			x.mu.Unlock()
			return
		}
	}
}

// confirmDeadman disarms the dead-man entries of a node (control message).
func (a *Agent) confirmDeadman(ctx context.Context, planID, node, id string) {
	if id != "" {
		if _, err := a.dm.Confirm(ctx, id); err != nil {
			a.log.Warn("deadman confirm failed", "id", id, "err", err)
		}
		return
	}
	entries, err := a.dm.List()
	if err != nil {
		a.log.Warn("deadman list", "err", err)
		return
	}
	key := nodeKey(planID, node)
	n := 0
	for _, e := range entries {
		if e.NodeID == key && e.State == deadman.StateArmed {
			n++
			if _, err := a.dm.Confirm(ctx, e.ID); err != nil {
				a.log.Warn("deadman confirm failed", "id", e.ID, "err", err)
			}
		}
	}
	if n == 0 {
		a.log.Info("deadman confirm: nothing armed for node", "plan", planID, "node", node)
	}
}
