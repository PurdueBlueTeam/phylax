package agent
import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/PurdueBlueTeam/phylax/internal/action"
	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// stateDir returns the agent's state directory.
func (a *Agent) stateDir() string { return a.dir }

func writeFile(path string, b []byte, mode int32) error {
	return os.WriteFile(path, b, os.FileMode(mode))
}
// steps.go implements the agent side of plan execution: step verification,
// action dispatch, and per-phase step results (docs: Build plan → M2).

// SetRegistry overrides the action catalog (tests).
func (a *Agent) SetRegistry(r *action.Registry) {
	if r != nil {
		a.reg = r
	}
}

// Registry exposes the action catalog.
func (a *Agent) Registry() *action.Registry {
	if a.reg == nil {
		a.reg = action.Default()
	}
	return a.reg
}

// safeModeFlagPath is the persistent safe-mode flag (agent.safe_mode).
func (a *Agent) safeModeFlagPath() string { return a.stateDir() + "/safe_mode" }

// SetSafeMode toggles the flag file and the in-memory state.
func (a *Agent) SetSafeMode(on bool) {
	v := "0"
	if on {
		v = "1"
	}
	if err := os.WriteFile(a.safeModeFlagPath(), []byte(v), 0o600); err == nil {
		a.safeMode = on
	}
	a.log.Printf("safe mode %v", on)
}

func (a *Agent) handleStep(_ context.Context, lc *link.Conn, m *link.Message) error {
	var st link.Step
	if err := link.DecodeJSON(m.Payload, &st); err != nil {
		return err
	}
	a.log.Printf("step %s/%s op=%s action=%s", st.Plan, st.Node, st.Op, st.Action)

	if a.bundle.PlanKey != "" {
		pub, err := base64.StdEncoding.DecodeString(a.bundle.PlanKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			a.stepResult(lc, st, "check", false, false, "bad plan key", nil)
			a.Publish("plan_rejected", map[string]any{"plan": st.Plan, "node": st.Node, "why": "bad plan key"})
			return nil
		}
		sig, err := base64.StdEncoding.DecodeString(st.Sig)
		can := canonicalStep(st)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), []byte(can), sig) {
			a.stepResult(lc, st, "check", false, false, "bad signature", nil)
			a.Publish("plan_rejected", map[string]any{"plan": st.Plan, "node": st.Node, "why": "bad signature"})
			return nil
		}
	}

	act, err := a.Registry().Get(st.Action)
	if err != nil {
		a.stepResult(lc, st, "check", false, false, err.Error(), nil)
		return nil
	}

	params := action.Params(map[string]any{})
	for k, v := range st.Params {
		params[k] = v
	}
	for k, v := range st.Secrets {
		params[k] = v
	}
	// Action resource locks: a step may not run while another step holds
	// one of its declared resources.
	var held []string
	a.locksMu.Lock()
	for _, r := range act.Locks() {
		if other, busy := a.locks[r]; busy && other != st.Node {
			a.locksMu.Unlock()
			a.stepResult(lc, st, st.Phase, false, false, "lock held by "+other+": "+r, nil)
			return nil
		}
	}
	for _, r := range act.Locks() {
		a.locks[r] = st.Node
		held = append(held, r)
	}
	a.locksMu.Unlock()
	defer func() {
		a.locksMu.Lock()
		for _, r := range held {
			if a.locks[r] == st.Node {
				delete(a.locks, r)
			}
		}
		a.locksMu.Unlock()
	}()
	switch st.Op {
	case "run":
		if a.safeMode {
			a.stepResult(lc, st, st.Phase, false, false, "safe mode: run refused (rollback allowed)", nil)
			return nil
		}
		switch st.Phase {
		case "apply":
			cr, err := act.Apply(params)
			a.stepResult(lc, st, "apply", err == nil, false, cr.Diff, cr.Before)
		case "verify":
			cr, err := act.Verify(params)
			a.stepResult(lc, st, "verify", err == nil, cr.Done, cr.Diff, cr.Before)
		default: // "check" (the controller dispatches one phase per step)
			cr, err := act.Check(params)
			a.stepResult(lc, st, "check", err == nil, cr.Done, cr.Diff, cr.Before)
		}
	case "rollback":
		before := st.Before
		cr, err := act.Rollback(params, before)
		detail := cr.Diff
		if err != nil {
			detail = err.Error()
		}
		a.stepResult(lc, st, "rollback", err == nil, cr.Done, detail, cr.Before)
	default:
		a.stepResult(lc, st, st.Phase, false, false, "unknown op "+st.Op, nil)
	}
	return nil
}

// canonicalStep is the signing string (must match plan.Canonical on the
// controller).
func canonicalStep(st link.Step) string {
	ps, _ := json.Marshal(st.Params)
	return st.Plan + "|" + st.Node + "|" + fmt.Sprint(st.Epoch) + "|" +
		fmt.Sprint(st.Seq) + "|" + st.Op + "|" + st.Phase + "|" + st.Action + "|" + string(ps)
}

func (a *Agent) stepResult(lc *link.Conn, st link.Step, phase string, ok, done bool, detail string, before []byte) {
	sr := &link.StepResult{
		Plan:   st.Plan,
		Node:   st.Node,
		Epoch:  st.Epoch,
		Seq:    st.Seq,
		Phase:  phase,
		OK:     ok,
		Done:   done,
		Detail: detail,
	}
	if before != nil {
		sr.Before = before
	}
	_ = a.send(lc, link.TypStepResult, sr)
}

func (a *Agent) handleControl(_ context.Context, lc *link.Conn, m *link.Message) error {
	var ct link.Control
	if err := link.DecodeJSON(m.Payload, &ct); err != nil {
		return err
	}
	switch ct.Kind {
	case "safe_mode":
		a.SetSafeMode(ct.On)
	case "freeze":
		a.log.Printf("freeze %v (planned)", ct.On)
	case "patch_window":
		a.log.Printf("patch window %v (planned)", ct.On)
	}
	return nil
}

