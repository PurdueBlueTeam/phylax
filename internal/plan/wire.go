package plan

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/PurdueBlueTeam/phylax/internal/link"
)

// Conversions between the signed plan types and their typed link messages.
// Nothing is carried inside a generic field: every signed field has a field of
// the same meaning on the wire message, and the signature is recomputed from
// the fields on the receiving side, so a mismatch can only fail verification.

// StepToWire converts a signed step to its link message.
func StepToWire(s *Step) *link.Step {
	w := &link.Step{V: s.V, Plan: s.PlanID, PlanHash: s.PlanHash, Node: s.NodeID, Host: s.Host, Action: s.Action,
		Phase: s.Phase, Params: append(json.RawMessage(nil), s.Params...), Risk: string(s.Risk), RollbackPolicy: s.RollbackPolicy,
		RollbackDigest: s.RollbackDigest, SecretsDigest: s.SecretsDigest, Epoch: s.Epoch, Seq: s.Seq,
		NotBefore: s.NotBefore, NotAfter: s.NotAfter, DeadmanS: s.DeadmanSec,
		Class: string(s.Class), ExpiresAfterS: s.ExpiresAfterSec,
		Secrets: append([]byte(nil), s.Secrets...), Sig: append([]byte(nil), s.Sig...)}
	if s.Approval != nil {
		w.Approval = &link.Approval{By: s.Approval.By, At: s.Approval.At, Note: s.Approval.Note}
	}
	return w
}

// StepFromWire is the inverse of StepToWire (it does not verify anything).
func StepFromWire(w *link.Step) *Step {
	s := &Step{Secrets: append([]byte(nil), w.Secrets...), Sig: append([]byte(nil), w.Sig...)}
	s.StepBody = StepBody{V: w.V, PlanID: w.Plan, PlanHash: w.PlanHash, NodeID: w.Node, Host: w.Host, Action: w.Action,
		Phase: w.Phase, Params: append(json.RawMessage(nil), w.Params...), Risk: Risk(w.Risk), RollbackPolicy: w.RollbackPolicy,
		RollbackDigest: w.RollbackDigest, SecretsDigest: w.SecretsDigest, Epoch: w.Epoch, Seq: w.Seq,
		NotBefore: w.NotBefore, NotAfter: w.NotAfter, DeadmanSec: w.DeadmanS,
		Class: ApprovalClass(w.Class), ExpiresAfterSec: w.ExpiresAfterS}
	if w.Approval != nil {
		s.Approval = &Approval{By: w.Approval.By, At: w.Approval.At, Note: w.Approval.Note}
	}
	if len(s.Params) == 0 {
		s.Params = nil
	}
	return s
}

// ControlToWire converts a signed control to its link message.
func ControlToWire(c *Control) *link.Control {
	return &link.Control{V: c.V, Host: c.Host, Kind: c.Kind, On: c.On, Args: append(json.RawMessage(nil), c.Args...),
		Epoch: c.Epoch, Seq: c.Seq, NotBefore: c.NotBefore, NotAfter: c.NotAfter, Sig: append([]byte(nil), c.Sig...)}
}

// ControlFromWire is the inverse of ControlToWire. Absent args mean `{}`, the
// form the signer always uses.
func ControlFromWire(w *link.Control) *Control {
	args := append(json.RawMessage(nil), w.Args...)
	if len(bytes.TrimSpace(args)) == 0 {
		args = json.RawMessage("{}")
	}
	return &Control{ControlBody: ControlBody{V: w.V, Host: w.Host, Kind: w.Kind, On: w.On, Args: args, Epoch: w.Epoch,
		Seq: w.Seq, NotBefore: w.NotBefore, NotAfter: w.NotAfter}, Sig: append([]byte(nil), w.Sig...)}
}

// ResultToWire converts a signed result (and its optional detail object, whose
// SHA-256 is AfterDigest) to its link message.
func ResultToWire(r *StepResult, detail []byte) *link.StepResult {
	w := &link.StepResult{V: r.V, Plan: r.PlanID, Node: r.NodeID, Host: r.Host, Epoch: r.Epoch, Seq: r.Seq, Phase: r.Phase,
		Status: r.Outcome, Error: r.Error, StepDigest: r.StepDigest, RollbackDataHash: r.RollbackDataHash,
		BeforeDigest: r.BeforeDigest, AfterDigest: r.AfterDigest, StartedMS: r.StartedMS, FinishedMS: r.FinishedMS,
		Sig: append([]byte(nil), r.Sig...)}
	if len(detail) > 0 {
		w.Detail = append(json.RawMessage(nil), detail...)
	}
	return w
}

// ResultFromWire rebuilds the signed result from a link message. The caller
// verifies it (StepResult.Verify / VerifyExpect). Unsigned messages are refused.
func ResultFromWire(w *link.StepResult) (*StepResult, error) {
	if len(w.Sig) == 0 {
		return nil, errors.New("result: unsigned")
	}
	return &StepResult{ResultBody: ResultBody{V: w.V, PlanID: w.Plan, NodeID: w.Node, Host: w.Host, Phase: w.Phase,
		Epoch: w.Epoch, Seq: w.Seq, StepDigest: w.StepDigest, Outcome: w.Status, Error: w.Error,
		RollbackDataHash: w.RollbackDataHash, BeforeDigest: w.BeforeDigest, AfterDigest: w.AfterDigest,
		StartedMS: w.StartedMS, FinishedMS: w.FinishedMS}, Sig: append([]byte(nil), w.Sig...)}, nil
}
