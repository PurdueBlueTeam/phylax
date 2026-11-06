package plan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// Results are signed with the agent's own ECDSA P-256 identity key (the key
// the controller recorded at enrollment), not a MAC: no shared secret exists,
// and a stolen agent key only lets that host forge its own results.

const resultDomain = "phylax-result-v1\x00"

// Outcomes.
const (
	OutcomeChecked    = "checked"
	OutcomeApplied    = "applied"
	OutcomeVerified   = "verified"
	OutcomeFailed     = "failed"
	OutcomeRolledBack = "rolled_back"
	// OutcomeRollbackFailed is a failed apply or rollback whose own undo also
	// failed. It is a typed result outcome, never parsed from the error text.
	OutcomeRollbackFailed = "rollback_failed"
	// OutcomeBusy is a valid step the agent did not start because its
	// executor is full. The controller retries it; it is never a failure.
	OutcomeBusy = "busy"
)

// ResultBody is the signed content of a step result.
type ResultBody struct {
	V                int    `json:"v"`
	PlanID           string `json:"plan_id"`
	NodeID           string `json:"node_id"`
	Host             string `json:"host"`
	Phase            string `json:"phase"`
	Epoch            uint64 `json:"epoch"`
	Seq              uint64 `json:"seq"`
	StepDigest       string `json:"step_digest"`
	Outcome          string `json:"outcome"`
	Error            string `json:"error"`
	RollbackDataHash string `json:"rollback_data_hash"` // hash of the snapshot the agent took
	BeforeDigest     string `json:"before_digest"`
	AfterDigest      string `json:"after_digest"`
	StartedMS        int64  `json:"started_ms"`
	FinishedMS       int64  `json:"finished_ms"`
}

// StepResult is the agent -> controller message.
type StepResult struct {
	ResultBody
	Sig []byte `json:"sig"`
}

// NewResult starts a result bound to the step it answers.
func NewResult(s *Step, outcome string) (*StepResult, error) {
	d, err := s.Digest()
	if err != nil {
		return nil, err
	}
	return &StepResult{ResultBody: ResultBody{
		V: 1, PlanID: s.PlanID, NodeID: s.NodeID, Host: s.Host, Phase: s.Phase,
		Epoch: s.Epoch, Seq: s.Seq, StepDigest: d, Outcome: outcome,
	}}, nil
}

func (b *ResultBody) signingHash() ([32]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return [32]byte{}, err
	}
	c, err := Canonicalize(raw)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append([]byte(resultDomain), c...)), nil
}

// Sign signs the result with the agent key (P-256 only).
func (r *StepResult) Sign(key *ecdsa.PrivateKey) error {
	if key == nil || key.Curve != elliptic.P256() {
		return errors.New("result: need a P-256 key")
	}
	h, err := r.signingHash()
	if err != nil {
		return err
	}
	r.Sig, err = ecdsa.SignASN1(randReader(), key, h[:])
	return err
}

// Verify checks the signature against the host's enrolled key and that the
// result answers the given step.
func (r *StepResult) Verify(pub *ecdsa.PublicKey, step *Step) error {
	e, err := step.Expect()
	if err != nil {
		return err
	}
	return r.VerifyExpect(pub, e)
}

// Expect is what a result must answer: enough of a step to verify a result
// without holding the step itself (a controller that restarted keeps only this).
type Expect struct {
	Host, PlanID, NodeID, Phase string
	Epoch, Seq                  uint64
	Digest                      string // step digest
}

// Expect describes the result this step should get.
func (s *Step) Expect() (Expect, error) {
	d, err := s.Digest()
	if err != nil {
		return Expect{}, err
	}
	return Expect{Host: s.Host, PlanID: s.PlanID, NodeID: s.NodeID, Phase: s.Phase, Epoch: s.Epoch, Seq: s.Seq, Digest: d}, nil
}

// VerifyExpect checks the signature against the host's enrolled key and that
// the result answers the described step.
func (r *StepResult) VerifyExpect(pub *ecdsa.PublicKey, step Expect) error {
	if pub == nil || pub.Curve != elliptic.P256() {
		return errors.New("result: need a P-256 key")
	}
	h, err := r.signingHash()
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(pub, h[:], r.Sig) {
		return errors.New("result: bad signature")
	}
	if r.StepDigest != step.Digest || r.Host != step.Host || r.PlanID != step.PlanID || r.NodeID != step.NodeID ||
		r.Phase != step.Phase || r.Epoch != step.Epoch || r.Seq != step.Seq {
		return fmt.Errorf("result: does not answer step (%s,%d,%d)", step.NodeID, step.Epoch, step.Seq)
	}
	switch r.Outcome {
	case OutcomeChecked, OutcomeApplied, OutcomeVerified, OutcomeFailed, OutcomeRolledBack, OutcomeRollbackFailed, OutcomeBusy:
	default:
		return fmt.Errorf("result: unknown outcome %q", r.Outcome)
	}
	if r.FinishedMS < r.StartedMS {
		return errors.New("result: finished before started")
	}
	return nil
}
