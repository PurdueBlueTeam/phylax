package plan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Signature algorithm: Ed25519 for plan steps (design: "Ed25519 plan-signing
// key held only in controller memory"). It is deterministic, has no nonce
// failure mode, and steps are verified only by our own agent code, so the
// SChannel limitation that forces P-256 for TLS does not apply. Results are
// signed with the agent's P-256 identity key (see result.go).

const (
	stepVersion   = 1
	stepDomain    = "phylax-step-v1\x00"
	MaxStepBytes  = 4 << 20 // design: max message size
	MaxStepWindow = 24 * time.Hour
	DefaultSkew   = 60 * time.Second
	maxSafe       = uint64(1) << 53
)

// Phases a step can request.
const (
	PhaseCheck    = "check"
	PhaseApply    = "apply"
	PhaseVerify   = "verify"
	PhaseRollback = "rollback"
	// PhaseExpire reports a time-boxed node whose change ended at its
	// expires_after deadline (design: Execution engine, Expiry).
	PhaseExpire = "expire"
)

// Rollback policies.
const (
	RollbackAuto   = "auto"   // agent rolls back by itself on failure or dead-man expiry
	RollbackManual = "manual" // only on an explicit rollback step
	RollbackNone   = "none"   // irreversible, must be destructive-approved
)

// StepBody is everything the signature covers. Adding a field here covers it
// automatically; the tamper test iterates over every field by reflection.
type StepBody struct {
	V               int             `json:"v"`
	PlanID          string          `json:"plan_id"`
	PlanHash        string          `json:"plan_hash"`
	NodeID          string          `json:"node_id"`
	Host            string          `json:"host"`
	Action          string          `json:"action"`
	Phase           string          `json:"phase"`
	Params          json.RawMessage `json:"params"`
	Risk            Risk            `json:"risk"`
	Approval        *Approval       `json:"approval"`
	RollbackPolicy  string          `json:"rollback_policy"`
	RollbackDigest  string          `json:"rollback_digest"` // sha256 hex of rollback data, "" if none
	SecretsDigest   string          `json:"secrets_digest"`  // sha256 hex of Secrets, "" if none
	Epoch           uint64          `json:"epoch"`
	Seq             uint64          `json:"seq"`
	NotBefore       int64           `json:"not_before"` // unix seconds
	NotAfter        int64           `json:"not_after"`
	DeadmanSec      int             `json:"deadman_sec"`
	Class           ApprovalClass   `json:"class,omitempty"`
	ExpiresAfterSec int             `json:"expires_after_sec,omitempty"`
}

// Step is the wire message. Secrets is the per-host secrets blob; it is not
// signed byte-for-byte but its SHA-256 is (SecretsDigest), so it is covered
// transitively. It rides inside the pinned mutual-TLS stream; the design
// specifies no further encryption to the agent.
type Step struct {
	StepBody
	Secrets []byte `json:"secrets,omitempty"`
	Sig     []byte `json:"sig"`
}

func digest(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// DataDigest hashes rollback data or secrets the way steps expect.
func DataDigest(b []byte) string { return digest(b) }

func (b *StepBody) signingBytes() ([]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	c, err := Canonicalize(raw)
	if err != nil {
		return nil, err
	}
	return append([]byte(stepDomain), c...), nil
}

// Digest identifies this step (SHA-256 of what is signed); results echo it.
func (s *Step) Digest() (string, error) {
	m, err := s.signingBytes()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(m)
	return hex.EncodeToString(h[:]), nil
}

// Encode serialises the step for the wire.
func (s *Step) Encode() ([]byte, error) { return json.Marshal(s) }

// DecodeStep parses a wire step strictly: size-capped, unknown fields and
// trailing data rejected.
func DecodeStep(data []byte) (*Step, error) {
	if len(data) > MaxStepBytes {
		return nil, &StepError{ErrMalformed, "step too large"}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Step
	if err := dec.Decode(&s); err != nil {
		return nil, &StepError{ErrMalformed, err.Error()}
	}
	if dec.More() {
		return nil, &StepError{ErrMalformed, "trailing data"}
	}
	if _, err := dec.Token(); err == nil {
		return nil, &StepError{ErrMalformed, "trailing data"}
	}
	return &s, nil
}

// Typed verification errors; use errors.Is.
var (
	ErrNoKey          = errors.New("step: no plan-signing key configured")
	ErrNoStore        = errors.New("step: no sequence store configured")
	ErrNoHost         = errors.New("step: verifier has no host id")
	ErrMalformed      = errors.New("step: malformed")
	ErrBadSignature   = errors.New("step: bad signature")
	ErrWrongHost      = errors.New("step: addressed to a different host")
	ErrStaleEpoch     = errors.New("step: epoch older than accepted")
	ErrReplay         = errors.New("step: sequence not greater than last accepted")
	ErrNotYetValid    = errors.New("step: not yet valid")
	ErrExpired        = errors.New("step: expired")
	ErrDigestMismatch = errors.New("step: secrets digest mismatch")
	ErrUnexpectedPlan = errors.New("step: unexpected plan id")
	ErrStore          = errors.New("step: sequence store failure")
)

// StepError carries a sentinel and detail.
type StepError struct {
	Err    error
	Detail string
}

func (e *StepError) Error() string {
	if e.Detail == "" {
		return e.Err.Error()
	}
	return e.Err.Error() + ": " + e.Detail
}
func (e *StepError) Unwrap() error { return e.Err }

// Mark is the persisted high-water mark.
type Mark struct {
	Epoch uint64 `json:"epoch"`
	Seq   uint64 `json:"seq"`
}

// Less orders marks lexicographically by (epoch, seq).
func (m Mark) Less(o Mark) bool { return m.Epoch < o.Epoch || (m.Epoch == o.Epoch && m.Seq < o.Seq) }

// SeqStore persists the highest accepted (epoch, seq) for one agent.
type SeqStore interface {
	Load() (Mark, error) // zero Mark if nothing stored yet
	Save(Mark) error     // must be durable before returning
}

// Verifier is the agent-side step checker.
type Verifier struct {
	Key    ed25519.PublicKey
	HostID string
	Store  SeqStore
	// PlanOK, if set, must accept the step's plan id (agent-side pinning of
	// expected plans). Nil accepts any signed plan.
	PlanOK func(planID string) bool
	Skew   time.Duration    // tolerated clock skew; DefaultSkew if zero
	Now    func() time.Time // time.Now if nil

	mu sync.Mutex
}

// VerifyBytes decodes and verifies a wire step.
func (v *Verifier) VerifyBytes(data []byte) (*Step, error) {
	s, err := DecodeStep(data)
	if err != nil {
		return nil, err
	}
	if err := v.Verify(s); err != nil {
		return nil, err
	}
	return s, nil
}

// Verify checks a step and, only if every check passes, durably advances the
// sequence mark before returning nil. A step that returns nil must be
// executed at most once; the same step presented again is a replay.
func (v *Verifier) Verify(s *Step) error {
	if len(v.Key) != ed25519.PublicKeySize {
		return &StepError{ErrNoKey, ""}
	}
	if v.Store == nil {
		return &StepError{ErrNoStore, ""}
	}
	if v.HostID == "" {
		return &StepError{ErrNoHost, ""}
	}
	if s == nil || len(s.Sig) != ed25519.SignatureSize {
		return &StepError{ErrBadSignature, "missing or short signature"}
	}
	msg, err := s.signingBytes()
	if err != nil {
		return &StepError{ErrMalformed, err.Error()}
	}
	if !ed25519.Verify(v.Key, msg, s.Sig) {
		return &StepError{ErrBadSignature, ""}
	}
	// From here the content is authentic.
	if s.V != stepVersion {
		return &StepError{ErrMalformed, fmt.Sprintf("version %d", s.V)}
	}
	if s.Host != v.HostID {
		return &StepError{ErrWrongHost, fmt.Sprintf("step for %q", s.Host)}
	}
	if s.Epoch > maxSafe || s.Seq > maxSafe || s.Seq == 0 {
		return &StepError{ErrMalformed, "epoch/seq out of range"}
	}
	if s.NotAfter <= s.NotBefore || time.Duration(s.NotAfter-s.NotBefore)*time.Second > MaxStepWindow {
		return &StepError{ErrMalformed, "invalid time window"}
	}
	if s.DeadmanSec < 0 {
		return &StepError{ErrMalformed, "negative deadman"}
	}
	if d := digest(s.Secrets); d != s.SecretsDigest {
		return &StepError{ErrDigestMismatch, ""}
	}
	if v.PlanOK != nil && !v.PlanOK(s.PlanID) {
		return &StepError{ErrUnexpectedPlan, s.PlanID}
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	skew := v.Skew
	if skew == 0 {
		skew = DefaultSkew
	}
	if now.Add(skew).Unix() < s.NotBefore {
		return &StepError{ErrNotYetValid, ""}
	}
	if now.Add(-skew).Unix() > s.NotAfter {
		return &StepError{ErrExpired, ""}
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	last, err := v.Store.Load()
	if err != nil {
		return &StepError{ErrStore, err.Error()}
	}
	got := Mark{s.Epoch, s.Seq}
	if got.Epoch < last.Epoch {
		return &StepError{ErrStaleEpoch, fmt.Sprintf("%d < %d", got.Epoch, last.Epoch)}
	}
	if !last.Less(got) {
		return &StepError{ErrReplay, fmt.Sprintf("(%d,%d) <= (%d,%d)", got.Epoch, got.Seq, last.Epoch, last.Seq)}
	}
	if err := v.Store.Save(got); err != nil {
		return &StepError{ErrStore, err.Error()}
	}
	return nil
}

// SeqAllocator hands the controller per-host strictly increasing sequence numbers.
type SeqAllocator interface {
	Next(host string, epoch uint64) (uint64, error)
}

// MemSeq is an in-memory SeqAllocator. The controller persists its own state
// (and bumps the epoch on snapshot restore) elsewhere.
type MemSeq struct {
	mu sync.Mutex
	m  map[string]uint64
}

// Next implements SeqAllocator.
func (m *MemSeq) Next(host string, epoch uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string]uint64{}
	}
	m.m[host]++
	return m.m[host], nil
}

// Signer is the controller-side step issuer.
type Signer struct {
	Key   ed25519.PrivateKey
	Epoch uint64
	Seqs  SeqAllocator
	Now   func() time.Time
}

// IssueOpts parameterises Issue.
type IssueOpts struct {
	Phase          string
	Secrets        []byte // this host's secrets only
	RollbackPolicy string // default auto for dead-man/lockout nodes, else manual
	RollbackData   []byte // digest is signed; the data itself travels as chunks
	Validity       time.Duration
}

// Issue builds and signs the step for one node of a run. The node must be
// approved (the approval record is signed in).
func (s *Signer) Issue(p *Plan, run *Run, nodeID string, o IssueOpts) (*Step, error) {
	if len(s.Key) != ed25519.PrivateKeySize || s.Seqs == nil {
		return nil, errors.New("step: signer not configured")
	}
	run.mu.Lock()
	n, ok := run.node(nodeID)
	appr, hasAppr := run.approvals[nodeID]
	eff := run.res.risk[nodeID]
	run.mu.Unlock()
	if !ok || n.Gate {
		return nil, fmt.Errorf("step: %q is not an action node", nodeID)
	}
	if !hasAppr {
		return nil, fmt.Errorf("step: node %q has no approval record", nodeID)
	}
	switch o.Phase {
	case PhaseCheck, PhaseApply, PhaseVerify, PhaseRollback:
	default:
		return nil, fmt.Errorf("step: bad phase %q", o.Phase)
	}
	hash, err := p.Hash()
	if err != nil {
		return nil, err
	}
	params := n.ActionParams()
	if params == nil {
		params = map[string]any{}
	}
	praw, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	pol := o.RollbackPolicy
	if pol == "" {
		pol = RollbackManual
		if EffectiveDeadmanSec(n, eff) > 0 {
			pol = RollbackAuto
		}
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	val := o.Validity
	if val <= 0 {
		val = 5 * time.Minute
	}
	seq, err := s.Seqs.Next(n.Target, s.Epoch)
	if err != nil {
		return nil, err
	}
	st := &Step{Secrets: o.Secrets}
	st.StepBody = StepBody{
		V: stepVersion, PlanID: p.ID, PlanHash: hash, NodeID: nodeID, Host: n.Target,
		Action: n.Action, Phase: o.Phase, Params: praw, Risk: eff, Approval: &appr,
		RollbackPolicy: pol, RollbackDigest: digest(o.RollbackData), SecretsDigest: digest(o.Secrets),
		Epoch: s.Epoch, Seq: seq, NotBefore: now.Unix(), NotAfter: now.Add(val).Unix(),
		DeadmanSec: EffectiveDeadmanSec(n, eff), Class: p.Class, ExpiresAfterSec: n.ExpiresAfterSec,
	}
	return st, s.sign(st)
}

func (s *Signer) sign(st *Step) error {
	msg, err := st.signingBytes()
	if err != nil {
		return err
	}
	st.Sig = ed25519.Sign(s.Key, msg)
	return nil
}
