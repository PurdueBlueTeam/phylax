package plan

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Controls (safe mode, dead-man confirm, step-status queries, ...) are signed
// with the same Ed25519 plan key as steps. A control carries the host it is for,
// the controller epoch, a per-host control sequence number that is strictly
// increasing (a parallel counter to the step sequence: steps and controls travel
// on different send queues and may overtake each other, so a shared mark would
// refuse legitimate messages) and a short validity window. The agent verifies
// every control before acting; an unsigned, forged, replayed or expired control
// is refused.

const (
	controlDomain = "phylax-control-v1\x00"
	controlV      = 1
	// DefaultControlValidity is how long a signed control stays valid.
	DefaultControlValidity = 60 * time.Second
	// MaxControlWindow bounds NotAfter-NotBefore on the verifying side.
	MaxControlWindow = 5 * time.Minute
)

// Control kinds the executor understands.
const (
	ControlSafeMode       = "safe_mode"
	ControlDeadmanConfirm = "deadman_confirm"
	ControlStepStatus     = "step_status"
)

// ControlBody is everything a control signature covers.
type ControlBody struct {
	V         int             `json:"v"`
	Host      string          `json:"host"`
	Kind      string          `json:"kind"`
	On        bool            `json:"on"`
	Args      json.RawMessage `json:"args"`
	Epoch     uint64          `json:"epoch"`
	Seq       uint64          `json:"seq"`
	NotBefore int64           `json:"not_before"`
	NotAfter  int64           `json:"not_after"`
}

// Control is a signed controller command.
type Control struct {
	ControlBody
	Sig []byte `json:"sig"`
}

func (b *ControlBody) signingBytes() ([]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	c, err := Canonicalize(raw)
	if err != nil {
		return nil, err
	}
	return append([]byte(controlDomain), c...), nil
}

// Digest identifies the control (SHA-256 of what is signed).
func (c *Control) Digest() (string, error) {
	m, err := c.signingBytes()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(m)
	return fmt.Sprintf("%x", h[:]), nil
}

// ControlSigner is the controller-side control issuer.
type ControlSigner struct {
	Key      ed25519.PrivateKey
	Epoch    uint64
	Seqs     SeqAllocator // allocates the per-host control sequence (separate from steps)
	Now      func() time.Time
	Validity time.Duration // DefaultControlValidity if zero
}

// Issue builds and signs a control for host. args must be a JSON object or nil.
func (s *ControlSigner) Issue(host, kind string, on bool, args []byte) (*Control, error) {
	if len(s.Key) != ed25519.PrivateKeySize || s.Seqs == nil {
		return nil, errors.New("control: signer not configured")
	}
	if host == "" || kind == "" {
		return nil, errors.New("control: host and kind are required")
	}
	if len(args) == 0 {
		args = []byte("{}")
	}
	seq, err := s.Seqs.Next(host, s.Epoch)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	val := s.Validity
	if val <= 0 {
		val = DefaultControlValidity
	}
	c := &Control{ControlBody: ControlBody{V: controlV, Host: host, Kind: kind, On: on, Args: json.RawMessage(args),
		Epoch: s.Epoch, Seq: seq, NotBefore: now.Unix(), NotAfter: now.Add(val).Unix()}}
	msg, err := c.signingBytes()
	if err != nil {
		return nil, err
	}
	c.Sig = ed25519.Sign(s.Key, msg)
	return c, nil
}

// ControlVerifier is the agent-side control checker. It keeps its own durable
// (epoch, seq) mark, separate from the step verifier's.
type ControlVerifier struct {
	Key    ed25519.PublicKey
	HostID string
	Store  SeqStore
	Skew   time.Duration
	Now    func() time.Time

	mu sync.Mutex
}

// Verify checks a control and, only if every check passes, durably advances
// the sequence mark before returning nil: a control that verifies is acted on
// at most once; presenting it again is a replay.
func (v *ControlVerifier) Verify(c *Control) error {
	if len(v.Key) != ed25519.PublicKeySize {
		return &StepError{ErrNoKey, ""}
	}
	if v.Store == nil {
		return &StepError{ErrNoStore, ""}
	}
	if v.HostID == "" {
		return &StepError{ErrNoHost, ""}
	}
	if c == nil || len(c.Sig) != ed25519.SignatureSize {
		return &StepError{ErrBadSignature, "missing or short signature"}
	}
	msg, err := c.signingBytes()
	if err != nil {
		return &StepError{ErrMalformed, err.Error()}
	}
	if !ed25519.Verify(v.Key, msg, c.Sig) {
		return &StepError{ErrBadSignature, ""}
	}
	if c.V != controlV {
		return &StepError{ErrMalformed, fmt.Sprintf("control version %d", c.V)}
	}
	if c.Host != v.HostID {
		return &StepError{ErrWrongHost, fmt.Sprintf("control for %q", c.Host)}
	}
	if c.Kind == "" || c.Epoch > maxSafe || c.Seq > maxSafe || c.Seq == 0 {
		return &StepError{ErrMalformed, "kind/epoch/seq out of range"}
	}
	if c.NotAfter <= c.NotBefore || time.Duration(c.NotAfter-c.NotBefore)*time.Second > MaxControlWindow {
		return &StepError{ErrMalformed, "invalid time window"}
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	skew := v.Skew
	if skew == 0 {
		skew = DefaultSkew
	}
	if now.Add(skew).Unix() < c.NotBefore {
		return &StepError{ErrNotYetValid, ""}
	}
	if now.Add(-skew).Unix() > c.NotAfter {
		return &StepError{ErrExpired, ""}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	last, err := v.Store.Load()
	if err != nil {
		return &StepError{ErrStore, err.Error()}
	}
	got := Mark{c.Epoch, c.Seq}
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
