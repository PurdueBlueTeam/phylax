// Package event defines the telemetry event record shared by agents, the
// spool, the wire protocol and the controller store, with a canonical encoding
// and the per-agent hash chain (design: "Wire protocol and data flow", "The spool").
package event

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Priority orders events for transport and shedding. Lower values ship first
// and are shed last.
type Priority uint8

const (
	PriorityCritical Priority = iota // detections, changes, heartbeats
	PriorityHigh                     // security-relevant telemetry
	PriorityNormal                   // routine telemetry
	PriorityBulk                     // flows, sweeps, inventory
)

// Event is one record from one agent. Seq and the hashes are assigned by the
// agent's spool when the event is appended.
type Event struct {
	Agent    string         `json:"agent"`
	Seq      uint64         `json:"seq"`
	Time     time.Time      `json:"time"`
	Kind     string         `json:"kind"`
	Priority Priority       `json:"prio"`
	Fields   map[string]any `json:"fields,omitempty"`
	PrevHash string         `json:"prev"` // hex sha256 of the previous event's Hash, "" for the first
	Hash     string         `json:"hash"` // hex sha256 over the canonical body (everything except Hash)
}

// GenesisHash is the PrevHash of an agent's first event.
const GenesisHash = ""

// Canonical returns the canonical encoding of the event body used for hashing:
// JSON with object keys sorted (encoding/json sorts map keys), the Hash field
// empty, and the time in UTC with nanoseconds.
func (e Event) Canonical() ([]byte, error) {
	b := e
	b.Hash = ""
	b.Time = b.Time.UTC()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(b); err != nil {
		return nil, fmt.Errorf("event: canonical encode: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ComputeHash returns the hex sha256 of the canonical body.
func (e Event) ComputeHash() (string, error) {
	c, err := e.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// Seal sets Seq, PrevHash and Hash so the event extends a chain whose last
// event had sequence prevSeq and hash prevHash. Use prevSeq 0 and GenesisHash
// for the first event; its Seq becomes 1.
func (e *Event) Seal(prevSeq uint64, prevHash string) error {
	e.Seq = prevSeq + 1
	e.PrevHash = prevHash
	h, err := e.ComputeHash()
	if err != nil {
		return err
	}
	e.Hash = h
	return nil
}

// ErrChain reports a break in an agent's hash chain.
var ErrChain = errors.New("event: chain broken")

// Verify checks that e is a correctly sealed successor of (prevSeq, prevHash).
func (e Event) Verify(prevSeq uint64, prevHash string) error {
	if e.Seq != prevSeq+1 {
		return fmt.Errorf("%w: seq %d after %d", ErrChain, e.Seq, prevSeq)
	}
	if e.PrevHash != prevHash {
		return fmt.Errorf("%w: seq %d prev hash mismatch", ErrChain, e.Seq)
	}
	h, err := e.ComputeHash()
	if err != nil {
		return err
	}
	if h != e.Hash {
		return fmt.Errorf("%w: seq %d hash mismatch", ErrChain, e.Seq)
	}
	return nil
}
