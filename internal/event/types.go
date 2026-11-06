package event

import (
	"errors"
	"sort"
	"sync"
)

// Type is one declared event kind: its schema version, default priority, alert
// flag and payload struct.
type Type struct {
	Kind     string   `json:"kind"`
	Schema   int      `json:"schema"`
	Priority Priority `json:"prio"`
	Alert    bool     `json:"alert,omitempty"`
	Fields   any      `json:"-"` // zero value of the payload struct
}

var (
	ErrUndeclared   = errors.New("event: kind not declared")
	ErrKindMismatch = errors.New("event: kind or payload type mismatch")
	ErrSchema       = errors.New("event: schema version not understood")
)

var (
	typesMu sync.RWMutex
	types   = map[string]Type{}
)

// Declare adds a kind to the process-wide registry. It is called from init and
// panics on a duplicate kind, a schema below 1, a nil payload or an empty kind.
func Declare(t Type) {
	typesMu.Lock()
	defer typesMu.Unlock()
	if t.Kind == "" || t.Schema < 1 || t.Fields == nil {
		panic("event: invalid declaration")
	}
	if _, dup := types[t.Kind]; dup {
		panic("event: duplicate kind " + t.Kind)
	}
	types[t.Kind] = t
}

// Lookup returns a declared kind.
func Lookup(kind string) (Type, bool) {
	typesMu.RLock()
	defer typesMu.RUnlock()
	t, ok := types[kind]
	return t, ok
}

// Declared returns every declared kind sorted by kind name.
func Declared() []Type {
	typesMu.RLock()
	out := make([]Type, 0, len(types))
	for _, t := range types {
		out = append(out, t)
	}
	typesMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

// New builds an event of a declared kind. The payload must be the declared
// struct type; numbers are kept as json.Number so an in-process consumer sees
// the same shape as one reading the store.
func New[T any](kind string, v T) (Event, error) { panic("unimplemented: W1 Task 3") }

// Decode strictly decodes an event payload against its declared kind. Fields
// prefixed "x_" are ignored.
func Decode[T any](e Event, kind string) (T, error) { panic("unimplemented: W1 Task 3") }

// Validate strictly decodes e against its declared kind.
func Validate(e Event) error { panic("unimplemented: W1 Task 3") }

// WithExtra returns a copy of e carrying a producer-only field under the x_
// prefix. Decode and Validate ignore such fields.
func (e Event) WithExtra(key string, v any) Event { panic("unimplemented: W1 Task 3a") }
