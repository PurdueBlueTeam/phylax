package event

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
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
func New[T any](kind string, v T) (Event, error) {
	ty, err := declared(kind)
	if err != nil {
		return Event{}, err
	}
	if reflect.TypeOf(v) != reflect.TypeOf(ty.Fields) {
		return Event{}, fmt.Errorf("%w: %s payload %T", ErrKindMismatch, kind, v)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return Event{}, fmt.Errorf("event: encode %s: %w", kind, err)
	}
	fields := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil {
		return Event{}, fmt.Errorf("event: encode %s: %w", kind, err)
	}
	return Event{Kind: kind, Schema: ty.Schema, Priority: ty.Priority, Fields: fields}, nil
}

// Decode strictly decodes an event payload against its declared kind. Fields
// prefixed "x_" are ignored.
func Decode[T any](e Event, kind string) (T, error) {
	var out T
	ty, err := declared(kind)
	if err != nil {
		return out, err
	}
	if e.Kind != kind || reflect.TypeOf(out) != reflect.TypeOf(ty.Fields) {
		return out, fmt.Errorf("%w: event kind %q, declared %q", ErrKindMismatch, e.Kind, kind)
	}
	if e.Schema != ty.Schema {
		return out, fmt.Errorf("%w: %s schema %d, declared %d", ErrSchema, kind, e.Schema, ty.Schema)
	}
	if err := decodeFields(&out, e.Fields); err != nil {
		return out, err
	}
	return out, nil
}

// Validate strictly decodes e against its declared kind.
func Validate(e Event) error {
	ty, err := declared(e.Kind)
	if err != nil {
		return err
	}
	if e.Schema != ty.Schema {
		return fmt.Errorf("%w: %s schema %d, declared %d", ErrSchema, e.Kind, e.Schema, ty.Schema)
	}
	return decodeFields(reflect.New(reflect.TypeOf(ty.Fields)).Interface(), e.Fields)
}

// declared looks a kind up, reporting an undeclared kind as ErrUndeclared.
func declared(kind string) (Type, error) {
	ty, ok := Lookup(kind)
	if !ok {
		return Type{}, fmt.Errorf("%w: %s", ErrUndeclared, kind)
	}
	return ty, nil
}

// decodeFields decodes an event's fields into dst, dropping the producer-only
// "x_" keys and rejecting any key the declared struct does not carry.
func decodeFields(dst any, fields map[string]any) error {
	clean := make(map[string]any, len(fields))
	for k, v := range fields {
		if strings.HasPrefix(k, "x_") {
			continue
		}
		clean[k] = v
	}
	raw, err := json.Marshal(clean)
	if err != nil {
		return fmt.Errorf("event: encode fields: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("event: fields do not match the declared kind: %w", err)
	}
	return nil
}

// WithExtra returns a copy of e carrying a producer-only field under the x_
// prefix. Decode and Validate ignore such fields.
func (e Event) WithExtra(key string, v any) Event { panic("unimplemented: W1 Task 3a") }
