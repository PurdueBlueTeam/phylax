// Package action is the typed, Go-native action catalog: every operation a
// plan node can perform on a host. An action has four phases — check
// (idempotency probe, produces a readable diff), apply, verify and rollback —
// declares a risk class and the named resource locks it takes.
//
// Actions run inside the agent, with root, on the live host. They must be
// idempotent: the hardening plan re-runs from zero after a VM reset, so a
// second apply over an already-applied state is a no-op, not an error.
package action

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Risk class for a plan node (design: Execution → Actions).
type Risk string

const (
	RiskNone        Risk = "none"
	RiskService     Risk = "service"
	RiskLockout     Risk = "lockout"
	RiskDestructive Risk = "destructive"
)

// CheckResult is what each phase reports.
type CheckResult struct {
	// Done means the host is already in the desired state (check phase) or
	// the state matches what apply produced (verify phase).
	Done bool
	// Diff is a human-readable description of the change (check) or the
	// observed state (verify). Empty when Done in the check phase.
	Diff string
	// Before/After are raw state snapshots for the UI diff and rollback.
	Before []byte
	After  []byte
}

// Action is one typed operation. All calls are synchronous and blocking.
type Action interface {
	// Name is the catalog name, e.g. "file.write".
	Name() string
	// Risk is the node's risk class.
	Risk() Risk
	// Locks are the named host resources this action takes while running.
	Locks() []string
	// Check probes current state and reports the would-be change.
	Check(params Params) (CheckResult, error)
	// Apply makes the change; Before holds the snapshot rollback uses.
	Apply(params Params) (CheckResult, error)
	// Verify confirms the host is in the applied state.
	Verify(params Params) (CheckResult, error)
	// Rollback restores Before, captured by Apply.
	Rollback(params Params, before []byte) (CheckResult, error)
}

// Params is an action's parameter map (JSON-decoded from the plan).
type Params map[string]any

// Get returns the string parameter key, or def when absent.
func (p Params) Get(key, def string) string {
	if v, ok := p[key].(string); ok {
		return v
	}
	return def
}

// GetInt returns the integer parameter key (accepts float64 from JSON), or
// def when absent.
func (p Params) GetInt(key string, def int) int {
	switch v := p[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return def
}

// GetBool returns the boolean parameter key, or def when absent.
func (p Params) GetBool(key string, def bool) bool {
	if v, ok := p[key].(bool); ok {
		return v
	}
	return def
}

// GetList returns the string-list parameter key, or nil when absent. It
// accepts both the JSON-decoded form ([]any) and native []string, so plan
// params and Go callers work alike.
func (p Params) GetList(key string) []string {
	switch v := p[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}

// GetJSON decodes the parameter key into out; missing key leaves out alone.
func (p Params) GetJSON(key string, out any) error {
	raw, ok := p[key]
	if !ok {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}
// Enc is a string snapshot encoder for wire state.
func Enc(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Dec is Enc's inverse.
func Dec(s string) []byte {
	if s == "" {
		return nil
	}
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

// Registry maps catalog names to action factories.
type Registry struct {
	m map[string]func() Action
}

func NewRegistry() *Registry { return &Registry{m: map[string]func() Action{}} }

// Register adds an action under its catalog name.
func (r *Registry) Register(name string, f func() Action) {
	r.m[name] = f
}

// Get returns a fresh action instance.
func (r *Registry) Get(name string) (Action, error) {
	f, ok := r.m[name]
	if !ok {
		return nil, fmt.Errorf("unknown action %q", name)
	}
	return f(), nil
}

// Names lists the catalog, sorted.
func (r *Registry) Names() []string {
	ks := make([]string, 0, len(r.m))
	for k := range r.m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// HashBytes is a short content hash for diff annotations.
func HashBytes(b []byte) string {
	s := sum256(b)
	return hex.EncodeToString(s[:])[:12]
}
