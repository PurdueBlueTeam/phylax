// Package actions is the agent's action framework (design: Execution,
// "Actions"): typed actions with check / plan / apply / verify / rollback
// capture, risk classes, named per-host resource locks, safe mode, tagging, a
// scoring guard, and the first core actions (files, local accounts, services).
package actions

import (
	"context"
	"errors"
)

// Risk is an action's risk class.
type Risk string

const (
	RiskNone        Risk = "none"
	RiskService     Risk = "service"
	RiskLockout     Risk = "lockout"
	RiskDestructive Risk = "destructive"
)

// Plan is the dry-run result of an action: what Apply would do.
type Plan struct {
	Done    bool     // already in the desired state; Apply is skipped
	Diff    string   // human-readable diff (secrets redacted)
	Notes   []string // warnings, e.g. "not reversible"
	Blocked string   // set by the executor when a needed lock is held
}

// Rollback is the data needed to undo an Apply, in the form the dead-man
// journal stores. A zero Kind means the change cannot be undone automatically.
type Rollback struct {
	Kind string
	Data any
}

// Output carries an action's results (e.g. the hash computed by file.hash).
type Output map[string]string

// Action is one typed operation. Implementations are stateless; everything
// they need comes from Env and Params.
type Action interface {
	Spec() Spec
	// Locks names the resources the action needs (see lock.go).
	Locks(p Params) []string
	// Touches lists the scorer-visible properties the action affects, for the
	// ScoringGuard.
	Touches(p Params) []Touch
	// Plan is the read-only check/dry-run. It must not change anything.
	Plan(ctx context.Context, env *Env, p Params) (Plan, error)
	// Capture records the state needed to undo Apply. Called under the locks,
	// before Apply.
	Capture(ctx context.Context, env *Env, p Params) (Rollback, error)
	Apply(ctx context.Context, env *Env, p Params) (Output, error)
	// Verify checks the post-condition after Apply.
	Verify(ctx context.Context, env *Env, p Params) error
}

var (
	ErrSafeMode      = errors.New("actions: agent is in safe mode; only rollback and read-only actions are permitted")
	ErrNoDeadman     = errors.New("actions: risky action needs the dead-man switch but none is configured")
	ErrUnsupported   = errors.New("actions: not supported on this platform")
	ErrUnknown       = errors.New("actions: unknown action")
	ErrNotReversible = errors.New("actions: action cannot be rolled back automatically")
)
