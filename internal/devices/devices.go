// Package devices holds the network-device adapter interface and the
// controller-side safe-change runner. The adapter exposes primitives; the
// runner owns the protocol (lock, snapshot, stage, validate, commit with a
// dead-man, health check, confirm or roll back), so the same runner serves
// every device (design: "Network devices and credentials").
package devices

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"
)

// Kind names a device family.
type Kind string

const (
	PanOS Kind = "panos"
	VyOS  Kind = "vyos"
)

// Risk classes, matching internal/manifest/render.
type Risk string

const (
	RiskNone        Risk = "none"
	RiskService     Risk = "service"
	RiskLockout     Risk = "lockout"
	RiskDestructive Risk = "destructive"
)

// Scope values for TxOptions.Scope.
const (
	ScopePolicy     = "policy"
	ScopeManagement = "management"
)

// Transport is how the controller reaches a device (directly or through a
// device-proxy host). The adapter never dials on its own.
type Transport struct {
	HTTP *http.Client                                             // pinned TLS, proxied dial
	Dial func(ctx context.Context, addr string) (net.Conn, error) // for SSH
	Host string                                                   // management address as seen from the proxy
}

// Caps says what a device does natively.
type Caps struct {
	NativeConfirm  bool // the device itself reverts if not confirmed (none today)
	SoftDeadman    bool // the adapter can arm an on-box timer revert (VyOS over SSH)
	ConfigLock     bool
	ScopedCommit   bool
	StagedDiff     bool
	Validate       bool
	ConnEvents     bool
	AuditLog       bool
	RollbackNative bool
}

// Info is liveness and identity.
type Info struct {
	Kind     Kind
	Hostname string
	Version  string
	Serial   string
	Uptime   time.Duration
	Clock    time.Time
	Extra    map[string]string
}

// Snapshot is a canonical copy of the running configuration.
type Snapshot struct {
	Device string
	Label  string
	Taken  time.Time
	Data   []byte // canonical bytes (hash input)
	Hash   string // sha256 hex of Data
	Meta   map[string]string
}

// ConfigEvent feeds the controller's device_config events and D14.
type ConfigEvent struct {
	Device string
	// Change: diff|commit|login|login_fail|lock|admin_add|admin_del|key_change|oob|pending
	Change string
	Actor  string
	SrcIP  string
	Detail string
	Path   string
	Ours   bool   // true only inside our own Tx window and matching our actor
	Tag    string // plan id when Ours
	When   time.Time
}

// DriftReport is the result of comparing the device with the last known-good.
type DriftReport struct {
	Device  string
	Drifted bool
	Hash    string
	Diff    Diff
	Events  []ConfigEvent
}

// AdminSession is a live or configured administrator.
type AdminSession struct {
	Name string
	From string
	Type string
}

// AdminState is who is on the device now and who is configured.
type AdminState struct {
	Sessions   []AdminSession
	Configured []string
}

// Cursor is an opaque high-water mark for Events.
type Cursor string

// Event is one log or audit record.
type Event struct {
	When   time.Time
	Source string // config|system|traffic|commit
	Actor  string
	SrcIP  string
	Cmd    string
	Path   string
	Detail string
	Seq    string
}

// EventFilter selects events.
type EventFilter struct {
	Source string // config|system|traffic (PAN-OS); commit (VyOS)
	Since  Cursor
	Query  string // device query expression, optional
	Limit  int
}

// Adapter is the per-device primitive set. Drift emits ConfigEvents; Begin
// opens a Tx the safe-change runner drives.
type Adapter interface {
	Kind() Kind
	Caps() Caps
	Close() error

	Info(ctx context.Context) (Info, error)
	// Probe opens a fresh connection, authenticates and does one read. It is
	// the lockout canary: it must not reuse an established session.
	Probe(ctx context.Context) error

	Snapshot(ctx context.Context, label string) (Snapshot, error)
	Diff(ctx context.Context, a, b Snapshot) (Diff, error)
	Drift(ctx context.Context, lastGood Snapshot) (DriftReport, error)

	Begin(ctx context.Context, opt TxOptions) (Tx, error)

	Admins(ctx context.Context) (AdminState, error)
	Events(ctx context.Context, f EventFilter) ([]Event, Cursor, error)
}

// TxOptions parameterises a transaction.
type TxOptions struct {
	Plan, Node  string
	Scope       string // ScopePolicy | ScopeManagement
	Risk        Risk
	Deadman     time.Duration // 0: none. Lockout risk needs a dead-man or a console acknowledgement.
	LockWait    time.Duration // how long to wait for a foreign lock (0: fail fast)
	LastGood    *Snapshot     // for the preflight drift check; nil skips it
	Description string
}

// Preflight is the result of the pre-change checks.
type Preflight struct {
	OK       bool
	Reasons  []string
	LockedBy string   // another admin holds the config lock (not itself a refusal; Lock waits or fails)
	Foreign  []string // staged changes we did not make
	Drifted  bool
}

// PendingSet lists staged-but-uncommitted changes.
type PendingSet struct {
	Ours    []string
	Foreign []string
}

// Validation is the result of a dry validation.
type Validation struct {
	OK       bool
	Warnings []string
	Errors   []string
}

// CommitResult describes an applied change.
type CommitResult struct {
	JobID     string
	NoChanges bool
	Warnings  []string
	Details   string
}

// RollbackMode picks the undo.
type RollbackMode int

const (
	// RollbackGranular undoes only what this Tx changed (and recommits if it was committed).
	RollbackGranular RollbackMode = iota
	// RollbackToSnapshot restores the pre-change whole configuration.
	RollbackToSnapshot
	// RollbackDiscardStaged drops staged, uncommitted changes of this Tx only.
	RollbackDiscardStaged
)

// Tx is one safe-change transaction.
type Tx interface {
	ID() string
	Preflight(ctx context.Context) (Preflight, error)
	Lock(ctx context.Context) error
	Stage(ctx context.Context, cs ChangeSet) error
	Pending(ctx context.Context) (PendingSet, error)
	Validate(ctx context.Context) (Validation, error)
	// Commit blocks until the change is active (or ctx ends). For management
	// scope it must prove a brand-new connection still works before returning.
	Commit(ctx context.Context) (CommitResult, error)
	// Confirm disarms any dead-man, persists, and releases locks.
	Confirm(ctx context.Context) error
	Rollback(ctx context.Context, how RollbackMode) error
	// Close releases locks and temporary state; idempotent, safe after a crash.
	Close(ctx context.Context) error
}

// Tainted is implemented by a Tx that noticed a foreign change during its
// window; the new snapshot must then not become the last known-good unseen.
type Tainted interface{ Tainted() []string }

// ChangeSet is an ordered list of operations.
type ChangeSet struct{ Ops []Op }

// Op is one device operation. Payload is device specific.
type Op struct {
	Kind    string // rule.upsert, rule.delete, nat.upsert, object.upsert, mgmt.permit, mgmt.remove, raw
	Key     string // stable name
	Payload json.RawMessage
}

var (
	ErrPreflight      = errors.New("devices: preflight refused")
	ErrLocked         = errors.New("devices: config lock held by another admin")
	ErrForeignPending = errors.New("devices: foreign pending changes")
	ErrNoDeadman      = errors.New("devices: lockout-risk change needs a dead-man or a console acknowledgement")
	ErrValidation     = errors.New("devices: validation failed")
	ErrCommit         = errors.New("devices: commit failed")
	ErrHealth         = errors.New("devices: health check failed")
	ErrNotManaged     = errors.New("devices: refusing to edit an item phylax did not create")
	ErrProbe          = errors.New("devices: fresh-connection probe failed")
	ErrRollback       = errors.New("devices: rollback failed")
)
