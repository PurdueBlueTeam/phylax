package actions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

// DefaultDeadman is the design's default dead-man window.
const DefaultDeadman = 90 * time.Second

// NoDeadman, as Request.Deadman, explicitly opts out of arming the dead-man
// switch (the plan engine does this only for approved nodes).
const NoDeadman time.Duration = -1

// Env is everything actions need from the host. All filesystem access goes
// through Root, and account/service access through interfaces, so tests run
// against a temp dir and fakes.
type Env struct {
	Host     string
	Root     string // filesystem root; "/" or "" = the real system
	Registry *Registry
	Locks    *Locks
	Safe     *SafeMode
	Guard    ScoringGuard
	Deadman  *deadman.Manager
	Tags     TagSink
	Accounts AccountBackend
	Services ServiceManager
	// Win carries the Windows, AD, network-device and Splunk backends (win_env.go).
	Win WinEnv
	// QuarantineDir is where file.quarantine moves files (a real path, not under Root).
	QuarantineDir string
	Now           func() time.Time
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Resolve maps an absolute path in the managed system to a real path.
func (e *Env) Resolve(p string) string {
	if e.Root == "" || e.Root == "/" {
		return filepath.Clean(p)
	}
	p = filepath.ToSlash(p)
	if len(p) > 1 && p[1] == ':' { // drive letter
		p = p[2:]
	}
	return filepath.Join(e.Root, filepath.FromSlash(filepath.Clean("/"+p)))
}

func (e *Env) guard() ScoringGuard {
	if e.Guard == nil {
		return AllowAll{}
	}
	return e.Guard
}

// DeadmanHandlers returns the rollback handlers for the kinds this package
// arms; pass them in deadman.Options.Handlers.
func DeadmanHandlers(env *Env) map[string]deadman.Handler {
	m := map[string]deadman.Handler{
		kindQuarantineUndo: undoQuarantine,
		kindPerms:          undoPerms,
		kindServiceState:   func(ctx context.Context, en deadman.Entry) error { return restoreServices(ctx, env, en) },
	}
	for kind, fn := range extraHandlers {
		m[kind] = func(ctx context.Context, en deadman.Entry) error { return fn(ctx, env, en) }
	}
	return m
}

// Request is one action invocation.
type Request struct {
	Action string
	Params map[string]any
	NodeID string
	DryRun bool
	// Deadman: 0 = default (90s for lockout-class actions, none otherwise),
	// >0 = arm with this window, NoDeadman = never arm.
	Deadman time.Duration
	// PCR marks the change as part of a PCR transaction (scored passwords).
	PCR bool
}

// Outcome is the result of Execute.
type Outcome struct {
	Action    string
	Risk      Risk
	Plan      Plan
	Changed   bool
	Output    Output
	DeadmanID string // armed entry awaiting Confirm; empty if none
	Tag       Tag
}

var idClean = regexp.MustCompile(`[^A-Za-z0-9]+`)

func newDeadmanID(action, node string) string {
	var r [4]byte
	_, _ = rand.Read(r[:])
	base := idClean.ReplaceAllString(action, "-")
	if node != "" {
		base = idClean.ReplaceAllString(node, "-") + "-" + base
	}
	if len(base) > 40 {
		base = base[:40]
	}
	return strings.Trim(base, "-") + "-" + hex.EncodeToString(r[:])
}

// Execute runs one action: validate, scoring guard, (dry-run stops here after
// Plan), safe mode, locks, check, dead-man arm, apply, verify. A failed apply
// or verify fires the dead-man rollback immediately. A successful risky apply
// leaves the entry armed: the caller confirms it (Confirm) once the fresh
// controller connection works, or the timer rolls it back.
func (e *Env) Execute(ctx context.Context, req Request) (*Outcome, error) {
	reg := e.Registry
	if reg == nil {
		reg = Core()
		e.Registry = reg
	}
	a, err := reg.Get(req.Action)
	if err != nil {
		return nil, err
	}
	spec := a.Spec()
	p, err := spec.Validate(req.Params)
	if err != nil {
		return nil, err
	}
	tag := TagFrom(ctx)
	if tag.IsZero() {
		tag = Tag{Node: req.NodeID}
	}
	ctx = WithTag(ctx, tag)
	out := &Outcome{Action: spec.Name, Risk: spec.Risk, Tag: tag}

	for _, t := range a.Touches(p) {
		t.PCR = req.PCR
		if err := e.guard().Allow(ctx, t); err != nil {
			return out, err
		}
	}
	locks := a.Locks(p)
	if e.Locks == nil {
		e.Locks = NewLocks()
	}

	if req.DryRun {
		rel, busy := e.Locks.TryAcquire(locks...)
		if rel != nil {
			defer rel()
		}
		out.Plan, err = a.Plan(ctx, e, p)
		out.Plan.Blocked = busy
		return out, err
	}

	if e.Safe.On() {
		return out, ErrSafeMode
	}
	rel, err := e.Locks.Acquire(ctx, locks...)
	if err != nil {
		return out, err
	}
	defer rel()
	if e.Safe.On() { // re-check: it may have flipped while we waited
		return out, ErrSafeMode
	}

	out.Plan, err = a.Plan(ctx, e, p)
	if err != nil {
		return out, err
	}
	if out.Plan.Done && !spec.ReadOnly {
		return out, nil
	}

	var armed string
	if !spec.ReadOnly {
		window := req.Deadman
		if window == 0 && spec.Risk == RiskLockout {
			window = DefaultDeadman
		}
		if window > 0 {
			rb, err := a.Capture(ctx, e, p)
			if err != nil {
				return out, fmt.Errorf("capture rollback data: %w", err)
			}
			switch {
			case rb.Kind == "" && req.Deadman > 0:
				return out, ErrNotReversible
			case rb.Kind == "":
				out.Plan.Notes = append(out.Plan.Notes, "not reversible: dead-man switch not armed")
			case e.Deadman == nil:
				return out, ErrNoDeadman
			default:
				ent, err := e.Deadman.Arm(ctx, deadman.ArmRequest{
					ID: newDeadmanID(spec.Name, req.NodeID), NodeID: req.NodeID,
					Timeout: window, Kind: rb.Kind, Data: rb.Data})
				if err != nil {
					return out, fmt.Errorf("arm dead-man: %w", err)
				}
				armed = ent.ID
			}
		}
	}

	fail := func(err error) (*Outcome, error) {
		if armed != "" {
			if _, ferr := e.Deadman.Fire(context.WithoutCancel(ctx), armed, "executor"); ferr != nil {
				err = errors.Join(err, fmt.Errorf("rollback: %w", ferr))
			}
		}
		return out, err
	}
	o, err := a.Apply(ctx, e, p)
	out.Output = o
	if err != nil {
		return fail(fmt.Errorf("apply %s: %w", spec.Name, err))
	}
	out.Changed = !spec.ReadOnly
	if err := a.Verify(ctx, e, p); err != nil {
		out.Changed = false
		return fail(fmt.Errorf("verify %s: %w", spec.Name, err))
	}
	out.DeadmanID = armed
	e.recordTags(a, p, tag, spec.Name)
	return out, nil
}

func (e *Env) recordTags(a Action, p Params, tag Tag, name string) {
	if e.Tags == nil || a.Spec().ReadOnly {
		return
	}
	for _, t := range a.Touches(p) {
		_ = e.Tags.Record(TagRecord{Time: e.now(), Tag: tag, Action: name, Resource: string(t.Kind) + ":" + t.Name})
	}
}

// Confirm disarms a dead-man entry after the fresh-connection check passed.
func (e *Env) Confirm(ctx context.Context, id string) error {
	if e.Deadman == nil {
		return ErrNoDeadman
	}
	_, err := e.Deadman.Confirm(ctx, id)
	return err
}

// Rollback fires a dead-man entry now. It is permitted in safe mode.
func (e *Env) Rollback(ctx context.Context, id string) error {
	if e.Deadman == nil {
		return ErrNoDeadman
	}
	_, err := e.Deadman.Fire(ctx, id, "manual")
	return err
}

// IsWindows reports the platform (the registry of backends differs).
func IsWindows() bool { return runtime.GOOS == "windows" }

// NewEnv builds an Env with the core registry and this platform's account and
// service backends. root is "/" (or "") on a real host.
func NewEnv(host, root string) *Env {
	return &Env{Host: host, Root: root, Registry: Core(), Locks: NewLocks(), Guard: AllowAll{},
		Accounts: defaultAccounts(root), Services: defaultServices(), Win: defaultWinEnv()}
}
