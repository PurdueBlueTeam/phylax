package devices

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Request is one safe change.
type Request struct {
	Opts    TxOptions
	Changes ChangeSet
	// Health runs after the commit, on fresh connections. A non-nil error
	// rolls the change back. It gets a context bounded by the dead-man.
	Health func(ctx context.Context) error
	// ConsoleAck: the Network role confirmed the console is ready, which
	// lets a lockout-risk change run on a device with no dead-man.
	ConsoleAck bool
	// RollbackTimeout bounds the undo (default 5 minutes).
	RollbackTimeout time.Duration
}

// Result describes what happened. On error it is still returned when a
// rollback was attempted.
type Result struct {
	TxID       string
	Before     *Snapshot
	After      *Snapshot
	Commit     CommitResult
	RolledBack bool
	Tainted    []string // foreign changes seen during the window; After is not a trusted last-known-good
}

// SafeChange runs lock, snapshot, stage, validate, commit (with a dead-man
// where the device has one), health check, then confirm or roll back. It
// works with any Adapter.
func SafeChange(ctx context.Context, ad Adapter, req Request) (*Result, error) {
	opt := req.Opts
	caps := ad.Caps()
	if opt.Risk == RiskLockout && !caps.SoftDeadman && !caps.NativeConfirm && !req.ConsoleAck {
		return nil, ErrNoDeadman
	}
	if opt.Risk == RiskLockout && opt.Deadman == 0 && (caps.SoftDeadman || caps.NativeConfirm) {
		opt.Deadman = 90 * time.Second
	}
	if (caps.SoftDeadman || caps.NativeConfirm) && opt.Risk != RiskNone && opt.Deadman == 0 {
		opt.Deadman = 90 * time.Second
	}
	rbTimeout := req.RollbackTimeout
	if rbTimeout == 0 {
		rbTimeout = 5 * time.Minute
	}

	tx, err := ad.Begin(ctx, opt)
	if err != nil {
		return nil, fmt.Errorf("devices: begin: %w", err)
	}
	res := &Result{TxID: tx.ID()}
	// Cleanup must run even if ctx was cancelled.
	bg := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.WithoutCancel(ctx), rbTimeout)
	}
	defer func() {
		cctx, cancel := bg()
		defer cancel()
		_ = tx.Close(cctx)
	}()

	committed := false
	rollback := func(cause error) (*Result, error) {
		cctx, cancel := bg()
		defer cancel()
		mode := RollbackDiscardStaged
		if committed {
			mode = RollbackGranular
		}
		err := tx.Rollback(cctx, mode)
		if err != nil && committed {
			err2 := tx.Rollback(cctx, RollbackToSnapshot)
			if err2 == nil {
				err = nil
			} else {
				err = errors.Join(err, err2)
			}
		}
		if err != nil {
			return res, fmt.Errorf("%w; %w: %v", cause, ErrRollback, err)
		}
		res.RolledBack = true
		return res, cause
	}

	// 0 preflight
	pf, err := tx.Preflight(ctx)
	if err != nil {
		return nil, fmt.Errorf("devices: preflight: %w", err)
	}
	if !pf.OK {
		if len(pf.Foreign) > 0 {
			return nil, fmt.Errorf("%w: %w: %s", ErrPreflight, ErrForeignPending, strings.Join(pf.Foreign, ", "))
		}
		return nil, fmt.Errorf("%w: %s", ErrPreflight, strings.Join(pf.Reasons, "; "))
	}
	// 1 lock
	if err := tx.Lock(ctx); err != nil {
		return nil, fmt.Errorf("devices: lock: %w", err)
	}
	// 2 snapshot
	before, err := ad.Snapshot(ctx, "pre-"+tx.ID())
	if err != nil {
		return nil, fmt.Errorf("devices: snapshot: %w", err)
	}
	res.Before = &before
	// 3 stage, then verify only our changes are pending
	if err := tx.Stage(ctx, req.Changes); err != nil {
		return rollback(fmt.Errorf("devices: stage: %w", err))
	}
	ps, err := tx.Pending(ctx)
	if err != nil {
		return rollback(fmt.Errorf("devices: pending: %w", err))
	}
	if len(ps.Foreign) > 0 {
		return rollback(fmt.Errorf("%w: %s", ErrForeignPending, strings.Join(ps.Foreign, ", ")))
	}
	// 4 validate
	v, err := tx.Validate(ctx)
	if err != nil {
		return rollback(fmt.Errorf("devices: validate: %w", err))
	}
	if !v.OK {
		return rollback(fmt.Errorf("%w: %s", ErrValidation, strings.Join(v.Errors, "; ")))
	}
	// 5 commit
	committed = true // from here a failure may have partly applied
	cr, err := tx.Commit(ctx)
	res.Commit = cr
	if err != nil {
		if errors.Is(err, ErrCommit) || errors.Is(err, ErrProbe) {
			return rollback(err)
		}
		return rollback(fmt.Errorf("%w: %w", ErrCommit, err))
	}
	// 6 health, bounded so it ends before a dead-man fires
	hctx, hcancel := ctx, context.CancelFunc(func() {})
	if opt.Deadman > 0 {
		hctx, hcancel = context.WithTimeout(ctx, opt.Deadman*3/4)
	}
	var herr error
	if req.Health != nil {
		herr = req.Health(hctx)
	}
	if herr == nil {
		herr = hctx.Err()
	}
	hcancel()
	if herr != nil {
		return rollback(fmt.Errorf("%w: %v", ErrHealth, herr))
	}
	// 7 confirm
	if err := tx.Confirm(ctx); err != nil {
		return rollback(fmt.Errorf("devices: confirm: %w", err))
	}
	if t, ok := tx.(Tainted); ok {
		res.Tainted = t.Tainted()
	}
	after, err := ad.Snapshot(ctx, "post-"+tx.ID())
	if err != nil {
		return res, fmt.Errorf("devices: post snapshot (change is live and confirmed): %w", err)
	}
	res.After = &after
	return res, nil
}
