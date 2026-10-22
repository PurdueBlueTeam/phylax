package palo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/devices"
	"github.com/PurdueBlueTeam/phylax/internal/devices/palo/xmlapi"
)

// Payload is the Op payload for PAN-OS: a concrete node xpath and, for an
// upsert, the replacement XML. Kind picks the action (".delete" and
// "mgmt.remove" delete; "raw" takes Action).
type Payload struct {
	Action  string `json:"action,omitempty"` // raw only: set | edit | delete
	XPath   string `json:"xpath"`
	Element string `json:"element,omitempty"`
}

// MakeOp builds an Op.
func MakeOp(kind, key, xpath, element string) devices.Op {
	b, _ := json.Marshal(Payload{XPath: xpath, Element: element})
	return devices.Op{Kind: kind, Key: key, Payload: b}
}

type inverse struct {
	xpath string
	prior *xmlapi.Node // nil: the node did not exist
}

type tx struct {
	a   *Adapter
	opt devices.TxOptions
	id  string

	mu        sync.Mutex
	locked    bool
	staged    []string // xpaths we touched
	inv       []inverse
	committed bool
	preSaved  string
	startSeq  int
	tainted   []string
	closed    bool
}

func (a *Adapter) Begin(ctx context.Context, opt devices.TxOptions) (devices.Tx, error) {
	t := &tx{a: a, opt: opt, id: a.nextID(opt)}
	if seq, err := a.latestCfgSeq(ctx); err == nil {
		t.startSeq = seq
	}
	return t, nil
}

func (t *tx) ID() string { return t.id }

func (t *tx) isOurs(c xmlapi.Change) bool {
	if c.Admin != "" {
		return c.Admin == t.a.cfg.Admin
	}
	// The device did not name an admin: fall back to our own staged paths.
	for _, x := range t.staged {
		if x == c.XPath {
			return true
		}
	}
	return false
}

func (t *tx) Preflight(ctx context.Context) (devices.Preflight, error) {
	pf := devices.Preflight{OK: true}
	fail := func(f string, a ...any) {
		pf.OK = false
		pf.Reasons = append(pf.Reasons, fmt.Sprintf(f, a...))
	}
	if _, err := t.a.c.SystemInfo(ctx); err != nil {
		return pf, fmt.Errorf("palo: device unreachable: %w", err)
	}
	jobs, err := t.a.c.ShowJobs(ctx)
	if err != nil {
		return pf, err
	}
	for _, j := range jobs {
		if !j.Done() {
			fail("job %s (%s) is %s: a commit is running or queued", j.ID, j.Type, j.Status)
		}
	}
	locks, err := t.a.c.ShowConfigLocks(ctx, t.a.cfg.Vsys)
	if err != nil {
		return pf, err
	}
	for _, l := range locks {
		if l.Admin != t.a.cfg.Admin {
			pf.LockedBy = l.Admin // Lock() waits or refuses; not a reason by itself
		}
	}
	ch, err := t.a.c.ListChanges(ctx)
	if err != nil {
		return pf, err
	}
	for _, c := range ch {
		if !t.isOurs(c) {
			who := c.Admin
			if who == "" {
				who = "unknown admin"
			}
			pf.Foreign = append(pf.Foreign, who+": "+c.XPath)
		}
	}
	if len(pf.Foreign) > 0 {
		fail("foreign pending changes: %s", strings.Join(pf.Foreign, ", "))
	}
	if t.opt.LastGood != nil {
		cur, err := t.a.Snapshot(ctx, "preflight")
		if err != nil {
			return pf, err
		}
		if cur.Hash != t.opt.LastGood.Hash {
			pf.Drifted = true
			fail("running config differs from the last known-good (drift)")
		}
	}
	return pf, nil
}

func (t *tx) Lock(ctx context.Context) error {
	deadline := time.Now().Add(t.opt.LockWait)
	comment := "phylax " + t.id
	for {
		err := t.a.c.ConfigLockAdd(ctx, comment)
		if err == nil {
			break
		}
		if !errors.Is(err, xmlapi.ErrLockHeld) {
			return err
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%w: %v", devices.ErrLocked, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(t.a.cfg.PollInterval):
		}
	}
	t.mu.Lock()
	t.locked = true
	t.mu.Unlock()
	// A device-side copy for the whole-config fallback. The preflight proved
	// no foreign edits are pending, so the candidate equals running.
	name := "phylax-pre-" + t.id + ".xml"
	if err := t.a.c.SaveConfig(ctx, name); err == nil {
		t.preSaved = name
	}
	return nil
}

func actionFor(op devices.Op, p Payload) (string, error) {
	switch {
	case op.Kind == "raw":
		switch p.Action {
		case "set", "edit", "delete":
			return p.Action, nil
		}
		return "", fmt.Errorf("palo: raw op %q needs action set|edit|delete", op.Key)
	case strings.HasSuffix(op.Kind, ".delete"), op.Kind == "mgmt.remove":
		return "delete", nil
	case strings.HasSuffix(op.Kind, ".upsert"), op.Kind == "mgmt.permit":
		return "edit", nil
	}
	return "", fmt.Errorf("palo: unknown op kind %q", op.Kind)
}

// managedKind reports whether the managed-tag rule applies.
func managedKind(kind string) bool {
	switch kind {
	case "rule.upsert", "rule.delete", "nat.upsert", "nat.delete", "object.upsert", "object.delete":
		return true
	}
	return false
}

func isManaged(n *xmlapi.Node) bool {
	tag := n.Child("tag")
	if tag == nil {
		return false
	}
	for _, m := range tag.Children {
		if m.Text == ManagedTag {
			return true
		}
	}
	return false
}

func (t *tx) Stage(ctx context.Context, cs devices.ChangeSet) error {
	var ops []xmlapi.MultiOp
	var invs []inverse
	for _, op := range cs.Ops {
		var p Payload
		if err := json.Unmarshal(op.Payload, &p); err != nil || p.XPath == "" {
			return fmt.Errorf("palo: op %s/%s: bad payload", op.Kind, op.Key)
		}
		act, err := actionFor(op, p)
		if err != nil {
			return err
		}
		if act != "delete" && p.Element == "" {
			return fmt.Errorf("palo: op %s/%s: %s needs an element", op.Kind, op.Key, act)
		}
		prior, err := t.a.c.ConfigGet(ctx, p.XPath)
		if err != nil {
			return fmt.Errorf("palo: read prior %s: %w", p.XPath, err)
		}
		if managedKind(op.Kind) && prior != nil && !isManaged(prior) {
			return fmt.Errorf("%w: %s", devices.ErrNotManaged, p.XPath)
		}
		if act == "delete" && prior == nil {
			continue // nothing to delete
		}
		invs = append(invs, inverse{xpath: p.XPath, prior: prior})
		ops = append(ops, xmlapi.MultiOp{Action: act, XPath: p.XPath, Element: p.Element})
		t.mu.Lock()
		t.staged = append(t.staged, p.XPath)
		t.mu.Unlock()
	}
	if len(ops) == 0 {
		return nil
	}
	// Record inverses before sending so a failed or partial send is still undone.
	t.mu.Lock()
	t.inv = append(t.inv, invs...)
	t.mu.Unlock()
	return t.a.c.MultiConfig(ctx, ops, true)
}

func (t *tx) Pending(ctx context.Context) (devices.PendingSet, error) {
	ch, err := t.a.c.ListChanges(ctx)
	if err != nil {
		return devices.PendingSet{}, err
	}
	var ps devices.PendingSet
	for _, c := range ch {
		if t.isOurs(c) {
			ps.Ours = append(ps.Ours, c.XPath)
		} else {
			ps.Foreign = append(ps.Foreign, c.Admin+": "+c.XPath)
		}
	}
	return ps, nil
}

func (t *tx) Validate(ctx context.Context) (devices.Validation, error) {
	id, err := t.a.c.ValidateFull(ctx)
	if err != nil {
		return devices.Validation{}, err
	}
	j, err := t.a.c.WaitJob(ctx, id, t.a.cfg.PollInterval, t.a.cfg.JobTimeout)
	if err != nil {
		return devices.Validation{}, err
	}
	v := devices.Validation{OK: j.Result == "OK"}
	if v.OK {
		v.Warnings = j.Details
	} else {
		v.Errors = j.Details
		if len(v.Errors) == 0 {
			v.Errors = []string{"validation job " + j.ID + " failed"}
		}
	}
	return v, nil
}

func (t *tx) commit(ctx context.Context) (devices.CommitResult, error) {
	desc := t.opt.Description
	if desc == "" {
		desc = "phylax " + t.id
	}
	id, none, err := t.a.c.CommitPartialAdmin(ctx, t.a.cfg.Admin, desc)
	if err != nil {
		return devices.CommitResult{}, fmt.Errorf("%w: %v", devices.ErrCommit, err)
	}
	if none {
		return devices.CommitResult{NoChanges: true}, nil
	}
	j, err := t.a.c.WaitJob(ctx, id, t.a.cfg.PollInterval, t.a.cfg.JobTimeout)
	if err != nil {
		return devices.CommitResult{JobID: id}, fmt.Errorf("%w: %v", devices.ErrCommit, err)
	}
	res := devices.CommitResult{JobID: id, Details: strings.Join(j.Details, "\n")}
	if j.Result != "OK" {
		return res, fmt.Errorf("%w: job %s: %s", devices.ErrCommit, id, res.Details)
	}
	res.Warnings = j.Details
	// PAN-OS drops the committer's config lock when the commit completes.
	t.mu.Lock()
	t.locked = false
	t.mu.Unlock()
	return res, nil
}

func (t *tx) Commit(ctx context.Context) (devices.CommitResult, error) {
	res, err := t.commit(ctx)
	if err != nil {
		return res, err
	}
	t.mu.Lock()
	t.committed = !res.NoChanges
	t.mu.Unlock()
	if t.opt.Scope == devices.ScopeManagement || t.opt.Risk == devices.RiskLockout {
		// PAN-OS has no commit-confirm: prove a brand-new connection still works
		// before anything else is done on top of this commit.
		if err := t.a.Probe(ctx); err != nil {
			return res, err
		}
	}
	return res, nil
}

func (t *tx) Confirm(ctx context.Context) error {
	// A foreign commit during our window means the new running config is not
	// purely ours: do not let the caller promote it to last-known-good unseen.
	if evs, _, err := t.a.Events(ctx, devices.EventFilter{Source: "config", Since: devices.Cursor(strconv.Itoa(t.startSeq))}); err == nil {
		for _, e := range evs {
			if e.Actor != t.a.cfg.Admin {
				t.tainted = append(t.tainted, fmt.Sprintf("%s %s %s", e.Actor, e.Cmd, e.Path))
			}
		}
	}
	if len(t.tainted) == 0 {
		if ps, err := t.Pending(ctx); err == nil && len(ps.Foreign) == 0 {
			// Best effort: a named on-device copy of the new good state.
			_ = t.a.c.SaveConfig(ctx, "phylax-"+t.id+".xml")
		}
	}
	t.releaseLock(ctx)
	return nil
}

func (t *tx) Tainted() []string { return t.tainted }

func (t *tx) releaseLock(ctx context.Context) {
	t.mu.Lock()
	was := t.locked
	t.locked = false
	t.mu.Unlock()
	if was {
		_ = t.a.c.ConfigLockRemove(ctx)
	}
}

func (t *tx) Rollback(ctx context.Context, how devices.RollbackMode) error {
	// The commit dropped our lock; take it back for the revert.
	if err := t.a.c.ConfigLockAdd(ctx, "phylax rollback "+t.id); err != nil && !t.heldByUs(ctx) {
		return fmt.Errorf("palo: rollback needs the config lock: %w", err)
	}
	t.mu.Lock()
	t.locked = true
	t.mu.Unlock()

	switch how {
	case devices.RollbackToSnapshot:
		if t.preSaved == "" {
			return errors.New("palo: no device-side snapshot to load")
		}
		if err := t.a.c.LoadConfig(ctx, t.preSaved); err != nil {
			return err
		}
	default: // granular and discard-staged both replay our own inverses only
		if err := t.undo(ctx); err != nil {
			return err
		}
	}
	t.mu.Lock()
	wasCommitted := t.committed
	t.mu.Unlock()
	if wasCommitted || how == devices.RollbackToSnapshot {
		if _, err := t.commit(ctx); err != nil {
			return fmt.Errorf("palo: revert commit: %w", err)
		}
		t.mu.Lock()
		t.committed = false
		t.mu.Unlock()
		if t.opt.Scope == devices.ScopeManagement || t.opt.Risk == devices.RiskLockout {
			if err := t.a.Probe(ctx); err != nil {
				return fmt.Errorf("palo: reverted, but management is still unreachable on a new connection (use the console): %w", err)
			}
		}
	}
	t.releaseLock(ctx)
	return nil
}

// undo replays the recorded prior state, newest first. Missing nodes on
// delete are fine.
func (t *tx) undo(ctx context.Context) error {
	t.mu.Lock()
	inv := append([]inverse(nil), t.inv...)
	t.mu.Unlock()
	var errs []error
	for i := len(inv) - 1; i >= 0; i-- {
		iv := inv[i]
		if iv.prior == nil {
			if err := t.a.c.ConfigDelete(ctx, iv.xpath); err != nil && !strings.Contains(strings.ToLower(err.Error()), "not present") {
				errs = append(errs, err)
			}
			continue
		}
		prior := iv.prior.Clone()
		prior.Strip()
		if err := t.a.c.ConfigEdit(ctx, iv.xpath, string(prior.Marshal())); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	t.mu.Lock()
	t.inv = nil
	t.mu.Unlock()
	return nil
}

func (t *tx) Close(ctx context.Context) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()
	t.releaseLock(ctx)
	return nil
}

func (t *tx) heldByUs(ctx context.Context) bool {
	locks, err := t.a.c.ShowConfigLocks(ctx, t.a.cfg.Vsys)
	if err != nil {
		return false
	}
	for _, l := range locks {
		if l.Admin == t.a.cfg.Admin {
			return true
		}
	}
	return false
}

// ReleaseStaleLock removes a config lock our admin left behind (a crashed
// controller). It never touches another admin's lock.
func (a *Adapter) ReleaseStaleLock(ctx context.Context) error {
	locks, err := a.c.ShowConfigLocks(ctx, a.cfg.Vsys)
	if err != nil {
		return err
	}
	for _, l := range locks {
		if l.Admin == a.cfg.Admin {
			if err := a.c.ConfigLockRemove(ctx); err != nil && !errors.Is(err, xmlapi.ErrNotLocked) {
				return err
			}
		}
	}
	return nil
}
