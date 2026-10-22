//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

// Snapshot is the previous state of the tables we own, plus what else was
// there. Restoring it puts our tables back exactly (tables that did not exist
// are removed).
type Snapshot struct {
	Version int            `json:"version"`
	Taken   time.Time      `json:"taken"`
	Owned   *Ruleset       `json:"owned"`
	Foreign []ForeignTable `json:"foreign,omitempty"`
}

// LinuxOptions configures a LinuxManager.
type LinuxOptions struct {
	// Deadman arms the rollback around Apply. May be nil (no dead-man).
	Deadman *deadman.Manager
	// NewConn opens a netlink connection; default: the current network namespace.
	NewConn func() (*nftables.Conn, error)
	Now     func() time.Time

	// afterReplace, if set, runs between the netlink batch and the read-back.
	// Tests use it to simulate something tampering with the tables mid-apply.
	afterReplace func()
}

// LinuxManager applies and audits the host's nftables policy.
type LinuxManager struct {
	opt LinuxOptions
	mu  sync.Mutex // serializes apply/restore/panic-open within the process
}

// NewLinux returns a manager.
func NewLinux(opt LinuxOptions) *LinuxManager {
	if opt.NewConn == nil {
		opt.NewConn = func() (*nftables.Conn, error) { return &nftables.Conn{}, nil }
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &LinuxManager{opt: opt}
}

// Handlers returns the dead-man handlers to register in deadman.Options
// (the rollback must work from a fresh `phylax agent rollback` process, so it
// needs nothing but the journal entry).
func Handlers(newConn func() (*nftables.Conn, error)) map[string]deadman.Handler {
	m := NewLinux(LinuxOptions{NewConn: newConn})
	return map[string]deadman.Handler{KindNftRestore: m.rollbackHandler}
}

func (m *LinuxManager) rollbackHandler(ctx context.Context, e deadman.Entry) error {
	var s Snapshot
	if err := json.Unmarshal(e.Data, &s); err != nil {
		return fmt.Errorf("decode %s data: %w", KindNftRestore, err)
	}
	_, err := m.Restore(ctx, &s)
	return err
}

// ApplyResult reports an Apply.
type ApplyResult struct {
	Changed      bool           `json:"changed"`
	Hash         string         `json:"hash"`          // of the installed (declared) ruleset
	PrevHash     string         `json:"prev_hash"`     // of our tables before
	Snapshot     *Snapshot      `json:"snapshot"`      // previous state, for fw.restore
	DeadmanArmed bool           `json:"deadman_armed"` // the caller must Confirm
	Foreign      []ForeignTable `json:"foreign,omitempty"`
}

// Apply installs hp: translate, snapshot the previous state, arm the dead-man
// switch, replace our tables in one netlink batch, read back and verify. If the
// batch is rejected nothing changed (the entry is cancelled). If verification
// fails the snapshot is restored and an error wrapping ErrVerify is returned.
// A policy that is already installed is a no-op (nothing armed).
func (m *LinuxManager) Apply(ctx context.Context, hp *render.HostPolicy, opt ApplyOptions) (*ApplyResult, error) {
	desired, err := Translate(hp, TranslateOptions{Mode: opt.Mode, AllowNoManagement: opt.AllowNoManagement})
	if err != nil {
		return nil, err
	}
	if err := managementIntact(desired); err != nil {
		return nil, fmt.Errorf("firewall: declared policy would break the management channel: %w", err)
	}
	return m.ApplyRuleset(ctx, desired, opt)
}

// ApplyRuleset is Apply for an already translated ruleset.
func (m *LinuxManager) ApplyRuleset(ctx context.Context, desired *Ruleset, opt ApplyOptions) (*ApplyResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snap, err := m.snapshot()
	if err != nil {
		return nil, err
	}
	res := &ApplyResult{Snapshot: snap, PrevHash: snap.Owned.Hash(), Hash: desired.Hash(), Foreign: snap.Foreign}
	if len(DiffRulesets(desired, snap.Owned)) == 0 {
		return res, nil
	}
	res.Changed = true

	armed := false
	if m.opt.Deadman != nil && opt.DeadmanID != "" && opt.Timeout > 0 {
		if _, err := m.opt.Deadman.Arm(ctx, deadman.ArmRequest{
			ID: opt.DeadmanID, NodeID: opt.NodeID, Timeout: opt.Timeout, Kind: KindNftRestore, Data: snap,
		}); err != nil {
			return nil, fmt.Errorf("firewall: arm dead-man before apply: %w", err)
		}
		armed, res.DeadmanArmed = true, true
	}
	if err := m.replace(desired); err != nil {
		// The batch is atomic: the kernel kept the old state.
		if armed {
			_, _ = m.opt.Deadman.Cancel(context.WithoutCancel(ctx), opt.DeadmanID)
			res.DeadmanArmed = false
		}
		return nil, err
	}
	if m.opt.afterReplace != nil {
		m.opt.afterReplace()
	}
	got, _, err := m.read()
	if err == nil {
		if d := DiffRulesets(desired, got); len(d) > 0 {
			err = fmt.Errorf("%w: %d differences, first: %s", ErrVerify, len(d), d[0])
		} else if merr := managementIntact(got); merr != nil {
			err = fmt.Errorf("%w: management channel: %v", ErrVerify, merr)
		}
	} else {
		err = fmt.Errorf("%w: read back: %v", ErrVerify, err)
	}
	if err != nil {
		bg := context.WithoutCancel(ctx)
		var rerr error
		if armed {
			_, rerr = m.opt.Deadman.Fire(bg, opt.DeadmanID, "verify") // journals the outcome
			res.DeadmanArmed = false
		} else {
			_, rerr = m.restoreLocked(&Snapshot{Version: SnapshotVersion, Owned: snap.Owned})
		}
		if rerr != nil {
			err = errors.Join(err, fmt.Errorf("rollback after failed verify: %w", rerr))
		}
		return res, err
	}
	return res, nil
}

// Snapshot captures the current state of our tables.
func (m *LinuxManager) Snapshot(ctx context.Context) (*Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.snapshot()
}

func (m *LinuxManager) snapshot() (*Snapshot, error) {
	owned, foreign, err := m.read()
	if err != nil {
		return nil, err
	}
	return &Snapshot{Version: SnapshotVersion, Taken: m.opt.Now().UTC(), Owned: owned, Foreign: foreign}, nil
}

// Restore puts our tables back as the snapshot recorded (fw.restore, and the
// dead-man rollback). It is idempotent. Rules that could not be captured are
// skipped and reported in the returned warnings.
func (m *LinuxManager) Restore(ctx context.Context, s *Snapshot) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.restoreLocked(s)
}

func (m *LinuxManager) restoreLocked(s *Snapshot) ([]string, error) {
	if s == nil || s.Owned == nil {
		return nil, errors.New("firewall: empty snapshot")
	}
	if s.Version != SnapshotVersion {
		return nil, fmt.Errorf("firewall: snapshot version %d not supported", s.Version)
	}
	c, err := m.opt.NewConn()
	if err != nil {
		return nil, err
	}
	defer c.CloseLasting()
	skipped, err := replaceOwned(c, s.Owned)
	if err != nil {
		return nil, err
	}
	if err := c.Flush(); err != nil {
		return nil, fmt.Errorf("firewall: restore: %w", err)
	}
	return skipped, nil
}

func (m *LinuxManager) replace(desired *Ruleset) error {
	c, err := m.opt.NewConn()
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	if _, err := replaceOwned(c, desired); err != nil {
		return err
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("firewall: netlink batch rejected: %w", err)
	}
	return nil
}

func (m *LinuxManager) read() (*Ruleset, []ForeignTable, error) {
	c, err := m.opt.NewConn()
	if err != nil {
		return nil, nil, err
	}
	defer c.CloseLasting()
	return readKernel(c)
}

// Read returns the current state of our tables and a summary of foreign ones.
func (m *LinuxManager) Read(ctx context.Context) (*Ruleset, []ForeignTable, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return m.read()
}

// Drift is the result of comparing the kernel with the declared ruleset.
type Drift struct {
	Clean        bool           `json:"clean"`
	Diffs        []string       `json:"diffs,omitempty"`
	Hash         string         `json:"hash"`          // of our tables now
	DeclaredHash string         `json:"declared_hash"` // of the declared ruleset
	Foreign      []ForeignTable `json:"foreign,omitempty"`
	// ManagementIntact is false if the management table or its mark rule is
	// gone or altered; ManagementProblem says how.
	ManagementIntact  bool   `json:"management_intact"`
	ManagementProblem string `json:"management_problem,omitempty"`
}

// DetectDrift reads the kernel and diffs our tables against declared. This is
// the function D10 calls (every 10 s, hashing is cheap): Drift.Hash changes
// whenever anyone touches our tables, and Drift.Foreign lists other firewalls.
func (m *LinuxManager) DetectDrift(ctx context.Context, declared *Ruleset) (*Drift, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	got, foreign, err := m.read()
	if err != nil {
		return nil, err
	}
	d := &Drift{Hash: got.Hash(), DeclaredHash: declared.Hash(), Foreign: foreign}
	d.Diffs = DiffRulesets(declared, got)
	d.Clean = len(d.Diffs) == 0
	if merr := managementIntact(got); merr != nil {
		d.ManagementProblem = merr.Error()
	} else {
		d.ManagementIntact = true
	}
	return d, nil
}

// PanicOpen is the safe action for "the firewall is hurting us": it removes
// every filtering rule we own (our tables become accept-all placeholders, the
// management and sinkhole tables are deleted) in one batch and returns the
// snapshot of what was there so it can be re-applied. Foreign tables are not
// touched, so a foreign drop (visible in Snapshot.Foreign) still applies.
func (m *LinuxManager) PanicOpen(ctx context.Context) (*Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	snap, err := m.snapshot()
	if err != nil {
		return nil, err
	}
	if err := m.replace(OpenRuleset()); err != nil {
		return snap, err
	}
	return snap, nil
}

// OpenRuleset is the accept-everything placeholder PanicOpen installs.
func OpenRuleset() *Ruleset {
	t := newTable(render.TableMain)
	baseChain(t, "input", "filter", hookNum(render.In), 0, nftables.ChainPolicyAccept)
	baseChain(t, "output", "filter", hookNum(render.Out), 0, nftables.ChainPolicyAccept)
	return (&Ruleset{Tables: []*TableSpec{t.spec}}).normalized()
}

// managementIntact checks the structural invariants that keep the agent link
// alive: the management table has accept-policy input and output chains and
// each main base chain accepts flows carrying the management mark before
// anything else can drop them. (Whether the right peers are allowed is the
// renderer's and the diff's job.)
func managementIntact(rs *Ruleset) error {
	mg := rs.Table(render.TableMgmt)
	if mg == nil {
		return errors.New("management table missing")
	}
	for _, n := range []string{"input", "output"} {
		c := chainOf(mg, n)
		if c == nil || c.Hook == nil || c.Policy == nil || *c.Policy != uint32(nftables.ChainPolicyAccept) {
			return fmt.Errorf("management chain %s missing, unhooked or not accept-policy", n)
		}
	}
	mn := rs.Table(render.TableMain)
	if mn == nil {
		return errors.New("main table missing")
	}
	for _, n := range []string{"input", "output"} {
		c := chainOf(mn, n)
		if c == nil {
			return fmt.Errorf("main chain %s missing", n)
		}
		found := false
		for _, r := range c.Rules {
			if hasMarkAccept(r) {
				found = true
				break
			}
			if len(r.Exprs) > 0 && lastIsDrop(r) {
				return fmt.Errorf("main chain %s drops before the management mark is accepted", n)
			}
		}
		if !found {
			return fmt.Errorf("main chain %s has no management-mark accept rule", n)
		}
	}
	return nil
}

func chainOf(t *TableSpec, name string) *ChainSpec {
	for _, c := range t.Chains {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func lastIsDrop(r *RuleSpec) bool {
	v, ok := r.Exprs[len(r.Exprs)-1].Any.(*expr.Verdict)
	return ok && v.Kind == expr.VerdictDrop && !isInvalidStateDrop(r)
}

// isInvalidStateDrop recognises `ct state invalid drop`, which legitimately
// precedes the management accept (it cannot match a mark-bearing flow).
func isInvalidStateDrop(r *RuleSpec) bool {
	if len(r.Exprs) != 4 {
		return false
	}
	ct, ok := r.Exprs[0].Any.(*expr.Ct)
	return ok && ct.Key == expr.CtKeySTATE
}

func hasMarkAccept(r *RuleSpec) bool {
	if len(r.Exprs) != 4 {
		return false
	}
	ct, ok := r.Exprs[0].Any.(*expr.Ct)
	if !ok || ct.Key != expr.CtKeyMARK || ct.SourceRegister {
		return false
	}
	if _, ok := r.Exprs[1].Any.(*expr.Bitwise); !ok {
		return false
	}
	cmp, ok := r.Exprs[2].Any.(*expr.Cmp)
	if !ok || cmp.Op != expr.CmpOpEq || !bytes.Equal(cmp.Data, binaryutil.NativeEndian.PutUint32(mgmtMark)) {
		return false
	}
	v, ok := r.Exprs[3].Any.(*expr.Verdict)
	return ok && v.Kind == expr.VerdictAccept
}
