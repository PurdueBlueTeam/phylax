package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

// WinBackend is the Windows Firewall as seen by the manager. The real
// implementation is COM (HNetCfg.FwPolicy2); tests use an in-memory fake.
// Rules() returns every rule on the machine, ours and foreign, so the manager
// can detect name collisions and report foreign blockers; it never modifies a
// rule outside a Phylax group.
type WinBackend interface {
	Profiles() ([]WinProfileState, error)
	SetProfile(WinProfileState) error
	Rules() ([]WinRuleState, error)
	AddRule(WinRuleState) error
	// UpdateRule changes the named rule in place (no remove/add gap).
	UpdateRule(WinRuleState) error
	RemoveRule(name string) error
	Close() error
}

// WinSnapshot is the previous state of our rule groups and the profiles.
type WinSnapshot struct {
	Version int            `json:"version"`
	Taken   time.Time      `json:"taken"`
	State   *WinState      `json:"state"`
	Foreign []WinRuleState `json:"foreign,omitempty"` // enabled foreign Block rules (informational)
}

// WinOptions configures a WinManager.
type WinOptions struct {
	Deadman    *deadman.Manager
	NewBackend func() (WinBackend, error)
	Now        func() time.Time
}

// WinManager applies and audits the Windows Firewall policy.
type WinManager struct {
	opt WinOptions
	mu  sync.Mutex
}

// NewWindows returns a manager. NewBackend must be set (on Windows,
// NewComBackend).
func NewWindows(opt WinOptions) *WinManager {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &WinManager{opt: opt}
}

// WinHandlers returns the dead-man handlers to register in deadman.Options.
func WinHandlers(newBackend func() (WinBackend, error)) map[string]deadman.Handler {
	m := NewWindows(WinOptions{NewBackend: newBackend})
	return map[string]deadman.Handler{KindWinRestore: func(ctx context.Context, e deadman.Entry) error {
		var s WinSnapshot
		if err := json.Unmarshal(e.Data, &s); err != nil {
			return fmt.Errorf("decode %s data: %w", KindWinRestore, err)
		}
		return m.Restore(ctx, &s)
	}}
}

// WinApplyResult reports an Apply.
type WinApplyResult struct {
	Changed      bool         `json:"changed"`
	Hash         string       `json:"hash"`
	PrevHash     string       `json:"prev_hash"`
	Snapshot     *WinSnapshot `json:"snapshot"`
	DeadmanArmed bool         `json:"deadman_armed"`
	// ForeignBlockers are enabled Block rules outside our groups.
	ForeignBlockers []WinRuleState `json:"foreign_blockers,omitempty"`
	// Unapplied lists parts of the policy this action does not install
	// (the denied-egress audit is the audit-policy action's job).
	Unapplied []string `json:"unapplied,omitempty"`
}

// Apply installs wp: translate, snapshot, arm the dead-man switch, apply,
// read back and verify, rolling back on a failed verify.
//
// Windows has no atomic ruleset swap, so the order keeps the machine
// reachable at every step: rules are added or updated in place first, then the
// profiles (defaults, enabled), and only then are stale rules removed.
func (m *WinManager) Apply(ctx context.Context, wp *render.WinPolicy, opt ApplyOptions) (*WinApplyResult, error) {
	desired, err := TranslateWindows(wp, WinTranslateOptions{Mode: opt.Mode, AllowNoManagement: opt.AllowNoManagement})
	if err != nil {
		return nil, err
	}
	res, err := m.ApplyState(ctx, desired, opt)
	if res != nil && wp.DeniedEgressAudit {
		res.Unapplied = append(res.Unapplied, "denied_egress_audit")
	}
	return res, err
}

// ApplyState is Apply for an already translated state.
func (m *WinManager) ApplyState(ctx context.Context, desired *WinState, opt ApplyOptions) (*WinApplyResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := m.opt.NewBackend()
	if err != nil {
		return nil, err
	}
	defer b.Close()
	cur, all, err := readWin(b)
	if err != nil {
		return nil, err
	}
	snap := &WinSnapshot{Version: SnapshotVersion, Taken: m.opt.Now().UTC(), State: cur, Foreign: foreignBlockers(all)}
	res := &WinApplyResult{Snapshot: snap, PrevHash: cur.Hash(), Hash: desired.Hash(), ForeignBlockers: snap.Foreign}
	if len(DiffWinStates(desired, cur)) == 0 {
		return res, nil
	}
	res.Changed = true
	armed := false
	if m.opt.Deadman != nil && opt.DeadmanID != "" && opt.Timeout > 0 {
		if _, err := m.opt.Deadman.Arm(ctx, deadman.ArmRequest{ID: opt.DeadmanID, NodeID: opt.NodeID, Timeout: opt.Timeout, Kind: KindWinRestore, Data: snap}); err != nil {
			return nil, fmt.Errorf("firewall: arm dead-man before apply: %w", err)
		}
		armed, res.DeadmanArmed = true, true
	}
	fail := func(err error) (*WinApplyResult, error) {
		// Not atomic: whatever was applied is rolled back.
		bg := context.WithoutCancel(ctx)
		var rerr error
		if armed {
			_, rerr = m.opt.Deadman.Fire(bg, opt.DeadmanID, "apply-failed")
			res.DeadmanArmed = false
		} else {
			rerr = convergeWin(b, snap.State)
		}
		if rerr != nil {
			err = errors.Join(err, fmt.Errorf("rollback: %w", rerr))
		}
		return res, err
	}
	if err := convergeWin(b, desired); err != nil {
		return fail(fmt.Errorf("firewall: apply: %w", err))
	}
	got, _, err := readWin(b)
	if err == nil {
		if d := DiffWinStates(desired, got); len(d) > 0 {
			err = fmt.Errorf("%w: %d differences, first: %s", ErrVerify, len(d), d[0])
		}
	} else {
		err = fmt.Errorf("%w: read back: %v", ErrVerify, err)
	}
	if err != nil {
		return fail(err)
	}
	return res, nil
}

// readWin returns our state (profiles + owned rules) and every rule.
func readWin(b WinBackend) (*WinState, []WinRuleState, error) {
	profs, err := b.Profiles()
	if err != nil {
		return nil, nil, err
	}
	all, err := b.Rules()
	if err != nil {
		return nil, nil, err
	}
	st := &WinState{Profiles: profs}
	for _, r := range all {
		if WinOwnedGroup(r.Group) {
			st.Rules = append(st.Rules, r)
		}
	}
	st.normalize()
	return st, all, nil
}

func foreignBlockers(all []WinRuleState) []WinRuleState {
	var out []WinRuleState
	for _, r := range all {
		if !WinOwnedGroup(r.Group) && r.Enabled && r.Action == "Block" {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > 100 {
		out = out[:100]
	}
	return out
}

// convergeWin makes our groups and the profiles equal to want. Only rules in
// Phylax groups are ever changed; it reads the live rules itself so it also
// works after a partial apply.
func convergeWin(b WinBackend, want *WinState) error {
	all, err := b.Rules()
	if err != nil {
		return err
	}
	foreignNames := map[string]bool{}
	cur := map[string]WinRuleState{}
	for _, r := range all {
		if WinOwnedGroup(r.Group) {
			cur[r.Name] = r
		} else {
			foreignNames[r.Name] = true
		}
	}
	wantNames := map[string]bool{}
	// 1. Add or update, management group first.
	rules := append([]WinRuleState(nil), want.Rules...)
	sort.SliceStable(rules, func(i, j int) bool {
		return (rules[i].Group == WinMgmtGroup) && (rules[j].Group != WinMgmtGroup)
	})
	for _, r := range rules {
		wantNames[r.Name] = true
		if foreignNames[r.Name] {
			return fmt.Errorf("rule name %q collides with a rule outside the Phylax groups", r.Name)
		}
		o, ok := cur[r.Name]
		switch {
		case !ok:
			if err := b.AddRule(r); err != nil {
				return fmt.Errorf("add rule %q: %w", r.Name, err)
			}
		default:
			a, c := r, o
			a.Description, c.Description = "", ""
			if a != c {
				if err := b.UpdateRule(r); err != nil {
					return fmt.Errorf("update rule %q: %w", r.Name, err)
				}
			}
		}
	}
	// 2. Profiles.
	have, err := b.Profiles()
	if err != nil {
		return err
	}
	hp := map[string]WinProfileState{}
	for _, p := range have {
		hp[p.Name] = p
	}
	for _, p := range want.Profiles {
		if hp[p.Name] != p {
			if err := b.SetProfile(p); err != nil {
				return fmt.Errorf("set profile %s: %w", p.Name, err)
			}
		}
	}
	// 3. Remove stale rules of ours.
	var stale []string
	for n := range cur {
		if !wantNames[n] {
			stale = append(stale, n)
		}
	}
	sort.Strings(stale)
	for _, n := range stale {
		if foreignNames[n] {
			return fmt.Errorf("stale rule %q shares its name with a foreign rule; not removing", n)
		}
		if err := b.RemoveRule(n); err != nil {
			return fmt.Errorf("remove rule %q: %w", n, err)
		}
	}
	return nil
}

// Snapshot captures the current state of our groups and the profiles.
func (m *WinManager) Snapshot(ctx context.Context) (*WinSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, all, err := m.read()
	if err != nil {
		return nil, err
	}
	return &WinSnapshot{Version: SnapshotVersion, Taken: m.opt.Now().UTC(), State: st, Foreign: foreignBlockers(all)}, nil
}

func (m *WinManager) read() (*WinState, []WinRuleState, error) {
	b, err := m.opt.NewBackend()
	if err != nil {
		return nil, nil, err
	}
	defer b.Close()
	return readWin(b)
}

// Restore puts our groups and the profiles back as the snapshot recorded
// (fw.restore and the dead-man rollback). Idempotent.
func (m *WinManager) Restore(ctx context.Context, s *WinSnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.State == nil {
		return errors.New("firewall: empty snapshot")
	}
	if s.Version != SnapshotVersion {
		return fmt.Errorf("firewall: snapshot version %d not supported", s.Version)
	}
	b, err := m.opt.NewBackend()
	if err != nil {
		return err
	}
	defer b.Close()
	return convergeWin(b, s.State)
}

// WinDrift is the result of DetectDrift.
type WinDrift struct {
	Clean           bool           `json:"clean"`
	Diffs           []string       `json:"diffs,omitempty"`
	Hash            string         `json:"hash"`
	DeclaredHash    string         `json:"declared_hash"`
	ForeignBlockers []WinRuleState `json:"foreign_blockers,omitempty"`
}

// DetectDrift diffs the machine against the declared state. D10 calls it.
func (m *WinManager) DetectDrift(ctx context.Context, declared *WinState) (*WinDrift, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	got, all, err := m.read()
	if err != nil {
		return nil, err
	}
	d := &WinDrift{Hash: got.Hash(), DeclaredHash: declared.Hash(), ForeignBlockers: foreignBlockers(all)}
	d.Diffs = DiffWinStates(declared, got)
	d.Clean = len(d.Diffs) == 0
	return d, nil
}

// PanicOpen is the safe action for "the firewall is hurting us": every profile
// gets default Allow in both directions and our Block rules are removed, so
// only a foreign rule can still block. The previous state is returned for
// re-applying. Defaults change first: that is the step that opens the machine.
func (m *WinManager) PanicOpen(ctx context.Context) (*WinSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := m.opt.NewBackend()
	if err != nil {
		return nil, err
	}
	defer b.Close()
	st, all, err := readWin(b)
	if err != nil {
		return nil, err
	}
	snap := &WinSnapshot{Version: SnapshotVersion, Taken: m.opt.Now().UTC(), State: st, Foreign: foreignBlockers(all)}
	var errs []error
	for _, p := range st.Profiles {
		p.Enabled, p.DefaultInbound, p.DefaultOutbound = true, "Allow", "Allow"
		if err := b.SetProfile(p); err != nil {
			errs = append(errs, err)
		}
	}
	for _, r := range st.Rules {
		if r.Action == "Block" {
			if err := b.RemoveRule(r.Name); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return snap, errors.Join(errs...)
}
