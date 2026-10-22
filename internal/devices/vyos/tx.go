package vyos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/devices"
)

// Payload is the Op payload for VyOS: configure-mode commands run in order in
// one session. Guard, if set, is a config path (without the leading "set")
// that must be absent or carry a phylax-managed description before the op may
// replace it.
type Payload struct {
	Guard string   `json:"guard,omitempty"`
	Cmds  []string `json:"cmds"`
}

// MakeOp builds an Op.
func MakeOp(kind, key, guard string, cmds ...string) devices.Op {
	b, _ := json.Marshal(Payload{Guard: guard, Cmds: cmds})
	return devices.Op{Kind: kind, Key: key, Payload: b}
}

var cmdRE = regexp.MustCompile(`^(set|delete) [A-Za-z0-9_./:@+*, '=-]+$`)

// checkCmd keeps a command to one line of plain words and balanced single
// quotes, so a value can never break out of the vbash script.
func checkCmd(c string) error {
	if !cmdRE.MatchString(c) || strings.Count(c, "'")%2 != 0 {
		return fmt.Errorf("vyos: refusing command %q (only set/delete of plain words)", c)
	}
	return nil
}

type tx struct {
	a   *Adapter
	opt devices.TxOptions
	id  string

	mu        sync.Mutex
	cmds      []string
	pre       string // snapshot file on the router
	armed     bool
	committed bool
	done      bool // confirmed or rolled back: the dead-man is no longer needed
	startSig  string
	tainted   []string
}

func (a *Adapter) Begin(ctx context.Context, opt devices.TxOptions) (devices.Tx, error) {
	t := &tx{a: a, opt: opt, id: a.nextID(opt)}
	t.pre = a.cfg.ArchiveDir + "/pre-" + t.id + ".boot"
	if cs, err := a.commits(ctx); err == nil && len(cs) > 0 {
		t.startSig = cs[0].Sig()
	}
	return t, nil
}

func (t *tx) ID() string { return t.id }

func (t *tx) Preflight(ctx context.Context) (devices.Preflight, error) {
	pf := devices.Preflight{OK: true}
	fail := func(f string, a ...any) {
		pf.OK = false
		pf.Reasons = append(pf.Reasons, fmt.Sprintf(f, a...))
	}
	cs, err := t.a.commits(ctx)
	if err != nil {
		return pf, fmt.Errorf("vyos: router unreachable: %w", err)
	}
	if lg := t.opt.LastGood; lg != nil && lg.Meta["commit"] != "" {
		if len(cs) == 0 || cs[0].Sig() != lg.Meta["commit"] {
			pf.Drifted = true
			fail("latest commit differs from the last known-good (foreign commit): drift")
		}
	}
	out, err := t.a.vbash(ctx, "configure\ncompare commands\nexit discard\n")
	if err != nil {
		return pf, err
	}
	if strings.TrimSpace(stripNoChange(out)) != "" {
		pf.Foreign = append(pf.Foreign, "uncommitted changes in the shared session")
		fail("compare is not empty: %s", strings.TrimSpace(out))
	}
	if lg := t.opt.LastGood; lg != nil {
		cur, err := t.a.Snapshot(ctx, "preflight")
		if err != nil {
			return pf, err
		}
		if cur.Hash != lg.Hash {
			pf.Drifted = true
			fail("running config differs from the last known-good (drift)")
		}
	}
	// A leftover timer from a crashed plan would revert our change under us.
	if out, err := t.a.ssh.run(ctx, "systemctl is-active "+t.a.cfg.RevertUnit+".timer", ""); err == nil && strings.TrimSpace(out) == "active" {
		fail("a %s timer is already armed on the router", t.a.cfg.RevertUnit)
	}
	return pf, nil
}

// Lock is a no-op: VyOS has per-session working configs and no config lock.
func (t *tx) Lock(context.Context) error { return nil }

func (t *tx) Stage(ctx context.Context, cs devices.ChangeSet) error {
	var lines []string
	needGuard := false
	for _, op := range cs.Ops {
		var p Payload
		if err := json.Unmarshal(op.Payload, &p); err != nil {
			return fmt.Errorf("vyos: op %s: bad payload", op.Key)
		}
		if p.Guard != "" {
			needGuard = true
		}
	}
	if needGuard {
		var err error
		if lines, err = t.a.configLines(ctx); err != nil {
			return err
		}
	}
	var add []string
	for _, op := range cs.Ops {
		var p Payload
		_ = json.Unmarshal(op.Payload, &p)
		if p.Guard != "" {
			if err := guardOK(lines, p.Guard); err != nil {
				return err
			}
		}
		for _, c := range p.Cmds {
			if err := checkCmd(c); err != nil {
				return err
			}
			add = append(add, c)
		}
	}
	t.mu.Lock()
	t.cmds = append(t.cmds, add...)
	t.mu.Unlock()
	return nil
}

// guardOK: the item at guard may be replaced only if absent or phylax-managed.
func guardOK(lines []string, guard string) error {
	prefix := "set " + guard + " "
	exists, managed := false, false
	for _, l := range lines {
		if !strings.HasPrefix(l, prefix) && l != "set "+guard {
			continue
		}
		exists = true
		rest := strings.TrimPrefix(l, prefix)
		if strings.HasPrefix(rest, "description '"+ManagedTag) {
			managed = true
		}
	}
	if exists && !managed {
		return fmt.Errorf("%w: %s", devices.ErrNotManaged, guard)
	}
	return nil
}

func (t *tx) script(tail ...string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var b strings.Builder
	b.WriteString("configure\n")
	for _, c := range t.cmds {
		b.WriteString(c + "\n")
	}
	for _, l := range tail {
		b.WriteString(l + "\n")
	}
	return b.String()
}

func (t *tx) Pending(ctx context.Context) (devices.PendingSet, error) {
	out, err := t.a.vbash(ctx, t.script("compare commands", "exit discard"))
	if err != nil {
		return devices.PendingSet{}, err
	}
	if err := scriptErr(out); err != nil {
		return devices.PendingSet{}, err
	}
	var ps devices.PendingSet
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "set ") || strings.HasPrefix(l, "delete ") {
			ps.Ours = append(ps.Ours, l)
		}
	}
	return ps, nil
}

// Validate: VyOS validates at commit time only; the dry run shows command
// errors and the exact diff.
func (t *tx) Validate(ctx context.Context) (devices.Validation, error) {
	out, err := t.a.vbash(ctx, t.script("compare commands", "exit discard"))
	if err != nil {
		return devices.Validation{}, err
	}
	if err := scriptErr(out); err != nil {
		return devices.Validation{Errors: []string{err.Error()}}, nil
	}
	return devices.Validation{OK: true}, nil
}

func durArg(d time.Duration) string {
	if d%time.Second == 0 {
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

// revertScript is what the on-box timer and a manual rollback both run.
func (t *tx) revertScript() string {
	return fmt.Sprintf("configure\nload %s\ncommit\nexit\n", t.pre)
}

func (t *tx) armCmd() string {
	inner := fmt.Sprintf(`source /opt/vyatta/etc/functions/script-template; configure; load %s; commit; exit`, t.pre)
	return fmt.Sprintf(`sudo systemd-run --quiet --on-active=%s --unit=%s sg vyattacfg -c '/bin/vbash -c "%s"'`,
		durArg(t.opt.Deadman), t.a.cfg.RevertUnit, inner)
}

func (t *tx) Commit(ctx context.Context) (devices.CommitResult, error) {
	var res devices.CommitResult
	if _, err := t.a.ssh.run(ctx, "mkdir -p "+t.a.cfg.ArchiveDir, ""); err != nil {
		return res, fmt.Errorf("%w: archive dir: %v", devices.ErrCommit, err)
	}
	// 1 snapshot to a file that is not /config/config.boot.
	out, err := t.a.vbash(ctx, fmt.Sprintf("configure\nsave %s\nexit\n", t.pre))
	if err == nil {
		err = scriptErr(out)
	}
	if err != nil {
		return res, fmt.Errorf("%w: pre-change snapshot: %v", devices.ErrCommit, err)
	}
	// 2 arm the soft revert before touching anything.
	if t.opt.Deadman > 0 {
		if _, err := t.a.ssh.run(ctx, t.armCmd(), ""); err != nil {
			return res, fmt.Errorf("%w: arm dead-man: %v", devices.ErrCommit, err)
		}
		t.mu.Lock()
		t.armed = true
		t.mu.Unlock()
	}
	// 3 apply with a plain commit (never commit-confirm: it reboots).
	t.mu.Lock()
	t.committed = true
	t.mu.Unlock()
	out, err = t.a.vbash(ctx, t.script("commit", "exit"))
	if err == nil {
		err = scriptErr(out)
	}
	if err != nil {
		return res, fmt.Errorf("%w: %v", devices.ErrCommit, err)
	}
	res.Details = strings.TrimSpace(out)
	// 4 lockout-class: prove a brand-new connection still works.
	if t.opt.Scope == devices.ScopeManagement || t.opt.Risk == devices.RiskLockout {
		if err := t.a.Probe(ctx); err != nil {
			return res, err
		}
	}
	return res, nil
}

func (t *tx) disarm(ctx context.Context) {
	t.mu.Lock()
	armed := t.armed
	t.armed = false
	t.mu.Unlock()
	if armed {
		_, _ = t.a.ssh.run(ctx, "sudo systemctl stop "+t.a.cfg.RevertUnit+".timer", "")
	}
}

func (t *tx) Confirm(ctx context.Context) error {
	t.disarm(ctx)
	// If the timer already fired (health was too slow) the change is gone:
	// re-applying it would show a diff.
	ps, err := t.Pending(ctx)
	if err != nil {
		return err
	}
	if len(ps.Ours) != 0 {
		return fmt.Errorf("vyos: the change is no longer active (dead-man fired?): %s", strings.Join(ps.Ours, "; "))
	}
	// Foreign commits during our window taint the new known-good.
	if cs, err := t.a.commits(ctx); err == nil {
		fresh, _ := newSince(cs, t.startSig)
		for _, c := range fresh {
			if c.User == t.a.cfg.SSH.User {
				continue
			}
			t.tainted = append(t.tainted, fmt.Sprintf("%s via %s at %s", c.User, c.Via, c.When))
		}
	}
	// Persist only now: a surprise reboot before this point returns to the old boot config.
	out, err := t.a.vbash(ctx, "configure\nsave\nexit\n")
	if err == nil {
		err = scriptErr(out)
	}
	if err != nil {
		return fmt.Errorf("vyos: save: %w", err)
	}
	_, _ = t.a.ssh.run(ctx, "rm -f "+t.pre, "")
	t.mu.Lock()
	t.done = true
	t.mu.Unlock()
	return nil
}

func (t *tx) Tainted() []string { return t.tainted }

func (t *tx) Rollback(ctx context.Context, how devices.RollbackMode) error {
	t.mu.Lock()
	committed := t.committed
	t.cmds = nil
	t.mu.Unlock()
	if !committed {
		return nil // nothing reached the router: staged commands only lived in memory
	}
	out, err := t.a.vbash(ctx, t.revertScript())
	if err == nil {
		err = scriptErr(out)
	}
	if err != nil {
		wait := ""
		t.mu.Lock()
		armed := t.armed
		t.mu.Unlock()
		if armed {
			wait = fmt.Sprintf("; the dead-man timer on the router will revert within %s", t.opt.Deadman)
		}
		return fmt.Errorf("vyos: revert failed: %w%s", err, wait)
	}
	t.disarm(ctx)
	t.mu.Lock()
	t.committed = false
	t.done = true
	t.mu.Unlock()
	if t.opt.Scope == devices.ScopeManagement || t.opt.Risk == devices.RiskLockout {
		if err := t.a.Probe(ctx); err != nil {
			return fmt.Errorf("vyos: reverted, but a new connection still fails: %w", err)
		}
	}
	return nil
}

// Close leaves an armed dead-man in place on purpose: if the controller died
// mid-change, the router reverts itself.
func (t *tx) Close(context.Context) error { return nil }

// DisarmStale stops a leftover revert timer after a controller restart, once
// an operator has checked the router state.
func (a *Adapter) DisarmStale(ctx context.Context) error {
	_, err := a.ssh.run(ctx, "sudo systemctl stop "+a.cfg.RevertUnit+".timer", "")
	var ee *ExitError
	if errors.As(err, &ee) {
		return nil // not loaded
	}
	return err
}
