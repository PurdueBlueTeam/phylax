//go:build linux

package audit

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"syscall"

	libaudit "github.com/elastic/go-libaudit/v2"
)

// kernelControl is the command-and-control surface of the audit client that
// the guard needs (satisfied by *libaudit.AuditClient).
type kernelControl interface {
	GetStatus() (*libaudit.AuditStatus, error)
	GetRules() ([][]byte, error)
	AddRule([]byte) error
	DeleteRule([]byte) error
	SetEnabled(bool, libaudit.WaitMode) error
	Close() error
}

// guard installs the rule set and verifies it by hash.
type guard struct {
	ctl  kernelControl
	log  *slog.Logger
	want map[string][]byte // canonical line -> wire, for every rule we mean to have

	baseLines []string // our rules as read back from the kernel after install
	baseHash  string
	failed    map[string]string // line -> error for rules the kernel refused
	lastNever int
}

func newGuard(ctl kernelControl, rs *RuleSet, log *slog.Logger) (*guard, error) {
	g := &guard{ctl: ctl, log: log, want: map[string][]byte{}, failed: map[string]string{}}
	for i, wf := range rs.Wire {
		l, err := canonLine(wf)
		if err != nil {
			return nil, fmt.Errorf("audit: render %q: %w", rs.Lines[i], err)
		}
		g.want[l] = wf
	}
	return g, nil
}

// RulesReport is the outcome of one reconcile or verify.
type RulesReport struct {
	Hash      string
	Baseline  string
	Missing   []string // wanted but absent from the kernel (before repair)
	Stale     []string // our-keyed rules in the kernel that are not wanted
	Repaired  bool
	Failed    map[string]string
	Never     []string
	Foreign   int
	Installed int
}

// Reconcile makes the kernel's rules with our keys equal to the wanted set,
// never touching rules with other keys, and records the result as the new
// baseline.
func (g *guard) Reconcile() (RulesReport, error) {
	rep := RulesReport{}
	raw, err := g.ctl.GetRules()
	if err != nil {
		return rep, fmt.Errorf("audit: get rules: %w", err)
	}
	have := map[string][]byte{}
	for _, wf := range raw {
		if l, err := canonLine(wf); err == nil && isOurs(l) {
			have[l] = wf
		}
	}
	for l, wf := range have {
		if _, ok := g.want[l]; !ok {
			rep.Stale = append(rep.Stale, l)
			if err := g.ctl.DeleteRule(wf); err != nil {
				g.log.Warn("audit: delete stale rule", "rule", l, "err", err)
			}
		}
	}
	g.failed = map[string]string{}
	lines := make([]string, 0, len(g.want))
	for l := range g.want {
		lines = append(lines, l)
	}
	sort.Strings(lines)
	for _, l := range lines {
		if _, ok := have[l]; ok {
			continue
		}
		rep.Missing = append(rep.Missing, l)
		if err := g.ctl.AddRule(g.want[l]); err != nil && !errors.Is(err, syscall.EEXIST) {
			g.failed[l] = err.Error()
			g.log.Warn("audit: add rule", "rule", l, "err", err)
		}
	}
	rep.Repaired = len(rep.Missing) > 0 || len(rep.Stale) > 0
	return g.finish(rep)
}

func (g *guard) finish(rep RulesReport) (RulesReport, error) {
	raw, err := g.ctl.GetRules()
	if err != nil {
		return rep, fmt.Errorf("audit: get rules: %w", err)
	}
	v := ClassifyKernelRules(raw)
	g.baseLines, g.baseHash = v.Ours, HashLines(v.Ours)
	rep.Hash, rep.Baseline = g.baseHash, g.baseHash
	rep.Never, rep.Foreign, rep.Installed = v.Never, v.Foreign, len(v.Ours)
	rep.Failed = g.failed
	g.lastNever = len(v.Never)
	return rep, nil
}

// Verify compares the kernel's rules with the baseline by hash; on a mismatch
// it reinstalls what is missing and reports what it found.
func (g *guard) Verify() (RulesReport, bool, error) {
	raw, err := g.ctl.GetRules()
	if err != nil {
		return RulesReport{}, false, fmt.Errorf("audit: get rules: %w", err)
	}
	v := ClassifyKernelRules(raw)
	h := HashLines(v.Ours)
	if h == g.baseHash {
		rep := RulesReport{Hash: h, Baseline: g.baseHash, Never: v.Never, Foreign: v.Foreign,
			Installed: len(v.Ours), Failed: g.failed}
		changedNever := len(v.Never) != g.lastNever
		g.lastNever = len(v.Never)
		return rep, changedNever, nil
	}
	// Tampered or flushed. Record what differs from the baseline, repair, and
	// re-baseline. Missing is computed against the baseline, not just `want`,
	// so rules that failed to install at startup do not look like tampering.
	rep := RulesReport{Baseline: g.baseHash, Hash: h,
		Missing: Missing(g.baseLines, v.Ours), Stale: Missing(v.Ours, g.baseLines)}
	fixed, err := g.Reconcile()
	if err != nil {
		return rep, true, err
	}
	rep.Repaired = true
	rep.Never, rep.Foreign, rep.Installed, rep.Failed = fixed.Never, fixed.Foreign, fixed.Installed, fixed.Failed
	return rep, true, nil
}

// Remove deletes the rules with our keys that are in the wanted set.
func (g *guard) Remove() {
	raw, err := g.ctl.GetRules()
	if err != nil {
		return
	}
	for _, wf := range raw {
		if l, err := canonLine(wf); err == nil && isOurs(l) {
			if _, ok := g.want[l]; ok {
				_ = g.ctl.DeleteRule(wf)
			}
		}
	}
}
