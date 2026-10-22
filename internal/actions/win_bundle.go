package actions

import (
	"context"
	"fmt"
)

// regBundle is a registry-only action: a set of value edits computed from the
// parameters, with an optional precondition. secure_channel, rpc_range and
// smb1 are all instances.
type regBundle struct {
	spec Spec
	lock []string
	// edits returns the wanted registry state and notes for the plan.
	edits func(p Params) ([]regEdit, []string, error)
	// pre runs before planning (e.g. "must be a domain controller").
	pre func(ctx context.Context, env *Env, rs RegistryStore, p Params) error
	// report returns true if the action must only report (no change).
	reportOnly func(p Params) bool
}

func (b regBundle) Spec() Spec { return b.spec }
func (b regBundle) Locks(Params) []string {
	if b.lock != nil {
		return b.lock
	}
	return []string{"registry"}
}

func (b regBundle) Touches(p Params) []Touch {
	es, _, err := b.edits(p)
	if err != nil {
		return nil
	}
	var ts []Touch
	for _, e := range es {
		t, _ := registryPolicy(e.Key, e.Name, e.Val, true)
		ts = append(ts, t...)
	}
	return ts
}

func (b regBundle) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	rs, err := regStore(env)
	if err != nil {
		return Plan{}, err
	}
	es, notes, err := b.edits(p)
	if err != nil {
		return Plan{}, err
	}
	for _, e := range es {
		if _, err := registryPolicy(e.Key, e.Name, e.Val, true); err != nil {
			return Plan{}, err
		}
	}
	if b.pre != nil {
		if err := b.pre(ctx, env, rs, p); err != nil {
			return Plan{}, err
		}
	}
	pend, diff, err := planRegEdits(ctx, rs, es)
	if err != nil {
		return Plan{}, err
	}
	if b.reportOnly != nil && b.reportOnly(p) {
		if diff != "" {
			notes = append(notes, "report only; would change:\n"+diff)
		}
		return Plan{Done: true, Notes: notes}, nil
	}
	if len(pend) == 0 {
		return Plan{Done: true, Notes: notes}, nil
	}
	return Plan{Diff: diff, Notes: notes}, nil
}

func (b regBundle) Capture(ctx context.Context, env *Env, p Params) (Rollback, error) {
	rs, err := regStore(env)
	if err != nil {
		return Rollback{}, err
	}
	es, _, err := b.edits(p)
	if err != nil {
		return Rollback{}, err
	}
	return regRollbackOf(ctx, rs, es)
}

func (b regBundle) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	es, _, err := b.edits(p)
	if err != nil {
		return nil, err
	}
	return nil, applyRegEdits(ctx, env.Win.Reg, es)
}

func (b regBundle) Verify(ctx context.Context, env *Env, p Params) error {
	es, _, err := b.edits(p)
	if err != nil {
		return err
	}
	return verifyRegEdits(ctx, env.Win.Reg, es)
}

// regString reads a string value ("" if absent).
func regString(ctx context.Context, rs RegistryStore, key, name string) (string, bool, error) {
	v, ok, err := rs.Get(ctx, key, name)
	if err != nil || !ok {
		return "", ok, err
	}
	return v.Str, true, nil
}

// regUint reads a numeric value.
func regUint(ctx context.Context, rs RegistryStore, key, name string) (uint64, bool, error) {
	v, ok, err := rs.Get(ctx, key, name)
	if err != nil || !ok {
		return 0, ok, err
	}
	n, isNum := regNumeric(v)
	if !isNum {
		return 0, true, fmt.Errorf("%s\\%s is %s, want a number", key, name, v.Type)
	}
	return n, true, nil
}

func dword(n uint64) *RegValue { return &RegValue{Type: "dword", Num: n} }
func sz(s string) *RegValue    { return &RegValue{Type: "sz", Str: s} }
func multi(s ...string) *RegValue {
	return &RegValue{Type: "multi_sz", Multi: s}
}
