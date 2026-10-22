package devices_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/devices"
)

// memAdapter is a minimal in-memory device used to prove the runner's
// ordering and failure handling independent of any vendor.
type memAdapter struct {
	caps               devices.Caps
	log                []string
	failAt             string
	foreign            []string
	rollbackFailsFirst bool
	rollbackCalls      int
	ctxCancelOnCommit  context.CancelFunc
}

func (m *memAdapter) Kind() devices.Kind                         { return "mem" }
func (m *memAdapter) Caps() devices.Caps                         { return m.caps }
func (m *memAdapter) Close() error                               { return nil }
func (m *memAdapter) Info(context.Context) (devices.Info, error) { return devices.Info{}, nil }
func (m *memAdapter) Probe(context.Context) error                { return nil }
func (m *memAdapter) Admins(context.Context) (devices.AdminState, error) {
	return devices.AdminState{}, nil
}
func (m *memAdapter) Events(context.Context, devices.EventFilter) ([]devices.Event, devices.Cursor, error) {
	return nil, "", nil
}
func (m *memAdapter) Diff(context.Context, devices.Snapshot, devices.Snapshot) (devices.Diff, error) {
	return devices.Diff{}, nil
}
func (m *memAdapter) Drift(context.Context, devices.Snapshot) (devices.DriftReport, error) {
	return devices.DriftReport{}, nil
}
func (m *memAdapter) Snapshot(_ context.Context, l string) (devices.Snapshot, error) {
	m.log = append(m.log, "snapshot")
	return devices.Snapshot{Label: l}, nil
}
func (m *memAdapter) Begin(_ context.Context, o devices.TxOptions) (devices.Tx, error) {
	m.log = append(m.log, "begin")
	return &memTx{m: m, opt: o}, nil
}

type memTx struct {
	m   *memAdapter
	opt devices.TxOptions
}

func (t *memTx) step(s string) error {
	t.m.log = append(t.m.log, s)
	if t.m.failAt == s {
		return errors.New(s + " boom")
	}
	return nil
}
func (t *memTx) ID() string { return "tx1" }
func (t *memTx) Preflight(context.Context) (devices.Preflight, error) {
	t.m.log = append(t.m.log, "preflight")
	return devices.Preflight{OK: t.m.failAt != "preflight-refuse", Reasons: []string{"nope"}}, nil
}
func (t *memTx) Lock(context.Context) error                     { return t.step("lock") }
func (t *memTx) Stage(context.Context, devices.ChangeSet) error { return t.step("stage") }
func (t *memTx) Pending(context.Context) (devices.PendingSet, error) {
	t.m.log = append(t.m.log, "pending")
	return devices.PendingSet{Foreign: t.m.foreign}, nil
}
func (t *memTx) Validate(context.Context) (devices.Validation, error) {
	t.m.log = append(t.m.log, "validate")
	return devices.Validation{OK: t.m.failAt != "validate-fail", Errors: []string{"bad"}}, nil
}
func (t *memTx) Commit(context.Context) (devices.CommitResult, error) {
	if t.m.ctxCancelOnCommit != nil {
		t.m.ctxCancelOnCommit()
	}
	return devices.CommitResult{}, t.step("commit")
}
func (t *memTx) Confirm(context.Context) error { return t.step("confirm") }
func (t *memTx) Rollback(_ context.Context, how devices.RollbackMode) error {
	t.m.rollbackCalls++
	t.m.log = append(t.m.log, map[devices.RollbackMode]string{
		devices.RollbackGranular: "rollback-granular", devices.RollbackToSnapshot: "rollback-snapshot", devices.RollbackDiscardStaged: "rollback-discard"}[how])
	if t.m.rollbackFailsFirst && t.m.rollbackCalls == 1 {
		return errors.New("granular failed")
	}
	return nil
}
func (t *memTx) Close(context.Context) error { t.m.log = append(t.m.log, "close"); return nil }

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRunnerOrderAndHappyPath(t *testing.T) {
	m := &memAdapter{}
	_, err := devices.SafeChange(context.Background(), m, devices.Request{
		Opts:   devices.TxOptions{Risk: devices.RiskService},
		Health: func(context.Context) error { m.log = append(m.log, "health"); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"begin", "preflight", "lock", "snapshot", "stage", "pending", "validate", "commit", "health", "confirm", "snapshot", "close"}
	if !eq(m.log, want) {
		t.Errorf("order:\n got %v\nwant %v", m.log, want)
	}
}

func TestRunnerFailures(t *testing.T) {
	cases := []struct {
		name   string
		m      *memAdapter
		want   error
		rollTo string
		noRoll bool
	}{
		{"preflight", &memAdapter{failAt: "preflight-refuse"}, devices.ErrPreflight, "", true},
		{"stage", &memAdapter{failAt: "stage"}, nil, "rollback-discard", false},
		{"foreign pending", &memAdapter{foreign: []string{"x"}}, devices.ErrForeignPending, "rollback-discard", false},
		{"validate", &memAdapter{failAt: "validate-fail"}, devices.ErrValidation, "rollback-discard", false},
		{"commit", &memAdapter{failAt: "commit"}, devices.ErrCommit, "rollback-granular", false},
		{"confirm", &memAdapter{failAt: "confirm"}, nil, "rollback-granular", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := devices.SafeChange(context.Background(), c.m, devices.Request{Opts: devices.TxOptions{Risk: devices.RiskService}})
			if err == nil {
				t.Fatal("no error")
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("err = %v", err)
			}
			if c.noRoll {
				if c.m.rollbackCalls != 0 {
					t.Error("rolled back before anything was staged")
				}
			} else if !res.RolledBack || !contains(c.m.log, c.rollTo) {
				t.Errorf("log %v, rolledBack=%v", c.m.log, res.RolledBack)
			}
			if c.m.log[len(c.m.log)-1] != "close" {
				t.Error("tx not closed")
			}
		})
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestRunnerHealthFailureRollsBackAndFallsBackToSnapshot(t *testing.T) {
	m := &memAdapter{rollbackFailsFirst: true}
	res, err := devices.SafeChange(context.Background(), m, devices.Request{
		Opts:   devices.TxOptions{Risk: devices.RiskService},
		Health: func(context.Context) error { return errors.New("probe") },
	})
	if !errors.Is(err, devices.ErrHealth) || !res.RolledBack {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if !contains(m.log, "rollback-granular") || !contains(m.log, "rollback-snapshot") {
		t.Errorf("no snapshot fallback: %v", m.log)
	}
}

func TestRunnerBothRollbacksFail(t *testing.T) {
	m := &memAdapter{}
	m.rollbackFailsFirst = true
	m.failAt = "commit"
	// make the second rollback fail too by wrapping: use a distinct adapter
	m2 := &failingRollback{memAdapter: m}
	_, err := devices.SafeChange(context.Background(), m2, devices.Request{Opts: devices.TxOptions{Risk: devices.RiskService}})
	if !errors.Is(err, devices.ErrRollback) || !errors.Is(err, devices.ErrCommit) {
		t.Fatalf("got %v", err)
	}
}

type failingRollback struct{ *memAdapter }

func (f *failingRollback) Begin(ctx context.Context, o devices.TxOptions) (devices.Tx, error) {
	tx, _ := f.memAdapter.Begin(ctx, o)
	return &alwaysFail{tx}, nil
}

type alwaysFail struct{ devices.Tx }

func (a *alwaysFail) Rollback(context.Context, devices.RollbackMode) error { return errors.New("dead") }

func TestRunnerLockoutRules(t *testing.T) {
	// No dead-man and no console ack: refused before anything is touched.
	m := &memAdapter{}
	if _, err := devices.SafeChange(context.Background(), m, devices.Request{Opts: devices.TxOptions{Risk: devices.RiskLockout}}); !errors.Is(err, devices.ErrNoDeadman) {
		t.Fatalf("got %v", err)
	}
	if len(m.log) != 0 {
		t.Errorf("touched the device: %v", m.log)
	}
	// Console acknowledged: allowed.
	if _, err := devices.SafeChange(context.Background(), m, devices.Request{Opts: devices.TxOptions{Risk: devices.RiskLockout}, ConsoleAck: true}); err != nil {
		t.Fatal(err)
	}
	// A device with a soft dead-man gets one by default.
	m = &memAdapter{caps: devices.Caps{SoftDeadman: true}}
	var got devices.TxOptions
	m3 := &optSpy{memAdapter: m, got: &got}
	if _, err := devices.SafeChange(context.Background(), m3, devices.Request{Opts: devices.TxOptions{Risk: devices.RiskLockout}}); err != nil {
		t.Fatal(err)
	}
	if got.Deadman == 0 {
		t.Error("lockout change on a dead-man device ran without a dead-man")
	}
}

type optSpy struct {
	*memAdapter
	got *devices.TxOptions
}

func (o *optSpy) Begin(ctx context.Context, opt devices.TxOptions) (devices.Tx, error) {
	*o.got = opt
	return o.memAdapter.Begin(ctx, opt)
}

func TestRunnerRollsBackEvenIfContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := &memAdapter{failAt: "commit", ctxCancelOnCommit: cancel}
	res, err := devices.SafeChange(ctx, m, devices.Request{Opts: devices.TxOptions{Risk: devices.RiskService}})
	if err == nil || !res.RolledBack {
		t.Fatalf("err=%v res=%+v: a cancelled controller context must not skip the undo", err, res)
	}
}

func TestDiffMaps(t *testing.T) {
	d := devices.DiffMaps(map[string]string{"a": "1", "b": "2", "c": "3"}, map[string]string{"a": "1", "b": "9", "d": "4"})
	if len(d.Entries) != 3 || d.Entries[0].Path != "b" || d.Entries[0].Kind != devices.Changed || d.Entries[1].Kind != devices.Removed || d.Entries[2].Kind != devices.Added {
		t.Errorf("%+v", d)
	}
	if !devices.DiffMaps(nil, nil).Empty() {
		t.Error("empty diff not empty")
	}
}
