package deadman

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeBackstop struct {
	mu      sync.Mutex
	armed   map[string]time.Time
	arms    []string
	disarms []string
	armErr  error
}

func newFake() *fakeBackstop { return &fakeBackstop{armed: map[string]time.Time{}} }

func (f *fakeBackstop) Arm(_ context.Context, id string, d time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.armErr != nil {
		return f.armErr
	}
	f.armed[id] = d
	f.arms = append(f.arms, id)
	return nil
}

func (f *fakeBackstop) Disarm(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.armed, id)
	f.disarms = append(f.disarms, id)
	return nil
}

func (f *fakeBackstop) isArmed(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.armed[id]
	return ok
}

func open(t *testing.T, dir string, opt Options) *Manager {
	t.Helper()
	m, err := Open(dir, opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func waitState(t *testing.T, m *Manager, id string, want State) Entry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		e, err := m.Get(id)
		if err == nil && e.State == want {
			return e
		}
		if time.Now().After(deadline) {
			t.Fatalf("entry %s: want state %s, have %+v err=%v", id, want, e, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// protectedFile makes a file, snapshots it, arms a rollback and then "applies"
// the risky change by overwriting it.
func protectedFile(t *testing.T, m *Manager, id string, timeout time.Duration) (path string, orig []byte) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "sshd_config")
	orig = []byte("Port 22\nPermitRootLogin no\n\x00\xff binary tail")
	if err := os.WriteFile(path, orig, 0o640); err != nil {
		t.Fatal(err)
	}
	snap, err := SnapshotFiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Arm(context.Background(), ArmRequest{ID: id, NodeID: "n1", Timeout: timeout, Kind: KindFileRestore, Data: snap}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("Port 2222\n"), 0o600); err != nil { // the risky step
		t.Fatal(err)
	}
	return path, orig
}

func TestArmConfirmCancelsRollback(t *testing.T) {
	fb := newFake()
	m := open(t, t.TempDir(), Options{Backstop: fb})
	path, _ := protectedFile(t, m, "step1", 150*time.Millisecond)
	if !fb.isArmed("step1") {
		t.Fatal("OS backstop not armed")
	}
	if _, err := m.Confirm(context.Background(), "step1"); err != nil {
		t.Fatal(err)
	}
	if fb.isArmed("step1") {
		t.Fatal("OS backstop not disarmed by confirm")
	}
	time.Sleep(400 * time.Millisecond)
	if b, _ := os.ReadFile(path); string(b) != "Port 2222\n" {
		t.Fatalf("rollback fired after confirm: %q", b)
	}
	e, _ := m.Get("step1")
	if e.State != StateConfirmed {
		t.Fatalf("state %s", e.State)
	}
	// confirm is idempotent; a fire after confirm is a no-op
	if _, err := m.Confirm(context.Background(), "step1"); err != nil {
		t.Fatal(err)
	}
	if e, err := m.Fire(context.Background(), "step1", "os-timer"); err != nil || e.State != StateConfirmed {
		t.Fatalf("fire after confirm: %v %v", e.State, err)
	}
	if b, _ := os.ReadFile(path); string(b) != "Port 2222\n" {
		t.Fatal("late OS-timer fire undid a confirmed change")
	}
}

func TestNoConfirmFiresAndRestoresExactly(t *testing.T) {
	fb := newFake()
	results := make(chan Entry, 4)
	m := open(t, t.TempDir(), Options{Backstop: fb, OnResult: func(e Entry, err error) { results <- e }})
	path, orig := protectedFile(t, m, "step2", 100*time.Millisecond)
	e := waitState(t, m, "step2", StateRolledBack)
	if e.FiredBy != "timer" || e.Attempts != 1 || e.Outcome == "" {
		t.Fatalf("outcome not recorded: %+v", e)
	}
	select {
	case <-results:
	case <-time.After(2 * time.Second):
		t.Fatal("OnResult not called")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, orig) {
		t.Fatalf("content not restored exactly: %q", got)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode not restored: %v", st.Mode())
	}
	if fb.isArmed("step2") {
		t.Fatal("backstop left armed after fire")
	}
	if _, err := m.Confirm(context.Background(), "step2"); !errors.Is(err, ErrAlreadyFired) {
		t.Fatalf("confirm after fire: %v", err)
	}
}

func TestRestoreRemovesFileThatDidNotExist(t *testing.T) {
	m := open(t, t.TempDir(), Options{})
	p := filepath.Join(t.TempDir(), "new.conf")
	snap, _ := SnapshotFiles(p)
	m.Arm(context.Background(), ArmRequest{ID: "s", Timeout: time.Hour, Kind: KindFileRestore, Data: snap})
	os.WriteFile(p, []byte("created by step"), 0o600)
	if _, err := m.Fire(context.Background(), "s", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file created by the step was not removed")
	}
}

func TestCrashBetweenArmAndConfirmRecoveryFires(t *testing.T) {
	jdir := t.TempDir()
	now := time.Now()
	clock := &atomic.Pointer[time.Time]{}
	clock.Store(&now)
	nowFn := func() time.Time { return *clock.Load() }

	// "Process 1" arms and applies, then dies: we simply never confirm or Close.
	// A very long in-process timer means only recovery can fire it.
	m1 := open(t, jdir, Options{Backstop: newFake(), Now: nowFn})
	path, orig := protectedFile(t, m1, "crash", time.Hour)

	// "Process 2" starts after the deadline.
	later := now.Add(2 * time.Hour)
	clock.Store(&later)
	fb2 := newFake()
	m2 := open(t, jdir, Options{Backstop: fb2, Now: nowFn})
	acted, err := m2.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(acted) != 1 || acted[0].State != StateRolledBack || acted[0].FiredBy != "recovery" {
		t.Fatalf("acted: %+v", acted)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, orig) {
		t.Fatalf("recovery did not restore: %q", got)
	}
	// m1's stale in-process timer (still counting an hour) firing later is harmless.
	if e, err := m1.Fire(context.Background(), "crash", "timer"); err != nil || e.Attempts != 1 {
		t.Fatalf("stale fire not idempotent: %+v %v", e, err)
	}
}

func TestRecoveryRearmsUnexpiredEntries(t *testing.T) {
	jdir := t.TempDir()
	m1 := open(t, jdir, Options{Backstop: newFake()})
	path, orig := protectedFile(t, m1, "live", 300*time.Millisecond)
	m1.Close() // agent exits; journal remains

	fb := newFake()
	m2 := open(t, jdir, Options{Backstop: fb})
	acted, err := m2.Recover(context.Background())
	if err != nil || len(acted) != 1 || acted[0].State != StateArmed {
		t.Fatalf("acted=%+v err=%v", acted, err)
	}
	if !fb.isArmed("live") {
		t.Fatal("OS backstop not re-armed")
	}
	waitState(t, m2, "live", StateRolledBack)
	if got, _ := os.ReadFile(path); !bytes.Equal(got, orig) {
		t.Fatal("re-armed timer did not roll back")
	}
}

func TestDoubleFireIdempotentUnderConcurrency(t *testing.T) {
	var calls atomic.Int32
	h := map[string]Handler{"count": func(context.Context, Entry) error { calls.Add(1); return nil }}
	jdir := t.TempDir()
	// separate Managers = separate lock-file descriptors, like agent + OS timer process
	ms := []*Manager{open(t, jdir, Options{Handlers: h}), open(t, jdir, Options{Handlers: h})}
	if _, err := ms[0].Arm(context.Background(), ArmRequest{ID: "d", Timeout: time.Hour, Kind: "count", Data: nil}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ms[i%2].Fire(context.Background(), "d", "race"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("handler ran %d times", calls.Load())
	}
}

func TestFailedRollbackIsRetriedByRecover(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	h := map[string]Handler{"flaky": func(context.Context, Entry) error {
		if fail.Load() {
			return errors.New("disk busy")
		}
		return nil
	}}
	m := open(t, t.TempDir(), Options{Handlers: h})
	m.Arm(context.Background(), ArmRequest{ID: "f", Timeout: time.Hour, Kind: "flaky"})
	e, err := m.Fire(context.Background(), "f", "x")
	if err == nil || e.State != StateRollbackFailed || e.Error == "" {
		t.Fatalf("%+v %v", e, err)
	}
	fail.Store(false)
	if _, err := m.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e, _ := m.Get("f"); e.State != StateRolledBack || e.Attempts != 2 {
		t.Fatalf("%+v", e)
	}
}

func TestBackstopArmFailureCancelsEntry(t *testing.T) {
	fb := newFake()
	fb.armErr = errors.New("systemd unavailable")
	m := open(t, t.TempDir(), Options{Backstop: fb})
	_, err := m.Arm(context.Background(), ArmRequest{ID: "b", Timeout: time.Hour, Kind: KindFileRestore, Data: FileRestore{}})
	if err == nil {
		t.Fatal("Arm must fail when the OS timer cannot be armed")
	}
	if e, _ := m.Get("b"); e.State != StateCancelled {
		t.Fatalf("state %s", e.State)
	}
}

func TestArmValidation(t *testing.T) {
	m := open(t, t.TempDir(), Options{})
	ctx := context.Background()
	for _, id := range []string{"", "../x", "a/b", "a b", ".hidden", "x..y"} {
		if _, err := m.Arm(ctx, ArmRequest{ID: id, Timeout: time.Second, Kind: KindFileRestore, Data: FileRestore{}}); !errors.Is(err, ErrBadID) {
			t.Errorf("id %q: %v", id, err)
		}
	}
	ok := ArmRequest{ID: "ok", Timeout: time.Hour, Kind: KindFileRestore, Data: FileRestore{}}
	if _, err := m.Arm(ctx, ok); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Arm(ctx, ok); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate arm: %v", err)
	}
	if _, err := m.Arm(ctx, ArmRequest{ID: "k", Timeout: time.Second, Kind: "nope"}); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if _, err := m.Cancel(ctx, "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(ctx, "ok"); !errors.Is(err, ErrNotArmed) {
		t.Fatalf("confirm after cancel: %v", err)
	}
	if _, err := m.Confirm(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestPrune(t *testing.T) {
	m := open(t, t.TempDir(), Options{})
	ctx := context.Background()
	m.Arm(ctx, ArmRequest{ID: "a", Timeout: time.Hour, Kind: KindFileRestore, Data: FileRestore{}})
	m.Arm(ctx, ArmRequest{ID: "b", Timeout: time.Hour, Kind: KindFileRestore, Data: FileRestore{}})
	m.Confirm(ctx, "a")
	if n, err := m.Prune(0); err != nil || n != 1 {
		t.Fatalf("pruned %d %v", n, err)
	}
	if l, _ := m.List(); len(l) != 1 || l[0].ID != "b" {
		t.Fatalf("%+v", l)
	}
}

func TestCorruptEntryDoesNotBlockRecovery(t *testing.T) {
	jdir := t.TempDir()
	m := open(t, jdir, Options{})
	os.WriteFile(filepath.Join(jdir, "junk.json"), []byte("{not json"), 0o600)
	m.Arm(context.Background(), ArmRequest{ID: "good", Timeout: -0 + time.Millisecond, Kind: KindFileRestore, Data: FileRestore{}})
	time.Sleep(20 * time.Millisecond)
	_, err := m.Recover(context.Background())
	if err == nil {
		t.Fatal("corrupt entry should be reported")
	}
	waitState(t, m, "good", StateRolledBack)
}
