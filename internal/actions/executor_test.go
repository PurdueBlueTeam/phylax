package actions

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/atomicfile"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

func TestDryRunShowsDiffAndChangesNothing(t *testing.T) {
	f := newFixture(t)
	f.write(t, "etc/motd", "hello\nworld\n", 0o644)
	o, err := f.run(t, "file.write", map[string]any{"path": "/etc/motd", "content": "hello\nthere\n"}, func(r *Request) { r.DryRun = true })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(o.Plan.Diff, "-world") || !strings.Contains(o.Plan.Diff, "+there") || o.Plan.Done {
		t.Fatalf("diff: %+v", o.Plan)
	}
	if f.read(t, "etc/motd") != "hello\nworld\n" {
		t.Fatal("dry run modified the file")
	}
	o, _ = f.run(t, "file.write", map[string]any{"path": "/etc/new", "content": "x\n"}, func(r *Request) { r.DryRun = true })
	if !strings.Contains(o.Plan.Diff, "create /etc/new") {
		t.Fatalf("create diff: %q", o.Plan.Diff)
	}
	if _, err := os.Stat(f.path("etc/new")); err == nil {
		t.Fatal("dry run created a file")
	}
	// shadow dry run
	o, err = f.run(t, "user.lock", map[string]any{"user": "sysadmin"}, func(r *Request) { r.DryRun = true })
	if err != nil || !strings.Contains(o.Plan.Diff, "locked false -> true") || f.read(t, "etc/shadow") != shadowFix {
		t.Fatalf("lock dry run: %+v %v", o.Plan, err)
	}
}

func TestDryRunReportsBlockedByLock(t *testing.T) {
	f := newFixture(t)
	rel, err := f.env.Locks.Acquire(t.Context(), LockAccounts)
	if err != nil {
		t.Fatal(err)
	}
	defer rel()
	o, err := f.run(t, "user.lock", map[string]any{"user": "sysadmin"}, func(r *Request) { r.DryRun = true })
	if err != nil || o.Plan.Blocked != LockAccounts {
		t.Fatalf("blocked=%q err=%v", o.Plan.Blocked, err)
	}
	// a real run waits for the lock and honours ctx
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err = f.env.Execute(ctx, Request{Action: "user.lock", Params: map[string]any{"user": "sysadmin"}, Deadman: NoDeadman})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline while waiting for lock, got %v", err)
	}
}

func TestLocksSerializeAndNamesIndependent(t *testing.T) {
	l := NewLocks()
	rel1, _ := l.Acquire(t.Context(), LockFirewall, LockAccounts)
	if _, busy := l.TryAcquire(LockSSHD, LockFirewall); busy != LockFirewall {
		t.Fatalf("busy=%q", busy)
	}
	// failed TryAcquire must not leak the sshd lock
	if r, busy := l.TryAcquire(LockSSHD); r == nil {
		t.Fatalf("sshd leaked: %q", busy)
	} else {
		r()
	}
	done := make(chan struct{})
	go func() {
		r, _ := l.Acquire(t.Context(), LockAccounts, LockFirewall) // opposite order: must not deadlock
		r()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("acquired while held")
	case <-time.After(50 * time.Millisecond):
	}
	rel1()
	rel1() // idempotent
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("never acquired")
	}
}

func TestDeadmanTimerRestoresWhenNotConfirmed(t *testing.T) {
	f := newFixture(t)
	o := f.ok(t, "user.set_password", map[string]any{"user": "sysadmin", "password": "Locked-Out-1"}, func(r *Request) { r.Deadman = 150 * time.Millisecond })
	if o.DeadmanID == "" {
		t.Fatal("lockout-class action did not leave an armed entry")
	}
	if f.read(t, "etc/shadow") == shadowFix {
		t.Fatal("change not applied")
	}
	waitFor(t, "rollback", func() bool { return f.read(t, "etc/shadow") == shadowFix })
	waitFor(t, "journal outcome", func() bool {
		e, _ := f.dm.Get(o.DeadmanID)
		return e.State == deadman.StateRolledBack
	})
	// owner/mode intact
	if st, _ := os.Stat(f.path("etc/shadow")); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode after rollback %v", st.Mode())
	}
}

func TestDeadmanConfirmKeepsChange(t *testing.T) {
	f := newFixture(t)
	o := f.ok(t, "user.lock", map[string]any{"user": "sysadmin"}, func(r *Request) { r.Deadman = 150 * time.Millisecond })
	if err := f.env.Confirm(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if !strings.Contains(f.read(t, "etc/shadow"), "sysadmin:!$6$") {
		t.Fatal("confirmed change was rolled back")
	}
}

func TestLockoutDefaultsToDeadman(t *testing.T) {
	f := newFixture(t)
	o := f.ok(t, "user.lock", map[string]any{"user": "sysadmin"})
	if o.DeadmanID == "" {
		t.Fatal("no default dead-man for lockout class")
	}
	e, _ := f.dm.Get(o.DeadmanID)
	if d := e.Deadline.Sub(e.ArmedAt); d != DefaultDeadman {
		t.Fatalf("default window %v", d)
	}
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatal(err)
	}
	if f.read(t, "etc/shadow") != shadowFix {
		t.Fatal("manual rollback did not restore")
	}
}

func TestLockoutWithoutDeadmanRefused(t *testing.T) {
	f := newFixture(t)
	f.env.Deadman = nil
	_, err := f.run(t, "user.lock", map[string]any{"user": "sysadmin"})
	if !errors.Is(err, ErrNoDeadman) {
		t.Fatalf("want ErrNoDeadman, got %v", err)
	}
	if f.read(t, "etc/shadow") != shadowFix {
		t.Fatal("applied without dead-man")
	}
}

// failVerify writes a file and then fails verification, to prove the executor
// rolls back through the dead-man journal.
type failVerify struct{ path string }

func (failVerify) Spec() Spec {
	return Spec{Name: "test.failverify", Risk: RiskService}
}
func (failVerify) Locks(Params) []string  { return nil }
func (failVerify) Touches(Params) []Touch { return nil }
func (failVerify) Plan(context.Context, *Env, Params) (Plan, error) {
	return Plan{Diff: "x"}, nil
}
func (a failVerify) Capture(context.Context, *Env, Params) (Rollback, error) {
	return snapshotRollback(a.path)
}
func (a failVerify) Apply(context.Context, *Env, Params) (Output, error) {
	return nil, atomicfile.WriteFile(a.path, []byte("broken"), 0o644)
}
func (failVerify) Verify(context.Context, *Env, Params) error {
	return errors.New("health probe failed")
}

func TestVerifyFailureRollsBackImmediately(t *testing.T) {
	f := newFixture(t)
	p := f.path("etc/important")
	if err := os.WriteFile(p, []byte("good"), 0o640); err != nil {
		t.Fatal(err)
	}
	f.env.Registry = NewRegistry()
	f.env.Registry.Register(failVerify{path: p})
	o, err := f.run(t, "test.failverify", nil, func(r *Request) { r.Deadman = time.Minute })
	if err == nil || !strings.Contains(err.Error(), "health probe failed") {
		t.Fatalf("err=%v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "good" {
		t.Fatalf("not rolled back: %q", b)
	}
	if o.Changed || o.DeadmanID != "" {
		t.Fatalf("outcome: %+v", o)
	}
	ents, _ := f.dm.List()
	if len(ents) != 1 || ents[0].State != deadman.StateRolledBack {
		t.Fatalf("journal: %+v", ents)
	}
}

func TestSafeModeRefusesEverythingButRollback(t *testing.T) {
	f := newFixture(t)
	// arm a change first
	o := f.ok(t, "user.lock", map[string]any{"user": "sysadmin"})
	sm, err := NewSafeMode(filepath.Join(t.TempDir(), "safe"))
	if err != nil {
		t.Fatal(err)
	}
	f.env.Safe = sm
	if err := sm.Set(true); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		a string
		p map[string]any
	}{
		{"user.lock", map[string]any{"user": "bob"}},
		{"file.write", map[string]any{"path": "/etc/x", "content": "x"}},
		{"service.start", map[string]any{"unit": "cups"}},
	} {
		if _, err := f.run(t, c.a, c.p); !errors.Is(err, ErrSafeMode) {
			t.Errorf("%s in safe mode: %v", c.a, err)
		}
	}
	if _, err := f.run(t, "file.hash", map[string]any{"path": "/etc/passwd"}); err != nil {
		t.Fatalf("read-only action in safe mode: %v", err)
	}
	if _, err := os.Stat(f.path("etc/x")); err == nil {
		t.Fatal("file written in safe mode")
	}
	// dry run (read-only) is still allowed
	if _, err := f.run(t, "user.lock", map[string]any{"user": "bob"}, func(r *Request) { r.DryRun = true }); err != nil {
		t.Fatal(err)
	}
	// rollback is allowed
	if err := f.env.Rollback(t.Context(), o.DeadmanID); err != nil {
		t.Fatalf("rollback in safe mode: %v", err)
	}
	if f.read(t, "etc/shadow") != shadowFix {
		t.Fatal("rollback did not restore")
	}
	// persisted across restarts
	sm2, _ := NewSafeMode(sm.path)
	if !sm2.On() {
		t.Fatal("safe mode lost on restart")
	}
	_ = sm2.Set(false)
	sm3, _ := NewSafeMode(sm.path)
	if sm3.On() {
		t.Fatal("safe mode stuck")
	}
	f.env.Safe = sm3
	if _, err := f.run(t, "user.lock", map[string]any{"user": "bob"}, func(r *Request) { r.Deadman = NoDeadman }); err != nil {
		t.Fatal(err)
	}
}

func TestScoringGuardRefusals(t *testing.T) {
	f := newFixture(t)
	f.env.Guard = StaticGuard{
		Accounts: []string{"sysadmin", "alice"}, Services: []string{"sshd", "httpd"},
		Paths: []string{"/var/www/html"}, Groups: []string{"sudo"},
	}
	f.write(t, "var/www/html/index.html", "scored", 0o644)
	cases := []struct {
		name string
		a    string
		p    map[string]any
		mut  []func(*Request)
	}{
		{"lock scored", "user.lock", map[string]any{"user": "sysadmin"}, nil},
		{"delete scored", "user.delete", map[string]any{"user": "ALICE"}, nil},
		{"set scored pw without PCR", "user.set_password", map[string]any{"user": "sysadmin", "password": "x"}, nil},
		{"remove scored from access group", "group.members", map[string]any{"group": "sudo", "remove": []any{"sysadmin"}}, nil},
		{"exact member list drops scored", "group.members", map[string]any{"group": "sudo", "members": []any{}}, nil},
		{"stop scored svc", "service.stop", map[string]any{"unit": "sshd.service"}, nil},
		{"disable scored svc", "service.disable", map[string]any{"unit": "sshd"}, nil},
		{"mask scored svc", "service.mask", map[string]any{"unit": "httpd"}, nil},
		{"state stopped", "service.state", map[string]any{"unit": "httpd", "state": "stopped"}, nil},
		{"write scored content", "file.write", map[string]any{"path": "/var/www/html/index.html", "content": "pwn"}, nil},
		{"quarantine scored content", "file.quarantine", map[string]any{"path": "/var/www/html/index.html"}, nil},
	}
	for _, c := range cases {
		mut := append([]func(*Request){func(r *Request) { r.Deadman = NoDeadman }}, c.mut...)
		if _, err := f.run(t, c.a, c.p, mut...); !errors.Is(err, ErrScoringUnsafe) {
			t.Errorf("%s: want ErrScoringUnsafe, got %v", c.name, err)
		}
		// dry-run reports the refusal too (plan lint)
		if _, err := f.run(t, c.a, c.p, func(r *Request) { r.DryRun = true }); !errors.Is(err, ErrScoringUnsafe) {
			t.Errorf("%s dry-run: want ErrScoringUnsafe, got %v", c.name, err)
		}
	}
	if f.read(t, "etc/shadow") != shadowFix || f.read(t, "var/www/html/index.html") != "scored" || f.read(t, "etc/group") != groupFix {
		t.Fatal("a refused action changed state")
	}
	if got := f.env.Services.(*fakeServices).calls; len(got) != 0 {
		t.Fatalf("services touched: %v", got)
	}
	// Allowed: a PCR transaction may set a scored password; unscored accounts and
	// non-destructive service ops are fine.
	f.ok(t, "user.set_password", map[string]any{"user": "sysadmin", "password": "pcr-pw"}, func(r *Request) { r.PCR = true; r.Deadman = NoDeadman })
	f.ok(t, "user.lock", map[string]any{"user": "bob"}, func(r *Request) { r.Deadman = NoDeadman })
	f.ok(t, "service.restart", map[string]any{"unit": "httpd"})
	f.ok(t, "service.start", map[string]any{"unit": "cups"})
	f.ok(t, "group.members", map[string]any{"group": "sudo", "add": []any{"bob"}}, func(r *Request) { r.Deadman = NoDeadman }) // adding is fine
}

func TestParamValidation(t *testing.T) {
	s := Spec{Name: "t", Params: []ParamSpec{
		{Name: "n", Type: Int, Required: true}, {Name: "m", Type: Mode}, {Name: "p", Type: Path},
		{Name: "e", Type: Enum, Enum: []string{"a", "b"}}, {Name: "l", Type: StringList, Max: 2},
		{Name: "pw", Type: String, Secret: true}, {Name: "d", Type: Bool, Default: true}}}
	p, err := s.Validate(map[string]any{"n": float64(3), "m": "0640", "p": "/x/y", "e": "a", "l": []any{"q"}, "pw": "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := p.Int("n"); n != 3 {
		t.Fatal("int")
	}
	if m, _ := p.FileMode("m"); m != 0o640 {
		t.Fatalf("mode %v", m)
	}
	if !p.Bool("d") {
		t.Fatal("default")
	}
	if strings.Contains(p.Redacted(), "hunter2") {
		t.Fatalf("redaction: %s", p.Redacted())
	}
	for name, raw := range map[string]map[string]any{
		"missing":     {},
		"fractional":  {"n": 1.5},
		"badmode":     {"n": 1, "m": "99"},
		"relpath":     {"n": 1, "p": "rel/path"},
		"nulpath":     {"n": 1, "p": "/a\x00b"},
		"badenum":     {"n": 1, "e": "z"},
		"listtoolong": {"n": 1, "l": []any{"a", "b", "c"}},
		"wrongtype":   {"n": "1"},
		"unknown":     {"n": 1, "zzz": 1},
	} {
		if _, err := s.Validate(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Core().Get("nope"); !errors.Is(err, ErrUnknown) {
		t.Fatal("unknown action")
	}
	if names := strings.Join(Core().Names(), " "); !strings.Contains(names, "file.quarantine") || !strings.Contains(names, "service.mask") || !strings.Contains(names, "ssh.authorized_keys") {
		t.Fatal(names)
	}
}

func TestTagRecordedAndLogged(t *testing.T) {
	f := newFixture(t)
	tl, err := OpenTagLog(filepath.Join(t.TempDir(), "tags.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	f.env.Tags = tl
	ctx := WithTag(t.Context(), Tag{Plan: "plan-9", Node: "n3"})
	if _, err := f.env.Execute(ctx, Request{Action: "file.write", Params: map[string]any{"path": "/etc/tagged", "content": "x"}}); err != nil {
		t.Fatal(err)
	}
	r, ok := tl.Lookup("path:/etc/tagged")
	if !ok || r.Tag.Plan != "plan-9" || r.Action != "file.write" {
		t.Fatalf("record: %+v %v", r, ok)
	}
	// reopen reads back the index
	re, err := OpenTagLog(tl.path)
	if err != nil {
		t.Fatal(err)
	}
	if r2, ok := re.Lookup("path:/etc/tagged"); !ok || r2.Tag.Node != "n3" {
		t.Fatalf("persisted: %+v", r2)
	}
}

// failUndo fails verification and its own rollback, so the executor must mark
// the outcome typed as RollbackFailed (the agent turns that into the signed
// result outcome `rollback_failed`).
type failUndo struct{}

func (failUndo) Spec() Spec                                       { return Spec{Name: "test.failundo", Risk: RiskService} }
func (failUndo) Locks(Params) []string                            { return nil }
func (failUndo) Touches(Params) []Touch                           { return nil }
func (failUndo) Plan(context.Context, *Env, Params) (Plan, error) { return Plan{}, nil }
func (failUndo) Capture(context.Context, *Env, Params) (Rollback, error) {
	return Rollback{Kind: "test.failundo", Data: map[string]string{}}, nil
}
func (failUndo) Apply(context.Context, *Env, Params) (Output, error) { return nil, nil }
func (failUndo) Verify(context.Context, *Env, Params) error {
	return errors.New("health probe failed")
}

func TestRollbackFailureIsTyped(t *testing.T) {
	f := newFixture(t)
	dm, err := deadman.Open(t.TempDir(), deadman.Options{Handlers: map[string]deadman.Handler{
		"test.failundo": func(context.Context, deadman.Entry) error { return errors.New("undo broken") },
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dm.Close() })
	f.env.Deadman = dm
	f.env.Registry = NewRegistry()
	f.env.Registry.Register(failUndo{})
	o, err := f.run(t, "test.failundo", nil, func(r *Request) { r.Deadman = time.Minute })
	if err == nil || !strings.Contains(err.Error(), "undo broken") {
		t.Fatalf("err=%v", err)
	}
	if !o.RollbackFailed {
		t.Fatalf("outcome did not carry the typed rollback failure: %+v", o)
	}
}
