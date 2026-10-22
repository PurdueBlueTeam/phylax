package actions

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

var fixedNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

const (
	passwdFix = "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"sysadmin:x:1000:1000:Sys Admin,,,:/home/sysadmin:/bin/bash\n" +
		"alice:x:1001:1001::/home/alice:/bin/bash\n" +
		"bob:x:1002:1002::/home/bob:/bin/bash\n"
	shadowFix = "root:$6$rootsalt$rootrootrootrootrootrootrootrootrootrootrootrootrootrootrootrootrootrootrootrootrootroot:19000:0:99999:7:::\n" +
		"daemon:*:19000:0:99999:7:::\n" +
		"sysadmin:$6$oldsalt$oldhasholdhasholdhash:19500:1:90:14:30:20000:\n" +
		"# a comment that must survive\n" +
		"alice:!$6$asalt$ahash:19001:5:60:7:::\n" +
		"bob:*:19002:0:99999:7:::\n"
	groupFix = "root:x:0:\n" +
		"sudo:x:27:sysadmin,alice\n" +
		"sysadmin:x:1000:\n" +
		"alice:x:1001:\n" +
		"bob:x:1002:\n"
	gshadowFix = "root:*::\n" +
		"sudo:*:sysadmin:sysadmin,alice\n" +
		"sysadmin:!::\n" +
		"alice:!::\n" +
		"bob:!::\n"
)

type fixture struct {
	root string
	env  *Env
	dm   *deadman.Manager
}

func (f *fixture) path(rel string) string { return filepath.Join(f.root, rel) }
func (f *fixture) read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(f.path(rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func (f *fixture) write(t *testing.T, rel, content string, mode os.FileMode) {
	t.Helper()
	p := f.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, mode)
}

// newFixture builds a temp "root" with account files and an Env wired to fakes.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{root: t.TempDir()}
	f.write(t, "etc/passwd", passwdFix, 0o644)
	f.write(t, "etc/shadow", shadowFix, 0o640)
	f.write(t, "etc/group", groupFix, 0o644)
	f.write(t, "etc/gshadow", gshadowFix, 0o640)
	env := &Env{Host: "testhost", Root: f.root, Registry: Core(), Locks: NewLocks(), Guard: AllowAll{},
		Accounts:      &FileAccounts{Root: f.root, Now: func() time.Time { return fixedNow }},
		Services:      newFakeServices(),
		QuarantineDir: filepath.Join(t.TempDir(), "quarantine"),
		Now:           func() time.Time { return fixedNow }}
	dm, err := deadman.Open(filepath.Join(t.TempDir(), "dm"), deadman.Options{
		Handlers: DeadmanHandlers(env), RetryInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dm.Close() })
	env.Deadman = dm
	f.env, f.dm = env, dm
	return f
}

func (f *fixture) run(t *testing.T, action string, params map[string]any, mut ...func(*Request)) (*Outcome, error) {
	t.Helper()
	r := Request{Action: action, Params: params, NodeID: "n1"}
	for _, m := range mut {
		m(&r)
	}
	return f.env.Execute(context.Background(), r)
}

// ok runs the action and fails the test on error.
func (f *fixture) ok(t *testing.T, action string, params map[string]any, mut ...func(*Request)) *Outcome {
	t.Helper()
	o, err := f.run(t, action, params, mut...)
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", action, err)
	}
	return o
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---- fake services ----

type fakeServices struct {
	mu    sync.Mutex
	units map[string]*UnitState
	calls []string
}

func newFakeServices() *fakeServices {
	return &fakeServices{units: map[string]*UnitState{
		"sshd.service":  {Exists: true, Active: true, Enabled: "enabled"},
		"httpd.service": {Exists: true, Active: true, Enabled: "enabled"},
		"cups.service":  {Exists: true, Active: false, Enabled: "disabled"},
	}}
}
func (f *fakeServices) get(u string) (*UnitState, error) {
	if !strings.Contains(u, ".") {
		u += ".service"
	}
	s, ok := f.units[u]
	if !ok {
		return &UnitState{}, nil
	}
	return s, nil
}
func (f *fakeServices) State(_ context.Context, u string) (UnitState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, _ := f.get(u)
	return *s, nil
}
func (f *fakeServices) mut(op, u string, fn func(s *UnitState)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op+" "+u)
	s, _ := f.get(u)
	fn(s)
	return nil
}
func (f *fakeServices) Start(_ context.Context, u string) error {
	return f.mut("start", u, func(s *UnitState) { s.Active = true })
}
func (f *fakeServices) Stop(_ context.Context, u string) error {
	return f.mut("stop", u, func(s *UnitState) { s.Active = false })
}
func (f *fakeServices) Restart(_ context.Context, u string) error {
	return f.mut("restart", u, func(s *UnitState) { s.Active = true })
}
func (f *fakeServices) Enable(_ context.Context, u string) error {
	return f.mut("enable", u, func(s *UnitState) { s.Enabled = "enabled" })
}
func (f *fakeServices) Disable(_ context.Context, u string) error {
	return f.mut("disable", u, func(s *UnitState) { s.Enabled = "disabled" })
}
func (f *fakeServices) Mask(_ context.Context, u string) error {
	return f.mut("mask", u, func(s *UnitState) { s.Enabled = "masked"; s.Active = false })
}
func (f *fakeServices) Unmask(_ context.Context, u string) error {
	return f.mut("unmask", u, func(s *UnitState) { s.Enabled = "disabled" })
}
