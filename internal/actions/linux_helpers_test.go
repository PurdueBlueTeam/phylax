package actions

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner scripts host commands. Rules match on the joined argv prefix.
type fakeRunner struct {
	mu    sync.Mutex
	rules []fakeRule
	calls []Cmd
}

type fakeRule struct {
	prefix string
	res    CmdResult
	fn     func(c Cmd) CmdResult
}

func (r *fakeRunner) on(prefix string, res CmdResult) {
	r.rules = append(r.rules, fakeRule{prefix: prefix, res: res})
}
func (r *fakeRunner) onFn(prefix string, fn func(Cmd) CmdResult) {
	r.rules = append(r.rules, fakeRule{prefix: prefix, fn: fn})
}

func (r *fakeRunner) Run(_ context.Context, c Cmd) (CmdResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c)
	j := strings.Join(c.Argv, " ")
	for i := len(r.rules) - 1; i >= 0; i-- { // later rules win
		if strings.HasPrefix(j, r.rules[i].prefix) {
			if r.rules[i].fn != nil {
				return r.rules[i].fn(c), nil
			}
			return r.rules[i].res, nil
		}
	}
	return CmdResult{}, errors.New("fakeRunner: unscripted command: " + j)
}

func (r *fakeRunner) ran(prefix string) []Cmd {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Cmd
	for _, c := range r.calls {
		if strings.HasPrefix(strings.Join(c.Argv, " "), prefix) {
			out = append(out, c)
		}
	}
	return out
}

// reloadServices adds DaemonReload to the fake service manager.
type reloadServices struct {
	*fakeServices
	reloads int
}

func (r *reloadServices) DaemonReload(context.Context) error { r.reloads++; return nil }

func (f *fixture) linux(t *testing.T) *LinuxEnv {
	t.Helper()
	if f.env.Linux == nil {
		f.env.Linux = &LinuxEnv{}
	}
	return f.env.Linux
}

func (f *fixture) refused(t *testing.T, action string, params map[string]any) error {
	t.Helper()
	_, err := f.run(t, action, params)
	if err == nil {
		t.Fatalf("%s %v: expected a refusal", action, params)
	}
	return err
}

func (f *fixture) openWindow(t *testing.T) {
	t.Helper()
	f.linux(t).PatchWindow = func(context.Context) (*PatchWindow, error) {
		return &PatchWindow{ID: "w1", Tag: "patch-1", Proxy: "http://127.0.0.1:3128", Until: fixedNow.Add(15 * time.Minute)}, nil
	}
}

func writeTestFile(p string) error { return os.WriteFile(p, []byte("x"), 0o644) }

func sha1hex(s string) string { x := sha1.Sum([]byte(s)); return hex.EncodeToString(x[:]) }
