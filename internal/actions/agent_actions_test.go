package actions

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testPin       = "abababababababababababababababababababababababababababababababab"
	testPlanKey   = "0000000000000000000000000000000000000000000000000000000000000000"
	testBootstrap = `{
  "controllers": ["10.0.0.1:443"],
  "controller_pin": "` + testPin + `",
  "host": "h1",
  "plan_key": "` + testPlanKey + `"
}
`
)

// agentEnv gives the fixture an agent state directory (Env.AgentRoot).
func agentEnv(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.env.AgentRoot = t.TempDir()
	return f
}

func (f *fixture) bootstrapPath() string {
	return filepath.Join(f.env.AgentRoot, "bootstrap.json")
}

func TestSetControllerAction(t *testing.T) {
	f := agentEnv(t)
	if err := os.WriteFile(f.bootstrapPath(), []byte(testBootstrap), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(f.bootstrapPath())
	if err != nil {
		t.Fatal(err)
	}
	o, err := f.run(t, "agent.set_controller", map[string]any{"controllers": "10.0.0.2:443, 10.0.0.3:443"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(o.Plan.Diff, "10.0.0.1:443") || !strings.Contains(o.Plan.Diff, "10.0.0.3:443") {
		t.Fatalf("plan diff does not show the old and new lists: %q", o.Plan.Diff)
	}
	var got struct {
		Controllers []string `json:"controllers"`
		Host        string   `json:"host"`
	}
	raw, err := os.ReadFile(f.bootstrapPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Controllers, ",") != "10.0.0.2:443,10.0.0.3:443" {
		t.Fatalf("controllers %v", got.Controllers)
	}
	if got.Host != "h1" {
		t.Fatalf("rewrite dropped an unknown field: %s", raw)
	}
	// The lockout-class action arms the dead-man switch: firing it puts the
	// old file back byte for byte.
	if o.DeadmanID == "" {
		t.Fatal("lockout action did not arm the dead-man switch")
	}
	if _, err := f.dm.Fire(context.Background(), o.DeadmanID, "test"); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(f.bootstrapPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("rollback did not restore the old bootstrap:\n%s", after)
	}
	// A nonsense address is refused before anything is written.
	if _, err := f.run(t, "agent.set_controller", map[string]any{"controllers": "nonsense"}); err == nil {
		t.Fatal("Plan accepted a bad controller address")
	}
	if raw, _ := os.ReadFile(f.bootstrapPath()); string(raw) != string(before) {
		t.Fatal("a refused plan changed the bootstrap")
	}
}

func TestSafeModeAction(t *testing.T) {
	f := newFixture(t)
	marker := filepath.Join(t.TempDir(), "safe_mode")
	sm, err := NewSafeMode(marker)
	if err != nil {
		t.Fatal(err)
	}
	f.env.Safe = sm
	if _, err := f.run(t, "agent.safe_mode", map[string]any{"on": true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("safe-mode marker not written: %v", err)
	}
	if !sm.On() {
		t.Fatal("safe mode not on")
	}
	a, err := Core().Get("agent.safe_mode")
	if err != nil {
		t.Fatal(err)
	}
	off, err := a.Spec().Validate(map[string]any{"on": false})
	if err != nil {
		t.Fatal(err)
	}
	// Turning safe mode off stays a signed control from the operator UI: the
	// executor refuses every action while safe mode is on.
	if _, err := a.Plan(context.Background(), f.env, off); err == nil || !strings.Contains(err.Error(), "operator UI") {
		t.Fatalf("off accepted by Plan: %v", err)
	}
	if _, err := a.Apply(context.Background(), f.env, off); err == nil || !strings.Contains(err.Error(), "operator UI") {
		t.Fatalf("off accepted by Apply: %v", err)
	}
	if !sm.On() {
		t.Fatal("a refused off changed the marker")
	}
	on, err := a.Spec().Validate(map[string]any{"on": true})
	if err != nil {
		t.Fatal(err)
	}
	if pl, err := a.Plan(context.Background(), f.env, on); err != nil || !pl.Done {
		t.Fatalf("Plan when already on: %+v %v", pl, err)
	}
}

func TestAgentConfigAction(t *testing.T) {
	f := agentEnv(t)
	optPath := filepath.Join(f.env.AgentRoot, "options.json")
	if _, err := f.run(t, "agent.config", map[string]any{"memory_limit_mb": 128}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(optPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]int
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
	if got["memory_limit_mb"] != 128 {
		t.Fatalf("options.json %s", raw)
	}
	if fi, err := os.Stat(optPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("options.json mode: %v %v", fi.Mode(), err)
	}
	for _, bad := range []int{16, 4096} {
		if _, err := f.run(t, "agent.config", map[string]any{"memory_limit_mb": bad}); err == nil {
			t.Fatalf("accepted memory_limit_mb %d", bad)
		}
	}
	// The rollback removes a file the action created...
	g := agentEnv(t)
	gPath := filepath.Join(g.env.AgentRoot, "options.json")
	o, err := g.run(t, "agent.config", map[string]any{"memory_limit_mb": 64}, func(r *Request) { r.Deadman = DefaultDeadman })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.dm.Fire(context.Background(), o.DeadmanID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(gPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rollback kept a file that did not exist before: %v", err)
	}
	// ...and restores the previous content otherwise.
	if err := os.WriteFile(optPath, []byte("{\"memory_limit_mb\":64}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err = f.run(t, "agent.config", map[string]any{"memory_limit_mb": 256}, func(r *Request) { r.Deadman = DefaultDeadman })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.dm.Fire(context.Background(), o.DeadmanID, "test"); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(optPath); string(raw) != "{\"memory_limit_mb\":64}\n" {
		t.Fatalf("rollback did not restore the previous content: %s", raw)
	}
}

func TestAgentFamilyRegistered(t *testing.T) {
	for _, name := range []string{"agent.set_controller", "agent.safe_mode", "agent.config", "agent.replace_binary", "agent.rename"} {
		if _, err := Core().Get(name); err != nil {
			t.Error(err)
		}
	}
}
