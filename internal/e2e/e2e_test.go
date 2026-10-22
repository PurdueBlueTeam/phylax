// Package e2e wires a real controller to real in-process agents and runs
// signed plans end to end. Actions run against temp roots and fakes; nothing
// touches the host.
package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

const (
	passwdFix = "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"alice:x:1001:1001::/home/alice:/bin/bash\n" +
		"bob:x:1002:1002::/home/bob:/bin/bash\n"
	shadowFix = "root:$6$rootsalt$rootrootrootrootrootrootrootrootrootrootrootrootrootrootrootrootrootrootrootrootrootroot:19000:0:99999:7:::\n" +
		"daemon:*:19000:0:99999:7:::\n" +
		"alice:!$6$asalt$ahash:19001:5:60:7:::\n" +
		"bob:*:19002:0:99999:7:::\n"
	groupFix   = "root:x:0:\nsudo:x:27:alice\nalice:x:1001:\nbob:x:1002:\n"
	gshadowFix = "root:*::\nsudo:*:alice:alice\nalice:!::\nbob:!::\n"
)

// ---- fakes ----

type fakeSvc struct {
	mu    sync.Mutex
	units map[string]*actions.UnitState
	calls []string
}

func newFakeSvc() *fakeSvc {
	return &fakeSvc{units: map[string]*actions.UnitState{
		"httpd.service": {Exists: true, Active: true, Enabled: "enabled"}}}
}
func (f *fakeSvc) st(u string) *actions.UnitState {
	if !strings.Contains(u, ".") {
		u += ".service"
	}
	s, ok := f.units[u]
	if !ok {
		return &actions.UnitState{}
	}
	return s
}
func (f *fakeSvc) State(_ context.Context, u string) (actions.UnitState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.st(u), nil
}
func (f *fakeSvc) mut(op, u string, fn func(*actions.UnitState)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, op+" "+u)
	fn(f.st(u))
	return nil
}
func (f *fakeSvc) Start(_ context.Context, u string) error {
	return f.mut("start", u, func(s *actions.UnitState) { s.Active = true })
}
func (f *fakeSvc) Stop(_ context.Context, u string) error {
	return f.mut("stop", u, func(s *actions.UnitState) { s.Active = false })
}
func (f *fakeSvc) Restart(_ context.Context, u string) error {
	return f.mut("restart", u, func(s *actions.UnitState) { s.Active = true })
}
func (f *fakeSvc) Enable(_ context.Context, u string) error {
	return f.mut("enable", u, func(s *actions.UnitState) { s.Enabled = "enabled" })
}
func (f *fakeSvc) Disable(_ context.Context, u string) error {
	return f.mut("disable", u, func(s *actions.UnitState) { s.Enabled = "disabled" })
}
func (f *fakeSvc) Mask(_ context.Context, u string) error {
	return f.mut("mask", u, func(s *actions.UnitState) { s.Enabled = "masked"; s.Active = false })
}
func (f *fakeSvc) Unmask(_ context.Context, u string) error {
	return f.mut("unmask", u, func(s *actions.UnitState) { s.Enabled = "disabled" })
}
func (f *fakeSvc) called(c string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.calls {
		if x == c {
			return true
		}
	}
	return false
}

// driftAction is file.write whose post-condition holds when the action
// applies but no longer when the controller re-verifies: drift between apply
// and verify.
type driftAction struct {
	actions.Action
	calls *atomic.Int32
}

func (d driftAction) Spec() actions.Spec {
	s := d.Action.Spec()
	s.Name = "test.drift"
	return s
}
func (d driftAction) Verify(ctx context.Context, env *actions.Env, p actions.Params) error {
	if d.calls.Add(1) > 1 {
		return os.ErrInvalid
	}
	return d.Action.Verify(ctx, env, p)
}

func newRegistry() *actions.Registry {
	r := actions.Core()
	inner, err := r.Get("file.write")
	if err != nil {
		panic(err)
	}
	r.Register(driftAction{Action: inner, calls: new(atomic.Int32)})
	return r
}

// ---- harness ----

type testHost struct {
	name   string
	root   string
	svc    *fakeSvc
	layout agent.Layout
	cancel context.CancelFunc
	done   chan error
}

func (h *testHost) path(rel string) string { return filepath.Join(h.root, rel) }
func (h *testHost) read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(h.path(rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func (h *testHost) exists(rel string) bool { _, err := os.Stat(h.path(rel)); return err == nil }

// accounts is the exact bytes of the four account files.
func (h *testHost) accounts(t *testing.T) string {
	var b strings.Builder
	for _, f := range []string{"passwd", "shadow", "group", "gshadow"} {
		b.WriteString(h.read(t, "etc/"+f))
	}
	return b.String()
}

type harness struct {
	t     *testing.T
	c     *controller.Controller
	addr  string
	hosts map[string]*testHost

	mu     sync.Mutex
	steps  []*link.Step
	events []controller.StepEvent
	drop   func(controller.StepEvent) bool
}

func (h *harness) setDrop(f func(controller.StepEvent) bool) {
	h.mu.Lock()
	h.drop = f
	h.mu.Unlock()
}

func (h *harness) eventsFor(planID, phase string) []controller.StepEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []controller.StepEvent
	for _, e := range h.events {
		if e.Plan == planID && (phase == "" || e.Phase == phase) {
			out = append(out, e)
		}
	}
	return out
}

func (h *harness) firstStep(planID, node, phase string) *link.Step {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range h.steps {
		if s.Plan == planID && s.Node == node && s.Phase == phase {
			cp := *s
			return &cp
		}
	}
	return nil
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func eventually(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	end := time.Now().Add(d)
	for !cond() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func testManifest() *manifest.Manifest {
	return &manifest.Manifest{
		Accounts: map[string]manifest.Account{
			"alice": {Scope: "local", Hosts: []string{"h1"}, Scored: manifest.ScoredYes, Rotation: "pcr_transaction"},
			"bob":   {Scope: "local", Hosts: []string{"h1"}, Scored: manifest.ScoredNo, Rotation: "free"},
		},
		Services: map[string]manifest.Service{
			"web": {Host: "h2", Kind: "http", Scored: true, Process: &manifest.Process{Unit: "httpd.service"}},
		},
	}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, hosts: map[string]*testHost{}}
	m := testManifest()
	cfg := controller.Config{AgentListen: "127.0.0.1:0", DataDir: filepath.Join(t.TempDir(), "data"),
		SilenceThreshold: controller.Duration(time.Minute)}
	c, err := controller.New(context.Background(), cfg, controller.Options{
		Logger:      quiet(),
		Registry:    newRegistry(),
		StepTimeout: 4 * time.Second,
		// The controller lints only h1: h2's scored service is left to the
		// agent's own guard, which must refuse by itself.
		Guard: func(host string) actions.ScoringGuard {
			if host == "h1" {
				return actions.GuardFromManifest(m, host)
			}
			return actions.AllowAll{}
		},
		OnStepSent: func(_ string, s *link.Step) {
			h.mu.Lock()
			h.steps = append(h.steps, s)
			h.mu.Unlock()
		},
		OnStepResult: func(e controller.StepEvent) bool {
			h.mu.Lock()
			h.events = append(h.events, e)
			f := h.drop
			h.mu.Unlock()
			return f != nil && f(e)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.c = c
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Serve(ctx, ln) }()
	t.Cleanup(func() {
		for _, th := range h.hosts {
			th.cancel()
			<-th.done
		}
		cancel()
		<-done
		c.Close()
	})
	return h
}

func (h *harness) addHost(name string) *testHost {
	t := h.t
	t.Helper()
	th := &testHost{name: name, root: t.TempDir(), svc: newFakeSvc(), layout: agent.Layout{Root: filepath.Join(t.TempDir(), "state")}}
	for f, c := range map[string]string{"passwd": passwdFix, "shadow": shadowFix, "group": groupFix, "gshadow": gshadowFix} {
		if err := os.MkdirAll(th.path("etc"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(th.path("etc/"+f), []byte(c), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	tok, err := h.c.MintToken(name, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := th.layout.SaveBundle(&agent.Bundle{Controllers: []string{h.addr}, ControllerPin: h.c.Pin().String(),
		Host: name, Token: tok, PlanKey: hex.EncodeToString(h.c.PlanPublicKey())}); err != nil {
		t.Fatal(err)
	}
	env := &actions.Env{Host: name, Root: th.root, Registry: newRegistry(), Locks: actions.NewLocks(),
		Guard:         actions.GuardFromManifest(testManifest(), name),
		Accounts:      &actions.FileAccounts{Root: th.root},
		Services:      th.svc,
		QuarantineDir: filepath.Join(t.TempDir(), "quarantine")}
	a, err := agent.New(agent.Config{Layout: th.layout, Logger: quiet(), Exec: &agent.ExecConfig{Env: env, FreshCheck: true},
		HeartbeatInterval: 100 * time.Millisecond, DialTimeout: 3 * time.Second,
		Backoff:    link.Backoff{Min: 20 * time.Millisecond, Max: 100 * time.Millisecond},
		Supervisor: agent.SupervisorOptions{Backoff: link.Backoff{Min: time.Millisecond, Max: 10 * time.Millisecond}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	th.cancel, th.done = cancel, make(chan error, 1)
	go func() { th.done <- a.Run(ctx) }()
	h.hosts[name] = th
	eventually(t, name+" to connect", 10*time.Second, func() bool {
		st, ok := h.c.AgentStatus(name)
		return ok && st.Connected
	})
	return th
}

func (h *harness) mustApproveAndRun(planID string, own ...string) controller.PlanStatus {
	t := h.t
	t.Helper()
	ctx := context.Background()
	dr, err := h.c.DryRun(ctx, planID)
	if err != nil {
		t.Fatal(err)
	}
	if !dr.Approvable {
		t.Fatalf("dry run not approvable: %+v", dr)
	}
	if err := h.c.ApprovePlan(ctx, planID, "alice-operator"); err != nil {
		t.Fatal(err)
	}
	for _, n := range own {
		if err := h.c.ApproveNode(ctx, planID, n, "alice-operator", "reviewed"); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.c.Apply(ctx, planID); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	st, err := h.c.Wait(wctx, planID)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func (th *testHost) deadmanStates(t *testing.T, planID string) map[string]deadman.State {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(th.layout.DeadmanDir(), "*.json"))
	out := map[string]deadman.State{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var e deadman.Entry
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(e.NodeID, planID+":") {
			out[strings.TrimPrefix(e.NodeID, planID+":")] = e.State
		}
	}
	return out
}

func (h *harness) agentEvents(host, kind string) []string {
	evs, err := h.c.Store().Events(context.Background(), store.Query{Agent: host, Kind: kind})
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, e := range evs {
		b, _ := json.Marshal(e.Fields)
		out = append(out, string(b))
	}
	return out
}

// ---- the scenarios ----

func TestEndToEnd(t *testing.T) {
	h := newHarness(t)
	h1, h2 := h.addHost("h1"), h.addHost("h2")
	ctx := context.Background()

	t.Run("dryrun_approve_apply_verify_confirm", func(t *testing.T) {
		p := plan.Plan{ID: "p1", Name: "rotate, write, restart", Nodes: []plan.Node{
			{ID: "pw", Action: "user.set_password", Target: "h1", Risk: plan.RiskLockout, DeadmanSec: 60,
				Params: map[string]any{"user": "bob", "password": "S3cret-new-1"}},
			{ID: "motd", Action: "file.write", Target: "h2", Risk: plan.RiskService,
				Params: map[string]any{"path": "/etc/motd", "content": "managed by phylax\n"}},
			{ID: "restart", Action: "service.state", Target: "h2", Risk: plan.RiskService, Needs: []string{"motd"},
				Params: map[string]any{"unit": "httpd.service", "state": "restarted"}},
		}}
		if err := h.c.CreatePlan(ctx, p, "tester"); err != nil {
			t.Fatal(err)
		}
		if err := h.c.CreatePlan(ctx, p, "tester"); err == nil {
			t.Fatal("duplicate plan id accepted")
		}
		if err := h.c.ApprovePlan(ctx, "p1", "x"); err == nil {
			t.Fatal("approved a plan with no dry run")
		}
		before := h1.accounts(t)
		dr, err := h.c.DryRun(ctx, "p1")
		if err != nil {
			t.Fatal(err)
		}
		if !dr.Approvable || dr.Counts["will_change"] != 3 {
			t.Fatalf("dry run: %+v", dr)
		}
		if h1.accounts(t) != before || h2.exists("etc/motd") || h2.svc.called("restart httpd.service") {
			t.Fatal("dry run changed state")
		}
		for _, n := range dr.Nodes {
			if n.NodeID == "pw" && !n.NeedsOwnOK {
				t.Fatal("lockout node must need its own approval")
			}
			if strings.Contains(n.Diff, "S3cret-new-1") {
				t.Fatalf("diff leaks the password: %q", n.Diff)
			}
		}
		if err := h.c.ApprovePlan(ctx, "p1", "operator"); err != nil {
			t.Fatal(err)
		}
		if err := h.c.Apply(ctx, "p1"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond)
		if st, _ := h.c.PlanStatus("p1"); st.Nodes["pw"].State != plan.StatePending {
			t.Fatalf("pw ran without its own approval: %v", st.Nodes["pw"].State)
		}
		if err := h.c.ApproveNode(ctx, "p1", "pw", "operator", "ok"); err != nil {
			t.Fatal(err)
		}
		wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		st, err := h.c.Wait(wctx, "p1")
		if err != nil {
			t.Fatal(err)
		}
		if st.State != controller.PlanSucceeded {
			t.Fatalf("plan state %s: %+v", st.State, st.Nodes)
		}
		for id, n := range st.Nodes {
			if n.State != plan.StateVerified {
				t.Errorf("node %s: %s (%s)", id, n.State, n.Reason)
			}
		}
		be := &actions.FileAccounts{Root: h1.root}
		if ok, _ := be.PasswordIs(ctx, "bob", "S3cret-new-1"); !ok {
			t.Fatal("password not rotated")
		}
		if h2.read(t, "etc/motd") != "managed by phylax\n" || !h2.svc.called("restart httpd.service") {
			t.Fatal("file not written or service not restarted")
		}
		eventually(t, "dead-man entry confirmed", 5*time.Second, func() bool {
			return h1.deadmanStates(t, "p1")["pw"] == deadman.StateConfirmed
		})
		// Persisted: plan, nodes and signed results.
		row, err := h.c.Store().Plan(ctx, "p1")
		if err != nil || row.State != controller.PlanSucceeded {
			t.Fatalf("stored plan: %+v %v", row, err)
		}
		steps, _ := h.c.Store().PlanSteps(ctx, "p1")
		if len(steps) != 3 {
			t.Fatalf("stored steps: %d", len(steps))
		}
		for _, s := range steps {
			if s.State != "verified" || !strings.Contains(s.Result, `"signed":true`) || strings.Contains(s.Result, "S3cret") {
				t.Errorf("stored step %s: %s %s", s.Step, s.State, s.Result)
			}
		}
	})

	t.Run("failed_verify_rolls_the_plan_back_in_reverse_order", func(t *testing.T) {
		beforeH1, beforeH2 := h1.accounts(t), h2.accounts(t)
		motdBefore := h2.read(t, "etc/motd")
		p := plan.Plan{ID: "p2", OnFailure: plan.RollbackPlan, Nodes: []plan.Node{
			{ID: "a_pw", Action: "user.set_password", Target: "h1", Risk: plan.RiskLockout,
				Params: map[string]any{"user": "bob", "password": "Another-pass-2"}},
			{ID: "b_file", Action: "file.write", Target: "h2", Risk: plan.RiskService, Needs: []string{"a_pw"},
				Params: map[string]any{"path": "/etc/motd", "content": "second version\n"}},
			{ID: "c_drift", Action: "test.drift", Target: "h2", Risk: plan.RiskService, Needs: []string{"b_file"},
				Params: map[string]any{"path": "/etc/drifted", "content": "x\n"}},
		}}
		if err := h.c.CreatePlan(ctx, p, "tester"); err != nil {
			t.Fatal(err)
		}
		st := h.mustApproveAndRun("p2", "a_pw")
		if st.State != controller.PlanRolledBack {
			t.Fatalf("plan state %s: %+v", st.State, st.Nodes)
		}
		if st.Nodes["c_drift"].State != plan.StateRolledBack || !strings.Contains(st.Nodes["c_drift"].Reason, "verify") {
			t.Fatalf("drift node: %+v", st.Nodes["c_drift"])
		}
		var order []string
		for _, e := range h.eventsFor("p2", plan.PhaseRollback) {
			if e.Outcome != plan.OutcomeRolledBack {
				t.Fatalf("rollback event: %+v", e)
			}
			order = append(order, e.Node)
		}
		if strings.Join(order, ",") != "c_drift,b_file,a_pw" {
			t.Fatalf("rollback order %v", order)
		}
		if h1.accounts(t) != beforeH1 || h2.accounts(t) != beforeH2 {
			t.Fatal("account files not restored byte for byte")
		}
		if h2.read(t, "etc/motd") != motdBefore || h2.exists("etc/drifted") {
			t.Fatal("files not restored")
		}
		if ok, _ := (&actions.FileAccounts{Root: h1.root}).PasswordIs(ctx, "bob", "Another-pass-2"); ok {
			t.Fatal("rotated password survived the rollback")
		}
	})

	t.Run("tampered_and_replayed_steps_are_refused", func(t *testing.T) {
		step := h.firstStep("p1", "motd", plan.PhaseApply)
		if step == nil {
			t.Fatal("no captured step")
		}
		refused := func() int { return len(h.agentEvents("h2", "agent.step_refused")) }
		base := refused()

		// Replay: exactly what the controller sent before.
		if err := h.c.SendRaw(ctx, "h2", step); err != nil {
			t.Fatal(err)
		}
		eventually(t, "replay refusal", 5*time.Second, func() bool { return refused() > base })
		if got := h.agentEvents("h2", "agent.step_refused"); !strings.Contains(got[len(got)-1], "sequence") {
			t.Fatalf("replay refused for the wrong reason: %v", got[len(got)-1])
		}

		// Tamper: same signature, different file. Bump the sequence too so
		// only the signature can save the agent.
		inner, err := plan.DecodeStep(step.Params)
		if err != nil {
			t.Fatal(err)
		}
		inner.Params = json.RawMessage(`{"path":"/etc/evil","content":"pwned\n"}`)
		inner.Seq += 1000
		w, err := agent.StepToWire(inner)
		if err != nil {
			t.Fatal(err)
		}
		base = refused()
		if err := h.c.SendRaw(ctx, "h2", w); err != nil {
			t.Fatal(err)
		}
		eventually(t, "tamper refusal", 5*time.Second, func() bool { return refused() > base })
		if got := h.agentEvents("h2", "agent.step_refused"); !strings.Contains(got[len(got)-1], "bad signature") {
			t.Fatalf("tamper refused for the wrong reason: %v", got[len(got)-1])
		}

		// A step signed by some other key, otherwise perfectly formed.
		_, rogue, _ := ed25519.GenerateKey(rand.Reader)
		rp := plan.Plan{ID: "rogue", Nodes: []plan.Node{{ID: "n", Action: "file.write", Target: "h2", Risk: plan.RiskService,
			Params: map[string]any{"path": "/etc/evil", "content": "pwned\n"}}}}
		run, err := plan.NewRun(&rp, plan.MapCatalog{"file.write": {Name: "file.write", Risk: plan.RiskService}})
		if err != nil {
			t.Fatal(err)
		}
		run.ApprovePlan("mallory", time.Now())
		sg := &plan.Signer{Key: rogue, Epoch: 1, Seqs: &plan.MemSeq{}}
		rs, err := sg.Issue(&rp, run, "n", plan.IssueOpts{Phase: plan.PhaseApply})
		if err != nil {
			t.Fatal(err)
		}
		w, _ = agent.StepToWire(rs)
		base = refused()
		if err := h.c.SendRaw(ctx, "h2", w); err != nil {
			t.Fatal(err)
		}
		eventually(t, "rogue refusal", 5*time.Second, func() bool { return refused() > base })
		time.Sleep(200 * time.Millisecond)
		if h2.exists("etc/evil") {
			t.Fatal("a refused step executed")
		}
	})

	t.Run("scoring_guard_refuses_at_dry_run", func(t *testing.T) {
		// Controller-side lint: lock a scored account.
		p := plan.Plan{ID: "p4", Nodes: []plan.Node{
			{ID: "lock_alice", Action: "user.lock", Target: "h1", Risk: plan.RiskLockout, Params: map[string]any{"user": "alice"}},
			{ID: "ok", Action: "file.write", Target: "h1", Risk: plan.RiskService,
				Params: map[string]any{"path": "/etc/ok", "content": "fine\n"}},
		}}
		if err := h.c.CreatePlan(ctx, p, "tester"); err != nil {
			t.Fatal(err)
		}
		dr, err := h.c.DryRun(ctx, "p4")
		if err != nil {
			t.Fatal(err)
		}
		if dr.Approvable || dr.Counts["rejected"] != 1 {
			t.Fatalf("dry run: %+v", dr)
		}
		for _, n := range dr.Nodes {
			if n.NodeID == "lock_alice" && (n.Status != "rejected" || !strings.Contains(n.Reason, "scored account")) {
				t.Fatalf("lock node: %+v", n)
			}
		}
		if err := h.c.ApprovePlan(ctx, "p4", "operator"); err == nil {
			t.Fatal("approved a rejected plan")
		}
		if err := h.c.Apply(ctx, "p4"); err == nil {
			t.Fatal("applied an unapproved plan")
		}
		if h1.exists("etc/ok") || strings.Contains(h1.read(t, "etc/shadow"), "alice:!!") {
			t.Fatal("something ran")
		}

		// The agent enforces its own guard even when the controller's lint
		// lets the node through: stopping the scored web service on h2.
		p = plan.Plan{ID: "p4b", Nodes: []plan.Node{
			{ID: "stop_web", Action: "service.state", Target: "h2", Risk: plan.RiskService,
				Params: map[string]any{"unit": "httpd.service", "state": "stopped"}}}}
		if err := h.c.CreatePlan(ctx, p, "tester"); err != nil {
			t.Fatal(err)
		}
		dr, err = h.c.DryRun(ctx, "p4b")
		if err != nil {
			t.Fatal(err)
		}
		if dr.Approvable || dr.Nodes[0].Status != "rejected" || !strings.Contains(dr.Nodes[0].Reason, "scoring guard") {
			t.Fatalf("agent guard: %+v", dr)
		}
	})

	t.Run("link_drop_mid_plan_deadman_rolls_back_unconfirmed_lockout", func(t *testing.T) {
		before := h1.accounts(t)
		p := plan.Plan{ID: "p5", Nodes: []plan.Node{
			{ID: "pw", Action: "user.set_password", Target: "h1", Risk: plan.RiskLockout, DeadmanSec: 2,
				Params: map[string]any{"user": "bob", "password": "Lost-link-3"}}}}
		if err := h.c.CreatePlan(ctx, p, "tester"); err != nil {
			t.Fatal(err)
		}
		// Lose the "applied" result and the link; the controller then never
		// verifies or confirms.
		h.setDrop(func(e controller.StepEvent) bool {
			return e.Plan == "p5" && e.Phase == plan.PhaseApply && e.Outcome == plan.OutcomeApplied
		})
		defer h.setDrop(nil)
		st := h.mustApproveAndRun("p5", "pw")
		if st.State != controller.PlanFailed || st.Nodes["pw"].State != plan.StateFailed {
			t.Fatalf("plan: %s %+v", st.State, st.Nodes)
		}
		for _, e := range h.eventsFor("p5", plan.PhaseVerify) {
			t.Fatalf("verify was sent after the link dropped: %+v", e)
		}
		eventually(t, "dead-man rollback", 10*time.Second, func() bool {
			return h1.accounts(t) == before && h1.deadmanStates(t, "p5")["pw"] == deadman.StateRolledBack
		})
		eventually(t, "agent reports the rollback", 10*time.Second, func() bool {
			return len(h.agentEvents("h1", "agent.deadman_fired")) > 0
		})
		eventually(t, "agent reconnects", 10*time.Second, func() bool {
			s, _ := h.c.AgentStatus("h1")
			return s.Connected
		})
	})

	t.Run("safe_mode_refuses_apply_but_not_check", func(t *testing.T) {
		if err := h.c.SendRaw(ctx, "h2", &link.Control{Kind: "safe_mode", On: true}); err != nil {
			t.Fatal(err)
		}
		eventually(t, "safe mode on", 5*time.Second, func() bool { s, _ := h.c.AgentStatus("h2"); return s.SafeMode })
		p := plan.Plan{ID: "p6", Nodes: []plan.Node{
			{ID: "w", Action: "file.write", Target: "h2", Risk: plan.RiskService,
				Params: map[string]any{"path": "/etc/safe", "content": "x\n"}}}}
		if err := h.c.CreatePlan(ctx, p, "tester"); err != nil {
			t.Fatal(err)
		}
		st := h.mustApproveAndRun("p6")
		if st.State != controller.PlanFailed || !strings.Contains(st.Nodes["w"].Reason, "safe mode") || h2.exists("etc/safe") {
			t.Fatalf("safe mode: %s %+v", st.State, st.Nodes)
		}
		if err := h.c.SendRaw(ctx, "h2", &link.Control{Kind: "safe_mode", On: false}); err != nil {
			t.Fatal(err)
		}
		eventually(t, "safe mode off", 5*time.Second, func() bool { s, _ := h.c.AgentStatus("h2"); return !s.SafeMode })
	})
}
