package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func (h *harness) approveAndApply(planID string) {
	h.t.Helper()
	ctx := context.Background()
	dr, err := h.c.DryRun(ctx, planID)
	if err != nil || !dr.Approvable {
		h.t.Fatalf("dry run: %+v %v", dr, err)
	}
	if err := h.c.ApprovePlan(ctx, planID, "operator"); err != nil {
		h.t.Fatal(err)
	}
	if err := h.c.Apply(ctx, planID); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) waitPlan(planID string) controller.PlanStatus {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	st, err := h.c.Wait(ctx, planID)
	if err != nil {
		h.t.Fatal(err)
	}
	return st
}

func (h *harness) countSteps(planID, node, phase string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, s := range h.steps {
		if s.Plan == planID && s.Node == node && s.Phase == phase {
			n++
		}
	}
	return n
}

func (h *harness) assertUniqueSeqs() {
	h.t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	seen := map[[3]any]bool{}
	for _, s := range h.steps {
		k := [3]any{s.Host, s.Epoch, s.Seq}
		if seen[k] {
			h.t.Fatalf("step sequence reused: %v", k)
		}
		seen[k] = true
	}
}

func fileWrite(id, host, path string, dm int, needs ...string) plan.Node {
	return plan.Node{ID: id, Action: "file.write", Target: host, Risk: plan.RiskService, DeadmanSec: dm, Needs: needs,
		Params: map[string]any{"path": path, "content": id + "\n"}}
}

// Forged, replayed and tampered messages never take effect.
func TestControlsAndStepsAreAuthentic(t *testing.T) {
	h := newHarness(t)
	h2 := h.addHost("h2")
	ctx := context.Background()
	p := plan.Plan{ID: "c1", Nodes: []plan.Node{fileWrite("w", "h2", "/etc/c1", 120)}}
	if err := h.c.CreatePlan(ctx, p, "t"); err != nil {
		t.Fatal(err)
	}
	if st := h.mustApproveAndRun("c1"); st.State != controller.PlanSucceeded {
		t.Fatalf("plan: %s %+v", st.State, st.Nodes)
	}
	eventually(t, "entry confirmed", 5*time.Second, func() bool { return h2.deadmanStates(t, "c1")["w"] == deadman.StateConfirmed })

	refusals := func() string { return strings.Join(h.agentEvents("h2", "agent.control_refused"), "|") }
	// Replay of the genuine confirm.
	var confirm *link.Control
	h.mu.Lock()
	for _, c := range h.ctls {
		if c.Kind == "deadman_confirm" {
			confirm = c
		}
	}
	h.mu.Unlock()
	if confirm == nil {
		t.Fatal("no confirm captured")
	}
	if err := h.c.SendRaw(ctx, "h2", confirm); err != nil {
		t.Fatal(err)
	}
	eventually(t, "replay refused", 5*time.Second, func() bool { return strings.Contains(refusals(), "sequence") })

	// Forged: a safe_mode signed by another key.
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	fc, _ := (&plan.ControlSigner{Key: rogue, Epoch: 1, Seqs: &plan.MemSeq{}}).Issue("h2", "safe_mode", true, nil)
	h.c.SendRaw(ctx, "h2", plan.ControlToWire(fc))
	eventually(t, "forgery refused", 5*time.Second, func() bool { return strings.Contains(refusals(), "bad signature") })
	// Unsigned (as the old protocol sent it).
	h.c.SendRaw(ctx, "h2", &link.Control{V: 1, Host: "h2", Kind: "safe_mode", On: true, Epoch: 1, Seq: 1 << 40,
		NotBefore: time.Now().Unix(), NotAfter: time.Now().Add(time.Minute).Unix(), Sig: []byte("x")})
	time.Sleep(300 * time.Millisecond)
	if s, _ := h.c.AgentStatus("h2"); s.SafeMode {
		t.Fatal("a refused control switched safe mode on")
	}
	// Typed-field tampering: change a signed field of a genuine step on the wire.
	step := h.firstStep("c1", "w", plan.PhaseApply)
	step.Action = "file.delete"
	base := len(h.agentEvents("h2", "agent.step_refused"))
	h.c.SendRaw(ctx, "h2", step)
	eventually(t, "tampered field refused", 5*time.Second, func() bool { return len(h.agentEvents("h2", "agent.step_refused")) > base })
}

// A lost apply result (link drop) is recovered by asking the agent; the change
// is applied exactly once.
func TestLostApplyResultRecoveredByQuery(t *testing.T) {
	h := newHarness(t)
	h1 := h.addHost("h1")
	var dropped atomic.Bool
	h.setDrop(func(e controller.StepEvent) bool {
		return e.Plan == "q1" && e.Phase == plan.PhaseApply && e.Outcome == plan.OutcomeApplied && dropped.CompareAndSwap(false, true)
	})
	p := plan.Plan{ID: "q1", Nodes: []plan.Node{fileWrite("w", "h1", "/etc/q1", 120)}}
	if err := h.c.CreatePlan(context.Background(), p, "t"); err != nil {
		t.Fatal(err)
	}
	st := h.mustApproveAndRun("q1")
	if st.State != controller.PlanSucceeded || !dropped.Load() {
		t.Fatalf("plan %s dropped=%v %+v", st.State, dropped.Load(), st.Nodes)
	}
	if n := h.countSteps("q1", "w", plan.PhaseApply); n != 1 {
		t.Fatalf("apply sent %d times", n)
	}
	if h1.read(t, "etc/q1") != "w\n" {
		t.Fatal("file missing")
	}
	h.assertUniqueSeqs()
}

// The controller dies mid-plan. R1: the apply result of A is lost; B waits on A.
// R2: C is applied and its dead-man switch fires during the outage.
func TestControllerRestartResumes(t *testing.T) {
	h := newHarness(t)
	h1, h2 := h.addHost("h1"), h.addHost("h2")
	ctx := context.Background()
	r1 := plan.Plan{ID: "r1", Nodes: []plan.Node{fileWrite("a", "h2", "/etc/ra", 120), fileWrite("b", "h1", "/etc/rb", 0, "a")}}
	r2 := plan.Plan{ID: "r2", Nodes: []plan.Node{fileWrite("c", "h1", "/etc/rc", 3), fileWrite("d", "h2", "/etc/rd", 0, "c")}}
	for _, p := range []plan.Plan{r1, r2} {
		if err := h.c.CreatePlan(ctx, p, "t"); err != nil {
			t.Fatal(err)
		}
	}
	var hitA, hitC atomic.Bool
	h.setDrop(func(e controller.StepEvent) bool {
		switch {
		case e.Plan == "r1" && e.Node == "a" && e.Phase == plan.PhaseApply && e.Outcome == plan.OutcomeApplied:
			hitA.Store(true)
			return true
		case e.Plan == "r2" && e.Node == "c" && e.Phase == plan.PhaseVerify && e.Outcome == plan.OutcomeVerified:
			hitC.Store(true)
			return true
		}
		return false
	})
	for _, id := range []string{"r1", "r2"} {
		if dr, err := h.c.DryRun(ctx, id); err != nil || !dr.Approvable {
			t.Fatalf("dry run %s: %+v %v", id, dr, err)
		}
		if err := h.c.ApprovePlan(ctx, id, "operator"); err != nil {
			t.Fatal(err)
		}
	}
	// One at a time: a dropped result flaps its host's link.
	if err := h.c.Apply(ctx, "r2"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "crash point C", 20*time.Second, hitC.Load)
	if err := h.c.Apply(ctx, "r1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "crash point A", 20*time.Second, hitA.Load)
	h.stopController()
	// While the controller is away C's dead-man switch fires.
	eventually(t, "C rolled back by its dead-man", 15*time.Second, func() bool {
		return h1.deadmanStates(t, "r2")["c"] == deadman.StateRolledBack && !h1.exists("etc/rc")
	})
	h.setDrop(nil)
	h.startController()

	s1 := h.waitPlan("r1")
	if s1.State != controller.PlanSucceeded {
		t.Fatalf("r1: %s %+v", s1.State, s1.Nodes)
	}
	for id, n := range s1.Nodes {
		if n.State != plan.StateVerified {
			t.Errorf("r1 %s: %s %s", id, n.State, n.Reason)
		}
	}
	if h1.read(t, "etc/rb") != "b\n" || h2.read(t, "etc/ra") != "a\n" {
		t.Fatal("r1 files")
	}
	eventually(t, "A confirmed", 10*time.Second, func() bool { return h2.deadmanStates(t, "r1")["a"] == deadman.StateConfirmed })
	if n := h.countSteps("r1", "a", plan.PhaseApply); n != 1 {
		t.Fatalf("A applied %d times", n)
	}
	s2 := h.waitPlan("r2")
	if s2.State != controller.PlanFailed || s2.Nodes["c"].State != plan.StateRolledBack ||
		!strings.Contains(s2.Nodes["c"].Reason, "dead-man") || s2.Nodes["d"].State != plan.StateSkipped {
		t.Fatalf("r2: %s %+v", s2.State, s2.Nodes)
	}
	if h2.exists("etc/rd") || h1.exists("etc/rc") {
		t.Fatal("r2 left changes behind")
	}
	if n := h.countSteps("r2", "c", plan.PhaseApply); n != 1 {
		t.Fatalf("C applied %d times", n)
	}
	h.assertUniqueSeqs()
	row, err := h.c.Store().Plan(ctx, "r1")
	if err != nil || row.State != controller.PlanSucceeded {
		t.Fatalf("stored r1: %+v %v", row, err)
	}
}

// The apply result is lost together with the controller, and the agent has
// restarted too: it answers "lost" (armed dead-man entry: verify decides) or,
// when it never accepted the step, "unknown" (the apply is issued afresh).
func TestLostApplyAfterRestartAndAgentRestart(t *testing.T) {
	for _, mode := range []string{"lost", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			h1 := h.addHost("h1")
			id := "l_" + mode
			p := plan.Plan{ID: id, Nodes: []plan.Node{fileWrite("w", "h1", "/etc/"+id, 120)}}
			if err := h.c.CreatePlan(context.Background(), p, "t"); err != nil {
				t.Fatal(err)
			}
			var hit atomic.Bool
			h.setDrop(func(e controller.StepEvent) bool {
				if e.Plan == id && e.Phase == plan.PhaseApply && e.Outcome == plan.OutcomeApplied {
					hit.Store(true)
					return true
				}
				return false
			})
			h.approveAndApply(id)
			eventually(t, "crash point", 20*time.Second, func() bool { return hit.Load() })
			h.stopController()
			h1.stop()
			os.Remove(h1.layout.Results())
			if mode == "unknown" {
				var m plan.Mark
				b, err := os.ReadFile(h1.layout.PlanSeq())
				if err != nil || json.Unmarshal(b, &m) != nil {
					t.Fatal(err)
				}
				m.Seq--
				b, _ = json.Marshal(m)
				if err := os.WriteFile(h1.layout.PlanSeq(), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			h.setDrop(nil)
			h1.start(h)
			h.startController()
			st := h.waitPlan(id)
			if st.State != controller.PlanSucceeded {
				t.Fatalf("%s: %s %+v", mode, st.State, st.Nodes)
			}
			want := 1
			if mode == "unknown" {
				want = 2
			}
			if n := h.countSteps(id, "w", plan.PhaseApply); n != want {
				t.Fatalf("apply sent %d times, want %d", n, want)
			}
			if mode == "lost" {
				var recovered bool
				for _, ph := range st.Nodes["w"].Phases {
					recovered = recovered || (ph.Phase == plan.PhaseApply && !ph.Signed && strings.Contains(ph.Detail, "recovered"))
				}
				if !recovered {
					t.Fatalf("apply not recorded as recovered: %+v", st.Nodes["w"].Phases)
				}
			}
			h.assertUniqueSeqs()
		})
	}
}
