package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// startExpiryAgent starts an agent that executes signed steps against root and
// connects it to a fake controller (the harness of exec and control tests).
func startExpiryAgent(t *testing.T) (*fakeController, ed25519.PrivateKey, *runningAgent, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctl := newFakeController(t, "h", "tok", 0)
	l := Layout{Root: t.TempDir()}
	if err := l.SaveBundle(&Bundle{Controllers: []string{ctl.addr}, ControllerPin: ctl.id.Pin.String(), Host: "h", Token: "tok",
		PlanKey: hex.EncodeToString(pub)}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	r := startAgent(t, Config{Layout: l, HeartbeatInterval: 30 * time.Millisecond,
		Exec: &ExecConfig{Env: actions.NewEnv("h", root)}})
	eventually(t, 5*time.Second, "agent connected", func() bool { return ctl.send(&link.Ack{Seq: 0}) == nil })
	return ctl, priv, r, root
}

// issueExpiry signs an approved apply step; one signer per test keeps the
// per-host sequence increasing across re-applies.
func issueExpiry(t *testing.T, sg *plan.Signer, planID, node, action string, risk plan.Risk, params map[string]any, expiresSec int) *plan.Step {
	t.Helper()
	p := &plan.Plan{ID: planID, OnFailure: plan.StopDependents, Class: plan.ClassAuto, Nodes: []plan.Node{{
		ID: node, Action: action, Target: "h", Risk: risk, Params: params, ExpiresAfterSec: plan.MinExpiresAfterSec}}}
	cat := plan.MapCatalog{action: {Name: action, Risk: risk}}
	run, err := plan.NewRun(p, cat)
	if err != nil {
		t.Fatal(err)
	}
	// The plan validates the design's 60 s lower bound; shorten the issued
	// step so the test does not wait out a real expiry window.
	p.Nodes[0].ExpiresAfterSec = expiresSec
	now := time.Now()
	run.ApprovePlan("operator", now) // approves the node unless it needs its own record
	if run.State(node) == plan.StatePending {
		if err := run.ApproveNode(node, plan.Approval{By: "operator", At: now.Unix()}); err != nil {
			t.Fatal(err)
		}
	}
	s, err := sg.Issue(p, run, node, plan.IssueOpts{Phase: plan.PhaseApply})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func stepResultsFor(ctl *fakeController, node string) []link.StepResult {
	ctl.mu.Lock()
	defer ctl.mu.Unlock()
	var out []link.StepResult
	for _, r := range ctl.results {
		if r.Node == node {
			out = append(out, r)
		}
	}
	return out
}

func armedFor(t *testing.T, r *runningAgent, nodeKey string) []deadman.Entry {
	t.Helper()
	entries, err := r.a.dm.List()
	if err != nil {
		t.Fatal(err)
	}
	var out []deadman.Entry
	for _, e := range entries {
		if e.NodeID == nodeKey && e.State == deadman.StateArmed {
			out = append(out, e)
		}
	}
	return out
}

func TestExpiryRollsBackWithoutConfirm(t *testing.T) {
	ctl, priv, r, root := startExpiryAgent(t)
	target := filepath.Join(root, "srv", "x")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	sg := &plan.Signer{Key: priv, Epoch: 1, Seqs: &plan.MemSeq{}}
	step := issueExpiry(t, sg, "exp", "n", "file.write", plan.RiskService,
		map[string]any{"path": "/srv/x", "content": "new\n"}, 1)
	if err := ctl.send(plan.StepToWire(step)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "apply result", func() bool { return len(stepResultsFor(ctl, "n")) == 1 })
	if res := stepResultsFor(ctl, "n")[0]; res.Status != plan.OutcomeApplied {
		t.Fatalf("apply: %+v", res)
	}
	if b, _ := os.ReadFile(target); string(b) != "new\n" {
		t.Fatalf("apply did not write: %q", b)
	}

	// No deadman_confirm is sent: the expiry fires on its own and undoes it.
	eventually(t, 5*time.Second, "expiry rolled back the file", func() bool {
		b, _ := os.ReadFile(target)
		return string(b) == "old\n"
	})
	eventually(t, 5*time.Second, "expire result reported", func() bool {
		for _, f := range ctl.eventsOf("agent.step_result") {
			if f["phase"] == plan.PhaseExpire && f["plan"] == "exp" && f["node"] == "n" {
				return true
			}
		}
		return false
	})
	if left := armedFor(t, r, "exp:n"); len(left) != 0 {
		t.Fatalf("record still armed: %+v", left)
	}
}

func TestExpiryActionWithoutUndoFails(t *testing.T) {
	ctl, priv, _, root := startExpiryAgent(t)
	target := filepath.Join(root, "etc", "hosts")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sg := &plan.Signer{Key: priv, Epoch: 1, Seqs: &plan.MemSeq{}}
	// file.hash is read-only: it can never produce undo data.
	step := issueExpiry(t, sg, "exp2", "h", "file.hash", plan.RiskNone,
		map[string]any{"path": "/etc/hosts"}, 1)
	if err := ctl.send(plan.StepToWire(step)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "failed result", func() bool { return len(stepResultsFor(ctl, "h")) == 1 })
	res := stepResultsFor(ctl, "h")[0]
	if res.Status != plan.OutcomeFailed || !strings.Contains(res.Error, "has no undo") {
		t.Fatalf("read-only expiry: %+v", res)
	}
}

func TestExpiryExtendReplacesRecord(t *testing.T) {
	ctl, priv, r, root := startExpiryAgent(t)
	target := filepath.Join(root, "srv", "y")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sg := &plan.Signer{Key: priv, Epoch: 1, Seqs: &plan.MemSeq{}}
	send := func(content string, want int) {
		t.Helper()
		step := issueExpiry(t, sg, "ext", "n", "file.write", plan.RiskService,
			map[string]any{"path": "/srv/y", "content": content}, 60)
		if err := ctl.send(plan.StepToWire(step)); err != nil {
			t.Fatal(err)
		}
		eventually(t, 5*time.Second, "apply result", func() bool { return len(stepResultsFor(ctl, "n")) == want })
		if res := stepResultsFor(ctl, "n")[want-1]; res.Status != plan.OutcomeApplied {
			t.Fatalf("apply %d: %+v", want, res)
		}
	}

	send("one\n", 1)
	first := armedFor(t, r, "ext:n")
	if len(first) != 1 {
		t.Fatalf("armed after the first apply: %+v", first)
	}
	time.Sleep(300 * time.Millisecond)
	send("two\n", 2)
	got := armedFor(t, r, "ext:n")
	if len(got) != 1 || !got[0].Deadline.After(first[0].Deadline) {
		t.Fatalf("the second apply must replace the record: first %v, after %+v", first[0].Deadline, got)
	}
}
