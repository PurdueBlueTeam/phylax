package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

type failUndoAction struct{}

func (failUndoAction) Spec() actions.Spec {
	return actions.Spec{Name: "test.failundo", Risk: actions.RiskService}
}
func (failUndoAction) Locks(actions.Params) []string          { return nil }
func (failUndoAction) Touches(actions.Params) []actions.Touch { return nil }
func (failUndoAction) Plan(context.Context, *actions.Env, actions.Params) (actions.Plan, error) {
	return actions.Plan{}, nil
}
func (failUndoAction) Capture(context.Context, *actions.Env, actions.Params) (actions.Rollback, error) {
	return actions.Rollback{Kind: "test.failundo", Data: map[string]string{}}, nil
}
func (failUndoAction) Apply(context.Context, *actions.Env, actions.Params) (actions.Output, error) {
	return nil, nil
}
func (failUndoAction) Verify(context.Context, *actions.Env, actions.Params) error {
	return errors.New("health probe failed")
}

// A failed apply whose own rollback fails is reported with the typed
// rollback_failed status, not just a failed status with an error string.
func TestAgentReportsTypedRollbackFailure(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reg := actions.NewRegistry()
	reg.Register(failUndoAction{})
	env := actions.NewEnv("h", t.TempDir())
	env.Registry = reg
	dm, err := deadman.Open(t.TempDir(), deadman.Options{Handlers: map[string]deadman.Handler{
		"test.failundo": func(context.Context, deadman.Entry) error { return errors.New("undo broken") },
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dm.Close() })
	env.Deadman = dm
	rl, err := openResultLog(filepath.Join(t.TempDir(), "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := link.GenerateIdentity("h")
	if err != nil {
		t.Fatal(err)
	}
	x := &execState{env: env, sem: make(chan struct{}, 1), running: map[resultKey]bool{}, log: rl,
		ver: &plan.Verifier{Key: priv.Public().(ed25519.PublicKey), HostID: "h",
			Store: plan.FileSeqStore{Path: filepath.Join(t.TempDir(), "seq.json")}}}
	a := &Agent{exec: x, id: id, log: quietLog(), runCtx: context.Background()}
	a.sink = func(event.Event) error { return nil }

	p := &plan.Plan{ID: "failundo", Nodes: []plan.Node{
		{ID: "n1", Action: "test.failundo", Target: "h", Risk: plan.RiskService, DeadmanSec: 60},
	}}
	run, err := plan.NewRun(p, plan.MapCatalog{"test.failundo": {Name: "test.failundo", Risk: plan.RiskService}})
	if err != nil {
		t.Fatal(err)
	}
	run.ApprovePlan("test", time.Now())
	sg := &plan.Signer{Key: priv, Epoch: 1, Seqs: &plan.MemSeq{}, Now: time.Now}
	st, err := sg.Issue(p, run, "n1", plan.IssueOpts{Phase: plan.PhaseApply})
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan *link.StepResult, 1)
	reply := func(_ context.Context, _ link.Priority, m link.Message) error {
		if r, ok := m.(*link.StepResult); ok {
			results <- r
		}
		return nil
	}
	if err := a.handleStep(context.Background(), plan.StepToWire(st), reply); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-results:
		if r.Status != plan.OutcomeRollbackFailed {
			t.Fatalf("status %q, want %q (%s)", r.Status, plan.OutcomeRollbackFailed, r.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no step result")
	}
	a.execWG.Wait()
}
