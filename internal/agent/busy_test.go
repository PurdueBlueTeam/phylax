package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

type slowAction struct {
	started chan struct{}
	delay   time.Duration
}

func (slowAction) Spec() actions.Spec                     { return actions.Spec{Name: "test.slow"} }
func (slowAction) Locks(actions.Params) []string          { return nil }
func (slowAction) Touches(actions.Params) []actions.Touch { return nil }
func (slowAction) Plan(context.Context, *actions.Env, actions.Params) (actions.Plan, error) {
	return actions.Plan{}, nil
}
func (slowAction) Capture(context.Context, *actions.Env, actions.Params) (actions.Rollback, error) {
	return actions.Rollback{}, nil
}
func (a slowAction) Apply(ctx context.Context, _ *actions.Env, _ actions.Params) (actions.Output, error) {
	select {
	case a.started <- struct{}{}:
	default:
	}
	select {
	case <-time.After(a.delay):
		return actions.Output{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (slowAction) Verify(context.Context, *actions.Env, actions.Params) error { return nil }

func TestAgentAnswersBusyOverCap(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reg := actions.NewRegistry()
	reg.Register(slowAction{started: make(chan struct{}, 2), delay: 500 * time.Millisecond})
	env := actions.NewEnv("h", t.TempDir())
	env.Registry = reg
	sm, err := actions.NewSafeMode("")
	if err != nil {
		t.Fatal(err)
	}
	env.Safe = sm
	rl, err := openResultLog(filepath.Join(t.TempDir(), "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := link.GenerateIdentity("h")
	if err != nil {
		t.Fatal(err)
	}
	x := &execState{env: env, sem: make(chan struct{}, 2), running: map[resultKey]bool{}, log: rl,
		ver: &plan.Verifier{Key: priv.Public().(ed25519.PublicKey), HostID: "h",
			Store: plan.FileSeqStore{Path: filepath.Join(t.TempDir(), "seq.json")}}}
	a := &Agent{exec: x, id: id, log: quietLog(), runCtx: context.Background()}
	a.sink = func(event.Event) error { return nil }

	p := &plan.Plan{ID: "busy", Nodes: []plan.Node{
		{ID: "n1", Action: "test.slow", Target: "h"},
		{ID: "n2", Action: "test.slow", Target: "h"},
		{ID: "n3", Action: "test.slow", Target: "h"},
	}}
	cat := plan.MapCatalog{"test.slow": {Name: "test.slow", Risk: plan.RiskNone}}
	run, err := plan.NewRun(p, cat)
	if err != nil {
		t.Fatal(err)
	}
	run.ApprovePlan("test", time.Now())
	sg := &plan.Signer{Key: priv, Epoch: 1, Seqs: &plan.MemSeq{}, Now: time.Now}
	results := make(chan *link.StepResult, 3)
	reply := func(_ context.Context, _ link.Priority, m link.Message) error {
		if r, ok := m.(*link.StepResult); ok {
			results <- r
		}
		return nil
	}
	var seqs []uint64
	for _, node := range []string{"n1", "n2", "n3"} {
		st, err := sg.Issue(p, run, node, plan.IssueOpts{Phase: plan.PhaseApply})
		if err != nil {
			t.Fatal(err)
		}
		seqs = append(seqs, st.Seq)
		if err := a.handleStep(context.Background(), plan.StepToWire(st), reply); err != nil {
			t.Fatal(err)
		}
	}
	var busy *link.StepResult
	deadline := time.After(5 * time.Second)
	for busy == nil {
		select {
		case r := <-results:
			if r.Status == plan.OutcomeBusy {
				busy = r
			}
		case <-deadline:
			t.Fatal("no busy answer")
		}
	}
	if busy.Node != "n3" || busy.Seq != seqs[2] || busy.StepDigest == "" {
		t.Fatalf("busy result %+v", busy)
	}
	x.mu.Lock()
	_, running := x.running[resultKey{1, seqs[2]}]
	x.mu.Unlock()
	if running {
		t.Fatal("the busy step was recorded as running")
	}
	a.execWG.Wait()
}
