package plan

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeHost records dispatched steps and answers them on demand.
type fakeHost struct {
	mu       sync.Mutex
	dispatch []Step
	fail     map[string]bool // node -> fail at apply
	send     Dispatch         // override; nil means standard auto-answers
}

// e is set per test before Start (closure target).
var e *Exec
func (f *fakeHost) dispatches() []Step {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Step(nil), f.dispatch...)
}
// stdSend is the default auto-answering behavior.
func (f *fakeHost) stdSend() Dispatch {
	return func(host string, s Step) error {
		f.mu.Lock()
		f.dispatch = append(f.dispatch, s)
		failApply := f.fail[s.Node]
		f.mu.Unlock()
		switch s.Phase {
		case PhaseCheck:
			e.Result(s.Node, Result{OK: true, Detail: "change " + s.Node, Before: []byte("pre-" + s.Node)})
		case PhaseApply:
			if failApply {
				e.Result(s.Node, Result{OK: false, Detail: "apply exploded"})
			} else {
				e.Result(s.Node, Result{OK: true})
			}
		case PhaseVerify:
			e.Result(s.Node, Result{OK: true})
		case PhaseRollback:
			e.Result(s.Node, Result{OK: true})
		}
		return nil
	}
}


func mustPlan(t *testing.T, name string, nodes ...Node) *Plan {
	t.Helper()
	p := &Plan{Name: name, Nodes: nodes}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}
func runPlan(t *testing.T, host *fakeHost, p *Plan, dry bool, timeout time.Duration) Snapshot {
	t.Helper()
	if host.send == nil {
		host.send = host.stdSend()
	}
	e = New("h1", p, host.send, t.Logf, 1)
	if err := e.Start(context.Background(), dry); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(timeout)
	for {
		select {
		case <-e.Done():
			return e.Status()
		case <-deadline:
			t.Fatalf("timeout; status: %+v", e.Status().State)
		}
	}
}

func TestPlanOrderAndCycles(t *testing.T) {
	p := &Plan{Name: "p", Nodes: []Node{
		{ID: "c", Action: "file.write", Depends: []string{"b"}},
		{ID: "b", Action: "file.write", Depends: []string{"a"}},
		{ID: "a", Action: "file.write"},
	}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	got, err := p.Order()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
	cyc := &Plan{Name: "cyc", Nodes: []Node{
		{ID: "x", Action: "file.write", Depends: []string{"y"}},
		{ID: "y", Action: "file.write", Depends: []string{"x"}},
	}}
	if err := cyc.Validate(); err == nil {
		t.Fatal("expected cycle error")
	}
}

func TestPlanHappyPath(t *testing.T) {
	fh := &fakeHost{}
	p := mustPlan(t, "harden",
		Node{ID: "creds", Action: "user.set_password"},
		Node{ID: "fw", Action: "fw.apply"},
		Node{ID: "svc", Action: "service.state", Depends: []string{"creds", "fw"}},
	)
	snap := runPlan(t, fh, p, false, 5*time.Second)
	if snap.State != PStSuccess {
		t.Fatalf("state = %s (%v)", snap.State, snap.Err)
	}
	// 3 nodes × (check, apply, verify) = 9 dispatches
	d := fh.dispatches()
	if len(d) != 9 {
		t.Fatalf("dispatches = %d, want 9: %+v", len(d), d)
	}
	// svc must not start before creds and fw complete
	pos := map[string]int{}
	for i, s := range d {
		if _, ok := pos[s.Node]; !ok {
			pos[s.Node] = i
		}
	}
	if pos["svc"] <= pos["fw"] || pos["svc"] <= pos["creds"] {
		t.Fatalf("ordering violated: %v", pos)
	}
	for _, id := range []string{"creds", "fw", "svc"} {
		if snap.Nodes[id].State != StDone {
			t.Fatalf("node %s = %s", id, snap.Nodes[id].State)
		}
	}
}

func TestPlanCheckDoneSkipsApply(t *testing.T) {
	fh := &fakeHost{}
	// make the first node's check report done
	fh.send = func(host string, s Step) error {
		fh.mu.Lock()
		fh.dispatch = append(fh.dispatch, s)
		fh.mu.Unlock()
		if s.Phase == PhaseCheck && s.Node == "nochange" {
			e.Result(s.Node, Result{OK: true, Done: true})
			return nil
		}
		return fh.dispatchOne(s)
	}
	p := mustPlan(t, "idem",
		Node{ID: "nochange", Action: "file.write"},
	)
	snap := runPlan(t, fh, p, false, 5*time.Second)
	if snap.State != PStSuccess {
		t.Fatalf("state = %s", snap.State)
	}
	d := fh.dispatches()
	if len(d) != 1 {
		t.Fatalf("expected 1 dispatch (check only), got %d: %+v", len(d), d)
	}
}

func (f *fakeHost) dispatchOne(s Step) error {
	f.mu.Lock()
	failApply := f.fail[s.Node]
	f.mu.Unlock()
	switch s.Phase {
	case PhaseCheck:
		e.Result(s.Node, Result{OK: true, Detail: "change " + s.Node, Before: []byte("pre-" + s.Node)})
	case PhaseApply:
		if failApply {
			e.Result(s.Node, Result{OK: false, Detail: "apply exploded"})
		} else {
			e.Result(s.Node, Result{OK: true})
		}
	case PhaseVerify:
		e.Result(s.Node, Result{OK: true})
	case PhaseRollback:
		e.Result(s.Node, Result{OK: true})
	}
	return nil
}

func TestPlanDryRunStopsAfterCheck(t *testing.T) {
	fh := &fakeHost{}
	p := mustPlan(t, "dry",
		Node{ID: "a", Action: "file.write"},
		Node{ID: "b", Action: "file.write", Depends: []string{"a"}},
	)
	snap := runPlan(t, fh, p, true, 5*time.Second)
	if snap.State != PStDryRun {
		t.Fatalf("state = %s", snap.State)
	}
	d := fh.dispatches()
	if len(d) != 2 {
		t.Fatalf("expected 2 check dispatches, got %d", len(d))
	}
	for _, s := range d {
		if s.Phase != PhaseCheck {
			t.Fatalf("dry run dispatched %s", s.Phase)
		}
	}
	// the diff is captured for the UI
	if snap.Nodes["a"].Diff == "" {
		t.Fatal("expected a check diff in the snapshot")
	}
}

func TestPlanFailureTriggersOrderedRollback(t *testing.T) {
	fh := &fakeHost{}
	fh.fail = map[string]bool{"mid": true}
	p := mustPlan(t, "break",
		Node{ID: "first", Action: "user.set_password"},
		Node{ID: "mid", Action: "fw.apply", Depends: []string{"first"}},
		Node{ID: "last", Action: "service.state", Depends: []string{"mid"}},
	)
	snap := runPlan(t, fh, p, false, 5*time.Second)
	if snap.State != PStRolledBack {
		t.Fatalf("state = %s (%v)", snap.State, snap.Err)
	}
	if snap.Nodes["last"].State != StSkipped {
		t.Fatalf("last = %s, want skipped", snap.Nodes["last"].State)
	}
	// rollback order: mid (failed, applied) then first (reverse completion)
	d := fh.dispatches()
	var rb []string
	for _, s := range d {
		if s.Op == OpRollback {
			rb = append(rb, s.Node)
		}
	}
	if len(rb) != 2 || rb[0] != "mid" || rb[1] != "first" {
		t.Fatalf("rollback order = %v, want [mid first]", rb)
	}
	// rollback carried the captured before-state
	for _, s := range d {
		if s.Op == OpRollback && s.Node == "first" {
			if string(s.Before) != "pre-first" {
				t.Fatalf("rollback before = %q", s.Before)
			}
		}
	}
}

func TestPlanDeadman(t *testing.T) {
	fh := &fakeHost{}
	// never answer the check for "stuck"
	fh.send = func(host string, s Step) error {
		fh.mu.Lock()
		fh.dispatch = append(fh.dispatch, s)
		fh.mu.Unlock()
		if s.Node == "stuck" {
			return nil
		}
		return fh.dispatchOne(s)
	}
	p := mustPlan(t, "dead",
		Node{ID: "stuck", Action: "file.write", Deadman: 1},
	)
	snap := runPlan(t, fh, p, false, 10*time.Second)
	if snap.State != PStFailed {
		t.Fatalf("state = %s (deadman with nothing applied should fail in place)", snap.State)
	}
	if snap.Nodes["stuck"].State != StFailed {
		t.Fatalf("stuck = %s", snap.Nodes["stuck"].State)
	}
}
// TestPlanLinkLossBlocksRollbackThenResumes is the T17 core: the link drops
// while a step is applying, the dead-man fires, the rollback is queued but
// cannot be sent, and resumes (without lockout) when the host reconnects.
func TestPlanLinkLossBlocksRollbackThenResumes(t *testing.T) {
	p := mustPlan(t, "t17",
		Node{ID: "first", Action: "file.write"},
		Node{ID: "fw", Action: "fw.apply", Depends: []string{"first"}},
	)
	var (
		fh       = &fakeHost{}
		linkDown = make(chan struct{})
		resume   = make(chan struct{})
	)
	disp := func(host string, s Step) error {
		fh.mu.Lock()
		fh.dispatch = append(fh.dispatch, s)
		fh.mu.Unlock()
		if s.Op == OpRollback {
			<-resume // the rollback lands after the link is back
			e.Result(s.Node, Result{OK: true})
			return nil
		}
		if s.Node == "fw" && s.Phase == PhaseApply {
			// the link dies mid-apply: the step is swallowed, no result
			close(linkDown)
			return nil
		}
		return fh.dispatchOne(s)
	}
	e = New("h1", p, disp, t.Logf, 1)
	if err := e.Start(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	// wait for the apply to be swallowed, then declare the link lost
	select {
	case <-linkDown:
	case <-time.After(5 * time.Second):
		t.Fatal("fw apply never dispatched")
	}
	e.HostGone()

	// the plan must be blocked with a rollback queue, and nothing may be
	// delivered while the link is down
	deadline := time.After(5 * time.Second)
	for {
		s := e.Status()
		if s.State == PStBlocked && len(s.Rollback) == 2 {
			break
		}
		if s.State == PStFailed || s.State == PStRolledBack || s.State == PStSuccess {
			t.Fatalf("unexpected terminal %s", s.State)
		}
		select {
		case <-deadline:
			t.Fatalf("never blocked; state = %s", s.State)
		case <-time.After(10 * time.Millisecond):
		}
	}
	for _, s := range fh.dispatches() {
		if s.Op == OpRollback {
			t.Fatalf("rollback dispatched while link down: %+v", s)
		}
	}

	// link comes back; rollbacks must resume in order
	close(resume)
	e.HostBack()
	<-e.Done()
	snap := e.Status()
	if snap.State != PStRolledBack {
		t.Fatalf("state = %s (%v)", snap.State, snap.Err)
	}
	var rb []string
	for _, s := range fh.dispatches() {
		if s.Op == OpRollback {
			rb = append(rb, s.Node)
		}
	}
	if len(rb) != 2 || rb[0] != "fw" || rb[1] != "first" {
		t.Fatalf("rollback order = %v, want [fw first]", rb)
	}
}

func TestPlanSafeModeBlocks(t *testing.T) {
	fh := &fakeHost{}
	e = New("h1", mustPlan(t, "sm", Node{ID: "a", Action: "file.write"}),
		fh.send, t.Logf, 1)
	e.SetSafeMode(true)
	if err := e.Start(context.Background(), false); err == nil {
		t.Fatal("expected safe-mode refusal")
	}
}

func TestPlanLoadYAML(t *testing.T) {
	doc := []byte(`
name: harden-web
nodes:
  - id: fw
    action: fw.apply
    locks: [packages]
  - id: ssh
    action: service.state
    params: {unit: sshd, state: stopped}
    depends: [fw]
    deadman: 30
`)
	p, err := Load(doc)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "harden-web" || len(p.Nodes) != 2 {
		t.Fatalf("parse: %+v", p)
	}
	if p.Nodes[1].Deadman != 30 {
		t.Fatalf("deadman = %d", p.Nodes[1].Deadman)
	}
	if got, _ := p.Order(); got[0] != "fw" {
		t.Fatalf("order = %v", got)
	}
}

func TestCanonicalStable(t *testing.T) {
	a := Canonical("p", "n", 3, 7, "run", "check", "file.write", map[string]any{"x": 1})
	b := Canonical("p", "n", 3, 7, "run", "check", "file.write", map[string]any{"x": 1})
	if a != b {
		t.Fatalf("canonical not stable: %q vs %q", a, b)
	}
	if a == Canonical("p", "n", 3, 8, "run", "check", "file.write", map[string]any{"x": 1}) {
		t.Fatal("seq must be in the signing string")
	}
	if a == Canonical("p", "n", 3, 7, "run", "apply", "file.write", map[string]any{"x": 1}) {
		t.Fatal("phase must be in the signing string")
	}
}
