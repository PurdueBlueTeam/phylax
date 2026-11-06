package plan

import (
	"strings"
	"testing"
	"time"
)

func cat() Catalog {
	return MapCatalog{
		"collect.inventory": {Name: "collect.inventory", Risk: RiskNone},
		"fw.apply":          {Name: "fw.apply", Risk: RiskLockout, Locks: []string{"firewall"}},
		"file.template":     {Name: "file.template", Risk: RiskService, Locks: []string{"file"}},
		"service.state":     {Name: "service.state", Risk: RiskService, Locks: []string{"svc"}},
		"host.exec":         {Name: "host.exec", Risk: RiskService},
		"needs.path": {Name: "needs.path", ValidateParams: func(p map[string]any) error {
			if _, ok := p["path"].(string); !ok {
				return errTest("path required")
			}
			return nil
		}},
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }

func samplePlan() *Plan {
	return &Plan{ID: "harden", Class: ClassAuto, Nodes: []Node{
		{ID: "baseline", Action: "collect.inventory", Target: "h1"},
		{ID: "fw_shadow", Action: "fw.apply", Target: "h1", Risk: RiskLockout, Needs: []string{"baseline"}, ExpiresAfterSec: 1800, Params: map[string]any{"mode": "shadow"}},
		{ID: "review", Gate: true, Needs: []string{"fw_shadow"}},
		{ID: "fw_enf", Action: "fw.apply", Target: "h1", Risk: RiskLockout, Needs: []string{"review"}, DeadmanSec: 90, Params: map[string]any{"mode": "enforce"}},
		{ID: "php", Action: "file.template", Target: "h1", Risk: RiskService, Params: map[string]any{"path": "/etc/php.ini"}},
		{ID: "other", Action: "collect.inventory", Target: "h2"},
	}}
}

func TestValidate(t *testing.T) {
	if err := samplePlan().Validate(cat()); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		mut  func(p *Plan)
		want string
	}{
		{"cycle", func(p *Plan) { p.Nodes[0].Needs = []string{"fw_enf"} }, "cycle"},
		{"self", func(p *Plan) { p.Nodes[0].Needs = []string{"baseline"} }, "itself"},
		{"unknown need", func(p *Plan) { p.Nodes[0].Needs = []string{"nope"} }, "unknown node"},
		{"unknown action", func(p *Plan) { p.Nodes[0].Action = "nope.x" }, "unknown action"},
		{"dup id", func(p *Plan) { p.Nodes[1].ID = "baseline" }, "duplicate id"},
		{"bad id", func(p *Plan) { p.Nodes[0].ID = "a b" }, "invalid id"},
		{"no target", func(p *Plan) { p.Nodes[0].Target = "" }, "missing target"},
		{"gate with action", func(p *Plan) { p.Nodes[2].Action = "fw.apply" }, "gate must not"},
		{"understated risk", func(p *Plan) { p.Nodes[1].Risk = RiskNone }, "understates"},
		{"bad risk", func(p *Plan) { p.Nodes[0].Risk = "wild" }, "unknown risk"},
		{"bad policy", func(p *Plan) { p.OnFailure = "explode" }, "on_failure"},
		{"bad params", func(p *Plan) { p.Nodes[0].Action = "needs.path" }, "path required"},
		{"float param", func(p *Plan) { p.Nodes[0].Params = map[string]any{"x": 1.5} }, "serialisable"},
		{"lock conflict", func(p *Plan) {
			p.Nodes = append(p.Nodes, Node{ID: "php2", Action: "file.template", Target: "h1", Risk: RiskService})
		}, "both lock"},
		{"empty", func(p *Plan) { p.Nodes = nil }, "no nodes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := samplePlan()
			tc.mut(p)
			err := p.Validate(cat())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
	// Same lock on different hosts, or ordered, is fine.
	p := samplePlan()
	p.Nodes = append(p.Nodes, Node{ID: "php2", Action: "file.template", Target: "h1", Risk: RiskService, Needs: []string{"php"}},
		Node{ID: "php3", Action: "file.template", Target: "h2", Risk: RiskService})
	if err := p.Validate(cat()); err != nil {
		t.Fatal(err)
	}
}

func TestHashDeterministic(t *testing.T) {
	a, b := samplePlan(), samplePlan()
	// shuffle node order, needs order, nil vs empty
	b.Nodes[0], b.Nodes[4] = b.Nodes[4], b.Nodes[0]
	b.Nodes[1].Needs = append([]string{}, "baseline")
	b.Nodes[5].Params = map[string]any{}
	ha, _ := a.Hash()
	hb, _ := b.Hash()
	if ha != hb || ha == "" {
		t.Fatalf("hash differs: %s %s", ha, hb)
	}
	b.Nodes[2].Needs = []string{"baseline"}
	if hc, _ := b.Hash(); hc == ha {
		t.Fatal("hash ignored a change")
	}
	for i := 0; i < 20; i++ {
		if h, _ := samplePlan().Hash(); h != ha {
			t.Fatal("nondeterministic")
		}
	}
	// Default policy is spelled out so "" and explicit hash equal.
	c := samplePlan()
	c.OnFailure = StopDependents
	if hc, _ := c.Hash(); hc != ha {
		t.Fatal("default policy changes hash")
	}
}

func mkRun(t *testing.T, p *Plan) *Run {
	t.Helper()
	r, err := NewRun(p, cat())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestScheduling(t *testing.T) {
	r := mkRun(t, samplePlan())
	if got := r.Next(Limits{}); len(got) != 0 {
		t.Fatalf("nothing approved yet, got %v", got)
	}
	r.ApprovePlan("alice", time.Unix(100, 0))
	if s := r.State("fw_shadow"); s != StatePending { // lockout needs its own approval
		t.Fatalf("fw_shadow %s", s)
	}
	must(t, r.ApproveNode("fw_shadow", Approval{By: "bob", At: 2}))
	if s := r.State("fw_enf"); s != StatePending { // lockout needs own approval
		t.Fatalf("fw_enf %s", s)
	}
	if s := r.State("review"); s != StatePending {
		t.Fatalf("gate %s", s)
	}
	// baseline (h1), php (h1; per-host 1), other (h2) are ready; per-host limit.
	got := r.Next(Limits{PerHost: 1})
	if strings.Join(got, ",") != "baseline,other" {
		t.Fatalf("got %v", got)
	}
	// php blocked by per-host limit until baseline done.
	if g := r.Next(Limits{PerHost: 1}); len(g) != 0 {
		t.Fatalf("got %v", g)
	}
	must(t, r.MarkApplied("baseline"))
	must(t, r.MarkVerified("baseline"))
	got = r.Next(Limits{PerHost: 1})
	if strings.Join(got, ",") != "fw_shadow" { // order: topo then id; fw_shadow before php
		t.Fatalf("got %v", got)
	}
	// With PerHost 2, php (different lock) may join.
	if g := r.Next(Limits{PerHost: 2}); strings.Join(g, ",") != "php" {
		t.Fatalf("got %v", g)
	}
	must(t, r.MarkApplied("fw_shadow"))
	must(t, r.MarkVerified("fw_shadow"))
	// Gate needs approval; fw_enf needs its own.
	must(t, r.ApproveNode("review", Approval{By: "bob", At: 1}))
	must(t, r.ApproveNode("fw_enf", Approval{By: "bob", At: 1}))
	if g := r.Next(Limits{PerHost: 2}); strings.Join(g, ",") != "fw_enf" {
		t.Fatalf("got %v", g)
	}
	if r.State("review") != StateVerified {
		t.Fatal("gate should have completed")
	}
	if r.Done() {
		t.Fatal("not done")
	}
	must(t, r.MarkApplied("fw_enf"))
	must(t, r.MarkVerified("fw_enf"))
	must(t, r.MarkApplied("php"))
	must(t, r.MarkVerified("php"))
	must(t, r.MarkApplied("other"))
	must(t, r.MarkVerified("other"))
	if !r.Done() {
		t.Fatalf("not done: %v", r.Snapshot())
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestLocksExternalAndRuntime(t *testing.T) {
	p := &Plan{ID: "p", Nodes: []Node{
		{ID: "a", Action: "file.template", Target: "h", Risk: RiskService},
		{ID: "b", Action: "service.state", Target: "h", Risk: RiskService},
	}}
	r := mkRun(t, p)
	r.ApprovePlan("x", time.Now())
	held := func(h, l string) bool { return h == "h" && l == "svc" }
	if g := r.Next(Limits{PerHost: 5, HeldExternally: held}); strings.Join(g, ",") != "a" {
		t.Fatalf("got %v", g)
	}
	if g := r.Next(Limits{PerHost: 5}); strings.Join(g, ",") != "b" {
		t.Fatalf("got %v", g)
	}
}

func TestIllegalTransitions(t *testing.T) {
	r := mkRun(t, samplePlan())
	if err := r.MarkApplied("baseline"); err == nil {
		t.Fatal("pending -> applied allowed")
	}
	if err := r.ApproveNode("nope", Approval{By: "x"}); err == nil {
		t.Fatal("unknown node")
	}
	if err := r.ApproveNode("baseline", Approval{}); err == nil {
		t.Fatal("empty approver")
	}
}

func chain(policy FailurePolicy) *Run {
	p := &Plan{ID: "p", OnFailure: policy, Nodes: []Node{
		{ID: "a", Action: "collect.inventory", Target: "h1"},
		{ID: "b", Action: "collect.inventory", Target: "h1", Needs: []string{"a"}},
		{ID: "c", Action: "collect.inventory", Target: "h1", Needs: []string{"b"}},
		{ID: "d", Action: "collect.inventory", Target: "h2"},
	}}
	r, err := NewRun(p, cat())
	if err != nil {
		panic(err)
	}
	r.ApprovePlan("x", time.Now())
	return r
}

func TestFailurePolicies(t *testing.T) {
	r := chain("")
	r.Next(Limits{})
	must(t, r.Fail("a", "boom"))
	if r.State("b") != StateSkipped || r.State("c") != StateSkipped {
		t.Fatalf("%v", r.Snapshot())
	}
	if r.State("d") != StateRunning || r.FailureReason("a") != "boom" {
		t.Fatalf("%v", r.Snapshot())
	}

	r = chain(Continue)
	r.Next(Limits{})
	must(t, r.Fail("a", "x"))
	if g := r.Next(Limits{}); strings.Join(g, ",") != "b" {
		t.Fatalf("continue: %v", g)
	}

	r = chain(RollbackPlan)
	r.Next(Limits{PerHost: 2})
	must(t, r.MarkApplied("a"))
	must(t, r.MarkVerified("a"))
	r.Next(Limits{PerHost: 2}) // b running
	must(t, r.Fail("b", "x"))
	if r.State("c") != StateSkipped {
		t.Fatal("c should be skipped")
	}
	if got := strings.Join(r.RollbackOrder(), ","); got != "b,a" {
		t.Fatalf("rollback order %s", got)
	}
	must(t, r.MarkRolledBack("a"))
	must(t, r.MarkRolledBack("b"))
}

func TestDryRunAggregation(t *testing.T) {
	r := mkRun(t, samplePlan())
	checks := []NodeCheck{
		{NodeID: "baseline"},
		{NodeID: "fw_shadow", WillChange: true, Diff: "+rule"},
		{NodeID: "fw_enf", WillChange: true, LintReject: "ICMP drop"},
		{NodeID: "php", WillChange: true},
		{NodeID: "other"},
	}
	dr := r.AggregateDryRun(checks, Limits{})
	if dr.Approvable || dr.Counts["rejected"] != 1 || dr.Counts["will_change"] != 2 || dr.Counts["unchanged"] != 3 {
		t.Fatalf("%+v", dr.Counts)
	}
	checks[2].LintReject = ""
	dr = r.AggregateDryRun(checks, Limits{})
	if !dr.Approvable {
		t.Fatalf("%+v", dr.Counts)
	}
	dr = r.AggregateDryRun(checks, Limits{HeldExternally: func(h, l string) bool { return l == "firewall" }})
	if dr.Approvable || dr.Counts["blocked"] != 2 {
		t.Fatalf("%+v", dr.Counts)
	}
	dr = r.AggregateDryRun(checks[:2], Limits{})
	if dr.Approvable || dr.Counts["missing"] == 0 {
		t.Fatalf("%+v", dr.Counts)
	}
}

func TestCanonicalize(t *testing.T) {
	got, err := Canonicalize([]byte(` {"b":[1,-0,"é\n",true,null],"a":{"z":1,"y":2},"😀":3,"￿":4} `))
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":{\"y\":2,\"z\":1},\"b\":[1,0,\"é\\n\",true,null],\"😀\":3,\"￿\":4}"
	if string(got) != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	for _, bad := range []string{`1.5`, `1e3`, `{"a":1,"a":2}`, `{} {}`, `[`, `9007199254740993`, ``} {
		if _, err := Canonicalize([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
