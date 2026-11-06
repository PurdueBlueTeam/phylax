package plan

import "testing"

func TestAutoGateValidates(t *testing.T) {
	ok := Node{ID: "g", Gate: true, Needs: []string{"a"}, Until: &GateUntil{AfterSec: 600, Probe: "*"}}
	if err := validateNode(ok); err != nil {
		t.Fatal(err)
	}
	for i, n := range []Node{
		{ID: "a", Action: "file.hash", Target: "h1", Until: &GateUntil{AfterSec: 5}}, // Until on a non-gate
		{ID: "g", Gate: true, Until: &GateUntil{}},                                   // no condition
		{ID: "g", Gate: true, Until: &GateUntil{AfterSec: 90000}},
		{ID: "g", Gate: true, Until: &GateUntil{NoEvent: &NoEvent{Kind: "no.such.kind"}}},
	} {
		if validateNode(n) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if RequiresOwnApproval(ok, RiskNone) {
		t.Fatal("an auto gate needs no approval record")
	}
	if !RequiresOwnApproval(Node{ID: "g", Gate: true}, RiskNone) {
		t.Fatal("a plain gate lost its approval")
	}
}
