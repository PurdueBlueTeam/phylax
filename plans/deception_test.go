package plans

import (
	"strings"
	"testing"
)

// The deception template carries secret parameters by reference only.
func TestDeceptionDeployTemplateShape(t *testing.T) {
	cat, err := NewCatalog()
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := Load("deception.deploy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pl, err := tpl.Expand(cat, map[string]any{"decoy_hosts": []any{"a", "b", "c"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := pl.Validate(cat); err != nil {
		t.Fatal(err)
	}
	checks, plants, ads := 0, 0, 0
	for _, n := range pl.Nodes {
		switch n.Action {
		case "deception.decoy_check":
			checks++
			if len(n.Needs) != 1 || n.Needs[0] != "approve-deception" {
				t.Errorf("%s must wait for the approval gate: %v", n.ID, n.Needs)
			}
		case "file.plant":
			plants++
			if n.Params["only_if_absent"] != true {
				t.Errorf("%s may clobber an existing file", n.ID)
			}
			if _, has := n.Params["content"]; has {
				t.Errorf("%s carries content in the plan", n.ID)
			}
			refs, _ := n.Params["secret_refs"].(map[string]any)
			if ref, _ := refs["content"].(string); !strings.HasPrefix(ref, "honeytoken/") {
				t.Errorf("%s: secret ref %q", n.ID, ref)
			}
		case "ad.honey_account":
			ads++
			if _, has := n.Params["password"]; has {
				t.Errorf("%s carries a password in the plan", n.ID)
			}
		}
	}
	if checks != 3 || plants != 1 || ads != 1 {
		t.Fatalf("checks=%d plants=%d ads=%d", checks, plants, ads)
	}
}
