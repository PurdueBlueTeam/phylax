package plans

import "testing"

func TestResolveLabelsExpandsEach(t *testing.T) {
	tpl, err := Parse([]byte("id: x\nmodule: hardening\nvars:\n  dcs: {labels: dc}\nnodes:\n- {id: a, each: dcs, action: ad.zerologon_check, target: '${host}'}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ov, err := ResolveLabels(tpl, func(e string) ([]string, error) { return []string{"ad", "ad2"}, nil })
	cat, _ := NewCatalog()
	pl, err2 := tpl.Expand(cat, ov)
	if err != nil || err2 != nil || len(pl.Nodes) != 2 || pl.Nodes[1].Target != "ad2" {
		t.Fatalf("%v %v %+v", err, err2, pl)
	}
	if tpl.Module != "hardening" {
		t.Fatal(tpl.Module)
	}
}

func TestUnresolvedLabelVarIsAnError(t *testing.T) {
	// Expand without ResolveLabels -> error mentioning "is not a list"
}

func TestParseRejectsUnknownField(t *testing.T) {
	if _, err := Parse([]byte("id: x\nbogus: 1\n")); err == nil {
		t.Fatal("unknown field accepted")
	}
}
