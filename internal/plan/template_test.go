package plan

import "testing"

func TestExpandTemplate(t *testing.T) {
	p := Plan{ID: "t", Nodes: []Node{{ID: "a", Action: "file.hash", Target: "${host}", Params: map[string]any{"path": "/srv/${f}", "list": []any{"${f}", 3}}}}}
	got, err := ExpandTemplate(p, map[string]string{"host": "h1", "f": "x", "trigger": "h1:7"})
	if err != nil {
		t.Fatal(err)
	}
	n := got.Nodes[0]
	if n.Target != "h1" || n.Params["path"] != "/srv/x" || n.Params["list"].([]any)[0] != "x" {
		t.Fatalf("%+v", n)
	}
	if p.Nodes[0].Target != "${host}" {
		t.Fatal("input plan modified")
	}
	for i, params := range []map[string]string{{"host": "h1"}, {"host": "h1", "f": "x", "extra": "1"}, {"host": "h1", "f": "${x}"}} {
		if _, err := ExpandTemplate(p, params); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}
