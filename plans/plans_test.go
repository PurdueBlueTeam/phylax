package plans

import (
	"strings"
	"testing"
)

func TestAllTemplatesValidate(t *testing.T) {
	cat, err := NewCatalog()
	if err != nil {
		t.Fatal(err)
	}
	paths := Paths()
	if len(paths) < 13 {
		t.Fatalf("expected the wazuh, splunk and first-hour templates, got %v", paths)
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			tpl, err := Load(p)
			if err != nil {
				t.Fatal(err)
			}
			pl, err := tpl.Expand(cat, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := pl.Validate(cat); err != nil {
				t.Fatalf("validate: %v", err)
			}
		})
	}
}

func TestWazuhDeployShape(t *testing.T) {
	cat, _ := NewCatalog()
	tpl, err := Load("wazuh.deploy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pl, err := tpl.Expand(cat, map[string]any{"linux_agents": []any{"a", "b"}, "win_agents": []any{"w"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := pl.Validate(cat); err != nil {
		t.Fatal(err)
	}
	installs := map[string]string{}
	for _, n := range pl.Nodes {
		if n.Action == "pkg.install" {
			installs[n.Target] = n.Params["version"].(string)
		}
		if n.ID == "agent-up-linux.a" && len(n.Needs) != 2 {
			t.Fatalf("per-host needs not expanded to own instance: %v", n.Needs)
		}
	}
	if len(installs) != 4 { // manager + 3 agents
		t.Fatalf("installs: %v", installs)
	}
	for h, v := range installs {
		if v != "4.14.9" {
			t.Fatalf("%s pinned to %s", h, v)
		}
	}
}

func TestFirstHourZerologonBeforeSpooler(t *testing.T) {
	cat, _ := NewCatalog()
	tpl, _ := Load("first-hour/dc.zerologon_first.yaml")
	pl, _ := tpl.Expand(cat, nil)
	for _, n := range pl.Nodes {
		if strings.HasPrefix(n.ID, "secure-channel.") || strings.HasPrefix(n.ID, "spooler-off.") {
			if len(n.Needs) != 1 || !strings.HasPrefix(n.Needs[0], "check.") {
				t.Fatalf("%s must follow the zerologon check on the same DC: %v", n.ID, n.Needs)
			}
		}
	}
}

func TestBadTemplateRejected(t *testing.T) {
	cat, _ := NewCatalog()
	tpl := &Template{ID: "x", Nodes: []TNode{{ID: "a", Action: "nope.action", Target: "h"}}}
	pl, _ := tpl.Expand(cat, nil)
	if err := pl.Validate(cat); err == nil {
		t.Fatal("unknown action accepted")
	}
	tpl = &Template{ID: "x", Nodes: []TNode{{ID: "a", Action: "pkg.install", Target: "h", Params: map[string]any{"bogus": 1}}}}
	pl, _ = tpl.Expand(cat, nil)
	if err := pl.Validate(cat); err == nil {
		t.Fatal("bad params accepted")
	}
	tpl = &Template{ID: "x", Nodes: []TNode{{ID: "a", Action: "service.stop", Target: "${nope}", Params: map[string]any{"unit": "x"}}}}
	if _, err := tpl.Expand(cat, nil); err == nil {
		t.Fatal("undefined variable accepted")
	}
}
