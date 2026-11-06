package controller

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/module/conformance"
)

func TestLoadModuleTemplateForResolvesLabels(t *testing.T) {
	t.Skip("unimplemented: W1 Task 22b")
	// plansRoot/demo/pack.yaml: a pack with `vars: {servers: {labels: server}}` and an `each: servers` node, module: demo
	// manifest (newTestControllerWithManifest): h1 has label server, db1 does not
	// LoadModuleTemplateFor(root, "demo", "pack", c.hostsMatching) -> one node with Target "h1"
	// LoadModuleTemplate(root, "demo", "pack") (nil resolver) -> error
	// a pack whose module: is "other" -> error
}

func TestLoadModuleTemplateForPlainFile(t *testing.T) {
	t.Skip("unimplemented: W1 Task 22b")
	// the Task 22 ok.yml loads unchanged through LoadModuleTemplateFor with a nil resolver
}

func TestCoreImportsHasPlans(t *testing.T) {
	t.Skip("unimplemented: W1 Task 22b")
	found := false
	for _, p := range conformance.CoreImports {
		if p == "github.com/PurdueBlueTeam/phylax/plans" {
			found = true
		}
	}
	if !found {
		t.Fatal("plans package missing from CoreImports")
	}
}
