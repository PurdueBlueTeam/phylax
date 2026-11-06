package all

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

var updateSchemas = flag.Bool("update", false, "rewrite manifest/schema/modules/*.schema.json")

// TestModuleSchemasCommitted generates the JSON Schema of every contract
// module's config block and compares it with the committed file, so the two
// cannot drift.
func TestModuleSchemasCommitted(t *testing.T) {
	blocks := map[string]any{}
	for _, f := range agent.Registered() {
		if f.Manifest.Name == "" {
			continue // a pre-contract module has no manifest and no block
		}
		b, ok := plan.BlockFor(&plan.AgentConfig{}, f.Manifest.Name)
		if !ok {
			t.Errorf("agent module %s has no config block in plan.ModuleSettings", f.Manifest.Name)
			continue
		}
		blocks[f.Manifest.Name] = b
	}
	for _, m := range module.Registered() {
		if c, ok := m.(module.Configurable); ok {
			blocks[m.Manifest().Name] = c.ConfigBlock()
		}
	}
	dir := filepath.Join("..", "..", "..", "manifest", "schema", "modules")
	for name, b := range blocks {
		want, err := module.Schema(b)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		path := filepath.Join(dir, name+".schema.json")
		if *updateSchemas {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run: go test ./internal/module/all -run Schema -update)", err)
		}
		if string(got) != string(want) {
			t.Errorf("%s is stale (run: go test ./internal/module/all -run Schema -update)", path)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	for _, e := range ents {
		name := strings.TrimSuffix(e.Name(), ".schema.json")
		if _, ok := blocks[name]; !ok {
			t.Errorf("%s has no contract module %q", filepath.Join(dir, e.Name()), name)
		}
	}
}
