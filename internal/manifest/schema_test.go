package manifest

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateSchema = flag.Bool("update-schema", false, "rewrite manifest/schema/*.schema.json")

const schemaDir = "../../manifest/schema"

func TestSchemasAreCurrent(t *testing.T) {
	for file, s := range Schemas() {
		want, err := MarshalSchema(s)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(schemaDir, file+".schema.json")
		if *updateSchema {
			if err := os.MkdirAll(schemaDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run: go test ./internal/manifest -update-schema)", err)
		}
		if string(got) != string(want) {
			t.Errorf("%s is stale (run: go test ./internal/manifest -update-schema)", path)
		}
	}
}

func TestSchemasAreClosedAndComplete(t *testing.T) {
	s := Schemas()
	if len(s) != 10 {
		t.Fatalf("want a schema per manifest file (10), got %d", len(s))
	}
	h := s[FileHosts]["properties"].(map[string]any)["hosts"].(map[string]any)["additionalProperties"].(map[string]any)
	if h["additionalProperties"] != false {
		t.Error("host schema must reject unknown keys")
	}
	if _, ok := h["properties"].(map[string]any)["os"]; !ok {
		t.Error("host schema missing os")
	}
}
