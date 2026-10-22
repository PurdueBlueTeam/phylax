package firewall

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

var refs = map[string]string{
	"2027":        "../../manifest/2027",
	"two-segment": "../../manifest/two-segment",
}

func golden(t *testing.T, path, got string) {
	t.Helper()
	full := filepath.Join("testdata", "golden", path)
	if *update {
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/firewall -update)", err)
	}
	if string(want) != got {
		t.Errorf("%s differs from golden (run with -update to accept)", path)
	}
}
