package controller

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadModuleTemplateChecksModule(t *testing.T) {
	t.Skip("unimplemented: W1 Task 22")
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "demo"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "demo", "ok.yml"), []byte("id: ok\nmodule: demo\non_failure: stop_dependents\nnodes: []\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "demo", "bad.yml"), []byte("id: bad\nmodule: other\non_failure: stop_dependents\nnodes: []\n"), 0o644)
	if p, err := LoadModuleTemplate(root, "demo", "ok"); err != nil || p.Module != "demo" {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := LoadModuleTemplate(root, "demo", "bad"); err == nil {
		t.Fatal("foreign module accepted")
	}
}
