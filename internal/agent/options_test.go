package agent

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func TestAgentOptionsApplied(t *testing.T) {
	dir := t.TempDir()
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })
	path := filepath.Join(dir, "options.json")
	if err := os.WriteFile(path, []byte(`{"memory_limit_mb":128}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: Config{Layout: Layout{Root: dir}}, log: quietLog()}
	a.applyOptions()
	if got := debug.SetMemoryLimit(-1); got != 128<<20 {
		t.Fatalf("memory limit %d, want %d", got, 128<<20)
	}
	// A file that does not parse is ignored: the applied limit stays.
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.applyOptions()
	if got := debug.SetMemoryLimit(-1); got != 128<<20 {
		t.Fatalf("a broken options.json changed the limit to %d", got)
	}
	// A file with an out-of-range value is ignored too (the action bounds it;
	// the agent does not trust the file).
	if err := os.WriteFile(path, []byte(`{"memory_limit_mb":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a.applyOptions()
	if got := debug.SetMemoryLimit(-1); got != 128<<20 {
		t.Fatalf("an out-of-range options.json changed the limit to %d", got)
	}
}
