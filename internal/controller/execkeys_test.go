package controller

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPlanKeyPersistedWithRestrictivePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.key")
	k1, err := loadPlanKey(path)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := loadPlanKey(path)
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("key not stable across loads: %v", err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPlanKey(path); err == nil {
		t.Fatal("a world-readable plan key was accepted")
	}
}
