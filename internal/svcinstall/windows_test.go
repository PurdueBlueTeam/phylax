//go:build windows

package svcinstall

import (
	"context"
	"os"
	"testing"
)

func TestWindowsInstallUninstall(t *testing.T) {
	if os.Getenv("PHYLAX_PRIVILEGED_TESTS") != "1" {
		t.Skip("registers a real Windows service; set PHYLAX_PRIVILEGED_TESTS=1 (as Administrator) to run")
	}
	name := DeriveNames([]byte(t.Name())).Service
	exe, _ := os.Executable()
	i := New()
	if err := i.Install(context.Background(), Spec{Name: name, Binary: exe, Args: []string{"version"}}); err != nil {
		t.Fatal(err)
	}
	if err := i.Uninstall(context.Background(), name); err != nil {
		t.Fatal(err)
	}
}
