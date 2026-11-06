//go:build linux

package depot

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// prepareExec must pick a path that execs on this host: the memfd through
// /proc/self/fd only when procfs allows exec, the private copy otherwise.
func TestPrepareExecPicksAnExecutablePath(t *testing.T) {
	dir := t.TempDir()
	content := []byte("#!/bin/sh\nexit 0\n")
	cmd := &exec.Cmd{Args: []string{"tool"}}
	cleanup, err := prepareExec(cmd, filepath.Join(dir, "on-disk"), dir, content)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got, want := cmd.Path == "/proc/self/fd/3", procIsExecutable(); got != want {
		t.Fatalf("path %q, /proc executable = %v", cmd.Path, want)
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("exec %q: %v", cmd.Path, err)
	}
}

// The copy fallback holds the verified bytes, not a reference to the deployed
// file: replacing the file after the command is built cannot change what runs.
func TestPrepareExecCopyRunsVerifiedBytes(t *testing.T) {
	dir := t.TempDir()
	content := []byte("#!/bin/sh\necho verified\n")
	cmd := &exec.Cmd{Args: []string{"tool"}}
	cleanup, err := prepareExecCopy(cmd, dir, content)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if filepath.Dir(filepath.Dir(cmd.Path)) != dir {
		t.Fatalf("copy %q is not under %q", cmd.Path, dir)
	}
	fi, err := os.Stat(cmd.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o500 {
		t.Fatalf("copy mode %v, want 0500", fi.Mode().Perm())
	}
	b, err := os.ReadFile(cmd.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, content) {
		t.Fatalf("copy content %q", b)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("run copy: %v", err)
	}
	if out.String() != "verified\n" {
		t.Fatalf("copy printed %q", out.String())
	}
	cleanup()
	if _, err := os.Stat(cmd.Path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("cleanup left %q: %v", cmd.Path, err)
	}
}
