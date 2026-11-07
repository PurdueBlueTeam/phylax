//go:build linux

package main

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSwapHelperRunsInItsOwnSession proves the swap helper is not in the
// agent's session (and so not in the process group a stop signal reaches):
// with KillMode=process systemd stops only the unit's main process, and the
// helper must outlive the agent it is about to restart.
func TestSwapHelperRunsInItsOwnSession(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary to spawn a detached helper with")
	}
	cmd := exec.Command(sleep, "30")
	cmd.SysProcAttr = detachAttr()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	own, err := unix.Getsid(0)
	if err != nil {
		t.Fatal(err)
	}
	helper, err := unix.Getsid(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if helper == own {
		t.Fatalf("helper session %d is the agent's: a stop would kill it", helper)
	}
}
