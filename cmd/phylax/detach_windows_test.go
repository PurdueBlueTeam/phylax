//go:build windows

package main

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
)

// TestDetachAttrWindows proves the swap helper is not a child the service
// manager kills: a detached process in its own group, and breaking away from
// the agent's Job Object when there is one.
func TestDetachAttrWindows(t *testing.T) {
	flags := detachAttr().CreationFlags
	for _, want := range []uint32{windows.DETACHED_PROCESS, windows.CREATE_NEW_PROCESS_GROUP, windows.CREATE_BREAKAWAY_FROM_JOB} {
		if flags&want == 0 {
			t.Fatalf("creation flags %#x lack %#x", flags, want)
		}
	}
	if fallback := detachAttrFallback().CreationFlags; fallback&windows.CREATE_BREAKAWAY_FROM_JOB != 0 {
		t.Fatalf("fallback flags %#x still ask to break away", fallback)
	}
}

// TestDetachedHelperBreaksAwayFromTheAgentJob proves the swap helper really
// leaves the agent's Job Object: CREATE_BREAKAWAY_FROM_JOB is refused unless
// the job allows breakaway, so this fails without
// JOB_OBJECT_LIMIT_BREAKAWAY_OK.
func TestDetachedHelperBreaksAwayFromTheAgentJob(t *testing.T) {
	if err := agent.ApplyJobLimits(agent.JobLimits{MemoryBytes: 256 << 20}); err != nil {
		t.Skipf("cannot create a job object in this environment: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.SysProcAttr = detachAttr()
	if err := cmd.Start(); err != nil {
		t.Fatalf("a detached swap helper cannot start inside the agent's job: %v", err)
	}
	_ = cmd.Wait()
}
