//go:build windows

package agent

import (
	"os"
	"os/exec"
	"testing"
)

// TestApplyJobLimitsSetsMemoryLimit puts a child process in a Job Object with
// a 64 MiB memory cap; the child then commits 200 MB, which the OS refuses and
// the Go runtime turns into a fatal error. The parent (outside that job)
// survives.
func TestApplyJobLimitsSetsMemoryLimit(t *testing.T) {
	if os.Getenv("PHYLAX_JOB_CHILD") == "1" {
		if err := ApplyJobLimits(JobLimits{MemoryBytes: 64 << 20}); err != nil {
			os.Stderr.WriteString("apply: " + err.Error() + "\n")
			os.Exit(3)
		}
		b := make([]byte, 200<<20)
		for i := 0; i < len(b); i += 4096 {
			b[i] = 1
		}
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestApplyJobLimitsSetsMemoryLimit$")
	cmd.Env = append(os.Environ(), "PHYLAX_JOB_CHILD=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("the child committed 200 MB under a 64 MiB job limit and survived")
	}
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 3 {
		t.Fatalf("the child could not apply the job limits: %v", ee)
	}
}
