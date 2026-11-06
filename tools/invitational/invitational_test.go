package invitational

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
)

func TestScripts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("collector harness runs under POSIX sh")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	cmd := exec.Command(sh, "test.sh")
	cmd.Env = append(os.Environ(), "INV_TEST=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("test.sh failed: %v\n%s", err, out)
	}
}
