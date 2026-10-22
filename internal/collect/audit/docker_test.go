//go:build linux

package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Real-kernel test. It never touches the dev machine directly: the outer test
// (PHYLAX_AUDIT_DOCKER=1) builds this package's test binary statically and runs
// only the inner test inside a container that has just AUDIT_CONTROL and
// AUDIT_READ added (no --privileged, bridge network, not the host's). The inner
// test reads the multicast group, installs rules under a unique key, removes
// exactly those rules on exit, and never changes global audit settings.
//
// Note: the kernel only honours audit commands from the initial network
// namespace (see design/research: "containers cannot configure audit"), so on
// many hosts the container is refused and the inner test skips; the outer test
// then skips with that reason rather than passing silently.

const (
	envDocker      = "PHYLAX_AUDIT_DOCKER"
	envInContainer = "PHYLAX_AUDIT_INCONTAINER"
	dockerImage    = "alpine:3"
)

func TestDockerKernelExec(t *testing.T) {
	if os.Getenv(envInContainer) == "1" {
		t.Skip("outer driver; the inner test is TestInContainerKernelExec")
	}
	if os.Getenv(envDocker) != "1" {
		t.Skipf("real-kernel audit test skipped: set %s=1 to run it inside a Docker container with --cap-add=AUDIT_CONTROL,AUDIT_READ", envDocker)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found in PATH")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "audit.test")
	build := exec.Command("go", "test", "-c", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build test binary: %v\n%s", err, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"--cap-add=AUDIT_CONTROL", "--cap-add=AUDIT_READ",
		"-v", dir+":/t:ro", "-e", envInContainer+"=1", dockerImage,
		"/t/audit.test", "-test.run", "^TestInContainerKernelExec$", "-test.v")
	out, err := cmd.CombinedOutput()
	t.Logf("container output:\n%s", out)
	if err != nil {
		t.Fatalf("container run failed: %v", err)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("kernel audit not usable from the container: %s", skipReason(string(out)))
	}
	if !strings.Contains(string(out), "--- PASS: TestInContainerKernelExec") {
		t.Fatal("inner test did not pass")
	}
}

func skipReason(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, ".go:") && strings.Contains(l, "audit") {
			return strings.TrimSpace(l)
		}
	}
	return "see container output"
}

func TestInContainerKernelExec(t *testing.T) {
	if os.Getenv(envInContainer) != "1" {
		t.Skip("runs only inside the container started by TestDockerKernelExec")
	}
	suffix := fmt.Sprintf("_t%d", os.Getpid())
	m, err := New(Config{
		Mode: "multicast", NoManageSettings: true, RemoveRulesOnExit: true, TestKeySuffix: suffix,
		SweepInterval: -1, VerifyInterval: time.Second, Logger: quietLog(),
		// Only the exec rule matters here; keep the container's footprint tiny.
		ExtraWatches: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Narrow the rule set to exec only so the test touches nothing else.
	var execOnly []string
	for _, l := range m.Rules() {
		if strings.Contains(l, KeyExec) {
			execOnly = append(execOnly, l)
		}
	}
	rs, err := NewRuleSet(execOnly)
	if err != nil {
		t.Fatal(err)
	}
	m.rs = rs

	c := &collector{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx, c.emit) }()

	// Wait for the module to be running (rules installed) or fail.
	deadline := time.Now().Add(10 * time.Second)
	for m.Status().Mode == "" {
		select {
		case err := <-done:
			if refused(err) {
				t.Skipf("audit netlink refused in container (needs the initial network namespace and CAP_AUDIT_*): %v", err)
			}
			t.Fatalf("Start returned early: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("module did not start")
		}
	}
	if m.Status().RulesInstall == 0 {
		cancel()
		<-done
		t.Skip("audit rules could not be installed from the container (kernel refused or audit locked)")
	}

	cmd := exec.Command("sh", "-c", "id; true")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh: %v %s", err, out)
	}
	var got *event.Event
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end) && got == nil; time.Sleep(100 * time.Millisecond) {
		for _, e := range c.kind(KindProcessStart) {
			if av, _ := e.Fields["argv"].([]string); len(av) == 3 && av[0] == "sh" && av[1] == "-c" && av[2] == "id; true" {
				ev := e
				got = &ev
			}
		}
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Logf("Start: %v", err)
	}
	if got == nil {
		t.Fatalf("no process_start for `sh -c 'id; true'`; saw %d events, status %+v", len(c.all()), m.Status())
	}
	if got.Fields["success"] != true || got.Fields["pid"] == 0 || got.Fields["ppid"] == 0 {
		t.Fatalf("event: %v", got.Fields)
	}
	if !strings.HasSuffix(got.Fields["exe"].(string), "/busybox") && !strings.Contains(got.Fields["exe"].(string), "sh") {
		t.Fatalf("exe %v", got.Fields["exe"])
	}
}

func refused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EINVAL) ||
		(err != nil && strings.Contains(err.Error(), "refused"))
}
