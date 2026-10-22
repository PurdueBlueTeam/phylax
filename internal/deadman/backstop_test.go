package deadman

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type call struct {
	name string
	args []string
}

func recorder(out string, err error) (Runner, *[]call) {
	var calls []call
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, call{name, append([]string(nil), args...)})
		return []byte(out), err
	}, &calls
}

func TestSystemdArmCommandLine(t *testing.T) {
	run, calls := recorder("", nil)
	now := time.Unix(1000, 0)
	s := &Systemd{Command: Command{Binary: "/usr/local/bin/phylax"}, Run: run, Now: func() time.Time { return now }}
	if err := s.Arm(context.Background(), "step-1", now.Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 || (*calls)[0].name != "systemctl" || (*calls)[1].name != "systemd-run" {
		t.Fatalf("calls: %+v", *calls)
	}
	got := strings.Join((*calls)[1].args, " ")
	for _, want := range []string{"--unit=phylax-deadman-step-1", "--on-active=90s", "--collect",
		"-- /usr/local/bin/phylax agent rollback step-1"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if !strings.HasSuffix(got, "agent rollback step-1") {
		t.Errorf("id must be the last arg: %q", got)
	}
}

func TestSystemdSubSecondRoundsUp(t *testing.T) {
	run, calls := recorder("", nil)
	now := time.Unix(1000, 0)
	s := &Systemd{Command: Command{Binary: "/x"}, Run: run, Now: func() time.Time { return now }}
	s.Arm(context.Background(), "a", now.Add(-time.Minute))
	if !strings.Contains(strings.Join((*calls)[1].args, " "), "--on-active=1s") {
		t.Fatalf("%+v", *calls)
	}
}

func TestSystemdDisarmToleratesNotLoaded(t *testing.T) {
	run, calls := recorder("Failed to stop x.timer: Unit x.timer not loaded.", errors.New("exit 5"))
	s := &Systemd{Run: run, User: true}
	if err := s.Disarm(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join((*calls)[0].args, " "); got != "--user stop phylax-deadman-x.timer" {
		t.Fatalf("%q", got)
	}
	run2, _ := recorder("permission denied", errors.New("exit 1"))
	if err := (&Systemd{Run: run2}).Disarm(context.Background(), "x"); err == nil {
		t.Fatal("real failures must surface")
	}
}

func TestSystemdArmErrorPropagates(t *testing.T) {
	n := 0
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		n++
		if name == "systemd-run" {
			return []byte("boom"), errors.New("exit 1")
		}
		return nil, nil
	}
	s := &Systemd{Command: Command{Binary: "/x"}, Run: run}
	if err := s.Arm(context.Background(), "a", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("expected error")
	}
}

func TestBadIDRejectedByBackstops(t *testing.T) {
	run, calls := recorder("", nil)
	if (&Systemd{Run: run}).Arm(context.Background(), "a;rm -rf /", time.Now()) == nil ||
		(&Schtasks{Run: run}).Arm(context.Background(), "a b", time.Now()) == nil {
		t.Fatal("bad ids accepted")
	}
	if len(*calls) != 0 {
		t.Fatal("ran a command for a bad id")
	}
}

func TestSchtasksXMLAndCommands(t *testing.T) {
	var xmlSeen []byte
	var calls []call
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, call{name, args})
		for i, a := range args {
			if a == "/XML" {
				xmlSeen, _ = os.ReadFile(args[i+1])
			}
		}
		return nil, nil
	}
	s := &Schtasks{Command: Command{Binary: `C:\Program Files\Phylax\phylax.exe`}, Run: run, TempDir: t.TempDir()}
	dl := time.Date(2027, 3, 4, 5, 6, 7, 0, time.Local)
	if err := s.Arm(context.Background(), "step-9", dl); err != nil {
		t.Fatal(err)
	}
	c := calls[0]
	if c.name != "schtasks.exe" || c.args[0] != "/Create" || c.args[1] != "/TN" || c.args[2] != `\Phylax\Deadman-step-9` || c.args[len(c.args)-1] != "/F" {
		t.Fatalf("%+v", c)
	}
	if len(xmlSeen) < 2 || xmlSeen[0] != 0xFF || xmlSeen[1] != 0xFE {
		t.Fatal("task xml must be UTF-16LE with BOM")
	}
	x, _ := s.TaskXML("step-9", dl)
	for _, want := range []string{"<StartBoundary>2027-03-04T05:06:07</StartBoundary>", "S-1-5-18",
		`<Command>C:\Program Files\Phylax\phylax.exe</Command>`, "<Arguments>agent rollback step-9</Arguments>", "StartWhenAvailable>true"} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %q", want)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(s.TempDir, "*.xml")); len(left) != 0 {
		t.Fatal("staged xml not removed")
	}
	// disarm: missing task is fine
	run2, _ := recorder("ERROR: The system cannot find the file specified.", errors.New("exit 1"))
	if err := (&Schtasks{Run: run2}).Disarm(context.Background(), "step-9"); err != nil {
		t.Fatal(err)
	}
}

func TestCommandQuoting(t *testing.T) {
	s := &Schtasks{Command: Command{Binary: "p.exe", Args: []string{"--journal", `C:\Program Data\j`, "rollback"}}}
	x, _ := s.TaskXML("i", time.Now())
	if !strings.Contains(x, `<Arguments>--journal &#34;C:\Program Data\j&#34; rollback i</Arguments>`) &&
		!strings.Contains(x, `<Arguments>--journal &quot;C:\Program Data\j&quot; rollback i</Arguments>`) {
		t.Fatalf("args not quoted: %s", x)
	}
}

func privileged(t *testing.T) {
	t.Helper()
	if os.Getenv("PHYLAX_PRIVILEGED_TESTS") != "1" {
		t.Skip("set PHYLAX_PRIVILEGED_TESTS=1 to run tests that create real systemd units / scheduled tasks")
	}
}

func TestSystemdReal(t *testing.T) {
	privileged(t)
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	if _, err := exec.LookPath("systemd-run"); err != nil || os.Geteuid() != 0 {
		t.Skip("needs systemd-run and root")
	}
	marker := filepath.Join(t.TempDir(), "fired")
	s := &Systemd{Command: Command{Binary: "/bin/sh", Args: []string{"-c", `echo "$1" > ` + marker, "sh"}}}
	ctx := context.Background()
	id := "ptest-" + time.Now().Format("150405")
	t.Cleanup(func() { s.Disarm(ctx, id) })

	// armed far in the future: timer exists, then Disarm removes it
	if err := s.Arm(ctx, id, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := ExecRunner(ctx, "systemctl", "is-active", UnitName(id)+".timer"); err != nil {
		t.Fatalf("timer not active: %v", err)
	}
	if err := s.Disarm(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := ExecRunner(ctx, "systemctl", "is-active", UnitName(id)+".timer"); err == nil {
		t.Fatal("timer still active after Disarm")
	}
	// real fire
	if err := s.Arm(ctx, id, time.Now().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if b, _ := os.ReadFile(marker); strings.TrimSpace(string(b)) == id {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("systemd timer never ran the command")
}

func TestSchtasksReal(t *testing.T) {
	privileged(t)
	if runtime.GOOS != "windows" {
		t.Skip("windows only")
	}
	s := &Schtasks{Command: Command{Binary: `C:\Windows\System32\cmd.exe`, Args: []string{"/c", "rem"}}}
	ctx := context.Background()
	id := "ptest"
	t.Cleanup(func() { s.Disarm(ctx, id) })
	if err := s.Arm(ctx, id, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := ExecRunner(ctx, "schtasks.exe", "/Query", "/TN", s.TaskName(id)); err != nil {
		t.Fatalf("task not registered: %v", err)
	}
	if err := s.Disarm(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := ExecRunner(ctx, "schtasks.exe", "/Query", "/TN", s.TaskName(id)); err == nil {
		t.Fatal("task still present")
	}
}
