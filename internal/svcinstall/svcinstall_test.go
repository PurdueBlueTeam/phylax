package svcinstall

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		os.WriteFile(p, []byte(got), 0o644)
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatalf("%s differs from golden (run with -update):\n%s", name, got)
	}
}

func TestSystemdUnitGolden(t *testing.T) {
	u, err := SystemdUnit(Spec{Name: "udev-netd-1a2b3c", Description: "System network helper",
		Binary: "/opt/udev-netd/kern-logd-9f8e7d", Args: []string{"agent", "run", "--state-dir", "/var/lib/my dir"},
		MemoryMax: "256M", CPUQuota: "50%", WatchdogSec: 30})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "agent.service.golden", u)
	for _, must := range []string{"Restart=always", "RestartSec=1", "StartLimitIntervalSec=0", "WatchdogSec=30", "Type=notify", "OOMScoreAdjust=-900", "KillMode=process"} {
		if !strings.Contains(u, must) {
			t.Errorf("missing %s", must)
		}
	}
	// Must not confine a root agent.
	for _, bad := range []string{"ProtectSystem", "CapabilityBoundingSet", "PrivateTmp", "ReadOnlyPaths", "User="} {
		if strings.Contains(u, bad) {
			t.Errorf("unit contains %s, which would break the root agent", bad)
		}
	}
}

func TestSystemdUnitMinimalAndQuoting(t *testing.T) {
	u, err := SystemdUnit(Spec{Name: "a", Binary: "/b/$x%y", Args: []string{`q"r`}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(u, `ExecStart=/b/$$x%%y "q\"r"`) || !strings.Contains(u, "Type=simple") || strings.Contains(u, "MemoryMax") {
		t.Fatal(u)
	}
	for _, bad := range []Spec{{Name: "../x", Binary: "/b"}, {Name: "ok"}, {Name: "", Binary: "/b"}} {
		if _, err := SystemdUnit(bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestSystemdInstallUninstallWithFakeSystemctl(t *testing.T) {
	dir := t.TempDir()
	var calls []string
	s := &Systemd{UnitDir: dir, Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}}
	if err := s.Install(context.Background(), Spec{Name: "svc-x", Binary: "/bin/x", Args: []string{"agent", "run"}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "svc-x.service"))
	if err != nil || !strings.Contains(string(data), "ExecStart=/bin/x agent run") {
		t.Fatalf("%v %s", err, data)
	}
	want := []string{"systemctl daemon-reload", "systemctl enable svc-x.service", "systemctl restart svc-x.service"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls %v", calls)
	}
	if err := s.Uninstall(context.Background(), "svc-x"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "svc-x.service")); !os.IsNotExist(err) {
		t.Fatal("unit not removed")
	}
	if err := s.Uninstall(context.Background(), "../etc/passwd"); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestDeriveNamesStableAndSecretDependent(t *testing.T) {
	a, b := DeriveNames([]byte("event-1")), DeriveNames([]byte("event-1"))
	c := DeriveNames([]byte("event-2"))
	if a != b || a == c {
		t.Fatalf("%+v %+v %+v", a, b, c)
	}
	for _, n := range []string{a.Service, a.Binary, a.Dir} {
		if !validName(n) {
			t.Errorf("derived invalid name %q", n)
		}
	}
	if a.Service == a.Binary {
		t.Fatal("names not distinct")
	}
}

func TestSystemdStopAndRestart(t *testing.T) {
	var calls []string
	s := &Systemd{UnitDir: t.TempDir(), Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}}
	if err := s.Stop(context.Background(), "svc-x"); err != nil {
		t.Fatal(err)
	}
	if err := s.Restart(context.Background(), "svc-x"); err != nil {
		t.Fatal(err)
	}
	want := []string{"systemctl stop svc-x.service", "systemctl restart svc-x.service"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls %v", calls)
	}
	if err := s.Restart(context.Background(), "../etc/passwd"); err == nil {
		t.Fatal("path traversal accepted")
	}
}
