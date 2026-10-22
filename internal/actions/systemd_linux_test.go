//go:build linux

package actions

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
)

// fakeSystemd serves the subset of org.freedesktop.systemd1.Manager that the
// Systemd backend uses, on a private dbus-daemon (never the host's bus).
type fakeSystemd struct {
	mu    sync.Mutex
	conn  *dbus.Conn
	units map[string]*fakeUnit
	log   []string
}

type fakeUnit struct {
	load, active, file string
	props              *prop.Properties
}

type change struct{ Type, File, Dest string }

func unitPath(name string) dbus.ObjectPath {
	r := strings.NewReplacer(".", "_2e", "-", "_2d")
	return dbus.ObjectPath("/org/freedesktop/systemd1/unit/" + r.Replace(name))
}

func (f *fakeSystemd) sync(name string) {
	u := f.units[name]
	if u.props == nil {
		return // not loaded over the bus yet; LoadUnit exports it
	}
	u.props.SetMust("org.freedesktop.systemd1.Unit", "LoadState", u.load)
	u.props.SetMust("org.freedesktop.systemd1.Unit", "ActiveState", u.active)
}

func (f *fakeSystemd) LoadUnit(name string) (dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.units[name]
	if !ok {
		u = &fakeUnit{load: "not-found", active: "inactive"}
		f.units[name] = u
	}
	if u.props == nil {
		p, err := prop.Export(f.conn, unitPath(name), prop.Map{"org.freedesktop.systemd1.Unit": {
			"LoadState":   {Value: u.load, Writable: false, Emit: prop.EmitFalse},
			"ActiveState": {Value: u.active, Writable: false, Emit: prop.EmitFalse}}})
		if err != nil {
			return "", dbus.MakeFailedError(err)
		}
		u.props = p
	}
	f.sync(name)
	return unitPath(name), nil
}

func (f *fakeSystemd) GetUnitFileState(name string) (string, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.units[name]
	if !ok || u.file == "" {
		return "", dbus.NewError("org.freedesktop.systemd1.NoSuchUnit", []any{name})
	}
	return u.file, nil
}

func (f *fakeSystemd) job(name, op, active string) (dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.units[name]
	if !ok || u.load != "loaded" {
		return "", dbus.NewError("org.freedesktop.systemd1.NoSuchUnit", []any{name})
	}
	f.log = append(f.log, op+" "+name)
	u.active = active
	f.sync(name)
	return "/org/freedesktop/systemd1/job/1", nil
}
func (f *fakeSystemd) StartUnit(n, mode string) (dbus.ObjectPath, *dbus.Error) {
	return f.job(n, "start", "active")
}
func (f *fakeSystemd) StopUnit(n, mode string) (dbus.ObjectPath, *dbus.Error) {
	return f.job(n, "stop", "inactive")
}
func (f *fakeSystemd) RestartUnit(n, mode string) (dbus.ObjectPath, *dbus.Error) {
	return f.job(n, "restart", "active")
}

func (f *fakeSystemd) setFile(op string, files []string, state string) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range files {
		u, ok := f.units[n]
		if !ok || u.load == "not-found" {
			return dbus.NewError("org.freedesktop.systemd1.NoSuchUnit", []any{n})
		}
		f.log = append(f.log, op+" "+n)
		u.file = state
		if state == "masked" {
			u.load = "masked"
		} else if u.load == "masked" {
			u.load = "loaded"
		}
		f.sync(n)
	}
	return nil
}
func (f *fakeSystemd) EnableUnitFiles(files []string, runtime, force bool) (bool, []change, *dbus.Error) {
	return true, []change{{"symlink", "a", "b"}}, f.setFile("enable", files, "enabled")
}
func (f *fakeSystemd) DisableUnitFiles(files []string, runtime bool) ([]change, *dbus.Error) {
	return []change{{"unlink", "a", ""}}, f.setFile("disable", files, "disabled")
}
func (f *fakeSystemd) MaskUnitFiles(files []string, runtime, force bool) ([]change, *dbus.Error) {
	return []change{{"symlink", "a", "/dev/null"}}, f.setFile("mask", files, "masked")
}
func (f *fakeSystemd) UnmaskUnitFiles(files []string, runtime bool) ([]change, *dbus.Error) {
	return []change{{"unlink", "a", ""}}, f.setFile("unmask", files, "disabled")
}
func (f *fakeSystemd) Reload() *dbus.Error { return nil }

func startPrivateBus(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon not installed; cannot run the D-Bus backend test")
	}
	conf := t.TempDir() + "/bus.conf"
	cfg := `<busconfig><type>session</type><listen>unix:tmpdir=` + os.TempDir() + `</listen>
<auth>EXTERNAL</auth><policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy></busconfig>`
	if err := os.WriteFile(conf, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("dbus-daemon", "--config-file="+conf, "--nofork", "--print-address")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start private dbus-daemon: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Skipf("no bus address: %v", err)
	}
	return strings.TrimSpace(addr)
}

func TestSystemdBackendOverPrivateBus(t *testing.T) {
	addr := startPrivateBus(t)
	srv, err := dbus.Connect(addr)
	if err != nil {
		t.Skipf("connect private bus: %v", err)
	}
	defer srv.Close()
	fake := &fakeSystemd{conn: srv, units: map[string]*fakeUnit{
		"ssh.service":  {load: "loaded", active: "active", file: "enabled"},
		"cups.service": {load: "loaded", active: "inactive", file: "disabled"},
	}}
	if err := srv.Export(fake, sdPath, "org.freedesktop.systemd1.Manager"); err != nil {
		t.Fatal(err)
	}
	if rep, err := srv.RequestName(sdDest, dbus.NameFlagDoNotQueue); err != nil || rep != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("request name: %v %v", rep, err)
	}
	cli, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	sd := &Systemd{Conn: cli}
	ctx := context.Background()

	st, err := sd.State(ctx, "ssh")
	if err != nil || !st.Exists || !st.Active || st.Enabled != "enabled" {
		t.Fatalf("state: %+v %v", st, err)
	}
	if st, err := sd.State(ctx, "ghost.service"); err != nil || st.Exists {
		t.Fatalf("ghost: %+v %v", st, err)
	}
	for _, step := range []struct {
		unit string
		do   func() error
		want UnitState
	}{
		{"cups", func() error { return sd.Start(ctx, "cups") }, UnitState{Exists: true, Active: true, Enabled: "disabled"}},
		{"cups", func() error { return sd.Enable(ctx, "cups") }, UnitState{Exists: true, Active: true, Enabled: "enabled"}},
		{"cups", func() error { return sd.Stop(ctx, "cups") }, UnitState{Exists: true, Active: false, Enabled: "enabled"}},
		{"cups", func() error { return sd.Mask(ctx, "cups") }, UnitState{Exists: true, Active: false, Enabled: "masked"}},
		{"cups", func() error { return sd.Unmask(ctx, "cups") }, UnitState{Exists: true, Active: false, Enabled: "disabled"}},
		{"ssh", func() error { return sd.Restart(ctx, "ssh") }, UnitState{Exists: true, Active: true, Enabled: "enabled"}},
	} {
		if err := step.do(); err != nil {
			t.Fatal(err)
		}
		got, err := sd.State(ctx, step.unit)
		if err != nil || got != step.want {
			t.Fatalf("%s: got %+v want %+v err=%v", step.unit, got, step.want, err)
		}
	}
	if err := sd.Start(ctx, "ghost"); err == nil {
		t.Fatal("starting a missing unit should error")
	}

	// And through the full action path.
	f := newFixture(t)
	f.env.Services = sd
	f.ok(t, "service.state", map[string]any{"unit": "cups", "state": "running", "enable": "enabled"})
	if st, _ := sd.State(ctx, "cups"); !st.Active || st.Enabled != "enabled" {
		t.Fatalf("%+v", st)
	}
}

// Real systemd: read-only query, only when explicitly enabled.
func TestSystemdRealReadOnly(t *testing.T) {
	if os.Getenv("PHYLAX_PRIVILEGED_TESTS") != "1" {
		t.Skip("set PHYLAX_PRIVILEGED_TESTS=1 to query the real system bus (read-only)")
	}
	sd := &Systemd{}
	st, err := sd.State(context.Background(), "dbus.service")
	if err != nil {
		t.Skipf("system bus unavailable: %v", err)
	}
	t.Logf("dbus.service: %+v", st)
}
