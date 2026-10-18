package action

import (
	"fmt"
	"testing"

	"github.com/godbus/dbus/v5"
)

// fakeSystemd is an in-memory systemd for service.state unit tests.
type fakeSystemd struct {
	units map[string]*fakeUnit // by canonical name (with .service)
}

type fakeUnit struct {
	active   string // active | inactive | failed
	sub      string
	load     string // loaded | masked
	enabled  bool
	masked   bool
	started  bool
	stopped  bool
	restarts int
	enabledCalls, disabledCalls, maskCalls, unmaskCalls int
}

func newFakeSystemd() *fakeSystemd {
	f := &fakeSystemd{units: map[string]*fakeUnit{}}
	f.units["nginx.service"] = &fakeUnit{active: "active", sub: "running", load: "loaded", enabled: true}
	f.units["sshd.service"] = &fakeUnit{active: "active", sub: "running", load: "loaded", enabled: true}
	return f
}

func (f *fakeSystemd) unit(name string) *fakeUnit {
	if !hasUnitSuffix(name) {
		name += ".service"
	}
	return f.units[name]
}

func hasUnitSuffix(name string) bool {
	for _, s := range []string{".service", ".target", ".socket", ".timer"} {
		if len(name) > len(s) && name[len(name)-len(s):] == s {
			return true
		}
	}
	return false
}

func (f *fakeSystemd) getUnit(name string) (dbus.ObjectPath, error) {
	u := f.unit(name)
	if u == nil {
		return "", fmt.Errorf("no unit %s", name)
	}
	return dbus.ObjectPath("/org/freedesktop/systemd1/unit/" + name), nil
}

func (f *fakeSystemd) unitProps(p dbus.ObjectPath) (active, sub, load string, err error) {
	name := string(p[len("/org/freedesktop/systemd1/unit/"):])
	u := f.units[name]
	if u == nil {
		return "", "", "", fmt.Errorf("no unit %s", name)
	}
	return u.active, u.sub, u.load, nil
}
func (a *fakeSystemd) start(name string) error {
	u := a.unit(name)
	if u.masked {
		return fmt.Errorf("%s is masked", name)
	}
	u.active, u.sub = "active", "running"
	u.started = true
	return nil
}

func (a *fakeSystemd) stop(name string) error {
	u := a.unit(name)
	u.active, u.sub = "inactive", "dead"
	u.stopped = true
	return nil
}

func (a *fakeSystemd) restart(name string) error {
	u := a.unit(name)
	if u.masked {
		return fmt.Errorf("%s is masked", name)
	}
	u.restarts++
	u.active, u.sub = "active", "running"
	return nil
}

func (a *fakeSystemd) enable(name string) error  { a.unit(name).enabled = true; a.unit(name).enabledCalls++; return nil }
func (a *fakeSystemd) disable(name string) error { a.unit(name).enabled = false; a.unit(name).disabledCalls++; return nil }
func (a *fakeSystemd) mask(name string) error    { u := a.unit(name); u.masked, u.load = true, "masked"; u.maskCalls++; return nil }
func (a *fakeSystemd) unmask(name string) error  { u := a.unit(name); u.masked, u.load = false, "loaded"; u.unmaskCalls++; return nil }

var _ systemdCtl = (*fakeSystemd)(nil)

func TestServiceStateStopAndRestart(t *testing.T) {
	f := newFakeSystemd()
	a := serviceState{ctl: f}

	// stop sshd
	r, err := a.Check(Params(map[string]any{"unit": "sshd", "state": "stopped"}))
	if err != nil || r.Done {
		t.Fatalf("expected diff, got %+v %v", r, err)
	}
	if _, err := a.Apply(Params(map[string]any{"unit": "sshd", "state": "stopped"})); err != nil {
		t.Fatal(err)
	}
	if !f.unit("sshd.service").stopped {
		t.Fatal("sshd not stopped")
	}
	if r, _ := a.Verify(Params(map[string]any{"unit": "sshd", "state": "stopped"})); !r.Done {
		t.Fatal("verify should pass")
	}
	// idempotent
	if r, _ := a.Check(Params(map[string]any{"unit": "sshd", "state": "stopped"})); !r.Done {
		t.Fatal("expected idempotent check")
	}

	// restart nginx
	if _, err := a.Apply(Params(map[string]any{"unit": "nginx", "state": "restarted"})); err != nil {
		t.Fatal(err)
	}
	if f.unit("nginx.service").restarts != 1 {
		t.Fatalf("restarts = %d", f.unit("nginx.service").restarts)
	}
}

func TestServiceStateMaskBlocksStart(t *testing.T) {
	f := newFakeSystemd()
	a := serviceState{ctl: f}
	if _, err := a.Apply(Params(map[string]any{"unit": "sshd", "state": "masked"})); err != nil {
		t.Fatal(err)
	}
	if r, _ := a.Verify(Params(map[string]any{"unit": "sshd", "state": "masked"})); !r.Done {
		t.Fatal("verify masked should pass")
	}
	// starting a masked unit fails
	if _, err := a.Apply(Params(map[string]any{"unit": "sshd", "state": "started"})); err == nil {
		t.Fatal("expected start to fail on masked unit")
	}
}

func TestServiceStateEnableDisable(t *testing.T) {
	f := newFakeSystemd()
	a := serviceState{ctl: f}
	if _, err := a.Apply(Params(map[string]any{"unit": "nginx", "state": "disabled"})); err != nil {
		t.Fatal(err)
	}
	if f.unit("nginx.service").enabled {
		t.Fatal("nginx should be disabled")
	}
	// enabled/disabled always report will-change (config not in props);
	// apply is idempotent.
	if _, err := a.Apply(Params(map[string]any{"unit": "nginx", "state": "enabled"})); err != nil {
		t.Fatal(err)
	}
	if !f.unit("nginx.service").enabled {
		t.Fatal("nginx should be enabled")
	}
}

func TestServiceStateRollbackRestoresActive(t *testing.T) {
	f := newFakeSystemd()
	a := serviceState{ctl: f}
	r, err := a.Check(Params(map[string]any{"unit": "nginx", "state": "stopped"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(Params(map[string]any{"unit": "nginx", "state": "stopped"})); err != nil {
		t.Fatal(err)
	}
	if !f.unit("nginx.service").stopped {
		t.Fatal("nginx should be stopped")
	}
	// rollback to the captured "active/running"
	if _, err := a.Rollback(Params(map[string]any{"unit": "nginx", "state": "stopped"}), r.Before); err != nil {
		t.Fatal(err)
	}
	if f.unit("nginx.service").active != "active" {
		t.Fatalf("active = %q after rollback", f.unit("nginx.service").active)
	}
}

func TestServiceStateUnknownState(t *testing.T) {
	f := newFakeSystemd()
	a := serviceState{ctl: f}
	if _, err := a.Check(Params(map[string]any{"unit": "nginx", "state": "exploded"})); err == nil {
		t.Fatal("expected error for unknown state")
	}
}
