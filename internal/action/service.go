package action

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// ---- service.state --------------------------------------------------------------
//
// systemd over D-Bus (the design's Linux implementation). The bus address
// comes from the standard DBUS_SYSTEM_BUS_ADDRESS override, which the test
// harness points at an in-memory fake bus implementing the systemd1
// manager surface.

const (
	systemdService   = "org.freedesktop.systemd1"
	systemdPath      = "/org/freedesktop/systemd1"
	systemdManagerIface = "org.freedesktop.systemd1.Manager"
	systemdUnitIface    = "org.freedesktop.systemd1.Unit"
)

type unitFileChange struct {
	Type   uint32
	Path   string
	Name   string
}

// The system-bus connection is created lazily on first use; the handshake
// is bounded so a hung dbus-daemon cannot wedge a plan step.
var (
	serviceBusOnce sync.Once
	serviceBus     *dbus.Conn
	serviceBusErr  error
)

func systemBus() (*dbus.Conn, error) {
	serviceBusOnce.Do(func() {
		c, err := dbus.SystemBusPrivate()
		if err != nil {
			serviceBusErr = err
			return
		}
		errCh := make(chan error, 1)
		go func() { errCh <- c.Hello() }()
		select {
		case err := <-errCh:
			if err != nil {
				c.Close()
				serviceBusErr = err
				return
			}
		case <-time.After(3 * time.Second):
			c.Close()
			serviceBusErr = fmt.Errorf("system bus handshake timeout")
			return
		}
		serviceBus = c
	})
	return serviceBus, serviceBusErr
}

// SetServiceBusForTest swaps the D-Bus connection (fake bus in tests).
func SetServiceBusForTest(c *dbus.Conn) {
	serviceBus = c
	serviceBusErr = nil
	serviceBusOnce = sync.Once{}
}

type systemdManager struct {
	conn *dbus.Conn
	mgr  dbus.BusObject
}

// busUnavailable is the ctl fallback when the system bus cannot be
// reached; every op surfaces the cause.
type busUnavailable struct{ err error }

func (b busUnavailable) getUnit(string) (dbus.ObjectPath, error) { return "", b.err }
func (b busUnavailable) unitProps(dbus.ObjectPath) (string, string, string, error) {
	return "", "", "", b.err
}
func (b busUnavailable) start(string) error  { return b.err }
func (b busUnavailable) stop(string) error   { return b.err }
func (b busUnavailable) restart(string) error { return b.err }
func (b busUnavailable) enable(string) error  { return b.err }
func (b busUnavailable) disable(string) error { return b.err }
func (b busUnavailable) mask(string) error    { return b.err }
func (b busUnavailable) unmask(string) error  { return b.err }

func newSystemdManager() systemdCtl {
	if c, err := systemBus(); err != nil || c == nil {
		return busUnavailable{err: serviceBusErr}
	}
	return systemdManager{
		conn: serviceBus,
		mgr:  serviceBus.Object(systemdService, systemdPath),
	}
}

func (m systemdManager) getUnit(name string) (dbus.ObjectPath, error) {
	var path dbus.ObjectPath
	err := m.mgr.Call("Manager.GetUnit", 0, name).Store(&path)
	return path, err
}

func (m systemdManager) unitProps(unit dbus.ObjectPath) (active, sub, load string, err error) {
	obj := m.conn.Object(systemdService, unit)
	for i, name := range []string{"ActiveState", "SubState", "LoadState"} {
		var v interface{}
		if err = obj.Call("org.freedesktop.DBus.Properties.Get", 0, systemdUnitIface, name).Store(&v); err != nil {
			return
		}
		switch i {
		case 0:
			active, _ = v.(string)
		case 1:
			sub, _ = v.(string)
		case 2:
			load, _ = v.(string)
		}
	}
	return
}

func (m systemdManager) do(name, method string) error {
	return m.mgr.Call(method, 0, name, "replace").Store()
}

func (m systemdManager) doReloadOrRestart(name string) error {
	return m.mgr.Call("ReloadOrRestartUnit", 0, name, "replace").Store()
}

type unitFileChangesResult struct {
	Count   uint32
	Changes []unitFileChange
}

func (m systemdManager) enableUnit(names []string, replace, force bool) error {
	var r unitFileChangesResult
	return m.mgr.Call("EnableUnitFiles", 0, names, replace, force).Store(&r.Count, &r.Changes)
}

func (m systemdManager) disableUnit(names []string, force bool) error {
	var r unitFileChangesResult
	return m.mgr.Call("DisableUnitFiles", 0, names, force).Store(&r.Count, &r.Changes)
}

func (m systemdManager) maskUnit(names []string, runtime bool) error {
	mode := "filesystem"
	if runtime {
		mode = "runtime"
	}
	var r unitFileChangesResult
	return m.mgr.Call("MaskUnitFiles", 0, names, mode).Store(&r.Count, &r.Changes)
}

func (m systemdManager) unmaskUnit(names []string, runtime bool) error {
	mode := "filesystem"
	if runtime {
		mode = "runtime"
	}
	var r unitFileChangesResult
	return m.mgr.Call("UnmaskUnitFiles", 0, names, mode).Store(&r.Count, &r.Changes)
}
// systemdCtl is the surface service.state needs from systemd; the D-Bus
// implementation is the default, tests inject a fake.
type systemdCtl interface {
	getUnit(name string) (dbus.ObjectPath, error)
	unitProps(unit dbus.ObjectPath) (active, sub, load string, err error)
	start(name string) error
	stop(name string) error
	restart(name string) error
	enable(name string) error
	disable(name string) error
	mask(name string) error
	unmask(name string) error
}

func (m systemdManager) start(name string) error  { return m.do(name, "StartUnit") }
func (m systemdManager) stop(name string) error   { return m.do(name, "StopUnit") }
func (m systemdManager) restart(name string) error { return m.doReloadOrRestart(name) }
func (m systemdManager) enable(name string) error  { return m.enableUnit([]string{name}, true, false) }
func (m systemdManager) disable(name string) error { return m.disableUnit([]string{name}, false) }
func (m systemdManager) mask(name string) error    { return m.maskUnit([]string{name}, false) }
func (m systemdManager) unmask(name string) error  { return m.unmaskUnit([]string{name}, false) }

type serviceState struct {
	ctl systemdCtl // nil means the real D-Bus manager
}

func (a serviceState) control() systemdCtl {
	if a.ctl != nil {
		return a.ctl
	}
	return newSystemdManager()
}

func (serviceState) Name() string    { return "service.state" }
func (serviceState) Risk() Risk      { return RiskService }
func (serviceState) Locks() []string { return nil }

// LocksFor returns the per-service lock name for a unit.
func LocksForService(unit string) []string {
	return []string{"service:" + strings.TrimSuffix(unit, ".service")}
}

// wantedDescription maps the plan's state verb to the systemd ActiveState
// it implies (for the diff text only; enable/mask are config, not state).
var wantedDescription = map[string]string{
	"started":   "active",
	"stopped":   "inactive",
	"enabled":   "enabled (config)",
	"disabled":  "disabled (config)",
	"masked":    "masked",
	"unmasked":  "unmasked",
	"reloaded":  "reloaded",
	"restarted": "restarted",
	"reload":    "reloaded",
	"restart":   "restarted",
}

func (a serviceState) state(p Params) (string, string, error) {
	unit := p.Get("unit", "")
	if !strings.HasSuffix(unit, ".service") && !strings.HasSuffix(unit, ".target") &&
		!strings.HasSuffix(unit, ".socket") && !strings.HasSuffix(unit, ".timer") {
		unit += ".service"
	}
	state := p.Get("state", "")
	want, ok := wantedDescription[state]
	if !ok {
		return unit, "", fmt.Errorf("service.state: unknown state %q", p.Get("state", ""))
	}
	return unit, want, nil
}

func (a serviceState) Check(p Params) (CheckResult, error) {
	unit, want, err := a.state(p)
	if err != nil {
		return CheckResult{}, err
	}
	m := a.control()
	up, err := m.getUnit(unit)
	if err != nil {
		return CheckResult{Diff: fmt.Sprintf("%s: %v", unit, err)}, nil
	}
	active, sub, load, err := m.unitProps(up)
	if err != nil {
		return CheckResult{}, err
	}
	cur := fmt.Sprintf("%s/%s", active, sub)
	if a.matches(stateOf(p), active, sub, load) {
		return CheckResult{Done: true, Diff: fmt.Sprintf("%s: %s", unit, cur)}, nil
	}
	return CheckResult{Diff: fmt.Sprintf("%s: %s -> %s", unit, cur, want),
		Before: []byte(Enc(cur))}, nil
}

func stateOf(p Params) string { return p.Get("state", "") }

func (a serviceState) matches(state, active, sub, load string) bool {
	switch state {
	case "started", "restart", "restarted", "reload", "reloaded":
		return active == "active"
	case "stopped":
		return active == "inactive" || active == "failed"
	case "enabled", "disabled":
		// config state is not in the unit properties we fetch; report
		// will-change and let apply idempotently no-op.
		return false
	case "masked":
		return load == "masked"
	case "unmasked":
		return load != "masked"
	}
	return false
}

func (a serviceState) Apply(p Params) (CheckResult, error) {
	unit, _, err := a.state(p)
	if err != nil {
		return CheckResult{}, err
	}
	m := a.control()
	up, err := m.getUnit(unit)
	if err != nil {
		return CheckResult{}, fmt.Errorf("get unit %s: %w", unit, err)
	}
	active, sub, _, _ := m.unitProps(up)
	before := fmt.Sprintf("%s/%s", active, sub)
	state := stateOf(p)
	var applyErr error
	switch state {
	case "started":
		applyErr = m.start(unit)
	case "restarted", "restart", "reloaded", "reload":
		applyErr = m.restart(unit)
	case "stopped":
		applyErr = m.stop(unit)
	case "enabled":
		applyErr = m.enable(unit)
	case "disabled":
		applyErr = m.disable(unit)
	case "masked":
		applyErr = m.mask(unit)
	case "unmasked":
		applyErr = m.unmask(unit)
	}
	if applyErr != nil {
		return CheckResult{}, applyErr
	}
	time.Sleep(200 * time.Millisecond) // let systemd settle
	up, err = m.getUnit(unit)
	if err != nil {
		return CheckResult{}, err
	}
	active, sub, _, _ = m.unitProps(up)
	return CheckResult{Before: []byte(Enc(before)),
		After: []byte(Enc(fmt.Sprintf("%s/%s", active, sub)))}, nil
}

func (a serviceState) Verify(p Params) (CheckResult, error) {
	unit, _, err := a.state(p)
	if err != nil {
		return CheckResult{}, err
	}
	m := a.control()
	up, err := m.getUnit(unit)
	if err != nil {
		return CheckResult{Diff: fmt.Sprintf("%s: %v", unit, err)}, nil
	}
	active, sub, load, err := m.unitProps(up)
	if err != nil {
		return CheckResult{}, err
	}
	if !a.matches(stateOf(p), active, sub, load) {
		return CheckResult{Diff: fmt.Sprintf("%s is %s/%s", unit, active, sub)}, nil
	}
	return CheckResult{Done: true}, nil
}

func (a serviceState) Rollback(p Params, before []byte) (CheckResult, error) {
	// Best effort: restore the previous active state.
	unit, _, _ := a.state(p)
	prev := string(Dec(string(before)))
	if prev == "" {
		return CheckResult{Done: true}, nil
	}
	m := a.control()
	var err error
	if strings.HasPrefix(prev, "active") {
		err = m.start(unit)
	} else {
		err = m.stop(unit)
	}
	if err != nil {
		return CheckResult{}, err
	}
	return CheckResult{Done: true, Diff: fmt.Sprintf("%s back to %s", unit, prev)}, nil
}
