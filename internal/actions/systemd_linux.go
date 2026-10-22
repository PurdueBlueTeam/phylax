//go:build linux

package actions

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	sdDest = "org.freedesktop.systemd1"
	sdPath = dbus.ObjectPath("/org/freedesktop/systemd1")
	sdMgr  = "org.freedesktop.systemd1.Manager."
	sdUnit = "org.freedesktop.systemd1.Unit."
	sdWait = 30 * time.Second
	sdPoll = 50 * time.Millisecond
)

// Systemd controls units through the systemd manager's D-Bus API (pure Go,
// no systemctl). The zero value dials the system bus on first use; set Conn
// to use another bus (tests run a private dbus-daemon).
type Systemd struct {
	Conn *dbus.Conn

	mu sync.Mutex
}

func (s *Systemd) conn() (*dbus.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Conn == nil {
		c, err := dbus.ConnectSystemBus()
		if err != nil {
			return nil, fmt.Errorf("connect system bus: %w", err)
		}
		s.Conn = c
	}
	return s.Conn, nil
}

func unitName(u string) string {
	if !strings.Contains(u, ".") {
		return u + ".service"
	}
	return u
}

func (s *Systemd) call(ctx context.Context, method string, store []any, args ...any) error {
	c, err := s.conn()
	if err != nil {
		return err
	}
	call := c.Object(sdDest, sdPath).CallWithContext(ctx, sdMgr+method, 0, args...)
	if call.Err != nil {
		return call.Err
	}
	if len(store) > 0 {
		return call.Store(store...)
	}
	return nil
}

func (s *Systemd) State(ctx context.Context, unit string) (UnitState, error) {
	name := unitName(unit)
	c, err := s.conn()
	if err != nil {
		return UnitState{}, err
	}
	var path dbus.ObjectPath
	if err := s.call(ctx, "LoadUnit", []any{&path}, name); err != nil {
		return UnitState{}, err
	}
	obj := c.Object(sdDest, path)
	prop := func(p string) (string, error) {
		v, err := obj.GetProperty(sdUnit + p)
		if err != nil {
			return "", err
		}
		str, _ := v.Value().(string)
		return str, nil
	}
	load, err := prop("LoadState")
	if err != nil {
		return UnitState{}, err
	}
	if load == "not-found" {
		return UnitState{}, nil
	}
	active, err := prop("ActiveState")
	if err != nil {
		return UnitState{}, err
	}
	st := UnitState{Exists: true, Active: active == "active"}
	var ufs string
	if err := s.call(ctx, "GetUnitFileState", []any{&ufs}, name); err == nil {
		st.Enabled = ufs
	} else if load == "masked" {
		st.Enabled = "masked"
	}
	if load == "masked" {
		st.Enabled = "masked"
	}
	return st, nil
}

func (s *Systemd) waitActive(ctx context.Context, unit string, want bool) error {
	ctx, cancel := context.WithTimeout(ctx, sdWait)
	defer cancel()
	for {
		st, err := s.State(ctx, unit)
		if err != nil {
			return err
		}
		if st.Active == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for %s active=%v", unit, want)
		case <-time.After(sdPoll):
		}
	}
}

func (s *Systemd) job(ctx context.Context, method, unit string, wantActive bool) error {
	var job dbus.ObjectPath
	if err := s.call(ctx, method, []any{&job}, unitName(unit), "replace"); err != nil {
		return err
	}
	return s.waitActive(ctx, unit, wantActive)
}

func (s *Systemd) Start(ctx context.Context, unit string) error {
	return s.job(ctx, "StartUnit", unit, true)
}
func (s *Systemd) Stop(ctx context.Context, unit string) error {
	return s.job(ctx, "StopUnit", unit, false)
}
func (s *Systemd) Restart(ctx context.Context, unit string) error {
	return s.job(ctx, "RestartUnit", unit, true)
}

func (s *Systemd) files(ctx context.Context, method string, unit string, args ...any) error {
	var carries bool
	var changes [][]any
	all := append([]any{[]string{unitName(unit)}}, args...)
	var store []any
	switch method {
	case "EnableUnitFiles":
		store = []any{&carries, &changes}
	default:
		store = []any{&changes}
	}
	if err := s.call(ctx, method, store, all...); err != nil {
		return err
	}
	return s.call(ctx, "Reload", nil)
}

func (s *Systemd) Enable(ctx context.Context, unit string) error {
	return s.files(ctx, "EnableUnitFiles", unit, false, true)
}
func (s *Systemd) Disable(ctx context.Context, unit string) error {
	return s.files(ctx, "DisableUnitFiles", unit, false)
}
func (s *Systemd) Mask(ctx context.Context, unit string) error {
	return s.files(ctx, "MaskUnitFiles", unit, false, true)
}
func (s *Systemd) Unmask(ctx context.Context, unit string) error {
	return s.files(ctx, "UnmaskUnitFiles", unit, false)
}
