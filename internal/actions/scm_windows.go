//go:build windows

package actions

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// SCM controls Windows services through the service control manager.
// "mask" is reported and implemented as Disabled (Windows has no mask);
// "unmask" restores Manual start.
type SCM struct{}

const scmWait = 30 * time.Second

func (SCM) with(unit string, access uint32, fn func(s *mgr.Service) error) error {
	m, err := connectSCM()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	h, err := windows.OpenService(m.Handle, windows.StringToUTF16Ptr(unit), access)
	if err != nil {
		return err
	}
	s := &mgr.Service{Name: unit, Handle: h}
	defer s.Close()
	return fn(s)
}

func connectSCM() (*mgr.Mgr, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, err
	}
	return &mgr.Mgr{Handle: h}, nil
}

func (c SCM) State(_ context.Context, unit string) (UnitState, error) {
	var st UnitState
	err := c.with(unit, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS, func(s *mgr.Service) error {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		q, err := s.Query()
		if err != nil {
			return err
		}
		st.Exists = true
		st.Active = q.State == svc.Running || q.State == svc.StartPending
		switch cfg.StartType {
		case mgr.StartAutomatic:
			st.Enabled = "enabled"
		case mgr.StartDisabled:
			st.Enabled = "disabled"
		default:
			st.Enabled = "manual"
		}
		return nil
	})
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return UnitState{}, nil
	}
	return st, err
}

func waitState(ctx context.Context, s *mgr.Service, want svc.State) error {
	ctx, cancel := context.WithTimeout(ctx, scmWait)
	defer cancel()
	for {
		q, err := s.Query()
		if err != nil {
			return err
		}
		if q.State == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for service state %d", want)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (c SCM) Start(ctx context.Context, unit string) error {
	return c.with(unit, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS, func(s *mgr.Service) error {
		if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return err
		}
		return waitState(ctx, s, svc.Running)
	})
}

func (c SCM) Stop(ctx context.Context, unit string) error {
	return c.with(unit, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS, func(s *mgr.Service) error {
		if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return err
		}
		return waitState(ctx, s, svc.Stopped)
	})
}

func (c SCM) Restart(ctx context.Context, unit string) error {
	if err := c.Stop(ctx, unit); err != nil {
		return err
	}
	return c.Start(ctx, unit)
}

func (c SCM) setStart(unit string, t uint32) error {
	return c.with(unit, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_CHANGE_CONFIG, func(s *mgr.Service) error {
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		cfg.StartType = t
		return s.UpdateConfig(cfg)
	})
}

func (c SCM) Enable(_ context.Context, unit string) error {
	return c.setStart(unit, mgr.StartAutomatic)
}
func (c SCM) Disable(_ context.Context, unit string) error {
	return c.setStart(unit, mgr.StartDisabled)
}
func (c SCM) Mask(_ context.Context, unit string) error   { return c.setStart(unit, mgr.StartDisabled) }
func (c SCM) Unmask(_ context.Context, unit string) error { return c.setStart(unit, mgr.StartManual) }
