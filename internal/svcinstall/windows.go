//go:build windows

package svcinstall

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type winInstaller struct{}

// New returns the Windows service installer.
func New() Installer { return winInstaller{} }

// Install registers an auto-start LocalSystem service whose recovery actions
// restart it forever, then starts it.
func (winInstaller) Install(_ context.Context, sp Spec) error {
	if err := sp.validate(); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	disp := sp.DisplayName
	if disp == "" {
		disp = sp.Name
	}
	s, err := m.CreateService(sp.Name, sp.Binary, mgr.Config{
		DisplayName: disp, Description: sp.Description, StartType: mgr.StartAutomatic,
	}, sp.Args...)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: time.Second}
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 86400); err != nil {
		return fmt.Errorf("recovery actions: %w", err)
	}
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("recovery on non-crash failures: %w", err)
	}
	return s.Start()
}

func (winInstaller) Uninstall(_ context.Context, name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	return s.Delete()
}

type winHandler struct {
	run func(context.Context) error
}

func (h winHandler) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		case err := <-done:
			// The agent ended on its own: exit non-zero so recovery restarts us.
			if err != nil && !errors.Is(err, context.Canceled) {
				return false, 1
			}
			return false, 1
		}
	}
}

// RunService runs run under the service control manager if the process was
// started as a Windows service, and reports true. Otherwise it returns false
// immediately and the caller runs in the foreground.
func RunService(name string, run func(context.Context) error) (bool, error) {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		return false, err
	}
	return true, svc.Run(strings.TrimSpace(name), winHandler{run: run})
}
