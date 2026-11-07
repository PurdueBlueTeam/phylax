//go:build !linux && !windows

package svcinstall

import (
	"context"
	"errors"
)

type unsupported struct{}

func (unsupported) Install(context.Context, Spec) error {
	return errors.New("svcinstall: unsupported platform")
}
func (unsupported) Uninstall(context.Context, string) error {
	return errors.New("svcinstall: unsupported platform")
}
func (unsupported) Stop(context.Context, string) error {
	return errors.New("svcinstall: unsupported platform")
}
func (unsupported) Restart(context.Context, string) error {
	return errors.New("svcinstall: unsupported platform")
}

// New returns an installer that reports the platform as unsupported.
func New() Installer { return unsupported{} }

// RunService reports that the process is not a Windows service.
func RunService(string, func(context.Context) error, func() []string) (bool, error) {
	return false, nil
}
