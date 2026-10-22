//go:build !windows && linux

package svcinstall

import "context"

// RunService reports that the process is not a Windows service.
func RunService(string, func(context.Context) error) (bool, error) { return false, nil }
