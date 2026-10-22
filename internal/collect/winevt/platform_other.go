//go:build !windows

package winevt

import (
	"context"
	"errors"
)

const platformSupported = false

// platformOpen is the non-Windows stub: there is no event log to read.
func platformOpen(context.Context, Channel, string, bool) (Source, error) {
	return nil, errors.New("winevt: Windows event log is not available on this platform")
}

// platformProbe is the non-Windows stub: Sysmon (Windows) is never present.
func platformProbe([]string) (SysmonInfo, error) { return SysmonInfo{}, nil }
