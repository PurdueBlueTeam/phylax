//go:build !linux

package integrity

import (
	"context"
	"errors"
)

// ScanProcess is Linux-only here; Windows uses ReadProcessMemory in the agent
// (not yet implemented).
func (g GoScanner) ScanProcess(context.Context, int) ([]RuleMatch, error) {
	return nil, errors.New("integrity: process memory scan not implemented on this platform")
}
