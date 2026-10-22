//go:build linux

package deadman

// DefaultBackstop is the OS timer for this platform.
func DefaultBackstop(c Command) Backstop { return &Systemd{Command: c} }
