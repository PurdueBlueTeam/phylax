//go:build windows

package deadman

// DefaultBackstop is the OS timer for this platform.
func DefaultBackstop(c Command) Backstop { return &Schtasks{Command: c} }
