//go:build !linux && !windows

package deadman

// DefaultBackstop returns nil on platforms without a supported OS timer; the
// Manager then runs journal + in-process timer only.
func DefaultBackstop(c Command) Backstop { return nil }
