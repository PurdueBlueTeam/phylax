//go:build linux

package actions

import "context"

// DaemonReload runs systemd's Manager.Reload over D-Bus.
func (s *Systemd) DaemonReload(ctx context.Context) error {
	return s.call(ctx, "Reload", nil)
}
