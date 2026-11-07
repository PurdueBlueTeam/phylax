package svcinstall

import (
	"context"
	"fmt"
)

// Stop stops the unit. systemd returns only once the unit is stopped, and an
// explicit stop does not trigger Restart=always.
func (s *Systemd) Stop(ctx context.Context, name string) error {
	if !validName(name) {
		return fmt.Errorf("svcinstall: bad service name %q", name)
	}
	return s.run(ctx, "stop", name+".service")
}

// Restart starts or restarts the unit.
func (s *Systemd) Restart(ctx context.Context, name string) error {
	if !validName(name) {
		return fmt.Errorf("svcinstall: bad service name %q", name)
	}
	return s.run(ctx, "restart", name+".service")
}
