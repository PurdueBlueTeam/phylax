package plan

import (
	"fmt"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Expiry bounds (design: Execution engine, Expiry).
const (
	MinExpiresAfterSec = 60
	MaxExpiresAfterSec = 86400
	// MaxGateUntilSec bounds gate: auto's shadow time.
	MaxGateUntilSec = 86400
)

// validateNode checks one node's own fields (used by the plan parser and the
// expiry and auto-gate options).
func validateNode(n Node) error {
	switch {
	case n.ExpiresAfterSec < 0:
		return fmt.Errorf("node %q: negative expires_after_sec", n.ID)
	case n.ExpiresAfterSec == 0:
	case n.ExpiresAfterSec < MinExpiresAfterSec || n.ExpiresAfterSec > MaxExpiresAfterSec:
		return fmt.Errorf("node %q: expires_after_sec must be 0 or %d-%d", n.ID, MinExpiresAfterSec, MaxExpiresAfterSec)
	}
	if n.Gate && n.ExpiresAfterSec > 0 {
		return fmt.Errorf("node %q: a gate cannot expire", n.ID)
	}
	if n.Until != nil {
		if !n.Gate {
			return fmt.Errorf("node %q: until is only valid on a gate", n.ID)
		}
		if n.Until.AfterSec < 0 || n.Until.AfterSec > MaxGateUntilSec {
			return fmt.Errorf("node %q: until.after_sec must be 0-%d", n.ID, MaxGateUntilSec)
		}
		if n.Until.AfterSec == 0 && n.Until.Probe == "" && n.Until.NoEvent == nil {
			return fmt.Errorf("node %q: until needs at least one condition", n.ID)
		}
		if n.Until.NoEvent != nil {
			if n.Until.NoEvent.Kind == "" {
				return fmt.Errorf("node %q: until.no_event.kind is empty", n.ID)
			}
			if _, ok := event.Lookup(n.Until.NoEvent.Kind); !ok {
				return fmt.Errorf("node %q: until.no_event.kind %q is not a declared event kind", n.ID, n.Until.NoEvent.Kind)
			}
		}
	}
	return nil
}
