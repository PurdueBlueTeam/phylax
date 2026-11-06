package plan

import "fmt"

// Expiry bounds (design: Execution engine, Expiry).
const (
	MinExpiresAfterSec = 60
	MaxExpiresAfterSec = 86400
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
	return nil
}
