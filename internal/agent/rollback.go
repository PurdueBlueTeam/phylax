package agent

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
)

var (
	rbMu       sync.Mutex
	rbRegistry = map[string]deadman.Handler{}
)

// RegisterRollbackHandler registers the dead-man rollback code for an entry
// kind. The executor registers its action handlers (typically from init) so
// both the running agent and `phylax agent rollback <id>` can use them.
func RegisterRollbackHandler(kind string, h deadman.Handler) {
	rbMu.Lock()
	defer rbMu.Unlock()
	rbRegistry[kind] = h
}

// RollbackHandlers returns a copy of the registered handlers.
func RollbackHandlers() map[string]deadman.Handler {
	rbMu.Lock()
	defer rbMu.Unlock()
	return maps.Clone(rbRegistry)
}

// RollbackOptions parameterise Rollback.
type RollbackOptions struct {
	// Handlers are merged over the registry.
	Handlers map[string]deadman.Handler
	// Backstop is the OS timer to disarm after a successful rollback (may be nil).
	Backstop deadman.Backstop
}

// Rollback is the target of the OS-level timer: it opens the dead-man journal
// in the agent's state directory and fires entry id as "os-timer". Firing is
// idempotent, so it is safe if the in-process timer already rolled back.
func Rollback(ctx context.Context, l Layout, id string, o RollbackOptions) (deadman.Entry, error) {
	if !deadman.ValidID(id) {
		return deadman.Entry{}, deadman.ErrBadID
	}
	hs := RollbackHandlers()
	maps.Copy(hs, o.Handlers)
	m, err := deadman.Open(l.DeadmanDir(), deadman.Options{Handlers: hs, Backstop: o.Backstop})
	if err != nil {
		return deadman.Entry{}, fmt.Errorf("agent: open dead-man journal: %w", err)
	}
	defer m.Close()
	return m.Fire(ctx, id, "os-timer")
}
