// Package storetest provides a seeded event store for module tests.
package storetest

import (
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// New opens a temporary store, groups evs by Agent, assigns Seq 1..n in the
// order given (per agent), seals each agent's chain, ingests them and returns
// the store (closed by t.Cleanup).
func New(t *testing.T, evs ...event.Event) *store.Store { panic("unimplemented: W1 Task 8a") }
