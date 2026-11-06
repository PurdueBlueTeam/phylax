// Package storetest provides a seeded event store for module tests.
package storetest

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// defaultTime is where an event without a Time starts; one second is added
// per position so a seeded store keeps the order it was given.
var defaultTime = time.Date(2027, 2, 6, 9, 0, 0, 0, time.UTC)

// New opens a temporary store, groups evs by Agent, assigns Seq 1..n in the
// order given (per agent), seals each agent's chain, ingests them and returns
// the store (closed by t.Cleanup).
func New(t *testing.T, evs ...event.Event) *store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "phylax.db"))
	if err != nil {
		t.Fatalf("storetest: open: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	byAgent := map[string][]event.Event{}
	var agents []string
	for i, e := range evs {
		if _, ok := event.Lookup(e.Kind); !ok {
			t.Fatalf("storetest: event %d: undeclared kind %q", i, e.Kind)
		}
		if e.Time.IsZero() {
			e.Time = defaultTime.Add(time.Duration(i) * time.Second)
			evs[i] = e
		}
		if _, seen := byAgent[e.Agent]; !seen {
			agents = append(agents, e.Agent)
		}
		byAgent[e.Agent] = append(byAgent[e.Agent], e)
	}
	for _, agent := range agents {
		batch := byAgent[agent]
		if err := st.EnrollAgent(ctx, agent, []byte("storetest-key-"+agent)); err != nil {
			t.Fatalf("storetest: enroll %q: %v", agent, err)
		}
		var prevSeq uint64
		var prevHash string
		for i := range batch {
			if err := batch[i].Seal(prevSeq, prevHash); err != nil {
				t.Fatalf("storetest: seal %q: %v", agent, err)
			}
			prevSeq, prevHash = batch[i].Seq, batch[i].Hash
		}
		if _, err := st.Ingest(ctx, agent, batch); err != nil {
			t.Fatalf("storetest: ingest %q: %v", agent, err)
		}
	}
	return st
}
