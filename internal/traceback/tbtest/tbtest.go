// Package tbtest builds synthetic multi-host event streams in a real store for
// trace-back and chain tests. Nothing is mocked: events are sealed into
// per-agent hash chains and ingested.
package tbtest

import (
	"context"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// Fixture is a store plus per-agent chain heads.
type Fixture struct {
	T     *testing.T
	Store *store.Store
	Ctx   context.Context
	T0    time.Time // scenario start
	seq   map[string]uint64
	prev  map[string]string
}

// New opens a temp store; t0 is the scenario origin.
func New(t *testing.T, t0 time.Time) *Fixture {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, t.TempDir()+"/phylax.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &Fixture{T: t, Store: s, Ctx: ctx, T0: t0, seq: map[string]uint64{}, prev: map[string]string{}}
}

// Add appends one event for agent at t0+at.
func (f *Fixture) Add(agent string, at time.Duration, kind string, fields map[string]any) event.Event {
	f.T.Helper()
	if _, ok := f.seq[agent]; !ok {
		if err := f.Store.EnrollAgent(f.Ctx, agent, []byte("key-"+agent)); err != nil {
			f.T.Fatal(err)
		}
	}
	ev := event.Event{Agent: agent, Time: f.T0.Add(at), Kind: kind, Priority: event.PriorityHigh, Fields: fields}
	if err := ev.Seal(f.seq[agent], f.prev[agent]); err != nil {
		f.T.Fatal(err)
	}
	if _, err := f.Store.Ingest(f.Ctx, agent, []event.Event{ev}); err != nil {
		f.T.Fatal(err)
	}
	f.seq[agent], f.prev[agent] = ev.Seq, ev.Hash
	return ev
}

// Gap records a spool gap of lost events on agent at t0+at: the agent shed
// count events (class "shed"), and the gap record bridges them.
func (f *Fixture) Gap(agent string, at time.Duration, lost uint64) {
	f.T.Helper()
	from := f.seq[agent] + 1
	to := from + lost - 1
	ev := event.Event{Agent: agent, Time: f.T0.Add(at), Kind: store.KindGap, Priority: event.PriorityCritical,
		Fields: map[string]any{"from": from, "to": to, "count": lost, "class": "bulk"}}
	if err := ev.Seal(to, f.prev[agent]); err != nil {
		f.T.Fatal(err)
	}
	if _, err := f.Store.Ingest(f.Ctx, agent, []event.Event{ev}); err != nil {
		f.T.Fatal(err)
	}
	f.seq[agent], f.prev[agent] = ev.Seq, ev.Hash
}
