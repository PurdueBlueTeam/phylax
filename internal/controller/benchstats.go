package controller

import (
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/bench"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// benchStats are the controller's cumulative bench counters: what the ingest
// drain stores, per priority class and as event-to-commit latency, plus the
// gaps, the accepted hellos and the disconnected time. Every field is an
// atomic counter or a fixed-size histogram, so counting adds no lock and no
// allocation beyond one JSON marshal per stored event.
type benchStats struct {
	events, bytes                   [bench.NumClasses]atomic.Uint64
	lat                             [bench.NumClasses]bench.AtomicHist
	gapRecords, gapEvents, connects atomic.Uint64
	down                            bench.AtomicHist
}

// stored counts one stored (non-gap) event: its class, its JSON size and its
// age at the commit. skew is subtracted from the raw age, so it is the
// controller clock minus the agent clock at the last heartbeat; AgentStatus.
// ClockSkew has the opposite sign (agent minus controller), so drain negates
// it.
func (b *benchStats) stored(e event.Event, now time.Time, skew time.Duration) {
	class := int(e.Priority)
	if class < 0 || class >= bench.NumClasses {
		class = bench.NumClasses - 1
	}
	b.events[class].Add(1)
	// shortcut: one extra marshal per stored event, upgrade to the wire length
	// if the controller CPU shows it.
	if n, err := json.Marshal(e); err == nil {
		b.bytes[class].Add(uint64(len(n)))
	}
	age := now.Sub(e.Time) - skew
	if age < 0 {
		age = 0 // a skewed or future-dated event: never a negative latency
	}
	b.lat[class].Observe(age)
}

// gap counts one stored gap record and the events its range covers.
func (b *benchStats) gap(e event.Event) {
	b.gapRecords.Add(1)
	if from, ok := gapFrom(e); ok && e.Seq > from {
		b.gapEvents.Add(e.Seq - from)
	}
}

// counters is the cumulative snapshot the recorder turns into deltas. Commit is
// left zero here: the bench source fills it from the store.
func (b *benchStats) counters() bench.Counters {
	var c bench.Counters
	for i := 0; i < bench.NumClasses; i++ {
		c.Events[i] = b.events[i].Load()
		c.Bytes[i] = b.bytes[i].Load()
		c.Latency[i] = b.lat[i].Snapshot()
	}
	c.GapRecords = b.gapRecords.Load()
	c.GapEvents = b.gapEvents.Load()
	c.Connects = b.connects.Load()
	c.Down = b.down.Snapshot()
	return c
}
