package store

import (
	"math"
	"sync/atomic"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Admit reports whether an event is stored when the data disk is pct full. A
// class may fill the quota only up to its limit. alert is true when the kind is
// alert-class and the priority is high or critical, i.e. the event becomes an
// alert row: it is always admitted (design: Event store and vault, Storage).
func Admit(pct float64, prio event.Priority, alert bool) bool {
	return alert || pct < float64(prio.AdmitPercent())
}

// Refused lists the classes refused at pct, lowest class first.
func Refused(pct float64) []event.Priority {
	var out []event.Priority
	for _, p := range []event.Priority{event.PriorityBulk, event.PriorityNormal, event.PriorityHigh, event.PriorityCritical} {
		if pct >= float64(p.AdmitPercent()) {
			out = append(out, p)
		}
	}
	return out
}

// Quota samples the controller data disk's usage.
type Quota struct {
	used func() (usedPct float64, err error)
	pct  atomic.Uint64 // math.Float64bits of the last successful sample
}

// NewQuota returns a quota that reads its usage through used.
func NewQuota(used func() (usedPct float64, err error)) *Quota {
	return &Quota{used: used}
}

// UsedPct returns the usage of the last successful sample.
func (q *Quota) UsedPct() float64 { return math.Float64frombits(q.pct.Load()) }

// Sample re-reads the usage. A failed read leaves the last good sample in
// force.
func (q *Quota) Sample() error {
	pct, err := q.used()
	if err != nil {
		return err
	}
	q.pct.Store(math.Float64bits(pct))
	return nil
}

// AdmitChunk reports whether a content-addressed transfer of the given class
// is accepted. A chunk is classed by the priority of the message it travels
// in (alert evidence is high; pcap slices, collected files, depot blobs and
// binaries are bulk).
func (q *Quota) AdmitChunk(prio event.Priority) bool {
	return Admit(q.UsedPct(), prio, false)
}

// SetQuota installs the store's quota; Ingest consults its last sample once
// per batch. A nil quota admits everything.
func (s *Store) SetQuota(q *Quota) { s.quota.Store(q) }
