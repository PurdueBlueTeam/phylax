package store

import (
	"math"
	"sync/atomic"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// QuotaLevel is the controller disk's shed level (design: Event store and
// vault, Quotas).
type QuotaLevel int

const (
	QuotaOK       QuotaLevel = iota
	QuotaBulk                // >= 90% used: refuse bulk events and bulk transfers
	QuotaEvidence            // >= 95%: also refuse alert evidence chunks and pcap slices
	QuotaCritical            // >= 98%: accept only high and critical events
)

func (l QuotaLevel) String() string {
	switch l {
	case QuotaOK:
		return "ok"
	case QuotaBulk:
		return "bulk"
	case QuotaEvidence:
		return "evidence"
	case QuotaCritical:
		return "critical"
	}
	return "unknown"
}

// Admit reports whether an event is stored at this level. alert is true when
// the kind is alert-class and the priority is high or critical, i.e. the event
// becomes an alert row: it is always admitted.
func (l QuotaLevel) Admit(prio event.Priority, alert bool) bool {
	if alert {
		return true
	}
	switch l {
	case QuotaOK:
		return true
	case QuotaBulk, QuotaEvidence:
		return prio != event.PriorityBulk
	case QuotaCritical:
		return prio == event.PriorityHigh || prio == event.PriorityCritical
	}
	return true
}

// AdmitChunk reports whether a content-addressed transfer of the given class
// ("bulk" | "evidence") is accepted.
func (l QuotaLevel) AdmitChunk(class string) bool {
	switch l {
	case QuotaOK:
		return true
	case QuotaBulk:
		return class == "evidence"
	default:
		return false
	}
}

// quotaHysteresis is how far usage must fall below a threshold before the
// level steps down.
const quotaHysteresis = 2.0

// Quota samples the controller data disk's usage. Rising crosses at 90/95/98;
// falling steps down only when usage is 2 points below the threshold.
type Quota struct {
	used  func() (usedPct float64, err error)
	level atomic.Int32
	pct   atomic.Uint64 // math.Float64bits of the last successful sample
}

// NewQuota returns a quota that reads its usage through used.
func NewQuota(used func() (usedPct float64, err error)) *Quota {
	return &Quota{used: used}
}

// Level returns the current level.
func (q *Quota) Level() QuotaLevel { return QuotaLevel(q.level.Load()) }

// UsedPct returns the usage of the last successful sample.
func (q *Quota) UsedPct() float64 { return math.Float64frombits(q.pct.Load()) }

// Sample re-reads the usage and returns the new level and whether it changed.
func (q *Quota) Sample() (QuotaLevel, bool) {
	pct, err := q.used()
	if err != nil {
		return q.Level(), false
	}
	q.pct.Store(math.Float64bits(pct))
	lvl := q.Level()
	start := lvl
	for {
		switch {
		case lvl == QuotaOK && pct >= 90:
			lvl = QuotaBulk
		case lvl == QuotaBulk && pct >= 95:
			lvl = QuotaEvidence
		case lvl == QuotaEvidence && pct >= 98:
			lvl = QuotaCritical
		case lvl == QuotaCritical && pct <= 95:
			lvl = QuotaEvidence
		case lvl == QuotaEvidence && pct <= 90:
			lvl = QuotaBulk
		case lvl == QuotaBulk && pct < 90-quotaHysteresis:
			lvl = QuotaOK
		default:
			q.level.Store(int32(lvl))
			return lvl, lvl != start
		}
	}
}

// SetQuota installs the store's quota; Ingest consults its level once per
// batch. A nil quota admits everything.
func (s *Store) SetQuota(q *Quota) { s.quota.Store(q) }
