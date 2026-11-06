package store

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func TestAdmitAtClassLimits(t *testing.T) {
	for _, p := range []event.Priority{event.PriorityCritical, event.PriorityHigh, event.PriorityNormal, event.PriorityBulk} {
		limit := float64(p.AdmitPercent())
		if !Admit(limit-0.1, p, false) {
			t.Errorf("%v just below its limit is refused", p)
		}
		if Admit(limit, p, false) {
			t.Errorf("%v at its limit is admitted", p)
		}
		if !Admit(100, p, true) {
			t.Errorf("%v: an alert is never shed", p)
		}
	}
}

func TestRefusedClasses(t *testing.T) {
	for _, s := range []struct {
		pct  float64
		want []event.Priority
	}{
		{0, nil},
		{49.9, nil},
		{50, []event.Priority{event.PriorityBulk}},
		{75, []event.Priority{event.PriorityBulk, event.PriorityNormal}},
		{90, []event.Priority{event.PriorityBulk, event.PriorityNormal, event.PriorityHigh}},
		{97, []event.Priority{event.PriorityBulk, event.PriorityNormal, event.PriorityHigh, event.PriorityCritical}},
	} {
		if got := Refused(s.pct); !slices.Equal(got, s.want) {
			t.Errorf("%.1f%%: refused %v, want %v", s.pct, got, s.want)
		}
	}
}

// A class is admitted again as soon as use falls below its limit: no
// hysteresis state remains.
func TestQuotaSampleNoHysteresis(t *testing.T) {
	pct := 90.0
	q := NewQuota(func() (float64, error) { return pct, nil })
	if err := q.Sample(); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(Refused(q.UsedPct()), event.PriorityHigh) {
		t.Fatalf("high not refused at 90%%: %v", Refused(q.UsedPct()))
	}
	pct = 89.9
	if err := q.Sample(); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(Refused(q.UsedPct()), event.PriorityHigh) {
		t.Fatalf("high still refused at 89.9%%: %v", Refused(q.UsedPct()))
	}
}

// sealedAt appends one sealed event at an explicit priority.
func sealedAt(c *chain, kind string, prio event.Priority, fields map[string]any) event.Event {
	e := event.Event{Agent: c.agent, Time: t0.Add(time.Duration(c.seq) * time.Second), Kind: kind, Priority: prio, Fields: fields}
	if err := e.Seal(c.seq, c.hash); err != nil {
		panic(err)
	}
	c.seq, c.hash = e.Seq, e.Hash
	return e
}

// At each class limit an event of that class is chain-verified and
// acknowledged past but not stored, and the run is a gap with reason
// controller_quota and the refused class.
func TestIngestRefusesEachClassAtItsLimit(t *testing.T) {
	for _, prio := range []event.Priority{event.PriorityCritical, event.PriorityHigh, event.PriorityNormal, event.PriorityBulk} {
		t.Run(prio.String(), func(t *testing.T) {
			ctx := context.Background()
			s, _ := open(t)
			enroll(t, s, "h1")
			pct := float64(prio.AdmitPercent())
			q := NewQuota(func() (float64, error) { return pct, nil })
			if err := q.Sample(); err != nil {
				t.Fatal(err)
			}
			s.SetQuota(q)
			ch := &chain{agent: "h1"}
			ev := sealedAt(ch, "agent.health", prio, map[string]any{"i": 1})
			ack, err := s.Ingest(ctx, "h1", []event.Event{ev})
			if err != nil {
				t.Fatal(err)
			}
			if ack.Seq != 1 || ack.Accepted != 0 || ack.Skipped != 1 {
				t.Fatalf("ack %+v", ack)
			}
			if evs, _ := s.Events(ctx, Query{Agent: "h1", Limit: 10}); len(evs) != 0 {
				t.Fatalf("stored %+v", evs)
			}
			gaps, err := s.Gaps(ctx, "h1")
			if err != nil {
				t.Fatal(err)
			}
			if len(gaps) != 1 || gaps[0].From != 1 || gaps[0].To != 1 || gaps[0].Reason != "controller_quota" ||
				gaps[0].Class != prio.String() || gaps[0].Count != 1 {
				t.Fatalf("gaps %+v", gaps)
			}
		})
	}
}

func TestIngestSkipsRefusedAndKeepsChain(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "h1")
	q := NewQuota(func() (float64, error) { return 60, nil })
	if err := q.Sample(); err != nil {
		t.Fatal(err)
	}
	s.SetQuota(q)
	ch := &chain{agent: "h1"}
	batch := []event.Event{
		sealedAt(ch, "agent.health", event.PriorityNormal, map[string]any{"i": 1}),
		sealedAt(ch, "agent.health", event.PriorityBulk, map[string]any{"i": 2}),
		sealedAt(ch, "agent.health", event.PriorityBulk, map[string]any{"i": 3}),
		sealedAt(ch, "agent.health", event.PriorityHigh, map[string]any{"i": 4}),
	}
	ack, err := s.Ingest(ctx, "h1", batch)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Seq != 4 || ack.Accepted != 2 || ack.Skipped != 2 {
		t.Fatalf("ack %+v", ack)
	}
	evs, err := s.Events(ctx, Query{Agent: "h1", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || evs[0].Seq != 1 || evs[1].Seq != 4 {
		t.Fatalf("stored %+v", evs)
	}
	next := sealedAt(ch, "agent.health", event.PriorityNormal, map[string]any{"i": 5})
	if next.PrevHash != batch[3].Hash {
		t.Fatal("test chain did not continue from seq 4")
	}
	ack, err = s.Ingest(ctx, "h1", []event.Event{next})
	if err != nil || ack.Accepted != 1 || ack.Seq != 5 {
		t.Fatalf("following batch %+v %v", ack, err)
	}
	gaps, err := s.Gaps(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 1 || gaps[0].From != 2 || gaps[0].To != 3 || gaps[0].Reason != "controller_quota" ||
		gaps[0].Class != "bulk" || gaps[0].Count != 2 {
		t.Fatalf("gaps %+v", gaps)
	}
	n, dropped, err := s.GapTotals(ctx)
	if err != nil || n != 1 || dropped != 2 {
		t.Fatalf("gap totals %d %d %v", n, dropped, err)
	}
}

// A run that switches class is one gap record with class "mixed", as in the
// spool.
func TestIngestMixedClassRunIsOneGap(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "h1")
	q := NewQuota(func() (float64, error) { return 80, nil })
	if err := q.Sample(); err != nil {
		t.Fatal(err)
	}
	s.SetQuota(q)
	ch := &chain{agent: "h1"}
	batch := []event.Event{
		sealedAt(ch, "agent.health", event.PriorityNormal, map[string]any{"i": 1}),
		sealedAt(ch, "agent.health", event.PriorityBulk, map[string]any{"i": 2}),
		sealedAt(ch, "agent.health", event.PriorityNormal, map[string]any{"i": 3}),
		sealedAt(ch, "agent.health", event.PriorityHigh, map[string]any{"i": 4}),
	}
	ack, err := s.Ingest(ctx, "h1", batch)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Accepted != 1 || ack.Skipped != 3 {
		t.Fatalf("ack %+v", ack)
	}
	gaps, err := s.Gaps(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 1 || gaps[0].From != 1 || gaps[0].To != 3 || gaps[0].Class != "mixed" || gaps[0].Count != 3 {
		t.Fatalf("gaps %+v", gaps)
	}
}

func TestIngestNeverSkipsAlerts(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "h1")
	q := NewQuota(func() (float64, error) { return 99, nil })
	if err := q.Sample(); err != nil {
		t.Fatal(err)
	}
	s.SetQuota(q)
	ch := &chain{agent: "h1"}
	// agent.silent is alert-class, but bulk priority is not an alert row: shed.
	shed := sealedAt(ch, "agent.silent", event.PriorityBulk, map[string]any{"host": "h1"})
	// A critical alert-class event is stored.
	keep := sealedAt(ch, "plan.failed", event.PriorityCritical, map[string]any{"host": "h1"})
	ack, err := s.Ingest(ctx, "h1", []event.Event{shed, keep})
	if err != nil {
		t.Fatal(err)
	}
	if ack.Seq != 2 || ack.Accepted != 1 || ack.Skipped != 1 {
		t.Fatalf("ack %+v", ack)
	}
	evs, err := s.Events(ctx, Query{Agent: "h1", Limit: 10})
	if err != nil || len(evs) != 1 || evs[0].Seq != 2 {
		t.Fatalf("stored %+v %v", evs, err)
	}
}

func TestIngestSkippedEventStillChainChecked(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "h1")
	q := NewQuota(func() (float64, error) { return 60, nil })
	if err := q.Sample(); err != nil {
		t.Fatal(err)
	}
	s.SetQuota(q)
	ch := &chain{agent: "h1"}
	bad := sealedAt(ch, "agent.health", event.PriorityBulk, map[string]any{"i": 1})
	bad.Hash = "0000000000000000000000000000000000000000000000000000000000000000"
	_, err := s.Ingest(ctx, "h1", []event.Event{bad})
	if err == nil || !errors.Is(err, ErrBadHash) || !errors.Is(err, event.ErrChain) {
		t.Fatalf("want ErrBadHash chain error, got %v", err)
	}
	if evs, _ := s.Events(ctx, Query{Agent: "h1", Limit: 10}); len(evs) != 0 {
		t.Fatalf("bad event stored: %+v", evs)
	}
	if gaps, _ := s.Gaps(ctx, "h1"); len(gaps) != 0 {
		t.Fatalf("bad event recorded as a quota gap: %+v", gaps)
	}
}
