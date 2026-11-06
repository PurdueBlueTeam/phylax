package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func TestQuotaLevelAdmit(t *testing.T) {
	type c struct {
		l     QuotaLevel
		prio  event.Priority
		alert bool
		want  bool
	}
	for i, k := range []c{
		{QuotaOK, event.PriorityBulk, false, true},
		{QuotaBulk, event.PriorityBulk, false, false},
		{QuotaBulk, event.PriorityNormal, false, true},
		{QuotaEvidence, event.PriorityNormal, false, true},
		{QuotaCritical, event.PriorityNormal, false, false},
		{QuotaCritical, event.PriorityHigh, false, true},
		{QuotaCritical, event.PriorityCritical, false, true},
		{QuotaCritical, event.PriorityBulk, true, true}, // an alert is never shed
	} {
		if got := k.l.Admit(k.prio, k.alert); got != k.want {
			t.Errorf("case %d: %v", i, got)
		}
	}
	if QuotaBulk.AdmitChunk("bulk") || !QuotaBulk.AdmitChunk("evidence") || QuotaEvidence.AdmitChunk("evidence") {
		t.Fatal("chunk classes")
	}
}

func TestQuotaSampleHysteresis(t *testing.T) {
	pct := 50.0
	q := NewQuota(func() (float64, error) { return pct, nil })
	for _, s := range []struct {
		pct  float64
		want QuotaLevel
	}{{89, QuotaOK}, {90, QuotaBulk}, {95, QuotaEvidence}, {98, QuotaCritical}, {97, QuotaCritical}, {95.9, QuotaCritical},
		{95.5, QuotaCritical}, {95, QuotaEvidence}, {92.5, QuotaEvidence}, {87.9, QuotaOK}} {
		pct = s.pct
		if got, _ := q.Sample(); got != s.want {
			t.Errorf("%.1f: got %v want %v", s.pct, got, s.want)
		}
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

func TestIngestSkipsRefusedAndKeepsChain(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "h1")
	q := NewQuota(func() (float64, error) { return 91, nil })
	q.Sample()
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
	if len(gaps) != 1 || gaps[0].From != 2 || gaps[0].To != 3 || gaps[0].Reason != "controller quota" {
		t.Fatalf("gaps %+v", gaps)
	}
	n, dropped, err := s.GapTotals(ctx)
	if err != nil || n != 1 || dropped != 2 {
		t.Fatalf("gap totals %d %d %v", n, dropped, err)
	}
}

func TestIngestNeverSkipsAlerts(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t)
	enroll(t, s, "h1")
	q := NewQuota(func() (float64, error) { return 99, nil })
	q.Sample()
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
	q := NewQuota(func() (float64, error) { return 91, nil })
	q.Sample()
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
		t.Fatalf("bad event recorded as a quota skip: %+v", gaps)
	}
}
