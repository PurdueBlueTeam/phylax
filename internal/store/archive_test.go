package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func openArchiveStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "phylax.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sealEvent(t *testing.T, e event.Event, prevSeq uint64, prevHash string) event.Event {
	t.Helper()
	if err := e.Seal(prevSeq, prevHash); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestArchiveAgentMovesChain(t *testing.T) {
	ctx := context.Background()
	s := openArchiveStore(t)
	if err := s.EnrollAgent(ctx, "h1", []byte("keyA")); err != nil {
		t.Fatal(err)
	}
	prevSeq, prevHash := uint64(0), ""
	for i := 0; i < 3; i++ {
		e := sealEvent(t, event.Event{Agent: "h1", Time: time.Now().UTC(), Kind: "test.ev",
			Priority: event.PriorityNormal, Fields: map[string]any{"i": i}}, prevSeq, prevHash)
		if _, err := s.Ingest(ctx, "h1", []event.Event{e}); err != nil {
			t.Fatal(err)
		}
		prevSeq, prevHash = e.Seq, e.Hash
	}
	gap, err := event.New(KindGap, event.SpoolGap{From: 4, To: 5, Count: 2, Class: "bulk"})
	if err != nil {
		t.Fatal(err)
	}
	gap.Agent, gap.Time, gap.Seq, gap.PrevHash = "h1", time.Now().UTC(), 6, prevHash
	gap.Hash, err = gap.ComputeHash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(ctx, "h1", []event.Event{gap}); err != nil {
		t.Fatal(err)
	}
	prevSeq, prevHash = gap.Seq, gap.Hash

	if _, err := s.InsertAlert(ctx, AlertRow{Rule: "test.rule", Host: "h1", Time: time.Now().UTC(), Agent: "h1"}); err != nil {
		t.Fatal(err)
	}
	before, err := s.Count(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	var gapsBefore int
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM gaps WHERE agent='h1'`).Scan(&gapsBefore); err != nil {
		t.Fatal(err)
	}

	archived, err := s.ArchiveAgent(ctx, "h1", []byte("keyB"))
	if err != nil {
		t.Fatal(err)
	}
	if archived != "h1~1" {
		t.Fatalf("archived as %q, want h1~1", archived)
	}
	old, err := s.Agent(ctx, archived)
	if err != nil {
		t.Fatal(err)
	}
	if string(old.PubKey) != "keyA" || old.LastSeq != prevSeq || old.LastHash != prevHash {
		t.Fatalf("archived agent = key %q last_seq %d hash %q, want keyA/%d/%s",
			old.PubKey, old.LastSeq, old.LastHash, prevSeq, prevHash)
	}
	if n, err := s.Count(ctx, archived); err != nil || n != before {
		t.Fatalf("archived events = %d, %v; want %d", n, err, before)
	}
	var gapsAfter int
	if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM gaps WHERE agent=?`, archived).Scan(&gapsAfter); err != nil {
		t.Fatal(err)
	}
	if gapsAfter != gapsBefore || gapsAfter != 1 {
		t.Fatalf("archived gaps = %d, want %d (1)", gapsAfter, gapsBefore)
	}
	alerts, err := s.Alerts(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Agent != archived || alerts[0].Host != "h1" {
		t.Fatalf("alerts after archive = %+v, want agent %q host h1", alerts, archived)
	}

	fresh, err := s.Agent(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if string(fresh.PubKey) != "keyB" || fresh.LastSeq != 0 || fresh.LastHash != "" {
		t.Fatalf("reset agent = key %q last_seq %d hash %q, want keyB/0/empty", fresh.PubKey, fresh.LastSeq, fresh.LastHash)
	}
	first := sealEvent(t, event.Event{Agent: "h1", Time: time.Now().UTC(), Kind: "test.ev",
		Priority: event.PriorityNormal, Fields: map[string]any{"fresh": json.Number("1")}}, 0, "")
	if _, err := s.Ingest(ctx, "h1", []event.Event{first}); err != nil {
		t.Fatalf("fresh chain from seq 1: %v", err)
	}

	second, err := s.ArchiveAgent(ctx, "h1", []byte("keyC"))
	if err != nil {
		t.Fatal(err)
	}
	if second != "h1~2" {
		t.Fatalf("second archive as %q, want h1~2", second)
	}
	if _, err := s.ArchiveAgent(ctx, "ghost", []byte("keyD")); !errors.Is(err, ErrUnknownAgent) {
		t.Fatalf("archive unknown agent err = %v, want ErrUnknownAgent", err)
	}
}
