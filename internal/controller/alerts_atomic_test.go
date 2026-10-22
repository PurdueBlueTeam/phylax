package controller

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func alertFields() map[string]any {
	return map[string]any{"rule": "W1.webshell", "title": "Web shell", "severity": "critical", "tier": 1, "message": "php written",
		"entities": map[string]any{"path": "/var/www/html/uploads/y.php"}}
}

func openAlerts(t *testing.T, c *Controller) []store.AlertRow {
	t.Helper()
	rows, err := c.Store().Alerts(context.Background(), "", 100)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// The alert row is written in the ingest transaction: when it cannot be
// written the events are not stored either (the agent resends), and a retry
// stores both exactly once.
func TestAlertQueueAtomicWithIngest(t *testing.T) {
	c := newBareController(t, filepath.Join(t.TempDir(), "data"))
	defer c.Close()
	ctx := context.Background()
	st := c.Store()
	if err := st.EnrollAgent(ctx, "ecom", []byte("k")); err != nil {
		t.Fatal(err)
	}
	ev := event.Event{Agent: "ecom", Time: time.Now(), Kind: "detect.alert", Priority: event.PriorityHigh, Fields: alertFields()}
	if err := ev.Seal(0, ""); err != nil {
		t.Fatal(err)
	}

	// Crash between "events written" and "queue row written".
	boom := errors.New("simulated crash while queueing the alert")
	st.SetIngestHook(func(ctx context.Context, tx *store.IngestTx, evs []event.Event) error {
		if err := c.ingestHook(ctx, tx, evs); err != nil {
			return err
		}
		return boom
	})
	ack, err := st.Ingest(ctx, "ecom", []event.Event{ev})
	if !errors.Is(err, boom) || ack.Seq != 0 {
		t.Fatalf("crashing ingest: ack %+v err %v", ack, err)
	}
	if n, _ := st.Count(ctx, "ecom"); n != 0 {
		t.Fatalf("event stored although its alert row was lost: %d events", n)
	}
	if rows := openAlerts(t, c); len(rows) != 0 {
		t.Fatalf("alert row survived the rolled-back ingest: %+v", rows)
	}

	// The agent resends; with the real hook both land together.
	st.SetIngestHook(c.ingestHook)
	if ack, err = st.Ingest(ctx, "ecom", []event.Event{ev}); err != nil || ack.Seq != 1 {
		t.Fatalf("retry: %+v %v", ack, err)
	}
	rows := openAlerts(t, c)
	if len(rows) != 1 || rows[0].Rule != "W1.webshell" || rows[0].Severity != 4 || rows[0].Seq != 1 {
		t.Fatalf("queue after retry: %+v", rows)
	}
	// A duplicate resend and an explicit replay do not duplicate the row.
	if _, err := st.Ingest(ctx, "ecom", []event.Event{ev}); err != nil {
		t.Fatal(err)
	}
	c.replayAgentAlerts(ctx)
	if rows := openAlerts(t, c); len(rows) != 1 {
		t.Fatalf("duplicate alert rows: %+v", rows)
	}
}

// Events stored before the hook existed (or whose row was lost) are queued
// again when the controller starts, once.
func TestAlertQueueReplayedOnStart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	c := newBareController(t, dir)
	ctx := context.Background()
	st := c.Store()
	st.EnrollAgent(ctx, "ecom", []byte("k"))
	st.SetIngestHook(nil) // the old behaviour: ingest and queue were separate steps
	var prev string
	for i := uint64(1); i <= 3; i++ {
		f := alertFields()
		if i == 2 {
			delete(f, "rule") // malformed: must be skipped, not retried forever
		}
		ev := event.Event{Agent: "ecom", Time: time.Now().Add(time.Duration(i) * time.Second), Kind: "detect.alert", Priority: event.PriorityHigh, Fields: f}
		if err := ev.Seal(i-1, prev); err != nil {
			t.Fatal(err)
		}
		prev = ev.Hash
		if _, err := st.Ingest(ctx, "ecom", []event.Event{ev}); err != nil {
			t.Fatal(err)
		}
	}
	if rows := openAlerts(t, c); len(rows) != 0 {
		t.Fatalf("setup: %+v", rows)
	}
	c.Close() // crash window: events stored, queue empty

	c2 := newBareControllerAt(t, dir, nil)
	if rows := openAlerts(t, c2); len(rows) != 2 {
		t.Fatalf("after restart: %d rows, want 2 (one malformed event skipped): %+v", len(rows), rows)
	}
	c3 := newBareControllerAt(t, dir, nil)
	if rows := openAlerts(t, c3); len(rows) != 2 {
		t.Fatalf("second restart duplicated rows: %d", len(rows))
	}
}
