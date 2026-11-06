package controller

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func quotaEvents(t *testing.T, c *Controller) []event.StoreQuota {
	t.Helper()
	ctx := context.Background()
	evs, err := c.Store().Events(ctx, store.Query{Agent: ControllerAgent, Kind: event.KindStoreQuota, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	out := make([]event.StoreQuota, 0, len(evs))
	for _, e := range evs {
		v, err := event.Decode[event.StoreQuota](e, event.KindStoreQuota)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

func waitQuotaEvents(t *testing.T, c *Controller, n int) []event.StoreQuota {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := quotaEvents(t, c)
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("want %d store.quota events, have %+v", n, got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestQuotaEmitsOnCrossing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newTestController(t)
	defer c.Close()
	clk := newFakeClock(time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC))
	c.clk = clk
	pct := 50.0
	c.quota = store.NewQuota(func() (float64, error) { return pct, nil })
	go c.startQuota(ctx, time.Second)
	clk.waitOps(t, 1)

	pct = 91
	clk.Advance(time.Second)
	got := waitQuotaEvents(t, c, 1)
	if last := got[len(got)-1]; last.Level != "bulk" || !shedHas(last, "bulk") {
		t.Fatalf("bulk crossing: %+v", last)
	}
	evs, err := c.Store().Events(ctx, store.Query{Agent: ControllerAgent, Kind: event.KindStoreQuota, Limit: 10})
	if err != nil || len(evs) == 0 || evs[len(evs)-1].Priority != event.PriorityHigh {
		t.Fatalf("bulk priority: %+v %v", evs, err)
	}

	pct = 98.5
	clk.Advance(time.Second)
	got = waitQuotaEvents(t, c, 2)
	if last := got[len(got)-1]; last.Level != "critical" || !shedHas(last, "normal") {
		t.Fatalf("critical crossing: %+v", last)
	}
	evs, _ = c.Store().Events(ctx, store.Query{Agent: ControllerAgent, Kind: event.KindStoreQuota, Limit: 10})
	if evs[len(evs)-1].Priority != event.PriorityCritical {
		t.Fatalf("critical priority: %+v", evs[len(evs)-1])
	}

	pct = 10
	clk.Advance(time.Second)
	got = waitQuotaEvents(t, c, 3)
	if last := got[len(got)-1]; last.Level != "ok" || len(last.Shed) != 0 {
		t.Fatalf("recovery: %+v", last)
	}
	evs, _ = c.Store().Events(ctx, store.Query{Agent: ControllerAgent, Kind: event.KindStoreQuota, Limit: 10})
	if evs[len(evs)-1].Priority != event.PriorityNormal {
		t.Fatalf("recovery priority: %+v", evs[len(evs)-1])
	}
}

func TestChunkRefusedAtEvidenceLevel(t *testing.T) {
	c := newTestController(t)
	defer c.Close()
	pct := 96.0
	c.quota = store.NewQuota(func() (float64, error) { return pct, nil })
	c.quota.Sample()
	for _, class := range []string{"evidence", "bulk"} {
		if ok, code := c.admitChunk(class); ok || code != "quota" {
			t.Errorf("%s at evidence level: %v %q", class, ok, code)
		}
	}
	pct = 10
	c.quota.Sample()
	for _, class := range []string{"evidence", "bulk"} {
		if ok, code := c.admitChunk(class); !ok || code != "" {
			t.Errorf("%s at ok level: %v %q", class, ok, code)
		}
	}
}

func shedHas(s event.StoreQuota, class string) bool {
	for _, c := range s.Shed {
		if c == class {
			return true
		}
	}
	return false
}

// newQuotaController builds a controller whose data-disk usage is pct, so a
// test can drive the installed quota without filling a filesystem.
func newQuotaController(t *testing.T, pct *float64) *Controller {
	t.Helper()
	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: filepath.Join(t.TempDir(), "data")}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := New(context.Background(), cfg, Options{QuotaUsed: func() (float64, error) { return *pct, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// The controller installs its quota in the store: at the bulk level a bulk
// event is chain-verified and acknowledged past but not stored (one
// quota_skips row), while an alert-class event is always stored.
func TestQuotaInstalledAndSkipsBulk(t *testing.T) {
	ctx := context.Background()
	pct := 50.0
	c := newQuotaController(t, &pct)
	if err := c.Store().EnrollAgent(ctx, "h1", []byte("key-h1")); err != nil {
		t.Fatal(err)
	}
	pct = 91
	if lvl, changed := c.quota.Sample(); lvl != store.QuotaBulk || !changed {
		t.Fatalf("sample: %v changed=%v", lvl, changed)
	}
	at := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
	bulk := event.Event{Agent: "h1", Time: at, Kind: "agent.health", Priority: event.PriorityBulk,
		Fields: map[string]any{"host": "h1"}}
	if err := bulk.Seal(0, ""); err != nil {
		t.Fatal(err)
	}
	alert := event.Event{Agent: "h1", Time: at.Add(time.Second), Kind: "agent.silent", Priority: event.PriorityHigh,
		Fields: map[string]any{"host": "h1"}}
	if err := alert.Seal(bulk.Seq, bulk.Hash); err != nil {
		t.Fatal(err)
	}
	ack, err := c.Store().Ingest(ctx, "h1", []event.Event{bulk, alert})
	if err != nil {
		t.Fatal(err)
	}
	if ack.Seq != 2 || ack.Accepted != 1 || ack.Skipped != 1 {
		t.Fatalf("ack %+v", ack)
	}
	evs, err := c.Store().Events(ctx, store.Query{Agent: "h1", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].Seq != 2 || evs[0].Kind != "agent.silent" {
		t.Fatalf("stored %+v", evs)
	}
	gaps, err := c.Store().Gaps(ctx, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 1 || gaps[0].From != 1 || gaps[0].To != 1 || gaps[0].Reason != "controller quota" {
		t.Fatalf("quota_skips rows %+v", gaps)
	}
}

// The first sample happens at start, not one interval later.
func TestQuotaFirstSampleImmediate(t *testing.T) {
	pct := 91.0
	c := newQuotaController(t, &pct)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.clk = newFakeClock(time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC))
	go c.startQuota(ctx, time.Hour)
	got := waitQuotaEvents(t, c, 1)
	if last := got[len(got)-1]; last.Level != "bulk" || !shedHas(last, "bulk") {
		t.Fatalf("first sample: %+v", last)
	}
}
