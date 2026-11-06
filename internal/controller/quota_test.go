package controller

import (
	"context"
	"path/filepath"
	"slices"
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

func lastQuotaPriority(t *testing.T, c *Controller) event.Priority {
	t.Helper()
	evs, err := c.Store().Events(context.Background(), store.Query{Agent: ControllerAgent, Kind: event.KindStoreQuota, Limit: 10})
	if err != nil || len(evs) == 0 {
		t.Fatalf("store.quota events: %v %v", evs, err)
	}
	return evs[len(evs)-1].Priority
}

func TestQuotaEmitsOnCrossing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newTestController(t)
	defer c.Close()
	clk := newFakeClock(time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC))
	c.clk = clk
	pct := 40.0
	c.quota = store.NewQuota(func() (float64, error) { return pct, nil })
	go c.startQuota(ctx, time.Second)
	clk.waitOps(t, 1)
	if got := quotaEvents(t, c); len(got) != 0 {
		t.Fatalf("event at start with nothing refused: %+v", got)
	}

	pct = 51
	clk.Advance(time.Second)
	got := waitQuotaEvents(t, c, 1)
	if last := got[len(got)-1]; !slices.Equal(last.Shed, []string{"bulk"}) {
		t.Fatalf("bulk crossing: %+v", last)
	}
	if prio := lastQuotaPriority(t, c); prio != event.PriorityHigh {
		t.Fatalf("bulk priority: %v", prio)
	}

	pct = 76
	clk.Advance(time.Second)
	got = waitQuotaEvents(t, c, 2)
	if last := got[len(got)-1]; !slices.Equal(last.Shed, []string{"bulk", "normal"}) {
		t.Fatalf("normal crossing: %+v", last)
	}
	if prio := lastQuotaPriority(t, c); prio != event.PriorityHigh {
		t.Fatalf("normal priority: %v", prio)
	}

	pct = 91
	clk.Advance(time.Second)
	got = waitQuotaEvents(t, c, 3)
	if last := got[len(got)-1]; !slices.Equal(last.Shed, []string{"bulk", "normal", "high"}) {
		t.Fatalf("high crossing: %+v", last)
	}
	if prio := lastQuotaPriority(t, c); prio != event.PriorityCritical {
		t.Fatalf("high priority: %v", prio)
	}

	pct = 98
	clk.Advance(time.Second)
	got = waitQuotaEvents(t, c, 4)
	if last := got[len(got)-1]; !slices.Equal(last.Shed, []string{"bulk", "normal", "high", "critical"}) {
		t.Fatalf("critical crossing: %+v", last)
	}
	if prio := lastQuotaPriority(t, c); prio != event.PriorityCritical {
		t.Fatalf("critical priority: %v", prio)
	}

	pct = 10
	clk.Advance(time.Second)
	got = waitQuotaEvents(t, c, 5)
	if last := got[len(got)-1]; len(last.Shed) != 0 {
		t.Fatalf("recovery: %+v", last)
	}
	if prio := lastQuotaPriority(t, c); prio != event.PriorityNormal {
		t.Fatalf("recovery priority: %v", prio)
	}
}

func TestChunkRefusedAtClassLimits(t *testing.T) {
	c := newTestController(t)
	defer c.Close()
	pct := 60.0
	c.quota = store.NewQuota(func() (float64, error) { return pct, nil })
	if err := c.quota.Sample(); err != nil {
		t.Fatal(err)
	}
	for _, k := range []struct {
		prio event.Priority
		want bool
	}{
		{event.PriorityBulk, false},
		{event.PriorityNormal, true},
		{event.PriorityHigh, true},
		{event.PriorityCritical, true},
	} {
		if ok, code := c.admitChunk(k.prio); ok != k.want || (k.want && code != "") || (!k.want && code != "quota") {
			t.Errorf("%v at 60%%: %v %q", k.prio, ok, code)
		}
	}
	pct = 80
	if err := c.quota.Sample(); err != nil {
		t.Fatal(err)
	}
	for _, k := range []struct {
		prio event.Priority
		want bool
	}{
		{event.PriorityBulk, false},
		{event.PriorityNormal, false},
		{event.PriorityHigh, true},
		{event.PriorityCritical, true},
	} {
		if ok, _ := c.admitChunk(k.prio); ok != k.want {
			t.Errorf("%v at 80%%: %v", k.prio, ok)
		}
	}
	pct = 10
	if err := c.quota.Sample(); err != nil {
		t.Fatal(err)
	}
	for _, class := range []event.Priority{event.PriorityBulk, event.PriorityNormal, event.PriorityHigh, event.PriorityCritical} {
		if ok, code := c.admitChunk(class); !ok || code != "" {
			t.Errorf("%v at ok level: %v %q", class, ok, code)
		}
	}
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

// The controller installs its quota in the store: at the bulk class limit a
// bulk event is chain-verified and acknowledged past but not stored (one gap
// with reason controller_quota), while an alert-class event is always stored.
func TestQuotaInstalledAndSkipsBulk(t *testing.T) {
	ctx := context.Background()
	pct := 50.0
	c := newQuotaController(t, &pct)
	if err := c.Store().EnrollAgent(ctx, "h1", []byte("key-h1")); err != nil {
		t.Fatal(err)
	}
	pct = 60
	if err := c.quota.Sample(); err != nil {
		t.Fatal(err)
	}
	if got := store.Refused(c.quota.UsedPct()); !slices.Equal(got, []event.Priority{event.PriorityBulk}) {
		t.Fatalf("refused at 60%%: %v", got)
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
	if len(gaps) != 1 || gaps[0].From != 1 || gaps[0].To != 1 || gaps[0].Reason != "controller_quota" || gaps[0].Class != "bulk" {
		t.Fatalf("gaps %+v", gaps)
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
	if last := got[len(got)-1]; !slices.Contains(last.Shed, "high") {
		t.Fatalf("first sample: %+v", last)
	}
}
