package controller

import (
	"context"
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
