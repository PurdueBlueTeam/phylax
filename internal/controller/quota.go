package controller

import (
	"context"
	"math"
	"slices"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// quotaSampleEvery is how often the controller re-reads the data disk's usage.
const quotaSampleEvery = 30 * time.Second

// startQuota samples the controller data disk until ctx ends. A change in the
// set of refused classes emits store.quota; refusing the high class raises the
// event's priority.
func (c *Controller) startQuota(ctx context.Context, every time.Duration) {
	if c.quota == nil {
		return
	}
	if every <= 0 {
		every = quotaSampleEvery
	}
	clk := c.clk
	if clk == nil {
		clk = realClock{}
	}
	var prev []event.Priority
	sample := func() {
		if err := c.quota.Sample(); err != nil {
			return
		}
		refused := store.Refused(c.quota.UsedPct())
		if slices.Equal(refused, prev) {
			return
		}
		prev = refused
		if err := c.emitQuota(ctx, refused); err != nil {
			c.log.Warn("cannot emit store.quota", "refused", quotaShed(refused), "err", err)
		}
	}
	sample()
	t := clk.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
		}
		sample()
	}
}

func (c *Controller) emitQuota(ctx context.Context, refused []event.Priority) error {
	prio := event.PriorityHigh
	switch {
	case len(refused) == 0:
		prio = event.PriorityNormal
	case slices.Contains(refused, event.PriorityHigh):
		prio = event.PriorityCritical
	}
	e, err := event.New(event.KindStoreQuota, event.StoreQuota{
		UsedPct: int(math.Round(c.quota.UsedPct())),
		Shed:    quotaShed(refused),
	})
	if err != nil {
		return err
	}
	e.Priority = prio
	_, err = c.EmitController(ctx, e)
	return err
}

func quotaShed(refused []event.Priority) []string {
	if len(refused) == 0 {
		return nil
	}
	out := make([]string, len(refused))
	for i, p := range refused {
		out[i] = p.String()
	}
	return out
}

// admitChunk applies the quota to a content-addressed transfer class. code is
// the wire error code the sender retries on later ("quota"); empty means the
// chunk may be accepted.
func (c *Controller) admitChunk(prio event.Priority) (bool, string) {
	if c.quota == nil || c.quota.AdmitChunk(prio) {
		return true, ""
	}
	return false, "quota"
}
