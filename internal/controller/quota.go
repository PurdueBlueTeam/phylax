package controller

import (
	"context"
	"math"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// quotaSampleEvery is how often the controller re-reads the data disk's usage.
const quotaSampleEvery = 30 * time.Second

// startQuota samples the controller data disk until ctx ends. A level change
// emits store.quota; the critical level raises the event's priority.
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
	t := clk.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
		}
		lvl, changed := c.quota.Sample()
		if !changed {
			continue
		}
		if err := c.emitQuota(ctx, lvl); err != nil {
			c.log.Warn("cannot emit store.quota", "level", lvl.String(), "err", err)
		}
	}
}

func (c *Controller) emitQuota(ctx context.Context, lvl store.QuotaLevel) error {
	prio := event.PriorityHigh
	switch lvl {
	case store.QuotaOK:
		prio = event.PriorityNormal
	case store.QuotaCritical:
		prio = event.PriorityCritical
	}
	e, err := event.New(event.KindStoreQuota, event.StoreQuota{
		Level:   lvl.String(),
		UsedPct: int(math.Round(c.quota.UsedPct())),
		Shed:    quotaShed(lvl),
	})
	if err != nil {
		return err
	}
	e.Priority = prio
	_, err = c.EmitController(ctx, e)
	return err
}

func quotaShed(lvl store.QuotaLevel) []string {
	switch lvl {
	case store.QuotaBulk:
		return []string{"bulk"}
	case store.QuotaEvidence:
		return []string{"bulk", "evidence"}
	case store.QuotaCritical:
		return []string{"bulk", "evidence", "normal"}
	}
	return nil
}

// admitChunk applies the quota to a content-addressed transfer class. code is
// the wire error code the sender retries on later ("quota"); empty means the
// chunk may be accepted.
func (c *Controller) admitChunk(class string) (bool, string) {
	if c.quota == nil || c.quota.Level().AdmitChunk(class) {
		return true, ""
	}
	return false, "quota"
}
