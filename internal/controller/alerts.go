package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// kindDetectAlert is the event an agent's detect module emits per alert.
const kindDetectAlert = "detect.alert"

// recordAgentAlerts copies stored detect.alert events (seq <= stored) into
// the operator alert queue. It never fails ingest: a problem is logged.
func (c *Controller) recordAgentAlerts(ctx context.Context, run []event.Event, stored uint64) {
	for _, e := range run {
		if e.Kind != kindDetectAlert || e.Seq > stored {
			continue
		}
		if err := c.recordAgentAlert(ctx, e); err != nil {
			c.log.Error("cannot queue detect alert", "agent", e.Agent, "seq", e.Seq, "err", err)
		}
	}
}

func fstr(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func (c *Controller) recordAgentAlert(ctx context.Context, e event.Event) error {
	row, err := agentAlertRow(e, func(kind string, t time.Time) (uint64, bool) {
		found, err := c.st.Events(ctx, store.Query{Agent: e.Agent, Kind: kind, From: t, To: t.Add(time.Nanosecond), Limit: 1})
		if err != nil || len(found) != 1 {
			return 0, false
		}
		return found[0].Seq, true
	})
	if err != nil {
		return err
	}
	_, err = c.st.InsertAlertOnce(ctx, row)
	return err
}

// ingestHook runs inside the store's ingest transaction (store.SetIngestHook):
// the alert-queue rows and check results derived from newly stored events
// commit atomically with the events. Events it cannot use are skipped and
// logged, never failed, so one malformed event cannot block an agent; a
// database error rolls the batch back and the agent resends it.
func (c *Controller) ingestHook(ctx context.Context, tx *store.IngestTx, evs []event.Event) error {
	for _, e := range evs {
		switch e.Kind {
		case kindDetectAlert:
			row, err := agentAlertRow(e, func(kind string, t time.Time) (uint64, bool) {
				seq, ok, err := tx.FindEventAt(e.Agent, kind, t)
				return seq, ok && err == nil
			})
			if err != nil {
				c.log.Error("cannot queue detect alert", "agent", e.Agent, "seq", e.Seq, "err", err)
				continue
			}
			if _, err := tx.InsertAlertOnce(row); err != nil {
				return err
			}
		case kindVantageCheck:
			if cr, ok := c.checks.resultFromEvent(e); ok {
				if err := tx.RecordCheck(cr); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// afterIngest runs once a batch is durably stored: in-memory consumers of
// derived data (SLA streaks) see only committed results.
func (c *Controller) afterIngest(run []event.Event, stored uint64) {
	for _, e := range run {
		if e.Kind == kindVantageCheck && e.Seq <= stored {
			c.checks.observeEvent(e)
		}
	}
}

// replayAgentAlerts queues every stored detect.alert event that has no queue
// row (a crash window from before the ingest hook existed, or a row removed
// by hand). It is idempotent and runs on start.
func (c *Controller) replayAgentAlerts(ctx context.Context) {
	evs, err := c.st.UnqueuedEvents(ctx, kindDetectAlert, 5000)
	if err != nil {
		c.log.Error("alert replay failed", "err", err)
		return
	}
	n := 0
	for _, e := range evs {
		if err := c.recordAgentAlert(ctx, e); err != nil {
			c.log.Error("cannot queue detect alert", "agent", e.Agent, "seq", e.Seq, "err", err)
			continue
		}
		n++
	}
	if n > 0 {
		c.log.Info("queued stored detect alerts missing from the queue", "count", n)
	}
}

// agentAlertRow builds the queue row for a stored detect.alert event. find
// resolves a matched event (kind and exact time) to its stored seq.
func agentAlertRow(e event.Event, find func(kind string, t time.Time) (uint64, bool)) (store.AlertRow, error) {
	k := alertKeys{Title: fstr(e.Fields, "title"), Message: fstr(e.Fields, "message"), Entities: map[string]string{}}
	if t, ok := e.Fields["tier"].(json.Number); ok {
		n, _ := t.Int64()
		k.Tier = int(n)
	} else if t, ok := e.Fields["tier"].(float64); ok {
		k.Tier = int(t)
	}
	if ents, ok := e.Fields["entities"].(map[string]any); ok {
		for n, v := range ents {
			if s, ok := v.(string); ok {
				k.Entities[n] = s
			}
		}
	}
	if at, ok := e.Fields["attack"].([]any); ok {
		for _, v := range at {
			if s, ok := v.(string); ok {
				k.Attack = append(k.Attack, s)
			}
		}
	}
	// The alert event itself first (it embeds the matched events), then each
	// matched event that can be found in the store: the last one seeds a
	// trace-back.
	k.Evidence = append(k.Evidence, evRef{e.Agent, e.Seq})
	if evs, ok := e.Fields["evidence"].([]any); ok {
		for _, v := range evs {
			m, _ := v.(map[string]any)
			kind, ts := fstr(m, "kind"), fstr(m, "time")
			t, err := time.Parse(time.RFC3339Nano, ts)
			if err != nil || kind == "" {
				continue
			}
			if seq, ok := find(kind, t); ok {
				k.Evidence = append(k.Evidence, evRef{e.Agent, seq})
			}
		}
	}
	raw, err := json.Marshal(k)
	if err != nil {
		return store.AlertRow{}, err
	}
	rule := fstr(e.Fields, "rule")
	if rule == "" {
		return store.AlertRow{}, fmt.Errorf("detect alert without a rule")
	}
	return store.AlertRow{Rule: rule, Host: e.Agent, Severity: SeverityLevel(fstr(e.Fields, "severity")),
		Time: e.Time, Keys: string(raw), Agent: e.Agent, Seq: e.Seq}, nil
}
