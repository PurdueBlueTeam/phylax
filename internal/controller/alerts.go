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
			found, err := c.st.Events(ctx, store.Query{Agent: e.Agent, Kind: kind, From: t, To: t.Add(time.Nanosecond), Limit: 1})
			if err == nil && len(found) == 1 {
				k.Evidence = append(k.Evidence, evRef{found[0].Agent, found[0].Seq})
			}
		}
	}
	c.attributeHoneytoken(e, &k)
	raw, err := json.Marshal(k)
	if err != nil {
		return err
	}
	rule := fstr(e.Fields, "rule")
	if rule == "" {
		return fmt.Errorf("detect alert without a rule")
	}
	_, err = c.st.InsertAlert(ctx, store.AlertRow{Rule: rule, Host: e.Agent, Severity: SeverityLevel(fstr(e.Fields, "severity")),
		Time: e.Time, Keys: string(raw), Agent: e.Agent, Seq: e.Seq})
	return err
}
