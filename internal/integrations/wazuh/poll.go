package wazuh

import (
	"context"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// Poller imports new alerts as events, de-duplicating the overlap at the
// boundary so a re-query never yields an alert twice.
type Poller struct {
	C        *Client
	MinLevel int
	Limit    int
	since    time.Time
	seen     map[string]struct{}
}

// NewPoller starts at since.
func NewPoller(c *Client, since time.Time, minLevel int) *Poller {
	return &Poller{C: c, since: since, MinLevel: minLevel, seen: map[string]struct{}{}}
}

// Poll fetches new alerts. On error nothing is consumed.
func (p *Poller) Poll(ctx context.Context) ([]event.Event, error) {
	as, err := p.C.Alerts(ctx, p.since, p.MinLevel, p.Limit)
	if err != nil {
		return nil, err
	}
	var out []event.Event
	for _, a := range as {
		if _, dup := p.seen[a.ID]; dup {
			continue
		}
		out = append(out, a.ToEvent())
		if a.Time.After(p.since) {
			p.since = a.Time
			p.seen = map[string]struct{}{}
		}
		p.seen[a.ID] = struct{}{}
	}
	return out, nil
}
