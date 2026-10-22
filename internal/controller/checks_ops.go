package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
)

var _ ui.ChecksOps = (*WebOps)(nil)

type checkDetail struct {
	Class     string `json:"class"`
	Err       string `json:"err"`
	Mode      string `json:"mode"`
	Item      string `json:"item"`
	ElapsedMS int64  `json:"elapsed_ms"`
	ScorerOK  *bool  `json:"scorer_ok"`
}

func parseCheckDetail(s string) checkDetail {
	var d checkDetail
	_ = json.Unmarshal([]byte(s), &d)
	return d
}

func slaLevel(threshold, streak int) string {
	switch {
	case streak >= max(threshold-1, 1):
		return "critical"
	case streak >= max(threshold-2, 1):
		return "warn"
	}
	return "ok"
}

// Checks lists the stored probe results per service and vantage.
func (o *WebOps) Checks(ctx context.Context) (ui.ChecksView, error) {
	var v ui.ChecksView
	rows, err := o.c.st.Checks(ctx)
	if err != nil {
		return v, err
	}
	hub := o.c.checks
	th := hub.sla.Threshold()
	by := map[string]*ui.ServiceChecks{}
	for _, ck := range rows {
		sc := by[ck.Service]
		if sc == nil {
			sc = &ui.ServiceChecks{Service: ck.Service, Streak: hub.sla.Streak(ck.Service), Penalties: hub.sla.Penalties(ck.Service)}
			sc.Level = slaLevel(th, sc.Streak)
			by[ck.Service] = sc
		}
		hist, err := o.c.st.CheckHistory(ctx, ck.ID, 200)
		if err != nil {
			return v, err
		}
		perV := map[string][]store.CheckResult{}
		var order []string
		for _, r := range hist { // newest first
			if _, seen := perV[r.Vantage]; !seen {
				order = append(order, r.Vantage)
			}
			perV[r.Vantage] = append(perV[r.Vantage], r)
		}
		sort.Strings(order)
		if len(order) == 0 {
			sc.Checks = append(sc.Checks, ui.CheckSummary{ID: ck.ID, Kind: ck.Kind})
		}
		for _, vt := range order {
			rs := perV[vt]
			last := rs[0]
			d := parseCheckDetail(last.Detail)
			cs := ui.CheckSummary{ID: ck.ID, Kind: ck.Kind, Vantage: vt, OK: last.OK, Known: true, Class: d.Class, Err: d.Err,
				Time: last.Time, Elapsed: (time.Duration(d.ElapsedMS) * time.Millisecond).String(), Samples: len(rs)}
			up := 0
			for i, r := range rs {
				if r.OK {
					up++
				}
				if i < 20 {
					cs.Recent = append(cs.Recent, r.OK)
				}
			}
			cs.UpPercent = up * 100 / len(rs)
			sc.Checks = append(sc.Checks, cs)
		}
	}
	for _, sc := range by {
		v.Services = append(v.Services, *sc)
	}
	sort.Slice(v.Services, func(i, j int) bool { return v.Services[i].Service < v.Services[j].Service })
	if len(v.Services) > 0 {
		v.Note = fmt.Sprintf("SLA streaks count consecutive failed faithful probes per service (penalty at %d); sweep and auth-only runs are stored but do not count.", th)
	}
	return v, nil
}

// CheckHistory returns the stored results of one check, newest first.
func (o *WebOps) CheckHistory(ctx context.Context, id string) (ui.CheckHistoryView, error) {
	rows, err := o.c.st.Checks(ctx)
	if err != nil {
		return ui.CheckHistoryView{}, err
	}
	var ck *store.CheckRow
	for i := range rows {
		if rows[i].ID == id {
			ck = &rows[i]
		}
	}
	if ck == nil {
		return ui.CheckHistoryView{}, ui.ErrNotFound
	}
	hub := o.c.checks
	v := ui.CheckHistoryView{ID: ck.ID, Service: ck.Service, Kind: ck.Kind,
		Streak: hub.sla.Streak(ck.Service), Penalties: hub.sla.Penalties(ck.Service)}
	v.Level = slaLevel(hub.sla.Threshold(), v.Streak)
	hist, err := o.c.st.CheckHistory(ctx, id, 200)
	if err != nil {
		return v, err
	}
	for _, r := range hist {
		d := parseCheckDetail(r.Detail)
		v.Rows = append(v.Rows, ui.CheckHistoryRow{Time: r.Time, Vantage: r.Vantage, OK: r.OK, Class: d.Class, Err: d.Err,
			Mode: d.Mode, Item: d.Item, Elapsed: (time.Duration(d.ElapsedMS) * time.Millisecond).String()})
	}
	return v, nil
}
