package controller

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
)

var _ ui.HealthOps = (*WebOps)(nil)

// maxHealthySkew is the agent clock offset above which the page flags the
// agent: timestamps across hosts stop lining up in chains and reports.
const maxHealthySkew = 2 * time.Second

func moduleProblem(name, state string) string {
	if name == "config" {
		switch state {
		case "", "none", "applied":
			return ""
		}
		return "config: " + state
	}
	switch s := strings.ToLower(state); {
	case s == "", s == "ok", s == "running", s == "starting", s == "stopped", s == "disabled":
		return ""
	}
	return name + ": " + state
}

// Health gathers the platform self-health page: agents, link state, spool
// depth, store size, clock skew, dropped events and module errors.
func (o *WebOps) Health(ctx context.Context) (ui.HealthView, error) {
	c := o.c
	var v ui.HealthView
	now := c.now()
	problem := func(f string, a ...any) { v.Problems = append(v.Problems, fmt.Sprintf(f, a...)) }

	hosts := c.AgentHosts()
	sort.Strings(hosts)
	var connected int
	var spool, dropped uint64
	for _, h := range hosts {
		st, ok := c.AgentStatus(h)
		if !ok {
			continue
		}
		row := agentRow(st)
		ha := ui.HealthAgent{Host: h, State: row.State, LastSeen: st.LastSeen, ClockSkew: st.ClockSkew,
			SkewBad:    st.ClockSkew > maxHealthySkew || st.ClockSkew < -maxHealthySkew,
			SpoolDepth: st.SpoolDepth, Congestion: st.Congestion, Dropped: st.Drops, Modules: len(st.Modules)}
		if gaps, err := c.st.Gaps(ctx, h); err == nil {
			ha.GapRecords = len(gaps)
			for _, g := range gaps {
				if g.Class != "" || g.Reason == "shed" {
					ha.Dropped += g.Count
				}
			}
		}
		names := make([]string, 0, len(st.Modules))
		for n := range st.Modules {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if p := moduleProblem(n, st.Modules[n]); p != "" {
				ha.ModuleErrors = append(ha.ModuleErrors, p)
			}
		}
		if row.State == "connected" {
			connected++
		} else {
			problem("agent %s is %s (last seen %s)", h, row.State, st.LastSeen.UTC().Format("15:04:05Z"))
		}
		if ha.SkewBad {
			problem("agent %s clock is %s off the controller", h, st.ClockSkew.Round(time.Millisecond))
		}
		if len(ha.ModuleErrors) > 0 {
			problem("agent %s modules: %s", h, strings.Join(ha.ModuleErrors, "; "))
		}
		if ha.Dropped > 0 {
			problem("agent %s dropped %d events (see its gap records)", h, ha.Dropped)
		}
		spool += st.SpoolDepth
		dropped += ha.Dropped
		v.Agents = append(v.Agents, ha)
	}

	db, wal := c.st.DiskSize()
	events, audit, err := c.st.CountAll(ctx)
	if err != nil {
		return v, err
	}
	open, err := c.st.AlertQueueDepth(ctx)
	if err != nil {
		return v, err
	}
	gapRecs, shed, err := c.st.GapTotals(ctx)
	if err != nil {
		return v, err
	}
	schema, _ := c.st.SchemaVersion(ctx)
	epoch, _ := c.st.Epoch(ctx)

	team := "not set (config team)"
	if c.cfg.Team > 0 {
		team = fmt.Sprintf("%02d", c.cfg.Team)
	}
	v.Platform = []ui.KV{
		{Key: "Version", Value: orDash(c.opt.Version)},
		{Key: "Controller time", Value: now.UTC().Format("2006-01-02 15:04:05Z")},
		{Key: "Go", Value: runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH},
		{Key: "Agents connected", Value: fmt.Sprintf("%d of %d", connected, len(v.Agents))},
		{Key: "Total spool depth", Value: fmt.Sprint(spool)},
		{Key: "Team number", Value: team},
		{Key: "Alerts held in memory", Value: fmt.Sprint(len(c.Alerts()))},
	}
	v.Store = []ui.KV{
		{Key: "Database", Value: humanBytes(db)},
		{Key: "WAL", Value: humanBytes(wal)},
		{Key: "Schema version", Value: fmt.Sprint(schema)},
		{Key: "Epoch", Value: fmt.Sprint(epoch)},
		{Key: "Stored events", Value: fmt.Sprint(events)},
		{Key: "Audit entries", Value: fmt.Sprint(audit)},
		{Key: "Open alerts (queue depth)", Value: fmt.Sprint(open)},
		{Key: "Gap records", Value: fmt.Sprintf("%d (%d events shed)", gapRecs, shed)},
	}
	if wal > 256<<20 {
		problem("the store WAL is %s: checkpointing is not keeping up", humanBytes(wal))
	}
	if open > 500 {
		problem("%d open alerts: the queue needs triage", open)
	}
	if c.cfg.Team == 0 {
		problem("no team number configured: IR and inject drafts are disabled")
	}
	return v, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// Audit returns one page of the operator audit log, filtered by operator and
// action, newest first; Next is the cursor for the older page.
func (o *WebOps) Audit(ctx context.Context, q ui.AuditQuery) (ui.AuditPageView, error) {
	rows, next, err := o.c.st.AuditPage(ctx, store.AuditFilter{Actor: q.Actor, Action: q.Action, Before: q.Before, Limit: q.Limit})
	if err != nil {
		return ui.AuditPageView{}, err
	}
	v := ui.AuditPageView{Next: next, Query: q}
	for _, r := range rows {
		v.Rows = append(v.Rows, ui.AuditRowView{ID: r.ID, Time: r.Time, Actor: r.Actor, Action: r.Action, Remote: r.Remote, Detail: r.Detail})
	}
	if v.Actors, v.Actions, err = o.c.st.AuditFacets(ctx); err != nil {
		return v, err
	}
	return v, nil
}
