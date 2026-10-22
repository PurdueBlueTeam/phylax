package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/chains"
	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
)

// WebOps implements ui.Ops on a Controller: the read models and actions behind
// the operator pages.
type WebOps struct {
	c        *Controller
	plansDir string
	chainCfg chains.Config

	traceMu sync.Mutex // one chain build at a time

	smu      sync.Mutex
	est      *scorer.Estimator
	sla      *scorer.SLATracker
	services func() []string
}

var _ ui.Ops = (*WebOps)(nil)

// NewWebOps builds the UI backend. plansDir is the plan template directory
// (may be empty); cc configures trace-back (agent clock offsets are filled in
// from heartbeats when cc.Offset is nil).
func NewWebOps(c *Controller, plansDir string, cc chains.Config) *WebOps {
	o := &WebOps{c: c, plansDir: plansDir, chainCfg: cc}
	if o.chainCfg.Offset == nil {
		o.chainCfg.Offset = func(agent string) time.Duration {
			st, ok := c.AgentStatus(agent)
			if !ok {
				return 0
			}
			return st.ClockSkew
		}
	}
	return o
}

// SetScorer feeds the dashboard's round clock and SLA streaks. Until it is
// called (or when est has seen no bursts and there are no services) the
// dashboard says "no scorer data".
func (o *WebOps) SetScorer(est *scorer.Estimator, sla *scorer.SLATracker, services func() []string) {
	o.smu.Lock()
	o.est, o.sla, o.services = est, sla, services
	o.smu.Unlock()
}

// ---- severity ----

var sevNames = []string{"info", "low", "medium", "high", "critical"}

func sevName(n int) string {
	if n < 0 || n >= len(sevNames) {
		return "info"
	}
	return sevNames[n]
}

// SeverityLevel maps a rule severity name to the stored level.
func SeverityLevel(s string) int {
	for i, n := range sevNames {
		if strings.EqualFold(s, n) {
			return i
		}
	}
	return 0
}

// alertKeys is the JSON document kept in alerts.keys.
type alertKeys struct {
	Title    string            `json:"title,omitempty"`
	Message  string            `json:"message,omitempty"`
	Tier     int               `json:"tier,omitempty"`
	Attack   []string          `json:"attack,omitempty"`
	Entities map[string]string `json:"entities,omitempty"`
	Evidence []evRef           `json:"evidence,omitempty"`
	ChainID  int64             `json:"chain_id,omitempty"`
}

type evRef struct {
	Agent string `json:"agent"`
	Seq   uint64 `json:"seq"`
}

// RecordAlert stores a detection alert in the operator queue. The evidence
// events are referenced, not copied.
func (c *Controller) RecordAlert(ctx context.Context, a detect.Alert) (int64, error) {
	k := alertKeys{Title: a.Title, Message: a.Message, Tier: a.Tier, Attack: a.Attack, Entities: a.Entities}
	for _, e := range a.Evidence {
		k.Evidence = append(k.Evidence, evRef{e.Agent, e.Seq})
	}
	raw, err := json.Marshal(k)
	if err != nil {
		return 0, err
	}
	row := store.AlertRow{Rule: a.RuleID, Host: a.Agent, Severity: SeverityLevel(a.Severity), Time: a.Time, Keys: string(raw), Agent: a.Agent}
	if row.Time.IsZero() {
		row.Time = c.now()
	}
	if n := len(a.Evidence); n > 0 {
		row.Agent, row.Seq = a.Evidence[n-1].Agent, a.Evidence[n-1].Seq
		if row.Host == "" {
			row.Host = row.Agent
		}
	}
	return c.st.InsertAlert(ctx, row)
}

func parseKeys(s string) alertKeys {
	var k alertKeys
	_ = json.Unmarshal([]byte(s), &k)
	return k
}

func (o *WebOps) alertRow(a store.AlertRow) ui.AlertRow {
	k := parseKeys(a.Keys)
	title := k.Title
	if title == "" {
		title = a.Rule
	}
	return ui.AlertRow{ID: a.ID, Time: a.Time, Severity: sevName(a.Severity), Rule: a.Rule, Title: title,
		Host: a.Host, State: a.State, ChainID: k.ChainID}
}

// ---- dashboard ----

func (o *WebOps) Overview(ctx context.Context) (ui.OpsDashboard, error) {
	var d ui.OpsDashboard
	c := o.c
	for _, h := range c.AgentHosts() {
		st, ok := c.AgentStatus(h)
		if !ok {
			continue
		}
		row := agentRow(st)
		d.Agents.Rows = append(d.Agents.Rows, row)
		d.Agents.Total++
		switch row.State {
		case "connected":
			d.Agents.Connected++
		case "silent":
			d.Agents.Silent++
		}
		if st.SafeMode {
			d.Agents.SafeMode++
		}
	}
	open, err := c.st.Alerts(ctx, "open", 5000)
	if err != nil {
		return d, err
	}
	d.OpenAlerts = len(open)
	cnt := map[int]int{}
	for _, a := range open {
		cnt[a.Severity]++
	}
	for l := len(sevNames) - 1; l >= 0; l-- {
		if cnt[l] > 0 {
			d.AlertsBySev = append(d.AlertsBySev, ui.SevCount{Severity: sevNames[l], Count: cnt[l]})
		}
	}
	plans, err := o.Plans(ctx)
	if err != nil {
		return d, err
	}
	for _, p := range plans {
		if p.Waiting != "" && (p.State == PlanDryRun || p.State == PlanRunning || p.State == PlanApproved) {
			d.Awaiting = append(d.Awaiting, p)
		}
	}
	d.Scorer = o.scorerView()
	camps, chs, err := o.loadChains(ctx)
	if err != nil {
		return d, err
	}
	for i, ch := range chs {
		if i >= 5 {
			break
		}
		d.Chains = append(d.Chains, chainBrief(ch))
	}
	for i, cp := range camps {
		if i >= 3 {
			break
		}
		d.Campaigns = append(d.Campaigns, ui.CampaignBrief{ID: cp.ID, Name: cp.Name, Chains: len(cp.Chains), Last: cp.Last})
	}
	d.Health = o.health(d.Agents)
	return d, nil
}

func (o *WebOps) health(a ui.AgentSummary) []string {
	h := []string{"Controller: ok", fmt.Sprintf("Agents: %d/%d connected", a.Connected, a.Total)}
	for _, r := range a.Rows {
		if r.State != "connected" {
			h = append(h, "Agent "+r.Host+" is "+r.State)
		}
		if r.Config != "" && r.Config != "applied" && r.Config != "none" {
			h = append(h, "Agent "+r.Host+" config: "+r.Config)
		}
	}
	al := o.c.Alerts()
	if n := len(al); n > 0 {
		for i := n - 1; i >= 0 && i >= n-3; i-- {
			h = append(h, fmt.Sprintf("%s %s %s", al[i].Time.UTC().Format("15:04:05Z"), al[i].Kind, al[i].Host))
		}
	}
	return h
}

func agentRow(st AgentStatus) ui.AgentRow {
	state := "disconnected"
	switch {
	case st.Silent:
		state = "silent"
	case st.Connected:
		state = "connected"
	}
	return ui.AgentRow{Host: st.Host, State: state, Config: st.ConfigState, ConfigVer: st.ConfigVersion,
		SpoolDepth: st.SpoolDepth, SafeMode: st.SafeMode, LastSeen: st.LastSeen}
}

func (o *WebOps) scorerView() *ui.ScorerView {
	o.smu.Lock()
	est, sla, svcFn := o.est, o.sla, o.services
	o.smu.Unlock()
	now := o.c.now()
	v := &ui.ScorerView{}
	have := false
	if est != nil {
		e := est.Estimate(now)
		if e.Bursts > 0 {
			have = true
			v.Round = fmt.Sprintf("burst #%d at %s", e.LastSeq, e.LastStart.UTC().Format("15:04:05Z"))
			v.Confidence = fmt.Sprintf("%.0f%%", e.Confidence*100)
			v.Lines = append(v.Lines, fmt.Sprintf("round interval %s +/- %s%s", e.Delay.Round(time.Second), e.Jitter.Round(time.Millisecond), map[bool]string{true: " (provisional)", false: ""}[e.Provisional]))
			w := est.SafeNow(now)
			switch {
			case w.Overdue:
				v.Lines = append(v.Lines, "expected burst is overdue (round gap?)")
			case !w.NextBurstFrom.IsZero():
				v.Lines = append(v.Lines, fmt.Sprintf("next burst in %s to %s", w.NextBurstFrom.Sub(now).Round(time.Second), w.NextBurstTo.Sub(now).Round(time.Second)))
			}
			if w.Safe {
				v.Lines = append(v.Lines, "quiet window: safe for time-critical changes")
			} else {
				v.Lines = append(v.Lines, "not a safe window: "+w.Reason)
			}
		}
	}
	if sla != nil && svcFn != nil {
		th := sla.Threshold()
		for _, s := range svcFn() {
			have = true
			r := ui.SLARow{Service: s, Streak: sla.Streak(s), Penalties: sla.Penalties(s), Level: "ok"}
			switch {
			case r.Streak >= max(th-1, 1):
				r.Level = "critical"
			case r.Streak >= max(th-2, 1):
				r.Level = "warn"
			}
			v.Services = append(v.Services, r)
		}
		sort.Slice(v.Services, func(i, j int) bool { return v.Services[i].Service < v.Services[j].Service })
		if v.Round == "" {
			v.Round = "SLA streaks (threshold " + strconv.Itoa(th) + ")"
		}
	}
	if !have {
		return nil
	}
	return v
}

// ---- agents ----

func (o *WebOps) AgentDetail(ctx context.Context, host string) (ui.AgentDetail, error) {
	c := o.c
	st, ok := c.AgentStatus(host)
	if !ok {
		if _, err := c.st.Agent(ctx, host); err != nil {
			return ui.AgentDetail{}, ui.ErrNotFound
		}
		st = AgentStatus{Host: host}
	}
	row := agentRow(st)
	d := ui.AgentDetail{Host: host, Known: true, State: row.State, Connected: st.Connected, Silent: st.Silent,
		LastSeen: st.LastSeen, ClockSkew: st.ClockSkew, SkewAt: st.SkewAt, ConfigState: st.ConfigState,
		ConfigEpoch: st.ConfigEpoch, ConfigVersion: st.ConfigVersion, SafeMode: st.SafeMode, SpoolDepth: st.SpoolDepth,
		Congestion: st.Congestion, Drops: st.Drops, Acked: st.Acked}
	for k, v := range st.Modules {
		d.Modules = append(d.Modules, ui.KV{Key: k, Value: v})
	}
	sort.Slice(d.Modules, func(i, j int) bool { return d.Modules[i].Key < d.Modules[j].Key })
	gaps, err := c.st.Gaps(ctx, host)
	if err != nil {
		return d, err
	}
	for _, g := range gaps {
		d.Gaps = append(d.Gaps, ui.GapRow{From: g.From, To: g.To, Reason: g.Reason, Class: g.Class, Count: g.Count, Time: g.Time})
	}
	d.LastEvents, _ = c.st.Count(ctx, host)
	return d, nil
}

// SetSafeMode sends a signed safe_mode control to a connected agent.
func (o *WebOps) SetSafeMode(ctx context.Context, host string, on bool, by string) error {
	if _, ok := o.c.AgentStatus(host); !ok {
		return ui.ErrNotFound
	}
	if err := o.c.SendControl(ctx, host, plan.ControlSafeMode, on, nil); err != nil {
		return fmt.Errorf("%w: %v", ui.ErrConflict, err)
	}
	o.c.log.Warn("safe mode set", "host", host, "on", on, "by", by)
	return nil
}

// ListAgents implements ui.AgentLister for the agents table.
func (c *Controller) ListAgents(ctx context.Context) ([]ui.AgentInfo, error) {
	var out []ui.AgentInfo
	for _, h := range c.AgentHosts() {
		st, ok := c.AgentStatus(h)
		if !ok {
			continue
		}
		link := "down"
		switch {
		case st.Silent:
			link = "degraded"
		case st.Connected:
			link = "up"
		}
		out = append(out, ui.AgentInfo{Name: h, LinkState: link, SpoolDepth: int(st.SpoolDepth), SafeMode: st.SafeMode,
			LastSeen: st.LastSeen, LagMillis: st.ClockSkew.Milliseconds(), Version: "config v" + strconv.FormatUint(st.ConfigVersion, 10)})
	}
	return out, nil
}

// ---- alerts ----

func (o *WebOps) Alerts(ctx context.Context, state string) ([]ui.AlertRow, error) {
	rows, err := o.c.st.Alerts(ctx, state, 500)
	if err != nil {
		return nil, err
	}
	out := make([]ui.AlertRow, 0, len(rows))
	for _, a := range rows {
		out = append(out, o.alertRow(a))
	}
	return out, nil
}

func (o *WebOps) Alert(ctx context.Context, id int64) (ui.AlertDetail, error) {
	a, err := o.c.st.Alert(ctx, id)
	if errors.Is(err, store.ErrNoAlert) {
		return ui.AlertDetail{}, ui.ErrNotFound
	}
	if err != nil {
		return ui.AlertDetail{}, err
	}
	k := parseKeys(a.Keys)
	d := ui.AlertDetail{AlertRow: o.alertRow(a), Message: k.Message, Keys: a.Keys}
	ents := make([]string, 0, len(k.Entities))
	for e := range k.Entities {
		ents = append(ents, e)
	}
	sort.Strings(ents)
	for _, e := range ents {
		d.Entities = append(d.Entities, ui.KV{Key: e, Value: k.Entities[e]})
	}
	refs := k.Evidence
	if len(refs) == 0 && a.Agent != "" && a.Seq != 0 {
		refs = []evRef{{a.Agent, a.Seq}}
	}
	if len(refs) > 50 {
		refs = refs[len(refs)-50:]
	}
	for _, r := range refs {
		ev, err := o.c.st.Event(ctx, r.Agent, r.Seq)
		if err != nil {
			d.Evidence = append(d.Evidence, ui.EvidenceRow{Agent: r.Agent, Seq: r.Seq, Kind: "(not in the store)"})
			continue
		}
		body, _ := json.Marshal(ev.Fields)
		if len(body) > 800 {
			body = append(body[:800], "..."...)
		}
		d.Evidence = append(d.Evidence, ui.EvidenceRow{Agent: ev.Agent, Seq: ev.Seq, Time: ev.Time, Kind: ev.Kind, Body: string(body)})
	}
	return d, nil
}

func (o *WebOps) SetAlertState(ctx context.Context, id int64, state, by string) error {
	switch state {
	case "open", "acked", "closed":
	default:
		return fmt.Errorf("%w: unknown alert state", ui.ErrInvalid)
	}
	if err := o.c.st.SetAlertState(ctx, id, state); err != nil {
		if errors.Is(err, store.ErrNoAlert) {
			return ui.ErrNotFound
		}
		return err
	}
	return nil
}

// TraceAlert builds the attack chain for an alert (once; later calls return
// the same chain) and records its id on the alert.
func (o *WebOps) TraceAlert(ctx context.Context, id int64, by string) (int64, error) {
	o.traceMu.Lock()
	defer o.traceMu.Unlock()
	c := o.c
	a, err := c.st.Alert(ctx, id)
	if errors.Is(err, store.ErrNoAlert) {
		return 0, ui.ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	k := parseKeys(a.Keys)
	if k.ChainID != 0 {
		if _, err := c.st.Chain(ctx, k.ChainID); err == nil {
			return k.ChainID, nil
		}
	}
	refs := k.Evidence
	if len(refs) == 0 && a.Agent != "" && a.Seq != 0 {
		refs = []evRef{{a.Agent, a.Seq}}
	}
	if len(refs) == 0 {
		return 0, fmt.Errorf("%w: the alert has no source event to trace from", ui.ErrInvalid)
	}
	var evs []event.Event
	for _, r := range refs {
		if ev, err := c.st.Event(ctx, r.Agent, r.Seq); err == nil {
			evs = append(evs, ev)
		}
	}
	if len(evs) == 0 {
		return 0, fmt.Errorf("%w: the alert's evidence is not in the store", ui.ErrConflict)
	}
	da := detect.Alert{RuleID: a.Rule, Title: k.Title, Severity: sevName(a.Severity), Agent: a.Agent, Time: a.Time,
		Message: k.Message, Evidence: evs, Entities: k.Entities}
	seed, ok := chains.SeedFromAlert(da)
	if !ok { // below the automatic threshold: the operator asked, so trace anyway
		last := evs[len(evs)-1]
		seed = chains.Seed{Kind: chains.SeedAlert, Agent: last.Agent, Time: a.Time, Event: &last, Alert: &da}
	}
	b := chains.Builder{Src: c.st, Cfg: o.chainCfg}
	ch, err := b.Build(ctx, seed)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ui.ErrConflict, err)
	}
	if err := chains.Save(ctx, c.st, ch); err != nil {
		return 0, err
	}
	if all, err := chains.LoadAll(ctx, c.st); err == nil {
		_, _ = chains.SyncCampaigns(ctx, c.st, all, o.chainCfg)
	}
	k.ChainID = ch.ID
	raw, _ := json.Marshal(k)
	if err := c.st.SetAlertKeys(ctx, id, string(raw)); err != nil {
		return 0, err
	}
	return ch.ID, nil
}

// ---- chains ----

func chainHosts(ch *chains.Chain) string {
	seen := map[string]bool{}
	var hs []string
	for _, h := range ch.Hops {
		if h.DstHost != "" && !seen[h.DstHost] {
			seen[h.DstHost] = true
			hs = append(hs, h.DstHost)
		}
	}
	return strings.Join(hs, ", ")
}

func chainBrief(ch *chains.Chain) ui.ChainBrief {
	return ui.ChainBrief{ID: ch.ID, Hosts: chainHosts(ch), Hops: len(ch.Hops),
		Confidence: fmt.Sprintf("%.0f%% (%s)", ch.Confidence*100, chains.Level(ch.Confidence)), Created: ch.Created}
}

// loadChains returns campaigns (newest activity first) and chains (newest first).
func (o *WebOps) loadChains(ctx context.Context) ([]*chains.Campaign, []*chains.Chain, error) {
	all, err := chains.LoadAll(ctx, o.c.st)
	if err != nil {
		return nil, nil, err
	}
	rows, err := o.c.st.Campaigns(ctx)
	if err != nil {
		return nil, nil, err
	}
	names := map[int64]string{}
	for _, r := range rows {
		names[r.ID] = r.Name
	}
	byID := map[int64]*chains.Campaign{}
	var camps []*chains.Campaign
	for _, ch := range all {
		cp := byID[ch.CampaignID]
		if cp == nil {
			cp = &chains.Campaign{ID: ch.CampaignID, Name: names[ch.CampaignID]}
			if cp.ID == 0 {
				cp.Name = "Ungrouped"
			}
			byID[ch.CampaignID] = cp
			camps = append(camps, cp)
		}
		cp.Chains = append(cp.Chains, ch)
		if cp.First.IsZero() || ch.Created.Before(cp.First) {
			cp.First = ch.Created
		}
		if ch.Created.After(cp.Last) {
			cp.Last = ch.Created
		}
		k := chains.ChainKeys(ch, o.chainCfg)
		cp.Keys.Sources = union(cp.Keys.Sources, k.Sources)
		cp.Keys.Accounts = union(cp.Keys.Accounts, k.Accounts)
	}
	sort.SliceStable(camps, func(i, j int) bool { return camps[i].Last.After(camps[j].Last) })
	return camps, all, nil
}

func union(a, b []string) []string {
	m := map[string]bool{}
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		m[s] = true
	}
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func (o *WebOps) Chains(ctx context.Context) ([]ui.CampaignView, error) {
	camps, _, err := o.loadChains(ctx)
	if err != nil {
		return nil, err
	}
	var out []ui.CampaignView
	for _, cp := range camps {
		v := ui.CampaignView{ID: cp.ID, Name: cp.Name, First: cp.First, Last: cp.Last, Sources: cp.Keys.Sources, Accounts: cp.Keys.Accounts}
		for _, ch := range cp.Chains {
			v.Chains = append(v.Chains, chainBrief(ch))
		}
		out = append(out, v)
	}
	return out, nil
}

func (o *WebOps) Chain(ctx context.Context, id int64) (ui.ChainView, error) {
	ch, err := chains.Load(ctx, o.c.st, id)
	if errors.Is(err, store.ErrNoChain) {
		return ui.ChainView{}, ui.ErrNotFound
	}
	if err != nil {
		return ui.ChainView{}, err
	}
	v := ui.ChainView{ID: ch.ID, CampaignID: ch.CampaignID, Confidence: fmt.Sprintf("%.0f%% (%s)", ch.Confidence*100, chains.Level(ch.Confidence)),
		Truncated: ch.Truncated, Notes: ch.Notes}
	for _, r := range ch.Timeline(nil) {
		tr := ui.TimelineRow{Ord: r.Ord, Cause: r.Cause, Local: r.Local, UTC: r.UTC, Host: r.Host, Kind: string(r.Kind), What: r.What,
			Technique: r.Technique, Method: r.Method, Level: r.Level, Guess: r.Guess, Notes: r.Notes}
		for _, e := range r.Evidence {
			tr.Evidence = append(tr.Evidence, fmt.Sprintf("%s#%d", e.Agent, e.Seq))
		}
		for _, it := range r.Items {
			tr.Items = append(tr.Items, ui.ItemRow{Text: it.Text, State: it.State, Verified: it.Verified})
		}
		v.Rows = append(v.Rows, tr)
	}
	return v, nil
}

// ---- plans ----

func (o *WebOps) Templates(ctx context.Context) ([]ui.TemplateInfo, error) {
	ts, err := ListTemplates(o.plansDir)
	if err != nil {
		return nil, err
	}
	out := make([]ui.TemplateInfo, 0, len(ts))
	for _, t := range ts {
		out = append(out, ui.TemplateInfo{Name: t.Name, Title: t.Title, Nodes: t.Nodes})
	}
	return out, nil
}

func planErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNoSuchPlan):
		return ui.ErrNotFound
	case errors.Is(err, ErrPlanState), errors.Is(err, ErrNotApprovable), errors.Is(err, ErrPlanExists), errors.Is(err, ErrNoRollbackData):
		return fmt.Errorf("%w: %v", ui.ErrConflict, err)
	}
	return err
}

func (o *WebOps) CreatePlan(ctx context.Context, template, planID, by string) (string, error) {
	p, err := LoadTemplate(o.plansDir, template)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ui.ErrInvalid, err)
	}
	p.ID = PlanIDFor(p, template, planID, o.c.now())
	if err := o.c.CreatePlan(ctx, p, by); err != nil {
		if errors.Is(err, ErrPlanExists) {
			return "", planErr(err)
		}
		return "", fmt.Errorf("%w: %v", ui.ErrInvalid, err)
	}
	return p.ID, nil
}

func (o *WebOps) DryRun(ctx context.Context, id string) error {
	_, err := o.c.DryRun(ctx, id)
	return planErr(err)
}
func (o *WebOps) ApprovePlan(ctx context.Context, id, by string) error {
	return planErr(o.c.ApprovePlan(ctx, id, by))
}
func (o *WebOps) ApproveNode(ctx context.Context, id, node, by, note string) error {
	err := o.c.ApproveNode(ctx, id, node, by, note)
	if err != nil && !errors.Is(err, ErrNoSuchPlan) && !errors.Is(err, ErrPlanState) && !errors.Is(err, ErrNotApprovable) {
		return fmt.Errorf("%w: %v", ui.ErrConflict, err)
	}
	return planErr(err)
}
func (o *WebOps) Apply(ctx context.Context, id, by string) error {
	return planErr(o.c.Apply(ctx, id))
}
func (o *WebOps) Rollback(ctx context.Context, id, by string) error {
	return planErr(o.c.RollbackPlan(ctx, id))
}

// waiting says what a plan needs from the operator next.
func waiting(d PlanDetail) (string, []string) {
	var pend []string
	for _, n := range d.Plan.Nodes {
		nd := d.Nodes[n.ID]
		if nd.State == plan.StatePending && plan.RequiresOwnApproval(n, nd.Risk) && nd.Approval == nil {
			pend = append(pend, n.ID)
		}
	}
	switch d.State {
	case PlanDraft:
		return "dry run", pend
	case PlanDryRun:
		if d.DryRun != nil && d.DryRun.Approvable {
			return "plan approval", pend
		}
		return "a clean dry run", pend
	case PlanApproved:
		if len(pend) > 0 {
			return "apply and approval of " + strings.Join(pend, ", "), pend
		}
		return "apply", pend
	case PlanRunning:
		if len(pend) > 0 {
			return "approval of " + strings.Join(pend, ", "), pend
		}
	}
	return "", pend
}

func briefOf(d PlanDetail) ui.PlanBrief {
	w, pend := waiting(d)
	return ui.PlanBrief{ID: d.Plan.ID, Name: d.Plan.Name, State: d.State, By: d.By, Created: d.Created, Pending: pend, Waiting: w}
}

func (o *WebOps) Plans(ctx context.Context) ([]ui.PlanBrief, error) {
	rows, err := o.c.StoredPlans(ctx)
	if err != nil {
		return nil, err
	}
	live := map[string]bool{}
	var out []ui.PlanBrief
	for _, id := range o.c.LivePlanIDs() {
		d, err := o.c.PlanDetail(id)
		if err != nil {
			continue
		}
		live[id] = true
		out = append(out, briefOf(d))
	}
	for _, r := range rows {
		if !live[r.ID] {
			out = append(out, ui.PlanBrief{ID: r.ID, Name: r.Name, State: r.State, Created: r.Created})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

func (o *WebOps) Plan(ctx context.Context, id string) (ui.PlanView, error) {
	d, err := o.c.PlanDetail(id)
	if err != nil {
		if errors.Is(err, ErrNoSuchPlan) {
			if row, serr := o.c.st.Plan(ctx, id); serr == nil { // finished in an earlier run: summary only
				return ui.PlanView{PlanBrief: ui.PlanBrief{ID: row.ID, Name: row.Name, State: row.State, Created: row.Created}, Done: true}, nil
			}
			return ui.PlanView{}, ui.ErrNotFound
		}
		return ui.PlanView{}, err
	}
	v := ui.PlanView{PlanBrief: briefOf(d), OnFailure: string(d.Plan.OnFailure), Hash: d.Hash}
	if v.OnFailure == "" {
		v.OnFailure = string(plan.StopDependents)
	}
	switch d.State {
	case PlanSucceeded, PlanFailed, PlanRolledBack, PlanInterrupted:
		v.Done = true
	}
	dry := map[string]plan.DryRunNode{}
	if d.DryRun != nil {
		v.HasDryRun, v.Approvable = true, d.DryRun.Approvable
		for _, n := range d.DryRun.Nodes {
			dry[n.NodeID] = n
		}
		keys := make([]string, 0, len(d.DryRun.Counts))
		for k := range d.DryRun.Counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v.Counts = append(v.Counts, ui.KV{Key: k, Value: strconv.Itoa(d.DryRun.Counts[k])})
		}
	}
	v.CanDryRun = d.State == PlanDraft || d.State == PlanDryRun
	v.CanApprove = d.State == PlanDryRun && v.Approvable
	v.CanApply = d.State == PlanApproved
	v.CanRollback = d.State == PlanRunning && !d.Draining && d.Plan.OnFailure == plan.RollbackPlan
	// Show nodes in dry-run (topological) order when there is one.
	order := d.NodeOrder
	if d.DryRun != nil && len(d.DryRun.Nodes) == len(order) {
		order = order[:0:0]
		for _, n := range d.DryRun.Nodes {
			order = append(order, n.NodeID)
		}
	}
	byID := map[string]plan.Node{}
	for _, n := range d.Plan.Nodes {
		byID[n.ID] = n
	}
	for _, id := range order {
		n, nd := byID[id], d.Nodes[id]
		nv := ui.PlanNodeView{ID: id, Host: n.Target, Action: n.Action, Risk: string(nd.Risk), Needs: n.Needs, Gate: n.Gate,
			State: string(nd.State), Reason: nd.Reason, NeedsOwnApproval: plan.RequiresOwnApproval(n, nd.Risk), DryStatus: "-"}
		if dn, ok := dry[id]; ok {
			nv.DryStatus, nv.Diff, nv.DryReason = dn.Status, dn.Diff, dn.Reason
		}
		if nd.Approval != nil {
			nv.Approved, nv.ApprovedBy = true, nd.Approval.By
		}
		nv.CanApprove = nv.NeedsOwnApproval && !nv.Approved && nd.State == plan.StatePending && v.Approvable &&
			(d.State == PlanDryRun || d.State == PlanApproved || d.State == PlanRunning)
		for _, p := range nd.Phases {
			s := p.Phase + ": " + p.Outcome
			if p.Error != "" {
				s += " (" + p.Error + ")"
			}
			nv.Phases = append(nv.Phases, s)
		}
		v.Nodes = append(v.Nodes, nv)
	}
	return v, nil
}
