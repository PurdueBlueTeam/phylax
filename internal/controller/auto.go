package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/plan/lint"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// autoHeartbeatMax is how fresh a target's heartbeat must be for an auto plan.
const autoHeartbeatMax = 15 * time.Second

// RunAuto starts a template plan without a click when every auto condition
// holds. The first condition that fails records a click proposal and returns
// module.ErrProposed; an unknown state never becomes an apply.
func (c *Controller) RunAuto(ctx context.Context, mod, template string, params map[string]string) (string, error) {
	fail := func(reason string) (string, error) {
		return c.proposeFallback(ctx, mod, template, params, reason)
	}
	man, err := c.currentManifest()
	if err != nil {
		return fail("manifest: " + err.Error())
	}
	block, ok := man.Modules[mod]
	if !ok {
		return fail("module block " + mod + " is missing")
	}
	autonomy := block.Autonomy[template]
	if autonomy == "" {
		autonomy = "propose"
	}
	if autonomy != "propose" && autonomy != "shadow" && autonomy != "auto" {
		return fail("template " + template + " has autonomy " + autonomy)
	}
	if autonomy == "propose" {
		return fail("template " + template + " is propose")
	}
	p, err := c.moduleTemplate(mod, template, params)
	if err != nil {
		return fail("template: " + err.Error())
	}
	hosts := p.Hosts()
	for _, h := range hosts {
		if !man.ActEnabled(h, mod) {
			return fail("act_enabled is false on " + h)
		}
	}
	now := c.now()
	safe := map[string]bool{}
	for _, h := range man.SafeModeHostSet() {
		safe[h] = true
	}
	for _, h := range hosts {
		st, ok := c.AgentStatus(h)
		if !ok || st.LastSeen.IsZero() || now.Sub(st.LastSeen) > autoHeartbeatMax {
			return fail("no recent heartbeat from " + h)
		}
		if st.SafeMode || safe[h] {
			return fail("safe mode is on for " + h)
		}
	}
	p.Class = plan.ClassAuto
	if fs := lint.Run(p, lint.Ctx{Manifest: man, Query: c.st, Class: p.Class, Actions: c.reg}); len(fs) > 0 {
		parts := make([]string, 0, len(fs))
		for _, f := range fs {
			parts = append(parts, fmt.Sprintf("%s node %s: %s", f.Rule, f.Node, f.Message))
		}
		return fail("lint: " + strings.Join(parts, "; "))
	}
	for _, n := range p.Nodes {
		if n.Gate {
			continue
		}
		if len(c.scoredTouch(man, n)) > 0 && c.opt.Probe == nil {
			return fail("probe cannot run: node " + n.ID + " touches a scored service")
		}
	}
	object := params["object"]
	if object == "" {
		object = autoObject(p)
	}
	p.OnFailure = plan.RollbackPlan
	p.Module = mod
	p.Template = template
	if autonomy == "shadow" {
		p.Approver = "shadow:" + mod + "/" + template
		if t := params[plan.TriggerParam]; t != "" {
			p.Approver += " trigger " + t
		}
		p.ID = PlanIDFor(p, template, "", now)
		if err := c.CreatePlan(ctx, p, p.Approver); err != nil {
			return "", err
		}
		dr, err := c.DryRun(ctx, p.ID)
		if err != nil {
			return "", err
		}
		_ = c.st.AppendAudit(ctx, store.AuditRow{Time: now, Actor: p.Approver, Action: "auto_shadow",
			Detail: fmt.Sprintf("%s/%s on %s: %s dry run, approvable=%t", mod, template, strings.Join(hosts, ","), object, dr.Approvable)})
		return p.ID, nil
	}
	for _, h := range hosts {
		allowed, opened, err := c.noteAutoAttempt(ctx, h, object, template, now)
		if err != nil {
			return "", fmt.Errorf("controller: auto ledger: %w", err)
		}
		if !allowed {
			return fail("ledger halted on " + h)
		}
		if opened {
			c.emitAutoHalted(ctx, h, object, template, now)
		}
	}
	approver := "auto:" + mod + "/" + template
	if t := params[plan.TriggerParam]; t != "" {
		approver += " trigger " + t
	}
	p.Approver = approver
	p.ID = PlanIDFor(p, template, "", now)
	if err := c.CreatePlan(ctx, p, approver); err != nil {
		return "", err
	}
	if err := c.approveNow(ctx, p.ID, approver); err != nil {
		return "", err
	}
	if err := c.Apply(ctx, p.ID); err != nil {
		return "", err
	}
	return p.ID, nil
}

// autoObject names what an auto plan touches, for the attempt ledger: the
// first action object of the plan (path, account, unit, ...), else its target.
//
// shortcut: one object identifies the whole template plan; upgrade if a
// template must keep separate ledger entries for several objects.
func autoObject(p plan.Plan) string {
	for _, n := range p.Nodes {
		if n.Gate {
			continue
		}
		for _, k := range []string{"object", "path", "account", "user", "sid", "unit", "service", "gpo", "rule", "name", "id", "target", "host"} {
			if v, ok := n.Params[k]; ok {
				return fmt.Sprint(v)
			}
		}
		return n.Target
	}
	return p.Template
}

// scoredTouch resolves the node's action and returns the manifest-scored
// services its Touches hits.
func (c *Controller) scoredTouch(m *manifest.Manifest, n plan.Node) []string {
	if n.Gate {
		return nil
	}
	a, err := c.reg.Get(n.Action)
	if err != nil {
		return nil
	}
	p, err := a.Spec().Validate(n.ActionParams())
	if err != nil {
		return nil
	}
	return plan.ScoredTouch(m, n, a.Touches(p))
}

// evalAutoGatesLocked evaluates every ready gate: auto node.
func (rt *planRT) evalAutoGatesLocked() {
	for _, id := range rt.run.ReadyAutoGates() {
		rt.evalAutoGateLocked(id)
	}
}

// evalAutoGateLocked checks a gate's until conditions in order: shadow time,
// probe, absence of an event. A missing condition passes; a missing probe
// callback fails the gate (never a silent pass).
//
// shortcut: conditions are time, probe and absence of an event; a nested
// summary condition (the firewall's would-drop table) is evaluated by the
// owning module before it calls RunAuto, upgrade when a second module needs one.
func (rt *planRT) evalAutoGateLocked(id string) {
	n := rt.node(id)
	if n.Until == nil {
		return
	}
	gs := rt.gates[id]
	if gs == nil {
		gs = &gateRT{}
		rt.gates[id] = gs
	}
	if gs.failed || gs.probing {
		return
	}
	c := rt.c
	now := c.now()
	if gs.start.IsZero() {
		gs.start = now
	}
	if n.Until.AfterSec > 0 {
		need := time.Duration(n.Until.AfterSec) * time.Second
		if elapsed := now.Sub(gs.start); elapsed < need {
			left := int((need - elapsed + time.Second - 1) / time.Second)
			rt.nodes[id].reason = fmt.Sprintf("waiting: %ds of shadow time left", left)
			rt.scheduleGatePollLocked(id, gs)
			return
		}
	}
	if n.Until.Probe != "" && !gs.probeOK {
		services, err := rt.gateProbeServices(n)
		if err != nil {
			rt.failGateLocked(id, "gate: auto failed: "+err.Error())
			return
		}
		if c.opt.Probe == nil {
			rt.failGateLocked(id, "gate: auto failed: no probe configured")
			return
		}
		if len(services) == 0 {
			gs.probeOK = true
		} else {
			gs.probing = true
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				err, svc := c.probeServices(ctx, services)
				rt.mu.Lock()
				defer rt.mu.Unlock()
				gs.probing = false
				if err != nil {
					rt.failGateLocked(id, "gate: auto failed: probe red: "+svc)
					rt.advanceLocked()
					return
				}
				gs.probeOK = true
				rt.evalAutoGateLocked(id)
				rt.advanceLocked()
			}()
			return
		}
	}
	if ne := n.Until.NoEvent; ne != nil && !gs.checked {
		evs, err := c.st.Events(context.Background(), store.Query{Kind: ne.Kind, Fields: ne.Fields, From: gs.start, Limit: 1})
		if err != nil {
			rt.failGateLocked(id, "gate: auto failed: "+err.Error())
			return
		}
		if len(evs) > 0 {
			rt.failGateLocked(id, "gate: auto failed: event "+ne.Kind)
			return
		}
		gs.checked = true
	}
	if gs.timer != nil {
		gs.timer.Stop()
		gs.timer = nil
	}
	if err := rt.run.PassGate(id, plan.Approval{By: "auto", At: now.Unix(), Note: "gate: auto"}); err != nil {
		rt.failGateLocked(id, "gate: auto failed: "+err.Error())
		return
	}
	rt.nodes[id].reason = ""
	_ = rt.persistLocked(context.Background())
}

// gateProbeServices resolves a gate's probe condition to service names. "*"
// means every scored service on the plan's target hosts.
func (rt *planRT) gateProbeServices(n plan.Node) ([]string, error) {
	if n.Until.Probe != "*" {
		return []string{n.Until.Probe}, nil
	}
	man, err := rt.c.currentManifest()
	if err != nil {
		return nil, err
	}
	hosts := map[string]bool{}
	for _, h := range rt.p.Hosts() {
		hosts[h] = true
	}
	seen := map[string]bool{}
	for id, s := range man.Services {
		if s.Scored && hosts[s.Host] {
			seen[id] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

// scheduleGatePollLocked re-evaluates a waiting gate every GatePoll.
func (rt *planRT) scheduleGatePollLocked(id string, gs *gateRT) {
	if gs.waiting {
		return
	}
	gs.waiting = true
	gs.timer = time.AfterFunc(rt.c.opt.GatePoll, func() {
		rt.mu.Lock()
		defer rt.mu.Unlock()
		gs.waiting = false
		gs.timer = nil
		if rt.state != PlanRunning {
			return
		}
		rt.evalAutoGateLocked(id)
		rt.advanceLocked()
	})
}

// failGateLocked fails a gate: auto node and applies the plan's failure policy.
func (rt *planRT) failGateLocked(id, reason string) {
	gs := rt.gates[id]
	if gs != nil {
		gs.failed = true
		if gs.timer != nil {
			gs.timer.Stop()
			gs.timer = nil
		}
	}
	if err := rt.run.FailGate(id, reason); err != nil {
		rt.c.log.Error("plan: cannot fail gate", "plan", rt.p.ID, "node", id, "err", err)
		return
	}
	rt.nodes[id].reason = reason
	rt.failed = true
	if rt.policy() == plan.RollbackPlan {
		rt.draining = true
	}
	_ = rt.persistLocked(context.Background())
}

// autoLedgerCount and autoLedgerWindow are the one fixed rule: two automatic
// attempts of one (host, object, kind) inside ten minutes open the breaker.
const (
	autoLedgerCount  = 2
	autoLedgerWindow = 10 * time.Minute
)

// autoLedger is the persisted attempt ledger entry for one key.
type autoLedger struct {
	Times []int64 `json:"times"`
	Open  bool    `json:"open,omitempty"`
}

// noteAutoAttempt records one automatic attempt for (host, object, kind).
// allowed is false while the breaker is open for that key; opened is true
// exactly once, when this attempt reaches the count and opens it. Only a
// missing key means a closed breaker; every other store error fails closed.
func (c *Controller) noteAutoAttempt(ctx context.Context, host, object, kind string, at time.Time) (allowed, opened bool, err error) {
	key := autoLedgerKey(host, object, kind)
	var l autoLedger
	raw, err := c.st.MetaGet(ctx, key)
	if err != nil && !errors.Is(err, store.ErrNoMeta) {
		return false, false, err
	}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			return false, false, err
		}
	}
	if l.Open {
		return false, false, nil
	}
	cutoff := at.Add(-autoLedgerWindow).UnixMilli()
	kept := l.Times[:0]
	for _, t := range l.Times {
		if t >= cutoff && t <= at.UnixMilli() {
			kept = append(kept, t)
		}
	}
	l.Times = append(kept, at.UnixMilli())
	if len(l.Times) >= autoLedgerCount {
		l.Open = true
		opened = true
	}
	b, err := json.Marshal(l)
	if err != nil {
		return false, false, err
	}
	if err := c.st.MetaSet(ctx, key, string(b)); err != nil {
		return false, false, err
	}
	return true, opened, nil
}

// emitAutoHalted records the ledger's stop: plan.failed with reason
// auto_halted at critical priority.
func (c *Controller) emitAutoHalted(ctx context.Context, host, object, kind string, at time.Time) {
	e, err := event.New(event.KindPlanFailed, event.PlanFailed{Reason: event.ReasonAutoHalted,
		Host: host, Object: object, Kind: kind, Count: autoLedgerCount,
		WindowSec: int(autoLedgerWindow / time.Second), Trigger: "repeat"})
	if err != nil {
		c.log.Error("auto ledger: build event", "err", err)
		return
	}
	if _, err := c.EmitController(ctx, e); err != nil {
		c.log.Error("auto ledger: emit plan.failed", "host", host, "object", object, "kind", kind, "err", err)
	}
}

// autoHalted reports whether the ledger's breaker is open for a key.
func (c *Controller) autoHalted(ctx context.Context, host, object, kind string) (bool, error) {
	raw, err := c.st.MetaGet(ctx, autoLedgerKey(host, object, kind))
	if errors.Is(err, store.ErrNoMeta) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var l autoLedger
	if err := json.Unmarshal([]byte(raw), &l); err != nil {
		return false, err
	}
	return l.Open, nil
}

// ReenableAuto clears the ledger's breaker for one key and records the
// operator in the audit log.
func (c *Controller) ReenableAuto(ctx context.Context, host, object, kind, by string) error {
	if err := requireOperator(by); err != nil {
		return err
	}
	if err := c.st.MetaDelete(ctx, autoLedgerKey(host, object, kind)); err != nil {
		return err
	}
	return c.st.AppendAudit(ctx, store.AuditRow{Time: c.now(), Actor: by, Action: "auto_reenable",
		Detail: fmt.Sprintf("auto %s on %s (%s)", kind, host, object)})
}

func autoLedgerKey(host, object, kind string) string {
	return "auto_ledger/" + base64.RawURLEncoding.EncodeToString([]byte(host)) + "/" +
		base64.RawURLEncoding.EncodeToString([]byte(object)) + "/" +
		base64.RawURLEncoding.EncodeToString([]byte(kind))
}
