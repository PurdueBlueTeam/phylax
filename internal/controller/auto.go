package controller

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

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
	allowed := false
	for _, t := range block.Auto {
		if t == template {
			allowed = true
			break
		}
	}
	if !allowed {
		return fail("template " + template + " is not in the module's auto list")
	}
	now := c.now()
	for _, h := range hosts {
		st, ok := c.AgentStatus(h)
		if !ok || st.LastSeen.IsZero() || now.Sub(st.LastSeen) > autoHeartbeatMax {
			return fail("no recent heartbeat from " + h)
		}
		if st.SafeMode {
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
	for _, h := range hosts {
		if c.autoHalted(ctx, mod, template, h) {
			return fail("template halted on " + h)
		}
	}
	p.OnFailure = plan.RollbackPlan
	approver := "auto:" + mod + "/" + template
	if t := params[plan.TriggerParam]; t != "" {
		approver += " trigger " + t
	}
	p.Module = mod
	p.Template = template
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
	p, err := a.Spec().Validate(n.Params)
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

// autoHalted reports whether the circuit breaker has halted (module, template,
// host). Task 28 fills in the kv-backed breaker.
func (c *Controller) autoHalted(ctx context.Context, mod, template, host string) bool {
	return false
}
