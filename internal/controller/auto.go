package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/plan/lint"
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

// autoHalted reports whether the circuit breaker has halted (module, template,
// host). Task 28 fills in the kv-backed breaker.
func (c *Controller) autoHalted(ctx context.Context, mod, template, host string) bool {
	return false
}
