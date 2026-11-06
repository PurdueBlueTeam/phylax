package controller

import (
	"context"
	"fmt"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/plan/lint"
)

// RunReadOnly starts a template plan that only reads. SS000 must pass on every
// node; any finding refuses the whole plan before it is stored.
func (c *Controller) RunReadOnly(ctx context.Context, mod, template string, params map[string]string) (string, error) {
	approver := "auto_readonly:" + mod
	p, err := c.moduleTemplate(mod, template, params)
	if err != nil {
		return "", err
	}
	p.Class = plan.ClassAutoReadOnly
	p.Module = mod
	p.Template = template
	p.Approver = approver
	p.ID = PlanIDFor(p, template, "", c.now())
	man, _ := c.currentManifest()
	if fs := lint.Run(p, lint.Ctx{Manifest: man, Query: c.st, Class: p.Class, Actions: c.reg}); len(fs) > 0 {
		parts := make([]string, 0, len(fs))
		for _, f := range fs {
			parts = append(parts, fmt.Sprintf("%s node %s: %s", f.Rule, f.Node, f.Message))
		}
		return "", fmt.Errorf("controller: read-only plan %s/%s refused: %s", mod, template, strings.Join(parts, "; "))
	}
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

// approveNow approves a plan the controller starts itself (auto_readonly,
// standing, auto, or an accepted proposal) without a separate dry-run click.
func (c *Controller) approveNow(ctx context.Context, id, by string) error {
	rt, err := c.plan(id)
	if err != nil {
		return err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.state != PlanDraft {
		return ErrPlanState
	}
	rt.run.ApprovePlan(by, c.now())
	rt.state = PlanApproved
	return rt.persistLocked(ctx)
}
