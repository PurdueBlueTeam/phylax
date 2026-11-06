package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/plan/lint"
	"github.com/PurdueBlueTeam/phylax/internal/store"
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

// maxStanding is the longest standing approval the controller accepts. The
// design caps it at "the event's end", which the manifest does not record yet.
//
// shortcut: 72 h cap stands in for "the event's end", upgrade when the
// manifest records the event window.
const maxStanding = 72 * time.Hour

// CreateStanding validates and stores an operator's standing approval.
func (c *Controller) CreateStanding(ctx context.Context, sa store.StandingApproval) error {
	now := c.now()
	switch {
	case sa.ID == "":
		return fmt.Errorf("controller: standing approval needs an id")
	case sa.Module == "":
		return fmt.Errorf("controller: standing approval needs a module")
	case sa.Template == "":
		return fmt.Errorf("controller: standing approval needs a template")
	case sa.Approver == "":
		return fmt.Errorf("controller: standing approval needs an approver")
	case sa.Created == "":
		return fmt.Errorf("controller: standing approval needs the operator login")
	case len(sa.Actions) == 0:
		return fmt.Errorf("controller: standing approval needs an action list")
	}
	if _, err := manifest.ParseLabels(sa.Targets); err != nil {
		return fmt.Errorf("controller: standing approval targets: %w", err)
	}
	for _, name := range sa.Actions {
		if name == "host.exec" {
			return fmt.Errorf("controller: standing approval cannot include host.exec")
		}
		a, err := c.reg.Get(name)
		if err != nil {
			return fmt.Errorf("controller: standing approval action: %w", err)
		}
		switch plan.Risk(a.Spec().Risk) {
		case plan.RiskLockout, plan.RiskDestructive:
			return fmt.Errorf("controller: standing approval cannot include %s action %s", a.Spec().Risk, name)
		}
	}
	if !sa.Expires.After(now) {
		return fmt.Errorf("controller: standing approval must expire in the future")
	}
	if sa.Expires.After(now.Add(maxStanding)) {
		return fmt.Errorf("controller: standing approval may not outlast %s", maxStanding)
	}
	sa.Revoked = false
	return c.st.InsertStanding(ctx, sa)
}

// RevokeStanding revokes a standing approval and records the operator in the
// audit log.
func (c *Controller) RevokeStanding(ctx context.Context, id, by string) error {
	if err := requireOperator(by); err != nil {
		return err
	}
	sa, err := c.st.Standing(ctx, id)
	if err != nil {
		return err
	}
	if err := c.st.SetStandingRevoked(ctx, id); err != nil {
		return err
	}
	return c.st.AppendAudit(ctx, store.AuditRow{Time: c.now(), Actor: by, Action: "standing_revoke",
		Detail: "standing " + sa.ID + " (" + sa.Module + "/" + sa.Template + ")"})
}

// RunStanding starts a plan inside an operator's standing approval. Any scope
// mismatch falls back to the same plan as a click proposal.
func (c *Controller) RunStanding(ctx context.Context, mod, approvalID, template string, params map[string]string) (string, error) {
	fail := func(reason string) (string, error) {
		return c.proposeFallback(ctx, mod, template, params, "standing "+approvalID+": "+reason)
	}
	sa, err := c.st.Standing(ctx, approvalID)
	if err != nil {
		return fail(err.Error())
	}
	switch {
	case sa.Revoked:
		return fail("revoked")
	case !sa.Expires.After(c.now()):
		return fail("expired")
	case sa.Module != mod:
		return fail(fmt.Sprintf("module %q is not %q", mod, sa.Module))
	case sa.Template != template:
		return fail(fmt.Sprintf("template %q is not %q", template, sa.Template))
	}
	p, err := c.moduleTemplate(mod, template, params)
	if err != nil {
		return "", err
	}
	man, err := c.currentManifest()
	if err != nil {
		return "", err
	}
	expr, err := manifest.ParseLabels(sa.Targets)
	if err != nil {
		return "", fmt.Errorf("controller: standing %s targets: %w", approvalID, err)
	}
	allowed := map[string]bool{}
	for _, a := range sa.Actions {
		allowed[a] = true
	}
	for _, n := range p.Nodes {
		if n.Gate {
			continue
		}
		switch {
		case n.Action == "host.exec":
			return fail("node " + n.ID + " uses host.exec")
		case !allowed[n.Action]:
			return fail(fmt.Sprintf("node %s action %s is not in the standing approval", n.ID, n.Action))
		}
		spec, ok := c.catalog().Action(n.Action)
		if !ok {
			return "", fmt.Errorf("controller: standing %s: node %s: unknown action %s", approvalID, n.ID, n.Action)
		}
		switch plan.EffectiveRisk(n, spec) {
		case plan.RiskLockout, plan.RiskDestructive:
			return fail(fmt.Sprintf("node %s risk is %s", n.ID, plan.EffectiveRisk(n, spec)))
		}
		h, ok := man.Hosts[n.Target]
		if !ok {
			return fail(fmt.Sprintf("node %s target %s is not in the manifest", n.ID, n.Target))
		}
		if !expr.Match(h.Labels) {
			return fail(fmt.Sprintf("node %s target %s does not match targets %q", n.ID, n.Target, sa.Targets))
		}
	}
	approver := sa.Approver + " (standing " + sa.ID + ")"
	p.Class = plan.ClassStanding
	p.Module = mod
	p.Template = template
	p.Approver = approver
	p.ID = PlanIDFor(p, template, "", c.now())
	if fs := lint.Run(p, lint.Ctx{Manifest: man, Query: c.st, Class: p.Class, Actions: c.reg}); len(fs) > 0 {
		parts := make([]string, 0, len(fs))
		for _, f := range fs {
			parts = append(parts, fmt.Sprintf("%s node %s: %s", f.Rule, f.Node, f.Message))
		}
		return "", fmt.Errorf("controller: standing plan %s/%s refused: %s", mod, template, strings.Join(parts, "; "))
	}
	if err := c.CreatePlan(ctx, p, sa.Approver); err != nil {
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
