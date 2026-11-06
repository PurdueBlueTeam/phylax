package controller

import (
	"context"
	"errors"
	"fmt"

	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// maxOpenProposalsPerModule bounds the proposal queue. Beyond it the oldest
// open proposal of that module is dismissed.
const maxOpenProposalsPerModule = 1000

// ErrProposalClosed is returned when a proposal is accepted or dismissed twice.
var ErrProposalClosed = errors.New("controller: proposal is already closed")

// Propose records a one-click plan suggestion. The template must load and
// expand now: a broken proposal is refused at creation, not at the click.
func (c *Controller) Propose(ctx context.Context, p module.Proposal) (int64, error) {
	if p.Module == "" {
		return 0, errors.New("controller: proposal has no module")
	}
	if len(p.Title) > 200 {
		return 0, fmt.Errorf("controller: proposal title is %d bytes, limit 200", len(p.Title))
	}
	def, err := c.moduleTemplate(p.Module, p.Template, p.Params)
	if err != nil {
		return 0, err
	}
	_ = def // validation only; AcceptProposal expands the template again
	open, err := c.st.OpenProposals(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	var oldest *store.ProposalRow
	for i := range open {
		if open[i].Module != p.Module {
			continue
		}
		if oldest == nil {
			oldest = &open[i]
		}
		n++
	}
	if n >= maxOpenProposalsPerModule && oldest != nil {
		if err := c.st.CloseProposal(ctx, oldest.ID, "dismissed", "", "system"); err != nil {
			return 0, err
		}
	}
	ev := make([]string, 0, len(p.Evidence))
	for _, e := range p.Evidence {
		ev = append(ev, fmt.Sprintf("%s:%d", e.Agent, e.Seq))
	}
	if p.Params == nil {
		p.Params = map[string]string{}
	}
	return c.st.InsertProposal(ctx, store.ProposalRow{
		Module: p.Module, Title: p.Title, Template: p.Template, Params: p.Params,
		Evidence: ev, Reason: p.Reason, Created: c.now(), State: "open",
	})
}

// moduleTemplate loads and expands one module template for params.
func (c *Controller) moduleTemplate(mod, template string, params map[string]string) (plan.Plan, error) {
	p, err := LoadModuleTemplateFor(c.cfg.PlansPath, mod, template, c.hostsMatching)
	if err != nil {
		return p, err
	}
	return plan.ExpandTemplate(p, params)
}

// OpenProposals lists open proposals, oldest first.
func (c *Controller) OpenProposals(ctx context.Context) ([]store.ProposalRow, error) {
	return c.st.OpenProposals(ctx)
}

// AcceptProposal creates the proposed plan with the click class, runs its dry
// run, approves and applies it, then closes the proposal as accepted.
func (c *Controller) AcceptProposal(ctx context.Context, id int64, by string) (string, error) {
	row, err := c.st.Proposal(ctx, id)
	if err != nil {
		return "", err
	}
	if row.State != "open" {
		return "", fmt.Errorf("%w: proposal %d is %s", ErrProposalClosed, id, row.State)
	}
	p, err := c.moduleTemplate(row.Module, row.Template, row.Params)
	if err != nil {
		return "", err
	}
	p.Class = plan.ClassClick
	p.Module = row.Module
	p.Template = row.Template
	p.Approver = by
	p.ID = PlanIDFor(p, row.Template, "", c.now())
	if err := c.CreatePlan(ctx, p, by); err != nil {
		return "", err
	}
	if _, err := c.DryRun(ctx, p.ID); err != nil {
		return "", err
	}
	if err := c.ApprovePlan(ctx, p.ID, by); err != nil {
		return "", err
	}
	if err := c.Apply(ctx, p.ID); err != nil {
		return "", err
	}
	if err := c.st.CloseProposal(ctx, id, "accepted", p.ID, by); err != nil {
		return "", err
	}
	return p.ID, nil
}

// DismissProposal closes an open proposal without a plan.
func (c *Controller) DismissProposal(ctx context.Context, id int64, by string) error {
	row, err := c.st.Proposal(ctx, id)
	if err != nil {
		return err
	}
	if row.State != "open" {
		return fmt.Errorf("%w: proposal %d is %s", ErrProposalClosed, id, row.State)
	}
	return c.st.CloseProposal(ctx, id, "dismissed", "", by)
}

// proposeFallback records the click proposal an automatic path degrades to and
// returns module.ErrProposed with the reason.
func (c *Controller) proposeFallback(ctx context.Context, mod, template string, params map[string]string, reason string) (string, error) {
	title := template + ": " + reason
	if len(title) > 200 {
		title = title[:200]
	}
	if params == nil {
		params = map[string]string{}
	}
	if _, err := c.Propose(ctx, module.Proposal{Module: mod, Title: title, Template: template, Params: params, Reason: reason}); err != nil {
		return "", fmt.Errorf("%w: %s (proposal not recorded: %v)", module.ErrProposed, reason, err)
	}
	return "", fmt.Errorf("%w: %s", module.ErrProposed, reason)
}
