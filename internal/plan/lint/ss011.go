package lint

import "github.com/PurdueBlueTeam/phylax/internal/plan"

func init() {
	Register(Rule{
		ID:  "SS011",
		Doc: "A plan that touches a scored service must use on_failure: rollback_plan; an explicit stop_dependents or continue is refused.",
		Check: func(n plan.Node, c Ctx) []Finding {
			return ss011(n, c)
		},
	})
}

func ss011(n plan.Node, c Ctx) []Finding {
	if c.Plan == nil || c.Manifest == nil || c.Actions == nil || n.Gate {
		return nil
	}
	switch c.Class {
	case plan.ClassClick, plan.ClassStanding, plan.ClassAuto:
	default:
		return nil
	}
	switch c.Plan.OnFailure {
	case plan.StopDependents, plan.Continue:
	default:
		return nil // omitted (defaulted by the controller) or already rollback_plan
	}
	a, err := c.Actions.Get(n.Action)
	if err != nil {
		return nil
	}
	params, err := a.Spec().Validate(n.Params)
	if err != nil {
		return nil
	}
	if len(plan.ScoredTouch(c.Manifest, n, a.Touches(params))) == 0 {
		return nil
	}
	return []Finding{{Rule: "SS011", Node: n.ID,
		Message: "plan touches a scored service: on_failure must be rollback_plan"}}
}
