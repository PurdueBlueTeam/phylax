package lint

import (
	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// ClickOnly are the actions that always need a human click: they are never run
// from an `auto` plan even when the module may act.
var ClickOnly = map[string]bool{
	"proc.kill_tree":          true,
	"ad.account.krbtgt_reset": true,
	"palo.revert":             true,
	"backup.restore":          true,
}

// hostExec is the design's explicit escape hatch; it is never automatic.
const hostExec = "host.exec"

func init() {
	Register(Rule{
		ID:  "SS000",
		Doc: "Automatic plans run only read-only, no-risk, untouching actions; auto plans refuse click-only and destructive actions.",
		Check: func(n plan.Node, c Ctx) []Finding {
			return ss000(n, c)
		},
	})
}

func ss000(n plan.Node, c Ctx) []Finding {
	if c.Class != plan.ClassAutoReadOnly && c.Class != plan.ClassAuto {
		return nil
	}
	refuse := func(msg string) []Finding {
		return []Finding{{Rule: "SS000", Node: n.ID, Message: msg}}
	}
	if n.Action == hostExec {
		return refuse("host.exec is never automatic")
	}
	if c.Actions == nil {
		return refuse("no action registry to check " + n.Action)
	}
	a, err := c.Actions.Get(n.Action)
	if err != nil {
		return refuse("unknown action " + n.Action)
	}
	sp := a.Spec()
	if c.Class == plan.ClassAuto {
		if sp.Risk == actions.RiskDestructive {
			return refuse("destructive action " + n.Action)
		}
		if ClickOnly[n.Action] {
			return refuse(n.Action + " always needs a click")
		}
		return nil
	}
	// auto_readonly: nothing may change, and nothing scored may be touched.
	if n.Gate {
		return refuse("a gate is not read-only")
	}
	if !sp.ReadOnly {
		return refuse(n.Action + " is not read-only")
	}
	if sp.Risk != actions.RiskNone {
		return refuse(n.Action + " has risk " + string(sp.Risk))
	}
	p, err := sp.Validate(n.Params)
	if err != nil {
		return refuse(n.Action + " params: " + err.Error())
	}
	if t := a.Touches(p); len(t) != 0 {
		return refuse(n.Action + " touches " + string(t[0].Kind) + " " + t[0].Name)
	}
	return nil
}
