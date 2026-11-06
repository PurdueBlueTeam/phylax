package lint

import (
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// ClickOnly are the actions that always need a human click: they are never run
// from an auto plan even when the module may act.
var ClickOnly = map[string]bool{
	"proc.kill_tree":            true,
	"ad.account.krbtgt_reset":   true,
	"palo.revert":               true,
	"backup.restore":            true,
	"user.set_password":         true,
	"ad.account.reset_password": true,
	"splunk.password":           true,
}

// PinnedReadOnlyHostExec is the pre-approved read-only host.exec tool list.
// The list is unbuilt, so an empty map refuses every host.exec in an auto
// plan.
//
// shortcut: the pinned read-only tool list is not in the tree yet; empty means
// host.exec is never automatic, upgrade when the hash-pinned list lands.
var PinnedReadOnlyHostExec = map[string]bool{}

func init() {
	Register(Rule{
		ID:  "SS010",
		Doc: "Auto plans run only reversible or read-only nodes; the click-only set is refused.",
		Check: func(n plan.Node, c Ctx) []Finding {
			return ss010(n, c)
		},
	})
}

func ss010(n plan.Node, c Ctx) []Finding {
	if c.Class != plan.ClassAuto || n.Gate {
		return nil
	}
	refuse := func(msg string) []Finding {
		return []Finding{{Rule: "SS010", Node: n.ID, Message: msg}}
	}
	if n.Action == hostExec {
		if !pinnedReadOnlyHostExec(n, c.Actions) {
			return refuse("host.exec outside the pinned read-only tools")
		}
		return nil
	}
	if ClickOnly[n.Action] {
		return refuse(n.Action + " always needs a click")
	}
	if c.Actions == nil {
		return refuse("no action registry to check " + n.Action)
	}
	a, err := c.Actions.Get(n.Action)
	if err != nil {
		return refuse("unknown action " + n.Action)
	}
	sp := a.Spec()
	params, err := lintParams(sp, n)
	if err != nil {
		return refuse(n.Action + " params: " + err.Error())
	}
	touches := a.Touches(params)
	if scoredPasswordSet(c.Manifest, touches) && !resync(n) {
		return refuse(n.Action + " sets a scored account password outside a resync transaction")
	}
	if sp.Risk == actions.RiskDestructive {
		return refuse("destructive action " + n.Action)
	}
	eff := plan.EffectiveRisk(n, plan.ActionSpec{Name: sp.Name, Risk: plan.Risk(sp.Risk)})
	if !reversible(n, sp, eff) {
		return refuse(n.Action + " is not reversible: no rollback data, dead-man or pre-change snapshot")
	}
	return nil
}

// pinnedReadOnlyHostExec reports whether the node runs a pinned read-only tool.
func pinnedReadOnlyHostExec(n plan.Node, reg *actions.Registry) bool {
	if reg == nil {
		return false
	}
	a, err := reg.Get(hostExec)
	if err != nil {
		return false
	}
	p, err := a.Spec().Validate(n.Params)
	if err != nil {
		return false
	}
	argv := p.List("argv")
	return len(argv) > 0 && PinnedReadOnlyHostExec[argv[0]]
}

// lintParams validates the node's params, allowing the future resync marker
// (`txn: resync`) without treating it as an action parameter.
func lintParams(sp actions.Spec, n plan.Node) (actions.Params, error) {
	raw := n.Params
	if resync(n) && raw != nil {
		cp := make(map[string]any, len(raw))
		for k, v := range raw {
			if k != "txn" {
				cp[k] = v
			}
		}
		raw = cp
	}
	return sp.Validate(raw)
}

// resync reports whether the node is a creds resync re-apply. W7 adds the
// plan-level transaction marker; today a node may carry txn: resync.
func resync(n plan.Node) bool {
	v, _ := n.Params["txn"].(string)
	return v == "resync"
}

// scoredPasswordSet reports whether any touch sets a protected account's
// password. An unknown manifest fails closed.
func scoredPasswordSet(m *manifest.Manifest, touches []actions.Touch) bool {
	for _, t := range touches {
		if t.Kind != actions.TouchAccount || t.Op != actions.OpSetPassword {
			continue
		}
		if m == nil {
			return true
		}
		for id, a := range m.Accounts {
			if !a.Protected() {
				continue
			}
			name := a.Username
			if name == "" {
				name, _, _ = strings.Cut(id, "@")
			}
			if strings.EqualFold(name, t.Name) || strings.EqualFold(id, t.Name) {
				return true
			}
		}
	}
	return false
}

// reversible reports whether a node is read-only or has an automatic undo:
// rollback data (service risk), a dead-man window or a pre-change snapshot.
func reversible(n plan.Node, sp actions.Spec, eff plan.Risk) bool {
	if sp.ReadOnly || n.ExpiresAfterSec > 0 {
		return true
	}
	if plan.EffectiveDeadmanSec(n, eff) > 0 {
		return true
	}
	switch sp.Risk {
	case actions.RiskNone, actions.RiskService:
		return true
	}
	return false
}
