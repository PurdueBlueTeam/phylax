// Package lint is the scoring-safety rule registry over plans.
package lint

import (
	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// Finding is one lint result.
type Finding struct{ Rule, Node, Message string }

// Ctx is what a rule may inspect.
type Ctx struct {
	Manifest *manifest.Manifest
	Query    store.Reader
	Class    plan.ApprovalClass
	Actions  *actions.Registry
}

// Rule is one lint rule.
type Rule struct {
	ID    string // ^[A-Z]{2,4}[0-9]{3}$
	Doc   string
	Check func(n plan.Node, c Ctx) []Finding
}

// Register adds a rule from init. It panics on a bad or duplicate id.
func Register(r Rule) { panic("unimplemented: W1 Task 21") }

// Rules returns every rule sorted by id.
func Rules() []Rule { panic("unimplemented: W1 Task 21") }

// Run checks every node of p.
func Run(p plan.Plan, c Ctx) []Finding { panic("unimplemented: W1 Task 21") }
