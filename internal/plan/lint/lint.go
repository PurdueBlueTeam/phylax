// Package lint is the scoring-safety rule registry over plans.
package lint

import (
	"regexp"
	"sort"
	"sync"

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

var (
	rulesMu sync.RWMutex
	rules   = map[string]Rule{}
)

var idRE = regexp.MustCompile(`^[A-Z]{2,4}[0-9]{3}$`)

// Register adds a rule from init. It panics on a bad or duplicate id.
func Register(r Rule) {
	if !idRE.MatchString(r.ID) {
		panic("lint: bad rule id " + r.ID)
	}
	if r.Check == nil {
		panic("lint: rule " + r.ID + " has no check")
	}
	rulesMu.Lock()
	defer rulesMu.Unlock()
	if _, dup := rules[r.ID]; dup {
		panic("lint: duplicate rule " + r.ID)
	}
	rules[r.ID] = r
}

// Rules returns every rule sorted by id.
func Rules() []Rule {
	rulesMu.RLock()
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		out = append(out, r)
	}
	rulesMu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Run checks every node of p.
func Run(p plan.Plan, c Ctx) []Finding {
	var out []Finding
	for _, r := range Rules() {
		for _, n := range p.Nodes {
			out = append(out, r.Check(n, c)...)
		}
	}
	return out
}
