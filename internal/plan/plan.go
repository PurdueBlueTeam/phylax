package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
)

// Risk is an action's risk class, ordered none < service < lockout < destructive.
type Risk string

const (
	RiskNone        Risk = "none"
	RiskService     Risk = "service"
	RiskLockout     Risk = "lockout"
	RiskDestructive Risk = "destructive"
)

func (r Risk) rank() int {
	switch r {
	case RiskNone, "":
		return 0
	case RiskService:
		return 1
	case RiskLockout:
		return 2
	case RiskDestructive:
		return 3
	}
	return -1
}

// Valid reports whether r is a known risk class.
func (r Risk) Valid() bool { return r.rank() >= 0 }

// FailurePolicy decides what a failed node does to the rest of the plan.
type FailurePolicy string

const (
	StopDependents FailurePolicy = "stop_dependents" // default
	Continue       FailurePolicy = "continue"
	RollbackPlan   FailurePolicy = "rollback_plan"
)

// DefaultDeadman is the dead-man timeout applied to lockout-class nodes that
// don't set one (design: default 90 s).
const DefaultDeadmanSec = 90

// ActionSpec is what the plan engine needs to know about an action.
type ActionSpec struct {
	Name  string
	Risk  Risk
	Locks []string // named per-host resource locks the action takes
	// ValidateParams optionally checks the typed parameters.
	ValidateParams func(params map[string]any) error
}

// Catalog resolves action names. Agents and the controller each supply one.
type Catalog interface {
	Action(name string) (ActionSpec, bool)
}

// MapCatalog is a simple Catalog.
type MapCatalog map[string]ActionSpec

// Action implements Catalog.
func (m MapCatalog) Action(name string) (ActionSpec, bool) { s, ok := m[name]; return s, ok }

// Approval is the approval record that the step signature covers.
type Approval struct {
	By   string `json:"by"`
	At   int64  `json:"at"` // unix seconds
	Note string `json:"note,omitempty"`
}

// Node is one vertex of the plan DAG. A gate node has no action or target.
type Node struct {
	ID         string         `json:"id"`
	Action     string         `json:"action,omitempty"`
	Target     string         `json:"target,omitempty"` // host id
	Params     map[string]any `json:"params"`
	Needs      []string       `json:"needs"`
	Risk       Risk           `json:"risk"`
	Gate       bool           `json:"gate,omitempty"`
	DeadmanSec int            `json:"deadman_sec,omitempty"`
	Note       string         `json:"note,omitempty"`
	// ExpiresAfterSec time-boxes an applied node; 0 means no expiry.
	ExpiresAfterSec int `json:"expires_after_sec,omitempty"`
	// Until turns a gate into gate: auto with its conditions.
	Until *GateUntil `json:"until,omitempty"`
}

// GateUntil is the condition set of a gate: auto node.
type GateUntil struct {
	AfterSec int      `json:"after_sec,omitempty"` // seconds after the gate's last dependency finished
	Probe    string   `json:"probe,omitempty"`     // scored service name, or "*" for every scored service on the plan's targets
	NoEvent  *NoEvent `json:"no_event,omitempty"`
}

// NoEvent fails a gate when an event of Kind (and Fields) appears.
type NoEvent struct {
	Kind   string            `json:"kind"`
	Fields map[string]string `json:"fields,omitempty"`
}

// Plan is an immutable plan definition; runtime state lives in Run.
type Plan struct {
	ID        string        `json:"id"`
	Name      string        `json:"name,omitempty"`
	OnFailure FailurePolicy `json:"on_failure"`
	Nodes     []Node        `json:"nodes"`
	Class     ApprovalClass `json:"class,omitempty"`
	Module    string        `json:"module,omitempty" yaml:"module,omitempty"`
	Template  string        `json:"template,omitempty" yaml:"template,omitempty"`
	Approver  string        `json:"approver,omitempty" yaml:"approver,omitempty"`
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

// RequiresOwnApproval reports whether a node needs its own approval record
// rather than the one-click plan approval: gates, host.exec, and lockout or
// destructive nodes (design: Plan, approve, apply).
func RequiresOwnApproval(n Node, effective Risk) bool {
	return n.Gate || n.Action == "host.exec" || effective.rank() >= RiskLockout.rank()
}

// EffectiveRisk is the max of the declared risk and the catalog's.
func EffectiveRisk(n Node, spec ActionSpec) Risk {
	if spec.Risk.rank() > n.Risk.rank() {
		return spec.Risk
	}
	if n.Risk == "" {
		return RiskNone
	}
	return n.Risk
}

// EffectiveDeadmanSec returns the node's dead-man timeout in seconds, 0 for none.
func EffectiveDeadmanSec(n Node, eff Risk) int {
	if n.DeadmanSec > 0 {
		return n.DeadmanSec
	}
	if eff == RiskLockout || eff == RiskDestructive {
		return DefaultDeadmanSec
	}
	return 0
}

func (p *Plan) policy() FailurePolicy {
	if p.OnFailure == "" {
		return StopDependents
	}
	return p.OnFailure
}

// Validate checks structure, known actions, parameters, risk, acyclicity and
// unordered resource-lock conflicts. All problems are reported together.
func (p *Plan) Validate(cat Catalog) error {
	_, err := p.resolve(cat)
	return err
}

type resolved struct {
	byID  map[string]int
	spec  map[string]ActionSpec
	risk  map[string]Risk
	order []string // deterministic topological order
}

func (p *Plan) resolve(cat Catalog) (*resolved, error) {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if !idRE.MatchString(p.ID) {
		add("plan: invalid id %q", p.ID)
	}
	switch p.policy() {
	case StopDependents, Continue, RollbackPlan:
	default:
		add("plan: unknown on_failure %q", p.OnFailure)
	}
	if len(p.Nodes) == 0 {
		add("plan: no nodes")
	}
	r := &resolved{byID: map[string]int{}, spec: map[string]ActionSpec{}, risk: map[string]Risk{}}
	for i, n := range p.Nodes {
		if !idRE.MatchString(n.ID) {
			add("node %q: invalid id", n.ID)
			continue
		}
		if _, dup := r.byID[n.ID]; dup {
			add("node %q: duplicate id", n.ID)
			continue
		}
		r.byID[n.ID] = i
	}
	for _, n := range p.Nodes {
		if !n.Risk.Valid() {
			add("node %q: unknown risk %q", n.ID, n.Risk)
		}
		if n.DeadmanSec < 0 {
			add("node %q: negative deadman", n.ID)
		}
		if n.Gate {
			if n.Action != "" || n.Target != "" || len(n.Params) > 0 {
				add("node %q: gate must not have action, target or params", n.ID)
			}
		} else {
			if n.Target == "" {
				add("node %q: missing target", n.ID)
			}
			spec, ok := cat.Action(n.Action)
			if !ok {
				add("node %q: unknown action %q", n.ID, n.Action)
			} else {
				r.spec[n.ID] = spec
				if n.Risk.rank() >= 0 && n.Risk.rank() < spec.Risk.rank() {
					add("node %q: declared risk %q understates action risk %q", n.ID, n.Risk, spec.Risk)
				}
				if spec.ValidateParams != nil {
					if err := spec.ValidateParams(n.Params); err != nil {
						add("node %q: params: %v", n.ID, err)
					}
				}
			}
		}
		r.risk[n.ID] = EffectiveRisk(n, r.spec[n.ID])
		seen := map[string]bool{}
		for _, d := range n.Needs {
			if _, ok := r.byID[d]; !ok {
				add("node %q: needs unknown node %q", n.ID, d)
			} else if d == n.ID {
				add("node %q: needs itself", n.ID)
			} else if seen[d] {
				add("node %q: duplicate need %q", n.ID, d)
			}
			seen[d] = true
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	order, cyc := p.topo(r)
	if cyc != nil {
		return nil, fmt.Errorf("plan: dependency cycle involving %v", cyc)
	}
	r.order = order
	// Lock conflicts: two nodes on one host taking the same lock with no
	// dependency path between them have no defined order.
	reach := p.reachability(r)
	for i := range p.Nodes {
		for j := i + 1; j < len(p.Nodes); j++ {
			a, b := p.Nodes[i], p.Nodes[j]
			if a.Gate || b.Gate || a.Target != b.Target {
				continue
			}
			if reach[a.ID][b.ID] || reach[b.ID][a.ID] {
				continue
			}
			if l := sharedLock(r.spec[a.ID].Locks, r.spec[b.ID].Locks); l != "" {
				errs = append(errs, fmt.Errorf("nodes %q and %q both lock %q on %q with no ordering; add a needs edge", a.ID, b.ID, l, a.Target))
			}
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if _, err := p.CanonicalJSON(); err != nil {
		return nil, fmt.Errorf("plan: not canonically serialisable: %w", err)
	}
	return r, nil
}

func sharedLock(a, b []string) string {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return x
			}
		}
	}
	return ""
}

// topo is Kahn's algorithm with ID tie-breaking; on a cycle it returns the
// nodes left over.
func (p *Plan) topo(r *resolved) (order, cycle []string) {
	indeg := map[string]int{}
	dependents := map[string][]string{}
	for _, n := range p.Nodes {
		indeg[n.ID] += len(n.Needs)
		for _, d := range n.Needs {
			dependents[d] = append(dependents[d], n.ID)
		}
	}
	var ready []string
	for _, n := range p.Nodes {
		if indeg[n.ID] == 0 {
			ready = append(ready, n.ID)
		}
	}
	for len(ready) > 0 {
		sort.Strings(ready)
		id := ready[0]
		ready = ready[1:]
		order = append(order, id)
		for _, d := range dependents[id] {
			if indeg[d]--; indeg[d] == 0 {
				ready = append(ready, d)
			}
		}
	}
	if len(order) != len(p.Nodes) {
		in := map[string]bool{}
		for _, id := range order {
			in[id] = true
		}
		for _, n := range p.Nodes {
			if !in[n.ID] {
				cycle = append(cycle, n.ID)
			}
		}
		sort.Strings(cycle)
	}
	return order, cycle
}

// reachability[a][b] is true when b (transitively) needs a... or either
// direction is checked by callers; here reach[x][y] means y is reachable from x
// following "needs" edges (x depends on y).
func (p *Plan) reachability(r *resolved) map[string]map[string]bool {
	reach := map[string]map[string]bool{}
	for _, id := range r.order { // needs come earlier in order
		m := map[string]bool{}
		for _, d := range p.Nodes[r.byID[id]].Needs {
			m[d] = true
			for k := range reach[d] {
				m[k] = true
			}
		}
		reach[id] = m
	}
	return reach
}

func (p *Plan) normalized() Plan {
	q := *p
	q.OnFailure = p.policy()
	q.Nodes = make([]Node, len(p.Nodes))
	for i, n := range p.Nodes {
		n.Needs = append([]string{}, n.Needs...)
		sort.Strings(n.Needs)
		if n.Params == nil {
			n.Params = map[string]any{}
		}
		if n.Risk == "" {
			n.Risk = RiskNone
		}
		q.Nodes[i] = n
	}
	sort.Slice(q.Nodes, func(i, j int) bool { return q.Nodes[i].ID < q.Nodes[j].ID })
	return q
}

// CanonicalJSON is the stable (RFC 8785) serialisation of the plan definition.
// Node order, needs order and nil-vs-empty do not change it.
func (p *Plan) CanonicalJSON() ([]byte, error) {
	q := p.normalized()
	raw, err := json.Marshal(&q)
	if err != nil {
		return nil, err
	}
	return Canonicalize(raw)
}

// Hash is the hex SHA-256 of CanonicalJSON.
func (p *Plan) Hash() (string, error) {
	c, err := p.CanonicalJSON()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(c)
	return hex.EncodeToString(h[:]), nil
}
