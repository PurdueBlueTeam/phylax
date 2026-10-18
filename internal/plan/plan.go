// Package plan implements the plan model and the controller-side execution
// state machine: a DAG of typed actions, dry-run diffs, named locks, the
// dead-man switch and ordered rollback (docs: Build plan → M2).
package plan

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)
// DefaultDeadman is the step timeout in seconds when a node does not set
// one.
const DefaultDeadman = 90

// Node is one typed action in the plan DAG.
type Node struct {
	ID      string         `json:"id" yaml:"id"`
	Action  string         `json:"action" yaml:"action"`
	Params  map[string]any `json:"params,omitempty" yaml:"params,omitempty"`
	Depends []string       `json:"depends,omitempty" yaml:"depends,omitempty"`
	Locks   []string       `json:"locks,omitempty" yaml:"locks,omitempty"`
	Deadman int            `json:"deadman,omitempty" yaml:"deadman,omitempty"`
}

// Plan is a named DAG of nodes.
type Plan struct {
	Name  string `json:"name" yaml:"name"`
	Nodes []Node `json:"nodes" yaml:"nodes"`
}

// Load parses a plan document (JSON or YAML) and validates it.
func Load(b []byte) (*Plan, error) {
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		if yerr := yaml.Unmarshal(b, &p); yerr != nil {
			return nil, fmt.Errorf("plan: %v (yaml: %v)", err, yerr)
		}
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks structure: unique ids, dependency closure, no cycles,
// known deadman.
func (p *Plan) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("plan: name required")
	}
	if len(p.Nodes) == 0 {
		return fmt.Errorf("plan %s: no nodes", p.Name)
	}
	seen := map[string]bool{}
	for _, n := range p.Nodes {
		if n.ID == "" || n.Action == "" {
			return fmt.Errorf("plan %s: node with empty id or action", p.Name)
		}
		if seen[n.ID] {
			return fmt.Errorf("plan %s: duplicate node %s", p.Name, n.ID)
		}
		seen[n.ID] = true
		if n.Deadman < 0 {
			return fmt.Errorf("plan %s: node %s has negative deadman", p.Name, n.ID)
		}
	}
	for _, n := range p.Nodes {
		for _, d := range n.Depends {
			if !seen[d] {
				return fmt.Errorf("plan %s: node %s depends on unknown %s", p.Name, n.ID, d)
			}
		}
	}
	if _, err := p.Order(); err != nil {
		return err
	}
	return nil
}

// Order returns node ids in topological order (stable: input order breaks
// ties). It errors on cycles.
func (p *Plan) Order() ([]string, error) {
	depCount := map[string]int{}
	dependents := map[string][]string{}
	pos := map[string]int{}
	for i, n := range p.Nodes {
		pos[n.ID] = i
		depCount[n.ID] = len(n.Depends)
		for _, d := range n.Depends {
			dependents[d] = append(dependents[d], n.ID)
		}
	}
	var out []string
	for len(out) < len(p.Nodes) {
		// pick the lowest input-position node with no remaining deps
		pick := ""
		for id, c := range depCount {
			if c != 0 {
				continue
			}
			if pick == "" || pos[id] < pos[pick] {
				pick = id
			}
		}
		if pick == "" {
			var stuck []string
			for id, c := range depCount {
				if c != 0 {
					stuck = append(stuck, id)
				}
			}
			sort.Strings(stuck)
			return nil, fmt.Errorf("plan %s: dependency cycle involving %v", p.Name, stuck)
		}
		out = append(out, pick)
		delete(depCount, pick)
		for _, d := range dependents[pick] {
			depCount[d]--
		}
	}
	return out, nil
}

// DepsOf returns the node's dependency list.
func (p *Plan) Node(id string) (Node, bool) {
	for _, n := range p.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

// Descendants returns all transitive dependents of id.
func (p *Plan) Descendants(id string) map[string]bool {
	out := map[string]bool{}
	var visit func(x string)
	visit = func(x string) {
		for _, n := range p.Nodes {
			if out[n.ID] {
				continue
			}
			for _, d := range n.Depends {
				if d == x {
					out[n.ID] = true
					visit(n.ID)
				}
			}
		}
	}
	visit(id)
	delete(out, id)
	return out
}

// Canonical is the signing string for a step (docs/protocol.md: ed25519 over
// plan|node|epoch|seq|op|phase|action|params).
func Canonical(planName string, node string, epoch int, seq uint64, op string, phase string, action string, params map[string]any) string {
	ps, _ := json.Marshal(params)
	return strings.Join([]string{planName, node, fmt.Sprint(epoch), fmt.Sprint(seq), op, phase, action, string(ps)}, "|")
}
