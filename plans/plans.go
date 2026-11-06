// Package plans embeds the plan templates (incl. the first-hour library) and
// validates them against internal/plan and the action catalog.
package plans

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/actions"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"gopkg.in/yaml.v3"
)

//go:embed *.yaml first-hour/*.yaml
var FS embed.FS

// Template is a plan with variables. A node with `each: <listvar>` expands to
// one node per list element; `${host}` is the element, `${var}` any variable.
type Template struct {
	ID        string             `yaml:"id"`
	Module    string             `yaml:"module"`
	Name      string             `yaml:"name"`
	OnFailure plan.FailurePolicy `yaml:"on_failure"`
	Vars      map[string]any     `yaml:"vars"`
	Scoring   string             `yaml:"scoring_note"`
	Probe     string             `yaml:"probe"`
	Nodes     []TNode            `yaml:"nodes"`
}

type TNode struct {
	ID         string         `yaml:"id"`
	Action     string         `yaml:"action"`
	Target     string         `yaml:"target"`
	Params     map[string]any `yaml:"params"`
	Needs      []string       `yaml:"needs"`
	Risk       plan.Risk      `yaml:"risk"`
	Gate       bool           `yaml:"gate"`
	DeadmanSec int            `yaml:"deadman_sec"`
	Note       string         `yaml:"note"`
	Each       string         `yaml:"each"`
}

type extSpec struct {
	Risk   plan.Risk                 `yaml:"risk"`
	Locks  []string                  `yaml:"locks"`
	Todo   string                    `yaml:"todo"`
	Params map[string]map[string]any `yaml:"params"`
}

// Catalog resolves core agent actions plus the data-only extension specs.
type Catalog struct {
	reg *actions.Registry
	ext map[string]extSpec
}

// NewCatalog loads actions.yaml on top of actions.Core().
func NewCatalog() (*Catalog, error) {
	b, err := FS.ReadFile("actions.yaml")
	if err != nil {
		return nil, err
	}
	var f struct {
		Actions map[string]extSpec `yaml:"actions"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("actions.yaml: %w", err)
	}
	c := &Catalog{reg: actions.Core(), ext: f.Actions}
	for n := range c.ext {
		if _, err := c.reg.Get(n); err == nil {
			return nil, fmt.Errorf("actions.yaml: %q already implemented; remove the stub", n)
		}
	}
	return c, nil
}

// Missing lists extension actions (TODO until the agent implements them).
func (c *Catalog) Missing() []string {
	var out []string
	for n := range c.ext {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Action implements plan.Catalog.
func (c *Catalog) Action(name string) (plan.ActionSpec, bool) {
	if a, err := c.reg.Get(name); err == nil {
		spec := a.Spec()
		return plan.ActionSpec{Name: spec.Name, Risk: plan.Risk(spec.Risk),
			ValidateParams: func(m map[string]any) error { _, err := spec.Validate(m); return err }}, true
	}
	e, ok := c.ext[name]
	if !ok {
		return plan.ActionSpec{}, false
	}
	return plan.ActionSpec{Name: name, Risk: e.Risk, Locks: e.Locks, ValidateParams: func(m map[string]any) error {
		for k := range m {
			if _, ok := e.Params[k]; !ok {
				return fmt.Errorf("unknown parameter %q", k)
			}
		}
		for k, s := range e.Params {
			if req, _ := s["required"].(bool); req {
				if _, ok := m[k]; !ok {
					return fmt.Errorf("missing parameter %q", k)
				}
			}
		}
		return nil
	}}, true
}

// Load reads a template by path within FS.
func Load(path string) (*Template, error) {
	b, err := FS.ReadFile(path)
	if err != nil {
		return nil, err
	}
	t, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return t, nil
}

// Paths lists every template file.
func Paths() []string {
	var out []string
	fs.WalkDir(FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".yaml") && p != "actions.yaml" {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

var varRE = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)\}`)

func subst(v any, vars map[string]any) (any, error) {
	switch x := v.(type) {
	case string:
		// A whole-string reference keeps the variable's type (lists, ints).
		if m := varRE.FindStringSubmatch(x); m != nil && m[0] == x {
			val, ok := vars[m[1]]
			if !ok {
				return nil, fmt.Errorf("undefined variable %q", m[1])
			}
			return val, nil
		}
		var err error
		out := varRE.ReplaceAllStringFunc(x, func(s string) string {
			name := s[2 : len(s)-1]
			val, ok := vars[name]
			if !ok {
				err = fmt.Errorf("undefined variable %q", name)
				return s
			}
			return fmt.Sprint(val)
		})
		return out, err
	case map[string]any:
		m := map[string]any{}
		for k, e := range x {
			r, err := subst(e, vars)
			if err != nil {
				return nil, err
			}
			m[k] = r
		}
		return m, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			r, err := subst(e, vars)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	}
	return v, nil
}

// Expand renders the template into a concrete plan. overrides replace Vars;
// a node with no declared risk takes its action's catalog risk.
func (t *Template) Expand(cat plan.Catalog, overrides map[string]any) (*plan.Plan, error) {
	vars := map[string]any{}
	for k, v := range t.Vars {
		vars[k] = v
	}
	for k, v := range overrides {
		vars[k] = v
	}
	p := &plan.Plan{ID: t.ID, Name: t.Name, OnFailure: t.OnFailure}
	inst := map[string][]string{} // template node id -> expanded ids
	for _, n := range t.Nodes {
		if n.Each == "" {
			inst[n.ID] = []string{n.ID}
			continue
		}
		list, ok := vars[n.Each].([]any)
		if !ok {
			return nil, fmt.Errorf("node %q: each %q is not a list", n.ID, n.Each)
		}
		for _, h := range list {
			inst[n.ID] = append(inst[n.ID], n.ID+"."+fmt.Sprint(h))
		}
	}
	for _, n := range t.Nodes {
		var hosts []any
		if n.Each != "" {
			hosts = vars[n.Each].([]any)
		} else {
			hosts = []any{nil}
		}
		for i, h := range hosts {
			v := map[string]any{}
			for k, x := range vars {
				v[k] = x
			}
			if h != nil {
				v["host"] = h
			}
			pn := plan.Node{ID: inst[n.ID][i], Action: n.Action, Risk: n.Risk, Gate: n.Gate, DeadmanSec: n.DeadmanSec, Note: n.Note}
			if n.Target != "" {
				tv, err := subst(n.Target, v)
				if err != nil {
					return nil, fmt.Errorf("node %q: %w", n.ID, err)
				}
				pn.Target = fmt.Sprint(tv)
			}
			if n.Params != nil {
				pv, err := subst(n.Params, v)
				if err != nil {
					return nil, fmt.Errorf("node %q: %w", n.ID, err)
				}
				pn.Params = pv.(map[string]any)
			}
			if !n.Gate {
				if pn.Params == nil {
					pn.Params = map[string]any{}
				}
				if pn.Risk == "" {
					if sp, ok := cat.Action(n.Action); ok {
						pn.Risk = sp.Risk
					}
				}
			}
			for _, d := range n.Needs {
				ids, ok := inst[d]
				if !ok {
					return nil, fmt.Errorf("node %q needs unknown %q", n.ID, d)
				}
				// Same-host expansion depends on its own instance only.
				if n.Each != "" && n.Each == eachOf(t, d) {
					pn.Needs = append(pn.Needs, ids[i])
				} else {
					pn.Needs = append(pn.Needs, ids...)
				}
			}
			p.Nodes = append(p.Nodes, pn)
		}
	}
	return p, nil
}

func eachOf(t *Template, id string) string {
	for _, n := range t.Nodes {
		if n.ID == id {
			return n.Each
		}
	}
	return ""
}
