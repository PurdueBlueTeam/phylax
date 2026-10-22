package detect

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"gopkg.in/yaml.v3"
)

type eventRef = event.Event

// Severity levels, lowest to highest.
var severities = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// ruleDoc is the YAML shape of one rule document.
type ruleDoc struct {
	ID           string            `yaml:"id"`
	Title        string            `yaml:"title"`
	Description  string            `yaml:"description"`
	Mode         string            `yaml:"mode"`
	Scope        string            `yaml:"scope"`
	When         *whenDoc          `yaml:"when"`
	ExemptTagged bool              `yaml:"exempt_tagged"`
	Severity     string            `yaml:"severity"`
	Tier         *int              `yaml:"tier"`
	Collect      []string          `yaml:"collect"`
	Attack       []string          `yaml:"attack"`
	IRTemplate   string            `yaml:"ir_template"`
	Message      string            `yaml:"message"`
	Entities     []string          `yaml:"entities"`
	Needs        string            `yaml:"needs"`
	Source       map[string]string `yaml:"source"`
	Profiles     []profileDoc      `yaml:"profiles"`
	Tests        []testDoc         `yaml:"tests"`
}

type whenDoc struct {
	Event    yaml.Node    `yaml:"event"`
	All      []yaml.Node  `yaml:"all"`
	Any      []yaml.Node  `yaml:"any"`
	Count    *countDoc    `yaml:"count"`
	Sequence *sequenceDoc `yaml:"sequence"`
}

type countDoc struct {
	Window   string    `yaml:"window"`
	Gte      int       `yaml:"gte"`
	By       []string  `yaml:"by"`
	Distinct yaml.Node `yaml:"distinct"`
	Cooldown string    `yaml:"cooldown"`
}

type sequenceDoc struct {
	By     []string `yaml:"by"`
	Within string   `yaml:"within"`
	Then   whenDoc  `yaml:"then"`
}

type profileDoc struct {
	Name      string      `yaml:"name"`
	Event     yaml.Node   `yaml:"event"`
	Key       []string    `yaml:"key"`
	Value     string      `yaml:"value"`
	Learn     string      `yaml:"learn"`
	MaxKeys   int         `yaml:"max_keys"`
	MaxValues int         `yaml:"max_values"`
	Where     []yaml.Node `yaml:"where"`
}

type testDoc struct {
	Name        string      `yaml:"name"`
	ShouldMatch *bool       `yaml:"should_match"`
	Seed        yaml.Node   `yaml:"seed"`
	Event       *testEvent  `yaml:"event"`
	Events      []testEvent `yaml:"events"`
}

type testEvent struct {
	Kind   string         `yaml:"kind"`
	At     string         `yaml:"at"`
	Agent  string         `yaml:"agent"`
	Fields map[string]any `yaml:"fields"`
}

// Rule is a compiled rule.
type Rule struct {
	ID, Title, Description string
	Mode                   string // act or alert
	Scope                  string // agent or controller
	Severity               string
	Tier                   int
	Collect, Attack        []string
	IRTemplate, Needs      string
	Source                 map[string]string
	Kinds                  []string
	File                   string
	Tests                  []TestCase

	exemptTagged bool
	cond         node
	entities     []fieldRef
	msg          *template
	count        *countSpec
	seq          *seqSpec
}

type countSpec struct {
	window   time.Duration
	gte      int
	by       []fieldRef
	distinct []fieldRef // composite: the tuple of values is counted
	cooldown time.Duration
}

type seqSpec struct {
	by         []fieldRef
	within     time.Duration
	thenKinds  []string
	thenCond   node
	thenExempt bool
}

// TestCase is an inline rule test.
type TestCase struct {
	Name        string
	ShouldMatch bool
	Events      []event.Event // times relative to the zero base, shifted by the runner
	Offsets     []time.Duration
	Seed        []seedSpec
}

type seedSpec struct {
	Profile string
	Key     []string
	Values  []string
}

var attackRE = regexp.MustCompile(`^T1\d{3}(\.\d{3})?$`)

// revokedAttack maps revoked ATT&CK ids to their v19 replacements.
var revokedAttack = map[string]string{
	"T1562": "T1685", "T1562.001": "T1685", "T1562.002": "T1685.001", "T1562.004": "T1686",
	"T1562.006": "T1685", "T1562.008": "T1685.002", "T1070.001": "T1685.005", "T1070.002": "T1685.006",
	"T1574.002": "T1574.001",
}

func parseKinds(n *yaml.Node, where string) ([]string, error) {
	switch {
	case n.Kind == 0:
		return nil, fmt.Errorf("%s: event kind is mandatory", where)
	case n.Kind == yaml.ScalarNode && !isNull(n) && n.Value != "":
		return []string{n.Value}, nil
	case n.Kind == yaml.SequenceNode && len(n.Content) > 0:
		var out []string
		for i, c := range n.Content {
			if c.Kind != yaml.ScalarNode || isNull(c) || c.Value == "" {
				return nil, fmt.Errorf("%s[%d]: empty or non-scalar event kind (dangling item?)", where, i)
			}
			out = append(out, c.Value)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s: want an event kind or a non-empty list of kinds", where)
}

func parseDur(s, where string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: bad duration %q", where, s)
	}
	return d, nil
}

func refs(names []string, where string) ([]fieldRef, error) {
	var out []fieldRef
	for i, n := range names {
		if !fieldNameRE.MatchString(n) {
			return nil, fmt.Errorf("%s[%d]: invalid field name %q", where, i, n)
		}
		out = append(out, newFieldRef(n))
	}
	return out, nil
}

// whenCond compiles the all/any lists of a when block into one condition.
func (env *compileEnv) whenCond(w *whenDoc, where string) (node, error) {
	if len(w.All) == 0 && len(w.Any) == 0 {
		return nil, fmt.Errorf("%s: needs a non-empty all or any list (a rule with no conditions would match every event)", where)
	}
	var parts allNode
	if w.All != nil {
		l, err := env.compileList(w.All, where+".all")
		if err != nil {
			return nil, err
		}
		parts = append(parts, l...)
	}
	if w.Any != nil {
		l, err := env.compileList(w.Any, where+".any")
		if err != nil {
			return nil, err
		}
		parts = append(parts, anyNode(l))
	}
	return parts, nil
}

func (env *compileEnv) compileRule(d *ruleDoc, file string) (*Rule, error) {
	r := &Rule{ID: d.ID, Title: d.Title, Description: d.Description, Collect: d.Collect, Attack: d.Attack,
		IRTemplate: d.IRTemplate, Needs: d.Needs, Source: d.Source, File: file, exemptTagged: d.ExemptTagged}
	where := "rule " + d.ID
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._\-]*$`).MatchString(d.ID) {
		return nil, fmt.Errorf("rule %q: invalid id", d.ID)
	}
	if d.Title == "" {
		return nil, fmt.Errorf("%s: title is required", where)
	}
	if r.Mode = d.Mode; r.Mode == "" {
		r.Mode = "act"
	}
	if r.Mode != "act" && r.Mode != "alert" {
		return nil, fmt.Errorf("%s: mode must be act or alert", where)
	}
	if r.Scope = d.Scope; r.Scope == "" {
		r.Scope = "agent"
	}
	if r.Scope != "agent" && r.Scope != "controller" {
		return nil, fmt.Errorf("%s: scope must be agent or controller", where)
	}
	if _, ok := severities[d.Severity]; !ok {
		return nil, fmt.Errorf("%s: severity must be one of info, low, medium, high, critical", where)
	}
	r.Severity = d.Severity
	if d.Tier == nil || *d.Tier < 0 || *d.Tier > 2 {
		return nil, fmt.Errorf("%s: tier must be 0, 1 or 2", where)
	}
	r.Tier = *d.Tier
	if len(d.Attack) == 0 {
		return nil, fmt.Errorf("%s: attack ids are required", where)
	}
	for _, a := range d.Attack {
		if rep, bad := revokedAttack[a]; bad {
			return nil, fmt.Errorf("%s: ATT&CK id %s is revoked in v19; use %s", where, a, rep)
		}
		if !attackRE.MatchString(a) {
			return nil, fmt.Errorf("%s: bad ATT&CK id %q", where, a)
		}
	}
	for i, c := range d.Collect {
		if c == "" {
			return nil, fmt.Errorf("%s: collect[%d] is empty", where, i)
		}
	}
	if d.When == nil {
		return nil, fmt.Errorf("%s: when is required", where)
	}
	w := d.When
	var err error
	if r.Kinds, err = parseKinds(&w.Event, where+".when.event"); err != nil {
		return nil, err
	}
	if r.cond, err = env.whenCond(w, where+".when"); err != nil {
		return nil, err
	}
	if w.Count != nil && w.Sequence != nil {
		return nil, fmt.Errorf("%s: count and sequence are mutually exclusive", where)
	}
	if c := w.Count; c != nil {
		cs := &countSpec{gte: c.Gte}
		if cs.gte < 2 {
			return nil, fmt.Errorf("%s.when.count: gte must be at least 2", where)
		}
		if cs.window, err = parseDur(c.Window, where+".when.count.window"); err != nil {
			return nil, err
		}
		cs.cooldown = cs.window
		if c.Cooldown != "" {
			if cs.cooldown, err = parseDur(c.Cooldown, where+".when.count.cooldown"); err != nil {
				return nil, err
			}
		}
		if cs.by, err = refs(c.By, where+".when.count.by"); err != nil {
			return nil, err
		}
		if c.Distinct.Kind != 0 {
			var names []string
			switch {
			case c.Distinct.Kind == yaml.ScalarNode && !isNull(&c.Distinct) && c.Distinct.Value != "":
				names = []string{c.Distinct.Value}
			case c.Distinct.Kind == yaml.SequenceNode && len(c.Distinct.Content) > 0:
				for i, n := range c.Distinct.Content {
					if n.Kind != yaml.ScalarNode || isNull(n) || n.Value == "" {
						return nil, fmt.Errorf("%s.when.count.distinct[%d]: want a field name (dangling item?)", where, i)
					}
					names = append(names, n.Value)
				}
			default:
				return nil, fmt.Errorf("%s.when.count.distinct: want a field name or a non-empty list of them", where)
			}
			if cs.distinct, err = refs(names, where+".when.count.distinct"); err != nil {
				return nil, err
			}
		}
		r.count = cs
	}
	if s := w.Sequence; s != nil {
		ss := &seqSpec{thenExempt: d.ExemptTagged}
		if len(s.By) == 0 {
			return nil, fmt.Errorf("%s.when.sequence: by is required", where)
		}
		if ss.by, err = refs(s.By, where+".when.sequence.by"); err != nil {
			return nil, err
		}
		if ss.within, err = parseDur(s.Within, where+".when.sequence.within"); err != nil {
			return nil, err
		}
		if ss.thenKinds, err = parseKinds(&s.Then.Event, where+".when.sequence.then.event"); err != nil {
			return nil, err
		}
		if ss.thenCond, err = env.whenCond(&s.Then, where+".when.sequence.then"); err != nil {
			return nil, err
		}
		r.seq = ss
	}
	if r.entities, err = refs(d.Entities, where+".entities"); err != nil {
		return nil, err
	}
	if r.count != nil && len(r.entities) == 0 {
		r.entities = r.count.by
	}
	if r.seq != nil && len(r.entities) == 0 {
		r.entities = r.seq.by
	}
	if r.msg, err = newTemplate(d.Message); err != nil {
		return nil, fmt.Errorf("%s: message: %v", where, err)
	}
	return r, nil
}

// template is a message with {field} placeholders.
type template struct {
	lits   []string
	fields []fieldRef
}

var tmplRE = regexp.MustCompile(`\{([A-Za-z0-9_][A-Za-z0-9_.\-]*)\}`)

func newTemplate(s string) (*template, error) {
	t := &template{}
	last := 0
	for _, m := range tmplRE.FindAllStringSubmatchIndex(s, -1) {
		t.lits = append(t.lits, s[last:m[0]])
		t.fields = append(t.fields, newFieldRef(s[m[2]:m[3]]))
		last = m[1]
	}
	t.lits = append(t.lits, s[last:])
	if strings.Count(s, "{") != len(t.fields) {
		return nil, fmt.Errorf("unbalanced or invalid placeholder in %q", s)
	}
	return t, nil
}

func (t *template) render(c *evalCtx) string {
	var b strings.Builder
	for i, f := range t.fields {
		b.WriteString(t.lits[i])
		if v, ok := f.get(c); ok {
			s, _ := toStr(v)
			b.WriteString(s)
		}
	}
	b.WriteString(t.lits[len(t.lits)-1])
	return b.String()
}
