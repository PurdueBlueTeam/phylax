// Package detect is the rule engine (docs: Local detection rules). Rules
// are YAML files with a deliberately small language: field matches, list
// membership, regex, negation, and count-over-window thresholds. No
// general query language; cross-host correlation happens on the
// controller. Every rule in the repo carries its severity, tier,
// ATT&CK mapping and a test reference; CI rejects a rule without a test.
package detect

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Rule is one detection rule.
type Rule struct {
	ID       string     `yaml:"id" json:"id"`
	When     When       `yaml:"when" json:"when"`
	Severity string     `yaml:"severity" json:"severity"` // info | low | medium | high | critical
	Tier     int        `yaml:"tier" json:"tier"`         // 0 automatic | 1 one-click | 2 manual
	Collect  []string   `yaml:"collect,omitempty" json:"collect,omitempty"`
	Attack   []string   `yaml:"attack,omitempty" json:"attack,omitempty"`
	Test     string     `yaml:"test,omitempty" json:"test,omitempty"`
	cooldown time.Duration
}

// When is a rule's trigger.
type When struct {
	Event string    `yaml:"event" json:"event"`
	All   []Cond    `yaml:"all,omitempty" json:"all,omitempty"`
	Any   []Cond    `yaml:"any,omitempty" json:"any,omitempty"`
	Count *Counting `yaml:"count,omitempty" json:"count,omitempty"`
}

// Counting is a count-over-window threshold.
type Counting struct {
	Event  string `yaml:"event,omitempty" json:"event,omitempty"` // default: the rule's own event
	Window string `yaml:"window" json:"window"`
	GTE    int    `yaml:"gte" json:"gte"`
}

// Cond is one condition. Either a single-key field map (comm: bash,
// path: {in: [...]}, {re: ...}, {not: ...}, {all: [...]}, {any: [...]})
// or a top-level not/all/any combinator.
type Cond map[string]any

// Alert is one fired rule.
type Alert struct {
	Rule     string         `json:"rule"`
	Severity string         `json:"severity"`
	Tier     int            `json:"tier"`
	Attack   []string       `json:"attack,omitempty"`
	Event    map[string]any `json:"event"`
	Key      string         `json:"key"` // dedupe key
	TS       time.Time      `json:"ts"`
}

// AlertSink receives fired alerts.
type AlertSink interface {
	Alert(Alert)
}

// Engine evaluates rules.
type Engine struct {
	mu      sync.RWMutex
	rules   []Rule
	sink    AlertSink
	cooldown time.Duration // default per rule+key cooldown

	countMu sync.Mutex
	counts  map[string]*window // rule id -> window of match timestamps
	seen    map[string]time.Time // rule|key -> last alert time
}

// New builds an engine with the given alert sink.
func New(sink AlertSink) *Engine {
	return &Engine{
		sink: sink, cooldown: 30 * time.Second,
		counts: map[string]*window{}, seen: map[string]time.Time{},
	}
}
// Load reads every *.yml file in dir; a file may hold several rules
// separated by "---".
func (e *Engine) Load(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var rules []Rule
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".yml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			return err
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		for {
			var r Rule
			if err := dec.Decode(&r); err != nil {
				if err == io.EOF {
					break
				}
				return fmt.Errorf("%s: %w", ent.Name(), err)
			}
			if r.ID == "" {
				return fmt.Errorf("%s: missing id", ent.Name())
			}
			if r.Test == "" {
				return fmt.Errorf("%s: rule %s has no test reference (CI requires one)", ent.Name(), r.ID)
			}
			if r.cooldown == 0 {
				r.cooldown = 30 * time.Second
			}
			rules = append(rules, r)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
	return nil
}

// Rules returns the loaded rule set.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Handle evaluates one event against all rules.
func (e *Engine) Handle(evType string, data map[string]any) {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()
	now := time.Now()
	for _, r := range rules {
		if r.When.Event != evType {
			continue
		}
		if !matchConds(r.When.All, data) {
			continue
		}
		if len(r.When.Any) > 0 && !matchAny(r.When.Any, data) {
			continue
		}
		if r.When.Count != nil && !e.countOK(r, now) {
			continue
		}
		key := alertKey(data)
		e.countMu.Lock()
		if last, ok := e.seen[r.ID+"|"+key]; ok && now.Sub(last) < r.cooldown {
			e.countMu.Unlock()
			continue
		}
		e.seen[r.ID+"|"+key] = now
		e.countMu.Unlock()
		e.sink.Alert(Alert{
			Rule: r.ID, Severity: r.Severity, Tier: r.Tier,
			Attack: r.Attack, Event: data, Key: key, TS: now,
		})
	}
}

func (e *Engine) countOK(r Rule, now time.Time) bool {
	c := r.When.Count
	// Same-event counts only: the rule's own event is the one being
	// handled. (The `count.event` field is accepted but unused in v1.)
	win, _ := time.ParseDuration(c.Window)
	if win <= 0 {
		win = 5 * time.Minute
	}
	e.countMu.Lock()
	defer e.countMu.Unlock()
	w, ok := e.counts[r.ID]
	if !ok {
		w = &window{}
		e.counts[r.ID] = w
	}
	w.add(now)
	return w.recent(now.Add(-win)) >= c.GTE
}

type window struct {
	t []time.Time
}

func (w *window) add(t time.Time) { w.t = append(w.t, t) }

func (w *window) recent(since time.Time) int {
	n := 0
	for i := range w.t {
		if w.t[i].After(since) {
			n++
		}
	}
	// prune
	kept := w.t[:0]
	for i := range w.t {
		if w.t[i].After(since) {
			kept = append(kept, w.t[i])
		}
	}
	w.t = kept
	return n
}

// alertKey is the dedupe identity of an event: the most specific
// identifier fields, in priority order.
func alertKey(data map[string]any) string {
	for _, f := range []string{"pid", "path", "inode", "file", "laddr", "raddr", "rule"} {
		if v, ok := data[f]; ok {
			return f + "=" + fmt.Sprint(v)
		}
	}
	return fmt.Sprint(data)
}

// matchConds evaluates all conditions (AND).
func matchConds(cs []Cond, data map[string]any) bool {
	for _, c := range cs {
		if !matchCond(c, data) {
			return false
		}
	}
	return true
}

func matchAny(cs []Cond, data map[string]any) bool {
	for _, c := range cs {
		if matchCond(c, data) {
			return true
		}
	}
	return false
}

// matchCond evaluates one condition.
func matchCond(c Cond, data map[string]any) bool {
	for k, v := range c {
		switch k {
		case "not":
			return !matchCond(oneCond(v), data)
		case "all":
			return matchConds(condList(v), data)
		case "any":
			return matchAny(condList(v), data)
		default:
			// field condition
			field, want := k, v
			return fieldMatch(field, want, data)
		}
	}
	return false
}

func oneCond(v any) Cond {
	if m, ok := v.(Cond); ok {
		return m
	}
	if m, ok := v.(map[string]any); ok {
		return Cond(m)
	}
	return Cond{}
}

func condList(v any) []Cond {
	switch l := v.(type) {
	case []Cond:
		return l
	case []any:
		var out []Cond
		for _, x := range l {
			switch c := x.(type) {
			case Cond:
				out = append(out, c)
			case map[string]any:
				out = append(out, c)
			}
		}
		return out
	}
	return nil
}

// fieldMatch evaluates one field spec against the event data.
func fieldMatch(field string, want any, data map[string]any) bool {
	got, ok := lookup(data, field)
	if !ok {
		return false
	}
	gs := asString(got)
	switch w := want.(type) {
	case map[string]any:
		return specOrNot(gs, got, w, data)
	case Cond:
		return specOrNot(gs, got, map[string]any(w), data)
	case []any:
		for _, x := range w {
			if eqVal(gs, asString(x)) {
				return true
			}
		}
		return false
	case []string:
		for _, x := range w {
			if eqVal(gs, x) {
				return true
			}
		}
		return false
	default:
		return eqVal(gs, asString(want))
	}
}

// specOrNot applies a spec, honoring a {not: ...} wrapper (the spec is
// evaluated normally and the result inverted).
func specOrNot(gs string, got any, w map[string]any, data map[string]any) bool {
	if inner, isNot := w["not"]; isNot {
		innerSpec, ok := inner.(map[string]any)
		if !ok {
			innerSpec = map[string]any(oneCond(inner))
		}
		return !specMatch(gs, got, innerSpec, data)
	}
	return specMatch(gs, got, w, data)
}

func specMatch(gs string, got any, w map[string]any, data map[string]any) bool {
	for op, val := range w {
		switch op {
		case "in":
			list, _ := val.([]any)
			for _, x := range list {
				if eqVal(gs, asString(x)) {
					return true
				}
			}
			return false
		case "not_in":
			list, _ := val.([]any)
			for _, x := range list {
				if eqVal(gs, asString(x)) {
					return false
				}
			}
			return true
		case "re":
			re, ok := val.(string)
			if !ok {
				return false
			}
			matched, _ := regexp.MatchString(re, gs)
			return matched
		case "ne":
			return !eqVal(gs, asString(val))
		case "eq":
			return eqVal(gs, asString(val))
		case "gt", "lt":
			g, gerr := toNum(got)
			v, verr := toNum(val)
			if gerr != nil || verr != nil {
				return false
			}
			if op == "gt" {
				return g > v
			}
			return g < v
		}
	}
	return false
}

// lookup resolves a dot path in the event map.
func lookup(data map[string]any, path string) (any, bool) {
	var cur any = data
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

func eqVal(a, b string) bool {
	if a == b {
		return true
	}
	// numeric equality: "8080" == 8080
	if na, err1 := strconv.ParseFloat(a, 64); err1 == nil {
		if nb, err2 := strconv.ParseFloat(b, 64); err2 == nil {
			return na == nb
		}
	}
	return false
}

func toNum(v any) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case int:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case string:
		return strconv.ParseFloat(x, 64)
	}
	return 0, fmt.Errorf("not a number: %v", v)
}
