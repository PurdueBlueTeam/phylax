package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/plans"
)

// Plan templates are YAML files in the plans directory (design: plans/). A
// template is a plan definition: `id` (the base of the plan id), `name`,
// `on_failure` and `nodes` with the same fields as plan.Node (`params` is a
// free map). Unknown fields are an error. Creating a plan from a template
// validates it against the action catalog like any other plan.

const maxTemplateBytes = 256 << 10

var templateNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// TemplateInfo describes one template file.
type TemplateInfo struct {
	Name  string // file name without extension
	Title string
	Nodes int
}

// ListTemplates reads the plans directory. Files that do not parse are listed
// with the error as their title so the operator sees them.
func ListTemplates(dir string) ([]TemplateInfo, error) {
	if dir == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []TemplateInfo
	for _, e := range ents {
		ext := filepath.Ext(e.Name())
		if e.IsDir() || (ext != ".yml" && ext != ".yaml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ext)
		if !templateNameRE.MatchString(name) {
			continue
		}
		ti := TemplateInfo{Name: name}
		if p, err := LoadTemplate(dir, name); err != nil {
			ti.Title = "invalid: " + err.Error()
		} else {
			ti.Title, ti.Nodes = p.Name, len(p.Nodes)
		}
		out = append(out, ti)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// LoadTemplate parses plans/<name>.yml (or .yaml). The name is a file base
// name; anything with a path separator is refused.
func LoadTemplate(dir, name string) (plan.Plan, error) {
	var p plan.Plan
	if dir == "" {
		return p, fmt.Errorf("no plans directory is configured")
	}
	if !templateNameRE.MatchString(name) {
		return p, fmt.Errorf("bad template name %q", name)
	}
	raw, err := readTemplateFile(dir, name)
	if err != nil {
		return p, err
	}
	return ParseTemplate(raw)
}

// readTemplateFile reads <dir>/<name>.yml or .yaml, capped.
func readTemplateFile(dir, name string) ([]byte, error) {
	var raw []byte
	var err error
	for _, ext := range []string{".yml", ".yaml"} {
		raw, err = readCapped(filepath.Join(dir, name+ext), maxTemplateBytes)
		if err == nil || !os.IsNotExist(err) {
			break
		}
	}
	return raw, err
}

func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, fmt.Errorf("%s: not a regular file or larger than %d bytes", filepath.Base(path), max)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(f)
	return buf.Bytes(), err
}

// ParseTemplate decodes a template's YAML.
func ParseTemplate(raw []byte) (plan.Plan, error) {
	var p plan.Plan
	var generic any
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&generic); err != nil {
		return p, fmt.Errorf("yaml: %w", err)
	}
	if err := translateNodeKeys(generic); err != nil {
		return p, err
	}
	js, err := json.Marshal(generic) // yaml.v3 maps have string keys
	if err != nil {
		return p, fmt.Errorf("yaml: %w", err)
	}
	jd := json.NewDecoder(bytes.NewReader(js))
	jd.DisallowUnknownFields()
	if err := jd.Decode(&p); err != nil {
		return p, fmt.Errorf("template: %w", err)
	}
	for i := range p.Nodes {
		if p.Nodes[i].Params == nil && !p.Nodes[i].Gate {
			p.Nodes[i].Params = map[string]any{}
		}
	}
	return p, nil
}

// PlanIDFor derives a plan id: the operator's choice, else the template's id
// (or name) plus a timestamp.
func PlanIDFor(p plan.Plan, template, chosen string, now time.Time) string {
	if chosen != "" {
		return chosen
	}
	base := p.ID
	if base == "" {
		base = template
	}
	id := base + "-" + now.UTC().Format("20060102-150405")
	if len(id) > 64 {
		id = id[len(id)-64:]
	}
	return id
}

// translateNodeKeys is the one place YAML sugar at node level becomes the JSON
// keys of plan.Node: `expires_after: 30m` becomes `expires_after_sec: 1800`.
// Every later option spelled as sugar (gate: auto, window:, txn:) is added here.
func translateNodeKeys(doc any) error {
	top, ok := doc.(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := top["nodes"]
	if !ok {
		return nil
	}
	nodes, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("template: nodes must be a list")
	}
	for i, item := range nodes {
		n, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("template: node %d must be a mapping", i)
		}
		if err := translateExpiresAfter(n); err != nil {
			return err
		}
		if err := translateGate(n); err != nil {
			return err
		}
	}
	return nil
}

func translateExpiresAfter(n map[string]any) error {
	raw, ok := n["expires_after"]
	if !ok {
		return nil
	}
	if _, dup := n["expires_after_sec"]; dup {
		return fmt.Errorf("template: node %v sets both expires_after and expires_after_sec", n["id"])
	}
	s, ok := raw.(string)
	if !ok {
		return fmt.Errorf("template: node %v: expires_after must be a duration like 30m", n["id"])
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("template: node %v: expires_after: %w", n["id"], err)
	}
	if d <= 0 {
		return fmt.Errorf("template: node %v: expires_after must be positive", n["id"])
	}
	delete(n, "expires_after")
	n["expires_after_sec"] = int(d.Seconds())
	return nil
}

// translateGate turns the gate: sugar into plan.Node's JSON keys. `gate: true`
// and `gate: approval` are a plain gate; `gate: auto` needs `until:`; `gate:
// manual` is W7's (today it is a plain gate).
func translateGate(n map[string]any) error {
	if raw, ok := n["gate"]; ok {
		switch v := raw.(type) {
		case bool:
			if !v {
				delete(n, "gate")
			}
		case string:
			switch v {
			case "approval", "manual":
				delete(n, "gate")
				n["gate"] = true
			case "auto":
				delete(n, "gate")
				n["gate"] = true
				if _, ok := n["until"]; !ok {
					return fmt.Errorf("template: node %v: gate: auto needs until:", n["id"])
				}
			default:
				return fmt.Errorf("template: node %v: unknown gate %q", n["id"], v)
			}
		default:
			return fmt.Errorf("template: node %v: gate must be true, false, approval, manual or auto", n["id"])
		}
	}
	return translateUntil(n)
}

// translateUntil turns `until: {after: 10m, probe: '*', no_event: {...}}` into
// GateUntil's JSON keys.
func translateUntil(n map[string]any) error {
	raw, ok := n["until"]
	if !ok {
		return nil
	}
	u, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("template: node %v: until must be a mapping", n["id"])
	}
	if a, ok := u["after"]; ok {
		if _, dup := u["after_sec"]; dup {
			return fmt.Errorf("template: node %v: until sets both after and after_sec", n["id"])
		}
		s, ok := a.(string)
		if !ok {
			return fmt.Errorf("template: node %v: until.after must be a duration like 10m", n["id"])
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("template: node %v: until.after: %w", n["id"], err)
		}
		if d <= 0 {
			return fmt.Errorf("template: node %v: until.after must be positive", n["id"])
		}
		delete(u, "after")
		u["after_sec"] = int(d.Seconds())
	}
	return nil
}

var moduleNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// LoadModuleTemplate loads plansRoot/<mod>/<name> with no label resolver; a
// pack with a label variable therefore errors.
func LoadModuleTemplate(plansRoot, mod, name string) (plan.Plan, error) {
	return LoadModuleTemplateFor(plansRoot, mod, name, nil)
}

// LoadModuleTemplateFor loads plansRoot/<mod>/<name> and refuses a template
// whose `module:` names another module. A file with a top-level `vars:` or a
// node with `each:` is a pack (plans.Parse, label resolution, Template.Expand);
// any other file is the controller file format (ParseTemplate).
func LoadModuleTemplateFor(plansRoot, mod, name string, hosts func(expr string) ([]string, error)) (plan.Plan, error) {
	var p plan.Plan
	if !moduleNameRE.MatchString(mod) {
		return p, fmt.Errorf("bad module name %q", mod)
	}
	if !templateNameRE.MatchString(name) {
		return p, fmt.Errorf("bad template name %q", name)
	}
	raw, err := readTemplateFile(filepath.Join(plansRoot, mod), name)
	if err != nil {
		return p, err
	}
	if isPack(raw) {
		tpl, err := plans.Parse(raw)
		if err != nil {
			return p, fmt.Errorf("%s/%s: %w", mod, name, err)
		}
		if tpl.Module != mod {
			return p, fmt.Errorf("%s/%s: template is for module %q, not %q", mod, name, tpl.Module, mod)
		}
		ov, err := plans.ResolveLabels(tpl, hosts)
		if err != nil {
			return p, fmt.Errorf("%s/%s: %w", mod, name, err)
		}
		cat, err := plans.NewCatalog()
		if err != nil {
			return p, fmt.Errorf("%s/%s: %w", mod, name, err)
		}
		expanded, err := tpl.Expand(cat, ov)
		if err != nil {
			return p, fmt.Errorf("%s/%s: %w", mod, name, err)
		}
		p = *expanded
		p.Module, p.Template = tpl.Module, name
		return p, nil
	}
	p, err = ParseTemplate(raw)
	if err != nil {
		return p, fmt.Errorf("%s/%s: %w", mod, name, err)
	}
	if p.Module != mod {
		return p, fmt.Errorf("%s/%s: template is for module %q, not %q", mod, name, p.Module, mod)
	}
	p.Template = name
	return p, nil
}

// isPack reports the pack format: a top-level `vars:` or a node with `each:`.
func isPack(raw []byte) bool {
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return false // the real parser reports the syntax error
	}
	if _, ok := doc["vars"]; ok {
		return true
	}
	nodes, _ := doc["nodes"].([]any)
	for _, n := range nodes {
		if m, ok := n.(map[string]any); ok {
			if _, ok := m["each"]; ok {
				return true
			}
		}
	}
	return false
}
