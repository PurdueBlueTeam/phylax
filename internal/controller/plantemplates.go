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
	var raw []byte
	var err error
	for _, ext := range []string{".yml", ".yaml"} {
		raw, err = readCapped(filepath.Join(dir, name+ext), maxTemplateBytes)
		if err == nil || !os.IsNotExist(err) {
			break
		}
	}
	if err != nil {
		return p, err
	}
	return ParseTemplate(raw)
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

var moduleNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// LoadModuleTemplate loads plansRoot/<mod>/<name> and refuses a template whose
// `module:` names another module.
func LoadModuleTemplate(plansRoot, mod, name string) (plan.Plan, error) {
	var p plan.Plan
	if !moduleNameRE.MatchString(mod) {
		return p, fmt.Errorf("bad module name %q", mod)
	}
	p, err := LoadTemplate(filepath.Join(plansRoot, mod), name)
	if err != nil {
		return p, err
	}
	if p.Module != mod {
		return p, fmt.Errorf("%s/%s: template is for module %q, not %q", mod, name, p.Module, mod)
	}
	return p, nil
}

// LoadModuleTemplateFor loads a module template, resolving label variables.
func LoadModuleTemplateFor(plansRoot, mod, name string, hosts func(expr string) ([]string, error)) (plan.Plan, error) {
	panic("unimplemented: W1 Task 22b")
}
