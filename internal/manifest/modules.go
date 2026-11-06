package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"

	"gopkg.in/yaml.v3"
)

// ModuleBlock is one modules/<name>.yml file.
type ModuleBlock struct {
	Raw        []byte // YAML of modules/<name>.yml after template expansion
	Enabled    *bool  // nil when the block omits enabled
	ActEnabled bool
	Auto       []string
}

// moduleFileRE is the only file name shape a module block may have.
var moduleFileRE = regexp.MustCompile(`^[a-z][a-z0-9_]*\.yml$`)

// actModuleRE is the key shape of an overrides act entry.
var actModuleRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// maxActExprs bounds the label expressions per module in act and the
// safe_mode_hosts list.
const maxActExprs = 64

// Decode strictly decodes the block into v.
func (b ModuleBlock) Decode(v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(b.Raw))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("module block: %w", err)
	}
	return nil
}

// ModuleEnabled is the enablement rule: the host's modules: entry, else the
// block's enabled, else the default. It mirrors module.Effective, which cannot
// be reused because internal/module imports this package.
func (m *Manifest) ModuleEnabled(host, module string, def bool) bool {
	var hostEntry *bool
	if h, ok := m.Hosts[host]; ok {
		if v, ok := h.Modules[module]; ok {
			v := v
			hostEntry = &v
		}
	}
	var block *bool
	if b, ok := m.Modules[module]; ok {
		block = b.Enabled
	}
	if hostEntry != nil {
		return *hostEntry
	}
	if block != nil {
		return *block
	}
	return def
}

// hostLabelSet returns the labels an expression matches for a host: its
// declared labels plus its own name as an implicit label.
func (m *Manifest) hostLabelSet(host string) []string {
	labels := []string{host}
	if h, ok := m.Hosts[host]; ok {
		labels = append(labels, h.Labels...)
	}
	return labels
}

func (m *Manifest) hostMatches(host string, e LabelExpr) bool {
	return e.Match(m.hostLabelSet(host))
}

// ActEnabled is the effective act switch of a module on a host: the module
// block's act_enabled, or a match of any expression listed under the module in
// Overrides.Act. An overrides entry only adds hosts; it never turns off a
// module whose block says true.
func (m *Manifest) ActEnabled(host, module string) bool {
	if b, ok := m.Modules[module]; ok && b.ActEnabled {
		return true
	}
	for _, expr := range m.Overrides.Act[module] {
		e, err := ParseLabels(expr)
		if err == nil && m.hostMatches(host, e) {
			return true
		}
	}
	return false
}

// SafeModeHostSet returns the sorted host names matching any
// Overrides.SafeModeHosts expression.
func (m *Manifest) SafeModeHostSet() []string {
	set := map[string]bool{}
	for _, expr := range m.Overrides.SafeModeHosts {
		e, err := ParseLabels(expr)
		if err != nil {
			continue
		}
		for name := range m.Hosts {
			if m.hostMatches(name, e) {
				set[name] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// validateActAndSafeMode checks the overrides act map and safe_mode_hosts
// list. A key without a module block is a lint warning, not a load error.
func validateActAndSafeMode(o Overrides, e *ErrorList) {
	for _, module := range SortedKeys(o.Act) {
		if !actModuleRE.MatchString(module) {
			e.Addf("overrides: act key %q must match %s", module, actModuleRE)
		}
		exprs := o.Act[module]
		if len(exprs) > maxActExprs {
			e.Addf("overrides: act %s has %d expressions (limit %d)", module, len(exprs), maxActExprs)
		}
		for i, expr := range exprs {
			if _, err := ParseLabels(expr); err != nil {
				e.Addf("overrides: act %s[%d]: %v", module, i, err)
			}
		}
	}
	if len(o.SafeModeHosts) > maxActExprs {
		e.Addf("overrides: safe_mode_hosts has %d expressions (limit %d)", len(o.SafeModeHosts), maxActExprs)
	}
	for i, expr := range o.SafeModeHosts {
		if _, err := ParseLabels(expr); err != nil {
			e.Addf("overrides: safe_mode_hosts[%d]: %v", i, err)
		}
	}
}
