package manifest

import "gopkg.in/yaml.v3"

// ModuleBlock is one modules/<name>.yml file.
type ModuleBlock struct {
	Raw        []byte // YAML of modules/<name>.yml after template expansion
	Enabled    *bool  // nil when the block omits enabled
	ActEnabled bool
	Auto       []string
}

// Decode strictly decodes the block into v.
func (b ModuleBlock) Decode(v any) error { panic("unimplemented: W1 Task 11") }

// ModuleEnabled is the enablement rule: the host's modules: entry, else the
// block's enabled, else the default.
func (m *Manifest) ModuleEnabled(host, module string, def bool) bool {
	panic("unimplemented: W1 Task 11")
}

var _ = yaml.Node{}
