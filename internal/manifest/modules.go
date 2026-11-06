package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"

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
