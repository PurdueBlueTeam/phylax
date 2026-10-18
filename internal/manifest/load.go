package manifest

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

//go:embed schema/*.json
var schemaFS embed.FS

const (
	fileTopology  = "topology.yml"
	fileHosts     = "hosts.yml"
	fileServices  = "services.yml"
	fileAccounts  = "accounts.yml"
	fileDevices   = "devices.yml"
	fileDecoys    = "decoys.yml"
	filePolicy    = "policy.yml"
	fileOverrides = "overrides.yml"
)

var requiredFiles = map[string]bool{
	fileTopology: true,
	fileHosts:    true,
	fileServices: true,
	filePolicy:   true,
}

var fileOrder = []string{fileTopology, fileHosts, fileServices, fileAccounts, fileDevices, fileDecoys, filePolicy, fileOverrides}

// field returns the address of the manifest field that file name binds to.
func (m *Manifest) field(name string) any {
	switch name {
	case fileTopology:
		return &m.Topology
	case fileHosts:
		return &m.Hosts
	case fileServices:
		return &m.Services
	case fileAccounts:
		return &m.Accounts
	case fileDevices:
		return &m.Devices
	case fileDecoys:
		return &m.Decoys
	case filePolicy:
		return &m.Policy
	case fileOverrides:
		return &m.Overrides
	}
	return nil
}

// Load reads every manifest file from dir, applies template variables,
// validates each file against its JSON Schema, unmarshals into the Manifest
// struct and runs the lint checks.
//
// If vars is nil, the team number is read from hosts.yml first so that
// templated manifests with no explicit vars still resolve.
func Load(dir string, vars Vars) (*Manifest, error) {
	m := &Manifest{Dir: dir}
	if vars == nil {
		team, err := peekTeam(filepath.Join(dir, fileHosts))
		if err != nil {
			return nil, err
		}
		vars = TeamVars(team)
	}
	for _, name := range fileOrder {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			if requiredFiles[name] {
				return nil, fmt.Errorf("manifest: missing required file %s", name)
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("manifest: %s: %w", name, err)
		}
		if err := loadFile(m, name, data, vars); err != nil {
			return nil, err
		}
	}
	if m.Hosts.Team == 0 && len(m.Hosts.Hosts) > 0 {
		return nil, fmt.Errorf("manifest: hosts.yml must declare a team number")
	}
	if err := m.lint(); err != nil {
		return nil, err
	}
	return m, nil
}

// LoadReference loads the built-in reference manifest (the 2026 two-segment
// shape) from the repo's manifest/ directory.
func LoadReference(dir string) (*Manifest, error) {
	return Load(dir, nil)
}

// peekTeam extracts the team integer from hosts.yml without full validation.
func peekTeam(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("manifest: %s: %w", fileHosts, err)
	}
	var doc struct {
		Team int `yaml:"team"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return 0, fmt.Errorf("manifest: %s: %w", fileHosts, err)
	}
	return doc.Team, nil
}

func loadFile(m *Manifest, name string, data []byte, vars Vars) error {
	rendered, err := vars.Render(string(data))
	if err != nil {
		return fmt.Errorf("manifest: %s: %w", name, err)
	}
	if err := validateSchema(name, []byte(rendered)); err != nil {
		return fmt.Errorf("manifest: %s: %w", name, err)
	}
	var raw any
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	dec.KnownFields(false)
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("manifest: %s: %w", name, err)
	}
	target := m.field(name)
	if target == nil {
		return fmt.Errorf("manifest: unknown file %s", name)
	}
	// services.yml & friends wrap their content in a top-level key; unwrap
	// it so the map-typed fields receive the inner object.
	if m, ok := raw.(map[string]any); ok && len(m) == 1 {
		key := strings.TrimSuffix(name, ".yml")
		if inner, has := m[key]; has {
			raw = inner
		}
	}
	// Re-encode to JSON so typed structs get the right zero values.
	buf, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("manifest: %s: json encode: %w", name, err)
	}
	if err := json.Unmarshal(buf, target); err != nil {
		return fmt.Errorf("manifest: %s: %w", name, err)
	}
	return nil
}

var schemaCache = map[string]*jsonschema.Schema{}

func validateSchema(name string, data []byte) error {
	schemaName := strings.TrimSuffix(name, ".yml")
	s, ok := schemaCache[schemaName]
	if !ok {
		blob, err := schemaFS.ReadFile("schema/" + schemaName + ".json")
		if err != nil {
			return fmt.Errorf("no schema for %s: %w", name, err)
		}
		var doc any
		if err := json.Unmarshal(blob, &doc); err != nil {
			return fmt.Errorf("schema %s: %w", schemaName, err)
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource(schemaName+".json", doc); err != nil {
			return err
		}
		s, err = c.Compile(schemaName + ".json")
		if err != nil {
			return fmt.Errorf("schema %s: %w", schemaName, err)
		}
		schemaCache[schemaName] = s
	}
	var doc any
	if err := json.Unmarshal(yamlToJSON(data), &doc); err != nil {
		return fmt.Errorf("schema input: %w", err)
	}
	if err := s.Validate(doc); err != nil {
		return err
	}
	return nil
}

// yamlToJSON converts YAML bytes to JSON so the JSON Schema validator can
// consume it. The input is already templated and UTF-8.
func yamlToJSON(data []byte) []byte {
	var v any
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&v); err != nil {
		// Schema validation will surface a clearer error; return empty.
		return []byte("{}")
	}
	out, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return out
}
