package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Bounds on what the loader will read.
const (
	maxFileBytes = 4 << 20
	maxEntries   = 4096
)

// Options tune loading.
type Options struct {
	// Team overrides `team` from topology.yml.
	Team *int
}

// LoadDir loads and validates the manifest in dir.
func LoadDir(dir string, opts Options) (*Manifest, error) {
	return Load(os.DirFS(dir), opts)
}

// Load decodes every manifest file present in fsys strictly (unknown keys are
// errors), expands `{{ ... }}` templates, merges the files and validates
// cross-references. topology.yml and hosts.yml are required.
func Load(fsys fs.FS, opts Options) (*Manifest, error) {
	m := &Manifest{}
	var errs ErrorList

	// topology first: it carries the team number used by templates.
	topoNode, ok, err := readNode(fsys, FileTopology)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("manifest: %s is required", FileTopology)
	}
	team, err := teamOf(topoNode)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FileTopology, err)
	}
	if opts.Team != nil {
		team = *opts.Team
	}
	m.Team = team

	decode := func(file string, root *yaml.Node, dst any) {
		if err := expandNode(root, team); err != nil {
			errs.Addf("%s: %v", file, err)
			return
		}
		buf, err := yaml.Marshal(root)
		if err != nil {
			errs.Addf("%s: %v", file, err)
			return
		}
		dec := yaml.NewDecoder(bytes.NewReader(buf))
		dec.KnownFields(true)
		if err := dec.Decode(dst); err != nil && !errors.Is(err, io.EOF) {
			errs.Addf("%s: %v", file, err)
		}
		m.Loaded = append(m.Loaded, file)
	}

	decode(FileTopology, topoNode, &m.Topology)
	m.Topology.Team = team

	type optional struct {
		file string
		dst  any
	}
	var hostsF struct {
		Hosts map[string]Host `yaml:"hosts"`
	}
	var svcF struct {
		Services map[string]Service `yaml:"services"`
	}
	var accF struct {
		Accounts map[string]Account `yaml:"accounts"`
	}
	var scorerF struct {
		Scorer Scorer `yaml:"scorer"`
	}
	var devF struct {
		Devices map[string]Device `yaml:"devices"`
	}
	var decF struct {
		Decoys map[string]HostDecoys `yaml:"decoys"`
	}
	var intF struct {
		Integrations map[string]Integration `yaml:"integrations"`
	}
	var polF struct {
		Policy Policy `yaml:"policy"`
	}
	var ovF struct {
		Overrides Overrides `yaml:"overrides"`
	}
	files := []optional{
		{FileHosts, &hostsF}, {FileServices, &svcF}, {FileAccounts, &accF}, {FileScorer, &scorerF},
		{FileDevices, &devF}, {FileDecoys, &decF}, {FileIntegrations, &intF},
		{FilePolicy, &polF}, {FileOverrides, &ovF},
	}
	for _, f := range files {
		n, present, err := readNode(fsys, f.file)
		if err != nil {
			errs.Addf("%v", err)
			continue
		}
		if !present {
			if f.file == FileHosts {
				errs.Addf("%s is required", FileHosts)
			}
			continue
		}
		decode(f.file, n, f.dst)
	}
	m.Hosts = hostsF.Hosts
	m.Services = svcF.Services
	m.Accounts = accF.Accounts
	m.Scorer = scorerF.Scorer
	m.Decoys = decF.Decoys
	m.Integrations = intF.Integrations
	m.Policy = polF.Policy
	m.Overrides = ovF.Overrides

	// Devices: topology.yml and devices.yml are merged; a name in both is an error.
	m.Devices = map[string]Device{}
	for k, v := range m.Topology.Devices {
		m.Devices[k] = v
	}
	for k, v := range devF.Devices {
		if _, dup := m.Devices[k]; dup {
			errs.Addf("device %q is declared in both %s and %s", k, FileTopology, FileDevices)
		}
		m.Devices[k] = v
	}

	mods, modErrs := loadModuleBlocks(fsys, team)
	errs = append(errs, modErrs...)
	m.Modules = mods

	if len(m.Hosts) > maxEntries || len(m.Services) > maxEntries || len(m.Accounts) > maxEntries {
		errs.Addf("too many entries (limit %d per file)", maxEntries)
	}
	if len(errs) > 0 {
		return nil, errs.Err()
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

// loadModuleBlocks reads modules/*.yml. Each file name must be a lower-case
// module name ending in .yml; each file is template-expanded like the rest of
// the manifest. The generic keys are parsed here, the rest is kept as Raw.
func loadModuleBlocks(fsys fs.FS, team int) (map[string]ModuleBlock, ErrorList) {
	entries, err := fs.ReadDir(fsys, "modules")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrorList{fmt.Sprintf("modules/: %v", err)}
	}
	if len(entries) > maxEntries {
		return nil, ErrorList{fmt.Sprintf("modules/: more than %d entries", maxEntries)}
	}
	out := map[string]ModuleBlock{}
	var errs ErrorList
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !moduleFileRE.MatchString(name) {
			errs.Addf("modules/%s: a module block must be named %s", name, moduleFileRE)
			continue
		}
		n, ok, err := readNode(fsys, "modules/"+name)
		if err != nil {
			errs.Addf("%v", err)
			continue
		}
		if !ok {
			continue
		}
		if err := expandNode(n, team); err != nil {
			errs.Addf("modules/%s: %v", name, err)
			continue
		}
		buf, err := yaml.Marshal(n)
		if err != nil {
			errs.Addf("modules/%s: %v", name, err)
			continue
		}
		var generic struct {
			Enabled    *bool             `yaml:"enabled"`
			ActEnabled bool              `yaml:"act_enabled"`
			Autonomy   map[string]string `yaml:"autonomy"`
		}
		if err := yaml.Unmarshal(buf, &generic); err != nil {
			errs.Addf("modules/%s: %v", name, err)
			continue
		}
		out[strings.TrimSuffix(name, ".yml")] = ModuleBlock{
			Raw:        buf,
			Enabled:    generic.Enabled,
			ActEnabled: generic.ActEnabled,
			Autonomy:   generic.Autonomy,
		}
	}
	return out, errs
}

func readNode(fsys fs.FS, name string) (*yaml.Node, bool, error) {
	f, err := fsys.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", name, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", name, err)
	}
	if len(data) > maxFileBytes {
		return nil, false, fmt.Errorf("%s: larger than %d bytes", name, maxFileBytes)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, false, fmt.Errorf("%s: %w", name, err)
	}
	if doc.Kind == 0 { // empty file
		return &yaml.Node{Kind: yaml.MappingNode}, true, nil
	}
	return &doc, true, nil
}

func teamOf(doc *yaml.Node) (int, error) {
	n := doc
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return 0, errors.New("top level must be a mapping")
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "team" {
			v, err := strconv.Atoi(n.Content[i+1].Value)
			if err != nil || v < 0 || v > 255 {
				return 0, fmt.Errorf("line %d: team must be an integer 0-255", n.Content[i+1].Line)
			}
			return v, nil
		}
	}
	return 0, errors.New("`team` is required")
}

// expandNode expands {{ expr }} templates in every scalar value (not keys).
func expandNode(n *yaml.Node, team int) error {
	switch n.Kind {
	case yaml.ScalarNode:
		if strings.Contains(n.Value, "{{") {
			v, err := expandTemplate(n.Value, team)
			if err != nil {
				return fmt.Errorf("line %d: %w", n.Line, err)
			}
			n.Value = v
			n.Tag = "!!str"
		}
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			if err := expandNode(n.Content[i], team); err != nil {
				return err
			}
		}
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			if err := expandNode(c, team); err != nil {
				return err
			}
		}
	}
	return nil
}

// expandTemplate replaces each {{ expr }} with its integer value. expr is
// integers and the identifier `team` joined by + and -.
func expandTemplate(s string, team int) (string, error) {
	var out strings.Builder
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			out.WriteString(s)
			return out.String(), nil
		}
		j := strings.Index(s[i:], "}}")
		if j < 0 {
			return "", fmt.Errorf("unterminated template in %q", s)
		}
		v, err := evalExpr(s[i+2:i+j], team)
		if err != nil {
			return "", fmt.Errorf("template %q: %w", s[i:i+j+2], err)
		}
		out.WriteString(s[:i])
		out.WriteString(strconv.Itoa(v))
		s = s[i+j+2:]
	}
}

func evalExpr(e string, team int) (int, error) {
	toks := strings.Fields(strings.NewReplacer("+", " + ", "-", " - ").Replace(e))
	if len(toks) == 0 {
		return 0, errors.New("empty expression")
	}
	total, sign, wantOperand := 0, 1, true
	for _, t := range toks {
		if wantOperand {
			var v int
			switch {
			case t == "team":
				v = team
			default:
				n, err := strconv.Atoi(t)
				if err != nil {
					return 0, fmt.Errorf("unknown token %q (only integers and `team`)", t)
				}
				v = n
			}
			total += sign * v
			wantOperand = false
			continue
		}
		switch t {
		case "+":
			sign = 1
		case "-":
			sign = -1
		default:
			return 0, fmt.Errorf("expected + or -, got %q", t)
		}
		wantOperand = true
	}
	if wantOperand {
		return 0, errors.New("expression ends with an operator")
	}
	return total, nil
}

// ErrorList collects validation problems.
type ErrorList []string

// Addf appends a formatted problem.
func (e *ErrorList) Addf(format string, args ...any) { *e = append(*e, fmt.Sprintf(format, args...)) }

// Err returns nil for an empty list.
func (e ErrorList) Err() error {
	if len(e) == 0 {
		return nil
	}
	return e
}

func (e ErrorList) Error() string {
	s := append([]string(nil), e...)
	sort.Strings(s)
	return fmt.Sprintf("manifest: %d problem(s):\n  - %s", len(s), strings.Join(s, "\n  - "))
}
