package plans

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"gopkg.in/yaml.v3"
)

// Parse decodes a template strictly, with a 256 KiB cap.
func Parse(raw []byte) (*Template, error) {
	if len(raw) > 256<<10 {
		return nil, errors.New("template larger than 256 KiB")
	}
	var t Template
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return &t, nil
}

// ResolveLabels replaces every var shaped {labels: expr} with the hosts the
// resolver returns. A label var with no resolver is an error: a pack can never
// silently plan against no hosts.
func ResolveLabels(t *Template, hosts func(expr string) ([]string, error)) (map[string]any, error) {
	out := map[string]any{}
	names := make([]string, 0, len(t.Vars))
	for name := range t.Vars {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		m, ok := t.Vars[name].(map[string]any)
		if !ok {
			continue
		}
		raw, ok := m["labels"]
		if !ok {
			continue
		}
		if len(m) != 1 {
			return nil, fmt.Errorf("var %q: a label var carries only `labels`", name)
		}
		expr, ok := raw.(string)
		if !ok || expr == "" {
			return nil, fmt.Errorf("var %q: labels must be a non-empty expression", name)
		}
		if hosts == nil {
			return nil, fmt.Errorf("var %q: labels %q: no host resolver", name, expr)
		}
		hs, err := hosts(expr)
		if err != nil {
			return nil, fmt.Errorf("var %q: labels %q: %w", name, expr, err)
		}
		list := make([]any, len(hs))
		for i, h := range hs {
			list[i] = h
		}
		out[name] = list
	}
	return out, nil
}
