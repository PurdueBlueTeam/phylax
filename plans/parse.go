package plans

import (
	"bytes"
	"errors"
	"io"

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
// resolver returns.
func ResolveLabels(t *Template, hosts func(expr string) ([]string, error)) (map[string]any, error) {
	panic("unimplemented: W1 Task 22b")
}
