package module

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Duration is a time.Duration that reads and writes a string ("90s", "2m",
// "1h30m") in YAML and JSON. It is the one exception to the module contract's
// rule that YAML keys equal JSON tags: a duration is never a bare
// time.Duration in a config block, whose integer nanoseconds would be
// meaningless in a file an operator edits (R11).
type Duration struct{ time.Duration }

func (d *Duration) parse(s string) error {
	if s == "" {
		return errors.New("module: duration is empty")
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("module: duration %q: %w", s, err)
	}
	if v < 0 {
		return fmt.Errorf("module: duration %q is negative", s)
	}
	d.Duration = v
	return nil
}

// UnmarshalJSON accepts a string only.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("module: duration must be a string: %w", err)
	}
	return d.parse(s)
}

// UnmarshalYAML accepts a string only (yaml.v3's obsolete unmarshaler keeps
// this file on the standard library).
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return fmt.Errorf("module: duration must be a string: %w", err)
	}
	return d.parse(s)
}

// MarshalJSON writes d.String().
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// MarshalYAML writes d.String().
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }
