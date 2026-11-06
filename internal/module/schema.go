package module

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// durationPattern is the JSON Schema pattern of a Duration string; it matches
// exactly what time.ParseDuration accepts as a positive duration.
const durationPattern = `^[0-9]+(ns|us|ms|s|m|h)([0-9]+(ns|us|ms|s|m|h))*$`

var (
	durationType     = reflect.TypeOf(Duration{})
	timeDurationType = reflect.TypeOf(time.Duration(0))
)

// Schema returns the JSON Schema (2020-12) of a config struct, with
// additionalProperties false. YAML keys equal JSON tags, so the schema is
// generated from the json tags; an embedded struct is flattened. A bare
// time.Duration is refused: settings use module.Duration (R11).
func Schema(v any) ([]byte, error) {
	t := reflect.TypeOf(v)
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("module: schema of %T: a config struct is required", v)
	}
	body, err := typeSchema(t)
	if err != nil {
		return nil, err
	}
	title := t.Name()
	if title == "" {
		title = "config"
	}
	out := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"title":   title,
	}
	for k, val := range body {
		out[k] = val
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func typeSchema(t reflect.Type) (map[string]any, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == durationType {
		return map[string]any{"type": "string", "pattern": durationPattern}, nil
	}
	if t == timeDurationType {
		return nil, errors.New("module: a config block must use module.Duration, not time.Duration")
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}, nil
	case reflect.Bool:
		return map[string]any{"type": "boolean"}, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return map[string]any{"type": "integer"}, nil
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}, nil
	case reflect.Slice, reflect.Array:
		items, err := typeSchema(t.Elem())
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "array", "items": items}, nil
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return nil, fmt.Errorf("module: map key type %s is not a string", t.Key())
		}
		values, err := typeSchema(t.Elem())
		if err != nil {
			return nil, err
		}
		return map[string]any{"type": "object", "additionalProperties": values}, nil
	case reflect.Interface:
		return map[string]any{}, nil
	case reflect.Struct:
		return structSchema(t)
	}
	return nil, fmt.Errorf("module: unsupported type %s", t)
}

func structSchema(t reflect.Type) (map[string]any, error) {
	props := map[string]any{}
	var required []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue // unexported
		}
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			et := f.Type
			for et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() != reflect.Struct {
				return nil, fmt.Errorf("module: embedded field %s is not a struct", f.Name)
			}
			s, err := structSchema(et)
			if err != nil {
				return nil, err
			}
			for k, v := range s["properties"].(map[string]any) {
				props[k] = v
			}
			if r, ok := s["required"].([]string); ok {
				required = append(required, r...)
			}
			continue
		}
		if name == "" {
			name = f.Name
		}
		s, err := typeSchema(f.Type)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", t.Name(), f.Name, err)
		}
		props[name] = s
		if !strings.Contains(opts, "omitempty") {
			required = append(required, name)
		}
	}
	out := map[string]any{"type": "object", "additionalProperties": false, "properties": props}
	if len(required) > 0 {
		out["required"] = required
	}
	return out, nil
}
