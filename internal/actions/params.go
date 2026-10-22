package actions

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ParamType is the type of one action parameter.
type ParamType int

const (
	String ParamType = iota
	Int
	Bool
	StringList
	StringMap
	Mode // file mode: octal string ("0640") or integer
	Path // absolute path, no NUL
	Enum // string restricted to ParamSpec.Enum
)

// ParamSpec declares one parameter of an action.
type ParamSpec struct {
	Name     string
	Type     ParamType
	Required bool
	Default  any
	Enum     []string
	Secret   bool // redacted from diffs, logs and errors
	Max      int  // max length (String/Path/list element count); 0 = default bound
	Check    func(v any) error
}

const defaultMaxLen = 1 << 20

// Spec is an action's static declaration.
type Spec struct {
	Name     string
	Doc      string
	Risk     Risk
	ReadOnly bool // Apply only reads; "already done" is never short-circuited
	Params   []ParamSpec
}

// Params is a validated, typed parameter set.
type Params struct {
	spec Spec
	m    map[string]any
}

// Validate checks raw (typically decoded JSON) against the spec: unknown keys,
// missing required keys, types and bounds. Defaults are filled in.
func (s Spec) Validate(raw map[string]any) (Params, error) {
	out := map[string]any{}
	known := map[string]ParamSpec{}
	for _, ps := range s.Params {
		known[ps.Name] = ps
	}
	for k := range raw {
		if _, ok := known[k]; !ok {
			return Params{}, fmt.Errorf("%s: unknown parameter %q", s.Name, k)
		}
	}
	for _, ps := range s.Params {
		v, ok := raw[ps.Name]
		if !ok || v == nil {
			if ps.Required {
				return Params{}, fmt.Errorf("%s: missing required parameter %q", s.Name, ps.Name)
			}
			if ps.Default != nil {
				out[ps.Name] = ps.Default
			}
			continue
		}
		cv, err := coerce(ps, v)
		if err != nil {
			if ps.Secret {
				return Params{}, fmt.Errorf("%s: parameter %q: invalid value", s.Name, ps.Name)
			}
			return Params{}, fmt.Errorf("%s: parameter %q: %w", s.Name, ps.Name, err)
		}
		if ps.Check != nil {
			if err := ps.Check(cv); err != nil {
				return Params{}, fmt.Errorf("%s: parameter %q: %w", s.Name, ps.Name, err)
			}
		}
		out[ps.Name] = cv
	}
	return Params{spec: s, m: out}, nil
}

func coerce(ps ParamSpec, v any) (any, error) {
	max := ps.Max
	if max <= 0 {
		max = defaultMaxLen
	}
	switch ps.Type {
	case String, Path, Enum:
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("want string, got %T", v)
		}
		if len(s) > max {
			return nil, fmt.Errorf("longer than %d bytes", max)
		}
		if ps.Type == Path {
			if s == "" || strings.ContainsRune(s, 0) || len(s) > 4096 {
				return nil, fmt.Errorf("invalid path")
			}
			if !filepath.IsAbs(s) && !strings.HasPrefix(s, "/") {
				return nil, fmt.Errorf("path must be absolute")
			}
		}
		if ps.Type == Enum {
			for _, e := range ps.Enum {
				if e == s {
					return s, nil
				}
			}
			return nil, fmt.Errorf("must be one of %s", strings.Join(ps.Enum, ", "))
		}
		return s, nil
	case Int:
		switch n := v.(type) {
		case int:
			return n, nil
		case int64:
			return int(n), nil
		case float64:
			if n != float64(int(n)) {
				return nil, fmt.Errorf("not an integer")
			}
			return int(n), nil
		case json.Number:
			i, err := n.Int64()
			return int(i), err
		}
		return nil, fmt.Errorf("want integer, got %T", v)
	case Bool:
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("want bool, got %T", v)
		}
		return b, nil
	case Mode:
		switch n := v.(type) {
		case string:
			u, err := strconv.ParseUint(n, 8, 32)
			if err != nil || u > 07777 {
				return nil, fmt.Errorf("invalid octal mode")
			}
			return fs.FileMode(u), nil
		case float64:
			if n < 0 || n > 07777 || n != float64(int(n)) {
				return nil, fmt.Errorf("invalid mode")
			}
			return fs.FileMode(int(n)), nil
		case int:
			if n < 0 || n > 07777 {
				return nil, fmt.Errorf("invalid mode")
			}
			return fs.FileMode(n), nil
		case fs.FileMode:
			return n & 07777, nil
		}
		return nil, fmt.Errorf("want octal mode string")
	case StringList:
		var out []string
		switch l := v.(type) {
		case []string:
			out = append(out, l...)
		case []any:
			for _, e := range l {
				s, ok := e.(string)
				if !ok {
					return nil, fmt.Errorf("list element: want string, got %T", e)
				}
				out = append(out, s)
			}
		default:
			return nil, fmt.Errorf("want list of strings, got %T", v)
		}
		if ps.Max > 0 && len(out) > ps.Max {
			return nil, fmt.Errorf("more than %d elements", ps.Max)
		}
		if len(out) > 100000 {
			return nil, fmt.Errorf("too many elements")
		}
		return out, nil
	case StringMap:
		out := map[string]string{}
		switch l := v.(type) {
		case map[string]string:
			for k, e := range l {
				out[k] = e
			}
		case map[string]any:
			for k, e := range l {
				s, ok := e.(string)
				if !ok {
					return nil, fmt.Errorf("map value %q: want string, got %T", k, e)
				}
				out[k] = s
			}
		default:
			return nil, fmt.Errorf("want map of strings, got %T", v)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported parameter type")
}

// Has reports whether the parameter was supplied (or defaulted).
func (p Params) Has(k string) bool { _, ok := p.m[k]; return ok }

// Str returns a string parameter ("" if absent).
func (p Params) Str(k string) string { s, _ := p.m[k].(string); return s }

// Int returns an integer parameter; ok is false if absent.
func (p Params) Int(k string) (int, bool) { n, ok := p.m[k].(int); return n, ok }

// Bool returns a bool parameter (false if absent).
func (p Params) Bool(k string) bool { b, _ := p.m[k].(bool); return b }

// List returns a list parameter.
func (p Params) List(k string) []string { l, _ := p.m[k].([]string); return l }

// Map returns a map parameter.
func (p Params) Map(k string) map[string]string { m, _ := p.m[k].(map[string]string); return m }

// FileMode returns a mode parameter; ok is false if absent.
func (p Params) FileMode(k string) (fs.FileMode, bool) { m, ok := p.m[k].(fs.FileMode); return m, ok }

// Redacted renders the parameters for logs with secrets masked.
func (p Params) Redacted() string {
	secret := map[string]bool{}
	for _, ps := range p.spec.Params {
		if ps.Secret {
			secret[ps.Name] = true
		}
	}
	keys := make([]string, 0, len(p.m))
	for k := range p.m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		if secret[k] {
			fmt.Fprintf(&b, "%s=<redacted>", k)
			continue
		}
		s := fmt.Sprintf("%v", p.m[k])
		if len(s) > 80 {
			s = s[:80] + "..."
		}
		fmt.Fprintf(&b, "%s=%s", k, s)
	}
	return b.String()
}
