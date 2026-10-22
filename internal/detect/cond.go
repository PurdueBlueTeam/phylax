package detect

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// evalCtx carries one event through evaluation.
type evalCtx struct {
	ev  *eventRef
	eng *Engine
}

type node interface{ eval(*evalCtx) bool }

type allNode []node
type anyNode []node
type notNode struct{ n node }

func (a allNode) eval(c *evalCtx) bool {
	for _, n := range a {
		if !n.eval(c) {
			return false
		}
	}
	return true
}

func (a anyNode) eval(c *evalCtx) bool {
	for _, n := range a {
		if n.eval(c) {
			return true
		}
	}
	return false
}

func (n notNode) eval(c *evalCtx) bool { return !n.n.eval(c) }

// fieldNode applies one operator to one field. A missing field never matches
// (except present: false).
type fieldNode struct {
	ref fieldRef
	op  func(c *evalCtx, v any) bool
}

func (f fieldNode) eval(c *evalCtx) bool {
	v, ok := f.ref.get(c)
	if !ok {
		return false
	}
	return f.op(c, v)
}

type absentNode struct{ ref fieldRef }

func (a absentNode) eval(c *evalCtx) bool { _, ok := a.ref.get(c); return !ok }

// compileEnv gives the condition compiler access to declared profiles.
type compileEnv struct {
	profiles map[string]*profileDef
}

var fieldNameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.\-]*$`)

func yamlKind(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "mapping"
	case yaml.SequenceNode:
		return "list"
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			return "empty value"
		}
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	}
	return "node"
}

func isNull(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.Tag == "!!null" }

// compileList compiles a non-empty list of conditions.
func (env *compileEnv) compileList(ns []yaml.Node, where string) ([]node, error) {
	if len(ns) == 0 {
		return nil, fmt.Errorf("%s: empty list", where)
	}
	out := make([]node, 0, len(ns))
	for i := range ns {
		n, err := env.compile(&ns[i], fmt.Sprintf("%s[%d]", where, i))
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// compile compiles one condition: a mapping with exactly one key.
func (env *compileEnv) compile(n *yaml.Node, where string) (node, error) {
	if n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: condition must be a mapping with exactly one key, got %s (dangling list item?)", where, yamlKind(n))
	}
	if len(n.Content) != 2 {
		return nil, fmt.Errorf("%s: condition must have exactly one key, has %d", where, len(n.Content)/2)
	}
	key, val := n.Content[0].Value, n.Content[1]
	where = where + "." + key
	switch key {
	case "all", "any":
		if val.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s: want a list, got %s", where, yamlKind(val))
		}
		subs := make([]yaml.Node, len(val.Content))
		for i, c := range val.Content {
			subs[i] = *c
		}
		list, err := env.compileList(subs, where)
		if err != nil {
			return nil, err
		}
		if key == "all" {
			return allNode(list), nil
		}
		return anyNode(list), nil
	case "not":
		sub, err := env.compile(val, where)
		if err != nil {
			return nil, err
		}
		return notNode{sub}, nil
	}
	if !fieldNameRE.MatchString(key) {
		return nil, fmt.Errorf("%s: invalid field name %q", where, key)
	}
	ref := newFieldRef(key)
	switch val.Kind {
	case yaml.ScalarNode:
		if isNull(val) {
			return nil, fmt.Errorf("%s: empty value", where)
		}
		set, err := strSet([]*yaml.Node{val}, false, where)
		if err != nil {
			return nil, err
		}
		return fieldNode{ref, set.match}, nil
	case yaml.SequenceNode:
		set, err := strSet(val.Content, false, where)
		if err != nil {
			return nil, err
		}
		return fieldNode{ref, set.match}, nil
	case yaml.MappingNode:
		if len(val.Content) != 2 {
			return nil, fmt.Errorf("%s: operator mapping must have exactly one key, has %d", where, len(val.Content)/2)
		}
		return env.compileOp(ref, val.Content[0].Value, val.Content[1], where)
	}
	return nil, fmt.Errorf("%s: bad value (%s)", where, yamlKind(val))
}

type strSetT struct {
	m  map[string]struct{}
	cs bool
}

func (s *strSetT) match(_ *evalCtx, v any) bool {
	return anyElem(v, func(e any) bool {
		str, ok := toStr(e)
		if !ok {
			return false
		}
		if !s.cs {
			str = strings.ToLower(str)
		}
		_, hit := s.m[str]
		return hit
	})
}

func strSet(ns []*yaml.Node, cs bool, where string) (*strSetT, error) {
	if len(ns) == 0 {
		return nil, fmt.Errorf("%s: empty list", where)
	}
	s := &strSetT{m: map[string]struct{}{}, cs: cs}
	for i, n := range ns {
		if n.Kind != yaml.ScalarNode || isNull(n) || n.Value == "" {
			return nil, fmt.Errorf("%s[%d]: list item must be a non-empty scalar, got %s (dangling item?)", where, i, yamlKind(n))
		}
		v := n.Value
		if !cs {
			v = strings.ToLower(v)
		}
		s.m[v] = struct{}{}
	}
	return s, nil
}

func scalarArg(n *yaml.Node, where string) (string, error) {
	if n.Kind != yaml.ScalarNode || isNull(n) || n.Value == "" {
		return "", fmt.Errorf("%s: want a non-empty scalar, got %s", where, yamlKind(n))
	}
	return n.Value, nil
}

func listArg(n *yaml.Node, where string) ([]string, error) {
	if n.Kind != yaml.SequenceNode || len(n.Content) == 0 {
		return nil, fmt.Errorf("%s: want a non-empty list, got %s", where, yamlKind(n))
	}
	var out []string
	for i, c := range n.Content {
		s, err := scalarArg(c, fmt.Sprintf("%s[%d]", where, i))
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func strFn(vals []string, cs bool, f func(s, needle string) bool, fcs func(s, needle string) bool) func(*evalCtx, any) bool {
	needles := make([]string, len(vals))
	for i, v := range vals {
		if cs {
			needles[i] = v
		} else {
			needles[i] = strings.ToLower(v)
		}
	}
	return func(_ *evalCtx, v any) bool {
		return anyElem(v, func(e any) bool {
			s, ok := toStr(e)
			if !ok {
				return false
			}
			for _, nd := range needles {
				if cs {
					if fcs(s, nd) {
						return true
					}
				} else if f(s, nd) {
					return true
				}
			}
			return false
		})
	}
}

func (env *compileEnv) compileOp(ref fieldRef, op string, arg *yaml.Node, where string) (node, error) {
	where = where + "." + op
	base, cs := strings.CutSuffix(op, "_cs")
	switch base {
	case "equals":
		base = "eq"
	case "prefix":
		base = "startswith"
	case "suffix":
		base = "endswith"
	case "regex":
		base = "re"
	case "exists":
		base = "present"
	}
	if cs {
		switch base {
		case "eq", "in", "contains", "startswith", "endswith", "contains_any", "startswith_any", "endswith_any":
		default:
			return nil, fmt.Errorf("%s: unknown operator %q", where, op)
		}
	}
	switch base {
	case "eq":
		s, err := scalarArg(arg, where)
		if err != nil {
			return nil, err
		}
		set, _ := strSet([]*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}}, cs, where)
		return fieldNode{ref, set.match}, nil
	case "in":
		if arg.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s: want a list, got %s", where, yamlKind(arg))
		}
		set, err := strSet(arg.Content, cs, where)
		if err != nil {
			return nil, err
		}
		return fieldNode{ref, set.match}, nil
	case "contains", "startswith", "endswith":
		s, err := scalarArg(arg, where)
		if err != nil {
			return nil, err
		}
		f, fcs := strFns(base)
		return fieldNode{ref, strFn([]string{s}, cs, f, fcs)}, nil
	case "contains_any", "startswith_any", "endswith_any":
		l, err := listArg(arg, where)
		if err != nil {
			return nil, err
		}
		f, fcs := strFns(strings.TrimSuffix(base, "_any"))
		return fieldNode{ref, strFn(l, cs, f, fcs)}, nil
	case "re":
		s, err := scalarArg(arg, where)
		if err != nil {
			return nil, err
		}
		re, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("%s: bad regex: %v", where, err)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("%s: regex %q matches the empty string (would match every event that has the field)", where, s)
		}
		return fieldNode{ref, func(_ *evalCtx, v any) bool {
			return anyElem(v, func(e any) bool {
				s, ok := toStr(e)
				return ok && re.MatchString(s)
			})
		}}, nil
	case "gt", "lt", "gte", "lte":
		s, err := scalarArg(arg, where)
		if err != nil {
			return nil, err
		}
		lim, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil, fmt.Errorf("%s: want a number, got %q", where, s)
		}
		cmp := map[string]func(a float64) bool{
			"gt": func(a float64) bool { return a > lim }, "lt": func(a float64) bool { return a < lim },
			"gte": func(a float64) bool { return a >= lim }, "lte": func(a float64) bool { return a <= lim },
		}[base]
		return fieldNode{ref, func(_ *evalCtx, v any) bool {
			return anyElem(v, func(e any) bool { n, ok := toNum(e); return ok && cmp(n) })
		}}, nil
	case "cidr":
		var l []string
		var err error
		if arg.Kind == yaml.SequenceNode {
			l, err = listArg(arg, where)
		} else {
			var s string
			s, err = scalarArg(arg, where)
			l = []string{s}
		}
		if err != nil {
			return nil, err
		}
		var ps []netip.Prefix
		for _, s := range l {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("%s: bad CIDR %q", where, s)
			}
			ps = append(ps, p.Masked())
		}
		return fieldNode{ref, func(_ *evalCtx, v any) bool {
			return anyElem(v, func(e any) bool {
				s, ok := e.(string)
				if !ok {
					return false
				}
				a, err := netip.ParseAddr(s)
				if err != nil {
					return false
				}
				a = a.Unmap()
				for _, p := range ps {
					if p.Contains(a) {
						return true
					}
				}
				return false
			})
		}}, nil
	case "present":
		if arg.Kind != yaml.ScalarNode || (arg.Value != "true" && arg.Value != "false") {
			return nil, fmt.Errorf("%s: want true or false", where)
		}
		if arg.Value == "false" {
			return absentNode{ref}, nil
		}
		return fieldNode{ref, func(_ *evalCtx, v any) bool {
			if s, ok := v.(string); ok {
				return s != ""
			}
			return true
		}}, nil
	case "in_profile":
		name, err := scalarArg(arg, where)
		if err != nil {
			return nil, err
		}
		pd, ok := env.profiles[name]
		if !ok {
			return nil, fmt.Errorf("%s: unknown profile %q", where, name)
		}
		if pd.Value != "" && pd.Value != ref.name {
			return nil, fmt.Errorf("%s: profile %q learns field %q but is tested on %q", where, name, pd.Value, ref.name)
		}
		return fieldNode{ref, func(c *evalCtx, v any) bool {
			s, ok := toStr(v)
			return ok && c.eng.inProfile(pd, c, s)
		}}, nil
	}
	return nil, fmt.Errorf("%s: unknown operator %q", where, op)
}

func strFns(op string) (ci, cs func(s, needle string) bool) {
	switch op {
	case "contains":
		return containsFold, strings.Contains
	case "startswith":
		return hasPrefixFold, strings.HasPrefix
	}
	return hasSuffixFold, strings.HasSuffix
}
