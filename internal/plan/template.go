package plan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// TriggerParam is the reserved parameter carrying the event that started an
// auto plan ("<agent>:<seq>"). It is never substituted into a template.
const TriggerParam = "trigger"

var (
	paramNameRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	placeholderRE = regexp.MustCompile(`\$\{([^}]*)\}`)
)

// ExpandTemplate substitutes ${name} parameters in every node's target and in
// every string inside Params (recursing into maps and slices). It refuses a
// placeholder without a parameter, a parameter no placeholder uses (except the
// reserved trigger) and a parameter value that itself contains a placeholder.
func ExpandTemplate(p Plan, params map[string]string) (Plan, error) {
	names := make([]string, 0, len(params))
	for name, v := range params {
		names = append(names, name)
		if name == TriggerParam {
			continue
		}
		if strings.Contains(v, "${") {
			return Plan{}, fmt.Errorf("plan: parameter %q contains a placeholder", name)
		}
	}
	sort.Strings(names)
	used := map[string]bool{}
	sub := func(s string) (string, error) {
		return expandString(s, params, used)
	}
	out := p
	out.Nodes = make([]Node, len(p.Nodes))
	for i, n := range p.Nodes {
		target, err := sub(n.Target)
		if err != nil {
			return Plan{}, err
		}
		n.Target = target
		if n.Params != nil {
			v, err := expandValue(n.Params, sub)
			if err != nil {
				return Plan{}, err
			}
			n.Params = v.(map[string]any)
		}
		out.Nodes[i] = n
	}
	for _, name := range names {
		if name != TriggerParam && !used[name] {
			return Plan{}, fmt.Errorf("plan: parameter %q is not used", name)
		}
	}
	return out, nil
}

func expandString(s string, params map[string]string, used map[string]bool) (string, error) {
	var b strings.Builder
	rest := s
	for {
		loc := placeholderRE.FindStringSubmatchIndex(rest)
		if loc == nil {
			b.WriteString(rest)
			return b.String(), nil
		}
		name := rest[loc[2]:loc[3]]
		if !paramNameRE.MatchString(name) {
			return "", fmt.Errorf("plan: bad parameter name %q", name)
		}
		if name == TriggerParam {
			return "", fmt.Errorf("plan: ${%s} is reserved and not substituted", TriggerParam)
		}
		v, ok := params[name]
		if !ok {
			return "", fmt.Errorf("plan: no value for ${%s}", name)
		}
		used[name] = true
		b.WriteString(rest[:loc[0]])
		b.WriteString(v)
		rest = rest[loc[1]:]
	}
}

func expandValue(v any, sub func(string) (string, error)) (any, error) {
	switch x := v.(type) {
	case string:
		return sub(x)
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, vv := range x {
			ev, err := expandValue(vv, sub)
			if err != nil {
				return nil, err
			}
			m[k] = ev
		}
		return m, nil
	case []any:
		s := make([]any, len(x))
		for i, vv := range x {
			ev, err := expandValue(vv, sub)
			if err != nil {
				return nil, err
			}
			s[i] = ev
		}
		return s, nil
	case map[string]string:
		m := make(map[string]string, len(x))
		for k, vv := range x {
			ev, err := sub(vv)
			if err != nil {
				return nil, err
			}
			m[k] = ev
		}
		return m, nil
	case []string:
		s := make([]string, len(x))
		for i, vv := range x {
			ev, err := sub(vv)
			if err != nil {
				return nil, err
			}
			s[i] = ev
		}
		return s, nil
	}
	return v, nil
}
