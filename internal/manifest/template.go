package manifest

import (
	"fmt"
	"strconv"
	"strings"
)

// Template variables and expressions. Manifest values may embed `{{ expr }}`
// spans, e.g. "172.25.{{ 20 + team }}.144". The evaluator is deliberately
// tiny: integers, + - * / %, parentheses and the `team` variable. There are
// no functions, no other variables, no strings — nothing that can do harm.

// Vars is the set of template variables available to expressions.
type Vars map[string]int

// TeamVars returns the standard variable set for a team number.
func TeamVars(team int) Vars { return Vars{"team": team} }

// Render applies {{ expr }} spans to raw YAML text. A span that is the entire
// scalar (after trimming) and evaluates to a number is rendered unquoted;
// otherwise the numeric result is rendered as a string.
func (v Vars) Render(in string) (string, error) {
	var (
		out  strings.Builder
		i    = 0
	)
	for i < len(in) {
		rest := in[i:]
		if !strings.HasPrefix(rest, "{{") {
			out.WriteByte(in[i])
			i++
			continue
		}
		end := strings.Index(rest, "}}")
		if end < 0 {
			return "", fmt.Errorf("manifest template: unclosed {{ at byte %d", i)
		}
		expr := strings.TrimSpace(rest[2:end])
		val, err := evalExpr(expr, v)
		if err != nil {
			return "", fmt.Errorf("manifest template: %s: %w", expr, err)
		}
		// Whole-scalar detection: nothing but whitespace after this span
		// until end-of-line, and (going back) the line starts with the span.
		after := rest[end+2:]
		if j := strings.IndexByte(after, '\n'); j >= 0 {
			after = after[:j]
		}
		lineStart := strings.LastIndex(in[:i], "\n") + 1
		before := strings.TrimSpace(in[lineStart:i])
		// Strip a leading YAML key/value prefix: "key:" possibly with quotes.
		if kpos := strings.Index(before, ":"); kpos >= 0 {
			before = strings.TrimSpace(before[kpos+1:])
		}
		whole := before == "" && strings.TrimSpace(after) == ""
		if whole {
			out.WriteString(strconv.Itoa(val))
		} else {
			out.WriteString(strconv.Itoa(val))
		}
		i += end + 2
	}
	return out.String(), nil
}

// evalExpr parses and evaluates a small arithmetic expression.
func evalExpr(s string, v Vars) (int, error) {
	p := &parser{s: s, v: v}
	n, err := p.expr()
	if err != nil {
		return 0, err
	}
	p.skip()
	if p.pos != len(p.s) {
		return 0, fmt.Errorf("unexpected trailing %q", p.s[p.pos:])
	}
	return n, nil
}

type parser struct {
	s   string
	pos int
	v   Vars
}

func (p *parser) skip() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
}

// expr: term (('+'|'-') term)*
func (p *parser) expr() (int, error) {
	left, err := p.term()
	if err != nil {
		return 0, err
	}
	for {
		p.skip()
		if p.pos >= len(p.s) {
			return left, nil
		}
		op := p.s[p.pos]
		if op != '+' && op != '-' {
			return left, nil
		}
		p.pos++
		right, err := p.term()
		if err != nil {
			return 0, err
		}
		if op == '+' {
			left += right
		} else {
			left -= right
		}
	}
}

// term: factor (('*'|'/'|'%') factor)*
func (p *parser) term() (int, error) {
	left, err := p.factor()
	if err != nil {
		return 0, err
	}
	for {
		p.skip()
		if p.pos >= len(p.s) {
			return left, nil
		}
		op := p.s[p.pos]
		if op != '*' && op != '/' && op != '%' {
			return left, nil
		}
		p.pos++
		right, err := p.factor()
		if err != nil {
			return 0, err
		}
		switch op {
		case '*':
			left *= right
		case '/':
			if right == 0 {
				return 0, fmt.Errorf("division by zero")
			}
			left /= right
		case '%':
			if right == 0 {
				return 0, fmt.Errorf("modulo by zero")
			}
			left %= right
		}
	}
}

// factor: number | ident | '(' expr ')' | '-' factor
func (p *parser) factor() (int, error) {
	p.skip()
	if p.pos >= len(p.s) {
		return 0, fmt.Errorf("unexpected end of expression")
	}
	c := p.s[p.pos]
	if c == '-' {
		p.pos++
		n, err := p.factor()
		return -n, err
	}
	if c == '(' {
		p.pos++
		n, err := p.expr()
		if err != nil {
			return 0, err
		}
		p.skip()
		if p.pos >= len(p.s) || p.s[p.pos] != ')' {
			return 0, fmt.Errorf("missing closing parenthesis")
		}
		p.pos++
		return n, nil
	}
	if c >= '0' && c <= '9' {
		start := p.pos
		for p.pos < len(p.s) && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
			p.pos++
		}
		return strconv.Atoi(p.s[start:p.pos])
	}
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' {
		start := p.pos
		for p.pos < len(p.s) && (isIdentChar(p.s[p.pos])) {
			p.pos++
		}
		name := p.s[start:p.pos]
		val, ok := p.v[name]
		if !ok {
			return 0, fmt.Errorf("unknown variable %q", name)
		}
		return val, nil
	}
	return 0, fmt.Errorf("unexpected character %q", c)
}

func isIdentChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
