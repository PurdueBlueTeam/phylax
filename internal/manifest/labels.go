package manifest

import (
	"fmt"
	"sort"
	"strings"
)

// LabelExpr is a parsed host label expression.
type LabelExpr struct {
	root *labelNode
}

type labelNode struct {
	op    string // "", "!", "&&", "||"
	name  string // for a leaf
	left  *labelNode
	right *labelNode
}

// maxLabelExpr bounds a label expression's length.
const maxLabelExpr = 256

// ParseLabels parses an expression over host labels: identifiers, !, &&, ||,
// parentheses; precedence ! > && > ||; at most 256 bytes.
func ParseLabels(expr string) (LabelExpr, error) {
	if len(expr) > maxLabelExpr {
		return LabelExpr{}, fmt.Errorf("labels: expression longer than %d bytes", maxLabelExpr)
	}
	p := &labelParser{s: expr}
	if err := p.next(); err != nil {
		return LabelExpr{}, err
	}
	n, err := p.parseOr()
	if err != nil {
		return LabelExpr{}, err
	}
	if p.tok != "" {
		return LabelExpr{}, fmt.Errorf("labels: unexpected %q in %q", p.tok, expr)
	}
	return LabelExpr{root: n}, nil
}

type labelParser struct {
	s   string
	i   int
	tok string // the lookahead token; "" is end of input
}

// next advances the lookahead.
func (p *labelParser) next() error {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
	if p.i >= len(p.s) {
		p.tok = ""
		return nil
	}
	if strings.HasPrefix(p.s[p.i:], "&&") || strings.HasPrefix(p.s[p.i:], "||") {
		p.tok = p.s[p.i : p.i+2]
		p.i += 2
		return nil
	}
	c := p.s[p.i]
	if c == '!' || c == '(' || c == ')' {
		p.tok = string(c)
		p.i++
		return nil
	}
	if isLabelStart(c) {
		j := p.i
		for j < len(p.s) && isLabelChar(p.s[j]) {
			j++
		}
		p.tok = p.s[p.i:j]
		p.i = j
		return nil
	}
	return fmt.Errorf("labels: unexpected %q at %d", c, p.i)
}

func isLabelStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
}

func isLabelChar(c byte) bool { return isLabelStart(c) }

func (p *labelParser) parseOr() (*labelNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.tok == "||" {
		if err := p.next(); err != nil {
			return nil, err
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &labelNode{op: "||", left: left, right: right}
	}
	return left, nil
}

func (p *labelParser) parseAnd() (*labelNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.tok == "&&" {
		if err := p.next(); err != nil {
			return nil, err
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &labelNode{op: "&&", left: left, right: right}
	}
	return left, nil
}

func (p *labelParser) parseUnary() (*labelNode, error) {
	if p.tok == "!" {
		if err := p.next(); err != nil {
			return nil, err
		}
		operand, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &labelNode{op: "!", left: operand}, nil
	}
	if p.tok == "(" {
		if err := p.next(); err != nil {
			return nil, err
		}
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.tok != ")" {
			return nil, fmt.Errorf("labels: missing )")
		}
		if err := p.next(); err != nil {
			return nil, err
		}
		return inner, nil
	}
	if p.tok == "" || p.tok == ")" || p.tok == "&&" || p.tok == "||" {
		return nil, fmt.Errorf("labels: expected a label, got %q", p.tok)
	}
	n := &labelNode{name: p.tok}
	return n, p.next()
}

// Match reports whether labels satisfy the expression.
func (e LabelExpr) Match(labels []string) bool {
	if e.root == nil {
		return false
	}
	return e.root.match(labels)
}

func (n *labelNode) match(labels []string) bool {
	switch n.op {
	case "!":
		return !n.left.match(labels)
	case "&&":
		return n.left.match(labels) && n.right.match(labels)
	case "||":
		return n.left.match(labels) || n.right.match(labels)
	}
	for _, l := range labels {
		if l == n.name {
			return true
		}
	}
	return false
}

// HostsMatching returns the sorted host names whose labels match e.
func (m *Manifest) HostsMatching(e LabelExpr) []string {
	var out []string
	for name, h := range m.Hosts {
		if e.Match(h.Labels) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
