package manifest

// LabelExpr is a parsed host label expression.
type LabelExpr struct {
	root *labelNode
}

type labelNode struct {
	op    string
	name  string
	left  *labelNode
	right *labelNode
}

// ParseLabels parses an expression over host labels: identifiers, !, &&, ||,
// parentheses; precedence ! > && > ||; at most 256 bytes.
func ParseLabels(expr string) (LabelExpr, error) { panic("unimplemented: W1 Task 11") }

// Match reports whether labels satisfy the expression.
func (e LabelExpr) Match(labels []string) bool { panic("unimplemented: W1 Task 11") }

// HostsMatching returns the sorted host names whose labels match e.
func (m *Manifest) HostsMatching(e LabelExpr) []string { panic("unimplemented: W1 Task 11") }
