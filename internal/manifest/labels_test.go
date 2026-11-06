package manifest

import (
	"strings"
	"testing"
)

func TestParseLabels(t *testing.T) {
	cases := []struct {
		expr   string
		labels []string
		want   bool
	}{
		{"linux && !workstation", []string{"linux", "server"}, true},
		{"linux && !workstation", []string{"linux", "workstation"}, false},
		{"(a || b) && c", []string{"b", "c"}, true},
		{"a || b && c", []string{"a"}, true},
		{"!a", nil, true},
	}
	for _, c := range cases {
		e, err := ParseLabels(c.expr)
		if err != nil || e.Match(c.labels) != c.want {
			t.Errorf("%q %v: %v", c.expr, c.labels, err)
		}
	}
	for _, bad := range []string{"", "a &&", "a b", "!(", "a & b", strings.Repeat("a", 257)} {
		if _, err := ParseLabels(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
