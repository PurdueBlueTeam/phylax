package winevt

import (
	"strings"
	"testing"
)

func TestDefaultChannelsNormalize(t *testing.T) {
	for _, c := range DefaultChannels() {
		n, err := c.Normalize()
		if err != nil || len(n.Include) == 0 {
			t.Fatalf("%s: %v %v", c.Name, n.Include, err)
		}
	}
	if _, err := (Channel{Name: "Custom/Unknown"}).Normalize(); err == nil {
		t.Fatal("unknown channel without include must fail")
	}
	if _, err := (Channel{Name: ""}).Normalize(); err == nil {
		t.Fatal("empty name must fail")
	}
	if n, err := (Channel{Name: "Custom/Unknown", All: true}).Normalize(); err != nil || n.Query() != "*" {
		t.Fatalf("all: %v %q", err, n.Query())
	}
}

func TestDefaultsCoverRequiredEventIDs(t *testing.T) {
	need := map[string][]int{
		ChSecurity: {4624, 4625, 4688, 4697, 4698, 4720, 4728, 4732, 4742, 4768, 4769, 4776, 5136, 5137, 4670, 1102},
		ChSystem:   {7045, 104, 5829},
		ChSysmon:   {1, 3, 6, 7, 8, 10, 11, 12, 13, 14, 22, 25},
		ChDefender: {1116, 5001, 5007}, ChPowerShell: {4104}, ChTaskSched: {106}, ChWMIActivity: {5861},
	}
	for ch, ids := range need {
		have := map[int]bool{}
		for _, id := range DefaultInclude(ch) {
			have[id] = true
		}
		for _, id := range ids {
			if !have[id] {
				t.Errorf("%s default include lacks %d", ch, id)
			}
		}
	}
}

func TestQueryXPath(t *testing.T) {
	c, _ := Channel{Name: "X", Include: []int{4625, 4624, 4688, 4688, 5136, 5137, 5138}}.Normalize()
	got := c.Query()
	want := "*[System[(EventID=4624 or EventID=4625 or EventID=4688 or (EventID>=5136 and EventID<=5138))]]"
	if got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	// Too many clauses for the Windows XPath subset: fall back to client-side filtering.
	var many []int
	for i := 0; i < 40; i++ {
		many = append(many, i*10)
	}
	c, _ = Channel{Name: "X", Include: many}.Normalize()
	if c.Query() != "*" {
		t.Fatalf("expected fallback, got %s", c.Query())
	}
	for _, d := range DefaultChannels() {
		n, _ := d.Normalize()
		if q := n.Query(); strings.Count(q, " or ") > maxXPathClauses {
			t.Errorf("%s query too long: %s", n.Name, q)
		}
	}
}

func TestMatch(t *testing.T) {
	c, _ := Channel{Name: ChSecurity, Include: []int{4624, 4769}, Exclude: []int{4624},
		Drop: []DropRule{{EventID: 4769, Field: "service_name", Suffix: "$"}, {EventID: 4769, Field: "target_user_name", Equals: "NOISE"}}}.Normalize()
	rec := func(id int, kv ...string) *Record {
		r := &Record{EventID: id, Data: map[string]string{}}
		for i := 0; i < len(kv); i += 2 {
			r.Data[kv[i]] = kv[i+1]
		}
		return r
	}
	for name, tc := range map[string]struct {
		r    *Record
		want bool
	}{
		"excluded":     {rec(4624), false},
		"not included": {rec(4688), false},
		"pass":         {rec(4769, "service_name", "krbtgt"), true},
		"drop suffix":  {rec(4769, "service_name", "WKS01$"), false},
		"drop equals":  {rec(4769, "target_user_name", "noise"), false},
	} {
		if got := c.Match(tc.r); got != tc.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}
