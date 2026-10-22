package winevt

import (
	"fmt"
	"slices"
	"strings"
)

// maxXPathClauses is a conservative bound under the ~22 expression limit of
// the Windows event XPath subset. Over it the server-side query falls back to
// "*" and the client-side include list does the filtering.
const maxXPathClauses = 18

// DropRule drops records of one event id whose field (snake_case) matches.
// It is applied to the parsed record before mapping (e.g. drop 4769 tickets
// for machine accounts on a busy DC).
type DropRule struct {
	EventID int
	Field   string
	Equals  string // exact, case-insensitive
	Suffix  string // value ends with (case-insensitive); either Equals or Suffix
}

// Channel configures one subscription.
type Channel struct {
	Name string
	// Include lists event ids to collect. Empty means the built-in default for
	// the channel (DefaultInclude); All collects everything.
	Include []int
	All     bool
	Exclude []int
	Drop    []DropRule
}

// DefaultChannels returns the channels the design lists (Appendix A) with
// their default event ids.
func DefaultChannels() []Channel {
	names := []string{ChSecurity, ChSystem, ChSysmon, ChPowerShell, ChDefender, ChTaskSched, ChWMIActivity}
	out := make([]Channel, 0, len(names))
	for _, n := range names {
		out = append(out, Channel{Name: n})
	}
	return out
}

var defaultInclude = map[string][]int{
	ChSecurity: {1102, 4624, 4625, 4648, 4662, 4670, 4688, 4697, 4698, 4699, 4702, 4719, 4720, 4722, 4724,
		4728, 4729, 4732, 4733, 4738, 4739, 4741, 4742, 4756, 4757, 4768, 4769, 4771, 4776, 4781, 4929,
		5136, 5137, 5139, 5140, 5141, 5145},
	ChSystem:      {104, 7045, 5827, 5828, 5829, 5830, 5831},
	ChSysmon:      {1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 25, 26, 255},
	ChPowerShell:  {4104},
	ChDefender:    {1116, 1117, 5001, 5004, 5007, 5010, 5012},
	ChTaskSched:   {106, 140, 141},
	ChWMIActivity: {5861},
}

// DefaultInclude returns the built-in event ids for a channel (nil if unknown).
func DefaultInclude(channel string) []int { return slices.Clone(defaultInclude[channel]) }

// Normalize validates the channel and fills defaults.
func (c Channel) Normalize() (Channel, error) {
	if strings.TrimSpace(c.Name) == "" {
		return c, fmt.Errorf("winevt: channel with empty name")
	}
	if !c.All && len(c.Include) == 0 {
		c.Include = DefaultInclude(c.Name)
		if len(c.Include) == 0 {
			return c, fmt.Errorf("winevt: channel %q has no default event ids: set Include or All", c.Name)
		}
	}
	c.Include = slices.Clone(c.Include)
	slices.Sort(c.Include)
	c.Include = slices.Compact(c.Include)
	return c, nil
}

// Query builds the server-side XPath query.
func (c Channel) Query() string {
	if c.All || len(c.Include) == 0 {
		return "*"
	}
	ids := slices.Clone(c.Include)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	var clauses []string
	for i := 0; i < len(ids); {
		j := i
		for j+1 < len(ids) && ids[j+1] == ids[j]+1 {
			j++
		}
		switch {
		case j == i:
			clauses = append(clauses, fmt.Sprintf("EventID=%d", ids[i]))
		case j == i+1:
			clauses = append(clauses, fmt.Sprintf("EventID=%d", ids[i]), fmt.Sprintf("EventID=%d", ids[j]))
		default:
			clauses = append(clauses, fmt.Sprintf("(EventID>=%d and EventID<=%d)", ids[i], ids[j]))
		}
		i = j + 1
	}
	if len(clauses) > maxXPathClauses {
		return "*"
	}
	return "*[System[(" + strings.Join(clauses, " or ") + ")]]"
}

// Match reports whether the record passes the channel's filters.
func (c Channel) Match(r *Record) bool {
	if slices.Contains(c.Exclude, r.EventID) {
		return false
	}
	if !c.All && !slices.Contains(c.Include, r.EventID) {
		return false
	}
	for _, d := range c.Drop {
		if d.EventID != r.EventID {
			continue
		}
		v := r.Data[d.Field]
		if d.Equals != "" && strings.EqualFold(v, d.Equals) {
			return false
		}
		if d.Suffix != "" && strings.HasSuffix(strings.ToLower(v), strings.ToLower(d.Suffix)) {
			return false
		}
	}
	return true
}
