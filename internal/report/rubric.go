package report

import (
	"fmt"
	"strings"
)

// Status of a checklist item.
type Status string

const (
	Met          Status = "met"
	Partial      Status = "partial"       // some evidence, not enough to count (no partial points)
	Unmet        Status = "unmet"         // the drafter had no data; the operator can still supply it
	OperatorOnly Status = "operator-only" // only a human can judge it
)

// Rubric names.
const (
	RubricWK       = "WinterKnight" // red-team lead: 10/10/10/10/10 + 50% attack-path remediation
	RubricStout    = "UW-Stout"     // 0-3 per row, weighted
	RubricPlaybook = "Playbook"     // the section 6 pre-submission checklist
)

// CheckItem is one rubric row and whether the draft satisfies it.
type CheckItem struct {
	ID     string
	Rubric string
	Name   string
	Weight int // percent of that rubric (0 for the playbook list)
	Status Status
	Detail string
	// Lines are per-hop or per-item findings behind the status.
	Lines []string
}

// Checklist is the draft's self-score.
type Checklist []CheckItem

// Earned is the percent of rubric the draft satisfies (Met items only; the
// rules give no partial points). Pending is the percent still open.
func (c Checklist) Earned(rubric string) (earned, total int) {
	for _, it := range c {
		if it.Rubric != rubric {
			continue
		}
		total += it.Weight
		if it.Status == Met {
			earned += it.Weight
		}
	}
	return
}

// Open returns items that are not Met.
func (c Checklist) Open() Checklist {
	var out Checklist
	for _, it := range c {
		if it.Status != Met {
			out = append(out, it)
		}
	}
	return out
}

// Fillable returns items the operator can fix by supplying data (Unmet or
// Partial), as opposed to OperatorOnly judgements.
func (c Checklist) Fillable() Checklist {
	var out Checklist
	for _, it := range c {
		if it.Status == Unmet || it.Status == Partial {
			out = append(out, it)
		}
	}
	return out
}

// Get returns an item by id.
func (c Checklist) Get(id string) (CheckItem, bool) {
	for _, it := range c {
		if it.ID == id {
			return it, true
		}
	}
	return CheckItem{}, false
}

// Markdown renders the checklist for the reviewer (not part of the PDF).
func (c Checklist) Markdown() string {
	var b strings.Builder
	for _, r := range []string{RubricWK, RubricStout, RubricPlaybook} {
		e, t := c.Earned(r)
		if t > 0 {
			fmt.Fprintf(&b, "## %s rubric: %d%% of %d%% satisfied by the draft\n\n", r, e, t)
		} else {
			fmt.Fprintf(&b, "## %s checklist\n\n", r)
		}
		for _, it := range c {
			if it.Rubric != r {
				continue
			}
			box := "[ ]"
			if it.Status == Met {
				box = "[x]"
			}
			w := ""
			if it.Weight > 0 {
				w = fmt.Sprintf(" (%d%%)", it.Weight)
			}
			fmt.Fprintf(&b, "- %s %s%s: %s [%s] %s\n", box, it.ID, w, it.Name, it.Status, it.Detail)
			for _, l := range it.Lines {
				fmt.Fprintf(&b, "  - %s\n", l)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
