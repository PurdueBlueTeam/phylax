package chains

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/traceback"
)

// Central returns America/Chicago, or a fixed UTC-6 zone when the host has no
// tz database (the UI and IR draft show Central time with UTC alongside).
func Central() *time.Location {
	if l, err := time.LoadLocation("America/Chicago"); err == nil {
		return l
	}
	return time.FixedZone("CST", -6*3600)
}

// Row is one line of the timeline view model: one row per hop. There is no
// graph canvas; Cause lets the UI indent or annotate "after row N".
type Row struct {
	Ord        int
	Cause      int // row this one follows from, -1 for a root
	Kind       Kind
	Seed       bool
	Time       time.Time
	Local      string // "2006-01-02 15:04:05 MST" in the requested zone
	UTC        string
	Host       string
	What       string
	Technique  string
	Method     string
	Confidence float64
	// Level is "high" (>=0.9), "medium" (>=0.6) or "low"; Guess is set when the
	// link is a time-window guess or unmatched side, so the UI never shows it
	// as fact.
	Level    string
	Guess    bool
	Notes    []string
	Evidence []traceback.Ref
	Items    []ItemView
}

// ItemView is a remediation item as the UI shows it.
type ItemView struct {
	ID       int64
	Kind     ItemKind
	Text     string
	State    string
	Verified bool
	Note     string
}

// Level names a confidence.
func Level(conf float64) string {
	switch {
	case conf >= 0.9:
		return "high"
	case conf >= 0.6:
		return "medium"
	}
	return "low"
}

// Timeline renders the chain, one row per hop in time order, in zone loc
// (Central when nil).
func (c *Chain) Timeline(loc *time.Location) []Row {
	if loc == nil {
		loc = Central()
	}
	rows := make([]Row, 0, len(c.Hops))
	for _, h := range c.Hops {
		r := Row{Ord: h.Ord, Cause: h.Cause, Kind: h.Kind, Seed: h.Seed, Time: h.Start,
			Local: h.Start.In(loc).Format("2006-01-02 15:04:05 MST"), UTC: h.Start.UTC().Format("15:04:05Z"),
			Host: h.DstHost, What: h.What, Technique: h.Technique, Method: h.Method, Confidence: h.Confidence,
			Level: Level(h.Confidence), Guess: h.Method == MethodTimeWindow || h.Method == MethodUnmatched,
			Notes: h.Notes, Evidence: h.Evidence}
		if h.Kind == Move && h.SrcHost != "" {
			r.Host = h.SrcHost + " -> " + h.DstHost
		}
		for _, it := range h.Items {
			r.Items = append(r.Items, ItemView{ID: it.ID, Kind: it.Kind, Text: it.Text, State: it.State, Verified: it.Verified(), Note: it.Note})
		}
		rows = append(rows, r)
	}
	return rows
}

// IRSection is the chain's input to the IR drafter: the "attack path" and
// "remediation" sections come from here, every claim traced to evidence.
type IRSection struct {
	Timeline    []Row
	Remediation []RemediationLine
	Techniques  []string
	Sources     []string
	Accounts    []string
	Hosts       []string
	Confidence  float64
	Caveats     []string // truncation, agent gaps, low-confidence hops
	// ProofClosed is true only when every item is verified.
	ProofClosed bool
}

// RemediationLine is one remediation item with its hop.
type RemediationLine struct {
	Hop      int
	Item     ItemView
	HopWhat  string
	Evidence []traceback.Ref
}

// IRSection assembles the drafter input.
func (c *Chain) IRSection(loc *time.Location) IRSection {
	s := IRSection{Timeline: c.Timeline(loc), Confidence: c.Confidence, ProofClosed: true}
	techs, accts, hosts := map[string]bool{}, map[string]bool{}, map[string]bool{}
	k := ChainKeys(c, Config{})
	s.Sources = k.Sources
	for _, h := range c.Hops {
		if h.Technique != "" {
			techs[h.Technique] = true
		}
		if h.Account != "" {
			accts[h.Account] = true
		}
		for _, x := range []string{h.DstHost, h.SrcHost} {
			if x != "" {
				hosts[x] = true
			}
		}
		for _, it := range h.Items {
			s.Remediation = append(s.Remediation, RemediationLine{Hop: h.Ord, HopWhat: h.What, Evidence: h.Evidence,
				Item: ItemView{ID: it.ID, Kind: it.Kind, Text: it.Text, State: it.State, Verified: it.Verified(), Note: it.Note}})
			if !it.Verified() {
				s.ProofClosed = false
			}
		}
		if h.Confidence < 0.6 {
			s.Caveats = append(s.Caveats, fmt.Sprintf("hop %d (%s) is low confidence: %s", h.Ord, h.Kind, strings.Join(h.Notes, "; ")))
		}
	}
	if len(s.Remediation) == 0 {
		s.ProofClosed = false
	}
	s.Caveats = append(s.Caveats, c.Notes...)
	set := func(m map[string]bool) []string {
		var out []string
		for v := range m {
			out = append(out, v)
		}
		sort.Strings(out)
		return out
	}
	s.Techniques, s.Accounts, s.Hosts = set(techs), set(accts), set(hosts)
	return s
}
