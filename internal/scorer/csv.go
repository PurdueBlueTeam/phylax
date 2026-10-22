package scorer

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/creds"
)

// CSVPolicy holds the Appendix F rules that are specific to the portal path.
// Character and format rules live in internal/creds (PCRSafe, Scored class) so
// they exist in one place.
type CSVPolicy struct {
	KnownPaths map[string]bool // configured credlist paths; nil disables the check
}

func (p CSVPolicy) withDefaults() CSVPolicy { return p }

// CSVEntry is one account change. Path is the credlist path (never the display name).
type CSVEntry struct {
	Path     string
	Username string
	Password string
}

// CSVBlock is the text to paste for one credlist path.
type CSVBlock struct {
	Path  string
	Lines []string
	Text  string
	Count int
}

// ValidateEntry checks one entry against the portal's quirks (the page splits
// each line at the first comma, does not trim, strips a matching pair of
// surrounding quotes per field, and stores an empty password when the comma is
// missing) by delegating to creds.PCRSafe and the creds.Scored class rules.
func (p CSVPolicy) ValidateEntry(e CSVEntry) error {
	if e.Path == "" {
		return errors.New("empty credlist path")
	}
	if p.KnownPaths != nil && !p.KnownPaths[e.Path] {
		return fmt.Errorf("credlist %q is not a configured path (a display name makes the portal answer 500)", e.Path)
	}
	if err := creds.PCRSafe(e.Username, e.Password); err != nil {
		return fmt.Errorf("user %q: %w", e.Username, err)
	}
	if quoted(e.Username) {
		return fmt.Errorf("username %q starts and ends with a quote: the portal would strip them", e.Username)
	}
	if err := creds.Scored.Check(e.Password); err != nil {
		return fmt.Errorf("user %q: %w", e.Username, err)
	}
	return nil
}

func quoted(s string) bool {
	return len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[0] == s[len(s)-1]
}

// GenerateCSV builds one block per credlist path (sorted by path, lines in input
// order). A duplicate username within a path is an error: the portal would let
// the last line win silently.
func (p CSVPolicy) GenerateCSV(entries []CSVEntry) ([]CSVBlock, error) {
	by := map[string][]CSVEntry{}
	var paths []string
	for _, e := range entries {
		if err := p.ValidateEntry(e); err != nil {
			return nil, err
		}
		if _, ok := by[e.Path]; !ok {
			paths = append(paths, e.Path)
		}
		by[e.Path] = append(by[e.Path], e)
	}
	sort.Strings(paths)
	var blocks []CSVBlock
	for _, path := range paths {
		seen := map[string]bool{}
		b := CSVBlock{Path: path}
		for _, e := range by[path] {
			if seen[e.Username] {
				return nil, fmt.Errorf("duplicate username %q in credlist %q", e.Username, path)
			}
			seen[e.Username] = true
			b.Lines = append(b.Lines, e.Username+","+e.Password)
		}
		b.Count = len(b.Lines)
		b.Text = strings.Join(b.Lines, "\n")
		// Defence in depth: parse it back the way the portal will.
		got := PortalParse(b.Text)
		if len(got) != len(by[path]) {
			return nil, fmt.Errorf("credlist %q: portal would parse %d lines, expected %d", path, len(got), len(by[path]))
		}
		for i, e := range by[path] {
			if got[i].Username != e.Username || got[i].Password != e.Password {
				return nil, fmt.Errorf("credlist %q: line %d does not survive the portal parser", path, i+1)
			}
		}
		blocks = append(blocks, b)
	}
	return blocks, nil
}

// PortalPair is a parsed user/password pair.
type PortalPair struct{ Username, Password string }

// PortalParse reproduces pcr.html's client-side parsing (quotient.md section 5):
// split on newline, drop blank lines, split each at the first comma only, strip
// a matching pair of surrounding quotes from each field, never trim, and use
// an empty password when there is no comma.
func PortalParse(text string) []PortalPair {
	var out []PortalPair
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		u, pw, _ := strings.Cut(line, ",")
		out = append(out, PortalPair{strip(u), strip(pw)})
	}
	return out
}

func strip(s string) string {
	if quoted(s) {
		return s[1 : len(s)-1]
	}
	return s
}

// PCRReply is the portal's answer to a submission.
type PCRReply struct {
	Count   int
	Skipped []string
}

// ErrReplyMismatch is returned when count or skipped disagree with the submission.
var ErrReplyMismatch = errors.New("PCR reply does not match the submission (count/skipped)")

// VerifyReply requires count == number of lines and skipped empty.
func (b CSVBlock) VerifyReply(r PCRReply) error {
	if len(r.Skipped) > 0 {
		return fmt.Errorf("%w: skipped %v (unknown or wrong-case usernames)", ErrReplyMismatch, r.Skipped)
	}
	if r.Count != b.Count {
		return fmt.Errorf("%w: count %d, expected %d", ErrReplyMismatch, r.Count, b.Count)
	}
	return nil
}
