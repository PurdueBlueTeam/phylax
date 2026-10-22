package scorer

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Features describe one connection or transaction, extracted by the protocol
// parsers. The classifier is behaviour-only: AdvisoryRunner (source address
// matches a known runner) is a tiny hint that can never label traffic alone.
//
// Attr and List keys used by DefaultTable (absent keys never match):
//
//	ssh.hassh ssh.banner ssh.pty ssh.dwell_ms ssh.fail_then_accept  List: ssh.auth
//	http.method http.host http.ua                                    List: http.headers
//	tls.ja4 tls.ja3 tls.sni tls.hello_len                            List: tls.alpn
//	dns.edns dns.rd   icmp.payload_len icmp.seq
//	smtp.ehlo_arg smtp.mail_ext smtp.subject smtp.body imap.tag      List: smtp.cmds imap.cmds pop3.cmds ftp.cmds
//	smb.ntlm_flags smb.tree smb.domain_is_server
//	winrm.method winrm.path winrm.ua winrm.first_no_auth
//	tcp.zero_payload tcp.hold_ms
type Features struct {
	Proto string // ssh http tls dns icmp smtp imap pop3 ftp smb winrm tcp mssql splunk rdp ldap
	Port  int

	InBurst        bool // inside a detected burst (see Estimator.InBurst)
	OneShot        bool // first connection to this service this round
	LearnedCred    bool // logged in with a credential learned for the scorer
	AdvisoryRunner bool // source address is a known runner (advisory only)

	Attr map[string]string
	List map[string][]string
}

// MatchKind selects how a Rule compares a feature.
type MatchKind string

const (
	MatchEq        MatchKind = "eq"         // Attr[Key] equals one of Values (case-insensitive)
	MatchRegex     MatchKind = "regex"      // Attr[Key] matches Pattern
	MatchRange     MatchKind = "range"      // numeric Attr[Key] in [Min, Max]
	MatchSubseq    MatchKind = "subseq"     // List[Key] contains Values in order (case-insensitive)
	MatchExactSet  MatchKind = "exact_set"  // List[Key] has exactly the set Values
	MatchContains  MatchKind = "contains"   // List[Key] contains any of Values
	MatchSeqExact  MatchKind = "seq_exact"  // List[Key] equals Values in order
	MatchEmptyList MatchKind = "empty_list" // List[Key] present and empty
)

// Rule is one row of the fingerprint table. A positive rule adds evidence
// (noisy-or); a Negative rule that matches contradicts scorer origin and
// multiplies the score by 1-Weight.
type Rule struct {
	ID       string    `json:"id"`
	Proto    string    `json:"proto"`
	Layer    string    `json:"layer"`
	Key      string    `json:"key"`
	Kind     MatchKind `json:"kind"`
	Values   []string  `json:"values,omitempty"`
	Pattern  string    `json:"pattern,omitempty"`
	Min      float64   `json:"min,omitempty"`
	Max      float64   `json:"max,omitempty"`
	Weight   float64   `json:"weight"`
	Negative bool      `json:"negative,omitempty"`
	Note     string    `json:"note,omitempty"`
}

// GenericWeights are the protocol-independent behavioural hints.
type GenericWeights struct {
	Burst          float64 `json:"burst"`
	OneShot        float64 `json:"one_shot"`
	LearnedCred    float64 `json:"learned_cred"`
	AdvisoryRunner float64 `json:"advisory_runner"`
}

// Table is the versioned fingerprint table. Hashes (HASSH, JA4) follow the
// build of Quotient running at the event: re-learn them each event and load
// the result with ParseTable.
type Table struct {
	Version string         `json:"version"`
	Source  string         `json:"source"`
	Generic GenericWeights `json:"generic"`
	Rules   []Rule         `json:"rules"`
}

// ParseTable loads a table from JSON (an event-specific override).
func ParseTable(b []byte) (Table, error) {
	var t Table
	if err := json.Unmarshal(b, &t); err != nil {
		return t, err
	}
	if t.Version == "" {
		return t, fmt.Errorf("fingerprint table has no version")
	}
	return t, nil
}

// JSON serializes the table.
func (t Table) JSON() ([]byte, error) { return json.MarshalIndent(t, "", "  ") }

// Verdict labels.
const (
	VerdictScorer       = "scorer"
	VerdictLikelyScorer = "likely_scorer"
	VerdictUnknown      = "unknown"
	VerdictNotScorer    = "not_scorer"
)

// Evidence is one matched rule.
type Evidence struct {
	Rule     string
	Weight   float64
	Negative bool
}

// Result is a classification.
type Result struct {
	Score        float64
	Verdict      string
	Evidence     []Evidence
	Custom       bool // protocol has no native Quotient check: label by burst, port, account only
	TableVersion string
}

// Classifier scores Features against a Table.
type Classifier struct {
	table Table
	re    map[string]*regexp.Regexp
}

// NewClassifier validates and compiles a table.
func NewClassifier(t Table) (*Classifier, error) {
	c := &Classifier{table: t, re: map[string]*regexp.Regexp{}}
	for _, r := range t.Rules {
		if r.Weight < 0 || r.Weight > 1 {
			return nil, fmt.Errorf("rule %s: weight %v out of range", r.ID, r.Weight)
		}
		if r.Kind == MatchRegex {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
			c.re[r.ID] = re
		}
	}
	return c, nil
}

// Table returns the table in use.
func (c *Classifier) Table() Table { return c.table }

// customProtos have no native Quotient type (MW runs scripts or a fork).
var customProtos = map[string]bool{"mssql": true, "splunk": true, "rdp-auth": true}

func parseNum(s string) (float64, bool) {
	if u, err := strconv.ParseUint(strings.TrimSpace(s), 0, 64); err == nil {
		return float64(u), true
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f, err == nil
}

func (c *Classifier) match(r Rule, f Features) bool {
	switch r.Kind {
	case MatchEq:
		v, ok := f.Attr[r.Key]
		if !ok {
			return false
		}
		for _, w := range r.Values {
			if strings.EqualFold(v, w) {
				return true
			}
		}
	case MatchRegex:
		v, ok := f.Attr[r.Key]
		return ok && c.re[r.ID].MatchString(v)
	case MatchRange:
		v, ok := f.Attr[r.Key]
		if !ok {
			return false
		}
		n, ok := parseNum(v)
		return ok && n >= r.Min && n <= r.Max
	case MatchSubseq:
		l, ok := f.List[r.Key]
		if !ok {
			return false
		}
		i := 0
		for _, x := range l {
			if i < len(r.Values) && strings.EqualFold(x, r.Values[i]) {
				i++
			}
		}
		return i == len(r.Values)
	case MatchSeqExact:
		l, ok := f.List[r.Key]
		if !ok || len(l) != len(r.Values) {
			return false
		}
		for i := range l {
			if !strings.EqualFold(l[i], r.Values[i]) {
				return false
			}
		}
		return true
	case MatchExactSet:
		l, ok := f.List[r.Key]
		if !ok {
			return false
		}
		a, b := lowerSet(l), lowerSet(r.Values)
		return len(a) == len(b) && subset(a, b)
	case MatchContains:
		l, ok := f.List[r.Key]
		if !ok {
			return false
		}
		have := lowerSet(l)
		for _, w := range r.Values {
			if have[strings.ToLower(w)] {
				return true
			}
		}
	case MatchEmptyList:
		l, ok := f.List[r.Key]
		return ok && len(l) == 0
	}
	return false
}

func lowerSet(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[strings.ToLower(x)] = true
	}
	return m
}

func subset(a, b map[string]bool) bool {
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// Classify scores one connection/transaction. Score = noisy-or of matched
// positive rules and generic hints, times (1-w) for each matched contradiction.
func (c *Classifier) Classify(f Features) Result {
	res := Result{TableVersion: c.table.Version, Custom: customProtos[f.Proto]}
	g := c.table.Generic
	pos := 1.0
	add := func(id string, w float64) {
		if w > 0 {
			pos *= 1 - w
			res.Evidence = append(res.Evidence, Evidence{Rule: id, Weight: w})
		}
	}
	behavioural := 0.0
	if f.InBurst {
		add("generic.burst", g.Burst)
		behavioural = math.Max(behavioural, g.Burst)
	}
	if f.OneShot {
		add("generic.one_shot", g.OneShot)
	}
	if f.LearnedCred {
		add("generic.learned_cred", g.LearnedCred)
	}
	neg := 1.0
	for _, r := range c.table.Rules {
		if r.Proto != f.Proto || !c.match(r, f) {
			continue
		}
		if r.Negative {
			neg *= 1 - r.Weight
			res.Evidence = append(res.Evidence, Evidence{Rule: r.ID, Weight: r.Weight, Negative: true})
			continue
		}
		add(r.ID, r.Weight)
		behavioural = math.Max(behavioural, r.Weight)
	}
	// Source address is advisory: it counts only on top of some behaviour.
	if f.AdvisoryRunner && behavioural > 0 {
		add("generic.advisory_runner", g.AdvisoryRunner)
	}
	score := (1 - pos) * neg
	if res.Custom {
		// Script-defined: burst, port and account are all there is.
		score = math.Min(score, 0.7)
	}
	res.Score = score
	switch {
	case neg <= 0.35 && score < 0.3:
		res.Verdict = VerdictNotScorer
	case score >= 0.8:
		res.Verdict = VerdictScorer
	case score >= 0.5:
		res.Verdict = VerdictLikelyScorer
	default:
		res.Verdict = VerdictUnknown
	}
	return res
}

// HasEvidence reports whether the named rule matched.
func (r Result) HasEvidence(id string) bool {
	return slices.ContainsFunc(r.Evidence, func(e Evidence) bool { return e.Rule == id })
}
