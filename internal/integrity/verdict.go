package integrity

// Verdict is the ledger's judgement of a file. The names follow the design.
// Mapping to the shorthand used elsewhere: known-good = Match (and
// MatchOtherVersion), known-bad = KnownBad, modified = Mismatch,
// unsigned = SigInvalid.
type Verdict string

const (
	Match             Verdict = "match"               // hash equals a trusted entry for this path
	MatchOtherVersion Verdict = "match_other_version" // known-good for a different package version (patch drift; informational)
	Unknown           Verdict = "unknown"             // path/hash in no trusted source
	Mismatch          Verdict = "mismatch"            // path known, hash equals no known version
	KnownBad          Verdict = "known_bad"           // hash is on the known-bad list
	SigInvalid        Verdict = "sig_invalid"         // Authenticode/catalog failed or signer not allowed
)

// Alerting reports whether the verdict should raise an event by default.
func (v Verdict) Alerting() bool {
	switch v {
	case Unknown, Mismatch, KnownBad, SigInvalid:
		return true
	}
	return false
}

// rank orders verdicts by severity for "worst of" combinations.
func (v Verdict) rank() int {
	switch v {
	case KnownBad:
		return 5
	case Mismatch:
		return 4
	case SigInvalid:
		return 3
	case Unknown:
		return 2
	case MatchOtherVersion:
		return 1
	}
	return 0
}

// Worse returns the more severe of two verdicts.
func Worse(a, b Verdict) Verdict {
	if b.rank() > a.rank() {
		return b
	}
	return a
}

// Result is a verdict with its evidence.
type Result struct {
	Path     string
	SHA256   Sum
	Size     int64
	Verdict  Verdict
	Matched  *Entry  // entry that proved the file (Match/MatchOtherVersion)
	Expected []Entry // what the ledger expected at this path
	// HashKnownAt lists other trusted paths where this hash is a known-good
	// (for example /usr/bin/nologin replaced by a copy of /bin/bash).
	HashKnownAt []string
	BadLabel    string
	HintOnly    bool   // only a host-DB hint matched; hints never prove
	Signer      string // from signature verification, if run
	Note        string
}

// Judger is anything that can judge a file by path and hash; *Ledger does so
// locally, and the agent may supply a controller-backed implementation.
// claimedVersion is the package version the host claims (from its package DB),
// or "".
type Judger interface {
	Judge(path string, sum Sum, claimedVersion string) Result
}

// Judge implements Judger.
func (l *Ledger) Judge(path string, sum Sum, claimedVersion string) Result {
	np := NormalizePath(path)
	r := Result{Path: np, SHA256: sum}
	if lbl, ok := l.bad[sum]; ok {
		r.Verdict, r.BadLabel = KnownBad, lbl
		return r
	}
	atPath := l.ByPath(np)
	var trusted []Entry
	for _, e := range atPath {
		if e.Source.Trusted() {
			trusted = append(trusted, e)
		}
	}
	r.Expected = atPath
	var hintHit bool
	for _, e := range atPath {
		if e.SHA256 == sum && !e.Source.Trusted() {
			hintHit = true
		}
	}
	for i := range trusted {
		e := trusted[i]
		if e.SHA256 != sum {
			continue
		}
		r.Matched = &trusted[i]
		r.Size = e.Size
		r.Signer = e.Signer
		if claimedVersion == "" || e.Version == "" || e.Version == claimedVersion {
			r.Verdict = Match
			return r
		}
		// Keep looking for an exact version match among other entries.
		for j := range trusted {
			if trusted[j].SHA256 == sum && trusted[j].Version == claimedVersion {
				r.Matched = &trusted[j]
				r.Verdict = Match
				return r
			}
		}
		r.Verdict = MatchOtherVersion
		return r
	}
	for _, e := range l.ByHash(sum) {
		if e.Source.Trusted() && e.Path != np {
			r.HashKnownAt = append(r.HashKnownAt, e.Path)
		}
	}
	switch {
	case len(trusted) > 0:
		r.Verdict = Mismatch
	default:
		r.Verdict = Unknown
		r.HintOnly = hintHit
		if hintHit {
			r.Note = "only the host package database vouches for this hash (hint, not proof)"
		}
	}
	return r
}
