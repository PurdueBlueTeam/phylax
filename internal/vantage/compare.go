package vantage

import "github.com/PurdueBlueTeam/phylax/internal/checks"

// Verdict is the V1 comparison of the external probe with the in-LAN probe of
// the same check.
type Verdict string

// Comparison outcomes.
const (
	VerdictAgree        Verdict = "agree"          // both green
	VerdictServiceDown  Verdict = "service_down"   // both red: the service, not the path
	VerdictPathBroken   Verdict = "path_broken"    // external red, LAN green: Palo / NAT / VyOS path
	VerdictInternalOnly Verdict = "internal_only"  // external green, LAN red: the LAN-side probe's path or source
	VerdictContent      Verdict = "scorer_content" // transport fine from both, but the external (scorer-faithful) content check fails
)

// Compare classifies a pair of results for the same check (V1). A red external
// probe with a green in-LAN probe localizes the fault to the public path.
func Compare(external, lan checks.Result) Verdict {
	switch {
	case external.OK && lan.OK:
		return VerdictAgree
	case !external.OK && !lan.OK:
		return VerdictServiceDown
	case !external.OK && lan.OK:
		if external.Class == checks.ClassContent {
			return VerdictContent
		}
		return VerdictPathBroken
	default:
		return VerdictInternalOnly
	}
}
