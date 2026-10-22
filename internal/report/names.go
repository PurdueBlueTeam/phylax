package report

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/chains"
)

// Kind is the kind of document submitted.
type Kind string

const (
	KindIR     Kind = "incident"
	KindInject Kind = "inject"
)

var reFilename = regexp.MustCompile(`^(incident|inject)(\d{2})_team(\d{2})\.pdf$`)

// Filename returns the submission file name: incidentNN_teamTT.pdf or
// injectNN_teamTT.pdf (the Western-region style, safe everywhere: lower case,
// no spaces, no school name). Numbers are 1..99.
func Filename(k Kind, number, team int) (string, error) {
	if k != KindIR && k != KindInject {
		return "", fmt.Errorf("unknown document kind %q", k)
	}
	if number < 1 || number > 99 {
		return "", fmt.Errorf("%s number %d out of range 1..99", k, number)
	}
	if team < 1 || team > 99 {
		return "", fmt.Errorf("team number %d out of range 1..99", team)
	}
	return fmt.Sprintf("%s%02d_team%02d.pdf", k, number, team), nil
}

// ParseFilename is the inverse of Filename.
func ParseFilename(name string) (k Kind, number, team int, err error) {
	m := reFilename.FindStringSubmatch(name)
	if m == nil {
		return "", 0, 0, fmt.Errorf("file name %q does not match incidentNN_teamTT.pdf or injectNN_teamTT.pdf", name)
	}
	number, _ = strconv.Atoi(m[2])
	team, _ = strconv.Atoi(m[3])
	if number == 0 || team == 0 {
		return "", 0, 0, fmt.Errorf("file name %q has a zero number", name)
	}
	return Kind(m[1]), number, team, nil
}

// Central formats t in US Central time with UTC alongside:
// "2027-03-06 09:00:05 CST (15:00:05 UTC)". A zero time is "".
func Central(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(chains.Central()).Format("2006-01-02 15:04:05 MST") + " (" + t.UTC().Format("15:04:05") + " UTC)"
}

// CentralShort is the minute-resolution form used in header lines.
func CentralShort(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(chains.Central()).Format("2006-01-02 15:04 MST") + " (US Central)"
}

// Placeholder marks something the operator must fill. It is deliberately
// loud and machine-findable; the validator refuses to pass a PDF with one.
func Placeholder(what string) string { return "[[FILL: " + what + "]]" }

// Placeholders finds every [[FILL: ...]] marker in text.
func Placeholders(text string) []string {
	var out []string
	for _, m := range rePlaceholder.FindAllStringSubmatch(text, -1) {
		out = append(out, strings.TrimSpace(m[1]))
	}
	return out
}

var rePlaceholder = regexp.MustCompile(`\[\[FILL:\s*([^\]]*)\]\]`)
