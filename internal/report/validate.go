package report

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Severity of a validation finding.
type Severity string

const (
	SevFail Severity = "fail"
	SevWarn Severity = "warn"
	SevPass Severity = "pass"
)

// Check is one pre-submit finding.
type Check struct {
	ID       string
	Name     string
	Severity Severity
	Detail   string
}

// Validation is the pre-submit checklist result.
type Validation struct {
	Checks []Check
	Pages  int
	Words  int
}

// OK is true when nothing failed (warnings do not block).
func (v Validation) OK() bool {
	for _, c := range v.Checks {
		if c.Severity == SevFail {
			return false
		}
	}
	return true
}

// Failures returns the failed checks.
func (v Validation) Failures() []Check {
	var out []Check
	for _, c := range v.Checks {
		if c.Severity == SevFail {
			out = append(out, c)
		}
	}
	return out
}

// Get returns a check by id.
func (v Validation) Get(id string) (Check, bool) {
	for _, c := range v.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return Check{}, false
}

// Markdown renders the checklist.
func (v Validation) Markdown() string {
	var b strings.Builder
	for _, c := range v.Checks {
		box := "[x]"
		if c.Severity != SevPass {
			box = "[ ]"
		}
		fmt.Fprintf(&b, "- %s %s (%s): %s\n", box, c.Name, c.Severity, c.Detail)
	}
	return b.String()
}

// SubmitSpec says what is being submitted.
type SubmitSpec struct {
	Kind        Kind
	Number      int
	Team        int
	Filename    string
	Attachments []string // extra files submitted with the PDF; each must be named in it
	// Forbidden are words that must not appear (the school name, in any
	// spelling the operator lists).
	Forbidden []string
	// MaxPages is the hard limit (default 20 for injects, 12 for IRs);
	// WarnPages the soft limit (8 and 5).
	MaxPages, WarnPages int
	// MinWords is the shortest believable response (default 60).
	MinWords int
}

var (
	reAngle  = regexp.MustCompile(`<[A-Za-z][A-Za-z0-9 /,.'-]{2,40}>`)
	reInject = regexp.MustCompile(`(?i)^\s*inject\s*#?\s*0*(\d+)\b`)
)

func squash(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), ""))
}

// ValidateSubmission runs the pre-submit checklist on the final PDF bytes:
// file name, text-extractable, inject number first, team number only in the
// file name (injects), attachments mentioned, no placeholders, Central time,
// length sanity.
func ValidateSubmission(pdf []byte, spec SubmitSpec) Validation {
	var v Validation
	add := func(id, name string, sev Severity, detail string) {
		v.Checks = append(v.Checks, Check{ID: id, Name: name, Severity: sev, Detail: detail})
	}
	pass := func(id, name, detail string) { add(id, name, SevPass, detail) }

	// 1. File name.
	k, n, t, err := ParseFilename(filepath.Base(spec.Filename))
	switch {
	case err != nil:
		add("filename", "file name is incidentNN_teamTT.pdf / injectNN_teamTT.pdf", SevFail, err.Error())
	case k != spec.Kind || n != spec.Number || t != spec.Team:
		add("filename", "file name matches the document", SevFail, fmt.Sprintf("%s says %s %d team %d; expected %s %d team %d", spec.Filename, k, n, t, spec.Kind, spec.Number, spec.Team))
	default:
		pass("filename", "file name follows the rule", spec.Filename)
	}

	// 2. Text-extractable PDF.
	if !strings.HasPrefix(string(pdf[:min(len(pdf), 5)]), "%PDF-") {
		add("pdf", "file is a PDF", SevFail, "missing %PDF header")
		return v
	}
	pages, err := ExtractText(pdf)
	if err != nil {
		add("extractable", "PDF text is extractable", SevFail, err.Error())
		return v
	}
	v.Pages = len(pages)
	text := strings.Join(pages, "\n")
	v.Words = len(strings.Fields(text))
	empty := 0
	for _, p := range pages {
		if len(strings.Fields(p)) < 3 {
			empty++
		}
	}
	switch {
	case v.Pages == 0 || v.Words == 0:
		add("extractable", "PDF text is extractable (NISE reads text, not images)", SevFail, "no text found: the PDF is image-only or empty")
	case empty > 0:
		add("extractable", "PDF text is extractable (NISE reads text, not images)", SevWarn, fmt.Sprintf("%d of %d page(s) have almost no text; image-only pages are invisible to NISE", empty, v.Pages))
	default:
		pass("extractable", "PDF text is extractable", fmt.Sprintf("%d page(s), %d words", v.Pages, v.Words))
	}

	// 3. Number first.
	lines := nonEmptyLines(text)
	switch spec.Kind {
	case KindInject:
		first := ""
		if len(lines) > 0 {
			first = lines[0]
		}
		if m := reInject.FindStringSubmatch(first); m == nil {
			add("number-first", "inject number comes first", SevFail, fmt.Sprintf("first line is %q; it must start with \"Inject %d\"", clip(first, 60), spec.Number))
		} else if got, _ := strconv.Atoi(m[1]); got != spec.Number {
			add("number-first", "inject number comes first", SevFail, fmt.Sprintf("first line names inject %d, file name says %d", got, spec.Number))
		} else {
			pass("number-first", "inject number comes first", clip(first, 60))
		}
	case KindIR:
		head := text
		if len(head) > 900 {
			head = head[:900]
		}
		if !regexp.MustCompile(fmt.Sprintf(`(?i)incident\s+report\s+0*%d\b`, spec.Number)).MatchString(head) {
			add("number-first", "incident number is in the header", SevFail, fmt.Sprintf("\"Incident Report %d\" not found in the header (all three 2026 qualifier PDFs said Incident Report 1)", spec.Number))
		} else {
			pass("number-first", "incident number is in the header", fmt.Sprintf("Incident Report %d", spec.Number))
		}
	}

	// 4. Team number.
	teamRe := regexp.MustCompile(fmt.Sprintf(`(?i)\bteam\s*#?\s*0*%d\b`, spec.Team))
	switch spec.Kind {
	case KindInject:
		if loc := teamRe.FindString(text); loc != "" {
			add("team-number", "team number only in the file name", SevFail, fmt.Sprintf("body mentions %q", loc))
		} else {
			pass("team-number", "team number only in the file name", "not in the body")
		}
	case KindIR:
		head := text
		if len(head) > 600 {
			head = head[:600]
		}
		if !teamRe.MatchString(head) {
			add("team-number", "From line carries the team number (number only)", SevFail, fmt.Sprintf("\"Team %02d\" not found in the header", spec.Team))
		} else {
			pass("team-number", "From line carries the team number", fmt.Sprintf("Team %02d", spec.Team))
		}
	}
	low := strings.ToLower(text)
	var found []string
	for _, w := range spec.Forbidden {
		if w != "" && strings.Contains(low, strings.ToLower(w)) {
			found = append(found, w)
		}
	}
	if len(found) > 0 {
		add("school-name", "no school name", SevFail, "found: "+strings.Join(found, ", "))
	} else {
		pass("school-name", "no school name", fmt.Sprintf("checked %d word(s)", len(spec.Forbidden)))
	}

	// 5. Attachments mentioned.
	sq := squash(text)
	var unmentioned []string
	for _, a := range spec.Attachments {
		if !strings.Contains(sq, squash(filepath.Base(a))) {
			unmentioned = append(unmentioned, filepath.Base(a))
		}
	}
	switch {
	case len(spec.Attachments) == 0:
		pass("attachments", "every attached file is named in the PDF", "no extra attachments (only the PDF itself is read)")
	case len(unmentioned) > 0:
		add("attachments", "every attached file is named in the PDF", SevFail, "not mentioned: "+strings.Join(unmentioned, ", "))
	default:
		pass("attachments", "every attached file is named in the PDF", fmt.Sprintf("%d file(s) named", len(spec.Attachments)))
	}

	// 6. Placeholders.
	var left []string
	left = append(left, Placeholders(text)...)
	for _, m := range reAngle.FindAllString(text, 3) {
		left = append(left, m)
	}
	if strings.Contains(text, "TODO") {
		left = append(left, "TODO")
	}
	if len(left) > 0 {
		add("placeholders", "no placeholders left", SevFail, fmt.Sprintf("%d left, first: %s", len(left), clip(left[0], 80)))
	} else {
		pass("placeholders", "no placeholders left", "none")
	}

	// 7. Central time.
	switch {
	case strings.Contains(text, "Central"):
		pass("central-time", "times shown as US Central", "labelled")
	default:
		add("central-time", "times shown as US Central", SevWarn, "no \"US Central\" label; NISE runs on Central time, not \"CST\" year-round")
	}

	// 8. Length sanity.
	maxP, warnP := spec.MaxPages, spec.WarnPages
	if maxP == 0 {
		maxP, warnP = 20, 8
		if spec.Kind == KindIR {
			maxP, warnP = 12, 5
		}
	}
	minW := spec.MinWords
	if minW == 0 {
		minW = 60
	}
	switch {
	case v.Words < minW:
		add("length", "length is believable", SevFail, fmt.Sprintf("%d words; under %d looks empty", v.Words, minW))
	case v.Pages > maxP:
		add("length", "length is believable", SevFail, fmt.Sprintf("%d pages; over %d", v.Pages, maxP))
	case v.Pages > warnP:
		add("length", "length is believable", SevWarn, fmt.Sprintf("%d pages; judges read the first pages, keep the answer early and the rest as labelled attachments", v.Pages))
	default:
		pass("length", "length is believable", fmt.Sprintf("%d page(s), %d words", v.Pages, v.Words))
	}
	if len(pdf) > 10<<20 {
		add("size", "file size", SevWarn, fmt.Sprintf("%.1f MiB; NISE limits are unpublished, shrink the screenshots", float64(len(pdf))/(1<<20)))
	}
	return v
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}
