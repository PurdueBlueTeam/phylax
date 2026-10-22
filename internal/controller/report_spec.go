package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/chains"
	"github.com/PurdueBlueTeam/phylax/internal/report"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
)

// Kinds stored in report_drafts.kind.
const (
	draftIR     = string(report.KindIR)
	draftInject = string(report.KindInject)
)

// evSpec is one figure attached to a draft. Screenshots live under
// <data_dir>/reports/<draft id>/<File>; log excerpts carry their text.
type evSpec struct {
	Kind      string    `json:"kind"`
	File      string    `json:"file,omitempty"`
	SHA256    string    `json:"sha256,omitempty"` // of the file at upload time
	Host      string    `json:"host,omitempty"`
	Caption   string    `json:"caption,omitempty"`
	Taken     time.Time `json:"taken,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Annotated bool      `json:"annotated,omitempty"`
	Excerpt   string    `json:"excerpt,omitempty"`
}

type fileSpec struct {
	Host, Path, SHA256 string
}

// draftSpec is the JSON kept in report_drafts.spec. Operator text is kept raw
// (the textareas) and parsed on every render, so what the operator typed is
// what the next form shows.
type draftSpec struct {
	Created  time.Time         `json:"created"`
	Fills    map[string]string `json:"fills,omitempty"`
	Evidence []evSpec          `json:"evidence,omitempty"`

	// Incident report.
	Chains          []int64    `json:"chains,omitempty"`
	Campaign        int64      `json:"campaign,omitempty"`
	AlertID         int64      `json:"alert,omitempty"`
	To              string     `json:"to,omitempty"`
	DetectTime      string     `json:"detect_time,omitempty"`
	DetectMethod    string     `json:"detect_method,omitempty"`
	Downtime        string     `json:"downtime,omitempty"`
	RemediationTime string     `json:"remediation_time,omitempty"`
	Data            string     `json:"data,omitempty"`
	ServiceCheck    string     `json:"service_check,omitempty"`
	Containment     string     `json:"containment,omitempty"`
	Verification    string     `json:"verification,omitempty"`
	Prevention      string     `json:"prevention,omitempty"`
	TraceTime       time.Time  `json:"trace_time,omitempty"`
	TraceFiles      []fileSpec `json:"trace_files,omitempty"`

	// Inject.
	Kind         string            `json:"kind,omitempty"`
	Code         string            `json:"code,omitempty"`
	Fields       map[string]string `json:"fields,omitempty"`
	Deliverables string            `json:"deliverables,omitempty"`
	Hosts        string            `json:"hosts,omitempty"`
	Statements   string            `json:"statements,omitempty"`
	Done         string            `json:"done,omitempty"`
	Remaining    string            `json:"remaining,omitempty"`
}

var validTags = map[string]bool{report.TagRedActivity: true, report.TagVuln: true, report.TagDetection: true,
	report.TagEradication: true, report.TagRemediation: true, report.TagVerification: true, report.TagFirewall: true}

func cleanTags(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range in {
		if validTags[t] && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// draftDir is where a draft's uploaded files live.
func (o *WebOps) draftDir(id int64) string {
	return filepath.Join(o.c.cfg.DataDir, "reports", strconv.FormatInt(id, 10))
}

func (o *WebOps) loadDraft(ctx context.Context, id int64) (store.Draft, *draftSpec, error) {
	d, err := o.c.st.Draft(ctx, id)
	if errors.Is(err, store.ErrNoDraft) {
		return d, nil, ui.ErrNotFound
	}
	if err != nil {
		return d, nil, err
	}
	var sp draftSpec
	if err := json.Unmarshal(d.Spec, &sp); err != nil {
		return d, nil, fmt.Errorf("draft %d: unreadable spec: %w", id, err)
	}
	return d, &sp, nil
}

func (o *WebOps) saveDraft(ctx context.Context, d store.Draft, sp *draftSpec) error {
	raw, err := json.Marshal(sp)
	if err != nil {
		return err
	}
	d.Spec, d.Updated = raw, o.c.now()
	return o.c.st.UpdateDraft(ctx, d)
}

func (o *WebOps) team() (int, error) {
	if t := o.c.cfg.Team; t >= 1 && t <= 99 {
		return t, nil
	}
	return 0, fmt.Errorf("%w: the team number is not configured (config key \"team\")", ui.ErrConflict)
}

// nextNumber is the number a new draft of a kind gets: the configured start
// or one past the highest used, whichever is larger.
func (o *WebOps) nextNumber(ctx context.Context, kind string) (int, error) {
	start := o.c.cfg.NextIncident
	if kind == draftInject {
		start = o.c.cfg.NextInject
	}
	hi, err := o.c.st.MaxDraftNumber(ctx, kind)
	if err != nil {
		return 0, err
	}
	n := max(start, hi+1, 1)
	if n > 99 {
		return 0, fmt.Errorf("%w: %s number %d is past 99", ui.ErrConflict, kind, n)
	}
	return n, nil
}

// ---------------------------------------------------------------- text helpers

var timeLayouts = []string{"2006-01-02 15:04", "2006-01-02 15:04:05", "2006-01-02T15:04", time.RFC3339}

// parseCentral reads a time the operator typed. Without an offset it is US
// Central (the zone the competition runs on).
func parseCentral(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	for _, l := range timeLayouts {
		if t, err := time.ParseInLocation(l, s, chains.Central()); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: time %q: write it as YYYY-MM-DD HH:MM in US Central", ui.ErrInvalid, clip(s, 40))
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func centralText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.In(chains.Central()).Format("2006-01-02 15:04")
}

// lines splits a textarea into trimmed non-empty lines.
func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// cols splits a "a | b | c" line into n trimmed columns (missing ones empty).
func cols(l string, n int) []string {
	parts := strings.Split(l, "|")
	out := make([]string, n)
	for i := range out {
		if i < len(parts) {
			out[i] = strings.TrimSpace(parts[i])
		}
	}
	if len(parts) > n { // the last column keeps any extra bars
		out[n-1] = strings.TrimSpace(strings.Join(parts[n-1:], "|"))
	}
	return out
}

// oneLine makes an operator's fill safe to put in a placeholder's place: one
// line, and no marker that would read as another placeholder.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = strings.ReplaceAll(s, "[[", "[")
	return strings.ReplaceAll(s, "]]", "]")
}

// applyFills replaces each [[FILL: what]] marker whose fill is non-empty.
func applyFills(md string, fills map[string]string) string {
	for what, v := range fills {
		if v = oneLine(v); v != "" {
			md = strings.ReplaceAll(md, report.Placeholder(what), v)
		}
	}
	return md
}

// fillViews lists each distinct placeholder of the original draft with the
// operator's current text.
func fillViews(phs []report.PlaceholderRef, fills map[string]string) (out []ui.FillView, open int) {
	seen := map[string]bool{}
	for _, p := range phs {
		if seen[p.What] {
			continue
		}
		seen[p.What] = true
		v := oneLine(fills[p.What])
		fv := ui.FillView{Section: p.Section, What: p.What, Value: fills[p.What], Open: v == ""}
		if fv.Open {
			open++
		}
		out = append(out, fv)
	}
	return out, open
}

var reTplField = regexp.MustCompile(`\{\{f "([a-z_]+)" "([^"]*)"\}\}`)

// injectFields lists the {{f "key" "hint"}} inputs of a template in order.
func injectFields(kind report.InjectKind) ([][2]string, error) {
	raw, err := report.BlankTemplate(kind)
	if err != nil {
		return nil, err
	}
	var out [][2]string
	seen := map[string]bool{}
	for _, m := range reTplField.FindAllStringSubmatch(raw, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, [2]string{m[1], m[2]})
		}
	}
	return out, nil
}
