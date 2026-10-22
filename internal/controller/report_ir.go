package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/chains"
	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/report"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/traceback"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
)

// renderedDoc is a draft rendered with the operator's fills applied.
type renderedDoc struct {
	Filename  string
	Title     string
	Markdown  string
	Phs       []report.PlaceholderRef // as the drafter produced them, before fills
	Checklist report.Checklist
	Figures   []report.Figure
	PDF       []byte
	PDFErr    error
	Val       report.Validation
}

// NewIR drafts an incident report for a chain or a whole campaign from the
// stored chains, the alert that seeded them and the trace-back of that alert.
func (o *WebOps) NewIR(ctx context.Context, chainID, campaignID int64, by string) (int64, error) {
	team, err := o.team()
	if err != nil {
		return 0, err
	}
	sp := &draftSpec{Created: o.c.now()}
	var cs []*chains.Chain
	desc := ""
	switch {
	case chainID > 0:
		ch, err := chains.Load(ctx, o.c.st, chainID)
		if errors.Is(err, store.ErrNoChain) {
			return 0, ui.ErrNotFound
		}
		if err != nil {
			return 0, err
		}
		sp.Chains, cs, desc = []int64{ch.ID}, []*chains.Chain{ch}, "chain "+strconv.FormatInt(ch.ID, 10)
	default:
		camps, _, err := o.loadChains(ctx)
		if err != nil {
			return 0, err
		}
		for _, cp := range camps {
			if cp.ID == campaignID {
				cs, sp.Campaign, desc = cp.Chains, cp.ID, "campaign "+strconv.FormatInt(cp.ID, 10)+" "+cp.Name
			}
		}
		if len(cs) == 0 {
			return 0, ui.ErrNotFound
		}
	}
	o.seedFromAlert(ctx, sp, cs)

	o.dmu.Lock()
	defer o.dmu.Unlock()
	n, err := o.nextNumber(ctx, draftIR)
	if err != nil {
		return 0, err
	}
	raw, err := marshalSpec(sp)
	if err != nil {
		return 0, err
	}
	id, err := o.c.st.InsertDraft(ctx, store.Draft{Kind: draftIR, Number: n, Team: team, Title: desc, Spec: raw, CreatedBy: by, Created: sp.Created})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// seedFromAlert fills the detection facts and the collected-file evidence
// from the earliest alert that points at one of the chains. It is best effort:
// without an alert the operator fills the detection placeholders.
func (o *WebOps) seedFromAlert(ctx context.Context, sp *draftSpec, cs []*chains.Chain) {
	want := map[int64]bool{}
	for _, c := range cs {
		want[c.ID] = true
	}
	rows, err := o.c.st.Alerts(ctx, "", 5000)
	if err != nil {
		return
	}
	var pick *store.AlertRow
	for i := range rows {
		k := parseKeys(rows[i].Keys)
		if want[k.ChainID] && (pick == nil || rows[i].Time.Before(pick.Time)) {
			pick = &rows[i]
		}
	}
	if pick == nil {
		return
	}
	k := parseKeys(pick.Keys)
	sp.AlertID = pick.ID
	title := k.Title
	if title == "" {
		title = pick.Rule
	}
	sp.DetectTime = centralText(pick.Time)
	sp.DetectMethod = fmt.Sprintf("Phylax detection rule %s (%s), alert #%d on %s", pick.Rule, title, pick.ID, pick.Host)

	refs := k.Evidence
	if len(refs) == 0 && pick.Agent != "" && pick.Seq != 0 {
		refs = []evRef{{pick.Agent, pick.Seq}}
	}
	var evs []event.Event
	for _, r := range refs {
		if ev, err := o.c.st.Event(ctx, r.Agent, r.Seq); err == nil {
			evs = append(evs, ev)
		}
	}
	if len(evs) == 0 {
		return
	}
	da := detect.Alert{RuleID: pick.Rule, Title: k.Title, Severity: sevName(pick.Severity), Agent: pick.Agent, Time: pick.Time,
		Message: k.Message, Evidence: evs, Entities: k.Entities}
	tr := traceback.Tracer{Src: o.c.st, Cfg: traceback.Config{Offset: o.chainCfg.Offset}}
	res, err := tr.Trace(ctx, traceback.FromAlert(da))
	if err != nil || res == nil {
		return
	}
	sp.TraceTime = res.Trigger.Time
	for _, f := range res.Files {
		sp.TraceFiles = append(sp.TraceFiles, fileSpec{Host: f.Host, Path: f.Path, SHA256: f.SHA256})
	}
}

func evidenceOf(sp *draftSpec) []report.Evidence {
	out := make([]report.Evidence, 0, len(sp.Evidence))
	for _, e := range sp.Evidence {
		out = append(out, report.Evidence{Kind: report.EvidenceKind(e.Kind), Path: e.File, Host: e.Host, Caption: e.Caption,
			Taken: e.Taken, Excerpt: e.Excerpt, Tags: e.Tags, Annotated: e.Annotated})
	}
	return out
}

// irInput turns the stored draft into the drafter's input.
func (o *WebOps) irInput(ctx context.Context, d store.Draft, sp *draftSpec) (report.IRInput, error) {
	in := report.IRInput{Team: d.Team, Number: d.Number, Title: sp.Title(), To: strings.TrimSpace(sp.To), Now: sp.Created,
		Data: strings.TrimSpace(sp.Data), ServiceCheck: strings.TrimSpace(sp.ServiceCheck), Evidence: evidenceOf(sp), BaseDir: o.draftDir(d.ID)}
	for _, id := range sp.Chains {
		ch, err := chains.Load(ctx, o.c.st, id)
		if errors.Is(err, store.ErrNoChain) {
			return in, fmt.Errorf("%w: chain %d was deleted", ui.ErrConflict, id)
		}
		if err != nil {
			return in, err
		}
		in.Chains = append(in.Chains, ch)
	}
	if sp.Campaign > 0 {
		camps, _, err := o.loadChains(ctx)
		if err != nil {
			return in, err
		}
		for _, cp := range camps {
			if cp.ID == sp.Campaign {
				in.Campaign = cp
			}
		}
		if in.Campaign == nil {
			return in, fmt.Errorf("%w: campaign %d no longer exists", ui.ErrConflict, sp.Campaign)
		}
	}
	dt, err := parseCentral(sp.DetectTime)
	if err != nil {
		return in, err
	}
	if m := strings.TrimSpace(sp.DetectMethod); !dt.IsZero() && m != "" {
		in.Detection = &report.Detection{Time: dt, Method: m}
	}
	if in.Downtime, err = parseDowntime(sp.Downtime); err != nil {
		return in, err
	}
	if in.RemediationTime, err = parseCentral(sp.RemediationTime); err != nil {
		return in, err
	}
	for _, l := range lines(sp.Containment) {
		c := cols(l, 2)
		t, err := parseCentral(c[0])
		if err != nil {
			return in, fmt.Errorf("containment line %q: %w", clip(l, 40), err)
		}
		in.Containment = append(in.Containment, report.Step{Time: t, Text: c[1]})
	}
	for _, l := range lines(sp.Verification) {
		c := cols(l, 4)
		t, err := parseCentral(c[0])
		if err != nil {
			return in, fmt.Errorf("verification line %q: %w", clip(l, 40), err)
		}
		fig, _ := strconv.Atoi(strings.TrimPrefix(strings.ToLower(c[3]), "figure "))
		in.Verification = append(in.Verification, report.Step{Time: t, Text: c[1], Result: c[2], Figure: fig})
	}
	in.Prevention = lines(sp.Prevention)
	if len(sp.TraceFiles) > 0 {
		tr := &traceback.Result{Trigger: traceback.Trigger{Time: sp.TraceTime}}
		for _, f := range sp.TraceFiles {
			tr.Files = append(tr.Files, traceback.FileEvidence{Host: f.Host, Path: f.Path, SHA256: f.SHA256})
		}
		in.Trace = tr
	}
	return in, nil
}

// Title is the operator's title field (stored in Fields["title"] for both kinds).
func (sp *draftSpec) Title() string { return strings.TrimSpace(sp.Fields["title"]) }

func parseDowntime(s string) (*report.Downtime, error) {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "":
		return nil, nil
	case "none":
		return &report.Downtime{None: true}, nil
	}
	c := cols(s, 3)
	st, err := parseCentral(c[0])
	if err != nil {
		return nil, fmt.Errorf("downtime start: %w", err)
	}
	en, err := parseCentral(c[1])
	if err != nil {
		return nil, fmt.Errorf("downtime end: %w", err)
	}
	if st.IsZero() || en.IsZero() || en.Before(st) {
		return nil, fmt.Errorf("%w: downtime is \"none\" or \"start | end | services\" with end after start", ui.ErrInvalid)
	}
	return &report.Downtime{Start: st, End: en, Services: c[2]}, nil
}

// renderIR drafts, applies the fills, renders the PDF and validates it.
func (o *WebOps) renderIR(ctx context.Context, d store.Draft, sp *draftSpec) (*renderedDoc, error) {
	in, err := o.irInput(ctx, d, sp)
	if err != nil {
		return nil, err
	}
	dr, err := report.DraftIR(in)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ui.ErrConflict, err)
	}
	r := &renderedDoc{Filename: dr.Filename, Phs: dr.Placeholders, Checklist: dr.Checklist, Figures: dr.Figures}
	r.Title = "Incident Report " + strconv.Itoa(d.Number)
	if t := sp.Title(); t != "" {
		r.Title += ": " + t
	}
	r.Markdown = applyFills(dr.Markdown, sp.Fills)
	if len(report.Placeholders(r.Markdown)) == 0 {
		for i := range r.Checklist {
			if r.Checklist[i].ID == "PB-placeholders" {
				r.Checklist[i].Status, r.Checklist[i].Detail = report.Met, "none"
			}
		}
	}
	o.finishRender(r, d, sp, report.KindIR)
	return r, nil
}

// finishRender produces the PDF and runs ValidateSubmission on it. A render
// failure is reported as a failed validation, never a panic or a blank PDF.
func (o *WebOps) finishRender(r *renderedDoc, d store.Draft, sp *draftSpec, kind report.Kind) {
	r.PDF, r.PDFErr = report.MarkdownToPDF(r.Markdown, report.PDFOptions{Title: r.Title, EmbedImages: true, BaseDir: o.draftDir(d.ID)})
	if r.PDFErr == nil {
		r.Val = report.ValidateSubmission(r.PDF, report.SubmitSpec{Kind: kind, Number: d.Number, Team: d.Team,
			Filename: r.Filename, Forbidden: o.c.cfg.ForbiddenWords})
	}
	// A screenshot that changed or vanished since upload must not be submitted.
	for i, e := range sp.Evidence {
		if e.File == "" || i >= len(r.Figures) {
			continue
		}
		f := r.Figures[i]
		switch {
		case f.Missing:
			r.Val.Checks = append(r.Val.Checks, report.Check{ID: "evidence-file", Name: "evidence file present", Severity: report.SevFail,
				Detail: fmt.Sprintf("figure %d: %s is missing", f.N, e.File)})
		case e.SHA256 != "" && f.Hash != e.SHA256:
			r.Val.Checks = append(r.Val.Checks, report.Check{ID: "evidence-file", Name: "evidence file unchanged since upload", Severity: report.SevFail,
				Detail: fmt.Sprintf("figure %d: %s no longer matches its upload hash", f.N, e.File)})
		}
	}
}

func valView(r *renderedDoc) ui.ValidationView {
	if r.PDFErr != nil {
		return ui.ValidationView{Error: "the PDF could not be rendered: " + r.PDFErr.Error()}
	}
	v := ui.ValidationView{OK: r.Val.OK(), Pages: r.Val.Pages, Words: r.Val.Words}
	for _, c := range r.Val.Checks {
		v.Checks = append(v.Checks, ui.ValidationLine{Name: c.Name, Severity: string(c.Severity), Detail: c.Detail})
	}
	return v
}

func evidenceViews(sp *draftSpec, baseHash func(i int) string) []ui.EvidenceView {
	var out []ui.EvidenceView
	for i, e := range sp.Evidence {
		out = append(out, ui.EvidenceView{N: i + 1, Kind: e.Kind, Host: e.Host, Caption: e.Caption, Taken: centralText(e.Taken),
			SHA256: baseHash(i), Path: e.File, Tags: strings.Join(e.Tags, ", "), Annotated: e.Annotated, Excerpt: e.Excerpt != "", IsImage: e.File != ""})
	}
	return out
}

// irView builds the review page.
func (o *WebOps) irView(ctx context.Context, d store.Draft, sp *draftSpec) (ui.DraftView, error) {
	r, err := o.renderIR(ctx, d, sp)
	if err != nil {
		return ui.DraftView{}, err
	}
	v := ui.DraftView{ID: d.ID, Kind: draftIR, Number: d.Number, Team: d.Team, Filename: r.Filename, Title: r.Title, Updated: d.Updated,
		Source: "Source: " + d.Title + ".", Markdown: r.Markdown, Validation: valView(r)}
	v.Fills, v.OpenFills = fillViews(r.Phs, sp.Fills)
	for _, c := range r.Checklist {
		v.Checklist = append(v.Checklist, ui.CheckView{ID: c.ID, Rubric: c.Rubric, Name: c.Name, Status: string(c.Status), Detail: c.Detail,
			Weight: c.Weight, Lines: c.Lines})
	}
	for _, rb := range []string{report.RubricWK, report.RubricStout} {
		if e, t := r.Checklist.Earned(rb); t > 0 {
			v.Scores = append(v.Scores, ui.RubricScore{Rubric: rb, Earned: e, Total: t})
		}
	}
	v.Evidence = evidenceViews(sp, func(i int) string {
		if i < len(r.Figures) {
			return r.Figures[i].Hash
		}
		return ""
	})
	v.Fields = []ui.FieldView{
		{Name: "number", Label: "Incident number", Value: strconv.Itoa(d.Number), Hint: "1 to 99; goes in the file name and the header"},
		{Name: "title", Label: "One-line title", Value: sp.Title(), Hint: "what happened to what; generated when empty"},
		{Name: "to", Label: "To", Value: sp.To, Hint: "default Red Team Lead / White Team"},
		{Name: "detect_time", Label: "Detection time", Value: sp.DetectTime, Hint: "US Central, YYYY-MM-DD HH:MM"},
		{Name: "detect_method", Label: "How it was detected", Value: sp.DetectMethod, Hint: "tool, log source, query or rule", Multiline: true},
		{Name: "downtime", Label: "Service downtime", Value: sp.Downtime, Hint: "none, or: start | end | services", Multiline: false},
		{Name: "remediation_time", Label: "Remediation time", Value: sp.RemediationTime, Hint: "US Central, when the attack path was closed"},
		{Name: "data", Label: "Data statement", Value: sp.Data, Hint: "what data was seen or taken, or no evidence of data access and what you checked", Multiline: true},
		{Name: "service_check", Label: "Scored service after the fix", Value: sp.ServiceCheck, Hint: "status of the affected scored service", Multiline: true},
		{Name: "containment", Label: "Containment steps", Value: sp.Containment, Hint: "one per line: time | what you did", Multiline: true},
		{Name: "verification", Label: "Retests", Value: sp.Verification, Hint: "one per line: time | retest | result | figure number", Multiline: true},
		{Name: "prevention", Label: "Prevention", Value: sp.Prevention, Hint: "one per line", Multiline: true},
	}
	v.Help = []string{"Download stays blocked until every placeholder is filled, the validator passes and no figure file has changed. Operator-only rubric items (screenshot quality, whether red team caused it, the header re-read) are never ticked for you."}
	v.Hosts = o.hostNames(ctx)
	return v, nil
}

func (o *WebOps) hostNames(ctx context.Context) []string {
	ags, err := o.c.st.Agents(ctx)
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range ags {
		out = append(out, a.ID)
	}
	sort.Strings(out)
	return out
}

// saveIR applies the posted form to the spec and validates it by rendering.
func (o *WebOps) saveIR(d *store.Draft, sp *draftSpec, e ui.DraftEdit) error {
	set := func(k string, dst *string) {
		if v, ok := e.Fields[k]; ok {
			*dst = strings.TrimSpace(v)
		}
	}
	if v, ok := e.Fields["number"]; ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 || n > 99 {
			return fmt.Errorf("%w: number must be 1 to 99", ui.ErrInvalid)
		}
		d.Number = n
	}
	if v, ok := e.Fields["title"]; ok {
		if sp.Fields == nil {
			sp.Fields = map[string]string{}
		}
		sp.Fields["title"] = strings.TrimSpace(oneLine(v))
	}
	set("to", &sp.To)
	set("detect_time", &sp.DetectTime)
	set("detect_method", &sp.DetectMethod)
	set("downtime", &sp.Downtime)
	set("remediation_time", &sp.RemediationTime)
	set("data", &sp.Data)
	set("service_check", &sp.ServiceCheck)
	set("containment", &sp.Containment)
	set("verification", &sp.Verification)
	set("prevention", &sp.Prevention)
	return nil
}
