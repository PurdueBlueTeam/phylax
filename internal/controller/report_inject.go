package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/report"
	"github.com/PurdueBlueTeam/phylax/internal/store"
	"github.com/PurdueBlueTeam/phylax/internal/ui"
)

var injectTitles = map[report.InjectKind]string{
	report.InjectMemo:       "Business memo",
	report.InjectConfigMemo: "Configuration memo (per-host summary and evidence)",
	report.InjectPolicy:     "Policy document",
	report.InjectExtension:  "Extension request",
}

// InjectKinds lists the inject templates.
func (o *WebOps) InjectKinds(ctx context.Context) ([]ui.InjectKindInfo, error) {
	var out []ui.InjectKindInfo
	for _, k := range report.InjectKinds() {
		out = append(out, ui.InjectKindInfo{Kind: string(k), Title: injectTitles[k]})
	}
	return out, nil
}

func validInjectKind(k string) (report.InjectKind, bool) {
	for _, x := range report.InjectKinds() {
		if string(x) == k {
			return x, true
		}
	}
	return "", false
}

// NewInject starts an inject response from a template. number 0 takes the
// next free inject number.
func (o *WebOps) NewInject(ctx context.Context, kind string, number int, code, title, by string) (int64, error) {
	team, err := o.team()
	if err != nil {
		return 0, err
	}
	k, ok := validInjectKind(kind)
	if !ok {
		return 0, fmt.Errorf("%w: unknown inject template", ui.ErrInvalid)
	}
	o.dmu.Lock()
	defer o.dmu.Unlock()
	if number == 0 {
		if number, err = o.nextNumber(ctx, draftInject); err != nil {
			return 0, err
		}
	}
	if number < 1 || number > 99 {
		return 0, fmt.Errorf("%w: inject number must be 1 to 99", ui.ErrInvalid)
	}
	sp := &draftSpec{Created: o.c.now(), Kind: string(k), Code: clip(oneLine(code), 64), Fields: map[string]string{}}
	raw, err := marshalSpec(sp)
	if err != nil {
		return 0, err
	}
	return o.c.st.InsertDraft(ctx, store.Draft{Kind: draftInject, Number: number, Team: team, Title: clip(oneLine(title), 200), Spec: raw, CreatedBy: by, Created: sp.Created})
}

func injectData(d store.Draft, sp *draftSpec) (report.InjectData, error) {
	id := report.InjectData{Kind: report.InjectKind(sp.Kind), Num: d.Number, Team: d.Team, Code: sp.Code, Title: d.Title, Now: sp.Created,
		Fields: sp.Fields, Evidence: evidenceOf(sp)}
	for _, l := range lines(sp.Deliverables) {
		c := cols(l, 2)
		id.Deliverables = append(id.Deliverables, report.Deliverable{Heading: c[0], Body: c[1]})
	}
	for _, l := range lines(sp.Hosts) {
		c := cols(l, 7)
		if c[6] != "" {
			switch strings.ToLower(c[6]) {
			case "linux", "windows", "network":
			default:
				return id, fmt.Errorf("%w: host line %q: platform must be linux, windows or network", ui.ErrInvalid, clip(l, 40))
			}
		}
		id.Hosts = append(id.Hosts, report.HostRow{Host: c[0], Role: c[1], OS: c[2], Change: c[3], Method: c[4], Verified: c[5], Platform: strings.ToLower(c[6])})
	}
	for _, l := range lines(sp.Statements) {
		c := cols(l, 2)
		id.Statements = append(id.Statements, report.Statement{Text: c[0], Control: c[1]})
	}
	for _, l := range lines(sp.Done) {
		c := cols(l, 3)
		id.Done = append(id.Done, report.DoneRow{Item: c[0], Evidence: c[1], Figure: c[2]})
	}
	for _, l := range lines(sp.Remaining) {
		c := cols(l, 5)
		id.Remaining = append(id.Remaining, report.RemainRow{Task: c[0], Why: c[1], Resources: c[2], Have: c[3], Estimate: c[4]})
	}
	return id, nil
}

// renderInject renders the template with the fills applied, then validates.
func (o *WebOps) renderInject(d store.Draft, sp *draftSpec) (*renderedDoc, error) {
	data, err := injectData(d, sp)
	if err != nil {
		return nil, err
	}
	doc, err := report.RenderInject(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ui.ErrConflict, err)
	}
	r := &renderedDoc{Filename: doc.Filename, Phs: doc.Placeholders, Figures: doc.Figures}
	r.Title = fmt.Sprintf("Inject %d - %s - %s", d.Number, sp.Code, d.Title)
	r.Markdown = applyFills(doc.Markdown, sp.Fills)
	o.finishRender(r, d, sp, report.KindInject)
	return r, nil
}

func (o *WebOps) injectView(ctx context.Context, d store.Draft, sp *draftSpec) (ui.DraftView, error) {
	r, err := o.renderInject(d, sp)
	if err != nil {
		return ui.DraftView{}, err
	}
	kind := report.InjectKind(sp.Kind)
	v := ui.DraftView{ID: d.ID, Kind: draftInject, Number: d.Number, Team: d.Team, Filename: r.Filename, Title: d.Title, Updated: d.Updated,
		Source: "Template: " + injectTitles[kind] + ".", Markdown: r.Markdown, Validation: valView(r)}
	v.Fills, v.OpenFills = fillViews(r.Phs, sp.Fills)
	v.Evidence = evidenceViews(sp, func(i int) string {
		if i < len(r.Figures) {
			return r.Figures[i].Hash
		}
		return ""
	})
	v.Fields = []ui.FieldView{
		{Name: "number", Label: "Inject number", Value: strconv.Itoa(d.Number), Hint: "1 to 99; the first text in the PDF and the file name"},
		{Name: "code", Label: "Inject code", Value: sp.Code, Hint: "as the prompt writes it"},
		{Name: "title", Label: "Inject title", Value: d.Title, Hint: "exactly as the prompt writes it"},
	}
	tf, err := injectFields(kind)
	if err != nil {
		return v, err
	}
	for _, f := range tf {
		v.Fields = append(v.Fields, ui.FieldView{Name: "tpl_" + f[0], Label: f[0], Value: sp.Fields[f[0]], Hint: f[1], Multiline: true})
	}
	list := func(name, label, val, hint string) {
		v.Fields = append(v.Fields, ui.FieldView{Name: name, Label: label, Value: val, Hint: hint, Multiline: true})
	}
	switch kind {
	case report.InjectMemo:
		list("deliverables", "Deliverables", sp.Deliverables, "one per line: heading as the prompt words it | plain-English answer")
	case report.InjectConfigMemo:
		list("hosts", "Hosts and devices", sp.Hosts, "one per line: host | role | OS | change | method | verified how | linux, windows or network")
	case report.InjectPolicy:
		list("statements", "Policy statements", sp.Statements, "one per line: statement | control reference")
	case report.InjectExtension:
		list("done", "Finished", sp.Done, "one per line: item | evidence | figure")
		list("remaining", "Not finished", sp.Remaining, "one per line: task | why | resources needed | what we have | estimate")
	}
	v.Help = []string{"The team number is used only for the file name; the validator fails the PDF if it appears in the text. Add a log excerpt per host below: the config memo ties figures to hosts by the host name."}
	v.Hosts = o.hostNames(ctx)
	return v, nil
}

func (o *WebOps) saveInject(d *store.Draft, sp *draftSpec, e ui.DraftEdit) error {
	if v, ok := e.Fields["number"]; ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n < 1 || n > 99 {
			return fmt.Errorf("%w: number must be 1 to 99", ui.ErrInvalid)
		}
		d.Number = n
	}
	if v, ok := e.Fields["code"]; ok {
		sp.Code = clip(oneLine(v), 64)
	}
	if v, ok := e.Fields["title"]; ok {
		d.Title = clip(oneLine(v), 200)
	}
	if sp.Fields == nil {
		sp.Fields = map[string]string{}
	}
	tf, err := injectFields(report.InjectKind(sp.Kind))
	if err != nil {
		return err
	}
	for _, f := range tf {
		if v, ok := e.Fields["tpl_"+f[0]]; ok {
			if v = strings.TrimSpace(v); v == "" {
				delete(sp.Fields, f[0])
			} else {
				sp.Fields[f[0]] = v
			}
		}
	}
	for name, dst := range map[string]*string{"deliverables": &sp.Deliverables, "hosts": &sp.Hosts, "statements": &sp.Statements,
		"done": &sp.Done, "remaining": &sp.Remaining} {
		if v, ok := e.Fields[name]; ok {
			*dst = strings.TrimSpace(v)
		}
	}
	return nil
}
