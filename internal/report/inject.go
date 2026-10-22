package report

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/template"
	"time"

	injectkit "github.com/PurdueBlueTeam/phylax/inject-kit"
)

// InjectKind picks a template.
type InjectKind string

const (
	InjectMemo       InjectKind = "memo"
	InjectConfigMemo InjectKind = "config-memo"
	InjectPolicy     InjectKind = "policy"
	InjectExtension  InjectKind = "extension-request"
)

// InjectKinds lists the templates.
func InjectKinds() []InjectKind {
	return []InjectKind{InjectMemo, InjectConfigMemo, InjectPolicy, InjectExtension}
}

// Deliverable is one deliverable of the prompt and its answer.
type Deliverable struct{ Heading, Body string }

// HostRow is one row of the config memo's per-host table. Platform is
// "linux", "windows" or "network" and groups the appendix.
type HostRow struct {
	Host, Role, OS, Change, Method, Verified string
	Platform                                 string
	// Figure overrides the figure column; empty means "the figures whose
	// Host is this host".
	Figure string
}

// Statement is one policy statement with its control reference.
type Statement struct{ Text, Control string }

// DoneRow and RemainRow fill the extension request tables.
type DoneRow struct{ Item, Evidence, Figure string }

// RemainRow is something not finished.
type RemainRow struct{ Task, Why, Resources, Have, Estimate string }

// InjectData is the content of one inject response. Team is used only for the
// file name; it is not available to the templates, so it cannot leak into the
// body (NISE rule: team number only in the file name).
type InjectData struct {
	Kind         InjectKind
	Num          int
	Team         int
	Code         string
	Title        string
	Now          time.Time
	Fields       map[string]string // to, from, summary, verification, ... (see the templates)
	Deliverables []Deliverable
	Hosts        []HostRow
	Statements   []Statement
	Done         []DoneRow
	Remaining    []RemainRow
	Evidence     []Evidence
	Attachments  []string // extra files; each is named in the PDF
	BaseDir      string
}

// InjectDoc is a rendered inject response.
type InjectDoc struct {
	Filename     string
	Markdown     string
	Placeholders []PlaceholderRef
	Figures      []Figure
	baseDir      string
	title        string
}

// PDF renders the response; it refuses placeholders unless allowed.
func (d *InjectDoc) PDF(allowPlaceholders bool) ([]byte, error) {
	if !allowPlaceholders && len(d.Placeholders) > 0 {
		return nil, fmt.Errorf("%w: %d (%s ...)", ErrPlaceholders, len(d.Placeholders), d.Placeholders[0].What)
	}
	return MarkdownToPDF(d.Markdown, PDFOptions{Title: d.title, EmbedImages: true, BaseDir: d.baseDir})
}

// BlankTemplate returns the raw template text of a kind (the public data
// file).
func BlankTemplate(k InjectKind) (string, error) {
	b, err := injectkit.FS.ReadFile(string(k) + ".md.tmpl")
	if err != nil {
		return "", fmt.Errorf("unknown inject template %q", k)
	}
	return string(b), nil
}

type hostView struct {
	HostRow
	FigureRef string
}

type group struct {
	Title string
	Figs  []Figure
}

type tplData struct {
	Num          int
	Code, Title  string
	Date         string
	Deliverables []Deliverable
	Hosts        []hostView
	Statements   []Statement
	Done         []DoneRow
	Remaining    []RemainRow
	Figures      []Figure
	Groups       []group
	Attachments  []string
}

func figureMarkdown(f Figure, ph func(string) string) string {
	var b strings.Builder
	if f.Kind == EvScreenshot && f.Path != "" {
		fmt.Fprintf(&b, "![%s](%s)\n", f.Caption, f.Path)
	} else {
		fmt.Fprintf(&b, "%s\n", f.Caption)
	}
	if f.Path != "" && f.Kind != EvScreenshot {
		fmt.Fprintf(&b, "File: %s\n", f.Path)
	}
	switch {
	case f.Hash != "":
		fmt.Fprintf(&b, "SHA-256: %s\n", f.Hash)
	case f.Path != "":
		fmt.Fprintf(&b, "SHA-256: %s\n", ph("hash of "+f.Path+" (file not readable here)"))
	}
	if f.Excerpt != "" {
		fmt.Fprintf(&b, "```\n%s\n```\n", strings.TrimRight(f.Excerpt, "\n"))
	}
	return b.String()
}

var platformTitles = []struct{ key, title string }{
	{"linux", "APPENDIX A - LINUX"},
	{"windows", "APPENDIX B - WINDOWS"},
	{"network", "APPENDIX C - FIREWALLS / NETWORK"},
}

// RenderInject fills a template with data. Everything the data lacks becomes
// a [[FILL: ...]] placeholder, listed in the result.
func RenderInject(d InjectData) (*InjectDoc, error) {
	name, err := Filename(KindInject, d.Num, d.Team)
	if err != nil {
		return nil, err
	}
	raw, err := BlankTemplate(d.Kind)
	if err != nil {
		return nil, err
	}
	doc := &InjectDoc{Filename: name, baseDir: d.BaseDir}
	section := "document"
	var phs []PlaceholderRef
	ph := func(what string) string {
		phs = append(phs, PlaceholderRef{Section: section, What: what})
		return Placeholder(what)
	}
	figs := MakeFigures(d.Evidence, d.BaseDir, ph)
	now := d.Now
	if now.IsZero() {
		now = time.Now()
	}

	td := tplData{Num: d.Num, Code: d.Code, Title: d.Title, Date: CentralShort(now), Deliverables: d.Deliverables,
		Statements: d.Statements, Done: d.Done, Remaining: d.Remaining, Figures: figs, Attachments: d.Attachments}
	platform := map[string]string{}
	for _, h := range d.Hosts {
		platform[h.Host] = strings.ToLower(h.Platform)
		hv := hostView{HostRow: h}
		switch {
		case h.Figure != "":
			hv.FigureRef = h.Figure
		default:
			var ns []string
			for _, f := range figs {
				if f.Host == h.Host && h.Host != "" {
					ns = append(ns, fmt.Sprintf("Fig. %d", f.N))
				}
			}
			if len(ns) == 0 {
				hv.FigureRef = ph("figure for host " + h.Host)
			} else {
				hv.FigureRef = strings.Join(ns, ", ")
			}
		}
		td.Hosts = append(td.Hosts, hv)
	}
	if d.Kind == InjectConfigMemo {
		by := map[string][]Figure{}
		for _, f := range figs {
			p := platform[f.Host]
			if p == "" {
				p = "other"
			}
			by[p] = append(by[p], f)
		}
		for _, pt := range platformTitles {
			td.Groups = append(td.Groups, group{pt.title, by[pt.key]})
		}
		if len(by["other"]) > 0 {
			td.Groups = append(td.Groups, group{"APPENDIX D - OTHER", by["other"]})
		}
	}

	cell := func(v, what string) string {
		if strings.TrimSpace(v) == "" {
			return ph(what)
		}
		return strings.ReplaceAll(v, "|", "/")
	}
	funcs := template.FuncMap{
		"inc": func(i int) int { return i + 1 },
		"p":   ph,
		"f": func(key, what string) string {
			section = key
			if v := strings.TrimSpace(d.Fields[key]); v != "" {
				return v
			}
			return ph(what)
		},
		"cell": cell,
		"figures": func(fs []Figure) string {
			if len(fs) == 0 {
				return ""
			}
			var b strings.Builder
			b.WriteString("\n")
			for _, f := range fs {
				b.WriteString(figureMarkdown(f, ph))
				b.WriteString("\n")
			}
			return b.String()
		},
		"attachments": func(a []string) string {
			if len(a) == 0 {
				return ""
			}
			return "\nATTACHMENTS (also submitted with this response)\n- " + strings.Join(a, "\n- ") + "\n"
		},
		"evidenceTable": func(hosts []hostView, fs []Figure) string {
			var b strings.Builder
			b.WriteString("| Host | Figure | What it shows | Taken (US Central) | SHA-256 |\n|---|---|---|---|---|\n")
			n := 0
			for _, h := range hosts {
				found := false
				for _, f := range fs {
					if f.Host == h.Host {
						found = true
						n++
						fmt.Fprintf(&b, "| %s | %d | %s | %s | %s |\n", esc(h.Host), f.N, esc(f.Evidence.Caption), Central(f.Taken), f.Hash)
					}
				}
				if !found {
					n++
					fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", esc(cell(h.Host, "host")), ph("figure for host "+h.Host), ph("what it shows"), ph("time taken"), ph("hash"))
				}
			}
			if n == 0 {
				fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", ph("host"), ph("figure"), ph("what it shows"), ph("time taken"), ph("hash"))
			}
			return b.String()
		},
		"appendices": func(gs []group) string {
			var b strings.Builder
			for _, g := range gs {
				fmt.Fprintf(&b, "\n## %s\n", g.Title)
				if len(g.Figs) == 0 {
					b.WriteString("No figures for this platform.\n")
				}
				for _, f := range g.Figs {
					b.WriteString(figureMarkdown(f, ph))
					b.WriteString("\n")
				}
			}
			return b.String()
		},
	}
	t, err := template.New(string(d.Kind)).Funcs(funcs).Option("missingkey=error").Parse(raw)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := t.Execute(&out, td); err != nil {
		return nil, err
	}
	// Collapse runs of blank lines left by empty sections.
	md := out.String()
	for strings.Contains(md, "\n\n\n") {
		md = strings.ReplaceAll(md, "\n\n\n", "\n\n")
	}
	doc.Markdown = strings.TrimSpace(md) + "\n"
	doc.Placeholders = phs
	doc.Figures = figs
	doc.title = fmt.Sprintf("Inject %d - %s - %s", d.Num, d.Code, d.Title)
	return doc, nil
}

// SortedPlaceholders returns the placeholder descriptions, deduplicated.
func SortedPlaceholders(p []PlaceholderRef) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range p {
		k := x.Section + ": " + x.What
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
