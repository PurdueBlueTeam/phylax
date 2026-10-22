package report

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/chains"
	"github.com/PurdueBlueTeam/phylax/internal/traceback"
)

// Detection is how and when the incident was detected (the 10% "how and when
// detected" row). The operator or the alert pipeline supplies it.
type Detection struct {
	Time   time.Time
	Method string // tool, log source, query or rule
}

// Downtime is the service downtime; None means "none".
type Downtime struct {
	None       bool
	Start, End time.Time
	Services   string // which scored services
}

// Step is a containment or verification action. Result is what the retest
// showed ("exploit request now returns 404"). Figure is the figure number
// (1-based, in Evidence order) that shows it, 0 for none.
type Step struct {
	Time   time.Time
	Text   string
	Result string
	Figure int
}

// IRInput is everything the drafter needs. Chains come from the chain
// builder (one campaign = one report); Trace is the trace-back result for the
// seed; Evidence points at screenshots and log excerpts. Team and Number
// drive the header and file name.
type IRInput struct {
	Team   int
	Number int
	Title  string // one line: what happened to what (generated when empty)
	To     string // default "Red Team Lead / White Team"
	Now    time.Time

	Campaign *chains.Campaign
	Chains   []*chains.Chain
	Trace    *traceback.Result

	// HostNames maps an address to its manifest hostname for the header.
	HostNames map[string]string

	Detection       *Detection
	Downtime        *Downtime
	RemediationTime time.Time
	Data            string // what data was viewed or taken, or "no evidence of data access"
	ServiceCheck    string // the scored service status after the fix
	Containment     []Step
	Verification    []Step
	Prevention      []string
	Evidence        []Evidence
	Attachments     []string // extra files submitted with the PDF; each is named in the report

	// BaseDir resolves relative evidence paths.
	BaseDir string
}

// PlaceholderRef is a marker the operator must fill, with its section.
type PlaceholderRef struct {
	Section string
	What    string
}

// IRDraft is the drafter output.
type IRDraft struct {
	Filename     string
	Markdown     string
	Checklist    Checklist
	Placeholders []PlaceholderRef
	Figures      []Figure
	baseDir      string
	title        string
}

// ErrPlaceholders is returned by PDF when markers remain and drafts are not
// allowed.
var ErrPlaceholders = errors.New("report still contains placeholders the operator must fill")

// PDF renders the draft. With allowPlaceholders false it refuses while any
// [[FILL: ...]] marker remains, so a half-written report cannot be submitted
// by accident (the rules give no partial points).
func (d *IRDraft) PDF(allowPlaceholders bool) ([]byte, error) {
	if !allowPlaceholders && len(d.Placeholders) > 0 {
		return nil, fmt.Errorf("%w: %d (%s ...)", ErrPlaceholders, len(d.Placeholders), d.Placeholders[0].What)
	}
	return MarkdownToPDF(d.Markdown, PDFOptions{Title: d.title, EmbedImages: true, BaseDir: d.baseDir})
}

// Review renders the reviewer's page: placeholders and the rubric checklist.
// It is not part of the submitted PDF.
func (d *IRDraft) Review() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Review: %s\n\n", d.Filename)
	if len(d.Placeholders) == 0 {
		b.WriteString("No placeholders remain.\n\n")
	} else {
		b.WriteString("## Fill these before submitting\n\n")
		for _, p := range d.Placeholders {
			fmt.Fprintf(&b, "- [ ] %s: %s\n", p.Section, p.What)
		}
		b.WriteString("\n")
	}
	b.WriteString(d.Checklist.Markdown())
	return b.String()
}

type hopRef struct {
	label string
	chain int
	h     *chains.Hop
}

type irBuilder struct {
	in      IRInput
	loc     *time.Location
	sb      strings.Builder
	section string
	phs     []PlaceholderRef
	hops    []hopRef
	figs    []Figure
	multi   bool
	sec     []chains.IRSection
	cs      []*chains.Chain
}

func (b *irBuilder) ph(what string) string {
	b.phs = append(b.phs, PlaceholderRef{Section: b.section, What: what})
	return Placeholder(what)
}

func (b *irBuilder) pr(format string, a ...any) { fmt.Fprintf(&b.sb, format, a...) }

func (b *irBuilder) label(chain int, ord int) string {
	if b.multi {
		return fmt.Sprintf("C%d.H%d", chain+1, ord)
	}
	return fmt.Sprintf("H%d", ord)
}

func (b *irBuilder) hostLabel(host, addr string) string {
	name := host
	if name == "" {
		name = b.in.HostNames[addr]
	}
	switch {
	case name != "" && addr != "":
		return name + " (" + addr + ")"
	case name != "":
		return name
	}
	return addr
}

func isNetworkHop(h *chains.Hop) bool {
	return h.Kind == chains.Access || h.Kind == chains.Move || h.Kind == chains.Egress
}

// needsRemediation: the hops that open or keep a way in. Exec and egress
// hops are covered by the items of the access and change hops that start them.
func needsRemediation(h *chains.Hop) bool {
	return h.Kind == chains.Access || h.Kind == chains.Change || h.Kind == chains.Move
}

func eradicationKind(k chains.ItemKind) bool {
	return k == chains.RemoveArtifact || k == chains.RemovePersistence || k == chains.BlockSource
}

func (b *irBuilder) figRefs(pred func(Figure) bool) string {
	var ns []string
	for _, f := range b.figs {
		if pred(f) {
			ns = append(ns, fmt.Sprintf("Figure %d", f.N))
		}
	}
	return strings.Join(ns, ", ")
}

func (b *irBuilder) hopFigs(label string) string {
	var ns []string
	for _, f := range b.figs {
		if f.HopLabel == label {
			ns = append(ns, fmt.Sprintf("%d", f.N))
		}
	}
	return strings.Join(ns, ", ")
}

func (b *irBuilder) tagFigs(tag string) string {
	return b.figRefs(func(f Figure) bool { return f.HasTag(tag) })
}

func refsText(refs []traceback.Ref) string {
	var s []string
	for _, r := range refs {
		s = append(s, fmt.Sprintf("%s#%d", r.Agent, r.Seq))
	}
	return strings.Join(s, ", ")
}

func pct(c float64) string { return fmt.Sprintf("%.0f%%", c*100) }

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func orPH(b *irBuilder, v []string, what string) string {
	v = uniq(v)
	if len(v) == 0 {
		return b.ph(what)
	}
	return strings.Join(v, ", ")
}

// DraftIR builds the incident report draft for one attack narrative.
func DraftIR(in IRInput) (*IRDraft, error) {
	name, err := Filename(KindIR, in.Number, in.Team)
	if err != nil {
		return nil, err
	}
	b := &irBuilder{in: in, loc: chains.Central()}
	b.cs = append(b.cs, in.Chains...)
	if in.Campaign != nil {
		for _, c := range in.Campaign.Chains {
			dup := false
			for _, x := range b.cs {
				dup = dup || x == c
			}
			if !dup {
				b.cs = append(b.cs, c)
			}
		}
	}
	if len(b.cs) == 0 {
		return nil, errors.New("no chains: an IR needs at least one attack chain")
	}
	b.multi = len(b.cs) > 1
	for ci, c := range b.cs {
		b.sec = append(b.sec, c.IRSection(b.loc))
		for i := range c.Hops {
			b.hops = append(b.hops, hopRef{label: b.label(ci, c.Hops[i].Ord), chain: ci, h: &c.Hops[i]})
		}
	}
	sort.SliceStable(b.hops, func(i, j int) bool { return b.hops[i].h.Start.Before(b.hops[j].h.Start) })
	if len(b.hops) == 0 {
		return nil, errors.New("chains have no hops")
	}

	// Figures: caller evidence plus files the trace-back hashed.
	ev := append([]Evidence(nil), in.Evidence...)
	if in.Trace != nil {
		seen, _ := b.initial()
		taken := in.Trace.Trigger.Time
		if taken.IsZero() {
			taken = seen.h.Start
		}
		for _, f := range in.Trace.Files {
			dup := false
			for _, e := range ev {
				dup = dup || (e.Kind == EvFile && e.SHA256 == f.SHA256 && e.Path == f.Path)
			}
			if !dup && f.SHA256 != "" {
				ev = append(ev, Evidence{Kind: EvFile, Path: f.Path, Host: f.Host, SHA256: f.SHA256,
					Caption: "collected artifact " + f.Path, Taken: taken})
			}
		}
	}
	b.section = "figures"
	b.figs = MakeFigures(ev, in.BaseDir, b.ph)

	d := &IRDraft{Filename: name, baseDir: in.BaseDir}
	b.header(d)
	b.summary()
	b.timeline()
	b.attackPath()
	b.impact()
	b.eradication()
	b.remediation()
	b.verification()
	b.prevention()
	b.appendix()

	d.Markdown = b.sb.String()
	d.Placeholders = b.phs
	d.Figures = b.figs
	d.Checklist = b.checklist()
	return d, nil
}

// initial returns the hop that counts as initial access: the earliest access
// hop from outside, else the seed hop, else the first hop.
func (b *irBuilder) initial() (*hopRef, bool) {
	for i := range b.hops {
		h := b.hops[i].h
		if h.Kind == chains.Access && h.SrcHost == "" {
			return &b.hops[i], true
		}
	}
	for i := range b.hops {
		if b.hops[i].h.Seed {
			return &b.hops[i], false
		}
	}
	return &b.hops[0], false
}

func (b *irBuilder) sources() []string {
	var s []string
	for _, sec := range b.sec {
		s = append(s, sec.Sources...)
	}
	if len(s) == 0 && b.in.Trace != nil && b.in.Trace.Source != nil {
		s = append(s, b.in.Trace.Source.Addr)
	}
	return uniq(s)
}

func (b *irBuilder) accounts() []string {
	var s []string
	for _, sec := range b.sec {
		s = append(s, sec.Accounts...)
	}
	return uniq(s)
}

func (b *irBuilder) affectedHosts() []string {
	addr := map[string]string{}
	var order []string
	for _, r := range b.hops {
		h := r.h
		for _, p := range [][2]string{{h.DstHost, h.DstAddr}, {h.SrcHost, h.SrcAddr}} {
			if p[0] == "" {
				continue
			}
			if _, ok := addr[p[0]]; !ok {
				order = append(order, p[0])
			}
			if p[1] != "" {
				addr[p[0]] = p[1]
			} else if _, ok := addr[p[0]]; !ok {
				addr[p[0]] = ""
			}
		}
	}
	var out []string
	for _, h := range order {
		out = append(out, b.hostLabel(h, addr[h]))
	}
	return out
}

func (b *irBuilder) services() []string {
	var s []string
	for _, r := range b.hops {
		h := r.h
		if (h.Kind == chains.Access || h.Kind == chains.Move) && (h.DstPort != 0 || h.Service != "") {
			x := ""
			if h.DstPort != 0 {
				x = fmt.Sprintf("%d", h.DstPort)
				if h.Proto != "" {
					x += "/" + h.Proto
				}
			}
			if h.Service != "" {
				if x != "" {
					x += " "
				}
				x += h.Service
			}
			if h.DstHost != "" {
				x += " on " + h.DstHost
			}
			s = append(s, x)
		}
	}
	return uniq(s)
}

func (b *irBuilder) destinations() []string {
	var s []string
	for _, r := range b.hops {
		h := r.h
		if h.Kind == chains.Access || h.Kind == chains.Move {
			s = append(s, b.hostLabel(h.DstHost, h.DstAddr))
		}
	}
	return uniq(s)
}

func (b *irBuilder) header(d *IRDraft) {
	in := b.in
	b.section = "header"
	to := in.To
	if to == "" {
		to = "Red Team Lead / White Team"
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	first, _ := b.initial()
	title := in.Title
	if title == "" {
		what := first.h.What
		if what == "" {
			what = "intrusion"
		}
		host := first.h.DstHost
		if host == "" {
			host = "host"
		}
		title = fmt.Sprintf("%s on %s", what, host)
		if n := len(b.hops); n > 1 {
			title += fmt.Sprintf(" and %d follow-on steps", n-1)
		}
	}
	d.title = fmt.Sprintf("Incident Report %d: %s", in.Number, title)
	b.pr("To: %s\n", to)
	b.pr("From: Team %02d\n", in.Team)
	b.pr("Date / time zone: %s\n", CentralShort(now))
	b.pr("RE: Incident Report %d: %s\n\n", in.Number, title)

	b.pr("AFFECTED HOST(S) / IP: %s\n", orPH(b, b.affectedHosts(), "affected hosts and addresses"))
	b.pr("SOURCE IP (red team) / DESTINATION IP: %s / %s\n",
		orPH(b, b.sources(), "red-team source IP"), orPH(b, b.destinations(), "destination IP"))
	b.pr("PORT AND SERVICE: %s\n", orPH(b, b.services(), "destination port and service"))
	b.pr("AFFECTED ACCOUNT(S) (the account red team used): %s\n", orPH(b, b.accounts(), "account red team used"))

	hr, access := b.initial()
	basis := fmt.Sprintf("%s [%s; link %s, %s confidence", hr.h.What, hr.label, hr.h.Method, chains.Level(hr.h.Confidence))
	if len(hr.h.Evidence) > 0 {
		basis += "; stored events " + refsText(hr.h.Evidence)
	}
	basis += "]"
	if !access {
		basis += " " + b.ph("no inbound access hop was found: state how initial access happened")
	}
	b.pr("INITIAL-ACCESS TIMESTAMP (with TZ) and how we know: %s, %s\n", Central(hr.h.Start), basis)

	if in.Detection != nil && !in.Detection.Time.IsZero() && strings.TrimSpace(in.Detection.Method) != "" {
		b.pr("DETECTION TIMESTAMP and how it was detected (tool, log, query): %s, %s\n", Central(in.Detection.Time), in.Detection.Method)
	} else {
		b.pr("DETECTION TIMESTAMP and how it was detected (tool, log, query): %s\n", b.ph("detection time (Central) and the tool, log or query that found it"))
	}
	switch dt := in.Downtime; {
	case dt == nil:
		b.pr("SERVICE DOWNTIME (start - end) or \"none\": %s\n", b.ph("downtime start - end, or none"))
	case dt.None:
		b.pr("SERVICE DOWNTIME (start - end) or \"none\": none\n")
	default:
		b.pr("SERVICE DOWNTIME (start - end) or \"none\": %s - %s %s\n", Central(dt.Start), Central(dt.End), dt.Services)
	}
	if in.RemediationTime.IsZero() {
		b.pr("REMEDIATION TIMESTAMP: %s\n\n", b.ph("time the attack path was closed (Central)"))
	} else {
		b.pr("REMEDIATION TIMESTAMP: %s\n\n", Central(in.RemediationTime))
	}
}

func (b *irBuilder) allItems() (open, applied, verified int) {
	for _, r := range b.hops {
		for _, it := range r.h.Items {
			switch it.State {
			case chains.StateVerified:
				verified++
			case chains.StateApplied:
				applied++
			default:
				open++
			}
		}
	}
	return
}

func (b *irBuilder) summary() {
	b.section = "1. summary"
	b.pr("## 1. SUMMARY\n")
	hr, _ := b.initial()
	h := hr.h
	srcs := b.sources()
	src := "an outside source"
	if len(srcs) > 0 {
		src = strings.Join(srcs, ", ")
	}
	svc := h.Service
	if svc == "" {
		svc = "an exposed service"
	}
	acct := ""
	if h.Account != "" {
		acct = " as " + h.Account
	}
	s := fmt.Sprintf("On %s, %s reached %s through %s%s: %s.", Central(h.Start), src, b.hostLabel(h.DstHost, h.DstAddr), svc, acct, h.What)
	var rest []string
	for _, r := range b.hops {
		if r.h != h && !(r.h.Kind == chains.Access && r.h.SrcHost == "" && r.h.DstHost == h.DstHost) {
			rest = append(rest, r.h.What)
		}
	}
	if len(rest) > 0 {
		shown := rest
		more := ""
		if len(shown) > 5 {
			more = fmt.Sprintf(" and %d more steps", len(shown)-5)
			shown = shown[:5]
		}
		s += " The same actor then: " + strings.Join(shown, "; ") + more + "."
	}
	var pers []string
	for _, r := range b.hops {
		if r.h.Persistence {
			pers = append(pers, r.h.Path)
		}
	}
	if pers = uniq(pers); len(pers) > 0 {
		s += " Persistence was left at " + strings.Join(pers, ", ") + "."
	}
	op, ap, ve := b.allItems()
	if tot := op + ap + ve; tot > 0 {
		s += fmt.Sprintf(" Of %d remediation items, %d are verified by retest, %d applied and %d open.", tot, ve, ap, op)
	}
	b.pr("%s\n\n", s)
}

type tlRow struct {
	t     time.Time
	host  string
	event string
	link  string
	fig   string
}

func (b *irBuilder) timeline() {
	b.section = "2. timeline"
	b.pr("## 2. TIMELINE\n")
	var rows []tlRow
	for _, r := range b.hops {
		h := r.h
		host := h.DstHost
		if h.Kind == chains.Move && h.SrcHost != "" {
			host = h.SrcHost + " -> " + h.DstHost
		}
		ev := fmt.Sprintf("%s: %s", r.label, h.What)
		link := fmt.Sprintf("%s, %s", h.Method, chains.Level(h.Confidence))
		if h.Method == chains.MethodTimeWindow || h.Method == chains.MethodUnmatched {
			link += " (inferred, not confirmed)"
		}
		rows = append(rows, tlRow{h.Start, host, ev, link, b.hopFigs(r.label)})
	}
	if dt := b.in.Detection; dt != nil && !dt.Time.IsZero() {
		rows = append(rows, tlRow{dt.Time, "", "Detected: " + dt.Method, "operator", figList(b.tagFigNums("detection"))})
	}
	for _, s := range b.in.Containment {
		if !s.Time.IsZero() {
			rows = append(rows, tlRow{s.Time, "", "Containment: " + s.Text, "operator", figNum(s.Figure)})
		}
	}
	for _, s := range b.in.Verification {
		if !s.Time.IsZero() {
			rows = append(rows, tlRow{s.Time, "", "Retest: " + s.Text, "operator", figNum(s.Figure)})
		}
	}
	if !b.in.RemediationTime.IsZero() {
		rows = append(rows, tlRow{b.in.RemediationTime, "", "Attack path closed (remediation applied)", "operator", ""})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].t.Before(rows[j].t) })
	b.pr("| Time (US Central) | UTC | Host | Event | Link | Fig. |\n|---|---|---|---|---|---|\n")
	for _, r := range rows {
		b.pr("| %s | %s | %s | %s | %s | %s |\n", r.t.In(b.loc).Format("2006-01-02 15:04:05 MST"), r.t.UTC().Format("15:04:05Z"),
			esc(r.host), esc(r.event), esc(r.link), r.fig)
	}
	b.pr("\n")
}

func (b *irBuilder) tagFigNums(tag string) []int {
	var n []int
	for _, f := range b.figs {
		if f.HasTag(tag) {
			n = append(n, f.N)
		}
	}
	return n
}

func figNum(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", n)
}

func figList(n []int) string {
	var s []string
	for _, x := range n {
		s = append(s, fmt.Sprintf("%d", x))
	}
	return strings.Join(s, ", ")
}

func esc(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", "/"), "\n", " ") }

func (b *irBuilder) attackPath() {
	b.section = "3. attack path"
	b.pr("## 3. VULNERABILITY / ATTACK PATH\n")
	first, access := b.initial()
	if access {
		h := first.h
		how := h.What
		b.pr("Entry point: %s via %s%s. How they got in: %s.\n", b.hostLabel(h.DstHost, h.DstAddr),
			orDefault(h.Service, "the exposed service"), acctText(h.Account), how)
	} else {
		b.pr("Entry point: %s\n", b.ph("how red team got in: account, service and vulnerability"))
	}
	b.pr("\n")
	for _, r := range b.hops {
		h := r.h
		b.pr("- %s [%s] %s%s: %s\n", r.label, h.Kind, Central(h.Start), techText(h.Technique), h.What)
		var det []string
		if isNetworkHop(h) && (h.SrcAddr != "" || h.DstAddr != "") {
			det = append(det, fmt.Sprintf("%s -> %s%s", orDefault(b.hostLabel(h.SrcHost, h.SrcAddr), "outside"), b.hostLabel(h.DstHost, h.DstAddr), portText(h)))
		}
		if h.Account != "" {
			det = append(det, "account "+h.Account)
		}
		if h.Proc != nil && h.Proc.Exe != "" {
			p := "process " + h.Proc.Exe
			if h.Proc.Cmdline != "" {
				p += " (" + h.Proc.Cmdline + ")"
			}
			if h.Proc.SHA256 != "" {
				p += " sha256 " + h.Proc.SHA256
			}
			det = append(det, p)
		}
		if h.Path != "" {
			det = append(det, "path "+h.Path)
		}
		if len(det) > 0 {
			b.pr("  - %s\n", strings.Join(det, "; "))
		}
		linkTxt := fmt.Sprintf("link: %s, %s confidence (%s)", h.Method, chains.Level(h.Confidence), pct(h.Confidence))
		if h.Method == chains.MethodTimeWindow || h.Method == chains.MethodUnmatched {
			linkTxt += "; INFERRED, not confirmed by a matching record"
		}
		b.pr("  - %s\n", linkTxt)
		if h.Kind == chains.Change {
			left := h.Path
			if h.Proc != nil && h.Proc.Exe != "" {
				left += ", written by " + h.Proc.Exe
			}
			if h.Account != "" {
				left += " as " + h.Account
			}
			b.pr("  - left behind: %s\n", left)
		}
		if len(h.Evidence) > 0 {
			b.pr("  - stored events: %s\n", refsText(h.Evidence))
		}
		if f := b.hopFigs(r.label); f != "" {
			b.pr("  - figures: %s\n", f)
		}
		for _, n := range h.Notes {
			b.pr("  - note: %s\n", n)
		}
	}
	b.pr("\n")
	if b.in.Trace != nil {
		n := 0
		for _, e := range b.in.Trace.Timeline {
			if e.Role != "source" && e.Role != "activity" {
				continue
			}
			if n == 0 {
				b.pr("Other activity from the same source (trace-back):\n")
			}
			if n++; n > 15 {
				b.pr("- ... more in the controller timeline\n")
				break
			}
			b.pr("- %s %s: %s (%s)\n", Central(e.Time), e.Host, e.Summary, refsText(e.Refs))
		}
		if n > 0 {
			b.pr("\n")
		}
	}
	vuln, red := b.tagFigs(TagVuln), b.tagFigs(TagRedActivity)
	if vuln == "" {
		vuln = b.ph("figure of the vulnerable code or config (tag: vuln)")
	}
	if red == "" {
		red = b.ph("figure of a log line showing red team abusing it, with the source IP (tag: red_activity)")
	}
	b.pr("Evidence: %s (the vulnerable code or config); %s (red-team activity).\n\n", vuln, red)
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func acctText(a string) string {
	if a == "" {
		return ""
	}
	return " (account " + a + ")"
}

func techText(t string) string {
	if t == "" {
		return ""
	}
	return " " + t
}

func portText(h *chains.Hop) string {
	if h.DstPort == 0 {
		return ""
	}
	s := fmt.Sprintf(" port %d", h.DstPort)
	if h.Proto != "" {
		s += "/" + h.Proto
	}
	if h.Service != "" {
		s += " " + h.Service
	}
	return s
}

func (b *irBuilder) impact() {
	b.section = "4. impact"
	b.pr("## 4. IMPACT\n")
	b.pr("- Hosts affected: %s\n", orPH(b, b.affectedHosts(), "affected hosts"))
	b.pr("- Accounts used by red team: %s\n", orPH(b, b.accounts(), "accounts"))
	var mv, eg, pers []string
	for _, r := range b.hops {
		switch {
		case r.h.Kind == chains.Move:
			mv = append(mv, fmt.Sprintf("%s -> %s", orDefault(r.h.SrcHost, r.h.SrcAddr), orDefault(r.h.DstHost, r.h.DstAddr)))
		case r.h.Kind == chains.Egress:
			eg = append(eg, orDefault(r.h.DstAddr, r.h.DstHost))
		}
		if r.h.Persistence {
			pers = append(pers, r.h.DstHost+":"+r.h.Path)
		}
	}
	if mv = uniq(mv); len(mv) > 0 {
		b.pr("- Lateral movement: %s\n", strings.Join(mv, ", "))
	}
	if eg = uniq(eg); len(eg) > 0 {
		b.pr("- Outbound connections to: %s\n", strings.Join(eg, ", "))
	}
	if pers = uniq(pers); len(pers) > 0 {
		b.pr("- Persistence that would survive a restart: %s\n", strings.Join(pers, ", "))
	}
	switch dt := b.in.Downtime; {
	case dt == nil:
		b.pr("- Scored-service downtime: %s\n", b.ph("downtime start - end and which services, or none"))
	case dt.None:
		b.pr("- Scored-service downtime: none\n")
	default:
		b.pr("- Scored-service downtime: %s - %s %s\n", Central(dt.Start), Central(dt.End), dt.Services)
	}
	if strings.TrimSpace(b.in.Data) != "" {
		b.pr("- Data: %s\n", b.in.Data)
	} else {
		b.pr("- Data: %s\n", b.ph("what data red team could see or took, or \"no evidence of data access\" (state what you checked)"))
	}
	b.pr("\n")
}

func (b *irBuilder) itemLines(pred func(chains.Item) bool) (n int) {
	for _, r := range b.hops {
		for _, it := range r.h.Items {
			if !pred(it) {
				continue
			}
			n++
			b.pr("- %s %s: %s (%s", r.label, it.Kind, it.Text, it.State)
			if it.Note != "" {
				b.pr("; %s", it.Note)
			}
			b.pr(")\n")
		}
	}
	return
}

func (b *irBuilder) eradication() {
	b.section = "5. eradication"
	b.pr("## 5. ERADICATION\n")
	for _, s := range b.in.Containment {
		t := Central(s.Time)
		if t == "" {
			t = b.ph("time of containment step")
		}
		b.pr("- %s: %s%s\n", t, s.Text, figSuffix(s.Figure))
	}
	if n := b.itemLines(func(i chains.Item) bool { return eradicationKind(i.Kind) }); n == 0 {
		b.pr("- %s\n", b.ph("commands that removed their access and the artifacts that restart it"))
	}
	b.pr("Evidence: %s\n\n", orDefaultPH(b, b.tagFigs(TagEradication), "figure of the removal commands (tag: eradication)"))
}

func figSuffix(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(" (Figure %d)", n)
}

func orDefaultPH(b *irBuilder, s, what string) string {
	if s == "" {
		return b.ph(what)
	}
	return s
}

func (b *irBuilder) remediation() {
	b.section = "6. remediation"
	b.pr("## 6. REMEDIATION\n")
	b.pr("What closed each hop of the attack path (state: open, applied, verified):\n\n")
	for _, r := range b.hops {
		if !needsRemediation(r.h) {
			continue
		}
		b.pr("- %s %s\n", r.label, r.h.What)
		var shown int
		for _, it := range r.h.Items {
			shown++
			b.pr("  - %s %s on %s: %s [%s]", it.Kind, it.Target, orDefault(it.Host, r.h.DstHost), it.Text, strings.ToUpper(it.State))
			if it.Note != "" {
				b.pr(" verified by: %s", it.Note)
			}
			b.pr("\n")
		}
		if shown == 0 {
			b.pr("  - %s\n", b.ph("remediation of "+r.label+": what closes this step of the path"))
		}
	}
	b.pr("Evidence: %s\n\n", orDefaultPH(b, b.tagFigs(TagRemediation), "figure of the fix (tag: remediation)"))
}

func (b *irBuilder) verification() {
	b.section = "7. verification"
	b.pr("## 7. VERIFICATION\n")
	if len(b.in.Verification) == 0 {
		b.pr("- %s\n", b.ph("the retest of the same attack path and its failure"))
	}
	for _, s := range b.in.Verification {
		t := Central(s.Time)
		if t == "" {
			t = b.ph("retest time")
		}
		res := s.Result
		if res == "" {
			res = b.ph("retest result")
		}
		b.pr("- %s: %s. Result: %s%s\n", t, s.Text, res, figSuffix(s.Figure))
	}
	if strings.TrimSpace(b.in.ServiceCheck) != "" {
		b.pr("- Scored service after the fix: %s\n", b.in.ServiceCheck)
	} else {
		b.pr("- Scored service after the fix: %s\n", b.ph("scored service status after remediation"))
	}
	b.pr("Evidence: %s\n\n", orDefaultPH(b, b.tagFigs(TagVerification), "figure of the failed retest (tag: verification)"))
}

func (b *irBuilder) prevention() {
	b.section = "8. prevention"
	b.pr("## 8. PREVENTION / OPEN ITEMS\n")
	if len(b.in.Prevention) == 0 {
		b.pr("- %s\n", b.ph("what stops a repeat"))
	}
	for _, p := range b.in.Prevention {
		b.pr("- %s\n", p)
	}
	for _, r := range b.hops {
		for _, it := range r.h.Items {
			if !it.Verified() {
				b.pr("- Still open: %s %s (%s)\n", r.label, it.Text, it.State)
			}
		}
	}
	for _, sec := range b.sec {
		for _, c := range sec.Caveats {
			b.pr("- Limit of this report: %s\n", c)
		}
	}
	if b.in.Trace != nil {
		for _, c := range b.in.Trace.Breaks() {
			b.pr("- Limit of this report: %s\n", c)
		}
		for _, c := range b.in.Trace.Truncated {
			b.pr("- Limit of this report: %s\n", c)
		}
	}
	b.pr("\n")
}

func (b *irBuilder) appendix() {
	b.section = "appendix"
	b.pr("## EVIDENCE APPENDIX\n")
	if len(b.in.Attachments) > 0 {
		b.pr("Attachments submitted with this report: %s\n\n", strings.Join(b.in.Attachments, ", "))
	}
	if len(b.figs) == 0 {
		b.pr("%s\n\n", b.ph("evidence: screenshots, log excerpts and file hashes"))
	}
	for _, f := range b.figs {
		switch {
		case f.Kind == EvScreenshot && f.Path != "":
			b.pr("![%s](%s)\n", f.Caption, f.Path)
		default:
			b.pr("%s\n", f.Caption)
		}
		if f.Path != "" && f.Kind != EvScreenshot {
			b.pr("File: %s\n", f.Path)
		}
		switch {
		case f.Hash != "":
			b.pr("SHA-256: %s\n", f.Hash)
		case f.Path != "":
			b.pr("SHA-256: %s\n", b.ph("hash of "+f.Path+" (file not readable here)"))
		}
		if f.Excerpt != "" {
			b.pr("```\n%s\n```\n", strings.TrimRight(f.Excerpt, "\n"))
		}
		b.pr("\n")
	}
	var refs []string
	for _, r := range b.hops {
		if len(r.h.Evidence) > 0 {
			refs = append(refs, fmt.Sprintf("| %s | %s |", r.label, refsText(r.h.Evidence)))
		}
	}
	if len(refs) > 0 {
		b.pr("Stored event pointers (controller event store, agent#sequence):\n\n| Hop | Events |\n|---|---|\n%s\n", strings.Join(refs, "\n"))
	}
}
