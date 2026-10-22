package report

import (
	"strings"
	"testing"
	"time"
)

func TestBlankTemplatesAreBlank(t *testing.T) {
	for _, k := range InjectKinds() {
		raw, err := BlankTemplate(k)
		if err != nil {
			t.Fatal(k, err)
		}
		// Public-repo rule: placeholders only; no addresses, no dates.
		for _, bad := range []string{"10.", "192.168.", "2026", "2027", "Purdue", "Team 0"} {
			if strings.Contains(raw, bad) {
				t.Errorf("%s template contains %q", k, bad)
			}
		}
		d, err := RenderInject(InjectData{Kind: k, Num: 4, Team: 13, Now: t0})
		if err != nil {
			t.Fatal(k, err)
		}
		if len(d.Placeholders) < 5 {
			t.Errorf("%s: only %d placeholders", k, len(d.Placeholders))
		}
		if !strings.HasPrefix(d.Markdown, "# Inject 4 - ") {
			t.Errorf("%s: number is not first: %q", k, d.Markdown[:40])
		}
		if strings.Contains(strings.ToLower(d.Markdown), "13") && strings.Contains(strings.ToLower(d.Markdown), "team 13") {
			t.Errorf("%s: team number in the body", k)
		}
		if _, err := d.PDF(false); err == nil {
			t.Errorf("%s: blank template rendered to a PDF", k)
		}
		if _, err := d.PDF(true); err != nil {
			t.Errorf("%s draft PDF: %v", k, err)
		}
	}
	if _, err := BlankTemplate("nope"); err == nil {
		t.Error("unknown kind")
	}
}

func configMemo(t *testing.T) InjectData {
	tk := t0.Add(time.Hour)
	return InjectData{
		Kind: InjectConfigMemo, Num: 4, Team: 13, Code: "SVRA12T", Title: "Configure End-Point Protection Software", Now: t0.Add(2 * time.Hour),
		Fields: map[string]string{
			"to": "IT Director", "from": "Blue Operations", "summary": "We deployed endpoint protection on 2 of 2 servers, which reduces malware risk; scored services were re-tested and remain up.",
			"impl_linux": "apt install clamav; systemctl enable --now clamav-daemon", "impl_windows": "Not applicable", "impl_network": "Not applicable",
			"verification": "EICAR test file detected on both hosts; scored services pass.", "exceptions": "Scoring engine paths are excluded from scans; remove the exclusion list to undo.",
			"next_steps": "Review alerts every 30 minutes.",
		},
		Hosts: []HostRow{
			{Host: "web01", Role: "web", OS: "Ubuntu 24.04", Change: "ClamAV installed", Method: "apt", Verified: "yes, EICAR detected", Platform: "linux"},
			{Host: "dc01", Role: "domain controller", OS: "Windows Server 2022", Change: "Defender real-time on", Method: "GPO", Verified: "yes, EICAR detected", Platform: "windows"},
		},
		Evidence: []Evidence{
			{Kind: EvLog, Host: "web01", Caption: "clamdscan output detecting the EICAR file", Taken: tk, Excerpt: "eicar.txt: Eicar-Signature FOUND"},
			{Kind: EvLog, Host: "dc01", Caption: "Defender detection event 1116", Taken: tk, Excerpt: "Event 1116 EICAR"},
		},
		Attachments: []string{"clamav-install.sh"},
	}
}

func TestConfigMemoPerHostEvidence(t *testing.T) {
	d, err := RenderInject(configMemo(t))
	if err != nil {
		t.Fatal(err)
	}
	if d.Filename != "inject04_team13.pdf" {
		t.Fatal(d.Filename)
	}
	if len(d.Placeholders) != 0 {
		t.Fatalf("%v\n%s", d.Placeholders, d.Markdown)
	}
	for _, want := range []string{"# Inject 4 - SVRA12T - Configure End-Point Protection Software", "## EVIDENCE BY HOST", "| web01 | 1 |", "| dc01 | 2 |",
		"APPENDIX A - LINUX", "APPENDIX B - WINDOWS", "Figure 1: clamdscan output detecting the EICAR file (web01, taken 2027-03-06 10:00:00 CST", "clamav-install.sh", "Fig. 1"} {
		if !strings.Contains(d.Markdown, want) {
			t.Errorf("markdown lacks %q\n%s", want, d.Markdown)
		}
	}
	pdf, err := d.PDF(false)
	if err != nil {
		t.Fatal(err)
	}
	v := ValidateSubmission(pdf, SubmitSpec{Kind: KindInject, Number: 4, Team: 13, Filename: d.Filename, Attachments: []string{"clamav-install.sh"}, Forbidden: []string{"Purdue"}})
	if !v.OK() {
		t.Fatalf("\n%s", v.Markdown())
	}
	pages, _ := ExtractText(pdf)
	if !strings.HasPrefix(strings.TrimSpace(pages[0]), "Inject 4") {
		t.Errorf("first text on the PDF: %q", pages[0][:30])
	}
}

func TestConfigMemoHostWithoutFigureIsFlagged(t *testing.T) {
	in := configMemo(t)
	in.Hosts = append(in.Hosts, HostRow{Host: "db01", Role: "db", OS: "Fedora", Change: "x", Method: "y", Verified: "yes", Platform: "linux"})
	d, _ := RenderInject(in)
	found := false
	for _, p := range d.Placeholders {
		found = found || strings.Contains(p.What, "figure for host db01")
	}
	if !found {
		t.Errorf("a host with no figure must be flagged: %v", d.Placeholders)
	}
}

func TestOtherTemplatesRender(t *testing.T) {
	pol, err := RenderInject(InjectData{Kind: InjectPolicy, Num: 7, Team: 13, Code: "LEGP01T", Title: "Password Policy", Now: t0,
		Fields:     map[string]string{"company": "Example Corp", "policy_number": "POL-001", "effective_date": "d", "last_revised": "d", "owner": "CISO", "approved_by": "CEO", "applies_to": "all", "purpose": "p", "scope": "s", "definitions": "d", "roles": "r", "enforcement": "e", "implementation": "not requested", "review": "yearly", "sources": "NIST SP 800-63B"},
		Statements: []Statement{{Text: "Passwords must be at least 14 characters.", Control: "NIST 800-63B 5.1.1"}}})
	if err != nil || len(pol.Placeholders) != 0 || !strings.Contains(pol.Markdown, "4.1 Passwords must be at least 14 characters. [control reference: NIST 800-63B 5.1.1]") {
		t.Fatalf("%v %v\n%s", err, pol.Placeholders, pol.Markdown)
	}
	ext, err := RenderInject(InjectData{Kind: InjectExtension, Num: 9, Team: 13, Code: "BCOM04A", Now: t0,
		Fields:    map[string]string{"to": "CEO", "from": "Blue", "summary": "2 of 3 done", "risk": "low", "plan": "finish by noon"},
		Done:      []DoneRow{{Item: "a", Evidence: "b", Figure: "1"}},
		Remaining: []RemainRow{{Task: "c", Why: "d", Resources: "e", Have: "have", Estimate: "01:00"}}})
	if err != nil || len(ext.Placeholders) != 0 || !strings.Contains(ext.Markdown, "| c | d | e | have | 01:00 |") {
		t.Fatalf("%v %v\n%s", err, ext.Placeholders, ext.Markdown)
	}
	memo, err := RenderInject(InjectData{Kind: InjectMemo, Num: 3, Team: 2, Code: "BCOM01A", Title: "Report", Now: t0,
		Fields:       map[string]string{"to": "CIO", "from": "Blue", "summary": "s", "verification": "v", "next_steps": "n", "references": "r", "poc": "Inject writer"},
		Deliverables: []Deliverable{{"Risks", "Answer one"}, {"Plan", "Answer two"}}})
	if err != nil || len(memo.Placeholders) != 0 || !strings.Contains(memo.Markdown, "### 2.2 Plan") {
		t.Fatalf("%v %v\n%s", err, memo.Placeholders, memo.Markdown)
	}
	// The pipe in a cell must not break the table.
	ext2, _ := RenderInject(InjectData{Kind: InjectExtension, Num: 9, Team: 13, Done: []DoneRow{{Item: "a|b", Evidence: "x", Figure: "1"}}})
	if !strings.Contains(ext2.Markdown, "| a/b | x | 1 |") {
		t.Error("pipe not escaped")
	}
	if _, err := RenderInject(InjectData{Kind: InjectMemo, Num: 0, Team: 1}); err == nil {
		t.Error("bad number accepted")
	}
}

func mk(t *testing.T, md string) []byte {
	t.Helper()
	b, err := MarkdownToPDF(md, PDFOptions{Title: "x"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const body = "We completed the task on every server and re-tested the scored services, which all remain up. The change reduces risk because malware is detected on write. Verification used the EICAR test file on each host and the scanner reported it. Exceptions are the scoring paths."

func TestValidatorCases(t *testing.T) {
	spec := SubmitSpec{Kind: KindInject, Number: 4, Team: 13, Filename: "inject04_team13.pdf", Forbidden: []string{"Purdue"}}
	ok := "# Inject 4 - SVRA12T - Endpoint\n\nDate: 2027-03-06 09:00 CST (US Central)\n\n" + body
	cases := []struct {
		name string
		md   string
		mod  func(*SubmitSpec)
		fail string // id of the expected failure, "" for none
	}{
		{"clean", ok, nil, ""},
		{"wrong first line", "# Memo about endpoint\n\nInject 4 - x\n\n" + body, nil, "number-first"},
		{"wrong inject number", strings.Replace(ok, "Inject 4", "Inject 5", 1), nil, "number-first"},
		{"team in body", ok + "\nSubmitted by Team 13.", nil, "team-number"},
		{"team in body no space", ok + "\nteam13 did it", nil, "team-number"},
		{"school name", ok + "\nPurdue University", nil, "school-name"},
		{"attachment unmentioned", ok, func(s *SubmitSpec) { s.Attachments = []string{"scan-results.csv"} }, "attachments"},
		{"attachment mentioned", ok + "\nAttached: scan-results.csv", func(s *SubmitSpec) { s.Attachments = []string{"/tmp/scan-results.csv"} }, ""},
		{"placeholder", ok + "\n[[FILL: the exception list]]", nil, "placeholders"},
		{"angle placeholder", ok + "\n<host name here>", nil, "placeholders"},
		{"too short", "# Inject 4 - X\n\nok", nil, "length"},
		{"bad file name", ok, func(s *SubmitSpec) { s.Filename = "Team 13 - Inject 4.pdf" }, "filename"},
		{"file name for other inject", ok, func(s *SubmitSpec) { s.Filename = "inject05_team13.pdf" }, "filename"},
		{"too many pages", ok + strings.Repeat("\n\nFiller paragraph about the configuration of the hosts and services in scope.\n", 1500), nil, "length"},
	}
	for _, c := range cases {
		s := spec
		if c.mod != nil {
			c.mod(&s)
		}
		v := ValidateSubmission(mk(t, c.md), s)
		var failed []string
		for _, f := range v.Failures() {
			failed = append(failed, f.ID)
		}
		if c.fail == "" && len(failed) > 0 || c.fail != "" && !contains(failed, c.fail) {
			t.Errorf("%s: failures %v, want %q\n%s", c.name, failed, c.fail, v.Markdown())
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestValidatorRejectsNonTextPDF(t *testing.T) {
	spec := SubmitSpec{Kind: KindInject, Number: 4, Team: 13, Filename: "inject04_team13.pdf"}
	if v := ValidateSubmission([]byte("not a pdf"), spec); v.OK() {
		t.Error("garbage accepted")
	}
	// A PDF holding only a picture has no extractable text.
	img := evidence(t)[0].Path
	b, err := MarkdownToPDF("![x]("+img+")", PDFOptions{EmbedImages: true})
	if err != nil {
		t.Fatal(err)
	}
	pages, _ := ExtractText(b)
	// The caption text "x" and file line exist, but the word count is far below a real response.
	v := ValidateSubmission(b, spec)
	if v.OK() {
		t.Errorf("near-empty picture PDF accepted (pages %q)\n%s", pages, v.Markdown())
	}
	// Truncated PDF.
	good := mk(t, "# Inject 4 - X\n\n"+body)
	if v := ValidateSubmission(good[:len(good)/2], spec); v.OK() {
		t.Error("truncated PDF accepted")
	}
}

func TestValidatorIR(t *testing.T) {
	spec := SubmitSpec{Kind: KindIR, Number: 2, Team: 5, Filename: "incident02_team05.pdf"}
	good := "To: Red Team Lead\nFrom: Team 05\nDate / time zone: 2027-03-06 09:00 CST (US Central)\nRE: Incident Report 2: web shell\n\n" + body
	if v := ValidateSubmission(mk(t, good), spec); !v.OK() {
		t.Fatalf("\n%s", v.Markdown())
	}
	bad := strings.Replace(good, "Incident Report 2", "Incident Report 1", 1)
	v := ValidateSubmission(mk(t, bad), spec)
	if c, _ := v.Get("number-first"); c.Severity != SevFail {
		t.Error("stale incident number accepted")
	}
	noTeam := strings.Replace(good, "Team 05", "Blue Team", 1)
	if c, _ := ValidateSubmission(mk(t, noTeam), spec).Get("team-number"); c.Severity != SevFail {
		t.Error("missing team number accepted")
	}
	// A warning does not block: no Central label.
	nz := strings.Replace(good, "(US Central)", "", 1)
	v = ValidateSubmission(mk(t, nz), spec)
	if c, _ := v.Get("central-time"); c.Severity != SevWarn || !v.OK() {
		t.Error("central warning")
	}
}
