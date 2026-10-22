package report

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/chains"
	"github.com/PurdueBlueTeam/phylax/internal/traceback"
)

const (
	attacker = "198.51.100.7"
	webIP    = "10.0.1.10"
	dcIP     = "10.0.1.5"
)

var t0 = time.Date(2027, 3, 6, 15, 0, 0, 0, time.UTC) // 09:00 CST

func item(kind chains.ItemKind, host, target, text, state, note string) chains.Item {
	return chains.Item{Kind: kind, Host: host, Target: target, Text: text, State: state, Note: note}
}

// campaign is webshell -> persistence -> lateral to the DC.
func campaign() *chains.Campaign {
	ref := func(a string, s uint64) []traceback.Ref { return []traceback.Ref{{Agent: a, Seq: s}} }
	c := &chains.Chain{ID: 1, Seed: chains.SeedAlert, Confidence: 0.9, Created: t0, Hops: []chains.Hop{
		{Ord: 0, Cause: -1, Seed: true, Kind: chains.Access, SrcAddr: attacker, DstHost: "ecom", DstAddr: webIP,
			Account: "www-data", Proto: "tcp", DstPort: 80, Service: "http", Start: t0.Add(100 * time.Second), End: t0.Add(101 * time.Second),
			Technique: "T1190", What: "upload request to /uploads/x.php from " + attacker, Method: chains.MethodSocket, Confidence: 0.95,
			Evidence: ref("ecom", 101), Items: []chains.Item{item(chains.CloseEntry, "ecom", "/var/www/html/upload.php", "remove the unrestricted upload handler", chains.StateVerified, "re-sent the upload, got 403")}},
		{Ord: 1, Cause: 0, Kind: chains.Change, DstHost: "ecom", DstAddr: webIP, Account: "www-data",
			Proc: &chains.ProcRef{Host: "ecom", PID: 901, Exe: "/bin/sh", SHA256: strings.Repeat("ab", 32)}, Path: "/var/www/html/uploads/x.php",
			Start: t0.Add(101 * time.Second), End: t0.Add(102 * time.Second), Technique: "T1505.003", What: "web shell /var/www/html/uploads/x.php written",
			Method: chains.MethodLineage, Confidence: 0.95, Evidence: ref("ecom", 103),
			Items: []chains.Item{item(chains.RemoveArtifact, "ecom", "/var/www/html/uploads/x.php", "quarantine and delete the web shell", chains.StateVerified, "file gone, request returns 404")}},
		{Ord: 2, Cause: 1, Kind: chains.Change, DstHost: "ecom", DstAddr: webIP, Account: "www-data", Path: "/etc/cron.d/sysupd", Persistence: true,
			Start: t0.Add(300 * time.Second), End: t0.Add(301 * time.Second), Technique: "T1053.003", What: "cron job /etc/cron.d/sysupd re-downloads the shell",
			Method: chains.MethodSameAccount, Confidence: 0.9, Evidence: ref("ecom", 140),
			Items: []chains.Item{item(chains.RemovePersistence, "ecom", "/etc/cron.d/sysupd", "delete the cron file", chains.StateVerified, "cron.d listing clean")}},
		{Ord: 3, Cause: 2, Kind: chains.Move, SrcHost: "ecom", SrcAddr: webIP, DstHost: "dc01", DstAddr: dcIP, Account: "svc_backup",
			Proto: "tcp", DstPort: 445, Service: "smb", Start: t0.Add(900 * time.Second), End: t0.Add(901 * time.Second), Technique: "T1021.002",
			What: "SMB logon to dc01 as svc_backup from ecom", Method: chains.MethodTuple, Confidence: 0.92, Evidence: ref("dc01", 55),
			Items: []chains.Item{item(chains.RotateCredential, "dc01", "svc_backup", "reset the svc_backup password", chains.StateVerified, "old password rejected")}},
	}}
	return &chains.Campaign{ID: 1, Name: "webshell to dc", Chains: []*chains.Chain{c}, First: t0, Last: t0.Add(time.Hour)}
}

func evidence(t *testing.T) []Evidence {
	dir := t.TempDir()
	img := image.NewRGBA(image.Rect(0, 0, 40, 20))
	for x := 0; x < 40; x++ {
		img.Set(x, 5, color.RGBA{255, 0, 0, 255})
	}
	f, _ := os.Create(filepath.Join(dir, "fig_shell.png"))
	_ = png.Encode(f, img)
	f.Close()
	tk := t0.Add(20 * time.Minute)
	return []Evidence{
		{Kind: EvScreenshot, Path: filepath.Join(dir, "fig_shell.png"), Host: "ecom", Caption: "upload handler accepts any file type", Taken: tk, Tags: []string{TagVuln}, Annotated: true},
		{Kind: EvLog, Host: "ecom", Caption: "access log: red-team requests to x.php", Taken: tk, Tags: []string{TagRedActivity}, HopLabel: "H0", Annotated: true,
			Excerpt: attacker + ` - - [06/Mar/2027:09:01:40 -0600] "POST /uploads/x.php HTTP/1.1" 200 12`},
		{Kind: EvFirewall, Host: "palo", Caption: "Palo traffic log for the red-team session", Taken: tk, Tags: []string{TagFirewall}, Excerpt: "2027/03/06 09:01:40 allow " + attacker + " -> " + webIP + " tcp/80"},
		{Kind: EvLog, Host: "wazuh", Caption: "Wazuh rule 31108 fired on the shell request", Taken: tk, Tags: []string{TagDetection}, Excerpt: "rule 31108 level 12"},
		{Kind: EvScreenshot, Host: "ecom", Caption: "removal commands", Taken: tk, Tags: []string{TagEradication}, Excerpt: "rm -f x.php; rm /etc/cron.d/sysupd"},
		{Kind: EvLog, Host: "ecom", Caption: "upload handler removed", Taken: tk, Tags: []string{TagRemediation}, Excerpt: "git diff upload.php"},
		{Kind: EvLog, Host: "ecom", Caption: "retest: same upload now returns 403", Taken: tk, Tags: []string{TagVerification}, Excerpt: "HTTP/1.1 403 Forbidden"},
	}
}

func fullInput(t *testing.T) IRInput {
	ev := evidence(t)
	// Figure 5 is a log (not a real screenshot) so the file-less case is hashed from its excerpt.
	ev[4].Kind = EvLog
	return IRInput{
		Team: 7, Number: 1, Now: t0.Add(30 * time.Minute), Campaign: campaign(),
		Trace: &traceback.Result{Source: &traceback.SourceInfo{Addr: attacker, Port: 51000, Service: "http"},
			Files: []traceback.FileEvidence{{Host: "ecom", Path: "/var/www/html/uploads/x.php", SHA256: strings.Repeat("cd", 32)}}},
		Detection:       &Detection{Time: t0.Add(150 * time.Second), Method: "Wazuh rule 31108 (web shell request) on ecom"},
		Downtime:        &Downtime{None: true},
		RemediationTime: t0.Add(25 * time.Minute),
		Data:            "no evidence of data access: the shell ran only id and ls; the database was not opened (checked the mysql general log)",
		ServiceCheck:    "ecom-http passing in the scoreboard since 09:26",
		Containment:     []Step{{Time: t0.Add(10 * time.Minute), Text: "blocked " + attacker + " on the Palo", Figure: 3}, {Time: t0.Add(12 * time.Minute), Text: "disabled the svc_backup account"}},
		Verification:    []Step{{Time: t0.Add(24 * time.Minute), Text: "re-ran the upload request", Result: "403 Forbidden", Figure: 7}},
		Prevention:      []string{"upload directory is no longer executable"},
		Evidence:        ev,
		Attachments:     []string{"ecom-access.log"},
		HostNames:       map[string]string{dcIP: "dc01"},
	}
}

func TestIRDraftPassesRubricExceptOperatorOnly(t *testing.T) {
	d, err := DraftIR(fullInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if d.Filename != "incident01_team07.pdf" {
		t.Fatalf("filename %s", d.Filename)
	}
	if len(d.Placeholders) != 0 {
		t.Fatalf("placeholders: %+v\n%s", d.Placeholders, d.Markdown)
	}
	for _, it := range d.Checklist.Open() {
		if it.Status != OperatorOnly {
			t.Errorf("%s is %s: %s %v", it.ID, it.Status, it.Detail, it.Lines)
		}
	}
	if e, tot := d.Checklist.Earned(RubricWK); e != 100 || tot != 100 {
		t.Errorf("WK %d/%d", e, tot)
	}
	if e, tot := d.Checklist.Earned(RubricStout); e != 100 || tot != 100 {
		t.Errorf("Stout %d/%d", e, tot)
	}
	// The three operator-only judgements are listed, not silently passed.
	for _, id := range []string{"PB-screenshots", "PB-red-caused", "PB-header"} {
		it, ok := d.Checklist.Get(id)
		if !ok || it.Status != OperatorOnly {
			t.Errorf("%s: %+v", id, it)
		}
	}
	// Per-hop remediation lines with verified status.
	rem, _ := d.Checklist.Get("WK-remediate")
	if len(rem.Lines) != 4 {
		t.Errorf("per-hop lines: %v", rem.Lines)
	}
	for _, l := range rem.Lines {
		if !strings.Contains(l, "verified") || strings.Contains(l, "NOT") {
			t.Errorf("line %q", l)
		}
	}
	md := d.Markdown
	for _, want := range []string{
		"From: Team 07", "RE: Incident Report 1:", "SOURCE IP (red team) / DESTINATION IP: " + attacker,
		"2027-03-06 09:01:40 CST (15:01:40 UTC)", "dc01 (10.0.1.5)", "## 3. VULNERABILITY / ATTACK PATH",
		"## 7. VERIFICATION", "Figure 1: upload handler accepts any file type (ecom, taken 2027-03-06 09:20:00 CST",
		"[VERIFIED]", "SHA-256: " + strings.Repeat("cd", 32), "ecom-access.log", "T1021.002",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	if !strings.Contains(d.Review(), "No placeholders remain") {
		t.Error("review")
	}
}

func TestIRPDFRoundTripAndValidation(t *testing.T) {
	in := fullInput(t)
	d, err := DraftIR(in)
	if err != nil {
		t.Fatal(err)
	}
	pdf, err := d.PDF(false)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := ExtractText(pdf)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(pages, "\n")
	flat := squash(text)
	for _, want := range []string{"Incident Report 1", attacker, "From: Team 07", "T1505.003", "/var/www/html/uploads/x.php",
		"Figure 2: access log: red-team requests to x.php", strings.Repeat("cd", 32), "US Central"} {
		if !strings.Contains(flat, squash(want)) {
			t.Errorf("PDF text lacks %q", want)
		}
	}
	v := ValidateSubmission(pdf, SubmitSpec{Kind: KindIR, Number: 1, Team: 7, Filename: d.Filename, Attachments: in.Attachments, Forbidden: []string{"Purdue"}})
	if !v.OK() {
		t.Fatalf("validation failed:\n%s", v.Markdown())
	}
}

func TestIRIncompleteIsFlagged(t *testing.T) {
	in := fullInput(t)
	in.Detection, in.Downtime, in.Data = nil, nil, ""
	in.Verification = nil
	in.Evidence = in.Evidence[:2]
	// One hop loses its remediation, one item is only applied.
	c := in.Campaign.Chains[0]
	c.Hops[3].Items = nil
	c.Hops[1].Items[0].State = chains.StateApplied
	d, err := DraftIR(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Placeholders) == 0 {
		t.Fatal("expected placeholders")
	}
	if _, err := d.PDF(false); err == nil || !strings.Contains(err.Error(), "placeholders") {
		t.Fatalf("PDF must refuse a draft with placeholders: %v", err)
	}
	if _, err := d.PDF(true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Markdown, "[[FILL: detection time") {
		t.Error("detection placeholder missing")
	}
	for id, want := range map[string]Status{"WK-detect": Unmet, "WK-impact": Unmet, "WK-remediate": Unmet, "ST-general": Unmet, "PB-placeholders": Unmet} {
		it, _ := d.Checklist.Get(id)
		if it.Status != want {
			t.Errorf("%s = %s (%s), want %s", id, it.Status, it.Detail, want)
		}
	}
	rem, _ := d.Checklist.Get("WK-remediate")
	joined := strings.Join(rem.Lines, "\n")
	if !strings.Contains(joined, "H3 SMB logon to dc01 as svc_backup from ecom: NO remediation item") || !strings.Contains(joined, "NOT verified (applied)") {
		t.Errorf("per-hop lines:\n%s", joined)
	}
	if e, _ := d.Checklist.Earned(RubricWK); e >= 50 {
		t.Errorf("WK earned %d with the 50%% unmet", e)
	}
}

func TestIRGuessHopsAreLabelledInferred(t *testing.T) {
	in := fullInput(t)
	h := &in.Campaign.Chains[0].Hops[3]
	h.Method, h.Confidence, h.Evidence = chains.MethodTimeWindow, 0.4, nil
	d, err := DraftIR(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.Markdown, "INFERRED, not confirmed") || !strings.Contains(d.Markdown, "(inferred, not confirmed)") {
		t.Error("guess not labelled")
	}
	if it, _ := d.Checklist.Get("PB-trace"); it.Status != Partial {
		t.Errorf("PB-trace %s", it.Status)
	}
}

func TestIRNoChains(t *testing.T) {
	if _, err := DraftIR(IRInput{Team: 1, Number: 1}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := DraftIR(IRInput{Team: 0, Number: 1, Campaign: campaign()}); err == nil {
		t.Fatal("expected team error")
	}
}

func TestEmbeddedScreenshotIsInPDF(t *testing.T) {
	d, err := DraftIR(fullInput(t))
	if err != nil {
		t.Fatal(err)
	}
	pdf, _ := d.PDF(false)
	if !strings.Contains(string(pdf), "/Subtype /Image") {
		t.Error("screenshot not embedded")
	}
}
