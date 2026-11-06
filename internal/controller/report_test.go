package controller

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/checks/probe"
	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/report"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// newReportUITest is newUITest with the team and numbering configured.
func newReportUITest(t *testing.T) (*Controller, *WebOps, *uiClient, string) {
	t.Helper()
	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: filepath.Join(t.TempDir(), "data"), Team: 7, NextIncident: 3, NextInject: 5,
		ForbiddenWords: []string{"Hogwarts"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := New(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	srv, ops, err := c.NewUI(UIOptions{Addr: "127.0.0.1:8443"})
	if err != nil {
		t.Fatal(err)
	}
	pw, _, err := srv.EnsureAdmin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u := &uiClient{t: t, h: srv.Handler()}
	tok := u.token(u.do("GET", "/login", nil).Body.String())
	if w := u.do("POST", "/login", url.Values{"username": {"admin"}, "password": {pw}, "csrf_token": {tok}}); w.Code != 303 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	return c, ops, u, u.token(u.do("GET", "/", nil).Body.String())
}

func (u *uiClient) multipart(path, token string, fields map[string]string, tags []string, file []byte) *httptest.ResponseRecorder {
	u.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if token != "" {
		mw.WriteField("csrf_token", token)
	}
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	for _, tg := range tags {
		mw.WriteField("tag", tg)
	}
	if file != nil {
		fw, _ := mw.CreateFormFile("file", "shot.png")
		fw.Write(file)
	}
	mw.Close()
	r := httptest.NewRequest("POST", path, &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Host, r.RemoteAddr = "127.0.0.1:8443", "127.0.0.1:5000"
	if u.cookie != nil {
		r.AddCookie(u.cookie)
	}
	w := httptest.NewRecorder()
	u.h.ServeHTTP(w, r)
	return w
}

func pngBytes(t *testing.T) []byte {
	img := image.NewRGBA(image.Rect(0, 0, 60, 30))
	for x := 0; x < 60; x++ {
		img.Set(x, 10, color.RGBA{255, 0, 0, 255})
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// seedChain stores the web shell attack, alerts on it and traces it back; it
// returns the chain id.
func seedChain(t *testing.T, c *Controller, u *uiClient, tok string) int64 {
	t.Helper()
	f := &evFeeder{t: t, c: c, seq: map[string]uint64{}, prev: map[string]string{}}
	t0 := time.Date(2027, 3, 6, 15, 0, 0, 0, time.UTC)
	f.add("ecom", t0, "net.connection_opened", map[string]any{"dir": "inbound", "proto": "tcp", "laddr": "10.0.1.10", "lport": 80,
		"raddr": "198.51.100.7", "rport": 51000, "service": "http", "community_id": "1:abc", "pid": 800, "pid_start": 5000, "comm": "apache2", "exe": "/usr/sbin/apache2"})
	f.add("ecom", t0.Add(200*time.Millisecond), "process_start", map[string]any{"pid": 901, "ppid": 800, "exe": "/bin/sh",
		"cmdline": "sh -c echo pwn > uploads/x.php", "start_ticks": 5100, "parent": map[string]any{"pid": 800, "exe": "/usr/sbin/apache2"}, "pexe": "/usr/sbin/apache2"})
	ev := f.add("ecom", t0.Add(400*time.Millisecond), "file_change", map[string]any{"op": "create", "path": "/var/www/html/uploads/x.php",
		"pid": 901, "exe": "/bin/sh", "writer_start_ticks": 5100, "source": "audit"})
	id, err := c.RecordAlert(context.Background(), detect.Alert{RuleID: "W1.webshell", Title: "Web shell written", Severity: "high", Agent: "ecom",
		Time: ev.Time, Message: "uploads/x.php created by sh", Evidence: []event.Event{ev}})
	if err != nil {
		t.Fatal(err)
	}
	w := u.do("POST", "/alerts/"+itoa(id)+"/trace", url.Values{"csrf_token": {tok}})
	if w.Code != 303 {
		t.Fatalf("trace: %d %s", w.Code, w.Body)
	}
	return 1
}

var whatRE = regexp.MustCompile(`name="what" value="([^"]*)"`)

func pdfText(t *testing.T, b []byte) string {
	t.Helper()
	pages, err := report.ExtractText(b)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(pages, "\n")
}

// The IR flow: draft from a chain, review with placeholders and rubric, no
// download while placeholders remain, fill and attach a screenshot, validate,
// download incidentNN_teamTT.pdf whose text carries what the operator typed.
func TestUIIRDraftFillValidateDownload(t *testing.T) {
	c, _, u, tok := newReportUITest(t)
	chain := seedChain(t, c, u, tok)

	// The chain page offers the draft action.
	if !strings.Contains(u.do("GET", "/chains/1", nil).Body.String(), `action="/reports/ir"`) {
		t.Error("chain page has no Draft IR button")
	}
	w := u.do("POST", "/reports/ir", url.Values{"csrf_token": {tok}, "chain": {itoa(chain)}})
	if w.Code != 303 || w.Header().Get("Location") != "/reports/1" {
		t.Fatalf("draft: %d %q %s", w.Code, w.Header().Get("Location"), w.Body)
	}
	page := u.do("GET", "/reports/1", nil)
	body := page.Body.String()
	if page.Code != 200 {
		t.Fatalf("review: %d %s", page.Code, body)
	}
	for _, want := range []string{"incident03_team07.pdf", "Rubric self-score", "WK-proof", "operator-only", "PB-screenshots", "Placeholders (", "Download is blocked",
		"Phylax detection rule W1.webshell", "198.51.100.7"} {
		if !strings.Contains(body, want) {
			t.Errorf("review page lacks %q", want)
		}
	}
	whats := whatRE.FindAllStringSubmatch(body, -1)
	if len(whats) == 0 {
		t.Fatalf("no placeholders listed:\n%s", body)
	}

	// Blocked while placeholders remain.
	if d := u.do("GET", "/reports/1/download", nil); d.Code != 409 || d.Header().Get("Content-Type") == "application/pdf" {
		t.Fatalf("download with placeholders: %d %s", d.Code, d.Body)
	}

	// Screenshot upload (token inside the multipart body), hashed and stored.
	shot := pngBytes(t)
	if bad := u.multipart("/reports/1/upload", "", map[string]string{"host": "ecom"}, nil, shot); bad.Code != 403 {
		t.Fatalf("upload without csrf: %d", bad.Code)
	}
	if bad := u.multipart("/reports/1/upload", tok, nil, nil, []byte("GIF89a not a png")); bad.Code != 400 {
		t.Fatalf("non-image upload: %d %s", bad.Code, bad.Body)
	}
	up := u.multipart("/reports/1/upload", tok, map[string]string{"host": "ecom", "caption": "access log shows 198.51.100.7 posting x.php",
		"taken": "2027-03-06 09:01", "annotated": "1"}, []string{"red_activity", "vuln"}, shot)
	if up.Code != 303 {
		t.Fatalf("upload: %d %s", up.Code, up.Body)
	}
	if !strings.Contains(u.do("GET", "/reports/1", nil).Body.String(), "access log shows 198.51.100.7 posting x.php") {
		t.Error("figure not listed")
	}

	// Fill the structured fields and every remaining placeholder.
	form := url.Values{"csrf_token": {tok},
		"f_detect_time": {"2027-03-06 09:05"}, "f_detect_method": {"Phylax rule W1.webshell fired on ecom"},
		"f_downtime": {"none"}, "f_remediation_time": {"2027-03-06 09:40"},
		"f_data":          {"Zebra-quartz-7: web root readable by the shell, no database credentials were present"},
		"f_service_check": {"ecom http green on the Up/Down table at 09:42 Central"},
		"f_containment":   {"2027-03-06 09:30 | removed uploads/x.php and the cron entry"},
		"f_verification":  {"2027-03-06 09:41 | replayed the upload request | now returns 403 | 1"},
		"f_prevention":    {"disable PHP execution in uploads"},
	}
	for i, m := range whats {
		form.Add("what", html.UnescapeString(m[1]))
		form.Add("fill", fmt.Sprintf("filled value %d", i))
	}
	if w := u.do("POST", "/reports/1/save", form); w.Code != 303 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	if bad := u.do("POST", "/reports/1/save", url.Values{"csrf_token": {tok}, "f_remediation_time": {"yesterday-ish"}}); bad.Code != 400 {
		t.Errorf("unparseable time accepted: %d", bad.Code)
	}
	body = u.do("GET", "/reports/1", nil).Body.String()
	if strings.Contains(body, "Download is blocked") {
		i := strings.Index(body, `id="validation"`)
		t.Fatalf("still blocked after filling:\n%s", body[i:min(len(body), i+3500)])
	}
	if !strings.Contains(body, "All required checks pass") {
		t.Fatalf("no pass banner")
	}
	if w := u.do("POST", "/reports/1/validate", url.Values{"csrf_token": {tok}}); w.Code != 303 {
		t.Fatalf("validate: %d", w.Code)
	}

	d := u.do("GET", "/reports/1/download", nil)
	if d.Code != 200 || d.Header().Get("Content-Type") != "application/pdf" ||
		!strings.Contains(d.Header().Get("Content-Disposition"), `filename="incident03_team07.pdf"`) {
		t.Fatalf("download: %d %v %.200s", d.Code, d.Header(), d.Body)
	}
	pdf, _ := io.ReadAll(d.Body)
	text := pdfText(t, pdf)
	for _, want := range []string{"Zebra-quartz-7", "Incident Report 3", "Team 07", "198.51.100.7", "filled value 0", "now returns 403", "Phylax rule W1.webshell fired on ecom", "access log shows 198.51.100.7 posting x.php"} {
		if !strings.Contains(text, want) {
			t.Errorf("PDF text lacks %q", want)
		}
	}
	if strings.Contains(text, "[[FILL") {
		t.Error("PDF still has a placeholder")
	}
	v := report.ValidateSubmission(pdf, report.SubmitSpec{Kind: report.KindIR, Number: 3, Team: 7, Filename: "incident03_team07.pdf"})
	if !v.OK() {
		t.Errorf("independent validation: %+v", v.Failures())
	}

	// A changed screenshot file blocks the download.
	files, _ := filepath.Glob(filepath.Join(c.cfg.DataDir, "reports", "1", "*.png"))
	if len(files) != 1 {
		t.Fatalf("stored screenshots: %v", files)
	}
	if err := writeFileBytes(files[0], append(shot[:len(shot):len(shot)], 0)); err != nil {
		t.Fatal(err)
	}
	if d := u.do("GET", "/reports/1/download", nil); d.Code != 409 || !strings.Contains(d.Body.String(), "no longer matches") {
		t.Errorf("tampered figure: %d %s", d.Code, d.Body)
	}

	// Forbidden word (the school name) blocks it too.
	rows, _ := c.Store().Audit(context.Background(), 200)
	have := map[string]bool{}
	for _, r := range rows {
		have[r.Action] = true
	}
	for _, a := range []string{"ir_draft", "report_upload", "report_save", "report_validate", "report_download"} {
		if !have[a] {
			t.Errorf("audit lacks %q", a)
		}
	}
}

func TestUIIRNeedsTeamAndSplitsNumbers(t *testing.T) {
	c := newBareController(t, filepath.Join(t.TempDir(), "data"))
	defer c.Close()
	_, ops, err := c.NewUI(UIOptions{Addr: "127.0.0.1:8443"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ops.NewIR(context.Background(), 1, 0, "x"); err == nil || !strings.Contains(err.Error(), "team number") {
		t.Fatalf("draft without team: %v", err)
	}
	if _, err := ops.NewInject(context.Background(), "memo", 0, "I1", "t", "x"); err == nil {
		t.Fatal("inject without team")
	}
}

func TestUIInjectFlow(t *testing.T) {
	c, _, u, tok := newReportUITest(t)
	f := &evFeeder{t: t, c: c, seq: map[string]uint64{}, prev: map[string]string{}}
	t0 := time.Date(2027, 3, 6, 16, 0, 0, 0, time.UTC)
	f.add("ecom", t0, "file_change", map[string]any{"op": "modify", "path": "/etc/ssh/sshd_config"})
	f.add("ecom", t0.Add(time.Minute), "process_start", map[string]any{"exe": "/usr/sbin/sshd"})

	w := u.do("POST", "/reports/inject", url.Values{"csrf_token": {tok}, "kind": {"config-memo"}, "number": {"0"}, "code": {"HARD-2"}, "title": {"Harden SSH"}})
	if w.Code != 303 || w.Header().Get("Location") != "/reports/1" {
		t.Fatalf("new inject: %d %s", w.Code, w.Body)
	}
	if w := u.do("POST", "/reports/inject", url.Values{"csrf_token": {tok}, "kind": {"nope"}}); w.Code != 400 {
		t.Errorf("bad kind: %d", w.Code)
	}
	page := u.do("GET", "/reports/1", nil).Body.String()
	for _, want := range []string{"inject05_team07.pdf", "tpl_summary", "tpl_impl_linux", "Hosts and devices", "Download is blocked"} {
		if !strings.Contains(page, want) {
			t.Errorf("inject page lacks %q", want)
		}
	}
	if d := u.do("GET", "/reports/1/download", nil); d.Code != 409 {
		t.Fatalf("blocked download: %d", d.Code)
	}

	// Per-host evidence from the stored events.
	if bad := u.do("POST", "/reports/1/hostevidence", url.Values{"csrf_token": {tok}, "host": {"nonesuch"}}); bad.Code != 400 {
		t.Errorf("unknown host: %d", bad.Code)
	}
	if w := u.do("POST", "/reports/1/hostevidence", url.Values{"csrf_token": {tok}, "host": {"ecom"}, "limit": {"5"},
		"caption": {"sshd_config change recorded by the file integrity watch"}}); w.Code != 303 {
		t.Fatalf("host evidence: %d %s", w.Code, w.Body)
	}

	long := strings.Repeat("The change was applied and tested from outside the host. ", 4)
	form := url.Values{"csrf_token": {tok}, "f_number": {"5"}, "f_code": {"HARD-2"}, "f_title": {"Harden SSH"},
		"f_hosts": {"ecom | web store | Rocky 9 | PermitRootLogin no | sshd_config edit | ssh -l root refused | linux"}}
	for _, k := range []string{"to", "from", "summary", "impl_linux", "impl_windows", "impl_network", "verification", "exceptions", "next_steps"} {
		form.Set("f_tpl_"+k, "Quartz-"+k+" "+long)
	}
	if w := u.do("POST", "/reports/1/save", form); w.Code != 303 {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	body := u.do("GET", "/reports/1", nil).Body.String()
	whats := whatRE.FindAllStringSubmatch(body, -1)
	if strings.Contains(body, "Download is blocked") && len(whats) > 0 {
		form2 := url.Values{"csrf_token": {tok}}
		for _, m := range whats {
			form2.Add("what", html.UnescapeString(m[1]))
			form2.Add("fill", "Fill-"+long)
		}
		u.do("POST", "/reports/1/save", form2)
		body = u.do("GET", "/reports/1", nil).Body.String()
	}
	if strings.Contains(body, "Download is blocked") {
		i := strings.Index(body, `id="validation"`)
		t.Fatalf("inject blocked:\n%s", body[i:min(len(body), i+3000)])
	}
	d := u.do("GET", "/reports/1/download", nil)
	if d.Code != 200 || !strings.Contains(d.Header().Get("Content-Disposition"), "inject05_team07.pdf") {
		t.Fatalf("download: %d %s", d.Code, d.Body)
	}
	pdf, _ := io.ReadAll(d.Body)
	text := pdfText(t, pdf)
	if !strings.HasPrefix(strings.TrimSpace(text), "Inject 5") {
		t.Errorf("inject number is not first: %.80q", text)
	}
	for _, want := range []string{"Quartz-summary", "PermitRootLogin no", "sshd_config change recorded", "file_change", "HARD-2"} {
		if !strings.Contains(text, want) {
			t.Errorf("PDF lacks %q", want)
		}
	}
	if regexp.MustCompile(`(?i)team\s*0?7`).MatchString(text) {
		t.Error("team number leaked into the body")
	}
	// The team number inside the body fails validation.
	form.Set("f_tpl_next_steps", "Team 07 will review")
	u.do("POST", "/reports/1/save", form)
	if d := u.do("GET", "/reports/1/download", nil); d.Code != 409 || !strings.Contains(d.Body.String(), "team number") {
		t.Errorf("team number in body: %d %s", d.Code, d.Body)
	}
	// And the school name does.
	form.Set("f_tpl_next_steps", "Hogwarts review")
	u.do("POST", "/reports/1/save", form)
	if d := u.do("GET", "/reports/1/download", nil); d.Code != 409 || !strings.Contains(d.Body.String(), "school name") {
		t.Errorf("school name in body: %d %s", d.Code, d.Body)
	}
	// Evidence removal.
	if w := u.do("POST", "/reports/1/evidence/9/delete", url.Values{"csrf_token": {tok}}); w.Code != 404 {
		t.Errorf("remove missing figure: %d", w.Code)
	}
	if w := u.do("POST", "/reports/1/evidence/1/delete", url.Values{"csrf_token": {tok}}); w.Code != 303 {
		t.Errorf("remove figure: %d", w.Code)
	}
}

// Every new route refuses an anonymous request, and every state change
// refuses a session without the CSRF token.
func TestUIReportRoutesAuthAndCSRF(t *testing.T) {
	c, _, u, tok := newReportUITest(t)
	chain := seedChain(t, c, u, tok)
	u.do("POST", "/reports/ir", url.Values{"csrf_token": {tok}, "chain": {itoa(chain)}})
	posts := []string{"/reports/ir", "/reports/inject", "/reports/1/save", "/reports/1/validate", "/reports/1/upload", "/reports/1/hostevidence", "/reports/1/evidence/1/delete"}
	gets := []string{"/reports", "/reports/1", "/reports/1/download", "/checks", "/checks/x", "/health", "/audit"}
	anon := &uiClient{t: t, h: u.h}
	for _, p := range gets {
		if w := anon.do("GET", p, nil); w.Code != 303 || w.Header().Get("Location") != "/login" {
			t.Errorf("anonymous GET %s: %d", p, w.Code)
		}
		if w := u.do("GET", p, nil); w.Code == 303 && w.Header().Get("Location") == "/login" {
			t.Errorf("authenticated GET %s bounced to login", p)
		}
	}
	for _, p := range posts {
		if w := anon.do("POST", p, url.Values{"chain": {"1"}}); w.Code != 401 && w.Code != 403 {
			t.Errorf("anonymous POST %s: %d", p, w.Code)
		}
		if w := u.do("POST", p, url.Values{"chain": {"1"}}); w.Code != 403 {
			t.Errorf("POST %s without csrf: %d", p, w.Code)
		}
		if w := u.do("POST", p, url.Values{"chain": {"1"}, "csrf_token": {"wrong"}}); w.Code != 403 {
			t.Errorf("POST %s with a wrong csrf: %d", p, w.Code)
		}
	}
	if w := u.multipart("/reports/1/upload", "wrong", nil, nil, pngBytes(t)); w.Code != 403 {
		t.Errorf("multipart wrong csrf: %d", w.Code)
	}
	// Oversized uploads are cut off.
	if w := u.multipart("/reports/1/upload", tok, nil, nil, bytes.Repeat([]byte{0x89}, 9<<20)); w.Code == 303 || w.Code == 200 {
		t.Errorf("oversized upload accepted: %d", w.Code)
	}
}

// Probe results from both vantages are stored with history, drive SLA streaks
// and reach the dashboard through SetScorer.
func TestUIChecksFeedScorer(t *testing.T) {
	c, ops, u, tok := newReportUITest(t)
	_ = tok
	ctx := context.Background()
	if v := u.do("GET", "/checks", nil).Body.String(); !strings.Contains(v, "No check results yet") {
		t.Errorf("empty checks page: %s", v)
	}

	// Probe library against a real listener on the controller's vantage.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener: ", err)
	}
	go func() {
		for {
			cn, err := ln.Accept()
			if err != nil {
				return
			}
			cn.Close()
		}
	}()
	spec := probe.Spec{ID: "web:tcp", Type: probe.TCP, Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
	res, err := c.Checks().RunProbe(ctx, spec, probe.Options{Timeout: 2 * time.Second})
	if err != nil || !res.OK {
		t.Fatalf("probe: %+v %v", res, err)
	}
	d := u.do("GET", "/", nil).Body.String()
	if strings.Contains(d, "no scorer data") || !strings.Contains(d, ">web<") {
		t.Fatalf("dashboard has no SLA row after a probe result: %s", d)
	}
	ln.Close()
	for i := 0; i < 4; i++ {
		res, err = c.Checks().RunProbe(ctx, spec, probe.Options{Timeout: time.Second})
		if err != nil || res.OK {
			t.Fatalf("probe against a closed port: %+v %v", res, err)
		}
	}
	if s := c.Checks().SLA().Streak("web"); s != 4 {
		t.Fatalf("streak %d, want 4", s)
	}
	d = u.do("GET", "/", nil).Body.String()
	if !strings.Contains(d, "sla-critical") {
		t.Errorf("dashboard streak not critical: %s", d)
	}

	// vantage.check events from the Kali agent, through the real ingest.
	f := &evFeeder{t: t, c: c, seq: map[string]uint64{}, prev: map[string]string{}}
	at := time.Now().UTC().Add(-time.Minute)
	for i := 0; i < 3; i++ {
		f.add("kali", at.Add(time.Duration(i)*time.Second), "vantage.check", map[string]any{"id": "dns:udp", "type": "dns", "host": "10.0.0.2", "port": 53,
			"mode": "faithful", "ok": false, "scorer_ok": false, "class": "timeout", "err": "no answer", "elapsed_ms": 2000})
	}
	f.add("kali", at.Add(10*time.Second), "vantage.check", map[string]any{"id": "dns:udp", "type": "dns", "mode": "sweep", "ok": false, "scorer_ok": false, "class": "content", "item": "mx"})
	if s := c.Checks().SLA().Streak("dns"); s != 3 {
		t.Fatalf("dns streak %d, want 3 (sweep runs do not count)", s)
	}
	page := u.do("GET", "/checks", nil).Body.String()
	for _, want := range []string{"web", "dns", "kali", "controller", "timeout", "no answer", "/checks/web:tcp", "sla-"} {
		if !strings.Contains(page, want) {
			t.Errorf("checks page lacks %q:\n%s", want, page)
		}
	}
	hist := u.do("GET", "/checks/dns:udp", nil)
	if hist.Code != 200 || strings.Count(hist.Body.String(), "<tr><td>20") < 4 || !strings.Contains(hist.Body.String(), "sweep") {
		t.Errorf("history: %d %s", hist.Code, hist.Body)
	}
	if u.do("GET", "/checks/none", nil).Code != 404 {
		t.Error("unknown check is not 404")
	}
	// SetScorer by someone else is not overridden by later results.
	other := scorerForTest()
	ops.SetScorer(nil, other, func() []string { return []string{"other"} })
	c.Checks().observe("web", false)
	if d := u.do("GET", "/", nil).Body.String(); !strings.Contains(d, ">other<") || strings.Contains(d, ">dns<") {
		t.Errorf("hub overrode an explicit SetScorer: %s", d)
	}
	// The streak survives a restart: rebuilt from stored results.
	c2 := newBareControllerAt(t, c.cfg.DataDir, c)
	if s := c2.Checks().SLA().Streak("dns"); s != 3 {
		t.Errorf("rebuilt dns streak %d, want 3", s)
	}
}

func TestUIHealthAndAudit(t *testing.T) {
	c, _, u, tok := newReportUITest(t)
	f := &evFeeder{t: t, c: c, seq: map[string]uint64{}, prev: map[string]string{}}
	f.add("ecom", time.Now(), "heartbeat", map[string]any{})
	c.state("ecom").mu.Lock()
	c.state("ecom").hb.ClockSkew = 9 * time.Second
	c.state("ecom").hb.SpoolDepth = 1234
	c.state("ecom").hb.Modules = map[string]string{"audit": "ok", "capture": "error: no cap_net_raw", "config": "applied"}
	c.state("ecom").hb.Drops = 17
	c.state("ecom").mu.Unlock()

	h := u.do("GET", "/health", nil)
	body := h.Body.String()
	if h.Code != 200 {
		t.Fatalf("health: %d %s", h.Code, body)
	}
	for _, want := range []string{"ecom", "1234", "9s", "capture: error: no cap_net_raw", "clock is 9s", "Database", "Stored events", "Open alerts"} {
		if !strings.Contains(body, want) {
			t.Errorf("health lacks %q", want)
		}
	}
	if strings.Contains(body, "audit: ok") {
		t.Error("a healthy module is listed as an error")
	}

	// Audit viewer: filters and pagination.
	for i := 0; i < 60; i++ {
		u.do("POST", "/alerts/1/state", url.Values{"csrf_token": {tok}, "state": {"acked"}})
	}
	for i := 0; i < 5; i++ {
		_ = c.Store().AppendAudit(context.Background(), storeAuditRow("bob", "plan_apply", fmt.Sprintf("p%d", i)))
	}
	a := u.do("GET", "/audit", nil)
	ab := a.Body.String()
	if a.Code != 200 || !strings.Contains(ab, "Older entries") || !strings.Contains(ab, "bob") {
		t.Fatalf("audit: %d %s", a.Code, ab[:min(len(ab), 600)])
	}
	m := regexp.MustCompile(`before=(\d+)`).FindStringSubmatch(ab)
	if m == nil {
		t.Fatal("no older cursor")
	}
	older := u.do("GET", "/audit?before="+m[1], nil).Body.String()
	if strings.Contains(older, "<td>bob</td>") || !strings.Contains(older, "<td>request</td>") {
		t.Errorf("second page: %s", older[strings.Index(older, "<h1>"):])
	}
	onlyBob := u.do("GET", "/audit?actor=bob&action=plan_apply", nil).Body.String()
	if strings.Count(onlyBob, "<td>bob</td>") != 5 || strings.Contains(onlyBob, "admin</td>") || strings.Contains(onlyBob, "Older entries") {
		t.Errorf("filtered audit: %s", onlyBob)
	}
	if got := u.do("GET", "/audit?actor=%3Cscript%3E", nil).Body.String(); strings.Contains(got, "<script>") {
		t.Error("audit filter echoed unescaped")
	}
}

func writeFileBytes(p string, b []byte) error { return os.WriteFile(p, b, 0o600) }

func scorerForTest() *scorer.SLATracker { return scorer.NewSLATracker(scorer.SLAConfig{Threshold: 5}) }

func storeAuditRow(actor, action, detail string) store.AuditRow {
	return store.AuditRow{Time: time.Now(), Actor: actor, Action: action, Remote: "127.0.0.1", Detail: detail}
}

// newBareControllerAt reopens the data directory of an existing controller.
func newBareControllerAt(t *testing.T, dir string, _ *Controller) *Controller {
	t.Helper()
	cfg := Config{AgentListen: "127.0.0.1:0", DataDir: dir}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	c, err := New(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
