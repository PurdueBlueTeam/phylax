package traceback

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/traceback/tbtest"
)

var t0 = time.Date(2027, 3, 6, 15, 0, 0, 0, time.UTC)

const sec = time.Second

func link(r *Result, name string) *Link {
	for i := range r.Links {
		if r.Links[i].Name == name {
			return &r.Links[i]
		}
	}
	return nil
}

func inbound(pid, ticks int, raddr string, rport int, cid string) map[string]any {
	return map[string]any{"dir": "inbound", "proto": "tcp", "laddr": "10.0.1.10", "lport": 80, "raddr": raddr, "rport": rport,
		"service": "http", "community_id": cid, "pid": pid, "pid_start": ticks, "comm": "apache2", "exe": "/usr/sbin/apache2"}
}

// webshell scenario: red-team-ttps web-app compromise. A forked apache worker
// (no process_start of its own) serves a request that spawns sh, which writes
// a PHP file under the webroot.
func webshell(t *testing.T) (*tbtest.Fixture, Trigger) {
	f := tbtest.New(t, t0)
	f.Add("ecom", 0, "net.connection_opened", inbound(700, 4000, "203.0.113.5", 40000, "1:old"))
	f.Add("ecom", 100*sec, "net.connection_opened", inbound(800, 5000, "198.51.100.7", 51000, "1:abc"))
	f.Add("ecom", 100*sec+200*time.Millisecond, "process_start", map[string]any{
		"pid": 901, "ppid": 800, "exe": "/bin/sh", "image": "/bin/sh", "cmdline": "sh -c echo '<?php system($_GET[1]);' > uploads/x.php",
		"start_ticks": 5100, "parent": map[string]any{"pid": 800, "exe": "/usr/sbin/apache2", "comm": "apache2"}, "pexe": "/usr/sbin/apache2", "source": "audit"})
	ev := f.Add("ecom", 100*sec+400*time.Millisecond, "file_change", map[string]any{
		"op": "create", "path": "/var/www/html/uploads/x.php", "pid": 901, "exe": "/bin/sh", "writer_start_ticks": 5100, "source": "audit"})
	// What else the source did, on other hosts and earlier.
	f.Add("ecom", 60*sec, "auth_fail", map[string]any{"account": "admin", "source": "198.51.100.7", "service": "http"})
	f.Add("ecom", 61*sec, "auth_fail", map[string]any{"account": "admin", "source": "198.51.100.7", "service": "http"})
	f.Add("ecom", 62*sec, "auth_fail", map[string]any{"account": "admin", "source": "198.51.100.7", "service": "http"})
	f.Add("mail", 30*sec, "net.connection_opened", map[string]any{"dir": "inbound", "proto": "tcp", "laddr": "10.0.1.20", "lport": 25,
		"raddr": "198.51.100.7", "rport": 33333, "service": "smtp", "community_id": "1:scan"})
	f.Add("mail", 40*sec, "net.connection_opened", map[string]any{"dir": "inbound", "proto": "tcp", "laddr": "10.0.1.20", "lport": 25,
		"raddr": "192.0.2.99", "rport": 33334, "service": "smtp", "community_id": "1:other"})
	return f, Trigger{Reason: "file_change", Event: &ev}
}

func TestWebshellTracedToHTTPSource(t *testing.T) {
	f, trig := webshell(t)
	tr := &Tracer{Src: f.Store, Cfg: Config{Label: func(a string) string {
		if a == "198.51.100.7" {
			return "other"
		}
		return ""
	}}}
	res, err := tr.Trace(f.Ctx, trig)
	if err != nil {
		t.Fatal(err)
	}
	if b := res.Breaks(); len(b) != 0 {
		t.Fatalf("unexpected breaks: %v", b)
	}
	if res.Source == nil || res.Source.Addr != "198.51.100.7" || res.Source.Port != 51000 || res.Source.Label != "other" || res.Source.CID != "1:abc" {
		t.Fatalf("source = %+v", res.Source)
	}
	w := link(res, "change<-writer")
	if w.Confidence != 1 || !strings.Contains(w.Note, "start time") {
		t.Errorf("writer link %+v", w)
	}
	req := link(res, "lineage<-request")
	// sh does not own the socket; its parent (the worker) does, with start ticks matching nothing known for the
	// forked parent, so confidence is the pid-only ancestor value.
	if req.Method != MethodLineage || req.Confidence < 0.7 || req.Confidence > 0.9 {
		t.Errorf("request link %+v", req)
	}
	if !strings.Contains(req.Note, "apache2") {
		t.Errorf("request note %q", req.Note)
	}
	// The older connection by another pid must not be chosen.
	if len(res.Lineage) != 2 || res.Lineage[1].PID != 800 {
		t.Errorf("lineage = %d entries", len(res.Lineage))
	}
	// Source activity: failed logins grouped, the mail scan present, the other source absent.
	var fails, scans, others int
	for _, e := range res.Timeline {
		if e.Role != "activity" {
			continue
		}
		switch {
		case strings.Contains(e.Summary, "login failed") && strings.Contains(e.Summary, "x3"):
			fails++
		case e.Host == "mail" && strings.Contains(e.Summary, "198.51.100.7"):
			scans++
		case strings.Contains(e.Summary, "192.0.2.99"):
			others++
		}
	}
	if fails != 1 || scans != 1 || others != 0 {
		t.Errorf("activity fails=%d scans=%d others=%d: %+v", fails, scans, others, res.Timeline)
	}
	for i := 1; i < len(res.Timeline); i++ {
		if res.Timeline[i].Time.Before(res.Timeline[i-1].Time) {
			t.Fatal("timeline not chronological")
		}
	}
	if len(res.Freeze) == 0 || res.Files[0].Path != "/var/www/html/uploads/x.php" {
		t.Errorf("evidence: %+v %+v", res.Freeze, res.Files)
	}
}

func TestOwnerWithStartTicksIsExact(t *testing.T) {
	f := tbtest.New(t, t0)
	f.Add("web", 0, "net.connection_opened", inbound(800, 5000, "198.51.100.7", 51000, "1:abc"))
	ev := f.Add("web", 5*sec, "file_change", map[string]any{"op": "write", "path": "/var/www/a.php", "pid": 800, "exe": "/usr/sbin/apache2", "writer_start_ticks": 5000})
	res, err := (&Tracer{Src: f.Store}).Trace(f.Ctx, Trigger{Event: &ev})
	if err != nil {
		t.Fatal(err)
	}
	req := link(res, "lineage<-request")
	if req.Method != MethodSocket || req.Confidence < 0.9 {
		t.Fatalf("%+v", req)
	}
}

func TestPidReuseRejected(t *testing.T) {
	f := tbtest.New(t, t0)
	// The connection belongs to an earlier process that reused pid 800 (other start ticks).
	f.Add("web", 0, "net.connection_opened", inbound(800, 4444, "198.51.100.7", 51000, "1:abc"))
	ev := f.Add("web", 5*sec, "file_change", map[string]any{"op": "write", "path": "/var/www/a.php", "pid": 800, "exe": "/usr/sbin/apache2", "writer_start_ticks": 5000})
	res, _ := (&Tracer{Src: f.Store}).Trace(f.Ctx, Trigger{Event: &ev})
	req := link(res, "lineage<-request")
	if req.Method != MethodTimeWindow {
		t.Fatalf("pid reuse should fall back to time window, got %+v", req)
	}
}

func TestTimeWindowFallbackLowerConfidence(t *testing.T) {
	f := tbtest.New(t, t0)
	// php-fpm style: connections carry no owner for the writer.
	one := map[string]any{"dir": "inbound", "proto": "tcp", "laddr": "10.0.1.10", "lport": 80, "raddr": "198.51.100.7", "rport": 1, "service": "http", "community_id": "1:a"}
	f.Add("web", 10*sec, "net.connection_opened", one)
	ev := f.Add("web", 12*sec, "file_change", map[string]any{"op": "create", "path": "/var/www/a.php", "pid": 55, "exe": "/bin/sh"})
	res, _ := (&Tracer{Src: f.Store}).Trace(f.Ctx, Trigger{Event: &ev})
	req := link(res, "lineage<-request")
	if req.Method != MethodTimeWindow || req.Confidence != 0.5 {
		t.Fatalf("single candidate: %+v", req)
	}
	if w := link(res, "change<-writer"); w.Confidence >= 1 || !strings.Contains(w.Note, "no process_start") {
		t.Errorf("writer link %+v", w)
	}

	f2 := tbtest.New(t, t0)
	for i, a := range []string{"198.51.100.7", "203.0.113.9"} {
		m := map[string]any{"dir": "inbound", "proto": "tcp", "laddr": "10.0.1.10", "lport": 80, "raddr": a, "rport": 1, "service": "http", "community_id": "1:x"}
		f2.Add("web", time.Duration(10+i)*sec, "net.connection_opened", m)
	}
	ev = f2.Add("web", 12*sec, "file_change", map[string]any{"op": "create", "path": "/var/www/a.php", "pid": 55, "exe": "/bin/sh"})
	res, _ = (&Tracer{Src: f2.Store}).Trace(f2.Ctx, Trigger{Event: &ev})
	req = link(res, "lineage<-request")
	if req.Confidence != 0.3 || !strings.Contains(req.Note, "closest of 2") {
		t.Fatalf("ambiguous: %+v", req)
	}
	if res.Confidence != 0.3 {
		t.Errorf("overall confidence %v", res.Confidence)
	}
}

func TestLoopbackFrontEnd(t *testing.T) {
	f := tbtest.New(t, t0)
	f.Add("web", 9*sec, "net.connection_opened", map[string]any{"dir": "inbound", "proto": "tcp", "laddr": "10.0.1.10", "lport": 443, "raddr": "198.51.100.7", "rport": 7, "service": "https", "community_id": "1:ext"})
	f.Add("web", 10*sec, "net.connection_opened", map[string]any{"dir": "inbound", "proto": "tcp", "laddr": "127.0.0.1", "lport": 9000, "raddr": "127.0.0.1", "rport": 5555, "community_id": "1:loop", "pid": 60, "pid_start": 1})
	ev := f.Add("web", 11*sec, "file_change", map[string]any{"op": "create", "path": "/var/www/a.php", "pid": 60, "exe": "/usr/sbin/php-fpm", "writer_start_ticks": 1})
	res, _ := (&Tracer{Src: f.Store}).Trace(f.Ctx, Trigger{Event: &ev})
	fe := link(res, "request<-frontend")
	if fe == nil || fe.Method != MethodTimeWindow || fe.Confidence > 0.4 {
		t.Fatalf("front-end link %+v", fe)
	}
	if res.Source == nil || res.Source.Addr != "198.51.100.7" {
		t.Fatalf("source %+v", res.Source)
	}
}

func TestChainBreaksNameTheMissingLink(t *testing.T) {
	// Sweep-detected change: no writer.
	f := tbtest.New(t, t0)
	ev := f.Add("web", 5*sec, "file_change", map[string]any{"op": "modify", "path": "/var/www/index.php", "source": "sweep"})
	res, err := (&Tracer{Src: f.Store}).Trace(f.Ctx, Trigger{Event: &ev})
	if err != nil {
		t.Fatal(err)
	}
	b := res.Breaks()
	if len(b) != 1 || !strings.Contains(b[0], "change<-writer") || !strings.Contains(b[0], "no writer") {
		t.Fatalf("breaks %v", b)
	}
	if res.Confidence != 0 && res.Source != nil {
		t.Errorf("no source expected")
	}

	// Writer known, no inbound connection at all, and an agent gap nearby.
	f = tbtest.New(t, t0)
	f.Add("web", 0, "process_start", map[string]any{"pid": 9, "ppid": 1, "exe": "/bin/bash", "start_ticks": 9})
	f.Gap("web", 3*sec, 40)
	ev = f.Add("web", 5*sec, "file_change", map[string]any{"op": "create", "path": "/var/www/a.php", "pid": 9, "exe": "/bin/bash", "writer_start_ticks": 9})
	res, _ = (&Tracer{Src: f.Store}).Trace(f.Ctx, Trigger{Event: &ev})
	b = res.Breaks()
	if len(b) != 1 || !strings.Contains(b[0], "lineage<-request") || !strings.Contains(b[0], "telemetry gap") || !strings.Contains(b[0], "40 events") {
		t.Fatalf("breaks %v", b)
	}
	if res.Source != nil {
		t.Error("no source should be claimed")
	}
}

func TestTaggedFileChangeStillTraced(t *testing.T) {
	f := tbtest.New(t, t0)
	f.Add("web", 0, "net.connection_opened", inbound(800, 5000, "198.51.100.7", 51000, "1:abc"))
	// A change that carries a tag is still a trace source: the tag labels it,
	// it never hides it (R6).
	f.Add("web", 5*sec, "file_change", map[string]any{"op": "write", "path": "/var/www/a.php", "pid": 800, "exe": "/usr/sbin/apache2", "writer_start_ticks": 5000, "tag": "window:w1"})
	res, err := (&Tracer{Src: f.Store}).Trace(f.Ctx, Trigger{Reason: "red_check:http", Agent: "web", Time: t0.Add(10 * sec)})
	if err != nil {
		t.Fatal(err)
	}
	picked := false
	for _, e := range res.Timeline {
		if e.Role == "change" && strings.Contains(e.Summary, "a.php") {
			picked = true
		}
	}
	if !picked {
		t.Fatalf("tagged change was skipped: timeline %+v links %+v", res.Timeline, res.Links)
	}
	if req := link(res, "lineage<-request"); req == nil || req.Method != MethodSocket {
		t.Fatalf("trace stopped at the tagged change: %+v", req)
	}
}

func TestRedCheckTriggerFindsLatestChange(t *testing.T) {
	f, _ := webshell(t)
	// A tagged (our own) change after the red check is still a source: the
	// latest change wins whether or not it carries a tag (R6).
	f.Add("ecom", 120*sec, "file_change", map[string]any{"op": "write", "path": "/etc/apache2/ours.conf", "pid": 1, "tag": "plan-7"})
	res, err := (&Tracer{Src: f.Store}).Trace(f.Ctx, Trigger{Reason: "red_check:http", Agent: "ecom", Time: t0.Add(130 * sec)})
	if err != nil {
		t.Fatal(err)
	}
	picked := false
	for _, e := range res.Timeline {
		if e.Role == "change" {
			picked = strings.Contains(e.Summary, "ours.conf")
		}
	}
	if !picked {
		t.Fatalf("tagged change was skipped: %+v", res.Timeline)
	}
	// No change at all -> an explicit break.
	f2 := tbtest.New(t, t0)
	f2.Add("ecom", 0, "heartbeat", map[string]any{})
	res, _ = (&Tracer{Src: f2.Store}).Trace(context.Background(), Trigger{Agent: "ecom", Time: t0.Add(sec)})
	if len(res.Breaks()) != 1 {
		t.Fatalf("breaks %v", res.Breaks())
	}
}

func TestClockOffsetApplied(t *testing.T) {
	f := tbtest.New(t, t0)
	// web's clock runs 5 minutes fast; the connection is 20 s before the write in true time.
	f.Add("web", 5*time.Minute+10*sec, "net.connection_opened", map[string]any{"dir": "inbound", "proto": "tcp", "raddr": "198.51.100.7", "rport": 1, "service": "http"})
	ev := f.Add("web", 5*time.Minute+30*sec, "file_change", map[string]any{"op": "create", "path": "/a", "pid": 5})
	tr := &Tracer{Src: f.Store, Cfg: Config{Offset: func(string) time.Duration { return 5 * time.Minute }}}
	res, _ := tr.Trace(f.Ctx, Trigger{Event: &ev})
	for _, e := range res.Timeline {
		if e.Role == "change" && e.Time != t0.Add(30*sec) {
			t.Errorf("time %v", e.Time)
		}
	}
}
