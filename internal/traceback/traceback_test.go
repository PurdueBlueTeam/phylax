package traceback

import (
	"testing"
	"time"
)

// src16 builds the 16-byte src array a capture event carries (IPv4 at
// the end), in the JSON-decoded shape.
func src16(a, b, c, d int) []any {
	return []any{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, float64(a), float64(b), float64(c), float64(d)}
}

// TestT03Local (lab T03, local leg): a webshell-driven change — the
// scorer/red team POSTs a PHP payload, the service worker writes
// shell.php — fires the trace-back; the chain reaches the writer, its
// lineage, the exact request and the source IP, and lists the source's
// earlier traffic.
func TestT03Local(t *testing.T) {
	b := New()
	b.AddUSSource("10.9.0.1") // the controller: never a source
	b.SetLabeler(func(ip string) string {
		if ip == "10.5.5.5" {
			return "other"
		}
		return "other"
	})
	at := time.Date(2026, 10, 18, 14, 3, 12, 0, time.UTC)

	// service tree: apache parent (pid 100) -> worker (pid 101)
	b.AddEvent(Event{Host: "ubuntu-ecom", TS: at.Add(-30 * time.Minute), Type: "process_start", Data: map[string]any{
		"pid": float64(100), "ppid": float64(1), "comm": "apache2", "exe": "/usr/sbin/apache2",
	}})
	b.AddEvent(Event{Host: "ubuntu-ecom", TS: at.Add(-30 * time.Minute), Type: "process_start", Data: map[string]any{
		"pid": float64(101), "ppid": float64(100), "comm": "apache2", "exe": "/usr/sbin/apache2",
	}})

	// earlier traffic from the same source (first contact: a scan)
	b.AddEvent(Event{Host: "ubuntu-ecom", TS: at.Add(-9 * time.Minute), Type: "http", Data: map[string]any{
		"src": src16(10, 5, 5, 5), "sport": float64(5554), "dport": float64(80),
		"method": "GET", "path": "/.env", "resp": float64(404),
	}})
	// the webshell upload, 2 s before the change
	b.AddEvent(Event{Host: "ubuntu-ecom", TS: at.Add(-2 * time.Second), Type: "http", Data: map[string]any{
		"src": src16(10, 5, 5, 5), "sport": float64(5555), "dport": float64(80),
		"method": "POST", "path": "/shell.php", "body": "<?= system($_GET['c']); ?>",
		"resp": float64(200),
	}})
	// our own checker's request in the same window: must never be picked
	b.AddEvent(Event{Host: "ubuntu-ecom", TS: at.Add(-1 * time.Second), Type: "http", Data: map[string]any{
		"src": src16(10, 9, 0, 1), "sport": float64(6000), "dport": float64(80),
		"method": "GET", "path": "/index.html", "resp": float64(200),
	}})

	cw := ChangeWriter{
		Change: Change{
			Host: "ubuntu-ecom", Path: "/var/www/html/shell.php", Op: "created",
			TS: at, SHA256: "aa11", Size: 26, Service: "ecom", Port: 80,
		},
		PID: 101, Comm: "apache2",
	}
	tl := b.BuildWithWriter(cw)

	if tl.Writer == nil || tl.Writer.PID != 101 {
		t.Fatalf("writer: %+v", tl.Writer)
	}
	if len(tl.Lineage) != 2 || tl.Lineage[0].PID != 101 || tl.Lineage[1].PID != 100 {
		t.Fatalf("lineage: %+v", tl.Lineage)
	}
	if tl.Request == nil || tl.Request.Src != "10.5.5.5" || tl.Request.Method != "POST" || tl.Request.Path != "/shell.php" {
		t.Fatalf("request: %+v", tl.Request)
	}
	if tl.Request.Confidence != "high" || tl.Confidence != "high" {
		t.Fatalf("confidence: req=%s overall=%s", tl.Request.Confidence, tl.Confidence)
	}
	if tl.Source != "10.5.5.5" {
		t.Fatalf("source: %s", tl.Source)
	}
	// everything else from the source: the earlier /.env scan
	if len(tl.FromSource) != 1 || tl.FromSource[0].Type != "http" || tl.FromSource[0].Summary != "GET /.env -> 404" {
		t.Fatalf("from_source: %+v", tl.FromSource)
	}
	// evidence: the file + the ring window
	if len(tl.Evidence) != 2 || tl.Evidence[0].Kind != "file" || tl.Evidence[0].SHA256 != "aa11" || tl.Evidence[1].Kind != "ring" {
		t.Fatalf("evidence: %+v", tl.Evidence)
	}
	if len(tl.Missing) != 0 {
		t.Fatalf("missing: %v", tl.Missing)
	}
}

// TestTracebackFallback: without the writer, the chain still reaches the
// request and source via the time window, marked lower confidence, and
// names the missing links.
func TestTracebackFallback(t *testing.T) {
	b := New()
	at := time.Date(2026, 10, 18, 14, 3, 12, 0, time.UTC)
	b.AddEvent(Event{Host: "h", TS: at.Add(-5 * time.Second), Type: "http", Data: map[string]any{
		"src": src16(10, 5, 5, 5), "sport": float64(1), "dport": float64(80),
		"method": "POST", "path": "/x.php", "resp": float64(200),
	}})
	tl := b.Build(Change{Host: "h", Path: "/var/www/x.php", Op: "created", TS: at, Service: "s", Port: 80})
	if tl.Writer != nil {
		t.Fatalf("writer must be nil, got %+v", tl.Writer)
	}
	if tl.Request == nil || tl.Request.Src != "10.5.5.5" {
		t.Fatalf("request: %+v", tl.Request)
	}
	if tl.Request.Confidence != "low" || tl.Confidence != "low" {
		t.Fatalf("fallback must be low confidence: req=%s overall=%s", tl.Request.Confidence, tl.Confidence)
	}
	if len(tl.Missing) != 2 || tl.Missing[0] != "writer" || tl.Missing[1] != "lineage" {
		t.Fatalf("missing: %v", tl.Missing)
	}
}

// TestTracebackNoRequest: no candidate request in the window — the
// timeline names the broken links instead of guessing.
func TestTracebackNoRequest(t *testing.T) {
	b := New()
	at := time.Date(2026, 10, 18, 14, 3, 12, 0, time.UTC)
	// only platform traffic in the window
	b.AddEvent(Event{Host: "h", TS: at.Add(-5 * time.Second), Type: "http", Data: map[string]any{
		"src": src16(10, 9, 0, 1), "sport": float64(1), "dport": float64(80),
		"method": "GET", "path": "/", "resp": float64(200),
	}})
	b.AddUSSource("10.9.0.1")
	tl := b.Build(Change{Host: "h", Path: "/var/www/x.php", Op: "modified", TS: at, Service: "s", Port: 80})
	if tl.Request != nil || tl.Source != "" {
		t.Fatalf("must have no request/source: %+v %q", tl.Request, tl.Source)
	}
	found := map[string]bool{}
	for _, m := range tl.Missing {
		found[m] = true
	}
	if !found["writer"] || !found["request"] || !found["source"] {
		t.Fatalf("missing: %v", tl.Missing)
	}
}
