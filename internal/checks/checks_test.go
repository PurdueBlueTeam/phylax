package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/sim/servicetest"
)

// runEx executes one check directly (no scheduler) and returns the
// observed values and the diff (empty = pass).
func runEx(t *testing.T, ck Check) (map[string]any, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	actual, err := execute(ctx, ck)
	if err != nil {
		return actual, err.Error()
	}
	return actual, compare(ck, actual)
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestExecutors runs every executor against the in-test services and
// checks the diff against the deterministic content.
func TestExecutors(t *testing.T) {
	s := servicetest.New(t, servicetest.Config{})

	// http
	actual, diff := runEx(t, Check{
		Type:     "http",
		Params:   map[string]any{"url": "http://" + s.HTTP.Listener.Addr().String() + "/page"},
		Expected: map[string]any{"status": 200, "content_sha256": sha("page:/page")},
	})
	if diff != "" {
		t.Fatalf("http: %v (actual %v)", diff, actual)
	}

	// tcp banner
	_, diff = runEx(t, Check{
		Type:     "tcp",
		Params:   map[string]any{"host": s.Banner},
		Expected: map[string]any{"banner_re": "SSH-"},
	})
	if diff != "" {
		t.Fatalf("tcp: %v", diff)
	}

	// dns
	dnsActual, diff := runEx(t, Check{
		Type:     "dns",
		Params:   map[string]any{"server": s.DNS, "name": "svc.phylax.test", "qtype": "A"},
		Expected: map[string]any{"answers": []any{s.DNSAnswer()}},
	})
	t.Logf("dns actual: %v", dnsActual)
	if diff != "" {
		t.Fatalf("dns: %v", diff)
	}

	// ftp: normalized listing = each line trimmed, sorted, joined \n
	listing := s.Listing()
	lines := strings.Split(strings.TrimRight(listing, "\n"), "\n")
	sort.Strings(lines)
	_, diff = runEx(t, Check{
		Type:     "ftp",
		Params:   map[string]any{"host": s.FTP, "user": "ftp", "pass": "ftp"},
		Expected: map[string]any{"list_sha256": sha(strings.Join(lines, "\n"))},
	})
	if diff != "" {
		t.Fatalf("ftp: %v", diff)
	}

	// tftp
	_, diff = runEx(t, Check{
		Type:     "tftp",
		Params:   map[string]any{"host": s.TFTP, "file": "report.txt"},
		Expected: map[string]any{"sha256": sha(s.TFTPContent())},
	})
	if diff != "" {
		t.Fatalf("tftp: %v", diff)
	}

	// ntp
	_, diff = runEx(t, Check{
		Type:     "ntp",
		Params:   map[string]any{"server": s.NTP},
		Expected: map[string]any{"reachable": true},
	})
	if diff != "" {
		t.Fatalf("ntp: %v", diff)
	}

	// smtp: send, then the POP3 mailbox must carry the subject
	subject := "score-7f3a"
	_, diff = runEx(t, Check{
		Type: "smtp",
		Params: map[string]any{
			"smtp_host": s.SMTP, "from": "scorer@phylax.test", "to": "box@phylax.test",
			"subject": subject, "body": "payload",
			"mailbox_host": s.POP3, "mail_user": "popuser", "mail_pass": "p",
		},
		Expected: map[string]any{"subject": subject},
	})
	if diff != "" {
		t.Fatalf("smtp: %v", diff)
	}
	if n := s.MailCount(); n != 1 {
		t.Fatalf("smtp: queued %d messages, want 1", n)
	}
}

// sinkRec records sink calls for the scheduler tests.
type sinkRec struct {
	mu     sync.Mutex
	results []Result
	reds   []Result
}

func (r *sinkRec) Result(x Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.results = append(r.results, x)
}

func (r *sinkRec) Red(x Result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reds = append(r.reds, x)
}

// TestRedAfterTwo verifies the red transition: exactly 2 consecutive
// failures, Red fires once on the transition, a success resets the
// counter (docs: Active checks).
func TestRedAfterTwo(t *testing.T) {
	sr := &sinkRec{}
	c := NewChecker("controller")
	c.SetSink(sr)
	c.Timeout(2 * time.Second)
	c.Upsert(Check{
		ID: "r1", Service: "ecom", Type: "tcp",
		Params:   map[string]any{"host": "127.0.0.1:39999"}, // nothing listens
		Expected: map[string]any{"banner_re": "X"},
		Interval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		sr.mu.Lock()
		n := len(sr.results)
		nRed := len(sr.reds)
		sr.mu.Unlock()
		if n >= 3 && nRed == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	sr.mu.Lock()
	defer sr.mu.Unlock()
	if len(sr.results) < 2 {
		t.Fatalf("no results: %d", len(sr.results))
	}
	if len(sr.reds) != 1 {
		t.Fatalf("Red fired %d times, want 1", len(sr.reds))
	}
	if sr.reds[0].CheckID != "r1" {
		t.Fatalf("red check: %v", sr.reds[0])
	}
	// every run before the red must be a failure
	for i := 0; i < 2 && i < len(sr.results); i++ {
		if sr.results[i].OK {
			t.Fatalf("run %d unexpectedly ok", i)
		}
	}
}

// TestAcceptCurrent verifies "accept current response": after a failing
// change, accepting the last successful actual turns the check green.
func TestAcceptCurrent(t *testing.T) {
	s := servicetest.New(t, servicetest.Config{})
	body := "page:/accept"
	c := NewChecker("controller")
	c.Timeout(2 * time.Second)
	ck := Check{
		ID: "a1", Service: "web", Type: "http",
		Params:   map[string]any{"url": "http://" + s.HTTP.Listener.Addr().String() + "/accept"},
		Expected: map[string]any{"status": 200, "content_sha256": sha(body)},
		Interval: 20 * time.Millisecond,
	}
	c.Upsert(ck)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)

	// first run green
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if rs := c.Results("a1"); len(rs) > 0 && rs[0].OK {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if rs := c.Results("a1"); len(rs) == 0 || !rs[0].OK {
		t.Fatalf("first run not green: %v", c.Results("a1"))
	}

	// now the expected no longer matches (a legitimate change happened
	// upstream): the check fails
	c.Upsert(Check{
		ID: "a1", Service: "web", Type: "http",
		Params:   ck.Params,
		Expected: map[string]any{"status": 200, "content_sha256": sha("changed")},
		Interval: 20 * time.Millisecond,
	})
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if rs := c.Results("a1"); len(rs) > 0 && !rs[0].OK {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// accept the last successful actual -> green again
	if err := c.AcceptCurrent("a1"); err != nil {
		t.Fatal(err)
	}
	list := c.List()
	if list[0].Expected["content_sha256"] != sha(body) {
		t.Fatalf("accept current: expected %v, want sha of %q", list[0].Expected["content_sha256"], body)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if rs := c.Results("a1"); len(rs) > 0 && rs[0].OK {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("check not green after accept current: %v", c.Results("a1"))
}

// TestVantageFilter verifies that a checker only runs checks whose
// Vantages include its own (or empty).
func TestVantageFilter(t *testing.T) {
	c := NewChecker("segment:dmz")
	ck := Check{
		ID: "v1", Service: "web", Type: "tcp",
		Params:   map[string]any{"host": "127.0.0.1:39999"},
		Expected: map[string]any{"banner_re": "X"},
		Interval: 10 * time.Millisecond,
		Vantages: []string{"controller"}, // not this vantage
	}
	c.Upsert(ck)
	sr := &sinkRec{}
	c.SetSink(sr)
	c.Timeout(time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	c.Run(ctx)
	sr.mu.Lock()
	defer sr.mu.Unlock()
	if len(sr.results) != 0 {
		t.Fatalf("checker ran a check for another vantage: %d results", len(sr.results))
	}
}
