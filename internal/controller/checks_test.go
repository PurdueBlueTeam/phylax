package controller

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/checks"
	"github.com/PurdueBlueTeam/phylax/internal/discovery"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

// newMonController is a controller with the M4 monitoring modules wired
// (discovery + trace-back + labels) and one scored web service.
func newMonController(t *testing.T) *Controller {
	t.Helper()
	c, err := New(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Store().Close() })
	c.NewDiscovery([]string{"127.0.0.1"}, 60*time.Second)
	c.SetServices([]ServiceInfo{{
		Name: "ecom", Scored: true, Port: 80,
		ContentRoots: []string{"/var/www/html"},
	}})
	return c
}

func ipArr(a, b, c, d int) []any {
	return []any{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, float64(a), float64(b), float64(c), float64(d)}
}

// ev builds one store.Event with JSON data, as the link path stores it.
func ev(typ string, data map[string]any, at time.Time) store.Event {
	b, _ := json.Marshal(data)
	return store.Event{
		Seq: 1, TS: at.UTC().Format(time.RFC3339Nano), Type: typ, Data: b,
	}
}

func alertData(t *testing.T, b []byte) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestD17UntaggedChange: an untagged change inside a scored service's
// content root opens a D17 alert carrying the trace-back, which reaches
// the causing request and source (lab T03's controller leg).
func TestD17UntaggedChange(t *testing.T) {
	c := newMonController(t)
	at := time.Date(2026, 10, 18, 14, 3, 12, 0, time.UTC)

	// the service worker tree
	c.observeEvent("ubuntu-ecom", ev("process_start", map[string]any{
		"pid": float64(100), "ppid": float64(1), "comm": "apache2", "exe": "/usr/sbin/apache2",
	}, at.Add(-time.Hour)))
	c.observeEvent("ubuntu-ecom", ev("process_start", map[string]any{
		"pid": float64(101), "ppid": float64(100), "comm": "apache2", "exe": "/usr/sbin/apache2",
	}, at.Add(-time.Hour)))
	// the webshell upload, 2 s before the change
	c.observeEvent("ubuntu-ecom", ev("http", map[string]any{
		"src": ipArr(10, 5, 5, 5), "sport": float64(5555), "dport": float64(80),
		"method": "POST", "path": "/shell.php", "body": "<?= system($_GET['c']); ?>",
		"resp": float64(200),
	}, at.Add(-2*time.Second)))

	// untagged change in the webroot
	c.observeEvent("ubuntu-ecom", ev("file_change", map[string]any{
		"path": "/var/www/html/shell.php", "op": "created", "sha256": "aa11",
	}, at))

	evs, err := c.Store().QueryEvents("controller", "alert", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 {
		t.Fatal("expected a D17 alert")
	}
	last := alertData(t, evs[len(evs)-1].Data)
	if last["rule"] != "D17.service-change" {
		t.Fatalf("rule: %v", last["rule"])
	}
	tl, _ := last["trace_back"].(map[string]any)
	if tl == nil {
		t.Fatal("D17 must carry the trace-back")
	}
	tlj, _ := tl["request"].(map[string]any)
	if tlj == nil || tlj["src"] != "10.5.5.5" || tlj["method"] != "POST" || tlj["path"] != "/shell.php" {
		t.Fatalf("request link: %v", tlj)
	}
	if tl["source"] != "10.5.5.5" {
		t.Fatalf("source: %v", tl["source"])
	}
}

// TestD17TaggedChangeIsQuiet: a change tagged by our own plan updates the
// baseline quietly — no alert (docs: tagged changes).
func TestD17TaggedChangeIsQuiet(t *testing.T) {
	c := newMonController(t)
	c.observeEvent("ubuntu-ecom", ev("file_change", map[string]any{
		"path": "/var/www/html/index.php", "op": "modified", "tag": "plan-1",
	}, time.Now()))
	if evs, _ := c.Store().QueryEvents("controller", "alert", 10); len(evs) != 0 {
		t.Fatalf("tagged change must not alert: %d alerts", len(evs))
	}
}

// TestCheckRedOpensAlert: a check that fails twice from the controller
// vantage turns red and opens an alert with the response diff.
func TestCheckRedOpensAlert(t *testing.T) {
	c := newMonController(t)
	// a tcp-banner check against a port nothing listens on: both runs fail
	ck := checks.Check{
		ID: "c1", Service: "ecom", Type: "tcp",
		Params:   map[string]any{"host": "127.0.0.1:39999"},
		Expected: map[string]any{"banner_re": "SSH-"},
		Interval: 10 * time.Millisecond,
	}
	if err := c.UpsertCheck(ck); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.RunChecks(ctx)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		evs, _ := c.Store().QueryEvents("controller", "alert", 10)
		for _, e := range evs {
			al := alertData(t, e.Data)
			if al["rule"] == "check.red" {
				if al["check"] != "c1" || al["vantage"] != "controller" {
					t.Fatalf("red alert: %v", al)
				}
				if al["detail"] == "" {
					t.Fatal("red alert must carry the response diff")
				}
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("no check.red alert within 15 s")
}

// TestDiscoverySinkWiring: the discovery module's sink callbacks land
// where the checks view and the IR drafter read them: D16 alerts for
// new/stale/blocked, scored accounts marked (recognition heuristics
// themselves are tested in internal/discovery against the simulator).
func TestDiscoverySinkWiring(t *testing.T) {
	c := newMonController(t)
	now := time.Now().UTC()

	c.Proposal(discovery.Proposal{
		ID: "p1", Kind: "new",
		Check:    checks.Check{ID: "disc-1", Service: "webmail", Type: "http"},
		Observed: &discovery.ObservedCheck{Service: "webmail"},
		Reason:   "scorer started checking /login.html", TS: now,
	})
	c.Stale(discovery.Proposal{
		ID: "p2", Kind: "stale",
		Check: checks.Check{ID: "c-old", Service: "ecom"},
		Reason: "no scorer counterpart for 5 rounds", TS: now,
	})
	c.Blocked(discovery.Blocked{Service: "dns", WindowStart: now.Add(-time.Minute), WindowEnd: now})
	c.Account(discovery.AccountMark{Account: "popuser", Source: "10.5.5.5", TS: now})
	// once per (account, source): a repeat must not duplicate
	c.Account(discovery.AccountMark{Account: "popuser", Source: "10.5.5.5", TS: now})

	evs, err := c.Store().QueryEvents("controller", "alert", 20)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, e := range evs {
		al := alertData(t, e.Data)
		if al["rule"] == "D16.scorer-check-change" {
			kinds[al["kind"].(string)]++
		}
	}
	if kinds["new"] != 1 || kinds["stale"] != 1 || kinds["blocked"] != 1 {
		t.Fatalf("D16 kinds: %v", kinds)
	}
	accs := c.ScoredAccounts()
	if len(accs) != 1 || accs[0]["account"] != "popuser" || accs[0]["source"] != "10.5.5.5" {
		t.Fatalf("scored accounts: %v", accs)
	}
}
