package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	phyagent "github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/enroll"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// writeServed writes a stand-in agent binary into a web root and returns its path.
func writeServed(t *testing.T, dir, name, data string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// bundleToken reads the enrollment token out of a served bundle.
func bundleToken(t *testing.T, dir, host string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, host+".json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := phyagent.ParseBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	return b.Token
}

// enrollAlerts returns the enrollment alerts raised for host.
func enrollAlerts(c *Controller, host string) []Alert {
	var out []Alert
	for _, a := range c.Alerts() {
		if a.Host == host && strings.HasPrefix(a.Kind, "enroll.") {
			out = append(out, a)
		}
	}
	return out
}

// helloWith connects with id, sends a hello carrying hash and reports whether
// a welcome arrived.
func helloWith(t *testing.T, x *ctl, id *link.Identity, host, token, hash string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := link.Dial(ctx, x.addr, link.DialOptions{Identity: id, ServerPin: x.c.Pin(), ALPN: link.ALPNAgent})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{}, 1)
	sess := link.NewSession(conn, link.Options{Role: link.RoleAgent, Handler: func(_ context.Context, m link.Message) error {
		if _, ok := m.(*link.Welcome); ok {
			got <- struct{}{}
		}
		return nil
	}})
	go sess.Run(ctx)
	defer sess.Close()
	sess.Send(ctx, link.PrioCritical, &link.Hello{Proto: 1, Host: host, Version: "t", Token: token, BinarySHA256: hash})
	select {
	case <-got:
		return true
	case <-sess.Done():
		return false
	case <-time.After(10 * time.Second):
		t.Fatal("neither welcome nor close")
		return false
	}
}

func newIdent(t *testing.T, name string) *link.Identity {
	t.Helper()
	id, err := link.GenerateIdentity(name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// watchForTest writes bundles for hosts and starts the watch on a served
// stand-in binary whose hash is servedHash.
func watchForTest(t *testing.T, x *ctl, hosts []string, window time.Duration) (dir, servedHash string) {
	t.Helper()
	dir = t.TempDir()
	if err := x.c.Enroller().WriteBundles(dir, hosts, enroll.BundleOptions{Controllers: []string{"127.0.0.1:7443"}}); err != nil {
		t.Fatal(err)
	}
	served := writeServed(t, t.TempDir(), "phylax", "the served agent binary")
	if err := x.c.WatchEnrollment(dir, hosts, []string{served}, window); err != nil {
		t.Fatal(err)
	}
	return dir, sha256Hex("the served agent binary")
}

func TestWatchHashMismatchAlerts(t *testing.T) {
	x := newCtl(t)
	hosts := []string{"h1", "h2", "h3"}
	dir, good := watchForTest(t, x, hosts, time.Hour)
	trojan := sha256Hex("a trojan, not the served binary")

	h1 := newIdent(t, "h1")
	if !helloWith(t, x, h1, "h1", bundleToken(t, dir, "h1"), trojan) {
		t.Fatal("h1 was not admitted")
	}
	if !helloWith(t, x, newIdent(t, "h2"), "h2", bundleToken(t, dir, "h2"), good) {
		t.Fatal("h2 was not admitted")
	}
	if !helloWith(t, x, newIdent(t, "h3"), "h3", bundleToken(t, dir, "h3"), "") {
		t.Fatal("h3 was not admitted")
	}

	alerts := enrollAlerts(x.c, "h1")
	if len(alerts) != 1 || alerts[0].Kind != "enroll.hash_mismatch" {
		t.Fatalf("h1 alerts = %+v, want one enroll.hash_mismatch", alerts)
	}
	for _, want := range []string{trojan, good} {
		if !strings.Contains(alerts[0].Detail, want) {
			t.Errorf("h1 detail %q does not name the hash %q", alerts[0].Detail, want)
		}
	}
	if n := len(enrollAlerts(x.c, "h2")); n != 0 {
		t.Errorf("h2 reported the served hash but raised %d alerts", n)
	}
	alerts = enrollAlerts(x.c, "h3")
	if len(alerts) != 1 || alerts[0].Kind != "enroll.hash_mismatch" {
		t.Fatalf("h3 alerts = %+v, want one enroll.hash_mismatch", alerts)
	}
	if !strings.Contains(alerts[0].Detail, "no binary hash reported") {
		t.Errorf("h3 detail %q", alerts[0].Detail)
	}

	// A reconnect repeats neither alert: the host is already enrolled and
	// already alarmed.
	if !helloWith(t, x, h1, "h1", "", trojan) {
		t.Fatal("h1 reconnect was refused")
	}
	if n := len(enrollAlerts(x.c, "h1")); n != 1 {
		t.Errorf("h1 reconnect raised alerts again: %d", n)
	}
}

func TestWatchRemovesBundleOnConnect(t *testing.T) {
	x := newCtl(t)
	hosts := []string{"h1", "h2"}
	dir, good := watchForTest(t, x, hosts, time.Hour)

	if !helloWith(t, x, newIdent(t, "h1"), "h1", bundleToken(t, dir, "h1"), good) {
		t.Fatal("h1 was not admitted")
	}
	if _, err := os.Stat(filepath.Join(dir, "h1.json")); !os.IsNotExist(err) {
		t.Fatalf("h1 bundle after connect: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "h2.json")); err != nil {
		t.Fatalf("h2 bundle removed without a connection: %v", err)
	}
}

func TestWatchNoShowAndCleanup(t *testing.T) {
	x := newCtl(t)
	var fired func()
	var gotWindow time.Duration
	x.c.opt.EnrollTimer = func(d time.Duration, f func()) (stop func()) {
		gotWindow, fired = d, f
		return func() {}
	}
	hosts := []string{"h1", "h2"}
	dir, good := watchForTest(t, x, hosts, 30*time.Minute)
	if gotWindow != 30*time.Minute || fired == nil {
		t.Fatalf("window %v, timer %v", gotWindow, fired != nil)
	}
	if !helloWith(t, x, newIdent(t, "h1"), "h1", bundleToken(t, dir, "h1"), good) {
		t.Fatal("h1 was not admitted")
	}
	if _, err := os.Stat(filepath.Join(dir, "h2.json")); err != nil {
		t.Fatalf("h2 bundle removed before the window ended: %v", err)
	}

	fired()

	alerts := enrollAlerts(x.c, "h2")
	if len(alerts) != 1 || alerts[0].Kind != "enroll.no_show" {
		t.Fatalf("h2 alerts = %+v, want one enroll.no_show", alerts)
	}
	if n := len(enrollAlerts(x.c, "h1")); n != 0 {
		t.Errorf("h1 connected but got %d alerts", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "h2.json")); !os.IsNotExist(err) {
		t.Fatalf("h2 bundle kept after the window: %v", err)
	}

	// A hello after the window is over is handled normally (a fresh token is
	// needed: the served bundle is gone) and raises no enrollment alert.
	tok, err := x.c.Enroller().MintToken("h2", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !helloWith(t, x, newIdent(t, "late"), "h2", tok, "") {
		t.Fatal("late hello was refused")
	}
	if n := len(enrollAlerts(x.c, "h2")); n != 1 {
		t.Errorf("late hello raised %d alerts after enroll.no_show", n)
	}
}

func TestWatchRefusedEnrollmentAlerts(t *testing.T) {
	x := newCtl(t)
	hosts := []string{"h1"}
	dir, good := watchForTest(t, x, hosts, time.Hour)

	if helloWith(t, x, newIdent(t, "evil"), "h1", "NOTAREALTOKEN", good) {
		t.Fatal("bogus token admitted")
	}
	alerts := enrollAlerts(x.c, "h1")
	if len(alerts) != 1 || alerts[0].Kind != "enroll.refused" {
		t.Fatalf("h1 alerts = %+v, want one enroll.refused", alerts)
	}
	// A refused enrollment does not consume the bundle: the real host can
	// still enroll with it.
	if _, err := os.Stat(filepath.Join(dir, "h1.json")); err != nil {
		t.Fatalf("bundle removed on a refused enrollment: %v", err)
	}
}

func TestWatchServedFileMissing(t *testing.T) {
	x := newCtl(t)
	missing := filepath.Join(t.TempDir(), "phylax")
	err := x.c.WatchEnrollment(t.TempDir(), []string{"h1"}, []string{missing}, time.Hour)
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Fatalf("err = %v, want an error naming %s", err, missing)
	}
}

// storedControllerEvent returns the one stored controller event of kind and
// checks that it still validates against its declared kind.
func storedControllerEvent(t *testing.T, c *Controller, kind string) event.Event {
	t.Helper()
	evs, err := c.Store().Events(context.Background(), store.Query{Agent: ControllerAgent, Kind: kind, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("%s events = %d, want 1", kind, len(evs))
	}
	if err := event.Validate(evs[0]); err != nil {
		t.Fatalf("%s stored event does not validate: %v", kind, err)
	}
	return evs[0]
}

// The enrollment-watch alerts are declared events: each one is emitted on the
// controller chain with its declared payload, validates, and the ingest hook
// queues an alert row that points at the event.
func TestEnrollAlertsAreStoredAlerts(t *testing.T) {
	x := newCtl(t)
	var fired func()
	x.c.opt.EnrollTimer = func(_ time.Duration, f func()) func() { fired = f; return func() {} }
	dir, _ := watchForTest(t, x, []string{"h1", "h2"}, 30*time.Minute)
	trojan := sha256Hex("a trojan, not the served binary")
	if !helloWith(t, x, newIdent(t, "h1"), "h1", bundleToken(t, dir, "h1"), trojan) {
		t.Fatal("h1 was not admitted")
	}
	if fired == nil {
		t.Fatal("no window timer")
	}
	fired()

	mismatch := storedControllerEvent(t, x.c, event.KindEnrollHashMismatch)
	if mismatch.Priority != event.PriorityCritical {
		t.Errorf("hash mismatch priority = %v, want critical", mismatch.Priority)
	}
	hm, err := event.Decode[event.EnrollHashMismatch](mismatch, event.KindEnrollHashMismatch)
	if err != nil {
		t.Fatal(err)
	}
	if hm.Host != "h1" || hm.Reported != trojan || hm.Served == "" {
		t.Errorf("hash mismatch payload = %+v", hm)
	}

	noShow := storedControllerEvent(t, x.c, event.KindEnrollNoShow)
	if noShow.Priority != event.PriorityHigh {
		t.Errorf("no-show priority = %v, want high", noShow.Priority)
	}
	ns, err := event.Decode[event.EnrollNoShow](noShow, event.KindEnrollNoShow)
	if err != nil {
		t.Fatal(err)
	}
	if ns.Host != "h2" || ns.WindowSec != 1800 {
		t.Errorf("no-show payload = %+v", ns)
	}
	if _, err := time.Parse(time.RFC3339, ns.Since); err != nil {
		t.Errorf("no-show since %q: %v", ns.Since, err)
	}

	// Each alert has its queue row, keyed by the stored event's seq.
	rows, err := x.c.Store().Alerts(context.Background(), "", 100)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{event.KindEnrollHashMismatch: "h1", event.KindEnrollNoShow: "h2"}
	for _, r := range rows {
		host, ok := want[r.Rule]
		if !ok {
			continue
		}
		if r.Host != host || r.Agent != ControllerAgent || r.Seq == 0 {
			t.Errorf("alert row %+v, want host %s on the controller chain", r, host)
		}
		delete(want, r.Rule)
	}
	if len(want) != 0 {
		t.Errorf("no alert row for %v", want)
	}
}
