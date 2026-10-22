package vantage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/checks"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func webSpec(t *testing.T, srv *httptest.Server, id string, items ...checks.Item) checks.Spec {
	ap := netip.MustParseAddrPort(srv.Listener.Addr().String())
	return checks.Spec{ID: id, Type: checks.HTTP, Host: ap.Addr().String(), Port: int(ap.Port()), Items: items}
}

func TestCheckRunnerFaithfulSweepRefusalAndGate(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	var hitTimes []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		hitTimes = append(hitTimes, time.Now())
		mu.Unlock()
		if r.URL.Path == "/bad" {
			http.Error(w, "x", 500)
		}
	}))
	defer srv.Close()
	good := webSpec(t, srv, "web", checks.Item{Path: "/a", Status: 200}, checks.Item{Path: "/b", Status: 200}, checks.Item{Path: "/bad", Status: 200})
	// a spec aimed at an address outside the allowlist must never be contacted
	outside := checks.Spec{ID: "evil", Type: checks.HTTP, Host: "198.51.100.7", Port: 80}
	allow, _ := ParseAllowlist("127.0.0.0/8")

	fc := newFakeClock()
	gate := &fakeGate{clk: fc, opensAt: fc.Now().Add(2 * time.Second)}
	r, err := NewCheckRunner(CheckRunnerConfig{
		Allow: allow, Source: CheckSourceFunc(func(context.Context) []checks.Spec { return []checks.Spec{good, outside} }),
		SweepEvery: 2, Gate: gate, MinGap: time.Millisecond, MaxConcurrent: 1,
		Probe: checks.Options{Timeout: 2 * time.Second}, clock: fc.clock(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{}
	r.RunOnce(context.Background(), s.emit) // pass 1: gate closed at first, opens after the fake clock advances
	if fc.Now().Before(gate.opensAt) {
		t.Fatal("probed before the quiet window opened")
	}
	for _, n := range gate.needs {
		if n != 2*time.Second {
			t.Errorf("the window must cover the whole probe timeout, asked %v", n)
		}
	}
	checkEv := s.kind(KindCheck)
	if len(checkEv) != 1 {
		t.Fatalf("pass 1: %d check events (a faithful sample only)", len(checkEv))
	}
	if ref := s.kind(KindRefused); len(ref) != 1 || ref[0].Fields["host"] != "198.51.100.7" {
		t.Fatalf("refused: %+v", ref)
	}
	r.RunOnce(context.Background(), s.emit) // pass 2: faithful + sweep of all three items
	checkEv = s.kind(KindCheck)
	if len(checkEv) != 1+1+3 {
		t.Fatalf("after pass 2: %d check events", len(checkEv))
	}
	var sweep, bad int
	for _, e := range checkEv {
		if e.Fields["mode"] == "sweep" {
			sweep++
			if e.Fields["item"] == "/bad" {
				bad++
				if e.Fields["ok"] != false || e.Priority != event.PriorityHigh || e.Fields["class"] != "content" {
					t.Errorf("bad item event: %+v", e)
				}
			}
		}
	}
	if sweep != 3 || bad != 1 {
		t.Errorf("sweep=%d bad=%d: the union sweep must find the one broken item", sweep, bad)
	}
	r.RunOnce(context.Background(), s.emit) // refused spec is announced once only
	if len(s.kind(KindRefused)) != 1 {
		t.Error("refusal repeated")
	}
	_, probes, _, refused := r.Stats()
	if probes != 1+4+1 || refused != 3 {
		t.Errorf("probes=%d refused=%d", probes, refused)
	}
	// events are JSON-serialisable and carry no credential field
	b, err := json.Marshal(checkEv[0])
	if err != nil || strings.Contains(string(b), "pass") {
		t.Errorf("event json: %s %v", b, err)
	}
}

func TestCheckRunnerDefersWhenNoWindow(t *testing.T) {
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n++ }))
	defer srv.Close()
	allow, _ := ParseAllowlist("127.0.0.1")
	fc := newFakeClock()
	gate := &fakeGate{clk: fc, opensAt: fc.Now().Add(time.Hour)}
	r, _ := NewCheckRunner(CheckRunnerConfig{Allow: allow, Gate: gate, MaxDefer: 3 * time.Second, clock: fc.clock(),
		Source: CheckSourceFunc(func(context.Context) []checks.Spec { return []checks.Spec{webSpec(t, srv, "w")} })})
	s := &sink{}
	r.RunOnce(context.Background(), s.emit)
	if n != 0 {
		t.Fatal("probed inside a burst")
	}
	if d := s.kind(KindCheckDeferred); len(d) != 1 {
		t.Fatalf("deferred events: %v", s.all())
	}
	if _, _, def, _ := r.Stats(); def != 1 {
		t.Errorf("deferred=%d", def)
	}
}

func TestCheckRunnerAsAgentModule(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	allow, _ := ParseAllowlist("127.0.0.1")
	r, err := NewCheckRunner(CheckRunnerConfig{Allow: allow, Interval: 30 * time.Millisecond, MinGap: time.Millisecond,
		Source: CheckSourceFunc(func(context.Context) []checks.Spec { return []checks.Spec{webSpec(t, srv, "w")} })})
	if err != nil {
		t.Fatal(err)
	}
	var m agent.Module = r
	s := &sink{}
	sup := agent.NewSupervisor(agent.SupervisorOptions{Emit: s.emit})
	if err := sup.Add(agent.ModuleSpec{Module: m}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sup.Run(ctx); close(done) }()
	eventually(t, 5*time.Second, "several check events", func() bool { return len(s.kind(KindCheck)) >= 3 })
	cancel()
	<-done
	if m.Name() != "vantage.check_runner" {
		t.Error(m.Name())
	}
}

func TestCheckRunnerConfigValidation(t *testing.T) {
	if _, err := NewCheckRunner(CheckRunnerConfig{Source: CheckSourceFunc(nil)}); err == nil {
		t.Error("empty allowlist accepted")
	}
	a, _ := ParseAllowlist("127.0.0.1")
	if _, err := NewCheckRunner(CheckRunnerConfig{Allow: a}); err == nil {
		t.Error("missing source accepted")
	}
}

func TestCompare(t *testing.T) {
	ok := checks.Result{OK: true}
	down := checks.Result{OK: false, Class: checks.ClassUnreachable}
	content := checks.Result{OK: false, Class: checks.ClassContent}
	for _, c := range []struct {
		ext, lan checks.Result
		want     Verdict
	}{{ok, ok, VerdictAgree}, {down, down, VerdictServiceDown}, {down, ok, VerdictPathBroken}, {content, ok, VerdictContent}, {ok, down, VerdictInternalOnly}} {
		if got := Compare(c.ext, c.lan); got != c.want {
			t.Errorf("Compare(%v,%v)=%s want %s", c.ext.OK, c.lan.OK, got, c.want)
		}
	}
}
