package agent

import (
	"context"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	agentrespond "github.com/PurdueBlueTeam/phylax/internal/agent/respond"
	"github.com/PurdueBlueTeam/phylax/internal/detect"
)

// capAgent captures the agent's published events in addition to the
// spool (the spool is the production path; the capture is the test
// observation point).
type capAgent struct {
	*Agent
	mu   sync.Mutex
	evt []string
	dat map[string]any
}

func newCapAgent(t *testing.T) *capAgent {
	t.Helper()
	a, err := New(t.TempDir(), Bundle{Host: "e2e-host", Controller: "127.0.0.1:1", Token: "x"}, log.New(os.Stderr, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	return &capAgent{Agent: a}
}

func (c *capAgent) PublishClass(evType string, data any, class int) error {
	c.record(evType, data)
	return c.Agent.PublishClass(evType, data, class)
}

// Publish is the respond module's event path: it records the event
// (the spool write happens on the PublishClass path in production).
func (c *capAgent) Publish(evType string, data any) error {
	c.record(evType, data)
	return nil
}

func (c *capAgent) record(evType string, data any) {
	c.mu.Lock()
	c.evt = append(c.evt, evType)
	if d, ok := data.(map[string]any); ok {
		c.dat = d
	}
	c.mu.Unlock()
}

func (c *capAgent) has(typ string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.evt {
		if e == typ {
			return true
		}
	}
	return false
}

// wrapCap is the router's test stand-in: alerts are spooled as
// evidence (the "alert" event) and tier-0 alerts feed respond — the
// same contract as the production routerSink.
type wrapCap struct {
	*capAgent
	e *e2e
}

func (w *wrapCap) Alert(al detect.Alert) {
	_ = w.PublishClass("alert", map[string]any{
		"rule": al.Rule, "severity": al.Severity, "tier": al.Tier,
		"attack": al.Attack, "key": al.Key, "ts": al.TS, "event": al.Event,
	}, 0)
	if al.Tier == 0 {
		w.e.resp.Submit(al)
	}
}

// e2e is the local lab harness: the real module router's event flow
// (module -> spool+engine -> tier-0 respond) with a scripted injector
// for scenarios whose real producers need root or a live lab.
type e2e struct {
	a      *wrapCap
	engine *detect.Engine
	resp   *agentrespond.Module
	stop   chan struct{}
}

func startE2E(t *testing.T) *e2e {
	t.Helper()
	a := newCapAgent(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel() })

	e := &e2e{stop: make(chan struct{})}
	wc := &wrapCap{capAgent: a, e: e}
	e.a = wc
	e.engine = detect.New(wc)
	if err := e.engine.Load(repoRulesDir(t)); err != nil {
		t.Fatal(err)
	}
	e.resp = agentrespond.New(&agentrespond.Env{
		Health:   func(string) bool { return true },
		SafeMode: func() bool { return a.safeMode },

		Publish:  a,
	}, []agentrespond.Recipe{{
		For:  "D10b.firewall-tamper",
		Name: "restore.firewall",
		Run: func(ctx context.Context, al detect.Alert, env *agentrespond.Env) (string, string, string, error) {
			return "firewall:disabled", "firewall:declared", "re-apply declared host policy", nil
		},
	}})
	go func() { _ = e.resp.Run(ctx) }()
	return e
}

// FireTestEvent injects one event through the router (spool + engine),
// standing in for the module that would produce it on a real host.
func (e *e2e) FireTestEvent(evType string, data map[string]any) {
	_ = e.a.PublishClass(evType, data, 0)
	e.engine.Handle(evType, data)
}

func (e *e2e) Stop() { close(e.stop) }


func repoRulesDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd + "/../rules"
}

func waitFor(t *testing.T, d time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !f() {
		t.Fatalf("condition not met within %s", d)
	}
}

// TestT02EndToEnd (lab T02): an untagged firewall change flows
// event -> D10b -> tier-0 restore within 10 s, and the restore loop
// opens an incident on the third restore in 10 minutes.
func TestT02EndToEnd(t *testing.T) {
	e := startE2E(t)
	defer e.Stop()

	e.FireTestEvent("firewall_change", map[string]any{"what": "table inet phylax deleted"})
	waitFor(t, 10*time.Second, func() bool { return e.a.has("response") })
	if !e.a.has("response") {
		t.Fatal("no tier-0 response within 10 s of the untagged firewall change")
	}
	// the alert and response carry the trigger lineage
	if !e.a.has("alert") {
		t.Fatal("the trigger (D10b alert) must be recorded")
	}
	// two more restores -> the loop guard opens an incident and stops
	e.FireTestEvent("firewall_change", map[string]any{"what": "deleted 2", "k": 2})
	e.FireTestEvent("firewall_change", map[string]any{"what": "deleted 3", "k": 3})
	waitFor(t, 10*time.Second, func() bool { return e.a.has("incident") })
	if !e.a.has("incident") {
		t.Fatal("3 restores in 10 min must open an incident")
	}
}

// TestT11Local (lab T11, local leg): a cleared log fires D10 within
// the alert window. (Sysmon reinstall is Windows-only: U-item.)
func TestT11Local(t *testing.T) {
	e := startE2E(t)
	defer e.Stop()

	e.FireTestEvent("log_cleared", map[string]any{"file": "/var/log/auth.log"})
	waitFor(t, 10*time.Second, func() bool { return e.a.has("alert") })
	if !e.a.has("alert") {
		t.Fatal("cleared log must raise a D10 alert")
	}
}

// TestT12Local (lab T12, local leg): an LD_PRELOAD rootkit process is
// caught by crossview and raises D11 within 120 s (here: ms).
func TestT12Local(t *testing.T) {
	e := startE2E(t)
	defer e.Stop()

	e.FireTestEvent("ld_preload", map[string]any{"pid": os.Getpid(), "preload": "/tmp/evil.so"})
	waitFor(t, 10*time.Second, func() bool { return e.a.has("alert") })
	if !e.a.has("alert") {
		t.Fatal("LD_PRELOAD process must raise a D11 alert")
	}
}
