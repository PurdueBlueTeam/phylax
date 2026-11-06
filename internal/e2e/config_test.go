package e2e

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	_ "github.com/PurdueBlueTeam/phylax/internal/agent/mods" // the production module factories
	"github.com/PurdueBlueTeam/phylax/internal/controller"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

const e2eRule = `
id: Z9.e2e-synthetic
title: Synthetic probe from the end-to-end test
severity: high
tier: 1
attack: [T1059]
message: "probe {marker} on {path}"
entities: [marker, path]
when:
  event: synthetic.probe
  all:
    - marker: evil
tests:
  - name: evil marker
    should_match: true
    event: {kind: synthetic.probe, fields: {marker: evil, path: /x}}
  - name: fine marker
    should_match: false
    event: {kind: synthetic.probe, fields: {marker: fine, path: /x}}
`

// synthModule emits a synthetic.probe event each time trig is signalled.
type synthModule struct{ trig chan struct{} }

func (synthModule) Name() string { return "synth" }
func (m synthModule) Start(ctx context.Context, emit agent.Emit) error {
	for {
		select {
		case <-m.trig:
			emit(event.Event{Kind: "synthetic.probe", Priority: event.PriorityHigh,
				Fields: map[string]any{"marker": "evil", "path": "/srv/www/shell.php"}})
		case <-ctx.Done():
			return nil
		}
	}
}

type cfgHost struct {
	h      *harness
	name   string
	layout agent.Layout
	trig   chan struct{}
	a      *agent.Agent
	cancel context.CancelFunc
	done   chan error
}

func (c *cfgHost) start() {
	t := c.h.t
	t.Helper()
	cfg := agent.Config{Layout: c.layout, Logger: quiet(),
		HeartbeatInterval: 100 * time.Millisecond, DialTimeout: 3 * time.Second,
		Backoff:    link.Backoff{Min: 20 * time.Millisecond, Max: 100 * time.Millisecond},
		Supervisor: agent.SupervisorOptions{Backoff: link.Backoff{Min: time.Millisecond, Max: 10 * time.Millisecond}},
		Modules:    []agent.ModuleSpec{{Module: synthModule{c.trig}}}}
	if os.Geteuid() == 0 {
		// Never install real audit rules on a developer or CI machine.
		cfg.Factories = []agent.Factory{{Name: "audit",
			Section: func(cf *plan.AgentConfig) (string, bool) { return "stub", cf.Modules.Audit != nil },
			Build: func(agent.Env, *plan.AgentConfig) (agent.ModuleSpec, error) {
				return agent.ModuleSpec{Module: synthModule2{}}, nil
			}}}
	}
	a, err := agent.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.a, c.cancel, c.done = a, cancel, make(chan error, 1)
	go func() { c.done <- a.Run(ctx) }()
}

type synthModule2 struct{}

func (synthModule2) Name() string { return "audit" }
func (synthModule2) Start(ctx context.Context, _ agent.Emit) error {
	<-ctx.Done()
	return nil
}

func (c *cfgHost) stop() {
	if c.cancel == nil {
		return
	}
	c.cancel()
	<-c.done
	c.cancel = nil
}

// fire emits the synthetic event once a stream consumer (detect) has
// subscribed; a module reports "running" slightly before that
// and an event published in the gap would be lost to local detection.
func (c *cfgHost) fire() {
	eventually(c.h.t, "event stream subscribers", 10*time.Second, func() bool { return c.a.Subscribers() >= 1 })
	select {
	case c.trig <- struct{}{}:
	case <-time.After(30 * time.Second):
		c.h.t.Fatal("synthetic module not listening")
	}
}

func loadRealInputs(t *testing.T, mutate func(*manifest.Manifest)) controller.ConfigInputs {
	t.Helper()
	in, err := controller.LoadConfigInputs(controller.Config{ManifestPath: "../../manifest/2027", RulesPath: "../../rules"})
	if err != nil {
		t.Fatal(err)
	}
	in.Rules = append(in.Rules, plan.RuleFile{Name: "e2e.yml", YAML: e2eRule})
	if mutate != nil {
		mutate(in.Manifest)
	}
	return in
}

func alertsIn(t *testing.T, h *harness, host string) []event.Event {
	t.Helper()
	// Only the synthetic rule: the real net module's events may trip others.
	var out []event.Event
	for _, e := range kinds(t, h, host, "detect.alert") {
		if e.Fields["rule"] == "Z9.e2e-synthetic" {
			out = append(out, e)
		}
	}
	return out
}

func kinds(t *testing.T, h *harness, host, kind string) []event.Event {
	t.Helper()
	evs, err := h.c.Store().Events(context.Background(), store.Query{Agent: host, Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

// A real controller generates and signs the host's config from the manifest;
// a real agent verifies it, starts the modules, detects a synthetic event
// locally and the alert reaches the controller's store. A manifest change
// pushes a new version; a restarted agent runs the persisted config with no
// controller at all.
func TestAgentConfigEndToEnd(t *testing.T) {
	const host = "rocky-ecom"
	ctx := context.Background()
	h := newHarness(t)
	if err := h.c.SetConfigInputs(ctx, loadRealInputs(t, nil)); err != nil {
		t.Fatal(err)
	}
	tok, err := h.c.Enroller().MintToken(host, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ch := &cfgHost{h: h, name: host, layout: agent.Layout{Root: filepath.Join(t.TempDir(), "state")}, trig: make(chan struct{})}
	if err := ch.layout.SaveBundle(&agent.Bundle{Controllers: []string{h.addr}, ControllerPin: h.c.Pin().String(), Host: host, Token: tok,
		PlanKey: hex.EncodeToString(h.c.PlanPublicKey())}); err != nil {
		t.Fatal(err)
	}
	ch.start()
	t.Cleanup(ch.stop)

	wantState := agent.ConfigOK
	if os.Geteuid() != 0 {
		wantState = agent.ConfigDegraded // audit needs root: unavailable, not a crash loop
	}
	eventually(t, "config v1 applied and reported", 15*time.Second, func() bool {
		st, ok := h.c.AgentStatus(host)
		return ok && st.Connected && st.ConfigVersion == 1 && st.ConfigState == wantState
	})
	epoch, _ := h.c.Store().Epoch(ctx)
	if st, _ := h.c.AgentStatus(host); st.ConfigEpoch != epoch || epoch == 0 {
		t.Fatalf("epoch in config = %d, store epoch %d", st.ConfigEpoch, epoch)
	}
	cs := ch.a.ConfigStatus()
	if os.Geteuid() != 0 && !strings.HasPrefix(cs.Modules["audit"], "unavailable: ") {
		t.Fatalf("audit without root: %q", cs.Modules["audit"])
	}
	for _, m := range []string{"health", "net", "detect", "integrity"} {
		if cs.Modules[m] != "running" {
			t.Fatalf("module %s: %q (status %+v)", m, cs.Modules[m], cs)
		}
	}
	eventually(t, "modules running under the supervisor", 10*time.Second, func() bool {
		ms := ch.a.Modules()
		for _, m := range []string{"health", "net", "detect", "integrity", "synth"} {
			if ms[m].State != agent.StateRunning {
				return false
			}
		}
		return true
	})
	if cfg := ch.a.AppliedConfig(); cfg == nil || cfg.Modules.Detect.ActEnabled || len(cfg.Modules.Net.Services) == 0 {
		t.Fatalf("applied config: %+v", cfg)
	}

	// A detection fires locally on the synthetic event and reaches the store.
	ch.fire()
	eventually(t, "alert in the controller store", 10*time.Second, func() bool { return len(alertsIn(t, h, host)) == 1 })
	al := alertsIn(t, h, host)[0]
	if al.Priority != event.PriorityCritical || al.Fields["rule"] != "Z9.e2e-synthetic" ||
		!strings.Contains(al.Fields["message"].(string), "evil on /srv/www/shell.php") {
		t.Fatalf("alert: %+v", al)
	}
	if len(kinds(t, h, host, "synthetic.probe")) != 1 {
		t.Fatal("the raw event must be stored too")
	}

	// Manifest change: a new listener produces config v2, pushed to the live agent.
	in2 := loadRealInputs(t, func(m *manifest.Manifest) {
		for id, s := range m.Services {
			if s.Host == host && len(s.Listen) > 0 {
				s.Listen = append(append([]manifest.Listener(nil), s.Listen...), manifest.Listener{Proto: "tcp", Port: 8089})
				m.Services[id] = s
				return
			}
		}
		t.Fatal("no service to change")
	})
	if err := h.c.SetConfigInputs(ctx, in2); err != nil {
		t.Fatal(err)
	}
	eventually(t, "config v2 applied", 15*time.Second, func() bool {
		st, _ := h.c.AgentStatus(host)
		return st.ConfigVersion == 2 && st.ConfigState == wantState
	})
	if ch.a.AppliedConfig().Modules.Net.Services["tcp/8089"] == "" {
		t.Fatal("the new listener is not in the applied net settings")
	}
	eventually(t, "net module replaced and running", 10*time.Second, func() bool { return ch.a.Modules()["net"].State == agent.StateRunning })
	eventually(t, "both config_applied events stored", 10*time.Second, func() bool {
		return len(kinds(t, h, host, "agent.config_applied")) == 2
	})

	// Controller and agent both go away. The agent alone restarts and runs the
	// persisted config; detection still works and the alert waits in the spool.
	ch.stop()
	h.stopController()
	ch.start()
	eventually(t, "persisted config running without a controller", 15*time.Second, func() bool {
		st := ch.a.ConfigStatus()
		ms := ch.a.Modules()
		return st.Version == 2 && st.State == wantState && ms["net"].State == agent.StateRunning && ms["detect"].State == agent.StateRunning &&
			ms["synth"].State == agent.StateRunning
	})
	ch.fire()

	// The controller returns (same inputs, versions are durable): the agent
	// reconnects, sees its config as current and the offline alert arrives.
	h.startController()
	if err := h.c.SetConfigInputs(ctx, in2); err != nil {
		t.Fatal(err)
	}
	eventually(t, "offline alert delivered", 15*time.Second, func() bool {
		return len(alertsIn(t, h, host)) == 2
	})
	eventually(t, "agent reconnected with v2", 10*time.Second, func() bool {
		st, _ := h.c.AgentStatus(host)
		return st.Connected && st.ConfigVersion == 2
	})
	if rej := kinds(t, h, host, "agent.config_rejected"); len(rej) != 0 {
		t.Fatalf("config refused: %+v", rej[0].Fields)
	}
}
