package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// probeFactory builds a module that emits probe.started (carrying the service
// map it was configured with) and runs until stopped. It is enabled by a Net
// section, so tests can switch it with the config.
type probeFactory struct {
	builds, starts atomic.Int32
	unavailable    bool
}

func (p *probeFactory) factory() Factory {
	return Factory{
		Name: "probe",
		Section: func(c *plan.AgentConfig) (string, bool) {
			if c.Modules.Net == nil {
				return "", false
			}
			b, _ := json.Marshal(c.Modules.Net)
			return string(b), true
		},
		Build: func(env Env, c *plan.AgentConfig) (ModuleSpec, error) {
			p.builds.Add(1)
			if p.unavailable {
				return ModuleSpec{}, wrapUnavailable("needs a gadget")
			}
			svc := c.Modules.Net.Services["tcp/80"]
			return ModuleSpec{Module: funcModule{"probe", func(ctx context.Context, emit Emit) error {
				p.starts.Add(1)
				emit(event.Event{Kind: "probe.started", Priority: event.PriorityHigh, Fields: map[string]any{"svc": svc}})
				<-ctx.Done()
				return nil
			}}}, nil
		},
	}
}

func wrapUnavailable(why string) error { return &unavailErr{why} }

type unavailErr struct{ why string }

func (e *unavailErr) Error() string { return ErrUnavailable.Error() + ": " + e.why }
func (e *unavailErr) Unwrap() error { return ErrUnavailable }

func cfgBody(host string, epoch, ver uint64, svc string) *plan.AgentConfig {
	c := &plan.AgentConfig{Host: host, Epoch: epoch, Version: ver, IssuedAt: 1}
	if svc != "" {
		c.Modules.Net = &plan.NetSettings{Services: map[string]string{"tcp/80": svc}}
	}
	return c
}

type cfgEnv struct {
	ctl   *fakeController
	priv  ed25519.PrivateKey
	l     Layout
	probe *probeFactory
}

func newCfgEnv(t *testing.T) *cfgEnv {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctl := newFakeController(t, "h", "tok", 0)
	l := Layout{Root: t.TempDir()}
	if err := l.SaveBundle(&Bundle{Controllers: []string{ctl.addr}, ControllerPin: ctl.id.Pin.String(), Host: "h", Token: "tok",
		PlanKey: hex.EncodeToString(pub)}); err != nil {
		t.Fatal(err)
	}
	return &cfgEnv{ctl: ctl, priv: priv, l: l, probe: &probeFactory{}}
}

func (e *cfgEnv) start(t *testing.T) *runningAgent {
	return startAgent(t, Config{Layout: e.l, HeartbeatInterval: 20 * time.Millisecond, Factories: []Factory{e.probe.factory()}})
}

func (e *cfgEnv) sign(t *testing.T, c *plan.AgentConfig) *link.Config {
	t.Helper()
	w, err := plan.SignConfig(e.priv, c)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (e *cfgEnv) lastHB() (link.Heartbeat, bool) {
	_, _, hbs := e.ctl.snapshot()
	if len(hbs) == 0 {
		return link.Heartbeat{}, false
	}
	return hbs[len(hbs)-1], true
}

func (e *cfgEnv) waitConfig(t *testing.T, want string) {
	t.Helper()
	eventually(t, 5*time.Second, "heartbeat config "+want, func() bool {
		hb, ok := e.lastHB()
		return ok && hb.Modules[ConfigStatusModule] == want
	})
}

func (e *cfgEnv) rejections() string {
	var b strings.Builder
	for _, f := range e.ctl.eventsOf("agent.config_rejected") {
		b.WriteString(f["reason"].(string) + "|")
	}
	return b.String()
}

// The agent starts, replaces and stops modules as the signed config changes,
// and reports the config in force in every heartbeat.
func TestConfigLifecycle(t *testing.T) {
	e := newCfgEnv(t)
	e.start(t)
	eventually(t, 5*time.Second, "connected", func() bool { return e.ctl.send(&link.Ack{}) == nil })
	e.waitConfig(t, "none/0.0")

	e.ctl.send(e.sign(t, cfgBody("h", 1, 1, "web")))
	e.waitConfig(t, "ok/1.1")
	eventually(t, 5*time.Second, "probe started", func() bool {
		for _, f := range e.ctl.eventsOf("probe.started") {
			if f["svc"] == "web" {
				return true
			}
		}
		return false
	})
	if hb, _ := e.lastHB(); hb.Modules["probe"] != StateRunning {
		t.Fatalf("heartbeat modules: %v", hb.Modules)
	}

	// Same settings, new version: the module is left alone.
	e.ctl.send(e.sign(t, cfgBody("h", 1, 2, "web")))
	e.waitConfig(t, "ok/1.2")
	if e.probe.builds.Load() != 1 || e.probe.starts.Load() != 1 {
		t.Fatalf("unchanged settings rebuilt the module: builds %d starts %d", e.probe.builds.Load(), e.probe.starts.Load())
	}

	// Changed settings: replaced.
	e.ctl.send(e.sign(t, cfgBody("h", 1, 3, "mail")))
	e.waitConfig(t, "ok/1.3")
	eventually(t, 5*time.Second, "replacement started", func() bool {
		for _, f := range e.ctl.eventsOf("probe.started") {
			if f["svc"] == "mail" {
				return true
			}
		}
		return false
	})
	if e.probe.builds.Load() != 2 {
		t.Fatalf("builds = %d", e.probe.builds.Load())
	}

	// Section removed: the module stops and disappears from the heartbeat.
	e.ctl.send(e.sign(t, cfgBody("h", 1, 4, "")))
	e.waitConfig(t, "ok/1.4")
	eventually(t, 5*time.Second, "probe gone", func() bool {
		hb, _ := e.lastHB()
		_, has := hb.Modules["probe"]
		return !has
	})
	if hb, _ := e.lastHB(); hb.Modules["health"] == "" {
		t.Fatalf("health must keep running: %v", hb.Modules)
	}
	if got := e.rejections(); got != "" {
		t.Fatalf("unexpected rejections: %s", got)
	}
}

func TestConfigUnavailableModuleIsDegradedNotFatal(t *testing.T) {
	e := newCfgEnv(t)
	e.probe.unavailable = true
	r := e.start(t)
	e.ctl.send(&link.Ack{})
	eventually(t, 5*time.Second, "connected", func() bool { return e.ctl.send(&link.Ack{}) == nil })
	e.ctl.send(e.sign(t, cfgBody("h", 1, 1, "web")))
	e.waitConfig(t, "degraded/1.1")
	st := r.a.ConfigStatus()
	if !strings.HasPrefix(st.Modules["probe"], "unavailable: ") || !strings.Contains(st.Modules["probe"], "gadget") {
		t.Fatalf("status: %+v", st)
	}
	eventually(t, 5*time.Second, "applied event", func() bool {
		for _, f := range e.ctl.eventsOf("agent.config_applied") {
			if f["state"] == ConfigDegraded {
				return true
			}
		}
		return false
	})
}

// Tampered, replayed, old-epoch, foreign-host and unsigned configs are refused
// and change nothing.
func TestConfigRefusals(t *testing.T) {
	e := newCfgEnv(t)
	r := e.start(t)
	eventually(t, 5*time.Second, "connected", func() bool { return e.ctl.send(&link.Ack{}) == nil })
	good := e.sign(t, cfgBody("h", 2, 5, "web"))
	e.ctl.send(good)
	e.waitConfig(t, "ok/2.5")

	waitRej := func(substr string, n int) {
		t.Helper()
		eventually(t, 5*time.Second, "rejection "+substr, func() bool { return strings.Count(e.rejections(), substr) >= n })
	}
	// Tampered after signing.
	var c plan.AgentConfig
	json.Unmarshal(good.Body, &c)
	c.Modules.Net.Services["tcp/80"] = "evil"
	b, _ := json.Marshal(c)
	e.ctl.send(&link.Config{Version: 5, Epoch: 2, Body: b, Sig: good.Sig})
	waitRej("bad signature", 1)
	// Replay: an older version, correctly signed.
	e.ctl.send(e.sign(t, cfgBody("h", 2, 4, "old")))
	waitRej("sequence not greater", 1)
	// Old epoch with a large version.
	e.ctl.send(e.sign(t, cfgBody("h", 1, 99, "old")))
	waitRej("epoch older", 1)
	// Another host's config.
	e.ctl.send(e.sign(t, cfgBody("other", 3, 1, "x")))
	waitRej("different host", 1)
	// Signed by someone else.
	_, rogue, _ := ed25519.GenerateKey(rand.Reader)
	w, _ := plan.SignConfig(rogue, cfgBody("h", 9, 9, "x"))
	e.ctl.send(w)
	waitRej("bad signature", 2)
	// The same good config again is not an error: it is already in force.
	e.ctl.send(good)
	time.Sleep(150 * time.Millisecond)

	if st := r.a.ConfigStatus(); st.State != ConfigOK || st.Epoch != 2 || st.Version != 5 {
		t.Fatalf("status moved: %+v", st)
	}
	if e.probe.builds.Load() != 1 {
		t.Fatalf("a refused config rebuilt a module (%d builds)", e.probe.builds.Load())
	}
	for _, f := range e.ctl.eventsOf("probe.started") {
		if f["svc"] != "web" {
			t.Fatalf("a refused setting took effect: %v", f)
		}
	}
	if strings.Count(e.rejections(), "|") != 5 {
		t.Fatalf("rejections: %s", e.rejections())
	}
	// A newer good config still works afterwards.
	e.ctl.send(e.sign(t, cfgBody("h", 2, 6, "web")))
	e.waitConfig(t, "ok/2.6")
}

func TestConfigNeverAcceptedUnsigned(t *testing.T) {
	ctl := newFakeController(t, "h", "tok", 0)
	l := Layout{Root: t.TempDir()}
	writeBundle(t, l, ctl, "tok") // no plan key
	p := &probeFactory{}
	r := startAgent(t, Config{Layout: l, HeartbeatInterval: 20 * time.Millisecond, Factories: []Factory{p.factory()}})
	eventually(t, 5*time.Second, "connected", func() bool { return ctl.send(&link.Ack{}) == nil })
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	w, _ := plan.SignConfig(priv, cfgBody("h", 1, 1, "web"))
	ctl.send(w)
	eventually(t, 5*time.Second, "rejection", func() bool {
		for _, f := range ctl.eventsOf("agent.config_rejected") {
			if strings.Contains(f["reason"].(string), "never accepted unsigned") {
				return true
			}
		}
		return false
	})
	if p.builds.Load() != 0 || r.a.ConfigStatus().State != ConfigNone {
		t.Fatal("an unverifiable config was applied")
	}
}

// With the controller gone, a restarted agent runs the last good config from
// disk; a tampered file is refused; a controller that returns with the same
// config is not an error, and an older one is a replay.
func TestConfigPersistedAcrossRestartWithoutController(t *testing.T) {
	e := newCfgEnv(t)
	r := e.start(t)
	eventually(t, 5*time.Second, "connected", func() bool { return e.ctl.send(&link.Ack{}) == nil })
	good := e.sign(t, cfgBody("h", 1, 7, "web"))
	e.ctl.send(good)
	e.waitConfig(t, "ok/1.7")
	r.stop()
	e.ctl.stop() // the controller is gone for the rest of the test

	r2 := e.start(t)
	eventually(t, 5*time.Second, "persisted config running", func() bool {
		st := r2.a.ConfigStatus()
		return st.State == ConfigOK && st.Version == 7 && e.probe.starts.Load() == 2
	})
	if r2.a.AppliedConfig().Modules.Net.Services["tcp/80"] != "web" {
		t.Fatal("persisted settings lost")
	}
	r2.stop()

	// Tamper with the file at rest: the signature no longer verifies.
	raw, err := os.ReadFile(e.l.Config())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.l.Config(), []byte(strings.Replace(string(raw), "web", "evl", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	e.probe.starts.Store(0)
	r3 := e.start(t)
	time.Sleep(300 * time.Millisecond)
	if st := r3.a.ConfigStatus(); st.State != ConfigNone || e.probe.starts.Load() != 0 {
		t.Fatalf("tampered persisted config ran: %+v starts %d", st, e.probe.starts.Load())
	}
}

func TestConfigMarkSurvivesRestart(t *testing.T) {
	e := newCfgEnv(t)
	r := e.start(t)
	eventually(t, 5*time.Second, "connected", func() bool { return e.ctl.send(&link.Ack{}) == nil })
	e.ctl.send(e.sign(t, cfgBody("h", 1, 7, "web")))
	e.waitConfig(t, "ok/1.7")
	r.stop()

	// Heartbeats from the first run are still in the fake controller's log
	// and its previous session may linger, so wait for a heartbeat from the
	// restarted agent itself before sending on the (now current) session.
	_, _, old := e.ctl.snapshot()
	e.start(t)
	eventually(t, 5*time.Second, "restarted agent heartbeat", func() bool {
		_, _, hbs := e.ctl.snapshot()
		return len(hbs) > len(old) && hbs[len(hbs)-1].Modules[ConfigStatusModule] == "ok/1.7"
	})
	before := strings.Count(e.rejections(), "|")
	stale := e.sign(t, cfgBody("h", 1, 6, "stale"))
	eventually(t, 5*time.Second, "replay refused after restart", func() bool {
		if strings.Count(e.rejections(), "|") > before {
			return true
		}
		e.ctl.send(stale) // resend: a send racing the reconnect can be lost
		return false
	})
}

// Supervisor.Add/Remove while running.
func TestSupervisorDynamic(t *testing.T) {
	var got atomic.Int32
	s := NewSupervisor(SupervisorOptions{Emit: func(event.Event) error { got.Add(1); return nil }})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	eventually(t, time.Second, "run started", func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.ctx != nil })
	stopped := make(chan struct{})
	if err := s.Add(ModuleSpec{Module: funcModule{"a", func(ctx context.Context, emit Emit) error {
		emit(event.Event{Kind: "x"})
		<-ctx.Done()
		close(stopped)
		return nil
	}}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, "module emitted", func() bool { return got.Load() == 1 })
	if !s.Remove("a") {
		t.Fatal("remove")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("Remove returned before the module stopped")
	}
	if s.Has("a") || s.Remove("a") {
		t.Fatal("module still registered")
	}
	if err := s.Add(ModuleSpec{Module: funcModule{"a", func(ctx context.Context, _ Emit) error { <-ctx.Done(); return nil }}}); err != nil {
		t.Fatalf("re-add under the same name: %v", err)
	}
	cancel()
	<-done
	if err := s.Add(ModuleSpec{Module: funcModule{"late", nil}}); err == nil {
		t.Fatal("add after shutdown must fail")
	}
}
