package conformance

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

type fixtureModule struct {
	name   string
	start  func(ctx context.Context, emit agent.Emit) error
	health func() module.Health
}

func (m fixtureModule) Name() string { return m.name }
func (m fixtureModule) Start(ctx context.Context, emit agent.Emit) error {
	if m.start != nil {
		return m.start(ctx, emit)
	}
	<-ctx.Done()
	return nil
}
func (m fixtureModule) Health() module.Health {
	if m.health != nil {
		return m.health()
	}
	return module.Health{State: module.StateOK}
}

func fixtureFactory(name string, start func(context.Context, agent.Emit) error) agent.Factory {
	return agent.Factory{Name: name, Section: func(*plan.AgentConfig) (string, bool) { return "v1", true },
		Build: func(agent.Env, *plan.AgentConfig) (agent.ModuleSpec, error) {
			return agent.ModuleSpec{Module: fixtureModule{name: name, start: start}}, nil
		}}
}

func goodFactory() agent.Factory { return fixtureFactory("good", nil) }
func leakyFactory() agent.Factory {
	return fixtureFactory("leaky", func(ctx context.Context, _ agent.Emit) error {
		go func() { <-ctx.Done() }()
		<-ctx.Done()
		return nil
	})
}
func neverOKFactory() agent.Factory {
	return agent.Factory{Name: "neverok", Section: func(*plan.AgentConfig) (string, bool) { return "v1", true },
		Build: func(agent.Env, *plan.AgentConfig) (agent.ModuleSpec, error) {
			return agent.ModuleSpec{Module: fixtureModule{name: "neverok", health: func() module.Health {
				return module.Health{State: module.StateRestarting}
			}}}, nil
		}}
}
func panicsWithoutConfigFactory() agent.Factory {
	return agent.Factory{Name: "p", Section: func(*plan.AgentConfig) (string, bool) { panic("no config") },
		Build: func(agent.Env, *plan.AgentConfig) (agent.ModuleSpec, error) { return agent.ModuleSpec{}, nil }}
}
func emitsUndeclaredFactory() agent.Factory {
	return fixtureFactory("undecl", func(ctx context.Context, emit agent.Emit) error {
		_ = emit(event.Event{Kind: "undecl.nope"})
		<-ctx.Done()
		return nil
	})
}
func emitsConnWithSrcIPFactory() agent.Factory {
	return fixtureFactory("legacy", func(ctx context.Context, emit agent.Emit) error {
		_ = emit(event.Event{Kind: event.KindConn, Schema: 1, Fields: map[string]any{"op": "opened", "dir": "outbound", "proto": "tcp", "source": "net", "src_ip": "1.2.3.4"}})
		<-ctx.Done()
		return nil
	})
}
func heldBytesLiarFactory() agent.Factory {
	return agent.Factory{Name: "fat", Section: func(*plan.AgentConfig) (string, bool) { return "v1", true },
		Build: func(agent.Env, *plan.AgentConfig) (agent.ModuleSpec, error) {
			return agent.ModuleSpec{Module: fixtureModule{name: "fat", health: func() module.Health {
				return module.Health{State: module.StateOK, Usage: module.Usage{HeldBytes: 1 << 40}}
			}}}, nil
		}}
}
func crashOnEmitErrFactory() agent.Factory {
	return fixtureFactory("fragile", func(ctx context.Context, emit agent.Emit) error {
		if err := emit(event.Event{Kind: "fragile.x"}); err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	})
}
func wrongOSNoGapFactory() agent.Factory {
	f := fixtureFactory("os", nil)
	f.Manifest = module.Manifest{Name: "os", Sides: []module.Side{module.SideAgent}, OS: []string{"plan9"}, Privilege: "user"}
	return f
}
func forgetfulFactory() agent.Factory {
	return fixtureFactory("forget", nil)
}
func cfgWith(name string) *plan.AgentConfig  { return &plan.AgentConfig{Host: "h1"} }
func cfgWith2(name string) *plan.AgentConfig { return &plan.AgentConfig{Host: "h1"} }
func someLoad() []event.Event                { return []event.Event{{Kind: "agent.resumed"}} }

type looseSettings struct{ N int }

func (*looseSettings) UnmarshalJSON(b []byte) error {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	return nil
}

type ctlFixture struct {
	m module.Manifest
}

func (c ctlFixture) Manifest() module.Manifest                    { return c.m }
func (ctlFixture) Start(ctx context.Context, _ module.Host) error { <-ctx.Done(); return nil }
func (ctlFixture) Health() module.Health                          { return module.Health{State: module.StateOK} }

type anaFixture struct {
	ctlFixture
	as []module.Analyzer
}

func (a anaFixture) Analyzers() []module.Analyzer { return a.as }

func randomAnalyserModule() module.ControllerModule {
	return anaFixture{ctlFixture{module.Manifest{Name: "rand", Sides: []module.Side{module.SideController}, Privilege: "none"}},
		[]module.Analyzer{{Name: "rand", Every: time.Second, Run: func(context.Context, store.Reader, time.Time) ([]event.Event, error) {
			return []event.Event{{Kind: "rand.x", Fields: map[string]any{"n": atomic.AddInt64(new(int64), 1)}}}, nil
		}}}}
}

func ignoresConfigErrorModule() module.ControllerModule {
	return ctlFixture{module.Manifest{Name: "loose", Sides: []module.Side{module.SideController}, Privilege: "none"}}
}

func goodControllerModule() module.ControllerModule {
	return ctlFixture{module.Manifest{Name: "goodctl", Sides: []module.Side{module.SideController}, Privilege: "none"}}
}
