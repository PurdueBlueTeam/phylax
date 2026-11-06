package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

type anaMod struct {
	ctlMod
	as []module.Analyzer
}

func (a anaMod) Analyzers() []module.Analyzer { return a.as }

func TestAnalyzerTriggeredByInput(t *testing.T) {
	t.Skip("unimplemented: W1 Task 20")
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n"})
	m := anaMod{testMod(), []module.Analyzer{{Name: "count", Inputs: []string{"agent.resumed"},
		Run: func(ctx context.Context, q store.Reader, now time.Time) ([]event.Event, error) {
			evs, err := q.Events(ctx, store.Query{Kind: "agent.resumed"})
			if err != nil {
				return nil, err
			}
			out, err := event.New("ctltest.found", struct {
				X string `json:"x"`
			}{fmt.Sprint(len(evs))})
			return []event.Event{out}, err
		}}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.RunModules(ctx, []module.ControllerModule{m})
	_, _ = c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	// poll up to 4 s: c.st.Latest(ctx, "controller", "ctltest.found") has Fields["x"] == "1"
}

func TestAnalyzerDeadline(t *testing.T) {
	t.Skip("unimplemented: W1 Task 20")
	c := newTestControllerWithManifest(t, map[string]string{"modules/ctltest.yml": "enabled: true\n"})
	c.analysisDeadline = 100 * time.Millisecond
	m := anaMod{testMod(), []module.Analyzer{{Name: "slow", Every: 50 * time.Millisecond,
		Run: func(ctx context.Context, _ store.Reader, _ time.Time) ([]event.Event, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.RunModules(ctx, []module.ControllerModule{m})
	// poll up to 2 s: some gap in c.ModuleHealth()["ctltest"].Gaps has What == "analyser slow"
}
