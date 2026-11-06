package controller

import (
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func TestHostSubscribeCommitted(t *testing.T) {
	c := newTestControllerWithManifest(t, nil)
	h := c.hostFor(testMod())
	ch, stop := h.Subscribe([]string{"agent.resumed", "agent.silent"}, 8)
	defer stop()
	_, _ = c.EmitController(ctx, mustNew(t, "agent.silent", event.AgentSilent{Host: "h1"}))
	_, _ = c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	select {
	case e := <-ch:
		if e.Kind != "agent.resumed" {
			t.Fatalf("got %s (agent.silent is not in Consumes)", e.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
}

func TestHostSubscribeSlowConsumer(t *testing.T) {
	c := newTestControllerWithManifest(t, nil)
	_, stop := c.hostFor(testMod()).Subscribe([]string{"agent.resumed"}, 1)
	defer stop()
	start := time.Now()
	for i := 0; i < 50; i++ {
		_, _ = c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	}
	if time.Since(start) > 5*time.Second || c.bus.dropped("ctltest") == 0 {
		t.Fatalf("blocked or not counted: %v %d", time.Since(start), c.bus.dropped("ctltest"))
	}
}
