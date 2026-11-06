package controller

import (
	"errors"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func TestEmitControllerChain(t *testing.T) {
	t.Skip("unimplemented: W1 Task 16")
	c := newTestController(t)
	e1, err := c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	if err != nil {
		t.Fatal(err)
	}
	e2, _ := c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h2"}))
	if e1.Agent != "controller" || e1.Seq != 1 || e2.Seq != 2 || e2.PrevHash != e1.Hash {
		t.Fatalf("%+v %+v", e1, e2)
	}
}

func TestEmitControllerAfterRestart(t *testing.T) {
	t.Skip("unimplemented: W1 Task 16")
	dir := t.TempDir()
	c := newTestControllerAt(t, dir)
	_, _ = c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	c.Close()
	c = newTestControllerAt(t, dir)
	e, err := c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	if err != nil || e.Seq != 2 {
		t.Fatalf("seq %d err %v", e.Seq, err)
	}
}

func TestEmitControllerAlertRow(t *testing.T) {
	t.Skip("unimplemented: W1 Task 16")
	c := newTestController(t)
	_, _ = c.EmitController(ctx, mustNew(t, "agent.silent", event.AgentSilent{Host: "h1", Detail: "no message"}))
	_, _ = c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	// want: exactly one alert row (list rows with the store method alerts.go uses), rule "agent.silent", host "h1"
}

func TestEmitControllerRejectsUndeclared(t *testing.T) {
	t.Skip("unimplemented: W1 Task 16")
	c := newTestController(t)
	if _, err := c.EmitController(ctx, event.Event{Kind: "nope"}); !errors.Is(err, event.ErrUndeclared) {
		t.Fatalf("got %v", err)
	}
}

func TestDeclaredAlertBecomesEvent(t *testing.T) {
	t.Skip("unimplemented: W1 Task 16")
	c := newTestController(t)
	c.alert("h1", "agent.silent", "no message for 30s")
	// want: c.st.Latest(ctx, "controller", "agent.silent") returns an event with Fields["host"] == "h1"
}
