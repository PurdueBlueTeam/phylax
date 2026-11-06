package controller

import (
	"errors"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/store"
)

func TestEmitControllerChain(t *testing.T) {
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
	c := newTestController(t)
	_, _ = c.EmitController(ctx, mustNew(t, "agent.silent", event.AgentSilent{Host: "h1", Detail: "no message"}))
	_, _ = c.EmitController(ctx, mustNew(t, "agent.resumed", event.AgentResumed{Host: "h1"}))
	rows, err := c.st.Alerts(ctx, "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("alert rows: %+v", rows)
	}
	if rows[0].Rule != "agent.silent" || rows[0].Host != "h1" || rows[0].Agent != "controller" {
		t.Fatalf("row %+v", rows[0])
	}
}

func TestEmitControllerRejectsUndeclared(t *testing.T) {
	c := newTestController(t)
	if _, err := c.EmitController(ctx, event.Event{Kind: "nope"}); !errors.Is(err, event.ErrUndeclared) {
		t.Fatalf("got %v", err)
	}
}

func TestDeclaredAlertBecomesEvent(t *testing.T) {
	c := newTestController(t)
	c.alert("h1", "agent.silent", "no message for 30s")
	e, err := c.st.Latest(ctx, "controller", "agent.silent")
	if err != nil {
		t.Fatal(err)
	}
	if e.Fields["host"] != "h1" || e.Fields["detail"] != "no message for 30s" {
		t.Fatalf("%+v", e.Fields)
	}
	// An undeclared alert kind stays in the ring: nothing to store.
	c.alert("h1", "store.chain_error", "seq 4 hash mismatch")
	if _, err := c.st.Latest(ctx, "controller", "store.chain_error"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("undeclared kind stored: %v", err)
	}
	if n := len(c.Alerts()); n != 2 {
		t.Fatalf("ring holds %d alerts, want 2", n)
	}
}
