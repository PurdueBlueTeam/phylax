package controller

import (
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/module"
)

func TestSendFactValidates(t *testing.T) {
	t.Skip("unimplemented: W1 Task 30")
	c := newTestControllerWithManifest(t, nil)
	good := module.ControlMsg{Type: "fact", Hosts: []string{"h1"}, Fact: "round_clock", ID: "rc", TTL: time.Minute, Data: map[string]any{"delay": 60}}
	for i, f := range []func(*module.ControlMsg){
		func(m *module.ControlMsg) { m.Type = "safe_mode" },
		func(m *module.ControlMsg) { m.TTL = 0 },
		func(m *module.ControlMsg) { m.TTL = 25 * time.Hour },
		func(m *module.ControlMsg) { m.ID = "" },
		func(m *module.ControlMsg) { m.Data = map[string]any{"x": strings.Repeat("a", 17<<10)} },
		func(m *module.ControlMsg) { m.Hosts = []string{"nohost && x"} },
	} {
		m := good
		f(&m)
		if c.SendFact(ctx, "scorer", m) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if c.SendFact(ctx, "checks", good) == nil {
		t.Error("wrong sender accepted")
	}
}

func TestSendFactSigned(t *testing.T) {
	t.Skip("unimplemented: W1 Task 30")
	// e2e helpers with a connected agent h1; capture Options.OnControlSent
	// SendFact(ctx, "scorer", good) -> nil; the captured control has Kind "fact" and args decode to
	// event.ControllerFact{ID: "rc", Fact: "round_clock", TTL: time.Minute, ...}
}
