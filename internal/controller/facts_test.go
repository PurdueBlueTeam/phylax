package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/link"
	"github.com/PurdueBlueTeam/phylax/internal/module"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

func TestSendFactValidates(t *testing.T) {
	c := newTestControllerWithManifest(t, nil) // host h1
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

// newFactController starts a real controller with a manifest and a connected
// in-process agent h1, and captures every signed control it hands out.
func newFactController(t *testing.T) (*ctl, *agent, func() []*link.Control) {
	t.Helper()
	var mu sync.Mutex
	var sent []*link.Control
	x := newCtlWith(t, Config{AgentListen: "127.0.0.1:0", DataDir: filepath.Join(t.TempDir(), "data"),
		SilenceThreshold: Duration(300 * time.Millisecond), ManifestPath: writeManifest(t, nil)},
		Options{OnControlSent: func(host string, c *link.Control) {
			mu.Lock()
			sent = append(sent, c)
			mu.Unlock()
		}})
	tok, err := x.c.MintToken("h1", 0)
	if err != nil {
		t.Fatal(err)
	}
	a := newAgent(t, x, "h1", tok)
	actx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go a.run(actx)
	waitFor(t, 5*time.Second, "agent h1 connected", func() bool { return x.c.sessionFor("h1") != nil })
	return x, a, func() []*link.Control {
		mu.Lock()
		defer mu.Unlock()
		return append([]*link.Control(nil), sent...)
	}
}

func TestSendFactSigned(t *testing.T) {
	x, _, sent := newFactController(t)
	// A host that is not connected is logged and skipped, not an error.
	if err := x.c.SendFact(ctx, "scorer", module.ControlMsg{Type: "fact", Hosts: []string{"db1"}, Fact: "round_clock", ID: "skip", TTL: time.Minute}); err != nil {
		t.Fatalf("offline host: %v", err)
	}
	good := module.ControlMsg{Type: "fact", Hosts: []string{"h1"}, Fact: "round_clock", ID: "rc", TTL: time.Minute, Data: map[string]any{"delay": 60}}
	if err := x.c.SendFact(ctx, "scorer", good); err != nil {
		t.Fatalf("send: %v", err)
	}
	var got *link.Control
	waitFor(t, 5*time.Second, "signed fact", func() bool {
		for _, c := range sent() {
			if c.Kind == plan.ControlFact {
				got = c
				return true
			}
		}
		return false
	})
	if !got.On {
		t.Error("a fact is sent with on: true")
	}
	var f event.ControllerFact
	dec := json.NewDecoder(bytes.NewReader(got.Args))
	dec.UseNumber()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("args: %v (%s)", err, got.Args)
	}
	if f.ID != "rc" || f.Fact != "round_clock" || f.TTL != time.Minute {
		t.Fatalf("args %+v", f)
	}
	if v, ok := f.Data["delay"].(json.Number); !ok || v != "60" {
		t.Fatalf("data %#v", f.Data)
	}
	if d := time.Since(f.TS); d < -time.Minute || d > time.Minute {
		t.Errorf("ts %v is not now", f.TS)
	}
}
