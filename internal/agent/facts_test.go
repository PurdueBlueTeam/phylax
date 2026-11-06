package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// startBusHarness runs a harness with one subscriber module and waits until it
// has subscribed, so a published fact cannot land before the bus has a reader.
func startBusHarness(t *testing.T, dir string, factories []Factory) (*Harness, context.CancelFunc) {
	t.Helper()
	h, err := NewHarness(HarnessOptions{Host: "h1", StateDir: dir, Factories: factories})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go h.Run(ctx)
	h.Apply(&plan.AgentConfig{Host: "h1"})
	eventually(t, 5*time.Second, "module subscribed", func() bool { return h.a.Subscribers() > 0 })
	return h, cancel
}

func TestFactReachesBusNotSpool(t *testing.T) {
	h, cancel := startBusHarness(t, t.TempDir(), []Factory{subscriberFactory("fx", []string{"controller.fact"})})
	defer cancel()
	ch := testSubscriber("fx")
	h.Fact(event.ControllerFact{ID: "rc", Fact: "round_clock", TS: time.Now(), TTL: time.Minute, Data: map[string]any{"delay": 60}})
	select {
	case e := <-ch:
		if e.Kind != "controller.fact" || e.Fields["id"] != "rc" {
			t.Fatalf("bus event %s %#v", e.Kind, e.Fields)
		}
		if v, ok := e.Fields["data"].(map[string]any); !ok || v["delay"] != json.Number("60") {
			t.Fatalf("data %#v", e.Fields["data"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the fact never reached the bus")
	}
	for _, e := range h.Emitted() {
		if e.Kind == "controller.fact" {
			t.Fatal("a fact reached the spool path")
		}
	}
}

func TestFactTTLFromReceipt(t *testing.T) {
	h, _ := NewHarness(HarnessOptions{Host: "h1", StateDir: t.TempDir()})
	now := time.Now()
	h.setNow(func() time.Time { return now })
	h.Fact(event.ControllerFact{ID: "x", Fact: "round_clock", TS: now.Add(-time.Hour), TTL: time.Minute}) // controller clock an hour behind
	if _, ok := h.env().Fact("x"); !ok {
		t.Fatal("fact must be known right after receipt")
	}
	now = now.Add(61 * time.Second)
	if _, ok := h.env().Fact("x"); ok {
		t.Fatal("fact must be unknown after its TTL")
	}
	if _, ok := h.env().Fact("never"); ok {
		t.Fatal("unreceived fact must be unknown")
	}
}

func TestFactReplacedByID(t *testing.T) {
	h, _ := NewHarness(HarnessOptions{Host: "h1", StateDir: t.TempDir()})
	h.Fact(event.ControllerFact{ID: "x", Fact: "round_clock", TTL: time.Minute, Data: map[string]any{"v": 1}})
	h.Fact(event.ControllerFact{ID: "x", Fact: "round_clock", TTL: time.Minute, Data: map[string]any{"v": 2}})
	f, ok := h.env().Fact("x")
	if !ok {
		t.Fatal("fact missing")
	}
	if v, _ := f.Data["v"].(json.Number); v != json.Number("2") {
		t.Fatalf("a later fact with the same id must replace the earlier one: %#v", f.Data)
	}
}

func TestUnknownControlRefused(t *testing.T) {
	ctl, priv, _ := startWithKey(t)
	sg := &plan.ControlSigner{Key: priv, Epoch: 1, Seqs: &plan.MemSeq{}}
	c, err := sg.Issue("h", "made_up", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctl.send(plan.ControlToWire(c)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "refusal of the unknown control", func() bool {
		for _, f := range ctl.eventsOf("agent.control_refused") {
			if f["kind"] == "made_up" {
				return true
			}
		}
		return false
	})
	// The agent keeps running: a known control still takes effect.
	on, err := sg.Issue("h", plan.ControlSafeMode, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ctl.send(plan.ControlToWire(on)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "agent still accepts controls", func() bool {
		seeingOn, _ := safeModeSeen(ctl)
		return seeingOn
	})
}
