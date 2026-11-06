package agent

import (
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func TestFactReachesBusNotSpool(t *testing.T) {
	t.Skip("unimplemented: W1 Task 31")
	h, _ := NewHarness(HarnessOptions{Host: "h1", StateDir: t.TempDir(), Factories: []Factory{subscriberFactory("fx", []string{"controller.fact"})}})
	// run, apply; ch := the subscriber module's received channel
	h.Fact(event.ControllerFact{ID: "rc", Fact: "round_clock", TS: time.Now(), TTL: time.Minute, Data: map[string]any{"delay": 60}})
	// want: the subscriber receives one event of kind controller.fact with Fields["id"] == "rc"
	// want: no controller.fact in h.Emitted() (nothing reached the spool path)
}

func TestFactTTLFromReceipt(t *testing.T) {
	t.Skip("unimplemented: W1 Task 31")
	h, _ := NewHarness(HarnessOptions{Host: "h1", StateDir: t.TempDir()})
	now := time.Now()
	h.setNow(func() time.Time { return now })
	h.Fact(event.ControllerFact{ID: "x", Fact: "round_clock", TS: now.Add(-time.Hour), TTL: time.Minute})
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
	t.Skip("unimplemented: W1 Task 31")
	// two facts with ID "x", Data {"v":1} then {"v":2}: Env.Fact("x").Data["v"] == json.Number("2")
}

func TestUnknownControlRefused(t *testing.T) {
	t.Skip("unimplemented: W1 Task 31")
	// test agent of testutil_test.go: a correctly signed control of kind "made_up" -> an agent.control_refused event
	// with Fields["kind"] == "made_up" is spooled; the agent keeps running
}
