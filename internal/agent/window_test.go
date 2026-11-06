package agent

import (
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

func TestWorkWindowStampsTag(t *testing.T) {
	t.Skip("unimplemented: W1 Task 32")
	dir := t.TempDir()
	h, _ := NewHarness(HarnessOptions{Host: "h1", StateDir: dir, Factories: []Factory{emitterFactory("wx")}})
	now := time.Now()
	h.setNow(func() time.Time { return now })
	h.Fact(event.ControllerFact{ID: "ww", Fact: "work_window", TS: now, TTL: time.Hour,
		Data: map[string]any{"window": "w1", "tag": "window:w1", "until": now.Add(10 * time.Minute).UTC().Format(time.RFC3339)}})
	triggerEmit("wx")
	// last emitted event has Tag "window:w1"
	// an emit with Tag "plan:p1" keeps "plan:p1"
	now = now.Add(11 * time.Minute)
	triggerEmit("wx")
	// last emitted event has Tag ""
}

func TestWorkWindowSurvivesRestart(t *testing.T) {
	t.Skip("unimplemented: W1 Task 32")
	// open a window ending in 10 minutes in harness 1; build harness 2 on the same StateDir
	// trigger one emit in harness 2 -> Tag "window:w1"
}

func TestWorkWindowEnd(t *testing.T) {
	t.Skip("unimplemented: W1 Task 32")
	// open, then a fact with {"window":"w1","end":true} -> next emit has Tag ""
}
