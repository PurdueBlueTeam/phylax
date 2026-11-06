package link

import (
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/module"
)

func TestHeartbeatHealthBounds(t *testing.T) {
	t.Skip("unimplemented: W1 Task 14")
	ok := &Heartbeat{HostClock: time.Now(), Health: map[string]module.Health{"a": {State: module.StateOK}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	gaps := make([]module.Gap, 33)
	bad := &Heartbeat{HostClock: time.Now(), Health: map[string]module.Health{"a": {State: module.StateOK, Gaps: gaps}}}
	if bad.Validate() == nil {
		t.Fatal("33 gaps accepted")
	}
}
