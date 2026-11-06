package link

import (
	"strings"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/module"
)

func TestHeartbeatHealthBounds(t *testing.T) {
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

func TestHeartbeatHealthStateBound(t *testing.T) {
	ok := &Heartbeat{HostClock: time.Now(), Health: map[string]module.Health{"a": {State: module.StateOK}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, state := range []module.State{module.State(strings.Repeat("s", MaxHealthState)), module.State(strings.Repeat("s", MaxHealthState+1))} {
		hb := &Heartbeat{HostClock: time.Now(), Health: map[string]module.Health{"a": {State: state}}}
		err := hb.Validate()
		if len(state) == MaxHealthState && err != nil {
			t.Fatalf("%d-byte state rejected: %v", len(state), err)
		}
		if len(state) > MaxHealthState && err == nil {
			t.Fatalf("%d-byte state accepted", len(state))
		}
	}
}
