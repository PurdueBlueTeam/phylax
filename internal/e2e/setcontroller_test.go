package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/bootstrapfile"
)

// TestAgentFollowsSetController models an address change: controller A stops,
// controller B starts on another port over the same data dir (same identity),
// and set-controller rewrites the agent's bootstrap file. The agent must follow
// the file without re-enrolling.
func TestAgentFollowsSetController(t *testing.T) {
	h := newHarness(t)
	th := h.addHost("h1")
	before, err := h.c.Store().Agent(context.Background(), "h1")
	if err != nil {
		t.Fatal(err)
	}

	h.stopController()
	h.addr = ""
	h.startController()
	newAddr := h.addr
	if newAddr == "" {
		t.Fatal("the second controller did not pick an address")
	}

	if err := bootstrapfile.Rewrite(th.layout.Bootstrap(), []string{newAddr}, ""); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the agent to connect to the new controller address", 10*time.Second, func() bool {
		st, ok := h.c.AgentStatus("h1")
		return ok && st.Connected
	})
	after, err := h.c.Store().Agent(context.Background(), "h1")
	if err != nil {
		t.Fatal(err)
	}
	// No re-enrollment: the enrolled key and time are unchanged.
	if !after.EnrolledAt.Equal(before.EnrolledAt) {
		t.Fatalf("h1 enrolled again at %v (was %v)", after.EnrolledAt, before.EnrolledAt)
	}
	b, err := th.layout.LoadBundle()
	if err != nil {
		t.Fatal(err)
	}
	if b.Token != "" {
		t.Fatalf("the agent re-used its enrollment token: %q", b.Token)
	}
}
