package agent

import (
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// The agent reports its highest accepted epoch (its sequence mark) in hello, so
// a restored controller can pick an epoch above everything the fleet accepted.
func TestHelloCarriesEpoch(t *testing.T) {
	ctl := newFakeController(t, "ubuntu-ecom", "tok-1", 0)
	l := Layout{Root: t.TempDir()}
	writeBundle(t, l, ctl, "tok-1")
	if err := (plan.FileSeqStore{Path: l.PlanSeq()}).Save(plan.Mark{Epoch: 5, Seq: 9}); err != nil {
		t.Fatal(err)
	}
	startAgent(t, Config{Layout: l, Version: "9.9", HeartbeatInterval: 50 * time.Millisecond})

	eventually(t, 5*time.Second, "hello", func() bool {
		_, hellos, _ := ctl.snapshot()
		return len(hellos) > 0
	})
	_, hellos, _ := ctl.snapshot()
	if hellos[0].Epoch != 5 {
		t.Fatalf("hello epoch %d, want the mark's epoch 5", hellos[0].Epoch)
	}
}
