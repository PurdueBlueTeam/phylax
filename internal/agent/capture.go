package agent

import (
	"context"

	"github.com/PurdueBlueTeam/phylax/internal/capture"
	"github.com/PurdueBlueTeam/phylax/internal/checks"
	"github.com/PurdueBlueTeam/phylax/internal/spool"
)

// startCapture runs the capture role (docs: agent roles): the packet
// ring, flow tracker and phase-1 parsers, feeding the spool. Events flow
// through the normal spool path, so they are chain-hashed and mirrored
// like every other event.
func (a *Agent) startCapture(ctx context.Context) {
	cfg := a.bundle.Capture
	if cfg == nil {
		return
	}
	ringBytes := cfg.RingBytes
	if ringBytes <= 0 {
		ringBytes = 64 << 20
	}
	m := capture.New(cfg.Ifaces, cfg.Full, cfg.PortProto, capture.NewRing(int(ringBytes)), a)
	a.StartModule("capture", func(ctx context.Context) error {
		err := m.Run(ctx)
		a.SetModule("capture", "ok")
		return err
	})
}

// checkSink publishes check results and red transitions to the spool;
// the controller aggregates the vantage points (docs: two vantage
// points, side by side).
type checkSink struct {
	a *Agent
}

func (s *checkSink) Result(r checks.Result) {
	_ = s.a.PublishClass("check_result", r, spool.ClassProtected)
}

func (s *checkSink) Red(r checks.Result) {
	// a red check opens an alert on the controller with the response
	// diff attached (docs: Active checks — Results)
	_ = s.a.PublishClass("check_red", r, spool.ClassProtected)
}

// startChecks runs the check_runner role (docs: agent roles): the
// active-check list from inside this segment, on its own vantage.
func (a *Agent) startChecks(ctx context.Context) {
	if len(a.bundle.Checks) == 0 {
		return
	}
	v := "segment:" + a.bundle.Segment
	c := checks.NewChecker(v)
	for _, ck := range a.bundle.Checks {
		c.Upsert(ck)
	}
	c.SetSink(&checkSink{a: a})
	a.StartModule("checks", c.Run)
}
