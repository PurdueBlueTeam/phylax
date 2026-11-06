package controller

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"

	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// Controller-scope detection. Some rules need events from several agents
// (D13e: many sources in one network probing many host/port pairs). Agents
// cannot evaluate them, so the controller runs the rules whose scope is
// "controller" over the network events every agent ships:
//
//   - net.flow from the capture module (SYN-only and refused flows included),
//     translated to the net.connection_opened shape the rules are written
//     against;
//   - net.connection_opened from the net module, as is.
//
// Alerts go to the operator queue (RecordAlert) with the flow events as
// evidence. Only stored events are fed (the ingest path passes the stored
// prefix), in agent order, so a retransmitted batch is never counted twice.

const (
	kindFlow       = "net.flow"
	kindConnOpened = "net.connection_opened"
)

type captureState struct {
	c *Controller

	mu      sync.Mutex
	in      *ConfigInputs
	man     *manifest.Manifest
	eng     *detect.Engine
	learned map[string]bool
	noRules bool
	// lastErrIn is the inputs whose rules failed to load, so the error is
	// logged once per change.
	lastErrIn *ConfigInputs
}

var (
	capMu     sync.Mutex
	capStates = map[*Controller]*captureState{}
)

// capture returns the controller's capture-scope state (created on first use;
// the controller struct is shared with other tasks, so it lives here).
func (c *Controller) capture() *captureState {
	capMu.Lock()
	defer capMu.Unlock()
	s := capStates[c]
	if s == nil {
		s = &captureState{c: c, learned: map[string]bool{}}
		capStates[c] = s
	}
	return s
}

// engine returns the controller-scope engine for the current config inputs,
// rebuilding it when they changed. nil when there are no controller rules.
func (s *captureState) engine() *detect.Engine {
	c := s.c
	c.cfgs.mu.Lock()
	in := c.cfgs.in
	c.cfgs.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if in == nil {
		return nil
	}
	if s.in == in && s.man == in.Manifest && (s.eng != nil || s.noRules) {
		return s.eng
	}
	s.in, s.man, s.eng, s.noRules = in, in.Manifest, nil, true
	if len(in.Rules) == 0 {
		return nil
	}
	d := &plan.DetectSettings{Rules: in.Rules}
	rs, err := detect.Parse("controller", d.RuleStream(), detect.LoadOptions{AllowUntested: true})
	if err != nil {
		if s.lastErrIn != in {
			s.lastErrIn = in
			c.log.Error("controller-scope rules", "err", err)
		}
		return nil
	}
	rules := rs.Rules[:0:0]
	for _, r := range rs.Rules {
		if r.Scope == "controller" {
			rules = append(rules, r)
		}
	}
	if len(rules) == 0 {
		return nil
	}
	rs.Rules = rules
	eng := detect.NewEngine(rs, detect.Options{Clock: c.now})
	srcs := ManifestScorerSources(in.Manifest)
	for a := range s.learned {
		srcs = append(srcs, a)
	}
	if len(srcs) > 0 {
		// An error means the rules ship no such profile: nothing to seed.
		_ = eng.Seed(scorerSourceProfile, nil, srcs...)
	}
	s.eng, s.noRules = eng, false
	return eng
}

func (s *captureState) noteSource(addr string) bool {
	s.mu.Lock()
	if s.learned[addr] {
		s.mu.Unlock()
		return true
	}
	if len(s.learned) >= maxLearnedSources {
		s.mu.Unlock()
		return false
	}
	s.learned[addr] = true
	eng := s.eng
	s.mu.Unlock()
	if eng != nil {
		_ = eng.Seed(scorerSourceProfile, nil, addr)
	}
	return true
}

// captureObserve feeds the stored events of an ingest batch to the
// controller-scope rules. It never fails ingest.
func (c *Controller) captureObserve(ctx context.Context, run []event.Event, stored uint64) {
	var feed []event.Event
	for _, e := range run {
		if e.Seq > stored || (e.Kind != kindFlow && e.Kind != kindConnOpened) {
			continue
		}
		feed = append(feed, e)
	}
	if len(feed) == 0 {
		return
	}
	eng := c.capture().engine()
	if eng == nil {
		return
	}
	for _, e := range feed {
		ev, ok := connEvent(e)
		if !ok {
			continue
		}
		for _, a := range eng.Process(ev) {
			if _, err := c.RecordAlert(ctx, a); err != nil {
				c.log.Error("cannot queue controller-scope alert", "rule", a.RuleID, "err", err)
			}
		}
	}
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil
	case string:
		i, err := strconv.Atoi(n)
		return i, err == nil
	}
	return 0, false
}

// connEvent maps an agent network event to the net.connection_opened shape.
// Flows without a direction (the agent did not know its own addresses) and
// flows that never reached the host (outbound) are not fed; keeping Agent and
// Seq lets alerts reference the exact events as evidence.
func connEvent(e event.Event) (event.Event, bool) {
	f := e.Fields
	raddr, _ := f["raddr"].(string)
	laddr, _ := f["laddr"].(string)
	dir, _ := f["dir"].(string)
	port, ok := asInt(f["lport"])
	if raddr == "" || laddr == "" || dir == "" || !ok {
		return event.Event{}, false
	}
	out := map[string]any{"dir": dir, "raddr": raddr, "laddr": laddr, "lport": port}
	if rp, ok := asInt(f["rport"]); ok {
		out["rport"] = rp
	}
	if p, ok := f["proto"].(string); ok {
		out["proto"] = p
	}
	if h, ok := f["handshake"].(string); ok {
		out["handshake"] = h
	}
	if e.Kind == kindFlow {
		out["source"] = "capture"
	}
	return event.Event{Agent: e.Agent, Seq: e.Seq, Time: e.Time, Kind: kindConnOpened, Priority: e.Priority, Fields: out}, true
}
