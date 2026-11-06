package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/plan"
)

// maxFacts bounds the in-memory fact table; the oldest fact is evicted.
const maxFacts = 1024

// maxFactID bounds a fact id (the controller enforces the same bound).
const maxFactID = 128

// factStore holds the controller facts this agent received, keyed by id,
// together with the agent's receipt time: a fact's TTL counts from receipt, so
// the controller's clock cannot shorten or extend it.
type factStore struct {
	mu    sync.Mutex
	facts map[string]event.ControllerFact
	at    map[string]time.Time
	order []string
}

// put stores f, replacing an earlier fact of the same id and evicting the
// oldest when the table is full.
func (s *factStore) put(f event.ControllerFact, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.facts == nil {
		s.facts = map[string]event.ControllerFact{}
		s.at = map[string]time.Time{}
	}
	if _, ok := s.facts[f.ID]; ok {
		for i, id := range s.order {
			if id == f.ID {
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
	} else if len(s.facts) >= maxFacts {
		old := s.order[0]
		s.order = s.order[1:]
		delete(s.facts, old)
		delete(s.at, old)
	}
	s.facts[f.ID] = f
	s.at[f.ID] = at
	s.order = append(s.order, f.ID)
}

// get returns a fact by id; false when it was never received or its TTL,
// counted from the receipt time, has passed.
func (s *factStore) get(id string, now time.Time) (event.ControllerFact, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.facts[id]
	if !ok {
		return event.ControllerFact{}, false
	}
	if now.After(s.at[id].Add(f.TTL)) {
		return event.ControllerFact{}, false
	}
	return f, true
}

// clock is the agent's wall clock for facts. Tests replace it.
func (a *Agent) clock() time.Time {
	a.clkMu.RLock()
	f := a.nowFn
	a.clkMu.RUnlock()
	if f == nil {
		return time.Now()
	}
	return f()
}

// setNow replaces the agent's wall clock (tests). nil restores time.Now.
func (a *Agent) setNow(f func() time.Time) {
	a.clkMu.Lock()
	a.nowFn = f
	a.clkMu.Unlock()
}

// receiveFact decodes, bounds and stores a control: fact. The args are the
// control's signed JSON body; anything malformed or out of bounds is refused
// with an agent.control_refused event and never reaches the bus.
func (a *Agent) receiveFact(args []byte) error {
	refuse := func(why string) error {
		a.log.Warn("fact refused", "why", why)
		a.emit(core("agent.control_refused", event.AgentControlRefused{Kind: plan.ControlFact, Reason: why}))
		return nil
	}
	if len(args) == 0 {
		return refuse("empty fact")
	}
	if len(args) > plan.MaxFactData {
		return refuse("fact larger than the data limit")
	}
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	var f event.ControllerFact
	if err := dec.Decode(&f); err != nil {
		return refuse("bad fact: " + err.Error())
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return refuse("bad fact: trailing data")
	}
	switch {
	case f.Fact == "":
		return refuse("fact has no subtype")
	case len(f.ID) == 0 || len(f.ID) > maxFactID:
		return refuse("fact id outside 1..128 bytes")
	case f.TTL <= 0 || f.TTL > plan.MaxFactTTL:
		return refuse("fact ttl outside (0, " + plan.MaxFactTTL.String() + "]")
	}
	a.deliverFact(f)
	return nil
}

// deliverFact stores a verified fact and publishes it on the on-host bus. A
// fact is never spooled: it describes the controller's intent, not the host.
func (a *Agent) deliverFact(f event.ControllerFact) {
	a.facts.put(f, a.clock())
	e, err := event.New("controller.fact", f)
	if err != nil {
		a.log.Error("controller.fact event", "err", err)
		return
	}
	a.publish(e)
	if f.Fact == "work_window" {
		if err := a.window.apply(f); err != nil {
			a.log.Warn("work_window fact", "err", err)
		}
	}
}
