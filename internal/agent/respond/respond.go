// Package respond is the agent's `respond` module (docs: Response
// tiers): tier-0 automatic actions with guards. Only reversible actions
// on unscored state run automatically, and every automatic action is
// followed by a health check. Guards (docs: Guards on automatic
// actions): safe mode suspends; at most 3 tier-0 actions per host per
// minute (beyond that they become tier-1 proposals); if a health check
// goes red within 2 minutes of a tier-0 action, that action type is
// disabled on the host and escalated; the same restore 3 times in 10
// minutes opens an incident instead of restoring forever; plan locks
// are shared (a restore waits while a plan holds the lock).
package respond

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/detect"
)

// Outcome is one completed automatic action.
type Outcome struct {
	Action   string `json:"action"`
	Trigger  string `json:"trigger"` // rule id
	OK       bool   `json:"ok"`
	Detail   string `json:"detail,omitempty"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
	HealthOK bool   `json:"health_ok"`
	Escalate bool   `json:"escalate,omitempty"` // became a tier-1 proposal
	Reason   string `json:"reason,omitempty"`   // why it was not run / escalated
}

// Publish receives response events.
type Publisher interface {
	Publish(evType string, data any) error
}

// Env is what a recipe can touch.
type Env struct {
	// LockTry reports whether the named resource lock is free and takes
	// it for owner; false when held by someone else.
	LockTry func(name, owner string) bool
	// LockRelease returns a lock to the pool.
	LockRelease func(name, owner string)
	// LockOwner reports who holds the lock, or "" when free.
	LockOwner func(name string) string
	// Health checks the named resource; false means red.
	Health func(name string) bool
	// SafeMode reports the agent's safe-mode state.
	SafeMode func() bool
	// Publish emits events (response, incident).
	Publish Publisher
}

// Recipe is one automatic response.
type Recipe struct {
	For  string // rule id that triggers it
	Name string // action type (tracked by breaker/loop)
	Run  func(ctx context.Context, a detect.Alert, env *Env) (before, after, detail string, err error)
}

// Module runs tier-0 recipes on fired alerts.
type Module struct {
	env     *Env
	recipes []Recipe
	sink    chan detect.Alert

	mu         sync.Mutex
	rate       []time.Time            // timestamps of run attempts (last minute)
	breaker    map[string]time.Time   // action name -> until (disabled)
	breakCause map[string]string
	loops      map[string][]time.Time // action name -> restore timestamps (last 10 min)
}

// New builds the module.
func New(env *Env, recipes []Recipe) *Module {
	return &Module{
		env: env, recipes: recipes, sink: make(chan detect.Alert, 64),
		breaker: map[string]time.Time{}, breakCause: map[string]string{},
		loops: map[string][]time.Time{},
	}
}

// Submit hands an alert to the module (non-blocking: a full queue drops
// the alert, which is already spooled as an event).
func (m *Module) Submit(a detect.Alert) {
	select {
	case m.sink <- a:
	default:
	}
}

// Run processes alerts until ctx is done.
func (m *Module) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case a := <-m.sink:
			if a.Tier != 0 {
				continue
			}
			m.handle(ctx, a)
		}
	}
}

func (m *Module) handle(ctx context.Context, a detect.Alert) {
	var rc *Recipe
	for i := range m.recipes {
		if m.recipes[i].For == a.Rule {
			rc = &m.recipes[i]
			break
		}
	}
	if rc == nil {
		return // tier-1 or 2: the controller proposes, the operator clicks
	}
	out := Outcome{Action: rc.Name, Trigger: a.Rule}
	defer func() { _ = m.env.Publish.Publish("response", out) }()

	if m.env.SafeMode != nil && m.env.SafeMode() {
		out.Escalate, out.Reason = true, "safe mode: tier-0 suspended"
		return
	}
	m.mu.Lock()
	if until, ok := m.breaker[rc.Name]; ok && time.Now().Before(until) {
		m.mu.Unlock()
		out.Escalate, out.Reason = true, "circuit breaker: "+m.breakCause[rc.Name]
		return
	}
	m.mu.Unlock()

	// loop detection: the same restore 3 times in 10 minutes opens an
	// incident instead of restoring forever.
	m.mu.Lock()
	now := time.Now()
	ls := m.loops[rc.Name]
	cut := now.Add(-10 * time.Minute)
	kept := ls[:0]
	for _, t := range ls {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	loopsBefore := len(kept)
	kept = append(kept, now)
	m.loops[rc.Name] = kept
	m.mu.Unlock()
	if loopsBefore >= 2 {
		out.Reason = "loop: 3 restores in 10 minutes; opening incident"
		_ = m.env.Publish.Publish("incident", map[string]any{
			"kind": "restore-loop", "action": rc.Name, "trigger": a.Rule,
			"detail": "stop restoring; hunt the trigger lineage",
		})
		return
	}

	// shared lock: a restore waits while a plan holds the resource
	// (docs: Guards), up to a bound; then it skips and the next alert
	// retries.
	lock, owner := rc.Name, "tier0:"+rc.Name
	if m.env.LockTry != nil {
		deadline := time.Now().Add(5 * time.Minute)
		for !m.env.LockTry(lock, owner) {
			if time.Now().After(deadline) {
				out.Reason = "lock held: " + m.env.LockOwner(lock)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
		defer m.env.LockRelease(lock, owner)
	}

	// rate limit: at most 3 executed tier-0 actions per host per minute;
	// the 4th becomes a tier-1 proposal (docs: Guards).
	m.mu.Lock()
	nowR := time.Now()
	cutR := nowR.Add(-time.Minute)
	keptR := m.rate[:0]
	for _, t := range m.rate {
		if t.After(cutR) {
			keptR = append(keptR, t)
		}
	}
	m.rate = keptR
	overLimit := len(m.rate) >= 3
	m.mu.Unlock()
	if overLimit {
		out.Escalate, out.Reason = true, "rate limit: 3 tier-0 actions/minute"
		return
	}

	before, after, detail, err := rc.Run(ctx, a, m.env)
	out.Before, out.After, out.Detail = before, after, detail
	if err != nil {
		out.OK = false
		out.Detail = fmt.Sprintf("%s: %v", detail, err)
		return
	}
	out.OK = true
	m.mu.Lock()
	m.rate = append(m.rate, time.Now())
	m.mu.Unlock()


	// health check after the action; red within 2 minutes trips the
	// breaker for this action type.
	if m.env.Health != nil {
		out.HealthOK = m.env.Health(rc.Name)
		if !out.HealthOK {
			m.mu.Lock()
			m.breaker[rc.Name] = now.Add(10 * time.Minute)
			m.breakCause[rc.Name] = "health check red after " + rc.Name
			m.mu.Unlock()
			out.Escalate, out.Reason = true, "health check red after action"
		}
	}
}
