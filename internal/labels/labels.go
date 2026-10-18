// Package labels assigns the traffic label for a source address (docs:
// Traffic labels): us, scorer or other.
//
//	us     our active checkers, agents, relays and device adapters — the
//	       addresses we declare (the controller, every agent, every relay)
//	scorer learned by check discovery: round participation, rhythm,
//	       client and stack fingerprint, scored accounts
//	other  everything else: orange-team users, traffic generators and the
//	       red team. Within it, sources flagged by detections (scans,
//	       exploit payloads, webshell requests, decoy hits) are tagged
//	       attack-like so they are recognized on sight.
//
// The label answers the working question "is this neither the scorer nor
// us?": when something changes, other traffic to that service is where to
// look first.
package labels

import (
	"sort"
	"sync"
)

// Module holds the known sources and answers Classify.
type Module struct {
	mu     sync.RWMutex
	us     map[string]struct{}
	scorer map[string]struct{}
	red    map[string]struct{} // within other: flagged attack-like
}

// New returns a labeler with the platform's own addresses.
func New(us []string) *Module {
	m := &Module{
		us:     map[string]struct{}{},
		scorer: map[string]struct{}{},
		red:    map[string]struct{}{},
	}
	for _, a := range us {
		if a != "" {
			m.us[a] = struct{}{}
		}
	}
	return m
}

// AddUS declares one more platform address (e.g. a relay learned at link
// time).
func (m *Module) AddUS(addr string) {
	if addr == "" {
		return
	}
	m.mu.Lock()
	m.us[addr] = struct{}{}
	m.mu.Unlock()
}

// SetScorerSources replaces the learned scorer sources (docs: scorer
// learned by check discovery).
func (m *Module) SetScorerSources(srcs []string) {
	m.mu.Lock()
	m.scorer = map[string]struct{}{}
	for _, s := range srcs {
		if s != "" {
			m.scorer[s] = struct{}{}
		}
	}
	m.mu.Unlock()
}

// MarkRed tags a source as attack-like after a detection (scan, exploit
// payload, webshell request, decoy hit). It stays tagged: later
// connections from it are labeled on sight.
func (m *Module) MarkRed(src string) {
	if src == "" {
		return
	}
	m.mu.Lock()
	m.red[src] = struct{}{}
	m.mu.Unlock()
}

// Classify returns "us", "scorer" or "other" for the address. us wins
// over scorer: a platform address is never re-labeled.
func (m *Module) Classify(ip string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.us[ip]; ok {
		return "us"
	}
	if _, ok := m.scorer[ip]; ok {
		return "scorer"
	}
	return "other"
}

// IsRed reports whether the address is tagged attack-like.
func (m *Module) IsRed(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.red[ip]
	return ok
}

// RedSources lists the attack-like-tagged sources, sorted.
func (m *Module) RedSources() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.red))
	for s := range m.red {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ScorerSources lists the learned scorer sources, sorted.
func (m *Module) ScorerSources() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.scorer))
	for s := range m.scorer {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
