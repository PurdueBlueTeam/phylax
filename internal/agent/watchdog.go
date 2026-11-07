package agent

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Pulse is the agent's liveness record: the main loops call Beat whenever they
// make progress (a heartbeat tick, a supervisor tick, a config loop tick). A
// source that stopped beating is a loop that wedged, which a crashed-process
// check can never see.
type Pulse struct {
	now func() time.Time

	mu   sync.Mutex
	last map[string]time.Time // by source, guarded by mu
}

// NewPulse returns a pulse that starts every source healthy at now.
func NewPulse(now func() time.Time, sources ...string) *Pulse {
	p := &Pulse{now: now, last: make(map[string]time.Time, len(sources))}
	for _, s := range sources {
		p.last[s] = now()
	}
	return p
}

// Beat records progress for a known source; an unknown source is ignored.
func (p *Pulse) Beat(source string) {
	now := p.now()
	p.mu.Lock()
	if _, ok := p.last[source]; ok {
		p.last[source] = now
	}
	p.mu.Unlock()
}

// Stalled returns the sources whose last beat is older than limit, sorted.
// Empty means healthy.
func (p *Pulse) Stalled(limit time.Duration) []string {
	now := p.now()
	p.mu.Lock()
	var out []string
	for s, t := range p.last {
		if now.Sub(t) > limit {
			out = append(out, s)
		}
	}
	p.mu.Unlock()
	sort.Strings(out)
	return out
}

// watchdog sends WATCHDOG=1 to systemd while the agent makes progress. A
// wedged agent stops notifying and systemd (WatchdogSec=30, Restart=always)
// restarts it. Ticking at the heartbeat interval keeps the stall limit (three
// misses) well inside WatchdogSec.
func (a *Agent) watchdog(ctx context.Context, notify func(string)) {
	t := time.NewTicker(a.cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if len(a.Stalled()) == 0 {
				notify("WATCHDOG=1")
			}
		case <-ctx.Done():
			return
		}
	}
}

// Stalled is the agent's stall report: the pulse sources that stopped beating
// within the watchdog limit, plus "modules" when the supervisor reports every
// module dead. Empty means the agent is making progress. The Windows service
// handler uses the same report.
func (a *Agent) Stalled() []string {
	var out []string
	if a.pulse != nil {
		out = a.pulse.Stalled(3 * a.cfg.HeartbeatInterval)
	}
	if a.allModulesDead() {
		out = append(out, "modules")
	}
	return out
}

// allModulesDead reports whether the supervisor has modules and none of them
// is running: every module crashed or stopped on its own.
func (a *Agent) allModulesDead() bool {
	a.mu.Lock()
	sup := a.sup
	a.mu.Unlock()
	if sup == nil {
		return false
	}
	states := sup.States()
	if len(states) == 0 {
		return false
	}
	for _, st := range states {
		if st == StateRunning || st == StateStarting {
			return false
		}
	}
	return true
}

// beat records progress for the watchdog; it is a no-op before New has built
// the pulse (a test agent with no Run).
func (a *Agent) beat(source string) {
	if a.pulse != nil {
		a.pulse.Beat(source)
	}
}

// beatSupervisor is the supervisor's liveness tick. The supervisor has no loop
// of its own, so this goroutine beating at the heartbeat interval (and the
// all-modules-dead check in Stalled) is what proves it still answers.
func (a *Agent) beatSupervisor(ctx context.Context) {
	t := time.NewTicker(a.cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			a.beat("supervisor")
		case <-ctx.Done():
			return
		}
	}
}
