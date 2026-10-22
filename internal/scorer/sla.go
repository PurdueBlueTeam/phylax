package scorer

import (
	"fmt"
	"sort"
	"sync"
)

// Outcome is the inferred (or operator-given) result of one scorer attempt.
type Outcome int

const (
	OutcomeUnknown Outcome = iota // no data this round for this service
	OutcomePass
	OutcomeFail
)

func (o Outcome) String() string { return [...]string{"unknown", "pass", "fail"}[o] }

// AlertLevel of an SLA alert.
type AlertLevel string

const (
	AlertWarn     AlertLevel = "warn"     // streak reached threshold-2
	AlertCritical AlertLevel = "critical" // threshold-1
	AlertPenalty  AlertLevel = "penalty"  // threshold reached: penalty charged, streak reset
)

// SLAAlert is raised when a service's failure streak crosses a level.
type SLAAlert struct {
	Service string
	Level   AlertLevel
	Round   int
	Streak  int
	Detail  string
}

// SLAConfig tunes the tracker.
type SLAConfig struct {
	Threshold int // consecutive failures per penalty (upstream default 5)
	MaxRounds int // rounds kept per service (4096)
}

type slaRound struct {
	round int
	out   Outcome
}

type slaSvc struct {
	log        []slaRound // sorted by round
	baseStreak int        // folded state of trimmed rounds
	basePen    int
}

// SLATracker counts consecutive failed scorer attempts per service, as
// Quotient does: the penalty is global, the counter resets after each penalty,
// a pass resets it, and a discarded round neither advances nor resets it.
// The state is always recomputed by replaying the round log, so discarding a
// round or receiving an operator verdict later corrects history exactly.
type SLATracker struct {
	mu        sync.Mutex
	cfg       SLAConfig
	svcs      map[string]*slaSvc
	discarded map[int]bool
	verdicts  map[verdictKey]Outcome
	agree     int
	disagree  int
}

type verdictKey struct {
	svc   string
	round int
}

// NewSLATracker returns a tracker.
func NewSLATracker(cfg SLAConfig) *SLATracker {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 5
	}
	if cfg.MaxRounds <= 0 {
		cfg.MaxRounds = 4096
	}
	return &SLATracker{cfg: cfg, svcs: map[string]*slaSvc{}, discarded: map[int]bool{}, verdicts: map[verdictKey]Outcome{}}
}

// Threshold returns the active threshold.
func (t *SLATracker) Threshold() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg.Threshold
}

// SetThreshold replaces the assumed threshold with the observed value.
func (t *SLATracker) SetThreshold(n int) {
	if n < 1 {
		return
	}
	t.mu.Lock()
	t.cfg.Threshold = n
	t.mu.Unlock()
}

func (t *SLATracker) levels() (warn, crit int) {
	th := t.cfg.Threshold
	warn, crit = th-2, th-1
	if warn < 1 {
		warn = 1
	}
	if crit < 1 {
		crit = 1
	}
	return
}

func (t *SLATracker) effective(svc string, r slaRound) Outcome {
	if v, ok := t.verdicts[verdictKey{svc, r.round}]; ok {
		return v
	}
	return r.out
}

// replay returns the streak and penalty count.
func (t *SLATracker) replay(svc string, s *slaSvc) (streak, pens int) {
	streak, pens = s.baseStreak, s.basePen
	for _, r := range s.log {
		if t.discarded[r.round] {
			continue
		}
		switch t.effective(svc, r) {
		case OutcomePass:
			streak = 0
		case OutcomeFail:
			streak++
			if streak >= t.cfg.Threshold {
				pens++
				streak = 0
			}
		}
	}
	return
}

func (t *SLATracker) get(svc string) *slaSvc {
	s := t.svcs[svc]
	if s == nil {
		s = &slaSvc{}
		t.svcs[svc] = s
	}
	return s
}

func (t *SLATracker) put(svc string, s *slaSvc, round int, o Outcome) {
	i := sort.Search(len(s.log), func(i int) bool { return s.log[i].round >= round })
	if i < len(s.log) && s.log[i].round == round {
		s.log[i].out = o
	} else {
		s.log = append(s.log, slaRound{})
		copy(s.log[i+1:], s.log[i:])
		s.log[i] = slaRound{round, o}
	}
	for len(s.log) > t.cfg.MaxRounds {
		r := s.log[0]
		s.log = s.log[1:]
		if !t.discarded[r.round] {
			switch t.effective(svc, r) {
			case OutcomePass:
				s.baseStreak = 0
			case OutcomeFail:
				s.baseStreak++
				if s.baseStreak >= t.cfg.Threshold {
					s.basePen++
					s.baseStreak = 0
				}
			}
		}
	}
}

func (t *SLATracker) alerts(svc string, round, s0, p0, s1, p1 int) []SLAAlert {
	warn, crit := t.levels()
	var out []SLAAlert
	mk := func(l AlertLevel, st int, d string) {
		out = append(out, SLAAlert{Service: svc, Level: l, Round: round, Streak: st, Detail: d})
	}
	if p1 > p0 {
		mk(AlertPenalty, s1, fmt.Sprintf("%d consecutive failures: penalty charged, streak reset", t.cfg.Threshold))
		return out
	}
	if s1 >= crit && s0 < crit {
		mk(AlertCritical, s1, fmt.Sprintf("%d of %d failures: one more costs a penalty", s1, t.cfg.Threshold))
	} else if s1 >= warn && s0 < warn {
		mk(AlertWarn, s1, fmt.Sprintf("%d of %d failures", s1, t.cfg.Threshold))
	}
	return out
}

// ObserveRound records the inferred outcome of each service for a round and
// returns new alerts. Unknown outcomes (no scorer traffic for that service) are
// not recorded: silence is not a pass or a fail.
func (t *SLATracker) ObserveRound(round int, results map[string]Outcome) []SLAAlert {
	t.mu.Lock()
	defer t.mu.Unlock()
	names := make([]string, 0, len(results))
	for k := range results {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []SLAAlert
	for _, svc := range names {
		o := results[svc]
		if o == OutcomeUnknown {
			continue
		}
		s := t.get(svc)
		s0, p0 := t.replay(svc, s)
		t.put(svc, s, round, o)
		s1, p1 := t.replay(svc, s)
		out = append(out, t.alerts(svc, round, s0, p0, s1, p1)...)
	}
	return out
}

// Discard marks a whole round as discarded (the scorer dropped it: results
// missing at the deadline, or no burst at all). Streaks are rebuilt as if it
// never happened, so a missing burst is never an outage.
func (t *SLATracker) Discard(round int) {
	t.mu.Lock()
	t.discarded[round] = true
	t.mu.Unlock()
}

// Verdict feeds ground truth from the portal poll or a pasted Up/Down table
// for one service and round, overriding the inferred outcome. It returns
// alerts produced by the correction.
func (t *SLATracker) Verdict(round int, svc string, pass bool) []SLAAlert {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.get(svc)
	s0, p0 := t.replay(svc, s)
	want := OutcomeFail
	if pass {
		want = OutcomePass
	}
	for _, r := range s.log {
		if r.round == round && r.out != OutcomeUnknown {
			if r.out == want {
				t.agree++
			} else {
				t.disagree++
			}
		}
	}
	t.verdicts[verdictKey{svc, round}] = want
	if i := sort.Search(len(s.log), func(i int) bool { return s.log[i].round >= round }); i >= len(s.log) || s.log[i].round != round {
		t.put(svc, s, round, want)
	}
	s1, p1 := t.replay(svc, s)
	return t.alerts(svc, round, s0, p0, s1, p1)
}

// Calibration reports how often inference agreed with operator verdicts.
func (t *SLATracker) Calibration() (agree, disagree int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.agree, t.disagree
}

// Streak returns the current consecutive-failure count for a service.
func (t *SLATracker) Streak(svc string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.svcs[svc]; s != nil {
		st, _ := t.replay(svc, s)
		return st
	}
	return 0
}

// Penalties returns how many penalties the service has (inferred) incurred.
func (t *SLATracker) Penalties(svc string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.svcs[svc]; s != nil {
		_, p := t.replay(svc, s)
		return p
	}
	return 0
}
