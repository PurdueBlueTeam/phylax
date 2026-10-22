package scorer

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// ServiceKey identifies a scorer-checked service.
type ServiceKey struct {
	Host  string
	Port  int
	Proto string
}

func (k ServiceKey) String() string { return fmt.Sprintf("%s:%d/%s", k.Host, k.Port, k.Proto) }

// AuthResult is the outcome of a login seen in an observation.
type AuthResult int

const (
	AuthNone AuthResult = iota // no login in this observation
	AuthOK
	AuthFailed
)

// Observation is one scorer-attributed request (the caller has already
// classified it, see Classifier, and templated the variable part into Item).
type Observation struct {
	Time       time.Time
	Round      int // round index (Burst.Seq or caller's own), non-decreasing
	Key        ServiceKey
	Kind       string // item kind: url, record, file, command, query, share ...
	Item       string // templated item, "" if the check has none
	User       string
	Auth       AuthResult
	BadAttempt bool   // a Quotient BadAttempts login (random-UUID password): not a real credential
	Sample     []byte // first bytes of the exchange, kept for unknown (custom) services
}

// DiscoveryConfig tunes discovery.
type DiscoveryConfig struct {
	LearnRounds   int // distinct rounds that make a service learned (2); must happen within 3
	StaleRounds   int // rounds without scorer traffic before flagging (5)
	BlockedRounds int // consecutive missed rounds with other services seen before a block is suspected (2)
	MaxItems      int // distinct items kept per service (4096)
	MaxSamples    int // raw samples kept per service (3)
}

func (c *DiscoveryConfig) defaults() {
	if c.LearnRounds <= 0 {
		c.LearnRounds = 2
	}
	if c.StaleRounds <= 0 {
		c.StaleRounds = 5
	}
	if c.BlockedRounds <= 0 {
		c.BlockedRounds = 2
	}
	if c.MaxItems <= 0 {
		c.MaxItems = 4096
	}
	if c.MaxSamples <= 0 {
		c.MaxSamples = 3
	}
}

// Coverage is the item-set learning state. Each round the scorer draws one item
// uniformly at random per check, so seeing all k items takes k*H_k rounds in
// expectation (3 items ~4, 5 ~11, 10 ~29).
type Coverage struct {
	Observed       int     // distinct items seen
	Samples        int     // item draws seen
	Singletons     int     // items seen exactly once
	EstTotal       float64 // Chao1 (bias-corrected) estimate of the true set size
	Coverage       float64 // Good-Turing: share of draws that come from seen items
	ExpectedRounds float64 // EstTotal * H(EstTotal): expected draws to see all
	RoundsLeft     float64 // max(0, ExpectedRounds - Samples)
	Partial        bool    // the set is never final during the event; true until well covered
}

func harmonic(k float64) float64 {
	if k < 1 {
		return 0
	}
	n := int(math.Round(k))
	h := 0.0
	for i := 1; i <= n; i++ {
		h += 1 / float64(i)
	}
	return h
}

// ExpectedRoundsToSeeAll returns k*H_k.
func ExpectedRoundsToSeeAll(k int) float64 { return float64(k) * harmonic(float64(k)) }

func coverageOf(counts map[string]int, samples int) Coverage {
	c := Coverage{Observed: len(counts), Samples: samples}
	f1, f2 := 0, 0
	for _, n := range counts {
		switch n {
		case 1:
			f1++
		case 2:
			f2++
		}
	}
	c.Singletons = f1
	c.EstTotal = float64(c.Observed) + float64(f1)*float64(f1-1)/(2*float64(f2+1))
	if samples > 0 {
		c.Coverage = 1 - float64(f1)/float64(samples)
	}
	if c.Observed == 0 {
		c.Coverage = 0
	}
	c.ExpectedRounds = c.EstTotal * harmonic(c.EstTotal)
	c.RoundsLeft = math.Max(0, c.ExpectedRounds-float64(samples))
	c.Partial = !(c.Coverage >= 0.95 && float64(samples) >= ExpectedRoundsToSeeAll(c.Observed))
	return c
}

// Service is a learned (or candidate) scorer-checked service.
type Service struct {
	Key         ServiceKey
	Kind        string // dominant item kind
	Learned     bool
	FirstRound  int
	LastRound   int
	LastSeen    time.Time
	Rounds      int // distinct rounds seen
	MissStreak  int
	SilentFlag  bool
	BlockedFlag bool
	Items       map[string]int
	Samples     [][]byte
	Users       map[string]int

	itemSamples int
	kindCount   map[string]int
	lastCounted int
}

// Account is a user the scorer logs in as.
type Account struct {
	User      string
	Services  map[ServiceKey]int
	FirstSeen time.Time
	LastSeen  time.Time
	OK, Fail  int
}

// EventKind classifies discovery events.
type EventKind string

const (
	EventServiceLearned  EventKind = "service_learned"
	EventBlockedSuspect  EventKind = "blocked_suspected" // others seen this round, this one missing: upstream block?
	EventScorerSilent    EventKind = "scorer_silent"     // not "healthy": the scorer stopped checking
	EventAccountLearned  EventKind = "account_learned"
	EventServiceResumed  EventKind = "service_resumed"
	EventAccountNotScore EventKind = "account_not_scored"
)

// Event is something a human should see.
type Event struct {
	Kind    EventKind
	Round   int
	Service ServiceKey
	User    string
	Detail  string
}

// ProposalKind classifies proposals against the active-check list.
type ProposalKind string

const (
	ProposeNew    ProposalKind = "new_check"    // "Scorer started checking X"
	ProposeUpdate ProposalKind = "update_check" // covered, but items/request differ
	FlagStale     ProposalKind = "stale_check"  // active check with no scorer counterpart; never auto-removed
)

// ActiveCheck is the part of one of our active checks discovery compares with.
type ActiveCheck struct {
	ID     string
	Key    ServiceKey
	Items  []string // items the check covers; empty means "any / not itemized"
	Active bool
	Since  int // round index from which it has been active
}

// Proposal needs a human click; discovery never changes checks itself.
type Proposal struct {
	Kind    ProposalKind
	Service ServiceKey
	CheckID string
	Items   []string // observed items to add (new/update)
	Detail  string
}

// Discovery learns services, item sets and scored accounts from scorer-attributed
// observations. It is strictly passive: it never generates traffic.
type Discovery struct {
	mu       sync.Mutex
	cfg      DiscoveryConfig
	svcs     map[ServiceKey]*Service
	accounts map[string]*Account
	notScore map[string]bool // shown not scored (e.g. sysadmin absent from the PCR list)
	curRound int
	seenRnd  map[int]bool
}

// NewDiscovery returns an empty discovery engine.
func NewDiscovery(cfg DiscoveryConfig) *Discovery {
	cfg.defaults()
	return &Discovery{cfg: cfg, svcs: map[ServiceKey]*Service{}, accounts: map[string]*Account{},
		notScore: map[string]bool{}, seenRnd: map[int]bool{}}
}

// Observe folds one scorer observation in and returns any events.
func (d *Discovery) Observe(o Observation) []Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	var evs []Event
	if o.Round > d.curRound {
		d.curRound = o.Round
	}
	d.seenRnd[o.Round] = true
	s := d.svcs[o.Key]
	if s == nil {
		s = &Service{Key: o.Key, FirstRound: o.Round, Items: map[string]int{}, Users: map[string]int{},
			kindCount: map[string]int{}, lastCounted: math.MinInt}
		d.svcs[o.Key] = s
	}
	if o.Round != s.lastCounted {
		s.Rounds++
		s.lastCounted = o.Round
		if s.SilentFlag || s.BlockedFlag {
			evs = append(evs, Event{Kind: EventServiceResumed, Round: o.Round, Service: o.Key})
		}
		s.MissStreak, s.SilentFlag, s.BlockedFlag = 0, false, false
	}
	s.LastRound, s.LastSeen = o.Round, o.Time
	if o.Item != "" {
		if _, known := s.Items[o.Item]; known || len(s.Items) < d.cfg.MaxItems {
			s.Items[o.Item]++
			s.itemSamples++
		}
		s.kindCount[o.Kind]++
		best, bn := s.Kind, -1
		for k, n := range s.kindCount {
			if n > bn || (n == bn && k < best) {
				best, bn = k, n
			}
		}
		s.Kind = best
	}
	if len(o.Sample) > 0 && len(s.Samples) < d.cfg.MaxSamples {
		b := o.Sample
		if len(b) > 256 {
			b = b[:256]
		}
		s.Samples = append(s.Samples, append([]byte(nil), b...))
	}
	if !s.Learned && s.Rounds >= d.cfg.LearnRounds {
		s.Learned = true
		evs = append(evs, Event{Kind: EventServiceLearned, Round: o.Round, Service: o.Key,
			Detail: fmt.Sprintf("seen in %d rounds", s.Rounds)})
	}
	if o.User != "" && !o.BadAttempt {
		evs = append(evs, d.observeUserLocked(o, s)...)
	}
	return evs
}

func (d *Discovery) observeUserLocked(o Observation, s *Service) []Event {
	var evs []Event
	s.Users[o.User]++
	a := d.accounts[o.User]
	if a == nil {
		a = &Account{User: o.User, Services: map[ServiceKey]int{}, FirstSeen: o.Time}
		d.accounts[o.User] = a
		evs = append(evs, Event{Kind: EventAccountLearned, Round: o.Round, Service: o.Key, User: o.User})
	}
	a.Services[o.Key]++
	a.LastSeen = o.Time
	switch o.Auth {
	case AuthOK:
		a.OK++
	case AuthFailed:
		a.Fail++
	}
	return evs
}

// CloseRound is called once a round's traffic is complete (the next burst
// started, or the quiet window opened). A round with no scorer traffic at all
// is a round gap and counts against nobody.
func (d *Discovery) CloseRound(round int) []Event {
	d.mu.Lock()
	defer d.mu.Unlock()
	var evs []Event
	anySeen := false
	for _, s := range d.svcs {
		if s.LastRound == round {
			anySeen = true
			break
		}
	}
	if !anySeen {
		return nil
	}
	for _, s := range d.sortedLocked() {
		if !s.Learned || s.LastRound == round {
			continue
		}
		s.MissStreak++
		if s.MissStreak >= d.cfg.BlockedRounds && !s.BlockedFlag && !s.SilentFlag {
			s.BlockedFlag = true
			evs = append(evs, Event{Kind: EventBlockedSuspect, Round: round, Service: s.Key,
				Detail: "other services were checked this round but not this one: upstream block?"})
		}
		if s.MissStreak >= d.cfg.StaleRounds && !s.SilentFlag {
			s.SilentFlag = true
			evs = append(evs, Event{Kind: EventScorerSilent, Round: round, Service: s.Key,
				Detail: fmt.Sprintf("no scorer traffic for %d rounds: scorer stopped checking (not the same as healthy)", s.MissStreak)})
		}
	}
	return evs
}

func (d *Discovery) sortedLocked() []*Service {
	out := make([]*Service, 0, len(d.svcs))
	for _, s := range d.svcs {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.String() < out[j].Key.String() })
	return out
}

// Services returns copies of all services sorted by key.
func (d *Discovery) Services() []Service {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Service
	for _, s := range d.sortedLocked() {
		c := *s
		c.Items = cloneCounts(s.Items)
		c.Users = cloneCounts(s.Users)
		out = append(out, c)
	}
	return out
}

// Service returns one service.
func (d *Discovery) Service(k ServiceKey) (Service, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.svcs[k]
	if !ok {
		return Service{}, false
	}
	c := *s
	c.Items, c.Users = cloneCounts(s.Items), cloneCounts(s.Users)
	return c, true
}

func cloneCounts(m map[string]int) map[string]int {
	c := make(map[string]int, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// Coverage returns the item-set coverage estimate for a service.
func (d *Discovery) Coverage(k ServiceKey) (Coverage, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.svcs[k]
	if !ok {
		return Coverage{}, false
	}
	return coverageOf(s.Items, s.itemSamples), true
}

// Compare checks learned services against the active-check list at round
// current. Nothing is ever removed automatically; every result is a proposal.
func (d *Discovery) Compare(current int, actives []ActiveCheck) []Proposal {
	d.mu.Lock()
	defer d.mu.Unlock()
	byKey := map[ServiceKey][]ActiveCheck{}
	for _, a := range actives {
		byKey[a.Key] = append(byKey[a.Key], a)
	}
	var out []Proposal
	for _, s := range d.sortedLocked() {
		if !s.Learned {
			continue
		}
		observed := sortedKeys(s.Items)
		cs := byKey[s.Key]
		if len(cs) == 0 {
			out = append(out, Proposal{Kind: ProposeNew, Service: s.Key, Items: observed,
				Detail: "Scorer started checking " + s.Key.String()})
			continue
		}
		covered, anyItemized := map[string]bool{}, false
		for _, c := range cs {
			if len(c.Items) > 0 {
				anyItemized = true
			}
			for _, it := range c.Items {
				covered[it] = true
			}
		}
		if anyItemized {
			var missing []string
			for _, it := range observed {
				if !covered[it] {
					missing = append(missing, it)
				}
			}
			if len(missing) > 0 {
				out = append(out, Proposal{Kind: ProposeUpdate, Service: s.Key, CheckID: cs[0].ID, Items: missing,
					Detail: "scorer used items the active check does not cover"})
			}
		}
	}
	for _, a := range actives {
		if !a.Active {
			continue
		}
		s := d.svcs[a.Key]
		switch {
		case s == nil && current-a.Since >= d.cfg.StaleRounds:
			out = append(out, Proposal{Kind: FlagStale, Service: a.Key, CheckID: a.ID,
				Detail: fmt.Sprintf("no scorer counterpart for %d rounds", current-a.Since)})
		case s != nil && current-s.LastRound >= d.cfg.StaleRounds:
			out = append(out, Proposal{Kind: FlagStale, Service: a.Key, CheckID: a.ID,
				Detail: fmt.Sprintf("scorer last seen %d rounds ago", current-s.LastRound)})
		}
	}
	return out
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ErrScoredAccount is returned by GuardRotation for scored accounts.
type ErrScoredAccount struct{ User string }

func (e ErrScoredAccount) Error() string {
	return fmt.Sprintf("account %q is used by the scorer: change it only through a PCR transaction", e.User)
}

// IsScored reports whether user is (or must be treated as) a scored account.
// `sysadmin` is scored until MarkNotScored says otherwise (the PCR list or
// GET /api/credlists showed it is not a scored user).
func (d *Discovery) IsScored(user string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.isScoredLocked(user)
}

func (d *Discovery) isScoredLocked(user string) bool {
	if d.notScore[user] {
		return false
	}
	if _, ok := d.accounts[user]; ok {
		return true
	}
	return user == "sysadmin"
}

// MarkNotScored records authoritative knowledge that user is not scored.
func (d *Discovery) MarkNotScored(user string) {
	d.mu.Lock()
	d.notScore[user] = true
	d.mu.Unlock()
}

// MarkScored records authoritative knowledge (credlist listing) that user is scored.
func (d *Discovery) MarkScored(user string, at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.notScore, user)
	if d.accounts[user] == nil {
		d.accounts[user] = &Account{User: user, Services: map[ServiceKey]int{}, FirstSeen: at, LastSeen: at}
	}
}

// GuardRotation must be called before any unilateral lock, delete, rename,
// expire or rotate of an account; it fails for scored accounts.
func (d *Discovery) GuardRotation(user string) error {
	if d.IsScored(user) {
		return ErrScoredAccount{User: user}
	}
	return nil
}

// ScoredAccounts returns learned scored accounts sorted by name.
func (d *Discovery) ScoredAccounts() []Account {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []Account
	for _, a := range d.accounts {
		if d.notScore[a.User] {
			continue
		}
		c := *a
		c.Services = map[ServiceKey]int{}
		for k, v := range a.Services {
			c.Services[k] = v
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// ExpectedVerifyRounds is how many rounds it takes on average to see a passing
// login for one specific user among k equally likely users: k (geometric),
// and about k*ln(k) to see all k.
func ExpectedVerifyRounds(k int) (one, all float64) {
	if k < 1 {
		return 0, 0
	}
	return float64(k), ExpectedRoundsToSeeAll(k)
}
