// Package discovery implements check discovery (docs: Check discovery):
// recognizing scorer traffic, grouping its requests per service into
// observed checks with variable parts templated, comparing them against
// the active list, marking scored accounts and spotting blocked checks.
//
// Discovery is strictly passive: it observes what the scorer sends to our
// hosts and never connects to, scans or probes its addresses (the packet
// treats that as grounds for disqualification).
//
// Recognition (docs: Recognize scorer traffic): scorer traffic sweeps most
// services within a short window and repeats on a rhythm. A source that
// hits at least two declared services in a round is a round participant;
// a participant for two consecutive rounds is confirmed as scorer. Source
// IP is a hint, never a rule — one round of sweeping is not enough, and
// nothing is ever assumed from a single service.
//
// Comparison (docs: Compare against the active list):
//   - not covered: a proposal "scorer started checking X", with a sample
//     request and a pre-filled check
//   - covered, but the request changed (method or templated path/query
//     name differs): a proposal to update the existing check
//   - an active check with no scorer counterpart for 5 rounds: flagged
//     possibly stale, with a suggestion to pause it. Nothing is ever
//     removed automatically.
//
// Only check types that are visible in captured traffic can be matched to
// scorer counterparts: http, smtp (mail exchange), dns and ftp. tftp, ntp
// and tcp-banner checks are exempt from stale flagging: the capture
// parsers do not decode them, so their absence in the observation is
// proof of nothing.
package discovery

import (
	"context"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	checks "github.com/PurdueBlueTeam/phylax/internal/checks"
)

// staleRounds is how many consecutive rounds without a scorer counterpart
// flag an active check as possibly stale (docs: 5 rounds).
const staleRounds = 5

// recentCap bounds the per-source request history kept for the promotion
// replay (docs: bounded memory, oldest dropped first).
const recentCap = 256

// Service names one declared service: its listening port and whether it
// is scored.
type Service struct {
	Name   string
	Port   int
	Scored bool
}

// ObservedCheck is one scorer check as observed on the wire: the
// service, the templated request pattern and a raw sample of it.
type ObservedCheck struct {
	ID        string         `json:"id"`
	Service   string         `json:"service"`
	Type      string         `json:"type"` // http|smtp|dns|ftp
	Template  string         `json:"template"`
	Sample    map[string]any `json:"sample"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Count     int            `json:"count"`
	Sources   []string       `json:"sources"`
}

// Proposal is one suggested change to the active list; acceptance is a
// human click (docs: Rules of engagement).
type Proposal struct {
	ID       string
	Kind     string // new | changed | stale
	Check    checks.Check
	Observed *ObservedCheck
	Reason   string
	TS       time.Time
}

// AccountMark names an account the scorer authenticated with, with the
// source it came from (docs: Mark scored accounts).
type AccountMark struct {
	Account string
	Source  string
	TS      time.Time
}

// Blocked names a scored service the scorer did not reach in a round in
// which it reached the others (docs: Spot blocked checks).
type Blocked struct {
	Service     string
	WindowStart time.Time
	WindowEnd   time.Time
}

// Sink receives discovery output.
type Sink interface {
	// Proposal is called for new and changed scorer checks.
	Proposal(p Proposal)
	// Stale is called for active checks without a scorer counterpart
	// for 5 rounds, with a suggestion to pause.
	Stale(p Proposal)
	// Account marks a scored account.
	Account(a AccountMark)
	// Blocked reports an upstream block on one service.
	Blocked(b Blocked)
	// Alert carries any other discovery alert.
	Alert(rule string, event map[string]any, key string)
}

// Config drives a module.
type Config struct {
	// US are the platform's own addresses: never scorer, never
	// trace-back sources.
	US []string
	// RoundDuration is the discovery round (the scorer's sweep window).
	RoundDuration time.Duration
	// Now injects the clock (tests run on a fake time).
	Now func() time.Time
}

// Module is the check-discovery engine.
type Module struct {
	sink Sink
	cfg  Config
	now  func() time.Time

	mu         sync.Mutex
	services   map[string]Service // by name
	portSvc    map[int]string     // dport -> service name
	scored     []string           // scored service names, sorted
	active     []checks.Check     // the current active list
	sources    map[string]*source
	observed   map[string]*ObservedCheck // by observation ID
	proposals  map[string]Proposal       // pending, by proposal ID
	fired      map[string]struct{}       // template/service keys already proposed (dedup)
	staleFired map[string]struct{}       // check IDs already flagged stale
	seenAcct   map[string]struct{}       // account|source already marked
	round      int
	roundStart time.Time
	propSeq    int
}

// source is the per-source recognition state.
type source struct {
	ip         string
	streak     int                 // consecutive participant rounds
	scorer     bool
	accounts   map[string]struct{} // accounts seen from it
	firstSeen  time.Time
	roundHit   map[string]struct{} // services hit in the current round
	prevHitSet map[string]struct{} // services hit in the previous round
	recent     []obsRec            // bounded request history (promotion replay)
}

// obsRec is one observed request before (or after) confirmation.
type obsRec struct {
	ts   time.Time
	rec  observedEvent
}

// observedEvent is the normalized form of one observed request.
type observedEvent struct {
	src     string
	service string
	typ     string // http|smtp|dns|ftp
	tmpl    string
	sample  map[string]any
	account string
}

// New returns a module over the given sink.
func New(sink Sink, cfg Config) *Module {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.RoundDuration <= 0 {
		cfg.RoundDuration = time.Minute
	}
	return &Module{
		sink: sink,
		cfg:  cfg,
		now:  cfg.Now,
		services:   map[string]Service{},
		portSvc:    map[int]string{},
		sources:    map[string]*source{},
		observed:   map[string]*ObservedCheck{},
		proposals:  map[string]Proposal{},
		fired:      map[string]struct{}{},
		staleFired: map[string]struct{}{},
		seenAcct:   map[string]struct{}{},
		roundStart: cfg.Now(),
	}
}

// SetServices declares the service map (docs: the services the scorer
// sweeps).
func (m *Module) SetServices(s []Service) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services = map[string]Service{}
	m.portSvc = map[int]string{}
	m.scored = nil
	for _, sv := range s {
		if sv.Name == "" || sv.Port == 0 {
			continue
		}
		m.services[sv.Name] = sv
		m.portSvc[sv.Port] = sv.Name
		if sv.Scored {
			m.scored = append(m.scored, sv.Name)
		}
	}
	sort.Strings(m.scored)
}

// SetActive installs the current active check list for comparison (docs:
// compare against the active list).
func (m *Module) SetActive(list []checks.Check) {
	m.mu.Lock()
	m.active = list
	// a check re-entered the active list: it is covered again
	for _, ck := range list {
		delete(m.staleFired, ck.ID)
	}
	m.mu.Unlock()
}

// ScorerSources lists the confirmed scorer sources, sorted.
func (m *Module) ScorerSources() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.sources))
	for ip, s := range m.sources {
		if s.scorer {
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out
}

// Observed lists the recent observed scorer checks, newest first, for the
// checks view.
func (m *Module) Observed() []ObservedCheck {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ObservedCheck, 0, len(m.observed))
	for _, o := range m.observed {
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// Proposals lists the pending (unresolved) proposals, newest first.
func (m *Module) Proposals() []Proposal {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Proposal, 0, len(m.proposals))
	for _, p := range m.proposals {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS.After(out[j].TS) })
	return out
}

// Resolve records the operator's decision on a proposal. Accepting moves
// the check into the active list through the sink's owner (the controller
// upserts it); rejecting keeps the template out of the proposal stream.
func (m *Module) Resolve(id string, accept bool) {
	m.mu.Lock()
	p, ok := m.proposals[id]
	delete(m.proposals, id)
	if ok && !accept && p.Observed != nil {
		// a rejected template is not proposed again
		m.fired[p.Observed.Service+"|"+p.Observed.Template] = struct{}{}
	}
	m.mu.Unlock()
}

// HandleEvent feeds one mirrored agent event (docs: transactions and
// flows). Event types: http, exchange, dns, flow (anything with a
// destination port contributes to round participation).
func (m *Module) HandleEvent(typ string, data map[string]any) {
	now := m.now()
	src := srcIP(data["src"])
	if src == "" || inSet(m.cfg.US, src) {
		return
	}
	dport := intOf(data["dport"])
	m.mu.Lock()
	svc := m.portSvc[dport]
	// round participation: any traffic to a declared service
	if svc != "" {
		s := m.sourceLocked(src)
		s.roundHit[svc] = struct{}{}
	}
	var ev observedEvent
	switch typ {
	case "http":
		ev = m.obsHTTP(data, src, svc)
	case "exchange":
		ev = m.obsExchange(data, src, svc)
	case "dns":
		ev = m.obsDNS(data, src, svc)
	}
	if svc != "" && ev.tmpl != "" {
		s := m.sourceLocked(src)
		s.recent = append(s.recent, obsRec{ts: now, rec: ev})
		if len(s.recent) > recentCap {
			s.recent = s.recent[len(s.recent)-recentCap:]
		}
		if s.scorer {
			m.observeLocked(s, ev, now)
		}
	}
	m.mu.Unlock()
}

// RoundDuration returns the configured round (the labels sync reuses it).
func (m *Module) RoundDuration() time.Duration { return m.cfg.RoundDuration }

// Run advances the rounds until ctx is done: recognition, stale flags and
// blocked checks.
func (m *Module) Run(ctx context.Context) {
	t := time.NewTicker(m.cfg.RoundDuration)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.roundTick()
		}
	}
}

// roundTick closes the current round and opens the next.
func (m *Module) roundTick() {
	now := m.now()
	m.mu.Lock()
	m.round++
	// recognition: sweep (>= 2 services this round) + rhythm (two
	// consecutive participating rounds) confirms the scorer
	for _, s := range m.sources {
		if len(s.roundHit) >= 2 {
			s.streak++
		} else {
			s.streak = 0
		}
		if !s.scorer && s.streak >= 2 {
			s.scorer = true
			// replay the bounded request history: the sweeps that
			// confirmed it were already observed traffic
			for _, r := range s.recent {
				m.observeLocked(s, r.rec, r.ts)
			}
			s.recent = nil
		}
		s.prevHitSet = s.roundHit
		s.roundHit = map[string]struct{}{}
	}
	staleStart := m.roundStart
	m.roundStart = now
	m.staleAndBlockedLocked(now, staleStart)
	m.mu.Unlock()
}

// staleAndBlockedLocked implements the stale flag and the blocked check
// at a round boundary.
func (m *Module) staleAndBlockedLocked(now, windowStart time.Time) {
	// stale: an active check that had a scorer counterpart, then went
	// quiet for 5 rounds (docs: dropped checks flagged stale within 5
	// rounds). A check the scorer never performed is not stale: there
	// is no counterpart to go quiet.
	for _, ck := range m.active {
		if ck.State == "retired" {
			continue
		}
		if !staleEligible(ck.Type) {
			continue
		}
		if _, seen := m.staleFired[ck.ID]; seen {
			continue
		}
		cutoff := now.Add(-staleRounds * m.cfg.RoundDuration)
		covered := false
		had := false
		for _, o := range m.observed {
			if !coversCheck(ck, o) {
				continue
			}
			had = true
			if o.LastSeen.After(cutoff) {
				covered = true
			}
		}
		if !had {
			continue
		}
		if !covered {
			m.staleFired[ck.ID] = struct{}{}
			p := Proposal{
				ID:     m.nextIDLocked("stale"),
				Kind:   "stale",
				Check:  ck,
				Reason: fmt.Sprintf("no scorer counterpart for %d rounds; suggestion: pause", staleRounds),
				TS:     now,
			}
			m.proposals[p.ID] = p
			m.sink.Stale(p)
		}
	}
	// blocked: the round that just closed reached the other services
	// but no scorer traffic reached one of them
	reached := map[string]struct{}{}
	for _, s := range m.sources {
		if !s.scorer {
			continue
		}
		for svc := range s.prevHitSet {
			reached[svc] = struct{}{}
		}
	}
	for _, svc := range m.scored {
		if _, ok := reached[svc]; ok {
			continue
		}
		// only services that had scorer traffic before are "blocked":
		// a service never reached is not an upstream block
		had := false
		for _, o := range m.observed {
			if o.Service == svc {
				had = true
				break
			}
		}
		if !had {
			continue
		}
		b := Blocked{Service: svc, WindowStart: windowStart, WindowEnd: now}
		m.sink.Blocked(b)
	}
}

// observeLocked folds one observed request into the observed-check table
// and fires proposals for uncovered or changed templates.
func (m *Module) observeLocked(s *source, ev observedEvent, now time.Time) {
	id := obsID(ev.service, ev.typ, ev.tmpl)
	o, ok := m.observed[id]
	if !ok {
		o = &ObservedCheck{
			ID:        id,
			Service:   ev.service,
			Type:      ev.typ,
			Template:  ev.tmpl,
			Sample:    ev.sample,
			FirstSeen: now,
			LastSeen:  now,
			Count:     1,
			Sources:   []string{ev.src},
		}
		m.observed[id] = o
	} else {
		o.LastSeen = now
		o.Count++
		if !inList(o.Sources, ev.src) {
			o.Sources = append(o.Sources, ev.src)
		}
	}
	// scored accounts: any account the scorer authenticates with
	if ev.account != "" {
		k := ev.account + "|" + ev.src
		if _, seen := m.seenAcct[k]; !seen {
			m.seenAcct[k] = struct{}{}
			s.accounts[ev.account] = struct{}{}
			m.sink.Account(AccountMark{Account: ev.account, Source: ev.src, TS: now})
		}
	}
	m.evaluateLocked(o, now)
}

// evaluateLocked compares one observed check against the active list and
// fires a proposal when it is not covered (new) or covered but changed.
func (m *Module) evaluateLocked(o *ObservedCheck, now time.Time) {
	ck, kind := m.matchActive(o)
	if kind == "covered" {
		return
	}
	key := o.Service + "|" + o.Template
	if _, seen := m.fired[key]; seen {
		return
	}
	m.fired[key] = struct{}{}
	p := Proposal{
		ID:       m.nextIDLocked(kind),
		Kind:     kind,
		Check:    fillCheck(o),
		Observed: o,
		Reason:   proposalReason(o, ck),
		TS:       now,
	}
	if ck.ID != "" {
		p.Check.ID = ck.ID
	}
	m.proposals[p.ID] = p
	m.sink.Proposal(p)
}

// matchActive compares an observed check against the active list.
// Returns the related active check (when kind is "covered" or
// "changed") and the kind:
//
//	covered — the active check performs this request (http: same
//	          method and templated path; dns: same name; mail/ftp: an
//	          active check of that type exists for the service)
//	changed — the service has an active check of the type, but the
//	          request differs (dns: the scorer now resolves a
//	          different name). The proposal updates that check.
//	new     — the scorer checks something the active list does not
//	          cover at all.
func (m *Module) matchActive(o *ObservedCheck) (checks.Check, string) {
	switch o.Type {
	case "http":
		for _, ck := range m.active {
			if ck.Service == o.Service && ck.Type == "http" && httpMatches(ck, o) {
				return ck, "covered"
			}
		}
		return checks.Check{}, "new"
	case "dns":
		var best checks.Check
		found := false
		for _, ck := range m.active {
			if ck.Service != o.Service || ck.Type != "dns" {
				continue
			}
			found = true
			if dnsMatches(ck, o) {
				return ck, "covered"
			}
			if best.ID == "" {
				best = ck
			}
		}
		if found {
			return best, "changed"
		}
		return checks.Check{}, "new"
	default: // mail (smtp) and ftp: the bucket is the check
		for _, ck := range m.active {
			if ck.Service == o.Service && bucket(ck.Type) == o.Type {
				return ck, "covered"
			}
		}
		return checks.Check{}, "new"
	}
}

// dnsMatches reports whether the active dns check resolves the name the
// scorer resolves.
func dnsMatches(ck checks.Check, o *ObservedCheck) bool {
	name, _ := ck.Params["name"].(string)
	on, _ := o.Sample["name"].(string)
	return name != "" && name == on
}

// coversCheck reports whether an active check performs an observed
// request (the stale flag's "counterpart").
func coversCheck(ck checks.Check, o *ObservedCheck) bool {
	if ck.Service != o.Service || bucket(ck.Type) != o.Type {
		return false
	}
	switch o.Type {
	case "http":
		return httpMatches(ck, o)
	case "dns":
		return dnsMatches(ck, o)
	}
	return true
}

// fillCheck pre-fills the active-check entry a proposal points at (docs:
// a sample request and a pre-filled check).
func fillCheck(o *ObservedCheck) checks.Check {
	ck := checks.Check{
		Service: o.Service,
		Origin:  "discovered",
		Params:  map[string]any{},
	}
	switch o.Type {
	case "http":
		ck.Type = "http"
		if url, ok := o.Sample["url"].(string); ok && url != "" {
			ck.Params["url"] = url
		}
		if st, ok := o.Sample["resp"].(float64); ok {
			ck.Expected = map[string]any{"status": int(st)}
		}
	case "smtp":
		ck.Type = "smtp"
		for _, k := range []string{"smtp_host", "mailbox_host"} {
			if v, ok := o.Sample[k].(string); ok && v != "" {
				ck.Params[k] = v
			}
		}
		if u, ok := o.Sample["user"].(string); ok && u != "" {
			ck.Params["mail_user"] = u
		}
		ck.Expected = map[string]any{}
	case "dns":
		ck.Type = "dns"
		if v, ok := o.Sample["server"].(string); ok && v != "" {
			ck.Params["server"] = v
		}
		if v, ok := o.Sample["name"].(string); ok && v != "" {
			ck.Params["name"] = v
		}
		if v, ok := o.Sample["qtype"].(string); ok && v != "" {
			ck.Params["qtype"] = v
		}
		ck.Expected = map[string]any{}
	case "ftp":
		ck.Type = "ftp"
		if v, ok := o.Sample["host"].(string); ok && v != "" {
			ck.Params["host"] = v
		}
		if u, ok := o.Sample["user"].(string); ok && u != "" {
			ck.Params["user"] = u
		}
		ck.Expected = map[string]any{}
	}
	return ck
}

func proposalReason(o *ObservedCheck, existing checks.Check) string {
	switch {
	case existing.ID != "":
		return "scorer request changed: was " + existingTypePath(existing) + ", now " + o.Template
	default:
		return "scorer started checking " + o.Template
	}
}

func existingTypePath(ck checks.Check) string {
	switch ck.Type {
	case "http":
		u, _ := ck.Params["url"].(string)
		if p, _, ok := strings.Cut(u, "/"); ok {
			return p + " " + u[strings.Index(u, "/"):]
		}
		return u
	default:
		return ck.Type
	}
}

// ---- round-boundary helpers ----------------------------------------------

// httpMatches reports whether an active check covers an observed check.
// http: same method and same templated path; other buckets: same
// service and type is enough (the observed pattern is the bucket).
func httpMatches(ck checks.Check, o *ObservedCheck) bool {
	if ck.Type != "http" || o.Type != "http" {
		return true
	}
	u, _ := ck.Params["url"].(string)
	method, path := httpParts(u)
	want := strings.ToUpper(method) + " " + normPath(path)
	return want == o.Template
}

// bucket maps an active-check type to its observed-event type.
func bucket(t string) string {
	switch t {
	case "smtp":
		return "smtp" // mail exchange (smtp send + pop3 retrieve)
	default:
		return t
	}
}

// staleEligible reports whether the check type is visible in captured
// traffic and can therefore go stale (docs: tftp/ntp/tcp are not
// decoded by the capture parsers).
func staleEligible(t string) bool {
	switch t {
	case "http", "smtp", "dns", "ftp":
		return true
	}
	return false
}

func (m *Module) nextIDLocked(prefix string) string {
	m.propSeq++
	return prefix + "-" + strconv.Itoa(m.propSeq)
}

func (m *Module) sourceLocked(ip string) *source {
	s, ok := m.sources[ip]
	if !ok {
		s = &source{
			ip:       ip,
			accounts: map[string]struct{}{},
			firstSeen: m.now(),
			roundHit: map[string]struct{}{},
		}
		m.sources[ip] = s
	}
	return s
}

// ---- event normalization ---------------------------------------------------

func (m *Module) obsHTTP(data map[string]any, src, svc string) observedEvent {
	if svc == "" {
		return observedEvent{}
	}
	method, _ := data["method"].(string)
	if method == "" {
		method = "GET"
	}
	path, _ := data["path"].(string)
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		return observedEvent{}
	}
	sample := map[string]any{
		"method": method,
		"path":   path,
		"host":   strOf(data["host"]),
	}
	if h, ok := data["host"].(string); ok && h != "" {
		sample["url"] = "http://" + h + path
	} else {
		dst, _ := data["dst"].(string)
		dport := intOf(data["dport"])
		if dst != "" {
			sample["url"] = fmt.Sprintf("http://%s:%d%s", dst, dport, path)
		}
	}
	if st, ok := data["resp"].(float64); ok {
		sample["resp"] = st
	}
	return observedEvent{
		src:     src,
		service: svc,
		typ:     "http",
		tmpl:    strings.ToUpper(method) + " " + normPath(path),
		sample:  sample,
	}
}

func (m *Module) obsExchange(data map[string]any, src, svc string) observedEvent {
	if svc == "" {
		return observedEvent{}
	}
	proto, _ := data["proto"].(string)
	cmd, _ := data["cmd"].(string)
	user, _ := data["user"].(string)
	switch proto {
	case "smtp", "pop3", "imap":
		tmpl := "mail"
		// a POP3 retrieve is the observable half of the scorer's
		// mail check; the account is what matters for accounts
		sample := map[string]any{
			"proto": proto,
			"cmd":   strings.ToUpper(cmd),
			"user":  user,
		}
		if h, ok := hostFrom(data); ok {
			if proto == "pop3" || proto == "imap" {
				sample["mailbox_host"] = h
			} else {
				sample["smtp_host"] = h
			}
		}
		return observedEvent{
			src:     src,
			service: svc,
			typ:     "smtp",
			tmpl:    tmpl,
			sample:  sample,
			account: user,
		}
	case "ftp":
		sample := map[string]any{
			"proto": "ftp",
			"cmd":   strings.ToUpper(cmd),
			"user":  user,
		}
		if h, ok := hostFrom(data); ok {
			sample["host"] = h
		}
		return observedEvent{
			src:     src,
			service: svc,
			typ:     "ftp",
			tmpl:    "ftp",
			sample:  sample,
			account: user,
		}
	}
	return observedEvent{}
}

func (m *Module) obsDNS(data map[string]any, src, svc string) observedEvent {
	if svc == "" {
		return observedEvent{}
	}
	names, _ := data["names"].([]any)
	if len(names) == 0 {
		return observedEvent{}
	}
	name, _ := names[0].(string)
	if name == "" {
		return observedEvent{}
	}
	qtype := "A"
	if qt, ok := data["qtypes"].([]any); ok && len(qt) > 0 {
		if s, ok := qt[0].(string); ok && s != "" {
			qtype = s
		}
	}
	sample := map[string]any{
		"name":  name,
		"qtype": qtype,
	}
	if h, ok := hostFrom(data); ok {
		sample["server"] = h
	}
	return observedEvent{
		src:     src,
		service: svc,
		typ:     "dns",
		tmpl:    "dns " + normName(name) + " " + strings.ToUpper(qtype),
		sample:  sample,
	}
}

// hostFrom returns the event's destination host:port.
func hostFrom(data map[string]any) (string, bool) {
	dst, _ := data["dst"].(string)
	if dst == "" {
		return "", false
	}
	port := intOf(data["dport"])
	if port == 0 {
		return dst, true
	}
	return fmt.Sprintf("%s:%d", dst, port), true
}

// ---- templating ------------------------------------------------------------

// normPath templates a URL path: numeric segments become :id, long
// random-looking tokens become :rand (docs: rotating product IDs become
// one check with a set of values).
func normPath(p string) string {
	p = strings.Trim(p, "/")
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case isNumeric(s):
			segs[i] = ":id"
		case isRand(s):
			segs[i] = ":rand"
		}
	}
	return "/" + strings.Join(segs, "/")
}

// normName templates a DNS name label by label.
func normName(n string) string {
	labels := strings.Split(n, ".")
	for i, l := range labels {
		switch {
		case isNumeric(l):
			labels[i] = ":id"
		case isRand(l):
			labels[i] = ":rand"
		}
	}
	return strings.Join(labels, ".")
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// isRand treats an alphanumeric run of 12+ as a rotating token.
func isRand(s string) bool {
	if len(s) < 12 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return true
}

// obsID is the stable identity of an observed check.
func obsID(service, typ, tmpl string) string {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|%s|%s", service, typ, tmpl)
	return fmt.Sprintf("%s-%016x", typ, h.Sum64())
}

// httpParts splits a URL into method (default GET) and path.
func httpParts(u string) (method, path string) {
	method = "GET"
	path = u
	if i := strings.IndexAny(u, "://"); i >= 0 {
		rest := u[i+3:]
		j := strings.IndexByte(rest, '/')
		if j < 0 {
			return method, "/"
		}
		path = rest[j:]
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	return method, path
}

// ---- event field extraction --------------------------------------------------

// srcIP extracts a source address from an event field: a 16-element
// numeric array (the agent's [16]byte through JSON), a 4-element one (the
// DNS [4]byte), a base64 string, or a plain dotted quad.
func srcIP(v any) string {
	switch s := v.(type) {
	case []any:
		n := len(s)
		if n < 4 {
			return ""
		}
		parts := make([]string, 4)
		for i := 0; i < 4; i++ {
			f, ok := s[n-4+i].(float64)
			if !ok {
				return ""
			}
			parts[i] = strconv.Itoa(int(f))
		}
		return strings.Join(parts, ".")
	case string:
		if net.ParseIP(s) != nil {
			return s
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err == nil && len(b) >= 4 {
			return net.IP(b[len(b)-4:]).String()
		}
	}
	return ""
}

func intOf(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case uint16:
		return int(n)
	case uint32:
		return int(n)
	}
	return 0
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

func inSet(US []string, ip string) bool {
	for _, u := range US {
		if u == ip {
			return true
		}
	}
	return false
}

func inList(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
