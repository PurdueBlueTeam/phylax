// Package decoys implements the agent's decoy services (design: Deception,
// "Decoy services"): record-only listeners that emit a decoy.hit event for
// every touch. Nothing received is ever executed, nothing connects back out,
// and a listener is refused outright on a scored port.
package decoys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/honeytokens"
)

// KindHit is the event kind of every decoy touch.
const KindHit = "decoy.hit"

// Listener kinds (the manifest's DecoyListener.kind values plus smb).
const (
	KindSSH       = "ssh"
	KindMySQL     = "mysql"
	KindRedis     = "redis"
	KindTelnet    = "telnet"
	KindWinRM     = "winrm"
	KindRDP       = "rdp"
	KindHTTPAdmin = "http_admin"
	KindSMB       = "smb"
)

var knownKinds = map[string]bool{KindSSH: true, KindMySQL: true, KindRedis: true, KindTelnet: true,
	KindWinRM: true, KindRDP: true, KindHTTPAdmin: true, KindSMB: true}

// Hit stages, in order of depth.
const (
	StageConnect  = "connect"  // info
	StageLogin    = "login"    // high
	StageCommand  = "command"  // high
	StageRequest  = "request"  // info: an HTTP path or protocol probe, no credential
	StageRejected = "rejected" // over the session bounds
	StageEnd      = "end"      // session summary
)

// Severities carried in the event; priority is always Critical so a hit rides
// the spool's top class.
const (
	SevInfo     = "info"
	SevHigh     = "high"
	SevCritical = "critical"
)

// ErrScoredPort is returned when a decoy is configured on a scored port.
var ErrScoredPort = errors.New("decoys: refusing to place a decoy on a scored port")

// TokenMatcher recognises honeytokens used against a decoy. The controller's
// registry (honeytokens.Registry) implements it.
type TokenMatcher interface {
	MatchCredential(user, secret string) (honeytokens.Token, bool)
	MatchFingerprint(fp string) (honeytokens.Token, bool)
}

// Listener is one decoy service port.
type Listener struct {
	Kind string
	Port uint16
}

// Config configures the module. Zero values take safe defaults.
type Config struct {
	Host      string // host name shown by the fake shell
	Bind      string // listen address host part ("" = all interfaces)
	Listeners []Listener
	// ScoredPorts are the ports of every scored service on this host. New
	// refuses any listener on one of them.
	ScoredPorts []uint16
	Tokens      TokenMatcher
	// AllowEphemeral permits Port 0 (OS-chosen), for tests only.
	AllowEphemeral bool

	MaxSessions     int           // concurrent, all sources (default 64)
	MaxPerSource    int           // concurrent per source IP (default 4)
	SessionTimeout  time.Duration // hard cap on one session (default 2m)
	IdleTimeout     time.Duration // (default 30s)
	MaxCommands     int           // per session (default 100)
	MaxAuthAttempts int           // per session before the connection is dropped (default 6)
	AcceptAfter     int           // password attempts before the SSH/telnet decoy lets the client in (default 3)
	HitRate         float64       // sustained hit events/s per source (default 2)
	HitBurst        int           // (default 20)

	// Delay returns the pause before a fake response; nil = 40..300ms jitter.
	Delay  func() time.Duration
	Logger *slog.Logger
}

func (c *Config) defaults() {
	def := func(p *int, v int) {
		if *p <= 0 {
			*p = v
		}
	}
	def(&c.MaxSessions, 64)
	def(&c.MaxPerSource, 4)
	def(&c.MaxCommands, 100)
	def(&c.MaxAuthAttempts, 6)
	def(&c.AcceptAfter, 3)
	def(&c.HitBurst, 20)
	if c.SessionTimeout <= 0 {
		c.SessionTimeout = 2 * time.Minute
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 30 * time.Second
	}
	if c.HitRate <= 0 {
		c.HitRate = 2
	}
	if c.Delay == nil {
		c.Delay = func() time.Duration { return time.Duration(40+rand.IntN(260)) * time.Millisecond }
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Host == "" {
		c.Host = "srv01"
	}
}

// Validate checks the listener set against the scoring-safety rules.
func (c Config) Validate() error {
	scored := map[uint16]bool{}
	for _, p := range c.ScoredPorts {
		scored[p] = true
	}
	seen := map[uint16]bool{}
	for _, l := range c.Listeners {
		if !knownKinds[l.Kind] {
			return fmt.Errorf("decoys: unknown listener kind %q", l.Kind)
		}
		if l.Port == 0 && !c.AllowEphemeral {
			return fmt.Errorf("decoys: %s listener needs a port", l.Kind)
		}
		if scored[l.Port] {
			return fmt.Errorf("%w: %s on %d", ErrScoredPort, l.Kind, l.Port)
		}
		if l.Port == 445 {
			return fmt.Errorf("decoys: %s on 445: Windows holds 445 on every host (no SMB decoy there)", l.Kind)
		}
		if l.Port != 0 && seen[l.Port] {
			return fmt.Errorf("decoys: port %d declared twice", l.Port)
		}
		seen[l.Port] = true
	}
	return nil
}

// Stats are cumulative counters.
type Stats struct {
	Accepted, Rejected, Hits, HitsDropped uint64
}

// Module is the decoy agent module.
type Module struct {
	cfg  Config
	emit agent.Emit

	mu     sync.Mutex
	active int
	perSrc map[netip.Addr]int
	conns  map[net.Conn]struct{}
	bucket map[netip.Addr]*srcBucket
	addrs  map[string]net.Addr // kind -> bound address
	ready  chan struct{}
	// bannerIdx picks this run's banner from the pools (randomised per start).
	bannerIdx int

	accepted, rejected, hits, dropped atomic.Uint64
}

// New validates cfg and returns the module. It refuses scored ports.
func New(cfg Config) (*Module, error) {
	cfg.defaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Module{cfg: cfg, perSrc: map[netip.Addr]int{}, conns: map[net.Conn]struct{}{},
		bucket: map[netip.Addr]*srcBucket{}, addrs: map[string]net.Addr{}, ready: make(chan struct{}),
		bannerIdx: rand.IntN(1 << 20)}, nil
}

// Name implements agent.Module.
func (*Module) Name() string { return "decoys" }

// Ready is closed once every listener is bound.
func (m *Module) Ready() <-chan struct{} { return m.ready }

// Addr returns the bound address of the first listener of a kind.
func (m *Module) Addr(kind string) net.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.addrs[kind]
}

// Stats returns the counters.
func (m *Module) Stats() Stats {
	return Stats{m.accepted.Load(), m.rejected.Load(), m.hits.Load(), m.dropped.Load()}
}

type srcBucket struct {
	tokens float64
	last   time.Time
}

// allow is the per-source hit rate limit.
func (m *Module) allow(src netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	b := m.bucket[src]
	if b == nil {
		if len(m.bucket) >= 4096 { // bounded: forget everything rather than grow
			m.bucket = map[netip.Addr]*srcBucket{}
		}
		b = &srcBucket{tokens: float64(m.cfg.HitBurst), last: now}
		m.bucket[src] = b
	}
	b.tokens = min(float64(m.cfg.HitBurst), b.tokens+now.Sub(b.last).Seconds()*m.cfg.HitRate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Start implements agent.Module.
func (m *Module) Start(ctx context.Context, emit agent.Emit) error {
	m.emit = emit
	var lns []net.Listener
	closeAll := func() {
		for _, l := range lns {
			_ = l.Close()
		}
	}
	for _, l := range m.cfg.Listeners {
		ln, err := net.Listen("tcp", net.JoinHostPort(m.cfg.Bind, strconv.Itoa(int(l.Port))))
		if err != nil {
			closeAll()
			return fmt.Errorf("decoys: listen %s on %d: %w", l.Kind, l.Port, err)
		}
		lns = append(lns, ln)
		m.mu.Lock()
		if m.addrs[l.Kind] == nil {
			m.addrs[l.Kind] = ln.Addr()
		}
		m.mu.Unlock()
	}
	close(m.ready)
	var wg sync.WaitGroup
	for i, ln := range lns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.acceptLoop(ctx, ln, m.cfg.Listeners[i], &wg)
		}()
	}
	<-ctx.Done()
	closeAll()
	m.mu.Lock()
	for c := range m.conns {
		_ = c.Close()
	}
	m.mu.Unlock()
	wg.Wait()
	return nil
}

func (m *Module) acceptLoop(ctx context.Context, ln net.Listener, l Listener, wg *sync.WaitGroup) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		src := addrOf(c.RemoteAddr())
		m.mu.Lock()
		ok := m.active < m.cfg.MaxSessions && m.perSrc[src] < m.cfg.MaxPerSource
		if ok {
			m.active++
			m.perSrc[src]++
			m.conns[c] = struct{}{}
		}
		m.mu.Unlock()
		if !ok {
			m.rejected.Add(1)
			s := m.newSession(l, c)
			s.hit(StageRejected, SevInfo, nil)
			_ = c.Close()
			continue
		}
		m.accepted.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.serve(ctx, l, c, src)
		}()
	}
}

func (m *Module) serve(ctx context.Context, l Listener, c net.Conn, src netip.Addr) {
	s := m.newSession(l, c)
	defer func() {
		if r := recover(); r != nil {
			m.cfg.Logger.Error("decoy handler panic", "kind", l.Kind, "panic", r)
		}
		_ = c.Close()
		m.mu.Lock()
		m.active--
		if m.perSrc[src]--; m.perSrc[src] <= 0 {
			delete(m.perSrc, src)
		}
		delete(m.conns, c)
		m.mu.Unlock()
		s.end()
	}()
	_ = c.SetDeadline(s.deadline)
	s.hit(StageConnect, SevInfo, nil)
	switch l.Kind {
	case KindSSH:
		m.serveSSH(ctx, s, c)
	case KindMySQL:
		m.serveMySQL(s, c)
	case KindRedis:
		m.serveRedis(s, c)
	case KindTelnet:
		m.serveTelnet(s, c)
	case KindHTTPAdmin, KindWinRM:
		m.serveHTTP(ctx, s, c)
	case KindRDP:
		m.serveRDP(s, c)
	case KindSMB:
		m.serveSMB(s, c)
	}
}

// ---- sessions ----

const (
	maxCredLen   = 128
	maxCredsKept = 32
	maxCmdsKept  = 100
	maxCmdLen    = 512
)

// Cred is one credential attempt.
type Cred struct {
	User   string `json:"user"`
	Secret string `json:"secret,omitempty"`
	Method string `json:"method,omitempty"`
	Token  string `json:"honeytoken,omitempty"`
}

type sess struct {
	m        *Module
	l        Listener
	c        net.Conn
	src      netip.Addr
	srcPort  int
	start    time.Time
	deadline time.Time

	mu       sync.Mutex
	creds    []Cred
	cmds     []string
	attempts int
	depth    string
	tokens   map[string]honeytokens.Token
}

func addrOf(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		ip, _ := netip.AddrFromSlice(ta.IP)
		return ip.Unmap()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (m *Module) newSession(l Listener, c net.Conn) *sess {
	now := time.Now()
	s := &sess{m: m, l: l, c: c, src: addrOf(c.RemoteAddr()), start: now, deadline: now.Add(m.cfg.SessionTimeout),
		depth: StageConnect, tokens: map[string]honeytokens.Token{}}
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		s.srcPort = ta.Port
	}
	return s
}

// idle extends the read deadline by the idle timeout, never past the hard cap.
func (s *sess) idle() {
	d := time.Now().Add(s.m.cfg.IdleTimeout)
	if d.After(s.deadline) {
		d = s.deadline
	}
	_ = s.c.SetReadDeadline(d)
}

func (s *sess) pause() { time.Sleep(s.m.cfg.Delay()) }

func trunc(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

// hit emits one decoy.hit. Critical (honeytoken) hits bypass the rate limit.
func (s *sess) hit(stage, sev string, extra map[string]any) {
	m := s.m
	if sev != SevCritical && !m.allow(s.src) {
		m.dropped.Add(1)
		return
	}
	f := map[string]any{
		"protocol": s.l.Kind, "source": s.src.String(), "source_port": s.srcPort,
		"dest_port": portOf(s.c.LocalAddr()), "stage": stage, "severity": sev,
		"decoy_host": m.cfg.Host,
	}
	for k, v := range extra {
		f[k] = v
	}
	if m.emit == nil {
		return
	}
	_ = m.emit(event.Event{Time: time.Now(), Kind: KindHit, Priority: event.PriorityCritical, Fields: f})
	m.hits.Add(1)
}

func portOf(a net.Addr) int {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.Port
	}
	return 0
}

func tokenFields(t honeytokens.Token) map[string]any {
	return map[string]any{"honeytoken": t.ID, "token_origin": t.Host, "token_kind": string(t.Kind)}
}

// credential records one attempt, matches it against the honeytokens and emits
// the login hit. It reports the matched token (critical) if any.
func (s *sess) credential(user, secret, method string) (honeytokens.Token, bool) {
	user, secret = trunc(user, maxCredLen), trunc(secret, maxCredLen)
	var tok honeytokens.Token
	var ok bool
	if s.m.cfg.Tokens != nil && secret != "" {
		tok, ok = s.m.cfg.Tokens.MatchCredential(user, secret)
	}
	s.mu.Lock()
	s.attempts++
	c := Cred{User: user, Secret: secret, Method: method}
	if ok {
		c.Token = tok.ID
		s.tokens[tok.ID] = tok
	}
	if len(s.creds) < maxCredsKept {
		s.creds = append(s.creds, c)
	}
	s.depth = StageLogin
	s.mu.Unlock()
	extra := map[string]any{"account": user, "secret": secret, "method": method}
	sev := SevHigh
	if ok {
		sev = SevCritical
		for k, v := range tokenFields(tok) {
			extra[k] = v
		}
	}
	s.hit(StageLogin, sev, extra)
	return tok, ok
}

// fingerprintUse records a public-key login attempt (the SSH honey key).
func (s *sess) fingerprintUse(user, fp string) (honeytokens.Token, bool) {
	var tok honeytokens.Token
	var ok bool
	if s.m.cfg.Tokens != nil {
		tok, ok = s.m.cfg.Tokens.MatchFingerprint(fp)
	}
	s.mu.Lock()
	s.attempts++
	c := Cred{User: trunc(user, maxCredLen), Secret: trunc(fp, maxCredLen), Method: "publickey"}
	if ok {
		c.Token = tok.ID
		s.tokens[tok.ID] = tok
	}
	if len(s.creds) < maxCredsKept {
		s.creds = append(s.creds, c)
	}
	s.depth = StageLogin
	s.mu.Unlock()
	extra := map[string]any{"account": c.User, "key_fingerprint": c.Secret, "method": "publickey"}
	sev := SevHigh
	if ok {
		sev = SevCritical
		for k, v := range tokenFields(tok) {
			extra[k] = v
		}
	}
	s.hit(StageLogin, sev, extra)
	return tok, ok
}

func (s *sess) tooManyAttempts() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts >= s.m.cfg.MaxAuthAttempts
}

// command records one command line. It returns false when the per-session
// command cap is reached (the caller then closes the session).
func (s *sess) command(line string) bool {
	line = trunc(line, maxCmdLen)
	s.mu.Lock()
	n := len(s.cmds)
	if n < maxCmdsKept {
		s.cmds = append(s.cmds, line)
	}
	s.depth = StageCommand
	s.mu.Unlock()
	if n >= s.m.cfg.MaxCommands {
		return false
	}
	s.hit(StageCommand, SevHigh, map[string]any{"command": line})
	return true
}

// end emits the session summary.
func (s *sess) end() {
	s.mu.Lock()
	creds := append([]Cred(nil), s.creds...)
	cmds := append([]string(nil), s.cmds...)
	ids := make([]string, 0, len(s.tokens))
	origins := map[string]bool{}
	for id, t := range s.tokens {
		ids = append(ids, id)
		origins[t.Host] = true
	}
	depth := s.depth
	s.mu.Unlock()
	sort.Strings(ids)
	extra := map[string]any{"depth": depth, "credentials": creds, "commands": cmds,
		"duration_ms": time.Since(s.start).Milliseconds()}
	sev := SevInfo
	switch depth {
	case StageLogin, StageCommand:
		sev = SevHigh
	}
	if len(ids) > 0 {
		sev = SevCritical
		extra["honeytokens"] = ids
		var os []string
		for o := range origins {
			os = append(os, o)
		}
		sort.Strings(os)
		extra["token_origins"] = os
	}
	s.hit(StageEnd, sev, extra)
}

// LocalConfig is the decoy section of <state dir>/deception.json, written by
// the plan step that deploys decoys (values generated at competition time).
type LocalConfig struct {
	Bind        string              `json:"bind,omitempty"`
	Listeners   []LocalListener     `json:"listeners"`
	ScoredPorts []uint16            `json:"scored_ports,omitempty"`
	Tokens      []honeytokens.Token `json:"tokens,omitempty"`
	WatchPaths  []string            `json:"watch_paths,omitempty"`
}

// LocalListener is the JSON form of Listener.
type LocalListener struct {
	Kind string `json:"kind"`
	Port uint16 `json:"port"`
}

// LoadLocalConfig reads and bounds-checks deception.json.
func LoadLocalConfig(path string) (LocalConfig, error) {
	var lc LocalConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return lc, err
	}
	if len(b) > 4<<20 {
		return lc, errors.New("decoys: deception.json too large")
	}
	if err := json.Unmarshal(b, &lc); err != nil {
		return lc, fmt.Errorf("decoys: %s: %w", path, err)
	}
	return lc, nil
}

// Registry builds the token registry from the config.
func (lc LocalConfig) Registry() (*honeytokens.Registry, error) {
	r := honeytokens.NewRegistry()
	for _, t := range lc.Tokens {
		if err := r.Add(t); err != nil {
			return nil, err
		}
	}
	return r, nil
}
