package vantage

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// CanaryTag is the first line an agent's canary probe sends:
//
//	PHYLAX-CANARY/1 host=<name> nonce=<hex>\n
//
// The listener replies "ACK <nonce>\n", which is how the probing agent knows
// the connection really reached the Kali (a leak) rather than a middlebox.
const CanaryTag = "PHYLAX-CANARY/1"

// CanaryConfig tunes the egress canary listener.
type CanaryConfig struct {
	Listen   string // bind address (default "0.0.0.0")
	TCPPorts []int  // 0 picks a free port (tests)
	UDPPorts []int
	// Resolve maps a source address to an internal host name when the probe
	// carried no tag (the Kali sees translated addresses, so this is a hint).
	Resolve func(netip.Addr) string
	// DedupWindow suppresses repeats of the same (source, port, host) hit
	// (default 30s); the next event after the window carries the suppressed count.
	DedupWindow time.Duration
	// MaxEvents bounds emitted hits per second overall (default 5, burst 20).
	MaxEvents   float64
	MaxConns    int           // concurrent TCP handlers (default 64)
	ReadTimeout time.Duration // wait for the tag (default 2s)
	clock
}

// Canary is the agent module for the `canary` role.
type Canary struct {
	cfg CanaryConfig

	mu      sync.Mutex
	addrs   []net.Addr
	ready   chan struct{}
	seen    map[string]*dedup
	hits    uint64
	dropped uint64
	lim     *limiter
}

type dedup struct {
	last       time.Time
	suppressed int
}

var _ agent.Module = (*Canary)(nil)

// NewCanary validates the configuration.
func NewCanary(cfg CanaryConfig) (*Canary, error) {
	if len(cfg.TCPPorts)+len(cfg.UDPPorts) == 0 {
		return nil, errors.New("vantage: canary needs at least one port")
	}
	cfg.clock.defaults()
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0"
	}
	if cfg.DedupWindow <= 0 {
		cfg.DedupWindow = 30 * time.Second
	}
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = 5
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 64
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 2 * time.Second
	}
	return &Canary{cfg: cfg, ready: make(chan struct{}), seen: map[string]*dedup{}, lim: newLimiter(cfg.MaxEvents, 20, cfg.clock)}, nil
}

// Name implements agent.Module.
func (c *Canary) Name() string { return "vantage.canary" }

// Ready is closed once every listener is bound.
func (c *Canary) Ready() <-chan struct{} { return c.ready }

// Addrs returns the bound listener addresses (after Ready).
func (c *Canary) Addrs() []net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]net.Addr(nil), c.addrs...)
}

// Stats returns hits emitted and hits dropped by the rate limit.
func (c *Canary) Stats() (hits, dropped uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.dropped
}

// Start implements agent.Module.
func (c *Canary) Start(ctx context.Context, emit agent.Emit) error {
	var closers []func()
	var wg sync.WaitGroup
	defer func() {
		for _, f := range closers {
			f()
		}
		wg.Wait()
	}()
	sem := make(chan struct{}, c.cfg.MaxConns)
	for _, p := range c.cfg.TCPPorts {
		l, err := net.Listen("tcp", net.JoinHostPort(c.cfg.Listen, strconv.Itoa(p)))
		if err != nil {
			return fmt.Errorf("vantage: canary tcp/%d: %w", p, err)
		}
		closers = append(closers, func() { l.Close() })
		c.mu.Lock()
		c.addrs = append(c.addrs, l.Addr())
		c.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.serveTCP(ctx, l, sem, emit)
		}()
	}
	for _, p := range c.cfg.UDPPorts {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(c.cfg.Listen, strconv.Itoa(p)))
		if err != nil {
			return fmt.Errorf("vantage: canary udp/%d: %w", p, err)
		}
		closers = append(closers, func() { pc.Close() })
		c.mu.Lock()
		c.addrs = append(c.addrs, pc.LocalAddr())
		c.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.serveUDP(ctx, pc, emit)
		}()
	}
	close(c.ready)
	<-ctx.Done()
	return nil
}

func (c *Canary) serveTCP(ctx context.Context, l net.Listener, sem chan struct{}, emit agent.Emit) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close() // over the connection bound
			continue
		}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done(); conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(c.cfg.ReadTimeout))
			line, _ := bufio.NewReaderSize(conn, 512).ReadString('\n')
			host, nonce, valid := parseTag(line)
			if valid {
				_, _ = fmt.Fprintf(conn, "ACK %s\n", nonce)
			}
			la, _ := l.Addr().(*net.TCPAddr)
			c.hit(emit, "tcp", conn.RemoteAddr(), la.Port, host, nonce, valid, line)
		}()
	}
}

func (c *Canary) serveUDP(ctx context.Context, pc net.PacketConn, emit agent.Emit) {
	buf := make([]byte, 512)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		line, _, _ := strings.Cut(string(buf[:n]), "\n")
		host, nonce, valid := parseTag(line + "\n")
		if valid {
			_, _ = pc.WriteTo([]byte("ACK "+nonce+"\n"), from)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		c.hit(emit, "udp", from, port, host, nonce, valid, line)
	}
}

func parseTag(line string) (host, nonce string, ok bool) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) < 1 || f[0] != CanaryTag {
		return "", "", false
	}
	for _, kv := range f[1:] {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "host":
			host = v
		case "nonce":
			nonce = v
		}
	}
	return host, nonce, nonce != "" && len(host) <= 253 && len(nonce) <= 64
}

func (c *Canary) hit(emit agent.Emit, proto string, from net.Addr, dport int, host, nonce string, valid bool, first string) {
	src := ipOf(from)
	if host == "" && c.cfg.Resolve != nil {
		host = c.cfg.Resolve(src)
	}
	key := fmt.Sprintf("%s|%s|%d|%s", src, proto, dport, host)
	now := c.cfg.Now()
	c.mu.Lock()
	d := c.seen[key]
	if d != nil && now.Sub(d.last) < c.cfg.DedupWindow {
		d.suppressed++
		c.mu.Unlock()
		return
	}
	if d == nil {
		if len(c.seen) >= 4096 { // bounded
			for k, v := range c.seen {
				if now.Sub(v.last) >= c.cfg.DedupWindow {
					delete(c.seen, k)
				}
			}
			if len(c.seen) >= 4096 {
				c.dropped++
				c.mu.Unlock()
				return
			}
		}
		d = &dedup{}
		c.seen[key] = d
	}
	suppressed := d.suppressed
	d.last, d.suppressed = now, 0
	c.mu.Unlock()
	if !c.lim.tryNow() {
		c.mu.Lock()
		c.dropped++
		c.mu.Unlock()
		return
	}
	if len(first) > 64 {
		first = first[:64]
	}
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
	_ = emit(newEvent(KindCanaryHit, event.PriorityHigh, now, map[string]any{
		"src": src.String(), "src_port": portOf(from), "dst_port": dport, "proto": proto,
		"host": host, "nonce": nonce, "tag_valid": valid, "suppressed": suppressed,
		"first_bytes": hex.EncodeToString([]byte(first)),
	}))
}

func portOf(a net.Addr) int {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.Port
	case *net.UDPAddr:
		return v.Port
	}
	return 0
}

// tryNow takes a token if one is available without waiting.
func (l *limiter) tryNow() bool {
	if l.every == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.c.Now()
	if l.next.Before(now.Add(-l.burst)) {
		l.next = now.Add(-l.burst)
	}
	if l.next.After(now) {
		return false
	}
	l.next = l.next.Add(l.every)
	return true
}

// CanaryOutcome is what an agent reports for one egress canary attempt.
type CanaryOutcome struct {
	Leak  bool   // the Kali answered: the connection got out
	Error string // why it did not (refused, timeout, ...): "blocked as expected"
}

// SendCanary is the agent-side probe: connect to the Kali's canary port,
// send the tag and wait for the ACK. It is rate-limited by the caller.
func SendCanary(ctx context.Context, proto, addr, host string, timeout time.Duration) CanaryOutcome {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	var nb [8]byte
	_, _ = rand.Read(nb[:])
	nonce := hex.EncodeToString(nb[:])
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, proto, addr)
	if err != nil {
		return CanaryOutcome{Error: err.Error()}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := fmt.Fprintf(c, "%s host=%s nonce=%s\n", CanaryTag, host, nonce); err != nil {
		return CanaryOutcome{Error: err.Error()}
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return CanaryOutcome{Error: err.Error()}
	}
	return CanaryOutcome{Leak: strings.TrimSpace(line) == "ACK "+nonce}
}
