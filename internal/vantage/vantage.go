// Package vantage implements the Kali roles of the external vantage point
// (design: "The Kali as an external vantage point") as agent Modules plus the
// controller-side interfaces they talk to:
//
//   - CheckRunner: Quotient-faithful probes of our public IPs (events
//     "vantage.check"), aligned to the scorer's quiet window.
//   - VerifyService / RemoteVerifier: PCR credential verification through the
//     public path (implements scorer.Verifier on the controller).
//   - Scanner: external TCP connect and UDP scans of our public IPs, diffed
//     against the declared exposure ("vantage.exposure_change").
//   - Canary: a listener for egress canaries ("vantage.canary_hit" = a leak).
//
// Every verdict from here is advisory evidence about the public path. Targets
// are restricted to an explicit allowlist of our own public addresses: the
// scorer, other teams and global assets can never be probed, whatever the
// controller asks for.
package vantage

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/agent"
	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/scorer"
)

// Event kinds emitted by the vantage modules.
const (
	KindCheck          = "vantage.check"
	KindCheckDeferred  = "vantage.check_deferred"
	KindRefused        = "vantage.refused"
	KindScan           = "vantage.scan"
	KindExposureChange = "vantage.exposure_change" // V2
	KindCanaryHit      = "vantage.canary_hit"      // V3
	KindPCRVerify      = "vantage.pcr_verify"      // V4 on failure
)

// Allowlist is the set of our own public addresses a vantage module may touch.
type Allowlist struct{ prefixes []netip.Prefix }

// NewAllowlist builds an allowlist from prefixes (a single address is a /32).
func NewAllowlist(p ...netip.Prefix) Allowlist {
	return Allowlist{prefixes: append([]netip.Prefix(nil), p...)}
}

// ParseAllowlist parses "172.25.21.0/24" or "172.25.21.10" entries.
func ParseAllowlist(entries ...string) (Allowlist, error) {
	var out []netip.Prefix
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			return Allowlist{}, fmt.Errorf("vantage: bad allowlist entry %q", e)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return Allowlist{prefixes: out}, nil
}

// Allows reports whether host is an IP literal inside the allowlist.
// Hostnames are refused: the manifest carries addresses.
func (a Allowlist) Allows(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Gate is what the vantage modules need from the round clock; the scorer's
// WindowSource (and *scorer.Estimator) satisfy it.
type Gate interface {
	SafeFor(now time.Time, need time.Duration) scorer.Window
}

// clock bundles the injectable time functions.
type clock struct {
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) bool // false if ctx ended first
}

func (c *clock) defaults() {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Sleep == nil {
		c.Sleep = realSleep
	}
}

func realSleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// waitSafe blocks until a quiet window of at least need is open, ctx ends, or
// maxWait passes. It reports whether it is safe to start.
func waitSafe(ctx context.Context, g Gate, c clock, need, maxWait time.Duration) bool {
	if g == nil {
		return ctx.Err() == nil
	}
	deadline := c.Now().Add(maxWait)
	for {
		now := c.Now()
		w := g.SafeFor(now, need)
		if w.Safe {
			return true
		}
		if !now.Before(deadline) || ctx.Err() != nil {
			return false
		}
		d := 250 * time.Millisecond
		if !w.NextOpens.IsZero() && w.NextOpens.After(now) {
			d = min(w.NextOpens.Sub(now), time.Second)
		}
		if !c.Sleep(ctx, min(d, deadline.Sub(now))) {
			return false
		}
	}
}

// limiter paces events at a sustained rate with a small burst.
type limiter struct {
	mu    sync.Mutex
	every time.Duration
	burst time.Duration // how far ahead of schedule a caller may run
	next  time.Time
	c     clock
}

func newLimiter(perSecond float64, burst int, c clock) *limiter {
	c.defaults()
	if perSecond <= 0 {
		return &limiter{c: c}
	}
	every := time.Duration(float64(time.Second) / perSecond)
	return &limiter{every: every, burst: every * time.Duration(max(burst-1, 0)), c: c}
}

// Wait blocks until the next token; false if ctx ended.
func (l *limiter) Wait(ctx context.Context) bool {
	if l.every == 0 {
		return ctx.Err() == nil
	}
	l.mu.Lock()
	now := l.c.Now()
	if l.next.Before(now.Add(-l.burst)) {
		l.next = now.Add(-l.burst)
	}
	at := l.next
	l.next = l.next.Add(l.every)
	l.mu.Unlock()
	if d := at.Sub(now); d > 0 {
		return l.c.Sleep(ctx, d)
	}
	return ctx.Err() == nil
}

func newEvent(kind string, prio event.Priority, now time.Time, f map[string]any) event.Event {
	return event.Event{Time: now, Kind: kind, Priority: prio, Fields: f}
}

func ipOf(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}

var _ agent.Module = (*CheckRunner)(nil)
