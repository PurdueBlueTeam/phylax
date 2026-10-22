package netmod

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/event"
)

// CanaryTarget is a destination policy should block, probed on purpose.
type CanaryTarget struct {
	Addr netip.Addr
	Port uint16
	Tag  string // carried on the result and on matching denials
}

func (c CanaryTarget) matches(dst netip.AddrPort) bool {
	return c.Addr.Unmap() == dst.Addr().Unmap() && c.Port == dst.Port()
}

// ProbeCanary dials one target over TCP and classifies the result: "leak" if
// the connection was established (policy failed to block it), "blocked" for a
// timeout, refusal or unreachable (the expected outcome), "error" otherwise.
func ProbeCanary(ctx context.Context, t CanaryTarget, timeout time.Duration) event.Event {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(t.Addr.String(), strconv.Itoa(int(t.Port)))
	c, err := d.DialContext(ctx, "tcp", addr)
	result, detail := "leak", ""
	switch {
	case err == nil:
		c.Close()
	case errors.Is(err, context.Canceled):
		result, detail = "error", "cancelled"
	default:
		result = "blocked"
		var ne net.Error
		switch {
		case errors.Is(err, syscall.ECONNREFUSED):
			detail = "refused"
		case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.EPERM):
			detail = "unreachable"
		case errors.As(err, &ne) && ne.Timeout():
			detail = "timeout"
		default:
			result, detail = "error", err.Error()
		}
	}
	f := map[string]any{
		"raddr": t.Addr.String(), "rport": int(t.Port), "proto": "tcp", "tag": "canary",
		"result": result, "expected": result == "blocked", "elapsed_ms": time.Since(start).Milliseconds(),
	}
	if t.Tag != "" {
		f["canary_tag"] = t.Tag
	}
	if detail != "" {
		f["detail"] = detail
	}
	pr := event.PriorityNormal
	if result == "leak" {
		pr = event.PriorityCritical
	}
	return event.Event{Time: time.Now(), Kind: KindCanaryResult, Priority: pr, Fields: f}
}
