package actions

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// deception.decoy_check proves the decoy listeners the signed config asked for
// are accepting connections on this host. Read-only: it connects to loopback
// and closes (a bare connect is the lowest-severity decoy hit, D15a).
type decoyCheck struct{}

func (decoyCheck) Spec() Spec {
	return Spec{Name: "deception.decoy_check", Risk: RiskNone, ReadOnly: true,
		Doc: "Check that decoy listeners accept connections on loopback.",
		Params: []ParamSpec{
			{Name: "ports", Type: StringList, Required: true, Max: 64},
			{Name: "wait_sec", Type: Int, Default: 10},
		}}
}

func (decoyCheck) Locks(Params) []string  { return nil }
func (decoyCheck) Touches(Params) []Touch { return nil }

func (decoyCheck) down(ctx context.Context, p Params) ([]string, error) {
	var bad []string
	for _, s := range p.List("ports") {
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("bad port %q", s)
		}
		d := net.Dialer{Timeout: 2 * time.Second}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", s))
		if err != nil {
			bad = append(bad, s)
			continue
		}
		_ = c.Close()
	}
	return bad, nil
}

func (a decoyCheck) Plan(ctx context.Context, _ *Env, p Params) (Plan, error) {
	bad, err := a.down(ctx, p)
	if err != nil {
		return Plan{}, err
	}
	if len(bad) > 0 {
		return Plan{Diff: "decoy ports not listening yet: " + strings.Join(bad, ",")}, nil
	}
	return Plan{Done: true}, nil
}

func (decoyCheck) Capture(context.Context, *Env, Params) (Rollback, error) { return Rollback{}, nil }

func (a decoyCheck) Apply(ctx context.Context, _ *Env, p Params) (Output, error) {
	wait, _ := p.Int("wait_sec")
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		bad, err := a.down(ctx, p)
		if err != nil {
			return nil, err
		}
		if len(bad) == 0 {
			return nil, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, fmt.Errorf("decoy ports not accepting connections: %s", strings.Join(bad, ","))
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (a decoyCheck) Verify(ctx context.Context, _ *Env, p Params) error {
	bad, err := a.down(ctx, p)
	if err != nil {
		return err
	}
	if len(bad) > 0 {
		return fmt.Errorf("decoy ports not accepting connections: %s", strings.Join(bad, ","))
	}
	return nil
}
