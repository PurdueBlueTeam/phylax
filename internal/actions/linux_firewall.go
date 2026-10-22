package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/deadman"
	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

// FirewallBackend is the host firewall as firewall.allow sees it: the
// declared policy (the manifest-derived intent plus accepted deltas) and a way
// to install a new one atomically. The Linux adapter wraps
// internal/firewall.LinuxManager (NftFirewall); tests use a fake.
type FirewallBackend interface {
	// Policy returns the currently declared host policy.
	Policy(ctx context.Context) (*render.HostPolicy, error)
	// Apply installs hp and records it as the declared policy. It does not arm
	// a dead-man switch: the action executor does (Capture/Snapshot).
	Apply(ctx context.Context, hp *render.HostPolicy) error
	// Snapshot captures the current kernel and declared state for rollback.
	Snapshot(ctx context.Context) (json.RawMessage, error)
	// Restore puts a Snapshot back.
	Restore(ctx context.Context, snap json.RawMessage) error
}

const (
	kindFWAllowUndo = "firewall.allow.undo"
	fwAllowTag      = "phylax:allow:"
)

type firewallAllow struct{}

func (firewallAllow) Spec() Spec {
	return Spec{Name: "firewall.allow", Risk: RiskLockout,
		Doc: "Add (or update) an inbound allow rule to the declared host policy and install it through the firewall manager. Rollback restores the previous kernel and declared state.",
		Params: []ParamSpec{
			{Name: "ports", Type: String, Required: true, Max: 256, Check: func(v any) error { _, _, err := parsePorts(v.(string)); return err }},
			{Name: "proto", Type: Enum, Enum: []string{"tcp", "udp"}, Default: "tcp"},
			{Name: "from", Type: String, Required: true, Max: 1024, Check: func(v any) error { _, err := parsePeers(v.(string)); return err }},
			{Name: "name", Type: String, Max: 64, Check: func(v any) error {
				if !pkgNameRe.MatchString(v.(string)) {
					return errors.New("invalid rule name")
				}
				return nil
			}},
		}}
}

func (firewallAllow) Locks(Params) []string  { return []string{LockFirewall} }
func (firewallAllow) Touches(Params) []Touch { return nil }

func parsePorts(s string) (ports []uint16, ranges []manifest.PortRange, err error) {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			r, err := manifest.ParsePortRange(part)
			if err != nil {
				return nil, nil, err
			}
			ranges = append(ranges, r)
			continue
		}
		n, err := strconv.ParseUint(part, 10, 16)
		if err != nil || n == 0 {
			return nil, nil, fmt.Errorf("invalid port %q", part)
		}
		ports = append(ports, uint16(n))
	}
	if len(ports)+len(ranges) == 0 {
		return nil, nil, errors.New("no ports given")
	}
	slices.Sort(ports)
	return slices.Compact(ports), ranges, nil
}

// parsePeers accepts "any" (no source restriction), or comma-separated
// addresses and CIDR prefixes.
func parsePeers(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		switch {
		case part == "":
			continue
		case part == "any" || part == "*":
			if len(strings.Split(s, ",")) > 1 {
				return nil, errors.New(`"any" cannot be combined with other sources`)
			}
			return nil, nil
		}
		if pf, err := netip.ParsePrefix(part); err == nil {
			out = append(out, pf.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid source %q", part)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	if len(out) == 0 && s != "any" && s != "*" {
		return nil, errors.New("no sources given")
	}
	return out, nil
}

func fwRuleName(p Params) string {
	if p.Has("name") {
		return p.Str("name")
	}
	return "allow-" + p.Str("proto") + "-" + strings.ReplaceAll(strings.ReplaceAll(p.Str("ports"), ",", "_"), " ", "")
}

func fwRule(p Params) render.Rule {
	ports, ranges, _ := parsePorts(p.Str("ports"))
	peers, _ := parsePeers(p.Str("from"))
	name := fwRuleName(p)
	return render.Rule{Group: render.GroupService, Kind: render.KindService, Dir: render.In, Action: render.Accept,
		Proto: p.Str("proto"), LocalPorts: ports, LocalRanges: ranges, Peers: peers, Service: name, Comment: fwAllowTag + name}
}

func describeFWRule(r render.Rule) string {
	var ps []string
	for _, p := range r.LocalPorts {
		ps = append(ps, strconv.Itoa(int(p)))
	}
	for _, rg := range r.LocalRanges {
		ps = append(ps, rg.String())
	}
	src := "any"
	if len(r.Peers) > 0 {
		var l []string
		for _, p := range r.Peers {
			l = append(l, p.String())
		}
		src = strings.Join(l, ",")
	}
	return fmt.Sprintf("accept in %s %s from %s (%s)", r.Proto, strings.Join(ps, ","), src, r.Comment)
}

func sameRule(a, b render.Rule) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

// withRule returns hp with rule applied (replacing the rule with the same tag).
func withRule(hp *render.HostPolicy, r render.Rule) (out *render.HostPolicy, old *render.Rule) {
	cp := *hp
	cp.Rules = nil
	replaced := false
	for _, e := range hp.Rules {
		if e.Comment == r.Comment {
			ec := e
			old = &ec
			if !replaced {
				cp.Rules = append(cp.Rules, r)
				replaced = true
			}
			continue
		}
		cp.Rules = append(cp.Rules, e)
	}
	if !replaced {
		cp.Rules = append(cp.Rules, r)
	}
	return &cp, old
}

func (firewallAllow) backend(env *Env) (FirewallBackend, error) {
	if env.lx().Firewall == nil {
		return nil, fmt.Errorf("host firewall: %w", ErrUnsupported)
	}
	return env.lx().Firewall, nil
}

func (f firewallAllow) Plan(ctx context.Context, env *Env, p Params) (Plan, error) {
	b, err := f.backend(env)
	if err != nil {
		return Plan{}, err
	}
	hp, err := b.Policy(ctx)
	if err != nil {
		return Plan{}, err
	}
	r := fwRule(p)
	_, old := withRule(hp, r)
	if old != nil && sameRule(*old, r) {
		return Plan{Done: true}, nil
	}
	d := "+ " + describeFWRule(r)
	if old != nil {
		d = "- " + describeFWRule(*old) + "\n" + d
	}
	pl := Plan{Diff: "declared policy delta (" + hp.Host + "):\n" + d}
	if len(r.Peers) == 0 {
		pl.Notes = append(pl.Notes, "source is any: the port is open to every address")
	}
	return pl, nil
}

func (f firewallAllow) Capture(ctx context.Context, env *Env, _ Params) (Rollback, error) {
	b, err := f.backend(env)
	if err != nil {
		return Rollback{}, err
	}
	s, err := b.Snapshot(ctx)
	if err != nil {
		return Rollback{}, err
	}
	return Rollback{Kind: kindFWAllowUndo, Data: s}, nil
}

func undoFirewallAllow(ctx context.Context, env *Env, e deadman.Entry) error {
	if env.lx().Firewall == nil {
		return fmt.Errorf("host firewall: %w", ErrUnsupported)
	}
	return env.lx().Firewall.Restore(ctx, json.RawMessage(e.Data))
}

func (f firewallAllow) Apply(ctx context.Context, env *Env, p Params) (Output, error) {
	b, err := f.backend(env)
	if err != nil {
		return nil, err
	}
	hp, err := b.Policy(ctx)
	if err != nil {
		return nil, err
	}
	next, _ := withRule(hp, fwRule(p))
	return nil, b.Apply(ctx, next)
}

func (f firewallAllow) Verify(ctx context.Context, env *Env, p Params) error {
	b, err := f.backend(env)
	if err != nil {
		return err
	}
	hp, err := b.Policy(ctx)
	if err != nil {
		return err
	}
	r := fwRule(p)
	for _, e := range hp.Rules {
		if sameRule(e, r) {
			return nil
		}
	}
	return errors.New("allow rule missing from the declared policy after apply")
}
