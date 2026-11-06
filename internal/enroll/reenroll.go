package enroll

import (
	"context"
	"sort"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

// Step is one host of a re-enrollment run and the method that finishes it.
type Step struct{ Host, Method string }

// ReenrollOrder returns the manifest hosts in dependency order: every host
// with the domain_controller role first, then the hosts that are not domain
// members, then domain members, each group sorted by name.
func ReenrollOrder(m *manifest.Manifest) []string {
	var dcs, outside, members []string
	for name, h := range m.Hosts {
		switch {
		case h.HasRole(manifest.RoleDomainController):
			dcs = append(dcs, name)
		case h.DomainMember == "":
			outside = append(outside, name)
		default:
			members = append(members, name)
		}
	}
	sort.Strings(dcs)
	sort.Strings(outside)
	sort.Strings(members)
	return append(append(dcs, outside...), members...)
}

// ReenrollAll revokes every listed host's key (in order) and then pushes each
// one with its method. A "console" host is revoked but not pushed: the
// operator finishes it with the console one-liner. Pushes run one host at a
// time, so no member starts before the DCs return. Hosts whose push fails are
// returned with their error; they stay revoked so the console can finish them.
func (e *Enroller) ReenrollAll(ctx context.Context, order []string, method func(host string) string, push func(ctx context.Context, host string) error) []PushResult {
	revokeErr := make(map[string]error, len(order))
	for _, host := range order {
		if err := e.Revoke(ctx, host); err != nil {
			revokeErr[host] = err
			continue
		}
		if e.opt.Disconnect != nil {
			e.opt.Disconnect(host)
		}
	}
	results := make([]PushResult, 0, len(order))
	for _, host := range order {
		res := PushResult{Target: Target{Host: host}}
		switch {
		case revokeErr[host] != nil:
			res.Err = revokeErr[host]
		case method != nil && method(host) == "console":
			// Revoked; the operator finishes it on the console.
		default:
			res.Err = push(ctx, host)
		}
		results = append(results, res)
	}
	return results
}
