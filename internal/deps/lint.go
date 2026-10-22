package deps

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

// Scoring-safety lint rule IDs for observed dependencies (docs/deps.md).
const (
	RuleCutDependency      = "DEP001" // observed dependency of a scored service would be blocked by the egress policy
	RuleExternalDependency = "DEP002" // observed dependency on an address outside the manifest, not allowed
	RuleDependencyDown     = "DEP003" // a scored service depends on a service the manifest stops or disables
	RuleCutByPolicy        = "DEP101" // rendered host policy blocks an observed dependency
)

// CheckManifest lints a (proposed) manifest against observed dependencies:
// it errors when the egress rendering would cut a confirmed dependency of a
// scored service, and warns for weaker evidence. Gone edges are ignored.
func CheckManifest(g *Graph, m *manifest.Manifest) []manifest.Finding {
	var out []manifest.Finding
	edges := g.Edges()
	for _, e := range edges {
		if e.Gone {
			continue
		}
		s, ok := m.Services[e.From.Service]
		if !ok || !s.Scored || s.Host != e.From.Host {
			continue
		}
		subj := "service " + e.From.Service
		if cov, _ := Covered(m, e); !cov {
			if e.To.Host != "" {
				sev := manifest.SevWarn
				if e.Level == ConfHigh && e.Strength == StrengthStrong {
					sev = manifest.SevError
				}
				out = append(out, manifest.Finding{ID: RuleCutDependency, Severity: sev, Subject: subj,
					Message: fmt.Sprintf("observed dependency on %s %s/%d (%s, %s evidence, %d connections) is not allowed by depends_on or policy.egress; the egress rendering would cut it",
						e.To, e.To.Proto, e.To.Port, e.Level, e.Strength, e.Count)})
			} else {
				out = append(out, manifest.Finding{ID: RuleExternalDependency, Severity: manifest.SevWarn, Subject: subj,
					Message: fmt.Sprintf("observed outbound dependency on unknown address %s:%d/%s (%d connections) is not allowed; if it is not legitimate, leave it blocked and investigate",
						e.To.Addr, e.To.Port, e.To.Proto, e.Count)})
			}
		}
		// A scored service depending on a service this manifest takes down.
		if e.To.Host != "" {
			if t, ok := m.Services[e.To.Service]; ok && t.Host == e.To.Host && !t.IsServiceEnabled() && e.Level != ConfLow {
				out = append(out, manifest.Finding{ID: RuleDependencyDown, Severity: manifest.SevError, Subject: "service " + e.To.Service,
					Message: fmt.Sprintf("state %q but scored service %s on %s depends on it (%s evidence)", t.State, e.From.Service, e.From.Host, e.Strength)})
			}
		}
	}
	manifest.SortFindings(out)
	return out
}

// CheckHostPolicy lints a rendered host policy against observed dependencies
// of the services on that host (the hand-edited or regressed case that
// render.CheckHostPolicy cannot see, because it only knows depends_on).
func CheckHostPolicy(g *Graph, m *manifest.Manifest, hp *render.HostPolicy) []manifest.Finding {
	if hp.DefaultOut != render.Drop {
		return nil
	}
	var out []manifest.Finding
	for _, e := range g.Edges() {
		if e.Gone || e.From.Host != hp.Host || e.To.Host == hp.Host {
			continue
		}
		s, ok := m.Services[e.From.Service]
		if !ok || !s.Scored {
			continue
		}
		dst, err := netip.ParseAddr(e.To.Addr)
		if err != nil || e.Level == ConfLow && e.To.Host == "" {
			continue
		}
		if e.To.Host == "" {
			continue // external: the policy is meant to block it
		}
		if !policyAllows(hp, e.To.Proto, dst, e.To.Port) {
			sev := manifest.SevWarn
			if e.Level == ConfHigh && e.Strength == StrengthStrong {
				sev = manifest.SevError
			}
			out = append(out, manifest.Finding{ID: RuleCutByPolicy, Severity: sev, Subject: "firewall " + hp.Host,
				Message: fmt.Sprintf("observed dependency %s -> %s %s/%d would be blocked (%s evidence, %d connections)",
					e.From.Service, e.To, e.To.Proto, e.To.Port, e.Strength, e.Count)})
		}
	}
	manifest.SortFindings(out)
	return out
}

func policyAllows(hp *render.HostPolicy, proto string, dst netip.Addr, port uint16) bool {
	for _, r := range hp.Rules {
		if r.Dir != render.Out || r.Action != render.Accept {
			continue
		}
		if r.Proto != "" && r.Proto != proto {
			continue
		}
		if len(r.RemotePorts) > 0 || len(r.RemoteRanges) > 0 {
			if !(manifest.Ports{Ports: r.RemotePorts, Ranges: r.RemoteRanges}).Has(port) {
				continue
			}
		}
		if len(r.Peers) > 0 {
			in := false
			for _, p := range r.Peers {
				if p.Contains(dst) {
					in = true
					break
				}
			}
			if !in {
				continue
			}
		}
		return true
	}
	return false
}

// Dependents returns the scored services that depend on the named service (a
// manifest id, unit or binary name) on host with at least medium confidence
// and current evidence: stopping, disabling or firewalling the target cuts them.
func (g *Graph) Dependents(host, name string) []Edge {
	id := g.ServiceByName(host, name)
	if id == "" {
		id = name
	}
	var out []Edge
	for _, e := range g.DependedOnBy(host, id) {
		if e.Gone || e.Level == ConfLow || e.From.Host == host && e.From.Service == id {
			continue
		}
		if g.Scored(e.From.Host, e.From.Service) {
			out = append(out, e)
		}
	}
	return out
}

// DescribeEdges is a one-line summary for refusal messages.
func DescribeEdges(es []Edge) string {
	var parts []string
	for _, e := range es {
		parts = append(parts, fmt.Sprintf("%s (%s, %s)", e.From, e.Level, e.Strength))
	}
	return strings.Join(parts, ", ")
}
