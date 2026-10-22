package deps

import (
	"net/netip"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

// Covered reports whether the manifest already lets the edge through the
// egress policy, and why. The renderers allow, per host: the agent link,
// every depends_on of the services on it, policy.egress.allow entries and the
// domain-membership ports; workstations are not default-deny.
func Covered(m *manifest.Manifest, e Edge) (bool, string) {
	if e.From.Host == "" {
		return true, "unknown source"
	}
	if e.To.Host == e.From.Host {
		return true, "same host"
	}
	h, ok := m.Hosts[e.From.Host]
	if !ok {
		return true, "source host not in the manifest"
	}
	if h.IsWorkstation() {
		return true, "workstation egress is not default-deny"
	}
	proto := e.To.Proto
	if proto == "" {
		proto = "tcp"
	}
	port := e.To.Port
	dst, _ := netip.ParseAddr(e.To.Addr)
	if e.To.Host != "" && e.To.Host == m.ControllerHost() && port == m.Topology.Controller.AgentPort {
		return true, "agent link"
	}
	for _, id := range m.ServicesOn(e.From.Host) {
		for _, d := range m.Services[id].DependsOn {
			dp := d.Proto
			if dp == "" {
				dp = "tcp"
			}
			if d.To == e.To.Host && e.To.Host != "" && dp == proto && d.PortSet().Has(port) {
				return true, "depends_on of " + id
			}
		}
	}
	for _, a := range m.Policy.Egress.Allow {
		if a.Host != "" && a.Host != e.From.Host {
			continue
		}
		ap := a.Proto
		if ap == "" {
			ap = "tcp"
		}
		if ap != proto || !a.PortSet().Has(port) {
			continue
		}
		if _, isHost := m.Hosts[a.To]; isHost {
			if a.To == e.To.Host {
				return true, "policy.egress.allow " + a.To
			}
			continue
		}
		if p, err := netip.ParsePrefix(a.To); err == nil && dst.IsValid() && p.Contains(dst) {
			return true, "policy.egress.allow " + a.To
		}
	}
	if dc := h.DomainMember; dc != "" && dc == e.To.Host {
		for _, a := range m.DomainAllowances(dc) {
			if a.Proto == proto && (manifest.Ports{Ports: a.Ports, Ranges: a.Ranges}).Has(port) {
				return true, "domain membership of " + dc
			}
		}
	}
	return false, ""
}
