package render

import (
	"fmt"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

// Firewall lint rule IDs ("CI checks: a firewall lint that fails if any scored
// port, declared dependency, DHCP, ICMP or IPv6 need would be blocked").
const (
	RuleScoredPort = "FW101"
	RuleICMP       = "FW102"
	RuleICMPv6     = "FW103"
	RuleDHCPNeed   = "FW104"
	RuleDependency = "FW105"
	RuleAgentLink  = "FW106"
	RuleDefaults   = "FW107"
	RuleBlindDrop  = "FW108"
	RuleDomain     = "FW110" // domain member to DC allowances missing
)

// CheckHostPolicy verifies the invariants a host policy must hold, independent
// of how it was built, so a hand-edited or regressed policy is caught.
func CheckHostPolicy(m *manifest.Manifest, hp *HostPolicy) []manifest.Finding {
	var out []manifest.Finding
	subj := "firewall " + hp.Host
	add := func(id string, sev manifest.Severity, format string, args ...any) {
		out = append(out, manifest.Finding{ID: id, Severity: sev, Subject: subj, Message: fmt.Sprintf(format, args...)})
	}
	has := func(match func(Rule) bool) bool {
		for _, r := range hp.Rules {
			if r.Action == Accept && match(r) {
				return true
			}
		}
		return false
	}
	covers := func(r Rule, d Direction, proto string, want manifest.Ports) bool {
		if r.Dir != d || (r.Proto != "" && r.Proto != proto) {
			return false
		}
		have := manifest.Ports{Ports: r.LocalPorts, Ranges: r.LocalRanges}
		if d == Out {
			have = manifest.Ports{Ports: r.RemotePorts, Ranges: r.RemoteRanges}
		}
		return have.Covers(want)
	}

	// Scored ports: unrestricted accept from any source.
	for _, id := range m.ServicesOn(hp.Host) {
		s := m.Services[id]
		if !s.Scored || !s.IsServiceEnabled() {
			continue
		}
		for _, l := range s.Listen {
			ok := has(func(r Rule) bool { return len(r.Peers) == 0 && covers(r, In, l.Proto, l.PortSet()) })
			if !ok {
				add(RuleScoredPort, manifest.SevError, "scored service %s (%s/%s) is not accepted from all sources", id, l.Proto, l.PortSet())
			}
		}
	}
	// ICMP, ICMPv6, DHCP, both directions.
	for _, d := range []Direction{In, Out} {
		if !has(func(r Rule) bool { return r.Dir == d && r.Proto == "icmp" && len(r.Peers) == 0 }) {
			add(RuleICMP, manifest.SevError, "ICMP %s is not allowed", d)
		}
		if !has(func(r Rule) bool { return r.Dir == d && r.Proto == "icmpv6" && len(r.Peers) == 0 }) {
			add(RuleICMPv6, manifest.SevError, "ICMPv6 %s is not allowed (neighbour discovery needs it)", d)
		}
		if !has(func(r Rule) bool { return r.Dir == d && r.Kind == KindDHCP }) {
			add(RuleDHCPNeed, manifest.SevError, "DHCP %s is not allowed", d)
		}
		if !has(func(r Rule) bool { return r.Dir == d && r.Kind == KindDHCPv6 }) {
			add(RuleDHCPNeed, manifest.SevError, "DHCPv6 %s is not allowed", d)
		}
	}
	// Declared dependencies (needed only where egress is default-deny).
	if hp.DefaultOut == Drop {
		for _, id := range m.ServicesOn(hp.Host) {
			for _, d := range m.Services[id].DependsOn {
				proto := d.Proto
				if proto == "" {
					proto = "tcp"
				}
				if !has(func(r Rule) bool { return covers(r, Out, proto, d.PortSet()) && peerCovers(m, r, d.To) }) {
					add(RuleDependency, manifest.SevError, "dependency %s of %s (%s %s to %s) would be blocked", d.Egress, id, proto, d.PortSet(), d.To)
				}
			}
		}
	}
	// Agent link.
	ctl := m.ControllerHost()
	if hp.Host == ctl {
		if !has(func(r Rule) bool {
			return r.Kind == KindAgentLink && r.Dir == In && covers(r, In, "tcp", manifest.Ports{Ports: []uint16{m.Topology.Controller.AgentPort}})
		}) {
			add(RuleAgentLink, manifest.SevError, "controller does not accept agent streams on %d", m.Topology.Controller.AgentPort)
		}
	} else {
		if !has(func(r Rule) bool { return r.Kind == KindAgentLink && r.Dir == Out }) {
			add(RuleAgentLink, manifest.SevError, "no outbound agent link rule: the agent could not reach the controller")
		}
	}
	// Domain membership: the member reaches its DC on every AD port, and the
	// DC accepts the member (both ends rendered, so default-deny cannot cut
	// Kerberos, LDAP, DNS, SMB or RPC).
	if dc := m.Hosts[hp.Host].DomainMember; dc != "" {
		for _, a := range m.DomainAllowances(dc) {
			want := manifest.Ports{Ports: a.Ports, Ranges: a.Ranges}
			if !has(func(r Rule) bool {
				return r.Kind == KindDomain && covers(r, Out, a.Proto, want) && peerCovers(m, r, dc)
			}) {
				add(RuleDomain, manifest.SevError, "domain member of %s: %s %s to the DC would be blocked", dc, a.Proto, want)
			}
		}
	}
	if m.Hosts[hp.Host].IsDomainController() {
		for _, mn := range m.DomainMembers(hp.Host) {
			for _, a := range m.DomainAllowances(hp.Host) {
				want := manifest.Ports{Ports: a.Ports, Ranges: a.Ranges}
				if !has(func(r Rule) bool { return r.Kind == KindDomain && covers(r, In, a.Proto, want) && peerCovers(m, r, mn) }) {
					add(RuleDomain, manifest.SevError, "domain controller does not accept member %s on %s %s", mn, a.Proto, want)
				}
			}
		}
	}
	// Defaults: servers are default-deny both ways.
	if !hp.Workstation {
		if hp.DefaultIn != Drop || hp.DefaultOut != Drop {
			add(RuleDefaults, manifest.SevWarn, "server is not default-deny (in %s, out %s)", hp.DefaultIn, hp.DefaultOut)
		}
	}
	// Blind drops: a drop rule may only be a canary.
	for _, r := range hp.Rules {
		if r.Action != Drop || r.Group == GroupCanary {
			continue
		}
		out = append(out, manifest.Finding{ID: RuleBlindDrop, Severity: manifest.SevError, Subject: subj,
			Message: fmt.Sprintf("drop rule outside the canary group: %s", r.Comment)})
	}
	return out
}

// peerCovers reports whether the rule's peers include the host's address.
func peerCovers(m *manifest.Manifest, r Rule, host string) bool {
	if len(r.Peers) == 0 {
		return true
	}
	want, _ := m.HostPrefix(host)
	for _, p := range r.Peers {
		if p.Contains(want.Addr()) && p.Bits() <= want.Bits() {
			return true
		}
	}
	return false
}

// CheckAll builds and checks every host policy and, when device intents are
// requested, the Palo and VyOS intents as well.
func CheckAll(m *manifest.Manifest) ([]manifest.Finding, error) {
	hps, err := BuildAll(m)
	if err != nil {
		return nil, err
	}
	var out []manifest.Finding
	for _, name := range manifest.SortedKeys(hps) {
		out = append(out, CheckHostPolicy(m, hps[name])...)
	}
	for _, dn := range manifest.SortedKeys(m.Devices) {
		d := m.Devices[dn]
		switch d.Vendor {
		case "panos":
			pi, err := PaloIntents(m, dn)
			if err != nil {
				return nil, err
			}
			out = append(out, CheckPalo(m, pi)...)
		case "vyos":
			vi, err := VyOSIntents(m, dn)
			if err != nil {
				return nil, err
			}
			out = append(out, CheckVyOS(m, vi)...)
		}
	}
	return out, nil
}

// LintAll runs the manifest lint and the firewall lint over the rendered
// policies and returns all findings, sorted. This is the CI entry point.
func LintAll(m *manifest.Manifest) ([]manifest.Finding, error) {
	fw, err := CheckAll(m)
	if err != nil {
		return nil, err
	}
	out := append(manifest.Lint(m), fw...)
	manifest.SortFindings(out)
	return out, nil
}
