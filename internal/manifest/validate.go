package manifest

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// Validate checks structure and cross-references. Rule-level problems (things
// that are well formed but break scoring) are the lint's job.
func (m *Manifest) Validate() error {
	var e ErrorList
	t := m.Topology
	oneOf := func(subject, field, v string, allowed ...string) {
		if !slices.Contains(allowed, v) {
			e.Addf("%s: %s %q is not one of %s", subject, field, v, strings.Join(allowed, ", "))
		}
	}

	// Controller.
	ch, ok := m.Hosts[t.Controller.Host]
	switch {
	case t.Controller.Host == "":
		e.Addf("topology: controller.host is required")
	case !ok:
		e.Addf("topology: controller.host %q is not a host", t.Controller.Host)
	case !ch.HasRole(RoleController):
		e.Addf("topology: controller host %q must have the controller role", t.Controller.Host)
	}
	if t.Controller.AgentPort == 0 {
		e.Addf("topology: controller.agent_port is required")
	}
	if host, _, err := net.SplitHostPort(t.Controller.UI); err != nil {
		e.Addf("topology: controller.ui %q must be host:port", t.Controller.UI)
	} else if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		e.Addf("topology: controller.ui %q must be a loopback address (the operator UI is never network-reachable)", t.Controller.UI)
	}
	for name, h := range m.Hosts {
		if h.HasRole(RoleController) && name != t.Controller.Host {
			e.Addf("host %s: has the controller role but topology names %q as controller", name, t.Controller.Host)
		}
	}

	// Segments.
	if len(t.Segments) == 0 {
		e.Addf("topology: at least one segment is required")
	}
	pools := map[string]netip.Prefix{}
	for _, name := range SortedKeys(t.Segments) {
		s := t.Segments[name]
		subj := "segment " + name
		if _, err := netip.ParsePrefix(s.CIDR); err != nil {
			e.Addf("%s: cidr %q: %v", subj, s.CIDR, err)
		}
		for _, d := range []string{s.Firewall, s.Uplink} {
			if d != "" {
				if _, ok := m.Devices[d]; !ok {
					e.Addf("%s: device %q is not declared", subj, d)
				}
			}
		}
		if s.NAT != nil {
			p, err := netip.ParsePrefix(s.NAT.PublicPool)
			if err != nil {
				e.Addf("%s: nat.public_pool %q: %v", subj, s.NAT.PublicPool, err)
			} else {
				pools[name] = p
			}
			oneOf(subj, "nat.mode", s.NAT.Mode, "static_1to1_same_octet")
		}
		if s.Relay != "" {
			rh, ok := m.Hosts[s.Relay]
			switch {
			case !ok:
				e.Addf("%s: relay host %q is not a host", subj, s.Relay)
			case rh.Segment != name:
				e.Addf("%s: relay host %q is in segment %q, not this one", subj, s.Relay, rh.Segment)
			case !rh.HasRole(RoleRelay):
				e.Addf("%s: relay host %q must have the relay role", subj, s.Relay)
			}
		}
		if s.Parent != "" {
			if _, ok := t.Segments[s.Parent]; !ok {
				e.Addf("%s: parent segment %q is not declared", subj, s.Parent)
			}
		}
		if cp := s.ControllerPath; cp != nil {
			oneOf(subj, "controller_path.via", cp.Via, "static_nat")
			if _, err := netip.ParseAddr(cp.Public); err != nil {
				e.Addf("%s: controller_path.public %q: %v", subj, cp.Public, err)
			}
			if cp.Port == 0 {
				e.Addf("%s: controller_path.port is required", subj)
			}
			af, ok := m.Hosts[cp.AllowFrom]
			switch {
			case !ok:
				e.Addf("%s: controller_path.allow_from host %q is not a host", subj, cp.AllowFrom)
			case af.Segment != name:
				e.Addf("%s: controller_path.allow_from host %q is not in this segment", subj, cp.AllowFrom)
			}
		}
	}
	for _, role := range m.relayedSegmentsWithoutPath() {
		e.Addf("segment %s: cannot reach the controller (no controller_path, no relay with a path to it)", role)
	}

	// Devices.
	for _, name := range SortedKeys(m.Devices) {
		d := m.Devices[name]
		subj := "device " + name
		oneOf(subj, "vendor", d.Vendor, "panos", "vyos", "ftd")
		if _, err := netip.ParseAddr(d.Mgmt); err != nil {
			e.Addf("%s: mgmt %q: %v", subj, d.Mgmt, err)
		}
		if d.ExternalIP != "" {
			if _, err := netip.ParseAddr(d.ExternalIP); err != nil {
				e.Addf("%s: external_ip %q: %v", subj, d.ExternalIP, err)
			}
		}
		if _, ok := t.Segments[d.Segment]; !ok {
			e.Addf("%s: segment %q is not declared", subj, d.Segment)
		}
		if d.Via != "" {
			if _, ok := m.Devices[d.Via]; !ok {
				e.Addf("%s: via device %q is not declared", subj, d.Via)
			}
			if d.Via == name {
				e.Addf("%s: via itself", subj)
			}
		}
		if d.Proxy != "" {
			if ph, ok := m.Hosts[d.Proxy]; !ok || !ph.HasRole(RoleDeviceProxy) {
				e.Addf("%s: proxy %q must be a host with the device_proxy role", subj, d.Proxy)
			}
		}
	}

	// Hosts.
	seenIP := map[string]string{}
	seenPub := map[string]string{}
	for _, name := range SortedKeys(m.Hosts) {
		h := m.Hosts[name]
		subj := "host " + name
		seg, ok := t.Segments[h.Segment]
		if !ok {
			e.Addf("%s: segment %q is not declared", subj, h.Segment)
		}
		oneOf(subj, "os.family", h.OS.Family, "debian", "rhel", "suse", "arch", "alpine", "windows")
		if h.OS.Version == "" {
			e.Addf("%s: os.version is required", subj)
		}
		if h.Class != "" {
			oneOf(subj, "class", h.Class, "server", "workstation")
		}
		for _, r := range h.Roles {
			oneOf(subj, "role", r, validRoles...)
		}
		if h.Hardening != nil {
			if h.Hardening.NTLM != "" {
				oneOf(subj, "hardening.ntlm", h.Hardening.NTLM, "allow", "deny")
			}
			if h.Hardening.ICMPEcho != "" {
				oneOf(subj, "hardening.icmp_echo", h.Hardening.ICMPEcho, "allow", "drop")
			}
		}
		if h.IsDHCP() {
			if h.Public != "" {
				e.Addf("%s: a DHCP host cannot have a same-octet public address", subj)
			}
		} else {
			a, err := netip.ParseAddr(h.IP)
			if err != nil {
				e.Addf("%s: ip %q must be an address or \"dhcp\"", subj, h.IP)
			} else {
				if p, perr := netip.ParsePrefix(seg.CIDR); ok && perr == nil && !p.Contains(a) {
					e.Addf("%s: ip %s is outside segment %s (%s)", subj, a, h.Segment, seg.CIDR)
				}
				if prev, dup := seenIP[h.IP]; dup {
					e.Addf("%s: ip %s is also used by %s", subj, h.IP, prev)
				}
				seenIP[h.IP] = name
			}
		}
		if h.Public != "" {
			pa, err := netip.ParseAddr(h.Public)
			switch {
			case err != nil:
				e.Addf("%s: public %q: %v", subj, h.Public, err)
			case seg.NAT == nil:
				e.Addf("%s: has a public address but segment %s has no nat", subj, h.Segment)
			default:
				if pool, ok := pools[h.Segment]; ok && !pool.Contains(pa) {
					e.Addf("%s: public %s is outside the pool %s", subj, pa, pool)
				}
				if ia, err := netip.ParseAddr(h.IP); err == nil && ia.Is4() && pa.Is4() && ia.As4()[3] != pa.As4()[3] {
					e.Addf("%s: public %s does not keep the last octet of %s (mode static_1to1_same_octet)", subj, pa, ia)
				}
				if prev, dup := seenPub[h.Public]; dup {
					e.Addf("%s: public %s is also used by %s", subj, h.Public, prev)
				}
				seenPub[h.Public] = name
			}
		}
	}
	// controller_path.public must not collide with a host's public address.
	for _, sn := range SortedKeys(t.Segments) {
		if cp := t.Segments[sn].ControllerPath; cp != nil {
			if prev, dup := seenPub[cp.Public]; dup {
				e.Addf("segment %s: controller_path.public %s is already host %s's public address", sn, cp.Public, prev)
			}
		}
	}

	// Services.
	type portKey struct {
		host, proto string
		port        uint16
	}
	owner := map[portKey]string{}
	for _, id := range SortedKeys(m.Services) {
		s := m.Services[id]
		subj := "service " + id
		if _, ok := m.Hosts[s.Host]; !ok {
			e.Addf("%s: host %q is not a host", subj, s.Host)
		}
		oneOf(subj, "kind", s.Kind, validKinds...)
		if s.State != "" {
			oneOf(subj, "state", s.State, "running", "stopped", "disabled")
		}
		if s.Scored && s.Kind != "icmp" && len(s.Listen) == 0 {
			e.Addf("%s: a scored service needs at least one listener", subj)
		}
		for _, l := range s.Listen {
			oneOf(subj, "listen.proto", l.Proto, "tcp", "udp")
			if l.Port == 0 {
				e.Addf("%s: listener port is required", subj)
			}
			for _, src := range l.Sources {
				if _, err := netip.ParsePrefix(src); err != nil {
					if _, err2 := netip.ParseAddr(src); err2 != nil {
						e.Addf("%s: listener source %q is not an address or CIDR", subj, src)
					}
				}
			}
			k := portKey{s.Host, l.Proto, l.Port}
			if prev, dup := owner[k]; dup {
				e.Addf("%s: %s/%d on %s is already listened on by %s", subj, l.Proto, l.Port, s.Host, prev)
			}
			owner[k] = id
		}
		if s.Transport != nil {
			t := s.Transport
			if t.StartTLS != "" {
				oneOf(subj, "transport.starttls", t.StartTLS, "never", "optional", "required")
			}
			if t.Auth != "" {
				oneOf(subj, "transport.auth", t.Auth, "password", "ntlm", "key", "none")
			}
			if t.Encryption != "" {
				oneOf(subj, "transport.encryption", t.Encryption, "none", "optional", "required")
			}
		}
		if len(s.Outbound) > 1 && slices.Contains([]string(s.Outbound), "none") {
			e.Addf("%s: outbound \"none\" cannot be combined with hosts", subj)
		}
		if !s.Outbound.IsNone() {
			for _, o := range s.Outbound {
				if _, ok := m.Hosts[o]; !ok {
					e.Addf("%s: outbound host %q is not a host", subj, o)
				}
			}
		}
		for _, d := range s.DependsOn {
			if _, ok := m.Hosts[d.To]; !ok {
				e.Addf("%s: depends_on %q: host %q is not a host", subj, d.Egress, d.To)
			}
			if len(d.Ports) == 0 {
				e.Addf("%s: depends_on %q: ports are required", subj, d.Egress)
			}
			if d.Proto != "" {
				oneOf(subj, "depends_on.proto", d.Proto, "tcp", "udp")
			}
			if d.Service != "" {
				if ts, ok := m.Services[d.Service]; !ok || ts.Host != d.To {
					e.Addf("%s: depends_on %q: service %q is not a service on %s", subj, d.Egress, d.Service, d.To)
				}
			}
		}
	}
	if cyc := m.serviceDependencyCycle(); cyc != "" {
		e.Addf("services: dependency cycle: %s", cyc)
	}

	// Scorer and accounts.
	if m.Scorer.Engine != "" {
		oneOf("scorer", "engine", m.Scorer.Engine, "quotient")
	}
	if m.Scorer.PollPortal != "" {
		oneOf("scorer", "poll_portal", m.Scorer.PollPortal, "off", "ask_organizers", "operator_paste", "cookie_poll")
	}
	for _, n := range SortedKeys(m.Scorer.Credlists) {
		if m.Scorer.Credlists[n].Path == "" {
			e.Addf("scorer: credlist %q needs a path", n)
		}
	}
	for _, id := range SortedKeys(m.Accounts) {
		a := m.Accounts[id]
		subj := "account " + id
		oneOf(subj, "scope", a.Scope, "local", "domain", "service", "device")
		oneOf(subj, "rotation", a.Rotation, "pcr_transaction", "free", "manual")
		if a.Scored == "" {
			e.Addf("%s: scored is required (true, false or unknown)", subj)
		}
		if a.SSHAuth != "" {
			oneOf(subj, "ssh_auth", a.SSHAuth, "password", "both", "key_only")
		}
		for _, h := range a.Hosts {
			if _, ok := m.Hosts[h]; !ok {
				e.Addf("%s: host %q is not a host", subj, h)
			}
		}
		if a.Credlist != "" {
			if _, ok := m.Scorer.Credlists[a.Credlist]; !ok {
				e.Addf("%s: credlist %q is not declared in scorer.yml", subj, a.Credlist)
			}
		}
	}

	// Decoys.
	for _, h := range SortedKeys(m.Decoys) {
		d := m.Decoys[h]
		subj := "decoys " + h
		if _, ok := m.Hosts[h]; !ok {
			e.Addf("%s: host is not declared", subj)
		}
		if d.Exposure != "" {
			oneOf(subj, "exposure", d.Exposure, "lan", "public", "both")
		}
		for _, l := range d.Listeners {
			oneOf(subj, "listener.kind", l.Kind, "ssh", "mysql", "redis", "telnet", "winrm", "rdp", "http_admin")
			if l.Port == 0 {
				e.Addf("%s: listener %s needs a port", subj, l.Kind)
			}
		}
	}
	for _, k := range SortedKeys(m.Integrations) {
		oneOf("integration "+k, "name", k, "wazuh", "suricata", "zeek", "splunk_hec", "clamav")
		for _, h := range m.Integrations[k].Hosts {
			if _, ok := m.Hosts[h]; !ok {
				e.Addf("integration %s: host %q is not a host", k, h)
			}
		}
	}

	// Policy.
	for _, f := range []struct{ n, v string }{{"icmp", m.Policy.Firewall.ICMP}, {"dhcp", m.Policy.Firewall.DHCP}, {"ipv6", m.Policy.Firewall.IPv6}} {
		if f.v != "" {
			oneOf("policy", "firewall."+f.n, f.v, "allow", "drop")
		}
	}
	for i, a := range m.Policy.Egress.Allow {
		subj := fmt.Sprintf("policy egress.allow[%d]", i)
		if a.Host != "" {
			if _, ok := m.Hosts[a.Host]; !ok {
				e.Addf("%s: host %q is not a host", subj, a.Host)
			}
		}
		if _, ok := m.Hosts[a.To]; !ok {
			if _, err := netip.ParsePrefix(a.To); err != nil {
				e.Addf("%s: to %q is neither a host nor a CIDR", subj, a.To)
			}
		}
		if len(a.Ports) == 0 || a.Reason == "" {
			e.Addf("%s: ports and reason are required", subj)
		}
		if a.Proto != "" {
			oneOf(subj, "proto", a.Proto, "tcp", "udp")
		}
	}
	if pw := m.Policy.PatchWindows; pw.MaxMinutes != 0 && pw.DefaultMinutes > pw.MaxMinutes {
		e.Addf("policy: patch_windows.default_minutes exceeds max_minutes")
	}
	for _, a := range m.Overrides.AcceptedFindings {
		if a.ID == "" || a.Subject == "" || a.Reason == "" {
			e.Addf("overrides: accepted_findings need id, subject and reason")
		}
	}
	return e.Err()
}

// relayedSegmentsWithoutPath lists segments (other than the controller's) with
// no controller_path and no relay chain reaching the controller.
func (m *Manifest) relayedSegmentsWithoutPath() []string {
	ctl := m.ControllerSegment()
	var bad []string
	for _, name := range SortedKeys(m.Topology.Segments) {
		if name == ctl {
			continue
		}
		seen := map[string]bool{}
		cur := name
		ok := false
		for !seen[cur] {
			seen[cur] = true
			s := m.Topology.Segments[cur]
			if cur == ctl {
				ok = true
				break
			}
			if s.ControllerPath != nil {
				ok = true
				break
			}
			if s.Relay == "" {
				break
			}
			cur = m.ParentSegment(cur)
			if _, exists := m.Topology.Segments[cur]; !exists {
				break
			}
		}
		if !ok {
			bad = append(bad, name)
		}
	}
	return bad
}

// serviceDependencyCycle finds a cycle among service-level depends_on edges
// (entries that name a target service).
func (m *Manifest) serviceDependencyCycle() string {
	const (
		white = iota
		grey
		black
	)
	color := map[string]int{}
	var path []string
	var visit func(id string) string
	visit = func(id string) string {
		color[id] = grey
		path = append(path, id)
		for _, d := range m.Services[id].DependsOn {
			if d.Service == "" {
				continue
			}
			switch color[d.Service] {
			case grey:
				i := slices.Index(path, d.Service)
				return strings.Join(append(append([]string(nil), path[i:]...), d.Service), " -> ")
			case white:
				if c := visit(d.Service); c != "" {
					return c
				}
			}
		}
		path = path[:len(path)-1]
		color[id] = black
		return ""
	}
	for _, id := range SortedKeys(m.Services) {
		if color[id] == white {
			if c := visit(id); c != "" {
				return c
			}
		}
	}
	return ""
}
