package manifest

import (
	"fmt"
	"net"
	"sort"
	"strconv"
)

// lint runs the cross-file checks that JSON Schemas cannot express:
// dependency cycles, firewall lint, decoy collisions, relay/controller
// placement and address sanity.
func (m *Manifest) lint() error {
	if err := m.lintAddresses(); err != nil {
		return err
	}
	if err := m.lintDependencies(); err != nil {
		return err
	}
	if err := m.lintPortCollisions(); err != nil {
		return err
	}
	if err := m.lintFirewall(); err != nil {
		return err
	}
	return m.lintRoles()
}

// lintAddresses checks IP uniqueness, CIDR membership and the controller UI
// binding.
func (m *Manifest) lintAddresses() error {
	seen := map[string]string{}
	for _, name := range m.HostNames() {
		h := m.Hosts.Hosts[name]
		ip := net.ParseIP(h.IP)
		if ip == nil {
			return fmt.Errorf("manifest: host %s: invalid ip %q", name, h.IP)
		}
		if prev, dup := seen[h.IP]; dup {
			return fmt.Errorf("manifest: ip %s used by both %s and %s", h.IP, prev, name)
		}
		seen[h.IP] = name
		seg, ok := m.Topology.Segments[h.Segment]
		if !ok {
			return fmt.Errorf("manifest: host %s: unknown segment %q", name, h.Segment)
		}
		_, cidr, err := net.ParseCIDR(seg.CIDR)
		if err != nil {
			return fmt.Errorf("manifest: segment %s: invalid cidr %q", h.Segment, seg.CIDR)
		}
		if !cidr.Contains(ip) {
			return fmt.Errorf("manifest: host %s ip %s outside segment %s cidr %s", name, h.IP, h.Segment, seg.CIDR)
		}
	}
	if host, port, err := net.SplitHostPort(m.Topology.Controller.UI); err != nil || host != "127.0.0.1" {
		return fmt.Errorf("manifest: controller.ui must be bound to 127.0.0.1 (got %q)", m.Topology.Controller.UI)
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("manifest: controller.ui port invalid (got %q)", m.Topology.Controller.UI)
	}
	if _, err := m.Host(m.Topology.Controller.Host); err != nil {
		return fmt.Errorf("manifest: controller host not in hosts.yml: %w", err)
	}
	return nil
}

// lintDependencies checks that service dependencies reference known
// services/hosts and contains no cycles.
func (m *Manifest) lintDependencies() error {
	// Graph over service names; egress deps do not create cycles between
	// services.
	adj := map[string][]string{}
	for name, svc := range m.Services {
		if _, err := m.Host(svc.Host); err != nil {
			return fmt.Errorf("manifest: service %s: %w", name, err)
		}
		for _, d := range svc.Depends {
			if d.Service != "" {
				if _, ok := m.Services[d.Service]; !ok {
					return fmt.Errorf("manifest: service %s: unknown dependency %q", name, d.Service)
				}
				adj[name] = append(adj[name], d.Service)
			}
			if d.Egress != "" && d.To != "" {
				if _, err := m.Host(d.To); err != nil {
					return fmt.Errorf("manifest: service %s: egress target %q: %w", name, d.To, err)
				}
			}
		}
	}
	// DFS cycle detection (graph is small; recursion depth is bounded by
	// the number of services).
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var visit func(node string) error
	visit = func(node string) error {
		color[node] = gray
		for _, next := range adj[node] {
			switch color[next] {
			case white:
				if err := visit(next); err != nil {
					return err
				}
			case gray:
				return fmt.Errorf("manifest: service dependency cycle through %s", next)
			}
		}
		color[node] = black
		return nil
	}
	for _, start := range m.ServiceNames() {
		if color[start] == white {
			if err := visit(start); err != nil {
				return err
			}
		}
	}
	return nil
}

// ServiceNames returns service names in stable order.
func (m *Manifest) ServiceNames() []string {
	out := make([]string, 0, len(m.Services))
	for name := range m.Services {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// lintPortCollisions checks that no two services on a host claim the same
// listener, and that decoy ports never collide with a SCORED service's
// port (decoys are never on scored ports; a decoy may share a port with a
// service that hardening will disable, e.g. the ssh_shell decoy on 22).
func (m *Manifest) lintPortCollisions() error {
	type key struct {
		proto string
		port  int
	}
	for _, name := range m.HostNames() {
		claimed := map[key]string{}
		scored := map[key]bool{}
		for _, svcName := range m.ServiceNames() {
			svc := m.Services[svcName]
			if svc.Host != name {
				continue
			}
			for _, l := range svc.Listen {
				k := key{l.Proto, l.Port}
				if prev, dup := claimed[k]; dup {
					return fmt.Errorf("manifest: host %s: ports %s/%d claimed by both %s and %s", name, l.Proto, l.Port, prev, svcName)
				}
				claimed[k] = svcName
				if svc.Scored {
					scored[k] = true
				}
			}
		}
		if hd, ok := m.Decoys[name]; ok {
			for _, l := range hd.Listeners {
				if scored[key{"tcp", l.Port}] {
					return fmt.Errorf("manifest: host %s: decoy port %d sits on a scored service port", name, l.Port)
				}
			}
		}
	}
	return nil
}

// lintFirewall is the firewall lint the CI runs: no rendered policy may block
// a scored service port or a declared dependency, and every segment that
// needs a relay has one whose host is declared.
func (m *Manifest) lintFirewall() error {
	cseg, err := m.SegmentOf(m.Topology.Controller.Host)
	if err != nil {
		return err
	}
	for segName, seg := range m.Topology.Segments {
		if segName == cseg {
			continue
		}
		if seg.Relay == nil {
			return fmt.Errorf("manifest: segment %s is not the controller segment and has no relay", segName)
		}
		_, err := m.Host(seg.Relay.Host)
		if err != nil {
			return fmt.Errorf("manifest: segment %s relay: %w", segName, err)
		}
	}
	// Scored service ports must be reachable: they are in the inbound accept
	// chain by construction, but a disabled scored service is a manifest bug.
	for _, svcName := range m.ServiceNames() {
		svc := m.Services[svcName]
		if svc.Scored && svc.State == "disabled" {
			return fmt.Errorf("manifest: scored service %s is declared disabled", svcName)
		}
	}
	return nil
}

// lintRoles checks role placement constraints.
func (m *Manifest) lintRoles() error {
	for _, name := range m.HostNames() {
		h := m.Hosts.Hosts[name]
		if h.HasRole(RoleRelay) {
			seg, _ := m.SegmentOf(name)
			s, ok := m.Topology.Segments[seg]
			if !ok || s.Relay == nil || s.Relay.Host != name {
				return fmt.Errorf("manifest: host %s has role relay but its segment does not name it as relay", name)
			}
			// A relay host must not host scored services.
			for _, svcName := range m.ServiceNames() {
				if svc := m.Services[svcName]; svc.Host == name && svc.Scored {
					return fmt.Errorf("manifest: relay host %s hosts scored service %s", name, svcName)
				}
			}
		}
	}
	// Relay hosts must be in a non-controller segment.
	for segName, seg := range m.Topology.Segments {
		if seg.Relay == nil {
			continue
		}
		r, err := m.Host(seg.Relay.Host)
		if err != nil {
			return err
		}
		cseg, _ := m.SegmentOf(m.Topology.Controller.Host)
		if r.Segment == cseg {
			return fmt.Errorf("manifest: relay for segment %s sits in the controller segment", segName)
		}
	}
	return nil
}
