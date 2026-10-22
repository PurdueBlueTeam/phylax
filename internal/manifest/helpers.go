package manifest

import (
	"net/netip"
	"sort"
)

// Defaults applied when a field is omitted.
const (
	DefaultRelayPort    = 7444
	DefaultSinkholePort = 7480
	DefaultDenyLogGroup = 100
)

// SortedKeys returns the keys of m in order, for deterministic output.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// HostAddr returns the host's static address. ok is false for DHCP hosts.
func (m *Manifest) HostAddr(name string) (netip.Addr, bool) {
	h, found := m.Hosts[name]
	if !found || h.IsDHCP() {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(h.IP)
	return a, err == nil
}

// SegmentPrefix returns the segment's CIDR.
func (m *Manifest) SegmentPrefix(seg string) (netip.Prefix, bool) {
	s, ok := m.Topology.Segments[seg]
	if !ok {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(s.CIDR)
	return p, err == nil
}

// HostPrefix returns the narrowest prefix that identifies the host: its /32
// (/128) when static, else its segment's CIDR (DHCP hosts have no known
// address). approx is true in the latter case.
func (m *Manifest) HostPrefix(name string) (p netip.Prefix, approx bool) {
	h := m.Hosts[name]
	if a, ok := m.HostAddr(name); ok {
		return netip.PrefixFrom(a, a.BitLen()), false
	}
	p, _ = m.SegmentPrefix(h.Segment)
	return p, true
}

// ControllerHost returns the controller host's name.
func (m *Manifest) ControllerHost() string { return m.Topology.Controller.Host }

// ControllerSegment returns the segment the controller lives in.
func (m *Manifest) ControllerSegment() string { return m.Hosts[m.Topology.Controller.Host].Segment }

// RelayPort returns the relay listening port of the segment.
func (s Segment) RelayPortOrDefault() uint16 {
	if s.RelayPort == 0 {
		return DefaultRelayPort
	}
	return s.RelayPort
}

// ParentSegment returns the segment s's relay dials toward the controller.
func (m *Manifest) ParentSegment(seg string) string {
	if p := m.Topology.Segments[seg].Parent; p != "" {
		return p
	}
	return m.ControllerSegment()
}

// TranslatedSource returns the address the Kali-style segment's traffic is
// source-NATed to by its firewall device (device.external_ip), if declared.
func (m *Manifest) TranslatedSource(seg string) (netip.Addr, bool) {
	s, ok := m.Topology.Segments[seg]
	if !ok || s.Firewall == "" {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(m.Devices[s.Firewall].ExternalIP)
	return a, err == nil
}

// DevicePorts returns the management ports for the device (vendor default
// when none are declared).
func (d Device) DevicePorts() []uint16 {
	if len(d.Ports) > 0 {
		return d.Ports
	}
	switch d.Vendor {
	case "panos":
		return []uint16{443}
	case "vyos":
		return []uint16{22, 443}
	}
	return []uint16{22, 443}
}

// SinkholePort returns the effective sinkhole catcher port, 0 if disabled.
func (p Policy) SinkholePort() uint16 {
	if p.Egress.Sinkhole == nil || !p.Egress.Sinkhole.Enabled {
		return 0
	}
	if p.Egress.Sinkhole.Port == 0 {
		return DefaultSinkholePort
	}
	return p.Egress.Sinkhole.Port
}

// DenyLogGroup returns the NFLOG group for denied egress.
func (p Policy) DenyLogGroup() uint16 {
	if p.Egress.DenyLogGroup == 0 {
		return DefaultDenyLogGroup
	}
	return p.Egress.DenyLogGroup
}

// ServicesOn returns the ids of the services on host, sorted.
func (m *Manifest) ServicesOn(host string) []string {
	var ids []string
	for id, s := range m.Services {
		if s.Host == host {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// IsServiceEnabled reports whether the service is meant to be running.
func (s Service) IsServiceEnabled() bool { return s.State == "" || s.State == "running" }
