// Package render turns a validated manifest into firewall policy: a typed
// per-host rule list (HostPolicy) with nftables and Windows Firewall
// renderings, plus Palo Alto and VyOS rule intents for the device adapters.
//
// Principles (design: "Rule hygiene and bring-up", "Egress policy"):
//   - management rules (agent links, device access) are a separate group from
//     service, dependency, decoy and egress rules;
//   - servers default-deny egress with an allowlist; workstations are not
//     covered by server egress rules;
//   - DHCP, ICMP and ICMPv6 are always allowed, whatever policy.yml says
//     (the lint reports a policy that asks otherwise);
//   - scored services accept from every source.
package render

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

// Group tags a rule so restore and drift detection can treat groups separately.
type Group string

// Rule groups.
const (
	GroupBase       Group = "base"       // loopback, established, ICMP, DHCP
	GroupMgmt       Group = "mgmt"       // agent links, relay, device access
	GroupService    Group = "service"    // declared listeners
	GroupDependency Group = "dependency" // depends_on egress
	GroupDecoy      Group = "decoy"      // decoy listeners
	GroupEgress     Group = "egress"     // policy.egress.allow
	GroupCanary     Group = "canary"     // egress canaries, expected blocked
)

// Direction of a rule relative to the host.
type Direction string

// Directions.
const (
	In  Direction = "in"
	Out Direction = "out"
)

// Action of a rule.
type Action string

// Actions.
const (
	Accept Action = "accept"
	Drop   Action = "drop"
)

// Kind classifies base rules so the checker can find them.
type Kind string

// Kinds.
const (
	KindLoopback    Kind = "loopback"
	KindEstablished Kind = "established"
	KindICMP        Kind = "icmp"
	KindICMPv6      Kind = "icmpv6"
	KindDHCP        Kind = "dhcp"
	KindDHCPv6      Kind = "dhcpv6"
	KindAgentLink   Kind = "agent_link"
	KindRelay       Kind = "relay"
	KindDevice      Kind = "device"
	KindService     Kind = "service"
	KindDependency  Kind = "dependency"
	KindDecoy       Kind = "decoy"
	KindEgress      Kind = "egress"
	KindCanary      Kind = "canary"
)

// Rule is one host firewall rule intent. For In rules Peers are source
// prefixes and LocalPorts the listening ports; for Out rules Peers are
// destination prefixes and RemotePorts the destination ports. Empty Peers
// means any address. A DHCP-style rule sets both port lists.
type Rule struct {
	Group       Group          `json:"group"`
	Kind        Kind           `json:"kind"`
	Dir         Direction      `json:"dir"`
	Action      Action         `json:"action"`
	Proto       string         `json:"proto,omitempty"` // tcp | udp | icmp | icmpv6; empty: any
	LocalPorts  []uint16       `json:"local_ports,omitempty"`
	RemotePorts []uint16       `json:"remote_ports,omitempty"`
	Peers       []netip.Prefix `json:"peers,omitempty"`
	Approx      bool           `json:"approx,omitempty"`    // a peer is the whole segment because the host address is DHCP
	Log         bool           `json:"log,omitempty"`       // NFLOG the packets this rule matches
	LogGroup    uint16         `json:"log_group,omitempty"` // NFLOG group when Log is set
	Service     string         `json:"service,omitempty"`
	Comment     string         `json:"comment,omitempty"`
}

// HostPolicy is the complete host firewall intent for one host.
type HostPolicy struct {
	Host         string `json:"host"`
	Family       string `json:"os_family"`
	Workstation  bool   `json:"workstation,omitempty"`
	DefaultIn    Action `json:"default_in"`
	DefaultOut   Action `json:"default_out"`
	DenyLogGroup uint16 `json:"deny_log_group,omitempty"` // NFLOG group for denied egress (servers)
	// SinkholePort, if non-zero, redirects denied outbound TCP to a loopback
	// catcher (Linux servers only).
	SinkholePort uint16 `json:"sinkhole_port,omitempty"`
	Rules        []Rule `json:"rules"`
}

// BuildAll builds the host policy of every host, keyed by host name.
func BuildAll(m *manifest.Manifest) (map[string]*HostPolicy, error) {
	out := map[string]*HostPolicy{}
	for _, name := range manifest.SortedKeys(m.Hosts) {
		hp, err := BuildHostPolicy(m, name)
		if err != nil {
			return nil, err
		}
		out[name] = hp
	}
	return out, nil
}

// BuildHostPolicy derives the firewall intent for one host.
func BuildHostPolicy(m *manifest.Manifest, name string) (*HostPolicy, error) {
	h, ok := m.Hosts[name]
	if !ok {
		return nil, fmt.Errorf("render: unknown host %q", name)
	}
	hp := &HostPolicy{
		Host: name, Family: h.OS.Family, Workstation: h.IsWorkstation(),
		DefaultIn: Drop, DefaultOut: Drop,
	}
	if hp.Workstation {
		hp.DefaultOut = Accept
	} else {
		hp.DenyLogGroup = m.Policy.DenyLogGroup()
		if !h.IsWindows() {
			hp.SinkholePort = m.Policy.SinkholePort()
		}
	}
	b := &builder{m: m, h: h, name: name, hp: hp}
	b.base()
	b.mgmt()
	b.canary()
	b.dependencies()
	b.egress()
	b.services()
	b.decoys()
	return hp, nil
}

type builder struct {
	m    *manifest.Manifest
	h    manifest.Host
	name string
	hp   *HostPolicy
}

func (b *builder) add(r Rule) { b.hp.Rules = append(b.hp.Rules, r) }

// base: loopback, established, ICMP (v4 and v6), DHCP (v4 and v6). Always
// emitted, in both directions, regardless of policy.yml.
func (b *builder) base() {
	for _, d := range []Direction{In, Out} {
		b.add(Rule{Group: GroupBase, Kind: KindLoopback, Dir: d, Action: Accept, Comment: "loopback"})
		b.add(Rule{Group: GroupBase, Kind: KindEstablished, Dir: d, Action: Accept, Comment: "established and related"})
		b.add(Rule{Group: GroupBase, Kind: KindICMP, Dir: d, Action: Accept, Proto: "icmp", Comment: "ICMP stays (ping is scored; rules require ICMP)"})
		b.add(Rule{Group: GroupBase, Kind: KindICMPv6, Dir: d, Action: Accept, Proto: "icmpv6", Comment: "ICMPv6: neighbour discovery, PMTU, echo"})
	}
	b.add(Rule{Group: GroupBase, Kind: KindDHCP, Dir: Out, Action: Accept, Proto: "udp", LocalPorts: []uint16{68}, RemotePorts: []uint16{67}, Comment: "DHCP client request"})
	b.add(Rule{Group: GroupBase, Kind: KindDHCP, Dir: In, Action: Accept, Proto: "udp", LocalPorts: []uint16{68}, RemotePorts: []uint16{67}, Comment: "DHCP server reply"})
	b.add(Rule{Group: GroupBase, Kind: KindDHCPv6, Dir: Out, Action: Accept, Proto: "udp", LocalPorts: []uint16{546}, RemotePorts: []uint16{547}, Comment: "DHCPv6 client request"})
	b.add(Rule{Group: GroupBase, Kind: KindDHCPv6, Dir: In, Action: Accept, Proto: "udp", LocalPorts: []uint16{546}, RemotePorts: []uint16{547}, Comment: "DHCPv6 server reply"})
}

// mgmt: agent link, relay and device access. These are the management group.
func (b *builder) mgmt() {
	m, name := b.m, b.name
	t := m.Topology
	ctl := m.ControllerHost()

	// Outbound agent link (every host but the controller).
	if name != ctl {
		if peer, port, comment, ok := b.agentLink(name); ok {
			b.add(Rule{Group: GroupMgmt, Kind: KindAgentLink, Dir: Out, Action: Accept, Proto: "tcp",
				RemotePorts: []uint16{port}, Peers: []netip.Prefix{peer.p}, Approx: peer.approx, Comment: comment})
		}
	}

	// Inbound agent streams on the controller.
	if name == ctl {
		var srcs []netip.Prefix
		approx := false
		seen := map[netip.Prefix]bool{}
		addSrc := func(p netip.Prefix, ap bool, why string) {
			if !seen[p] {
				seen[p] = true
				srcs = append(srcs, p)
				approx = approx || ap
			}
		}
		if p, ok := m.SegmentPrefix(b.h.Segment); ok {
			addSrc(p, true, "LAN agents")
		}
		for _, sn := range manifest.SortedKeys(t.Segments) {
			seg := t.Segments[sn]
			if cp := seg.ControllerPath; cp != nil {
				if a, ok := m.TranslatedSource(sn); ok {
					addSrc(netip.PrefixFrom(a, a.BitLen()), false, "translated source of "+cp.AllowFrom)
				}
			}
			// relays whose parent is the controller's segment
			if seg.Relay != "" && m.ParentSegment(sn) == b.h.Segment && sn != b.h.Segment && seg.ControllerPath == nil {
				p, _ := m.HostPrefix(seg.Relay)
				addSrc(p, false, "relay "+seg.Relay)
			}
		}
		sort.Slice(srcs, func(i, j int) bool { return srcs[i].String() < srcs[j].String() })
		b.add(Rule{Group: GroupMgmt, Kind: KindAgentLink, Dir: In, Action: Accept, Proto: "tcp",
			LocalPorts: []uint16{t.Controller.AgentPort}, Peers: srcs, Approx: approx,
			Comment: "agent streams and bootstrap downloads: LAN agents, relays and the Kali's translated source"})
	}

	// Relay: accept from its segment and from child relays; dial the parent (above).
	if b.h.HasRole(manifest.RoleRelay) {
		for _, sn := range manifest.SortedKeys(t.Segments) {
			seg := t.Segments[sn]
			if seg.Relay != name {
				continue
			}
			var srcs []netip.Prefix
			if p, ok := m.SegmentPrefix(sn); ok {
				srcs = append(srcs, p)
			}
			for _, cn := range manifest.SortedKeys(t.Segments) {
				child := t.Segments[cn]
				if child.Relay != "" && child.Relay != name && m.ParentSegment(cn) == sn {
					p, _ := m.HostPrefix(child.Relay)
					srcs = append(srcs, p)
				}
			}
			b.add(Rule{Group: GroupMgmt, Kind: KindRelay, Dir: In, Action: Accept, Proto: "tcp",
				LocalPorts: []uint16{seg.RelayPortOrDefault()}, Peers: srcs,
				Comment: "relay: agents of segment " + sn + " (only the segment's manifest addresses)"})
		}
	}

	// Device access: the controller reaches unproxied devices; a device_proxy
	// reaches the devices it proxies.
	for _, dn := range manifest.SortedKeys(m.Devices) {
		d := m.Devices[dn]
		mgmt, err := netip.ParseAddr(d.Mgmt)
		if err != nil {
			continue
		}
		if (d.Proxy == "" && name == ctl) || (d.Proxy == name) {
			b.add(Rule{Group: GroupMgmt, Kind: KindDevice, Dir: Out, Action: Accept, Proto: "tcp",
				RemotePorts: d.DevicePorts(), Peers: []netip.Prefix{netip.PrefixFrom(mgmt, mgmt.BitLen())},
				Comment: "device management: " + dn + " (" + d.Vendor + ")"})
		}
	}
}

type peer struct {
	p      netip.Prefix
	approx bool
}

// agentLink resolves where host dials to reach the controller.
func (b *builder) agentLink(host string) (peer, uint16, string, bool) {
	m := b.m
	t := m.Topology
	ctl := m.ControllerHost()
	seg := m.Hosts[host].Segment
	// A relay host dials its parent; every other host dials its segment's relay.
	for hops := 0; hops < 16; hops++ {
		if seg == m.ControllerSegment() {
			p, ap := m.HostPrefix(ctl)
			return peer{p, ap}, t.Controller.AgentPort, "agent link to the controller", true
		}
		s := t.Segments[seg]
		if cp := s.ControllerPath; cp != nil {
			a, err := netip.ParseAddr(cp.Public)
			if err != nil {
				return peer{}, 0, "", false
			}
			return peer{netip.PrefixFrom(a, a.BitLen()), false}, cp.Port, "agent link to the controller's public address (static NAT)", true
		}
		if s.Relay == "" {
			return peer{}, 0, "", false
		}
		if s.Relay != host {
			p, ap := m.HostPrefix(s.Relay)
			return peer{p, ap}, s.RelayPortOrDefault(), "agent link to the segment relay " + s.Relay, true
		}
		// The host is this segment's relay: continue with the parent segment.
		seg = m.ParentSegment(seg)
		host = "" // the parent's relay is a different host
	}
	return peer{}, 0, "", false
}

func (b *builder) canary() {
	ports := b.m.Policy.Egress.CanaryPorts
	if len(ports) == 0 {
		return
	}
	if b.h.HasRole(manifest.RoleCanary) {
		// The canary host listens on the canary ports so probes that should be
		// blocked on the way can be recognised when they leak.
		b.add(Rule{Group: GroupCanary, Kind: KindCanary, Dir: In, Action: Accept, Proto: "tcp",
			LocalPorts: sorted(ports), Comment: "egress canary listener: a connection here means egress leaked"})
	}
	for _, kn := range manifest.SortedKeys(b.m.Hosts) {
		k := b.m.Hosts[kn]
		if !k.HasRole(manifest.RoleCanary) || kn == b.name || b.h.HasRole(manifest.RoleCanary) {
			continue
		}
		p, ap := b.m.HostPrefix(kn)
		b.add(Rule{Group: GroupCanary, Kind: KindCanary, Dir: Out, Action: Drop, Proto: "tcp",
			RemotePorts: sorted(ports), Peers: []netip.Prefix{p}, Approx: ap, Log: true, LogGroup: b.m.Policy.DenyLogGroup() + 1,
			Comment: "egress canary to " + kn + ": expected to be blocked, logged separately"})
	}
}

func (b *builder) dependencies() {
	for _, id := range b.m.ServicesOn(b.name) {
		for _, d := range b.m.Services[id].DependsOn {
			p, ap := b.m.HostPrefix(d.To)
			proto := d.Proto
			if proto == "" {
				proto = "tcp"
			}
			b.add(Rule{Group: GroupDependency, Kind: KindDependency, Dir: Out, Action: Accept, Proto: proto,
				RemotePorts: sorted(d.Ports), Peers: []netip.Prefix{p}, Approx: ap, Service: id,
				Comment: fmt.Sprintf("%s: %s -> %s", id, d.Egress, d.To)})
		}
	}
}

func (b *builder) egress() {
	for _, a := range b.m.Policy.Egress.Allow {
		if a.Host != "" && a.Host != b.name {
			continue
		}
		if a.Host == "" && b.h.IsWorkstation() {
			continue // server allowances do not apply to workstations
		}
		var p netip.Prefix
		ap := false
		if _, isHost := b.m.Hosts[a.To]; isHost {
			p, ap = b.m.HostPrefix(a.To)
		} else {
			p, _ = netip.ParsePrefix(a.To)
		}
		proto := a.Proto
		if proto == "" {
			proto = "tcp"
		}
		b.add(Rule{Group: GroupEgress, Kind: KindEgress, Dir: Out, Action: Accept, Proto: proto,
			RemotePorts: sorted(a.Ports), Peers: []netip.Prefix{p}, Approx: ap, Comment: a.Reason})
	}
}

func (b *builder) services() {
	for _, id := range b.m.ServicesOn(b.name) {
		s := b.m.Services[id]
		if !s.IsServiceEnabled() {
			continue // a stopped service needs no listener rule (the lint rejects it when scored)
		}
		byProto := map[string][]uint16{}
		var srcs []netip.Prefix
		restricted := false
		for _, l := range s.Listen {
			byProto[l.Proto] = append(byProto[l.Proto], l.Port)
			if len(l.Sources) > 0 {
				restricted = true
				for _, src := range l.Sources {
					if p, err := netip.ParsePrefix(src); err == nil {
						srcs = append(srcs, p)
					} else if a, err := netip.ParseAddr(src); err == nil {
						srcs = append(srcs, netip.PrefixFrom(a, a.BitLen()))
					}
				}
			}
		}
		for _, proto := range []string{"tcp", "udp"} {
			if ports := byProto[proto]; len(ports) > 0 {
				r := Rule{Group: GroupService, Kind: KindService, Dir: In, Action: Accept, Proto: proto,
					LocalPorts: sorted(ports), Service: id, Comment: fmt.Sprintf("%s (%s)", id, s.Kind)}
				if restricted {
					r.Peers = srcs // only reachable if the manifest says so; the lint rejects it when scored
				}
				b.add(r)
			}
		}
	}
}

func (b *builder) decoys() {
	d, ok := b.m.Decoys[b.name]
	if !ok {
		return
	}
	byPort := map[uint16][]string{}
	for _, l := range d.Listeners {
		byPort[l.Port] = append(byPort[l.Port], l.Kind)
	}
	ports := make([]int, 0, len(byPort))
	for p := range byPort {
		ports = append(ports, int(p))
	}
	sort.Ints(ports)
	for _, p := range ports {
		kinds := byPort[uint16(p)]
		sort.Strings(kinds)
		b.add(Rule{Group: GroupDecoy, Kind: KindDecoy, Dir: In, Action: Accept, Proto: "tcp",
			LocalPorts: []uint16{uint16(p)}, Log: false,
			Comment: fmt.Sprintf("decoy %v (record only)", kinds)})
	}
}

func sorted(p []uint16) []uint16 {
	out := slices.Clone(p)
	slices.Sort(out)
	return slices.Compact(out)
}
