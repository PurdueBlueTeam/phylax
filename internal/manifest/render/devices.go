package render

import (
	"fmt"
	"sort"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

// ManagedTag marks every rule and object phylax creates on a device; adapters
// edit only tagged items (design: "Network devices and credentials").
const ManagedTag = "phylax-managed"

// Commit groups. PAN-OS has no commit-confirm, so management-path edits are
// their own commit, never combined with service rules.
const (
	CommitPolicy     = "policy"
	CommitManagement = "management"
)

// Risk classes for the adapters' safe-change protocol.
const (
	RiskNone    = "none"
	RiskService = "service" // changes a scored path
	RiskLockout = "lockout" // can cut management access
)

// Endpoint is an address that may not be known: a DHCP host resolves to its
// segment CIDR with Approx set, or to nothing at all (Unresolved) when a
// single address is required (a static NAT target).
type Endpoint struct {
	Host       string `json:"host,omitempty"`
	Value      string `json:"value,omitempty"` // address or CIDR
	Approx     bool   `json:"approx,omitempty"`
	Unresolved bool   `json:"unresolved,omitempty"` // fill in by hand (printed checklist)
}

// ServiceSpec is protocol and ports.
type ServiceSpec struct {
	Proto  string               `json:"proto"` // tcp | udp | icmp
	Ports  []uint16             `json:"ports,omitempty"`
	Ranges []manifest.PortRange `json:"ranges,omitempty"` // inclusive port ranges ("lo-hi" in JSON)
}

// ---- Palo Alto ----

// PaloIntent is the desired Palo Alto policy for one firewall: typed data the
// panos adapter turns into XML-API calls.
type PaloIntent struct {
	Device string `json:"device"`
	Tag    string `json:"tag"`
	// Zones: Inside is the zone of the guarded segment(s), Outside the zone toward VyOS.
	InsideZone  string     `json:"inside_zone"`
	OutsideZone string     `json:"outside_zone"`
	Addresses   []PaloAddr `json:"addresses"`
	StaticNAT   []PaloNAT  `json:"static_nat"`
	Rules       []PaloRule `json:"rules"`
	Mgmt        *PaloMgmt  `json:"mgmt_lockdown,omitempty"`
}

// PaloAddr is an address object.
type PaloAddr struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// PaloNAT is a bidirectional static 1:1 NAT: traffic to Original (outside)
// reaches Translated (inside).
type PaloNAT struct {
	Name       string   `json:"name"`
	Original   Endpoint `json:"original"`   // public address (pre-NAT destination)
	Translated Endpoint `json:"translated"` // internal address
	Commit     string   `json:"commit"`
	Comment    string   `json:"comment,omitempty"`
}

// PaloRule is a security rule. For outside-to-inside rules Destination is the
// pre-NAT (public) address, as PAN-OS evaluates it.
type PaloRule struct {
	Name         string        `json:"name"`
	Phase        string        `json:"phase"` // service | decoy | icmp | kali_path | device_access | egress
	FromZone     string        `json:"from_zone"`
	ToZone       string        `json:"to_zone"`
	Sources      []Endpoint    `json:"sources,omitempty"` // empty: any
	Destinations []Endpoint    `json:"destinations,omitempty"`
	Services     []ServiceSpec `json:"services,omitempty"`
	Action       string        `json:"action"` // allow | deny
	LogEnd       bool          `json:"log_end"`
	Commit       string        `json:"commit"`
	Risk         string        `json:"risk"`
	Comment      string        `json:"comment,omitempty"`
}

// PaloMgmt restricts the device's management plane to the controller (first
// hour mitigation: lock Palo management to the controller's address).
type PaloMgmt struct {
	PermittedFrom []Endpoint `json:"permitted_from"`
	Commit        string     `json:"commit"`
	Risk          string     `json:"risk"`
	Additive      bool       `json:"additive"` // add the new permitted entry first, verify, then remove the old
}

// PaloIntents derives the policy for the named PAN-OS device.
func PaloIntents(m *manifest.Manifest, device string) (*PaloIntent, error) {
	d, ok := m.Devices[device]
	if !ok || d.Vendor != "panos" {
		return nil, fmt.Errorf("render: %q is not a PAN-OS device", device)
	}
	pi := &PaloIntent{Device: device, Tag: ManagedTag, OutsideZone: "outside"}
	var guarded []string
	for _, sn := range manifest.SortedKeys(m.Topology.Segments) {
		if m.Topology.Segments[sn].Firewall == device {
			guarded = append(guarded, sn)
		}
	}
	if len(guarded) == 0 {
		return nil, fmt.Errorf("render: no segment is guarded by %s", device)
	}
	pi.InsideZone = guarded[0]
	inGuard := map[string]bool{}
	for _, g := range guarded {
		inGuard[g] = true
	}
	ctl := m.ControllerHost()

	// Static NAT and service/decoy rules per host with a public address.
	for _, hn := range manifest.SortedKeys(m.Hosts) {
		h := m.Hosts[hn]
		if !inGuard[h.Segment] || h.Public == "" {
			continue
		}
		pi.Addresses = append(pi.Addresses, PaloAddr{"phylax-" + hn + "-public", h.Public + "/32"})
		pi.StaticNAT = append(pi.StaticNAT, PaloNAT{
			Name: "phylax-nat-" + hn, Commit: CommitPolicy,
			Original:   Endpoint{Host: hn, Value: h.Public},
			Translated: Endpoint{Host: hn, Value: h.IP},
			Comment:    "static 1:1 NAT, same last octet",
		})
		if svc := serviceSpecs(m, hn); len(svc) > 0 {
			pi.Rules = append(pi.Rules, PaloRule{
				Name: "phylax-svc-" + hn, Phase: "service", FromZone: pi.OutsideZone, ToZone: pi.InsideZone,
				Destinations: []Endpoint{{Host: hn, Value: h.Public}}, Services: svc, Action: "allow", LogEnd: true,
				Commit: CommitPolicy, Risk: RiskService,
				Comment: "scored services: reachable from every source address (no source filtering)",
			})
		}
		if svc := decoySpecs(m, hn); len(svc) > 0 {
			if e := m.Decoys[hn].Exposure; e == "" || e == "public" || e == "both" {
				pi.Rules = append(pi.Rules, PaloRule{
					Name: "phylax-decoy-" + hn, Phase: "decoy", FromZone: pi.OutsideZone, ToZone: pi.InsideZone,
					Destinations: []Endpoint{{Host: hn, Value: h.Public}}, Services: svc, Action: "allow", LogEnd: true,
					Commit: CommitPolicy, Risk: RiskNone, Comment: "decoy listeners (record only), never on scored ports",
				})
			}
		}
	}

	// ICMP is never blocked.
	pi.Rules = append(pi.Rules, PaloRule{
		Name: "phylax-icmp", Phase: "icmp", FromZone: "any", ToZone: "any",
		Services: []ServiceSpec{{Proto: "icmp"}}, Action: "allow", LogEnd: false,
		Commit: CommitPolicy, Risk: RiskService, Comment: "ICMP stays on every device (ping is scored); no zone protection that drops ping",
	})

	// The Kali's path to the controller: static NAT plus one rule that allows
	// only the translated source on the agent port.
	if m.Hosts[ctl].Segment != "" && inGuard[m.Hosts[ctl].Segment] {
		for _, sn := range manifest.SortedKeys(m.Topology.Segments) {
			cp := m.Topology.Segments[sn].ControllerPath
			if cp == nil {
				continue
			}
			ctlEP := controllerEndpoint(m)
			src, hasSrc := m.TranslatedSource(sn)
			srcEP := Endpoint{Host: cp.AllowFrom, Unresolved: true}
			if hasSrc {
				srcEP = Endpoint{Host: cp.AllowFrom, Value: src.String()}
			}
			if ctlEP.Unresolved {
				ctlEP = Endpoint{Host: ctl, Unresolved: true} // a static NAT needs an exact target
			}
			pi.Addresses = append(pi.Addresses, PaloAddr{"phylax-controller-public", cp.Public + "/32"})
			pi.StaticNAT = append(pi.StaticNAT, PaloNAT{
				Name: "phylax-nat-controller-" + sn, Commit: CommitPolicy,
				Original:   Endpoint{Host: ctl, Value: cp.Public},
				Translated: ctlEP,
				Comment:    "controller static NAT for " + sn + "; needs a DHCP reservation",
			})
			pi.Rules = append(pi.Rules, PaloRule{
				Name: "phylax-" + sn + "-to-controller", Phase: "kali_path", FromZone: pi.OutsideZone, ToZone: pi.InsideZone,
				Sources: []Endpoint{srcEP}, Destinations: []Endpoint{{Host: ctl, Value: cp.Public}},
				Services: []ServiceSpec{{Proto: "tcp", Ports: []uint16{cp.Port}}}, Action: "allow", LogEnd: true,
				Commit: CommitPolicy, Risk: RiskService,
				Comment: "agent link from " + cp.AllowFrom + ": only its translated source address, only the agent port",
			})
		}
	}

	// Management of devices reached through this Palo (VyOS) from the controller.
	for _, dn := range manifest.SortedKeys(m.Devices) {
		dv := m.Devices[dn]
		if dv.Via != device {
			continue
		}
		src := controllerEndpoint(m)
		if dv.Proxy != "" {
			p, ap := m.HostPrefix(dv.Proxy)
			src = Endpoint{Host: dv.Proxy, Value: p.String(), Approx: ap}
		}
		pi.Rules = append(pi.Rules, PaloRule{
			Name: "phylax-mgmt-" + dn, Phase: "device_access", FromZone: pi.InsideZone, ToZone: pi.OutsideZone,
			Sources: []Endpoint{src}, Destinations: []Endpoint{{Host: dn, Value: dv.Mgmt}},
			Services: []ServiceSpec{{Proto: "tcp", Ports: dv.DevicePorts()}}, Action: "allow", LogEnd: true,
			Commit: CommitPolicy, Risk: RiskLockout, Comment: "device management of " + dn + " from the controller",
		})
	}

	paloDomain(m, pi, inGuard)

	// Egress: servers are denied to the outside (logged for the 30 s deny pull),
	// except explicit allowances. Workstations have PAT access and are not listed.
	var servers []Endpoint
	for _, hn := range manifest.SortedKeys(m.Hosts) {
		h := m.Hosts[hn]
		if inGuard[h.Segment] && !h.IsWorkstation() {
			p, ap := m.HostPrefix(hn)
			servers = append(servers, Endpoint{Host: hn, Value: p.String(), Approx: ap})
		}
	}
	for i, a := range m.Policy.Egress.Allow {
		if _, isHost := m.Hosts[a.To]; isHost {
			continue // intra-LAN host allowances never cross the Palo
		}
		src := servers
		if a.Host != "" {
			p, ap := m.HostPrefix(a.Host)
			src = []Endpoint{{Host: a.Host, Value: p.String(), Approx: ap}}
		}
		proto := a.Proto
		if proto == "" {
			proto = "tcp"
		}
		pi.Rules = append(pi.Rules, PaloRule{
			Name: fmt.Sprintf("phylax-egress-allow-%d", i+1), Phase: "egress", FromZone: pi.InsideZone, ToZone: pi.OutsideZone,
			Sources: src, Destinations: []Endpoint{{Value: a.To}}, Services: []ServiceSpec{{Proto: proto, Ports: sorted(a.Ports), Ranges: manifest.SortRanges(manifest.MustPortRanges(a.PortRanges))}},
			Action: "allow", LogEnd: true, Commit: CommitPolicy, Risk: RiskService, Comment: a.Reason,
		})
	}
	if len(servers) > 0 {
		pi.Rules = append(pi.Rules, PaloRule{
			Name: "phylax-egress-deny-servers", Phase: "egress", FromZone: pi.InsideZone, ToZone: pi.OutsideZone,
			Sources: servers, Services: []ServiceSpec{{Proto: "any"}}, Action: "deny", LogEnd: true,
			Commit: CommitPolicy, Risk: RiskNone,
			Comment: "network-layer default-deny egress for servers; still holds if a host implant disables the host firewall",
		})
	}

	// Management lockdown: its own commit, additive.
	pi.Mgmt = &PaloMgmt{PermittedFrom: []Endpoint{controllerEndpoint(m)}, Commit: CommitManagement, Risk: RiskLockout, Additive: true}
	return pi, nil
}

func controllerEndpoint(m *manifest.Manifest) Endpoint {
	ctl := m.ControllerHost()
	if a, ok := m.HostAddr(ctl); ok {
		return Endpoint{Host: ctl, Value: a.String()}
	}
	p, _ := m.HostPrefix(ctl)
	return Endpoint{Host: ctl, Value: p.String(), Approx: true, Unresolved: true}
}

// serviceSpecs groups the host's enabled scored listeners by protocol.
func serviceSpecs(m *manifest.Manifest, host string) []ServiceSpec {
	by := map[string]*manifest.Ports{}
	for _, id := range m.ServicesOn(host) {
		s := m.Services[id]
		if !s.Scored || !s.IsServiceEnabled() {
			continue
		}
		for _, l := range s.Listen {
			addPorts(by, l.Proto, l.PortSet())
		}
	}
	return specs(by)
}

func addPorts(by map[string]*manifest.Ports, proto string, ps manifest.Ports) {
	p := by[proto]
	if p == nil {
		p = &manifest.Ports{}
		by[proto] = p
	}
	p.Ports = append(p.Ports, ps.Ports...)
	p.Ranges = append(p.Ranges, ps.Ranges...)
}

func decoySpecs(m *manifest.Manifest, host string) []ServiceSpec {
	by := map[string]*manifest.Ports{}
	for _, l := range m.Decoys[host].Listeners {
		addPorts(by, "tcp", manifest.Ports{Ports: []uint16{l.Port}})
	}
	return specs(by)
}

func specs(by map[string]*manifest.Ports) []ServiceSpec {
	var out []ServiceSpec
	for _, proto := range []string{"tcp", "udp"} {
		if p := by[proto]; p != nil && (len(p.Ports) > 0 || len(p.Ranges) > 0) {
			out = append(out, ServiceSpec{Proto: proto, Ports: sorted(p.Ports), Ranges: manifest.SortRanges(p.Ranges)})
		}
	}
	return out
}

// domainSpecs is the member-to-DC service set as device service specs.
func domainSpecs(m *manifest.Manifest, dc string) []ServiceSpec {
	var out []ServiceSpec
	for _, a := range m.DomainAllowances(dc) {
		out = append(out, ServiceSpec{Proto: a.Proto, Ports: a.Ports, Ranges: manifest.SortRanges(a.Ranges)})
	}
	return out
}

// domainPair is a member and its DC in different segments.
type domainPair struct{ member, dc string }

// crossSegmentDomain lists member/DC pairs whose hosts are in different segments.
func crossSegmentDomain(m *manifest.Manifest) []domainPair {
	var out []domainPair
	for _, hn := range manifest.SortedKeys(m.Hosts) {
		h := m.Hosts[hn]
		if h.DomainMember != "" && m.Hosts[h.DomainMember].Segment != h.Segment {
			out = append(out, domainPair{hn, h.DomainMember})
		}
	}
	return out
}

// paloDomain adds member-to-DC rules for pairs that cross this Palo: both
// segments behind it (zone to zone) or one behind it and one outside (inside
// to outside, or outside to inside with the DC's public address if it has one).
// The rule sits before the egress deny so default-deny never cuts domain auth.
func paloDomain(m *manifest.Manifest, pi *PaloIntent, inGuard map[string]bool) {
	for _, p := range crossSegmentDomain(m) {
		mh, dh := m.Hosts[p.member], m.Hosts[p.dc]
		mIn, dIn := inGuard[mh.Segment], inGuard[dh.Segment]
		if !mIn && !dIn {
			continue
		}
		from, to := mh.Segment, dh.Segment
		switch {
		case mIn && !dIn:
			to = pi.OutsideZone
		case !mIn && dIn:
			from = pi.OutsideZone
		}
		mp, mAp := m.HostPrefix(p.member)
		dp, dAp := m.HostPrefix(p.dc)
		dst := Endpoint{Host: p.dc, Value: dp.String(), Approx: dAp}
		if !mIn && dIn && dh.Public != "" {
			dst = Endpoint{Host: p.dc, Value: dh.Public}
		}
		pi.Rules = append(pi.Rules, PaloRule{
			Name: "phylax-domain-" + p.member + "-to-" + p.dc, Phase: "domain", FromZone: from, ToZone: to,
			Sources: []Endpoint{{Host: p.member, Value: mp.String(), Approx: mAp}}, Destinations: []Endpoint{dst},
			Services: domainSpecs(m, p.dc), Action: "allow", LogEnd: true, Commit: CommitPolicy, Risk: RiskService,
			Comment: "domain auth: " + p.member + " is a member of " + p.dc + " (DNS, Kerberos, LDAP, SMB, RPC, NTP)",
		})
	}
}

// CheckPalo verifies the Palo intent against the scoring rules: scored ports
// open to any source, ICMP allowed, the Kali path restricted as designed.
func CheckPalo(m *manifest.Manifest, pi *PaloIntent) []manifest.Finding {
	var out []manifest.Finding
	subj := "device " + pi.Device
	add := func(id string, sev manifest.Severity, f string, a ...any) {
		out = append(out, manifest.Finding{ID: id, Severity: sev, Subject: subj, Message: fmt.Sprintf(f, a...)})
	}
	for _, r := range pi.Rules {
		if r.Phase == "service" && len(r.Sources) > 0 {
			add(RuleScoredPort, manifest.SevError, "rule %s restricts a scored port by source", r.Name)
		}
	}
	icmp := false
	for _, r := range pi.Rules {
		if r.Phase == "icmp" && r.Action == "allow" {
			icmp = true
		}
	}
	if !icmp {
		add(RuleICMP, manifest.SevError, "no ICMP allow rule")
	}
	for _, n := range pi.StaticNAT {
		if n.Translated.Unresolved {
			add("FW109", manifest.SevInfo, "NAT %s targets %s, whose address is DHCP: fix it by hand from the checklist", n.Name, n.Translated.Host)
		}
	}
	for hn, h := range m.Hosts {
		if h.Public == "" || pi.InsideZone != h.Segment {
			continue
		}
		want := serviceSpecs(m, hn)
		if len(want) == 0 {
			continue
		}
		found := false
		for _, r := range pi.Rules {
			if r.Name == "phylax-svc-"+hn {
				found = true
			}
		}
		if !found {
			add(RuleScoredPort, manifest.SevError, "no service rule for %s", hn)
		}
	}
	return out
}

// ---- VyOS ----

// VyOSIntent is the desired VyOS policy for one router.
type VyOSIntent struct {
	Device    string     `json:"device"`
	Tag       string     `json:"tag"` // description prefix used to find managed items
	SourceNAT []VyOSNAT  `json:"source_nat"`
	Firewall  []VyOSRule `json:"firewall"`
	Mgmt      *VyOSMgmt  `json:"mgmt_access,omitempty"`
}

// VyOSNAT is a source NAT: traffic from Source leaves with the Translation address.
type VyOSNAT struct {
	Rule        int    `json:"rule"`
	Description string `json:"description"`
	FromSegment string `json:"from_segment"`
	Source      string `json:"source"`      // CIDR
	Translation string `json:"translation"` // address
	Risk        string `json:"risk"`
}

// VyOSRule is a forward firewall rule on the routed path.
type VyOSRule struct {
	Rule        int           `json:"rule"`
	Description string        `json:"description"`
	Action      string        `json:"action"` // accept
	Source      []Endpoint    `json:"source,omitempty"`
	Destination []Endpoint    `json:"destination,omitempty"`
	Services    []ServiceSpec `json:"services,omitempty"`
	Risk        string        `json:"risk"`
}

// VyOSMgmt restricts the router's own SSH and HTTPS service to the controller
// (or its device proxy). It is a lockout-class change: it follows the
// soft-revert protocol.
type VyOSMgmt struct {
	PermittedFrom []Endpoint `json:"permitted_from"`
	Ports         []uint16   `json:"ports"`
	Risk          string     `json:"risk"`
}

// VyOSIntents derives the policy for the named VyOS router.
func VyOSIntents(m *manifest.Manifest, device string) (*VyOSIntent, error) {
	d, ok := m.Devices[device]
	if !ok || d.Vendor != "vyos" {
		return nil, fmt.Errorf("render: %q is not a VyOS device", device)
	}
	vi := &VyOSIntent{Device: device, Tag: ManagedTag}
	rule := 100
	next := func() int { rule += 10; return rule }

	hasExt := d.ExternalIP != ""
	for _, sn := range manifest.SortedKeys(m.Topology.Segments) {
		seg := m.Topology.Segments[sn]
		if seg.Firewall != device {
			continue
		}
		if !hasExt {
			continue
		}
		vi.SourceNAT = append(vi.SourceNAT, VyOSNAT{
			Rule: next(), FromSegment: sn, Source: seg.CIDR, Translation: d.ExternalIP,
			Description: ManagedTag + ": source NAT for " + sn, Risk: RiskService,
		})
	}
	rule = 0
	vi.Firewall = append(vi.Firewall, VyOSRule{
		Rule: next(), Action: "accept", Services: []ServiceSpec{{Proto: "icmp"}},
		Description: ManagedTag + ": ICMP stays", Risk: RiskService,
	})
	for _, sn := range manifest.SortedKeys(m.Topology.Segments) {
		seg := m.Topology.Segments[sn]
		cp := seg.ControllerPath
		if cp == nil || seg.Firewall != device {
			continue
		}
		p, ap := m.HostPrefix(cp.AllowFrom)
		src := []Endpoint{{Host: cp.AllowFrom, Value: p.String(), Approx: ap}}
		vi.Firewall = append(vi.Firewall, VyOSRule{
			Rule: next(), Action: "accept", Source: src,
			Destination: []Endpoint{{Host: m.ControllerHost(), Value: cp.Public}},
			Services:    []ServiceSpec{{Proto: "tcp", Ports: []uint16{cp.Port}}},
			Description: ManagedTag + ": agent link from " + cp.AllowFrom + " to the controller's public address", Risk: RiskService,
		})
	}
	// Scored services must stay reachable through the router from every source.
	for _, hn := range manifest.SortedKeys(m.Hosts) {
		h := m.Hosts[hn]
		if h.Public == "" {
			continue
		}
		if svc := serviceSpecs(m, hn); len(svc) > 0 {
			vi.Firewall = append(vi.Firewall, VyOSRule{
				Rule: next(), Action: "accept", Destination: []Endpoint{{Host: hn, Value: h.Public}}, Services: svc,
				Description: ManagedTag + ": scored services of " + hn + " from any source", Risk: RiskService,
			})
		}
	}
	for _, p := range crossSegmentDomain(m) {
		ms, ds := m.Hosts[p.member].Segment, m.Hosts[p.dc].Segment
		if m.Topology.Segments[ms].Firewall != device && m.Topology.Segments[ds].Firewall != device {
			continue
		}
		mp, mAp := m.HostPrefix(p.member)
		dp, dAp := m.HostPrefix(p.dc)
		vi.Firewall = append(vi.Firewall, VyOSRule{
			Rule: next(), Action: "accept",
			Source:      []Endpoint{{Host: p.member, Value: mp.String(), Approx: mAp}},
			Destination: []Endpoint{{Host: p.dc, Value: dp.String(), Approx: dAp}},
			Services:    domainSpecs(m, p.dc),
			Description: ManagedTag + ": domain auth, " + p.member + " to its DC " + p.dc, Risk: RiskService,
		})
	}
	if d.Via != "" || d.Mgmt != "" {
		src := controllerEndpoint(m)
		if d.Proxy != "" {
			p, ap := m.HostPrefix(d.Proxy)
			src = Endpoint{Host: d.Proxy, Value: p.String(), Approx: ap}
		}
		vi.Mgmt = &VyOSMgmt{PermittedFrom: []Endpoint{src}, Ports: d.DevicePorts(), Risk: RiskLockout}
	}
	sort.SliceStable(vi.SourceNAT, func(i, j int) bool { return vi.SourceNAT[i].Rule < vi.SourceNAT[j].Rule })
	return vi, nil
}

// CheckVyOS verifies ICMP and scored reachability on the router.
func CheckVyOS(m *manifest.Manifest, vi *VyOSIntent) []manifest.Finding {
	var out []manifest.Finding
	subj := "device " + vi.Device
	icmp := false
	for _, r := range vi.Firewall {
		if r.Action == "accept" && len(r.Services) == 1 && r.Services[0].Proto == "icmp" && len(r.Source) == 0 {
			icmp = true
		}
		if len(r.Source) > 0 && len(r.Destination) > 0 && r.Destination[0].Host != m.ControllerHost() &&
			m.Hosts[r.Source[0].Host].DomainMember != r.Destination[0].Host {
			out = append(out, manifest.Finding{ID: RuleScoredPort, Severity: manifest.SevError, Subject: subj,
				Message: fmt.Sprintf("rule %d restricts a scored destination by source", r.Rule)})
		}
	}
	if !icmp {
		out = append(out, manifest.Finding{ID: RuleICMP, Severity: manifest.SevError, Subject: subj, Message: "no ICMP accept rule"})
	}
	return out
}
