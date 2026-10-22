package render

import (
	"fmt"
	"sort"
	"strings"
)

// WinGroup names for Windows Firewall rule groups. Management is its own
// group so restore and drift detection treat it separately.
var winGroups = map[Group]string{
	GroupBase:       "Phylax Base",
	GroupMgmt:       "Phylax Mgmt",
	GroupService:    "Phylax Service",
	GroupDependency: "Phylax Dependency",
	GroupDecoy:      "Phylax Decoy",
	GroupEgress:     "Phylax Egress",
	GroupCanary:     "Phylax Canary",
}

// WinRule is one Windows Firewall rule intent. It is typed data for the
// agent's COM firewall action (`fw.apply`), not PowerShell.
type WinRule struct {
	Group         string   `json:"group"` // Windows rule group (DisplayGroup)
	Name          string   `json:"name"`  // unique, stable
	Description   string   `json:"description,omitempty"`
	Direction     string   `json:"direction"` // Inbound | Outbound
	Action        string   `json:"action"`    // Allow | Block
	Protocol      string   `json:"protocol"`  // TCP | UDP | ICMPv4 | ICMPv6 | Any
	LocalPorts    []uint16 `json:"local_ports,omitempty"`
	RemotePorts   []uint16 `json:"remote_ports,omitempty"`
	RemoteAddress []string `json:"remote_addresses,omitempty"` // CIDRs; empty means Any
	ICMPTypes     string   `json:"icmp_types,omitempty"`       // "*" for all types and codes
	Profiles      string   `json:"profiles"`                   // Any
	Enabled       bool     `json:"enabled"`
}

// WinPolicy is the Windows Firewall intent for one host.
type WinPolicy struct {
	Host            string    `json:"host"`
	DefaultInbound  string    `json:"default_inbound"`  // Block
	DefaultOutbound string    `json:"default_outbound"` // Block (servers) | Allow (workstations)
	Rules           []WinRule `json:"rules"`
	// DeniedEgressAudit asks for blocked-connection auditing (Security 5157),
	// the Windows denied-egress log (servers only).
	DeniedEgressAudit bool `json:"denied_egress_audit,omitempty"`
}

// WindowsRules converts a host policy to Windows Firewall rule intents.
// Windows has no loopback or established-state rules (the firewall is stateful
// and exempts loopback); Block rules win over Allow rules, which matches the
// canary rules' intent.
func WindowsRules(hp *HostPolicy) (*WinPolicy, error) {
	if hp.Family != "windows" {
		return nil, fmt.Errorf("render: host %s is not Windows", hp.Host)
	}
	wp := &WinPolicy{
		Host: hp.Host, DefaultInbound: "Block", DefaultOutbound: "Block",
		DeniedEgressAudit: !hp.Workstation,
	}
	if hp.DefaultOut == Accept {
		wp.DefaultOutbound = "Allow"
	}
	counts := map[string]int{}
	for _, r := range hp.Rules {
		if r.Kind == KindLoopback || r.Kind == KindEstablished {
			continue
		}
		wr := WinRule{
			Group: winGroups[r.Group], Description: r.Comment, Profiles: "Any", Enabled: true,
			Direction:  map[Direction]string{In: "Inbound", Out: "Outbound"}[r.Dir],
			Action:     map[Action]string{Accept: "Allow", Drop: "Block"}[r.Action],
			LocalPorts: r.LocalPorts, RemotePorts: r.RemotePorts,
		}
		switch r.Proto {
		case "tcp":
			wr.Protocol = "TCP"
		case "udp":
			wr.Protocol = "UDP"
		case "icmp":
			wr.Protocol, wr.ICMPTypes = "ICMPv4", "*"
		case "icmpv6":
			wr.Protocol, wr.ICMPTypes = "ICMPv6", "*"
		default:
			wr.Protocol = "Any"
		}
		for _, p := range r.Peers {
			wr.RemoteAddress = append(wr.RemoteAddress, p.String())
		}
		key := fmt.Sprintf("%s %s %s", wr.Group, strings.ToLower(wr.Direction), r.Kind)
		if r.Service != "" {
			key += " " + r.Service
		}
		counts[key]++
		wr.Name = fmt.Sprintf("%s %d", key, counts[key])
		wp.Rules = append(wp.Rules, wr)
	}
	sort.SliceStable(wp.Rules, func(i, j int) bool { return wp.Rules[i].Group < wp.Rules[j].Group })
	return wp, nil
}
