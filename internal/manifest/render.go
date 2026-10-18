package manifest

import (
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/PurdueBlueTeam/phylax/internal/firewall"
)

// NFLogGroup is the nftables nflog group the agent reads denied-egress
// packets from.
const NFLogGroup = 1

// BuildHostPolicy renders the declared host firewall policy for one Linux
// host. The sinkhole catcher is included only when the host runs the
// capture role and is not the controller host (the controller's egress is
// its own management traffic; see design doc § Egress policy).
func (m *Manifest) BuildHostPolicy(hostName string, mode firewall.Mode, sink *firewall.SinkholeCatcher) (*firewall.HostPolicy, error) {
	h, err := m.Host(hostName)
	if err != nil {
		return nil, err
	}
	if h.Windows() {
		return nil, fmt.Errorf("manifest: host %s is windows; host firewall rendering lands in M2 (COM rule groups)", hostName)
	}
	p := &firewall.HostPolicy{Host: hostName, Mode: mode, Table: "phylax"}

	in := &firewall.Chain{Name: "in", Hook: "input", Priority: 0}
	out := &firewall.Chain{Name: "out", Hook: "output", Priority: 0}

	// --- input: management group first, then services, then decoys ---
	in.Rules = append(in.Rules,
		firewall.Rule{Iif: "lo", Verdict: firewall.Accept, Comment: "phylax:lo"},
		firewall.Rule{CT: []string{"established", "related"}, Verdict: firewall.Accept, Comment: "phylax:conntrack"},
	)

	isController := hostName == m.Topology.Controller.Host
	csegName, err := m.SegmentOf(m.Topology.Controller.Host)
	if err != nil {
		return nil, err
	}

	if isController {
		// Agent port: local-segment agents directly, relays of other
		// segments from their NAT public addresses (as seen after
		// translation on palo1).
		src := []string{}
		for _, name := range m.HostNames() {
			oh, _ := m.Host(name)
			if oh.Segment == csegName && name != hostName {
				src = append(src, oh.IP)
			}
		}
		for _, seg := range m.Topology.Segments {
			if seg.NAT != nil {
				src = append(src, seg.NAT.RelayPublic)
			}
		}
		in.Rules = append(in.Rules, firewall.Rule{
			Proto: "tcp", DPorts: []int{m.Topology.Controller.AgentPort},
			Src: src, Verdict: firewall.Accept, Comment: "phylax:agent-in",
		})
	}

	if h.HasRole(RoleRelay) {
		seg, _ := m.SegmentOf(hostName)
		s := m.Topology.Segments[seg]
		src := []string{}
		for _, name := range m.HostNames() {
			oh, _ := m.Host(name)
			if oh.Segment == seg && name != hostName {
				src = append(src, oh.IP)
			}
		}
		in.Rules = append(in.Rules, firewall.Rule{
			Proto: "tcp", DPorts: []int{s.Relay.Port},
			Src: src, Verdict: firewall.Accept, Comment: "phylax:relay-in",
		})
	}

	for _, svcName := range m.ServiceNames() {
		svc := m.Services[svcName]
		if svc.Host != hostName || svc.State == "disabled" {
			continue
		}
		for _, l := range svc.Listen {
			in.Rules = append(in.Rules, firewall.Rule{
				Proto: l.Proto, DPorts: []int{l.Port},
				Verdict: firewall.Accept, Comment: "phylax:svc:" + svcName,
			})
		}
	}

	if hd, ok := m.Decoys[hostName]; ok {
		for _, l := range hd.Listeners {
			in.Rules = append(in.Rules, firewall.Rule{
				Proto: "tcp", DPorts: []int{l.Port},
				Verdict: firewall.Accept, Comment: "phylax:decoy:" + l.Kind,
			})
		}
	}

	// --- output: management, declared dependencies, sinkhole, default ---
	out.Rules = append(out.Rules,
		firewall.Rule{Oif: "lo", Verdict: firewall.Accept, Comment: "phylax:lo"},
		firewall.Rule{CT: []string{"established", "related"}, Verdict: firewall.Accept, Comment: "phylax:conntrack"},
	)

	dest, err := m.AgentDestination(hostName)
	if err != nil {
		return nil, err
	}
	dstIP, _, err := net.SplitHostPort(dest)
	agentPort, err := m.AgentDestinationPort(hostName)
	if err != nil {
		return nil, err
	}
	out.Rules = append(out.Rules, firewall.Rule{
		Proto: "tcp", Dst: []string{dstIP}, DPorts: []int{agentPort},
		Verdict: firewall.Accept, Comment: "phylax:agent",
	})

	for _, svcName := range m.ServiceNames() {
		svc := m.Services[svcName]
		if svc.Host != hostName || svc.State == "disabled" {
			continue
		}
		for _, dep := range svc.Depends {
			if dep.Service != "" {
				t := m.Services[dep.Service]
				th, _ := m.Host(t.Host)
				for _, l := range t.Listen {
					out.Rules = append(out.Rules, firewall.Rule{
						Proto: l.Proto, Dst: []string{th.IP}, DPorts: []int{l.Port},
						Verdict: firewall.Accept, Comment: "phylax:dep:" + svcName,
					})
				}
			}
			if dep.Egress != "" {
				ph, ports := dep.EgressProto()
				toh, _ := m.Host(dep.To)
				out.Rules = append(out.Rules, firewall.Rule{
					Proto: ph, Dst: []string{toh.IP}, DPorts: ports,
					Verdict: firewall.Accept, Comment: "phylax:dep:" + svcName,
				})
			}
		}
	}

	if !isController && h.HasRole(RoleCapture) && sink != nil {
		out.Rules = append(out.Rules, firewall.Rule{
			Proto: "tcp", Verdict: firewall.NFLogRedirect,
			Redirect: net.JoinHostPort(sink.Addr, strconv.Itoa(sink.Port)),
			LogGroup: NFLogGroup, LogPrefix: "phylax-sinkhole: ",
			Comment: "phylax:sinkhole",
		})
	}

	switch mode {
	case firewall.Shadow:
		out.Rules = append(out.Rules, firewall.Rule{
			Verdict: firewall.Log, LogPrefix: "phylax-shadow-drop: ",
			Comment: "phylax:shadow",
		})
	default:
		out.Rules = append(out.Rules, firewall.Rule{
			Verdict: firewall.NFLogDrop,
			LogGroup: NFLogGroup, LogPrefix: "phylax-denied: ",
			Comment: "phylax:default-deny",
		})
	}

	p.Chains = []firewall.Chain{*in, *out}
	return p, nil
}

// AgentDestinationPort is the port the host's agent dials on its one
// outbound management link.
func (m *Manifest) AgentDestinationPort(hostName string) (int, error) {
	seg, err := m.SegmentOf(hostName)
	if err != nil {
		return 0, err
	}
	csegName, err := m.SegmentOf(m.Topology.Controller.Host)
	if err != nil {
		return 0, err
	}
	if seg == csegName {
		return m.Topology.Controller.AgentPort, nil
	}
	s, ok := m.Topology.Segments[seg]
	if !ok || s.Relay == nil {
		return 0, fmt.Errorf("manifest: segment %q has no relay", seg)
	}
	return s.Relay.Port, nil
}

// RenderAllHostPolicies renders every Linux host's policy in stable order.
// Windows hosts are skipped with a note (their rule groups render in M2).
func (m *Manifest) RenderAllHostPolicies(mode firewall.Mode, sink *firewall.SinkholeCatcher) (map[string]string, []string, error) {
	out := map[string]string{}
	skipped := []string{}
	for _, name := range m.HostNames() {
		h := m.Hosts.Hosts[name]
		if h.Windows() {
			skipped = append(skipped, name)
			continue
		}
		p, err := m.BuildHostPolicy(name, mode, sink)
		if err != nil {
			return nil, nil, err
		}
		out[name] = p.RenderNFT()
	}
	sort.Strings(skipped)
	return out, skipped, nil
}
