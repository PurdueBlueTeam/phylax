package render

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

func mustBuild(t *testing.T, m *manifest.Manifest, host string) *HostPolicy {
	t.Helper()
	hp, err := BuildHostPolicy(m, host)
	if err != nil {
		t.Fatal(err)
	}
	return hp
}

func domainRules(hp *HostPolicy, d Direction) []Rule {
	var out []Rule
	for _, r := range hp.Rules {
		if r.Kind == KindDomain && r.Dir == d {
			out = append(out, r)
		}
	}
	return out
}

func TestDomainMemberWindowsRules(t *testing.T) {
	m := loadRef(t, "2027")
	hp := mustBuild(t, m, "mssql")
	wp, err := WindowsRules(hp)
	if err != nil {
		t.Fatal(err)
	}
	var tcp, udp *WinRule
	for i, r := range wp.Rules {
		if r.Group == "Phylax Domain" && r.Direction == "Outbound" {
			if r.Protocol == "TCP" {
				tcp = &wp.Rules[i]
			} else if r.Protocol == "UDP" {
				udp = &wp.Rules[i]
			}
		}
	}
	if tcp == nil || udp == nil {
		t.Fatalf("missing domain outbound rules: %+v", wp.Rules)
	}
	if wp.DefaultOutbound != "Block" {
		t.Fatal("the server must stay default-deny; the domain rules are what let it authenticate")
	}
	for _, p := range []uint16{53, 88, 135, 389, 445, 464, 636, 3268, 3269} {
		if !contains16(tcp.RemotePorts, p) {
			t.Errorf("tcp %d missing", p)
		}
	}
	for _, p := range []uint16{53, 88, 123, 389, 464} {
		if !contains16(udp.RemotePorts, p) {
			t.Errorf("udp %d missing", p)
		}
	}
	if len(tcp.RemoteRanges) != 1 || tcp.RemoteRanges[0].String() != "50000-50199" {
		t.Errorf("pinned RPC range = %v", tcp.RemoteRanges)
	}
	if len(tcp.RemoteAddress) != 1 || tcp.RemoteAddress[0] != "172.20.240.100/32" {
		t.Errorf("must be scoped to the DC, got %v", tcp.RemoteAddress)
	}
	b, _ := json.Marshal(tcp)
	if !strings.Contains(string(b), `"remote_ranges":["50000-50199"]`) {
		t.Errorf("JSON range form: %s", b)
	}
}

func TestDomainUnpinnedUsesDynamicRange(t *testing.T) {
	m := loadRef(t, "2027")
	h := m.Hosts["ad"]
	h.RPCRange = ""
	m.Hosts["ad"] = h
	r := domainRules(mustBuild(t, m, "mssql"), Out)
	if len(r) != 2 || r[0].RemoteRanges[0].String() != "49152-65535" {
		t.Fatalf("rules = %+v", r)
	}
	s, _ := NFTables(mustBuild(t, m, "ubuntu-email"))
	if !strings.Contains(s, "tcp dport { 53, 88, 135, 389, 445, 464, 636, 3268, 3269, 49152-65535 }") {
		t.Errorf("nft range missing:\n%s", s)
	}
}

func TestDomainMemberLinuxNFT(t *testing.T) {
	m := loadRef(t, "2027")
	s, err := NFTables(mustBuild(t, m, "ubuntu-email"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip daddr 172.20.240.100/32 tcp dport { 53, 88, 135, 389, 445, 464, 636, 3268, 3269, 50000-50199 } accept",
		"ip daddr 172.20.240.100/32 udp dport { 53, 88, 123, 389, 464 } accept",
		"ip daddr 172.20.240.100/32 tcp dport { 53, 88, 135, 389, 445, 464, 636, 3268, 3269, 50000-50199 } return", // sinkhole must not redirect it
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func TestDomainControllerAcceptsMembers(t *testing.T) {
	m := loadRef(t, "2027")
	hp := mustBuild(t, m, "ad")
	in := domainRules(hp, In)
	if len(in) != 2 {
		t.Fatalf("DC inbound rules = %d", len(in))
	}
	var peers []string
	for _, p := range in[0].Peers {
		peers = append(peers, p.String())
	}
	got := strings.Join(peers, " ")
	// mssql and ubuntu-email by address, the DHCP workstation by its whole segment.
	for _, want := range []string{"172.20.240.120/32", "172.20.240.15/32", "172.20.240.0/24"} {
		if !strings.Contains(got, want) {
			t.Errorf("peer %s missing from %s", want, got)
		}
	}
	if !in[0].Approx {
		t.Error("a DHCP member makes the peer approximate")
	}
	if len(domainRules(hp, Out)) != 0 {
		t.Error("the DC is not a member of itself")
	}
	// The scored listeners stay open to every source, whatever the domain rules say.
	if fs := CheckHostPolicy(m, hp); len(fs) != 0 {
		t.Errorf("findings: %v", fs)
	}
}

func TestNoDomainRulesWithoutMembership(t *testing.T) {
	m := loadRef(t, "2027")
	for _, n := range []string{"mssql", "ubuntu-email", "win11-wkst"} {
		h := m.Hosts[n]
		h.DomainMember = ""
		m.Hosts[n] = h
	}
	for _, n := range manifest.SortedKeys(m.Hosts) {
		if len(domainRules(mustBuild(t, m, n), Out))+len(domainRules(mustBuild(t, m, n), In)) != 0 {
			t.Errorf("%s: domain rules without membership", n)
		}
	}
}

func TestDomainCrossSegmentPaloAndHosts(t *testing.T) {
	m := loadRef(t, "two-segment")
	pi, err := PaloIntents(m, "palo1")
	if err != nil {
		t.Fatal(err)
	}
	var rule *PaloRule
	deny := -1
	for i, r := range pi.Rules {
		if r.Phase == "domain" {
			rr := r
			rule = &rr
		}
		if r.Name == "phylax-egress-deny-servers" {
			deny = i
		}
	}
	if rule == nil {
		t.Fatalf("no domain rule on the Palo: %+v", pi.Rules)
	}
	if rule.FromZone != "dmz" || rule.ToZone != "corp" || rule.Sources[0].Host != "mail" || rule.Destinations[0].Value != "10.10.1.10/32" {
		t.Errorf("rule = %+v", rule)
	}
	if rule.Action != "allow" {
		t.Error("must allow")
	}
	var tcp ServiceSpec
	for _, s := range rule.Services {
		if s.Proto == "tcp" {
			tcp = s
		}
	}
	if len(tcp.Ranges) != 1 || tcp.Ranges[0].String() != "50000-50199" || !contains16(tcp.Ports, 88) {
		t.Errorf("services = %+v", rule.Services)
	}
	for i, r := range pi.Rules {
		if r.Phase == "domain" && deny >= 0 && i > deny {
			t.Error("the domain allow must precede the egress deny")
		}
	}
	// Both ends are rendered on the hosts.
	if s, _ := NFTables(mustBuild(t, m, "mail")); !strings.Contains(s, "ip daddr 10.10.1.10/32 tcp dport { 53, 88, 135, 389, 445, 464, 636, 3268, 3269, 50000-50199 } accept") {
		t.Errorf("mail:\n%s", s)
	}
	wp, _ := WindowsRules(mustBuild(t, m, "dc"))
	found := false
	for _, r := range wp.Rules {
		if r.Group == "Phylax Domain" && r.Direction == "Inbound" && r.Protocol == "TCP" && len(r.RemoteAddress) == 1 && r.RemoteAddress[0] == "10.10.2.20/32" {
			found = true
		}
	}
	if !found {
		t.Errorf("dc inbound rule from mail missing: %+v", wp.Rules)
	}
	if fs, err := CheckAll(m); err != nil || len(fs) != 0 {
		for _, f := range fs {
			if f.Severity != manifest.SevInfo {
				t.Errorf("finding: %s", f)
			}
		}
	}
}

func TestDomainCrossesVyOS(t *testing.T) {
	m := loadRef(t, "2027")
	// Move the DC behind the VyOS leg: member traffic now crosses a router.
	ad := m.Hosts["ad"]
	ad.Segment, ad.IP, ad.Public = "kali_leg", "172.17.0.50", ""
	m.Hosts["ad"] = ad
	seg := m.Topology.Segments["kali_leg"]
	vi, err := VyOSIntents(m, seg.Firewall)
	if err != nil {
		t.Skipf("no VyOS guarding kali_leg in this layout: %v", err)
	}
	var n int
	for _, r := range vi.Firewall {
		if strings.Contains(r.Description, "domain auth") {
			n++
		}
	}
	if n == 0 {
		t.Errorf("no domain rule on VyOS: %+v", vi.Firewall)
	}
	if fs := CheckVyOS(m, vi); len(fs) != 0 {
		t.Errorf("a domain rule is not a scored-source restriction: %v", fs)
	}
}

func TestPortRangesInDependenciesListenersAndEgress(t *testing.T) {
	m := loadRef(t, "2027")
	s := m.Services["email-mail"]
	s.DependsOn = append(s.DependsOn, manifest.Dependency{Egress: "rpc", To: "ad", Ports: []uint16{135}, PortRanges: []string{"50000-50100"}})
	m.Services["email-mail"] = s
	svc := m.Services["splunk"]
	svc.Listen = append(svc.Listen, manifest.Listener{Proto: "tcp", PortRange: "9000-9010"})
	m.Services["splunk"] = svc
	m.Policy.Egress.Allow = []manifest.EgressAllow{{Host: "rocky-ecom", To: "198.51.100.0/24", PortRanges: []string{"8000-8010"}, Reason: "x"}}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	nft, _ := NFTables(mustBuild(t, m, "ubuntu-email"))
	if !strings.Contains(nft, "tcp dport { 135, 50000-50100 }") {
		t.Errorf("dependency range:\n%s", nft)
	}
	nft, _ = NFTables(mustBuild(t, m, "debian-splunk"))
	if !strings.Contains(nft, "tcp dport { 8000, 8089, 9000-9010 } accept") {
		t.Errorf("listener range:\n%s", nft)
	}
	nft, _ = NFTables(mustBuild(t, m, "rocky-ecom"))
	if !strings.Contains(nft, "ip daddr 198.51.100.0/24 tcp dport 8000-8010 accept") {
		t.Errorf("egress range:\n%s", nft)
	}
	if fs, _ := CheckAll(m); len(fs) != 0 {
		for _, f := range fs {
			if f.Severity != manifest.SevInfo {
				t.Errorf("finding: %s", f)
			}
		}
	}
	// A scored range listener that is not accepted is caught.
	hp := mustBuild(t, m, "debian-splunk")
	for i := range hp.Rules {
		hp.Rules[i].LocalRanges = nil
	}
	svc.Scored = true
	m.Services["splunk"] = svc
	found := false
	for _, f := range CheckHostPolicy(m, hp) {
		found = found || f.ID == RuleScoredPort && strings.Contains(f.Message, "9000-9010")
	}
	if !found {
		t.Error("dropping the range listener must trip FW101")
	}
	pi, _ := PaloIntents(m, "palo1")
	if len(pi.Rules) == 0 {
		t.Fatal("no palo rules")
	}
	b, _ := json.Marshal(pi)
	if !strings.Contains(string(b), `"ranges":["9000-9010"]`) {
		t.Errorf("palo service ranges missing: %s", b)
	}
}

// TestDomainNFTValid runs the domain-bearing rulesets through nft -c where possible.
func TestDomainNFTValid(t *testing.T) {
	chk := newNFTChecker(t)
	if chk.run == nil {
		t.Skipf("SKIPPED: nft -c cannot run here (%s)", chk.reason)
	}
	dir := t.TempDir()
	for _, tc := range []struct{ ref, host string }{{"2027", "ubuntu-email"}, {"two-segment", "mail"}} {
		m := loadRef(t, tc.ref)
		text, err := NFTables(mustBuild(t, m, tc.host))
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, tc.ref+"-"+tc.host+".nft")
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := chk.run(p); err != nil {
			t.Errorf("%s/%s: nft -c: %v\n%s", tc.ref, tc.host, err, out)
		}
	}
}

func contains16(s []uint16, v uint16) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestNFTCommentsStayWithinNftLimit(t *testing.T) {
	r := Rule{Group: GroupEgress, Kind: KindEgress, Dir: Out, Action: Accept, Proto: "tcp", RemotePorts: []uint16{1},
		Comment: strings.Repeat("long reason ", 40)}
	line := ruleLines(r, false)[0]
	i := strings.Index(line, `comment "`)
	if i < 0 {
		t.Fatal("no comment")
	}
	if c := line[i+len(`comment "`) : len(line)-1]; len(c) > 128 || !strings.HasSuffix(c, "...") {
		t.Errorf("comment length %d: %q", len(c), c)
	}
}
