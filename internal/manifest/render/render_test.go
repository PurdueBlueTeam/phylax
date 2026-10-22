package render

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func TestWindowsGolden(t *testing.T) {
	for name := range refs {
		m := loadRef(t, name)
		for _, host := range manifest.SortedKeys(m.Hosts) {
			if !m.Hosts[host].IsWindows() {
				continue
			}
			t.Run(name+"/"+host, func(t *testing.T) {
				hp, _ := BuildHostPolicy(m, host)
				wp, err := WindowsRules(hp)
				if err != nil {
					t.Fatal(err)
				}
				golden(t, name+"/"+host+".winfw.json", asJSON(t, wp))
			})
		}
	}
}

func TestWindowsProperties(t *testing.T) {
	m := loadRef(t, "2027")
	hp, _ := BuildHostPolicy(m, "mssql")
	wp, err := WindowsRules(hp)
	if err != nil {
		t.Fatal(err)
	}
	if wp.DefaultInbound != "Block" || wp.DefaultOutbound != "Block" || !wp.DeniedEgressAudit {
		t.Errorf("server defaults wrong: %+v", wp)
	}
	var icmp4, icmp6, dhcpOut, mgmt, canary, rdp bool
	names := map[string]bool{}
	for _, r := range wp.Rules {
		if names[r.Name] {
			t.Errorf("duplicate rule name %q", r.Name)
		}
		names[r.Name] = true
		switch {
		case r.Protocol == "ICMPv4" && r.Action == "Allow":
			icmp4 = true
		case r.Protocol == "ICMPv6" && r.Action == "Allow":
			icmp6 = true
		case r.Protocol == "UDP" && r.Direction == "Outbound" && len(r.LocalPorts) == 1 && r.LocalPorts[0] == 68:
			dhcpOut = true
		case r.Group == "Phylax Mgmt" && r.Direction == "Outbound" && r.Protocol == "TCP" && r.RemotePorts[0] == 7443:
			mgmt = true
		case r.Group == "Phylax Canary" && r.Action == "Block":
			canary = true
		case r.Direction == "Inbound" && r.Protocol == "TCP" && len(r.LocalPorts) == 1 && r.LocalPorts[0] == 3389 && len(r.RemoteAddress) == 0 && r.Action == "Allow":
			rdp = true
		}
	}
	for what, ok := range map[string]bool{"icmpv4": icmp4, "icmpv6": icmp6, "dhcp out": dhcpOut, "agent link": mgmt, "canary block": canary, "rdp from any": rdp} {
		if !ok {
			t.Errorf("missing %s rule", what)
		}
	}
	// Linux hosts are refused.
	lhp, _ := BuildHostPolicy(m, "rocky-ecom")
	if _, err := WindowsRules(lhp); err == nil {
		t.Error("Linux host accepted by WindowsRules")
	}
	// Workstation: outbound allowed, no audit.
	whp, _ := BuildHostPolicy(m, "win11-wkst")
	ww, _ := WindowsRules(whp)
	if ww.DefaultOutbound != "Allow" || ww.DeniedEgressAudit {
		t.Errorf("workstation defaults wrong: %+v", ww)
	}
}

func TestDeviceIntentsGolden(t *testing.T) {
	for name := range refs {
		m := loadRef(t, name)
		for _, dn := range manifest.SortedKeys(m.Devices) {
			switch m.Devices[dn].Vendor {
			case "panos":
				pi, err := PaloIntents(m, dn)
				if err != nil {
					t.Fatal(err)
				}
				golden(t, name+"/"+dn+".palo.json", asJSON(t, pi))
			case "vyos":
				vi, err := VyOSIntents(m, dn)
				if err != nil {
					t.Fatal(err)
				}
				golden(t, name+"/"+dn+".vyos.json", asJSON(t, vi))
			}
		}
	}
}

func TestPaloIntent2027(t *testing.T) {
	m := loadRef(t, "2027")
	pi, err := PaloIntents(m, "palo1")
	if err != nil {
		t.Fatal(err)
	}
	rule := func(name string) *PaloRule {
		for i := range pi.Rules {
			if pi.Rules[i].Name == name {
				return &pi.Rules[i]
			}
		}
		t.Fatalf("no rule %s", name)
		return nil
	}
	nat := func(name string) *PaloNAT {
		for i := range pi.StaticNAT {
			if pi.StaticNAT[i].Name == name {
				return &pi.StaticNAT[i]
			}
		}
		t.Fatalf("no NAT %s", name)
		return nil
	}
	if n := nat("phylax-nat-ad"); n.Original.Value != "172.25.21.100" || n.Translated.Value != "172.20.240.100" {
		t.Errorf("ad NAT = %+v", n)
	}
	if n := nat("phylax-nat-controller-kali_leg"); n.Original.Value != "172.25.21.30" || !n.Translated.Unresolved || n.Translated.Value != "" {
		t.Errorf("controller NAT must be unresolved (DHCP): %+v", n)
	}
	k := rule("phylax-kali_leg-to-controller")
	if len(k.Sources) != 1 || k.Sources[0].Value != "172.31.21.2" || k.Services[0].Ports[0] != 7443 || k.Destinations[0].Value != "172.25.21.30" {
		t.Errorf("kali path rule = %+v", k)
	}
	if svc := rule("phylax-svc-mssql"); len(svc.Sources) != 0 || svc.Action != "allow" || svc.FromZone != "outside" {
		t.Errorf("scored service rule must allow any source: %+v", svc)
	}
	// Scored ports of the ad host, TCP and UDP split.
	ad := rule("phylax-svc-ad")
	if len(ad.Services) != 2 || ad.Services[0].Proto != "tcp" || ad.Services[1].Proto != "udp" {
		t.Errorf("ad services = %+v", ad.Services)
	}
	if rule("phylax-icmp").Action != "allow" {
		t.Error("ICMP rule missing")
	}
	if r := rule("phylax-egress-deny-servers"); r.Action != "deny" || !r.LogEnd {
		t.Errorf("egress deny: %+v", r)
	}
	for _, r := range pi.Rules {
		if r.Phase == "egress" {
			for _, s := range r.Sources {
				if s.Host == "ubuntu-wkst" || s.Host == "win11-wkst" {
					t.Errorf("workstations must not be in server egress rules: %+v", r)
				}
			}
		}
		if r.Commit == CommitManagement {
			t.Errorf("management commit must not carry service rules: %s", r.Name)
		}
	}
	if pi.Mgmt == nil || pi.Mgmt.Commit != CommitManagement || !pi.Mgmt.Additive || pi.Mgmt.Risk != RiskLockout {
		t.Errorf("management lockdown = %+v", pi.Mgmt)
	}
	if r := rule("phylax-mgmt-vyos1"); r.Risk != RiskLockout || r.Destinations[0].Value != "172.16.0.254" {
		t.Errorf("vyos management rule = %+v", r)
	}
	for _, r := range pi.Rules {
		if strings.HasPrefix(r.Name, "phylax-decoy-") && r.Phase != "decoy" {
			t.Errorf("decoy rule phase: %+v", r)
		}
	}
}

func TestVyOSIntent2027(t *testing.T) {
	m := loadRef(t, "2027")
	vi, err := VyOSIntents(m, "vyos1")
	if err != nil {
		t.Fatal(err)
	}
	if len(vi.SourceNAT) != 1 || vi.SourceNAT[0].Source != "172.17.0.0/24" || vi.SourceNAT[0].Translation != "172.31.21.2" {
		t.Errorf("source NAT = %+v", vi.SourceNAT)
	}
	var kali, icmp bool
	for _, r := range vi.Firewall {
		if len(r.Services) == 1 && r.Services[0].Proto == "icmp" {
			icmp = true
		}
		if len(r.Source) == 1 && r.Source[0].Host == "kali" && r.Destination[0].Value == "172.25.21.30" {
			kali = true
		}
	}
	if !kali || !icmp {
		t.Errorf("firewall rules: kali=%v icmp=%v", kali, icmp)
	}
	if vi.Mgmt == nil || vi.Mgmt.Risk != RiskLockout || vi.Mgmt.PermittedFrom[0].Host != "ubuntu-wkst" {
		t.Errorf("mgmt = %+v", vi.Mgmt)
	}
	if _, err := VyOSIntents(m, "palo1"); err == nil {
		t.Error("palo accepted as VyOS")
	}
	if _, err := PaloIntents(m, "vyos1"); err == nil {
		t.Error("vyos accepted as Palo")
	}
	if _, err := PaloIntents(m, "nope"); err == nil {
		t.Error("unknown device accepted")
	}
}

func TestReferenceManifestsPassFirewallLint(t *testing.T) {
	for name := range refs {
		m := loadRef(t, name)
		fs, err := CheckAll(m)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			if f.Severity != manifest.SevInfo {
				t.Errorf("%s: %s", name, f)
			}
		}
	}
}

func TestCheckHostPolicyCatchesBlockedNeeds(t *testing.T) {
	cut := func(match func(Rule) bool) func(*HostPolicy) {
		return func(hp *HostPolicy) {
			var keep []Rule
			for _, r := range hp.Rules {
				if !match(r) {
					keep = append(keep, r)
				}
			}
			hp.Rules = keep
		}
	}
	tests := []struct {
		name   string
		host   string
		mutate func(*HostPolicy)
		wantID string
	}{
		{"scored port removed", "rocky-ecom", cut(func(r Rule) bool { return r.Service == "ecom-ssh" }), RuleScoredPort},
		{"scored port source-restricted", "rocky-ecom", func(hp *HostPolicy) {
			for i := range hp.Rules {
				if hp.Rules[i].Service == "ecom-http" {
					hp.Rules[i].Peers = hp.Rules[i].Peers[:0:0]
					hp.Rules[i].Peers = append(hp.Rules[i].Peers, mustPrefix("10.0.0.0/8"))
				}
			}
		}, RuleScoredPort},
		{"icmp in removed", "rocky-ecom", cut(func(r Rule) bool { return r.Kind == KindICMP && r.Dir == In }), RuleICMP},
		{"icmp out removed", "rocky-ecom", cut(func(r Rule) bool { return r.Kind == KindICMP && r.Dir == Out }), RuleICMP},
		{"icmpv6 removed", "rocky-ecom", cut(func(r Rule) bool { return r.Kind == KindICMPv6 }), RuleICMPv6},
		{"dhcp removed", "ubuntu-wkst", cut(func(r Rule) bool { return r.Kind == KindDHCP }), RuleDHCPNeed},
		{"dhcpv6 removed", "ubuntu-wkst", cut(func(r Rule) bool { return r.Kind == KindDHCPv6 }), RuleDHCPNeed},
		{"dependency removed", "ubuntu-email", cut(func(r Rule) bool { return r.Kind == KindDependency }), RuleDependency},
		{"agent link removed", "mssql", cut(func(r Rule) bool { return r.Kind == KindAgentLink }), RuleAgentLink},
		{"controller listener removed", "ubuntu-wkst", cut(func(r Rule) bool { return r.Kind == KindAgentLink }), RuleAgentLink},
		{"server default allow", "rocky-ecom", func(hp *HostPolicy) { hp.DefaultOut = Accept }, RuleDefaults},
		{"blind icmp drop", "rocky-ecom", func(hp *HostPolicy) {
			hp.Rules = append(hp.Rules, Rule{Group: GroupBase, Kind: KindICMP, Dir: In, Action: Drop, Proto: "icmp", Comment: "oops"})
		}, RuleBlindDrop},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := loadRef(t, "2027")
			hp, err := BuildHostPolicy(m, tc.host)
			if err != nil {
				t.Fatal(err)
			}
			if fs := CheckHostPolicy(m, hp); len(fs) != 0 {
				t.Fatalf("baseline not clean: %v", fs)
			}
			tc.mutate(hp)
			for _, f := range CheckHostPolicy(m, hp) {
				if f.ID == tc.wantID {
					return
				}
			}
			t.Fatalf("no %s finding after mutation: %v", tc.wantID, CheckHostPolicy(m, hp))
		})
	}
}

func TestEgressAllowAndStoppedService(t *testing.T) {
	m := loadRef(t, "2027")
	m.Policy.Egress.Allow = []manifest.EgressAllow{
		{Host: "rocky-ecom", To: "198.51.100.0/24", Ports: []uint16{443, 80}, Reason: "opencart updates"},
		{To: "debian-splunk", Ports: []uint16{8089}, Reason: "forwarders"},
	}
	hp, _ := BuildHostPolicy(m, "rocky-ecom")
	s, _ := NFTables(hp)
	if !strings.Contains(s, "ip daddr 198.51.100.0/24 tcp dport { 80, 443 } accept") {
		t.Errorf("host-scoped allowance missing:\n%s", s)
	}
	hp, _ = BuildHostPolicy(m, "ubuntu-email")
	s, _ = NFTables(hp)
	if strings.Contains(s, "198.51.100.0/24") || !strings.Contains(s, "ip daddr 172.20.240.20/32 tcp dport 8089 accept") {
		t.Errorf("all-server allowance wrong:\n%s", s)
	}
	hp, _ = BuildHostPolicy(m, "ubuntu-wkst")
	s, _ = NFTables(hp)
	if strings.Contains(s, "8089") {
		t.Error("server allowances must not apply to workstations")
	}
	pi, _ := PaloIntents(m, "palo1")
	var n int
	for _, r := range pi.Rules {
		if r.Phase == "egress" && r.Action == "allow" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("only the outside-bound allowance belongs on the Palo, got %d", n)
	}
}

func TestUnknownHost(t *testing.T) {
	m := loadRef(t, "2027")
	if _, err := BuildHostPolicy(m, "nope"); err == nil {
		t.Error("expected error")
	}
}

func TestNFTCheckerRejectsBadRuleset(t *testing.T) {
	chk := newNFTChecker(t)
	if chk.run == nil {
		t.Skipf("SKIPPED: nft -c cannot run here (%s)", chk.reason)
	}
	p := filepath.Join(t.TempDir(), "bad.nft")
	if err := os.WriteFile(p, []byte("table inet phylax {\n\tchain input { type filter hook input priority 0; policy drop;\n\t\ttcp dport banana accept\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := chk.run(p); err == nil {
		t.Fatalf("the checker accepted a bad ruleset: %s", out)
	}
}

func TestLintAllMergesAndSorts(t *testing.T) {
	m := loadRef(t, "2027")
	m.Policy.PatchWindows.MaxMinutes = 240
	m.Services["ecom-ssh"] = func() manifest.Service { s := m.Services["ecom-ssh"]; s.State = "disabled"; return s }()
	fs, err := LintAll(m)
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.HasErrors(fs) || fs[0].Severity != manifest.SevError {
		t.Fatalf("expected errors first: %v", fs)
	}
}
