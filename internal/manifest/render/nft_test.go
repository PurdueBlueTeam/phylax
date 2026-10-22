package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
)

func linuxHosts(m *manifest.Manifest) []string {
	var out []string
	for _, h := range manifest.SortedKeys(m.Hosts) {
		if !m.Hosts[h].IsWindows() {
			out = append(out, h)
		}
	}
	return out
}

func TestNFTablesGolden(t *testing.T) {
	for name := range refs {
		m := loadRef(t, name)
		for _, host := range linuxHosts(m) {
			t.Run(name+"/"+host, func(t *testing.T) {
				hp, err := BuildHostPolicy(m, host)
				if err != nil {
					t.Fatal(err)
				}
				got, err := NFTables(hp)
				if err != nil {
					t.Fatal(err)
				}
				again, _ := NFTables(hp)
				if got != again {
					t.Fatal("rendering is not deterministic")
				}
				golden(t, name+"/"+host+".nft", got)
			})
		}
	}
}

// TestNFTablesValidWithNft runs every rendered ruleset through `nft -c -f`.
func TestNFTablesValidWithNft(t *testing.T) {
	chk := newNFTChecker(t)
	if chk.run == nil {
		t.Skipf("SKIPPED: nft -c cannot run here (%s). Golden tests still ran; CI must provide privileges.", chk.reason)
	}
	dir := t.TempDir()
	for name := range refs {
		m := loadRef(t, name)
		for _, host := range linuxHosts(m) {
			hp, _ := BuildHostPolicy(m, host)
			text, err := NFTables(hp)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name+"-"+host+".nft")
			if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
			if out, err := chk.run(path); err != nil {
				t.Errorf("nft -c rejected %s/%s: %v\n%s\n%s", name, host, err, out, text)
			}
		}
	}
}

func TestNFTablesRejectsWindows(t *testing.T) {
	m := loadRef(t, "2027")
	hp, _ := BuildHostPolicy(m, "ad")
	if _, err := NFTables(hp); err == nil {
		t.Fatal("expected an error for a Windows host")
	}
}

func TestNFTablesProperties(t *testing.T) {
	m := loadRef(t, "2027")
	get := func(host string) string {
		hp, err := BuildHostPolicy(m, host)
		if err != nil {
			t.Fatal(err)
		}
		s, err := NFTables(hp)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Run("never drops DHCP ICMP or ICMPv6", func(t *testing.T) {
		for _, h := range linuxHosts(m) {
			s := get(h)
			for _, want := range []string{
				"meta l4proto icmp accept", "meta l4proto ipv6-icmp accept",
				"udp sport 67 udp dport 68 accept", "udp sport 68 udp dport 67 accept",
				"udp sport 547 udp dport 546 accept", "udp sport 546 udp dport 547 accept",
			} {
				if !strings.Contains(s, want) {
					t.Errorf("%s: missing %q", h, want)
				}
			}
		}
	})
	t.Run("server egress is default deny with the allowlist", func(t *testing.T) {
		s := get("ubuntu-email")
		if !strings.Contains(s, "hook output priority 0; policy drop;") {
			t.Error("server output must default to drop")
		}
		for _, want := range []string{"ip daddr 172.20.240.100/32 tcp dport 389 accept", "ip daddr 172.20.240.100/32 tcp dport 88 accept", "log group 100 prefix \"phylax-egress-deny: \""} {
			if !strings.Contains(s, want) {
				t.Errorf("missing %q", want)
			}
		}
	})
	t.Run("workstations are not covered by server egress rules", func(t *testing.T) {
		if s := get("ubuntu-wkst"); !strings.Contains(s, "hook output priority 0; policy accept;") || strings.Contains(s, "phylax_nat") {
			t.Error("workstation output must accept and have no sinkhole")
		}
	})
	t.Run("scored ports accept from any source", func(t *testing.T) {
		s := get("rocky-ecom")
		if !strings.Contains(s, "\t\ttcp dport { 80, 443 } accept") || !strings.Contains(s, "\t\ttcp dport 22 accept") {
			t.Errorf("scored ports must have unrestricted accepts:\n%s", s)
		}
	})
	t.Run("sinkhole is a nat chain that spares allowed egress", func(t *testing.T) {
		s := get("ubuntu-email")
		i := strings.Index(s, "table inet phylax_nat {")
		if i < 0 || !strings.Contains(s[i:], "type nat hook output") || !strings.Contains(s[i:], "redirect to :7480") {
			t.Fatal("sinkhole nat chain missing")
		}
		if !strings.Contains(s[i:], "ip daddr 172.20.240.100/32 tcp dport 389 return") {
			t.Error("dependency egress must be excluded from the redirect")
		}
		if strings.Contains(s[:i], "redirect") {
			t.Error("redirect must not live in a filter table")
		}
	})
	t.Run("management has its own table and conntrack mark", func(t *testing.T) {
		s := get("ubuntu-wkst")
		if !strings.Contains(s, "table inet phylax_mgmt {") || !strings.Contains(s, "ct mark set ct mark | 0x7068") || !strings.Contains(s, "ct mark & 0x7068 == 0x7068 accept") {
			t.Error("management table or mark missing")
		}
		if !strings.Contains(s, "ip saddr { 172.20.240.0/24, 172.31.21.2/32 } tcp dport 7443") {
			t.Error("controller must admit the LAN and the Kali's translated source on the agent port")
		}
	})
	t.Run("kali reaches the controller's public address and listens for canaries", func(t *testing.T) {
		s := get("kali")
		if !strings.Contains(s, "ip daddr 172.25.21.30/32 tcp dport 7443 ct state new") || !strings.Contains(s, "tcp dport { 4444, 8888, 9001 } accept") {
			t.Errorf("kali rules wrong:\n%s", s)
		}
	})
	t.Run("relay chain in the two-segment variant", func(t *testing.T) {
		m2 := loadRef(t, "two-segment")
		for host, want := range map[string]string{
			"web":  "ip daddr 10.10.1.50/32 tcp dport 7443", // relay dials the controller
			"mail": "ip daddr 10.10.2.10/32 tcp dport 7444", // agents dial their relay
		} {
			hp, _ := BuildHostPolicy(m2, host)
			s, _ := NFTables(hp)
			if !strings.Contains(s, want) {
				t.Errorf("%s: missing %q", host, want)
			}
		}
		hp, _ := BuildHostPolicy(m2, "web")
		s, _ := NFTables(hp)
		if !strings.Contains(s, "ip saddr 10.10.2.0/24 tcp dport 7444") {
			t.Errorf("relay must accept only from its segment:\n%s", s)
		}
		hp, _ = BuildHostPolicy(m2, "ctl-wkst")
		s, _ = NFTables(hp)
		if !strings.Contains(s, "10.10.2.10/32") {
			t.Errorf("controller must admit the relay's address:\n%s", s)
		}
	})
}
