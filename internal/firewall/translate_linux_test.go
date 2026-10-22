//go:build linux

package firewall

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/nftables/expr"

	"github.com/PurdueBlueTeam/phylax/internal/manifest"
	"github.com/PurdueBlueTeam/phylax/internal/manifest/render"
)

func loadRef(t *testing.T, name string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.LoadDir(refs[name], manifest.Options{})
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return m
}

func linuxPolicies(t *testing.T, name string) map[string]*render.HostPolicy {
	t.Helper()
	m := loadRef(t, name)
	out := map[string]*render.HostPolicy{}
	for _, h := range manifest.SortedKeys(m.Hosts) {
		if m.Hosts[h].IsWindows() {
			continue
		}
		hp, err := render.BuildHostPolicy(m, h)
		if err != nil {
			t.Fatal(err)
		}
		out[h] = hp
	}
	return out
}

func dump(rs *Ruleset) string {
	b, err := json.MarshalIndent(rs.normalized(), "", " ")
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

func TestTranslateGolden(t *testing.T) {
	for name := range refs {
		for host, hp := range linuxPolicies(t, name) {
			t.Run(name+"/"+host, func(t *testing.T) {
				rs, err := Translate(hp, TranslateOptions{})
				if err != nil {
					t.Fatal(err)
				}
				again, _ := Translate(hp, TranslateOptions{})
				if dump(rs) != dump(again) {
					t.Fatal("translation is not deterministic")
				}
				if err := managementIntact(rs); err != nil {
					t.Fatalf("management channel: %v", err)
				}
				golden(t, name+"/"+host+".json", dump(rs))
			})
		}
	}
}

// The typed translation must have exactly the rules the reviewed nft text has:
// same tables, same chains, same number of rules per chain.
func TestTranslateMatchesNFTText(t *testing.T) {
	for name := range refs {
		for host, hp := range linuxPolicies(t, name) {
			text, err := render.NFTables(hp)
			if err != nil {
				t.Fatal(err)
			}
			want := countTextRules(text)
			rs, err := Translate(hp, TranslateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]int{}
			for _, tb := range rs.Tables {
				for _, c := range tb.Chains {
					got[tb.Name+"/"+c.Name] = len(c.Rules)
				}
			}
			if len(got) != len(want) {
				t.Errorf("%s/%s: chains %v, text has %v", name, host, got, want)
			}
			for k, n := range want {
				if got[k] != n {
					t.Errorf("%s/%s: chain %s has %d rules, nft text has %d", name, host, k, got[k], n)
				}
			}
		}
	}
}

func countTextRules(text string) map[string]int {
	out := map[string]int{}
	var table, chain string
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "table inet ") && strings.HasSuffix(l, "{"):
			table = strings.Fields(l)[2]
		case strings.HasPrefix(l, "chain ") && strings.HasSuffix(l, "{"):
			chain = strings.Fields(l)[1]
			out[table+"/"+chain] = 0
		case l == "}":
			chain = ""
		case chain != "" && l != "" && !strings.HasPrefix(l, "type "):
			out[table+"/"+chain]++
		}
	}
	return out
}

func TestTranslateRefusesUnmanagedDropPolicy(t *testing.T) {
	hp := &render.HostPolicy{Host: "x", Family: "linux", DefaultIn: render.Drop, DefaultOut: render.Drop}
	if _, err := Translate(hp, TranslateOptions{}); err == nil {
		t.Fatal("default-drop policy without management rules must be refused")
	}
	if _, err := Translate(hp, TranslateOptions{AllowNoManagement: true}); err != nil {
		t.Fatal(err)
	}
	hp.Family = "windows"
	if _, err := Translate(hp, TranslateOptions{AllowNoManagement: true}); err == nil {
		t.Fatal("windows host must be refused")
	}
}

func TestShadowNeverDrops(t *testing.T) {
	for host, hp := range linuxPolicies(t, "2027") {
		rs, err := Translate(hp, TranslateOptions{Mode: ModeShadow})
		if err != nil {
			t.Fatal(err)
		}
		if rs.Table(render.TableNAT) != nil {
			t.Errorf("%s: shadow must not redirect to the sinkhole", host)
		}
		for _, tb := range rs.Tables {
			for _, c := range tb.Chains {
				if c.Policy != nil && *c.Policy != 1 { // 1 = accept
					t.Errorf("%s: shadow chain %s/%s policy %d is not accept", host, tb.Name, c.Name, *c.Policy)
				}
				for _, r := range c.Rules {
					if v, ok := r.Exprs[len(r.Exprs)-1].Any.(*expr.Verdict); ok && v.Kind == expr.VerdictDrop {
						t.Errorf("%s: shadow chain %s/%s still drops: %s", host, tb.Name, c.Name, describeRule(r))
					}
				}
			}
		}
	}
}

func TestPrefixHelpers(t *testing.T) {
	p := netip.MustParsePrefix
	end := func(s string) string {
		b, ok := prefixEnd(p(s))
		if !ok {
			return "top"
		}
		a, _ := netip.AddrFromSlice(b)
		return a.String()
	}
	for in, want := range map[string]string{
		"10.0.0.0/24":      "10.0.1.0",
		"10.0.0.5/32":      "10.0.0.6",
		"10.0.255.0/24":    "10.1.0.0",
		"192.168.0.0/16":   "192.169.0.0",
		"255.255.255.0/24": "top",
		"0.0.0.0/0":        "top",
		"fd00::/64":        "fd00:0:0:1::",
		"2001:db8::1/128":  "2001:db8::2",
		"ffff:ffff::/32":   "top",
	} {
		if got := end(in); got != want {
			t.Errorf("prefixEnd(%s) = %s, want %s", in, got, want)
		}
	}
	got := foldPrefixes([]netip.Prefix{p("10.0.0.5/32"), p("10.0.0.0/24"), p("10.0.0.0/24"), p("10.1.0.0/16"), p("10.0.0.0/8")})
	if len(got) != 1 || got[0] != p("10.0.0.0/8") {
		t.Errorf("foldPrefixes = %v", got)
	}
	got = foldPrefixes([]netip.Prefix{p("10.1.0.0/16"), p("10.0.0.0/24")})
	if len(got) != 2 || got[0] != p("10.0.0.0/24") {
		t.Errorf("foldPrefixes disjoint = %v", got)
	}
}

func TestSnapshotJSONRoundTrip(t *testing.T) {
	for _, hp := range linuxPolicies(t, "2027") {
		rs, err := Translate(hp, TranslateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(&Snapshot{Version: SnapshotVersion, Owned: rs})
		if err != nil {
			t.Fatal(err)
		}
		var back Snapshot
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if d := DiffRulesets(rs, back.Owned); len(d) > 0 {
			t.Fatalf("round trip changed the ruleset: %v", d)
		}
		if rs.Hash() != back.Owned.Hash() {
			t.Fatal("hash changed in round trip")
		}
	}
}

func TestDiffAndHashSeeChanges(t *testing.T) {
	hp := linuxPolicies(t, "2027")
	var any *render.HostPolicy
	for _, h := range hp {
		any = h
		break
	}
	a, _ := Translate(any, TranslateOptions{})
	b, _ := Translate(any, TranslateOptions{})
	if len(DiffRulesets(a, b)) != 0 || a.Hash() != b.Hash() {
		t.Fatal("identical rulesets differ")
	}
	c := b.Table(render.TableMain).Chains[0]
	c.Rules = c.Rules[:len(c.Rules)-1]
	if d := DiffRulesets(a, b); len(d) == 0 {
		t.Fatal("removed rule not reported")
	}
	if a.Hash() == b.Hash() {
		t.Fatal("hash did not change")
	}
	b.Tables = b.Tables[1:]
	found := false
	for _, d := range DiffRulesets(a, b) {
		if strings.Contains(d, "missing") {
			found = true
		}
	}
	if !found {
		t.Fatal("removed table not reported")
	}
}

func TestManagementIntactDetectsDamage(t *testing.T) {
	hp := linuxPolicies(t, "2027")
	var any *render.HostPolicy
	for _, h := range hp {
		any = h
		break
	}
	good, _ := Translate(any, TranslateOptions{})
	if err := managementIntact(good); err != nil {
		t.Fatal(err)
	}
	noMgmt, _ := Translate(any, TranslateOptions{})
	noMgmt.Tables = noMgmt.Tables[1:] // phylax, phylax_nat sort before phylax_mgmt? drop whichever is first
	if noMgmt.Table(render.TableMgmt) == nil {
		if managementIntact(noMgmt) == nil {
			t.Fatal("missing management table not detected")
		}
	}
	bad, _ := Translate(any, TranslateOptions{})
	mn := bad.Table(render.TableMain)
	for _, c := range mn.Chains {
		// remove the mark-accept rule (4th rule)
		c.Rules = append(c.Rules[:3:3], c.Rules[4:]...)
	}
	if managementIntact(bad) == nil {
		t.Fatal("missing mark-accept rule not detected")
	}
}

func pfx(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}
