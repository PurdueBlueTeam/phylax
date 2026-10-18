package manifest

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/firewall"
)

var goldenDir = "testdata/golden"

// TestRenderAllHostPolicies renders every Linux host's policy for the
// reference manifest (enforce mode, sinkhole on port 47443) and compares
// against golden files. Run with PHYLAX_UPDATE_GOLDEN=1 to regenerate.
func TestRenderAllHostPolicies(t *testing.T) {
	m, err := LoadReference(refDir)
	if err != nil {
		t.Fatalf("LoadReference: %v", err)
	}
	sink := &firewall.SinkholeCatcher{Addr: "127.0.0.1", Port: 47443}
	policies, skipped, err := m.RenderAllHostPolicies(firewall.Enforce, sink)
	if err != nil {
		t.Fatalf("RenderAllHostPolicies: %v", err)
	}
	for _, s := range skipped {
		t.Logf("skipped windows host: %s", s)
	}

	update := os.Getenv("PHYLAX_UPDATE_GOLDEN") != ""
	if update {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		got := policies[name]
		path := filepath.Join(goldenDir, name+".nft")
		if update {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("no golden for %s: %v (run with PHYLAX_UPDATE_GOLDEN=1)", name, err)
		}
		if got != string(want) {
			t.Errorf("policy for %s differs from golden:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
		}
	}
}

// TestShadowModeRendersLog verifies shadow mode substitutes log for the
// final drop, so a shadow policy never actually drops.
func TestShadowModeRendersLog(t *testing.T) {
	m, err := LoadReference(refDir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.BuildHostPolicy("ubuntu-ecom", firewall.Shadow, nil)
	if err != nil {
		t.Fatal(err)
	}
	script := p.RenderNFT()
	if strings.Contains(script, "default-deny") || strings.Contains(script, "nflog") {
		t.Error("shadow policy must not drop or nflog anything")
	}
	if !strings.Contains(script, `log prefix "phylax-shadow-drop: " counter accept`) {
		t.Error("shadow policy must log would-be drops")
	}
}

// TestPolicyCoversScoredPorts is the firewall lint's rendering side: every
// service port and every declared egress dependency appears as an accept
// rule in its host's policy.
func TestPolicyCoversScoredPorts(t *testing.T) {
	m, err := LoadReference(refDir)
	if err != nil {
		t.Fatal(err)
	}
	sink := &firewall.SinkholeCatcher{Addr: "127.0.0.1", Port: 47443}
	for _, svcName := range m.ServiceNames() {
		svc := m.Services[svcName]
		h := m.Hosts.Hosts[svc.Host]
		if h.Windows() {
			continue
		}
		p, err := m.BuildHostPolicy(svc.Host, firewall.Enforce, sink)
		if err != nil {
			t.Fatal(err)
		}
		script := p.RenderNFT()
		for _, l := range svc.Listen {
			needle := l.Proto + " dport " + strconv.Itoa(l.Port)
			if !strings.Contains(script, needle) {
				t.Errorf("service %s (%s) port %d not accepted in host policy: missing %q", svcName, svc.Host, l.Port, needle)
			}
		}
		for _, dep := range svc.Depends {
			if dep.Service != "" {
				continue
			}
			to := m.Hosts.Hosts[dep.To]
			ph, ports := dep.EgressProto()
			for _, port := range ports {
				needle := "ip daddr " + to.IP + " meta l4proto " + ph + " " + ph + " dport " + strconv.Itoa(port)
				if !strings.Contains(script, needle) {
					t.Errorf("dependency %s -> %s:%d not accepted in %s policy", svcName, dep.To, port, svc.Host)
				}
			}
		}
	}
}
