package capture

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShippedOrgNetsClassifyDestinations(t *testing.T) {
	h, err := NewHTTPEvents(DefaultOrgNets())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ip    string
		org   string
		cloud bool
	}{
		{"13.107.4.50", "microsoft", false}, {"52.97.1.1", "microsoft", false}, {"3.5.6.7", "aws", true},
		{"138.68.1.1", "digitalocean", true}, {"8.8.8.8", "", false}, {"203.0.113.9", "", false},
	} {
		org, cloud := h.classify(netip.MustParseAddr(c.ip))
		if org != c.org || cloud != c.cloud {
			t.Errorf("%s: %q %v, want %q %v", c.ip, org, cloud, c.org, c.cloud)
		}
	}
}

func TestOrgNetsFileOverridesAndIsValidated(t *testing.T) {
	d := t.TempDir()
	if n, err := LoadOrgNets(filepath.Join(d, "missing.json")); err != nil || len(n) == 0 {
		t.Fatalf("missing file should fall back to the shipped lists: %v", err)
	}
	p := filepath.Join(d, "orgnets.json")
	os.WriteFile(p, []byte(`{"nets":[{"org":"lab","cloud":true,"cidrs":["198.51.100.0/24"]}]}`), 0o600)
	n, err := LoadOrgNets(p)
	if err != nil || len(n) != 1 || n[0].Org != "lab" {
		t.Fatalf("%v %v", n, err)
	}
	for name, body := range map[string]string{
		"bad cidr":      `{"nets":[{"org":"x","cidrs":["999.1.1.1/8"]}]}`,
		"no org":        `{"nets":[{"org":"","cidrs":["10.0.0.0/8"]}]}`,
		"unknown field": `{"nets":[],"surprise":1}`,
		"not json":      `<<<`,
	} {
		os.WriteFile(p, []byte(body), 0o600)
		if _, err := LoadOrgNets(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	var sb strings.Builder
	sb.WriteString(`{"nets":[{"org":"big","cidrs":[`)
	for i := 0; i <= maxOrgCIDRs; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`"10.0.0.0/8"`)
	}
	sb.WriteString(`]}]}`)
	os.WriteFile(p, []byte(sb.String()), 0o600)
	if _, err := LoadOrgNets(p); err == nil {
		t.Error("oversized list accepted")
	}
}
