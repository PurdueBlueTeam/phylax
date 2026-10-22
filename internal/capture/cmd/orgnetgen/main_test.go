package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/PurdueBlueTeam/phylax/internal/capture"
)

func TestGenerateRoundTripsThroughTheLoader(t *testing.T) {
	d := t.TempDir()
	w := func(name, s string) string {
		p := filepath.Join(d, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	az := w("az.json", `{"values":[{"properties":{"addressPrefixes":["13.70.0.0/16","13.70.0.0/16","2603:1000::/40"]}}]}`)
	aws := w("aws.json", `{"prefixes":[{"ip_prefix":"3.5.0.0/16"}],"ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/32"}]}`)
	do := w("do.txt", "# digitalocean\n138.68.0.0/16\n")
	var out bytes.Buffer
	if err := run(&out, az, "", aws, []string{"digitalocean=cloud:" + do}); err != nil {
		t.Fatal(err)
	}
	nets, err := capture.ParseOrgNets(&out)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := capture.NewHTTPEvents(nets)
	_ = h
	got := map[string]bool{}
	for _, n := range nets {
		got[n.Org] = n.Cloud
		if n.Org == "microsoft" && len(n.CIDRs) != 2 {
			t.Fatalf("microsoft prefixes not de-duplicated: %v", n.CIDRs)
		}
	}
	if len(got) != 3 || got["microsoft"] || !got["aws"] || !got["digitalocean"] {
		t.Fatalf("orgs %v", got)
	}
	if err := run(&out, "", "", "", []string{"x=bogus:y"}); err == nil {
		t.Fatal("bad -list accepted")
	}
	if err := run(&out, w("bad.json", `{"values":[{"properties":{"addressPrefixes":["not a cidr"]}}]}`), "", "", nil); err == nil {
		t.Fatal("bad prefix accepted")
	}
}
