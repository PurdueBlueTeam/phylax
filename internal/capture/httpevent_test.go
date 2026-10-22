package capture

import (
	"net/netip"
	"testing"
	"time"

	"github.com/PurdueBlueTeam/phylax/internal/detect"
	"github.com/PurdueBlueTeam/phylax/internal/parsers/txn"
)

func httpTxn(server string) txn.Txn {
	t := txn.New(txn.Meta{Client: netip.MustParseAddrPort("10.0.0.5:51000"), Server: netip.MustParseAddrPort(server)}, "http", "exchange", time.Unix(100, 0))
	t.Set("http.method", "GET")
	t.Set("http.host", "download.windowsupdate.com")
	t.Set("http.path", "/c/msdownload/update/others/2016/12/29136388_x.cab")
	t.Set("http.ua", "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.40")
	t.SetInt("http.status", 200)
	t.Set("http.auth_scheme", "basic")
	return t
}

func TestHTTPEventFieldsAndOrgClassification(t *testing.T) {
	h, err := NewHTTPEvents([]OrgNet{
		{Org: "microsoft", CIDRs: []string{"13.64.0.0/11"}},
		{Org: "aws", Cloud: true, CIDRs: []string{"3.0.0.0/9", "2600:1f00::/24"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		server, org string
		cloud       bool
	}{
		{"13.70.1.2:80", "microsoft", false},
		{"3.5.6.7:80", "aws", true},
		{"[2600:1f18::1]:80", "aws", true},
		{"198.51.100.9:80", "", false},
	}
	for _, c := range cases {
		e, ok := h.Event(httpTxn(c.server))
		if !ok || e.Kind != KindHTTPRequest {
			t.Fatalf("%s: %v %v", c.server, ok, e.Kind)
		}
		org, _ := e.Fields["dst_org"].(string)
		cloud, _ := e.Fields["dst_cloud"].(bool)
		if org != c.org || cloud != c.cloud {
			t.Errorf("%s: org=%q cloud=%v", c.server, org, cloud)
		}
		if e.Fields["method"] != "GET" || e.Fields["ua"] == "" || e.Fields["status"] != 200 || e.Fields["dst_port"] != 80 {
			t.Errorf("fields: %v", e.Fields)
		}
		for k := range e.Fields {
			if k == "auth_scheme" || k == "cred" {
				t.Errorf("credential-derived field %s leaked", k)
			}
		}
	}
}

func TestHTTPEventsIgnoresOtherTxnsAndRejectsBadConfig(t *testing.T) {
	h, _ := NewHTTPEvents(nil)
	other := txn.New(txn.Meta{}, "dns", "query", time.Now())
	if _, ok := h.Event(other); ok {
		t.Fatal("dns txn converted")
	}
	if _, err := NewHTTPEvents([]OrgNet{{Org: "x", CIDRs: []string{"nope"}}}); err == nil {
		t.Fatal("bad CIDR accepted")
	}
	if _, err := NewHTTPEvents([]OrgNet{{CIDRs: []string{"10.0.0.0/8"}}}); err == nil {
		t.Fatal("unnamed org accepted")
	}
}

func TestHTTPEventFiresC2ProfileRule(t *testing.T) {
	rs, err := detect.LoadDir("../../rules", detect.LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h, _ := NewHTTPEvents([]OrgNet{{Org: "microsoft", CIDRs: []string{"13.64.0.0/11"}}})
	fire := func(server, host string) bool {
		tx := httpTxn(server)
		tx.Set("http.host", host)
		e, _ := h.Event(tx)
		e.Agent = "ws1"
		for _, a := range detect.NewEngine(rs, detect.Options{}).Process(e) {
			if a.RuleID == "D13d.c2-profile-http" {
				return true
			}
		}
		return false
	}
	if !fire("203.0.113.9:80", "updates.cdn-example.net") {
		t.Fatal("Windows-Update-lookalike to a non-Microsoft host did not fire")
	}
	if fire("13.70.1.2:80", "download.windowsupdate.com") {
		t.Fatal("real Windows Update fired")
	}
}
