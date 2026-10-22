package manifest

import (
	"strings"
	"testing"
)

func TestValidateDecoysSMBAndHoneytokenKinds(t *testing.T) {
	ad := func(d HostDecoys) func(*Manifest) {
		return func(m *Manifest) { m.Decoys["ad"] = d }
	}
	tests := []struct {
		name   string
		mutate func(*Manifest)
		want   string
	}{
		{"smb decoy on a spare port", func(m *Manifest) {
			m.Decoys["mssql"] = HostDecoys{Listeners: []DecoyListener{{Kind: "smb", Port: 4450}}}
		}, ""},
		{"smb decoy on 445", func(m *Manifest) {
			m.Decoys["mssql"] = HostDecoys{Listeners: []DecoyListener{{Kind: "smb", Port: 445}}}
		}, "445"},
		{"unknown listener kind", func(m *Manifest) {
			m.Decoys["mssql"] = HostDecoys{Listeners: []DecoyListener{{Kind: "ftp", Port: 21}}}
		}, "listener.kind"},
		{"unknown token kind", func(m *Manifest) {
			m.Decoys["mssql"] = HostDecoys{Honeytokens: []Honeytoken{{Kind: "lsass_session"}}}
		}, "honeytoken.kind"},
		{"ad token needs a domain", ad(HostDecoys{Honeytokens: []Honeytoken{{Kind: "ad_spn"}}}), "domain"},
		{"ad token on a DC with a domain", ad(HostDecoys{Domain: "corp.example", Honeytokens: []Honeytoken{{Kind: "ad_spn"}, {Kind: "ad_asrep"}, {Kind: "ad_admin"}}}), ""},
		{"ad token on a non-DC", func(m *Manifest) {
			m.Decoys["mssql"] = HostDecoys{Domain: "corp.example", Honeytokens: []Honeytoken{{Kind: "ad_admin"}}}
		}, "domain_controller"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := loadRef(t, ref2027)
			tc.mutate(m)
			err := m.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.want)
			}
		})
	}
}
