package manifest

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestParsePortRange(t *testing.T) {
	good := map[string]PortRange{"135": {135, 135}, "49152-65535": {49152, 65535}, " 80 - 90 ": {80, 90}}
	for in, want := range good {
		got, err := ParsePortRange(in)
		if err != nil || got != want {
			t.Errorf("ParsePortRange(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0", "0-10", "10-5", "abc", "1-", "-5", "1-65536", "70000", "1-2-3"} {
		if _, err := ParsePortRange(in); err == nil {
			t.Errorf("ParsePortRange(%q) accepted", in)
		}
	}
	if s := (PortRange{49152, 65535}).String(); s != "49152-65535" {
		t.Errorf("String = %s", s)
	}
	b, _ := (PortRange{1, 2}).MarshalText()
	if string(b) != "1-2" {
		t.Errorf("MarshalText = %s", b)
	}
}

func TestPortsCoverOverlap(t *testing.T) {
	have := Ports{Ports: []uint16{135}, Ranges: []PortRange{{49152, 65535}}}
	if !have.Covers(Ports{Ports: []uint16{135, 50000}, Ranges: []PortRange{{50000, 50100}}}) {
		t.Error("should cover")
	}
	if have.Covers(Ports{Ranges: []PortRange{{40000, 50000}}}) {
		t.Error("partially covered range must not count as covered")
	}
	if have.Covers(Ports{Ports: []uint16{136}}) {
		t.Error("136 not covered")
	}
	if !have.Overlaps(Ports{Ranges: []PortRange{{40000, 49152}}}) || have.Overlaps(Ports{Ports: []uint16{80}}) {
		t.Error("overlap wrong")
	}
}

func TestDomainAllowancesUseDefaultOrPinnedRange(t *testing.T) {
	m := loadRef(t, ref2027)
	has := func(as []DomainAllowance, proto string, port uint16) bool {
		for _, a := range as {
			if a.Proto == proto && (Ports{Ports: a.Ports}).Has(port) {
				return true
			}
		}
		return false
	}
	as := m.DomainAllowances("ad")
	for _, p := range []uint16{53, 88, 135, 389, 445, 464, 636, 3268, 3269} {
		if !has(as, "tcp", p) {
			t.Errorf("tcp/%d missing", p)
		}
	}
	for _, p := range []uint16{53, 88, 123, 389, 464} {
		if !has(as, "udp", p) {
			t.Errorf("udp/%d missing", p)
		}
	}
	if as[0].Ranges[0] != (PortRange{50000, 50199}) {
		t.Errorf("pinned range = %v", as[0].Ranges)
	}
	mutateHost("ad", func(h *Host) { h.RPCRange = "" })(m)
	if got := m.DomainAllowances("ad")[0].Ranges[0]; got != DefaultRPCRange {
		t.Errorf("unpinned range = %v, want %v", got, DefaultRPCRange)
	}
	if got := m.DomainMembers("ad"); strings.Join(got, ",") != "mssql,ubuntu-email,win11-wkst" {
		t.Errorf("members = %v", got)
	}
}

func TestValidateDomainAndRanges(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
		want   string
	}{
		{"member of a non-host", mutateHost("mssql", func(h *Host) { h.DomainMember = "nope" }), "is not a host"},
		{"member of a non-DC", mutateHost("mssql", func(h *Host) { h.DomainMember = "ubuntu-email" }), "domain_controller role"},
		{"member of itself", mutateHost("mssql", func(h *Host) { h.DomainMember = "mssql" }), "the host itself"},
		{"DC that is a member", mutateHost("ad", func(h *Host) { h.DomainMember = "ad" }), "the host itself"},
		{"bad rpc range", mutateHost("ad", func(h *Host) { h.RPCRange = "9-1" }), "rpc_range"},
		{"rpc range below 1024", mutateHost("ad", func(h *Host) { h.RPCRange = "100-2000" }), "below 1024"},
		{"rpc range on a non-DC", mutateHost("mssql", func(h *Host) { h.RPCRange = "50000-50100" }), "only valid on a host with the domain_controller role"},
		{"listener with port and range", mutateSvc("ad-dns", func(s *Service) { s.Listen[0].PortRange = "1000-2000" }), "both port and port_range"},
		{"listener with neither", mutateSvc("ad-dns", func(s *Service) { s.Listen[0].Port = 0 }), "port or port_range is required"},
		{"listener bad range", mutateSvc("ad-dns", func(s *Service) { s.Listen[0].Port = 0; s.Listen[0].PortRange = "x-y" }), "port range"},
		{"listener range covers another listener", mutateSvc("ad-ldap", func(s *Service) { s.Listen = append(s.Listen, Listener{Proto: "tcp", PortRange: "5000-6000"}) }), "is inside the range 5000-6000"},
		{"dependency with no ports", mutateSvc("email-mail", func(s *Service) { s.DependsOn[0].Ports = nil }), "ports or port_ranges are required"},
		{"dependency bad range", mutateSvc("email-mail", func(s *Service) { s.DependsOn[0].PortRanges = []string{"70000"} }), "port range"},
		{"egress allow bad range", func(m *Manifest) {
			m.Policy.Egress.Allow = []EgressAllow{{To: "ad", PortRanges: []string{"5-1"}, Reason: "x"}}
		}, "low port is above high port"},
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

func TestValidateListenerRangeOverlap(t *testing.T) {
	m := loadRef(t, ref2027)
	mutateSvc("ad-ldap", func(s *Service) { s.Listen = []Listener{{Proto: "tcp", PortRange: "300-500"}} })(m)
	mutateSvc("ad-winrm", func(s *Service) { s.Listen = []Listener{{Proto: "tcp", Port: 400}} })(m)
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("a port inside another service's range must be rejected, got %v", err)
	}
}

const rangeYAML = `
topology.yml: |
  team: 1
  controller: { host: c, agent_port: 7443, ui: "127.0.0.1:8443" }
  segments: { lan: { cidr: 10.0.0.0/24 } }
hosts.yml: |
  hosts:
    c:   { segment: lan, ip: 10.0.0.2, os: { family: debian, version: "12" }, roles: [controller] }
    dc:  { segment: lan, ip: 10.0.0.10, os: { family: windows, version: "server-2022" }, roles: [domain_controller], rpc_range: "50000-50100" }
    sql: { segment: lan, ip: 10.0.0.20, os: { family: windows, version: "server-2019" }, domain_member: dc }
services.yml: |
  services:
    rpc:  { host: dc, kind: tcp, listen: [{ proto: tcp, port_range: "50000-50100" }, { proto: tcp, port: 135 }] }
    sql:  { host: sql, kind: mssql, listen: [{ proto: tcp, port: 1433 }], depends_on: [{ egress: rpc, to: dc, ports: [135], port_ranges: ["50000-50100"] }] }
`

func fsFromYAML(t *testing.T, doc string) fstest.MapFS {
	t.Helper()
	// Tiny splitter: "name: |" lines start a file whose body is the indented block.
	files := fstest.MapFS{}
	var name string
	var body []string
	flush := func() {
		if name != "" {
			files[name] = &fstest.MapFile{Data: []byte(strings.Join(body, "\n") + "\n")}
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasSuffix(line, ": |") && !strings.HasPrefix(line, " ") {
			flush()
			name, body = strings.TrimSuffix(line, ": |"), nil
			continue
		}
		body = append(body, strings.TrimPrefix(line, "  "))
	}
	flush()
	return files
}

func TestLoadPortRangesFromYAML(t *testing.T) {
	m, err := Load(fsFromYAML(t, rangeYAML), Options{})
	if err != nil {
		t.Fatal(err)
	}
	l := m.Services["rpc"].Listen[0]
	if l.PortRange != "50000-50100" || l.PortSet().Ranges[0] != (PortRange{50000, 50100}) {
		t.Errorf("listener range = %+v", l)
	}
	d := m.Services["sql"].DependsOn[0]
	if got := d.PortSet(); len(got.Ports) != 1 || got.Ranges[0].Hi != 50100 {
		t.Errorf("dependency ports = %+v", got)
	}
	// A dependency on a range is satisfied by a listener inside it: no NET003.
	for _, f := range Lint(m) {
		if f.ID == RuleDepPort {
			t.Errorf("unexpected %s", f)
		}
	}
}

func TestLoadRejectsBadRangeInYAML(t *testing.T) {
	bad := strings.Replace(rangeYAML, `port_ranges: ["50000-50100"]`, `port_ranges: ["60000-50"]`, 1)
	if _, err := Load(fsFromYAML(t, bad), Options{}); err == nil || !strings.Contains(err.Error(), "low port is above high port") {
		t.Fatalf("err = %v", err)
	}
}

func findingFor(fs []Finding, id, subject string) *Finding {
	for i := range fs {
		if fs[i].ID == id && strings.Contains(fs[i].Subject, subject) {
			return &fs[i]
		}
	}
	return nil
}

func TestLintWindowsHostWithDCNotMember(t *testing.T) {
	m := loadRef(t, ref2027)
	if f := findingFor(Lint(m), RuleDomainMember, ""); f != nil {
		t.Fatalf("reference manifest must not trip AD001: %s", f)
	}
	mutateHost("mssql", func(h *Host) { h.DomainMember = "" })(m)
	f := findingFor(Lint(m), RuleDomainMember, "mssql")
	if f == nil || f.Severity != SevError {
		t.Fatalf("want AD001 error for mssql, got %v", Lint(m))
	}
	if !HasErrors(Lint(m)) {
		t.Error("AD001 must fail the lint")
	}
	// An error cannot be accepted away.
	m.Overrides.AcceptedFindings = []AcceptedFinding{{ID: RuleDomainMember, Subject: "host mssql", Reason: "x"}}
	if !HasErrors(Lint(m)) {
		t.Error("errors cannot be accepted")
	}
}

func TestLintDomainMemberRuleScope(t *testing.T) {
	m := loadRef(t, ref2027)
	mutateHost("mssql", func(h *Host) { h.DomainMember = "" })(m)
	// No scored service using domain auth: nothing to protect, no error.
	for _, id := range m.ServicesOn("mssql") {
		mutateSvc(id, func(s *Service) { s.Scored = false })(m)
	}
	if f := findingFor(Lint(m), RuleDomainMember, "mssql"); f != nil {
		t.Errorf("unscored host must not trip AD001: %s", f)
	}
	// A Linux host in the DC's segment is not covered by the rule.
	m = loadRef(t, ref2027)
	mutateHost("ubuntu-email", func(h *Host) { h.DomainMember = "" })(m)
	if f := findingFor(Lint(m), RuleDomainMember, "ubuntu-email"); f != nil {
		t.Errorf("Linux host: %s", f)
	}
	// A different segment without a DC is not covered.
	m = loadRef(t, ref2027)
	mutateHost("mssql", func(h *Host) { h.DomainMember = ""; h.Segment = "kali_leg"; h.IP = "172.17.0.9"; h.Public = "" })(m)
	if f := findingFor(Lint(m), RuleDomainMember, "mssql"); f != nil {
		t.Errorf("no DC in the segment: %s", f)
	}
}

func TestLintDomainAccountOnHost(t *testing.T) {
	m := loadRef(t, ref2027)
	mutateHost("mssql", func(h *Host) { h.DomainMember = "" })(m)
	for _, id := range m.ServicesOn("mssql") {
		mutateSvc(id, func(s *Service) { s.Scored = false })(m)
	}
	m.Accounts["dba"] = Account{Scope: "domain", Hosts: []string{"mssql"}, Scored: ScoredYes, Rotation: "pcr_transaction", Credlist: "mail"}
	if f := findingFor(Lint(m), RuleDomainMember, "mssql"); f == nil || !strings.Contains(f.Message, "account dba") {
		t.Fatalf("scored domain account on the host must trip AD001, got %v", f)
	}
}

func TestLintRPCPin(t *testing.T) {
	m := loadRef(t, ref2027)
	if f := findingFor(Lint(m), RuleRPCPin, ""); f != nil {
		t.Fatalf("pinned DC must not warn: %s", f)
	}
	mutateHost("ad", func(h *Host) { h.RPCRange = "" })(m)
	f := findingFor(Lint(m), RuleRPCPin, "host ad")
	if f == nil || f.Severity != SevWarn || !strings.Contains(f.Message, "49152-65535") {
		t.Fatalf("want AD002 warning, got %v", f)
	}
	// A DC without members has nothing to pin for.
	for _, n := range []string{"mssql", "ubuntu-email", "win11-wkst"} {
		mutateHost(n, func(h *Host) { h.DomainMember = "" })(m)
	}
	if f := findingFor(Lint(m), RuleRPCPin, ""); f != nil {
		t.Errorf("no members, no warning: %s", f)
	}
}

func TestSchemaHasRangeAndDomainFields(t *testing.T) {
	b, _ := MarshalSchema(Schemas()[FileHosts])
	for _, want := range []string{`"domain_member"`, `"rpc_range"`, `"domain_controller"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("hosts schema missing %s", want)
		}
	}
	b, _ = MarshalSchema(Schemas()[FileServices])
	for _, want := range []string{`"port_range"`, `"port_ranges"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("services schema missing %s", want)
		}
	}
}
