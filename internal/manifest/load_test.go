package manifest

import (
	"strings"
	"testing"
	"testing/fstest"
)

// Examples live in the repo's manifest/ directory, two levels up.
const (
	ref2027 = "../../manifest/2027"
	refTwo  = "../../manifest/two-segment"
)

func loadRef(t *testing.T, dir string) *Manifest {
	t.Helper()
	m, err := LoadDir(dir, Options{})
	if err != nil {
		t.Fatalf("LoadDir(%s): %v", dir, err)
	}
	return m
}

func TestReferenceManifestsLoadAndLintClean(t *testing.T) {
	for _, dir := range []string{ref2027, refTwo} {
		t.Run(dir, func(t *testing.T) {
			m := loadRef(t, dir)
			for _, f := range Lint(m) {
				if f.Severity != SevInfo && !f.Accepted {
					t.Errorf("unexpected finding: %s", f)
				}
			}
		})
	}
}

func Test2027Values(t *testing.T) {
	m := loadRef(t, ref2027)
	if m.Team != 1 {
		t.Fatalf("team = %d", m.Team)
	}
	if got := m.Topology.Segments["lan"].NAT.PublicPool; got != "172.25.21.0/24" {
		t.Errorf("public pool = %q", got)
	}
	if got := m.Hosts["ad"].Public; got != "172.25.21.100" {
		t.Errorf("ad public = %q", got)
	}
	if got := m.Topology.Segments["kali_leg"].ControllerPath.Public; got != "172.25.21.30" {
		t.Errorf("controller path public = %q", got)
	}
	if m.Scorer.Identifier != "21" {
		t.Errorf("identifier = %q", m.Scorer.Identifier)
	}
	if got := m.Devices["vyos1"].ExternalIP; got != "172.31.21.2" {
		t.Errorf("vyos external = %q", got)
	}
	if !m.Hosts["kali"].HasRole(RoleCanary) || !m.Hosts["ubuntu-wkst"].IsDHCP() {
		t.Error("host roles or DHCP not decoded")
	}
	if m.Accounts["sysadmin@linux"].Scored != ScoredUnknown || !m.Accounts["sysadmin@linux"].Protected() {
		t.Error("sysadmin must be protected")
	}
	if !m.Services["email-mail"].Outbound.IsNone() == false || !m.Services["ecom-http"].Outbound.IsNone() {
		t.Error("outbound none/list decoding wrong")
	}
	if m.Scorer.EffectiveTimeout().Seconds() != 30 {
		t.Errorf("timeout default = %v", m.Scorer.EffectiveTimeout())
	}
}

func TestTeamOverride(t *testing.T) {
	team := 12
	m, err := LoadDir(ref2027, Options{Team: &team})
	if err != nil {
		t.Fatal(err)
	}
	if m.Hosts["ad"].Public != "172.25.32.100" || m.Scorer.Identifier != "32" {
		t.Errorf("override not applied: %q %q", m.Hosts["ad"].Public, m.Scorer.Identifier)
	}
}

func TestEvalExpr(t *testing.T) {
	tests := []struct {
		in   string
		want int
		err  string
	}{
		{" 20 + team ", 21, ""},
		{"team", 1, ""},
		{"team+2-1", 2, ""},
		{"100 - team", 99, ""},
		{"", 0, "empty"},
		{"20 +", 0, "ends with an operator"},
		{"20 * 2", 0, "expected + or -"},
		{"20 team", 0, "expected + or -"},
		{"foo", 0, "unknown token"},
	}
	for _, tc := range tests {
		got, err := evalExpr(tc.in, 1)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%q: err = %v, want %q", tc.in, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q = %d, %v; want %d", tc.in, got, err, tc.want)
		}
	}
	if _, err := expandTemplate("a {{ 1 + ", 1); err == nil {
		t.Error("unterminated template accepted")
	}
}

// miniFS is a tiny valid manifest used as the base for error cases.
func miniFS() fstest.MapFS {
	return fstest.MapFS{
		FileTopology: {Data: []byte(`
team: 3
controller: { host: c, agent_port: 7443, ui: "127.0.0.1:8443" }
segments:
  lan: { cidr: 10.0.0.0/24, nat: { public_pool: "172.25.{{ 20 + team }}.0/24", mode: static_1to1_same_octet } }
`)},
		FileHosts: {Data: []byte(`
hosts:
  c: { segment: lan, ip: 10.0.0.2, public: "172.25.23.2", os: { family: debian, version: "12" }, roles: [controller] }
  w: { segment: lan, ip: 10.0.0.10, public: "172.25.23.10", os: { family: debian, version: "12" } }
`)},
		FileServices: {Data: []byte(`
services:
  w-ssh: { host: w, kind: ssh, scored: true, listen: [{ proto: tcp, port: 22 }], transport: { auth: password, pty: true, shell: true } }
`)},
	}
}

func TestMiniLoads(t *testing.T) {
	if _, err := Load(miniFS(), Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(fstest.MapFS)
		want   string
	}{
		{"unknown key in topology", func(f fstest.MapFS) {
			f[FileTopology].Data = append(f[FileTopology].Data, []byte("bogus: 1\n")...)
		}, "field bogus not found"},
		{"unknown key in service", func(f fstest.MapFS) {
			f[FileServices] = &fstest.MapFile{Data: []byte("services:\n  s: { host: w, kind: ssh, listn: [] }\n")}
		}, "field listn not found"},
		{"missing hosts file", func(f fstest.MapFS) { delete(f, FileHosts) }, "hosts.yml is required"},
		{"missing topology", func(f fstest.MapFS) { delete(f, FileTopology) }, "topology.yml is required"},
		{"missing team", func(f fstest.MapFS) {
			f[FileTopology] = &fstest.MapFile{Data: []byte("controller: {}\n")}
		}, "`team` is required"},
		{"bad template", func(f fstest.MapFS) {
			f[FileHosts] = &fstest.MapFile{Data: []byte("hosts:\n  c: { segment: lan, ip: \"{{ nope }}\", os: { family: debian, version: '1' } }\n")}
		}, "unknown token"},
		{"syntax error", func(f fstest.MapFS) {
			f[FileHosts] = &fstest.MapFile{Data: []byte("hosts: [unclosed\n")}
		}, "hosts.yml"},
		{"unknown host in service", func(f fstest.MapFS) {
			f[FileServices] = &fstest.MapFile{Data: []byte("services:\n  s: { host: nope, kind: ssh, scored: false }\n")}
		}, `host "nope" is not a host`},
		{"bad kind", func(f fstest.MapFS) {
			f[FileServices] = &fstest.MapFile{Data: []byte("services:\n  s: { host: w, kind: gopher, scored: false }\n")}
		}, `kind "gopher" is not one of`},
		{"bad ip", func(f fstest.MapFS) {
			f[FileHosts] = &fstest.MapFile{Data: []byte("hosts:\n  c: { segment: lan, ip: 10.0.9.2, os: { family: debian, version: '1' }, roles: [controller] }\n")}
		}, "outside segment lan"},
		{"duplicate ip", func(f fstest.MapFS) {
			f[FileHosts] = &fstest.MapFile{Data: []byte("hosts:\n  c: { segment: lan, ip: 10.0.0.2, os: { family: debian, version: '1' }, roles: [controller] }\n  w: { segment: lan, ip: 10.0.0.2, os: { family: debian, version: '1' } }\n")}
		}, "is also used by"},
		{"public octet mismatch", func(f fstest.MapFS) {
			f[FileHosts] = &fstest.MapFile{Data: []byte("hosts:\n  c: { segment: lan, ip: 10.0.0.2, public: 172.25.23.99, os: { family: debian, version: '1' }, roles: [controller] }\n")}
		}, "does not keep the last octet"},
		{"public outside pool", func(f fstest.MapFS) {
			f[FileHosts] = &fstest.MapFile{Data: []byte("hosts:\n  c: { segment: lan, ip: 10.0.0.2, public: 172.26.23.2, os: { family: debian, version: '1' }, roles: [controller] }\n")}
		}, "outside the pool"},
		{"no controller role", func(f fstest.MapFS) {
			f[FileHosts] = &fstest.MapFile{Data: []byte("hosts:\n  c: { segment: lan, ip: 10.0.0.2, os: { family: debian, version: '1' } }\n")}
		}, "must have the controller role"},
		{"ui not loopback", func(f fstest.MapFS) {
			f[FileTopology] = &fstest.MapFile{Data: []byte(strings.Replace(string(f[FileTopology].Data), "127.0.0.1:8443", "0.0.0.0:8443", 1))}
		}, "must be a loopback address"},
		{"port clash", func(f fstest.MapFS) {
			f[FileServices] = &fstest.MapFile{Data: []byte("services:\n  a: { host: w, kind: ssh, scored: false, listen: [{ proto: tcp, port: 22 }] }\n  b: { host: w, kind: tcp, scored: false, listen: [{ proto: tcp, port: 22 }] }\n")}
		}, "is already listened on by"},
		{"scored without listener", func(f fstest.MapFS) {
			f[FileServices] = &fstest.MapFile{Data: []byte("services:\n  a: { host: w, kind: ssh, scored: true }\n")}
		}, "needs at least one listener"},
		{"service dependency cycle", func(f fstest.MapFS) {
			f[FileServices] = &fstest.MapFile{Data: []byte(`
services:
  a: { host: w, kind: tcp, scored: false, listen: [{ proto: tcp, port: 1 }], depends_on: [{ egress: x, to: c, ports: [2], service: b }] }
  b: { host: c, kind: tcp, scored: false, listen: [{ proto: tcp, port: 2 }], depends_on: [{ egress: y, to: w, ports: [1], service: a }] }
`)}
		}, "dependency cycle: a -> b -> a"},
		{"unknown credlist", func(f fstest.MapFS) {
			f[FileAccounts] = &fstest.MapFile{Data: []byte("accounts:\n  u: { scope: local, scored: true, credlist: nope, rotation: pcr_transaction }\n")}
		}, `credlist "nope" is not declared`},
		{"bad scored value", func(f fstest.MapFS) {
			f[FileAccounts] = &fstest.MapFile{Data: []byte("accounts:\n  u: { scope: local, scored: maybe, rotation: free }\n")}
		}, "scored must be true, false or unknown"},
		{"bad duration", func(f fstest.MapFS) {
			f[FileScorer] = &fstest.MapFile{Data: []byte("scorer: { engine: quotient, delay: soon }\n")}
		}, "duration"},
		{"unreachable segment", func(f fstest.MapFS) {
			f[FileTopology].Data = append(f[FileTopology].Data, []byte("")...)
			f[FileTopology] = &fstest.MapFile{Data: []byte(strings.Replace(string(f[FileTopology].Data), "segments:\n", "segments:\n  far: { cidr: 10.9.0.0/24 }\n", 1))}
		}, "segment far: cannot reach the controller"},
		{"device in both files", func(f fstest.MapFS) {
			f[FileTopology] = &fstest.MapFile{Data: append(append([]byte(nil), f[FileTopology].Data...), []byte("devices:\n  d: { vendor: vyos, mgmt: 10.0.0.1, segment: lan }\n")...)}
			f[FileDevices] = &fstest.MapFile{Data: []byte("devices:\n  d: { vendor: vyos, mgmt: 10.0.0.1, segment: lan }\n")}
		}, "declared in both"},
		{"decoy on unknown host", func(f fstest.MapFS) {
			f[FileDecoys] = &fstest.MapFile{Data: []byte("decoys:\n  zz: { listeners: [{ kind: ssh, port: 2222 }] }\n")}
		}, "host is not declared"},
		{"dhcp with public", func(f fstest.MapFS) {
			f[FileHosts] = &fstest.MapFile{Data: []byte("hosts:\n  c: { segment: lan, ip: dhcp, public: 172.25.23.2, os: { family: debian, version: '1' }, roles: [controller] }\n")}
		}, "DHCP host cannot have"},
		{"oversize file", func(f fstest.MapFS) {
			f[FilePolicy] = &fstest.MapFile{Data: []byte("# " + strings.Repeat("x", maxFileBytes+10))}
		}, "larger than"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := miniFS()
			// copy file contents so mutations don't alias
			for k, v := range f {
				f[k] = &fstest.MapFile{Data: append([]byte(nil), v.Data...)}
			}
			tc.mutate(f)
			_, err := Load(f, Options{})
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}
