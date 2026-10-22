package manifest

import (
	"strings"
	"testing"
)

func boolp(b bool) *bool { return &b }
func intp(i int) *int    { return &i }

func mutateSvc(id string, f func(*Service)) func(*Manifest) {
	return func(m *Manifest) {
		s := m.Services[id]
		f(&s)
		m.Services[id] = s
	}
}

func mutateAcct(id string, f func(*Account)) func(*Manifest) {
	return func(m *Manifest) {
		a := m.Accounts[id]
		f(&a)
		m.Accounts[id] = a
	}
}

func mutateHost(id string, f func(*Host)) func(*Manifest) {
	return func(m *Manifest) {
		h := m.Hosts[id]
		f(&h)
		m.Hosts[id] = h
	}
}

func TestLintScoringSafety(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Manifest)
		wantID  string
		wantSev Severity
		subject string // substring of Subject
	}{
		{"scored ssh disabled", mutateSvc("ecom-ssh", func(s *Service) { s.State = "disabled" }), RuleDisabled, SevError, "ecom-ssh"},
		{"scored winrm stopped", mutateSvc("ad-winrm", func(s *Service) { s.State = "stopped" }), RuleDisabled, SevError, "ad-winrm"},
		{"scored rdp disabled", mutateSvc("mssql-rdp", func(s *Service) { s.State = "disabled" }), RuleDisabled, SevError, "mssql-rdp"},
		{"source filter on scored port", mutateSvc("ecom-http", func(s *Service) { s.Listen[0].Sources = []string{"10.0.0.0/8"} }), RuleSourceFilter, SevError, "ecom-http"},
		{"ssh key auth", mutateSvc("ecom-ssh", func(s *Service) { s.Transport.Auth = "key" }), RuleSSH, SevError, "ecom-ssh"},
		{"ssh no pty", mutateSvc("ecom-ssh", func(s *Service) { s.Transport.PTY = boolp(false) }), RuleSSH, SevError, "ecom-ssh"},
		{"ssh no shell", mutateSvc("ecom-ssh", func(s *Service) { s.Transport.Shell = boolp(false) }), RuleSSH, SevError, "ecom-ssh"},
		{"ssh no transport", mutateSvc("ecom-ssh", func(s *Service) { s.Transport = nil }), RuleSSH, SevWarn, "ecom-ssh"},
		{"starttls required", mutateSvc("email-mail", func(s *Service) { s.Transport.StartTLS = "required" }), RuleMail, SevError, "email-mail"},
		{"plaintext refused", mutateSvc("email-mail", func(s *Service) { s.Transport.Plaintext = boolp(false) }), RuleMail, SevError, "email-mail"},
		{"http plaintext refused", mutateSvc("ecom-http", func(s *Service) { s.Transport.Plaintext = boolp(false) }), RuleMail, SevError, "ecom-http"},
		{"winrm required encryption", mutateSvc("ad-winrm", func(s *Service) { s.Transport.Encryption = "required" }), RuleNTLM, SevError, "ad-winrm"},
		{"winrm kerberos only", mutateSvc("ad-winrm", func(s *Service) { s.Transport.Auth = "none" }), RuleNTLM, SevError, "ad-winrm"},
		{"lockout on scored host", mutateHost("rocky-ecom", func(h *Host) { h.Hardening = &Hardening{LockoutPolicy: true} }), RuleLockout, SevError, "rocky-ecom"},
		{"ntlm deny", mutateHost("ad", func(h *Host) { h.Hardening = &Hardening{NTLM: "deny"} }), RuleNTLM, SevError, "host ad"},
		{"lm compat 2", mutateHost("mssql", func(h *Host) { h.Hardening = &Hardening{LMCompatLevel: intp(2)} }), RuleNTLM, SevError, "mssql"},
		{"icmp echo dropped on host", mutateHost("mssql", func(h *Host) { h.Hardening = &Hardening{ICMPEcho: "drop"} }), RuleICMP, SevError, "mssql"},
		{"icmp drop policy", func(m *Manifest) { m.Policy.Firewall.ICMP = "drop" }, RuleICMP, SevError, "policy firewall"},
		{"dhcp drop policy", func(m *Manifest) { m.Policy.Firewall.DHCP = "drop" }, RuleDHCP, SevError, "policy firewall"},
		{"ipv6 drop policy", func(m *Manifest) { m.Policy.Firewall.IPv6 = "drop" }, RuleIPv6, SevError, "policy firewall"},
		{"key-only scored user", mutateAcct("sysadmin@linux", func(a *Account) { a.SSHAuth = "key_only" }), RuleAccountLogin, SevError, "sysadmin@linux"},
		{"nologin scored user", mutateAcct("sysadmin@linux", func(a *Account) { a.Shell = "/usr/sbin/nologin" }), RuleAccountLogin, SevError, "sysadmin@linux"},
		{"rbash protected user", mutateAcct("sysadmin@linux", func(a *Account) { a.Shell = "/bin/rbash" }), RuleAccountLogin, SevError, "sysadmin@linux"},
		{"scored password rotated freely", mutateAcct("mail-users", func(a *Account) { a.Rotation = "free" }), RulePCR, SevError, "mail-users"},
		{"protected sysadmin rotated freely", mutateAcct("sysadmin@linux", func(a *Account) { a.Rotation = "free" }), RulePCR, SevError, "sysadmin@linux"},
		{"scored account without credlist", mutateAcct("mail-users", func(a *Account) { a.Credlist = "" }), RuleCredlist, SevError, "mail-users"},
		{"protected account without credlist", mutateAcct("sysadmin@linux", func(a *Account) { a.Credlist = "" }), RuleCredlist, SevWarn, "sysadmin@linux"},
		{"decoy on scored port", func(m *Manifest) {
			d := m.Decoys["rocky-ecom"]
			d.Listeners = append(d.Listeners, DecoyListener{Kind: "telnet", Port: 22})
			m.Decoys["rocky-ecom"] = d
		}, RuleDecoyPort, SevError, "rocky-ecom"},
		{"decoy ssh on scored ssh host", func(m *Manifest) {
			d := m.Decoys["debian-splunk"]
			d.Listeners = append(d.Listeners, DecoyListener{Kind: "ssh", Port: 22})
			m.Decoys["debian-splunk"] = d
		}, RuleDecoyPort, SevError, "debian-splunk"},
		{"decoy host without role", func(m *Manifest) { m.Decoys["ad"] = HostDecoys{Listeners: []DecoyListener{{Kind: "ssh", Port: 22}}} }, RuleDecoyRole, SevError, "decoys ad"},
		{"wide egress", func(m *Manifest) {
			m.Policy.Egress.Allow = append(m.Policy.Egress.Allow, EgressAllow{To: "0.0.0.0/0", Ports: []uint16{443}, Reason: "x"})
		}, RuleEgressWide, SevError, "egress.allow"},
		{"long patch window", func(m *Manifest) { m.Policy.PatchWindows.MaxMinutes = 240 }, RulePatchWindow, SevWarn, "patch_windows"},
		{"kill scored service response", func(m *Manifest) { m.Policy.Response.Tiers["t2"] = []string{"service.stop"} }, RuleKill, SevError, "t2"},
		{"dependency port nobody listens on", mutateSvc("email-mail", func(s *Service) { s.DependsOn[0].Ports = []uint16{4000} }), RuleDepPort, SevWarn, "email-mail"},
		{"scored service without public address", mutateHost("rocky-ecom", func(h *Host) { h.Public = "" }), RuleNoPublic, SevWarn, "rocky-ecom"},
		{"timeout beyond delay", func(m *Manifest) { m.Scorer.Timeout = &Duration{Duration: 2 * m.Scorer.EffectiveDelay()} }, RuleScorerTime, SevWarn, "scorer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := loadRef(t, ref2027)
			tc.mutate(m)
			var got *Finding
			for _, f := range Lint(m) {
				if f.ID == tc.wantID && strings.Contains(f.Subject, tc.subject) {
					f := f
					got = &f
					break
				}
			}
			if got == nil {
				t.Fatalf("no %s finding for %q; findings: %v", tc.wantID, tc.subject, Lint(m))
			}
			if got.Severity != tc.wantSev {
				t.Errorf("severity = %s, want %s", got.Severity, tc.wantSev)
			}
			if got.Message == "" {
				t.Error("empty message")
			}
		})
	}
}

func TestLintUnscoredIsNotConstrained(t *testing.T) {
	m := loadRef(t, ref2027)
	mutateSvc("ad-ldap", func(s *Service) { s.State = "disabled"; s.Listen[0].Sources = []string{"10.0.0.1"} })(m)
	mutateAcct("ecom-admin", func(a *Account) { a.SSHAuth = "key_only"; a.Shell = "/sbin/nologin" })(m)
	for _, f := range Lint(m) {
		if f.Severity == SevError {
			t.Errorf("unscored changes must not be errors: %s", f)
		}
	}
}

func TestLintAcceptedFindings(t *testing.T) {
	m := loadRef(t, ref2027)
	m.Policy.PatchWindows.MaxMinutes = 240
	has := func(want bool) {
		t.Helper()
		for _, f := range Lint(m) {
			if f.ID == RulePatchWindow {
				if f.Accepted != want {
					t.Fatalf("accepted = %v, want %v", f.Accepted, want)
				}
				return
			}
		}
		t.Fatal("finding missing")
	}
	has(false)
	m.Overrides.AcceptedFindings = append(m.Overrides.AcceptedFindings, AcceptedFinding{ID: RulePatchWindow, Subject: "policy patch_windows", Reason: "inject"})
	has(true)

	// Errors can never be accepted.
	m.Policy.Firewall.ICMP = "drop"
	m.Overrides.AcceptedFindings = append(m.Overrides.AcceptedFindings, AcceptedFinding{ID: RuleICMP, Subject: "policy firewall", Reason: "no"})
	if !HasErrors(Lint(m)) {
		t.Fatal("an accepted error must still fail")
	}
}

func TestLintOrderIsStable(t *testing.T) {
	m := loadRef(t, ref2027)
	mutateSvc("ecom-ssh", func(s *Service) { s.Transport.Auth = "key"; s.State = "disabled" })(m)
	m.Policy.PatchWindows.MaxMinutes = 240
	a, b := Lint(m), Lint(m)
	if len(a) < 3 {
		t.Fatalf("expected several findings, got %v", a)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("lint order is not deterministic")
		}
	}
	for i := 1; i < len(a); i++ {
		if a[i-1].Severity == SevWarn && a[i].Severity == SevError {
			t.Fatal("errors must sort before warnings")
		}
	}
}
