package manifest

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Severity of a lint finding.
type Severity string

// Severities. Errors fail `phylax` plan generation and CI; warnings and info
// may be accepted through overrides.yml (errors may not).
const (
	SevError Severity = "error"
	SevWarn  Severity = "warn"
	SevInfo  Severity = "info"
)

// Finding is one lint result.
type Finding struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Subject  string   `json:"subject"` // e.g. "service ecom-ssh"
	Message  string   `json:"message"`
	Accepted bool     `json:"accepted,omitempty"` // suppressed by overrides.yml
}

func (f Finding) String() string {
	s := fmt.Sprintf("%s %-5s %s: %s", f.ID, f.Severity, f.Subject, f.Message)
	if f.Accepted {
		s += " (accepted)"
	}
	return s
}

// HasErrors reports whether any non-accepted finding is an error.
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == SevError && !f.Accepted {
			return true
		}
	}
	return false
}

// Rule IDs, documented in docs/manifest.md.
const (
	RuleLockout         = "SS001"
	RuleSSH             = "SS002"
	RuleAccountLogin    = "SS003"
	RuleMail            = "SS004"
	RuleSourceFilter    = "SS005"
	RuleICMP            = "SS006"
	RuleNTLM            = "SS007"
	RuleDisabled        = "SS008"
	RulePCR             = "SS009"
	RuleCredlist        = "SS012"
	RuleKill            = "SS013"
	RuleDecoyPort       = "DC001"
	RuleDecoyRole       = "DC002"
	RuleDHCP            = "FW002"
	RuleIPv6            = "FW003"
	RuleEgressWide      = "EG001"
	RulePatchWindow     = "EG002"
	RuleReservation     = "NET001"
	RuleNoPublic        = "NET002"
	RuleDepPort         = "NET003"
	RuleDomainMember    = "AD001"
	RuleRPCPin          = "AD002"
	RuleScorerEst       = "SC001"
	RuleScorerTime      = "SC002"
	RuleOverridesNoHost = "OV001"
)

// RuleIDs lists every manifest lint rule id. The plan lint registry test
// compares it with the plan rules: lint ids are one namespace.
func RuleIDs() []string {
	return []string{
		RuleLockout, RuleSSH, RuleAccountLogin, RuleMail, RuleSourceFilter, RuleICMP, RuleNTLM,
		RuleDisabled, RulePCR, RuleCredlist, RuleKill, RuleDecoyPort, RuleDecoyRole, RuleDHCP,
		RuleIPv6, RuleEgressWide, RulePatchWindow, RuleReservation, RuleNoPublic, RuleDepPort,
		RuleDomainMember, RuleRPCPin, RuleScorerEst, RuleScorerTime, RuleOverridesNoHost,
	}
}

// Lint checks the manifest against the design's scoring-safety rules ("The
// scoring-safety lint"), decoy rules and egress hygiene. The firewall lint on
// rendered policies lives in the render package. The result is sorted.
func Lint(m *Manifest) []Finding {
	l := &linter{m: m}
	l.hosts()
	l.services()
	l.accounts()
	l.decoys()
	l.policy()
	l.network()
	l.domain()
	l.scorer()
	l.overrides()
	return l.finish()
}

type linter struct {
	m  *Manifest
	fs []Finding
}

func (l *linter) add(id string, sev Severity, subject, format string, args ...any) {
	l.fs = append(l.fs, Finding{ID: id, Severity: sev, Subject: subject, Message: fmt.Sprintf(format, args...)})
}

func (l *linter) finish() []Finding {
	accepted := map[string]bool{}
	for _, a := range l.m.Overrides.AcceptedFindings {
		accepted[a.ID+"\x00"+a.Subject] = true
	}
	for i := range l.fs {
		if l.fs[i].Severity != SevError && accepted[l.fs[i].ID+"\x00"+l.fs[i].Subject] {
			l.fs[i].Accepted = true
		}
	}
	SortFindings(l.fs)
	return l.fs
}

// scoredOn reports whether the host carries a scored service or a protected
// account.
func (l *linter) scoredOn(host string) bool {
	for _, s := range l.m.Services {
		if s.Host == host && s.Scored {
			return true
		}
	}
	for _, a := range l.m.Accounts {
		if !a.Protected() {
			continue
		}
		for _, h := range a.Hosts {
			if h == host {
				return true
			}
		}
	}
	return false
}

func (l *linter) hosts() {
	for _, name := range SortedKeys(l.m.Hosts) {
		h := l.m.Hosts[name]
		subj := "host " + name
		hd := h.Hardening
		if hd == nil {
			continue
		}
		scored := l.scoredOn(name)
		if hd.LockoutPolicy && scored {
			l.add(RuleLockout, SevError, subj, "lockout machinery (pam_faillock, fail2ban, sshguard, lockout GPO) on a host with scored services or protected accounts: the scorer's failed logins would lock the scored user")
		}
		if hd.ICMPEcho == "drop" {
			l.add(RuleICMP, SevError, subj, "ICMP echo must stay allowed on every device and host (ping is scored and competition rules require ICMP)")
		}
		if scored {
			if hd.NTLM == "deny" {
				l.add(RuleNTLM, SevError, subj, "NTLM denied on a host with scored services: the scorer authenticates with NTLM")
			}
			if hd.LMCompatLevel != nil && *hd.LMCompatLevel < 3 {
				l.add(RuleNTLM, SevError, subj, "lm_compat_level %d is below 3 for the scored paths", *hd.LMCompatLevel)
			}
			if hd.ProtectedUsers {
				for id, a := range l.m.Accounts {
					if a.Protected() && containsStr(a.Hosts, name) {
						l.add(RuleNTLM, SevError, subj, "Protected Users group enabled while account %s is scored or protected (it disables NTLM for members)", id)
						break
					}
				}
			}
		}
	}
}

func (l *linter) services() {
	for _, id := range SortedKeys(l.m.Services) {
		s := l.m.Services[id]
		subj := "service " + id
		if !s.Scored {
			continue
		}
		if !s.IsServiceEnabled() {
			extra := ""
			switch s.Kind {
			case "ssh", "winrm", "rdp":
				extra = " (" + strings.ToUpper(s.Kind) + " is scored here and is never disabled)"
			}
			l.add(RuleDisabled, SevError, subj, "scored service is declared %s%s: downtime scores zero", s.State, extra)
		}
		for _, ln := range s.Listen {
			if len(ln.Sources) > 0 {
				l.add(RuleSourceFilter, SevError, subj, "%s/%d is restricted to sources %v: scored services must be reachable from all source addresses", ln.Proto, ln.Port, ln.Sources)
			}
		}
		t := s.Transport
		switch s.Kind {
		case "ssh":
			if t == nil {
				l.add(RuleSSH, SevWarn, subj, "scored SSH without a transport block: declare auth, pty and shell as the scorer uses them")
				break
			}
			if t.Auth == "key" || t.Auth == "none" {
				l.add(RuleSSH, SevError, subj, "scored SSH auth %q: the scorer logs in with a password", t.Auth)
			}
			if t.PTY != nil && !*t.PTY {
				l.add(RuleSSH, SevError, subj, "scored SSH with pty disabled (PermitTTY no): the scorer requests a PTY")
			}
			if t.Shell != nil && !*t.Shell {
				l.add(RuleSSH, SevError, subj, "scored SSH with shell disabled (ForceCommand/nologin): the scorer runs a command in a shell")
			}
		case "mail", "smtp", "imap", "pop3":
			if t == nil {
				l.add(RuleMail, SevWarn, subj, "scored mail service without a transport block: declare plaintext and starttls as the scorer uses them")
				break
			}
			if t.StartTLS == "required" {
				l.add(RuleMail, SevError, subj, "STARTTLS required on a scored mail service: the scorer uses plaintext")
			}
			if t.Plaintext != nil && !*t.Plaintext {
				l.add(RuleMail, SevError, subj, "plaintext refused on a scored mail service (disable_plaintext_auth, smtpd_tls_auth_only)")
			}
		}
		if t != nil && t.Encryption == "required" {
			l.add(RuleNTLM, SevError, subj, "required encryption on a scored %s service (SMB encrypt, WinRM AllowUnencrypted=false, FTPS-only, MSSQL ForceEncryption): the scorer cannot do it without a scorer-mimic pass", s.Kind)
		}
		if s.Kind == "winrm" && t != nil && t.Auth != "" && t.Auth != "ntlm" {
			l.add(RuleNTLM, SevError, subj, "scored WinRM auth %q: the scorer uses NTLM", t.Auth)
		}
		if t != nil && t.Plaintext != nil && !*t.Plaintext && (s.Kind == "ftp" || s.Kind == "http") {
			l.add(RuleMail, SevError, subj, "plaintext refused on scored %s: the scorer uses plaintext", s.Kind)
		}
	}
}

func (l *linter) accounts() {
	for _, id := range SortedKeys(l.m.Accounts) {
		a := l.m.Accounts[id]
		subj := "account " + id
		if !a.Protected() {
			continue
		}
		if a.Rotation != "pcr_transaction" {
			l.add(RulePCR, SevError, subj, "scored or protected account with rotation %q: scored passwords change only by PCR transaction", a.Rotation)
		}
		if a.SSHAuth == "key_only" {
			l.add(RuleAccountLogin, SevError, subj, "key-only SSH auth for a scored or protected user: the scorer logs in with a password")
		}
		switch base(a.Shell) {
		case "nologin", "false", "rbash", "sync", "halt":
			l.add(RuleAccountLogin, SevError, subj, "login shell %q for a scored or protected user: the scorer needs a working shell", a.Shell)
		}
		if a.Credlist == "" {
			sev := SevWarn
			if a.Scored == ScoredYes {
				sev = SevError
			}
			l.add(RuleCredlist, sev, subj, "no credlist: PCR transactions need the credlist path")
		}
	}
}

func (l *linter) decoys() {
	for _, host := range SortedKeys(l.m.Decoys) {
		d := l.m.Decoys[host]
		subj := "decoys " + host
		h, ok := l.m.Hosts[host]
		if !ok {
			continue
		}
		if !h.HasRole(RoleDecoys) {
			l.add(RuleDecoyRole, SevError, subj, "decoys declared on a host without the decoys role")
		}
		for _, dl := range d.Listeners {
			for _, id := range l.m.ServicesOn(host) {
				s := l.m.Services[id]
				for _, ln := range s.Listen {
					if ln.Port != dl.Port {
						continue
					}
					sev := SevWarn
					msg := "decoy %s on port %d collides with service %s"
					if s.Scored {
						sev = SevError
						msg = "decoy %s on port %d is on a scored port (service %s): decoys never sit on scored ports"
					}
					l.add(RuleDecoyPort, sev, subj, msg, dl.Kind, dl.Port, id)
				}
			}
		}
	}
}

func (l *linter) policy() {
	p := l.m.Policy
	if p.Firewall.ICMP == "drop" {
		l.add(RuleICMP, SevError, "policy firewall", "icmp: drop is not allowed: ICMP echo stays on every host and device")
	}
	if p.Firewall.DHCP == "drop" {
		l.add(RuleDHCP, SevError, "policy firewall", "dhcp: drop would strand DHCP hosts (the controller and the workstations)")
	}
	if p.Firewall.IPv6 == "drop" {
		l.add(RuleIPv6, SevError, "policy firewall", "ipv6: drop would break neighbour discovery; ICMPv6 must stay allowed")
	}
	for i, a := range p.Egress.Allow {
		subj := fmt.Sprintf("policy egress.allow[%d]", i)
		if pf, err := netip.ParsePrefix(a.To); err == nil && pf.Bits() < 16 {
			l.add(RuleEgressWide, SevError, subj, "allowance to %s is wider than a /16: egress is default-deny with a narrow allowlist", a.To)
		}
	}
	pw := p.PatchWindows
	if pw.MaxMinutes > 60 {
		l.add(RulePatchWindow, SevWarn, "policy patch_windows", "max_minutes %d: patch windows are meant to be short", pw.MaxMinutes)
	}
	if pw.DefaultMinutes > 0 && len(pw.Allowlist) == 0 {
		l.add(RulePatchWindow, SevWarn, "policy patch_windows", "patch windows without an upstream allowlist can only serve the controller's cache")
	}
	for tier, acts := range p.Response.Tiers {
		for _, a := range acts {
			switch a {
			case "service.stop", "service.disable", "kill_service", "service.kill":
				l.add(RuleKill, SevError, "policy response."+tier, "action %q kills a service: never kill a scored service as a response", a)
			}
		}
	}
}

func (l *linter) network() {
	m := l.m
	ctl := m.Hosts[m.ControllerHost()]
	if ctl.IsDHCP() {
		for _, sn := range SortedKeys(m.Topology.Segments) {
			if cp := m.Topology.Segments[sn].ControllerPath; cp != nil {
				l.add(RuleReservation, SevWarn, "host "+m.ControllerHost(), "controller address is DHCP but segment %s maps %s to it by static NAT: request a DHCP reservation", sn, cp.Public)
			}
		}
	}
	for _, name := range SortedKeys(m.Hosts) {
		h := m.Hosts[name]
		if h.HasRole(RoleRelay) && h.IsDHCP() {
			l.add(RuleReservation, SevWarn, "host "+name, "relay host has a DHCP address: the relay allowlist and children need a fixed address")
		}
		if h.Public == "" && h.Class != "workstation" && m.Topology.Segments[h.Segment].NAT != nil {
			for _, id := range m.ServicesOn(name) {
				if m.Services[id].Scored {
					l.add(RuleNoPublic, SevWarn, "host "+name, "scored service %s but no public address: the scorer reaches teams through the public pool", id)
					break
				}
			}
		}
	}
	for _, id := range SortedKeys(m.Services) {
		s := m.Services[id]
		for _, d := range s.DependsOn {
			if !m.hostListensOn(d.To, d.PortSet(), d.Proto) {
				l.add(RuleDepPort, SevWarn, "service "+id, "depends_on %q: no declared service or decoy on %s listens on %v", d.Egress, d.To, d.PortSet().String())
			}
		}
	}
}

func (m *Manifest) hostListensOn(host string, want Ports, proto string) bool {
	if proto == "" {
		proto = "tcp"
	}
	var have Ports
	for _, id := range m.ServicesOn(host) {
		for _, ln := range m.Services[id].Listen {
			if ln.Proto == proto {
				ps := ln.PortSet()
				have.Ports = append(have.Ports, ps.Ports...)
				have.Ranges = append(have.Ranges, ps.Ranges...)
			}
		}
	}
	for _, x := range want.Ports {
		if !have.Has(x) {
			return false
		}
	}
	// A range dependency is satisfied by any listener inside it (the target
	// picks its own port in the range), e.g. dynamic RPC.
	for _, r := range want.Ranges {
		if !have.Overlaps(Ports{Ranges: []PortRange{r}}) {
			return false
		}
	}
	return true
}

// domain: AD001 a Windows host sharing a segment with a DC but not declared a
// domain member while scored services use domain accounts (it would lose
// Kerberos, LDAP, SYSVOL and Netlogon once egress is default-deny); AD002 a DC
// with members that does not pin its RPC dynamic range.
func (l *linter) domain() {
	m := l.m
	for _, name := range SortedKeys(m.Hosts) {
		h := m.Hosts[name]
		if h.IsDomainController() {
			if len(m.DomainMembers(name)) > 0 && h.RPCRange == "" {
				l.add(RuleRPCPin, SevWarn, "host "+name, "domain controller does not pin its dynamic RPC range (rpc_range): members are allowed %s, which is wide; pin the range on the DC and declare it", DefaultRPCRange)
			}
			continue
		}
		if !h.IsWindows() || h.DomainMember != "" {
			continue
		}
		var dc string
		for _, d := range SortedKeys(m.Hosts) {
			if dh := m.Hosts[d]; d != name && dh.IsDomainController() && dh.Segment == h.Segment {
				dc = d
				break
			}
		}
		if dc == "" {
			continue
		}
		if id := l.domainScored(name); id != "" {
			l.add(RuleDomainMember, SevError, "host "+name, "Windows host in segment %s with domain controller %s is not marked domain_member, but %s uses domain accounts: default-deny egress would block Kerberos, LDAP, DNS, SMB and RPC to %s; set domain_member: %s", h.Segment, dc, id, dc, dc)
		}
	}
}

// domainScored returns a scored service (or protected domain account) on the
// host that authenticates with domain accounts, or "".
func (l *linter) domainScored(host string) string {
	m := l.m
	for _, a := range SortedKeys(m.Accounts) {
		acct := m.Accounts[a]
		if acct.Scope == "domain" && acct.Protected() && containsStr(acct.Hosts, host) {
			return "account " + a
		}
	}
	domainAuth := map[string]bool{"smb": true, "winrm": true, "rdp": true, "mssql": true}
	var generic bool
	for _, a := range m.Accounts {
		if a.Scope == "domain" && a.Protected() && len(a.Hosts) == 0 {
			generic = true
		}
	}
	for _, id := range m.ServicesOn(host) {
		s := m.Services[id]
		if s.Scored && s.IsServiceEnabled() && domainAuth[s.Kind] && (generic || s.Transport == nil || s.Transport.Auth != "key") {
			return "scored service " + id
		}
	}
	return ""
}

func (l *linter) scorer() {
	sc := l.m.Scorer
	if sc.Engine == "" {
		return
	}
	if !sc.Known {
		l.add(RuleScorerEst, SevInfo, "scorer", "delay, jitter and timeout are estimates (known: false); the round-clock estimator will replace them after about 10 bursts")
	}
	if sc.Timeout != nil && sc.Timeout.Duration > sc.EffectiveDelay() {
		l.add(RuleScorerTime, SevWarn, "scorer", "timeout %s exceeds delay %s", sc.Timeout.Duration, sc.EffectiveDelay())
	}
}

func containsStr(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func base(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// SortFindings orders findings by severity (errors first), ID, then subject.
func SortFindings(fs []Finding) {
	rank := map[Severity]int{SevError: 0, SevWarn: 1, SevInfo: 2}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Subject < b.Subject
	})
}

// overrides reports act or safe_mode_hosts expressions that name no host and
// act keys with no module block. Both are warnings: the file still loads, but
// a typo is visible.
func (l *linter) overrides() {
	for _, module := range SortedKeys(l.m.Overrides.Act) {
		if _, ok := l.m.Modules[module]; !ok {
			l.add(RuleOverridesNoHost, SevWarn, "overrides: act "+module,
				"module %s has no modules/%s.yml", module, module)
		}
		for _, expr := range l.m.Overrides.Act[module] {
			e, err := ParseLabels(expr)
			if err != nil {
				continue // validation reports it
			}
			matched := false
			for name := range l.m.Hosts {
				if l.m.hostMatches(name, e) {
					matched = true
					break
				}
			}
			if !matched {
				l.add(RuleOverridesNoHost, SevWarn, "overrides: act "+module,
					"expression %q matches no host", expr)
			}
		}
	}
	for _, expr := range l.m.Overrides.SafeModeHosts {
		e, err := ParseLabels(expr)
		if err != nil {
			continue
		}
		matched := false
		for name := range l.m.Hosts {
			if l.m.hostMatches(name, e) {
				matched = true
				break
			}
		}
		if !matched {
			l.add(RuleOverridesNoHost, SevWarn, "overrides: safe_mode_hosts",
				"expression %q matches no host", expr)
		}
	}
}
