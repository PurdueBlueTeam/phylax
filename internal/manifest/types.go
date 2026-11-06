// Package manifest is the typed, strictly decoded model of the Phylax manifest
// (design: "Manifest", "Topology, relays and firewalls"). The manifest is the
// only place infra facts live; firewall policy, plans, checks and inject
// artifacts are generated from it. This package loads and validates it and
// lints it against the scoring-safety rules. Rendering lives in
// internal/manifest/render.
package manifest

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// File names of the manifest, in the order the design lists them.
const (
	FileTopology     = "topology.yml"
	FileHosts        = "hosts.yml"
	FileServices     = "services.yml"
	FileAccounts     = "accounts.yml"
	FileScorer       = "scorer.yml"
	FileDevices      = "devices.yml"
	FileDecoys       = "decoys.yml"
	FileIntegrations = "integrations.yml"
	FilePolicy       = "policy.yml"
	FileOverrides    = "overrides.yml"
)

// Manifest is the merged content of all manifest files.
type Manifest struct {
	Team         int                    // value of `team` in topology.yml (or the load override)
	Topology     Topology               // topology.yml
	Hosts        map[string]Host        // hosts.yml
	Services     map[string]Service     // services.yml
	Accounts     map[string]Account     // accounts.yml
	Scorer       Scorer                 // scorer.yml
	Devices      map[string]Device      // topology.yml `devices` merged with devices.yml
	Decoys       map[string]HostDecoys  // decoys.yml, keyed by host
	Integrations map[string]Integration // integrations.yml
	Policy       Policy                 // policy.yml
	Overrides    Overrides              // overrides.yml
	Modules      map[string]ModuleBlock // modules/*.yml
	Loaded       []string               // files that were present
}

// ---- topology.yml ----

// Topology declares the controller, segments, devices and backup targets.
type Topology struct {
	Team       int                `yaml:"team" json:"team"`
	Controller Controller         `yaml:"controller" json:"controller"`
	Segments   map[string]Segment `yaml:"segments" json:"segments"`
	Devices    map[string]Device  `yaml:"devices,omitempty" json:"devices,omitempty"`
	Backups    []BackupTarget     `yaml:"backups,omitempty" json:"backups,omitempty"`
}

// Controller names the controller host and its listeners.
type Controller struct {
	Host      string `yaml:"host" json:"host"`
	AgentPort uint16 `yaml:"agent_port" json:"agent_port"` // agent streams and bootstrap downloads only
	UI        string `yaml:"ui" json:"ui"`                 // host:port, must be loopback
}

// Segment is one L2/L3 network the manifest knows about.
type Segment struct {
	CIDR     string `yaml:"cidr" json:"cidr"`
	Firewall string `yaml:"firewall,omitempty" json:"firewall,omitempty"` // device name guarding the segment
	Uplink   string `yaml:"uplink,omitempty" json:"uplink,omitempty"`     // device name reached through the firewall's outside
	NAT      *NAT   `yaml:"nat,omitempty" json:"nat,omitempty"`
	// Relay is the host (in this segment) that splices agent connections to
	// Parent. Only for segments that cannot reach the controller directly.
	Relay     string `yaml:"relay,omitempty" json:"relay,omitempty"`
	RelayPort uint16 `yaml:"relay_port,omitempty" json:"relay_port,omitempty"` // default 7444
	// Parent is the segment whose relay (or the controller) this segment's
	// relay dials. Default: the controller's segment.
	Parent         string          `yaml:"parent,omitempty" json:"parent,omitempty"`
	ControllerPath *ControllerPath `yaml:"controller_path,omitempty" json:"controller_path,omitempty"`
}

// NAT is a segment's static public mapping.
type NAT struct {
	PublicPool string `yaml:"public_pool" json:"public_pool"`
	Mode       string `yaml:"mode" json:"mode"` // static_1to1_same_octet
}

// ControllerPath describes how an agent in a segment outside the controller's
// LAN reaches the controller through a declared firewall rule.
type ControllerPath struct {
	Via       string `yaml:"via" json:"via"`               // static_nat
	Public    string `yaml:"public" json:"public"`         // controller's public address
	AllowFrom string `yaml:"allow_from" json:"allow_from"` // host whose (translated) source address the rule allows
	Port      uint16 `yaml:"port" json:"port"`
}

// BackupTarget is a place service backups are written.
type BackupTarget struct {
	Name string `yaml:"name" json:"name"`
	Host string `yaml:"host" json:"host"`
	Path string `yaml:"path" json:"path"`
}

// ---- devices.yml ----

// Device is a network device managed agentlessly by an adapter.
type Device struct {
	Vendor  string `yaml:"vendor" json:"vendor"` // panos | vyos | ftd
	Mgmt    string `yaml:"mgmt" json:"mgmt"`     // management address
	Segment string `yaml:"segment" json:"segment"`
	Via     string `yaml:"via,omitempty" json:"via,omitempty"` // device the management path crosses
	// ExternalIP is the address the device source-NATs traffic to on its
	// outside, e.g. VyOS 172.31.(20+T).2.
	ExternalIP string   `yaml:"external_ip,omitempty" json:"external_ip,omitempty"`
	Ports      []uint16 `yaml:"ports,omitempty" json:"ports,omitempty"`     // management ports; vendor default if empty
	Adapter    string   `yaml:"adapter,omitempty" json:"adapter,omitempty"` // adapter name; vendor default if empty
	Proxy      string   `yaml:"proxy,omitempty" json:"proxy,omitempty"`     // device_proxy host that reaches it
}

// ---- hosts.yml ----

// Host is one machine.
type Host struct {
	Segment           string          `yaml:"segment" json:"segment"`
	Modules           map[string]bool `yaml:"modules,omitempty" json:"modules,omitempty"`
	Labels            []string        `yaml:"labels,omitempty" json:"labels,omitempty"`
	IP                string          `yaml:"ip" json:"ip"`                             // address or "dhcp"
	Public            string          `yaml:"public,omitempty" json:"public,omitempty"` // public NAT address
	OS                OS              `yaml:"os" json:"os"`
	Roles             []string        `yaml:"roles,omitempty" json:"roles,omitempty"`
	Class             string          `yaml:"class,omitempty" json:"class,omitempty"`                             // server (default) | workstation
	DefaultCredential string          `yaml:"default_credentials,omitempty" json:"default_credentials,omitempty"` // secret name, never a value
	Hardening         *Hardening      `yaml:"hardening,omitempty" json:"hardening,omitempty"`
	// DomainMember names the domain controller host this host joins. The
	// renderers emit the complete member-to-DC allowance set (DNS, Kerberos,
	// LDAP, SMB, RPC, NTP) so default-deny egress cannot break domain auth.
	// Works for Windows members and for Linux members (sssd/realmd).
	DomainMember string `yaml:"domain_member,omitempty" json:"domain_member,omitempty"`
	// RPCRange pins the DC's dynamic RPC port range ("lo-hi", only on a host
	// with the domain_controller role). Unpinned, the renderers open
	// 49152-65535 from every member and the lint warns.
	RPCRange string `yaml:"rpc_range,omitempty" json:"rpc_range,omitempty"`
}

// OS identifies the operating system.
type OS struct {
	Family  string `yaml:"family" json:"family"` // debian | rhel | suse | arch | alpine | windows
	Distro  string `yaml:"distro,omitempty" json:"distro,omitempty"`
	Version string `yaml:"version" json:"version"`
}

// Hardening declares the scorer-sensitive knobs the plans intend to leave in
// place on this host. The lint rejects values that break scoring.
type Hardening struct {
	LockoutPolicy  bool   `yaml:"lockout_policy,omitempty" json:"lockout_policy,omitempty"` // pam_faillock, fail2ban, Windows lockout GPO...
	NTLM           string `yaml:"ntlm,omitempty" json:"ntlm,omitempty"`                     // allow | deny
	LMCompatLevel  *int   `yaml:"lm_compat_level,omitempty" json:"lm_compat_level,omitempty"`
	ProtectedUsers bool   `yaml:"protected_users,omitempty" json:"protected_users,omitempty"` // Protected Users group for scored accounts
	ICMPEcho       string `yaml:"icmp_echo,omitempty" json:"icmp_echo,omitempty"`             // allow | drop
}

// Valid roles (Agent roles, plus controller).
const (
	RoleController  = "controller"
	RoleRelay       = "relay"
	RoleDeviceProxy = "device_proxy"
	RoleCheckRunner = "check_runner"
	RoleScanner     = "scanner"
	RoleCanary      = "canary"
	RoleDecoys      = "decoys"
	RoleCapture     = "capture"
	// RoleDomainController marks an Active Directory domain controller; hosts
	// that name it in domain_member get member-to-DC allowances.
	RoleDomainController = "domain_controller"
	// RoleVantage is shorthand for check_runner + scanner + canary (the Kali).
	RoleVantage = "vantage"
)

var validRoles = []string{RoleController, RoleRelay, RoleDeviceProxy, RoleCheckRunner, RoleScanner, RoleCanary, RoleDecoys, RoleCapture, RoleVantage, RoleDomainController}

// HasRole reports whether the host has the role, expanding `vantage`.
func (h Host) HasRole(role string) bool {
	for _, r := range h.Roles {
		if r == role {
			return true
		}
		if r == RoleVantage && (role == RoleCheckRunner || role == RoleScanner || role == RoleCanary) {
			return true
		}
	}
	return false
}

// IsDHCP reports whether the host takes its address from DHCP.
func (h Host) IsDHCP() bool { return h.IP == "dhcp" }

// IsWorkstation reports whether the host is a workstation (not covered by
// server egress rules).
func (h Host) IsWorkstation() bool { return h.Class == "workstation" }

// IsWindows reports whether the host runs Windows.
func (h Host) IsWindows() bool { return h.OS.Family == "windows" }

// ---- services.yml ----

// Service is a service running on a host.
type Service struct {
	Host      string       `yaml:"host" json:"host"`
	Kind      string       `yaml:"kind" json:"kind"`
	Scored    bool         `yaml:"scored" json:"scored"`
	State     string       `yaml:"state,omitempty" json:"state,omitempty"` // running (default) | stopped | disabled
	Listen    []Listener   `yaml:"listen,omitempty" json:"listen,omitempty"`
	Process   *Process     `yaml:"process,omitempty" json:"process,omitempty"`
	Transport *Transport   `yaml:"transport,omitempty" json:"transport,omitempty"`
	Content   *Content     `yaml:"content,omitempty" json:"content,omitempty"`
	Data      []DataRef    `yaml:"data,omitempty" json:"data,omitempty"`
	Outbound  StringList   `yaml:"outbound,omitempty" json:"outbound,omitempty"` // hosts reached outward, or "none"
	DependsOn []Dependency `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	Health    []Health     `yaml:"health,omitempty" json:"health,omitempty"`
}

// Listener is one listening socket. Sources, if set, restricts who may
// connect; the lint rejects that on scored services.
type Listener struct {
	Proto string `yaml:"proto" json:"proto"`                   // tcp | udp
	Port  uint16 `yaml:"port,omitempty" json:"port,omitempty"` // a single port, or:
	// PortRange is "lo-hi" instead of Port (exactly one of the two).
	PortRange string   `yaml:"port_range,omitempty" json:"port_range,omitempty"`
	Sources   []string `yaml:"sources,omitempty" json:"sources,omitempty"`
}

// Process identifies the service's process for pinning.
type Process struct {
	Unit     string   `yaml:"unit,omitempty" json:"unit,omitempty"`
	Units    []string `yaml:"units,omitempty" json:"units,omitempty"`
	Binaries []string `yaml:"binaries,omitempty" json:"binaries,omitempty"`
	Pin      bool     `yaml:"pin,omitempty" json:"pin,omitempty"`
}

// Transport records what the scorer does (and therefore what must stay true).
type Transport struct {
	Plaintext  *bool  `yaml:"plaintext,omitempty" json:"plaintext,omitempty"`
	TLSVerify  *bool  `yaml:"tls_verify,omitempty" json:"tls_verify,omitempty"`
	StartTLS   string `yaml:"starttls,omitempty" json:"starttls,omitempty"` // never | optional | required
	Auth       string `yaml:"auth,omitempty" json:"auth,omitempty"`         // password | ntlm | key | none
	PTY        *bool  `yaml:"pty,omitempty" json:"pty,omitempty"`
	Shell      *bool  `yaml:"shell,omitempty" json:"shell,omitempty"`
	Encryption string `yaml:"encryption,omitempty" json:"encryption,omitempty"` // none | optional | required
}

// Content is scored content that must not change.
type Content struct {
	Roots      []string `yaml:"roots,omitempty" json:"roots,omitempty"`
	UploadDirs []string `yaml:"upload_dirs,omitempty" json:"upload_dirs,omitempty"`
	Normalize  []string `yaml:"normalize,omitempty" json:"normalize,omitempty"`
}

// DataRef names data the service reads.
type DataRef struct {
	Kind     string `yaml:"kind" json:"kind"`
	Database string `yaml:"database,omitempty" json:"database,omitempty"`
}

// Dependency is an outbound allowance a service needs.
type Dependency struct {
	Egress string   `yaml:"egress" json:"egress"` // label
	To     string   `yaml:"to" json:"to"`         // host name
	Ports  []uint16 `yaml:"ports,omitempty" json:"ports,omitempty"`
	// PortRanges are "lo-hi" strings, additional to Ports (at least one of the two).
	PortRanges []string `yaml:"port_ranges,omitempty" json:"port_ranges,omitempty"`
	Proto      string   `yaml:"proto,omitempty" json:"proto,omitempty"`     // tcp (default) | udp
	Service    string   `yaml:"service,omitempty" json:"service,omitempty"` // optional service id on the target, for cycle checks
}

// Health is a manifest-declared health check.
type Health struct {
	HTTPGet      string `yaml:"http_get,omitempty" json:"http_get,omitempty"`
	TCPConnect   uint16 `yaml:"tcp_connect,omitempty" json:"tcp_connect,omitempty"`
	ExpectStatus int    `yaml:"expect_status,omitempty" json:"expect_status,omitempty"`
	ExpectRegex  string `yaml:"expect_regex,omitempty" json:"expect_regex,omitempty"`
	TrackContent bool   `yaml:"track_content,omitempty" json:"track_content,omitempty"`
	Interval     string `yaml:"interval,omitempty" json:"interval,omitempty"`
}

// Service kinds.
var validKinds = []string{"http", "https", "ssh", "mail", "smtp", "imap", "pop3", "ftp", "dns", "icmp", "smb", "winrm", "rdp", "mssql", "mysql", "splunk", "ldap", "tcp"}

// ---- accounts.yml ----

// Scoped says whether an account is scored. `unknown` means protected: treated
// as scored until the PCR list says otherwise.
type Scored string

const (
	ScoredYes     Scored = "scored"
	ScoredNo      Scored = "unscored"
	ScoredUnknown Scored = "protected"
)

// UnmarshalYAML accepts true, false, "unknown" (and the canonical names).
func (s *Scored) UnmarshalYAML(n *yaml.Node) error {
	var raw string
	if err := n.Decode(&raw); err != nil {
		return err
	}
	switch raw {
	case "true", "scored":
		*s = ScoredYes
	case "false", "unscored":
		*s = ScoredNo
	case "unknown", "protected":
		*s = ScoredUnknown
	default:
		return fmt.Errorf("line %d: scored must be true, false or unknown, got %q", n.Line, raw)
	}
	return nil
}

// MarshalYAML writes the compact form.
func (s Scored) MarshalYAML() (any, error) {
	switch s {
	case ScoredYes:
		return true, nil
	case ScoredNo:
		return false, nil
	}
	return "unknown", nil
}

// Account is a managed account (or a group of identical accounts).
type Account struct {
	Username  string   `yaml:"username,omitempty" json:"username,omitempty"` // default: key up to '@'
	Scope     string   `yaml:"scope" json:"scope"`                           // local | domain | service | device
	Hosts     []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Scored    Scored   `yaml:"scored" json:"scored"`
	Credlist  string   `yaml:"credlist,omitempty" json:"credlist,omitempty"` // key in scorer.yml credlists
	Rotation  string   `yaml:"rotation" json:"rotation"`                     // pcr_transaction | free | manual
	LearnFrom string   `yaml:"learn_from,omitempty" json:"learn_from,omitempty"`
	Embedded  []string `yaml:"embedded_in,omitempty" json:"embedded_in,omitempty"` // files that embed the credential
	SSHAuth   string   `yaml:"ssh_auth,omitempty" json:"ssh_auth,omitempty"`       // password | both | key_only
	Shell     string   `yaml:"shell,omitempty" json:"shell,omitempty"`             // login shell, e.g. /bin/bash
}

// Protected reports whether the account must be treated as scored.
func (a Account) Protected() bool { return a.Scored == ScoredYes || a.Scored == ScoredUnknown }

// ---- scorer.yml ----

// Scorer describes the scoring engine (Quotient).
type Scorer struct {
	Engine     string              `yaml:"engine" json:"engine"`
	Portal     string              `yaml:"portal,omitempty" json:"portal,omitempty"`
	Identifier string              `yaml:"identifier,omitempty" json:"identifier,omitempty"`
	Delay      *Duration           `yaml:"delay,omitempty" json:"delay,omitempty"`
	Jitter     *Duration           `yaml:"jitter,omitempty" json:"jitter,omitempty"`
	Timeout    *Duration           `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Known      bool                `yaml:"known,omitempty" json:"known,omitempty"` // false: values are estimates
	SLA        int                 `yaml:"sla_threshold,omitempty" json:"sla_threshold,omitempty"`
	Credlists  map[string]Credlist `yaml:"credlists,omitempty" json:"credlists,omitempty"`
	PollPortal string              `yaml:"poll_portal,omitempty" json:"poll_portal,omitempty"` // off | ask_organizers | operator_paste | cookie_poll
}

// Credlist names a PCR credential list by path (the display name is never used).
type Credlist struct {
	Path string `yaml:"path" json:"path"`
}

// Duration is a time.Duration written as "60s".
type Duration struct{ time.Duration }

// UnmarshalYAML parses a Go duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %v", n.Line, err)
	}
	if v < 0 {
		return fmt.Errorf("line %d: negative duration", n.Line)
	}
	d.Duration = v
	return nil
}

// MarshalYAML writes the duration string.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// EffectiveDelay etc. apply the upstream Quotient defaults (60s +- 5s,
// timeout Delay/2).
func (s Scorer) EffectiveDelay() time.Duration {
	if s.Delay != nil {
		return s.Delay.Duration
	}
	return 60 * time.Second
}

// EffectiveJitter returns the jitter or the 5s default.
func (s Scorer) EffectiveJitter() time.Duration {
	if s.Jitter != nil {
		return s.Jitter.Duration
	}
	return 5 * time.Second
}

// EffectiveTimeout returns the timeout or Delay/2.
func (s Scorer) EffectiveTimeout() time.Duration {
	if s.Timeout != nil {
		return s.Timeout.Duration
	}
	return s.EffectiveDelay() / 2
}

// ---- decoys.yml ----

// HostDecoys declares the decoys on one host. Token values and banners are
// generated at competition time, never stored here.
type HostDecoys struct {
	Listeners   []DecoyListener `yaml:"listeners,omitempty" json:"listeners,omitempty"`
	HoneyFiles  []string        `yaml:"honey_files,omitempty" json:"honey_files,omitempty"`
	Honeytokens []Honeytoken    `yaml:"honeytokens,omitempty" json:"honeytokens,omitempty"`
	Exposure    string          `yaml:"exposure,omitempty" json:"exposure,omitempty"` // lan | public | both (default both)
	// Domain is the AD DNS domain (corp.example). Needed on a domain controller
	// for the ad_spn / ad_asrep / ad_admin honeytokens.
	Domain string `yaml:"domain,omitempty" json:"domain,omitempty"`
}

// DecoyListener is a decoy service port.
type DecoyListener struct {
	Kind string `yaml:"kind" json:"kind"` // ssh | mysql | redis | telnet | winrm | rdp | http_admin | smb (banner only, never 445)
	Port uint16 `yaml:"port" json:"port"`
}

// Honeytoken is a planted fake credential or key.
type Honeytoken struct {
	Kind string `yaml:"kind" json:"kind"`
	At   string `yaml:"at" json:"at"`
}

// ---- integrations.yml ----

// Integration is an optional sensor with a pinned version.
type Integration struct {
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Version string   `yaml:"version,omitempty" json:"version,omitempty"`
	SHA256  string   `yaml:"sha256,omitempty" json:"sha256,omitempty"`
	Hosts   []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
}

// ---- policy.yml ----

// Policy is response, egress and firewall policy.
type Policy struct {
	Firewall           FirewallPolicy `yaml:"firewall,omitempty" json:"firewall,omitempty"`
	Egress             EgressPolicy   `yaml:"egress,omitempty" json:"egress,omitempty"`
	PatchWindows       PatchWindows   `yaml:"patch_windows,omitempty" json:"patch_windows,omitempty"`
	Response           Response       `yaml:"response,omitempty" json:"response,omitempty"`
	ProtectedProcesses []string       `yaml:"protected_processes,omitempty" json:"protected_processes,omitempty"`
	Retention          Retention      `yaml:"retention,omitempty" json:"retention,omitempty"`
	Limits             Limits         `yaml:"limits,omitempty" json:"limits,omitempty"`
	CacheTiers         []string       `yaml:"cache_tiers,omitempty" json:"cache_tiers,omitempty"`
}

// FirewallPolicy states the always-on allowances. `allow` is the only value
// that passes the lint; the renderer always emits the allowance regardless.
type FirewallPolicy struct {
	ICMP string `yaml:"icmp,omitempty" json:"icmp,omitempty"` // allow (default) | drop
	DHCP string `yaml:"dhcp,omitempty" json:"dhcp,omitempty"` // allow (default) | drop
	IPv6 string `yaml:"ipv6,omitempty" json:"ipv6,omitempty"` // allow (default) | drop
}

// EgressPolicy is "what's allowed out".
type EgressPolicy struct {
	Allow        []EgressAllow `yaml:"allow,omitempty" json:"allow,omitempty"` // extra allowances beyond agent link and depends_on
	Sinkhole     *Sinkhole     `yaml:"sinkhole,omitempty" json:"sinkhole,omitempty"`
	CanaryPorts  []uint16      `yaml:"canary_ports,omitempty" json:"canary_ports,omitempty"`
	DenyLogGroup uint16        `yaml:"deny_log_group,omitempty" json:"deny_log_group,omitempty"` // NFLOG group, default 100
}

// EgressAllow is one extra egress allowance for a host (or all servers).
type EgressAllow struct {
	Host  string   `yaml:"host,omitempty" json:"host,omitempty"` // empty: every server
	To    string   `yaml:"to" json:"to"`                         // host name or CIDR
	Ports []uint16 `yaml:"ports,omitempty" json:"ports,omitempty"`
	// PortRanges are "lo-hi" strings, additional to Ports (at least one of the two).
	PortRanges []string `yaml:"port_ranges,omitempty" json:"port_ranges,omitempty"`
	Proto      string   `yaml:"proto,omitempty" json:"proto,omitempty"`
	Reason     string   `yaml:"reason" json:"reason"`
}

// Sinkhole configures the Linux denied-egress catcher.
type Sinkhole struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Port    uint16 `yaml:"port,omitempty" json:"port,omitempty"` // loopback catcher port, default 7480
}

// PatchWindows bounds patch windows and lists allowed upstreams.
type PatchWindows struct {
	DefaultMinutes int      `yaml:"default_minutes,omitempty" json:"default_minutes,omitempty"`
	MaxMinutes     int      `yaml:"max_minutes,omitempty" json:"max_minutes,omitempty"`
	Allowlist      []string `yaml:"allowlist,omitempty" json:"allowlist,omitempty"` // distro mirrors, Microsoft update endpoints
}

// Response holds response tiers.
type Response struct {
	AlertOnly bool                `yaml:"alert_only,omitempty" json:"alert_only,omitempty"`
	Tiers     map[string][]string `yaml:"tiers,omitempty" json:"tiers,omitempty"`
}

// Retention bounds how long data is kept.
type Retention struct {
	Events *Duration `yaml:"events,omitempty" json:"events,omitempty"`
	Pcap   *Duration `yaml:"pcap,omitempty" json:"pcap,omitempty"`
}

// Limits are resource bounds.
type Limits struct {
	PacketRingMaxBytes int64 `yaml:"packet_ring_max_bytes,omitempty" json:"packet_ring_max_bytes,omitempty"`
	PacketRingFreePct  int   `yaml:"packet_ring_free_pct,omitempty" json:"packet_ring_free_pct,omitempty"`
}

// ---- overrides.yml ----

// Overrides are competition-day changes written by the UI.
type Overrides struct {
	AdoptedDrift     []OverrideEntry   `yaml:"adopted_drift,omitempty" json:"adopted_drift,omitempty"`
	InjectChanges    []OverrideEntry   `yaml:"inject_changes,omitempty" json:"inject_changes,omitempty"`
	AcceptedFindings []AcceptedFinding `yaml:"accepted_findings,omitempty" json:"accepted_findings,omitempty"`
	LearnedListeners []LearnedListener `yaml:"learned_listeners,omitempty" json:"learned_listeners,omitempty"`
}

// LearnedListener is a port on which scorer traffic was seen arriving.
type LearnedListener struct {
	Host     string `yaml:"host" json:"host"`
	Proto    string `yaml:"proto" json:"proto"` // tcp | udp
	Port     uint16 `yaml:"port" json:"port"`
	Reason   string `yaml:"reason" json:"reason"`
	Observed string `yaml:"observed" json:"observed"` // RFC 3339, UTC
}

// OverrideEntry is a generic dated note on a host or service.
type OverrideEntry struct {
	Subject string `yaml:"subject" json:"subject"`
	Note    string `yaml:"note,omitempty" json:"note,omitempty"`
	At      string `yaml:"at,omitempty" json:"at,omitempty"`
}

// AcceptedFinding suppresses a warning-level lint finding for a subject.
// Errors cannot be accepted.
type AcceptedFinding struct {
	ID      string `yaml:"id" json:"id"`
	Subject string `yaml:"subject" json:"subject"`
	Reason  string `yaml:"reason" json:"reason"`
}

// StringList decodes either a scalar or a list of strings.
type StringList []string

// UnmarshalYAML accepts "x" or [x, y].
func (s *StringList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var v string
		if err := n.Decode(&v); err != nil {
			return err
		}
		*s = StringList{v}
		return nil
	case yaml.SequenceNode:
		var v []string
		if err := n.Decode(&v); err != nil {
			return err
		}
		*s = v
		return nil
	}
	return fmt.Errorf("line %d: expected a string or a list of strings", n.Line)
}

// IsNone reports the `none` marker.
func (s StringList) IsNone() bool { return len(s) == 1 && s[0] == "none" }

// PortSet returns the listener's port or range.
func (l Listener) PortSet() Ports {
	if l.PortRange != "" {
		return Ports{Ranges: MustPortRanges([]string{l.PortRange})}
	}
	return Ports{Ports: []uint16{l.Port}}
}

// PortSet returns the dependency's ports and ranges.
func (d Dependency) PortSet() Ports {
	return Ports{Ports: d.Ports, Ranges: MustPortRanges(d.PortRanges)}
}

// PortSet returns the allowance's ports and ranges.
func (a EgressAllow) PortSet() Ports {
	return Ports{Ports: a.Ports, Ranges: MustPortRanges(a.PortRanges)}
}

// IsDomainController reports whether the host has the domain_controller role.
func (h Host) IsDomainController() bool { return h.HasRole(RoleDomainController) }
