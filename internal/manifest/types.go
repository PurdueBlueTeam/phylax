// Package manifest loads, validates and renders the Phylax manifest: the
// single source of truth for infrastructure. Plans, agent configs, firewall
// rules, health checks, decoys and inject artifacts are all generated from it.
//
// Files (see phylax_design.md § Manifest):
//
//	topology.yml   controller host and ports, segments, relays, NAT, backup targets
//	hosts.yml      hosts: segment, addresses, OS, default credentials, roles
//	services.yml   services: kind, scored, listeners, process, content, data,
//	               dependencies, health checks
//	accounts.yml   managed accounts: scope, scored, rotation policy, embedding files
//	devices.yml    network devices: vendor, management address, segment, proxy
//	decoys.yml     decoys per host: listeners, honey files, honeytokens
//	policy.yml     response tiers, protected processes, retention, limits,
//	               patch-window allowlist
//	overrides.yml  competition-day changes written by the UI
//
// Secrets never appear in the manifest: entries refer to vault names by
// string (e.g. `secret: ecom.db`).
package manifest

import (
	"fmt"
	"net"
	"sort"
	"strconv"
)

// Manifest is the fully loaded, templated and validated set of manifest files.
type Manifest struct {
	Topology  Topology  `yaml:"topology"`
	Hosts     Hosts     `yaml:"hosts"`
	Services  Services  `yaml:"services"`
	Accounts  Accounts  `yaml:"accounts"`
	Devices   Devices   `yaml:"devices"`
	Decoys    Decoys    `yaml:"decoys"`
	Policy    Policy    `yaml:"policy"`
	Overrides Overrides `yaml:"overrides"`

	// Dir is the manifest directory, used for relative references.
	Dir string `yaml:"-"`
}

// ---------------------------------------------------------------- topology

type Topology struct {
	Controller Controller `yaml:"controller" json:"controller"`
	Segments   Segments   `yaml:"segments" json:"segments"`
	Backups    []string   `yaml:"backups" json:"backups"`
}

type Controller struct {
	Host      string `yaml:"host" json:"host"`
	AgentPort int    `yaml:"agent_port" json:"agent_port"`
	UI        string `yaml:"ui" json:"ui"`
}

type Segments map[string]Segment

type Segment struct {
	CIDR     string `yaml:"cidr" json:"cidr"`
	Firewall string `yaml:"firewall" json:"firewall"`
	Relay    *Relay `yaml:"relay" json:"relay"`
	NAT      *NAT   `yaml:"nat" json:"nat"`
}

type Relay struct {
	Host string `yaml:"host" json:"host"`
	Port int    `yaml:"port" json:"port"`
}

// NAT declares how the segment appears to the controller's side: the public
// address of the relay and the static inbound NAT for the controller.
type NAT struct {
	RelayPublic      string `yaml:"relay_public" json:"relay_public"`
	ControllerPublic string `yaml:"controller_public" json:"controller_public"`
}

// Host returns a host by name; error if absent.
func (m *Manifest) Host(name string) (*Host, error) {
	h, ok := m.Hosts.Hosts[name]
	if !ok {
		return nil, fmt.Errorf("manifest: host %q not found", name)
	}
	return h, nil
}

// HostNames returns manifest host names in stable order.
func (m *Manifest) HostNames() []string {
	out := make([]string, 0, len(m.Hosts.Hosts))
	for name := range m.Hosts.Hosts {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ControllerHost returns the controller host entry.
func (m *Manifest) ControllerHost() *Host {
	h, _ := m.Hosts.Hosts[m.Topology.Controller.Host]
	return h
}

// SegmentOf returns the segment a host belongs to.
func (m *Manifest) SegmentOf(host string) (string, error) {
	h, err := m.Host(host)
	if err != nil {
		return "", err
	}
	return h.Segment, nil
}

// AgentDestination returns the address:port a host's agent dials: the
// controller directly for hosts in the controller's segment, the segment's
// relay otherwise.
func (m *Manifest) AgentDestination(host string) (string, error) {
	seg, err := m.SegmentOf(host)
	if err != nil {
		return "", err
	}
	csegName, err := m.SegmentOf(m.Topology.Controller.Host)
	if err != nil {
		return "", err
	}
	if seg == csegName {
		c, _ := m.Host(m.Topology.Controller.Host)
		return net.JoinHostPort(c.IP, strconv.Itoa(m.Topology.Controller.AgentPort)), nil
	}
	s, ok := m.Topology.Segments[seg]
	if !ok || s.Relay == nil {
		return "", fmt.Errorf("manifest: segment %q has no relay and is not the controller segment", seg)
	}
	r, _ := m.Host(s.Relay.Host)
	return net.JoinHostPort(r.IP, strconv.Itoa(s.Relay.Port)), nil
}

// ---------------------------------------------------------------- hosts

type Hosts struct {
	Team  int              `yaml:"team" json:"team"`
	Hosts map[string]*Host `yaml:"hosts" json:"hosts"`
}

type Host struct {
	Segment      string `yaml:"segment" json:"segment"`
	IP           string `yaml:"ip" json:"ip"`
	PublicIP     string `yaml:"public_ip" json:"public_ip"`
	OS           OS     `yaml:"os" json:"os"`
	DefaultCreds string `yaml:"default_creds" json:"default_creds"`
	Roles        []Role `yaml:"roles" json:"roles"`
}

type OS struct {
	Family  string `yaml:"family" json:"family"`
	Distro  string `yaml:"distro" json:"distro"`
	Version string `yaml:"version" json:"version"`
}

// Role is an agent role switch from the manifest.
type Role string

const (
	RoleRelay       Role = "relay"
	RoleDeviceProxy Role = "device_proxy"
	RoleCheckRunner Role = "check_runner"
	RoleDecoys      Role = "decoys"
	RoleCapture     Role = "capture"
)

func (h *Host) HasRole(r Role) bool {
	for _, x := range h.Roles {
		if x == r {
			return true
		}
	}
	return false
}

// Linux returns true for non-Windows host OS families.
func (h *Host) Linux() bool { return h.OS.Family != "windows" }

// Windows returns true for windows host OS.
func (h *Host) Windows() bool { return h.OS.Family == "windows" }

// ---------------------------------------------------------------- services

type Services map[string]*Service

type Service struct {
	Host    string       `yaml:"host" json:"host"`
	Kind    ServiceKind  `yaml:"kind" json:"kind"`
	Scored  bool         `yaml:"scored" json:"scored"`
	State   string       `yaml:"state" json:"state"`
	Listen  []Listener   `yaml:"listen" json:"listen"`
	Process *Process     `yaml:"process" json:"process"`
	Content *Content     `yaml:"content" json:"content"`
	Data    []Data       `yaml:"data" json:"data"`
	Depends []Dependency `yaml:"depends_on" json:"depends_on"`
	Health  []Health     `yaml:"health" json:"health"`
}

type ServiceKind string

const (
	KindHTTP     ServiceKind = "http"
	KindHTTPS    ServiceKind = "https"
	KindSMTP     ServiceKind = "smtp"
	KindPOP3     ServiceKind = "pop3"
	KindIMAP     ServiceKind = "imap"
	KindFTP      ServiceKind = "ftp"
	KindDNS      ServiceKind = "dns"
	KindKerberos ServiceKind = "kerberos"
	KindLDAP     ServiceKind = "ldap"
	KindNTP      ServiceKind = "ntp"
	KindTFTP     ServiceKind = "tftp"
	KindSSH      ServiceKind = "ssh"
	KindMySQL    ServiceKind = "mysql"
	KindSplunk   ServiceKind = "splunk"
	KindWinRM    ServiceKind = "winrm"
	KindRDP      ServiceKind = "rdp"
	KindOther    ServiceKind = "other"
)

// WellKnownPorts returns the default ports for an egress kind, used when a
// dependency does not list ports explicitly.
func (k ServiceKind) WellKnownPorts() (proto string, ports []int) {
	switch k {
	case KindDNS:
		return "udp", []int{53}
	case KindLDAP:
		return "tcp", []int{389}
	case KindKerberos:
		return "udp", []int{88}
	case KindSMTP:
		return "tcp", []int{25}
	case KindNTP:
		return "udp", []int{123}
	case KindPOP3:
		return "tcp", []int{110}
	case KindIMAP:
		return "tcp", []int{143}
	case KindFTP:
		return "tcp", []int{21}
	case KindTFTP:
		return "udp", []int{69}
	case KindMySQL:
		return "tcp", []int{3306}
	}
	return "tcp", nil
}

type Listener struct {
	Proto string `yaml:"proto" json:"proto"`
	Port  int    `yaml:"port" json:"port"`
}

type Process struct {
	Unit string `yaml:"unit" json:"unit"`
}

type Content struct {
	Roots      []string `yaml:"roots" json:"roots"`
	UploadDirs []string `yaml:"upload_dirs" json:"upload_dirs"`
	Normalize  []string `yaml:"normalize" json:"normalize"`
}

type Data struct {
	Kind     string `yaml:"kind" json:"kind"`
	Database string `yaml:"database" json:"database"`
	Path     string `yaml:"path" json:"path"`
}

// Dependency is either another service ({service: name}) or a declared
// egress target ({egress: kind, to: host, ports: [...]}).
type Dependency struct {
	Service string      `yaml:"service" json:"service"`
	Egress  ServiceKind `yaml:"egress" json:"egress"`
	To      string      `yaml:"to" json:"to"`
	Ports   []int       `yaml:"ports" json:"ports"`
}

// EgressProto returns the protocol and ports for an egress dependency.
func (d Dependency) EgressProto() (string, []int) {
	if len(d.Ports) > 0 {
		proto := "tcp"
		switch d.Egress {
		case KindDNS, KindNTP, KindKerberos, KindTFTP:
			proto = "udp"
		}
		return proto, d.Ports
	}
	return d.Egress.WellKnownPorts()
}

type Health struct {
	HTTPGet   *HealthHTTPGet   `yaml:"http_get" json:"http_get"`
	HTTPSGet  *HealthHTTPGet   `yaml:"https_get" json:"https_get"`
	POP3Login *HealthPOP3Login `yaml:"pop3_login" json:"pop3_login"`
	TCPBanner *HealthTCPBanner `yaml:"tcp_banner" json:"tcp_banner"`
	DNSQuery  *HealthDNSQuery  `yaml:"dns_query" json:"dns_query"`
	FTPList   *HealthFTPList   `yaml:"ftp_list" json:"ftp_list"`
	TFTPGet   *HealthTFTPGet   `yaml:"tftp_get" json:"tftp_get"`
	NTPQuery  *HealthNTPQuery  `yaml:"ntp_query" json:"ntp_query"`
}

type HealthHTTPGet struct {
	Path         string `yaml:"path" json:"path"`
	ExpectStatus int    `yaml:"expect_status" json:"expect_status"`
	TrackContent bool   `yaml:"track_content" json:"track_content"`
}

type HealthPOP3Login struct {
	Account string `yaml:"account" json:"account"`
	Expect  string `yaml:"expect" json:"expect"`
}

type HealthTCPBanner struct {
	Port    int    `yaml:"port" json:"port"`
	Matches string `yaml:"matches" json:"matches"`
}

type HealthDNSQuery struct {
	Name   string   `yaml:"name" json:"name"`
	Expect []string `yaml:"expect" json:"expect"`
}

type HealthFTPList struct {
	Path string `yaml:"path" json:"path"`
	File string `yaml:"file" json:"file"`
}

type HealthTFTPGet struct {
	File string `yaml:"file" json:"file"`
}

type HealthNTPQuery struct{}

// ---------------------------------------------------------------- accounts

type Accounts map[string]*Account

type Account struct {
	Scope    string   `yaml:"scope" json:"scope"`
	Host     string   `yaml:"host" json:"host"`
	Scored   bool     `yaml:"scored" json:"scored"`
	Rotation string   `yaml:"rotation" json:"rotation"`
	EmbedsIn []string `yaml:"embeds_in" json:"embeds_in"`
}

// ---------------------------------------------------------------- devices

type Devices map[string]*Device

type Device struct {
	Vendor       string `yaml:"vendor" json:"vendor"`
	Admin        string `yaml:"admin" json:"admin"`
	Segment      string `yaml:"segment" json:"segment"`
	Adapter      string `yaml:"adapter" json:"adapter"`
	Via          string `yaml:"via" json:"via"`
	BackupTarget bool   `yaml:"backup_target" json:"backup_target"`
}

// ---------------------------------------------------------------- decoys

type Decoys map[string]*HostDecoys

type HostDecoys struct {
	Listeners []DecoyListener `yaml:"listeners" json:"listeners"`
	Files     []DecoyFile     `yaml:"files" json:"files"`
	Tokens    []string        `yaml:"tokens" json:"tokens"`
	AD        []string        `yaml:"ad" json:"ad"`
}

type DecoyListener struct {
	Kind     string `yaml:"kind" json:"kind"`
	Port     int    `yaml:"port" json:"port"`
	Exposure string `yaml:"exposure" json:"exposure"`
}

type DecoyFile struct {
	Path string `yaml:"path" json:"path"`
	Kind string `yaml:"kind" json:"kind"`
}

// ---------------------------------------------------------------- policy

type Policy struct {
	Tiers            Tiers       `yaml:"tiers" json:"tiers"`
	ProtectedProcess []string    `yaml:"protected_process" json:"protected_process"`
	Retention        Retention   `yaml:"retention" json:"retention"`
	Limits           Limits      `yaml:"limits" json:"limits"`
	PatchWindow      PatchWindow `yaml:"patch_window" json:"patch_window"`
}

type Tiers struct {
	Tier0Actions []string `yaml:"tier0_actions" json:"tier0_actions"`
}

type Retention struct {
	Events   string `yaml:"events" json:"events"`
	Evidence string `yaml:"evidence" json:"evidence"`
}

type Limits struct {
	SpoolMaxMB         int `yaml:"spool_max_mb" json:"spool_max_mb"`
	PacketRingMaxMB    int `yaml:"packet_ring_max_mb" json:"packet_ring_max_mb"`
	PacketRingPctFree  int `yaml:"packet_ring_pct_free" json:"packet_ring_pct_free"`
	Tier0PerHostPerMin int `yaml:"tier0_per_host_per_min" json:"tier0_per_host_per_min"`
	AgentMsgRatePerSec int `yaml:"agent_msg_rate_per_sec" json:"agent_msg_rate_per_sec"`
	AgentBytesPerMin   int `yaml:"agent_bytes_per_min" json:"agent_bytes_per_min"`
}

type PatchWindow struct {
	DurationSec int      `yaml:"duration_sec" json:"duration_sec"`
	Allowlist   []string `yaml:"allowlist" json:"allowlist"`
}

// ---------------------------------------------------------------- overrides

// Overrides holds competition-day changes written by the UI: adopted drift,
// inject changes, accepted findings. The loader validates it against its
// schema; values are applied on top of the base manifest at load time.
type Overrides struct {
	Hosts    map[string]map[string]interface{} `yaml:"hosts" json:"hosts"`
	Services map[string]map[string]interface{} `yaml:"services" json:"services"`
	Notes    []string                          `yaml:"notes" json:"notes"`
}
