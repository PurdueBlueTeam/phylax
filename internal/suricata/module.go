package suricata

import (
	"context"
	"sync"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
)

// Kind is the one kind this module emits (design: Event kinds). Type names the
// record and the rest of the payload is that record's fields.
const Kind = "suricata.event"

// The record types carried by the one kind.
const (
	TypeAlert    = "alert"
	TypeDNS      = "dns"
	TypeHTTP     = "http"
	TypeZeekConn = "zeek_conn"
	TypeZeekDNS  = "zeek_dns"
	TypeRun      = "run"
)

// Event is one Suricata or Zeek record. The flow fields are shared by alert,
// dns, http, zeek_conn and zeek_dns; the rest belong to the record named by
// Type.
type Event struct {
	Type string `json:"type"`

	// flow fields
	SrcIP       string `json:"src_ip,omitempty"`
	SrcPort     int    `json:"src_port,omitempty"`
	DestIP      string `json:"dest_ip,omitempty"`
	DestPort    int    `json:"dest_port,omitempty"`
	Proto       string `json:"proto,omitempty"`
	CommunityID string `json:"community_id,omitempty"`
	FlowID      int64  `json:"flow_id,omitempty"`

	// alert
	SignatureID int    `json:"signature_id,omitempty"`
	Signature   string `json:"signature,omitempty"`
	Category    string `json:"category,omitempty"`
	Severity    int    `json:"severity,omitempty"`
	Action      string `json:"action,omitempty"`

	// dns and zeek_dns
	RRName    string `json:"rrname,omitempty"`
	RRType    string `json:"rrtype,omitempty"`
	Query     any    `json:"query,omitempty"`
	QTypeName any    `json:"qtype_name,omitempty"`
	RCodeName any    `json:"rcode_name,omitempty"`
	Answers   any    `json:"answers,omitempty"`

	// http
	Hostname string `json:"hostname,omitempty"`
	URL      string `json:"url,omitempty"`
	Method   string `json:"method,omitempty"`

	// zeek_conn
	UID       string `json:"uid,omitempty"`
	Service   any    `json:"service,omitempty"`
	ConnState any    `json:"conn_state,omitempty"`
	Duration  any    `json:"duration,omitempty"`
	OrigBytes any    `json:"orig_bytes,omitempty"`
	RespBytes any    `json:"resp_bytes,omitempty"`

	// run
	Pcap    string `json:"pcap,omitempty"`
	Alerts  int    `json:"alerts,omitempty"`
	Records int    `json:"records,omitempty"`
	Error   string `json:"error,omitempty"`
}

func init() {
	// Not alert-class: even a high record is stored and shown, never an alert
	// row. The priority is set per record (alert severity, bulk context).
	event.Declare(event.Type{Kind: Kind, Schema: 1, Priority: event.PriorityNormal, Fields: Event{}})
	module.Register(&Module{})
}

// Config is modules/suricata.yml.
type Config struct {
	module.Common `yaml:",inline"`
	// Hosts names where Suricata and Zeek run; empty means the controller.
	Hosts []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
}

// Module is the controller side of suricata. The readers are built; the run
// and the suricata.analyze_pcap action are W11.
type Module struct {
	mu sync.Mutex
	hl module.Health
}

func (*Module) Manifest() module.Manifest {
	return module.Manifest{
		Name:      "suricata",
		Sides:     []module.Side{module.SideController},
		Privilege: "none",
		Emits:     []event.Type{mustType(Kind)},
		Default:   false,
		Actions:   []string{"suricata.analyze_pcap"},
	}
}

// Start decodes the module block and reports what is missing. It starts no
// run: a run is on demand, from the incident page or a plan node.
func (m *Module) Start(ctx context.Context, h module.Host) error {
	var cfg Config
	if err := h.Config(&cfg); err != nil {
		return err // ErrNoConfig: the runner reports the module unavailable
	}
	m.setHealth(module.Health{
		State:  module.StateUnavailable,
		Detail: "the pcap run is not built",
		Gaps:   []module.Gap{{What: "suricata.analyze_pcap", Why: "not built (W11)"}},
	})
	<-ctx.Done()
	return nil
}

// Health reports the module's state; reading a pcap is not implemented yet.
func (m *Module) Health() module.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hl.State == "" {
		return module.Health{State: module.StateDegraded, Detail: "starting"}
	}
	return m.hl
}

func (m *Module) setHealth(h module.Health) {
	m.mu.Lock()
	m.hl = h
	m.mu.Unlock()
}

// ConfigBlock returns a zero block for the JSON Schema and the conformance
// suite's strict-decode check.
func (*Module) ConfigBlock() any { return Config{} }

// mustType returns the declared type of a kind the module emits; an undeclared
// kind is a programming error, not a missing event.
func mustType(kind string) event.Type {
	ty, ok := event.Lookup(kind)
	if !ok {
		panic("suricata: emits undeclared kind " + kind)
	}
	return ty
}
