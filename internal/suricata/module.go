package suricata

import (
	"context"
	"sync"

	"github.com/PurdueBlueTeam/phylax/internal/event"
	"github.com/PurdueBlueTeam/phylax/internal/module"
)

// The kinds this module emits. Zeek's records are named under suricata because
// the contract allows only the module's own prefix, and the module is the
// integration for both tools (design: renaming map).
const (
	KindAlert    = "suricata.alert"
	KindDNS      = "suricata.dns"
	KindHTTP     = "suricata.http"
	KindZeekConn = "suricata.zeek_conn"
	KindZeekDNS  = "suricata.zeek_dns"
	KindRun      = "suricata.run"
)

// Alert is one Suricata alert, with the flow it belongs to.
type Alert struct {
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Proto       string `json:"proto"`
	CommunityID string `json:"community_id,omitempty"`
	FlowID      int64  `json:"flow_id,omitempty"`
	SignatureID int    `json:"signature_id"`
	Signature   string `json:"signature,omitempty"`
	Category    string `json:"category,omitempty"`
	Severity    int    `json:"severity"`
	Action      string `json:"action,omitempty"`
}

// DNS is one EVE dns record, carried as context for the alerts on its flow.
type DNS struct {
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Proto       string `json:"proto"`
	CommunityID string `json:"community_id,omitempty"`
	FlowID      int64  `json:"flow_id,omitempty"`
	RRName      string `json:"rrname,omitempty"`
	RRType      string `json:"rrtype,omitempty"`
}

// HTTP is one EVE http record, carried as context for the alerts on its flow.
type HTTP struct {
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Proto       string `json:"proto"`
	CommunityID string `json:"community_id,omitempty"`
	FlowID      int64  `json:"flow_id,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	URL         string `json:"url,omitempty"`
	Method      string `json:"method,omitempty"`
}

// ZeekConn is one Zeek conn.log record.
type ZeekConn struct {
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Proto       string `json:"proto"`
	CommunityID string `json:"community_id,omitempty"`
	UID         string `json:"uid,omitempty"`
	Service     any    `json:"service,omitempty"`
	ConnState   any    `json:"conn_state,omitempty"`
	Duration    any    `json:"duration,omitempty"`
	OrigBytes   any    `json:"orig_bytes,omitempty"`
	RespBytes   any    `json:"resp_bytes,omitempty"`
}

// ZeekDNS is one Zeek dns.log record.
type ZeekDNS struct {
	SrcIP       string `json:"src_ip"`
	SrcPort     int    `json:"src_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Proto       string `json:"proto"`
	CommunityID string `json:"community_id,omitempty"`
	UID         string `json:"uid,omitempty"`
	Query       any    `json:"query,omitempty"`
	QTypeName   any    `json:"qtype_name,omitempty"`
	RCodeName   any    `json:"rcode_name,omitempty"`
	Answers     any    `json:"answers,omitempty"`
}

// Run is one pcap analysis: what was read, and why it failed if it did.
type Run struct {
	Pcap    string `json:"pcap"`
	Alerts  int    `json:"alerts"`
	Records int    `json:"records"`
	Error   string `json:"error,omitempty"`
}

func init() {
	event.Declare(event.Type{Kind: KindAlert, Schema: 1, Priority: event.PriorityNormal, Fields: Alert{}})
	event.Declare(event.Type{Kind: KindDNS, Schema: 1, Priority: event.PriorityBulk, Fields: DNS{}})
	event.Declare(event.Type{Kind: KindHTTP, Schema: 1, Priority: event.PriorityBulk, Fields: HTTP{}})
	event.Declare(event.Type{Kind: KindZeekConn, Schema: 1, Priority: event.PriorityBulk, Fields: ZeekConn{}})
	event.Declare(event.Type{Kind: KindZeekDNS, Schema: 1, Priority: event.PriorityBulk, Fields: ZeekDNS{}})
	event.Declare(event.Type{Kind: KindRun, Schema: 1, Priority: event.PriorityNormal, Fields: Run{}})
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
		Emits: []event.Type{
			mustType(KindAlert), mustType(KindDNS), mustType(KindHTTP),
			mustType(KindZeekConn), mustType(KindZeekDNS), mustType(KindRun),
		},
		Default: false,
		Actions: []string{"suricata.analyze_pcap"},
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
